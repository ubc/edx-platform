"""Auth pipeline definitions.

Auth pipelines handle the process of authenticating a user. They involve a
consumer system and a provider service. The general pattern is:

    1. The consumer system exposes a URL endpoint that starts the process.
    2. When a user visits that URL, the client system redirects the user to a
       page served by the provider. The user authenticates with the provider.
       The provider handles authentication failure however it wants.
    3. On success, the provider POSTs to a URL endpoint on the consumer to
       invoke the pipeline. It sends back an arbitrary payload of data about
       the user.
    4. The pipeline begins, executing each function in its stack. The stack is
       defined on django's settings object's SOCIAL_AUTH_PIPELINE. This is done
       in settings._set_global_settings.
    5. Each pipeline function is variadic. Most pipeline functions are part of
       the pythons-social-auth library; our extensions are defined below. The
       pipeline is the same no matter what provider is used.
    6. Pipeline functions can return a dict to add arguments to the function
       invoked next. They can return None if this is not necessary.
    7. Pipeline functions may be decorated with @partial.partial. This pauses
       the pipeline and serializes its state onto the request's session. When
       this is done they may redirect to other edX handlers to execute edX
       account registration/sign in code.
    8. In that code, redirecting to get_complete_url() resumes the pipeline.
       This happens by hitting a handler exposed by the consumer system.
    9. In this way, execution moves between the provider, the pipeline, and
       arbitrary consumer system code.

Gotcha alert!:

Bear in mind that when pausing and resuming a pipeline function decorated with
@partial.partial, execution resumes by re-invoking the decorated function
instead of invoking the next function in the pipeline stack. For example, if
you have a pipeline of

    A
    B
    C

with an implementation of

    @partial.partial
    def B(*args, **kwargs):
        [...]

B will be invoked twice: once when initially proceeding through the pipeline
before it is paused, and once when other code finishes and the pipeline
resumes. Consequently, many decorated functions will first invoke a predicate
to determine if they are in their first or second execution (usually by
checking side-effects from the first run).

This is surprising but important behavior, since it allows a single function in
the pipeline to consolidate all the operations needed to establish invariants
rather than spreading them across two functions in the pipeline.

See http://psa.matiasaguirre.net/docs/pipeline.html for more docs.
"""

import random
import string  # pylint: disable-msg=deprecated-module
from collections import OrderedDict
import urllib
from ipware.ip import get_ip
import analytics
from eventtracking import tracker

from django.contrib.auth.models import User
from django.core.urlresolvers import reverse
from django.http import HttpResponseBadRequest
from django.shortcuts import redirect
from social.apps.django_app.default import models
from social.exceptions import AuthException
from social.pipeline import partial
from social.pipeline.social_auth import associate_by_email

import student

from logging import getLogger

from . import provider

# Note that this lives in openedx, so this dependency should be refactored.
from openedx.core.djangoapps.user_api.preferences.api import update_email_opt_in


# These are the query string params you can pass
# to the URL that starts the authentication process.
#
# `AUTH_ENTRY_KEY` is required and indicates how the user
# enters the authentication process.
#
# `AUTH_REDIRECT_KEY` provides an optional URL to redirect
# to upon successful authentication
# (if not provided, defaults to `_SOCIAL_AUTH_LOGIN_REDIRECT_URL`)
AUTH_ENTRY_KEY = 'auth_entry'
AUTH_REDIRECT_KEY = 'next'


# The following are various possible values for the AUTH_ENTRY_KEY.
AUTH_ENTRY_LOGIN = 'login'
AUTH_ENTRY_REGISTER = 'register'
AUTH_ENTRY_ACCOUNT_SETTINGS = 'account_settings'

# This is left-over from an A/B test
# of the new combined login/registration page (ECOM-369)
# We need to keep both the old and new entry points
# until every session from before the test ended has expired.
AUTH_ENTRY_LOGIN_2 = 'account_login'
AUTH_ENTRY_REGISTER_2 = 'account_register'

# Entry modes into the authentication process by a remote API call (as opposed to a browser session).
AUTH_ENTRY_LOGIN_API = 'login_api'
AUTH_ENTRY_REGISTER_API = 'register_api'


def is_api(auth_entry):
    """Returns whether the auth entry point is via an API call."""
    return (auth_entry == AUTH_ENTRY_LOGIN_API) or (auth_entry == AUTH_ENTRY_REGISTER_API)

# URLs associated with auth entry points
# These are used to request additional user information
# (for example, account credentials when logging in),
# and when the user cancels the auth process
# (e.g., refusing to grant permission on the provider's login page).
# We don't use "reverse" here because doing so may cause modules
# to load that depend on this module.
AUTH_DISPATCH_URLS = {
    AUTH_ENTRY_LOGIN: '/login',
    AUTH_ENTRY_REGISTER: '/register',
    AUTH_ENTRY_ACCOUNT_SETTINGS: '/account/settings',

    # This is left-over from an A/B test
    # of the new combined login/registration page (ECOM-369)
    # We need to keep both the old and new entry points
    # until every session from before the test ended has expired.
    AUTH_ENTRY_LOGIN_2: '/account/login/',
    AUTH_ENTRY_REGISTER_2: '/account/register/',

}

_AUTH_ENTRY_CHOICES = frozenset([
    AUTH_ENTRY_LOGIN,
    AUTH_ENTRY_REGISTER,
    AUTH_ENTRY_ACCOUNT_SETTINGS,

    # This is left-over from an A/B test
    # of the new combined login/registration page (ECOM-369)
    # We need to keep both the old and new entry points
    # until every session from before the test ended has expired.
    AUTH_ENTRY_LOGIN_2,
    AUTH_ENTRY_REGISTER_2,

    AUTH_ENTRY_LOGIN_API,
    AUTH_ENTRY_REGISTER_API,
])

_DEFAULT_RANDOM_PASSWORD_LENGTH = 12
_PASSWORD_CHARSET = string.letters + string.digits

logger = getLogger(__name__)


class AuthEntryError(AuthException):
    """Raised when auth_entry is missing or invalid on URLs.

    auth_entry tells us whether the auth flow was initiated to register a new
    user (in which case it has the value of AUTH_ENTRY_REGISTER) or log in an
    existing user (in which case it has the value of AUTH_ENTRY_LOGIN).

    This is necessary because the edX code we hook into the pipeline to
    redirect to the existing auth flows needs to know what case we are in in
    order to format its output correctly (for example, the register code is
    invoked earlier than the login code, and it needs to know if the login flow
    was requested to dispatch correctly).
    """


class NotActivatedException(AuthException):
    """ Raised when a user tries to login to an uverified account """
    def __str__(self):
        return 'This account has not yet been activated.'


class ProviderUserState(object):
    """Object representing the provider state (attached or not) for a user.

    This is intended only for use when rendering templates. See for example
    lms/templates/dashboard.html.
    """

    def __init__(self, enabled_provider, user, association_id=None):
        # UserSocialAuth row ID
        self.association_id = association_id
        # Boolean. Whether the user has an account associated with the provider
        self.has_account = association_id is not None
        # provider.BaseProvider child. Callers must verify that the provider is
        # enabled.
        self.provider = enabled_provider
        # django.contrib.auth.models.User.
        self.user = user

    def get_unlink_form_name(self):
        """Gets the name used in HTML forms that unlink a provider account."""
        return self.provider.provider_id + '_unlink_form'


def get(request):
    """Gets the running pipeline from the passed request."""
    return request.session.get('partial_pipeline')


def get_authenticated_user(auth_provider, username, uid):
    """Gets a saved user authenticated by a particular backend.

    Between pipeline steps User objects are not saved. We need to reconstitute
    the user and set its .backend, which is ordinarily monkey-patched on by
    Django during authenticate(), so it will function like a user returned by
    authenticate().

    Args:
        auth_provider: the third_party_auth provider in use for the current pipeline.
        username: string. Username of user to get.
        uid: string. The user ID according to the third party.

    Returns:
        User if user is found and has a social auth from the passed
        provider.

    Raises:
        User.DoesNotExist: if no user matching user is found, or the matching
        user has no social auth associated with the given backend.
        AssertionError: if the user is not authenticated.
    """
    match = models.DjangoStorage.user.get_social_auth(provider=auth_provider.backend_name, uid=uid)

    if not match or match.user.username != username:
        raise User.DoesNotExist

    user = match.user
    user.backend = auth_provider.get_authentication_backend()
    return user


def _get_enabled_provider(provider_id):
    """Gets an enabled provider by its provider_id member or throws."""
    enabled_provider = provider.Registry.get(provider_id)

    if not enabled_provider:
        raise ValueError('Provider %s not enabled' % provider_id)

    return enabled_provider


def _get_url(view_name, backend_name, auth_entry=None, redirect_url=None,
             extra_params=None, url_params=None):
    """Creates a URL to hook into social auth endpoints."""
    url_params = url_params or {}
    url_params['backend'] = backend_name
    url = reverse(view_name, kwargs=url_params)

    query_params = OrderedDict()
    if auth_entry:
        query_params[AUTH_ENTRY_KEY] = auth_entry

    if redirect_url:
        query_params[AUTH_REDIRECT_KEY] = redirect_url

    if extra_params:
        query_params.update(extra_params)

    return u"{url}?{params}".format(
        url=url,
        params=urllib.urlencode(query_params)
    )


def get_complete_url(backend_name):
    """Gets URL for the endpoint that returns control to the auth pipeline.

    Args:
        backend_name: string. Name of the python-social-auth backend from the
            currently-running pipeline.

    Returns:
        String. URL that finishes the auth pipeline for a provider.

    Raises:
        ValueError: if no provider is enabled with the given backend_name.
    """
    if not any(provider.Registry.get_enabled_by_backend_name(backend_name)):
        raise ValueError('Provider with backend %s not enabled' % backend_name)

    return _get_url('social:complete', backend_name)


def get_disconnect_url(provider_id, association_id):
    """Gets URL for the endpoint that starts the disconnect pipeline.

    Args:
        provider_id: string identifier of the models.ProviderConfig child you want
            to disconnect from.
        association_id: int. Optional ID of a specific row in the UserSocialAuth
            table to disconnect (useful if multiple providers use a common backend)

    Returns:
        String. URL that starts the disconnection pipeline.

    Raises:
        ValueError: if no provider is enabled with the given ID.
    """
    backend_name = _get_enabled_provider(provider_id).backend_name
    if association_id:
        return _get_url('social:disconnect_individual', backend_name, url_params={'association_id': association_id})
    else:
        return _get_url('social:disconnect', backend_name)


def get_login_url(provider_id, auth_entry, redirect_url=None):
    """Gets the login URL for the endpoint that kicks off auth with a provider.

    Args:
        provider_id: string identifier of the models.ProviderConfig child you want
            to disconnect from.
        auth_entry: string. Query argument specifying the desired entry point
            for the auth pipeline. Used by the pipeline for later branching.
            Must be one of _AUTH_ENTRY_CHOICES.

    Keyword Args:
        redirect_url (string): If provided, redirect to this URL at the end
            of the authentication process.

    Returns:
        String. URL that starts the auth pipeline for a provider.

    Raises:
        ValueError: if no provider is enabled with the given provider_id.
    """
    assert auth_entry in _AUTH_ENTRY_CHOICES
    enabled_provider = _get_enabled_provider(provider_id)
    return _get_url(
        'social:begin',
        enabled_provider.backend_name,
        auth_entry=auth_entry,
        redirect_url=redirect_url,
        extra_params=enabled_provider.get_url_params(),
    )


def get_duplicate_provider(messages):
    """Gets provider from message about social account already in use.

    python-social-auth's exception middleware uses the messages module to
    record details about duplicate account associations. It records exactly one
    message there is a request to associate a social account S with an edX
    account E if S is already associated with an edX account E'.

    This messaging approach is stringly-typed and the particular string is
    unfortunately not in a reusable constant.

    Returns:
        string name of the python-social-auth backend that has the duplicate
        account, or None if there is no duplicate (and hence no error).
    """
    social_auth_messages = [m for m in messages if m.message.endswith('is already in use.')]

    if not social_auth_messages:
        return

    assert len(social_auth_messages) == 1
    backend_name = social_auth_messages[0].extra_tags.split()[1]
    return backend_name


def get_provider_user_states(user):
    """Gets list of states of provider-user combinations.

    Args:
        django.contrib.auth.User. The user to get states for.

    Returns:
        List of ProviderUserState. The list of states of a user's account with
            each enabled provider.
    """
    states = []
    found_user_auths = list(models.DjangoStorage.user.get_social_auth_for_user(user))

    for enabled_provider in provider.Registry.enabled():
        association_id = None
        for auth in found_user_auths:
            if enabled_provider.match_social_auth(auth):
                association_id = auth.id
                break
        if enabled_provider.accepts_logins or association_id:
            states.append(
                ProviderUserState(enabled_provider, user, association_id)
            )

    return states


def make_random_password(length=None, choice_fn=random.SystemRandom().choice):
    """Makes a random password.

    When a user creates an account via a social provider, we need to create a
    placeholder password for them to satisfy the ORM's consistency and
    validation requirements. Users don't know (and hence cannot sign in with)
    this password; that's OK because they can always use the reset password
    flow to set it to a known value.

    Args:
        choice_fn: function or method. Takes an iterable and returns a random
            element.
        length: int. Number of chars in the returned value. None to use default.

    Returns:
        String. The resulting password.
    """
    length = length if length is not None else _DEFAULT_RANDOM_PASSWORD_LENGTH
    return ''.join(choice_fn(_PASSWORD_CHARSET) for _ in xrange(length))


def running(request):
    """Returns True iff request is running a third-party auth pipeline."""
    return request.session.get('partial_pipeline') is not None  # Avoid False for {}.


# Pipeline functions.
# Signatures are set by python-social-auth; prepending 'unused_' causes
# TypeError on dispatch to the auth backend's authenticate().
# pylint: disable-msg=unused-argument


def parse_query_params(strategy, response, *args, **kwargs):
    """Reads whitelisted query params, transforms them into pipeline args."""
    auth_entry = strategy.session.get(AUTH_ENTRY_KEY)
    if not (auth_entry and auth_entry in _AUTH_ENTRY_CHOICES):
        raise AuthEntryError(strategy.request.backend, 'auth_entry missing or invalid')

    return {'auth_entry': auth_entry}


@partial.partial
def ensure_user_information(strategy, auth_entry, backend=None, user=None, social=None,
                            allow_inactive_user=False, *args, **kwargs):
    """
    Ensure that we have the necessary information about a user (either an
    existing account or registration data) to proceed with the pipeline.
    """

    # We're deliberately verbose here to make it clear what the intended
    # dispatch behavior is for the various pipeline entry points, given the
    # current state of the pipeline. Keep in mind the pipeline is re-entrant
    # and values will change on repeated invocations (for example, the first
    # time through the login flow the user will be None so we dispatch to the
    # login form; the second time it will have a value so we continue to the
    # next pipeline step directly).
    #
    # It is important that we always execute the entire pipeline. Even if
    # behavior appears correct without executing a step, it means important
    # invariants have been violated and future misbehavior is likely.
    def dispatch_to_login():
        """Redirects to the login page."""
        return redirect(AUTH_DISPATCH_URLS[AUTH_ENTRY_LOGIN])

    def dispatch_to_register():
        """Redirects to the registration page."""
        return redirect(AUTH_DISPATCH_URLS[AUTH_ENTRY_REGISTER])

    if not user:
        if auth_entry in [AUTH_ENTRY_LOGIN_API, AUTH_ENTRY_REGISTER_API]:
            return HttpResponseBadRequest()
        elif auth_entry in [AUTH_ENTRY_LOGIN, AUTH_ENTRY_LOGIN_2]:
            # User has authenticated with the third party provider but we don't know which edX
            # account corresponds to them yet, if any.
            return dispatch_to_login()
        elif auth_entry in [AUTH_ENTRY_REGISTER, AUTH_ENTRY_REGISTER_2]:
            # User has authenticated with the third party provider and now wants to finish
            # creating their edX account.
            return dispatch_to_register()
        elif auth_entry == AUTH_ENTRY_ACCOUNT_SETTINGS:
            raise AuthEntryError(backend, 'auth_entry is wrong. Settings requires a user.')
        else:
            raise AuthEntryError(backend, 'auth_entry invalid')

    if not user.is_active:
        # The user account has not been verified yet.
        if allow_inactive_user:
            # This parameter is used by the auth_exchange app, which always allows users to
            # login, whether or not their account is validated.
            pass
        # IF the user has just registered a new account as part of this pipeline, that is fine
        # and we allow the login to continue this once, because if we pause again to force the
        # user to activate their account via email, the pipeline may get lost (e.g. email takes
        # too long to arrive, user opens the activation email on a different device, etc.).
        # This is consistent with first party auth and ensures that the pipeline completes
        # fully, which is critical.
        # But if this is an existing account, we refuse to allow them to login again until they
        # check their email and activate the account.
        elif social is not None:
            # This third party account is already linked to a user account. That means that the
            # user's account existed before this pipeline originally began (since the creation
            # of the 'social' link entry occurs in one of the following pipeline steps).
            # Reject this login attempt and tell the user to validate their account first.

            # TODO: resend validation email
            raise NotActivatedException(backend)
        # else: The user must have just successfully registered their account, so we proceed.
        # We know they did not just login, because the login process rejects unverified users.


@partial.partial
def set_logged_in_cookie(backend=None, user=None, strategy=None, auth_entry=None, *args, **kwargs):
    """This pipeline step sets the "logged in" cookie for authenticated users.

    Some installations have a marketing site front-end separate from
    edx-platform.  Those installations sometimes display different
    information for logged in versus anonymous users (e.g. a link
    to the student dashboard instead of the login page.)

    Since social auth uses Django's native `login()` method, it bypasses
    our usual login view that sets this cookie.  For this reason, we need
    to set the cookie ourselves within the pipeline.

    The procedure for doing this is a little strange.  On the one hand,
    we need to send a response to the user in order to set the cookie.
    On the other hand, we don't want to drop the user out of the pipeline.

    For this reason, we send a redirect back to the "complete" URL,
    so users immediately re-enter the pipeline.  The redirect response
    contains a header that sets the logged in cookie.

    If the user is not logged in, or the logged in cookie is already set,
    the function returns `None`, indicating that control should pass
    to the next pipeline step.

    """
    if not is_api(auth_entry) and user is not None and user.is_authenticated():
        request = strategy.request if strategy else None
        # n.b. for new users, user.is_active may be False at this point; set the cookie anyways.
        if request is not None:
            # Check that the cookie isn't already set.
            # This ensures that we allow the user to continue to the next
            # pipeline step once he/she has the cookie set by this step.
            has_cookie = student.helpers.is_logged_in_cookie_set(request)
            if not has_cookie:
                try:
                    redirect_url = get_complete_url(backend.name)
                except ValueError:
                    # If for some reason we can't get the URL, just skip this step
                    # This may be overly paranoid, but it's far more important that
                    # the user log in successfully than that the cookie is set.
                    pass
                else:
                    response = redirect(redirect_url)
                    return student.helpers.set_logged_in_cookie(request, response)


@partial.partial
def login_analytics(strategy, auth_entry, *args, **kwargs):
    """ Sends login info to Segment.io """

    event_name = None
    if auth_entry in [AUTH_ENTRY_LOGIN, AUTH_ENTRY_LOGIN_2]:
        event_name = 'edx.bi.user.account.authenticated'
    elif auth_entry in [AUTH_ENTRY_ACCOUNT_SETTINGS]:
        event_name = 'edx.bi.user.account.linked'

    if event_name is not None:
        tracking_context = tracker.get_tracker().resolve_context()
        analytics.track(
            kwargs['user'].id,
            event_name,
            {
                'category': "conversion",
                'label': None,
                'provider': getattr(kwargs['backend'], 'name')
            },
            context={
                'Google Analytics': {
                    'clientId': tracking_context.get('client_id')
                }
            }
        )


@partial.partial
def associate_by_email_if_login_api(auth_entry, backend, details, user, *args, **kwargs):
    """
    This pipeline step associates the current social auth with the user with the
    same email address in the database.  It defers to the social library's associate_by_email
    implementation, which verifies that only a single database user is associated with the email.

    This association is done ONLY if the user entered the pipeline through a LOGIN API.
    """
    if auth_entry == AUTH_ENTRY_LOGIN_API:
        association_response = associate_by_email(backend, details, user, *args, **kwargs)
        if (
            association_response and
            association_response.get('user') and
            association_response['user'].is_active
        ):
            # Only return the user matched by email if their email has been activated.
            # Otherwise, an illegitimate user can create an account with another user's
            # email address and the legitimate user would now login to the illegitimate
            # account.
            return association_response
