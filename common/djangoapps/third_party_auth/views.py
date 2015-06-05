"""
Extra views required for third party auth
"""
from django.conf import settings
from django.core.urlresolvers import reverse
from django.shortcuts import redirect
from django.http import HttpResponse, HttpResponseServerError, Http404, HttpResponseNotAllowed
from django.views.decorators.csrf import csrf_exempt
from social.apps.django_app.views import auth, complete
from social.apps.django_app.utils import load_strategy, load_backend

from .models import SAMLConfiguration


def saml_metadata_view(request):
    """
    Get the Service Provider metadata for this edx-platform instance.
    You must send this XML to any Shibboleth Identity Provider that you wish to use.
    """
    if not SAMLConfiguration.is_enabled():
        raise Http404
    complete_url = reverse('social:complete', args=("tpa-saml", ))
    if settings.APPEND_SLASH and not complete_url.endswith('/'):
        complete_url = complete_url + '/'  # Required for consistency
    saml_backend = load_backend(load_strategy(request), "tpa-saml", redirect_uri=complete_url)
    metadata, errors = saml_backend.generate_metadata_xml()

    if not errors:
        return HttpResponse(content=metadata, content_type='text/xml')
    return HttpResponseServerError(content=', '.join(errors))


def inactive_user_view(request):
    """
    A newly registered user has completed the social auth pipeline.
    Their account is not yet activated, but we let them login this once.
    """
    # 'next' may be set to '/account/finish_auth/.../' if this user needs to be auto-enrolled
    # in a course. Otherwise, just redirect them to the dashboard, which displays a message
    # about activating their account.
    return redirect(request.GET.get('next', 'dashboard'))


@csrf_exempt
def lti_login_view(request, *args, **kwargs):
    """This is a combination login/complete due to LTI being a one step login"""

    if request.method != 'POST':
        return HttpResponseNotAllowed('POST')

    backend = 'lti'
    auth(request, backend)
    return complete(request, backend, *args, **kwargs)
