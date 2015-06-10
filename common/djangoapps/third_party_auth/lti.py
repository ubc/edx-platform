import logging
import calendar
import time

from social.backends.base import BaseAuth
from social.exceptions import AuthFailed
from oauthlib.oauth1.rfc5849.signature import normalize_base_string_uri, normalize_parameters, collect_parameters, construct_base_string, sign_hmac_sha1
from django.contrib.auth import REDIRECT_FIELD_NAME, logout
from social.utils import sanitize_redirect

log = logging.getLogger(__name__)

LTI_PARAMS_KEY = 'tpa-lti-params'


class LTIAuthBackend(BaseAuth):
    name = 'lti'

    def start(self, redirect_name=REDIRECT_FIELD_NAME):
        """
        Prepare to handle a login request. This method replaces
        social.actions.do_auth and must be kept in sync with any
        upstream changes in that method.
        """

        # Clean any partial pipeline data
        self.strategy.clean_partial_pipeline()

        # Save validated LTI parameters (or None if invalid or not submitted)
        current_time = calendar.timegm(time.gmtime())
        validated_lti_params = self.get_validated_lti_params(self.strategy, current_time)
        if not validated_lti_params:
            self.strategy.session_set(LTI_PARAMS_KEY, None)
            raise AuthFailed(self)
        else:
            logout(self.strategy.request)
            self.strategy.session_set(LTI_PARAMS_KEY, validated_lti_params)

        # Save extra data into session.
        # While Basic LTI 1.0 specifies that the message is to be signed using OAuth, implying
        # that any GET parameters should be stripped from the base URL and included as signed
        # parameters, typical LTI Tool Consumer implementations do not support this behaviour. As
        # a workaround, we accept TPA parameters from LTI custom parameters prefixed with "tpa_".

        for field_name in self.setting('FIELDS_STORED_IN_SESSION', []):
            if 'custom_tpa_' + field_name in validated_lti_params:
                self.strategy.session_set(field_name, validated_lti_params['custom_tpa_' + field_name])

        if 'custom_tpa_' + redirect_name in validated_lti_params:
            # Check and sanitize a user-defined GET/POST next field value
            redirect_uri = validated_lti_params['custom_tpa_' + redirect_name]
            if self.setting('SANITIZE_REDIRECTS', True):
                redirect_uri = sanitize_redirect(self.strategy.request_host(),
                                                 redirect_uri)
            self.strategy.session_set(
                redirect_name,
                redirect_uri or self.setting('LOGIN_REDIRECT_URL')
            )

        # Set a auth_entry here so we don't have to receive that as a custom parameter
        self.strategy.session_setdefault('auth_entry', 'login')

    def auth_complete(self, *args, **kwargs):
        lti_params = self.strategy.session_get(LTI_PARAMS_KEY)
        kwargs.update({'response': {LTI_PARAMS_KEY: lti_params}, 'backend': self})
        return self.strategy.authenticate(*args, **kwargs)

    def get_user_id(self, details, response):
        lti_params = response[LTI_PARAMS_KEY]
        return lti_params['oauth_consumer_key'] + ":" + lti_params['user_id']

    def get_user_details(self, response):
        details = {}
        lti_params = response[LTI_PARAMS_KEY]

        def add_if_exists(lti_key, details_key):
            if lti_key in lti_params and lti_params[lti_key]:
                details.update({details_key: lti_params[lti_key]})

        add_if_exists('email', 'email')
        add_if_exists('lis_person_name_full', 'fullname')
        add_if_exists('lis_person_name_given', 'first_name')
        add_if_exists('lis_person_name_family', 'last_name')
        return details

    @classmethod
    def get_validated_lti_params(cls, strategy, current_time):
        data = strategy.request_data(merge=True)
        lti_consumer_key = data.get('oauth_consumer_key', '')
        (lti_consumer_valid, lti_consumer_secret, lti_max_timestamp_age) = cls.load_lti_consumer(lti_consumer_key)

        # Taking a cue from oauthlib, to avoid leaking information through a timing attack,
        # we proceed through the entire validation before rejecting any request for any reason.
        # However, as noted there, the value of doing this is dubious.

        base_uri = normalize_base_string_uri(unicode(strategy.request.build_absolute_uri()))
        parameters = collect_parameters(body=strategy.request.body)
        parameters_string = normalize_parameters(parameters)
        base_string = construct_base_string(unicode(strategy.request.method), base_uri, parameters_string)

        computed_signature = sign_hmac_sha1(base_string, lti_consumer_secret, '')
        submitted_signature = data.get('oauth_signature', '')

        def safe_int(value):
            try:
                return int(value)
            except ValueError:
                return 0

        oauth_timestamp = safe_int(data.get('oauth_timestamp', '0'))

        valid =  lti_consumer_valid
        valid &= submitted_signature == computed_signature
        valid &= data.get('oauth_version', '') == '1.0'
        valid &= data.get('oauth_signature_method', '') == 'HMAC-SHA1'
        valid &= oauth_timestamp >= current_time - lti_max_timestamp_age
        valid &= oauth_timestamp <= current_time
        if valid:
            return data
        else:
            return None

    @classmethod
    def load_lti_consumer(cls, lti_consumer_key):
        from .models import LTIProviderConfig
        provider_config = LTIProviderConfig.current(lti_consumer_key)
        if provider_config and provider_config.enabled:
            return True, provider_config.lti_consumer_secret, provider_config.lti_max_timestamp_age
        else:
            return False, '', -1
