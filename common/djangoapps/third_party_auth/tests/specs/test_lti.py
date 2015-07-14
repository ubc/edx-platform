"""
Integration tests for third_party_auth LTI auth providers
"""
import unittest
from django.contrib.auth.models import User
from django.core.urlresolvers import reverse
from oauthlib.oauth1.rfc5849 import Client, SIGNATURE_TYPE_BODY
from third_party_auth.tests import testutil

FORM_ENCODED = 'application/x-www-form-urlencoded'

LTI_CONSUMER_KEY = 'consumer'
LTI_CONSUMER_SECRET = 'secret'
LTI_TPA_LOGIN_URL = 'http://testserver/auth/login/lti/'
LTI_TPA_COMPLETE_URL = 'http://testserver/auth/complete/lti/'
LTI_USER_ID = 'lti_user_id'
EDX_USER_ID = 'test_user'
EMAIL = 'lti_user@example.com'

@unittest.skipUnless(testutil.AUTH_FEATURE_ENABLED, 'third_party_auth not enabled')
class IntegrationTestLTI(testutil.TestCase):

    def setUp(self):
        super(IntegrationTestLTI, self).setUp()
        self.configure_lti_provider(
            name='LTI Test Tool Consumer', enabled=True,
            lti_consumer_key=LTI_CONSUMER_KEY,
            lti_consumer_secret=LTI_CONSUMER_SECRET,
            lti_max_timestamp_age=10,
        )
        self.lti = Client(
            client_key=LTI_CONSUMER_KEY,
            client_secret=LTI_CONSUMER_SECRET,
            signature_type=SIGNATURE_TYPE_BODY,
        )

    def test_lti_login(self):
        # The user initiates a login from an external site
        (uri, headers, body) = self.lti.sign(
            uri=LTI_TPA_LOGIN_URL, http_method='POST',
            headers={'Content-Type': FORM_ENCODED},
            body={'user_id': LTI_USER_ID}
        )
        login_response = self.client.post(path=uri, content_type=FORM_ENCODED, data=body)
        # The user should be redirected to the registration form
        self.assertEqual(login_response.status_code, 302)
        self.assertTrue(login_response['Location'].endswith(reverse('signin_user')))
        register_response = self.client.get(login_response['Location'])
        self.assertEqual(register_response.status_code, 200)
        self.assertIn('currentProvider&#34;: &#34;LTI Test Tool Consumer&#34;', register_response.content)
        self.assertIn('&#34;errorMessage&#34;: null', register_response.content)

        # Now complete the form:
        ajax_register_response = self.client.post(
            reverse('user_api_registration'),
            {
                'email': EMAIL,
                'name': 'Myself',
                'username': EDX_USER_ID,
                'honor_code': True,
            }
        )
        self.assertEqual(ajax_register_response.status_code, 200)
        continue_response = self.client.get(LTI_TPA_COMPLETE_URL)
        # The user should be redirected to the dashboard
        self.assertEqual(continue_response.status_code, 302)
        self.assertTrue(continue_response['Location'].endswith(reverse('dashboard')))

        # Now check that we can login again
        self.client.logout()
        self.verify_user_email(EMAIL)
        (uri, headers, body) = self.lti.sign(
            uri=LTI_TPA_LOGIN_URL, http_method='POST',
            headers={'Content-Type': FORM_ENCODED},
            body={'user_id': LTI_USER_ID}
        )
        login_2_response = self.client.post(path=uri, content_type=FORM_ENCODED, data=body)
        # The user should be redirected to the dashboard
        self.assertEqual(login_2_response.status_code, 302)
        self.assertEqual(login_2_response['Location'], LTI_TPA_COMPLETE_URL)
        complete_2_response = self.client.get(login_2_response['Location'])
        self.assertEqual(complete_2_response.status_code, 302)
        self.assertTrue(complete_2_response['Location'].endswith(reverse('dashboard')))

        # Check that the user was created correctly
        user = User.objects.get(email=EMAIL)
        self.assertEqual(user.username, EDX_USER_ID)

    def test_reject_initiating_login(self):
        response = self.client.get(LTI_TPA_LOGIN_URL)
        self.assertEqual(response.status_code, 405)  # Not Allowed

    def test_reject_bad_login(self):
        response = self.client.post(
            path=LTI_TPA_LOGIN_URL, content_type=FORM_ENCODED,
            data="invalid=login"
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response['Location'], 'http://testserver/')
