"""
Unit tests for third_party_auth LTI auth providers
"""

import unittest
from oauthlib.common import Request
from third_party_auth.lti import LTIAuthBackend, LTI_PARAMS_KEY


class UnitTestLTI(unittest.TestCase):

    def test_get_user_details_missing_keys(self):
        lti = LTIAuthBackend()
        details = lti.get_user_details({LTI_PARAMS_KEY: {
            'lis_person_name_full': 'Full name'
        }})
        self.assertEquals(details, {
            'fullname': 'Full name'
        })

    def test_get_user_details_extra_keys(self):
        lti = LTIAuthBackend()
        details = lti.get_user_details({LTI_PARAMS_KEY: {
            'lis_person_name_full': 'Full name',
            'lis_person_name_given': 'Given',
            'lis_person_name_family': 'Family',
            'email': 'user@example.com',
            'other': 'something else'
        }})
        self.assertEquals(details, {
            'fullname': 'Full name',
            'first_name': 'Given',
            'last_name': 'Family',
            'email': 'user@example.com'
        })

    def test_get_user_id(self):
        lti = LTIAuthBackend()
        user_id = lti.get_user_id(None, {LTI_PARAMS_KEY: {
            'oauth_consumer_key': 'consumer',
            'user_id': 'user'
        }})
        self.assertEquals(user_id, 'consumer:user')

    def test_validate_lti_valid_request(self):
        request = Request(
            uri='https://example.com/lti',
            http_method='POST',
            body='lti_message_type=basic-lti-launch-request'
                + '&lti_version=LTI-1p0'
                + '&lis_outcome_service_url=http%3A%2F%2Fwww.imsglobal.org%2Fdevelopers%2FLTI%2Ftest%2Fv1p1%2Fcommon%2Ftool_consumer_outcome.php%3Fb64%3DMTIzNDU6OjpzZWNyZXQ%3D'
                + '&lis_result_sourcedid=feb-123-456-2929%3A%3A28883'
                + '&launch_presentation_return_url=http%3A%2F%2Fwww.imsglobal.org%2Fdevelopers%2FLTI%2Ftest%2Fv1p1%2Flms_return.php'
                + '&user_id=292832126'
                + '&custom_extra=parameter'
                + '&oauth_version=1.0'
                + '&oauth_nonce=c4936a7122f4f85c2d95afe32391573b'
                + '&oauth_timestamp=1436823553'
                + '&oauth_consumer_key=12345'
                + '&oauth_signature_method=HMAC-SHA1'
                + '&oauth_signature=STPWUouDw%2FlRGD4giWf8lpGTc54%3D'
                + '&oauth_callback=about%3Ablank'
        )
        parameters = LTIAuthBackend._get_validated_lti_params_from_values(
            request=request, current_time=1436823554,
            lti_consumer_valid=True, lti_consumer_secret='secret',
            lti_max_timestamp_age=10
        )
        self.assertTrue(parameters)
        self.assertDictContainsSubset({
            'custom_extra': 'parameter',
            'user_id': '292832126'
        }, parameters)

    def test_validate_lti_valid_request_with_get_params(self):
        request = Request(
            uri='https://example.com/lti?user_id=292832126&lti_version=LTI-1p0',
            http_method='POST',
            body='lti_message_type=basic-lti-launch-request'
                + '&lis_outcome_service_url=http%3A%2F%2Fwww.imsglobal.org%2Fdevelopers%2FLTI%2Ftest%2Fv1p1%2Fcommon%2Ftool_consumer_outcome.php%3Fb64%3DMTIzNDU6OjpzZWNyZXQ%3D'
                + '&lis_result_sourcedid=feb-123-456-2929%3A%3A28883'
                + '&launch_presentation_return_url=http%3A%2F%2Fwww.imsglobal.org%2Fdevelopers%2FLTI%2Ftest%2Fv1p1%2Flms_return.php'
                + '&custom_extra=parameter'
                + '&oauth_version=1.0'
                + '&oauth_nonce=c4936a7122f4f85c2d95afe32391573b'
                + '&oauth_timestamp=1436823553'
                + '&oauth_consumer_key=12345'
                + '&oauth_signature_method=HMAC-SHA1'
                + '&oauth_signature=STPWUouDw%2FlRGD4giWf8lpGTc54%3D'
                + '&oauth_callback=about%3Ablank'
        )
        parameters = LTIAuthBackend._get_validated_lti_params_from_values(
            request=request, current_time=1436823554,
            lti_consumer_valid=True, lti_consumer_secret='secret',
            lti_max_timestamp_age=10
        )
        self.assertTrue(parameters)
        self.assertDictContainsSubset({
            'custom_extra': 'parameter',
            'user_id': '292832126'
        }, parameters)

    def test_validate_lti_old_timestamp(self):
        request = Request(
            uri='https://example.com/lti',
            http_method='POST',
            body='lti_message_type=basic-lti-launch-request'
                 + '&lti_version=LTI-1p0'
                 + '&lis_outcome_service_url=http%3A%2F%2Fwww.imsglobal.org%2Fdevelopers%2FLTI%2Ftest%2Fv1p1%2Fcommon%2Ftool_consumer_outcome.php%3Fb64%3DMTIzNDU6OjpzZWNyZXQ%3D'
                 + '&lis_result_sourcedid=feb-123-456-2929%3A%3A28883'
                 + '&launch_presentation_return_url=http%3A%2F%2Fwww.imsglobal.org%2Fdevelopers%2FLTI%2Ftest%2Fv1p1%2Flms_return.php'
                 + '&user_id=292832126'
                 + '&custom_extra=parameter'
                 + '&oauth_version=1.0'
                 + '&oauth_nonce=c4936a7122f4f85c2d95afe32391573b'
                 + '&oauth_timestamp=1436823553'
                 + '&oauth_consumer_key=12345'
                 + '&oauth_signature_method=HMAC-SHA1'
                 + '&oauth_signature=STPWUouDw%2FlRGD4giWf8lpGTc54%3D'
                 + '&oauth_callback=about%3Ablank'
        )
        parameters = LTIAuthBackend._get_validated_lti_params_from_values(
            request=request, current_time=1436900000,
            lti_consumer_valid=True, lti_consumer_secret='secret',
            lti_max_timestamp_age=10
        )
        self.assertFalse(parameters)

    def test_validate_lti_invalid_signature(self):
        request = Request(
            uri='https://example.com/lti',
            http_method='POST',
            body='lti_message_type=basic-lti-launch-request'
                 + '&lti_version=LTI-1p0'
                 + '&lis_outcome_service_url=http%3A%2F%2Fwww.imsglobal.org%2Fdevelopers%2FLTI%2Ftest%2Fv1p1%2Fcommon%2Ftool_consumer_outcome.php%3Fb64%3DMTIzNDU6OjpzZWNyZXQ%3D'
                 + '&lis_result_sourcedid=feb-123-456-2929%3A%3A28883'
                 + '&launch_presentation_return_url=http%3A%2F%2Fwww.imsglobal.org%2Fdevelopers%2FLTI%2Ftest%2Fv1p1%2Flms_return.php'
                 + '&user_id=292832126'
                 + '&custom_extra=parameter'
                 + '&oauth_version=1.0'
                 + '&oauth_nonce=c4936a7122f4f85c2d95afe32391573b'
                 + '&oauth_timestamp=1436823553'
                 + '&oauth_consumer_key=12345'
                 + '&oauth_signature_method=HMAC-SHA1'
                 + '&oauth_signature=STPWUouDw%2FlRGD4giWf8lpXXXXX%3D'
                 + '&oauth_callback=about%3Ablank'
        )
        parameters = LTIAuthBackend._get_validated_lti_params_from_values(
            request=request, current_time=1436823554,
            lti_consumer_valid=True, lti_consumer_secret='secret',
            lti_max_timestamp_age=10
        )
        self.assertFalse(parameters)

    def test_validate_lti_cannot_add_get_params(self):
        request = Request(
            uri='https://example.com/lti?custom_another=parameter',
            http_method='POST',
            body='lti_message_type=basic-lti-launch-request'
                 + '&lti_version=LTI-1p0'
                 + '&lis_outcome_service_url=http%3A%2F%2Fwww.imsglobal.org%2Fdevelopers%2FLTI%2Ftest%2Fv1p1%2Fcommon%2Ftool_consumer_outcome.php%3Fb64%3DMTIzNDU6OjpzZWNyZXQ%3D'
                 + '&lis_result_sourcedid=feb-123-456-2929%3A%3A28883'
                 + '&launch_presentation_return_url=http%3A%2F%2Fwww.imsglobal.org%2Fdevelopers%2FLTI%2Ftest%2Fv1p1%2Flms_return.php'
                 + '&user_id=292832126'
                 + '&custom_extra=parameter'
                 + '&oauth_version=1.0'
                 + '&oauth_nonce=c4936a7122f4f85c2d95afe32391573b'
                 + '&oauth_timestamp=1436823553'
                 + '&oauth_consumer_key=12345'
                 + '&oauth_signature_method=HMAC-SHA1'
                 + '&oauth_signature=STPWUouDw%2FlRGD4giWf8lpGTc54%3D'
                 + '&oauth_callback=about%3Ablank'
        )
        parameters = LTIAuthBackend._get_validated_lti_params_from_values(
            request=request, current_time=1436823554,
            lti_consumer_valid=True, lti_consumer_secret='secret',
            lti_max_timestamp_age=10
        )
        self.assertFalse(parameters)

    def test_validate_lti_garbage(self):
        request = Request(
            uri='https://example.com/lti',
            http_method='POST',
            body='some=garbage&values=provided'
        )
        parameters = LTIAuthBackend._get_validated_lti_params_from_values(
            request=request, current_time=1436823554,
            lti_consumer_valid=True, lti_consumer_secret='secret',
            lti_max_timestamp_age=10
        )
        self.assertFalse(parameters)
