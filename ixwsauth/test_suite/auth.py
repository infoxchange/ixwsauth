"""
Tests for WSX Auth Components
"""
#
# pylint:disable=R0904,R0902,C0103,W0201
# - R0904: Stuff inheriting from TestCase always has too many public methods
# - R0902: Tests need as many instance attribute as they need (mocks etc)
# - C0103: Test function names need to follow unittest conventions
# - W0201: setting attributes outside __init__ is fine for tests
#
from copy import deepcopy
from mock import patch

from django.test import TestCase
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

from ixwsauth.auth import WebServicesConsumer, AuthManager


class WebServicesConsumerTests(TestCase):
    """
    Test cases for the WebServicesConsumer class
    """
    def setUp(self):
        """
        mocks and test values
        """
        self.cons_key = '99d27293b4bbd42d2937219aa5497ea51dee3bf9'
        self.cons_secret = '5b18ad13fe57d09b740b7985eddd1387da53e768'

    def test_consumer_key(self):
        """
        Constructor should throw exception if setting value is missing,
        otherwise it should place the value in the right place
        """
        self.settings_key_patcher = patch.object(settings,
                                'IXWS_CONSUMER_KEY', None, create=True,)
        self.settings_key_patcher.start()
        try:
            with self.assertRaises(ImproperlyConfigured):
                consumer = WebServicesConsumer()
        finally:
            self.settings_key_patcher.stop()

        self.settings_key_patcher = patch.object(settings,
                                        'IXWS_CONSUMER_KEY', self.cons_key,
                                        create=True)
        self.settings_secret_patcher = patch.object(settings,
                                    'IXWS_CONSUMER_SECRET', self.cons_secret,
                                    create=True)
        self.settings_key_patcher.start()
        self.settings_secret_patcher.start()
        try:
            consumer = WebServicesConsumer()
            self.assertEqual(consumer.key, self.cons_key)
        finally:
            self.settings_secret_patcher.stop()
            self.settings_key_patcher.stop()

    def test_consumer_secret(self):
        """
        Constructor should throw exception if setting value is missing,
        otherwise it should place the value in the right place
        """
        self.settings_key_patcher = patch.object(settings,
                                        'IXWS_CONSUMER_KEY', self.cons_key,
                                        create=True)
        self.settings_key_patcher.start()
        try:
            self.settings_secret_patcher = patch.object(settings,
                                        'IXWS_CONSUMER_SECRET', None,
                                        create=True)
            self.settings_secret_patcher.start()
            try:
                with self.assertRaises(ImproperlyConfigured):
                    consumer = WebServicesConsumer()
            finally:
                self.settings_secret_patcher.stop()

            self.settings_secret_patcher = patch.object(settings,
                                    'IXWS_CONSUMER_SECRET', self.cons_secret,
                                    create=True)
            self.settings_secret_patcher.start()
            try:
                consumer = WebServicesConsumer()
                self.assertEqual(consumer.secret(), self.cons_secret)
            finally:
                self.settings_secret_patcher.stop()
        finally:
            self.settings_key_patcher.stop()


class AuthManagerTests(TestCase):
    """
    Test cases for the AuthManager class
    """
    def setUp(self):
        """
        mocks and test values
        """
        self.instance = AuthManager()
        self.test_params = {
            'a': 'with whitespace',
            'b': '%with * weird @ stuff'
        }
        self.test_params_array_vals_for_b = [
            'an',
            'unsorted',
            'array',
            'of',
            'values'
        ]
        self.test_oauth_params = {
            'oauth_consumer_key': '99d27293b4bbd42d2937219aa5497ea51dee3bf9',
            'oauth_nonce': '2ZLE6ApP5B',
            'oauth_timestamp': 1334200159,
            'oauth_signature_method': 'HMAC-SHA1',
            'oauth_version': '1.0'
        }
        self.test_params_with_oauth = deepcopy(self.test_params)
        self.test_params_with_oauth.update(self.test_oauth_params)

        self.test_url = 'http://s2s.ozgur.dev?some=var'

        self.test_payload = {
            'params': self.test_params,
            'method': 'GET',
            'url': self.test_url
        }
        self.test_payload_oauth_params = deepcopy(self.test_payload)
        self.test_payload_oauth_params['params'] = \
                                    self.test_params_with_oauth
        self.test_payload_oauth_headers = deepcopy(self.test_payload)
        self.test_payload_oauth_headers['headers'] = {
                                'Authorization': self.test_oauth_params}

        #
        # mock consumer
        #
        self.consumer_patcher = patch(
            'ixwsauth.auth.WebServicesConsumer',
            autospec=True)
        self.addCleanup(self.consumer_patcher.stop)
        self.consumer_mock_class = self.consumer_patcher.start()
        self.consumer_mock_instance = self.consumer_mock_class.return_value
        self.consumer_mock_instance.key = \
            '99d27293b4bbd42d2937219aa5497ea51dee3bf9'
        self.consumer_mock_instance.secret.return_value = \
            '5b18ad13fe57d09b740b7985eddd1387da53e768'
        #
        # mock time
        #
        self.time_patcher = patch('ixwsauth.auth.time', autospec=True)
        self.addCleanup(self.time_patcher.stop)
        self.time_mock_class = self.time_patcher.start()
        self.time_mock_class.return_value = '1334200159'
        #
        # mock utils.random_string
        #
        self.util_patcher = patch('ixwsauth.auth.random_string',
                                  autospec=True)
        self.addCleanup(self.util_patcher.stop)
        self.util_mock_class = self.util_patcher.start()
        self.util_mock_class.return_value = '2ZLE6ApP5B'
        #
        # since both nonce and timestamp are fixed with mocks, using
        # the test_params should always result in the same signature
        #
        self.test_sig = 'stimk30kABrFN9rHHNltwpESOes%3D'

        self.test_payload_oauth_params_with_sig = \
                               deepcopy(self.test_payload_oauth_params)
        (self.test_payload_oauth_params_with_sig['params']
                                                ['oauth_signature']) = \
                                                            self.test_sig

        self.test_payload_oauth_headers_with_sig = \
                                   deepcopy(self.test_payload_oauth_headers)
        (self.test_payload_oauth_headers_with_sig['headers']
                                                 ['Authorization']
                                                 ['oauth_signature']) = \
                                                            self.test_sig

    def test_generate_oauth_signature(self):
        """
        this method makes use of others in this class so if their tests
        fail, fix them before retrying this test.
        """
        #
        # We can accept oauth stuff in the parameters
        #
        signature = self.instance.generate_oauth_signature(
                                              self.consumer_mock_instance,
                                              self.test_payload_oauth_params)
        self.assertEqual(signature, self.test_sig)

        #
        # We can also (preferably) accept oauth stuff in authorization
        # headers
        #
        signature = self.instance.generate_oauth_signature(
                                              self.consumer_mock_instance,
                                              self.test_payload_oauth_headers)
        self.assertEqual(signature, self.test_sig)

        #
        # QueryDicts (request params) require special treatment of multiple
        # values for a param so we need to test that such a case won't
        # break anything
        #
        self.test_payload_oauth_params['params']['b'] = \
                                           self.test_params_array_vals_for_b
        signature = self.instance.generate_oauth_signature(
                                              self.consumer_mock_instance,
                                              self.test_payload_oauth_params)
        self.assertEqual(signature, '4jLuUXeaQF9ytkFgkiPMoo%2FsO1g%3D')

    def test_oauth_signature_from_payload(self):
        """
        function returns value from right key in params
        """
        #
        # from params
        #
        self.assertEqual(
            self.instance.oauth_signature_from_payload(
                    self.test_payload_oauth_params_with_sig),
            self.test_sig)
        #
        # from headers
        #
        self.assertEqual(
            self.instance.oauth_signature_from_payload(
                    self.test_payload_oauth_headers_with_sig),
            self.test_sig)

    def test_consumer_key_from_payload(self):
        """
        function returns value from right key in params
        """
        #
        # from params
        #
        self.assertEqual(
            self.instance.consumer_key_from_payload(
                    self.test_payload_oauth_params),
            self.test_params_with_oauth['oauth_consumer_key'])
        #
        # from headers
        #
        self.assertEqual(
            self.instance.consumer_key_from_payload(
                    self.test_payload_oauth_headers),
            self.test_params_with_oauth['oauth_consumer_key'])

    def test_oauth_signed_payload(self):
        """
        all oAuth params should be added along with the signature
        """
        self.assertItemsEqual(
            self.instance.oauth_signed_payload(
                        self.consumer_mock_instance,
                        self.test_payload),
            self.test_payload_oauth_headers_with_sig)

    def test_oauth_n_url_str(self):
        """
        correct normalized url is returned
        """
        self.assertEqual(
            self.instance.oauth_n_url_str(self.test_url),
            'http://s2s.ozgur.dev')

    def test_oauth_n_params_str(self):
        """
        correct normalized string is returned
        """
        self.assertEqual(
            self.instance.oauth_n_params_str(self.test_params),
            'a=with%20whitespace&b=%25with%20%2A%20weird%20%40%20stuff')

        self.test_params['b'] = self.test_params_array_vals_for_b
        self.assertEqual(
            self.instance.oauth_n_params_str(self.test_params),
            'a=with%20whitespace&b=an&b=array&b=of&b=unsorted&b=values')
