"""
Auth Helpers

.. moduleauthor:: Infoxchange Development Team <development@infoxchange.net.au>

"""
import hashlib
import hmac
import binascii
from time import time
from copy import deepcopy
from urlparse import urlparse
from urllib import quote

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

from ixdjango.utils import random_string

OAUTH_SIG_METHOD = 'HMAC-SHA1'
OAUTH_VERSION = '1.0'
OAUTH_PARAMS = ['oauth_consumer_key',
                'oauth_nonce',
                'oauth_timestamp',
                'oauth_signature_method',
                'oauth_version',
                'oauth_signature']


class WebServicesConsumer(object):
    """
    Represents the consumer application for the web services. This class is
    mainly for representing the application using this package and requires
    IXWS_CONSUMER_KEY and IXWS_CONSUMER_SECRET to be present in the settings.
    """
    def __init__(self):
        """
        Make sure settings we need are available, set consumer key
        """
        if (not settings.IXWS_CONSUMER_KEY
           or not settings.IXWS_CONSUMER_SECRET):
            raise ImproperlyConfigured("Settings file does not contain " + \
                                       "authentication information.")
        self.key = settings.IXWS_CONSUMER_KEY

    #
    # pylint:disable=R0201
    # self isn't used YET
    #
    def secret(self):
        """
        Supply the consumer key. Unlike the key, this is done through a
        function as other classes of consumers are likely to need some
        evaluation to get this value
        """
        return settings.IXWS_CONSUMER_SECRET


class AuthManager(object):
    """
    Helper for commonly used authentication functionality
    """
    #
    # pylint:disable=R0201
    # self isn't used YET
    #
    def escape(self, string):
        """
        percentage escape a string as per oAuth standards
        """
        return quote(string, safe='~')

    def generate_oauth_signature(self, consumer, payload):
        """
        creates an oauth signature based on supplied params
        """
        secret = consumer.secret()
        local_params = {}
        if 'params' in payload and payload['params'] is not None:
            local_params.update(payload['params'])
        if 'headers' in payload and 'Authorization' in payload['headers']:
            for auth_param in payload['headers']['Authorization'].keys():
                if auth_param in OAUTH_PARAMS:
                    local_params[auth_param] = \
                        payload['headers']['Authorization'][auth_param]

        if 'oauth_signature' in local_params:
            del local_params['oauth_signature']
        
        raw_str_comps = (
            self.escape(payload['method'].upper()),
            self.escape(self.oauth_n_url_str(payload['url'])),
            self.escape(self.oauth_n_params_str(local_params)),
        )
        raw = '&'.join(raw_str_comps)
        #
        # secret should be ascii anyway but django magic presents it as unicode
        # which hmac doesn't accept?!
        #
        hashed = hmac.new("%s&" % secret.encode('ascii'), raw, hashlib.sha1)
        signature = binascii.b2a_base64(hashed.digest())[:-1]
        return self.escape(signature)

    def oauth_signature_from_payload(self, payload):
        """
        extracts the oauth signature from params or authorization headers
        """
        if 'params' in payload and 'oauth_signature' in payload['params']:
            return payload['params']['oauth_signature']
        if 'headers' in payload and 'Authorization' in payload['headers'] \
           and 'oauth_signature' in payload['headers']['Authorization']:
            return payload['headers']['Authorization']['oauth_signature']
        return None

    def consumer_key_from_payload(self, payload):
        """
        extracts the oauth consumer key from params or authorization headers
        """
        if 'params' in payload and 'oauth_consumer_key' in payload['params']:
            return payload['params']['oauth_consumer_key']
        if 'headers' in payload and 'Authorization' in payload['headers'] \
           and 'oauth_consumer_key' in payload['headers']['Authorization']:
            return payload['headers']['Authorization']['oauth_consumer_key']
        return None

    def oauth_signed_payload(self, consumer, payload):
        """
        Adds oAuth parameters to Authorization headers including a signature
        as per oAuth standards
        """
        if 'headers' not in payload:
            payload['headers'] = {}
        if 'Authorization' not in payload['headers']:
            payload['headers']['Authorization'] = {}
        payload['headers']['Authorization']['oauth_consumer_key'] = \
                                                            consumer.key
        payload['headers']['Authorization']['oauth_nonce'] = random_string()
        payload['headers']['Authorization']['oauth_timestamp'] = int(time())
        payload['headers']['Authorization']['oauth_signature_method'] = \
                                                            OAUTH_SIG_METHOD
        payload['headers']['Authorization']['oauth_version'] = OAUTH_VERSION
        payload['headers']['Authorization']['oauth_signature'] = \
                            self.generate_oauth_signature(consumer, payload)

        return payload

    #
    # pylint:disable=R0201
    # self isn't used YET
    #
    def oauth_n_url_str(self, url):
        """
        Normalizes a url to oAuth standards
        """
        parts = urlparse(url)
        url_str = '%s://%s%s' % (parts[0], parts[1], parts[2])
        return url_str

    def oauth_n_params_str(self, params):
        """
        Creates an oAuth standards compliant normalized parameters string
        """
        try:
            # exclude the signature if it exists
            del params['oauth_signature']
        except KeyError:
            pass
        key_values = params.items()
        # sort keys first
        key_values.sort()
        # combine key value pairs in string and escape
        sorted_params = []
        for key, value in key_values:
            if not isinstance(value, list):
                value = [value]
            # sort values for the same key
            value.sort()
            for value_item in value:
                sorted_params.append(
                    "%s=%s" % (self.escape(str(key)),
                               self.escape(str(value_item)))
                )

        return '&'.join(sorted_params)

    def remove_auth_params(self, params):
        """
        Returns a new params dict with all oAuth parameters removed
        """
        clean_params = deepcopy(params)
        for auth_param in OAUTH_PARAMS:
            if auth_param in clean_params:
                del(clean_params[auth_param])
        return clean_params
