"""
Steps for testing authentication
"""

import base64
from urlparse import parse_qs

from django.test.client import Client

from lettuce import before, step, world

from ixdjango.utils import flatten_auth_header
from ixwsauth import auth
from ixwsauth_server.middleware import ConsumerStore


class ApplicationClient(Client):
    """
    A Django test client authenticating using the consumer store.
    """

    consumer_store = ConsumerStore.get_consumer_store()

    def __init__(self, key, secret=None, **defaults):
        self._key = key

        if secret:
            self._secret = secret
        else:
            consumer = self.consumer_store.get_consumer(key)
            self._secret = consumer.secret()

        super(ApplicationClient, self).__init__(**defaults)

    def authorisation(self, request):
        """
        The HTTP Authorization header to add.
        """

        raise NotImplementedError("Must override authorisation().")

    def _base_environ(self, **request):
        """
        Add the HTTP Authorization header to the request.
        """

        environ = super(ApplicationClient, self)._base_environ(**request)

        environ['HTTP_AUTHORIZATION'] = self.authorisation(request)

        return environ


class OAuthClient(ApplicationClient):
    """
    A Django test Client which does IXA WS authentication using
    a consumer from the consumer store.
    """

    @property
    def key(self):
        """
        The API key
        """

        return self._key

    def secret(self):
        """
        The secret associated with the API key
        """

        return self._secret

    def authorisation(self, request):
        """
        The OAuth signature to add to the request.
        """

        auth_man = auth.AuthManager()

        method = request['REQUEST_METHOD']
        if method == 'GET':
            params = parse_qs(request['QUERY_STRING'])
        else:
            params = {}
        payload = {
            'method': method,
            'url': 'http://testserver' + request['PATH_INFO'],
            'params': params,
        }
        signed_payload = auth_man.oauth_signed_payload(self, payload)

        return flatten_auth_header(
            signed_payload['headers']['Authorization'],
            'OAuth'
        )


class BasicAuthClient(ApplicationClient):
    """
    A Django test client which authenticates request using HTTP Basic auth
    and a consumer from the consumer store.
    """

    def authorisation(self, request):
        """
        The HTTP Basic authorisation to add to the request.
        """

        base64string = (base64
                        .encodestring('{key}:{secret}'.format(
                            key=self._key,
                            secret=self._secret,
                        ))
                        .replace('\n', ''))

        return 'Basic {0}'.format(base64string)


@before.each_scenario  # pylint:disable=no-member
def set_default_client(scenario):
    """
    Set a default client that does not have authentication
    """

    world.client = Client()


@step(r'I authenticate to the API with key "([^\"]*)"$')
@step(r'I authenticate to the API using OAuth with key "([^\"]*)"$')
def authenticate_application(step_, key):
    """
    Authenticate as the application with given key and corresponding secret,
    using OAuth-like signature.
    """

    world.client = OAuthClient(key=key)


@step(r'I authenticate to the API with key "([^"]*)" and secret "([^"]*)"$')
@step(r'I authenticate to the API using OAuth '
      r'with key "([^"]*)" and secret "([^"]*)"')
def authenticate_with_secret(step_, key, secret):
    """
    Authenticate to the application with the given key and secret,
    using OAuth-like signature.
    """

    world.client = OAuthClient(key=key, secret=secret)


@step(r'I authenticate to the API using HTTP Basic auth '
      r'with key "([^\"]*)"$')
def authenticate_application_basic(step_, key):
    """
    Authenticate as the application with given key and corresponding secret,
    using HTTP Basic.
    """

    world.client = BasicAuthClient(key=key)


@step(r'I authenticate to the API using HTTP Basic auth '
      r'with key "([^\"]*)" and secret "([^\"]*)"')
def authenticate_with_secret_basic(step_, key, secret):
    """
    Authenticate to the application with the given key and secret,
    using HTTP Basic.
    """

    world.client = BasicAuthClient(key=key, secret=secret)
