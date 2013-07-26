"""
Steps for testing authentication
"""

from django.test.client import Client

from lettuce import before, step, world

from ixdjango.utils import flatten_auth_header
from ixwsauth import auth
from ixwsauth_server.middleware.oauth import ConsumerStore


class ApplicationClient(Client):
    """
    A Django test Client which does IXA WS authentication using
    a consumer from the consumer store.
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

    def _base_environ(self, **request):
        """
        Sign the request with key/secret
        """

        environ = super(ApplicationClient, self)._base_environ(**request)

        auth_man = auth.AuthManager()

        method = request['REQUEST_METHOD']
        payload = {
            'method': method,
            'url': 'http://testserver' + request['PATH_INFO'],
            'params': {},
        }
        signed_payload = auth_man.oauth_signed_payload(self, payload)

        environ['HTTP_AUTHORIZATION'] = flatten_auth_header(
            signed_payload['headers']['Authorization'],
            'OAuth'
        )

        return environ


@before.each_scenario  # pylint:disable=no-member
def set_default_client(scenario):
    """
    Set a default client that does not have authentication
    """

    world.client = Client()


@step(r'I authenticate to the API with key "([^\"]*)"')
def authenticate_application(step_, key):
    """
    Authenticate as the application with given key
    """

    world.client = ApplicationClient(key=key)


@step(r'I authenticate to the API with key "([^"]*)" and secret "([^"]*)"')
def authenticate_with_secret(step_, key, secret):
    """
    Authenticate to the application with the given key and secret
    """

    world.client = ApplicationClient(key=key, secret=secret)