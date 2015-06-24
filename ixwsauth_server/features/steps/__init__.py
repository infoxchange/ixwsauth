"""
Steps for testing authentication
"""

from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from future.builtins import *

import base64

from django.test.client import Client

try:
    from aloe import before, step, world
except ImportError:
    from lettuce import before, step, world

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


class BasicAuthClient(ApplicationClient):
    """
    A Django test client which authenticates request using HTTP Basic auth
    and a consumer from the consumer store.
    """

    def authorisation(self, request):
        """
        The HTTP Basic authorisation to add to the request.
        """

        auth = '{key}:{secret}'.format(key=self._key, secret=self._secret)

        # The authentication string is base64-encoded (as bytes), then the
        # result is decoded for inclusion in an HTTP header (which must be a
        # string).
        base64string = base64.encodestring(auth.encode()).decode()\
            .replace('\n', '')

        return 'Basic ' + base64string


class KeyParameterClient(ApplicationClient):
    """
    A Django test client which authenticates request using a 'key' parameter
    and a consumer from the consumer store.
    """

    def authorisation(self, request):
        """
        Adds the key,secret pair to the request.
        """

        request.GET['key'] = '{key}:{secret}'.format(
            key=self._key,
            secret=self._secret,
        )


# each_example is not available in Lettuce master
# pylint:disable=invalid-name,maybe-no-member
try:
    before_example = before.each_example
except AttributeError:
    before_example = before.each_scenario
# pylint:enable=invalid-name,maybe-no-member


@before_example
def set_default_client(scenario, outline, steps):
    """
    Set a default client that does not have authentication
    """

    world.client = Client()


@step(r'I authenticate to the API with key "([^\"]*)"$')
@step(r'I authenticate to the API using HTTP Basic auth '
      r'with key "([^\"]*)"$')
def authenticate_application_basic(step_, key):
    """
    Authenticate as the application with given key and corresponding secret,
    using HTTP Basic.
    """

    world.client = BasicAuthClient(key=key)


@step(r'I authenticate to the API with key "([^"]*)" and secret "([^"]*)"$')
@step(r'I authenticate to the API using HTTP Basic auth '
      r'with key "([^\"]*)" and secret "([^\"]*)"')
def authenticate_with_secret_basic(step_, key, secret):
    """
    Authenticate to the application with the given key and secret,
    using HTTP Basic.
    """

    world.client = BasicAuthClient(key=key, secret=secret)


@step(r'I authenticate to the API using a key parameter '
      r'with key "([^"]*)" and secret "([^"]*)"')
def authenticate_with_key_parameter(step_, key, secret):
    """
    Authenticate to the application with the given key and secret,
    using a key parameter.
    """

    world.client = KeyParameterClient(key=key, secret=secret)
