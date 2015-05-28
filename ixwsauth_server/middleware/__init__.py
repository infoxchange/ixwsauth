"""
Classes and functions to manage Web services authentication
"""

import base64

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.core.cache import cache
from django.http import HttpResponseForbidden
from django.utils.crypto import constant_time_compare
from django.utils.importlib import import_module

from functools import wraps


def import_by_path(dotted_path):
    """
    Reimplement this from django dev, can be replaced in Django 1.6

    Not as resiliant as the real version.
    """

    module_path, class_name = dotted_path.rsplit('.', 1)
    module = import_module(module_path)
    return getattr(module, class_name)


class Consumer(object):
    """
    Consumer class to supply to signature checking routines
    """

    def __init__(self, key=None, secret=None, obj=None):
        self._key = key
        self._secret = secret
        self._object = obj

    def key(self):
        """
        Return the consumer key
        """

        return self._key

    def secret(self):
        """
        Return the consumer secret
        """

        return self._secret


class ConsumerStore(object):
    """
    A default, database-backed store for looking up consumers by their API
    key.
    """

    consumer_class_key = 'key'
    consumer_class_secret = 'secret'

    @staticmethod
    def get_consumer_store():
        """
        Return the configured consumer store (not a singleton)
        """

        try:
            consumer_store_class = \
                import_by_path(settings.CONSUMER_STORE_CLASS)
        except AttributeError:
            raise ImproperlyConfigured(
                "Using CheckSignatureMiddleware requires "
                "settings.CONSUMER_STORE_CLASS")

        return consumer_store_class()

    @property
    def consumer_class(self):
        """
        The consumer class is a model in your database.

        The class must have a DB attribute suitable for use with a
        QuerySet.get() call, by default this is 'key' but can be overridden by
        defining consumer_class_key.

        The secret for the consumer is stored in the attribute 'secret' but
        can be overridden by defining consumer_class_secret.
        """

        raise ImproperlyConfigured("You must defined consumer_class")

    def get_consumer(self, key):
        """
        Retrieve the consumer from the store.
        """
        cache_key = 'consumer-%s' % key

        try:
            consumer = cache.get(cache_key)

            if isinstance(consumer, self.consumer_class.DoesNotExist):
                return None
            elif consumer is not None:
                return consumer

            obj = self.consumer_class.objects.get(
                **{self.consumer_class_key: key})

            consumer = Consumer(
                key=key,
                secret=getattr(obj, self.consumer_class_secret),
                obj=obj)

            cache.set(cache_key, consumer)
            return consumer

        except self.consumer_class.DoesNotExist as ex:

            cache.set(cache_key, ex)
            return None


class CheckSignatureMiddleware(object):
    """
    A middleware to check HTTP Basic and key parameter authentication.
    """

    def __init__(self):
        self.consumer_store = ConsumerStore.get_consumer_store()

    @staticmethod
    def get_basic_auth_headers(request):
        """
        Get HTTP Basic username and password from the request, if present.
        """

        try:
            (auth_type, data) = request.META['HTTP_AUTHORIZATION'].split()

            if auth_type.lower() != 'basic':
                return None

            bits = base64.b64decode(data).decode('utf-8')
            (user, password) = bits.split(':')
            return (user, password)
        except:  # pylint:disable=bare-except
            return None

    def verify_consumer(self, key, secret):
        """
        Given a key,secret pair, either returns the asociated consumer,
        or return none.
        """

        consumer = self.consumer_store.get_consumer(key)
        if not consumer:
            return None

        if not constant_time_compare(consumer.secret(), secret):
            return None

        return consumer

    def http_basic_consumer(self, request):
        """
        If the request has a valid HTTP Basic authentication, return the
        associated consumer; None otherwise.
        """

        http_basic = self.get_basic_auth_headers(request)
        if not http_basic:
            return None

        (key, secret) = http_basic  # pylint:disable=unpacking-non-sequence

        return self.verify_consumer(key, secret)

    def key_parameter_consumer(self, request):
        """
        If the request has a parameter named 'key', which consists of valid
        consumer credentials, the associated consumer will be returned;
        otherwise None.
        """

        try:
            (key, secret) = request.GET.get('key').split(':')
        except (AttributeError, ValueError):
            key = secret = None

        if not key and not secret:
            return None

        return self.verify_consumer(key, secret)

    def process_request(self, request):
        """
        Check HTTP Basic and key parameter authentication.
        """
        methods = (
            self.http_basic_consumer,
            self.key_parameter_consumer,
        )

        for method in methods:
            consumer = method(request)
            if consumer:
                request.consumer = consumer
                return


def consumer_required(view):
    """
    Decorator for views that checks that the request has a valid signature, and
    responds with Forbidden otherwise.
    """
    @wraps(view)
    # pylint:disable=C0111
    # Missing docstring
    def wrapper(request, *args, **kwargs):
        consumer = getattr(request, 'consumer', None)
        if consumer is None:
            return HttpResponseForbidden()
        return view(request, *args, **kwargs)
    return wrapper
