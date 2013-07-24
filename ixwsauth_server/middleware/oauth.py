"""
Classes and functions to work with OAuth-like signatures.
"""

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponseForbidden
from django.utils.importlib import import_module

from functools import wraps

from ixdjango.utils import flat_auth_header_val_to_data
from ixwsauth.auth import AuthManager


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
    Consumer class to supply to AuthManager
    """

    def __init__(self, key=None, secret=None, obj=None):
        self.key = key
        self.secret = secret


class ConsumerStore(object):
    """
    A default, database-backed store for looking up consumers by their API
    key.
    """

    consumer_class_key = 'key'
    consumer_class_secret = 'secret'

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

        try:
            obj = self.consumer_class.objects.get(
                **{self.consumer_class_key: key})
            return Consumer(key=key,
                            secret=getattr(obj, self.consumer_class_secret),
                            obj=obj)
        except self.consumer_class.DoesNotExist:
            return None


class CheckSignatureMiddleware(object):
    """
    A middleware to check requests' OAuth-like signatures.
    """

    def __init__(self):
        try:
            consumer_store_class = \
                import_by_path(settings.CONSUMER_STORE_CLASS)
        except AttributeError:
            raise ImproperlyConfigured(
                "Using CheckSignatureMiddleware requires "
                "settings.CONSUMER_STORE_CLASS")

        self.consumer_store = consumer_store_class()

    @staticmethod
    def get_oauth_headers(request):
        """
        Get OAuth authorization headers from the request, if present.
        """
        if 'HTTP_AUTHORIZATION' in request.META:
            (authorization_headers, auth_type) = flat_auth_header_val_to_data(
                request.META['HTTP_AUTHORIZATION']
            )

            if auth_type == 'OAuth':
                return authorization_headers

        return None

    def process_request(self, request):
        """
        Check the request's OAuth-like signature and, if one exists, add a
        'consumer' property onto it
        """

        auth = AuthManager()

        authorization_headers = self.get_oauth_headers(request)
        if authorization_headers is None:
            return

        url = auth.oauth_n_url_str(request.build_absolute_uri())

        params = request.GET if request.method == 'GET' else {}

        payload = {
            'method': request.method,
            'url': url,
            'params': params,
            'headers': {
                'Authorization': authorization_headers
            }
        }

        key = auth.consumer_key_from_payload(payload)
        if not key:
            return

        consumer = self.consumer_store.get_consumer(key)
        if not consumer:
            return

        signature = auth.oauth_signature_from_payload(payload)
        if not signature:
            return

        valid_sig = auth.generate_oauth_signature(consumer, payload)
        if signature != valid_sig:
            return

        request.consumer = consumer


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
