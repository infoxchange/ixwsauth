"""
Classes and functions to work with OAuth-like signatures.
"""

from django.http import HttpResponseForbidden

from functools import wraps

from ixdjango.utils import flat_auth_header_val_to_data
from ixwsauth.auth import AuthManager

from ixlogin.models import Website


class CheckSignatureMiddleware(object):
    """
    A middleware to check requests' OAuth-like signatures.
    """

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

        consumer = self.get_consumer(key)
        if not consumer:
            return

        signature = auth.oauth_signature_from_payload(payload)
        if not signature:
            return

        valid_sig = auth.generate_oauth_signature(consumer, payload)
        if signature != valid_sig:
            return

        request.consumer = consumer.consumer

    @staticmethod
    def get_consumer(key):
        """
        The consumer corresponding to the signing key.
        """

        class Consumer(object):
            """
            Consumer class to supply to AuthManager
            """

            def __init__(self, consumer):
                self.consumer = consumer

            def key(self):
                """
                Consumer key for OAuth signature
                """
                return self.consumer.abbr

            def secret(self):
                """
                Consumer secret for OAuth signature
                """
                return self.consumer.secret

        try:
            website = Website.objects.get(abbr=key)
            return Consumer(website)
        except Website.DoesNotExist:
            return None


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
