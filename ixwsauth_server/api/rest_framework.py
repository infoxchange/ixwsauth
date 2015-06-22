"""
Django REST Framework authentication handlers.
"""

from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from future.builtins import *

from rest_framework import (
    authentication,
    exceptions,
)


class ApplicationAuthentication(authentication.BaseAuthentication):
    """Authenticate against the API keys."""

    www_authenticate_realm = 'api'

    def authenticate(self, request):
        """
        Check that the request is signed by the application.
        """

        consumer = getattr(request, 'consumer', None)
        if consumer is None:
            raise exceptions.AuthenticationFailed("No valid API key.")

        # Make consumer look like a user for DRF
        consumer.is_authenticated = lambda: True

        return (consumer, None)

    def authenticate_header(self, request):
        return 'Basic realm="%s"' % self.www_authenticate_realm
