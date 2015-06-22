"""
Tastypie API authentication handlers.
"""

from __future__ import (absolute_import, division,
                        print_function, unicode_literals)
from future.builtins import *

from tastypie.authentication import Authentication
from tastypie.http import HttpUnauthorized


class ApplicationAuthentication(Authentication):
    """
    Authenticate the API request by checking the application key.
    """

    realm = 'tastypie'

    def is_authenticated(self, request, **kwargs):
        """
        Check that the request is signed by the application.
        """
        consumer = getattr(request, 'consumer', None)
        if consumer is None:
            response = HttpUnauthorized()
            response['WWW-Authenticate'] = 'Basic Realm="%s"' % self.realm
            return response
        else:
            return True

    def get_identifier(self, request):
        """
        Return a combination of the consumer, the IP address and the host
        """

        consumer = getattr(request, 'consumer', None)
        return '%s_%s' % (
            consumer.key(),
            super(ApplicationAuthentication, self).get_identifier(request))
