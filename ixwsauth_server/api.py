"""
Tastypie API Authorization handlers
"""

from tastypie.authentication import Authentication
from tastypie.authorization import Authorization


class ApplicationAuthentication(Authentication):
    """
    Authenticate the API request by checking the application key.
    """
    def is_authenticated(self, request, **kwargs):
        """
        Check that the request is signed by the application.
        """
        consumer = getattr(request, 'consumer', None)
        return consumer is not None


class ApplicationAuthorization(Authorization):
    """
    Authorize the API request by checking the application key.
    """

    #
    # pylint:disable=W0613,W0622,R0201
    # Redefining built-in 'object'
    # Unused argument 'object'
    # Method could be a function
    #
    # Part of Tastypie API - cannot change any of the above
    #
    def is_authorized(self, request, object=None):
        """
        Check that the request is signed by the application.
        """
        consumer = getattr(request, 'consumer', None)
        return consumer is not None
