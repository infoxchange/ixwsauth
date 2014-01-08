"""
Module for backward compatibility with existing imports.
"""

from warnings import warn

warn("ixwsauth_server.middleware.oauth is deprecated; "
     "use ixwsauth_server.middleware directly.",
     DeprecationWarning)

# pylint:disable=unused-wildcard-import
from ixwsauth_server.middleware import *
