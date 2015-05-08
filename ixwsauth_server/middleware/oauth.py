"""
Module for backward compatibility with existing imports.
"""

from warnings import warn

# pylint:disable=unused-wildcard-import
from ixwsauth_server.middleware import *

warn("ixwsauth_server.middleware.oauth is deprecated; "
     "use ixwsauth_server.middleware directly.",
     DeprecationWarning)
