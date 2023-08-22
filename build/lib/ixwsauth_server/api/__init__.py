"""
Common package for Tastypie and DRF authentication
"""

from __future__ import absolute_import

try:
    from .tastypie import ApplicationAuthentication
except ImportError:
    pass
