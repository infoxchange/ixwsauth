"""
Configures test suite for the package
"""
from django.utils import unittest

from ixwsauth.test_suite.auth import (
    WebServicesConsumerTests, AuthManagerTests
)


def suite():
    """
    Put together a suite of tests to run for the application
    """
    loader = unittest.TestLoader()

    all_tests = unittest.TestSuite([
        #
        # WebServicesConsumer class test cases
        #
        loader.loadTestsFromTestCase(WebServicesConsumerTests),
        #
        # Authmanager class test cases
        #
        loader.loadTestsFromTestCase(AuthManagerTests)
    ])

    return all_tests
