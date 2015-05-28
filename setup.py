"""
Package configuration
"""
# pylint:disable=no-name-in-module, import-error
from distutils.core import setup
from setuptools import find_packages

setup(
    name='IXWSAuth',
    version='0.1.1',
    author='Infoxchanhe Australia dev team',
    author_email='devs@infoxchange.net.au',
    packages=find_packages(),
    url='http://pypi.python.org/pypi/IXWSAuth/',
    license='MIT',
    description='Authentication libraries for IX web services',
    long_description=open('README').read(),
    install_requires=(
        'Django >= 1.4.0',
        'django-tastypie',
        'IXDjango >= 0.1.1',
    ),
    tests_require=(
        'aloe',
        'mock',
        'pep8',
        'pylint',
        'pylint-mccabe',
    )
)
