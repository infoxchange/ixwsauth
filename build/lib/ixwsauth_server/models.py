"""
Model mixins for authorization.
"""

import random

from django.db import models


def random_key(length):
    """
    Generate a 'random' key of length 'length'

    We are using pseudorandom since we are not a bank.
    """

    key = ''
    for _ in range(length):
        key += random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ')

    return key


def random_consumer_key():
    """
    A random key for consumer.
    """

    return random_key(32)


class Consumer(models.Model):
    """
    An API consumer.
    """

    class Meta(object):
        abstract = True

    key = models.CharField(max_length=32, default=random_consumer_key,
                           unique=True)
    secret = models.CharField(max_length=32, default=random_consumer_key)

    def __unicode__(self):
        return self.key
