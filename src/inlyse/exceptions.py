"""Module for all exceptions
"""


class InlyseApiError(Exception):
    """The INLYSE API returned an error"""

    def __init__(self, *args, **kwargs):
        self.response = kwargs.pop("response", None)


class RateLimitExceeded(Exception):
    """The rate limit for this license key exceeded"""

    pass


class MaxRetriesExceeded(Exception):
    """The maximal retries exceeded"""

    pass
