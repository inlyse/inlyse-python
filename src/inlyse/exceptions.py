"""Module for all exceptions"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any


class InlyseApiError(Exception):
    """The INLYSE API returned an error"""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.response = kwargs.pop("response", None)


class RateLimitExceeded(Exception):
    """The rate limit for this license key exceeded"""

    pass


class MaxRetriesExceeded(Exception):
    """The maximal retries exceeded"""

    pass
