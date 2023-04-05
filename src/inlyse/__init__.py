__version__ = "1.0.0"  # semantic-release

# Set default logging handler to avoid "No handler found" warnings.
import logging
from logging import NullHandler

from .cli import WebClient

logging.getLogger(__name__).addHandler(NullHandler())

__all__ = ["WebClient"]
