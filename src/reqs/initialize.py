import warnings
import urllib3
import logging
from logging import NullHandler

from .exceptions import RequestsDependencyWarning, (
    ConnectionError,
    ConnectTimeout,
    FileModeWarning,
    HTTPError,
    JSONDecodeError,
    ReadTimeout,
    RequestException,
    Timeout,
    TooManyRedirects,
    URLRequired,
)
from . import packages, utils
from .__version__ import (
    __author__,
    __author_email__,
    __build__,
    __cake__,
    __copyright__,
    __description__,
    __license__,
    __title__,
    __url__,
    __version__,
)
from .api import delete, get, head, options, patch, post, put, request
from .models import PreparedRequest, Request, Response
from .sessions import Session, session
from .status_codes import codes


# Attempt to load charset detection libraries
try:
    from charset_normalizer import __version__ as charset_normalizer_version
except ImportError:
    charset_normalizer_version = None

try:
    from chardet import __version__ as chardet_version
except ImportError:
    chardet_version = None


def validate_dependencies(urllib3_version, chardet_version, charset_normalizer_version):
    """Ensure urllib3, chardet, and charset_normalizer meet version requirements."""

    # Handle special dev builds like 'dev'
    parts = urllib3_version.split(".")
    assert parts != ["dev"]

    # Normalize version (e.g., 1.16
