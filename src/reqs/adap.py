import os
import typing
import warnings
import socket  # noqa: F401

from urllib3.poolmanager import PoolManager, proxy_from_url
from urllib3.util import Timeout as Urllib3Timeout, parse_url, Retry
from urllib3.exceptions import (
    ClosedPoolError,
    ConnectTimeoutError,
    HTTPError as Urllib3HTTPError,
    InvalidHeader as Urllib3InvalidHeader,
    LocationValueError,
    MaxRetryError,
    NewConnectionError,
    ProtocolError,
    ProxyError as Urllib3ProxyError,
    ReadTimeoutError,
    ResponseError,
    SSLError as Urllib3SSLError,
)

from .auth import _basic_auth_str
from .compat import basestring, urlparse
from .cookies import extract_cookies_to_jar
from .exceptions import (
    ConnectionError,
    ConnectTimeout,
    InvalidHeader,
    InvalidProxyURL,
    InvalidSchema,
    InvalidURL,
    ProxyError,
    ReadTimeout,
    RetryError,
    SSLError,
)
from .models import Response
from .structures import CaseInsensitiveDict
from .utils import (
    DEFAULT_CA_BUNDLE_PATH,
    extract_zipped_paths,
    get_auth_from_url,
    get_encoding_from_headers,
    prepend_scheme_if_needed,
    select_proxy,
    urldefragauth,
)

# SOCKS support
try:
    from urllib3.contrib.socks import SOCKSProxyManager
except ImportError:
    def SOCKSProxyManager(*args, **kwargs):
        raise InvalidSchema("SOCKS support requires extra dependencies.")

if typing.TYPE_CHECKING:
    from .models import PreparedRequest


# Default adapter settings
DEFAULT_POOLSIZE = 10
DEFAULT_RETRIES = 0
DEFAULT_POOLBLOCK = False
DEFAULT_POOL_TIMEOUT = None


def _urllib3_request_context(request, verify, client_cert, poolmanager):
    """
    Build connection context (host params + SSL params) for urllib3.
    """
    parsed_url = urlparse(request.url)
    host_params = {
        "scheme": parsed_url.scheme.lower(),
        "host": parsed_url.hostname,
        "port": parsed_url.port,
    }

    pool_kwargs = {"cert_reqs": "CERT_REQUIRED"}

    if verify is False:
        pool_kwargs["cert_reqs"] = "CERT_NONE"
    elif isinstance(verify, str):
        if os.path.isdir(verify):
            pool_kwargs["ca_cert_dir"] = verify
        else:
            pool_kwargs["ca_certs"] = verify

    if client_cert:
        if isinstance(client_cert, tuple) and len(client_cert) == 2:
            pool_kwargs.update(cert_file=client_cert[0], key_file=client_cert[1])
        else:
            pool_kwargs["cert_file"] = client_cert

    return host_params, pool_kwargs


class BaseAdapter:
    """Abstract transport adapter."""

    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        raise NotImplementedError

    def close(self):
        raise NotImplementedError


class HTTPAdapter(BaseAdapter):
    """
    Default HTTP/HTTPS adapter backed by urllib3’s connection pooling.
    """

    __attrs__ = ["max_retries", "config", "_pool_connections", "_pool_maxsize", "_pool_block"]

    def __init__(self, pool_connections=DEFAULT_POOLSIZE, pool_maxsize=DEFAULT_POOLSIZE,
                 max_retries=DEFAULT_RETRIES, pool_block=DEFAULT_POOLBLOCK):
        self.max_retries = Retry(0, read=False) if max_retries == DEFAULT_RETRIES else Retry.from_int(max_retries)
        self.config = {}
        self.proxy_manager = {}

        super().__init__()

        self._pool_connections = pool_connections
        self._pool_maxsize = pool_maxsize
        self._pool_block = pool_block
        self.init_poolmanager(pool_connections, pool_maxsize, block=pool_block)

    # Pickle support
    def __getstate__(self):
        return {attr: getattr(self, attr, None) for attr in self.__attrs__}

    def __setstate__(self, state):
        self.proxy_manager, self.config = {}, {}
        for attr, value in state.items():
            setattr(self, attr, value)
        self.init_poolmanager(self._pool_connections, self._pool_maxsize, block=self._pool_block)

    def init_poolmanager(self, connections, maxsize, block=DEFAULT_POOLBLOCK, **pool_kwargs):
        """Create urllib3 PoolManager."""
        self._pool_connections, self._pool_maxsize, self._pool_block = connections, maxsize, block
        self.poolmanager = PoolManager(num_pools=connections, maxsize=maxsize, block=block, **pool_kwargs)

    def proxy_manager_for(self, proxy, **proxy_kwargs):
        """Get or create ProxyManager for given proxy URL."""
        if proxy in self.proxy_manager:
            return self.proxy_manager[proxy]

        if proxy.lower().startswith("socks"):
            username, password = get_auth_from_url(proxy)
            manager = SOCKSProxyManager(
                proxy, username=username, password=password,
                num_pools=self._pool_connections, maxsize=self._pool_maxsize,
                block=self._pool_block, **proxy_kwargs
            )
        else:
            manager = proxy_from_url(
                proxy, proxy_headers=self.proxy_headers(proxy),
                num_pools=self._pool_connections, maxsize=self._pool_maxsize,
                block=self._pool_block, **proxy_kwargs
            )

        self.proxy_manager[proxy] = manager
        return manager

    def cert_verify(self, conn, url, verify, cert):
        """Configure TLS verification & certificates."""
        if url.lower().startswith("https") and verify:
            cert_loc = verify if verify is not True else extract_zipped_paths(DEFAULT_CA_BUNDLE_PATH)
            if not cert_loc or not os.path.exists(cert_loc):
                raise OSError(f"Invalid CA bundle path: {cert_loc}")
            conn.cert_reqs = "CERT_REQUIRED"
            conn.ca_certs, conn.ca_cert_dir = (cert_loc, None) if not os.path.isdir(cert_loc) else (None, cert_loc)
        else:
            conn.cert_reqs, conn.ca_certs, conn.ca_cert_dir = "CERT_NONE", None, None

        if cert:
            if isinstance(cert, basestring):
                conn.cert_file, conn.key_file = cert, None
            else:
                conn.cert_file, conn.key_file = cert
            if conn.cert_file and not os.path.exists(conn.cert_file):
                raise OSError(f"Invalid TLS certificate file: {conn.cert_file}")
            if conn.key_file and not os.path.exists(conn.key_file):
                raise OSError(f"Invalid TLS key file: {conn.key_file}")

    def build_response(self, req, resp):
        """Wrap urllib3 response into Requests Response."""
        response = Response()
        response.status_code = getattr(resp, "status", None)
        response.headers = CaseInsensitiveDict(getattr(resp, "headers", {}))
        response.encoding = get_encoding_from_headers(response.headers)
        response.raw, response.reason = resp, resp.reason
        response.url = req.url.decode("utf-8") if isinstance(req.url, bytes) else req.url
        extract_cookies_to_jar(response.cookies, req, resp)
        response.request, response.connection = req, self
        return response

    def get_connection_with_tls_context(self, request, verify, proxies=None, cert=None):
        """Return urllib3 connection with TLS settings applied."""
        proxy = select_proxy(request.url, proxies)
        host_params, pool_kwargs = _urllib3_request_context(request, verify, cert, self.poolmanager)

        if proxy:
            proxy = prepend_scheme_if_needed(proxy, "http")
            proxy_url = parse_url(proxy)
            if not proxy_url.host:
                raise InvalidProxyURL("Malformed proxy URL (missing host).")
            return self.proxy_manager_for(proxy).connection_from_host(**host_params, pool_kwargs=pool_kwargs)

        return self.poolmanager.connection_from_host(**host_params, pool_kwargs=pool_kwargs)

    def request_url(self, request, proxies):
        """Return correct URL (full if proxied, path otherwise)."""
        proxy = select_proxy(request.url, proxies)
        scheme = urlparse(request.url).scheme
        using_proxy = proxy and scheme != "https"
        socks = proxy and urlparse(proxy).scheme.lower().startswith("socks")
        url = f"/{request.path_url.lstrip('/')}" if request.path_url.startswith("//") else request.path_url
        return urldefragauth(request.url) if using_proxy and not socks else url

    def proxy_headers(self, proxy):
        """Return headers required for proxy auth."""
        headers = {}
        username, password = get_auth_from_url(proxy)
        if username:
            headers["Proxy-Authorization"] = _basic_auth_str(username, password)
        return headers

    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        """Send PreparedRequest and return Response."""
        try:
            conn = self.get_connection_with_tls_context(request, verify, proxies=proxies, cert=cert)
        except LocationValueError as e:
            raise InvalidURL(e, request=request)

        self.cert_verify(conn, request.url, verify, cert)
        url = self.request_url(request, proxies)
        self.add_headers(request, stream=stream, timeout=timeout, verify=verify, cert=cert, proxies=proxies)

        chunked = request.body is not None and "Content-Length" not in request.headers

        if isinstance(timeout, tuple):
            connect, read = timeout
            timeout = Urllib3Timeout(connect=connect, read=read)
        elif not isinstance(timeout, Urllib3Timeout):
            timeout = Urllib3Timeout(connect=timeout, read=timeout)

        try:
            resp = conn.urlopen(
                method=request.method, url=url, body=request.body,
                headers=request.headers, redirect=False, assert_same_host=False,
                preload_content=False, decode_content=False,
                retries=self.max_retries, timeout=timeout, chunked=chunked,
            )
        except (ProtocolError, OSError) as e:
            raise ConnectionError(e, request=request)
        except MaxRetryError as e:
            if isinstance(e.reason, ConnectTimeoutError) and not isinstance(e.reason, NewConnectionError):
                raise ConnectTimeout(e, request=request)
            if isinstance(e.reason, ResponseError):
                raise RetryError(e, request=request)
            if isinstance(e.reason, Urllib3ProxyError):
                raise ProxyError(e, request=request)
            if isinstance(e.reason, Urllib3SSLError):
                raise SSLError(e, request=request)
            raise ConnectionError(e, request=request)
        except ClosedPoolError as e:
            raise ConnectionError(e, request=request)
        except Urllib3ProxyError as e:
            raise ProxyError(e)
        except (Urllib3SSLError, Urllib3HTTPError) as e:
            if isinstance(e, Urllib3SSLError):
                raise SSLError(e, request=request)
            if isinstance(e, ReadTimeoutError):
                raise ReadTimeout(e, request=request)
            if isinstance(e, Urllib3InvalidHeader):
                raise InvalidHeader(e, request=request)
            raise
        return self.build_response(request, resp)
