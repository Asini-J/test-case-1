import calendar
import copy
import time
import threading
from collections.abc import MutableMapping
from http.cookies import Morsel
from urllib.parse import urlparse, urlunparse
from http import cookiejar as cookielib

from .internal_utils import to_native_string


class MockRequest:
    """Mimic urllib2.Request for http.cookiejar compatibility."""

    def __init__(self, request):
        self._r = request
        self._new_headers = {}
        self.type = urlparse(self._r.url).scheme

    def get_type(self): return self.type
    def get_host(self): return urlparse(self._r.url).netloc
    def get_origin_req_host(self): return self.get_host()

    def get_full_url(self):
        if not self._r.headers.get("Host"):
            return self._r.url
        host = to_native_string(self._r.headers["Host"], encoding="utf-8")
        parsed = urlparse(self._r.url)
        return urlunparse([parsed.scheme, host, parsed.path,
                           parsed.params, parsed.query, parsed.fragment])

    def is_unverifiable(self): return True
    def has_header(self, name): return name in self._r.headers or name in self._new_headers
    def get_header(self, name, default=None): return self._r.headers.get(name, self._new_headers.get(name, default))
    def add_header(self, key, val): raise NotImplementedError("Use add_unredirected_header() for cookies.")
    def add_unredirected_header(self, name, value): self._new_headers[name] = value
    def get_new_headers(self): return self._new_headers

    # CookieJar compatibility
    @property
    def unverifiable(self): return self.is_unverifiable()
    @property
    def origin_req_host(self): return self.get_origin_req_host()
    @property
    def host(self): return self.get_host()


class MockResponse:
    """Expose HTTP headers the way http.cookiejar expects."""

    def __init__(self, headers): self._headers = headers
    def info(self): return self._headers
    def getheaders(self, name): return self._headers.getheaders(name)


def extract_cookies_to_jar(jar, request, response):
    """Extract cookies from HTTP response into CookieJar."""
    if not (hasattr(response, "_original_response") and response._original_response):
        return
    req = MockRequest(request)
    res = MockResponse(response._original_response.msg)
    jar.extract_cookies(res, req)


def get_cookie_header(jar, request):
    """Return Cookie header string for request, or None."""
    r = MockRequest(request)
    jar.add_cookie_header(r)
    return r.get_new_headers().get("Cookie")


def remove_cookie_by_name(cookiejar, name, domain=None, path=None):
    """Remove cookie(s) by name (optionally filter by domain & path)."""
    clearables = [
        (c.domain, c.path, c.name)
        for c in cookiejar
        if c.name == name and (domain is None or domain == c.domain) and (path is None or path == c.path)
    ]
    for domain, path, name in clearables:
        cookiejar.clear(domain, path, name)


class CookieConflictError(RuntimeError):
    """Raised when multiple cookies match the given lookup criteria."""


class RequestsCookieJar(cookielib.CookieJar, MutableMapping):
    """A CookieJar with dict-like interface (compatible with requests)."""

    def get(self, name, default=None, domain=None, path=None):
        try:
            return self._find_no_duplicates(name, domain, path)
        except KeyError:
            return default

    def set(self, name, value, **kwargs):
        if value is None:
            remove_cookie_by_name(self, name, kwargs.get("domain"), kwargs.get("path"))
            return
        cookie = morsel_to_cookie(value) if isinstance(value, Morsel) else create_cookie(name, value, **kwargs)
        self.set_cookie(cookie)
        return cookie

    def keys(self): return [c.name for c in self]
    def values(self): return [c.value for c in self]
    def items(self): return [(c.name, c.value) for c in self]
    def __iter__(self): return (c.name for c in self)
    def __len__(self): return len(list(iter(self)))

    def list_domains(self): return list({c.domain for c in self if c.domain})
    def list_paths(self): return list({c.path for c in self if c.path})
    def multiple_domains(self): return len(self.list_domains()) > 1

    def get_dict(self, domain=None, path=None):
        return {
            c.name: c.value
            for c in self
            if (domain is None or c.domain == domain) and (path is None or c.path == path)
        }

    def __contains__(self, name):
        try:
            return super().__contains__(name)
        except CookieConflictError:
            return True

    def __getitem__(self, name): return self._find_no_duplicates(name)
    def __setitem__(self, name, value): self.set(name, value)
    def __delitem__(self, name): remove_cookie_by_name(self, name)

    def set_cookie(self, cookie, *args, **kwargs):
        if isinstance(cookie.value, str) and cookie.value.startswith('"') and cookie.value.endswith('"'):
            cookie.value = cookie.value.replace('\\"', "")
        return super().set_cookie(cookie, *args, **kwargs)

    def update(self, other):
        if isinstance(other, cookielib.CookieJar):
            for cookie in other:
                self.set_cookie(copy.copy(cookie))
        else:
            super().update(other)

    def _find(self, name, domain=None, path=None):
        for c in self:
            if c.name == name and (domain is None or c.domain == domain) and (path is None or c.path == path):
                return c.value
        raise KeyError(f"name={name!r}, domain={domain!r}, path={path!r}")

    def _find_no_duplicates(self, name, domain=None, path=None):
        result = None
        for c in self:
            if c.name == name and (domain is None or c.domain == domain) and (path is None or c.path == path):
                if result is not None:
                    raise CookieConflictError(f"Multiple cookies found for {name!r}")
                result = c.value
        if result is not None:
            return result
        raise KeyError(f"name={name!r}, domain={domain!r}, path={path!r}")

    def __getstate__(self):
        state = self.__dict__.copy()
        state.pop("_cookies_lock", None)
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)
        if "_cookies_lock" not in self.__dict__:
            self._cookies_lock = threading.RLock()

    def copy(self):
        new_cj = RequestsCookieJar()
        new_cj.set_policy(self.get_policy())
        new_cj.update(self)
        return new_cj

    def get_policy(self): return self._policy


def _copy_cookie_jar(jar):
    if jar is None: return None
    if hasattr(jar, "copy"): return jar.copy()
    new_jar = copy.copy(jar)
    new_jar.clear()
    for c in jar:
        new_jar.set_cookie(copy.copy(c))
    return new_jar


def create_cookie(name, value, **kwargs):
    """Create a new cookie with sensible defaults."""
    defaults = {
        "version": 0, "name": name, "value": value, "port": None,
        "domain": "", "path": "/", "secure": False, "expires": None,
        "discard": True, "comment": None, "comment_url": None,
        "rest": {"HttpOnly": None}, "rfc2109": False,
    }
    badargs = set(kwargs) - set(defaults)
    if badargs:
        raise TypeError(f"Unexpected arguments: {badargs}")
    defaults.update(kwargs)
    defaults["port_specified"] = bool(defaults["port"])
    defaults["domain_specified"] = bool(defaults["domain"])
    defaults["domain_initial_dot"] = defaults["domain"].startswith(".")
    defaults["path_specified"] = bool(defaults["path"])
    return cookielib.Cookie(**defaults)


def morsel_to_cookie(morsel: Morsel):
    """Convert a http.cookies.Morsel to a Cookie object."""
    expires = None
    if morsel["max-age"]:
        try:
            expires = int(time.time() + int(morsel["max-age"]))
        except ValueError:
            raise TypeError(f"Invalid max-age: {morsel['max-age']!r}")
    elif morsel["expires"]:
        time_template = "%a, %d-%b-%Y %H:%M:%S GMT"
        expires = calendar.timegm(time.strptime(morsel["expires"], time_template))
    return create_cookie(
        name=morsel.key, value=morsel.value, version=morsel["version"] or 0,
        domain=morsel["domain"], path=morsel["path"], secure=bool(morsel["secure"]),
        expires=expires, comment=morsel["comment"], comment_url=bool(morsel["comment"]),
        discard=False, rest={"HttpOnly": morsel["httponly"]}, port=None, rfc2109=False,
    )


def cookiejar_from_dict(cookie_dict, cookiejar=None, overwrite=True):
    """Build CookieJar from dict."""
    cookiejar = cookiejar or RequestsCookieJar()
    if cookie_dict:
        existing = {c.name for c in cookiejar}
        for name, value in cookie_dict.items():
            if overwrite or name not in existing:
                cookiejar.set_cookie(create_cookie(name, value))
    return cookiejar


def merge_cookies(cookiejar, cookies):
    """Merge dict or CookieJar into another CookieJar."""
    if not isinstance(cookiejar, cookielib.CookieJar):
        raise ValueError("You can only merge into CookieJar")

    if isinstance(cookies, dict):
        return cookiejar_from_dict(cookies, cookiejar, overwrite=False)
    if isinstance(cookies, cookielib.CookieJar):
        try:
            cookiejar.update(cookies)
        except AttributeError:
            for c in cookies:
                cookiejar.set_cookie(c)
    return cookiejar
