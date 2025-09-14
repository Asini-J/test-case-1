import hashlib
import os
import re
import threading
import time
import warnings
from base64 import b64encode

from .internal_utils import to_native_string
from .compat import basestring, str, urlparse
from .cookies import extract_cookies_to_jar
from .utils import parse_dict_header


CONTENT_TYPE_FORM_URLENCODED = "application/x-www-form-urlencoded"
CONTENT_TYPE_MULTI_PART = "multipart/form-data"


def _basic_auth_str(username, password):
    """Return a Basic Auth header value for given username/password."""

    # 🔔 Backward compatibility: non-string inputs will break in Requests 3.0
    if not isinstance(username, basestring):
        warnings.warn(
            f"Non-string usernames will be unsupported in Requests 3.0.0. "
            f"Convert {username!r} to str/bytes.",
            DeprecationWarning,
        )
        username = str(username)

    if not isinstance(password, basestring):
        warnings.warn(
            f"Non-string passwords will be unsupported in Requests 3.0.0. "
            f"Convert {password!r} to str/bytes.",
            DeprecationWarning,
        )
        password = str(password)

    if isinstance(username, str):
        username = username.encode("latin1")
    if isinstance(password, str):
        password = password.encode("latin1")

    return "Basic " + to_native_string(
        b64encode(b":".join((username, password))).strip()
    )


class AuthBase:
    """Base class for all authentication handlers."""

    def __call__(self, r):
        raise NotImplementedError("Auth hooks must be callable.")


class HTTPBasicAuth(AuthBase):
    """Attach HTTP Basic Authentication to a request."""

    def __init__(self, username, password):
        self.username = username
        self.password = password

    def __eq__(self, other):
        return (
            self.username == getattr(other, "username", None)
            and self.password == getattr(other, "password", None)
        )

    def __call__(self, r):
        r.headers["Authorization"] = _basic_auth_str(self.username, self.password)
        return r


class HTTPProxyAuth(HTTPBasicAuth):
    """Attach HTTP Proxy Authentication to a request."""

    def __call__(self, r):
        r.headers["Proxy-Authorization"] = _basic_auth_str(self.username, self.password)
        return r


class HTTPDigestAuth(AuthBase):
    """Attach HTTP Digest Authentication to a request."""

    def __init__(self, username, password):
        self.username = username
        self.password = password
        self._thread_local = threading.local()

    def _init_thread_state(self):
        if not hasattr(self._thread_local, "init"):
            self._thread_local.init = True
            self._thread_local.last_nonce = ""
            self._thread_local.nonce_count = 0
            self._thread_local.chal = {}
            self._thread_local.pos = None
            self._thread_local.num_401_calls = 1

    def _get_hash_func(self, algorithm):
        """Return hash function based on algorithm name."""
        algo = (algorithm or "MD5").upper()
        mapping = {
            "MD5": hashlib.md5,
            "MD5-SESS": hashlib.md5,
            "SHA": hashlib.sha1,
            "SHA-256": hashlib.sha256,
            "SHA-512": hashlib.sha512,
        }

        if algo not in mapping:
            return None

        def hash_utf8(x):
            if isinstance(x, str):
                x = x.encode("utf-8")
            return mapping[algo](x).hexdigest()

        return hash_utf8

    def build_digest_header(self, method, url):
        chal = self._thread_local.chal
        realm, nonce = chal["realm"], chal["nonce"]
        qop, algorithm, opaque = chal.get("qop"), chal.get("algorithm"), chal.get("opaque")

        hash_utf8 = self._get_hash_func(algorithm)
        if not hash_utf8:
            return None

        KD = lambda s, d: hash_utf8(f"{s}:{d}")  # noqa: E731

        parsed = urlparse(url)
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"

        A1 = f"{self.username}:{realm}:{self.password}"
        A2 = f"{method}:{path}"
        HA1, HA2 = hash_utf8(A1), hash_utf8(A2)

        # Nonce & counter handling
        if nonce == self._thread_local.last_nonce:
            self._thread_local.nonce_count += 1
        else:
            self._thread_local.nonce_count = 1
        ncvalue = f"{self._thread_local.nonce_count:08x}"
        self._thread_local.last_nonce = nonce

        # Client nonce
        cnonce = hashlib.sha1(
            str(self._thread_local.nonce_count).encode()
            + nonce.encode()
            + time.ctime().encode()
            + os.urandom(8)
        ).hexdigest()[:16]

        if algorithm and algorithm.upper() == "MD5-SESS":
            HA1 = hash_utf8(f"{HA1}:{nonce}:{cnonce}")

        # Response digest
        if not qop:
            respdig = KD(HA1, f"{nonce}:{HA2}")
        elif "auth" in qop.split(","):
            noncebit = f"{nonce}:{ncvalue}:{cnonce}:auth:{HA2}"
            respdig = KD(HA1, noncebit)
        else:
            return None  # auth-int not supported

        # Assemble header
        header = (
            f'username="{self.username}", realm="{realm}", nonce="{nonce}", '
            f'uri="{path}", response="{respdig}"'
        )
        if opaque:
            header += f', opaque="{opaque}"'
        if algorithm:
            header += f', algorithm="{algorithm}"'
        if qop:
            header += f', qop="auth", nc={ncvalue}, cnonce="{cnonce}"'

        return f"Digest {header}"

    def handle_redirect(self, r, **kwargs):
        if r.is_redirect:
            self._thread_local.num_401_calls = 1

    def handle_401(self, r, **kwargs):
        if not 400 <= r.status_code < 500:
            self._thread_local.num_401_calls = 1
            return r

        if self._thread_local.pos is not None:
            r.request.body.seek(self._thread_local.pos)

        s_auth = r.headers.get("www-authenticate", "")
        if "digest" in s_auth.lower() and self._thread_local.num_401_calls < 2:
            self._thread_local.num_401_calls += 1
            pat = re.compile(r"digest ", flags=re.IGNORECASE)
            self._thread_local.chal = parse_dict_header(pat.sub("", s_auth, count=1))

            r.content  # consume
            r.close()

            prep = r.request.copy()
            extract_cookies_to_jar(prep._cookies, r.request, r.raw)
            prep.prepare_cookies(prep._cookies)
            prep.headers["Authorization"] = self.build_digest_header(prep.method, prep.url)

            _r = r.connection.send(prep, **kwargs)
            _r.history.append(r)
            _r.request = prep
            return _r

        self._thread_local.num_401_calls = 1
        return r

    def __call__(self, r):
        self._init_thread_state()
        if self._thread_local.last_nonce:
            r.headers["Authorization"] = self.build_digest_header(r.method, r.url)

        try:
            self._thread_local.pos = r.body.tell()
        except AttributeError:
            self._thread_local.pos = None

        r.register_hook("response", self.handle_401)
        r.register_hook("response", self.handle_redirect)
        return r

    def __eq__(self, other):
        return (
            self.username == getattr(other, "username", None)
            and self.password == getattr(other, "password", None)
        )
