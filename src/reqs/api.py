from . import sessions


def request(method, url, **kwargs):
    """
    Create and send a Request.

    :param method: HTTP method (GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD).
    :param url: Target URL.
    :param params: (optional) Query string as dict, list of tuples, or bytes.
    :param data: (optional) Data to send in request body (dict, list, bytes, file-like).
    :param json: (optional) JSON-serializable object to send in body.
    :param headers: (optional) Dict of HTTP headers.
    :param cookies: (optional) Dict or CookieJar to include.
    :param files: (optional) Dict of form files: 
                  {"name": file} or {"name": (filename, file, content_type, headers)}.
    :param auth: (optional) Tuple for Basic/Digest/Custom HTTP Auth.
    :param timeout: (optional) Timeout (float) or (connect, read) tuple.
    :param allow_redirects: (optional) Follow redirects (default: True).
    :param proxies: (optional) Dict mapping protocol → proxy URL.
    :param verify: (optional) TLS verification:
                   - True (default) = use system CA bundle
                   - False = disable TLS verification
                   - str = path to custom CA bundle
    :param stream: (optional) If False, download response content immediately.
    :param cert: (optional) Client certificate: path string or (cert, key) tuple.
    :return: Response object
    """

    # Ensure session is closed properly to avoid leaking sockets.
    with sessions.Session() as session:
        return session.request(method=method, url=url, **kwargs)


def get(url, params=None, **kwargs):
    """Send a GET request."""
    return request("get", url, params=params, **kwargs)


def options(url, **kwargs):
    """Send an OPTIONS request."""
    return request("options", url, **kwargs)


def head(url, **kwargs):
    """
    Send a HEAD request.

    Unlike the default request behavior, `allow_redirects` defaults to False.
    """
    kwargs.setdefault("allow_redirects", False)
    return request("head", url, **kwargs)


def post(url, data=None, json=None, **kwargs):
    """Send a POST request."""
    return request("post", url, data=data, json=json, **kwargs)


def put(url, data=None, **kwargs):
    """Send a PUT request."""
    return request("put", url, data=data, **kwargs)


def patch(url, data=None, **kwargs):
    """Send a PATCH request."""
    return request("patch", url, data=data, **kwargs)


def delete(url, **kwargs):
    """Send a DELETE request."""
    return request("delete", url, **kwargs)
