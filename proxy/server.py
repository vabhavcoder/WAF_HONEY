"""
Core reverse proxy. Every incoming request is inspected (SQLi/XSS/
traversal/rate-limit heuristics — see proxy/detector.py); flagged
requests are forwarded to the fake web honeypot instead of the real
backend, everything else goes to BACKEND_URL as normal. Either way the
response relay, header filtering, and error handling are identical —
only which upstream app answers differs.
"""

import requests
from flask import Flask, request, Response

from proxy.logger import log_request
from proxy.detector import inspect_request
from proxy.config import BACKEND_URL, BACKEND_TIMEOUT, HONEYPOT_WEB_URL

app = Flask(__name__)

# Headers that are connection-specific per the HTTP/1.1 spec (RFC 7230
# 6.1) and must NOT be blindly copied between hops. Passing these
# through verbatim is a classic reverse-proxy bug: e.g. forwarding the
# client's own Content-Length/Transfer-Encoding pairing, or a stray
# Connection: keep-alive, can desync framing between the proxy<->client
# and proxy<->backend legs.
HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-encoding",  # requests already decodes this for us
}

# Headers that the local WSGI server (Werkzeug) injects itself on every
# outgoing response. If we also forward the backend's copies of these,
# the client sees duplicate headers (two Server:, two Date: lines) —
# technically invalid and confusing for anything parsing the response.
RESPONSE_AUTO_HEADERS = {"server", "date"}


def _filter_headers(headers, exclude_extra=()):
    exclude = HOP_BY_HOP_HEADERS | {h.lower() for h in exclude_extra}
    return [
        (name, value)
        for name, value in headers.items()
        if name.lower() not in exclude
    ]


def _build_target_url(base_url, path):
    target = f"{base_url.rstrip('/')}/{path}"
    if request.query_string:
        target += f"?{request.query_string.decode('utf-8')}"
    return target


@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def proxy(path):
    client_ip = request.remote_addr

    # Strip hop-by-hop + Host (requests sets its own Host for the
    # backend; forwarding the client's original Host would point the
    # backend at the wrong virtual host if it does name-based routing).
    forward_headers = _filter_headers(request.headers, exclude_extra=("host",))

    # get_data() is cached by Flask by default, so calling it once here
    # and reusing `body_bytes` below for the backend call doesn't read
    # the request stream twice.
    body_bytes = request.get_data()

    # ---- Known-bad-IP shortcut (future) ------------------------------
    # A persistent blocklist (Day 4+: something that survives a process
    # restart, e.g. a small file or sqlite table of IPs that have
    # triggered high-severity detections before) could check `client_ip`
    # here and skip straight to the honeypot without running
    # inspect_request() again. Day 3 re-inspects every request from
    # scratch — no cross-request/cross-session memory yet.
    # -------------------------------------------------------------------

    # ---- Detection (Day 2) ------------------------------------------
    # Inspect before forwarding, so a flagged request is visible in the
    # log even if the backend call itself times out or errors below.
    # Detection only classifies; it never blocks the request outright.
    detection = inspect_request(
        ip=client_ip,
        method=request.method,
        path=request.path,
        query_string=request.query_string.decode("utf-8", errors="ignore"),
        body=body_bytes,
        headers=request.headers,
    )

    # ---- Honeypot redirect (Day 3) ------------------------------------
    # A flagged request never reaches the real backend: it's forwarded
    # to the fake web app instead, using the exact same passthrough path
    # below (same header filtering, same error handling, same response
    # relay) so nothing about how the request is served differs from
    # the client's point of view — only which app answers it.
    # ---------------------------------------------------------------------
    if detection["flagged"]:
        base_url = HONEYPOT_WEB_URL
        detection["routed_to"] = "honeypot"
    else:
        base_url = BACKEND_URL
        detection["routed_to"] = "backend"

    target_url = _build_target_url(base_url, path)

    try:
        backend_response = requests.request(
            method=request.method,
            url=target_url,
            headers=dict(forward_headers),
            data=body_bytes,          # raw body, works for any content-type
            cookies=request.cookies,  # forwarded separately from headers so
                                       # `requests` re-encodes the Cookie
                                       # header correctly rather than us
                                       # hand-copying a raw string
            allow_redirects=False,    # let the CLIENT follow redirects,
                                       # not the proxy — else the client
                                       # would see the backend's final
                                       # destination as if it were direct
            timeout=BACKEND_TIMEOUT,
            stream=True,
        )
    except requests.exceptions.Timeout:
        log_request(client_ip, request.method, request.path, 504, extra=detection)
        return Response("Backend request timed out", status=504)
    except requests.exceptions.ConnectionError:
        log_request(client_ip, request.method, request.path, 502, extra=detection)
        return Response("Backend unreachable", status=502)
    except requests.exceptions.RequestException as exc:
        log_request(client_ip, request.method, request.path, 500, extra=detection)
        return Response(f"Proxy error: {exc}", status=500)

    response_headers = _filter_headers(
        backend_response.headers, exclude_extra=RESPONSE_AUTO_HEADERS
    )

    log_request(
        client_ip, request.method, request.path, backend_response.status_code,
        extra=detection,
    )

    return Response(
        backend_response.content,
        status=backend_response.status_code,
        headers=response_headers,
    )
