"""Flask-based reverse proxy implementation.

This module intentionally only proxies traffic.  Future detection and routing
logic can be inserted at the marked extension point in ``proxy``.
"""
from collections.abc import Iterable

import requests
from flask import Flask, Response, request
from requests import RequestException

from proxy.config import BACKEND_URL, REQUEST_TIMEOUT
from proxy.logger import log_request

app = Flask(__name__)

# Headers that apply only to one connection and must not be forwarded.
HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


def _connection_header_tokens(headers: Iterable[tuple[str, str]]) -> set[str]:
    """Find additional hop-by-hop headers named by a Connection header."""
    tokens: set[str] = set()
    for name, value in headers:
        if name.lower() == "connection":
            tokens.update(token.strip().lower() for token in value.split(","))
    return tokens


def _forward_headers() -> dict[str, str]:
    """Copy request headers while omitting hop-by-hop and Host headers."""
    incoming = list(request.headers.items())
    excluded = HOP_BY_HOP_HEADERS | _connection_header_tokens(incoming) | {"host"}
    return {name: value for name, value in incoming if name.lower() not in excluded}


def _response_headers(backend_response: requests.Response) -> list[tuple[str, str]]:
    """Copy end-to-end response headers, preserving repeated Set-Cookie lines."""
    excluded = HOP_BY_HOP_HEADERS | _connection_header_tokens(backend_response.headers.items())
    headers: list[tuple[str, str]] = []
    raw_headers = getattr(backend_response.raw, "headers", None)
    if raw_headers is not None and hasattr(raw_headers, "getlist"):
        for name, value in raw_headers.items():
            if name.lower() == "set-cookie":
                for cookie in raw_headers.getlist(name):
                    headers.append((name, cookie))
            elif name.lower() not in excluded:
                headers.append((name, value))
        return headers

    return [(name, value) for name, value in backend_response.headers.items()
            if name.lower() not in excluded]


@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
def proxy(path: str) -> Response:
    """Forward the current request to the configured backend and relay its response."""
    query = request.query_string.decode("latin-1")
    request_path = request.path
    target_url = f"{BACKEND_URL}{request_path}"
    if query:
        target_url = f"{target_url}?{query}"

    client_ip = request.remote_addr or "unknown"

    # Day 2 extension point: inspect this request here and decide its destination.
    # For Day 1 all traffic is sent to BACKEND_URL.
    try:
        backend_response = requests.request(
            method=request.method,
            url=target_url,
            headers=_forward_headers(),
            data=request.get_data(),
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
        )
    except requests.Timeout:
        status = 504
        log_request(client_ip, request.method, request.full_path, status,
                    extra={"error": "backend_timeout"})
        return Response("Backend request timed out\n", status=status, mimetype="text/plain")
    except RequestException as error:
        status = 502
        log_request(client_ip, request.method, request.full_path, status,
                    extra={"error": "backend_connection_error", "detail": str(error)})
        return Response("Backend is unavailable\n", status=status, mimetype="text/plain")

    log_request(client_ip, request.method, request.full_path, backend_response.status_code)
    return Response(
        backend_response.content,
        status=backend_response.status_code,
        headers=_response_headers(backend_response),
    )
