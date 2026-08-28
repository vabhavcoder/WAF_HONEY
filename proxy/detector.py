"""
Request inspection: hand-written regex heuristics for SQLi/XSS/path-
traversal indicators, plus an in-memory per-IP sliding-window rate
limiter. No third-party rule engine — every pattern lives in
proxy/config.py as a named constant; this module only compiles and
applies them.

Day 2 scope: detect and log only. `inspect_request()` never blocks or
redirects a request itself — see the comment in proxy/server.py at the
call site for where that decision (Day 3: honeypot redirect) will hook in.
"""

import re
import time
import threading
from collections import defaultdict
from urllib.parse import unquote_plus

from proxy.config import (
    SQLI_PATTERNS,
    XSS_PATTERNS,
    TRAVERSAL_PATTERNS,
    RATE_LIMIT_COUNT,
    RATE_LIMIT_WINDOW,
    RATE_LIMIT_SEVERITY,
    INSPECTED_HEADERS,
)

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}


def _compile(pattern_defs):
    # (name, compiled_regex, severity) — case-insensitive, since attackers
    # don't stick to lowercase and neither do real clients.
    return [
        (name, re.compile(pattern, re.IGNORECASE), severity)
        for name, pattern, severity in pattern_defs
    ]


_SQLI = _compile(SQLI_PATTERNS)
_XSS = _compile(XSS_PATTERNS)
_TRAVERSAL = _compile(TRAVERSAL_PATTERNS)
_ALL_PATTERN_GROUPS = _SQLI + _XSS + _TRAVERSAL


def _scan_text(text):
    """Run every pattern group against one string, return matched reason names."""
    if not text:
        return []
    hits = []
    for name, regex, severity in _ALL_PATTERN_GROUPS:
        if regex.search(text):
            hits.append((name, severity))
    return hits


def _body_to_text(body, content_type):
    """
    Normalize a request body to a searchable string regardless of whether
    it's form-encoded or JSON. Both are already text, so this doesn't
    need a real parser — a raw decode is enough since we're pattern-
    matching, not validating structure. bytes -> str only; anything that
    isn't valid UTF-8 (e.g. a binary upload) is skipped rather than
    guessed at.
    """
    if not body:
        return ""
    if isinstance(body, bytes):
        try:
            body = body.decode("utf-8", errors="ignore")
        except Exception:
            return ""
    return body


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

_ip_requests = defaultdict(list)  # ip -> [timestamps within the window]
_rate_lock = threading.Lock()


def check_rate_limit(ip):
    """
    Sliding window: record this request's timestamp, drop anything older
    than RATE_LIMIT_WINDOW seconds, and flag if what's left exceeds
    RATE_LIMIT_COUNT. State is an in-memory dict, so this resets on
    process restart and does not share state across multiple proxy
    processes — fine for a single-machine dev setup, a real deployment
    would need a shared store (Redis etc.) instead.
    """
    now = time.time()
    with _rate_lock:
        timestamps = _ip_requests[ip]
        cutoff = now - RATE_LIMIT_WINDOW
        # Prune in place rather than reassigning, so the defaultdict entry
        # (and thus this ip's history) doesn't get orphaned.
        i = 0
        for i, ts in enumerate(timestamps):
            if ts >= cutoff:
                break
        else:
            i = len(timestamps)
        del timestamps[:i]

        timestamps.append(now)
        return len(timestamps) > RATE_LIMIT_COUNT


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def inspect_request(ip, method, path, query_string, body, headers):
    """
    Args:
        ip: client source IP (string)
        method: HTTP method (string)
        path: request path, e.g. "/login" (string, no query string)
        query_string: raw query string, still percent-encoded (string)
        body: raw request body — bytes or str, form-encoded or JSON
        headers: dict-like of request headers (only the ones named in
            config.INSPECTED_HEADERS are actually checked)

    Returns:
        {"flagged": bool, "reasons": [str, ...], "severity": "low"|"medium"|"high"}
        severity is the highest severity among everything that matched;
        "low" if only rate_limit matched at its own configured severity,
        empty list -> flagged False and severity "low" by convention.
    """
    reasons = []
    max_severity = "low"

    def _record(name, severity):
        nonlocal max_severity
        reasons.append(name)
        if _SEVERITY_RANK[severity] > _SEVERITY_RANK[max_severity]:
            max_severity = severity

    # --- query string (still percent-encoded, so encoded XSS patterns
    #     like %3Cscript match here without needing a decode step) ---
    for name, severity in _scan_text(query_string or ""):
        _record(name, severity)

    # --- also check the decoded query string, so an attacker can't dodge
    #     the plain-text SQLi/traversal patterns purely by URL-encoding
    #     spaces/slashes/quotes. unquote_plus (not unquote) because query
    #     strings encode spaces as "+" as well as "%20" — plain unquote()
    #     leaves "+" untouched, which silently breaks any pattern that
    #     expects a real space (e.g. "' OR '1'='1" arrives as
    #     "%27+OR+%271%27%3D%271" from a typical client). ---
    if query_string:
        decoded_qs = unquote_plus(query_string)
        if decoded_qs != query_string:
            for name, severity in _scan_text(decoded_qs):
                if name not in reasons:
                    _record(name, severity)

    # --- POST body: JSON bodies are already literal text (a JSON string
    #     containing "<script>" appears as-is), but form-urlencoded
    #     bodies are percent-encoded exactly like a query string —
    #     "username=admin%27+OR+%271%27%3D%271" — so the same raw-then-
    #     decoded pass applies here too, for the same reason (attackers
    #     shouldn't be able to dodge plain-text patterns just by
    #     submitting the form-encoded form of a payload). ---
    body_text = _body_to_text(body, None)
    for name, severity in _scan_text(body_text):
        if name not in reasons:
            _record(name, severity)
    if body_text:
        decoded_body = unquote_plus(body_text)
        if decoded_body != body_text:
            for name, severity in _scan_text(decoded_body):
                if name not in reasons:
                    _record(name, severity)

    # --- path itself (traversal targets typically land here) ---
    for name, severity in _scan_text(path or ""):
        if name not in reasons:
            _record(name, severity)

    # --- selected headers only (User-Agent, Referer, Cookie) ---
    for header_name in INSPECTED_HEADERS:
        value = headers.get(header_name) if headers else None
        if not value:
            continue
        for name, severity in _scan_text(value):
            if name not in reasons:
                _record(name, severity)

    # --- rate limiting (independent of content-based checks above) ---
    if check_rate_limit(ip):
        _record("rate_limit", RATE_LIMIT_SEVERITY)

    return {
        "flagged": bool(reasons),
        "reasons": reasons,
        "severity": max_severity if reasons else "low",
    }
