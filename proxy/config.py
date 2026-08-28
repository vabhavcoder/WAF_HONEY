"""
Central configuration for the reverse proxy.
Values can be overridden via environment variables so the same code
runs unmodified in dev/test/CI without editing this file.
"""

import os

# Backend the proxy forwards requests to (the "real app" for now, will
# later be one of several targets once honeypot routing is added).
BACKEND_URL = os.environ.get("ADP_BACKEND_URL", "http://localhost:5000")

# Local port the proxy itself listens on.
LISTEN_PORT = int(os.environ.get("ADP_LISTEN_PORT", "8080"))

# Where structured (JSON-lines) request logs are written.
LOG_PATH = os.environ.get("ADP_LOG_PATH", "logs/requests.log")

# Seconds to wait for the backend before treating it as unreachable.
BACKEND_TIMEOUT = float(os.environ.get("ADP_BACKEND_TIMEOUT", "5"))

# ---------------------------------------------------------------------------
# DETECTION_RULES
# Every pattern/threshold the detector uses lives here as a named constant,
# not inline in proxy/detector.py, so tuning a rule (or adding one) never
# means touching detection logic. Each pattern entry is
# (name, regex_string, severity) — "name" is what shows up in a request's
# logged `reasons`, "severity" is this pattern's own weight; inspect_request()
# takes the highest severity among everything that matched.
# ---------------------------------------------------------------------------

# --- Rate limiting: sliding window, in-memory, per source IP ---
RATE_LIMIT_COUNT = int(os.environ.get("ADP_RATE_LIMIT_COUNT", "20"))   # requests
RATE_LIMIT_WINDOW = float(os.environ.get("ADP_RATE_LIMIT_WINDOW", "10"))  # seconds
RATE_LIMIT_SEVERITY = "medium"

# --- SQL injection indicators ---
# NOTE on false positives: `;` and `--`/`#` alone are extremely common in
# legitimate traffic (semicolons in JSON/URLs, `--` in free-text fields,
# `#` in URL fragments some clients still send server-side). Those two are
# deliberately tagged "low" rather than "high" so a lone hit doesn't carry
# the same weight as an unambiguous signal like `UNION SELECT` or
# `information_schema` — severity is about matched-pattern confidence, not
# just "did anything match."
SQLI_PATTERNS = [
    ("sqli_union_select", r"union\s+select", "high"),
    ("sqli_tautology", r"(\bor\b|\band\b)\s*'?\"?\s*1\s*=\s*1\s*'?\"?", "high"),
    ("sqli_tautology_quoted", r"'\s*or\s*'?1'?\s*=\s*'?1", "high"),
    ("sqli_sleep", r"sleep\s*\(", "high"),
    ("sqli_benchmark", r"benchmark\s*\(", "high"),
    ("sqli_information_schema", r"information_schema", "high"),
    ("sqli_stacked_query", r";\s*(select|insert|update|delete|drop|union)\b", "high"),
    ("sqli_comment_sequence", r"(--|#|/\*)", "low"),
    ("sqli_bare_semicolon", r";", "low"),
]

# --- Cross-site scripting indicators ---
# Encoded variants are checked against the RAW (still-percent-encoded)
# query string / body text — that's the point of matching "%3Cscript"
# literally rather than only after decoding.
XSS_PATTERNS = [
    ("xss_script_tag", r"<script", "high"),
    ("xss_onerror_attr", r"onerror\s*=", "high"),
    ("xss_onload_attr", r"onload\s*=", "high"),
    ("xss_javascript_uri", r"javascript\s*:", "high"),
    ("xss_img_onerror", r"<img[^>]+onerror", "high"),
    ("xss_encoded_script_tag", r"%3cscript", "medium"),
]

# --- Path traversal indicators ---
TRAVERSAL_PATTERNS = [
    ("traversal_dotdot_slash", r"\.\./", "high"),
    ("traversal_encoded_dotdot", r"\.\.%2f", "high"),
    ("traversal_etc_passwd", r"/etc/passwd", "high"),
    ("traversal_windows_system32", r"[/\\]windows[/\\]system32", "high"),
]

# Which request headers get checked against the patterns above. Kept short
# and explicit — inspecting every header (e.g. Accept, Accept-Encoding)
# would mostly add noise, not detection value.
INSPECTED_HEADERS = ("User-Agent", "Referer", "Cookie")

# ---------------------------------------------------------------------------
# Honeypot layer (Day 3)
# ---------------------------------------------------------------------------

# Fake web app (honeypot/fake_web.py) — what a flagged request gets routed
# to instead of the real BACKEND_URL.
HONEYPOT_PORT = int(os.environ.get("ADP_HONEYPOT_PORT", "5001"))
HONEYPOT_WEB_URL = os.environ.get(
    "ADP_HONEYPOT_WEB_URL", f"http://localhost:{HONEYPOT_PORT}"
)

# Fake SSH banner service (honeypot/fake_ssh.py) — standalone, not routed
# to by the HTTP proxy; attackers reach it directly the same way they'd
# reach a real exposed SSH port. 2222, not 22, so it doesn't need root
# and won't collide with a real sshd on the same machine.
HONEYPOT_SSH_PORT = int(os.environ.get("ADP_HONEYPOT_SSH_PORT", "2222"))

# Separate log file from the main proxy log (LOG_PATH) — honeypot traffic
# is a fundamentally different signal (every hit here is, by definition,
# either a flagged/malicious request or direct-to-honeypot probing with
# no legitimate traffic mixed in) and downstream analysis will want to
# read it independently.
HONEYPOT_LOG_PATH = os.environ.get("ADP_HONEYPOT_LOG_PATH", "logs/honeypot.log")

# Seconds fake_ssh.py waits on recv() for a client's post-banner input
# before giving up and closing the connection. Real SSH clients start
# their handshake immediately, but a human at `nc` can be slow — long
# enough to capture a manual probe, short enough not to tie up a thread
# on a client that just opened the socket and walked away.
HONEYPOT_SSH_RECV_TIMEOUT = float(os.environ.get("ADP_HONEYPOT_SSH_RECV_TIMEOUT", "15"))

# ---------------------------------------------------------------------------
# Dashboard (Day 4)
# ---------------------------------------------------------------------------

# Read-only monitoring UI, its own process/port — never touches proxy,
# detector, or honeypot state, only parses the log files above.
DASHBOARD_PORT = int(os.environ.get("ADP_DASHBOARD_PORT", "8090"))
