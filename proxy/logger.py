"""
Structured request logging in JSON-lines format (one JSON object per
line). Day 2+ detection logic will read this file line-by-line, so the
schema here needs to stay stable and machine-parseable — no free text.
"""

import json
import datetime
import os
import threading

from proxy.config import LOG_PATH

# Flask's dev server can run multi-threaded (see main.py), so multiple
# requests may call log_request() concurrently. A single process-wide
# lock keeps individual JSON lines from interleaving mid-write.
_write_lock = threading.Lock()


def _ensure_log_dir():
    log_dir = os.path.dirname(LOG_PATH)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)


def log_request(ip, method, path, status, extra=None):
    """
    Append one JSON line describing a proxied request.

    Args:
        ip: client source IP (string)
        method: HTTP method (string)
        path: request path, e.g. "/login" (string)
        status: response status code returned to the client (int),
            or None if the request failed before a status was obtained
            (e.g. backend timeout/connection error)
        extra: optional dict for future detection metadata (e.g.
            {"flagged": True, "rule": "sqli"}). Left empty today —
            this is the hook Day 2+ hangs off.
    """
    record = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "ip": ip,
        "method": method,
        "path": path,
        "status": status,
    }
    if extra:
        record["extra"] = extra

    _ensure_log_dir()
    line = json.dumps(record, ensure_ascii=False)

    with _write_lock:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
