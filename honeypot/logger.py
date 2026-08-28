"""
Shared structured logger for the honeypot layer (fake_web.py and
fake_ssh.py both use this). Kept as one module rather than each
honeypot writing its own JSON-lines file so the schema can't drift
between the two — a single log_honeypot_event() call site is easier
to keep consistent than two independent implementations of "append
a JSON line."

Deliberately a SEPARATE file from HONEYPOT_LOG_PATH's writer being
proxy/logger.py's log_request(): honeypot hits are a fundamentally
different signal (every line here is, by definition, either already-
flagged traffic or a direct probe of a fake service — no legitimate
requests mixed in) and analysis of one shouldn't need to filter the
other out.
"""

import json
import datetime
import os
import threading

from proxy.config import HONEYPOT_LOG_PATH

_write_lock = threading.Lock()


def _ensure_log_dir():
    log_dir = os.path.dirname(HONEYPOT_LOG_PATH)
    if log_dir and not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)


def log_honeypot_event(event_type, ip, data=None):
    """
    Append one JSON line describing a honeypot interaction.

    Args:
        event_type: short string identifying the kind of event, e.g.
            "http_login_attempt", "http_admin_probe", "ssh_connect",
            "ssh_input" (string)
        ip: source IP of the connecting client (string)
        data: event-specific detail dict — for HTTP: method, path,
            headers, query_string, body, parsed params; for SSH: bytes
            received (decoded + hex). Never anything the honeypot
            itself acted on — everything logged here was accepted,
            faked, and discarded, never actually used.
    """
    record = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "event_type": event_type,
        "ip": ip,
    }
    if data:
        record["data"] = data

    _ensure_log_dir()
    line = json.dumps(record, ensure_ascii=False)

    with _write_lock:
        with open(HONEYPOT_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
