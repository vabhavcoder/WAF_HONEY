"""
Read-only dashboard. Every view here only parses and displays
requests.log / honeypot.log via dashboard/log_reader.py — nothing in
this module writes to a log, calls into proxy/detector/honeypot code,
or has any way to affect what those processes do. It's a separate
process on its own port precisely so a crash or a slow page here can
never take down the actual proxy.
"""

from collections import Counter
from datetime import datetime, timezone

from flask import Flask, render_template, abort

from dashboard.log_reader import read_log
from proxy.config import LOG_PATH, HONEYPOT_LOG_PATH

app = Flask(__name__)

# How often the auto-refreshing pages (/ and /timeline) reload, in
# seconds. Plain <meta http-equiv="refresh">, not fetch()+setInterval —
# for a local single-page-at-a-time demo dashboard, a full reload every
# few seconds is simpler to reason about and debug than partial-DOM
# JS updates, and the pages are cheap enough to regenerate that the
# extra reload cost doesn't matter.
AUTO_REFRESH_SECONDS = 7


def _is_flagged(entry):
    return bool((entry.get("extra") or {}).get("flagged"))


def _honeypot_service(entry):
    event_type = entry.get("event_type", "")
    if event_type.startswith("ssh_"):
        return "ssh"
    if event_type.startswith("http_"):
        return "web"
    return "unknown"


def _honeypot_summary_line(entry):
    """
    One human-readable line summarizing what a honeypot entry captured,
    used in both the /honeypot table and the /ip/<ip> drill-down so the
    two views describe events the same way.
    """
    event_type = entry.get("event_type", "")
    data = entry.get("data") or {}

    if event_type == "http_login_attempt":
        params = data.get("params") or {}
        username = params.get("username", "")
        password = params.get("password", "")
        return f"login attempt — username={username!r} password={password!r}"
    if event_type == "http_admin_probe":
        return "probed /admin"
    if event_type in ("http_index_probe", "http_login_page_view"):
        return f"viewed {data.get('path', '')}"
    if event_type == "http_unknown_path_probe":
        return f"probed unknown path {data.get('path', '')}"
    if event_type == "ssh_connect":
        return "connected (banner sent)"
    if event_type == "ssh_input":
        text = data.get("text", "")
        return f"sent {data.get('byte_count', 0)} bytes: {text!r}"
    if event_type == "ssh_input_timeout":
        return "connected, sent nothing before timeout"
    if event_type == "ssh_connection_error":
        return f"connection error: {data.get('error', '')}"
    return event_type or "unknown event"


@app.route("/")
def summary():
    requests_log = read_log(LOG_PATH)
    honeypot_log = read_log(HONEYPOT_LOG_PATH)

    flagged_entries = [e for e in requests_log if _is_flagged(e)]

    total_requests = len(requests_log)
    total_flagged = len(flagged_entries)
    total_honeypot_hits = len(honeypot_log)

    ip_counts = Counter(e.get("ip", "unknown") for e in requests_log)
    flagged_ip_counts = Counter(e.get("ip", "unknown") for e in flagged_entries)

    top_ips = ip_counts.most_common(5)
    top_flagged_ips = flagged_ip_counts.most_common(5)

    return render_template(
        "summary.html",
        total_requests=total_requests,
        total_flagged=total_flagged,
        total_honeypot_hits=total_honeypot_hits,
        top_ips=top_ips,
        top_flagged_ips=top_flagged_ips,
        auto_refresh_seconds=AUTO_REFRESH_SECONDS,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        active_page="summary",
    )


@app.route("/timeline")
def timeline():
    requests_log = read_log(LOG_PATH)
    flagged_entries = [e for e in requests_log if _is_flagged(e)]
    # Newest first — during a live demo you want the most recent
    # flagged request visible without scrolling past everything older.
    flagged_entries.sort(key=lambda e: e.get("timestamp", ""), reverse=True)

    return render_template(
        "timeline.html",
        entries=flagged_entries,
        auto_refresh_seconds=AUTO_REFRESH_SECONDS,
        active_page="timeline",
    )


@app.route("/honeypot")
def honeypot_view():
    honeypot_log = read_log(HONEYPOT_LOG_PATH)
    honeypot_log.sort(key=lambda e: e.get("timestamp", ""), reverse=True)

    rows = [
        {
            "timestamp": e.get("timestamp", ""),
            "ip": e.get("ip", ""),
            "service": _honeypot_service(e),
            "event_type": e.get("event_type", ""),
            "summary": _honeypot_summary_line(e),
        }
        for e in honeypot_log
    ]

    return render_template("honeypot.html", rows=rows, active_page="honeypot")


@app.route("/ip/<ip_address>")
def ip_detail(ip_address):
    proxy_entries = read_log(LOG_PATH, ip_filter=ip_address)
    honeypot_entries = read_log(HONEYPOT_LOG_PATH, ip_filter=ip_address)

    if not proxy_entries and not honeypot_entries:
        abort(404, description=f"No log entries found for IP {ip_address}")

    combined = []
    for e in proxy_entries:
        extra = e.get("extra") or {}
        combined.append({
            "timestamp": e.get("timestamp", ""),
            "source": "proxy",
            "detail": (
                f"{e.get('method', '')} {e.get('path', '')} -> {e.get('status', '')} "
                f"({'FLAGGED: ' + ', '.join(extra.get('reasons', [])) if extra.get('flagged') else 'clean'}"
                f", routed to {extra.get('routed_to', '?')})"
            ),
            "severity": extra.get("severity", "low") if extra.get("flagged") else None,
        })
    for e in honeypot_entries:
        combined.append({
            "timestamp": e.get("timestamp", ""),
            "source": "honeypot",
            "detail": f"[{_honeypot_service(e)}] {_honeypot_summary_line(e)}",
            "severity": None,
        })

    combined.sort(key=lambda e: e["timestamp"], reverse=True)

    request_count = len(proxy_entries)
    flagged_count = sum(1 for e in proxy_entries if _is_flagged(e))
    honeypot_count = len(honeypot_entries)

    return render_template(
        "ip_detail.html",
        ip_address=ip_address,
        entries=combined,
        request_count=request_count,
        flagged_count=flagged_count,
        honeypot_count=honeypot_count,
        active_page="ip_detail",
    )

# Run via run_dashboard.py at the project root, not `python3
# dashboard/app.py` directly — the latter breaks the `from
# dashboard.log_reader import ...` above (see run_dashboard.py for why).
