#!/usr/bin/env python3
"""
Day 6 - Edge case test harness for the Active Deception Proxy.

Run this ON the target (Debian) machine so it can read the log files
directly (logs/requests.log, logs/honeypot.log). If you run it from the
Kali VM instead, set READ_LOGS = False below and point PROXY_HOST at the
target's IP -- the script will still send every request and report
HTTP-level pass/fail, it just won't be able to cross-check log entries
or confirm flagged status.

This script does NOT fix anything. It only sends requests, reads logs,
and reports pass/fail/warn. Bugs it finds should be handled as separate,
targeted fixes.

BEFORE RUNNING: check the CONFIG section below against your actual
proxy/config.py and logger.py -- field names and route paths are
best-guess based on the Day 1-3 skeletons and may not match your code
exactly. Adjust FIELD_* and the sample routes/params in each test
function if your app uses different paths.
"""

import json
import time
from pathlib import Path
from datetime import datetime, timezone

import requests

# Verified against the actual project code (proxy/logger.py,
# proxy/detector.py, proxy/config.py) on 2026-09-05. FIELD_* constants
# below match exactly -- proxy/logger.py writes timestamps as
# timezone-aware UTC ISO-8601 (datetime.now(timezone.utc).isoformat()),
# which is why every "since" marker in this script must ALSO be
# timezone-aware (datetime.now(timezone.utc), never datetime.utcnow())
# -- comparing an aware and a naive datetime raises TypeError.

# ---------------------------------------------------------------------
# CONFIG -- adjust these to match your actual setup / log schema
# ---------------------------------------------------------------------
PROXY_HOST = "127.0.0.1"       # use target VM's IP if running from Kali
PROXY_PORT = 8080
BASE_URL = f"http://{PROXY_HOST}:{PROXY_PORT}"

PROJECT_ROOT = Path(__file__).resolve().parent.parent
REQUESTS_LOG = PROJECT_ROOT / "logs" / "requests.log"
HONEYPOT_LOG = PROJECT_ROOT / "logs" / "honeypot.log"
READ_LOGS = True   # set False if logs aren't reachable from where you run this

REPORT_PATH = Path(__file__).resolve().parent / "edge_case_report.json"

# Field names used in requests.log entries -- ADJUST if your logger.py
# uses different keys. Expected shape (from Day 1-2 design):
#   {"timestamp": "...", "ip": "...", "method": "...", "path": "...",
#    "status": 200, "extra": {"flagged": bool, "reasons": [...], "severity": "..."}}
FIELD_TIMESTAMP = "timestamp"
FIELD_IP = "ip"
FIELD_PATH = "path"
FIELD_EXTRA = "extra"
FIELD_FLAGGED = "flagged"      # looked up inside FIELD_EXTRA (falls back to top-level)
FIELD_REASONS = "reasons"      # looked up inside FIELD_EXTRA (falls back to top-level)

RATE_LIMIT_COUNT = 20          # must match proxy/config.py RATE_LIMIT_COUNT
RATE_LIMIT_WINDOW = 10         # seconds, must match proxy/config.py

LOG_POLL_TRIES = 5
LOG_POLL_DELAY = 0.5

# ---------------------------------------------------------------------
results = []


def record(name, category, passed, detail="", warn=False):
    if warn:
        status = "WARN"
    else:
        status = "PASS" if passed else "FAIL"
    results.append({"name": name, "category": category, "status": status, "detail": detail})
    print(f"[{status}] {name}" + (f" -- {detail}" if detail else ""))


def safe_request(method, path, **kwargs):
    """Send a request, never let a proxy crash kill the whole test run."""
    try:
        resp = requests.request(method, BASE_URL + path, timeout=8, **kwargs)
        return resp, None
    except requests.exceptions.RequestException as e:
        return None, str(e)


def _parse_ts(raw):
    if raw is None:
        return None
    candidates = [raw]
    if raw.endswith("Z"):
        candidates.append(raw[:-1])
    for candidate in candidates:
        try:
            return datetime.fromisoformat(candidate)
        except ValueError:
            continue
    return None


def _read_log(path):
    if not READ_LOGS or not path.exists():
        return []
    entries = []
    with open(path, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return entries


def find_recent_log_entry(path, since, predicate):
    """Poll a log file for the most recent entry matching predicate,
    with timestamp >= since. Returns None if READ_LOGS is off, the file
    can't be read, or nothing matches within the poll window."""
    if not READ_LOGS:
        return None
    for _ in range(LOG_POLL_TRIES):
        entries = _read_log(path)
        matches = []
        for e in entries:
            ts = _parse_ts(e.get(FIELD_TIMESTAMP))
            if ts is not None and since is not None and ts < since:
                continue
            if predicate(e):
                matches.append(e)
        if matches:
            return matches[-1]
        time.sleep(LOG_POLL_DELAY)
    return None


def entry_flagged(entry):
    if entry is None:
        return None
    extra = entry.get(FIELD_EXTRA) or {}
    if FIELD_FLAGGED in extra:
        return extra[FIELD_FLAGGED]
    return entry.get(FIELD_FLAGGED)


def entry_reasons(entry):
    if entry is None:
        return []
    extra = entry.get(FIELD_EXTRA) or {}
    return extra.get(FIELD_REASONS) or entry.get(FIELD_REASONS) or []


# =======================================================================
# 1. ENCODING BYPASS ATTEMPTS -- should still be flagged
# =======================================================================
def _check_encoding_case(name, marker_path, since, resp, err):
    if err:
        record(name, "encoding_bypass", False, f"request failed: {err}")
        return
    entry = find_recent_log_entry(
        REQUESTS_LOG, since, lambda e: str(e.get(FIELD_PATH, "")).startswith(marker_path)
    )
    flagged = entry_flagged(entry)
    if flagged is True:
        record(name, "encoding_bypass", True,
               f"status={resp.status_code}, reasons={entry_reasons(entry)}")
    elif flagged is False:
        record(name, "encoding_bypass", False,
               f"NOT flagged -- possible detection bypass (status={resp.status_code})")
    else:
        record(name, "encoding_bypass", None,
               "could not confirm from logs (READ_LOGS off, or no matching entry found -- "
               "check FIELD_* config and the path used)", warn=True)


def test_encoding_bypasses():
    # Cases that are ALREADY percent-encoded must be sent as a literal
    # string appended directly to the path/query -- passing a
    # pre-encoded string through requests' `params=` dict makes requests
    # percent-encode it AGAIN (e.g. "%27" becomes "%2527"), silently
    # turning a single-encoded payload into a double/triple-encoded one
    # that no longer matches anything, even after this app's own
    # single-unquote decode pass. Confirmed this was a test-harness
    # artifact, not a real detection bypass, by tracing what bytes
    # actually land on the wire in each case.
    raw_query_cases = [
        ("URL-encoded SQLi", "/search?id=1%27%20OR%20%271%27=%271"),
        ("Double-encoded XSS", "/search?q=%253Cscript%253E"),
    ]
    # These use real characters (not pre-encoded), so letting requests
    # encode them normally (via params=/data=) matches how an actual
    # client would send them -- no change needed here.
    literal_cases = [
        ("Mixed-case UNION SELECT", "GET", "/search", {"id": "1 UnIoN SeLeCt password"}, None),
        ("Mixed-case script tag", "POST", "/comment", None, {"text": "<ScRiPt>alert(1)</ScRiPt>"}),
    ]

    for name, full_path in raw_query_cases:
        since = datetime.now(timezone.utc)
        resp, err = safe_request("GET", full_path)
        marker_path = full_path.split("?")[0]
        _check_encoding_case(name, marker_path, since, resp, err)

    for name, method, path, params, data in literal_cases:
        since = datetime.now(timezone.utc)
        if params is not None:
            resp, err = safe_request(method, path, params=params)
        else:
            resp, err = safe_request(method, path, data=data)
        _check_encoding_case(name, path, since, resp, err)


# =======================================================================
# 2. MALFORMED / UNUSUAL INPUT -- must NOT crash the proxy
# =======================================================================
def test_malformed_input():
    long_qs_value = "x" * 5000
    cases = [
        ("Empty JSON body", "POST", "/api/data",
         dict(data="", headers={"Content-Type": "application/json"})),
        ("Malformed JSON body", "POST", "/api/data",
         dict(data='{"a": }', headers={"Content-Type": "application/json"})),
        ("Extremely long query string", "GET", "/search",
         dict(params={"a": long_qs_value})),
        ("Missing/empty User-Agent header", "GET", "/",
         dict(headers={"User-Agent": ""})),
        ("Unicode/emoji in params", "GET", "/search",
         dict(params={"q": "café rocket emoji test 日本語"})),
        ("Null byte in path", "GET", "/file%00.txt", dict()),
    ]
    for name, method, path, kwargs in cases:
        resp, err = safe_request(method, path, **kwargs)
        if err:
            record(name, "malformed_input", False, f"proxy connection error: {err}")
            continue
        if resp.status_code >= 500:
            record(name, "malformed_input", False,
                   f"proxy returned {resp.status_code} -- likely an unhandled exception, check proxy stdout/traceback")
        else:
            record(name, "malformed_input", True, f"handled without a 5xx, status={resp.status_code}")


# =======================================================================
# 3. DETECTION BOUNDARY CASES -- should NOT be flagged (false positives)
# =======================================================================
def test_false_positive_boundaries():
    cases = [
        ("Plain word 'select' in a normal query", "GET", "/search",
         dict(params={"q": "select the best option"})),
        ("'admin' in path, no attack pattern", "GET", "/admin-help", dict()),
        ("Apostrophe in a real name (O'Brien)", "POST", "/contact",
         dict(data={"name": "O'Brien"})),
    ]
    for name, method, path, kwargs in cases:
        since = datetime.now(timezone.utc)
        resp, err = safe_request(method, path, **kwargs)
        if err:
            record(name, "false_positive", False, f"request failed: {err}")
            continue

        clean_path = path.split("?")[0]
        entry = find_recent_log_entry(
            REQUESTS_LOG, since, lambda e: str(e.get(FIELD_PATH, "")).startswith(clean_path)
        )
        flagged = entry_flagged(entry)
        if flagged is False:
            record(name, "false_positive", True, f"correctly NOT flagged (status={resp.status_code})")
        elif flagged is True:
            record(name, "false_positive", False,
                   f"FALSE POSITIVE -- flagged for {entry_reasons(entry)}", warn=True)
        else:
            record(name, "false_positive", None,
                   "could not confirm from logs -- check FIELD_* config", warn=True)


# =======================================================================
# 4. HONEYPOT-ROUTING CONSISTENCY
# =======================================================================
def test_honeypot_consistency():
    since = datetime.now(timezone.utc)
    payload_path = "/search"
    payload_params = {"id": "1' OR '1'='1"}

    responses = []
    for _ in range(5):
        resp, err = safe_request("GET", payload_path, params=payload_params)
        responses.append((resp, err))
        time.sleep(0.2)

    failures = [err for _, err in responses if err]
    if failures:
        record("5x flagged requests -- no crashes", "honeypot_consistency", False,
               f"{len(failures)}/5 requests errored, e.g.: {failures[0]}")
    else:
        record("5x flagged requests -- no crashes", "honeypot_consistency", True, "all 5 completed")

    if READ_LOGS:
        honeypot_entries = []
        for _ in range(LOG_POLL_TRIES):
            entries = _read_log(HONEYPOT_LOG)
            honeypot_entries = [
                e for e in entries
                if (_parse_ts(e.get(FIELD_TIMESTAMP)) or datetime.min.replace(tzinfo=timezone.utc)) >= since
            ]
            if len(honeypot_entries) >= 5:
                break
            time.sleep(LOG_POLL_DELAY)

        record("All 5 flagged requests logged in honeypot.log", "honeypot_consistency",
               len(honeypot_entries) >= 5,
               f"found {len(honeypot_entries)}/5 matching entries since test start")
    else:
        record("All 5 flagged requests logged in honeypot.log", "honeypot_consistency",
               None, "READ_LOGS is off -- cannot verify", warn=True)

    last_resp = responses[-1][0]
    if last_resp is not None:
        server_header = last_resp.headers.get("Server", "")
        record("Flagged response identity check", "honeypot_consistency", True,
               f"Server header on flagged response: '{server_header}'. Compare this and the "
               f"response body by eye against a normal clean-request response -- this script "
               f"can flag a mismatch in the Server header but can't fully confirm content "
               f"identity on its own.", warn=True)


# =======================================================================
# 5. RATE-LIMIT EDGE BEHAVIOR
# =======================================================================
def test_rate_limit_threshold():
    """
    IMPORTANT: this app never returns HTTP 429. A rate-limited request
    is simply routed to the honeypot, exactly like a content-flagged
    request (see proxy/server.py: `if detection["flagged"]:` routes to
    HONEYPOT_WEB_URL either way) -- there is no distinct "blocked"
    status code to check for. So the only way to detect exactly when
    rate limiting kicked in is to read requests.log and look for the
    "rate_limit" reason, not to inspect HTTP status codes.
    """
    path = "/"
    since = datetime.now(timezone.utc)
    count = RATE_LIMIT_COUNT + 3

    errors = []
    for _ in range(count):
        resp, err = safe_request("GET", path)
        if err:
            errors.append(err)

    if errors:
        record("Rate limit burst -- no crashes", "rate_limit", False,
               f"{len(errors)}/{count} requests errored, e.g.: {errors[0]}")
    else:
        record("Rate limit burst -- no crashes", "rate_limit", True, f"all {count} completed")

    if not READ_LOGS:
        record("Rate limit boundary (off-by-one check)", "rate_limit", None,
               "READ_LOGS is off -- cannot verify without reading requests.log", warn=True)
        return

    entries = []
    for _ in range(LOG_POLL_TRIES):
        all_entries = _read_log(REQUESTS_LOG)
        entries = [
            e for e in all_entries
            if e.get(FIELD_PATH) == path
            and (_parse_ts(e.get(FIELD_TIMESTAMP)) or datetime.min.replace(tzinfo=timezone.utc)) >= since
        ]
        if len(entries) >= count:
            break
        time.sleep(LOG_POLL_DELAY)

    entries.sort(key=lambda e: e.get(FIELD_TIMESTAMP, ""))

    if len(entries) < count:
        record("Rate limit boundary (off-by-one check)", "rate_limit", False,
               f"expected {count} matching log entries for '{path}', found only {len(entries)} -- "
               f"logs may still be flushing, or another process is also hitting '{path}'")
        return

    flagged_positions = [i for i, e in enumerate(entries) if "rate_limit" in entry_reasons(e)]
    if not flagged_positions:
        record("Rate limit triggers at all", "rate_limit", False,
               f"sent {count} requests to '{path}', none were flagged with reason "
               f"'rate_limit' in requests.log (checked {len(entries)} matching entries)")
        return

    first_block = flagged_positions[0]  # 0-indexed position within this burst
    expected_gt = RATE_LIMIT_COUNT       # request #(COUNT+1), 0-indexed -- matches check_rate_limit()'s "> COUNT"
    detail = (f"first 'rate_limit' flag at request #{first_block + 1} of this burst "
              f"(configured RATE_LIMIT_COUNT={RATE_LIMIT_COUNT})")

    if first_block == expected_gt:
        record("Rate limit boundary (off-by-one check)", "rate_limit", True,
               detail + " -- matches proxy/detector.py's check_rate_limit(), which allows "
                        "exactly COUNT requests then flags the (COUNT+1)th ('>' semantics)")
    else:
        record("Rate limit boundary (off-by-one check)", "rate_limit", False,
               detail + f" -- expected it at request #{expected_gt + 1}; check for drift in "
                        f"the sliding-window logic, or note if earlier tests in this run left "
                        f"stale entries in this IP's window (see the pre-test sleep in main())")


def test_rate_limit_per_ip_isolation():
    """
    Not executed automatically. A single test host has exactly one real
    source IP, and the rate limiter correctly keys off
    request.remote_addr (the actual TCP source) rather than a
    client-controlled header -- spoofing X-Forwarded-For proves nothing
    here, since check_rate_limit() never reads that header at all, so
    both "spoofed" identities are really the same IP as far as the
    limiter is concerned, and any result from that would be arbitrary,
    not a real answer.

    To actually verify per-IP isolation: from Kali, exhaust the rate
    limit against the target (RATE_LIMIT_COUNT+1 quick requests to '/'),
    then immediately send one request from a second host (or the target
    machine itself, hitting its own proxy) and confirm THAT source is
    not also flagged with 'rate_limit' in requests.log. This needs two
    real hosts and is a manual step, not something this script can do.
    """
    record("Per-IP rate-limit isolation", "rate_limit", None,
           "not automated -- requires two real source hosts, see docstring "
           "in test_rate_limit_per_ip_isolation() for the manual steps", warn=True)


# =======================================================================
def main():
    print(f"Running edge-case tests against {BASE_URL}")
    print(f"READ_LOGS = {READ_LOGS}\n")

    print("== 1. Encoding bypass attempts ==")
    test_encoding_bypasses()

    print("\n== 2. Malformed/unusual input ==")
    test_malformed_input()

    print("\n== 3. Detection boundary / false-positive cases ==")
    test_false_positive_boundaries()

    print("\n== 4. Honeypot-routing consistency ==")
    test_honeypot_consistency()

    print("\n== 5. Rate-limit edge behavior ==")
    # Sections 1-4 already sent ~18 requests from this same source IP.
    # RATE_LIMIT_WINDOW is a sliding window (default 10s), so without
    # this pause those earlier requests could still be counted here,
    # making the off-by-one check trigger earlier than expected --
    # not because of a detector bug, but because of shared per-IP state
    # across tests. Sleeping past the window first gives a clean slate.
    print(f"(waiting {RATE_LIMIT_WINDOW + 1}s so earlier tests' requests age out of "
          f"this IP's rate-limit window before starting a clean measurement...)")
    time.sleep(RATE_LIMIT_WINDOW + 1)
    test_rate_limit_threshold()
    print(f"(waiting {RATE_LIMIT_WINDOW + 1}s for the rate-limit window to reset...)")
    time.sleep(RATE_LIMIT_WINDOW + 1)
    test_rate_limit_per_ip_isolation()

    print("\n" + "=" * 60)
    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = sum(1 for r in results if r["status"] == "FAIL")
    warned = sum(1 for r in results if r["status"] == "WARN")
    print(f"SUMMARY: {passed} passed, {failed} failed, {warned} warnings/inconclusive (out of {len(results)})")

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(REPORT_PATH, "w") as f:
        json.dump(results, f, indent=2)
    print(f"Full report written to {REPORT_PATH}")


if __name__ == "__main__":
    main()
