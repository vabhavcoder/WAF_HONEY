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
from datetime import datetime

import requests

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
def test_encoding_bypasses():
    cases = [
        ("URL-encoded SQLi", "GET", "/search", {"id": "1%27%20OR%20%271%27=%271"}, None),
        ("Double-encoded XSS", "GET", "/search", {"q": "%253Cscript%253E"}, None),
        ("Mixed-case UNION SELECT", "GET", "/search", {"id": "1 UnIoN SeLeCt password"}, None),
        ("Mixed-case script tag", "POST", "/comment", None, {"text": "<ScRiPt>alert(1)</ScRiPt>"}),
    ]
    for name, method, path, params, data in cases:
        since = datetime.utcnow()
        if params is not None:
            resp, err = safe_request(method, path, params=params)
        else:
            resp, err = safe_request(method, path, data=data)
        if err:
            record(name, "encoding_bypass", False, f"request failed: {err}")
            continue

        entry = find_recent_log_entry(
            REQUESTS_LOG, since, lambda e: str(e.get(FIELD_PATH, "")).startswith(path)
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
        since = datetime.utcnow()
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
    since = datetime.utcnow()
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
                if (_parse_ts(e.get(FIELD_TIMESTAMP)) or datetime.min) >= since
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
    path = "/"
    statuses = []
    for _ in range(RATE_LIMIT_COUNT + 2):
        resp, err = safe_request("GET", path)
        statuses.append(None if err else resp.status_code)

    blocked_indices = [i for i, s in enumerate(statuses) if s == 429]
    if not blocked_indices:
        record("Rate limit triggers at all", "rate_limit", False,
               f"sent {RATE_LIMIT_COUNT + 2} requests, none returned 429 -- "
               f"statuses seen: {statuses}. Either the limit wasn't reached, or "
               f"rate limiting isn't wired into this route/response path.")
        return

    first_block = blocked_indices[0]
    expected_at_ge = RATE_LIMIT_COUNT       # 0-indexed: request #(COUNT+1) blocked -> uses '>'
    expected_at_gt = RATE_LIMIT_COUNT - 1   # 0-indexed: request #COUNT blocked -> uses '>='
    detail = f"first 429 at request #{first_block + 1} (configured limit={RATE_LIMIT_COUNT}); statuses={statuses}"

    if first_block == expected_at_ge:
        record("Rate limit boundary (off-by-one check)", "rate_limit", True,
               detail + " -- limiter allows exactly N requests then blocks (uses '>' semantics)")
    elif first_block == expected_at_gt:
        record("Rate limit boundary (off-by-one check)", "rate_limit", True,
               detail + " -- limiter blocks on the Nth request itself (uses '>=' semantics)")
    else:
        record("Rate limit boundary (off-by-one check)", "rate_limit", False,
               detail + " -- blocked at an unexpected position, check the sliding-window logic")


def test_rate_limit_per_ip_isolation():
    """
    IMPORTANT LIMITATION: a single machine only has one real source IP.
    This test spoofs X-Forwarded-For to approximate two different
    clients. It only proves anything if your proxy's rate limiter
    actually reads and trusts that header as the client identity.

    If your limiter correctly keys off request.remote_addr (the real
    TCP source, which is the recommended/secure approach and NOT
    something a client can spoof), then BOTH "ip_a" and "ip_b" here are
    really the same source as far as the limiter is concerned, and this
    test cannot distinguish "isolated correctly" from "shared correctly
    because they're actually the same IP". Treat a WARN result here as
    inconclusive, not as a pass -- for a real answer, run this same
    scenario from two separate VMs (e.g. Kali + your own machine) hitting
    the target at the same time.
    """
    ip_a = "10.10.10.101"
    ip_b = "10.10.10.102"

    for _ in range(RATE_LIMIT_COUNT + 1):
        safe_request("GET", "/", headers={"X-Forwarded-For": ip_a})

    resp_a, err_a = safe_request("GET", "/", headers={"X-Forwarded-For": ip_a})
    resp_b, err_b = safe_request("GET", "/", headers={"X-Forwarded-For": ip_b})

    status_a = None if err_a else resp_a.status_code
    status_b = None if err_b else resp_b.status_code

    record("Per-IP rate-limit isolation (X-Forwarded-For approximation)", "rate_limit",
           None,
           f"status_a={status_a}, status_b={status_b}. This test is INCONCLUSIVE by "
           f"itself -- see the docstring in test_rate_limit_per_ip_isolation() for why. "
           f"Re-run manually from two separate hosts for a real answer.",
           warn=True)


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
