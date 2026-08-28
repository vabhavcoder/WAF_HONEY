"""
Day 2 detection test script.

Run the dummy backend and the proxy first (see README), then:
    python3 test_detection.py

Sends: (a) a clean request, (b) SQLi in a query param, (c) XSS in a
POST body, (d) a burst of requests to trip rate limiting — then reads
back logs/requests.log and checks each got the expected `extra` flags.
"""

import json
import time
import requests

PROXY = "http://localhost:8080"
LOG_PATH = "logs/requests.log"


def tail_json(n=40):
    with open(LOG_PATH, "r", encoding="utf-8") as f:
        lines = f.readlines()[-n:]
    return [json.loads(line) for line in lines]


def check(label, condition):
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {label}")
    return condition


def main():
    results = []

    # (a) clean request
    r = requests.get(f"{PROXY}/")
    results.append(("clean request returns 200", r.status_code == 200))

    # (b) SQLi in query string — Day 3: flagged, so this now hits the
    # honeypot instead of the real backend. The honeypot doesn't define
    # a /search route, so it falls through to its own fake 404 — that's
    # correct decoy behavior, not a failure.
    r = requests.get(f"{PROXY}/search", params={"id": "1' OR '1'='1"})
    results.append(("SQLi request reaches proxy (routed to honeypot)", r.status_code in (200, 404)))

    # (c) XSS in POST body — Day 3: flagged, routed to honeypot's fake
    # /login, which always returns a fake "invalid credentials" 401.
    r = requests.post(
        f"{PROXY}/login",
        json={"comment": "<script>alert(1)</script>"},
    )
    results.append(("XSS request reaches proxy (routed to honeypot)", r.status_code in (200, 401)))

    # (d) rate limit burst — 25 rapid requests, threshold is 20/10s by default
    for _ in range(25):
        requests.get(f"{PROXY}/")

    time.sleep(0.3)  # let log writes flush

    log = tail_json(50)

    clean_entries = [e for e in log if e["path"] == "/" and not e.get("extra", {}).get("reasons")]
    sqli_entries = [e for e in log if e["path"] == "/search" and "sqli_tautology_quoted" in e.get("extra", {}).get("reasons", [])]
    xss_entries = [e for e in log if e["path"] == "/login" and "xss_script_tag" in e.get("extra", {}).get("reasons", [])]
    rate_limited = [e for e in log if "rate_limit" in e.get("extra", {}).get("reasons", [])]

    results.append(("at least one clean, unflagged '/' entry logged", len(clean_entries) >= 1))
    results.append(("SQLi entry flagged with sqli_tautology_quoted", len(sqli_entries) >= 1))
    results.append(("XSS entry flagged with xss_script_tag", len(xss_entries) >= 1))
    results.append(("at least one request flagged rate_limit", len(rate_limited) >= 1))
    results.append(("SQLi entry routed_to honeypot", any(e.get("extra", {}).get("routed_to") == "honeypot" for e in sqli_entries)))
    results.append(("XSS entry routed_to honeypot", any(e.get("extra", {}).get("routed_to") == "honeypot" for e in xss_entries)))
    results.append(("clean entry routed_to backend", all(e.get("extra", {}).get("routed_to") == "backend" for e in clean_entries)))

    print()
    all_pass = True
    for label, cond in results:
        all_pass &= check(label, cond)

    print()
    print("Sample flagged log lines:")
    for e in (sqli_entries[:1] + xss_entries[:1] + rate_limited[:1]):
        print(" ", json.dumps(e))

    print()
    print("ALL PASS" if all_pass else "SOME FAILED")


if __name__ == "__main__":
    main()
