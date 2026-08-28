# Active Deception Proxy — Day 1–4

Custom WAF/reverse-proxy built from scratch.
- **Day 1**: transparent HTTP passthrough + structured JSON-lines request logging.
- **Day 2**: hand-written SQLi/XSS/path-traversal detection + per-IP rate
  limiting. Detection classifies and logs.
- **Day 3**: flagged requests are routed to a fake honeypot layer (a
  decoy web app + a fake SSH banner service) instead of the real
  backend. Nothing the honeypot "accepts" is ever real; it's logged
  and discarded.
- **Day 4**: a read-only dashboard that parses `logs/requests.log` and
  `logs/honeypot.log` and renders summary stats, a live flagged-request
  timeline, the honeypot interaction log, and a per-IP drill-down. It
  never writes to a log or touches proxy/detector/honeypot behavior.

## Structure

```
active-deception-proxy/
├── proxy/
│   ├── __init__.py
│   ├── server.py        # reverse proxy + detection + honeypot routing
│   ├── config.py         # all ports/URLs/log paths/detection rules
│   ├── logger.py         # JSON-lines logger for real proxy traffic
│   └── detector.py       # SQLi/XSS/traversal patterns + rate limiting
├── honeypot/
│   ├── __init__.py
│   ├── fake_web.py        # decoy /, /login, /admin — never real auth
│   ├── fake_ssh.py         # raw-socket fake SSH banner, no real SSH protocol
│   └── logger.py           # JSON-lines logger for honeypot traffic
├── dashboard/
│   ├── __init__.py
│   ├── app.py               # read-only Flask views over the two logs
│   ├── log_reader.py         # safe JSON-lines reading, shared by all views
│   └── templates/
│       ├── base.html          # shared nav + embedded CSS
│       ├── summary.html       # / — totals + top IPs
│       ├── timeline.html      # /timeline — flagged requests, live
│       ├── honeypot.html      # /honeypot — honeypot interactions
│       └── ip_detail.html     # /ip/<ip> — everything from one source
├── dummy_backend/
│   └── app.py             # test Flask app standing in for the real app
├── logs/
│   ├── requests.log       # main proxy traffic (created at runtime)
│   └── honeypot.log        # honeypot interactions (created at runtime)
├── main.py                 # entry point: the real proxy (port 8080)
├── run_honeypot.py          # entry point: fake_web.py + fake_ssh.py together
├── run_dashboard.py          # entry point: the dashboard (port 8090)
├── test_detection.py       # Day 2/3: end-to-end detection + routing test
├── requirements.txt
└── README.md
```

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Run

Four terminals, all from the project root, all with the venv active.

**Terminal 1 — dummy backend (the "real app"):**
```bash
python3 dummy_backend/app.py
```
Runs on `http://localhost:5000`.

**Terminal 2 — honeypot layer (fake web app + fake SSH):**
```bash
python3 run_honeypot.py
```
Fake web app on `http://localhost:5001`, fake SSH on `localhost:2222`.

**Terminal 3 — the proxy:**
```bash
python3 main.py
```
Runs on `http://localhost:8080`. Clean requests go to the dummy backend
(:5000); flagged requests go to the honeypot's fake web app (:5001) instead.

**Terminal 4 — the dashboard:**
```bash
python3 run_dashboard.py
```
Runs on `http://localhost:8090`. Read-only — open it in a browser once
the other three processes have generated some traffic.

Run `python3 run_dashboard.py` from the project root, not
`python3 dashboard/app.py` directly — the latter fails with
`ModuleNotFoundError: No module named 'dashboard'` because a script
nested inside its own package only gets its own directory on
`sys.path`, not the project root.

## Test

```bash
# 1. Clean request → real backend
curl http://localhost:8080/
# logs/requests.log gets an entry with "routed_to": "backend"

# 2. Flagged request (SQLi) → honeypot instead
curl -G "http://localhost:8080/search" --data-urlencode "id=1' OR '1'='1"
# logs/requests.log: "flagged": true, "routed_to": "honeypot"
# logs/honeypot.log: a matching entry for the same request

# 3. Flagged login attempt → honeypot's fake /login (never real auth)
curl -X POST "http://localhost:8080/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "username=admin' OR '1'='1" \
  --data-urlencode "password=whatever"
# always returns a fake "Invalid username or password" page — the
# credentials are logged in logs/honeypot.log and never checked
# against anything real

# 4. Fake SSH banner
nc localhost 2222
# should immediately show: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
# type anything and press enter, then Ctrl-C — logs/honeypot.log gets
# an ssh_input entry with both a decoded-text and hex view of what you sent

# Backend-down handling still works as in Day 1:
# kill dummy_backend, then curl http://localhost:8080/ → HTTP 502
```

Automated version of steps 1–3 (plus a rate-limit burst):
```bash
python3 test_detection.py
```

## Config

Override via environment variables instead of editing `proxy/config.py`:

| Variable                    | Default                  |
|-------------------------------|---------------------------|
| `ADP_BACKEND_URL`            | `http://localhost:5000`  |
| `ADP_LISTEN_PORT`            | `8080`                   |
| `ADP_LOG_PATH`               | `logs/requests.log`      |
| `ADP_BACKEND_TIMEOUT`        | `5` (seconds)             |
| `ADP_RATE_LIMIT_COUNT`       | `20` (requests)           |
| `ADP_RATE_LIMIT_WINDOW`      | `10` (seconds)            |
| `ADP_HONEYPOT_PORT`          | `5001`                   |
| `ADP_HONEYPOT_WEB_URL`       | `http://localhost:5001`  |
| `ADP_HONEYPOT_SSH_PORT`      | `2222`                   |
| `ADP_HONEYPOT_LOG_PATH`      | `logs/honeypot.log`      |
| `ADP_HONEYPOT_SSH_RECV_TIMEOUT` | `15` (seconds)         |

All SQLi/XSS/path-traversal regex patterns live in `proxy/config.py`
as named `(name, pattern, severity)` tuples (`SQLI_PATTERNS`,
`XSS_PATTERNS`, `TRAVERSAL_PATTERNS`) — tune or add a rule there
without touching `proxy/detector.py`.

## Notes on the honeypot layer

- `honeypot/fake_web.py` never checks submitted credentials against
  anything, never grants `/admin` access, and never touches the real
  backend. A single `before_request` hook logs full detail (method,
  path, headers, query string, body, parsed params) for every request
  to any route, so a new route added later is covered automatically.
- Routes the honeypot doesn't specifically define (e.g. `/search`,
  which only exists on the real dummy backend) still resolve to the
  honeypot's own generic fake 404 — still logged, still fake, no
  crash or fallthrough to the real backend.
- `honeypot/fake_ssh.py` implements no real SSH protocol or crypto —
  it sends the plaintext version-exchange banner every SSH
  implementation sends first, reads back up to 8KB of whatever the
  client sends next (capped, so a client can't make it buffer
  unbounded data), logs both a decoded-text and a hex view of those
  bytes, and closes. Each connection is handled on its own thread so
  one slow/hanging client can't block new connections.

## Extension points for Day 4+

- `proxy/server.py`: a comment block right before the detection call
  marks where a persistent known-bad-IP list (something that survives
  a process restart) could skip `inspect_request()` entirely and route
  straight to the honeypot. Currently every request is re-inspected
  from scratch — no cross-request memory beyond the in-process rate
  limiter.

## Dashboard views (Day 4)

| Route | Shows |
|---|---|
| `/` | Total requests, total flagged, total honeypot hits, top 5 source IPs by request count, top 5 by flagged count. Auto-refreshes every 7s. |
| `/timeline` | Every flagged request from `requests.log`, most recent first — timestamp, IP, method, path, matched reasons, severity, and whether it was routed to the honeypot or the real backend. Auto-refreshes every 7s. |
| `/honeypot` | Every entry from `honeypot.log`, most recent first — timestamp, IP, service (web/ssh), event type, and a human-readable summary (submitted credentials for login attempts, decoded text for SSH input). |
| `/ip/<ip>` | Every entry from both logs for one IP, merged and sorted most-recent-first, with per-IP totals at the top. 404s if the IP has no entries in either log. |

The dashboard only reads `LOG_PATH` and `HONEYPOT_LOG_PATH` via
`dashboard/log_reader.py::read_log()` — it never writes to a log,
imports `proxy.detector`/`proxy.server`/`honeypot.*` logic, or has any
way to change what those processes do. `read_log()` is defensive by
design: a missing log file returns an empty list rather than erroring
(useful before the proxy/honeypot have generated any traffic yet), and
a malformed JSON line (e.g. read mid-write by another process) is
skipped rather than crashing the page — verified under load by hitting
`/` and `/timeline` continuously while 40 concurrent requests were
being written to `requests.log`.

No authentication, no log rotation, and no write-back (blocking an IP
from the dashboard) — all explicitly out of scope for this project.
