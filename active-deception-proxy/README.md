# Active Deception Proxy — Day 1

Day 1 implements only a modular HTTP reverse-proxy core. It forwards requests
to a configured backend and writes one JSON object per request to a local log.
Detection, honeypot routing, and rate limiting are deliberately out of scope.

## Requirements

Python 3.10 or later is required. On Ubuntu, create and activate a virtual
environment, then install the dependencies:

```bash
cd active-deception-proxy
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run the demo

In the first terminal, start the dummy backend on port 5000:

```bash
cd active-deception-proxy
source .venv/bin/activate
python dummy_backend/app.py
```

In a second terminal, start the proxy on port 8080:

```bash
cd active-deception-proxy
source .venv/bin/activate
python main.py
```

Test the end-to-end path from a third terminal:

```bash
curl -i http://localhost:8080/
curl -i 'http://localhost:8080/search?q=proxy-test'
curl -i -X POST -d 'username=student' http://localhost:8080/login
```

The first command returns the dummy backend JSON response. Each request appends
a JSON line to `logs/requests.log`, for example:

```json
{"timestamp":"2026-08-01T00:00:00+00:00","ip":"127.0.0.1","method":"GET","path":"/?","status":200}
```

## Configuration

Defaults are in `proxy/config.py`. Override them at runtime with environment
variables: `BACKEND_URL`, `LISTEN_PORT`, `LOG_PATH`, and `REQUEST_TIMEOUT`
(seconds). For example:

```bash
BACKEND_URL=http://localhost:5000 LISTEN_PORT=8080 python main.py
```

The `proxy()` function has a marked Day 2 extension point before the backend
request; `log_request(..., extra=...)` is ready for detection metadata.
