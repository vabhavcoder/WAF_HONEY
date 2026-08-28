"""
Entry point for the read-only dashboard. Lives at the project root
like main.py and run_honeypot.py — not inside dashboard/ itself —
because running a module that's nested inside its own package
directly (e.g. `python3 dashboard/app.py`) only puts that directory
on sys.path, not the project root, so `from dashboard.log_reader
import read_log` can't resolve. Running from the root fixes that the
same way main.py already does for proxy/server.py.
"""

from dashboard.app import app
from proxy.config import DASHBOARD_PORT

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=DASHBOARD_PORT, threaded=True)
