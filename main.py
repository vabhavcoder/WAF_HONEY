"""
Entry point. Starts the reverse proxy on LISTEN_PORT.
Run the dummy backend (dummy_backend/app.py) separately first — this
process only proxies, it does not serve any application logic itself.
"""

from proxy.server import app
from proxy.config import LISTEN_PORT

if __name__ == "__main__":
    # threaded=True: without it, Flask's dev server handles one request
    # at a time, so a slow/hanging backend call would stall every other
    # client. Fine for a dev server used in this mini-project; a real
    # deployment would sit behind gunicorn/waitress instead.
    app.run(host="0.0.0.0", port=LISTEN_PORT, threaded=True)
