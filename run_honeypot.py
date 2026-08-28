"""
Starts the full honeypot layer: the fake SSH banner service in a
background thread, and the fake web app in the foreground. Run this
as its own process, separate from main.py (the real proxy) and
dummy_backend/app.py (the real backend) — see README for the full
three-process setup.
"""

import threading

from honeypot.fake_web import app as web_app
from honeypot.fake_ssh import start_fake_ssh
from proxy.config import HONEYPOT_PORT

if __name__ == "__main__":
    threading.Thread(target=start_fake_ssh, daemon=True).start()

    print(f" * Fake web honeypot listening on 0.0.0.0:{HONEYPOT_PORT}")
    web_app.run(host="0.0.0.0", port=HONEYPOT_PORT, threaded=True)
