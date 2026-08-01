"""Runtime configuration for the reverse proxy.

Environment variables make the proxy easy to configure without code changes.
"""
import os

BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:5000").rstrip("/")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "8080"))
LOG_PATH = os.getenv("LOG_PATH", "logs/requests.log")
REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "10"))
