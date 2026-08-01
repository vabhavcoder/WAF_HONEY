from proxy.config import LISTEN_PORT
from proxy.server import app


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=LISTEN_PORT, debug=False)
