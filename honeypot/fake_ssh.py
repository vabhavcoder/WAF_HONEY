"""
Raw-socket fake SSH service. This does NOT implement the SSH protocol
or any cryptography — it sends a version-exchange banner (the one
real thing every SSH client/server sends in plaintext before the
protocol goes binary/encrypted), reads back whatever the other side
sends next, logs it, and closes. That's enough to look real to an
automated scanner or a human doing `nc host 2222` for a few seconds,
without building anything resembling actual SSH.
"""

import socket
import threading

from proxy.config import HONEYPOT_SSH_PORT, HONEYPOT_SSH_RECV_TIMEOUT
from honeypot.logger import log_honeypot_event

BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"

# Real SSH clients can send a large KEXINIT after the banner; cap what
# we'll read so a malicious/misbehaving client can't make us buffer
# unbounded data in memory.
MAX_RECV_BYTES = 8192


def handle_client(conn, addr):
    ip = addr[0]
    try:
        conn.settimeout(HONEYPOT_SSH_RECV_TIMEOUT)
        conn.sendall(BANNER)
        log_honeypot_event("ssh_connect", ip, {"port": HONEYPOT_SSH_PORT})

        try:
            data = conn.recv(MAX_RECV_BYTES)
        except socket.timeout:
            log_honeypot_event("ssh_input_timeout", ip, {})
            return

        if data:
            log_honeypot_event(
                "ssh_input",
                ip,
                {
                    # Both representations: decoded text is readable for
                    # the common case (a human typing at `nc`), hex is
                    # the lossless form for actual binary SSH protocol
                    # bytes (a real client's KEXINIT is not text).
                    "text": data.decode("utf-8", errors="replace"),
                    "hex": data.hex(),
                    "byte_count": len(data),
                },
            )
    except (ConnectionResetError, BrokenPipeError, OSError) as exc:
        # A client disconnecting mid-handshake is normal honeypot
        # traffic, not a bug — log it and move on rather than letting
        # the exception kill this connection's thread noisily.
        log_honeypot_event("ssh_connection_error", ip, {"error": str(exc)})
    finally:
        try:
            conn.close()
        except OSError:
            pass


def start_fake_ssh():
    """
    Bind, listen, and accept connections forever, handing each one to
    its own daemon thread so a slow/hanging client (deliberately or
    not) never blocks new connections from being accepted.
    """
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("0.0.0.0", HONEYPOT_SSH_PORT))
    server_sock.listen(128)

    print(f" * Fake SSH honeypot listening on 0.0.0.0:{HONEYPOT_SSH_PORT}")

    try:
        while True:
            conn, addr = server_sock.accept()
            threading.Thread(
                target=handle_client, args=(conn, addr), daemon=True
            ).start()
    finally:
        server_sock.close()
