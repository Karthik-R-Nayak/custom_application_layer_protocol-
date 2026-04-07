"""
tls_server.py — TLS/TCP Control Channel Server
===============================================
Handles secure client authentication over TCP+TLS before UDP telemetry begins.


Wire protocol (newline-delimited JSON over TLS):
  Client → Server:
      {"action": "AUTH", "username": "sensor1", "password": "secret"}

  Server → Client (success):
      {"status": "OK", "session_id": 4, "udp_port": 9000}

  Server → Client (failure):
      {"status": "ERROR", "reason": "Invalid credentials"}

Usage:
    python tls_server.py [--host 0.0.0.0] [--tls-port 9443] [--udp-port 9000]
                         [--cert server.crt] [--key server.key]
"""

import ssl
import socket
import threading
import argparse
import logging
import json
import time

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [TLS-SERVER] %(levelname)s %(message)s',
    datefmt='%H:%M:%S',
)
log = logging.getLogger(__name__)

# ── Simple credential store ──────────────────────────────────────────────────
# Replace with a database / bcrypt hash check in production.
VALID_USERS: dict[str, str] = {
    "sensor1": "secret",
    "sensor2": "pass123",
    "admin":   "adminpass",
}


class TLSControlServer:
    """
    Listens for TLS/TCP connections on `tls_port`.
    Each connection is handled in its own daemon thread.
    """

    def __init__(self, host: str, tls_port: int, udp_port: int,
                 certfile: str, keyfile: str):
        self.host      = host
        self.tls_port  = tls_port
        self.udp_port  = udp_port
        self.certfile  = certfile
        self.keyfile   = keyfile

        # Session counter — also serves as msg_id for UDP layer.
        # Protected by a lock so multiple threads can increment safely.
        self._session_counter = 0
        self._counter_lock    = threading.Lock()

        # Tracks currently active sessions: session_id → client addr string
        self.active_sessions: dict[int, str] = {}
        self._sessions_lock = threading.Lock()

        # Build the SSL context once; reuse for every connection.
        self._ssl_ctx = self._build_ssl_context()

        # Raw TCP socket (SSL wrapping happens per-connection).
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.tls_port))
        self._sock.listen(16)   # backlog: max queued connections
        log.info(
            f"TLS control server listening on {host}:{tls_port}  "
            f"(UDP data port={udp_port})"
        )

    # ── SSL context ──────────────────────────────────────────────────────────

    def _build_ssl_context(self) -> ssl.SSLContext:
        """
        Create a server-side SSL context.

        ssl.PROTOCOL_TLS_SERVER automatically negotiates the highest mutually
        supported TLS version (TLS 1.2 or 1.3).  We explicitly disable older,
        insecure protocol versions.
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        # Disable SSLv2, SSLv3, TLS 1.0, TLS 1.1 — all considered insecure.
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        # Load server certificate and private key.
        # For a CA-signed cert, pass ca_certs= and set verify_mode accordingly.
        ctx.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)

        # We do NOT require client certificates here (one-way TLS).
        # For mutual TLS (mTLS) add:
        #   ctx.verify_mode = ssl.CERT_REQUIRED
        #   ctx.load_verify_locations(cafile='ca.crt')
        return ctx

    # ── Session ID allocation ────────────────────────────────────────────────

    def _allocate_session_id(self) -> int:
        """Thread-safe monotonically increasing session counter."""
        with self._counter_lock:
            self._session_counter += 1
            return self._session_counter

    # ── Per-connection handler ───────────────────────────────────────────────

    def _handle_client(self, raw_sock: socket.socket, addr: tuple):
        """
        Runs in a dedicated daemon thread for each incoming connection.

        Steps:
          1. Wrap the raw socket in TLS.
          2. Read the AUTH JSON message.
          3. Validate credentials.
          4. Allocate a session_id.
          5. Reply with session info.
          6. Close the TLS connection cleanly.
        """
        peer = f"{addr[0]}:{addr[1]}"
        log.info(f"Incoming connection from {peer}")
        tls_sock = None

        try:
            # ── Step 1: TLS handshake ────────────────────────────────────────
            # wrap_socket() performs the TLS handshake synchronously.
            # Raises ssl.SSLError on failure (bad cert, version mismatch, etc.)
            tls_sock = self._ssl_ctx.wrap_socket(raw_sock, server_side=True)
            log.info(
                f"TLS handshake OK with {peer}  "
                f"protocol={tls_sock.version()}  "
                f"cipher={tls_sock.cipher()[0]}"
            )

            # ── Step 2: Receive AUTH message ─────────────────────────────────
            # Use a file-like interface so we can read a full newline-terminated
            # JSON line without worrying about partial recv() reads.
            tls_file = tls_sock.makefile('r', encoding='utf-8')
            raw_line = tls_file.readline(4096).strip()
            if not raw_line:
                raise ValueError("Client closed connection before sending AUTH")

            try:
                msg = json.loads(raw_line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Malformed JSON: {exc}") from exc

            # ── Step 3: Validate ─────────────────────────────────────────────
            if msg.get("action") != "AUTH":
                raise ValueError(f"Expected action=AUTH, got {msg.get('action')!r}")

            username = msg.get("username", "")
            password = msg.get("password", "")
            if VALID_USERS.get(username) != password:
                # Send error response before raising so the client gets feedback.
                self._send_json(tls_sock, {
                    "status": "ERROR",
                    "reason": "Invalid credentials",
                })
                raise PermissionError(f"Auth failed for user {username!r} from {peer}")

            # ── Step 4: Allocate session ─────────────────────────────────────
            session_id = self._allocate_session_id()
            with self._sessions_lock:
                self.active_sessions[session_id] = peer
            log.info(f"Auth OK — user={username!r}  session_id={session_id}  peer={peer}")

            # ── Step 5: Send session info ────────────────────────────────────
            self._send_json(tls_sock, {
                "status":     "OK",
                "session_id": session_id,
                "udp_port":   self.udp_port,
            })

        except PermissionError as exc:
            log.warning(str(exc))

        except ssl.SSLError as exc:
            log.error(f"TLS handshake failed with {peer}: {exc}")

        except (ValueError, OSError) as exc:
            log.error(f"Protocol error with {peer}: {exc}")

        finally:
            # ── Step 6: Clean shutdown ───────────────────────────────────────
            if tls_sock is not None:
                try:
                    tls_sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                tls_sock.close()
            else:
                raw_sock.close()
            log.info(f"Connection to {peer} closed")

    # ── Helper ───────────────────────────────────────────────────────────────

    @staticmethod
    def _send_json(tls_sock: ssl.SSLSocket, obj: dict):
        """Send a JSON object followed by a newline over the TLS socket."""
        line = json.dumps(obj) + "\n"
        tls_sock.sendall(line.encode('utf-8'))

    # ── Main accept loop ─────────────────────────────────────────────────────

    def run(self):
        """Accept connections forever; each is dispatched to a daemon thread."""
        log.info("TLS control server ready — waiting for clients …")
        try:
            while True:
                try:
                    raw_sock, addr = self._sock.accept()
                except OSError:
                    # Socket was closed (e.g. KeyboardInterrupt path).
                    break

                t = threading.Thread(
                    target=self._handle_client,
                    args=(raw_sock, addr),
                    daemon=True,    # dies automatically when main thread exits
                    name=f"tls-handler-{addr[0]}:{addr[1]}",
                )
                t.start()

        except KeyboardInterrupt:
            log.info("KeyboardInterrupt — shutting down TLS server.")
        finally:
            self._sock.close()
            log.info("TLS control server stopped.")


# ── Entry point ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="TLS Control Channel Server"
    )
    parser.add_argument('--host',      default='0.0.0.0',    help='Bind address')
    parser.add_argument('--tls-port',  type=int, default=9443, help='TLS TCP port')
    parser.add_argument('--udp-port',  type=int, default=9000, help='UDP data port')
    parser.add_argument('--cert',      default='server.crt',  help='TLS certificate file')
    parser.add_argument('--key',       default='server.key',  help='TLS private key file')
    args = parser.parse_args()

    server = TLSControlServer(
        host     = args.host,
        tls_port = args.tls_port,
        udp_port = args.udp_port,
        certfile = args.cert,
        keyfile  = args.key,
    )
    server.run()


if __name__ == '__main__':
    main()
