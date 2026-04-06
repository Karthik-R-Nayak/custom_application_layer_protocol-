"""
tls_client.py — TLS/TCP Control Channel Client
===============================================
Handles the secure handshake with the TLS control server BEFORE the
UDP telemetry session begins.

Responsibilities:
  1. Open a TCP connection to the TLS control server.
  2. Perform the TLS handshake (certificate verification optional).
  3. Send a JSON AUTH message with username + password.
  4. Receive and return the session_id and udp_port from the server.
  5. Close the TLS connection — UDP takes over from here.

This module is intentionally stateless: call `tls_authenticate()` once,
get back a SessionInfo, then pass session_id to ReliableUDPClient.

Wire protocol (same as tls_server.py):
  →  {"action": "AUTH", "username": "sensor1", "password": "secret"}
  ←  {"status": "OK",   "session_id": 4, "udp_port": 9000}
  ←  {"status": "ERROR", "reason": "..."}   (on failure)

Usage (standalone test):
    python tls_client.py [--host 127.0.0.1] [--tls-port 9443]
                         [--user sensor1] [--password secret]
                         [--cert server.crt]
"""

import ssl
import socket
import json
import logging
import argparse
from dataclasses import dataclass

log = logging.getLogger(__name__)


# ── Return type ───────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class SessionInfo:
    """
    Everything the UDP layer needs after a successful TLS handshake.

    Attributes:
        session_id  int   — use as msg_id in ReliableUDPClient
        udp_port    int   — UDP port to send telemetry to
    """
    session_id: int
    udp_port:   int


# ── Custom exceptions ─────────────────────────────────────────────────────────

class TLSAuthError(Exception):
    """Raised when the server rejects our credentials."""

class TLSHandshakeError(Exception):
    """Raised when the TLS layer itself fails (bad cert, timeout, etc.)."""


# ── Core function ─────────────────────────────────────────────────────────────

def tls_authenticate(
    host:       str,
    tls_port:   int,
    username:   str,
    password:   str,
    cafile:     str | None = None,   # path to CA cert for server verification
    timeout:    float      = 5.0,    # connect + handshake timeout in seconds
) -> SessionInfo:
    """
    Perform the full TLS control-channel handshake.

    Parameters
    ----------
    host       : TLS server hostname or IP
    tls_port   : TLS server TCP port
    username   : credential to send in the AUTH message
    password   : credential to send in the AUTH message
    cafile     : path to CA certificate for server verification.
                 Pass None to disable certificate verification
                 (acceptable for development / self-signed certs).
    timeout    : socket-level timeout for connect + handshake (seconds)

    Returns
    -------
    SessionInfo with session_id and udp_port

    Raises
    ------
    TLSHandshakeError  if the TLS layer fails
    TLSAuthError       if the server rejects credentials
    OSError            if the TCP connection itself cannot be established
    """

    # ── Step 1: Build SSL context ────────────────────────────────────────────
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    if cafile:
        # Verify the server certificate against the provided CA.
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cafile=cafile)
        log.debug(f"Certificate verification enabled using CA: {cafile}")
    else:
        # Development / self-signed: skip verification.
        # In production always provide a cafile.
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        log.warning(
            "TLS certificate verification is DISABLED. "
            "Provide --cert <ca.crt> for production use."
        )

    # ── Step 2: Open TCP connection and wrap with TLS ────────────────────────
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_sock.settimeout(timeout)

    try:
        raw_sock.connect((host, tls_port))
        log.debug(f"TCP connected to {host}:{tls_port}")
    except OSError as exc:
        raw_sock.close()
        raise OSError(f"Cannot connect to TLS server at {host}:{tls_port}: {exc}") from exc

    try:
        # wrap_socket() performs the TLS handshake.
        # server_hostname is required for SNI even if we're not verifying the cert.
        tls_sock = ctx.wrap_socket(raw_sock, server_hostname=host)
        log.info(
            f"TLS handshake OK  "
            f"protocol={tls_sock.version()}  "
            f"cipher={tls_sock.cipher()[0]}"
        )
    except ssl.SSLError as exc:
        raw_sock.close()
        raise TLSHandshakeError(
            f"TLS handshake with {host}:{tls_port} failed: {exc}"
        ) from exc

    # ── Steps 3–5 wrapped in try/finally to guarantee socket closure ─────────
    try:
        # ── Step 3: Send AUTH message ────────────────────────────────────────
        auth_msg = {
            "action":   "AUTH",
            "username": username,
            "password": password,
        }
        _send_json(tls_sock, auth_msg)
        log.debug(f"AUTH sent for user {username!r}")

        # ── Step 4: Receive server reply ─────────────────────────────────────
        tls_file = tls_sock.makefile('r', encoding='utf-8')
        raw_line = tls_file.readline(4096).strip()
        if not raw_line:
            raise TLSHandshakeError("Server closed connection without responding")

        try:
            reply = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            raise TLSHandshakeError(f"Server sent malformed JSON: {exc}") from exc

        # ── Step 5: Parse reply ──────────────────────────────────────────────
        status = reply.get("status")

        if status == "OK":
            try:
                session_id = int(reply["session_id"])
                udp_port   = int(reply["udp_port"])
            except (KeyError, ValueError) as exc:
                raise TLSHandshakeError(
                    f"Server OK reply missing fields: {reply}"
                ) from exc

            log.info(
                f"Session established — "
                f"session_id={session_id}  udp_port={udp_port}"
            )
            return SessionInfo(session_id=session_id, udp_port=udp_port)

        elif status == "ERROR":
            reason = reply.get("reason", "unknown")
            raise TLSAuthError(f"Server rejected auth: {reason}")

        else:
            raise TLSHandshakeError(f"Unexpected server reply: {reply}")

    finally:
        # ── Step 6: Clean shutdown of TLS connection ─────────────────────────
        # The control channel is done; UDP takes over from here.
        try:
            tls_sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        tls_sock.close()
        log.debug("TLS control channel closed")


# ── Helper ────────────────────────────────────────────────────────────────────

def _send_json(tls_sock: ssl.SSLSocket, obj: dict):
    """Encode obj as JSON + newline and send over the TLS socket."""
    line = json.dumps(obj) + "\n"
    tls_sock.sendall(line.encode('utf-8'))


# ── Standalone test entry point ───────────────────────────────────────────────

def main():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [TLS-CLIENT] %(levelname)s %(message)s',
        datefmt='%H:%M:%S',
    )

    parser = argparse.ArgumentParser(
        description="TLS Control Channel Client — standalone test"
    )
    parser.add_argument('--host',     default='127.0.0.1', help='TLS server host')
    parser.add_argument('--tls-port', type=int, default=9443, help='TLS server port')
    parser.add_argument('--user',     default='sensor1',   help='Username')
    parser.add_argument('--password', default='secret',    help='Password')
    parser.add_argument('--cert',     default=None,
                        help='CA certificate for server verification (omit to skip)')
    args = parser.parse_args()

    try:
        info = tls_authenticate(
            host     = args.host,
            tls_port = args.tls_port,
            username = args.user,
            password = args.password,
            cafile   = args.cert,
        )
        print(f"\n✓ TLS auth successful!")
        print(f"  session_id = {info.session_id}")
        print(f"  udp_port   = {info.udp_port}")
        print(f"\nPass session_id={info.session_id} as msg_id to ReliableUDPClient.\n")
    except TLSAuthError as exc:
        print(f"\n✗ Authentication failed: {exc}\n")
    except TLSHandshakeError as exc:
        print(f"\n✗ TLS error: {exc}\n")
    except OSError as exc:
        print(f"\n✗ Connection error: {exc}\n")


if __name__ == '__main__':
    main()
