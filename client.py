"""
client.py — Reliable UDP Telemetry Client  (TLS-integrated)
============================================================
Sends telemetry data with sequence numbers, ACK tracking, and retransmission.



"""

import socket
import argparse
import logging
import time
import json
import random
import threading
from dataclasses import dataclass, field
from protocol import (
    build_packet, parse_packet,
    PKT_DATA, PKT_ACK, PKT_NACK, PKT_HELLO, PKT_BYE,
    FLAG_RETX, FLAG_LAST,
    DEFAULT_TIMEOUT, MAX_RETRANSMITS, WINDOW_SIZE,
    MAX_PACKET_SIZE,
)

# ── TLS EXTENSION: import the control-channel helper ────────────────────────
# Only this import and the connect() / main() changes are new.
# Everything else in this file is identical to the non-TLS version.
from tls_client import tls_authenticate, TLSAuthError, TLSHandshakeError

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [CLIENT] %(levelname)s %(message)s',
    datefmt='%H:%M:%S',
)
log = logging.getLogger(__name__)


# ── PendingPacket (unchanged) ────────────────────────────────────────────────

@dataclass
class PendingPacket:
    """A packet awaiting acknowledgment."""
    msg_id:     int
    seq:        int
    payload:    bytes   # original payload, kept for NACK retransmit rebuild
    flags:      int     # original flags (without FLAG_RETX)
    raw:        bytes   # wire bytes of the most-recently-sent version
    send_time:  float = field(default_factory=time.time)
    retx_count: int   = 0
    acked:      bool  = False


# ── ReliableUDPClient ────────────────────────────────────────────────────────

class ReliableUDPClient:
    def __init__(self, host: str, port: int,
                 timeout: float = DEFAULT_TIMEOUT,
                 max_retx: int  = MAX_RETRANSMITS):
        self.server_addr = (host, port)
        self.timeout     = timeout
        self.max_retx    = max_retx
        self.msg_id      = 0    # overwritten by connect() from TLS session_id
        self.seq         = 0
        self.pending: dict[int, PendingPacket] = {}
        self.lock        = threading.Lock()
        self._stop_event = threading.Event()

        self.stats = {
            'sent':        0,
            'acked':       0,
            'retransmits': 0,
            'dropped':     0,
        }

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(0.1)

    # ── Internal helpers (unchanged) ─────────────────────────────────────────

    def _next_seq(self) -> int:
        s = self.seq
        self.seq += 1
        return s

    def _send_raw(self, raw: bytes):
        self.sock.sendto(raw, self.server_addr)

    def _build_data_pkt(self, seq: int, payload: bytes, flags: int = 0) -> bytes:
        return build_packet(self.msg_id, PKT_DATA, seq, payload, flags)

    # ── ACK receiver (unchanged) ─────────────────────────────────────────────

    def _ack_receiver(self):
        while not self._stop_event.is_set():
            try:
                raw, _ = self.sock.recvfrom(MAX_PACKET_SIZE + 16)
            except socket.timeout:
                continue
            except OSError:
                break

            try:
                msg_id, pkt_type, flags, seq, _ = parse_packet(raw)
            except ValueError as e:
                log.warning(f"Bad response: {e}")
                continue

            if pkt_type == PKT_ACK:
                with self.lock:
                    if seq in self.pending and not self.pending[seq].acked:
                        self.pending[seq].acked = True
                        self.stats['acked'] += 1
                        log.debug(f"ACK  seq={seq}")

            elif pkt_type == PKT_NACK:
                log.info(f"NACK received for seq={seq} — retransmitting")
                with self.lock:
                    if seq in self.pending and not self.pending[seq].acked:
                        pkt     = self.pending[seq]
                        retx_raw = self._build_data_pkt(
                            seq, pkt.payload, pkt.flags | FLAG_RETX
                        )
                        pkt.raw        = retx_raw
                        pkt.retx_count += 1
                        pkt.send_time  = time.time()
                        self.stats['retransmits'] += 1
                        self._send_raw(retx_raw)

    # ── Timeout watchdog (unchanged) ─────────────────────────────────────────

    def _timeout_watchdog(self):
        while not self._stop_event.is_set():
            time.sleep(0.05)
            now = time.time()
            with self.lock:
                for seq, pkt in list(self.pending.items()):
                    if pkt.acked:
                        continue
                    if now - pkt.send_time >= self.timeout:
                        if pkt.retx_count >= self.max_retx:
                            log.error(f"DROPPED seq={seq} after {self.max_retx} retransmits")
                            pkt.acked = True
                            self.stats['dropped'] += 1
                        else:
                            log.warning(
                                f"TIMEOUT seq={seq} "
                                f"(attempt {pkt.retx_count+1}/{self.max_retx})"
                            )
                            retx_raw = self._build_data_pkt(
                                seq, pkt.payload, pkt.flags | FLAG_RETX
                            )
                            pkt.raw        = retx_raw
                            pkt.retx_count += 1
                            pkt.send_time  = now
                            self.stats['retransmits'] += 1
                            self._send_raw(retx_raw)

    # ── Window management (unchanged) ────────────────────────────────────────

    def _window_full(self) -> bool:
        with self.lock:
            unacked = sum(1 for p in self.pending.values() if not p.acked)
            return unacked >= WINDOW_SIZE

    def _wait_for_window(self):
        while self._window_full():
            time.sleep(0.01)

    # ── connect() — only method changed for TLS ──────────────────────────────

    def connect(self, session_id: int | None = None):
        """
        Initiate the UDP session.

        TLS EXTENSION:
          `session_id` comes from tls_authenticate() in tls_client.py.
          If None (--no-tls mode), we fall back to auto-increment as before.
          Either way, msg_id is set exactly once here and the rest of the UDP
          logic is completely unchanged.

        Parameters
        ----------
        session_id : int | None
            The session_id returned by tls_authenticate().
            Pass None to use the internal auto-increment (dev / --no-tls mode).
        """
        # ── TLS EXTENSION: one new if/else to set msg_id ─────────────────────
        if session_id is not None:
            self.msg_id = session_id   # use server-assigned, globally unique ID
            log.info(
                f"UDP session starting with TLS-assigned "
                f"session_id={self.msg_id}  server={self.server_addr}"
            )
        else:
            self.msg_id += 1           # fallback: local auto-increment
            log.info(
                f"UDP session starting (no TLS)  "
                f"msg_id={self.msg_id}  server={self.server_addr}"
            )
        # ── Everything below is identical to the original connect() ──────────

        self.seq = 0
        hello = build_packet(self.msg_id, PKT_HELLO, 0)
        self._send_raw(hello)
        try:
            raw, _ = self.sock.recvfrom(MAX_PACKET_SIZE + 16)
            parse_packet(raw)
            log.info("HELLO acknowledged — UDP session started")
        except (socket.timeout, ValueError):
            log.warning("No HELLO ACK — proceeding anyway")

        self._stop_event.clear()
        self._ack_thread  = threading.Thread(target=self._ack_receiver,     daemon=True)
        self._retx_thread = threading.Thread(target=self._timeout_watchdog,  daemon=True)
        self._ack_thread.start()
        self._retx_thread.start()

    # ── send_telemetry, flush, disconnect, print_stats (all unchanged) ────────

    def send_telemetry(self, data: dict, last: bool = False) -> int:
        """Serialise `data` to JSON and send as a DATA packet."""
        self._wait_for_window()

        payload = json.dumps(data).encode('utf-8')
        if len(payload) > 512:
            raise ValueError(f"Payload too large: {len(payload)} bytes")

        flags = FLAG_LAST if last else 0
        seq   = self._next_seq()
        raw   = self._build_data_pkt(seq, payload, flags)

        pkt = PendingPacket(
            msg_id=self.msg_id, seq=seq,
            payload=payload, flags=flags, raw=raw,
        )
        with self.lock:
            self.pending[seq] = pkt
            self.stats['sent'] += 1

        self._send_raw(raw)
        log.info(f"SENT seq={seq:04d}  {data}")
        return seq

    def flush(self, timeout: float = 10.0) -> bool:
        """Block until all pending packets are ACKed or permanently dropped."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self.lock:
                unacked = sum(1 for p in self.pending.values() if not p.acked)
            if unacked == 0:
                break
            time.sleep(0.05)
        else:
            log.warning("flush() timed out with unacked packets remaining")

        with self.lock:
            dropped = self.stats['dropped']

        if dropped:
            log.warning(f"Session ended with {dropped} permanently dropped packet(s)")
            return False
        return True

    def disconnect(self):
        """Send BYE and tear down."""
        bye = build_packet(self.msg_id, PKT_BYE, self.seq)
        self._send_raw(bye)
        log.info("BYE sent")
        self._stop_event.set()
        self.sock.close()

    def print_stats(self):
        s = self.stats
        delivery = (s['acked'] / s['sent'] * 100) if s['sent'] else 0
        log.info(
            f"── Session stats ──────────────────────────\n"
            f"  Packets sent       : {s['sent']}\n"
            f"  Acknowledged       : {s['acked']}\n"
            f"  Retransmissions    : {s['retransmits']}\n"
            f"  Permanently dropped: {s['dropped']}\n"
            f"  Delivery rate      : {delivery:.1f}%\n"
            f"───────────────────────────────────────────"
        )


# ── Telemetry generator (unchanged) ─────────────────────────────────────────

def generate_telemetry(index: int) -> dict:
    return {
        "sensor_id":   "NODE-01",
        "index":       index,
        "timestamp":   round(time.time(), 3),
        "temperature": round(20.0 + random.uniform(-2, 5), 2),
        "humidity":    round(50.0 + random.uniform(-10, 10), 1),
        "voltage":     round(3.3 + random.uniform(-0.1, 0.1), 3),
    }


# ── main() — TLS auth injected before UDP session ───────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Reliable UDP Telemetry Client with TLS authentication"
    )
    # Original UDP flags (unchanged)
    parser.add_argument('--host',     default='127.0.0.1', help='Server IP')
    parser.add_argument('--port',     type=int, default=9000, help='UDP data port')
    parser.add_argument('--count',    type=int, default=20,
                        help='Number of telemetry packets to send')
    parser.add_argument('--interval', type=float, default=0.5,
                        help='Seconds between packets')
    parser.add_argument('--timeout',  type=float, default=DEFAULT_TIMEOUT,
                        help='Retransmission timeout (seconds)')

    # ── TLS EXTENSION: new flags (4 lines) ───────────────────────────────────
    parser.add_argument('--tls-port', type=int, default=9443,
                        help='TLS control server port')
    parser.add_argument('--user',     default='sensor1', help='Auth username')
    parser.add_argument('--password', default='secret',  help='Auth password')
    parser.add_argument('--ca-cert',  default=None,
                        help='CA certificate for TLS server verification')
    parser.add_argument('--no-tls',   action='store_true',
                        help='Skip TLS auth (development mode)')
    # ─────────────────────────────────────────────────────────────────────────

    args = parser.parse_args()

    # ── TLS EXTENSION: authenticate before opening UDP ───────────────────────
    session_id = None   # None triggers auto-increment fallback in connect()

    if not args.no_tls:
        log.info(f"Step 1/2 — TLS authentication with {args.host}:{args.tls_port}")
        try:
            info       = tls_authenticate(
                host     = args.host,
                tls_port = args.tls_port,
                username = args.user,
                password = args.password,
                cafile   = args.ca_cert,
            )
            session_id = info.session_id
            # Override UDP port with server-provided port (may differ from default)
            udp_port   = info.udp_port
            log.info(
                f"TLS auth complete — session_id={session_id}  udp_port={udp_port}"
            )
        except TLSAuthError as exc:
            log.error(f"Authentication failed: {exc}")
            return
        except TLSHandshakeError as exc:
            log.error(f"TLS error: {exc}")
            return
        except OSError as exc:
            log.error(f"Cannot reach TLS server: {exc}")
            return
    else:
        udp_port = args.port
        log.warning("TLS authentication SKIPPED (--no-tls mode)")
    # ─────────────────────────────────────────────────────────────────────────

    # ── Step 2/2: UDP telemetry session (unchanged logic) ────────────────────
    log.info(f"Step 2/2 — Starting UDP telemetry to {args.host}:{udp_port}")
    client = ReliableUDPClient(args.host, udp_port, timeout=args.timeout)
    client.connect(session_id=session_id)   # <-- only change: pass session_id

    try:
        for i in range(args.count):
            is_last = (i == args.count - 1)
            data    = generate_telemetry(i)
            client.send_telemetry(data, last=is_last)
            time.sleep(args.interval)

        log.info("All packets sent — waiting for ACKs …")
        success = client.flush(timeout=15.0)
        if not success:
            log.error("Some packets were lost permanently.")
    finally:
        client.print_stats()
        client.disconnect()


if __name__ == '__main__':
    main()
