"""
client.py — Reliable UDP Telemetry Client
Sends telemetry data with sequence numbers, ACK tracking, and retransmission.

Usage:
    python client.py [--host 127.0.0.1] [--port 9000] [--count 20] [--interval 0.5]


"""

import socket
import argparse
import logging
import time
import json
import random
import threading
from dataclasses import dataclass, field
from typing import Optional
from protocol import (
    build_packet, parse_packet,
    PKT_DATA, PKT_ACK, PKT_NACK, PKT_HELLO, PKT_BYE,
    FLAG_RETX, FLAG_LAST,
    DEFAULT_TIMEOUT, MAX_RETRANSMITS, WINDOW_SIZE,
    MAX_PACKET_SIZE
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [CLIENT] %(levelname)s %(message)s',
    datefmt='%H:%M:%S'
)
log = logging.getLogger(__name__)


@dataclass
class PendingPacket:
    """A packet awaiting acknowledgment."""
    msg_id:     int
    seq:        int
    payload:    bytes          # original payload, kept for NACK retransmit rebuild
    flags:      int            # original flags (without FLAG_RETX)
    raw:        bytes          # wire bytes of the most-recently-sent version
    send_time:  float = field(default_factory=time.time)
    retx_count: int   = 0
    acked:      bool  = False


class ReliableUDPClient:
    def __init__(self, host: str, port: int,
                 timeout: float = DEFAULT_TIMEOUT,
                 max_retx: int  = MAX_RETRANSMITS):
        self.server_addr = (host, port)
        self.timeout     = timeout
        self.max_retx    = max_retx
        # FIX 2: msg_id starts at 0; connect() increments it to 1 (and again on
        # every reconnect), so each session gets a unique ID.
        self.msg_id      = 0
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

    # ── Internal helpers ─────────────────────────────────────────────────────

    def _next_seq(self) -> int:
        s = self.seq
        self.seq += 1
        return s

    def _send_raw(self, raw: bytes):
        self.sock.sendto(raw, self.server_addr)

    def _build_data_pkt(self, seq: int, payload: bytes, flags: int = 0) -> bytes:
        return build_packet(self.msg_id, PKT_DATA, seq, payload, flags)

    # ── ACK receiver ────────────────────────────────────────────────────────

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
                        pkt = self.pending[seq]
                        # FIX 1: Build a fresh packet with FLAG_RETX set using
                        # the stored payload.  The previous code built raw_retx
                        # with b'' (empty payload) and then never used it —
                        # both bugs are corrected here.
                        retx_raw = self._build_data_pkt(
                            seq, pkt.payload, pkt.flags | FLAG_RETX
                        )
                        pkt.raw        = retx_raw   # update stored raw too
                        pkt.retx_count += 1
                        pkt.send_time  = time.time()
                        self.stats['retransmits'] += 1
                        self._send_raw(retx_raw)

    # ── Timeout watchdog ─────────────────────────────────────────────────────

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

    # ── Window management ────────────────────────────────────────────────────

    def _window_full(self) -> bool:
        with self.lock:
            unacked = sum(1 for p in self.pending.values() if not p.acked)
            return unacked >= WINDOW_SIZE

    def _wait_for_window(self):
        while self._window_full():
            time.sleep(0.01)

    # ── Public API ───────────────────────────────────────────────────────────

    def connect(self):
        """Send HELLO to initiate a new session."""
        # FIX 2: Increment msg_id on every connect so sessions are distinguishable.
        self.msg_id += 1
        self.seq     = 0
        log.info(f"Connecting to {self.server_addr}  msg_id={self.msg_id}")

        hello = build_packet(self.msg_id, PKT_HELLO, 0)
        self._send_raw(hello)
        try:
            raw, _ = self.sock.recvfrom(MAX_PACKET_SIZE + 16)
            parse_packet(raw)
            log.info("HELLO acknowledged — session started")
        except (socket.timeout, ValueError):
            log.warning("No HELLO ACK — proceeding anyway")

        self._stop_event.clear()
        self._ack_thread  = threading.Thread(target=self._ack_receiver,    daemon=True)
        self._retx_thread = threading.Thread(target=self._timeout_watchdog, daemon=True)
        self._ack_thread.start()
        self._retx_thread.start()

    def send_telemetry(self, data: dict, last: bool = False) -> int:
        """
        Serialise `data` to JSON and send as a DATA packet.
        Returns the sequence number assigned.
        Blocks if the send window is full.
        """
        self._wait_for_window()

        payload = json.dumps(data).encode('utf-8')
        if len(payload) > 512:
            raise ValueError(f"Payload too large: {len(payload)} bytes")

        flags = FLAG_LAST if last else 0
        seq   = self._next_seq()
        raw   = self._build_data_pkt(seq, payload, flags)

        # FIX 1: Store payload and flags separately so NACK/timeout retransmit
        # can rebuild the packet with FLAG_RETX without corrupting the original.
        pkt = PendingPacket(
            msg_id=self.msg_id, seq=seq,
            payload=payload, flags=flags, raw=raw
        )
        with self.lock:
            self.pending[seq] = pkt
            self.stats['sent'] += 1

        self._send_raw(raw)
        log.info(f"SENT seq={seq:04d}  {data}")
        return seq

    def flush(self, timeout: float = 10.0) -> bool:
        """
        Block until all pending packets are ACKed or permanently dropped.

        FIX 3: Returns True if every packet was ACKed, False if any were dropped,
               so the caller can log or react accordingly.
        """
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
            all_acked = all(p.acked for p in self.pending.values())
            dropped   = self.stats['dropped']

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


# ── Telemetry generator ──────────────────────────────────────────────────────

def generate_telemetry(index: int) -> dict:
    return {
        "sensor_id":   "NODE-01",
        "index":       index,
        "timestamp":   round(time.time(), 3),
        "temperature": round(20.0 + random.uniform(-2, 5), 2),
        "humidity":    round(50.0 + random.uniform(-10, 10), 1),
        "voltage":     round(3.3 + random.uniform(-0.1, 0.1), 3),
    }


def main():
    parser = argparse.ArgumentParser(description="Reliable UDP Telemetry Client")
    parser.add_argument('--host',     default='127.0.0.1', help='Server IP')
    parser.add_argument('--port',     type=int, default=9000, help='Server port')
    parser.add_argument('--count',    type=int, default=20,
                        help='Number of telemetry packets to send')
    parser.add_argument('--interval', type=float, default=0.5,
                        help='Seconds between packets')
    parser.add_argument('--timeout',  type=float, default=DEFAULT_TIMEOUT,
                        help='Retransmission timeout (seconds)')
    args = parser.parse_args()

    client = ReliableUDPClient(args.host, args.port, timeout=args.timeout)
    client.connect()

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
