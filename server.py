"""
server.py — Reliable UDP Telemetry Server
Receives telemetry packets, sends ACK/NACK, logs received data.

Usage:
    python server.py [--host 0.0.0.0] [--port 9000] [--loss-sim 0.0]
"""

import socket
import argparse
import logging
import time
import random
import json
from collections import defaultdict
from protocol import (
    parse_packet, build_ack, build_nack,
    PKT_DATA, PKT_HELLO, PKT_BYE,
    MAX_PACKET_SIZE
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [SERVER] %(levelname)s %(message)s',
    datefmt='%H:%M:%S'
)
log = logging.getLogger(__name__)


class TelemetrySession:
    """Tracks per-client session state."""
    def __init__(self, addr):
        self.addr        = addr
        self.expected_seq = 0
        self.received    = 0        # total packets accepted
        self.duplicates  = 0
        self.out_of_order = 0
        self.start_time  = time.time()
        self.buffer      = {}       # seq → payload (reorder buffer)

    def stats(self):
        elapsed = time.time() - self.start_time
        return {
            "client":       str(self.addr),
            "received":     self.received,
            "duplicates":   self.duplicates,
            "out_of_order": self.out_of_order,
            "duration_s":   round(elapsed, 2),
        }


class ReliableUDPServer:
    def __init__(self, host: str, port: int, loss_sim: float = 0.0):
        self.host     = host
        self.port     = port
        self.loss_sim = loss_sim          # artificial ACK drop rate for testing
        self.sessions: dict[tuple, TelemetrySession] = {}
        self.sock     = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        log.info(f"Listening on {host}:{port}  (ACK loss simulation={loss_sim*100:.0f}%)")

    def _get_session(self, addr) -> TelemetrySession:
        if addr not in self.sessions:
            self.sessions[addr] = TelemetrySession(addr)
            log.info(f"New session from {addr}")
        return self.sessions[addr]

    def _send_ack(self, addr, msg_id: int, seq: int):
        """Send ACK, optionally simulating loss for testing."""
        if self.loss_sim > 0 and random.random() < self.loss_sim:
            log.debug(f"[SIM] Dropping ACK seq={seq} to {addr}")
            return
        pkt = build_ack(msg_id, seq)
        self.sock.sendto(pkt, addr)
        log.debug(f"ACK  msg={msg_id} seq={seq} → {addr}")

    def _send_nack(self, addr, msg_id: int, seq: int):
        pkt = build_nack(msg_id, seq)
        self.sock.sendto(pkt, addr)
        log.debug(f"NACK msg={msg_id} seq={seq} → {addr}")

    def _handle_hello(self, addr, msg_id: int, seq: int):
        sess = self._get_session(addr)
        sess.expected_seq = 0
        log.info(f"HELLO from {addr} msg_id={msg_id}")
        self._send_ack(addr, msg_id, seq)

    def _handle_bye(self, addr, msg_id: int, seq: int):
        sess = self._get_session(addr)
        log.info(f"BYE from {addr} — session stats: {json.dumps(sess.stats())}")
        self._send_ack(addr, msg_id, seq)
        del self.sessions[addr]

    def _handle_data(self, addr, msg_id: int, seq: int, payload: bytes):
        sess = self._get_session(addr)

        # Duplicate detection
        if seq < sess.expected_seq:
            sess.duplicates += 1
            log.warning(f"Duplicate seq={seq} (expected {sess.expected_seq}) from {addr}")
            self._send_ack(addr, msg_id, seq)   # re-ACK so client stops retransmitting
            return

        # In-order delivery
        if seq == sess.expected_seq:
            self._deliver(addr, seq, payload, sess)
            sess.expected_seq += 1
            # Drain reorder buffer
            while sess.expected_seq in sess.buffer:
                buffered = sess.buffer.pop(sess.expected_seq)
                self._deliver(addr, sess.expected_seq, buffered, sess)
                sess.expected_seq += 1
        else:
            # Out-of-order: buffer and NACK the missing range
            sess.out_of_order += 1
            sess.buffer[seq] = payload
            log.warning(f"Out-of-order seq={seq} (expected {sess.expected_seq}), buffering")
            self._send_nack(addr, msg_id, sess.expected_seq)
            return

        self._send_ack(addr, msg_id, seq)

    def _deliver(self, addr, seq: int, payload: bytes, sess: TelemetrySession):
        """Process a correctly ordered payload."""
        sess.received += 1
        try:
            data = json.loads(payload.decode('utf-8'))
            log.info(f"DATA seq={seq:04d} from {addr}: {data}")
        except Exception:
            log.info(f"DATA seq={seq:04d} from {addr}: {payload.hex()}")

    def run(self):
        log.info("Server ready — waiting for telemetry packets …")
        while True:
            try:
                raw, addr = self.sock.recvfrom(MAX_PACKET_SIZE + 16)
            except KeyboardInterrupt:
                log.info("Shutting down.")
                break

            try:
                msg_id, pkt_type, flags, seq, payload = parse_packet(raw)
            except ValueError as e:
                log.warning(f"Bad packet from {addr}: {e}")
                continue

            if pkt_type == PKT_HELLO:
                self._handle_hello(addr, msg_id, seq)
            elif pkt_type == PKT_DATA:
                self._handle_data(addr, msg_id, seq, payload)
            elif pkt_type == PKT_BYE:
                self._handle_bye(addr, msg_id, seq)
            else:
                log.warning(f"Unknown packet type {pkt_type:#04x} from {addr}")


def main():
    parser = argparse.ArgumentParser(description="Reliable UDP Telemetry Server")
    parser.add_argument('--host',     default='0.0.0.0',  help='Bind address')
    parser.add_argument('--port',     type=int, default=9000, help='UDP port')
    parser.add_argument('--loss-sim', type=float, default=0.0,
                        help='Fraction of ACKs to drop (0.0–1.0) for testing')
    args = parser.parse_args()

    server = ReliableUDPServer(args.host, args.port, args.loss_sim)
    server.run()


if __name__ == '__main__':
    main()
