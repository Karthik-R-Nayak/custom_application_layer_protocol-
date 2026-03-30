"""
protocol.py — Reliable UDP Telemetry Protocol
Packet format and shared constants.

Packet Wire Format:
┌──────────┬──────────┬────────┬──────────┬────────┬─────────┬────────┬──────────────┐
│ Magic(4B)│MsgID (4B)│Type(1B)│ Flags(1B)│ Seq(2B)│ Len (2B)│ CRC(4B)│ Payload(...) │
└──────────┴──────────┴────────┴──────────┴────────┴─────────┴────────┴──────────────┘
Total header: 18 bytes (14-byte base + 4-byte CRC).
Payload: up to MAX_PAYLOAD bytes.


"""

import struct
import zlib

# ── Protocol constants ──────────────────────────────────────────────────────
MAGIC = b'RUTP'   # Reliable UDP Telemetry Protocol

# Base header WITHOUT crc: magic|msg_id|type|flags|seq|payload_len
_BASE_HEADER_FORMAT = '!4sIBBHH'
_BASE_HEADER_SIZE   = struct.calcsize(_BASE_HEADER_FORMAT)   # 14 bytes

# Wire header = base header (14 B) + crc32 (4 B) = 18 bytes total.
WIRE_HEADER_SIZE = _BASE_HEADER_SIZE + 4   # 18 bytes

MAX_PAYLOAD     = 512
MAX_PACKET_SIZE = WIRE_HEADER_SIZE + MAX_PAYLOAD   # 530 bytes

# ── Packet types ────────────────────────────────────────────────────────────
PKT_DATA  = 0x01   # Telemetry data from client
PKT_ACK   = 0x02   # Acknowledgment from server
PKT_NACK  = 0x03   # Negative-ack / retransmit request
PKT_HELLO = 0x04   # Session initiation
PKT_BYE   = 0x05   # Session teardown

# ── Flags ───────────────────────────────────────────────────────────────────
FLAG_NONE = 0x00
FLAG_RETX = 0x01   # This is a retransmission
FLAG_LAST = 0x02   # Last packet in session

# ── Reliability tunables ────────────────────────────────────────────────────
DEFAULT_TIMEOUT = 1.0   # seconds before retransmit
MAX_RETRANSMITS = 5     # give up after this many attempts
WINDOW_SIZE     = 8     # max unacknowledged packets in flight


def build_packet(msg_id: int, pkt_type: int, seq: int,
                 payload: bytes = b'', flags: int = FLAG_NONE) -> bytes:
    """
    Construct a wire-format packet.

    Layout:  [base_header (14 B)] [crc32 (4 B)] [payload (0–512 B)]

    FIX 2: Removed the unused `header` variable that was previously packed but
           never included in the returned bytes, making the layout confusing.
    FIX 1: CRC is stored as a full 32-bit unsigned int.
    """
    length = len(payload)
    # Pack the base header (crc field not yet present — compute over this + payload).
    base_header = struct.pack(_BASE_HEADER_FORMAT,
                              MAGIC, msg_id, pkt_type, flags, seq, length)
    crc32 = zlib.crc32(base_header + payload) & 0xFFFFFFFF   
    return base_header + struct.pack('!I', crc32) + payload


def parse_packet(data: bytes):
    """
    Parse a wire-format packet.
    Returns (msg_id, pkt_type, flags, seq, payload) or raises ValueError.
    """
    if len(data) < WIRE_HEADER_SIZE:
        raise ValueError(
            f"Packet too short: {len(data)} bytes (need at least {WIRE_HEADER_SIZE})"
        )

    base_header  = data[:_BASE_HEADER_SIZE]
    crc_received = struct.unpack('!I', data[_BASE_HEADER_SIZE:WIRE_HEADER_SIZE])[0]
    payload      = data[WIRE_HEADER_SIZE:]

    magic, msg_id, pkt_type, flags, seq, length = struct.unpack(_BASE_HEADER_FORMAT,
                                                                 base_header)

    if magic != MAGIC:
        raise ValueError(f"Bad magic: {magic!r}")
    if len(payload) != length:
        raise ValueError(
            f"Payload length mismatch: header says {length}, got {len(payload)}"
        )

    crc_computed = zlib.crc32(base_header + payload) & 0xFFFFFFFF
    if crc_computed != crc_received:
        raise ValueError(
            f"CRC mismatch: computed {crc_computed:#010x}, received {crc_received:#010x}"
        )

    return msg_id, pkt_type, flags, seq, payload


def build_ack(msg_id: int, seq: int) -> bytes:
    return build_packet(msg_id, PKT_ACK, seq)


def build_nack(msg_id: int, seq: int) -> bytes:
    return build_packet(msg_id, PKT_NACK, seq)
