"""
protocol.py — Reliable UDP Telemetry Protocol
Packet format and shared constants.

Packet Structure (fixed 64-byte header):
┌─────────────┬────────────┬──────────┬────────────┬──────────┬──────────┬─────────┐
│  Magic (4B) │ MsgID (4B) │ Type(1B) │ Flags (1B) │ Seq (2B) │ Len (2B) │ CRC(2B) │
└─────────────┴────────────┴──────────┴────────────┴──────────┴──────────┴─────────┘
Followed by variable-length payload (up to MAX_PAYLOAD bytes).
"""

import struct
import zlib

# ── Protocol constants ──────────────────────────────────────────────────────
MAGIC           = b'RUTP'   # Reliable UDP Telemetry Protocol
HEADER_FORMAT   = '!4sIBBHH'   # network byte order
HEADER_SIZE     = struct.calcsize(HEADER_FORMAT)   # 14 bytes
MAX_PAYLOAD     = 512
MAX_PACKET_SIZE = HEADER_SIZE + MAX_PAYLOAD

# ── Packet types ────────────────────────────────────────────────────────────
PKT_DATA  = 0x01   # Telemetry data from client
PKT_ACK   = 0x02   # Acknowledgment from server
PKT_NACK  = 0x03   # Negative-ack / retransmit request
PKT_HELLO = 0x04   # Session initiation
PKT_BYE   = 0x05   # Session teardown

# ── Flags ───────────────────────────────────────────────────────────────────
FLAG_NONE     = 0x00
FLAG_RETX     = 0x01   # This is a retransmission
FLAG_LAST     = 0x02   # Last packet in session

# ── Reliability tunables ────────────────────────────────────────────────────
DEFAULT_TIMEOUT    = 1.0    # seconds before retransmit
MAX_RETRANSMITS    = 5      # give up after this many attempts
WINDOW_SIZE        = 8      # max unacknowledged packets in flight


def build_packet(msg_id: int, pkt_type: int, seq: int,
                 payload: bytes = b'', flags: int = FLAG_NONE) -> bytes:
    """Construct a wire-format packet with CRC checksum."""
    length = len(payload)
    # Compute CRC over header (with crc=0) + payload
    header_no_crc = struct.pack('!4sIBBHH', MAGIC, msg_id, pkt_type, flags, seq, length)
    crc = zlib.crc32(header_no_crc + payload) & 0xFFFF   # truncate to 16-bit
    header = struct.pack(HEADER_FORMAT, MAGIC, msg_id, pkt_type, flags, seq, length) 
    # Re-pack with real CRC — we store CRC in the 'length' field slot after length
    # Actual layout: magic|msg_id|type|flags|seq|payload_len  then  CRC appended
    raw = header_no_crc + struct.pack('!H', crc) + payload
    return raw


def parse_packet(data: bytes):
    """
    Parse a wire-format packet.
    Returns (msg_id, pkt_type, flags, seq, payload) or raises ValueError.
    """
    if len(data) < HEADER_SIZE + 2:   # header + 2-byte CRC
        raise ValueError("Packet too short")

    header_size_no_crc = HEADER_SIZE  # 14 bytes
    header_no_crc = data[:header_size_no_crc]
    crc_received  = struct.unpack('!H', data[header_size_no_crc:header_size_no_crc + 2])[0]
    payload       = data[header_size_no_crc + 2:]

    magic, msg_id, pkt_type, flags, seq, length = struct.unpack(HEADER_FORMAT, header_no_crc)

    if magic != MAGIC:
        raise ValueError(f"Bad magic: {magic!r}")
    if len(payload) != length:
        raise ValueError(f"Payload length mismatch: expected {length}, got {len(payload)}")

    crc_computed = zlib.crc32(header_no_crc + payload) & 0xFFFF
    if crc_computed != crc_received:
        raise ValueError(f"CRC mismatch: {crc_computed:#06x} != {crc_received:#06x}")

    return msg_id, pkt_type, flags, seq, payload


def build_ack(msg_id: int, seq: int) -> bytes:
    return build_packet(msg_id, PKT_ACK, seq)


def build_nack(msg_id: int, seq: int) -> bytes:
    return build_packet(msg_id, PKT_NACK, seq)
