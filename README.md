# Reliable UDP Telemetry Protocol (RUTP)

A lightweight, application-layer reliability protocol built on top of UDP, designed for IoT telemetry in constrained network environments. The system provides ordered, acknowledged delivery using sequence numbers, ACKs/NACKs, sliding window flow control, and timeout-based retransmission — without the overhead of TCP.

---

## Project Structure

```
reliable_udp/
├── protocol.py          # Packet format, build/parse functions, constants
├── server.py            # Telemetry receiver (runs on Ubuntu / Raspberry Pi)
├── client.py            # Telemetry sender (runs on IoT device)
├── simulate_network.py  # tc netem wrapper for loss/delay simulation
└── run_tests.py         # Automated multi-scenario test runner
```

---

## Protocol Design

### Packet Format (16-byte header + variable payload)

```
 0      3  4      7  8   9  10  11  12  13  14  15   ...
┌────────┬────────┬───┬───┬──────┬──────┬──────┬──────────────┐
│ Magic  │ MsgID  │Typ│Flg│ Seq  │ Len  │ CRC  │   Payload    │
│ (4B)   │ (4B)   │1B │1B │ (2B) │ (2B) │(2B)  │  (0–512 B)   │
└────────┴────────┴───┴───┴──────┴──────┴──────┴──────────────┘
```

| Field   | Size | Description                              |
|---------|------|------------------------------------------|
| Magic   | 4 B  | `RUTP` — identifies protocol             |
| MsgID   | 4 B  | Session identifier                       |
| Type    | 1 B  | DATA / ACK / NACK / HELLO / BYE          |
| Flags   | 1 B  | RETX (retransmission) / LAST (final pkt) |
| Seq     | 2 B  | Per-session sequence number              |
| Len     | 2 B  | Payload length in bytes                  |
| CRC     | 2 B  | CRC-32 (lower 16 bits) over header+payload |
| Payload | var  | JSON-encoded telemetry data (max 512 B)  |

### Reliability Mechanisms

| Mechanism         | Implementation                                                    |
|-------------------|-------------------------------------------------------------------|
| Sequence numbers  | Per-session 16-bit counter, incremented per DATA packet           |
| Acknowledgment    | Server sends PKT_ACK with matching seq after in-order delivery    |
| NACK              | Server sends PKT_NACK to request immediate retransmission         |
| Timeout + Retx    | Client retransmits after 1 s (configurable), up to 5 attempts     |
| Sliding window    | Max 8 unacknowledged packets in flight simultaneously             |
| Duplicate detect  | Server discards seq < expected_seq, still sends ACK               |
| Reorder buffer    | Server buffers out-of-order packets, delivers once gap is filled  |
| CRC integrity     | Every packet carries a 16-bit CRC; corrupt packets are discarded  |

---

## Requirements

- Python 3.8+ (no external libraries needed for core protocol)
- Linux with `iproute2` for network simulation (`sudo apt install iproute2`)
- Wireshark (optional, for packet analysis)

---

## Quick Start

### 1. Clone / copy files to your machine

```bash
mkdir reliable_udp && cd reliable_udp
# Place all .py files here
```

### 2. Start the server (Ubuntu / Raspberry Pi)

```bash
python server.py --host 0.0.0.0 --port 9000
```

Optional: simulate ACK drops server-side (for extra testing):
```bash
python server.py --loss-sim 0.1   # drop 10% of ACKs
```

### 3. Run the client (IoT device or same machine)

```bash
python client.py --host 127.0.0.1 --port 9000 --count 20 --interval 0.5
```

### 4. Observe output

**Server:**
```
10:01:23 [SERVER] INFO New session from ('127.0.0.1', 54321)
10:01:23 [SERVER] INFO HELLO from ('127.0.0.1', 54321) msg_id=1
10:01:24 [SERVER] INFO DATA seq=0000 from ...: {"sensor_id": "NODE-01", "temperature": 22.4, ...}
```

**Client:**
```
10:01:24 [CLIENT] INFO SENT seq=0000  {'sensor_id': 'NODE-01', 'temperature': 22.4, ...}
10:01:24 [CLIENT] INFO SENT seq=0001  {'sensor_id': 'NODE-01', ...}
...
── Session stats ──────────────────────────
  Packets sent       : 20
  Acknowledged       : 20
  Retransmissions    : 0
  Permanently dropped: 0
  Delivery rate      : 100.0%
```

---

## Network Simulation with tc netem

### Apply conditions manually

```bash
# 10% loss, 50ms delay, 10ms jitter
sudo python simulate_network.py apply --loss 10 --delay 50 --jitter 10

# Use a pre-defined scenario
sudo python simulate_network.py apply --scenario heavy

# List all scenarios
python simulate_network.py list

# Remove all conditions
sudo python simulate_network.py remove

# Show current state
python simulate_network.py status
```

### Pre-defined scenarios

| Scenario | Loss | Delay    | Jitter  |
|----------|------|----------|---------|
| clean    | 0%   | 0 ms     | 0 ms    |
| light    | 5%   | 20 ms    | 5 ms    |
| medium   | 15%  | 50 ms    | 15 ms   |
| heavy    | 30%  | 100 ms   | 30 ms   |
| lossy    | 40%  | 20 ms    | 5 ms    |
| laggy    | 2%   | 200 ms   | 50 ms   |

---

## Automated Testing

Run all scenarios automatically and get a comparison table:

```bash
sudo python run_tests.py

# Run specific scenarios only
sudo python run_tests.py --scenarios clean medium heavy

# Save results to JSON
sudo python run_tests.py --json-out results.json

# More packets per scenario
sudo python run_tests.py --packets 50 --interval 0.2
```

**Example output:**
```
==========================================================
  SUMMARY
==========================================================
Scenario    Loss%   Delay   Sent   Acked   Retx   Drop   Delivery    Time
--------------------------------------------------------------------------
clean          0%     0ms     20     20      0      0    100.0%    10.2s
light          5%    20ms     20     20      3      0    100.0%    12.1s
medium        15%    50ms     20     20      9      0    100.0%    18.4s
heavy         30%   100ms     20     19     21      1     95.0%    28.7s
lossy         40%    20ms     20     18     26      2     90.0%    22.1s
```

---

## Wireshark Capture

Capture RUTP traffic on loopback:

```bash
sudo wireshark -i lo -k &

# or with tcpdump:
sudo tcpdump -i lo udp port 9000 -w capture.pcap
```

**Filter in Wireshark:**
```
udp.port == 9000
```

**Decode manually:** RUTP uses the first 4 bytes `52 55 54 50` ("RUTP") as a magic identifier. In Wireshark's hex view, each packet will show this header followed by the sequence number and payload.

---

## Configuration Reference

### Client options

| Flag         | Default     | Description                        |
|--------------|-------------|------------------------------------|
| `--host`     | `127.0.0.1` | Server IP address                  |
| `--port`     | `9000`      | UDP port                           |
| `--count`    | `20`        | Number of telemetry packets        |
| `--interval` | `0.5`       | Seconds between packets            |
| `--timeout`  | `1.0`       | Retransmission timeout (seconds)   |

### Server options

| Flag         | Default   | Description                             |
|--------------|-----------|-----------------------------------------|
| `--host`     | `0.0.0.0` | Bind address                            |
| `--port`     | `9000`    | UDP port                                |
| `--loss-sim` | `0.0`     | Fraction of ACKs to drop (0.0–1.0)     |

### Protocol constants (protocol.py)

| Constant          | Value | Description                            |
|-------------------|-------|----------------------------------------|
| `DEFAULT_TIMEOUT` | 1.0 s | Retransmit after this silence          |
| `MAX_RETRANSMITS` | 5     | Give up after this many retries        |
| `WINDOW_SIZE`     | 8     | Max in-flight unacknowledged packets   |
| `MAX_PAYLOAD`     | 512 B | Max JSON payload per packet            |

---

## Architecture Overview

```
IoT Client                           Server (Ubuntu / Raspberry Pi)
──────────────────────────           ──────────────────────────────
 generate_telemetry()
        │
        ▼
 send_telemetry(data)
   ├─ assign seq number
   ├─ build_packet()                 recvfrom()
   ├─ UDP sendto() ────────────────►  parse_packet()
   └─ add to pending{}               ├─ check seq order
                                     ├─ reorder buffer
Background threads:                  ├─ deliver to app
 _ack_receiver()    ◄──────────────  └─ send ACK/NACK
   └─ mark pkt acked
 _timeout_watchdog()
   └─ retransmit if timeout
```

---
Computer Networks Project — Reliable UDP Telemetry Protocol
## Authors
-Merwyn Prince Lobo (https://github.com/Merwyn-Prince-Lobo)

-Karthik R Nayak (https://github.com/Karthik-R-Nayak)

-Sneha Panini (https://github.com/sneha-panini)

