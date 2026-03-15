#!/usr/bin/env python3
"""
run_tests.py — Automated test runner for the Reliable UDP Telemetry Protocol.

Starts server, runs client under each scenario, collects and prints results.
Must be run as root (for tc netem), or set TC_SUDO=1 env var.

Usage:
    sudo python run_tests.py
    sudo python run_tests.py --scenarios clean light heavy
    sudo python run_tests.py --packets 30 --interval 0.2
"""

import subprocess
import argparse
import time
import sys
import os
import signal
import re
import json

SCENARIOS = {
    "clean":  {"loss": 0,  "delay": 0,   "jitter": 0},
    "light":  {"loss": 5,  "delay": 20,  "jitter": 5},
    "medium": {"loss": 15, "delay": 50,  "jitter": 15},
    "heavy":  {"loss": 30, "delay": 100, "jitter": 30},
    "lossy":  {"loss": 40, "delay": 20,  "jitter": 5},
}

IFACE   = "lo"
PORT    = 9100   # use separate port so it doesn't conflict with manual runs


def tc(cmd: str):
    full = f"tc {cmd}"
    subprocess.run(full, shell=True, capture_output=True)


def apply_netem(loss: int, delay: int, jitter: int):
    tc(f"qdisc del dev {IFACE} root")
    if loss == 0 and delay == 0:
        return
    tc(f"qdisc add dev {IFACE} root netem "
       f"delay {delay}ms {jitter}ms distribution normal loss {loss}%")


def remove_netem():
    tc(f"qdisc del dev {IFACE} root")


def run_scenario(name: str, params: dict, packets: int, interval: float) -> dict:
    print(f"\n{'='*60}")
    print(f"  Scenario: {name.upper()}  "
          f"(loss={params['loss']}%  delay={params['delay']}ms  "
          f"jitter={params['jitter']}ms)")
    print(f"{'='*60}")

    apply_netem(**params)

    # Start server
    srv = subprocess.Popen(
        [sys.executable, "server.py", "--port", str(PORT)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    time.sleep(0.3)

    # Run client
    start = time.time()
    cli = subprocess.run(
        [sys.executable, "client.py",
         "--host", "127.0.0.1", "--port", str(PORT),
         "--count", str(packets),
         "--interval", str(interval),
         "--timeout", "1.0"],
        capture_output=True, text=True, timeout=120
    )
    elapsed = time.time() - start

    # Kill server
    srv.send_signal(signal.SIGINT)
    try:
        srv_out, srv_err = srv.communicate(timeout=3)
    except subprocess.TimeoutExpired:
        srv.kill()
        srv_out, srv_err = srv.communicate()

    remove_netem()

    # Parse stats from client output
    result = {
        "scenario": name,
        "loss_pct": params["loss"],
        "delay_ms": params["delay"],
        "elapsed_s": round(elapsed, 2),
        "sent": 0, "acked": 0, "retransmits": 0, "dropped": 0,
    }

    combined = cli.stdout + cli.stderr
    for key, pattern in [
        ("sent",        r"Packets sent\s+:\s+(\d+)"),
        ("acked",       r"Acknowledged\s+:\s+(\d+)"),
        ("retransmits", r"Retransmissions\s+:\s+(\d+)"),
        ("dropped",     r"Permanently dropped\s+:\s+(\d+)"),
    ]:
        m = re.search(pattern, combined)
        if m:
            result[key] = int(m.group(1))

    if result["sent"]:
        result["delivery_pct"] = round(result["acked"] / result["sent"] * 100, 1)
    else:
        result["delivery_pct"] = 0.0

    print(f"  Result: sent={result['sent']}  acked={result['acked']}  "
          f"retx={result['retransmits']}  dropped={result['dropped']}  "
          f"delivery={result['delivery_pct']}%  time={elapsed:.1f}s")
    return result


def print_summary(results: list):
    print(f"\n{'='*60}")
    print("  SUMMARY")
    print(f"{'='*60}")
    header = f"{'Scenario':<10} {'Loss%':>6} {'Delay':>7} {'Sent':>6} "
    header += f"{'Acked':>6} {'Retx':>6} {'Drop':>6} {'Delivery':>9} {'Time':>7}"
    print(header)
    print("-" * len(header))
    for r in results:
        print(
            f"{r['scenario']:<10} {r['loss_pct']:>5}%  "
            f"{r['delay_ms']:>4}ms  {r['sent']:>6}  "
            f"{r['acked']:>6}  {r['retransmits']:>6}  {r['dropped']:>6}  "
            f"{r['delivery_pct']:>8.1f}%  {r['elapsed_s']:>5.1f}s"
        )
    print()


def main():
    parser = argparse.ArgumentParser(description="Automated test runner")
    parser.add_argument('--scenarios', nargs='+',
                        choices=list(SCENARIOS.keys()),
                        default=list(SCENARIOS.keys()))
    parser.add_argument('--packets',  type=int,   default=20)
    parser.add_argument('--interval', type=float, default=0.3)
    parser.add_argument('--json-out', default=None,
                        help='Save results to JSON file')
    args = parser.parse_args()

    results = []
    for name in args.scenarios:
        try:
            r = run_scenario(name, SCENARIOS[name], args.packets, args.interval)
            results.append(r)
        except Exception as e:
            print(f"  ERROR in scenario {name}: {e}")
            remove_netem()

    print_summary(results)

    if args.json_out:
        with open(args.json_out, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"Results saved to {args.json_out}")


if __name__ == '__main__':
    if os.geteuid() != 0:
        print("WARNING: Not running as root. tc netem commands may fail.")
        print("         Run with: sudo python run_tests.py\n")
    main()
