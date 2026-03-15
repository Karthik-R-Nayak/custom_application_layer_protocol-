#!/usr/bin/env python3
"""
simulate_network.py — Apply / remove tc netem network conditions on loopback.

Requires: iproute2 (tc), run as root or with sudo.

Usage:
    sudo python simulate_network.py apply  --loss 10 --delay 50 --jitter 10
    sudo python simulate_network.py remove
    sudo python simulate_network.py status
"""

import subprocess
import argparse
import sys


IFACE = "lo"   # loopback — change to eth0 / wlan0 for real-world use


def run(cmd: str, check: bool = True) -> str:
    print(f"  $ {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.stdout:
        print(result.stdout.strip())
    if result.returncode != 0 and check:
        print(f"ERROR: {result.stderr.strip()}", file=sys.stderr)
        sys.exit(1)
    return result.stdout


def apply_conditions(loss_pct: float, delay_ms: int,
                     jitter_ms: int, corrupt_pct: float,
                     reorder_pct: float):
    print(f"\n[tc netem] Applying conditions on {IFACE}:")
    print(f"  Packet loss  : {loss_pct}%")
    print(f"  Delay        : {delay_ms}ms ± {jitter_ms}ms")
    print(f"  Corruption   : {corrupt_pct}%")
    print(f"  Reorder      : {reorder_pct}%")
    print()

    # Remove any existing qdisc first (ignore errors)
    run(f"tc qdisc del dev {IFACE} root", check=False)

    netem_args = [
        f"delay {delay_ms}ms {jitter_ms}ms distribution normal",
        f"loss {loss_pct}%",
    ]
    if corrupt_pct > 0:
        netem_args.append(f"corrupt {corrupt_pct}%")
    if reorder_pct > 0:
        netem_args.append(f"reorder {reorder_pct}% 25%")

    cmd = f"tc qdisc add dev {IFACE} root netem " + " ".join(netem_args)
    run(cmd)
    print("✓ Network conditions applied.")


def remove_conditions():
    print(f"\n[tc netem] Removing all conditions from {IFACE} …")
    run(f"tc qdisc del dev {IFACE} root", check=False)
    print("✓ Conditions removed — network is clean.")


def show_status():
    print(f"\n[tc netem] Current qdisc on {IFACE}:")
    run(f"tc qdisc show dev {IFACE}", check=False)


# ── Pre-defined test scenarios ───────────────────────────────────────────────

SCENARIOS = {
    "clean":    dict(loss_pct=0,  delay_ms=0,  jitter_ms=0,  corrupt_pct=0, reorder_pct=0),
    "light":    dict(loss_pct=5,  delay_ms=20, jitter_ms=5,  corrupt_pct=0, reorder_pct=0),
    "medium":   dict(loss_pct=15, delay_ms=50, jitter_ms=15, corrupt_pct=0, reorder_pct=5),
    "heavy":    dict(loss_pct=30, delay_ms=100,jitter_ms=30, corrupt_pct=1, reorder_pct=10),
    "lossy":    dict(loss_pct=40, delay_ms=20, jitter_ms=5,  corrupt_pct=0, reorder_pct=0),
    "laggy":    dict(loss_pct=2,  delay_ms=200,jitter_ms=50, corrupt_pct=0, reorder_pct=0),
}


def main():
    parser = argparse.ArgumentParser(description="tc netem network simulator")
    sub = parser.add_subparsers(dest='cmd')

    # apply
    ap = sub.add_parser('apply', help='Apply network conditions')
    ap.add_argument('--scenario',  choices=SCENARIOS.keys(), default=None,
                    help='Use a pre-defined scenario (overrides other flags)')
    ap.add_argument('--loss',    type=float, default=10,  help='Packet loss %%')
    ap.add_argument('--delay',   type=int,   default=50,  help='One-way delay ms')
    ap.add_argument('--jitter',  type=int,   default=10,  help='Jitter ms')
    ap.add_argument('--corrupt', type=float, default=0,   help='Bit corruption %%')
    ap.add_argument('--reorder', type=float, default=0,   help='Reorder %%')

    sub.add_parser('remove', help='Remove all tc conditions')
    sub.add_parser('status', help='Show current tc qdisc')

    # list scenarios
    sub.add_parser('list', help='List pre-defined scenarios')

    args = parser.parse_args()

    if args.cmd == 'apply':
        if args.scenario:
            kw = SCENARIOS[args.scenario]
        else:
            kw = dict(loss_pct=args.loss, delay_ms=args.delay,
                      jitter_ms=args.jitter, corrupt_pct=args.corrupt,
                      reorder_pct=args.reorder)
        apply_conditions(**kw)

    elif args.cmd == 'remove':
        remove_conditions()

    elif args.cmd == 'status':
        show_status()

    elif args.cmd == 'list':
        print("\nPre-defined scenarios:")
        for name, kw in SCENARIOS.items():
            print(f"  {name:8s}  loss={kw['loss_pct']:4.0f}%  "
                  f"delay={kw['delay_ms']:4d}ms  jitter={kw['jitter_ms']:3d}ms")

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
