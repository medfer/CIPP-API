#!/usr/bin/env python3
"""End-to-end demo: run discovery against the simulated network and render
an interactive topology map.

    python demo.py [--out-dir DIR] [--max-devices N]

This is the fastest way to see the whole engine work without any real
hardware: SimulatedTransport serves realistic SNMP-style data for a
17-device, multi-vendor, redundant-core demo network (see
netdiscovery/simulator.py), and the exact same discovery/collector/
topology code that would run against LiveSnmpTransport on a real network
runs against it completely unchanged -- only the transport differs.
"""
from __future__ import annotations

import argparse
import os
import time

from netdiscovery import l2_topology, l3_topology
from netdiscovery.discovery import discover
from netdiscovery.simulator import DEFAULT_SEED_IPS, SimulatedTransport
from netdiscovery.topology import Topology
from netdiscovery.visualize import render_all


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", default=".", help="where to write topology.html/.graphml")
    parser.add_argument("--max-devices", type=int, default=1000)
    args = parser.parse_args()

    transport = SimulatedTransport()

    print(f"Discovering from seed(s): {', '.join(DEFAULT_SEED_IPS)} ...")
    start = time.monotonic()
    result = discover(transport, DEFAULT_SEED_IPS, max_devices=args.max_devices)
    elapsed = time.monotonic() - start

    for ip, device in sorted(result.devices.items()):
        if device.reachable:
            print(f"  [ok]      {ip:<16} {device.sysname:<18} {device.vendor:<10} {device.role.value}")
        else:
            print(f"  [timeout] {ip:<16} (unreachable, discovered as a neighbor but never answered)")

    l2 = l2_topology.build(result.devices)
    l3 = l3_topology.build(result.devices)
    topology = Topology.from_discovery(result.devices, l2, l3)
    summary = topology.summary()

    os.makedirs(args.out_dir, exist_ok=True)
    html_paths = render_all(topology, args.out_dir)
    graphml_path = os.path.join(args.out_dir, "topology.graphml")
    topology.to_graphml(graphml_path)

    print()
    print(f"Discovery finished in {elapsed:.3f}s")
    print(
        f"{summary['devices_discovered']} devices discovered "
        f"({summary['devices_unreachable']} unreachable), "
        f"{summary['l2_links']} L2 links, "
        f"{summary['l3_adjacencies']} L3 adjacencies, "
        f"{summary['endpoints_attached']} non-LLDP endpoints attached"
    )
    print()
    print("Wrote:")
    for path in html_paths.values():
        print(f"  {path}")
    print(f"  {graphml_path}")


if __name__ == "__main__":
    main()
