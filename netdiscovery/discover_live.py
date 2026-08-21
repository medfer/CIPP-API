#!/usr/bin/env python3
"""Run discovery against a real network over SNMP and render the topology map.

    python discover_live.py --seed 192.168.1.1 [192.168.1.2 ...] \
        --community public [--port 161] [--timeout 1.5] [--retries 1] \
        [--max-devices 1000] [--out-dir .]

This is the same engine as demo.py -- discovery BFS, device
classification, L2/L3 correlation, graph model, HTML rendering -- with
LiveSnmpTransport (real SNMP v2c over pysnmp) in place of the in-memory
SimulatedTransport. Requires `pip install pysnmp`.

Security note: the SNMP community string is read-only credential material.
Pass it via --community or the NETDISCOVERY_SNMP_COMMUNITY environment
variable -- avoid typing it where shell history persists on a shared
machine, and never commit it to source control.
"""
from __future__ import annotations

import argparse
import os
import time

from netdiscovery import l2_topology, l3_topology
from netdiscovery.discovery import discover
from netdiscovery.topology import Topology
from netdiscovery.transport import LiveSnmpTransport
from netdiscovery.visualize import render_all


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--seed", nargs="+", required=True, metavar="IP",
                         help="one or more seed management IPs to start discovery from")
    parser.add_argument("--community",
                         default=os.environ.get("NETDISCOVERY_SNMP_COMMUNITY", "public"),
                         help="SNMP v2c read community (default: env NETDISCOVERY_SNMP_COMMUNITY, or 'public')")
    parser.add_argument("--port", type=int, default=161)
    parser.add_argument("--timeout", type=float, default=1.5, help="per-request timeout in seconds")
    parser.add_argument("--retries", type=int, default=1)
    parser.add_argument("--max-devices", type=int, default=1000)
    parser.add_argument("--out-dir", default=".", help="where to write topology.html/.graphml")
    args = parser.parse_args()

    try:
        transport = LiveSnmpTransport(
            community=args.community, port=args.port,
            timeout=args.timeout, retries=args.retries,
        )
    except RuntimeError as exc:
        raise SystemExit(str(exc))

    print(f"Discovering from seed(s): {', '.join(args.seed)} "
          f"(SNMP v2c, port {args.port}, timeout {args.timeout}s x{args.retries + 1} tries) ...")

    def on_device(ip: str, device, error) -> None:
        if device.reachable:
            print(f"  [ok]      {ip:<16} {device.sysname:<18} {device.vendor:<10} {device.role.value}")
        elif error:
            print(f"  [error]   {ip:<16} {error}")
        else:
            print(f"  [timeout] {ip:<16} (unreachable)")

    start = time.monotonic()
    result = discover(transport, args.seed, max_devices=args.max_devices, on_device=on_device)
    elapsed = time.monotonic() - start

    if not result.reachable_devices:
        raise SystemExit(
            "\nNo device responded. Check: the seed IP(s) are correct and reachable, "
            "the community string is right, SNMP (UDP/161) isn't blocked by a firewall "
            "between this host and the target, and SNMP is actually enabled on the device."
        )

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
    if result.errors:
        print(f"{len(result.errors)} device(s) hit a collection error (see [error] lines above) "
              "-- treated as unreachable rather than aborting the run")
    print()
    print("Wrote:")
    for path in html_paths.values():
        print(f"  {path}")
    print(f"  {graphml_path}")


if __name__ == "__main__":
    main()
