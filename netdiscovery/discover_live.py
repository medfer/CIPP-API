#!/usr/bin/env python3
"""Run discovery against a real network over SNMP and render the topology map.

    # SNMP v2c (default):
    python discover_live.py --seed 192.168.1.1 [192.168.1.2 ...] \
        --community public [--port 161] [--timeout 1.5] [--retries 1] \
        [--max-devices 1000] [--concurrency 10] [--out-dir .]

    # SNMPv3 (auth+privacy -- the credential material a v3-only device needs):
    python discover_live.py --seed 192.168.1.1 --snmp-version v3 \
        --v3-user myuser --v3-security-level authPriv \
        --v3-auth-protocol sha --v3-auth-password '...' \
        --v3-priv-protocol aes128 --v3-priv-password '...'

This is the same engine as demo.py -- discovery BFS, device
classification, L2/L3 correlation, graph model, HTML rendering -- with
LiveSnmpTransport (real SNMP over pysnmp) in place of the in-memory
SimulatedTransport. Requires `pip install pysnmp`.

Security note: SNMP credentials (v2c community string, v3 auth/priv
passwords) are secrets. Pass them via the --community/--v3-*-password
flags or their NETDISCOVERY_* environment variable equivalents -- avoid
typing them where shell history persists on a shared machine, and never
commit them to source control. Plain v2c sends the community string
unencrypted on the wire; SNMPv3 authPriv is the only mode here that
doesn't.
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
    parser.add_argument("--snmp-version", choices=["v2c", "v3"], default="v2c")
    parser.add_argument("--community",
                         default=os.environ.get("NETDISCOVERY_SNMP_COMMUNITY", "public"),
                         help="SNMP v2c read community (default: env NETDISCOVERY_SNMP_COMMUNITY, or 'public')")
    parser.add_argument("--v3-user", default=os.environ.get("NETDISCOVERY_V3_USER"),
                         help="SNMPv3 username (required for --snmp-version v3)")
    parser.add_argument("--v3-security-level", choices=["noAuthNoPriv", "authNoPriv", "authPriv"],
                         default="authPriv")
    parser.add_argument("--v3-auth-protocol", choices=["md5", "sha", "sha224", "sha256", "sha384", "sha512"],
                         default="sha")
    parser.add_argument("--v3-auth-password", default=os.environ.get("NETDISCOVERY_V3_AUTH_PASSWORD"),
                         help="required unless --v3-security-level noAuthNoPriv "
                              "(default: env NETDISCOVERY_V3_AUTH_PASSWORD)")
    parser.add_argument("--v3-priv-protocol", choices=["des", "3des", "aes128", "aes192", "aes256"],
                         default="aes128")
    parser.add_argument("--v3-priv-password", default=os.environ.get("NETDISCOVERY_V3_PRIV_PASSWORD"),
                         help="required for --v3-security-level authPriv "
                              "(default: env NETDISCOVERY_V3_PRIV_PASSWORD)")
    parser.add_argument("--port", type=int, default=161)
    parser.add_argument("--timeout", type=float, default=1.5, help="per-request timeout in seconds")
    parser.add_argument("--retries", type=int, default=1)
    parser.add_argument("--max-devices", type=int, default=1000)
    parser.add_argument("--concurrency", type=int, default=10,
                         help="devices probed in parallel (default 10; 1 = strictly sequential)")
    parser.add_argument("--out-dir", default=".", help="where to write topology.html/.graphml")
    args = parser.parse_args()

    if args.snmp_version == "v3" and not args.v3_user:
        raise SystemExit("--snmp-version v3 requires --v3-user (or env NETDISCOVERY_V3_USER)")

    try:
        if args.snmp_version == "v3":
            transport = LiveSnmpTransport(
                port=args.port, timeout=args.timeout, retries=args.retries,
                username=args.v3_user, security_level=args.v3_security_level,
                auth_protocol=args.v3_auth_protocol, auth_password=args.v3_auth_password,
                priv_protocol=args.v3_priv_protocol, priv_password=args.v3_priv_password,
            )
        else:
            transport = LiveSnmpTransport(
                community=args.community, port=args.port,
                timeout=args.timeout, retries=args.retries,
            )
    except (RuntimeError, ValueError) as exc:
        raise SystemExit(str(exc))

    version_desc = (f"SNMPv3 {args.v3_security_level}, user {args.v3_user}"
                     if args.snmp_version == "v3" else "SNMP v2c")
    print(f"Discovering from seed(s): {', '.join(args.seed)} "
          f"({version_desc}, port {args.port}, timeout {args.timeout}s x{args.retries + 1} tries, "
          f"concurrency {args.concurrency}) ...")

    def on_device(ip: str, device, error) -> None:
        if device.reachable:
            print(f"  [ok]      {ip:<16} {device.sysname:<18} {device.vendor:<10} {device.role.value}")
        elif error:
            print(f"  [error]   {ip:<16} {error}")
        else:
            print(f"  [timeout] {ip:<16} (unreachable)")

    start = time.monotonic()
    result = discover(transport, args.seed, max_devices=args.max_devices,
                       on_device=on_device, concurrency=args.concurrency)
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
