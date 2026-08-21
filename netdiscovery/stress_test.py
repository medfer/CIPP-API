#!/usr/bin/env python3
"""Large-scale synthetic scaling test for the discovery BFS.

This is NOT a demo of realistic topology (see demo.py/simulator.py for
that) -- it exists purely to give an honest, measured answer to "does this
scale toward thousands of devices?" instead of an untested claim. It
builds a synthetic core/distribution/access hierarchy of a configurable
size, wraps every SNMP call with an injected artificial latency (to stand
in for real network round-trip time, since an in-memory dict lookup alone
proves nothing about real-world timing), and reports wall-clock time and
peak memory across a range of --concurrency values.

    python stress_test.py [--access 2000] [--dist 40] [--latency-ms 5]
                           [--concurrency 1,10,50,200] [--endpoints-per-access 5]

Read the results as: "this many devices, each with a simulated SNMP round
trip of --latency-ms, discovered in this much wall time at this
concurrency" -- a real network's actual per-device latency and the number
of OID walks per device (see collector.py; roughly 20 separate walks/gets
per device currently) determine how this maps to a real deployment.
"""
from __future__ import annotations

import argparse
import time
from typing import Optional

from netdiscovery import l2_topology, l3_topology
from netdiscovery.discovery import discover
from netdiscovery.mibs import (
    CDP_CACHE_ADDRESS, CDP_CACHE_DEVICE_ID, CDP_CACHE_DEVICE_PORT,
    DOT1Q_TP_FDB_PORT, IF_ADMIN_STATUS, IF_DESCR, IF_OPER_STATUS,
    IF_PHYS_ADDRESS, IF_SPEED, IP_AD_ENT_IF_INDEX, IP_AD_ENT_NET_MASK,
    LLDP_REM_CHASSIS_ID, LLDP_REM_MGMT_ADDR, LLDP_REM_PORT_ID,
    LLDP_REM_SYS_NAME, SYS_DESCR, SYS_NAME, SYS_OBJECT_ID, SYS_SERVICES,
    SYS_SERVICES_DATALINK, SYS_SERVICES_INTERNET, SYS_SERVICES_PHYSICAL,
)
from netdiscovery.topology import Topology
from netdiscovery.transport import SnmpTransport

try:
    import resource
except ImportError:  # pragma: no cover - resource is POSIX-only (no Windows)
    resource = None


def _ip_from_index(base: int, i: int) -> str:
    """Deterministically map an integer index to a unique 10.x.x.x IP."""
    n = base + i
    return f"10.{(n >> 16) & 0xFF}.{(n >> 8) & 0xFF}.{n & 0xFF}"


def _mac_from_index(prefix: int, i: int) -> str:
    return f"{prefix:02x}:{(i >> 24) & 0xFF:02x}:{(i >> 16) & 0xFF:02x}:{(i >> 8) & 0xFF:02x}:{i & 0xFF:02x}:00"


def build_synthetic_oid_tables(
    n_dist: int, n_access: int, endpoints_per_access: int,
) -> tuple[dict[str, dict[str, str]], str]:
    """Core(2) -> Dist(n_dist) -> Access(n_access), each access switch
    carrying `endpoints_per_access` FDB-only (non-LLDP) endpoints. Returns
    (oid_tables_by_ip, seed_ip)."""
    tables: dict[str, dict[str, str]] = {}
    l2_services = str(SYS_SERVICES_PHYSICAL | SYS_SERVICES_DATALINK)
    l3_services = str(SYS_SERVICES_PHYSICAL | SYS_SERVICES_DATALINK | SYS_SERVICES_INTERNET)

    core_ips = [_ip_from_index(0, i) for i in range(2)]
    dist_ips = [_ip_from_index(0x010000, i) for i in range(n_dist)]
    access_ips = [_ip_from_index(0x020000, i) for i in range(n_access)]

    def base_table(sysname: str, sysdescr: str, sysobjectid: str, services: str) -> dict[str, str]:
        return {
            SYS_DESCR: sysdescr,
            SYS_OBJECT_ID: sysobjectid,
            SYS_NAME: sysname,
            SYS_SERVICES: services,
        }

    # --- 2 core switches, full mesh with each other + every dist switch ---
    for ci, core_ip in enumerate(core_ips):
        t = base_table(f"core{ci + 1}", "Synthetic core L3 switch",
                        "1.3.6.1.4.1.9.12.3.1.3.1965", l3_services)
        ifidx = 1
        other_core = core_ips[1 - ci]
        t[f"{IF_DESCR}.{ifidx}"] = f"Eth1/{ifidx}"
        t[f"{IF_PHYS_ADDRESS}.{ifidx}"] = _mac_from_index(0xC0, ifidx)
        t[f"{IF_ADMIN_STATUS}.{ifidx}"] = "1"
        t[f"{IF_OPER_STATUS}.{ifidx}"] = "1"
        t[f"{IF_SPEED}.{ifidx}"] = "10000000000"
        t[f"{LLDP_REM_SYS_NAME}.{ifidx}"] = f"core{2 - ci}"
        t[f"{LLDP_REM_PORT_ID}.{ifidx}"] = "Eth1/1"
        t[f"{LLDP_REM_MGMT_ADDR}.{ifidx}"] = other_core
        ifidx += 1
        for di, dist_ip in enumerate(dist_ips):
            t[f"{IF_DESCR}.{ifidx}"] = f"Eth1/{ifidx}"
            t[f"{IF_PHYS_ADDRESS}.{ifidx}"] = _mac_from_index(0xC0, 1000 + ifidx)
            t[f"{IF_ADMIN_STATUS}.{ifidx}"] = "1"
            t[f"{IF_OPER_STATUS}.{ifidx}"] = "1"
            t[f"{IF_SPEED}.{ifidx}"] = "10000000000"
            t[f"{LLDP_REM_SYS_NAME}.{ifidx}"] = f"dist{di + 1}"
            t[f"{LLDP_REM_PORT_ID}.{ifidx}"] = "Eth1/1"
            t[f"{LLDP_REM_MGMT_ADDR}.{ifidx}"] = dist_ip
            ifidx += 1
        tables[core_ip] = t

    # --- N distribution switches, each linked to both cores + their access switches ---
    access_per_dist = max(1, -(-n_access // max(1, n_dist)))  # ceil
    for di, dist_ip in enumerate(dist_ips):
        t = base_table(f"dist{di + 1}", "Synthetic distribution switch",
                        "1.3.6.1.4.1.9.1.2694", l2_services)
        ifidx = 1
        for ci, core_ip in enumerate(core_ips):
            t[f"{IF_DESCR}.{ifidx}"] = f"Eth1/{ifidx}"
            t[f"{IF_PHYS_ADDRESS}.{ifidx}"] = _mac_from_index(0xD0, ifidx)
            t[f"{IF_ADMIN_STATUS}.{ifidx}"] = "1"
            t[f"{IF_OPER_STATUS}.{ifidx}"] = "1"
            t[f"{IF_SPEED}.{ifidx}"] = "10000000000"
            t[f"{LLDP_REM_SYS_NAME}.{ifidx}"] = f"core{ci + 1}"
            t[f"{LLDP_REM_PORT_ID}.{ifidx}"] = "Eth1/1"
            t[f"{LLDP_REM_MGMT_ADDR}.{ifidx}"] = core_ip
            ifidx += 1
        start = di * access_per_dist
        end = min(start + access_per_dist, n_access)
        for ai in range(start, end):
            access_ip = access_ips[ai]
            t[f"{IF_DESCR}.{ifidx}"] = f"Eth1/{ifidx}"
            t[f"{IF_PHYS_ADDRESS}.{ifidx}"] = _mac_from_index(0xD0, 1000 + ifidx)
            t[f"{IF_ADMIN_STATUS}.{ifidx}"] = "1"
            t[f"{IF_OPER_STATUS}.{ifidx}"] = "1"
            t[f"{IF_SPEED}.{ifidx}"] = "1000000000"
            t[f"{LLDP_REM_SYS_NAME}.{ifidx}"] = f"acc{ai + 1}"
            t[f"{LLDP_REM_PORT_ID}.{ifidx}"] = "Eth1/1"
            t[f"{LLDP_REM_MGMT_ADDR}.{ifidx}"] = access_ip
            ifidx += 1
        tables[dist_ip] = t

    # --- N access switches, each with synthetic FDB-only endpoints ---
    for ai, access_ip in enumerate(access_ips):
        t = base_table(f"acc{ai + 1}", "Synthetic access switch",
                        "1.3.6.1.4.1.9.1.2618", l2_services)
        t[f"{IF_DESCR}.1"] = "Eth1/1"
        t[f"{IF_PHYS_ADDRESS}.1"] = _mac_from_index(0xA0, ai)
        t[f"{IF_ADMIN_STATUS}.1"] = "1"
        t[f"{IF_OPER_STATUS}.1"] = "1"
        t[f"{IF_SPEED}.1"] = "1000000000"
        for ep in range(endpoints_per_access):
            port = ep + 2
            mac = _mac_from_index(0xE0, ai * endpoints_per_access + ep)
            mac_dotted = ".".join(str(int(o, 16)) for o in mac.split(":"))
            t[f"{IF_DESCR}.{port}"] = f"Eth1/{port}"
            t[f"{IF_PHYS_ADDRESS}.{port}"] = _mac_from_index(0xA0, 10000 + ai * 100 + ep)
            t[f"{IF_ADMIN_STATUS}.{port}"] = "1"
            t[f"{IF_OPER_STATUS}.{port}"] = "1"
            t[f"{IF_SPEED}.{port}"] = "1000000000"
            t[f"{DOT1Q_TP_FDB_PORT}.10.{mac_dotted}"] = str(port)
        tables[access_ip] = t

    return tables, core_ips[0]


class SlowSyntheticTransport(SnmpTransport):
    """Serves `build_synthetic_oid_tables` output, sleeping `latency_s`
    per SNMP call to stand in for real network round-trip time."""

    def __init__(self, oid_tables: dict[str, dict[str, str]], latency_s: float) -> None:
        self._tables = oid_tables
        self._latency_s = latency_s

    def is_reachable(self, ip: str) -> bool:
        time.sleep(self._latency_s)
        return ip in self._tables

    def get(self, ip: str, oid: str) -> Optional[str]:
        time.sleep(self._latency_s)
        return self._tables.get(ip, {}).get(oid)

    def walk(self, ip: str, oid_prefix: str) -> dict[str, str]:
        time.sleep(self._latency_s)
        table = self._tables.get(ip, {})
        dotted_prefix = oid_prefix + "."
        return {oid: v for oid, v in table.items()
                if oid == oid_prefix or oid.startswith(dotted_prefix)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--access", type=int, default=2000, help="number of access switches")
    parser.add_argument("--dist", type=int, default=40, help="number of distribution switches")
    parser.add_argument("--endpoints-per-access", type=int, default=5)
    parser.add_argument("--latency-ms", type=float, default=5.0,
                         help="simulated per-SNMP-call round-trip time")
    parser.add_argument("--concurrency", default="1,10,50,200",
                         help="comma-separated concurrency levels to test")
    args = parser.parse_args()

    n_total = 2 + args.dist + args.access
    print(f"Building synthetic network: 2 core + {args.dist} dist + {args.access} access "
          f"= {n_total} SNMP-speaking devices, {args.endpoints_per_access} FDB endpoints/access switch "
          f"({args.access * args.endpoints_per_access} endpoints total)")
    t0 = time.monotonic()
    oid_tables, seed_ip = build_synthetic_oid_tables(args.dist, args.access, args.endpoints_per_access)
    print(f"  built in {time.monotonic() - t0:.2f}s")

    levels = [int(x) for x in args.concurrency.split(",")]
    latency_s = args.latency_ms / 1000.0

    print(f"\n{'concurrency':>11}  {'wall time':>10}  {'devices/s':>10}  {'devices found':>13}  {'errors':>7}")
    for concurrency in levels:
        transport = SlowSyntheticTransport(oid_tables, latency_s)
        t0 = time.monotonic()
        result = discover(transport, [seed_ip], max_devices=n_total + 10, concurrency=concurrency)
        elapsed = time.monotonic() - t0
        rate = len(result.devices) / elapsed if elapsed > 0 else float("inf")
        print(f"{concurrency:>11}  {elapsed:>9.2f}s  {rate:>10.1f}  {len(result.devices):>13}  {len(result.errors):>7}")

        if len(result.reachable_devices) != n_total:
            print(f"  !! expected {n_total} reachable devices, got {len(result.reachable_devices)}")

    # One more pass to confirm topology correlation itself holds up at scale.
    transport = SlowSyntheticTransport(oid_tables, 0.0)
    t0 = time.monotonic()
    result = discover(transport, [seed_ip], max_devices=n_total + 10, concurrency=200)
    l2 = l2_topology.build(result.devices)
    l3 = l3_topology.build(result.devices)
    topo = Topology.from_discovery(result.devices, l2, l3)
    summary = topo.summary()
    elapsed = time.monotonic() - t0
    peak_mb = None
    if resource is not None:
        peak_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    print(f"\nFull pipeline (discovery + L2/L3 correlation + graph build), zero simulated latency:")
    print(f"  {elapsed:.2f}s total, {summary['devices_discovered']} devices, "
          f"{summary['l2_links']} L2 links, {summary['endpoints_attached']} endpoints attached")
    if peak_mb is not None:
        print(f"  peak RSS: {peak_mb:.0f} MB")


if __name__ == "__main__":
    main()
