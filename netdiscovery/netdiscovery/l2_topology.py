"""Layer-2 link correlation.

Two sources, in priority order:

1. LLDP/CDP neighbor tables -- authoritative switch<->switch (and
   switch<->firewall) links. A link reported from both ends (A says
   "neighbor B", B says "neighbor A") is deduplicated into one edge.
2. FDB fallback -- for devices that never speak LLDP/CDP (the printers,
   cameras, servers and PCs in the demo network), a switch port that has
   learned exactly one non-infrastructure MAC is a confident access-port
   attachment. Ports with more than one such MAC (an unmanaged hub, a
   shared segment) still attach every MAC seen, just without the
   single-MAC confidence signal.

Each edge/attachment is tagged with its discovery source (`lldp`/`cdp`/
`fdb`) so the visualization and the summary counts stay honest about how
each link was found.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from . import device_id
from .models import Device


@dataclass(frozen=True)
class L2Edge:
    """An infrastructure-to-infrastructure link (switch/router/firewall)."""
    device_a: str   # mgmt_ip
    if_a: str
    device_b: str   # mgmt_ip
    if_b: str
    source: str     # "lldp" | "cdp"


@dataclass(frozen=True)
class L2Endpoint:
    """A non-LLDP/CDP endpoint attached to a switch access port."""
    mac: str
    ip: Optional[str]
    switch_ip: str
    switch_if: str
    vlan: Optional[int]
    kind: str       # "printer" | "camera" | "server" | "workstation" | "unknown"
    source: str = "fdb"


@dataclass
class L2Topology:
    edges: list[L2Edge]
    endpoints: list[L2Endpoint]


def _sysname_lookup(devices: dict[str, Device]) -> dict[str, str]:
    return {d.sysname: ip for ip, d in devices.items() if d.reachable and d.sysname}


def _build_edges(devices: dict[str, Device]) -> list[L2Edge]:
    sysname_to_ip = _sysname_lookup(devices)
    seen: dict[frozenset, L2Edge] = {}

    for ip, device in devices.items():
        if not device.reachable:
            continue
        for n in device.neighbors:
            remote_ip = n.remote_mgmt_ip or sysname_to_ip.get(n.remote_sysname)
            if not remote_ip or remote_ip == ip:
                continue
            key = frozenset({(ip, n.local_if), (remote_ip, n.remote_port)})
            if key in seen:
                continue
            seen[key] = L2Edge(
                device_a=ip, if_a=n.local_if,
                device_b=remote_ip, if_b=n.remote_port,
                source=n.protocol,
            )

    return list(seen.values())


def _infra_ports(edges: list[L2Edge]) -> set[tuple[str, str]]:
    ports = set()
    for e in edges:
        ports.add((e.device_a, e.if_a))
        ports.add((e.device_b, e.if_b))
    return ports


def _build_endpoints(devices: dict[str, Device], edges: list[L2Edge]) -> list[L2Endpoint]:
    infra_macs = {mac for d in devices.values() for mac in d.all_macs()}
    infra_ports = _infra_ports(edges)

    mac_to_ip: dict[str, str] = {}
    for d in devices.values():
        for arp in d.arp:
            mac_to_ip.setdefault(arp.mac.lower(), arp.ip)

    # Group FDB rows by the (switch, port) they were learned on.
    by_port: dict[tuple[str, str], list[tuple[str, Optional[int]]]] = {}
    for ip, device in devices.items():
        if not device.reachable:
            continue
        for row in device.fdb:
            mac = row.mac.lower()
            if mac in infra_macs:
                continue
            key = (ip, row.local_if)
            if key in infra_ports:
                continue
            by_port.setdefault(key, []).append((mac, row.vlan))

    endpoints = []
    for (switch_ip, switch_if), rows in by_port.items():
        for mac, vlan in rows:
            endpoints.append(L2Endpoint(
                mac=mac,
                ip=mac_to_ip.get(mac),
                switch_ip=switch_ip,
                switch_if=switch_if,
                vlan=vlan,
                kind=device_id.fingerprint_endpoint(mac),
            ))
    return endpoints


def build(devices: dict[str, Device]) -> L2Topology:
    edges = _build_edges(devices)
    endpoints = _build_endpoints(devices, edges)
    return L2Topology(edges=edges, endpoints=endpoints)
