"""Layer-3 adjacency correlation.

Two sources, both driven purely by each device's connected subnets and
routing table (no LLDP/CDP involved -- L3 adjacency is a routing-plane
concept):

1. Shared subnet -- any two devices with a connected route into the same
   network are L3-neighbors on that subnet (e.g. both core switches'
   VLAN 10 SVI, or a core switch and the firewall on their transit /30).
2. Next-hop -- a non-connected route's next hop, when it resolves to
   another discovered device's own interface IP, is a routed adjacency
   toward whatever that route's destination is (e.g. a default route
   pointing at the firewall).

Both kinds are kept, and a pair of devices can be adjacent via more than
one subnet/route at once -- L3 adjacency is a graph here too, not a
routing tree.
"""
from __future__ import annotations

from dataclasses import dataclass

from .models import Device


@dataclass(frozen=True)
class L3Adjacency:
    device_a: str   # mgmt_ip (sorted with device_b for a stable identity)
    device_b: str
    subnet: str     # "network/prefix_len" this adjacency is justified by
    kind: str       # "shared_subnet" | "next_hop"


@dataclass
class L3Topology:
    adjacencies: list[L3Adjacency]
    subnets: dict[str, list[str]]  # "network/prefix_len" -> member device mgmt_ips


def _subnet_members(devices: dict[str, Device]) -> dict[str, list[tuple[str, str]]]:
    members: dict[str, list[tuple[str, str]]] = {}
    for ip, device in devices.items():
        if not device.reachable:
            continue
        for network, prefix_len, local_if in device.connected_subnets():
            members.setdefault(f"{network}/{prefix_len}", []).append((ip, local_if))
    return members


def _ip_owners(devices: dict[str, Device]) -> dict[str, str]:
    owners: dict[str, str] = {}
    for ip, device in devices.items():
        if not device.reachable:
            continue
        for iface in device.interfaces:
            if iface.ip:
                owners[iface.ip] = ip
    return owners


def build(devices: dict[str, Device]) -> L3Topology:
    subnet_members = _subnet_members(devices)
    adjacencies: set[L3Adjacency] = set()

    for subnet_key, members in subnet_members.items():
        ips = sorted({ip for ip, _local_if in members})
        for i in range(len(ips)):
            for j in range(i + 1, len(ips)):
                adjacencies.add(L3Adjacency(
                    device_a=ips[i], device_b=ips[j],
                    subnet=subnet_key, kind="shared_subnet",
                ))

    ip_owner = _ip_owners(devices)
    for ip, device in devices.items():
        if not device.reachable:
            continue
        for route in device.routes:
            if route.proto == "connected" or not route.next_hop or route.next_hop == "0.0.0.0":
                continue
            owner = ip_owner.get(route.next_hop)
            if not owner or owner == ip:
                continue
            a, b = sorted((ip, owner))
            adjacencies.add(L3Adjacency(
                device_a=a, device_b=b,
                subnet=f"{route.dest}/{route.prefix_len}", kind="next_hop",
            ))

    ordered = sorted(adjacencies, key=lambda a: (a.device_a, a.device_b, a.subnet, a.kind))
    return L3Topology(
        adjacencies=ordered,
        subnets={key: sorted({ip for ip, _if in members}) for key, members in subnet_members.items()},
    )
