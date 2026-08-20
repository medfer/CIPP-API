"""Core data models shared across the discovery engine.

These mirror the objects you actually pull off a device over SNMP:
the system group, interfaces, neighbor tables (LLDP/CDP), the bridge
FDB, the ARP cache and the routing table.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class DeviceRole(str, Enum):
    ROUTER = "router"
    L3_SWITCH = "l3_switch"
    SWITCH = "switch"
    FIREWALL = "firewall"
    ACCESS_POINT = "access_point"
    HOST = "host"
    UNKNOWN = "unknown"


@dataclass
class Interface:
    index: int
    name: str
    mac: Optional[str] = None
    ip: Optional[str] = None
    prefix_len: Optional[int] = None
    speed_mbps: Optional[int] = None
    admin_up: bool = True
    oper_up: bool = True


@dataclass
class Neighbor:
    """A neighbor learned from LLDP or CDP."""
    local_if: str
    remote_sysname: str
    remote_port: str
    remote_mgmt_ip: Optional[str] = None
    protocol: str = "lldp"          # lldp | cdp
    remote_chassis_id: Optional[str] = None


@dataclass
class FdbEntry:
    """One row of the bridge forwarding (MAC address) table."""
    mac: str
    local_if: str
    vlan: Optional[int] = None


@dataclass
class ArpEntry:
    ip: str
    mac: str
    local_if: str


@dataclass
class Route:
    dest: str            # network address
    prefix_len: int
    next_hop: str        # 0.0.0.0 == directly connected
    local_if: Optional[str] = None
    proto: str = "unknown"   # connected | static | ospf | bgp ...


@dataclass
class Device:
    """Everything discovery collects for a single node."""
    mgmt_ip: str
    sysname: str = ""
    sysdescr: str = ""
    sysobjectid: str = ""
    vendor: str = "unknown"
    model: str = ""
    role: DeviceRole = DeviceRole.UNKNOWN
    reachable: bool = True

    interfaces: list[Interface] = field(default_factory=list)
    neighbors: list[Neighbor] = field(default_factory=list)
    fdb: list[FdbEntry] = field(default_factory=list)
    arp: list[ArpEntry] = field(default_factory=list)
    routes: list[Route] = field(default_factory=list)

    def all_macs(self) -> set[str]:
        macs = {i.mac for i in self.interfaces if i.mac}
        return {m.lower() for m in macs if m}

    def connected_subnets(self) -> list[tuple[str, int, str]]:
        """(network, prefix_len, local_if) for each connected route."""
        out = []
        for r in self.routes:
            if r.next_hop in ("0.0.0.0", "", None) or r.proto == "connected":
                out.append((r.dest, r.prefix_len, r.local_if or ""))
        return out
