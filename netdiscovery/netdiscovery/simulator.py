"""In-memory simulated network the demo runs discovery against.

Models a small but non-trivial multi-vendor enterprise network:

- 2x Cisco Nexus core L3 switches (core1, core2), directly linked to each
  other AND both linked to both distribution switches -- a redundant
  dual-uplink ring, not a tree.
- 2x Cisco Catalyst distribution switches (dist1, dist2), L2 only.
- 4x mixed-vendor access switches: Cisco IOS, Aruba/HPE (ArubaOS-CX),
  Juniper (Junos EX), and a second Cisco IOS switch with LLDP disabled
  (CDP-only), to prove multi-protocol L2 discovery. acc1 is dual-homed to
  both distribution switches.
- 1x Fortinet FortiGate firewall as the L3 edge / default gateway.
- 1x unreachable "legacy" switch, discoverable as an LLDP neighbor of
  dist1 but never answering SNMP, to prove BFS discovery tolerates
  unreachable/timeout devices instead of crashing.
- 11 endpoints across 3 VLANs that never speak LLDP/CDP -- 3 servers
  (VLAN 20), 4 PCs + 2 printers (VLAN 10), 2 IP cameras (VLAN 30) --
  discoverable only via ARP (on the core switches) + FDB (on the access
  switches) + MAC-OUI fingerprinting.

`SimulatedTransport` implements the same `SnmpTransport` interface a real
device would answer: `get`/`walk` return OID -> value maps built from the
structured `_SimDevice` definitions below, using the same OID layout
`mibs.py` declares. The discovery engine cannot tell this apart from
`LiveSnmpTransport` talking to real hardware -- swap the transport and the
same engine runs against a real network.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from . import mibs
from .transport import SnmpTransport


@dataclass
class _SimInterface:
    index: int
    name: str
    mac: str
    ip: Optional[str] = None
    prefix_len: Optional[int] = None
    speed_mbps: int = 1000
    admin_up: bool = True
    oper_up: bool = True


@dataclass
class _SimNeighbor:
    local_if_index: int
    protocol: str  # "lldp" | "cdp"
    remote_sysname: str
    remote_port: str
    remote_mgmt_ip: Optional[str] = None
    remote_chassis_id: Optional[str] = None


@dataclass
class _SimFdbRow:
    mac: str
    if_index: int
    vlan: int


@dataclass
class _SimArpRow:
    ip: str
    mac: str
    if_index: int


@dataclass
class _SimRoute:
    dest: str
    prefix_len: int
    next_hop: str
    if_index: Optional[int]
    proto: str


@dataclass
class _SimDevice:
    mgmt_ip: str
    sysname: str = ""
    sysdescr: str = ""
    sysobjectid: str = ""
    sysservices: int = 0
    interfaces: list[_SimInterface] = field(default_factory=list)
    neighbors: list[_SimNeighbor] = field(default_factory=list)
    fdb: list[_SimFdbRow] = field(default_factory=list)
    arp: list[_SimArpRow] = field(default_factory=list)
    routes: list[_SimRoute] = field(default_factory=list)
    reachable: bool = True


def _mask(prefix_len: int) -> str:
    bits = "1" * prefix_len + "0" * (32 - prefix_len)
    return ".".join(str(int(bits[i:i + 8], 2)) for i in range(0, 32, 8))


def _mac_to_dotted_decimal(mac: str) -> str:
    return ".".join(str(int(octet, 16)) for octet in mac.split(":"))


def _build_oid_table(dev: _SimDevice) -> dict[str, str]:
    """Render a `_SimDevice` into the flat OID->value map a real SNMP agent
    would answer, using the layout declared in mibs.py."""
    table: dict[str, str] = {
        mibs.SYS_DESCR: dev.sysdescr,
        mibs.SYS_OBJECT_ID: dev.sysobjectid,
        mibs.SYS_NAME: dev.sysname,
        mibs.SYS_SERVICES: str(dev.sysservices),
        mibs.SYS_UPTIME: "123456700",
    }

    for intf in dev.interfaces:
        table[f"{mibs.IF_INDEX}.{intf.index}"] = str(intf.index)
        table[f"{mibs.IF_DESCR}.{intf.index}"] = intf.name
        table[f"{mibs.IF_SPEED}.{intf.index}"] = str(intf.speed_mbps * 1_000_000)
        table[f"{mibs.IF_PHYS_ADDRESS}.{intf.index}"] = intf.mac
        table[f"{mibs.IF_ADMIN_STATUS}.{intf.index}"] = "1" if intf.admin_up else "2"
        table[f"{mibs.IF_OPER_STATUS}.{intf.index}"] = "1" if intf.oper_up else "2"
        if intf.ip:
            table[f"{mibs.IP_AD_ENT_IF_INDEX}.{intf.ip}"] = str(intf.index)
            table[f"{mibs.IP_AD_ENT_NET_MASK}.{intf.ip}"] = _mask(intf.prefix_len or 32)

    for n in dev.neighbors:
        if n.protocol == "lldp":
            table[f"{mibs.LLDP_REM_SYS_NAME}.{n.local_if_index}"] = n.remote_sysname
            table[f"{mibs.LLDP_REM_PORT_ID}.{n.local_if_index}"] = n.remote_port
            if n.remote_chassis_id:
                table[f"{mibs.LLDP_REM_CHASSIS_ID}.{n.local_if_index}"] = n.remote_chassis_id
            if n.remote_mgmt_ip:
                table[f"{mibs.LLDP_REM_MGMT_ADDR}.{n.local_if_index}"] = n.remote_mgmt_ip
        else:
            table[f"{mibs.CDP_CACHE_DEVICE_ID}.{n.local_if_index}"] = n.remote_sysname
            table[f"{mibs.CDP_CACHE_DEVICE_PORT}.{n.local_if_index}"] = n.remote_port
            if n.remote_mgmt_ip:
                table[f"{mibs.CDP_CACHE_ADDRESS}.{n.local_if_index}"] = n.remote_mgmt_ip

    for row in dev.fdb:
        idx = f"{row.vlan}.{_mac_to_dotted_decimal(row.mac)}"
        table[f"{mibs.DOT1Q_TP_FDB_PORT}.{idx}"] = str(row.if_index)

    for row in dev.arp:
        idx = f"{row.if_index}.{row.ip}"
        table[f"{mibs.IP_NET_TO_MEDIA_PHYS_ADDRESS}.{idx}"] = row.mac

    for r in dev.routes:
        mask = _mask(r.prefix_len)
        idx = f"{r.dest}.{mask}.0.{r.next_hop}"
        table[f"{mibs.IP_CIDR_ROUTE_NEXT_HOP}.{idx}"] = r.next_hop
        table[f"{mibs.IP_CIDR_ROUTE_MASK}.{idx}"] = mask
        table[f"{mibs.IP_CIDR_ROUTE_PROTO}.{idx}"] = r.proto
        if r.if_index is not None:
            table[f"{mibs.IP_CIDR_ROUTE_IF_INDEX}.{idx}"] = str(r.if_index)

    return table


class SimulatedTransport(SnmpTransport):
    """Serves the modeled network below through the SnmpTransport interface."""

    def __init__(self) -> None:
        self._devices: dict[str, _SimDevice] = _build_network()
        self._oid_tables: dict[str, dict[str, str]] = {
            ip: _build_oid_table(dev) for ip, dev in self._devices.items()
        }

    def is_reachable(self, ip: str) -> bool:
        dev = self._devices.get(ip)
        return dev is not None and dev.reachable

    def get(self, ip: str, oid: str) -> Optional[str]:
        if not self.is_reachable(ip):
            return None
        return self._oid_tables[ip].get(oid)

    def walk(self, ip: str, oid_prefix: str) -> dict[str, str]:
        if not self.is_reachable(ip):
            return {}
        dotted_prefix = oid_prefix + "."
        return {
            oid: value
            for oid, value in self._oid_tables[ip].items()
            if oid == oid_prefix or oid.startswith(dotted_prefix)
        }

    def all_mgmt_ips(self) -> list[str]:
        """Every device the simulator knows about, reachable or not."""
        return list(self._devices.keys())


# One seed is enough -- BFS discovers everything else via LLDP/CDP.
DEFAULT_SEED_IPS = ["10.10.99.1"]


def _build_network() -> dict[str, _SimDevice]:
    devices: dict[str, _SimDevice] = {}

    def add(dev: _SimDevice) -> None:
        devices[dev.mgmt_ip] = dev

    # --- Endpoint MAC/IP plan (VLAN 10 users, 20 servers, 30 cameras) ------
    servers = [
        ("server1", "02:33:01:00:00:01", "10.10.20.11"),
        ("server2", "02:33:02:00:00:01", "10.10.20.12"),
        ("server3", "02:33:03:00:00:01", "10.10.20.13"),
    ]
    pcs = [
        ("pc1", "02:44:01:00:00:01", "10.10.10.21"),
        ("pc2", "02:44:02:00:00:01", "10.10.10.22"),
        ("pc3", "02:44:03:00:00:01", "10.10.10.23"),
        ("pc4", "02:44:04:00:00:01", "10.10.10.24"),
    ]
    printers = [
        ("printer1", "02:11:01:00:00:01", "10.10.10.31"),
        ("printer2", "02:11:02:00:00:01", "10.10.10.32"),
    ]
    cameras = [
        ("camera1", "02:22:01:00:00:01", "10.10.30.41"),
        ("camera2", "02:22:02:00:00:01", "10.10.30.42"),
    ]

    l3_switch_services = mibs.SYS_SERVICES_PHYSICAL | mibs.SYS_SERVICES_DATALINK | mibs.SYS_SERVICES_INTERNET
    l2_switch_services = mibs.SYS_SERVICES_PHYSICAL | mibs.SYS_SERVICES_DATALINK
    firewall_services = mibs.SYS_SERVICES_PHYSICAL | mibs.SYS_SERVICES_INTERNET

    # --- core1 (Cisco Nexus, L3) -------------------------------------------
    core1 = _SimDevice(
        mgmt_ip="10.10.99.1",
        sysname="core1-nexus",
        sysdescr="Cisco NX-OS(tm) n9000, Software (n9000-dk9), Version 9.3(10), "
                 "Nexus9000 C93180YC-EX Chassis",
        sysobjectid="1.3.6.1.4.1.9.12.3.1.3.1965",
        sysservices=l3_switch_services,
        interfaces=[
            _SimInterface(1, "Ethernet1/1", "aa:00:01:00:00:01", "10.255.0.1", 30, 10000),
            _SimInterface(2, "Ethernet1/2", "aa:00:01:00:00:02", speed_mbps=10000),
            _SimInterface(3, "Ethernet1/3", "aa:00:01:00:00:03", speed_mbps=10000),
            _SimInterface(4, "Ethernet1/4", "aa:00:01:00:00:04", "10.255.1.1", 30, 1000),
            _SimInterface(5, "Vlan10", "aa:00:01:00:00:05", "10.10.10.1", 24),
            _SimInterface(6, "Vlan20", "aa:00:01:00:00:06", "10.10.20.1", 24),
            _SimInterface(7, "Vlan30", "aa:00:01:00:00:07", "10.10.30.1", 24),
            _SimInterface(8, "Vlan99", "aa:00:01:00:00:08", "10.10.99.1", 24),
        ],
        neighbors=[
            _SimNeighbor(1, "lldp", "core2-nexus", "Ethernet1/1", "10.10.99.2"),
            _SimNeighbor(2, "lldp", "dist1-cat9k", "Ethernet1/0/1", "10.10.99.3"),
            _SimNeighbor(3, "lldp", "dist2-cat9k", "Ethernet1/0/1", "10.10.99.4"),
            _SimNeighbor(4, "lldp", "fw1-fortigate", "port1", "10.255.1.2"),
        ],
        routes=[
            _SimRoute("10.255.0.0", 30, "0.0.0.0", 1, "connected"),
            _SimRoute("10.255.1.0", 30, "0.0.0.0", 4, "connected"),
            _SimRoute("10.10.10.0", 24, "0.0.0.0", 5, "connected"),
            _SimRoute("10.10.20.0", 24, "0.0.0.0", 6, "connected"),
            _SimRoute("10.10.30.0", 24, "0.0.0.0", 7, "connected"),
            _SimRoute("10.10.99.0", 24, "0.0.0.0", 8, "connected"),
            _SimRoute("0.0.0.0", 0, "10.255.1.2", 4, "static"),
        ],
        arp=[
            *[_SimArpRow(ip, mac, 5) for _n, mac, ip in pcs],
            *[_SimArpRow(ip, mac, 5) for _n, mac, ip in printers],
            *[_SimArpRow(ip, mac, 6) for _n, mac, ip in servers],
            *[_SimArpRow(ip, mac, 7) for _n, mac, ip in cameras],
        ],
    )
    add(core1)

    # --- core2 (Cisco Nexus, L3) -------------------------------------------
    core2 = _SimDevice(
        mgmt_ip="10.10.99.2",
        sysname="core2-nexus",
        sysdescr="Cisco NX-OS(tm) n9000, Software (n9000-dk9), Version 9.3(10), "
                 "Nexus9000 C93180YC-EX Chassis",
        sysobjectid="1.3.6.1.4.1.9.12.3.1.3.1965",
        sysservices=l3_switch_services,
        interfaces=[
            _SimInterface(1, "Ethernet1/1", "aa:00:02:00:00:01", "10.255.0.2", 30, 10000),
            _SimInterface(2, "Ethernet1/2", "aa:00:02:00:00:02", speed_mbps=10000),
            _SimInterface(3, "Ethernet1/3", "aa:00:02:00:00:03", speed_mbps=10000),
            _SimInterface(4, "Vlan10", "aa:00:02:00:00:04", "10.10.10.2", 24),
            _SimInterface(5, "Vlan20", "aa:00:02:00:00:05", "10.10.20.2", 24),
            _SimInterface(6, "Vlan30", "aa:00:02:00:00:06", "10.10.30.2", 24),
            _SimInterface(7, "Vlan99", "aa:00:02:00:00:07", "10.10.99.2", 24),
        ],
        neighbors=[
            _SimNeighbor(1, "lldp", "core1-nexus", "Ethernet1/1", "10.10.99.1"),
            _SimNeighbor(2, "lldp", "dist1-cat9k", "Ethernet1/0/2", "10.10.99.3"),
            _SimNeighbor(3, "lldp", "dist2-cat9k", "Ethernet1/0/2", "10.10.99.4"),
        ],
        routes=[
            _SimRoute("10.255.0.0", 30, "0.0.0.0", 1, "connected"),
            _SimRoute("10.10.10.0", 24, "0.0.0.0", 4, "connected"),
            _SimRoute("10.10.20.0", 24, "0.0.0.0", 5, "connected"),
            _SimRoute("10.10.30.0", 24, "0.0.0.0", 6, "connected"),
            _SimRoute("10.10.99.0", 24, "0.0.0.0", 7, "connected"),
            _SimRoute("0.0.0.0", 0, "10.255.0.1", 1, "static"),
        ],
        # Secondary gateway: only sees infra ARP traffic, not every endpoint.
        arp=[],
    )
    add(core2)

    # --- fw1 (Fortinet FortiGate, L3 edge) -----------------------------------
    fw1 = _SimDevice(
        mgmt_ip="10.255.1.2",
        sysname="fw1-fortigate",
        sysdescr="Fortinet FortiGate-100F v7.2.5,build1517 (GA) FortiOS",
        sysobjectid="1.3.6.1.4.1.12356.101.1.10039",
        sysservices=firewall_services,
        interfaces=[
            _SimInterface(1, "port1", "bb:00:01:00:00:01", "10.255.1.2", 30, 1000),
            _SimInterface(2, "wan1", "bb:00:01:00:00:02", "203.0.113.2", 30, 1000),
        ],
        neighbors=[
            _SimNeighbor(1, "lldp", "core1-nexus", "Ethernet1/4", "10.10.99.1"),
        ],
        routes=[
            _SimRoute("10.255.1.0", 30, "0.0.0.0", 1, "connected"),
            _SimRoute("203.0.113.0", 30, "0.0.0.0", 2, "connected"),
            _SimRoute("0.0.0.0", 0, "203.0.113.1", 2, "static"),
        ],
    )
    add(fw1)

    # --- dist1 (Cisco Catalyst, L2 only) -------------------------------------
    dist1 = _SimDevice(
        mgmt_ip="10.10.99.3",
        sysname="dist1-cat9k",
        sysdescr="Cisco IOS Software, Catalyst L3 Switch Software (CAT9K_IOSXE), "
                 "Version 17.9.4",
        sysobjectid="1.3.6.1.4.1.9.1.2694",
        sysservices=l2_switch_services,
        interfaces=[
            _SimInterface(1, "Ethernet1/0/1", "cc:00:01:00:00:01"),
            _SimInterface(2, "Ethernet1/0/2", "cc:00:01:00:00:02"),
            _SimInterface(3, "Ethernet1/0/3", "cc:00:01:00:00:03"),
            _SimInterface(4, "Ethernet1/0/4", "cc:00:01:00:00:04"),
            _SimInterface(5, "Ethernet1/0/5", "cc:00:01:00:00:05"),
            _SimInterface(6, "Vlan99", "cc:00:01:00:00:06", "10.10.99.3", 24),
        ],
        neighbors=[
            _SimNeighbor(1, "lldp", "core1-nexus", "Ethernet1/2", "10.10.99.1"),
            _SimNeighbor(2, "lldp", "core2-nexus", "Ethernet1/2", "10.10.99.2"),
            _SimNeighbor(3, "lldp", "acc1-cisco", "GigabitEthernet0/1", "10.10.99.5"),
            _SimNeighbor(4, "lldp", "acc2-aruba", "1/1/1", "10.10.99.6"),
            _SimNeighbor(5, "lldp", "acc5-legacy", "Fa0/1", "10.10.99.11"),
        ],
    )
    add(dist1)

    # --- dist2 (Cisco Catalyst, L2 only) -------------------------------------
    dist2 = _SimDevice(
        mgmt_ip="10.10.99.4",
        sysname="dist2-cat9k",
        sysdescr="Cisco IOS Software, Catalyst L3 Switch Software (CAT9K_IOSXE), "
                 "Version 17.9.4",
        sysobjectid="1.3.6.1.4.1.9.1.2694",
        sysservices=l2_switch_services,
        interfaces=[
            _SimInterface(1, "Ethernet1/0/1", "cc:00:02:00:00:01"),
            _SimInterface(2, "Ethernet1/0/2", "cc:00:02:00:00:02"),
            _SimInterface(3, "Ethernet1/0/3", "cc:00:02:00:00:03"),
            _SimInterface(4, "Ethernet1/0/4", "cc:00:02:00:00:04"),
            _SimInterface(5, "Ethernet1/0/5", "cc:00:02:00:00:05"),
            _SimInterface(6, "Vlan99", "cc:00:02:00:00:06", "10.10.99.4", 24),
        ],
        neighbors=[
            _SimNeighbor(1, "lldp", "core1-nexus", "Ethernet1/3", "10.10.99.1"),
            _SimNeighbor(2, "lldp", "core2-nexus", "Ethernet1/3", "10.10.99.2"),
            _SimNeighbor(3, "lldp", "acc1-cisco", "GigabitEthernet0/2", "10.10.99.5"),
            _SimNeighbor(4, "lldp", "acc3-juniper", "ge-0/0/0", "10.10.99.7"),
            # acc4 only speaks CDP -- proves the multi-protocol L2 path.
            _SimNeighbor(5, "cdp", "acc4-cisco-cdp", "FastEthernet0/1", "10.10.99.8"),
        ],
    )
    add(dist2)

    # --- acc1 (Cisco IOS, LLDP, dual-homed) -- hosts servers (VLAN 20) ------
    acc1 = _SimDevice(
        mgmt_ip="10.10.99.5",
        sysname="acc1-cisco",
        sysdescr="Cisco IOS Software, C9200L Software, Version 17.6.5",
        sysobjectid="1.3.6.1.4.1.9.1.2618",
        sysservices=l2_switch_services,
        interfaces=[
            _SimInterface(1, "GigabitEthernet0/1", "dd:00:01:00:00:01"),
            _SimInterface(2, "GigabitEthernet0/2", "dd:00:01:00:00:02"),
            _SimInterface(3, "GigabitEthernet0/3", "dd:00:01:00:00:03"),
            _SimInterface(4, "GigabitEthernet0/4", "dd:00:01:00:00:04"),
            _SimInterface(5, "GigabitEthernet0/5", "dd:00:01:00:00:05"),
            _SimInterface(6, "Vlan99", "dd:00:01:00:00:06", "10.10.99.5", 24),
        ],
        neighbors=[
            _SimNeighbor(1, "lldp", "dist1-cat9k", "Ethernet1/0/3", "10.10.99.3"),
            _SimNeighbor(2, "lldp", "dist2-cat9k", "Ethernet1/0/3", "10.10.99.4"),
        ],
        fdb=[
            _SimFdbRow(servers[0][1], 3, 20),
            _SimFdbRow(servers[1][1], 4, 20),
            _SimFdbRow(servers[2][1], 5, 20),
        ],
    )
    add(acc1)

    # --- acc2 (Aruba/HPE ArubaOS-CX, LLDP) -- hosts PCs + printer1 (VLAN 10) -
    acc2 = _SimDevice(
        mgmt_ip="10.10.99.6",
        sysname="acc2-aruba",
        sysdescr="ArubaOS-CX 10.11.1000 Aruba 6300M",
        sysobjectid="1.3.6.1.4.1.14823.1.2.100",
        sysservices=l2_switch_services,
        interfaces=[
            _SimInterface(1, "1/1/1", "ee:00:01:00:00:01"),
            _SimInterface(2, "1/1/2", "ee:00:01:00:00:02"),
            _SimInterface(3, "1/1/3", "ee:00:01:00:00:03"),
            _SimInterface(4, "1/1/4", "ee:00:01:00:00:04"),
            _SimInterface(5, "1/1/5", "ee:00:01:00:00:05"),
            _SimInterface(6, "vlan99", "ee:00:01:00:00:06", "10.10.99.6", 24),
        ],
        neighbors=[
            _SimNeighbor(1, "lldp", "dist1-cat9k", "Ethernet1/0/4", "10.10.99.3"),
        ],
        fdb=[
            _SimFdbRow(pcs[0][1], 2, 10),
            _SimFdbRow(pcs[1][1], 3, 10),
            _SimFdbRow(pcs[2][1], 4, 10),
            _SimFdbRow(printers[0][1], 5, 10),
        ],
    )
    add(acc2)

    # --- acc3 (Juniper Junos EX, LLDP) -- hosts cameras (VLAN 30) -----------
    acc3 = _SimDevice(
        mgmt_ip="10.10.99.7",
        sysname="acc3-juniper",
        sysdescr="Juniper Networks, Inc. ex3400-24t internet router, kernel JUNOS 21.4R3",
        sysobjectid="1.3.6.1.4.1.2636.1.1.1.4.85.1.1",
        sysservices=l2_switch_services,
        interfaces=[
            _SimInterface(1, "ge-0/0/0", "ff:00:01:00:00:01"),
            _SimInterface(2, "ge-0/0/1", "ff:00:01:00:00:02"),
            _SimInterface(3, "ge-0/0/2", "ff:00:01:00:00:03"),
            _SimInterface(4, "irb.99", "ff:00:01:00:00:04", "10.10.99.7", 24),
        ],
        neighbors=[
            _SimNeighbor(1, "lldp", "dist2-cat9k", "Ethernet1/0/4", "10.10.99.4"),
        ],
        fdb=[
            _SimFdbRow(cameras[0][1], 2, 30),
            _SimFdbRow(cameras[1][1], 3, 30),
        ],
    )
    add(acc3)

    # --- acc4 (Cisco IOS, CDP only) -- hosts pc4 + printer2 (VLAN 10) -------
    acc4 = _SimDevice(
        mgmt_ip="10.10.99.8",
        sysname="acc4-cisco-cdp",
        sysdescr="Cisco IOS Software, C2960X Software, Version 15.2(7)E3",
        sysobjectid="1.3.6.1.4.1.9.1.1208",
        sysservices=l2_switch_services,
        interfaces=[
            _SimInterface(1, "FastEthernet0/1", "11:00:01:00:00:01"),
            _SimInterface(2, "FastEthernet0/2", "11:00:01:00:00:02"),
            _SimInterface(3, "FastEthernet0/3", "11:00:01:00:00:03"),
            _SimInterface(4, "Vlan99", "11:00:01:00:00:04", "10.10.99.8", 24),
        ],
        # LLDP disabled on this switch -- dist2 only ever sees it via CDP.
        neighbors=[
            _SimNeighbor(1, "cdp", "dist2-cat9k", "Ethernet1/0/5", "10.10.99.4"),
        ],
        fdb=[
            _SimFdbRow(pcs[3][1], 2, 10),
            _SimFdbRow(printers[1][1], 3, 10),
        ],
    )
    add(acc4)

    # --- acc5-legacy -- advertised by dist1 via LLDP, never answers SNMP ---
    add(_SimDevice(mgmt_ip="10.10.99.11", sysname="acc5-legacy", reachable=False))

    return devices
