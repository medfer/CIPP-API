"""Per-device SNMP collection.

`collect_device` pulls system info, ifTable, LLDP/CDP neighbors, the FDB,
the ARP cache and the routing table for one device over a `SnmpTransport`,
and returns a populated `models.Device`. It only ever calls
`transport.get`/`transport.walk` -- it has no idea whether the transport is
`SimulatedTransport` or `LiveSnmpTransport`.
"""
from __future__ import annotations

from typing import Optional

from . import device_id, mibs
from .models import ArpEntry, Device, FdbEntry, Interface, Neighbor, Route
from .transport import SnmpTransport


def _walk_suffixes(transport: SnmpTransport, ip: str, oid_prefix: str) -> dict[str, str]:
    """Like transport.walk, but keyed by the index suffix instead of the
    full OID (e.g. "1.3...2.1.2.2.1.2.5" under prefix "1.3...2.1.2.2.1.2"
    becomes key "5")."""
    raw = transport.walk(ip, oid_prefix)
    plen = len(oid_prefix) + 1
    return {oid[plen:]: value for oid, value in raw.items()}


def _mask_to_prefix_len(mask: str) -> int:
    return sum(bin(int(octet)).count("1") for octet in mask.split("."))


def _normalize_mac(value: Optional[str]) -> Optional[str]:
    """Normalize a MAC-typed SNMP value to "aa:bb:cc:dd:ee:ff".

    SimulatedTransport already returns MACs in this form (passthrough,
    just lowercased). LiveSnmpTransport (pysnmp) renders OctetString MAC
    values as a single "0x..." hex blob via prettyPrint() -- unpack that
    into colon-separated octets so device_id.py's OUI fingerprinting
    (written against the colon-hex form) works identically against a real
    device.
    """
    if not value:
        return value
    if value.startswith(("0x", "0X")):
        hexpart = value[2:]
        return ":".join(hexpart[i:i + 2] for i in range(0, len(hexpart), 2)).lower()
    return value.lower()


def _lldp_local_ifindex(suffix: str) -> Optional[int]:
    """Local ifIndex from an lldpRemEntry suffix.

    SimulatedTransport collapses the index to a single "<ifIndex>" (see
    mibs.py). A real device follows LLDP-MIB's actual 3-part index --
    "<lldpRemTimeMark>.<lldpRemLocalPortNum>.<lldpRemIndex>" -- so take the
    middle component there instead. (lldpRemLocalPortNum isn't guaranteed
    to equal ifIndex on every platform -- that mapping technically lives in
    lldpLocPortTable -- but it does on the Cisco/Aruba/Juniper gear this
    POC targets, and this is the pragmatic approximation for a POC that
    doesn't walk a second table just to resolve it.)
    """
    parts = suffix.split(".")
    try:
        return int(parts[0]) if len(parts) == 1 else int(parts[1])
    except (ValueError, IndexError):
        return None


def _cdp_local_ifindex(suffix: str) -> Optional[int]:
    """Local ifIndex from a cdpCacheEntry suffix.

    SimulatedTransport collapses the index to a single "<ifIndex>". A real
    device follows CDP-MIB's actual 2-part index --
    "<cdpCacheIfIndex>.<cdpCacheDeviceIndex>" -- where the first component
    already is the ifIndex either way.
    """
    parts = suffix.split(".")
    try:
        return int(parts[0])
    except (ValueError, IndexError):
        return None


def _parse_fdb_suffix(suffix: str) -> tuple[int, str]:
    """"<vlan>.<6 decimal mac octets>" -> (vlan, "aa:bb:cc:dd:ee:ff")."""
    parts = suffix.split(".")
    vlan = int(parts[0])
    mac = ":".join(f"{int(o):02x}" for o in parts[1:7])
    return vlan, mac


def _parse_arp_suffix(suffix: str) -> tuple[int, str]:
    """"<ifIndex>.<a.b.c.d>" -> (ifIndex, "a.b.c.d")."""
    parts = suffix.split(".")
    return int(parts[0]), ".".join(parts[1:5])


def _parse_route_suffix(suffix: str) -> tuple[str, str]:
    """"<dest a.b.c.d>.<mask a.b.c.d>.<tos>.<nexthop a.b.c.d>" -> (dest, mask)."""
    parts = suffix.split(".")
    dest = ".".join(parts[0:4])
    mask = ".".join(parts[4:8])
    return dest, mask


def _collect_interfaces(transport: SnmpTransport, ip: str) -> list[Interface]:
    names = _walk_suffixes(transport, ip, mibs.IF_DESCR)
    macs = _walk_suffixes(transport, ip, mibs.IF_PHYS_ADDRESS)
    speeds = _walk_suffixes(transport, ip, mibs.IF_SPEED)
    admin = _walk_suffixes(transport, ip, mibs.IF_ADMIN_STATUS)
    oper = _walk_suffixes(transport, ip, mibs.IF_OPER_STATUS)

    interfaces = []
    for idx_str, name in names.items():
        speed_bps = speeds.get(idx_str)
        interfaces.append(Interface(
            index=int(idx_str),
            name=name,
            mac=_normalize_mac(macs.get(idx_str)),
            speed_mbps=int(speed_bps) // 1_000_000 if speed_bps else None,
            admin_up=admin.get(idx_str, "1") == "1",
            oper_up=oper.get(idx_str, "1") == "1",
        ))

    ip_ifindex = _walk_suffixes(transport, ip, mibs.IP_AD_ENT_IF_INDEX)
    ip_mask = _walk_suffixes(transport, ip, mibs.IP_AD_ENT_NET_MASK)
    by_index = {iface.index: iface for iface in interfaces}
    for ip_addr, ifidx_str in ip_ifindex.items():
        iface = by_index.get(int(ifidx_str))
        if iface is None:
            continue
        iface.ip = ip_addr
        mask = ip_mask.get(ip_addr)
        if mask:
            iface.prefix_len = _mask_to_prefix_len(mask)

    return interfaces


def _collect_neighbors(transport: SnmpTransport, ip: str,
                        by_index: dict[int, Interface]) -> list[Neighbor]:
    neighbors = []

    lldp_names = _walk_suffixes(transport, ip, mibs.LLDP_REM_SYS_NAME)
    lldp_ports = _walk_suffixes(transport, ip, mibs.LLDP_REM_PORT_ID)
    lldp_chassis = _walk_suffixes(transport, ip, mibs.LLDP_REM_CHASSIS_ID)
    lldp_mgmt = _walk_suffixes(transport, ip, mibs.LLDP_REM_MGMT_ADDR)
    for idx_str, remote_sysname in lldp_names.items():
        local_ifindex = _lldp_local_ifindex(idx_str)
        local_if = by_index.get(local_ifindex) if local_ifindex is not None else None
        neighbors.append(Neighbor(
            local_if=local_if.name if local_if else idx_str,
            remote_sysname=remote_sysname,
            remote_port=lldp_ports.get(idx_str, ""),
            remote_mgmt_ip=lldp_mgmt.get(idx_str),
            protocol="lldp",
            remote_chassis_id=lldp_chassis.get(idx_str),
        ))

    cdp_names = _walk_suffixes(transport, ip, mibs.CDP_CACHE_DEVICE_ID)
    cdp_ports = _walk_suffixes(transport, ip, mibs.CDP_CACHE_DEVICE_PORT)
    cdp_addrs = _walk_suffixes(transport, ip, mibs.CDP_CACHE_ADDRESS)
    for idx_str, remote_sysname in cdp_names.items():
        local_ifindex = _cdp_local_ifindex(idx_str)
        local_if = by_index.get(local_ifindex) if local_ifindex is not None else None
        neighbors.append(Neighbor(
            local_if=local_if.name if local_if else idx_str,
            remote_sysname=remote_sysname,
            remote_port=cdp_ports.get(idx_str, ""),
            remote_mgmt_ip=cdp_addrs.get(idx_str),
            protocol="cdp",
        ))

    return neighbors


def _collect_fdb(transport: SnmpTransport, ip: str,
                  by_index: dict[int, Interface]) -> list[FdbEntry]:
    raw = _walk_suffixes(transport, ip, mibs.DOT1Q_TP_FDB_PORT)
    entries = []
    for suffix, ifidx_str in raw.items():
        vlan, mac = _parse_fdb_suffix(suffix)
        local_if = by_index.get(int(ifidx_str))
        entries.append(FdbEntry(
            mac=mac,
            local_if=local_if.name if local_if else ifidx_str,
            vlan=vlan,
        ))
    return entries


def _collect_arp(transport: SnmpTransport, ip: str,
                  by_index: dict[int, Interface]) -> list[ArpEntry]:
    raw = _walk_suffixes(transport, ip, mibs.IP_NET_TO_MEDIA_PHYS_ADDRESS)
    entries = []
    for suffix, mac in raw.items():
        if_index, ip_addr = _parse_arp_suffix(suffix)
        local_if = by_index.get(if_index)
        entries.append(ArpEntry(
            ip=ip_addr,
            mac=_normalize_mac(mac),
            local_if=local_if.name if local_if else str(if_index),
        ))
    return entries


def _collect_routes(transport: SnmpTransport, ip: str,
                     by_index: dict[int, Interface]) -> list[Route]:
    next_hops = _walk_suffixes(transport, ip, mibs.IP_CIDR_ROUTE_NEXT_HOP)
    protos = _walk_suffixes(transport, ip, mibs.IP_CIDR_ROUTE_PROTO)
    ifindexes = _walk_suffixes(transport, ip, mibs.IP_CIDR_ROUTE_IF_INDEX)

    routes = []
    for suffix, next_hop in next_hops.items():
        dest, mask = _parse_route_suffix(suffix)
        ifidx_str = ifindexes.get(suffix)
        local_if: Optional[str] = None
        if ifidx_str:
            iface = by_index.get(int(ifidx_str))
            local_if = iface.name if iface else ifidx_str
        routes.append(Route(
            dest=dest,
            prefix_len=_mask_to_prefix_len(mask),
            next_hop=next_hop,
            local_if=local_if,
            proto=protos.get(suffix, "unknown"),
        ))
    return routes


def collect_device(transport: SnmpTransport, ip: str) -> Device:
    """Collect everything discovery needs for one device. Never raises for
    an unreachable device -- returns a `Device(reachable=False)` instead,
    so a single dead host can't take down the discovery BFS."""
    if not transport.is_reachable(ip):
        return Device(mgmt_ip=ip, reachable=False)

    sysdescr = transport.get(ip, mibs.SYS_DESCR) or ""
    sysobjectid = transport.get(ip, mibs.SYS_OBJECT_ID) or ""
    sysname = transport.get(ip, mibs.SYS_NAME) or ""
    sysservices_raw = transport.get(ip, mibs.SYS_SERVICES)
    sysservices = int(sysservices_raw) if sysservices_raw is not None else None

    interfaces = _collect_interfaces(transport, ip)
    by_index = {iface.index: iface for iface in interfaces}

    neighbors = _collect_neighbors(transport, ip, by_index)
    fdb = _collect_fdb(transport, ip, by_index)
    arp = _collect_arp(transport, ip, by_index)
    routes = _collect_routes(transport, ip, by_index)

    return Device(
        mgmt_ip=ip,
        sysname=sysname,
        sysdescr=sysdescr,
        sysobjectid=sysobjectid,
        vendor=device_id.classify_vendor(sysobjectid, sysdescr),
        role=device_id.classify_role(sysdescr, sysservices, has_routes=bool(routes)),
        reachable=True,
        interfaces=interfaces,
        neighbors=neighbors,
        fdb=fdb,
        arp=arp,
        routes=routes,
    )
