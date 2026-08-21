"""OID constants and sysObjectID / sysServices lookup tables.

Only the OIDs the collector actually walks are listed here. Values are
kept as plain dotted strings (no external MIB compiler) so both the
simulator and a real `pysnmp` transport can share them.
"""
from __future__ import annotations

# --- SNMPv2-MIB (system group) ---------------------------------------------
SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"
SYS_SERVICES = "1.3.6.1.2.1.1.7.0"

# --- IF-MIB ------------------------------------------------------------------
IF_INDEX = "1.3.6.1.2.1.2.2.1.1"
IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
IF_SPEED = "1.3.6.1.2.1.2.2.1.5"
IF_PHYS_ADDRESS = "1.3.6.1.2.1.2.2.1.6"
IF_ADMIN_STATUS = "1.3.6.1.2.1.2.2.1.7"
IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"

# IP-MIB: ipAddrTable, indexed by IP address, yields the owning ifIndex + mask
IP_AD_ENT_IF_INDEX = "1.3.6.1.2.1.4.20.1.2"
IP_AD_ENT_NET_MASK = "1.3.6.1.2.1.4.20.1.3"

# --- LLDP-MIB ------------------------------------------------------------------
# Simplified indexing for this POC: <local-ifIndex> -> value (real LLDP-MIB
# indexes by lldpRemTimeMark.lldpRemLocalPortNum.lldpRemIndex; collapsed here
# since the simulator only ever models one neighbor per local port).
LLDP_REM_SYS_NAME = "1.0.8802.1.1.2.1.4.1.1.9"
LLDP_REM_PORT_ID = "1.0.8802.1.1.2.1.4.1.1.7"
LLDP_REM_CHASSIS_ID = "1.0.8802.1.1.2.1.4.1.1.5"
LLDP_REM_MGMT_ADDR = "1.0.8802.1.1.2.1.4.2.1.3"

# --- CISCO-CDP-MIB ------------------------------------------------------------
# Same simplified <local-ifIndex> indexing as LLDP above.
CDP_CACHE_DEVICE_ID = "1.3.6.1.4.1.9.9.23.1.2.1.1.6"
CDP_CACHE_DEVICE_PORT = "1.3.6.1.4.1.9.9.23.1.2.1.1.7"
CDP_CACHE_ADDRESS = "1.3.6.1.4.1.9.9.23.1.2.1.1.4"

# --- Q-BRIDGE-MIB (VLAN-aware FDB) ---------------------------------------------
# Simplified indexing for this POC: <vlan>.<mac-as-6-decimal-octets> -> ifIndex
# (a real device indexes dot1qTpFdbTable per-VLAN via SNMP community/context
# rather than folding the VLAN into the OID; folding it in here keeps a single
# flat walk while still carrying the same (mac, ifIndex, vlan) information).
DOT1Q_TP_FDB_PORT = "1.3.6.1.2.1.17.7.1.2.2.1.2"

# --- IP-MIB (ARP cache) --------------------------------------------------------
# RFC 1213 indexing: ipNetToMediaPhysAddress.<ifIndex>.<ip a.b.c.d> -> mac
# IPv4-only (RFC 1213 predates IPv6) -- see ipNetToPhysicalTable below for
# the version-neutral replacement that also covers the IPv6 neighbor cache.
IP_NET_TO_MEDIA_PHYS_ADDRESS = "1.3.6.1.2.1.4.22.1.2"

# --- IP-MIB (RFC 4293, version-neutral IPv4+IPv6 tables) -----------------------
# ipAddressTable: index is <ipAddressAddrType>.<address-bytes>, where type is
# 1 (IPv4, 4 address-byte components) or 2 (IPv6, 16 address-byte
# components); the *value* returned for this column is the owning ifIndex.
IP_ADDRESS_IF_INDEX = "1.3.6.1.2.1.4.34.1.3"

# ipNetToPhysicalTable: the version-neutral ARP/IPv6-neighbor-cache
# replacement for ipNetToMediaTable. Index is
# <ifIndex>.<ipNetToPhysicalNetAddressType>.<address-bytes>, same address
# type/length convention as ipAddressTable above.
IP_NET_TO_PHYSICAL_PHYS_ADDRESS = "1.3.6.1.2.1.4.35.1.4"

# InetAddressType (INET-ADDRESS-MIB, RFC 4001) values this POC understands.
INET_ADDRESS_TYPE_IPV4 = 1
INET_ADDRESS_TYPE_IPV6 = 2

# --- IP-FORWARD-MIB / IP-MIB (routing table) -----------------------------------
# RFC 2096 indexing: ipCidrRoute*.<dest a.b.c.d>.<mask a.b.c.d>.<tos>.<nexthop>
IP_CIDR_ROUTE_NEXT_HOP = "1.3.6.1.2.1.4.24.4.1.4"
IP_CIDR_ROUTE_IF_INDEX = "1.3.6.1.2.1.4.24.4.1.5"
IP_CIDR_ROUTE_PROTO = "1.3.6.1.2.1.4.24.4.1.7"
IP_CIDR_ROUTE_MASK = "1.3.6.1.2.1.4.24.4.1.3"

# sysServices bit values (RFC 1213) we care about for role hints.
SYS_SERVICES_PHYSICAL = 1 << 0    # layer 1
SYS_SERVICES_DATALINK = 1 << 1    # layer 2 (bridge/switch)
SYS_SERVICES_INTERNET = 1 << 3    # layer 3 (router)

# sysObjectID enterprise prefixes -> vendor name. The enterprise number sits
# right after 1.3.6.1.4.1. in a sysObjectID.
ENTERPRISE_OID_VENDORS: dict[str, str] = {
    "1.3.6.1.4.1.9": "cisco",
    "1.3.6.1.4.1.2636": "juniper",
    "1.3.6.1.4.1.11": "hpe",
    "1.3.6.1.4.1.14823": "aruba",
    "1.3.6.1.4.1.12356": "fortinet",
    "1.3.6.1.4.1.311": "microsoft",
    "1.3.6.1.4.1.674": "dell",
}


def vendor_from_sysobjectid(sysobjectid: str) -> str:
    """Longest-prefix match of a sysObjectID against known enterprise OIDs."""
    best_match = ""
    best_vendor = "unknown"
    for prefix, vendor in ENTERPRISE_OID_VENDORS.items():
        if sysobjectid == prefix or sysobjectid.startswith(prefix + "."):
            if len(prefix) > len(best_match):
                best_match = prefix
                best_vendor = vendor
    return best_vendor
