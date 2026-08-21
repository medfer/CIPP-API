"""Regression tests for value normalization in collector.py.

Every case here reproduces a bug that only showed up when discover_live.py
was pointed at a real Cisco switch -- SimulatedTransport's data never
exercises these formats because it hands back the already-normalized
shape collector.py expects. Losing any of these silently corrupts MAC/IP
addresses or crashes the LLDP/CDP neighbor walk against a real device.
"""
from netdiscovery.collector import (
    _cdp_local_ifindex, _collect_arp, _collect_interfaces,
    _lldp_local_ifindex, _normalize_ip, _normalize_mac,
    _parse_ip_address_suffix, _parse_net_to_physical_suffix,
)
from netdiscovery import mibs
from netdiscovery.models import Interface
from netdiscovery.transport import SnmpTransport


def test_normalize_mac_passthrough_for_simulated_colon_hex():
    assert _normalize_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"


def test_normalize_mac_from_pysnmp_hex_blob():
    # pysnmp's prettyPrint() on a real device's ifPhysAddress/ARP MAC.
    assert _normalize_mac("0x22c0b475371f") == "22:c0:b4:75:37:1f"


def test_normalize_mac_empty_and_none():
    assert _normalize_mac(None) is None
    assert _normalize_mac("") == ""


def test_normalize_ip_passthrough_for_simulated_dotted():
    assert _normalize_ip("192.168.1.1") == "192.168.1.1"


def test_normalize_ip_from_pysnmp_hex_blob():
    # pysnmp's prettyPrint() on a real device's LLDP remote-management-address
    # / CDP cache address -- reproduced live: crashed discovery.py's BFS by
    # handing "0xc0a81f8a" to UdpTransportTarget as if it were a hostname.
    assert _normalize_ip("0xc0a81f8a") == "192.168.31.138"


def test_normalize_ip_empty_and_none():
    assert _normalize_ip(None) is None
    assert _normalize_ip("") == ""


def test_normalize_ip_ipv6_hex_blob():
    # pysnmp's prettyPrint() on a real device's IPv6 LLDP/CDP management
    # address -- 16 raw bytes ("0x" + 32 hex chars), same OctetString
    # issue as the IPv4 case above, just longer.
    assert _normalize_ip("0x20010db8000000000000000000000001") == "2001:db8::1"


def test_normalize_ip_unrecognized_hex_length_left_as_is():
    # Not 8 or 32 hex chars (neither IPv4 nor IPv6 byte count) -- not
    # silently mangled into a bogus address, just passed through (won't
    # resolve as a neighbor, which is correct for a format this collector
    # doesn't understand).
    assert _normalize_ip("0xabcd") == "0xabcd"


def test_normalize_ip_non_hex_content_left_as_is():
    assert _normalize_ip("0xnotahexblob") == "0xnotahexblob"


def test_lldp_local_ifindex_simulated_single_component():
    assert _lldp_local_ifindex("5") == 5


def test_lldp_local_ifindex_real_device_three_component():
    # Real LLDP-MIB lldpRemEntry index: <timeMark>.<localPortNum>.<remIndex>.
    # Reproduced live against a Cisco switch: crashed with
    # "ValueError: invalid literal for int() with base 10: '10113.98'"
    # when the code assumed a single-component suffix.
    assert _lldp_local_ifindex("0.113.98") == 113


def test_lldp_local_ifindex_malformed_suffix_returns_none():
    assert _lldp_local_ifindex("not.an.int") is None


def test_cdp_local_ifindex_simulated_single_component():
    assert _cdp_local_ifindex("5") == 5


def test_cdp_local_ifindex_real_device_two_component():
    # Real CDP-MIB cdpCacheEntry index: <cdpCacheIfIndex>.<cdpCacheDeviceIndex>.
    assert _cdp_local_ifindex("113.1") == 113


def test_cdp_local_ifindex_malformed_suffix_returns_none():
    assert _cdp_local_ifindex("not-an-int") is None


# --- RFC 4293 version-neutral tables (ipAddressTable / ipNetToPhysicalTable) ---
# Not validated against real IPv6 SNMP traffic -- this dev sandbox has no
# IPv6 stack at all (no /proc/net/if_inet6). These test the parsing logic
# against hand-built, RFC-correct synthetic data instead; see README for
# that caveat stated plainly rather than implied.

def test_parse_ip_address_suffix_ipv4():
    assert _parse_ip_address_suffix("1.192.168.1.1") == "192.168.1.1"


def test_parse_ip_address_suffix_ipv6():
    suffix = "2." + ".".join(str(b) for b in bytes.fromhex("20010db8000000000000000000000001"))
    assert _parse_ip_address_suffix(suffix) == "2001:db8::1"


def test_parse_ip_address_suffix_unknown_type_returns_none():
    assert _parse_ip_address_suffix("16.1.2.3.4") is None


def test_parse_net_to_physical_suffix_ipv4():
    assert _parse_net_to_physical_suffix("5.1.192.168.1.1") == (5, "192.168.1.1")


def test_parse_net_to_physical_suffix_ipv6():
    addr_bytes = ".".join(str(b) for b in bytes.fromhex("fe800000000000000000000000000001"))
    assert _parse_net_to_physical_suffix(f"7.2.{addr_bytes}") == (7, "fe80::1")


def test_parse_net_to_physical_suffix_malformed_ifindex():
    assert _parse_net_to_physical_suffix("not-an-int.1.192.168.1.1") == (None, None)


class _FakeTable(SnmpTransport):
    """Minimal hand-built OID table -- like SimulatedTransport, but built
    inline per test instead of the full modeled network."""

    def __init__(self, table: dict[str, str]):
        self._table = table

    def is_reachable(self, ip: str) -> bool:
        return True

    def get(self, ip: str, oid: str):
        return self._table.get(oid)

    def walk(self, ip: str, oid_prefix: str) -> dict[str, str]:
        dotted = oid_prefix + "."
        return {oid: v for oid, v in self._table.items()
                if oid == oid_prefix or oid.startswith(dotted)}


def _ipv6_bytes_suffix(addr: str) -> str:
    import ipaddress
    return ".".join(str(b) for b in ipaddress.IPv6Address(addr).packed)


def test_collect_interfaces_dual_stack_keeps_legacy_ipv4_over_new_ipv6():
    table = {
        f"{mibs.IF_DESCR}.1": "Gi0/1",
        f"{mibs.IP_AD_ENT_IF_INDEX}.10.0.0.1": "1",
        f"{mibs.IP_ADDRESS_IF_INDEX}.2.{_ipv6_bytes_suffix('2001:db8::1')}": "1",
    }
    interfaces = _collect_interfaces(_FakeTable(table), "irrelevant")
    assert len(interfaces) == 1
    # Single-address model (models.py): legacy IPv4 wins on a dual-stack
    # interface rather than being silently overwritten by the IPv6 walk.
    assert interfaces[0].ip == "10.0.0.1"


def test_collect_interfaces_ipv6_only_interface_picked_up():
    table = {
        f"{mibs.IF_DESCR}.2": "Gi0/2",
        f"{mibs.IP_ADDRESS_IF_INDEX}.2.{_ipv6_bytes_suffix('2001:db8::2')}": "2",
    }
    interfaces = _collect_interfaces(_FakeTable(table), "irrelevant")
    assert len(interfaces) == 1
    assert interfaces[0].ip == "2001:db8::2"


def test_collect_arp_merges_ipv6_neighbor_cache_without_duplicating_ipv4():
    table = {
        f"{mibs.IF_DESCR}.1": "Gi0/1",
        # Legacy ARP: one IPv4 entry.
        f"{mibs.IP_NET_TO_MEDIA_PHYS_ADDRESS}.1.10.0.0.5": "aa:bb:cc:00:00:05",
        # RFC 4293 table: the *same* IPv4 entry answered again (common on
        # real devices) plus one genuinely new IPv6-only neighbor.
        f"{mibs.IP_NET_TO_PHYSICAL_PHYS_ADDRESS}.1.1.10.0.0.5": "aa:bb:cc:00:00:05",
        f"{mibs.IP_NET_TO_PHYSICAL_PHYS_ADDRESS}.1.2.{_ipv6_bytes_suffix('2001:db8::5')}": "aa:bb:cc:00:00:06",
    }
    by_index = {1: Interface(index=1, name="Gi0/1")}
    entries = _collect_arp(_FakeTable(table), "irrelevant", by_index)

    ips = {e.ip for e in entries}
    assert ips == {"10.0.0.5", "2001:db8::5"}, "IPv4 entry must not be duplicated by the RFC4293 walk"
