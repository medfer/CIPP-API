"""Regression tests for value normalization in collector.py.

Every case here reproduces a bug that only showed up when discover_live.py
was pointed at a real Cisco switch -- SimulatedTransport's data never
exercises these formats because it hands back the already-normalized
shape collector.py expects. Losing any of these silently corrupts MAC/IP
addresses or crashes the LLDP/CDP neighbor walk against a real device.
"""
from netdiscovery.collector import (
    _cdp_local_ifindex, _lldp_local_ifindex, _normalize_ip, _normalize_mac,
)


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


def test_normalize_ip_unrecognized_format_left_as_is():
    # e.g. an IPv6 management address -- not silently mangled into a bogus
    # IPv4-shaped string, just passed through (won't resolve as a neighbor,
    # which is correct: this collector doesn't understand it yet).
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
