from netdiscovery.device_id import classify_role, classify_vendor, fingerprint_endpoint
from netdiscovery.mibs import SYS_SERVICES_DATALINK, SYS_SERVICES_INTERNET
from netdiscovery.models import DeviceRole


def test_vendor_from_sysobjectid_cisco():
    assert classify_vendor("1.3.6.1.4.1.9.1.1861", "") == "cisco"


def test_vendor_from_sysobjectid_juniper():
    assert classify_vendor("1.3.6.1.4.1.2636.1.1.1.2.57", "") == "juniper"


def test_vendor_falls_back_to_sysdescr():
    assert classify_vendor("", "Aruba Operating System ArubaOS-CX") == "aruba"


def test_vendor_unknown_when_nothing_matches():
    assert classify_vendor("1.2.3.4", "some generic device") == "unknown"


def test_role_firewall_from_keyword():
    role = classify_role("Fortinet FortiGate-100F v7.2.5 FortiOS", sysservices=79)
    assert role == DeviceRole.FIREWALL


def test_role_access_point_from_keyword():
    role = classify_role("Aruba AP-515 Access Point", sysservices=None)
    assert role == DeviceRole.ACCESS_POINT


def test_role_l3_switch_when_both_bits_set():
    services = SYS_SERVICES_INTERNET | SYS_SERVICES_DATALINK
    role = classify_role("Cisco Nexus 9300 NX-OS", sysservices=services)
    assert role == DeviceRole.L3_SWITCH


def test_role_router_when_only_internet_bit_set():
    role = classify_role("Generic router", sysservices=SYS_SERVICES_INTERNET)
    assert role == DeviceRole.ROUTER


def test_role_switch_when_only_datalink_bit_set():
    role = classify_role("Cisco IOS switch", sysservices=SYS_SERVICES_DATALINK)
    assert role == DeviceRole.SWITCH


def test_role_host_when_no_relevant_bits():
    role = classify_role("Some end host OS", sysservices=0)
    assert role == DeviceRole.HOST


def test_role_unknown_when_nothing_to_go_on():
    assert classify_role("", None) == DeviceRole.UNKNOWN


def test_role_l3_switch_from_routes_without_sysservices():
    role = classify_role("Cisco IOS switch", sysservices=SYS_SERVICES_DATALINK, has_routes=True)
    assert role == DeviceRole.L3_SWITCH


def test_fingerprint_endpoint_by_oui():
    assert fingerprint_endpoint("02:11:01:aa:bb:cc") == "printer"
    assert fingerprint_endpoint("02:22:02:aa:bb:cc") == "camera"


def test_fingerprint_endpoint_by_sysdescr_fallback():
    assert fingerprint_endpoint("aa:bb:cc:dd:ee:ff", "HP LaserJet Printer") == "printer"


def test_fingerprint_endpoint_unknown():
    assert fingerprint_endpoint("aa:bb:cc:dd:ee:ff", "") == "unknown"
