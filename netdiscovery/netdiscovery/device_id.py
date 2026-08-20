"""Classify a collected device's vendor and role.

Vendor comes from the sysObjectID enterprise prefix, falling back to
keyword matching against sysDescr for devices that don't map cleanly (or
that a real network might report differently across firmware versions).

Role comes from sysServices bits plus keyword/route heuristics: a firewall
or AP is recognized by sysDescr keywords first (they can otherwise look
like an ordinary L3/L2 device), then routing/bridging capability from
sysServices decides router vs. L3 switch vs. switch vs. host.

Endpoints that never answer SNMP (cameras, printers, IoT) are fingerprinted
separately, from their MAC OUI, once they're seen in an ARP/FDB table --
see `fingerprint_endpoint`.
"""
from __future__ import annotations

import re
from typing import Optional

from .mibs import (
    SYS_SERVICES_DATALINK,
    SYS_SERVICES_INTERNET,
    vendor_from_sysobjectid,
)
from .models import DeviceRole

# Fallback vendor detection from sysDescr text, for devices whose
# sysObjectID isn't in mibs.ENTERPRISE_OID_VENDORS (or wasn't readable).
_SYSDESCR_VENDOR_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bcisco\b|\bnx-os\b|\bios-xe\b|\bios\b", re.I), "cisco"),
    (re.compile(r"\bjuniper\b|\bjunos\b", re.I), "juniper"),
    (re.compile(r"\baruba\b|\barubaos\b", re.I), "aruba"),
    (re.compile(r"\bhp\b|\bhpe\b|\bprocurve\b", re.I), "hpe"),
    (re.compile(r"\bfortinet\b|\bfortigate\b|\bfortios\b", re.I), "fortinet"),
]

_FIREWALL_KEYWORDS = re.compile(
    r"firewall|fortigate|fortios|palo alto|pan-os|asa\b", re.I
)
_AP_KEYWORDS = re.compile(
    r"\baccess point\b|\bwireless ap\b|\baruba ap\b|\bap-\d|\bap\d{3}\b", re.I
)

# Illustrative MAC OUI -> endpoint-kind table for this POC. These prefixes
# are made up for the simulated demo network; a production build would
# look these up against the real IEEE OUI registry.
OUI_ENDPOINT_KIND: dict[str, str] = {
    "02:11:01": "printer",
    "02:11:02": "printer",
    "02:22:01": "camera",
    "02:22:02": "camera",
    "02:33:01": "server",
    "02:33:02": "server",
    "02:33:03": "server",
    "02:44:01": "workstation",
    "02:44:02": "workstation",
    "02:44:03": "workstation",
    "02:44:04": "workstation",
}


def classify_vendor(sysobjectid: str, sysdescr: str) -> str:
    """Best-effort vendor name from sysObjectID, falling back to sysDescr."""
    vendor = vendor_from_sysobjectid(sysobjectid) if sysobjectid else "unknown"
    if vendor != "unknown":
        return vendor
    for pattern, name in _SYSDESCR_VENDOR_PATTERNS:
        if pattern.search(sysdescr or ""):
            return name
    return "unknown"


def classify_role(
    sysdescr: str,
    sysservices: Optional[int],
    has_routes: bool = False,
) -> DeviceRole:
    """Best-effort DeviceRole from sysDescr keywords + sysServices bits."""
    descr = sysdescr or ""

    if _FIREWALL_KEYWORDS.search(descr):
        return DeviceRole.FIREWALL
    if _AP_KEYWORDS.search(descr):
        return DeviceRole.ACCESS_POINT

    services = sysservices or 0
    routes_layer3 = bool(services & SYS_SERVICES_INTERNET) or has_routes
    bridges_layer2 = bool(services & SYS_SERVICES_DATALINK)

    if routes_layer3 and bridges_layer2:
        return DeviceRole.L3_SWITCH
    if routes_layer3:
        return DeviceRole.ROUTER
    if bridges_layer2:
        return DeviceRole.SWITCH
    if descr:
        return DeviceRole.HOST
    return DeviceRole.UNKNOWN


def fingerprint_endpoint(mac: str, sysdescr: str = "") -> str:
    """Guess an endpoint's kind ("printer"/"camera"/"server"/"workstation")
    for a device that never answered SNMP, from its MAC OUI (first 3
    octets) or, failing that, sysDescr keywords. Returns "unknown" when
    nothing matches.
    """
    if mac:
        oui = ":".join(mac.lower().split(":")[:3])
        if oui in OUI_ENDPOINT_KIND:
            return OUI_ENDPOINT_KIND[oui]

    descr = (sysdescr or "").lower()
    for keyword, kind in (
        ("printer", "printer"),
        ("camera", "camera"),
        ("server", "server"),
        ("workstation", "workstation"),
        ("pc", "workstation"),
    ):
        if keyword in descr:
            return kind
    return "unknown"
