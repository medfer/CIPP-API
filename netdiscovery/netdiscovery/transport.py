"""Transport abstraction the discovery engine talks to.

The engine only ever calls `SnmpTransport.is_reachable/get/walk`. It has no
idea whether the answers come from a real device over the wire
(`LiveSnmpTransport`, using pysnmp) or from an in-memory simulated network
(`SimulatedTransport`, see simulator.py). Swapping the transport is the only
change needed to point the same engine at a real network.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from . import mibs


class SnmpTransport(ABC):
    """Abstract SNMP-ish access to a fleet of devices, keyed by mgmt IP."""

    @abstractmethod
    def is_reachable(self, ip: str) -> bool:
        """Cheap reachability check (used before/while walking a device)."""

    @abstractmethod
    def get(self, ip: str, oid: str) -> Optional[str]:
        """SNMP GET for a single scalar OID. None if absent/unreachable."""

    @abstractmethod
    def walk(self, ip: str, oid_prefix: str) -> dict[str, str]:
        """SNMP WALK under oid_prefix.

        Returns {full_oid: value} for every instance found under the
        prefix, e.g. walking ifDescr (1.3.6.1.2.1.2.2.1.2) on a device with
        3 interfaces returns entries for
        1.3.6.1.2.1.2.2.1.2.1, .2.1.2.2.1.2.2, .2.1.2.2.1.2.3.
        Empty dict if the device is unreachable or has nothing there.
        """


_AUTH_PROTOCOL_NAMES = ("md5", "sha", "sha224", "sha256", "sha384", "sha512")
_PRIV_PROTOCOL_NAMES = ("des", "3des", "aes128", "aes192", "aes256")


class LiveSnmpTransport(SnmpTransport):
    """Real SNMP transport backed by pysnmp -- v2c (community) by default,
    or SNMPv3 (USM auth/priv) when `username` is given.

    pysnmp is an optional dependency of this POC -- it's only imported when
    this transport is actually instantiated, so the simulated demo path
    never needs it installed. pysnmp's hlapi is asyncio-based (there is no
    synchronous variant in any currently-maintained release), so each
    get/walk spins up its own event loop via `asyncio.run` -- this keeps
    `SnmpTransport`'s synchronous get/walk contract identical between
    `SimulatedTransport` and `LiveSnmpTransport`, at the cost of not
    overlapping requests to different devices within a single call
    (discovery.py's concurrency parameter is what overlaps *across*
    devices; see discovery.py).

    A fresh CommunityData/UsmUserData is built on every get/walk call
    rather than cached on self -- discovery.py's concurrent BFS calls
    these from multiple threads at once, and pysnmp's auth objects cache
    mutable per-conversation state (e.g. USM engine-boots/time discovery)
    that isn't documented as safe to share across concurrent requests.
    Rebuilding a lightweight credentials object per call avoids that
    question entirely, at negligible cost next to a real network round
    trip.
    """

    def __init__(self, community: str = "public", port: int = 161,
                 timeout: float = 1.5, retries: int = 1, *,
                 username: Optional[str] = None,
                 security_level: str = "authPriv",
                 auth_protocol: str = "sha",
                 auth_password: Optional[str] = None,
                 priv_protocol: str = "aes128",
                 priv_password: Optional[str] = None):
        """`username` set => SNMPv3 (USM); otherwise SNMPv2c (`community`).

        security_level: "noAuthNoPriv" | "authNoPriv" | "authPriv".
        auth_protocol: one of `_AUTH_PROTOCOL_NAMES` (SHA-1 by default --
        MD5 and SHA-1 are both weak; used here only because they're the
        two protocols virtually every SNMPv3 device still supports).
        priv_protocol: one of `_PRIV_PROTOCOL_NAMES` (AES-128 default).
        """
        try:
            import pysnmp.hlapi.asyncio  # noqa: F401
        except ImportError as exc:  # pragma: no cover - exercised only without pysnmp
            raise RuntimeError(
                "pysnmp is required for LiveSnmpTransport; "
                "pip install pysnmp, or use SimulatedTransport for the demo."
            ) from exc

        self._community = community
        self._port = port
        self._timeout = timeout
        self._retries = retries

        self._username = username
        if username:
            if security_level not in ("noAuthNoPriv", "authNoPriv", "authPriv"):
                raise ValueError(
                    f"security_level must be noAuthNoPriv/authNoPriv/authPriv, got {security_level!r}")
            if security_level in ("authNoPriv", "authPriv"):
                if auth_protocol not in _AUTH_PROTOCOL_NAMES:
                    raise ValueError(f"auth_protocol must be one of {_AUTH_PROTOCOL_NAMES}, got {auth_protocol!r}")
                if not auth_password:
                    raise ValueError(f"auth_password is required for security_level={security_level!r}")
            if security_level == "authPriv":
                if priv_protocol not in _PRIV_PROTOCOL_NAMES:
                    raise ValueError(f"priv_protocol must be one of {_PRIV_PROTOCOL_NAMES}, got {priv_protocol!r}")
                if not priv_password:
                    raise ValueError("priv_password is required for security_level='authPriv'")
        self._security_level = security_level
        self._auth_protocol = auth_protocol
        self._auth_password = auth_password
        self._priv_protocol = priv_protocol
        self._priv_password = priv_password

    def _build_auth_data(self):
        from pysnmp.hlapi.asyncio import (
            CommunityData, UsmUserData, usm3DESEDEPrivProtocol,
            usmAesCfb128Protocol, usmAesCfb192Protocol, usmAesCfb256Protocol,
            usmDESPrivProtocol, usmHMAC128SHA224AuthProtocol,
            usmHMAC192SHA256AuthProtocol, usmHMAC256SHA384AuthProtocol,
            usmHMAC384SHA512AuthProtocol, usmHMACMD5AuthProtocol,
            usmHMACSHAAuthProtocol,
        )

        if not self._username:
            return CommunityData(self._community, mpModel=1)

        auth_protocols = {
            "md5": usmHMACMD5AuthProtocol, "sha": usmHMACSHAAuthProtocol,
            "sha224": usmHMAC128SHA224AuthProtocol, "sha256": usmHMAC192SHA256AuthProtocol,
            "sha384": usmHMAC256SHA384AuthProtocol, "sha512": usmHMAC384SHA512AuthProtocol,
        }
        priv_protocols = {
            "des": usmDESPrivProtocol, "3des": usm3DESEDEPrivProtocol,
            "aes128": usmAesCfb128Protocol, "aes192": usmAesCfb192Protocol,
            "aes256": usmAesCfb256Protocol,
        }
        kwargs = {}
        if self._security_level in ("authNoPriv", "authPriv"):
            kwargs["authKey"] = self._auth_password
            kwargs["authProtocol"] = auth_protocols[self._auth_protocol]
        if self._security_level == "authPriv":
            kwargs["privKey"] = self._priv_password
            kwargs["privProtocol"] = priv_protocols[self._priv_protocol]
        return UsmUserData(self._username, **kwargs)

    def _build_transport_target(self, ip: str):
        """UdpTransportTarget for an IPv4 target, Udp6TransportTarget for
        an IPv6 one -- picked from the target address itself, since a
        dual-stack discovery run can have both IPv4 and IPv6 devices (or
        an IPv6-only device found via ipNetToPhysicalTable/LLDP) in the
        same BFS."""
        import ipaddress

        from pysnmp.hlapi.asyncio import Udp6TransportTarget, UdpTransportTarget

        target_cls = Udp6TransportTarget if ipaddress.ip_address(ip).version == 6 else UdpTransportTarget
        return target_cls((ip, self._port), timeout=self._timeout, retries=self._retries)

    def is_reachable(self, ip: str) -> bool:
        return self.get(ip, mibs.SYS_DESCR) is not None

    def get(self, ip: str, oid: str) -> Optional[str]:
        import asyncio

        from pysnmp.hlapi.asyncio import (
            ContextData, ObjectIdentity, ObjectType, SnmpEngine, getCmd,
        )
        from pysnmp.proto.rfc1905 import EndOfMibView, NoSuchInstance, NoSuchObject

        async def _get() -> Optional[str]:
            error_indication, error_status, _error_index, var_binds = await getCmd(
                SnmpEngine(),
                self._build_auth_data(),
                self._build_transport_target(ip),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
                lookupMib=False,
            )
            if error_indication or error_status or not var_binds:
                return None
            _name, value = var_binds[0]
            # A device that simply doesn't implement this OID (common --
            # e.g. sysServices is optional and widely omitted) answers
            # successfully with a NoSuchObject/NoSuchInstance/EndOfMibView
            # sentinel, not an error_indication/error_status. prettyPrint()
            # on one of those returns a human sentence like "No Such
            # Instance currently exists at this OID" -- reproduced live
            # against a real SNMPv3 agent -- which would otherwise get
            # collected as if it were the OID's real value.
            if isinstance(value, (NoSuchObject, NoSuchInstance, EndOfMibView)):
                return None
            # prettyPrint(), not str(): pysnmp's str() on byte-backed types
            # (IpAddress, MAC-typed OctetStrings) returns the raw undecoded
            # payload bytes, not a readable string -- prettyPrint() is the
            # one formatting path that's correct for every SNMP value type.
            return value.prettyPrint()

        return asyncio.run(_get())

    def walk(self, ip: str, oid_prefix: str) -> dict[str, str]:
        import asyncio

        from pysnmp.hlapi.asyncio import (
            ContextData, ObjectIdentity, ObjectType, SnmpEngine, walkCmd,
        )
        from pysnmp.proto.rfc1905 import EndOfMibView, NoSuchInstance, NoSuchObject

        async def _walk() -> dict[str, str]:
            results: dict[str, str] = {}
            async for error_indication, error_status, _error_index, var_binds in walkCmd(
                SnmpEngine(),
                self._build_auth_data(),
                self._build_transport_target(ip),
                ContextData(),
                ObjectType(ObjectIdentity(oid_prefix)),
                lexicographicMode=False,
                lookupMib=False,
            ):
                if error_indication or error_status:
                    break
                for name, value in var_binds:
                    oid_str = str(name)
                    if not oid_str.startswith(oid_prefix):
                        return results
                    # See the matching comment in get(): a sentinel value
                    # (e.g. a sparse/partially-implemented table row) isn't
                    # real data, don't collect it as if it were.
                    if isinstance(value, (NoSuchObject, NoSuchInstance, EndOfMibView)):
                        continue
                    results[oid_str] = value.prettyPrint()
            return results

        return asyncio.run(_walk())
