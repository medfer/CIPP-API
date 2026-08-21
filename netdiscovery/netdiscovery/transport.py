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


class LiveSnmpTransport(SnmpTransport):
    """Real SNMP (v2c) transport backed by pysnmp.

    pysnmp is an optional dependency of this POC -- it's only imported when
    this transport is actually instantiated, so the simulated demo path
    never needs it installed. pysnmp's hlapi is asyncio-based (there is no
    synchronous variant in any currently-maintained release), so each
    get/walk spins up its own event loop via `asyncio.run` -- this keeps
    `SnmpTransport`'s synchronous get/walk contract identical between
    `SimulatedTransport` and `LiveSnmpTransport`, at the cost of not
    overlapping requests to different devices within a single call. Fixing
    that (e.g. batching concurrent devices under one shared loop) is future
    work, not needed for this POC to talk to a real device correctly.
    """

    def __init__(self, community: str = "public", port: int = 161,
                 timeout: float = 1.5, retries: int = 1):
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

    def is_reachable(self, ip: str) -> bool:
        return self.get(ip, mibs.SYS_DESCR) is not None

    def get(self, ip: str, oid: str) -> Optional[str]:
        import asyncio

        from pysnmp.hlapi.asyncio import (
            CommunityData, ContextData, ObjectIdentity, ObjectType,
            SnmpEngine, UdpTransportTarget, getCmd,
        )

        async def _get() -> Optional[str]:
            error_indication, error_status, _error_index, var_binds = await getCmd(
                SnmpEngine(),
                CommunityData(self._community, mpModel=1),
                UdpTransportTarget((ip, self._port), timeout=self._timeout,
                                    retries=self._retries),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
                lookupMib=False,
            )
            if error_indication or error_status or not var_binds:
                return None
            _name, value = var_binds[0]
            # prettyPrint(), not str(): pysnmp's str() on byte-backed types
            # (IpAddress, MAC-typed OctetStrings) returns the raw undecoded
            # payload bytes, not a readable string -- prettyPrint() is the
            # one formatting path that's correct for every SNMP value type.
            return value.prettyPrint()

        return asyncio.run(_get())

    def walk(self, ip: str, oid_prefix: str) -> dict[str, str]:
        import asyncio

        from pysnmp.hlapi.asyncio import (
            CommunityData, ContextData, ObjectIdentity, ObjectType,
            SnmpEngine, UdpTransportTarget, walkCmd,
        )

        async def _walk() -> dict[str, str]:
            results: dict[str, str] = {}
            async for error_indication, error_status, _error_index, var_binds in walkCmd(
                SnmpEngine(),
                CommunityData(self._community, mpModel=1),
                UdpTransportTarget((ip, self._port), timeout=self._timeout,
                                    retries=self._retries),
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
                    results[oid_str] = value.prettyPrint()
            return results

        return asyncio.run(_walk())
