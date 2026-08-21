"""BFS discovery loop: seed IP(s) -> every reachable device out to the
edge of the network.

For each device collected, its LLDP/CDP neighbor management IPs are
enqueued if not already seen. An unreachable/timeout device is recorded
(so it still shows up as a discovered-but-dead node) and simply doesn't
expand any further -- one dead host never aborts the whole walk. The same
holds for a device that raises during collection (e.g. an unusual/
malformed MIB response from an unfamiliar vendor or firmware): it's
recorded unreachable with its error noted in `DiscoveryResult.errors`,
never allowed to crash the walk.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Optional

from .collector import collect_device
from .models import Device
from .transport import SnmpTransport

DEFAULT_MAX_DEVICES = 1000

ProgressCallback = Callable[[str, Device, Optional[str]], None]


@dataclass
class DiscoveryResult:
    devices: dict[str, Device] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)

    @property
    def reachable_devices(self) -> dict[str, Device]:
        return {ip: d for ip, d in self.devices.items() if d.reachable}

    @property
    def unreachable_ips(self) -> list[str]:
        return [ip for ip, d in self.devices.items() if not d.reachable]


def discover(
    transport: SnmpTransport,
    seed_ips: list[str],
    max_devices: int = DEFAULT_MAX_DEVICES,
    on_device: Optional[ProgressCallback] = None,
) -> DiscoveryResult:
    """BFS from `seed_ips` over the transport, returning every device
    visited (reachable or not). Stops when the frontier empties or
    `max_devices` devices have been collected, whichever comes first.
    """
    visited: dict[str, Device] = {}
    errors: dict[str, str] = {}
    seen_ips = set(seed_ips)
    queue: deque[str] = deque(seed_ips)

    while queue and len(visited) < max_devices:
        ip = queue.popleft()
        error: Optional[str] = None
        try:
            device = collect_device(transport, ip)
        except Exception as exc:  # noqa: BLE001 - one bad/unusual device must never abort the walk
            device = Device(mgmt_ip=ip, reachable=False)
            error = f"{type(exc).__name__}: {exc}"
            errors[ip] = error
        visited[ip] = device
        if on_device is not None:
            on_device(ip, device, error)

        if not device.reachable:
            continue

        for neighbor in device.neighbors:
            remote_ip = neighbor.remote_mgmt_ip
            if remote_ip and remote_ip not in seen_ips:
                seen_ips.add(remote_ip)
                queue.append(remote_ip)

    return DiscoveryResult(devices=visited, errors=errors)
