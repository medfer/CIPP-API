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

`concurrency` controls how many devices are probed in parallel (a thread
pool, since collect_device/SnmpTransport are synchronous). A real network
of a few dozen switches is survivable one at a time -- one dead/timing-out
host still costs a full `timeout * (retries + 1)` seconds serially -- but
scaling toward thousands of devices needs many outstanding SNMP
conversations at once. `concurrency=1` (the default) processes strictly
one device at a time in the same order the original sequential BFS did,
so it's a no-behavior-change default for callers that don't ask for more.
"""
from __future__ import annotations

from collections import deque
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from typing import Callable, Optional

from .collector import collect_device
from .models import Device
from .transport import SnmpTransport

DEFAULT_MAX_DEVICES = 1000
DEFAULT_CONCURRENCY = 1

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


def _collect_one(transport: SnmpTransport, ip: str) -> tuple[str, Device, Optional[str]]:
    try:
        return ip, collect_device(transport, ip), None
    except Exception as exc:  # noqa: BLE001 - one bad/unusual device must never abort the walk
        return ip, Device(mgmt_ip=ip, reachable=False), f"{type(exc).__name__}: {exc}"


def discover(
    transport: SnmpTransport,
    seed_ips: list[str],
    max_devices: int = DEFAULT_MAX_DEVICES,
    on_device: Optional[ProgressCallback] = None,
    concurrency: int = DEFAULT_CONCURRENCY,
) -> DiscoveryResult:
    """BFS from `seed_ips` over the transport, returning every device
    visited (reachable or not). Stops when the frontier empties or
    `max_devices` devices have been started, whichever comes first.

    Up to `concurrency` devices are probed in parallel via a thread pool;
    `concurrency=1` collects strictly one at a time, in the same order a
    plain sequential BFS would.
    """
    visited: dict[str, Device] = {}
    errors: dict[str, str] = {}
    seen_ips = set(seed_ips)
    frontier: deque[str] = deque(seed_ips)
    started = 0

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as executor:
        in_flight: dict[Future, str] = {}

        def _fill() -> None:
            nonlocal started
            while frontier and len(in_flight) < concurrency and started < max_devices:
                ip = frontier.popleft()
                in_flight[executor.submit(_collect_one, transport, ip)] = ip
                started += 1

        _fill()
        while in_flight:
            done, _pending = wait(in_flight.keys(), return_when=FIRST_COMPLETED)
            for future in done:
                in_flight.pop(future)
                ip, device, error = future.result()
                visited[ip] = device
                if error:
                    errors[ip] = error
                if on_device is not None:
                    on_device(ip, device, error)

                if not device.reachable:
                    continue
                for neighbor in device.neighbors:
                    remote_ip = neighbor.remote_mgmt_ip
                    if remote_ip and remote_ip not in seen_ips:
                        seen_ips.add(remote_ip)
                        frontier.append(remote_ip)
            _fill()

    return DiscoveryResult(devices=visited, errors=errors)
