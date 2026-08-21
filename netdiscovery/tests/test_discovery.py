"""Regression tests for discovery.py's BFS: concurrency correctness and
resilience to a device that raises during collection."""
from netdiscovery import l2_topology, l3_topology
from netdiscovery.discovery import discover
from netdiscovery.models import Device
from netdiscovery.simulator import DEFAULT_SEED_IPS, SimulatedTransport
from netdiscovery.topology import Topology
from netdiscovery.transport import SnmpTransport


def test_concurrency_does_not_change_discovered_topology():
    baseline = None
    for concurrency in (1, 4, 16):
        transport = SimulatedTransport()
        result = discover(transport, DEFAULT_SEED_IPS, concurrency=concurrency)
        l2 = l2_topology.build(result.devices)
        l3 = l3_topology.build(result.devices)
        summary = Topology.from_discovery(result.devices, l2, l3).summary()
        if baseline is None:
            baseline = summary
        else:
            assert summary == baseline, f"concurrency={concurrency} changed the discovered topology"
    assert baseline["devices_discovered"] > 0


class _OneBadAppleTransport(SnmpTransport):
    """Every device works except `bad_ip`, which raises during collection
    (simulating an unusual/malformed response this POC's parsing doesn't
    handle) instead of just timing out."""

    def __init__(self, bad_ip: str):
        self.bad_ip = bad_ip

    def is_reachable(self, ip: str) -> bool:
        return True

    def get(self, ip: str, oid: str) -> str:
        if ip == self.bad_ip:
            raise ValueError("simulated malformed device response")
        return "78"

    def walk(self, ip: str, oid_prefix: str) -> dict[str, str]:
        if ip == self.bad_ip:
            raise ValueError("simulated malformed device response")
        return {}


def test_one_device_raising_during_collection_does_not_abort_the_bfs():
    seeds = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    result = discover(_OneBadAppleTransport(bad_ip="10.0.0.2"), seeds)

    assert set(result.devices) == set(seeds)
    assert result.devices["10.0.0.1"].reachable is True
    assert result.devices["10.0.0.3"].reachable is True

    bad = result.devices["10.0.0.2"]
    assert bad.reachable is False
    assert isinstance(bad, Device)
    assert "10.0.0.2" in result.errors
    assert "simulated malformed device response" in result.errors["10.0.0.2"]
