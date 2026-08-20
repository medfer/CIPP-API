from netdiscovery.discovery import discover
from netdiscovery.l3_topology import build
from netdiscovery.models import Device, Interface, Route
from netdiscovery.simulator import DEFAULT_SEED_IPS, SimulatedTransport


def test_shared_subnet_creates_adjacency():
    a = Device(
        mgmt_ip="10.0.0.1", reachable=True,
        routes=[Route(dest="10.0.10.0", prefix_len=24, next_hop="0.0.0.0",
                       local_if="Vlan10", proto="connected")],
    )
    b = Device(
        mgmt_ip="10.0.0.2", reachable=True,
        routes=[Route(dest="10.0.10.0", prefix_len=24, next_hop="0.0.0.0",
                       local_if="Vlan10", proto="connected")],
    )
    topo = build({"10.0.0.1": a, "10.0.0.2": b})
    assert len(topo.adjacencies) == 1
    adj = topo.adjacencies[0]
    assert {adj.device_a, adj.device_b} == {"10.0.0.1", "10.0.0.2"}
    assert adj.kind == "shared_subnet"
    assert topo.subnets["10.0.10.0/24"] == ["10.0.0.1", "10.0.0.2"]


def test_single_member_subnet_has_no_adjacency():
    a = Device(
        mgmt_ip="10.0.0.1", reachable=True,
        routes=[Route(dest="10.0.10.0", prefix_len=24, next_hop="0.0.0.0",
                       local_if="Vlan10", proto="connected")],
    )
    topo = build({"10.0.0.1": a})
    assert topo.adjacencies == []


def test_next_hop_resolves_to_owning_device():
    router = Device(
        mgmt_ip="10.0.0.1", reachable=True,
        interfaces=[Interface(index=1, name="Gi0/1", mac="aa:aa:aa:aa:aa:aa",
                               ip="10.0.0.254", prefix_len=30)],
        routes=[Route(dest="10.0.0.252", prefix_len=30, next_hop="0.0.0.0",
                       local_if="Gi0/1", proto="connected")],
    )
    leaf = Device(
        mgmt_ip="10.0.0.2", reachable=True,
        routes=[Route(dest="0.0.0.0", prefix_len=0, next_hop="10.0.0.254", proto="static")],
    )
    topo = build({"10.0.0.1": router, "10.0.0.2": leaf})
    next_hop_edges = [a for a in topo.adjacencies if a.kind == "next_hop"]
    assert len(next_hop_edges) == 1
    assert {next_hop_edges[0].device_a, next_hop_edges[0].device_b} == {"10.0.0.1", "10.0.0.2"}
    assert next_hop_edges[0].subnet == "0.0.0.0/0"


def test_next_hop_to_unknown_ip_is_dropped_not_crashed():
    leaf = Device(
        mgmt_ip="10.0.0.2", reachable=True,
        routes=[Route(dest="0.0.0.0", prefix_len=0, next_hop="203.0.113.1", proto="static")],
    )
    topo = build({"10.0.0.2": leaf})
    assert topo.adjacencies == []


def test_unreachable_devices_excluded():
    dead = Device(mgmt_ip="10.0.0.9", reachable=False)
    topo = build({"10.0.0.9": dead})
    assert topo.adjacencies == []
    assert topo.subnets == {}


def test_simulated_network_l3_topology_matches_expected():
    """End-to-end sanity check against the demo network in simulator.py."""
    transport = SimulatedTransport()
    result = discover(transport, DEFAULT_SEED_IPS)
    topo = build(result.devices)

    core1, core2, fw1 = "10.10.99.1", "10.10.99.2", "10.255.1.2"

    # Both cores share 5 subnets (3 VLAN SVIs, mgmt VLAN, and the core-core
    # transit link) plus a next-hop default-route adjacency via each other.
    core_pair = [a for a in topo.adjacencies if {a.device_a, a.device_b} == {core1, core2}]
    assert len(core_pair) == 6

    # core1 <-> firewall: shared transit subnet + next-hop default route.
    fw_pair = [a for a in topo.adjacencies if {a.device_a, a.device_b} == {core1, fw1}]
    assert len(fw_pair) == 2

    # core2 has no direct L3 adjacency to the firewall (routes via core1).
    assert not any({a.device_a, a.device_b} == {core2, fw1} for a in topo.adjacencies)

    # L2-only distribution/access switches never populate a routing table,
    # so they don't participate in the L3 view at all.
    l3_participants = {ip for a in topo.adjacencies for ip in (a.device_a, a.device_b)}
    assert l3_participants == {core1, core2, fw1}
