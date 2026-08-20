from netdiscovery.l2_topology import build
from netdiscovery.models import Device, FdbEntry, Interface, Neighbor
from netdiscovery.discovery import discover
from netdiscovery.simulator import DEFAULT_SEED_IPS, SimulatedTransport


def test_bidirectional_lldp_neighbors_dedupe_to_one_edge():
    a = Device(
        mgmt_ip="10.0.0.1", sysname="switch-a", reachable=True,
        neighbors=[Neighbor(local_if="Gi0/1", remote_sysname="switch-b",
                             remote_port="Gi0/2", remote_mgmt_ip="10.0.0.2")],
    )
    b = Device(
        mgmt_ip="10.0.0.2", sysname="switch-b", reachable=True,
        neighbors=[Neighbor(local_if="Gi0/2", remote_sysname="switch-a",
                             remote_port="Gi0/1", remote_mgmt_ip="10.0.0.1")],
    )
    topo = build({"10.0.0.1": a, "10.0.0.2": b})
    assert len(topo.edges) == 1
    edge = topo.edges[0]
    assert {edge.device_a, edge.device_b} == {"10.0.0.1", "10.0.0.2"}
    assert edge.source == "lldp"


def test_cdp_only_neighbor_forms_edge():
    a = Device(
        mgmt_ip="10.0.0.1", sysname="switch-a", reachable=True,
        neighbors=[Neighbor(local_if="Fa0/1", remote_sysname="switch-c",
                             remote_port="Fa0/1", remote_mgmt_ip="10.0.0.3",
                             protocol="cdp")],
    )
    c = Device(mgmt_ip="10.0.0.3", sysname="switch-c", reachable=True)
    topo = build({"10.0.0.1": a, "10.0.0.3": c})
    assert len(topo.edges) == 1
    assert topo.edges[0].source == "cdp"


def test_edge_survives_unreachable_remote_end():
    a = Device(
        mgmt_ip="10.0.0.1", sysname="switch-a", reachable=True,
        neighbors=[Neighbor(local_if="Gi0/5", remote_sysname="dead-switch",
                             remote_port="Gi0/1", remote_mgmt_ip="10.0.0.9")],
    )
    dead = Device(mgmt_ip="10.0.0.9", reachable=False)
    topo = build({"10.0.0.1": a, "10.0.0.9": dead})
    assert len(topo.edges) == 1


def test_fdb_fallback_single_mac_port_is_confident_endpoint():
    switch = Device(
        mgmt_ip="10.0.0.1", sysname="switch-a", reachable=True,
        interfaces=[Interface(index=1, name="Gi0/1", mac="aa:aa:aa:aa:aa:aa")],
        fdb=[FdbEntry(mac="02:11:01:00:00:01", local_if="Gi0/10", vlan=10)],
    )
    topo = build({"10.0.0.1": switch})
    assert len(topo.endpoints) == 1
    ep = topo.endpoints[0]
    assert ep.switch_ip == "10.0.0.1"
    assert ep.switch_if == "Gi0/10"
    assert ep.kind == "printer"
    assert ep.vlan == 10


def test_fdb_fallback_ignores_infra_macs():
    a = Device(
        mgmt_ip="10.0.0.1", sysname="switch-a", reachable=True,
        interfaces=[Interface(index=1, name="Gi0/1", mac="aa:aa:aa:aa:aa:aa")],
        neighbors=[Neighbor(local_if="Gi0/1", remote_sysname="switch-b",
                             remote_port="Gi0/1", remote_mgmt_ip="10.0.0.2")],
        # Trunk port learned the neighbor's own interface MAC -- should
        # never be mistaken for an endpoint.
        fdb=[FdbEntry(mac="bb:bb:bb:bb:bb:bb", local_if="Gi0/1", vlan=1)],
    )
    b = Device(
        mgmt_ip="10.0.0.2", sysname="switch-b", reachable=True,
        interfaces=[Interface(index=1, name="Gi0/1", mac="bb:bb:bb:bb:bb:bb")],
        neighbors=[Neighbor(local_if="Gi0/1", remote_sysname="switch-a",
                             remote_port="Gi0/1", remote_mgmt_ip="10.0.0.1")],
    )
    topo = build({"10.0.0.1": a, "10.0.0.2": b})
    assert topo.endpoints == []


def test_endpoint_ip_correlated_from_arp():
    from netdiscovery.models import ArpEntry

    core = Device(
        mgmt_ip="10.0.0.1", sysname="core", reachable=True,
        arp=[ArpEntry(ip="10.0.10.50", mac="02:33:01:00:00:01", local_if="Vlan10")],
    )
    access = Device(
        mgmt_ip="10.0.0.2", sysname="access", reachable=True,
        fdb=[FdbEntry(mac="02:33:01:00:00:01", local_if="Gi0/5", vlan=10)],
    )
    topo = build({"10.0.0.1": core, "10.0.0.2": access})
    assert len(topo.endpoints) == 1
    assert topo.endpoints[0].ip == "10.0.10.50"
    assert topo.endpoints[0].kind == "server"


def test_simulated_network_l2_topology_matches_expected_counts():
    """End-to-end sanity check against the demo network in simulator.py."""
    transport = SimulatedTransport()
    result = discover(transport, DEFAULT_SEED_IPS)
    topo = build(result.devices)

    # core1-core2, core1-dist1, core1-dist2, core1-fw1, core2-dist1,
    # core2-dist2, dist1-acc1, dist1-acc2, dist1-acc5(dead), dist2-acc1,
    # dist2-acc3, dist2-acc4(cdp) = 12 infra links, including the ring.
    assert len(topo.edges) == 12
    cdp_edges = [e for e in topo.edges if e.source == "cdp"]
    assert len(cdp_edges) == 1

    # 3 servers + 4 PCs + 2 printers + 2 cameras = 11 non-LLDP endpoints.
    assert len(topo.endpoints) == 11
    kinds = sorted(ep.kind for ep in topo.endpoints)
    assert kinds.count("server") == 3
    assert kinds.count("workstation") == 4
    assert kinds.count("printer") == 2
    assert kinds.count("camera") == 2
    assert all(ep.ip is not None for ep in topo.endpoints)


def test_redundant_core_forms_a_real_cycle_not_a_tree():
    """core1-core2-dist1-core1 (and the dist2 leg) must all be present --
    proving the correlation doesn't collapse the ring into a spanning tree."""
    transport = SimulatedTransport()
    result = discover(transport, DEFAULT_SEED_IPS)
    topo = build(result.devices)

    def has_edge(a, b):
        return any({e.device_a, e.device_b} == {a, b} for e in topo.edges)

    core1, core2 = "10.10.99.1", "10.10.99.2"
    dist1, dist2 = "10.10.99.3", "10.10.99.4"
    assert has_edge(core1, core2)
    assert has_edge(core1, dist1)
    assert has_edge(core1, dist2)
    assert has_edge(core2, dist1)
    assert has_edge(core2, dist2)
