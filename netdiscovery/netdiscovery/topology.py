"""Unified topology graph: one networkx MultiGraph holding both the L2 and
L3 layers, plus the endpoints attached from FDB/ARP correlation.

A MultiGraph (not Graph/DiGraph) is deliberate: it's what lets two devices
be connected by more than one edge at once -- the dual uplinks and the
core-core link in the demo network's ring, or an L2 link and an L3
adjacency between the same pair of switches. Anything that collapsed
parallel edges (a plain Graph, or worse, a spanning tree) would silently
throw away the redundancy the discovery engine was built to represent.

Every node and edge attribute is coerced to a plain string so the graph
can round-trip through GraphML and JSON (for the HTML visualization)
without type-mismatch surprises.
"""
from __future__ import annotations

from typing import Any, Optional

import networkx as nx

from .l2_topology import L2Topology
from .l3_topology import L3Topology
from .models import Device


def _clean(attrs: dict[str, Any]) -> dict[str, str]:
    return {k: ("" if v is None else str(v)) for k, v in attrs.items()}


def build_graph(
    devices: dict[str, Device],
    l2: L2Topology,
    l3: L3Topology,
) -> nx.MultiGraph:
    graph = nx.MultiGraph()

    for ip, device in devices.items():
        graph.add_node(ip, **_clean({
            "kind": "infra",
            "label": device.sysname or ip,
            "role": device.role.value if device.reachable else "unreachable",
            "vendor": device.vendor,
            "sysdescr": device.sysdescr,
            "reachable": device.reachable,
            "mgmt_ip": ip,
        }))

    # An endpoint can show up attached from more than one switch port in a
    # pathological FDB (e.g. it moved, or a loop); node attributes just get
    # overwritten with the latest sighting, which is fine for this POC.
    for endpoint in l2.endpoints:
        graph.add_node(endpoint.mac, **_clean({
            "kind": "endpoint",
            "label": endpoint.ip or endpoint.mac,
            "role": endpoint.kind,
            "vendor": "unknown",
            "reachable": True,
            "mac": endpoint.mac,
            "ip": endpoint.ip,
            "vlan": endpoint.vlan,
        }))

    for edge in l2.edges:
        graph.add_edge(edge.device_a, edge.device_b, **_clean({
            "layer": "l2",
            "source": edge.source,
            "if_a": edge.if_a,
            "if_b": edge.if_b,
            "label": f"{edge.if_a} ↔ {edge.if_b} ({edge.source})",
        }))

    for endpoint in l2.endpoints:
        graph.add_edge(endpoint.switch_ip, endpoint.mac, **_clean({
            "layer": "l2",
            "source": endpoint.source,
            "if_a": endpoint.switch_if,
            "vlan": endpoint.vlan,
            "label": f"{endpoint.switch_if} (vlan {endpoint.vlan}, fdb)",
        }))

    for adjacency in l3.adjacencies:
        graph.add_edge(adjacency.device_a, adjacency.device_b, **_clean({
            "layer": "l3",
            "source": adjacency.kind,
            "subnet": adjacency.subnet,
            "label": f"{adjacency.subnet} ({adjacency.kind})",
        }))

    return graph


class Topology:
    """Convenience wrapper around the unified graph: layer views + export."""

    def __init__(self, graph: nx.MultiGraph):
        self.graph = graph

    @classmethod
    def from_discovery(cls, devices: dict[str, Device], l2: L2Topology, l3: L3Topology) -> "Topology":
        return cls(build_graph(devices, l2, l3))

    def _layer_view(self, layer: str) -> nx.MultiGraph:
        edges = [
            (u, v, k) for u, v, k, data in self.graph.edges(keys=True, data=True)
            if data.get("layer") == layer
        ]
        view = nx.MultiGraph()
        for u, v, k in edges:
            view.add_node(u, **self.graph.nodes[u])
            view.add_node(v, **self.graph.nodes[v])
            view.add_edge(u, v, key=k, **self.graph.edges[u, v, k])
        return view

    def l2_view(self) -> nx.MultiGraph:
        return self._layer_view("l2")

    def l3_view(self) -> nx.MultiGraph:
        return self._layer_view("l3")

    def to_graphml(self, path: str) -> None:
        nx.write_graphml(self.graph, path)

    def summary(self) -> dict[str, int]:
        infra = [n for n, d in self.graph.nodes(data=True) if d.get("kind") == "infra"]
        reachable_infra = [n for n in infra if self.graph.nodes[n].get("reachable") == "True"]
        endpoints = [n for n, d in self.graph.nodes(data=True) if d.get("kind") == "endpoint"]
        l2_edges = sum(1 for *_e, d in self.graph.edges(data=True) if d.get("layer") == "l2")
        l3_edges = sum(1 for *_e, d in self.graph.edges(data=True) if d.get("layer") == "l3")
        return {
            "devices_discovered": len(infra),
            "devices_reachable": len(reachable_infra),
            "devices_unreachable": len(infra) - len(reachable_infra),
            "l2_links": l2_edges,
            "l3_adjacencies": l3_edges,
            "endpoints_attached": len(endpoints),
        }
