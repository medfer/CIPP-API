"""Interactive HTML topology rendering (vis-network, via pyvis) + GraphML
export.

Produces three views from the same unified graph:
- `topology.html` -- everything, L2 and L3 edges together.
- `topology_l2.html` -- physical/LLDP-CDP-FDB layer only.
- `topology_l3.html` -- routing/subnet layer only.

Node color encodes role/kind, edge color+style encodes discovery source
(solid for L2 lldp/cdp/fdb, dashed for L3 shared-subnet/next-hop), and
hover tooltips carry the underlying device/link detail so a screenshot or
a live click-through both explain themselves.
"""
from __future__ import annotations

import networkx as nx
from pyvis.network import Network

from .topology import Topology

NODE_COLORS = {
    "router": "#e74c3c",
    "l3_switch": "#8e44ad",
    "switch": "#2980b9",
    "firewall": "#c0392b",
    "access_point": "#16a085",
    "host": "#7f8c8d",
    "unreachable": "#4a4a4a",
    "unknown": "#7f8c8d",
    "printer": "#f39c12",
    "camera": "#d35400",
    "server": "#27ae60",
    "workstation": "#95a5a6",
}

EDGE_COLORS = {
    "lldp": "#5dade2",
    "cdp": "#af7ac5",
    "fdb": "#48c9b0",
    "shared_subnet": "#f4d03f",
    "next_hop": "#eb984e",
}


def _node_style(node_id: str, data: dict) -> dict:
    role = data.get("role", "unknown")
    kind = data.get("kind")
    reachable = data.get("reachable") == "True"
    color = NODE_COLORS.get(role, "#7f8c8d") if reachable else NODE_COLORS["unreachable"]

    lines = [f"<b>{data.get('label', node_id)}</b>", f"role: {role}"]
    if kind == "infra":
        lines += [
            f"vendor: {data.get('vendor', '')}",
            f"mgmt IP: {data.get('mgmt_ip', node_id)}",
            f"reachable: {reachable}",
        ]
        if data.get("sysdescr"):
            lines.append(data["sysdescr"])
    else:
        lines.append(f"mac: {data.get('mac', node_id)}")
        if data.get("ip"):
            lines.append(f"ip: {data['ip']}")
        if data.get("vlan"):
            lines.append(f"vlan: {data['vlan']}")

    return {
        "label": data.get("label", node_id),
        "title": "<br>".join(lines),
        "color": color,
        "shape": "box" if kind == "infra" else "dot",
        "size": 26 if kind == "infra" else 12,
        "borderWidth": 1 if reachable else 3,
        "borderWidthSelected": 3,
    }


def _edge_style(data: dict) -> dict:
    source = data.get("source", "")
    return {
        "title": data.get("label", ""),
        "color": EDGE_COLORS.get(source, "#999999"),
        "dashes": data.get("layer") == "l3",
        "width": 2,
        "smooth": {"type": "continuous"},
    }


def render(graph: nx.MultiGraph, out_path: str, heading: str) -> None:
    net = Network(
        height="850px", width="100%",
        bgcolor="#11141a", font_color="#eaeaea",
        heading=heading, directed=False,
        cdn_resources="in_line",
    )
    net.barnes_hut(gravity=-18000, central_gravity=0.3, spring_length=150, spring_strength=0.05, damping=0.9)

    for node_id, data in graph.nodes(data=True):
        net.add_node(node_id, **_node_style(node_id, data))

    for u, v, _key, data in graph.edges(keys=True, data=True):
        net.add_edge(u, v, **_edge_style(data))

    net.write_html(out_path, notebook=False, open_browser=False)


def render_all(topology: Topology, out_dir: str) -> dict[str, str]:
    """Write topology.html (full), topology_l2.html and topology_l3.html
    into `out_dir`. Returns {view_name: path_written}."""
    paths = {
        "full": f"{out_dir}/topology.html",
        "l2": f"{out_dir}/topology_l2.html",
        "l3": f"{out_dir}/topology_l3.html",
    }
    render(topology.graph, paths["full"], "Network Topology -- L2 + L3")
    render(topology.l2_view(), paths["l2"], "Network Topology -- L2 (physical/switching)")
    render(topology.l3_view(), paths["l3"], "Network Topology -- L3 (routing/subnets)")
    return paths
