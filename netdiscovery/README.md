# netdiscovery -- Network Auto-Discovery & Topology Engine (POC)

A proof-of-concept network auto-discovery and topology engine. It walks a
network from one or more seed IPs, classifies every device it finds
(router / L3 switch / switch / firewall / access point / host), builds
Layer-2 topology from LLDP/CDP + the bridge FDB, builds Layer-3 topology
from routing tables + connected subnets, and picks up endpoints that never
speak LLDP/CDP at all (printers, cameras, servers, IoT) via ARP + FDB
correlation and MAC-OUI fingerprinting. The result is rendered as an
interactive HTML topology map.

This is a standalone Python project living under `netdiscovery/` inside
the CIPP-API repository -- it has no dependency on and no relationship to
the rest of that codebase; it's simply hosted here.

## Quickstart

```bash
cd netdiscovery
pip install -r requirements.txt
python demo.py
```

That runs the full discovery/collection/correlation pipeline against an
in-memory **simulated** network (no real devices needed) and writes:

- `topology.html` -- the full map, L2 + L3 layers together
- `topology_l2.html` -- physical/switching layer only
- `topology_l3.html` -- routing/subnet layer only
- `topology.graphml` -- for opening in Gephi/yEd/etc.

Open any of the `.html` files in a browser: nodes are draggable, edges
show their discovery source and interfaces on hover, and node color
encodes device role (router/switch/firewall/AP/endpoint kind).

Run the test suite with:

```bash
pytest
```

## The simulated demo network

`netdiscovery/simulator.py` models a small but non-trivial enterprise
network entirely in memory:

- A **redundant core**: 2 Cisco Nexus L3 switches, linked to each other
  *and* both linked to both distribution switches -- a ring, not a tree.
- 2 Cisco Catalyst distribution switches.
- 4 mixed-vendor access switches (Cisco IOS, Aruba/HPE ArubaOS-CX, Juniper
  Junos, and a second Cisco switch with LLDP disabled to prove the CDP
  fallback path). One access switch is dual-homed to both distribution
  switches.
- A Fortinet FortiGate as the L3 edge / default gateway.
- 3 VLANs (users/servers/cameras) with real subnets and SVIs.
- 11 endpoints that never run SNMP at all -- 3 servers, 4 PCs, 2 printers,
  2 IP cameras -- discoverable only via ARP + FDB + MAC-OUI fingerprinting.
- One switch that's advertised as an LLDP neighbor but never answers SNMP,
  to prove the discovery BFS survives a dead/unreachable host instead of
  crashing.

## Architecture

**Transport abstraction.** The engine never talks SNMP directly -- every
collection call goes through `SnmpTransport` (`transport.py`), an
interface with exactly two operations: `get(ip, oid)` and
`walk(ip, oid_prefix)`. `SimulatedTransport` answers those calls from the
in-memory network above; `LiveSnmpTransport` answers them with real SNMP
v2c GETs/WALKs over `pysnmp`. Nothing above the transport layer --
collection, discovery, topology correlation -- knows or cares which one
it's talking to. That's what makes this a genuine proof of concept rather
than a demo script: swap `SimulatedTransport()` for
`LiveSnmpTransport(community="...")` in `demo.py` and the identical engine
runs against a real network.

**Discovery BFS** (`discovery.py`). Starting from one or more seed IPs, the
engine collects each device, reads its LLDP/CDP neighbor table, and
enqueues any neighbor management IP it hasn't seen yet. An unreachable
device is recorded as a dead node in the graph and simply doesn't expand
any further -- one dead host can't abort the walk (a device that raises
during collection is caught and handled the same way, its error captured
in `DiscoveryResult.errors`, so an unusual/malformed response from one
unfamiliar device can't take down the whole run either). The BFS itself
is transport-agnostic concurrency: a thread pool probes up to
`concurrency` devices in parallel (frontier nodes are handed to workers
as they free up, same BFS order as the sequential walk at
`concurrency=1`), which is what makes scaling toward a fleet of hundreds
or thousands of devices tractable -- serially, one slow/dead host costs a
full `timeout * (retries + 1)` seconds each, and that adds up fast across
a large network.

**Device identification** (`device_id.py`). Vendor comes from the
sysObjectID enterprise prefix (falling back to sysDescr keyword matching).
Role comes from sysDescr keywords for firewall/AP (which would otherwise
look like an ordinary L3/L2 device), then from sysServices bits
(bridging vs. routing capability) for everything else.

**L2 correlation** (`l2_topology.py`). LLDP and CDP neighbor tables are the
primary source -- a link reported from both ends is deduplicated into one
edge, tagged with its protocol. For devices that never speak LLDP/CDP, a
switch's FDB is walked: a port that learned exactly one non-infrastructure
MAC is a confident access-port attachment. That MAC is then correlated
against every discovered device's ARP cache to recover its IP, and
fingerprinted by MAC-OUI to guess its kind (printer/camera/server/
workstation).

**L3 correlation** (`l3_topology.py`). Purely routing-plane: two devices
with a connected route into the same subnet are L3-neighbors on that
subnet (this is how the redundant core switches end up adjacent on every
VLAN they share); a non-connected route's next hop that resolves to
another discovered device's own interface IP is a routed adjacency toward
that route's destination (e.g. a default route pointing at the firewall).

**Graph, not tree** (`topology.py`). Both layers land in one
`networkx.MultiGraph`. A MultiGraph is the load-bearing decision here: it
allows more than one edge between the same pair of nodes, which is exactly
what a ring or dual-uplink design produces (core1↔core2 directly, *and*
core1↔dist1↔core2, *and* core1↔dist2↔core2 -- three parallel paths, none
of which should be discarded). `l2_view()`/`l3_view()` return filtered
sub-multigraphs; `to_graphml()` exports for external tools.

**Visualization** (`visualize.py`). Renders the unified graph (and each
layer view) as a self-contained, interactive vis-network HTML page via
`pyvis`, with node color by role/endpoint-kind and edge color/style by
discovery source and layer.

## Repository layout

```
netdiscovery/
├── README.md
├── requirements.txt
├── demo.py                 # end-to-end demo entry point (simulated network)
├── discover_live.py        # end-to-end entry point against a real network (SNMP)
├── netdiscovery/
│   ├── models.py            # Device/Interface/Neighbor/FdbEntry/ArpEntry/Route
│   ├── mibs.py               # OID constants + sysObjectID -> vendor map
│   ├── transport.py          # SnmpTransport ABC + LiveSnmpTransport (pysnmp)
│   ├── simulator.py          # SimulatedTransport + the modeled demo network
│   ├── device_id.py          # vendor/role classification + endpoint fingerprinting
│   ├── collector.py          # per-device SNMP collection
│   ├── discovery.py          # seed -> BFS neighbor expansion
│   ├── l2_topology.py        # LLDP/CDP + FDB-fallback link correlation
│   ├── l3_topology.py        # subnet/route-based L3 adjacency
│   ├── topology.py           # unified MultiGraph, layer views, GraphML export
│   └── visualize.py          # interactive HTML rendering
└── tests/
    ├── test_device_id.py
    ├── test_l2_topology.py
    └── test_l3_topology.py
```

## Pointing this at a real network

```bash
pip install -r requirements.txt   # pulls in pysnmp (pinned <7, see note below)
python discover_live.py --seed 192.168.1.1 [192.168.1.2 ...] --community public
```

`discover_live.py` is the same engine as `demo.py` -- discovery BFS, device
classification, L2/L3 correlation, graph model, HTML rendering -- with
`LiveSnmpTransport` (real SNMP v2c over `pysnmp`) in place of the in-memory
`SimulatedTransport`. `pysnmp` is only imported when `LiveSnmpTransport` is
actually instantiated, so the simulated demo path never needs it installed.
Useful flags: `--port`, `--timeout`, `--retries`, `--max-devices`,
`--concurrency` (default 10 -- how many devices are probed in parallel;
`1` for strictly sequential), `--out-dir`. Run `python discover_live.py
--help` for the full list.

The SNMP community string is read-only credential material -- pass it via
`--community` or the `NETDISCOVERY_SNMP_COMMUNITY` environment variable
rather than leaving it in shell history, and never commit it anywhere.

If nothing responds: check the seed IP(s), the community string, that
UDP/161 isn't firewalled between this host and the target, and that SNMP
is actually enabled on the device.

**pysnmp version note.** `pysnmp`'s `hlapi` is asyncio-only in every
currently maintained release -- `LiveSnmpTransport` wraps each
get/walk in its own `asyncio.run()` call to keep `SnmpTransport`'s
synchronous interface identical between the simulated and live paths.
`requirements.txt` pins `pysnmp<7`: version 7 restructured `hlapi` into
`v1arch`/`v3arch` submodules that also pull in the full USM/crypto stack
even for plain v2c polling, so this POC targets the lighter, still
fully-maintained `pysnmp.hlapi.asyncio` module from the 6.x line instead.
