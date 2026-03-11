#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  🕸️  SIREN KNOWLEDGE GRAPH — Memória Persistente Cross-Scan  🕸️              ██
██                                                                                ██
██  SIREN não esquece. Cada scan acumula CONHECIMENTO.                           ██
██                                                                                ██
██  O Knowledge Graph conecta:                                                    ██
██    • Vulnerabilidades ↔ Serviços ↔ Tecnologias ↔ Configurações               ██
██    • Credenciais encontradas ↔ Acessos que habilitam                          ██
██    • Cadeias de ataque → Impacto real observado                               ██
██    • Padrões recorrentes entre diferentes alvos                               ██
██                                                                                ██
██  Capacidades:                                                                  ██
██    • KnowledgeNode — entidade tipada no grafo                                 ██
██    • KnowledgeEdge — relação tipada entre entidades                           ██
██    • KnowledgeGraph — grafo in-memory com indices e persistência              ██
██    • GraphQueryEngine — queries: paths, patterns, subgraphs, reasoning        ██
██                                                                                ██
██  "SIREN lembra o que outras ferramentas descartam."                           ██
██                                                                                ██
████████████████████████████████████████████████████████████████████████████████████
"""

from __future__ import annotations

import hashlib
import heapq
import json
import logging
import math
import threading
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    FrozenSet,
    Iterator,
    List,
    Optional,
    Set,
    Tuple,
    Union,
)

logger = logging.getLogger("siren.cortex.knowledge_graph")


# ════════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════════════════════════════

THREAD_POOL_SIZE = 4
MAX_PATH_DEPTH = 20
MAX_QUERY_RESULTS = 1000


# ════════════════════════════════════════════════════════════════════════════════
# ENUMS
# ════════════════════════════════════════════════════════════════════════════════


class NodeType(Enum):
    """Types of entities in the knowledge graph."""
    # ── Target-level ──
    HOST = "host"                     # IP address or hostname
    SERVICE = "service"               # Running service (http, ssh, etc.)
    PORT = "port"                     # Open port
    DOMAIN = "domain"                 # Domain name
    URL = "url"                       # Specific URL endpoint

    # ── Technology ──
    TECHNOLOGY = "technology"         # Framework, language, library
    VERSION = "version"               # Specific version of a technology
    CONFIGURATION = "configuration"   # Configuration setting

    # ── Security ──
    VULNERABILITY = "vulnerability"   # Specific vulnerability
    CWE = "cwe"                       # CWE weakness class
    CVE = "cve"                       # CVE identifier
    EXPLOIT = "exploit"               # Exploit technique/chain
    PRIMITIVE = "primitive"           # Exploit primitive

    # ── Identity ──
    CREDENTIAL = "credential"         # Username/password/token
    USER = "user"                     # User account
    ROLE = "role"                     # User role/privilege level

    # ── Data ──
    DATABASE = "database"             # Database instance
    TABLE = "table"                   # Database table
    SENSITIVE_DATA = "sensitive_data" # PII, secrets, keys

    # ── Network ──
    NETWORK = "network"               # Network segment
    FIREWALL_RULE = "firewall_rule"   # Firewall/WAF rule

    # ── Meta ──
    SCAN = "scan"                     # Scan session
    FINDING = "finding"               # Scan finding
    EVIDENCE = "evidence"             # Supporting evidence


class EdgeType(Enum):
    """Types of relationships between entities."""
    # ── Structural ──
    HOSTS = "hosts"                   # host → service
    RUNS_ON = "runs_on"               # service → host
    LISTENS_ON = "listens_on"         # service → port
    RESOLVES_TO = "resolves_to"       # domain → host
    CONTAINS = "contains"             # url → endpoint

    # ── Technology ──
    USES = "uses"                     # service → technology
    HAS_VERSION = "has_version"       # technology → version
    CONFIGURED_WITH = "configured_with"  # service → configuration

    # ── Security ──
    HAS_VULN = "has_vulnerability"    # service/url → vulnerability
    CLASSIFIED_AS = "classified_as"   # vulnerability → CWE
    IDENTIFIED_AS = "identified_as"   # vulnerability → CVE
    EXPLOITED_BY = "exploited_by"     # vulnerability → exploit
    ENABLES = "enables"               # exploit → primitive
    LEADS_TO = "leads_to"             # primitive → state change
    CHAINS_TO = "chains_to"           # primitive → primitive

    # ── Identity ──
    AUTHENTICATES = "authenticates"   # credential → service
    BELONGS_TO = "belongs_to"         # credential → user
    HAS_ROLE = "has_role"             # user → role
    ACCESSES = "accesses"             # user → service/data

    # ── Data ──
    STORES = "stores"                 # service → database
    CONTAINS_TABLE = "contains_table" # database → table
    EXPOSES = "exposes"               # vulnerability → sensitive_data

    # ── Provenance ──
    FOUND_BY = "found_by"             # finding → scan
    SUPPORTED_BY = "supported_by"     # finding → evidence

    # ── Network ──
    CONNECTED_TO = "connected_to"     # host → host
    PROTECTS = "protects"             # firewall_rule → service
    BYPASSES = "bypasses"             # exploit → firewall_rule

    # ── Causal ──
    DEPENDS_ON = "depends_on"         # anything → prerequisite
    RELATED_TO = "related_to"         # generic relation
    SIMILAR_TO = "similar_to"         # similarity-based


# ════════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ════════════════════════════════════════════════════════════════════════════════


@dataclass
class KnowledgeNode:
    """An entity in the knowledge graph."""
    node_id: str                        # Unique identifier
    node_type: NodeType
    label: str                          # Human-readable label
    properties: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0             # [0-1] confidence in this node
    source: str = ""                    # Which scan/module produced this
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def __hash__(self) -> int:
        return hash(self.node_id)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, KnowledgeNode):
            return NotImplemented
        return self.node_id == other.node_id

    def update_properties(self, props: Dict[str, Any]) -> None:
        """Merge new properties into existing ones."""
        self.properties.update(props)
        self.updated_at = time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "type": self.node_type.value,
            "label": self.label,
            "properties": self.properties,
            "confidence": self.confidence,
            "source": self.source,
        }


@dataclass
class KnowledgeEdge:
    """A typed, directed relationship between two nodes."""
    edge_id: str
    source_id: str
    target_id: str
    edge_type: EdgeType
    weight: float = 1.0                 # Relationship strength
    confidence: float = 1.0
    properties: Dict[str, Any] = field(default_factory=dict)
    source: str = ""
    created_at: float = field(default_factory=time.time)

    def __hash__(self) -> int:
        return hash(self.edge_id)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "type": self.edge_type.value,
            "weight": self.weight,
            "confidence": self.confidence,
            "properties": self.properties,
        }


@dataclass
class QueryResult:
    """Result of a graph query."""
    nodes: List[KnowledgeNode] = field(default_factory=list)
    edges: List[KnowledgeEdge] = field(default_factory=list)
    paths: List[List[str]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "path_count": len(self.paths),
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "paths": self.paths,
            "metadata": self.metadata,
        }


# ════════════════════════════════════════════════════════════════════════════════
# CORE ENGINE: KnowledgeGraph
# ════════════════════════════════════════════════════════════════════════════════


class KnowledgeGraph:
    """Thread-safe directed knowledge graph with indexed lookups.

    Supports:
    - O(1) node/edge lookup by ID
    - O(1) neighbor lookup (adjacency lists)
    - O(1) type-indexed queries
    - Bulk insert for scan ingestion
    - Merge semantics (update existing nodes)
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._nodes: Dict[str, KnowledgeNode] = {}
        self._edges: Dict[str, KnowledgeEdge] = {}

        # Adjacency lists
        self._outgoing: Dict[str, List[str]] = defaultdict(list)   # node_id → [edge_ids]
        self._incoming: Dict[str, List[str]] = defaultdict(list)   # node_id → [edge_ids]

        # Type indices
        self._nodes_by_type: Dict[NodeType, Set[str]] = defaultdict(set)
        self._edges_by_type: Dict[EdgeType, Set[str]] = defaultdict(set)

        # Label index for fuzzy matching
        self._label_index: Dict[str, str] = {}  # lower(label) → node_id

    # ── Node operations ────────────────────────────────────────────────────

    def add_node(self, node: KnowledgeNode, merge: bool = True) -> KnowledgeNode:
        """Add or merge a node.

        If merge=True and node exists, properties are merged and confidence
        updated (max of old and new).
        """
        with self._lock:
            existing = self._nodes.get(node.node_id)
            if existing and merge:
                existing.update_properties(node.properties)
                existing.confidence = max(existing.confidence, node.confidence)
                existing.updated_at = time.time()
                return existing
            else:
                self._nodes[node.node_id] = node
                self._nodes_by_type[node.node_type].add(node.node_id)
                self._label_index[node.label.lower()] = node.node_id
                return node

    def get_node(self, node_id: str) -> Optional[KnowledgeNode]:
        """Get a node by ID."""
        with self._lock:
            return self._nodes.get(node_id)

    def get_nodes_by_type(self, node_type: NodeType) -> List[KnowledgeNode]:
        """Get all nodes of a type."""
        with self._lock:
            ids = self._nodes_by_type.get(node_type, set())
            return [self._nodes[nid] for nid in ids if nid in self._nodes]

    def find_node_by_label(self, label: str) -> Optional[KnowledgeNode]:
        """Find a node by label (case-insensitive)."""
        with self._lock:
            nid = self._label_index.get(label.lower())
            return self._nodes.get(nid) if nid else None

    def remove_node(self, node_id: str) -> bool:
        """Remove a node and all its edges."""
        with self._lock:
            if node_id not in self._nodes:
                return False
            node = self._nodes[node_id]

            # Remove all edges
            edge_ids = list(self._outgoing.get(node_id, []))
            edge_ids.extend(self._incoming.get(node_id, []))
            for eid in set(edge_ids):
                self._remove_edge_internal(eid)

            # Remove from indices
            self._nodes_by_type[node.node_type].discard(node_id)
            self._label_index.pop(node.label.lower(), None)
            del self._nodes[node_id]
            self._outgoing.pop(node_id, None)
            self._incoming.pop(node_id, None)
            return True

    @property
    def node_count(self) -> int:
        with self._lock:
            return len(self._nodes)

    # ── Edge operations ────────────────────────────────────────────────────

    def add_edge(self, edge: KnowledgeEdge) -> KnowledgeEdge:
        """Add an edge. Both source and target nodes must exist."""
        with self._lock:
            if edge.source_id not in self._nodes:
                raise ValueError(f"Source node '{edge.source_id}' not in graph")
            if edge.target_id not in self._nodes:
                raise ValueError(f"Target node '{edge.target_id}' not in graph")

            self._edges[edge.edge_id] = edge
            self._outgoing[edge.source_id].append(edge.edge_id)
            self._incoming[edge.target_id].append(edge.edge_id)
            self._edges_by_type[edge.edge_type].add(edge.edge_id)
            return edge

    def get_edge(self, edge_id: str) -> Optional[KnowledgeEdge]:
        with self._lock:
            return self._edges.get(edge_id)

    def get_edges_between(self, source_id: str, target_id: str) -> List[KnowledgeEdge]:
        """Get all edges from source to target."""
        with self._lock:
            result: List[KnowledgeEdge] = []
            for eid in self._outgoing.get(source_id, []):
                edge = self._edges.get(eid)
                if edge and edge.target_id == target_id:
                    result.append(edge)
            return result

    def get_outgoing_edges(self, node_id: str, edge_type: Optional[EdgeType] = None) -> List[KnowledgeEdge]:
        """Get outgoing edges from a node, optionally filtered by type."""
        with self._lock:
            eids = self._outgoing.get(node_id, [])
            edges = [self._edges[eid] for eid in eids if eid in self._edges]
            if edge_type:
                edges = [e for e in edges if e.edge_type == edge_type]
            return edges

    def get_incoming_edges(self, node_id: str, edge_type: Optional[EdgeType] = None) -> List[KnowledgeEdge]:
        """Get incoming edges to a node, optionally filtered by type."""
        with self._lock:
            eids = self._incoming.get(node_id, [])
            edges = [self._edges[eid] for eid in eids if eid in self._edges]
            if edge_type:
                edges = [e for e in edges if e.edge_type == edge_type]
            return edges

    def get_neighbors(
        self, node_id: str, direction: str = "both", edge_type: Optional[EdgeType] = None
    ) -> List[KnowledgeNode]:
        """Get neighbor nodes."""
        with self._lock:
            neighbor_ids: Set[str] = set()
            if direction in ("out", "both"):
                for edge in self.get_outgoing_edges(node_id, edge_type):
                    neighbor_ids.add(edge.target_id)
            if direction in ("in", "both"):
                for edge in self.get_incoming_edges(node_id, edge_type):
                    neighbor_ids.add(edge.source_id)
            return [self._nodes[nid] for nid in neighbor_ids if nid in self._nodes]

    def _remove_edge_internal(self, edge_id: str) -> None:
        """Remove an edge (no lock — caller must hold lock)."""
        edge = self._edges.pop(edge_id, None)
        if edge:
            out_list = self._outgoing.get(edge.source_id, [])
            if edge_id in out_list:
                out_list.remove(edge_id)
            in_list = self._incoming.get(edge.target_id, [])
            if edge_id in in_list:
                in_list.remove(edge_id)
            self._edges_by_type[edge.edge_type].discard(edge_id)

    @property
    def edge_count(self) -> int:
        with self._lock:
            return len(self._edges)

    # ── Bulk operations ────────────────────────────────────────────────────

    def add_nodes_bulk(self, nodes: List[KnowledgeNode]) -> int:
        """Add multiple nodes. Returns count of added/merged nodes."""
        count = 0
        for node in nodes:
            self.add_node(node)
            count += 1
        return count

    def add_edges_bulk(self, edges: List[KnowledgeEdge]) -> int:
        """Add multiple edges. Returns count of added edges (skips invalid)."""
        count = 0
        for edge in edges:
            try:
                self.add_edge(edge)
                count += 1
            except ValueError:
                continue
        return count

    # ── Graph algorithms ───────────────────────────────────────────────────

    def bfs(self, start_id: str, max_depth: int = MAX_PATH_DEPTH) -> List[KnowledgeNode]:
        """Breadth-first traversal from start node."""
        with self._lock:
            if start_id not in self._nodes:
                return []

            visited: Set[str] = {start_id}
            queue: deque = deque([(start_id, 0)])
            result: List[KnowledgeNode] = [self._nodes[start_id]]

            while queue:
                current_id, depth = queue.popleft()
                if depth >= max_depth:
                    continue
                for edge in self.get_outgoing_edges(current_id):
                    if edge.target_id not in visited:
                        visited.add(edge.target_id)
                        node = self._nodes.get(edge.target_id)
                        if node:
                            result.append(node)
                            queue.append((edge.target_id, depth + 1))

            return result

    def shortest_path(self, source_id: str, target_id: str) -> Optional[List[str]]:
        """Find shortest (lowest-weight) path using Dijkstra's algorithm."""
        with self._lock:
            if source_id not in self._nodes or target_id not in self._nodes:
                return None

            # dist[node_id] = best cumulative weight so far
            dist: Dict[str, float] = {source_id: 0.0}
            prev: Dict[str, Optional[str]] = {source_id: None}
            # priority queue: (cumulative_weight, node_id)
            heap: List[Tuple[float, str]] = [(0.0, source_id)]

            while heap:
                current_cost, current_id = heapq.heappop(heap)
                if current_id == target_id:
                    # Reconstruct path
                    path: List[str] = []
                    nid: Optional[str] = target_id
                    while nid is not None:
                        path.append(nid)
                        nid = prev.get(nid)
                    path.reverse()
                    return path
                if current_cost > dist.get(current_id, math.inf):
                    continue
                if len(dist) > MAX_PATH_DEPTH:
                    continue
                for edge in self.get_outgoing_edges(current_id):
                    new_cost = current_cost + edge.weight
                    if new_cost < dist.get(edge.target_id, math.inf):
                        dist[edge.target_id] = new_cost
                        prev[edge.target_id] = current_id
                        heapq.heappush(heap, (new_cost, edge.target_id))

            return None

    def find_all_paths(
        self, source_id: str, target_id: str, max_depth: int = 8
    ) -> List[List[str]]:
        """Find all paths from source to target up to max_depth.

        Returned paths are sorted by total edge weight (lowest first).
        """
        with self._lock:
            if source_id not in self._nodes or target_id not in self._nodes:
                return []

            all_paths: List[Tuple[float, List[str]]] = []

            def _dfs(current: str, path: List[str], visited: Set[str], cost: float) -> None:
                if len(path) > max_depth:
                    return
                if current == target_id:
                    all_paths.append((cost, list(path)))
                    return
                for edge in self.get_outgoing_edges(current):
                    if edge.target_id not in visited:
                        visited.add(edge.target_id)
                        path.append(edge.target_id)
                        _dfs(edge.target_id, path, visited, cost + edge.weight)
                        path.pop()
                        visited.discard(edge.target_id)

            _dfs(source_id, [source_id], {source_id}, 0.0)
            all_paths.sort(key=lambda x: x[0])
            return [p for _, p in all_paths]

    def subgraph(self, node_ids: Set[str]) -> Tuple[List[KnowledgeNode], List[KnowledgeEdge]]:
        """Extract a subgraph containing specific nodes and edges between them."""
        with self._lock:
            nodes = [self._nodes[nid] for nid in node_ids if nid in self._nodes]
            edges: List[KnowledgeEdge] = []
            for nid in node_ids:
                for edge in self.get_outgoing_edges(nid):
                    if edge.target_id in node_ids:
                        edges.append(edge)
            return nodes, edges

    def connected_components(self) -> List[Set[str]]:
        """Find connected components (treating graph as undirected)."""
        with self._lock:
            visited: Set[str] = set()
            components: List[Set[str]] = []

            for nid in self._nodes:
                if nid in visited:
                    continue
                component: Set[str] = set()
                queue: deque = deque([nid])
                while queue:
                    current = queue.popleft()
                    if current in visited:
                        continue
                    visited.add(current)
                    component.add(current)
                    for edge in self.get_outgoing_edges(current):
                        if edge.target_id not in visited:
                            queue.append(edge.target_id)
                    for edge in self.get_incoming_edges(current):
                        if edge.source_id not in visited:
                            queue.append(edge.source_id)
                if component:
                    components.append(component)

            return components

    def degree_centrality(self, top_k: int = 10) -> List[Tuple[str, float]]:
        """Calculate degree centrality (normalized)."""
        with self._lock:
            n = max(1, len(self._nodes) - 1)
            centrality: List[Tuple[str, float]] = []
            for nid in self._nodes:
                degree = len(self._outgoing.get(nid, [])) + len(self._incoming.get(nid, []))
                centrality.append((nid, degree / n))
            centrality.sort(key=lambda x: x[1], reverse=True)
            return centrality[:top_k]

    # ── Serialization ──────────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "nodes": [n.to_dict() for n in self._nodes.values()],
                "edges": [e.to_dict() for e in self._edges.values()],
                "stats": {
                    "node_count": len(self._nodes),
                    "edge_count": len(self._edges),
                    "node_types": {
                        nt.value: len(ids) for nt, ids in self._nodes_by_type.items() if ids
                    },
                    "edge_types": {
                        et.value: len(ids) for et, ids in self._edges_by_type.items() if ids
                    },
                },
            }

    def save(self, path: Union[str, Path]) -> None:
        """Save graph to JSON file."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.to_dict(), indent=2, default=str), encoding="utf-8")

    def load(self, path: Union[str, Path]) -> None:
        """Load graph from JSON file."""
        p = Path(path)
        if not p.exists():
            return

        data = json.loads(p.read_text(encoding="utf-8"))

        for n in data.get("nodes", []):
            node = KnowledgeNode(
                node_id=n["node_id"],
                node_type=NodeType(n["type"]),
                label=n["label"],
                properties=n.get("properties", {}),
                confidence=n.get("confidence", 1.0),
                source=n.get("source", ""),
            )
            self.add_node(node)

        for e in data.get("edges", []):
            edge = KnowledgeEdge(
                edge_id=e["edge_id"],
                source_id=e["source_id"],
                target_id=e["target_id"],
                edge_type=EdgeType(e["type"]),
                weight=e.get("weight", 1.0),
                confidence=e.get("confidence", 1.0),
                properties=e.get("properties", {}),
            )
            try:
                self.add_edge(edge)
            except ValueError:
                continue


# ════════════════════════════════════════════════════════════════════════════════
# QUERY ENGINE
# ════════════════════════════════════════════════════════════════════════════════


class GraphQueryEngine:
    """High-level query interface for the knowledge graph.

    Provides pattern-based queries, filtered traversals, and
    analytical queries that combine multiple graph operations.
    """

    def __init__(self, graph: KnowledgeGraph) -> None:
        self._graph = graph
        self._lock = threading.RLock()

    def find_attack_surface(self) -> QueryResult:
        """Find all entry points: services, URLs, exposed endpoints."""
        nodes: List[KnowledgeNode] = []
        nodes.extend(self._graph.get_nodes_by_type(NodeType.SERVICE))
        nodes.extend(self._graph.get_nodes_by_type(NodeType.URL))
        nodes.extend(self._graph.get_nodes_by_type(NodeType.PORT))

        edges: List[KnowledgeEdge] = []
        for node in nodes:
            edges.extend(self._graph.get_outgoing_edges(node.node_id))
            edges.extend(self._graph.get_incoming_edges(node.node_id))

        return QueryResult(nodes=nodes, edges=edges, metadata={"query": "attack_surface"})

    def find_vuln_chains(self, vuln_node_id: str) -> QueryResult:
        """Find all entities connected to a vulnerability."""
        reachable = self._graph.bfs(vuln_node_id, max_depth=5)
        node_ids = {n.node_id for n in reachable}
        _, edges = self._graph.subgraph(node_ids)
        return QueryResult(nodes=reachable, edges=edges, metadata={"root_vuln": vuln_node_id})

    def find_credential_impact(self, credential_id: str) -> QueryResult:
        """Trace what a found credential grants access to."""
        reachable = self._graph.bfs(credential_id, max_depth=6)
        services = [n for n in reachable if n.node_type in (NodeType.SERVICE, NodeType.DATABASE)]
        data = [n for n in reachable if n.node_type == NodeType.SENSITIVE_DATA]

        return QueryResult(
            nodes=reachable,
            metadata={
                "credential": credential_id,
                "accessible_services": len(services),
                "exposed_data": len(data),
            },
        )

    def find_path_to_target(
        self, start_id: str, target_type: NodeType, max_depth: int = 8
    ) -> QueryResult:
        """Find paths from a start node to any node of a target type."""
        targets = self._graph.get_nodes_by_type(target_type)
        all_paths: List[List[str]] = []

        for target in targets:
            paths = self._graph.find_all_paths(start_id, target.node_id, max_depth)
            all_paths.extend(paths)

        return QueryResult(
            paths=all_paths,
            metadata={"start": start_id, "target_type": target_type.value, "paths_found": len(all_paths)},
        )

    def find_related_vulns(self, cwe_id: str) -> QueryResult:
        """Find all vulnerabilities classified under a given CWE."""
        cwe_nodes = [
            n for n in self._graph.get_nodes_by_type(NodeType.CWE)
            if cwe_id in n.label or cwe_id in n.node_id
        ]

        vulns: List[KnowledgeNode] = []
        for cwe_node in cwe_nodes:
            incoming = self._graph.get_incoming_edges(cwe_node.node_id, EdgeType.CLASSIFIED_AS)
            for edge in incoming:
                node = self._graph.get_node(edge.source_id)
                if node:
                    vulns.append(node)

        return QueryResult(nodes=vulns, metadata={"cwe": cwe_id, "vuln_count": len(vulns)})

    def get_high_value_nodes(self, top_k: int = 10) -> QueryResult:
        """Find nodes with highest centrality — key assets and chokepoints."""
        centrality = self._graph.degree_centrality(top_k)
        nodes = []
        for nid, score in centrality:
            node = self._graph.get_node(nid)
            if node:
                node.properties["centrality_score"] = score
                nodes.append(node)

        return QueryResult(nodes=nodes, metadata={"metric": "degree_centrality"})

    def query_pattern(
        self,
        source_type: Optional[NodeType] = None,
        edge_type: Optional[EdgeType] = None,
        target_type: Optional[NodeType] = None,
    ) -> QueryResult:
        """Find all triples matching a pattern (source) -[edge]-> (target)."""
        matching_nodes: List[KnowledgeNode] = []
        matching_edges: List[KnowledgeEdge] = []

        sources = (
            self._graph.get_nodes_by_type(source_type)
            if source_type
            else list(self._graph._nodes.values())
        )

        for src in sources[:MAX_QUERY_RESULTS]:
            edges = self._graph.get_outgoing_edges(src.node_id, edge_type)
            for edge in edges:
                target = self._graph.get_node(edge.target_id)
                if target and (target_type is None or target.node_type == target_type):
                    if src not in matching_nodes:
                        matching_nodes.append(src)
                    if target not in matching_nodes:
                        matching_nodes.append(target)
                    matching_edges.append(edge)

        return QueryResult(nodes=matching_nodes, edges=matching_edges)


# ════════════════════════════════════════════════════════════════════════════════
# MAIN INTERFACE: SirenKnowledgeGraph
# ════════════════════════════════════════════════════════════════════════════════


class SirenKnowledgeGraph:
    """Main interface for SIREN's persistent knowledge graph.

    Usage:
        kg = SirenKnowledgeGraph()

        # Ingest scan results
        kg.ingest_scan_results(scan_id="scan_001", results=scan_data)

        # Query
        surface = kg.query_attack_surface()
        paths = kg.find_paths("vuln_001", NodeType.SENSITIVE_DATA)

        # Persist
        kg.save("knowledge_state.json")
    """

    def __init__(self) -> None:
        self._graph = KnowledgeGraph()
        self._query = GraphQueryEngine(self._graph)
        self._pool = ThreadPoolExecutor(
            max_workers=THREAD_POOL_SIZE, thread_name_prefix="siren-kg"
        )
        self._lock = threading.RLock()
        self._scan_count = 0

        logger.info("SirenKnowledgeGraph initialized")

    # ── Ingestion ──────────────────────────────────────────────────────────

    def ingest_scan_results(self, scan_id: str, results: Dict[str, Any]) -> Dict[str, int]:
        """Ingest structured scan results into the knowledge graph.

        Expected result format:
        {
            "hosts": [{"ip": "...", "hostname": "...", "ports": [...]}],
            "services": [{"id": "...", "name": "...", "version": "...", "host": "..."}],
            "vulnerabilities": [{"id": "...", "cwe": "...", "service": "...", "confidence": ...}],
            "credentials": [{"id": "...", "type": "...", "value": "...", "service": "..."}],
            "technologies": [{"name": "...", "version": "...", "service": "..."}],
        }
        """
        counts = {"nodes": 0, "edges": 0}

        # Basic schema validation
        _expected_sections = {"hosts", "services", "vulnerabilities", "credentials", "technologies"}
        for section in results:
            if section not in _expected_sections:
                logger.warning("Unexpected section '%s' in scan results for %s — skipping", section, scan_id)
        for section in _expected_sections:
            value = results.get(section)
            if value is not None and not isinstance(value, list):
                logger.warning("Section '%s' in scan %s is not a list — skipping", section, scan_id)
                results[section] = []

        # Scan node
        scan_node = KnowledgeNode(
            node_id=scan_id, node_type=NodeType.SCAN,
            label=f"Scan {scan_id}", source="ingestion",
        )
        self._graph.add_node(scan_node)
        counts["nodes"] += 1

        # Hosts
        for host in results.get("hosts", []):
            try:
                h_id = f"host_{host.get('ip', host.get('hostname', 'unknown'))}"
                self._graph.add_node(KnowledgeNode(
                    node_id=h_id, node_type=NodeType.HOST,
                    label=host.get("hostname", host.get("ip", "")),
                    properties=host, source=scan_id,
                ))
                counts["nodes"] += 1

                for port in host.get("ports", []):
                    p_id = f"{h_id}_port_{port}"
                    self._graph.add_node(KnowledgeNode(
                        node_id=p_id, node_type=NodeType.PORT,
                        label=f"Port {port}", properties={"port": port}, source=scan_id,
                    ))
                    self._graph.add_edge(KnowledgeEdge(
                        edge_id=f"{h_id}_listens_{p_id}", source_id=h_id, target_id=p_id,
                        edge_type=EdgeType.LISTENS_ON, source=scan_id,
                    ))
                    counts["nodes"] += 1
                    counts["edges"] += 1
            except (KeyError, TypeError, AttributeError) as exc:
                logger.warning("Skipping malformed host entry in scan %s: %s", scan_id, exc)
                continue

        # Services
        for svc in results.get("services", []):
            try:
                s_id = svc.get("id", f"svc_{svc.get('name', 'unknown')}")
                self._graph.add_node(KnowledgeNode(
                    node_id=s_id, node_type=NodeType.SERVICE,
                    label=svc.get("name", ""), properties=svc, source=scan_id,
                ))
                counts["nodes"] += 1

                host_id = svc.get("host")
                if host_id:
                    h_id = f"host_{host_id}"
                    if self._graph.get_node(h_id):
                        self._graph.add_edge(KnowledgeEdge(
                            edge_id=f"{h_id}_hosts_{s_id}", source_id=h_id, target_id=s_id,
                            edge_type=EdgeType.HOSTS, source=scan_id,
                        ))
                        counts["edges"] += 1
            except (KeyError, TypeError, AttributeError) as exc:
                logger.warning("Skipping malformed service entry in scan %s: %s", scan_id, exc)
                continue

        # Vulnerabilities
        for vuln in results.get("vulnerabilities", []):
            try:
                v_id = vuln.get("id", f"vuln_{hash(str(vuln))}")
                self._graph.add_node(KnowledgeNode(
                    node_id=v_id, node_type=NodeType.VULNERABILITY,
                    label=v_id, properties=vuln,
                    confidence=vuln.get("confidence", 0.8), source=scan_id,
                ))
                counts["nodes"] += 1

                # Link to CWE
                cwe = vuln.get("cwe")
                if cwe:
                    cwe_id = f"cwe_{cwe}"
                    self._graph.add_node(KnowledgeNode(
                        node_id=cwe_id, node_type=NodeType.CWE,
                        label=cwe, source=scan_id,
                    ))
                    self._graph.add_edge(KnowledgeEdge(
                        edge_id=f"{v_id}_classified_{cwe_id}", source_id=v_id, target_id=cwe_id,
                        edge_type=EdgeType.CLASSIFIED_AS, source=scan_id,
                    ))
                    counts["nodes"] += 1
                    counts["edges"] += 1

                # Link to service
                svc_id = vuln.get("service")
                if svc_id and self._graph.get_node(svc_id):
                    self._graph.add_edge(KnowledgeEdge(
                        edge_id=f"{svc_id}_has_vuln_{v_id}", source_id=svc_id, target_id=v_id,
                        edge_type=EdgeType.HAS_VULN, source=scan_id,
                    ))
                    counts["edges"] += 1

                # Link to scan
                self._graph.add_edge(KnowledgeEdge(
                    edge_id=f"{v_id}_found_by_{scan_id}", source_id=v_id, target_id=scan_id,
                    edge_type=EdgeType.FOUND_BY, source=scan_id,
                ))
                counts["edges"] += 1
            except (KeyError, TypeError, AttributeError) as exc:
                logger.warning("Skipping malformed vulnerability entry in scan %s: %s", scan_id, exc)
                continue

        # Credentials
        for cred in results.get("credentials", []):
            try:
                c_id = cred.get("id", f"cred_{hash(str(cred))}")
                self._graph.add_node(KnowledgeNode(
                    node_id=c_id, node_type=NodeType.CREDENTIAL,
                    label=cred.get("type", "credential"),
                    properties={k: v for k, v in cred.items() if k != "value"},
                    source=scan_id,
                ))
                counts["nodes"] += 1

                svc_id = cred.get("service")
                if svc_id and self._graph.get_node(svc_id):
                    self._graph.add_edge(KnowledgeEdge(
                        edge_id=f"{c_id}_auth_{svc_id}", source_id=c_id, target_id=svc_id,
                        edge_type=EdgeType.AUTHENTICATES, source=scan_id,
                    ))
                    counts["edges"] += 1
            except (KeyError, TypeError, AttributeError) as exc:
                logger.warning("Skipping malformed credential entry in scan %s: %s", scan_id, exc)
                continue

        # Technologies
        for tech in results.get("technologies", []):
            try:
                t_id = f"tech_{tech.get('name', 'unknown')}_{tech.get('version', 'x')}"
                self._graph.add_node(KnowledgeNode(
                    node_id=t_id, node_type=NodeType.TECHNOLOGY,
                    label=f"{tech.get('name', '')} {tech.get('version', '')}".strip(),
                    properties=tech, source=scan_id,
                ))
                counts["nodes"] += 1

                svc_id = tech.get("service")
                if svc_id and self._graph.get_node(svc_id):
                    self._graph.add_edge(KnowledgeEdge(
                        edge_id=f"{svc_id}_uses_{t_id}", source_id=svc_id, target_id=t_id,
                        edge_type=EdgeType.USES, source=scan_id,
                    ))
                    counts["edges"] += 1
            except (KeyError, TypeError, AttributeError) as exc:
                logger.warning("Skipping malformed technology entry in scan %s: %s", scan_id, exc)
                continue

        with self._lock:
            self._scan_count += 1

        logger.info(f"Ingested scan {scan_id}: {counts['nodes']} nodes, {counts['edges']} edges")
        return counts

    # ── Query interface ────────────────────────────────────────────────────

    def query_attack_surface(self) -> Dict[str, Any]:
        """Query the current attack surface."""
        return self._query.find_attack_surface().to_dict()

    def find_paths(self, start_id: str, target_type: NodeType, max_depth: int = 8) -> Dict[str, Any]:
        """Find paths from a node to all nodes of a type."""
        return self._query.find_path_to_target(start_id, target_type, max_depth).to_dict()

    def get_vuln_context(self, vuln_id: str) -> Dict[str, Any]:
        """Get full context around a vulnerability."""
        return self._query.find_vuln_chains(vuln_id).to_dict()

    def get_credential_blast_radius(self, cred_id: str) -> Dict[str, Any]:
        """Trace credential access impact."""
        return self._query.find_credential_impact(cred_id).to_dict()

    def find_related_vulnerabilities(self, cwe_id: str) -> Dict[str, Any]:
        """Find all vulnerabilities of a CWE class."""
        return self._query.find_related_vulns(cwe_id).to_dict()

    def get_high_value_targets(self, top_k: int = 10) -> Dict[str, Any]:
        """Find highest-centrality nodes."""
        return self._query.get_high_value_nodes(top_k).to_dict()

    def query_triples(
        self,
        source_type: Optional[str] = None,
        edge_type: Optional[str] = None,
        target_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Query graph by pattern matching."""
        st = NodeType(source_type) if source_type else None
        et = EdgeType(edge_type) if edge_type else None
        tt = NodeType(target_type) if target_type else None
        return self._query.query_pattern(st, et, tt).to_dict()

    # ── Graph access ───────────────────────────────────────────────────────

    def add_node(self, node: KnowledgeNode) -> KnowledgeNode:
        return self._graph.add_node(node)

    def add_edge(self, edge: KnowledgeEdge) -> KnowledgeEdge:
        return self._graph.add_edge(edge)

    def get_node(self, node_id: str) -> Optional[Dict[str, Any]]:
        node = self._graph.get_node(node_id)
        return node.to_dict() if node else None

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_nodes": self._graph.node_count,
            "total_edges": self._graph.edge_count,
            "scans_ingested": self._scan_count,
            "components": len(self._graph.connected_components()),
        }

    # ── Persistence ────────────────────────────────────────────────────────

    def save(self, path: Union[str, Path]) -> None:
        self._graph.save(path)

    def load(self, path: Union[str, Path]) -> None:
        self._graph.load(path)

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False)
        logger.info("SirenKnowledgeGraph shutdown")

    def __del__(self) -> None:
        """Safety net to ensure thread pool is cleaned up."""
        self.shutdown()
