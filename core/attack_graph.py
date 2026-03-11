#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  🕸️  SIREN ATTACK GRAPH ENGINE — Vulnerability Chain Analysis  🕸️            ██
██                                                                                ██
██  NENHUMA FERRAMENTA NO MERCADO FAZ ISSO:                                       ██
██                                                                                ██
██  Analise matematica de grafos de ataque que:                                   ██
██    • Constroi grafos direcionados de vulnerabilidades + pre-condicoes           ██
██    • Calcula caminho mais curto para cada ativo critico (Dijkstra)              ██
██    • Identifica "lynchpin vulnerabilities" (betweenness centrality)             ██
██    • Computa blast radius: dano total de cada cadeia de exploits                ██
██    • Gera cadeias de ataque otimas (multi-step exploitation)                    ██
██    • Scoring preditivo: probabilidade real de exploracao por cadeia             ██
██    • Deteccao de ciclos de escalonamento de privilegio                          ██
██    • Analise de superfcie de ataque com mutacao em tempo real                   ██
██    • Renderizacao visual do grafo (DOT/Mermaid)                                ██
██                                                                                ██
██  "Uma vulnerabilidade sozinha é um risco. Combinadas, são uma catástrofe."     ██
██                                                                                ██
████████████████████████████████████████████████████████████████████████████████████
"""

from __future__ import annotations

import hashlib
import heapq
import json
import logging
import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

logger = logging.getLogger("siren.attack_graph")


# ════════════════════════════════════════════════════════════════════════════
# ENUMS & CONSTANTS
# ════════════════════════════════════════════════════════════════════════════


class NodeType(Enum):
    """Type of node in the attack graph."""

    ENTRY_POINT = "entry_point"  # External access (internet, user input)
    VULNERABILITY = "vulnerability"  # A discovered vulnerability
    PRIVILEGE = "privilege"  # A privilege level (anon, user, admin, root)
    ASSET = "asset"  # A critical asset (DB, file system, secrets)
    SERVICE = "service"  # A running service/endpoint
    CREDENTIAL = "credential"  # An obtained credential


class EdgeType(Enum):
    """Type of edge (attack transition) in the graph."""

    EXPLOITS = "exploits"  # Vulnerability exploitation
    ESCALATES = "escalates"  # Privilege escalation
    PIVOTS = "pivots"  # Lateral movement
    ACCESSES = "accesses"  # Asset access
    LEAKS = "leaks"  # Information disclosure
    CHAINS = "chains"  # Multi-step chain link
    REQUIRES = "requires"  # Pre-condition dependency


class RiskTier(Enum):
    CATASTROPHIC = "catastrophic"  # CVSS 9.0+, full compromise
    SEVERE = "severe"  # CVSS 7.0-8.9, major breach
    ELEVATED = "elevated"  # CVSS 4.0-6.9, data leak
    MODERATE = "moderate"  # CVSS 2.0-3.9, limited impact
    MINIMAL = "minimal"  # CVSS 0.1-1.9, informational


# Pre-condition → post-condition mapping for common vuln types
VULN_TRANSITIONS: Dict[str, Dict[str, Any]] = {
    "sqli": {
        "precondition": "network_access",
        "postcondition": "database_read",
        "escalates_to": ["database_write", "os_command"],
        "base_probability": 0.85,
    },
    "xss": {
        "precondition": "network_access",
        "postcondition": "session_theft",
        "escalates_to": ["account_takeover"],
        "base_probability": 0.70,
    },
    "ssrf": {
        "precondition": "network_access",
        "postcondition": "internal_network",
        "escalates_to": ["metadata_access", "service_discovery"],
        "base_probability": 0.75,
    },
    "rce": {
        "precondition": "network_access",
        "postcondition": "os_command",
        "escalates_to": ["root_access", "lateral_movement"],
        "base_probability": 0.95,
    },
    "auth_bypass": {
        "precondition": "network_access",
        "postcondition": "authenticated_access",
        "escalates_to": ["admin_access", "data_exfil"],
        "base_probability": 0.80,
    },
    "idor": {
        "precondition": "authenticated_access",
        "postcondition": "data_exfil",
        "escalates_to": ["mass_data_leak"],
        "base_probability": 0.90,
    },
    "lfi": {
        "precondition": "network_access",
        "postcondition": "file_read",
        "escalates_to": ["credential_theft", "source_code_leak"],
        "base_probability": 0.80,
    },
    "xxe": {
        "precondition": "network_access",
        "postcondition": "file_read",
        "escalates_to": ["ssrf_internal", "credential_theft"],
        "base_probability": 0.70,
    },
    "ssti": {
        "precondition": "network_access",
        "postcondition": "os_command",
        "escalates_to": ["root_access"],
        "base_probability": 0.85,
    },
    "deserialization": {
        "precondition": "network_access",
        "postcondition": "os_command",
        "escalates_to": ["root_access", "lateral_movement"],
        "base_probability": 0.80,
    },
    "jwt_weakness": {
        "precondition": "network_access",
        "postcondition": "token_forge",
        "escalates_to": ["admin_access", "account_takeover"],
        "base_probability": 0.75,
    },
    "cors_misconfiguration": {
        "precondition": "network_access",
        "postcondition": "cross_origin_data",
        "escalates_to": ["session_theft", "data_exfil"],
        "base_probability": 0.60,
    },
    "open_redirect": {
        "precondition": "network_access",
        "postcondition": "phishing_vector",
        "escalates_to": ["credential_theft"],
        "base_probability": 0.50,
    },
    "cmdi": {
        "precondition": "network_access",
        "postcondition": "os_command",
        "escalates_to": ["root_access", "lateral_movement"],
        "base_probability": 0.90,
    },
    "privilege_escalation": {
        "precondition": "authenticated_access",
        "postcondition": "admin_access",
        "escalates_to": ["root_access"],
        "base_probability": 0.70,
    },
}

# Impact weights for post-conditions
IMPACT_WEIGHTS: Dict[str, float] = {
    "network_access": 0.1,
    "authenticated_access": 0.3,
    "session_theft": 0.5,
    "account_takeover": 0.7,
    "database_read": 0.6,
    "database_write": 0.8,
    "file_read": 0.5,
    "credential_theft": 0.7,
    "source_code_leak": 0.6,
    "os_command": 0.9,
    "root_access": 1.0,
    "admin_access": 0.8,
    "internal_network": 0.7,
    "lateral_movement": 0.9,
    "data_exfil": 0.8,
    "mass_data_leak": 0.95,
    "metadata_access": 0.6,
    "service_discovery": 0.4,
    "token_forge": 0.7,
    "cross_origin_data": 0.4,
    "phishing_vector": 0.3,
    "ssrf_internal": 0.7,
}


# ════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ════════════════════════════════════════════════════════════════════════════


@dataclass
class AttackNode:
    """A node in the attack graph."""

    id: str = ""
    name: str = ""
    node_type: NodeType = NodeType.VULNERABILITY
    cvss: float = 0.0
    cwe: str = ""
    description: str = ""
    url: str = ""
    preconditions: Set[str] = field(default_factory=set)
    postconditions: Set[str] = field(default_factory=set)
    exploit_probability: float = 0.5
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __hash__(self) -> int:
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, AttackNode):
            return self.id == other.id
        return NotImplemented


@dataclass
class AttackEdge:
    """An edge (attack transition) in the graph."""

    source_id: str = ""
    target_id: str = ""
    edge_type: EdgeType = EdgeType.EXPLOITS
    weight: float = 1.0  # Lower = easier to exploit
    probability: float = 0.5  # Probability of successful exploitation
    description: str = ""
    preconditions: Set[str] = field(default_factory=set)

    @property
    def risk_weight(self) -> float:
        """Inverse probability — higher probability = lower weight for shortest path."""
        return 1.0 - self.probability + 0.01  # Avoid zero


@dataclass
class AttackChain:
    """A complete attack chain (path through the graph)."""

    chain_id: str = ""
    nodes: List[str] = field(default_factory=list)
    edges: List[AttackEdge] = field(default_factory=list)
    total_probability: float = 0.0
    total_impact: float = 0.0
    blast_radius: float = 0.0
    risk_tier: RiskTier = RiskTier.MINIMAL
    entry_point: str = ""
    final_target: str = ""
    description: str = ""
    required_capabilities: Set[str] = field(default_factory=set)

    @property
    def chain_risk_score(self) -> float:
        """Compound risk: probability × impact × chain length bonus."""
        length_bonus = min(1.0 + (len(self.nodes) - 2) * 0.1, 2.0)
        return self.total_probability * self.total_impact * length_bonus


@dataclass
class BlastRadiusResult:
    """Blast radius analysis for a single vulnerability."""

    vuln_id: str = ""
    vuln_name: str = ""
    directly_reachable: List[str] = field(default_factory=list)
    transitively_reachable: List[str] = field(default_factory=list)
    affected_assets: List[str] = field(default_factory=list)
    max_privilege_reachable: str = ""
    blast_score: float = 0.0  # 0-100
    chains_enabled: int = 0


@dataclass
class LynchpinResult:
    """Lynchpin analysis — vulnerability whose fix blocks the most attack paths."""

    vuln_id: str = ""
    vuln_name: str = ""
    betweenness_centrality: float = 0.0
    chains_broken: int = 0
    risk_reduction: float = 0.0  # 0-100
    dependent_vulns: List[str] = field(default_factory=list)


@dataclass
class AttackSurfaceSnapshot:
    """Point-in-time snapshot of the attack surface."""

    timestamp: float = 0.0
    total_nodes: int = 0
    total_edges: int = 0
    total_chains: int = 0
    critical_chains: int = 0
    max_chain_probability: float = 0.0
    max_blast_radius: float = 0.0
    mean_betweenness: float = 0.0
    lynchpins: List[str] = field(default_factory=list)
    risk_score: float = 0.0


@dataclass
class GraphAnalysisResult:
    """Complete analysis result from the attack graph engine."""

    nodes: Dict[str, AttackNode] = field(default_factory=dict)
    edges: List[AttackEdge] = field(default_factory=list)
    chains: List[AttackChain] = field(default_factory=list)
    lynchpins: List[LynchpinResult] = field(default_factory=list)
    blast_radii: List[BlastRadiusResult] = field(default_factory=list)
    surface_snapshot: Optional[AttackSurfaceSnapshot] = None
    risk_score: float = 0.0
    generation_time: float = 0.0

    @property
    def critical_chains(self) -> List[AttackChain]:
        return [c for c in self.chains if c.risk_tier == RiskTier.CATASTROPHIC]

    @property
    def top_lynchpins(self) -> List[LynchpinResult]:
        return sorted(
            self.lynchpins, key=lambda l: l.betweenness_centrality, reverse=True
        )[:5]


# ════════════════════════════════════════════════════════════════════════════
# ATTACK GRAPH — CORE GRAPH STRUCTURE
# ════════════════════════════════════════════════════════════════════════════


class AttackGraph:
    """Directed weighted graph representing vulnerability chains.

    Uses adjacency lists for efficient traversal and supports:
    - Dijkstra's algorithm for shortest attack paths
    - BFS/DFS for reachability analysis
    - Betweenness centrality for lynchpin detection
    - Cycle detection for privilege escalation loops
    """

    def __init__(self) -> None:
        self.nodes: Dict[str, AttackNode] = {}
        self.adjacency: Dict[str, List[AttackEdge]] = defaultdict(list)
        self.reverse_adjacency: Dict[str, List[AttackEdge]] = defaultdict(list)
        self._node_counter = 0

    def add_node(self, node: AttackNode) -> str:
        """Add a node, generating ID if not set."""
        if not node.id:
            self._node_counter += 1
            node.id = f"node_{self._node_counter}"
        self.nodes[node.id] = node
        return node.id

    def add_edge(self, edge: AttackEdge) -> None:
        """Add a directed edge."""
        if edge.source_id not in self.nodes or edge.target_id not in self.nodes:
            logger.warning(
                "Edge references unknown node: %s -> %s", edge.source_id, edge.target_id
            )
            return
        self.adjacency[edge.source_id].append(edge)
        self.reverse_adjacency[edge.target_id].append(edge)

    def get_neighbors(self, node_id: str) -> List[Tuple[str, AttackEdge]]:
        """Get all outgoing neighbors of a node."""
        return [(e.target_id, e) for e in self.adjacency.get(node_id, [])]

    def get_predecessors(self, node_id: str) -> List[Tuple[str, AttackEdge]]:
        """Get all incoming neighbors of a node."""
        return [(e.source_id, e) for e in self.reverse_adjacency.get(node_id, [])]

    def dijkstra(
        self, source_id: str
    ) -> Tuple[Dict[str, float], Dict[str, Optional[str]]]:
        """Dijkstra's shortest path — finds easiest exploitation path.

        Uses risk_weight (1 - probability) as edge weight, so paths
        with highest exploitation probability become "shortest".
        """
        dist: Dict[str, float] = {nid: float("inf") for nid in self.nodes}
        prev: Dict[str, Optional[str]] = {nid: None for nid in self.nodes}
        dist[source_id] = 0.0

        # Min-heap: (distance, node_id)
        heap: List[Tuple[float, str]] = [(0.0, source_id)]

        while heap:
            d, u = heapq.heappop(heap)
            if d > dist[u]:
                continue
            for v, edge in self.get_neighbors(u):
                alt = d + edge.risk_weight
                if alt < dist[v]:
                    dist[v] = alt
                    prev[v] = u
                    heapq.heappush(heap, (alt, v))

        return dist, prev

    def reconstruct_path(
        self, prev: Dict[str, Optional[str]], target_id: str
    ) -> List[str]:
        """Reconstruct path from Dijkstra's predecessor map."""
        path: List[str] = []
        current: Optional[str] = target_id
        while current is not None:
            path.append(current)
            current = prev.get(current)
        path.reverse()
        return path if len(path) > 1 else []

    def bfs_reachable(self, source_id: str) -> Set[str]:
        """BFS — find all nodes reachable from source."""
        visited: Set[str] = set()
        queue: deque[str] = deque([source_id])
        while queue:
            node = queue.popleft()
            if node in visited:
                continue
            visited.add(node)
            for neighbor, _ in self.get_neighbors(node):
                if neighbor not in visited:
                    queue.append(neighbor)
        return visited - {source_id}

    def find_all_paths(
        self, source_id: str, target_id: str, max_depth: int = 10
    ) -> List[List[str]]:
        """DFS — find all paths between two nodes (bounded by depth)."""
        all_paths: List[List[str]] = []
        stack: List[Tuple[str, List[str]]] = [(source_id, [source_id])]

        while stack:
            node, path = stack.pop()
            if node == target_id and len(path) > 1:
                all_paths.append(path[:])
                continue
            if len(path) > max_depth:
                continue
            for neighbor, _ in self.get_neighbors(node):
                if neighbor not in path:  # Avoid cycles
                    stack.append((neighbor, path + [neighbor]))

        return all_paths

    def detect_cycles(self) -> List[List[str]]:
        """Detect all cycles — privilege escalation loops."""
        cycles: List[List[str]] = []
        visited: Set[str] = set()
        rec_stack: Set[str] = set()

        def _dfs(node: str, path: List[str]) -> None:
            visited.add(node)
            rec_stack.add(node)

            for neighbor, _ in self.get_neighbors(node):
                if neighbor not in visited:
                    _dfs(neighbor, path + [neighbor])
                elif neighbor in rec_stack:
                    # Found a cycle
                    cycle_start = path.index(neighbor) if neighbor in path else -1
                    if cycle_start >= 0:
                        cycles.append(path[cycle_start:] + [neighbor])

            rec_stack.discard(node)

        for node_id in self.nodes:
            if node_id not in visited:
                _dfs(node_id, [node_id])

        return cycles

    def betweenness_centrality(self) -> Dict[str, float]:
        """Compute betweenness centrality for all nodes.

        Betweenness = fraction of shortest paths passing through a node.
        High betweenness = "lynchpin" vulnerability — fixing it breaks many chains.
        Uses Brandes' algorithm (O(VE)).
        """
        centrality: Dict[str, float] = {nid: 0.0 for nid in self.nodes}

        for s in self.nodes:
            # Single-source shortest paths (BFS on unweighted / Dijkstra on weighted)
            stack: List[str] = []
            predecessors: Dict[str, List[str]] = defaultdict(list)
            sigma: Dict[str, int] = defaultdict(int)
            sigma[s] = 1
            dist_map: Dict[str, float] = defaultdict(lambda: float("inf"))
            dist_map[s] = 0.0

            # Dijkstra forward pass
            heap: List[Tuple[float, str]] = [(0.0, s)]
            while heap:
                d, v = heapq.heappop(heap)
                if d > dist_map[v]:
                    continue
                stack.append(v)
                for w, edge in self.get_neighbors(v):
                    new_dist = d + edge.risk_weight
                    if new_dist < dist_map[w]:
                        dist_map[w] = new_dist
                        sigma[w] = 0
                        predecessors[w] = []
                        heapq.heappush(heap, (new_dist, w))
                    if abs(new_dist - dist_map[w]) < 1e-9:
                        sigma[w] += sigma[v]
                        predecessors[w].append(v)

            # Backward accumulation
            delta: Dict[str, float] = defaultdict(float)
            while stack:
                w = stack.pop()
                for v in predecessors[w]:
                    if sigma[w] > 0:
                        delta[v] += (sigma[v] / sigma[w]) * (1.0 + delta[w])
                if w != s:
                    centrality[w] += delta[w]

        # Normalize
        n = len(self.nodes)
        if n > 2:
            norm = 1.0 / ((n - 1) * (n - 2))
            for nid in centrality:
                centrality[nid] *= norm

        return centrality

    def compute_chain_probability(self, path: List[str]) -> float:
        """Compute compound probability of an attack chain.

        P(chain) = product of P(each step) × discount for chain length.
        """
        if len(path) < 2:
            return 0.0

        probability = 1.0
        for i in range(len(path) - 1):
            src, tgt = path[i], path[i + 1]
            best_prob = 0.0
            for edge in self.adjacency.get(src, []):
                if edge.target_id == tgt:
                    best_prob = max(best_prob, edge.probability)
            probability *= best_prob

        # Discount for chain length (longer chains = less reliable)
        length_discount = 0.95 ** (len(path) - 2)
        return probability * length_discount

    def compute_blast_radius(self, node_id: str) -> BlastRadiusResult:
        """Compute blast radius — total damage reachable from a vulnerability."""
        result = BlastRadiusResult(vuln_id=node_id)
        node = self.nodes.get(node_id)
        if not node:
            return result
        result.vuln_name = node.name

        # Direct neighbors
        for neighbor, edge in self.get_neighbors(node_id):
            result.directly_reachable.append(neighbor)

        # Transitive closure (BFS)
        reachable = self.bfs_reachable(node_id)
        result.transitively_reachable = list(reachable)

        # Affected assets
        for nid in reachable:
            reachable_node = self.nodes.get(nid)
            if reachable_node and reachable_node.node_type == NodeType.ASSET:
                result.affected_assets.append(nid)

        # Max privilege
        max_priv = ""
        max_priv_weight = 0.0
        for nid in reachable:
            reachable_node = self.nodes.get(nid)
            if reachable_node and reachable_node.node_type == NodeType.PRIVILEGE:
                for pc in reachable_node.postconditions:
                    w = IMPACT_WEIGHTS.get(pc, 0.0)
                    if w > max_priv_weight:
                        max_priv_weight = w
                        max_priv = pc

        result.max_privilege_reachable = max_priv

        # Blast score: weighted sum of reachable impacts
        total_impact = sum(
            IMPACT_WEIGHTS.get(pc, 0.1)
            for nid in reachable
            for pc in self.nodes.get(nid, AttackNode()).postconditions
        )
        result.blast_score = min(total_impact * 20.0, 100.0)

        return result


# ════════════════════════════════════════════════════════════════════════════
# ATTACK GRAPH BUILDER — From Vulnerability Findings
# ════════════════════════════════════════════════════════════════════════════


class AttackGraphBuilder:
    """Builds attack graphs from vulnerability scan results.

    Transforms flat vulnerability lists into rich directed graphs
    with pre/post-conditions, enabling chain analysis.
    """

    def __init__(self) -> None:
        self.graph = AttackGraph()
        self._entry_points: List[str] = []
        self._asset_nodes: List[str] = []
        self._priv_nodes: Dict[str, str] = {}  # privilege_name → node_id

    def _ensure_privilege_node(self, privilege: str) -> str:
        """Get or create a privilege level node."""
        if privilege in self._priv_nodes:
            return self._priv_nodes[privilege]
        node = AttackNode(
            name=f"Privilege: {privilege}",
            node_type=NodeType.PRIVILEGE,
            postconditions={privilege},
        )
        nid = self.graph.add_node(node)
        self._priv_nodes[privilege] = nid
        return nid

    def _ensure_asset_node(self, asset_name: str) -> str:
        """Get or create an asset node."""
        for nid, node in self.graph.nodes.items():
            if node.node_type == NodeType.ASSET and node.name == asset_name:
                return nid
        node = AttackNode(
            name=asset_name,
            node_type=NodeType.ASSET,
        )
        nid = self.graph.add_node(node)
        self._asset_nodes.append(nid)
        return nid

    def add_entry_point(self, name: str, url: str = "") -> str:
        """Add an external entry point (internet-facing surface)."""
        node = AttackNode(
            name=name,
            node_type=NodeType.ENTRY_POINT,
            url=url,
            postconditions={"network_access"},
        )
        nid = self.graph.add_node(node)
        self._entry_points.append(nid)

        # Connect to network_access privilege
        priv_nid = self._ensure_privilege_node("network_access")
        self.graph.add_edge(
            AttackEdge(
                source_id=nid,
                target_id=priv_nid,
                edge_type=EdgeType.ACCESSES,
                probability=1.0,
                weight=0.01,
                description="External access",
            )
        )
        return nid

    def add_vulnerability(
        self,
        name: str,
        vuln_type: str,
        cvss: float = 5.0,
        cwe: str = "",
        url: str = "",
        description: str = "",
        custom_probability: Optional[float] = None,
    ) -> str:
        """Add a vulnerability and auto-wire pre/post-conditions."""
        transition = VULN_TRANSITIONS.get(vuln_type, {})
        precondition = transition.get("precondition", "network_access")
        postcondition = transition.get("postcondition", "unknown_access")
        base_prob = transition.get("base_probability", 0.5)

        # CVSS-adjusted probability
        cvss_factor = min(cvss / 10.0, 1.0)
        probability = custom_probability or (base_prob * (0.5 + 0.5 * cvss_factor))

        vuln_node = AttackNode(
            name=name,
            node_type=NodeType.VULNERABILITY,
            cvss=cvss,
            cwe=cwe,
            url=url,
            description=description,
            preconditions={precondition},
            postconditions={postcondition},
            exploit_probability=probability,
        )
        vuln_nid = self.graph.add_node(vuln_node)

        # Wire: precondition_privilege → vuln
        pre_nid = self._ensure_privilege_node(precondition)
        self.graph.add_edge(
            AttackEdge(
                source_id=pre_nid,
                target_id=vuln_nid,
                edge_type=EdgeType.REQUIRES,
                probability=1.0,
                weight=0.01,
                description=f"Requires {precondition}",
                preconditions={precondition},
            )
        )

        # Wire: vuln → postcondition_privilege
        post_nid = self._ensure_privilege_node(postcondition)
        self.graph.add_edge(
            AttackEdge(
                source_id=vuln_nid,
                target_id=post_nid,
                edge_type=EdgeType.EXPLOITS,
                probability=probability,
                weight=1.0 - probability + 0.01,
                description=f"{name} → {postcondition}",
            )
        )

        # Wire escalation paths
        for escalation in transition.get("escalates_to", []):
            esc_nid = self._ensure_privilege_node(escalation)
            esc_prob = probability * 0.6  # Escalation is harder
            self.graph.add_edge(
                AttackEdge(
                    source_id=post_nid,
                    target_id=esc_nid,
                    edge_type=EdgeType.ESCALATES,
                    probability=esc_prob,
                    weight=1.0 - esc_prob + 0.01,
                    description=f"Escalation: {postcondition} → {escalation}",
                )
            )

        return vuln_nid

    def add_finding(self, finding: Dict[str, Any]) -> str:
        """Add from a generic finding dict (interop with SIREN scanner output)."""
        # Map finding severity to CVSS
        severity_cvss = {
            "critical": 9.5,
            "high": 8.0,
            "medium": 5.5,
            "low": 3.0,
            "info": 1.0,
        }
        cvss = finding.get(
            "cvss_score",
            severity_cvss.get(finding.get("severity", "medium").lower(), 5.0),
        )

        # Detect vuln type from category/tags
        vuln_type = self._classify_vuln_type(finding)

        return self.add_vulnerability(
            name=finding.get("title", "Unknown Vulnerability"),
            vuln_type=vuln_type,
            cvss=cvss,
            cwe=finding.get("cwe", ""),
            url=finding.get("url", ""),
            description=finding.get("description", ""),
        )

    def _classify_vuln_type(self, finding: Dict[str, Any]) -> str:
        """Classify a finding into a known vuln type."""
        category = finding.get("category", "").lower()
        title = finding.get("title", "").lower()
        tags = [t.lower() for t in finding.get("tags", [])]
        combined = f"{category} {title} {' '.join(tags)}"

        type_keywords = {
            "sqli": ["sql", "sqli", "injection"],
            "xss": ["xss", "cross-site scripting", "reflected", "stored"],
            "ssrf": ["ssrf", "server-side request"],
            "rce": ["rce", "remote code", "command execution"],
            "auth_bypass": ["auth bypass", "authentication", "broken auth"],
            "idor": ["idor", "insecure direct", "object reference"],
            "lfi": ["lfi", "local file", "path traversal", "file inclusion"],
            "xxe": ["xxe", "xml external", "xml entity"],
            "ssti": ["ssti", "template injection", "server-side template"],
            "deserialization": ["deserialization", "deserialize", "pickle", "marshal"],
            "jwt_weakness": ["jwt", "json web token"],
            "cors_misconfiguration": ["cors"],
            "cmdi": ["command injection", "cmdi", "os command"],
            "privilege_escalation": ["privilege", "escalation", "privesc"],
        }

        for vuln_type, keywords in type_keywords.items():
            for kw in keywords:
                if kw in combined:
                    return vuln_type

        return "unknown"

    def add_critical_assets(self, assets: Optional[List[str]] = None) -> None:
        """Add critical assets (database, secrets, admin panel, etc.)."""
        default_assets = [
            "Production Database",
            "User Credentials Store",
            "Admin Panel",
            "Internal API",
            "Cloud Metadata",
            "Source Code Repository",
        ]
        for asset_name in assets or default_assets:
            self._ensure_asset_node(asset_name)

        # Wire high-privilege nodes to assets
        asset_access_map = {
            "database_read": ["Production Database"],
            "database_write": ["Production Database"],
            "credential_theft": ["User Credentials Store"],
            "admin_access": ["Admin Panel"],
            "internal_network": ["Internal API"],
            "metadata_access": ["Cloud Metadata"],
            "source_code_leak": ["Source Code Repository"],
            "root_access": [
                a for a in (assets or default_assets)
            ],  # Root accesses everything
        }
        for privilege, asset_names in asset_access_map.items():
            if privilege in self._priv_nodes:
                priv_nid = self._priv_nodes[privilege]
                for asset_name in asset_names:
                    for nid, node in self.graph.nodes.items():
                        if node.node_type == NodeType.ASSET and node.name == asset_name:
                            self.graph.add_edge(
                                AttackEdge(
                                    source_id=priv_nid,
                                    target_id=nid,
                                    edge_type=EdgeType.ACCESSES,
                                    probability=0.95,
                                    weight=0.06,
                                    description=f"{privilege} → {asset_name}",
                                )
                            )

    def build(self) -> AttackGraph:
        """Return the constructed graph."""
        return self.graph


# ════════════════════════════════════════════════════════════════════════════
# SIREN ATTACK GRAPH ANALYZER — THE BRAIN
# ════════════════════════════════════════════════════════════════════════════


class SirenAttackGraphAnalyzer:
    """The attack graph analysis engine.

    Takes vulnerability findings and produces:
    1. Attack graph with nodes (vulns) and edges (exploitations)
    2. Optimal attack chains (shortest = easiest to exploit)
    3. Blast radius per vulnerability
    4. Lynchpin identification (fix these first)
    5. Privilege escalation cycle detection
    6. Attack surface snapshots for trending
    7. Risk scoring with chain awareness

    This is what makes SIREN unique — no other tool does this.
    """

    VERSION = "1.0.0"

    def __init__(self) -> None:
        self.builder = AttackGraphBuilder()
        self.graph: Optional[AttackGraph] = None
        self._snapshots: List[AttackSurfaceSnapshot] = []

    def ingest_findings(
        self,
        findings: List[Dict[str, Any]],
        target_url: str = "",
        critical_assets: Optional[List[str]] = None,
    ) -> None:
        """Ingest vulnerability findings and build the attack graph."""
        # Add entry point
        self.builder.add_entry_point(
            name=f"Internet → {target_url or 'target'}",
            url=target_url,
        )

        # Add each finding as a vulnerability node
        for finding in findings:
            self.builder.add_finding(finding)

        # Add critical assets
        self.builder.add_critical_assets(critical_assets)

        # Build
        self.graph = self.builder.build()
        logger.info(
            "Attack graph built: %d nodes, %d edges",
            len(self.graph.nodes),
            sum(len(edges) for edges in self.graph.adjacency.values()),
        )

    def analyze(self) -> GraphAnalysisResult:
        """Run complete analysis on the attack graph."""
        if not self.graph:
            return GraphAnalysisResult()

        start_time = time.monotonic()
        result = GraphAnalysisResult(
            nodes=dict(self.graph.nodes),
            edges=[e for edges in self.graph.adjacency.values() for e in edges],
        )

        # 1. Find all attack chains from entry points to assets
        result.chains = self._find_attack_chains()

        # 2. Compute betweenness centrality → lynchpins
        result.lynchpins = self._find_lynchpins()

        # 3. Compute blast radius for each vulnerability
        result.blast_radii = self._compute_blast_radii()

        # 4. Detect privilege escalation cycles
        cycles = self.graph.detect_cycles()
        if cycles:
            logger.info("Detected %d privilege escalation cycles", len(cycles))

        # 5. Compute overall risk score
        result.risk_score = self._compute_risk_score(result)

        # 6. Take snapshot
        snapshot = self._take_snapshot(result)
        result.surface_snapshot = snapshot
        self._snapshots.append(snapshot)

        result.generation_time = time.monotonic() - start_time
        logger.info(
            "Analysis complete in %.3fs: %d chains, %d lynchpins, risk=%.1f",
            result.generation_time,
            len(result.chains),
            len(result.lynchpins),
            result.risk_score,
        )

        return result

    def _find_attack_chains(self) -> List[AttackChain]:
        """Find all meaningful attack chains."""
        if not self.graph:
            return []

        chains: List[AttackChain] = []
        entry_nodes = [
            nid
            for nid, n in self.graph.nodes.items()
            if n.node_type == NodeType.ENTRY_POINT
        ]
        asset_nodes = [
            nid for nid, n in self.graph.nodes.items() if n.node_type == NodeType.ASSET
        ]
        high_priv_nodes = [
            nid
            for nid, n in self.graph.nodes.items()
            if n.node_type == NodeType.PRIVILEGE
            and any(IMPACT_WEIGHTS.get(pc, 0) >= 0.7 for pc in n.postconditions)
        ]

        targets = asset_nodes + high_priv_nodes

        for entry in entry_nodes:
            dist, prev = self.graph.dijkstra(entry)

            for target in targets:
                if dist[target] == float("inf"):
                    continue

                # Shortest path
                path = self.graph.reconstruct_path(prev, target)
                if len(path) < 2:
                    continue

                probability = self.graph.compute_chain_probability(path)
                if probability < 0.01:
                    continue

                # Compute impact
                target_node = self.graph.nodes[target]
                impact = (
                    max(
                        IMPACT_WEIGHTS.get(pc, 0.1) for pc in target_node.postconditions
                    )
                    if target_node.postconditions
                    else 0.1
                )

                # Build chain object
                chain_edges = []
                for i in range(len(path) - 1):
                    for edge in self.graph.adjacency.get(path[i], []):
                        if edge.target_id == path[i + 1]:
                            chain_edges.append(edge)
                            break

                chain_id = hashlib.md5(":".join(path).encode()).hexdigest()[:12]

                chain = AttackChain(
                    chain_id=chain_id,
                    nodes=path,
                    edges=chain_edges,
                    total_probability=probability,
                    total_impact=impact,
                    blast_radius=probability * impact * 100,
                    entry_point=entry,
                    final_target=target,
                    description=self._describe_chain(path),
                )
                chain.risk_tier = self._classify_risk(chain)
                chains.append(chain)

            # Also find ALL paths (not just shortest) up to depth 8
            for target in targets:
                all_paths = self.graph.find_all_paths(entry, target, max_depth=8)
                for path in all_paths:
                    path_id = hashlib.md5(":".join(path).encode()).hexdigest()[:12]
                    # Skip if already found as shortest
                    if any(c.chain_id == path_id for c in chains):
                        continue

                    probability = self.graph.compute_chain_probability(path)
                    if probability < 0.05:
                        continue

                    target_node = self.graph.nodes[target]
                    impact = (
                        max(
                            IMPACT_WEIGHTS.get(pc, 0.1)
                            for pc in target_node.postconditions
                        )
                        if target_node.postconditions
                        else 0.1
                    )

                    chain = AttackChain(
                        chain_id=path_id,
                        nodes=path,
                        total_probability=probability,
                        total_impact=impact,
                        blast_radius=probability * impact * 100,
                        entry_point=entry,
                        final_target=target,
                        description=self._describe_chain(path),
                    )
                    chain.risk_tier = self._classify_risk(chain)
                    chains.append(chain)

        # Sort by risk score descending
        chains.sort(key=lambda c: c.chain_risk_score, reverse=True)
        return chains

    def _find_lynchpins(self) -> List[LynchpinResult]:
        """Identify lynchpin vulnerabilities via betweenness centrality."""
        if not self.graph:
            return []

        centrality = self.graph.betweenness_centrality()
        lynchpins: List[LynchpinResult] = []

        for nid, bc in centrality.items():
            node = self.graph.nodes[nid]
            if node.node_type != NodeType.VULNERABILITY:
                continue
            if bc < 0.01:
                continue

            # Count chains that pass through this node
            reachable = self.graph.bfs_reachable(nid)
            dependent = [
                r
                for r in reachable
                if self.graph.nodes.get(r, AttackNode()).node_type
                == NodeType.VULNERABILITY
            ]

            lynchpins.append(
                LynchpinResult(
                    vuln_id=nid,
                    vuln_name=node.name,
                    betweenness_centrality=bc,
                    chains_broken=len(dependent),
                    risk_reduction=bc * 100,
                    dependent_vulns=dependent,
                )
            )

        lynchpins.sort(key=lambda l: l.betweenness_centrality, reverse=True)
        return lynchpins

    def _compute_blast_radii(self) -> List[BlastRadiusResult]:
        """Compute blast radius for every vulnerability node."""
        if not self.graph:
            return []

        radii: List[BlastRadiusResult] = []
        for nid, node in self.graph.nodes.items():
            if node.node_type != NodeType.VULNERABILITY:
                continue
            radius = self.graph.compute_blast_radius(nid)
            radii.append(radius)

        radii.sort(key=lambda r: r.blast_score, reverse=True)
        return radii

    def _classify_risk(self, chain: AttackChain) -> RiskTier:
        """Classify a chain into a risk tier."""
        score = chain.chain_risk_score
        if score >= 0.7:
            return RiskTier.CATASTROPHIC
        if score >= 0.4:
            return RiskTier.SEVERE
        if score >= 0.2:
            return RiskTier.ELEVATED
        if score >= 0.05:
            return RiskTier.MODERATE
        return RiskTier.MINIMAL

    def _compute_risk_score(self, result: GraphAnalysisResult) -> float:
        """Compute overall risk score (0-100).

        Factors: chain count, max chain probability, blast radius,
        lynchpin concentration, and presence of catastrophic chains.
        """
        if not result.chains:
            return 0.0

        max_chain_prob = (
            max(c.total_probability for c in result.chains) if result.chains else 0
        )
        max_blast = (
            max(b.blast_score for b in result.blast_radii) if result.blast_radii else 0
        )
        catastrophic_count = sum(
            1 for c in result.chains if c.risk_tier == RiskTier.CATASTROPHIC
        )
        chain_density = min(len(result.chains) / 10.0, 1.0)

        score = (
            max_chain_prob * 30
            + max_blast * 0.3
            + min(catastrophic_count * 10, 30)
            + chain_density * 10
        )
        return min(score, 100.0)

    def _describe_chain(self, path: List[str]) -> str:
        """Generate human-readable description of a chain."""
        if not self.graph:
            return ""
        parts: List[str] = []
        for nid in path:
            node = self.graph.nodes.get(nid)
            if node:
                parts.append(node.name)
        return " → ".join(parts)

    def _take_snapshot(self, result: GraphAnalysisResult) -> AttackSurfaceSnapshot:
        """Take a point-in-time snapshot of the attack surface."""
        return AttackSurfaceSnapshot(
            timestamp=time.time(),
            total_nodes=len(result.nodes),
            total_edges=len(result.edges),
            total_chains=len(result.chains),
            critical_chains=len(result.critical_chains),
            max_chain_probability=max(
                (c.total_probability for c in result.chains), default=0.0
            ),
            max_blast_radius=max(
                (b.blast_score for b in result.blast_radii), default=0.0
            ),
            mean_betweenness=(
                sum(l.betweenness_centrality for l in result.lynchpins)
                / max(len(result.lynchpins), 1)
            ),
            lynchpins=[l.vuln_id for l in result.top_lynchpins],
            risk_score=result.risk_score,
        )

    def get_surface_trend(self) -> List[AttackSurfaceSnapshot]:
        """Get historical attack surface snapshots for trending."""
        return list(self._snapshots)

    def render_mermaid(self, result: Optional[GraphAnalysisResult] = None) -> str:
        """Render the attack graph as Mermaid diagram syntax."""
        if not self.graph:
            return ""

        lines = ["graph TD"]

        # Style definitions
        lines.append("    classDef entry fill:#2196F3,stroke:#1565C0,color:#fff")
        lines.append("    classDef vuln fill:#f44336,stroke:#c62828,color:#fff")
        lines.append("    classDef priv fill:#FF9800,stroke:#E65100,color:#fff")
        lines.append("    classDef asset fill:#4CAF50,stroke:#2E7D32,color:#fff")

        # Nodes
        for nid, node in self.graph.nodes.items():
            safe_name = node.name.replace('"', "'")[:50]
            safe_id = nid.replace("-", "_")
            if node.node_type == NodeType.ENTRY_POINT:
                lines.append(f'    {safe_id}["{safe_name}"]:::entry')
            elif node.node_type == NodeType.VULNERABILITY:
                lines.append(
                    f'    {safe_id}{{{{"{safe_name} (CVSS {node.cvss})"}}}}:::vuln'
                )
            elif node.node_type == NodeType.PRIVILEGE:
                lines.append(f'    {safe_id}(["{safe_name}"]):::priv')
            elif node.node_type == NodeType.ASSET:
                lines.append(f'    {safe_id}[["{safe_name}"]]:::asset')

        # Edges
        for src, edges in self.graph.adjacency.items():
            for edge in edges:
                safe_src = src.replace("-", "_")
                safe_tgt = edge.target_id.replace("-", "_")
                label = f"{edge.probability:.0%}"
                lines.append(f'    {safe_src} -->|"{label}"| {safe_tgt}')

        return "\n".join(lines)

    def render_dot(self, result: Optional[GraphAnalysisResult] = None) -> str:
        """Render the attack graph as DOT (Graphviz) syntax."""
        if not self.graph:
            return ""

        lines = [
            "digraph attack_graph {",
            "    rankdir=LR;",
            '    node [fontname="Helvetica", fontsize=10];',
            '    edge [fontname="Helvetica", fontsize=8];',
        ]

        # Node styles
        type_styles = {
            NodeType.ENTRY_POINT: 'shape=diamond,style=filled,fillcolor="#2196F3",fontcolor=white',
            NodeType.VULNERABILITY: 'shape=hexagon,style=filled,fillcolor="#f44336",fontcolor=white',
            NodeType.PRIVILEGE: 'shape=ellipse,style=filled,fillcolor="#FF9800"',
            NodeType.ASSET: 'shape=box,style=filled,fillcolor="#4CAF50",fontcolor=white',
            NodeType.SERVICE: 'shape=box,style=filled,fillcolor="#9C27B0",fontcolor=white',
            NodeType.CREDENTIAL: 'shape=note,style=filled,fillcolor="#795548",fontcolor=white',
        }

        for nid, node in self.graph.nodes.items():
            safe_id = nid.replace("-", "_")
            label = node.name.replace('"', '\\"')[:40]
            if node.cvss > 0:
                label += f"\\nCVSS: {node.cvss}"
            style = type_styles.get(node.node_type, "")
            lines.append(f'    {safe_id} [label="{label}",{style}];')

        for src, edges in self.graph.adjacency.items():
            for edge in edges:
                safe_src = src.replace("-", "_")
                safe_tgt = edge.target_id.replace("-", "_")
                label = f"{edge.probability:.0%}"
                color = (
                    "#c62828"
                    if edge.probability > 0.7
                    else "#FF9800" if edge.probability > 0.4 else "#757575"
                )
                lines.append(
                    f'    {safe_src} -> {safe_tgt} [label="{label}",color="{color}",penwidth=2];'
                )

        lines.append("}")
        return "\n".join(lines)

    def generate_report(self, result: GraphAnalysisResult) -> str:
        """Generate a comprehensive attack graph analysis report."""
        lines: List[str] = [
            "# 🕸️ SIREN Attack Graph Analysis Report",
            "",
            f"**Risk Score: {result.risk_score:.1f}/100**",
            f"**Analysis Time: {result.generation_time:.3f}s**",
            f"**Nodes: {len(result.nodes)} | Edges: {len(result.edges)} | "
            f"Chains: {len(result.chains)}**",
            "",
        ]

        # Critical chains
        critical = result.critical_chains
        if critical:
            lines.append(f"## ⚠️ CATASTROPHIC Attack Chains ({len(critical)})")
            lines.append("")
            for i, chain in enumerate(critical[:10], 1):
                lines.append(f"### Chain {i}: {chain.description}")
                lines.append(f"- **Probability:** {chain.total_probability:.1%}")
                lines.append(f"- **Impact:** {chain.total_impact:.1%}")
                lines.append(f"- **Blast Radius:** {chain.blast_radius:.1f}")
                lines.append(f"- **Steps:** {len(chain.nodes)}")
                lines.append("")

        # Lynchpins
        if result.lynchpins:
            lines.append(f"## 🔑 Lynchpin Vulnerabilities (Fix These First)")
            lines.append("")
            lines.append(
                "| # | Vulnerability | Betweenness | Chains Broken | Risk Reduction |"
            )
            lines.append(
                "|---|---------------|-------------|---------------|----------------|"
            )
            for i, lp in enumerate(result.top_lynchpins, 1):
                lines.append(
                    f"| {i} | {lp.vuln_name} | {lp.betweenness_centrality:.4f} | "
                    f"{lp.chains_broken} | {lp.risk_reduction:.1f}% |"
                )
            lines.append("")

        # Blast radii
        if result.blast_radii:
            lines.append(f"## 💥 Blast Radius Analysis")
            lines.append("")
            for br in result.blast_radii[:10]:
                lines.append(
                    f"- **{br.vuln_name}**: Score {br.blast_score:.1f}/100, "
                    f"reaches {len(br.transitively_reachable)} nodes, "
                    f"{len(br.affected_assets)} assets"
                )
            lines.append("")

        # All chains summary
        lines.append("## 📊 Chain Distribution")
        lines.append("")
        tier_counts: Dict[str, int] = defaultdict(int)
        for chain in result.chains:
            tier_counts[chain.risk_tier.value] += 1
        for tier in RiskTier:
            count = tier_counts.get(tier.value, 0)
            if count:
                lines.append(f"- **{tier.value.upper()}**: {count} chains")

        return "\n".join(lines)
