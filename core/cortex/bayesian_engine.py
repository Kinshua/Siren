#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  🧠  SIREN BAYESIAN ENGINE — Motor de Dedução Cognitiva  🧠                  ██
██                                                                                ██
██  Motor de inferência probabilística Bayesiana NATIVO que não depende de LLMs.  ██
██  Roda offline, no celular, num Raspberry Pi.                                   ██
██                                                                                ██
██  Capacidades:                                                                  ██
██    • Rede Bayesiana com propagação de crenças (belief propagation)             ██
██    • Atualização posterior em tempo real com novas evidências                  ██
██    • Priors calibrados com CWE/CVE/EPSS/vulnerability patterns                ██
██    • Inferência exata (variable elimination) e aproximada (likelihood weight)  ██
██    • Detecção de correlações entre evidências (mutual information)             ██
██    • Hipótese ranking com explicabilidade                                      ██
██    • Thread-safe para operações concorrentes                                  ██
██    • Serialização/deserialização completa do estado                           ██
██                                                                                ██
██  Referências acadêmicas:                                                       ██
██    • Muñoz-González et al. (2015-2016) — Bayesian Attack Graph Analysis       ██
██    • Perone et al. (IEEE CSR 2025) — Bayesian + CVSS Temporal                 ██
██    • Pearl (1988) — Probabilistic Reasoning in Intelligent Systems            ██
██                                                                                ██
██  "A SIREN não adivinha. Ela CALCULA a probabilidade de cada cenário."         ██
██                                                                                ██
████████████████████████████████████████████████████████████████████████████████████
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import logging
import math
import threading
import time
from collections import OrderedDict, defaultdict, deque
from concurrent.futures import ThreadPoolExecutor

from core.shannon.constants import EPSILON
from dataclasses import dataclass, field
from enum import Enum, auto
from functools import lru_cache
from pathlib import Path
from typing import (
    Any,
    Callable,
    Deque,
    Dict,
    FrozenSet,
    Iterator,
    List,
    Optional,
    Protocol,
    Set,
    Tuple,
    Union,
)

logger = logging.getLogger("siren.cortex.bayesian")


# ════════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════════════════════════════

LOG_FLOOR = 1e-300  # Minimum value before taking log (avoid -inf)
MAX_ITERATIONS_BP = 200  # Max belief propagation iterations
CONVERGENCE_THRESHOLD = 1e-6  # Belief propagation convergence
DEFAULT_PRIOR = 0.01  # Default vulnerability prior probability
MAX_EVIDENCE_HISTORY = 10_000  # Max evidence records retained
MAX_EXPLICIT_PARENTS = 10  # Max parents for explicit CPT enumeration
MAX_CACHE_SIZE = 2048  # Max inference cache entries (LRU eviction)
THREAD_POOL_SIZE = 4  # Concurrent inference threads


# ════════════════════════════════════════════════════════════════════════════════
# ENUMS
# ════════════════════════════════════════════════════════════════════════════════


class NodeCategory(Enum):
    """Categories of nodes in the Bayesian network."""
    VULNERABILITY = "vulnerability"
    OBSERVABLE = "observable"
    CONFIGURATION = "configuration"
    SERVICE = "service"
    BEHAVIOR = "behavior"
    COMPOUND = "compound"  # Combines multiple evidences


class EvidenceType(Enum):
    """Types of evidence that can be observed."""
    PORT_OPEN = "port_open"
    SERVICE_VERSION = "service_version"
    HEADER_PRESENT = "header_present"
    HEADER_MISSING = "header_missing"
    RESPONSE_PATTERN = "response_pattern"
    ERROR_MESSAGE = "error_message"
    DIRECTORY_LISTING = "directory_listing"
    DEFAULT_PAGE = "default_page"
    TECHNOLOGY_DETECTED = "technology_detected"
    BEHAVIOR_ANOMALY = "behavior_anomaly"
    TIMING_ANOMALY = "timing_anomaly"
    STATUS_CODE = "status_code"
    CONTENT_TYPE = "content_type"
    REDIRECT_CHAIN = "redirect_chain"
    CERTIFICATE_INFO = "certificate_info"
    DNS_RECORD = "dns_record"
    CORS_MISCONFIGURATION = "cors_misconfiguration"
    COOKIE_FLAG_MISSING = "cookie_flag_missing"
    INPUT_REFLECTION = "input_reflection"
    WAF_DETECTED = "waf_detected"
    CDN_DETECTED = "cdn_detected"
    API_SCHEMA_EXPOSED = "api_schema_exposed"
    DEBUG_ENDPOINT = "debug_endpoint"
    STACK_TRACE_LEAKED = "stack_trace_leaked"
    VERSION_HEADER = "version_header"
    CUSTOM = "custom"


class InferenceMethod(Enum):
    """Available inference algorithms."""
    VARIABLE_ELIMINATION = "variable_elimination"
    BELIEF_PROPAGATION = "belief_propagation"
    LIKELIHOOD_WEIGHTING = "likelihood_weighting"
    GIBBS_SAMPLING = "gibbs_sampling"


class HypothesisStatus(Enum):
    """Status of a vulnerability hypothesis."""
    ACTIVE = "active"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    INSUFFICIENT_DATA = "insufficient_data"


# ════════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ════════════════════════════════════════════════════════════════════════════════


@dataclass
class ConditionalProbability:
    """A conditional probability entry: P(child_state | parent_states)."""
    child_state: bool
    parent_states: Dict[str, bool]
    probability: float

    def matches(self, observed: Dict[str, bool]) -> bool:
        """Check if observed parent states match this CPT entry."""
        return all(
            observed.get(parent) == state
            for parent, state in self.parent_states.items()
        )


@dataclass
class CPT:
    """Conditional Probability Table for a Bayesian node."""
    node_id: str
    parents: List[str]
    entries: List[ConditionalProbability] = field(default_factory=list)
    _noisy_or_params: Optional[Dict[str, Any]] = field(default=None, repr=False)

    def get_probability(self, child_state: bool, parent_values: Dict[str, bool]) -> float:
        """Look up P(child=state | parents=values).

        For nodes with parametric Noisy-OR (>MAX_EXPLICIT_PARENTS parents),
        computes on-the-fly: P(child=1|parents) = 1 - (1-leak) * ∏(1 - w_i)
        for each active parent i.
        """
        # Parametric Noisy-OR path (avoids 2^n table)
        if self._noisy_or_params is not None:
            leak = self._noisy_or_params["leak"]
            weights = self._noisy_or_params["weights"]
            prob_not = 1.0 - leak
            for pid, is_true in parent_values.items():
                if is_true:
                    prob_not *= (1.0 - weights.get(pid, 0.5))
            prob_true = max(EPSILON, min(1.0 - EPSILON, 1.0 - prob_not))
            return prob_true if child_state else (1.0 - prob_true)

        for entry in self.entries:
            if entry.child_state == child_state and entry.matches(parent_values):
                return entry.probability
        # Default: use prior or complement
        return DEFAULT_PRIOR if child_state else (1.0 - DEFAULT_PRIOR)

    def add_entry(self, child_state: bool, parent_states: Dict[str, bool], prob: float) -> None:
        self.entries.append(ConditionalProbability(child_state, parent_states, prob))

    @classmethod
    def from_prior(cls, node_id: str, prior: float) -> "CPT":
        """Create a CPT for a root node (no parents) with a simple prior."""
        cpt = cls(node_id=node_id, parents=[])
        cpt.add_entry(True, {}, prior)
        cpt.add_entry(False, {}, 1.0 - prior)
        return cpt

    @classmethod
    def from_likelihood(
        cls, node_id: str, parent_id: str,
        true_positive: float, false_positive: float
    ) -> "CPT":
        """Create CPT for a binary evidence node given one parent.

        P(evidence=True  | vuln=True)  = true_positive
        P(evidence=True  | vuln=False) = false_positive
        P(evidence=False | vuln=True)  = 1 - true_positive
        P(evidence=False | vuln=False) = 1 - false_positive
        """
        cpt = cls(node_id=node_id, parents=[parent_id])
        cpt.add_entry(True, {parent_id: True}, true_positive)
        cpt.add_entry(True, {parent_id: False}, false_positive)
        cpt.add_entry(False, {parent_id: True}, 1.0 - true_positive)
        cpt.add_entry(False, {parent_id: False}, 1.0 - false_positive)
        return cpt

    @classmethod
    def from_noisy_or(cls, node_id: str, parent_ids: List[str],
                       individual_probs: Dict[str, float],
                       leak_prob: float = 0.01) -> "CPT":
        """Create CPT using Noisy-OR model for multiple parents.

        Efficient for nodes with many parents. Each parent independently
        has a probability of activating the child. The 'leak' probability
        accounts for unknown causes.
        """
        cpt = cls(node_id=node_id, parents=parent_ids)
        n = len(parent_ids)

        if n > MAX_EXPLICIT_PARENTS:
            # Parametric Noisy-OR: avoid 2^n enumeration.
            # Store coupling strengths and leak for on-the-fly computation.
            # P(child=1|parents) = 1 - (1 - leak) * prod_{i: parent_i=1}(1 - w_i)
            # where w_i = individual_probs[parent_i]
            logger.warning(
                "Node '%s' has %d parents (> %d). Using parametric Noisy-OR "
                "approximation instead of explicit CPT enumeration.",
                node_id, n, MAX_EXPLICIT_PARENTS,
            )
            cpt._noisy_or_params = {
                "leak": leak_prob,
                "weights": {pid: individual_probs.get(pid, 0.5) for pid in parent_ids},
            }
            return cpt

        # Explicit enumeration for ≤ MAX_EXPLICIT_PARENTS parents
        for combo_int in range(2 ** n):
            parent_states: Dict[str, bool] = {}
            for i, pid in enumerate(parent_ids):
                parent_states[pid] = bool((combo_int >> i) & 1)

            # Noisy-OR: P(child=False) = (1-leak) * product_active_parents(1-p_i)
            prob_not = 1.0 - leak_prob
            for pid, is_true in parent_states.items():
                if is_true:
                    prob_not *= (1.0 - individual_probs.get(pid, 0.5))

            prob_true = 1.0 - prob_not
            cpt.add_entry(True, parent_states, max(EPSILON, min(1.0 - EPSILON, prob_true)))
            cpt.add_entry(False, parent_states, max(EPSILON, min(1.0 - EPSILON, 1.0 - prob_true)))

        return cpt

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "parents": self.parents,
            "entries": [
                {"child": e.child_state, "parents": e.parent_states, "prob": e.probability}
                for e in self.entries
            ],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CPT":
        cpt = cls(node_id=data["node_id"], parents=data["parents"])
        for e in data.get("entries", []):
            cpt.add_entry(e["child"], e["parents"], e["prob"])
        return cpt


@dataclass
class BayesianNode:
    """A node in the Bayesian Network."""
    node_id: str
    category: NodeCategory
    label: str = ""
    description: str = ""
    cpt: Optional[CPT] = None
    parents: List[str] = field(default_factory=list)
    children: List[str] = field(default_factory=list)

    # Current belief state
    belief_true: float = DEFAULT_PRIOR
    belief_false: float = 1.0 - DEFAULT_PRIOR

    # Evidence (if observed)
    observed: Optional[bool] = None
    observation_confidence: float = 1.0

    # Metadata
    cve_ids: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    epss_score: Optional[float] = None
    tags: Set[str] = field(default_factory=set)

    @property
    def is_observed(self) -> bool:
        return self.observed is not None

    @property
    def is_root(self) -> bool:
        return len(self.parents) == 0

    @property
    def is_leaf(self) -> bool:
        return len(self.children) == 0

    @property
    def posterior(self) -> float:
        """Current posterior probability P(node=True | evidence)."""
        if self.is_observed:
            if self.observed:
                return self.observation_confidence
            return 1.0 - self.observation_confidence
        return self.belief_true

    def set_evidence(self, value: bool, confidence: float = 1.0) -> None:
        """Set this node as observed with given value and confidence."""
        self.observed = value
        self.observation_confidence = max(EPSILON, min(1.0 - EPSILON, confidence))
        if value:
            self.belief_true = self.observation_confidence
            self.belief_false = 1.0 - self.observation_confidence
        else:
            self.belief_true = 1.0 - self.observation_confidence
            self.belief_false = self.observation_confidence

    def clear_evidence(self) -> None:
        """Remove observation, revert to prior beliefs."""
        self.observed = None
        self.observation_confidence = 1.0
        if self.cpt and not self.cpt.parents:
            # Root node: revert to prior
            for entry in self.cpt.entries:
                if entry.child_state and not entry.parent_states:
                    self.belief_true = entry.probability
                    self.belief_false = 1.0 - entry.probability
                    return

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "category": self.category.value,
            "label": self.label,
            "description": self.description,
            "cpt": self.cpt.to_dict() if self.cpt else None,
            "parents": self.parents,
            "children": self.children,
            "belief_true": self.belief_true,
            "observed": self.observed,
            "observation_confidence": self.observation_confidence,
            "cve_ids": self.cve_ids,
            "cwe_ids": self.cwe_ids,
            "cvss_score": self.cvss_score,
            "epss_score": self.epss_score,
            "tags": list(self.tags),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BayesianNode":
        node = cls(
            node_id=data["node_id"],
            category=NodeCategory(data["category"]),
            label=data.get("label", ""),
            description=data.get("description", ""),
            parents=data.get("parents", []),
            children=data.get("children", []),
            belief_true=data.get("belief_true", DEFAULT_PRIOR),
            cve_ids=data.get("cve_ids", []),
            cwe_ids=data.get("cwe_ids", []),
            cvss_score=data.get("cvss_score"),
            epss_score=data.get("epss_score"),
            tags=set(data.get("tags", [])),
        )
        node.belief_false = 1.0 - node.belief_true
        node.observed = data.get("observed")
        node.observation_confidence = data.get("observation_confidence", 1.0)
        if data.get("cpt"):
            node.cpt = CPT.from_dict(data["cpt"])
        return node


@dataclass
class Evidence:
    """An observed piece of evidence from scanning."""
    evidence_id: str
    evidence_type: EvidenceType
    value: Any
    confidence: float = 0.95
    source: str = ""  # Which scanner/module produced this
    timestamp: float = field(default_factory=time.time)
    raw_data: Optional[Dict[str, Any]] = None

    @property
    def is_positive(self) -> bool:
        """Whether this evidence indicates presence (True) or absence (False)."""
        if isinstance(self.value, bool):
            return self.value
        if isinstance(self.value, str):
            return bool(self.value)
        return self.value is not None

    def fingerprint(self) -> str:
        """Unique hash for deduplication."""
        content = f"{self.evidence_type.value}:{self.value}:{self.source}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]


@dataclass
class Hypothesis:
    """A vulnerability hypothesis with supporting/contradicting evidence."""
    hypothesis_id: str
    label: str
    description: str = ""
    prior: float = DEFAULT_PRIOR
    posterior: float = DEFAULT_PRIOR
    status: HypothesisStatus = HypothesisStatus.ACTIVE

    supporting_evidence: List[str] = field(default_factory=list)
    contradicting_evidence: List[str] = field(default_factory=list)
    node_id: Optional[str] = None  # Link to BayesianNode

    # Metadata
    cve_ids: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    cvss_base: Optional[float] = None
    mitre_techniques: List[str] = field(default_factory=list)
    confidence_interval: Tuple[float, float] = (0.0, 1.0)

    # Explanation
    explanation_chain: List[str] = field(default_factory=list)

    @property
    def evidence_ratio(self) -> float:
        """Ratio of supporting to total evidence."""
        total = len(self.supporting_evidence) + len(self.contradicting_evidence)
        if total == 0:
            return 0.5
        return len(self.supporting_evidence) / total

    @property
    def risk_score(self) -> float:
        """Combined risk: posterior * CVSS (normalized)."""
        cvss = self.cvss_base if self.cvss_base else 5.0
        return self.posterior * (cvss / 10.0)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "label": self.label,
            "description": self.description,
            "prior": self.prior,
            "posterior": self.posterior,
            "status": self.status.value,
            "supporting_evidence": self.supporting_evidence,
            "contradicting_evidence": self.contradicting_evidence,
            "node_id": self.node_id,
            "cve_ids": self.cve_ids,
            "cwe_ids": self.cwe_ids,
            "cvss_base": self.cvss_base,
            "mitre_techniques": self.mitre_techniques,
            "confidence_interval": list(self.confidence_interval),
            "explanation_chain": self.explanation_chain,
            "risk_score": self.risk_score,
        }


@dataclass
class InferenceResult:
    """Result of a Bayesian inference operation."""
    method: InferenceMethod
    posteriors: Dict[str, float]  # node_id → P(True | evidence)
    iterations: int = 0
    converged: bool = True
    duration_ms: float = 0.0
    evidence_used: int = 0
    max_change: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def top_n(self, n: int = 10, category: Optional[NodeCategory] = None) -> List[Tuple[str, float]]:
        """Return top N highest posterior nodes."""
        items = list(self.posteriors.items())
        items.sort(key=lambda x: x[1], reverse=True)
        return items[:n]


# ════════════════════════════════════════════════════════════════════════════════
# BAYESIAN NETWORK — Core Graph Structure
# ════════════════════════════════════════════════════════════════════════════════


class BayesianNetwork:
    """Directed Acyclic Graph for probabilistic inference.

    Thread-safe implementation supporting:
    - Exact inference via variable elimination
    - Approximate inference via belief propagation (loopy BP)
    - Likelihood weighting for complex networks
    - Evidence integration with confidence scores
    - Incremental updates without full re-computation

    Architecture follows Pearl's Bayesian Network formalism with
    extensions for security-specific modeling (CVE priors, EPSS
    integration, attack graph correlation).
    """

    def __init__(self) -> None:
        self._nodes: Dict[str, BayesianNode] = {}
        self._lock = threading.RLock()
        self._evidence_log: Deque[Evidence] = deque(maxlen=MAX_EVIDENCE_HISTORY)
        self._inference_cache: OrderedDict[str, InferenceResult] = OrderedDict()
        self._dirty = True  # Need re-inference

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return sum(len(n.children) for n in self._nodes.values())

    @property
    def observed_count(self) -> int:
        return sum(1 for n in self._nodes.values() if n.is_observed)

    def add_node(self, node: BayesianNode) -> None:
        """Add a node to the network."""
        with self._lock:
            self._nodes[node.node_id] = node
            self._dirty = True

    def remove_node(self, node_id: str) -> None:
        """Remove a node and all its edges."""
        with self._lock:
            if node_id not in self._nodes:
                return
            node = self._nodes[node_id]
            # Remove from parents' children lists
            for p_id in node.parents:
                if p_id in self._nodes:
                    parent = self._nodes[p_id]
                    if node_id in parent.children:
                        parent.children.remove(node_id)
            # Remove from children's parent lists
            for c_id in node.children:
                if c_id in self._nodes:
                    child = self._nodes[c_id]
                    if node_id in child.parents:
                        child.parents.remove(node_id)
            del self._nodes[node_id]
            self._dirty = True

    def add_edge(self, parent_id: str, child_id: str) -> None:
        """Add a directed edge parent → child."""
        with self._lock:
            if parent_id not in self._nodes or child_id not in self._nodes:
                raise ValueError(f"Both nodes must exist: {parent_id} → {child_id}")
            parent = self._nodes[parent_id]
            child = self._nodes[child_id]
            if child_id not in parent.children:
                parent.children.append(child_id)
            if parent_id not in child.parents:
                child.parents.append(parent_id)
            self._dirty = True

    def get_node(self, node_id: str) -> Optional[BayesianNode]:
        return self._nodes.get(node_id)

    def get_nodes_by_category(self, category: NodeCategory) -> List[BayesianNode]:
        return [n for n in self._nodes.values() if n.category == category]

    def get_vulnerability_nodes(self) -> List[BayesianNode]:
        return self.get_nodes_by_category(NodeCategory.VULNERABILITY)

    def get_observable_nodes(self) -> List[BayesianNode]:
        return self.get_nodes_by_category(NodeCategory.OBSERVABLE)

    def set_evidence(self, node_id: str, value: bool, confidence: float = 1.0) -> None:
        """Set observed evidence on a node."""
        with self._lock:
            node = self._nodes.get(node_id)
            if node:
                node.set_evidence(value, confidence)
                self._dirty = True

    def clear_evidence(self, node_id: str) -> None:
        """Remove evidence from a node."""
        with self._lock:
            node = self._nodes.get(node_id)
            if node:
                node.clear_evidence()
                self._dirty = True

    def clear_all_evidence(self) -> None:
        """Reset all observations."""
        with self._lock:
            for node in self._nodes.values():
                node.clear_evidence()
            self._dirty = True

    # ── Topology Checks ────────────────────────────────────────────────

    def is_dag(self) -> bool:
        """Verify the network is a DAG (no cycles) via Kahn's algorithm."""
        in_degree: Dict[str, int] = {nid: 0 for nid in self._nodes}
        for node in self._nodes.values():
            for c_id in node.children:
                in_degree[c_id] = in_degree.get(c_id, 0) + 1

        queue = deque([nid for nid, deg in in_degree.items() if deg == 0])
        visited = 0

        while queue:
            nid = queue.popleft()
            visited += 1
            for c_id in self._nodes[nid].children:
                in_degree[c_id] -= 1
                if in_degree[c_id] == 0:
                    queue.append(c_id)

        return visited == len(self._nodes)

    def topological_order(self) -> List[str]:
        """Return nodes in topological order (parents before children)."""
        in_degree: Dict[str, int] = {nid: len(self._nodes[nid].parents) for nid in self._nodes}
        queue = deque([nid for nid, deg in in_degree.items() if deg == 0])
        order: List[str] = []

        while queue:
            nid = queue.popleft()
            order.append(nid)
            for c_id in self._nodes[nid].children:
                in_degree[c_id] -= 1
                if in_degree[c_id] == 0:
                    queue.append(c_id)

        return order

    def d_separated(self, x: str, y: str, z: Set[str]) -> bool:
        """Check if X and Y are d-separated given Z (Bayes ball algorithm).

        D-separation determines conditional independence:
        X ⊥ Y | Z means X and Y are independent given Z.
        """
        # Bayes Ball: mark reachable nodes from X given Z
        reachable = self._bayes_ball_reachable(x, z)
        return y not in reachable

    def _bayes_ball_reachable(self, start: str, observed: Set[str]) -> Set[str]:
        """Bayes Ball algorithm to find reachable nodes."""
        visited_up: Set[str] = set()
        visited_down: Set[str] = set()
        reachable: Set[str] = set()
        queue: Deque[Tuple[str, str]] = deque()  # (node_id, direction)

        queue.append((start, "up"))

        while queue:
            node_id, direction = queue.popleft()

            if direction == "up" and node_id not in visited_up:
                visited_up.add(node_id)
                if node_id not in observed:
                    reachable.add(node_id)
                    # Pass through to children (downward)
                    for c_id in self._nodes.get(node_id, BayesianNode("", NodeCategory.OBSERVABLE)).children:
                        queue.append((c_id, "down"))
                    # Pass through to parents (upward)
                    for p_id in self._nodes.get(node_id, BayesianNode("", NodeCategory.OBSERVABLE)).parents:
                        queue.append((p_id, "up"))

            elif direction == "down" and node_id not in visited_down:
                visited_down.add(node_id)
                if node_id not in observed:
                    reachable.add(node_id)
                    # Pass to children
                    for c_id in self._nodes.get(node_id, BayesianNode("", NodeCategory.OBSERVABLE)).children:
                        queue.append((c_id, "down"))
                else:
                    # Observed: can pass to parents (explaining away)
                    for p_id in self._nodes.get(node_id, BayesianNode("", NodeCategory.OBSERVABLE)).parents:
                        queue.append((p_id, "up"))

        return reachable

    # ── Inference Algorithms ───────────────────────────────────────────

    def infer(self, method: InferenceMethod = InferenceMethod.BELIEF_PROPAGATION,
              query_nodes: Optional[List[str]] = None) -> InferenceResult:
        """Run inference and compute posterior probabilities.

        Args:
            method: Which inference algorithm to use.
            query_nodes: Specific nodes to compute posteriors for.
                        If None, computes for ALL vulnerability nodes.

        Returns:
            InferenceResult with posteriors for queried nodes.
        """
        start = time.perf_counter()

        if method == InferenceMethod.BELIEF_PROPAGATION:
            result = self._belief_propagation(query_nodes)
        elif method == InferenceMethod.VARIABLE_ELIMINATION:
            result = self._variable_elimination(query_nodes)
        elif method == InferenceMethod.LIKELIHOOD_WEIGHTING:
            result = self._likelihood_weighting(query_nodes)
        else:
            result = self._belief_propagation(query_nodes)

        result.duration_ms = (time.perf_counter() - start) * 1000
        result.evidence_used = self.observed_count

        with self._lock:
            self._dirty = False
            # Update node beliefs from inference
            for node_id, posterior in result.posteriors.items():
                if node_id in self._nodes and not self._nodes[node_id].is_observed:
                    self._nodes[node_id].belief_true = posterior
                    self._nodes[node_id].belief_false = 1.0 - posterior

            cache_key = self._evidence_hash()
            # LRU eviction: move to end if exists, evict oldest if over limit
            if cache_key in self._inference_cache:
                self._inference_cache.move_to_end(cache_key)
            self._inference_cache[cache_key] = result
            while len(self._inference_cache) > MAX_CACHE_SIZE:
                self._inference_cache.popitem(last=False)

        return result

    def _evidence_hash(self) -> str:
        """Hash of current evidence state for caching."""
        evidence_state = sorted(
            (n.node_id, n.observed, n.observation_confidence)
            for n in self._nodes.values() if n.is_observed
        )
        return hashlib.md5(str(evidence_state).encode()).hexdigest()

    def _belief_propagation(self, query_nodes: Optional[List[str]] = None) -> InferenceResult:
        """Loopy Belief Propagation (Pearl's algorithm extended for loopy graphs).

        For tree-structured networks, this gives exact marginals.
        For loopy networks, converges to good approximations.
        """
        # Initialize messages: message[sender][receiver] = (msg_true, msg_false)
        messages: Dict[str, Dict[str, Tuple[float, float]]] = defaultdict(dict)

        for node in self._nodes.values():
            for child_id in node.children:
                messages[node.node_id][child_id] = (0.5, 0.5)
            for parent_id in node.parents:
                messages[node.node_id][parent_id] = (0.5, 0.5)

        max_change = float("inf")
        iteration = 0

        while iteration < MAX_ITERATIONS_BP and max_change > CONVERGENCE_THRESHOLD:
            old_messages = {
                s: {r: (t, f) for r, (t, f) in rdict.items()}
                for s, rdict in messages.items()
            }
            max_change = 0.0

            # Process in topological order for faster convergence
            order = self.topological_order()

            for node_id in order:
                node = self._nodes[node_id]

                if node.is_observed:
                    # Observed node sends certainty
                    val = node.observation_confidence if node.observed else (1.0 - node.observation_confidence)
                    for neighbor_id in node.children + node.parents:
                        messages[node_id][neighbor_id] = (val, 1.0 - val)
                    continue

                # Send messages to children (pi-messages: prior info)
                for child_id in node.children:
                    msg_t, msg_f = self._compute_pi_message(
                        node, child_id, messages
                    )
                    messages[node_id][child_id] = (msg_t, msg_f)

                # Send messages to parents (lambda-messages: likelihood info)
                for parent_id in node.parents:
                    msg_t, msg_f = self._compute_lambda_message(
                        node, parent_id, messages
                    )
                    messages[node_id][parent_id] = (msg_t, msg_f)

            # Check convergence
            for sender in messages:
                for receiver in messages[sender]:
                    if sender in old_messages and receiver in old_messages[sender]:
                        old_t, old_f = old_messages[sender][receiver]
                        new_t, new_f = messages[sender][receiver]
                        change = abs(new_t - old_t) + abs(new_f - old_f)
                        max_change = max(max_change, change)

            iteration += 1

        # Compute posteriors from converged messages
        posteriors: Dict[str, float] = {}
        target_nodes = query_nodes if query_nodes else [
            n.node_id for n in self._nodes.values()
            if n.category == NodeCategory.VULNERABILITY
        ]

        for node_id in target_nodes:
            node = self._nodes.get(node_id)
            if not node:
                continue
            if node.is_observed:
                posteriors[node_id] = node.posterior
                continue

            # Posterior ∝ prior × product(incoming messages)
            prior_t = node.belief_true
            prior_f = node.belief_false

            # If root node with CPT, use CPT prior
            if node.cpt and not node.cpt.parents:
                prior_t = node.cpt.get_probability(True, {})
                prior_f = node.cpt.get_probability(False, {})

            # Log-space computation to avoid underflow with many messages
            log_t = math.log(max(prior_t, LOG_FLOOR))
            log_f = math.log(max(prior_f, LOG_FLOOR))

            for neighbor_id in node.parents + node.children:
                if neighbor_id in messages and node_id in messages[neighbor_id]:
                    mt, mf = messages[neighbor_id][node_id]
                    log_t += math.log(max(mt, LOG_FLOOR))
                    log_f += math.log(max(mf, LOG_FLOOR))

            # Normalize in log-space using log-sum-exp trick
            log_max = max(log_t, log_f)
            if math.isfinite(log_max):
                exp_t = math.exp(log_t - log_max)
                exp_f = math.exp(log_f - log_max)
                total = exp_t + exp_f
                if total > EPSILON:
                    posteriors[node_id] = exp_t / total
                else:
                    posteriors[node_id] = prior_t
            else:
                posteriors[node_id] = prior_t

        return InferenceResult(
            method=InferenceMethod.BELIEF_PROPAGATION,
            posteriors=posteriors,
            iterations=iteration,
            converged=(max_change <= CONVERGENCE_THRESHOLD),
            max_change=max_change,
        )

    def _compute_pi_message(
        self, node: BayesianNode, child_id: str,
        messages: Dict[str, Dict[str, Tuple[float, float]]]
    ) -> Tuple[float, float]:
        """Compute pi-message from parent to child (prior influence)."""
        # Collect incoming messages from all sources EXCEPT the target child
        prod_t = 1.0
        prod_f = 1.0

        # Prior
        if node.cpt and not node.cpt.parents:
            prod_t = node.cpt.get_probability(True, {})
            prod_f = node.cpt.get_probability(False, {})
        else:
            prod_t = node.belief_true
            prod_f = node.belief_false

        # Log-space accumulation to avoid underflow
        log_t = math.log(max(prod_t, LOG_FLOOR))
        log_f = math.log(max(prod_f, LOG_FLOOR))

        for neighbor_id in node.parents + node.children:
            if neighbor_id == child_id:
                continue
            if neighbor_id in messages and node.node_id in messages[neighbor_id]:
                mt, mf = messages[neighbor_id][node.node_id]
                log_t += math.log(max(mt, LOG_FLOOR))
                log_f += math.log(max(mf, LOG_FLOOR))

        # Log-sum-exp normalization
        log_max = max(log_t, log_f)
        if math.isfinite(log_max):
            exp_t = math.exp(log_t - log_max)
            exp_f = math.exp(log_f - log_max)
            total = exp_t + exp_f
            if total > EPSILON:
                return (exp_t / total, exp_f / total)
        return (0.5, 0.5)

    def _compute_lambda_message(
        self, node: BayesianNode, parent_id: str,
        messages: Dict[str, Dict[str, Tuple[float, float]]]
    ) -> Tuple[float, float]:
        """Compute lambda-message from child to parent (likelihood influence)."""
        if not node.cpt:
            return (0.5, 0.5)

        # Marginalize over node's state given parent_id's state
        msg_t = 0.0  # P(evidence | parent=True)
        msg_f = 0.0  # P(evidence | parent=False)

        for parent_val in [True, False]:
            parent_states = {parent_id: parent_val}
            # For other parents, marginalize using their messages
            other_parents = [p for p in node.parents if p != parent_id]

            if not other_parents:
                # Simple case: only one parent
                p_node_true = node.cpt.get_probability(True, parent_states)
                p_node_false = node.cpt.get_probability(False, parent_states)

                # Lambda value from children
                lambda_t = 1.0
                lambda_f = 1.0
                for c_id in node.children:
                    if c_id in messages and node.node_id in messages[c_id]:
                        lt, lf = messages[c_id][node.node_id]
                        lambda_t *= lt
                        lambda_f *= lf

                contribution = p_node_true * lambda_t + p_node_false * lambda_f
            else:
                # Multi-parent: marginalize over other parents' states
                contribution = self._marginalize_other_parents(
                    node, parent_id, parent_val, other_parents, messages
                )

            if parent_val:
                msg_t = contribution
            else:
                msg_f = contribution

        # Normalize with log-space handling for numerical stability
        if msg_t <= 0.0 and msg_f <= 0.0:
            return (0.5, 0.5)
        log_t = math.log(max(msg_t, LOG_FLOOR))
        log_f = math.log(max(msg_f, LOG_FLOOR))
        log_max = max(log_t, log_f)
        if math.isfinite(log_max):
            exp_t = math.exp(log_t - log_max)
            exp_f = math.exp(log_f - log_max)
            total = exp_t + exp_f
            if total > EPSILON:
                return (exp_t / total, exp_f / total)
        return (0.5, 0.5)

    def _marginalize_other_parents(
        self, node: BayesianNode, fixed_parent: str, fixed_val: bool,
        other_parents: List[str],
        messages: Dict[str, Dict[str, Tuple[float, float]]]
    ) -> float:
        """Marginalize CPT over other parents' states using their messages.

        For nodes with > MAX_EXPLICIT_PARENTS other parents (or parametric
        Noisy-OR CPTs), uses expected-value approximation instead of 2^n
        enumeration.
        """
        n = len(other_parents)

        # Noisy-OR approximation for large parent sets
        if n > MAX_EXPLICIT_PARENTS or (node.cpt and node.cpt._noisy_or_params is not None):
            # Compute expected activation: use message means as soft parent states
            # P(child=1|parents) ≈ 1 - (1-leak) * ∏(1 - w_i * E[parent_i])
            if node.cpt and node.cpt._noisy_or_params is not None:
                params = node.cpt._noisy_or_params
                leak = params["leak"]
                weights = params["weights"]
            else:
                leak = 0.01
                weights = {p: 0.5 for p in other_parents}

            prob_not = 1.0 - leak
            # Fixed parent contribution
            if fixed_val:
                prob_not *= (1.0 - weights.get(fixed_parent, 0.5))

            # Other parents: use message-weighted expected contribution
            for p_id in other_parents:
                if p_id in messages and node.node_id in messages[p_id]:
                    mt, mf = messages[p_id][node.node_id]
                    total_m = mt + mf
                    p_active = mt / total_m if total_m > EPSILON else 0.5
                else:
                    p_active = 0.5
                w_i = weights.get(p_id, 0.5)
                prob_not *= (1.0 - w_i * p_active)

            return max(EPSILON, min(1.0 - EPSILON, 1.0 - prob_not))

        # Explicit enumeration for small parent sets
        result = 0.0
        for combo_int in range(2 ** n):
            parent_states = {fixed_parent: fixed_val}
            combo_prob = 1.0

            for i, p_id in enumerate(other_parents):
                val = bool((combo_int >> i) & 1)
                parent_states[p_id] = val
                if p_id in messages and node.node_id in messages[p_id]:
                    mt, mf = messages[p_id][node.node_id]
                    combo_prob *= mt if val else mf
                else:
                    combo_prob *= 0.5

            p_true = node.cpt.get_probability(True, parent_states)
            result += combo_prob * p_true

        return result

    def _variable_elimination(self, query_nodes: Optional[List[str]] = None) -> InferenceResult:
        """Exact inference via variable elimination.

        More expensive than BP but gives exact posteriors.
        Best for small-to-medium networks (< 100 nodes).
        """
        target_nodes = query_nodes or [
            n.node_id for n in self._nodes.values()
            if n.category == NodeCategory.VULNERABILITY
        ]
        observed = {
            n.node_id: n.observed
            for n in self._nodes.values() if n.is_observed
        }

        posteriors: Dict[str, float] = {}

        for query_id in target_nodes:
            if query_id in observed:
                posteriors[query_id] = (
                    self._nodes[query_id].observation_confidence
                    if observed[query_id]
                    else 1.0 - self._nodes[query_id].observation_confidence
                )
                continue

            # Compute P(query=True | evidence)
            # Enumerate over Markov blanket for efficiency
            blanket = self._markov_blanket(query_id)
            elimination_order = [
                nid for nid in self.topological_order()
                if nid != query_id and nid not in observed and nid in blanket
            ]

            p_true = self._ve_enumerate(query_id, True, observed, elimination_order)
            p_false = self._ve_enumerate(query_id, False, observed, elimination_order)

            total = p_true + p_false
            if total > EPSILON:
                posteriors[query_id] = p_true / total
            else:
                posteriors[query_id] = self._nodes[query_id].belief_true

        return InferenceResult(
            method=InferenceMethod.VARIABLE_ELIMINATION,
            posteriors=posteriors,
            iterations=1,
            converged=True,
        )

    def _ve_enumerate(self, query_id: str, query_val: bool,
                       observed: Dict[str, bool],
                       elim_order: List[str]) -> float:
        """Recursive enumeration for variable elimination."""
        assignment = dict(observed)
        assignment[query_id] = query_val
        return self._ve_recursive(assignment, list(elim_order))

    def _ve_recursive(self, assignment: Dict[str, bool],
                       remaining: List[str]) -> float:
        """Recursively enumerate and sum out variables."""
        if not remaining:
            return self._joint_probability(assignment)

        var = remaining[0]
        rest = remaining[1:]

        prob = 0.0
        for val in [True, False]:
            assignment[var] = val
            prob += self._ve_recursive(assignment, rest)
            del assignment[var]

        return prob

    def _joint_probability(self, assignment: Dict[str, bool]) -> float:
        """Compute joint probability of a (partial) assignment."""
        prob = 1.0

        for node_id, node in self._nodes.items():
            if node_id not in assignment:
                continue

            val = assignment[node_id]
            if node.cpt:
                parent_vals = {
                    p: assignment[p] for p in node.parents if p in assignment
                }
                if len(parent_vals) == len(node.parents):
                    p = node.cpt.get_probability(val, parent_vals)
                    prob *= p
            elif node.is_root:
                prob *= node.belief_true if val else node.belief_false

        return prob

    def _markov_blanket(self, node_id: str) -> Set[str]:
        """Compute Markov blanket: parents + children + co-parents."""
        blanket: Set[str] = set()
        node = self._nodes.get(node_id)
        if not node:
            return blanket

        blanket.update(node.parents)
        blanket.update(node.children)
        for c_id in node.children:
            child = self._nodes.get(c_id)
            if child:
                blanket.update(child.parents)

        blanket.discard(node_id)
        return blanket

    def _likelihood_weighting(self, query_nodes: Optional[List[str]] = None,
                               num_samples: int = 5000) -> InferenceResult:
        """Approximate inference via likelihood weighting (importance sampling).

        Faster than VE for large networks. Sampling-based.
        """
        import random as rng

        target_nodes = query_nodes or [
            n.node_id for n in self._nodes.values()
            if n.category == NodeCategory.VULNERABILITY
        ]
        observed = {
            n.node_id: n.observed
            for n in self._nodes.values() if n.is_observed
        }

        counts_true: Dict[str, float] = defaultdict(float)
        counts_total: Dict[str, float] = defaultdict(float)
        topo = self.topological_order()

        for _ in range(num_samples):
            sample: Dict[str, bool] = {}
            weight = 1.0

            for nid in topo:
                node = self._nodes[nid]

                if nid in observed:
                    # Observed: fix value, adjust weight
                    sample[nid] = observed[nid]
                    parent_vals = {p: sample[p] for p in node.parents if p in sample}
                    if node.cpt:
                        w = node.cpt.get_probability(observed[nid], parent_vals)
                    elif node.is_root:
                        w = node.belief_true if observed[nid] else node.belief_false
                    else:
                        w = 0.5
                    weight *= max(w, EPSILON)
                else:
                    # Unobserved: sample from conditional
                    parent_vals = {p: sample[p] for p in node.parents if p in sample}
                    if node.cpt:
                        p_true = node.cpt.get_probability(True, parent_vals)
                    elif node.is_root:
                        p_true = node.belief_true
                    else:
                        p_true = 0.5
                    sample[nid] = rng.random() < p_true

            for nid in target_nodes:
                if nid in sample:
                    counts_total[nid] += weight
                    if sample[nid]:
                        counts_true[nid] += weight

        posteriors: Dict[str, float] = {}
        for nid in target_nodes:
            total = counts_total.get(nid, 0.0)
            if total > EPSILON:
                posteriors[nid] = counts_true.get(nid, 0.0) / total
            else:
                posteriors[nid] = self._nodes[nid].belief_true if nid in self._nodes else DEFAULT_PRIOR

        return InferenceResult(
            method=InferenceMethod.LIKELIHOOD_WEIGHTING,
            posteriors=posteriors,
            iterations=num_samples,
            converged=True,
        )

    # ── Mutual Information & Sensitivity ───────────────────────────────

    def mutual_information(self, node_a: str, node_b: str) -> float:
        """Compute mutual information I(A;B) between two nodes.

        I(A;B) = sum P(a,b) * log(P(a,b) / (P(a)*P(b)))

        High MI means the nodes are strongly dependent.
        Useful for finding which evidence most reduces uncertainty.
        """
        a_node = self._nodes.get(node_a)
        b_node = self._nodes.get(node_b)
        if not a_node or not b_node:
            return 0.0

        # Get marginals from current beliefs
        p_a = a_node.posterior
        p_b = b_node.posterior

        # Estimate joint by temporary evidence setting
        mi = 0.0
        for a_val in [True, False]:
            for b_val in [True, False]:
                p_a_v = p_a if a_val else (1.0 - p_a)
                p_b_v = p_b if b_val else (1.0 - p_b)
                p_marginal = p_a_v * p_b_v

                # Better joint estimate: condition on one, observe effect
                p_joint = p_marginal  # Approximation for speed
                if node_a in {p for p in b_node.parents}:
                    # Direct parent: use CPT
                    if b_node.cpt:
                        p_b_given_a = b_node.cpt.get_probability(b_val, {node_a: a_val})
                        p_joint = p_a_v * p_b_given_a

                if p_joint > EPSILON and p_marginal > EPSILON:
                    mi += p_joint * math.log2(p_joint / p_marginal)

        return max(0.0, mi)

    def most_informative_evidence(self, unobserved_ids: Optional[List[str]] = None,
                                    top_n: int = 5) -> List[Tuple[str, float]]:
        """Find which unobserved nodes, if observed, would most reduce entropy.

        Uses expected information gain (entropy reduction).
        Critical for guided scanning: "what should I test NEXT?"
        """
        candidates = unobserved_ids or [
            n.node_id for n in self._nodes.values()
            if not n.is_observed and n.category == NodeCategory.OBSERVABLE
        ]

        vuln_nodes = [n.node_id for n in self.get_vulnerability_nodes()]
        gains: List[Tuple[str, float]] = []

        for candidate_id in candidates:
            # Current entropy of vulnerability posteriors
            current_entropy = sum(
                self._binary_entropy(self._nodes[vid].posterior)
                for vid in vuln_nodes if vid in self._nodes
            )

            # Expected entropy if we observe candidate=True
            expected_entropy = 0.0
            node = self._nodes[candidate_id]
            p_obs = node.belief_true

            for obs_val in [True, False]:
                p_val = p_obs if obs_val else (1.0 - p_obs)
                if p_val < EPSILON:
                    continue

                # Temporarily set evidence and run inference
                old_obs = node.observed
                old_conf = node.observation_confidence
                node.set_evidence(obs_val, 0.95)

                result = self._belief_propagation(vuln_nodes)

                entropy_given = sum(
                    self._binary_entropy(result.posteriors.get(vid, 0.5))
                    for vid in vuln_nodes
                )
                expected_entropy += p_val * entropy_given

                # Restore
                node.observed = old_obs
                node.observation_confidence = old_conf
                if old_obs is None:
                    node.clear_evidence()

            info_gain = current_entropy - expected_entropy
            gains.append((candidate_id, info_gain))

        gains.sort(key=lambda x: x[1], reverse=True)
        return gains[:top_n]

    @staticmethod
    def _binary_entropy(p: float) -> float:
        """H(X) = -p*log2(p) - (1-p)*log2(1-p)"""
        if p <= EPSILON or p >= 1.0 - EPSILON:
            return 0.0
        return -p * math.log2(p) - (1.0 - p) * math.log2(1.0 - p)

    # ── Serialization ──────────────────────────────────────────────────

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": {nid: n.to_dict() for nid, n in self._nodes.items()},
            "metadata": {
                "node_count": self.node_count,
                "edge_count": self.edge_count,
                "observed_count": self.observed_count,
            },
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BayesianNetwork":
        net = cls()
        for nid, ndata in data.get("nodes", {}).items():
            net.add_node(BayesianNode.from_dict(ndata))
        return net

    def save(self, path: Union[str, Path]) -> None:
        """Persist network to JSON."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)

    @classmethod
    def load(cls, path: Union[str, Path]) -> "BayesianNetwork":
        """Load network from JSON."""
        with open(path, "r", encoding="utf-8") as f:
            return cls.from_dict(json.load(f))


# ════════════════════════════════════════════════════════════════════════════════
# BELIEF STATE — Current beliefs about a target
# ════════════════════════════════════════════════════════════════════════════════


class BeliefState:
    """Manages the current set of beliefs about a target system.

    Tracks all evidence gathered, hypotheses formed, and their
    posterior probabilities. Acts as the "working memory" of SIREN's
    cognitive reasoning.
    """

    def __init__(self, target_id: str = "") -> None:
        self.target_id = target_id
        self.network = BayesianNetwork()
        self.hypotheses: Dict[str, Hypothesis] = {}
        self.evidence_log: List[Evidence] = []
        self._evidence_index: Dict[str, Evidence] = {}  # fingerprint → Evidence
        self.created_at = time.time()
        self.updated_at = time.time()
        self._lock = threading.RLock()

    def add_hypothesis(self, hypothesis: Hypothesis) -> None:
        """Register a new vulnerability hypothesis."""
        with self._lock:
            self.hypotheses[hypothesis.hypothesis_id] = hypothesis

            # Create corresponding Bayesian node if not exists
            if hypothesis.node_id and not self.network.get_node(hypothesis.node_id):
                node = BayesianNode(
                    node_id=hypothesis.node_id,
                    category=NodeCategory.VULNERABILITY,
                    label=hypothesis.label,
                    description=hypothesis.description,
                    cve_ids=hypothesis.cve_ids,
                    cwe_ids=hypothesis.cwe_ids,
                    cvss_score=hypothesis.cvss_base,
                )
                prior = hypothesis.prior
                node.cpt = CPT.from_prior(hypothesis.node_id, prior)
                node.belief_true = prior
                node.belief_false = 1.0 - prior
                self.network.add_node(node)

            self.updated_at = time.time()

    def add_evidence(self, evidence: Evidence) -> Dict[str, float]:
        """Add new evidence and update all posteriors.

        Returns:
            Dict of hypothesis_id → new posterior probability
        """
        with self._lock:
            fp = evidence.fingerprint()
            if fp in self._evidence_index:
                return {h.hypothesis_id: h.posterior for h in self.hypotheses.values()}

            self._evidence_index[fp] = evidence
            self.evidence_log.append(evidence)

            # Map evidence to network node and set observation
            ev_node_id = f"ev_{fp}"
            if not self.network.get_node(ev_node_id):
                ev_node = BayesianNode(
                    node_id=ev_node_id,
                    category=NodeCategory.OBSERVABLE,
                    label=f"Evidence: {evidence.evidence_type.value}",
                )
                self.network.add_node(ev_node)

            self.network.set_evidence(ev_node_id, evidence.is_positive, evidence.confidence)

            # Run inference
            vuln_nodes = [h.node_id for h in self.hypotheses.values() if h.node_id]
            if vuln_nodes:
                result = self.network.infer(query_nodes=vuln_nodes)

                # Update hypothesis posteriors
                for hyp in self.hypotheses.values():
                    if hyp.node_id and hyp.node_id in result.posteriors:
                        old_posterior = hyp.posterior
                        hyp.posterior = result.posteriors[hyp.node_id]

                        # Track supporting/contradicting
                        if hyp.posterior > old_posterior:
                            hyp.supporting_evidence.append(fp)
                        elif hyp.posterior < old_posterior:
                            hyp.contradicting_evidence.append(fp)

                        # Build explanation
                        delta = hyp.posterior - old_posterior
                        if abs(delta) > 0.01:
                            direction = "↑" if delta > 0 else "↓"
                            hyp.explanation_chain.append(
                                f"{direction} {abs(delta):.3f} from {evidence.evidence_type.value}"
                                f" ({evidence.value})"
                            )

                        # Update status
                        if hyp.posterior >= 0.9:
                            hyp.status = HypothesisStatus.CONFIRMED
                        elif hyp.posterior <= 0.05:
                            hyp.status = HypothesisStatus.REJECTED

                        # Confidence interval (simple approximation)
                        n = len(hyp.supporting_evidence) + len(hyp.contradicting_evidence)
                        if n > 0:
                            stderr = math.sqrt(hyp.posterior * (1 - hyp.posterior) / max(n, 1))
                            hyp.confidence_interval = (
                                max(0.0, hyp.posterior - 1.96 * stderr),
                                min(1.0, hyp.posterior + 1.96 * stderr),
                            )

            self.updated_at = time.time()
            return {h.hypothesis_id: h.posterior for h in self.hypotheses.values()}

    def get_ranked_hypotheses(self, min_posterior: float = 0.0) -> List[Hypothesis]:
        """Get hypotheses ranked by posterior probability (descending)."""
        ranked = [
            h for h in self.hypotheses.values()
            if h.posterior >= min_posterior and h.status != HypothesisStatus.REJECTED
        ]
        ranked.sort(key=lambda h: h.posterior, reverse=True)
        return ranked

    def get_next_best_test(self, top_n: int = 5) -> List[Tuple[str, float]]:
        """Determine what to scan/test next based on information gain."""
        return self.network.most_informative_evidence(top_n=top_n)

    def entropy(self) -> float:
        """Total uncertainty across all active hypotheses."""
        return sum(
            BayesianNetwork._binary_entropy(h.posterior)
            for h in self.hypotheses.values()
            if h.status == HypothesisStatus.ACTIVE
        )

    def summary(self) -> Dict[str, Any]:
        """Current state summary."""
        ranked = self.get_ranked_hypotheses()
        return {
            "target_id": self.target_id,
            "total_hypotheses": len(self.hypotheses),
            "active": sum(1 for h in self.hypotheses.values() if h.status == HypothesisStatus.ACTIVE),
            "confirmed": sum(1 for h in self.hypotheses.values() if h.status == HypothesisStatus.CONFIRMED),
            "rejected": sum(1 for h in self.hypotheses.values() if h.status == HypothesisStatus.REJECTED),
            "total_evidence": len(self.evidence_log),
            "total_entropy": self.entropy(),
            "top_5_hypotheses": [
                {"id": h.hypothesis_id, "label": h.label, "posterior": round(h.posterior, 4),
                 "risk_score": round(h.risk_score, 4)}
                for h in ranked[:5]
            ],
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_id": self.target_id,
            "network": self.network.to_dict(),
            "hypotheses": {hid: h.to_dict() for hid, h in self.hypotheses.items()},
            "evidence_count": len(self.evidence_log),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


# ════════════════════════════════════════════════════════════════════════════════
# EVIDENCE COLLECTOR — Converts scan results to Bayesian evidence
# ════════════════════════════════════════════════════════════════════════════════


class EvidenceCollector:
    """Converts raw scan results into structured Bayesian evidence.

    Maps scanner output (ports, headers, responses, errors) to
    evidence nodes with calibrated confidence scores.
    """

    # Evidence type → default confidence mapping
    CONFIDENCE_MAP: Dict[EvidenceType, float] = {
        EvidenceType.PORT_OPEN: 0.99,
        EvidenceType.SERVICE_VERSION: 0.95,
        EvidenceType.HEADER_PRESENT: 0.98,
        EvidenceType.HEADER_MISSING: 0.90,
        EvidenceType.RESPONSE_PATTERN: 0.85,
        EvidenceType.ERROR_MESSAGE: 0.92,
        EvidenceType.DIRECTORY_LISTING: 0.97,
        EvidenceType.DEFAULT_PAGE: 0.93,
        EvidenceType.TECHNOLOGY_DETECTED: 0.88,
        EvidenceType.BEHAVIOR_ANOMALY: 0.70,
        EvidenceType.TIMING_ANOMALY: 0.65,
        EvidenceType.STATUS_CODE: 0.99,
        EvidenceType.CORS_MISCONFIGURATION: 0.90,
        EvidenceType.INPUT_REFLECTION: 0.80,
        EvidenceType.WAF_DETECTED: 0.85,
        EvidenceType.API_SCHEMA_EXPOSED: 0.95,
        EvidenceType.STACK_TRACE_LEAKED: 0.97,
        EvidenceType.VERSION_HEADER: 0.92,
    }

    def __init__(self) -> None:
        self._collected: List[Evidence] = []
        self._dedup: Set[str] = set()

    def collect_port_scan(self, port: int, protocol: str = "tcp",
                          service: str = "", version: str = "",
                          source: str = "scanner") -> List[Evidence]:
        """Convert port scan result to evidence."""
        evidences: List[Evidence] = []

        ev = Evidence(
            evidence_id=f"port_{protocol}_{port}",
            evidence_type=EvidenceType.PORT_OPEN,
            value={"port": port, "protocol": protocol},
            confidence=0.99,
            source=source,
        )
        evidences.append(ev)

        if service:
            ev_svc = Evidence(
                evidence_id=f"service_{port}_{service}",
                evidence_type=EvidenceType.SERVICE_VERSION,
                value={"port": port, "service": service, "version": version},
                confidence=0.95 if version else 0.80,
                source=source,
            )
            evidences.append(ev_svc)

        for e in evidences:
            self._add(e)
        return evidences

    def collect_header(self, header_name: str, header_value: Optional[str],
                       url: str = "", source: str = "scanner") -> Evidence:
        """Convert HTTP header presence/absence to evidence."""
        present = header_value is not None
        ev = Evidence(
            evidence_id=f"header_{header_name.lower()}_{present}",
            evidence_type=EvidenceType.HEADER_PRESENT if present else EvidenceType.HEADER_MISSING,
            value={"header": header_name, "value": header_value, "url": url},
            confidence=self.CONFIDENCE_MAP.get(
                EvidenceType.HEADER_PRESENT if present else EvidenceType.HEADER_MISSING, 0.90
            ),
            source=source,
        )
        self._add(ev)
        return ev

    def collect_response_pattern(self, pattern: str, matched: bool,
                                  url: str = "", source: str = "scanner") -> Evidence:
        """Convert response pattern match to evidence."""
        ev = Evidence(
            evidence_id=f"pattern_{hashlib.md5(pattern.encode()).hexdigest()[:8]}_{matched}",
            evidence_type=EvidenceType.RESPONSE_PATTERN,
            value={"pattern": pattern, "matched": matched, "url": url},
            confidence=0.85 if matched else 0.75,
            source=source,
        )
        self._add(ev)
        return ev

    def collect_technology(self, tech_name: str, version: str = "",
                           source: str = "fingerprint") -> Evidence:
        """Detected technology/framework."""
        ev = Evidence(
            evidence_id=f"tech_{tech_name}_{version}".replace(" ", "_"),
            evidence_type=EvidenceType.TECHNOLOGY_DETECTED,
            value={"technology": tech_name, "version": version},
            confidence=0.92 if version else 0.80,
            source=source,
        )
        self._add(ev)
        return ev

    def collect_error_leak(self, error_type: str, stack_trace: bool = False,
                           details: str = "", source: str = "scanner") -> Evidence:
        """Error message or stack trace leakage."""
        ev = Evidence(
            evidence_id=f"error_{error_type}_{stack_trace}",
            evidence_type=EvidenceType.STACK_TRACE_LEAKED if stack_trace else EvidenceType.ERROR_MESSAGE,
            value={"error_type": error_type, "stack_trace": stack_trace, "details": details},
            confidence=0.97 if stack_trace else 0.90,
            source=source,
        )
        self._add(ev)
        return ev

    def collect_timing(self, url: str, baseline_ms: float, observed_ms: float,
                       source: str = "fuzzer") -> Evidence:
        """Timing anomaly (potential blind injection)."""
        ratio = observed_ms / max(baseline_ms, 1.0)
        is_anomaly = ratio > 2.5  # 2.5x slower = suspicious
        confidence = min(0.95, 0.5 + (ratio - 1.0) * 0.15)

        ev = Evidence(
            evidence_id=f"timing_{hashlib.md5(url.encode()).hexdigest()[:8]}",
            evidence_type=EvidenceType.TIMING_ANOMALY,
            value={"url": url, "baseline_ms": baseline_ms, "observed_ms": observed_ms,
                   "ratio": ratio, "is_anomaly": is_anomaly},
            confidence=confidence,
            source=source,
        )
        self._add(ev)
        return ev

    def collect_waf(self, waf_name: str, confidence: float = 0.85,
                    source: str = "fingerprint") -> Evidence:
        """WAF detection — reduces probability of simple exploits."""
        ev = Evidence(
            evidence_id=f"waf_{waf_name}",
            evidence_type=EvidenceType.WAF_DETECTED,
            value={"waf": waf_name},
            confidence=confidence,
            source=source,
        )
        self._add(ev)
        return ev

    def collect_custom(self, evidence_id: str, value: Any,
                       confidence: float = 0.80, source: str = "") -> Evidence:
        """Generic evidence for custom integrations."""
        ev = Evidence(
            evidence_id=evidence_id,
            evidence_type=EvidenceType.CUSTOM,
            value=value,
            confidence=confidence,
            source=source,
        )
        self._add(ev)
        return ev

    def _add(self, ev: Evidence) -> None:
        fp = ev.fingerprint()
        if fp not in self._dedup:
            self._dedup.add(fp)
            self._collected.append(ev)

    @property
    def all_evidence(self) -> List[Evidence]:
        return list(self._collected)

    def clear(self) -> None:
        self._collected.clear()
        self._dedup.clear()


# ════════════════════════════════════════════════════════════════════════════════
# POSTERIOR CALCULATOR — Real-time Bayesian updates
# ════════════════════════════════════════════════════════════════════════════════


class PosteriorCalculator:
    """Handles real-time Bayesian updates as new evidence arrives.

    Optimized for incremental updates — doesn't re-compute the entire
    network when a single piece of evidence is added.
    """

    def __init__(self, network: BayesianNetwork) -> None:
        self._network = network
        self._update_count = 0
        self._executor = ThreadPoolExecutor(max_workers=THREAD_POOL_SIZE)

    def update_single(self, evidence_node_id: str, value: bool,
                       confidence: float = 1.0) -> Dict[str, float]:
        """Update network with a single new evidence observation.

        Uses local update propagation instead of full inference
        for efficiency.
        """
        self._network.set_evidence(evidence_node_id, value, confidence)
        self._update_count += 1

        # For small networks, just re-run full inference
        if self._network.node_count < 50:
            result = self._network.infer(method=InferenceMethod.BELIEF_PROPAGATION)
            return result.posteriors

        # For larger networks, do local propagation
        # Only re-compute nodes in the Markov blanket
        affected = self._network._markov_blanket(evidence_node_id)
        affected.add(evidence_node_id)

        # Expand one more level
        extended: Set[str] = set(affected)
        for nid in affected:
            extended.update(self._network._markov_blanket(nid))

        # Run inference only on affected region
        query = [nid for nid in extended
                 if self._network.get_node(nid) and
                 self._network.get_node(nid).category == NodeCategory.VULNERABILITY]

        if query:
            result = self._network.infer(
                method=InferenceMethod.BELIEF_PROPAGATION,
                query_nodes=query,
            )
            return result.posteriors

        return {}

    def batch_update(self, evidence_list: List[Tuple[str, bool, float]]) -> Dict[str, float]:
        """Update network with multiple evidence observations at once.

        More efficient than calling update_single repeatedly.
        """
        for node_id, value, confidence in evidence_list:
            self._network.set_evidence(node_id, value, confidence)

        result = self._network.infer(method=InferenceMethod.BELIEF_PROPAGATION)
        self._update_count += len(evidence_list)
        return result.posteriors

    async def async_update(self, evidence_node_id: str, value: bool,
                            confidence: float = 1.0) -> Dict[str, float]:
        """Async version for pipeline integration."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            self._executor,
            self.update_single,
            evidence_node_id, value, confidence,
        )

    @property
    def update_count(self) -> int:
        return self._update_count

    def shutdown(self) -> None:
        """Shutdown thread pool."""
        self._executor.shutdown(wait=False)
        logger.info("PosteriorCalculator shutdown")

    def __del__(self) -> None:
        """Safety net to ensure thread pool is cleaned up."""
        self.shutdown()


# ════════════════════════════════════════════════════════════════════════════════
# HYPOTHESIS RANKER — Intelligent prioritization
# ════════════════════════════════════════════════════════════════════════════════


class HypothesisRanker:
    """Ranks vulnerability hypotheses using multi-criteria scoring.

    Combines:
    - Posterior probability (Bayesian)
    - CVSS severity
    - EPSS exploitability
    - Evidence quality (confidence-weighted)
    - Chain potential (from attack graph)
    """

    def __init__(self, weights: Optional[Dict[str, float]] = None) -> None:
        self.weights = weights or {
            "posterior": 0.35,
            "cvss": 0.20,
            "epss": 0.15,
            "evidence_quality": 0.15,
            "chain_potential": 0.15,
        }

    def rank(self, hypotheses: List[Hypothesis],
             chain_scores: Optional[Dict[str, float]] = None) -> List[Tuple[Hypothesis, float]]:
        """Rank hypotheses by composite score."""
        scored: List[Tuple[Hypothesis, float]] = []

        for hyp in hypotheses:
            if hyp.status == HypothesisStatus.REJECTED:
                continue

            # Posterior component
            s_posterior = hyp.posterior

            # CVSS component (normalized to 0-1)
            s_cvss = (hyp.cvss_base or 5.0) / 10.0

            # EPSS component
            s_epss = 0.5  # Default if unknown
            if hyp.node_id:
                # Could integrate with EPSS API here
                pass

            # Evidence quality: weighted by confidence
            total_ev = len(hyp.supporting_evidence) + len(hyp.contradicting_evidence)
            s_evidence = hyp.evidence_ratio if total_ev > 0 else 0.5

            # Chain potential: can this vuln be chained?
            s_chain = 0.5
            if chain_scores and hyp.hypothesis_id in chain_scores:
                s_chain = chain_scores[hyp.hypothesis_id]

            # Weighted composite
            composite = (
                self.weights["posterior"] * s_posterior
                + self.weights["cvss"] * s_cvss
                + self.weights["epss"] * s_epss
                + self.weights["evidence_quality"] * s_evidence
                + self.weights["chain_potential"] * s_chain
            )

            scored.append((hyp, composite))

        scored.sort(key=lambda x: x[1], reverse=True)
        return scored

    def explain(self, hypothesis: Hypothesis,
                chain_score: float = 0.5) -> Dict[str, Any]:
        """Provide detailed explanation of ranking for a hypothesis."""
        components = {
            "posterior": {"value": hypothesis.posterior, "weight": self.weights["posterior"]},
            "cvss": {"value": (hypothesis.cvss_base or 5.0) / 10.0, "weight": self.weights["cvss"]},
            "evidence_quality": {"value": hypothesis.evidence_ratio, "weight": self.weights["evidence_quality"]},
            "chain_potential": {"value": chain_score, "weight": self.weights["chain_potential"]},
        }

        total = sum(c["value"] * c["weight"] for c in components.values())

        return {
            "hypothesis_id": hypothesis.hypothesis_id,
            "label": hypothesis.label,
            "composite_score": total,
            "components": components,
            "evidence_chain": hypothesis.explanation_chain,
            "confidence_interval": hypothesis.confidence_interval,
            "status": hypothesis.status.value,
        }


# ════════════════════════════════════════════════════════════════════════════════
# VULNERABILITY PRIOR DATABASE — Calibrated priors from real-world data
# ════════════════════════════════════════════════════════════════════════════════


class VulnPriorDB:
    """Database of calibrated vulnerability priors based on real-world statistics.

    These priors are not guesses — they're based on:
    - OWASP statistical data
    - NVD CVE frequency analysis
    - EPSS historical data
    - Penetration testing experience patterns
    """

    # Technology → vulnerability type → prior probability
    TECH_PRIORS: Dict[str, Dict[str, float]] = {
        "apache": {
            "path_traversal": 0.15,
            "default_config": 0.25,
            "info_disclosure": 0.30,
            "directory_listing": 0.20,
            "mod_security_bypass": 0.05,
        },
        "nginx": {
            "path_traversal": 0.08,
            "default_config": 0.15,
            "info_disclosure": 0.20,
            "off_by_slash": 0.10,
            "alias_traversal": 0.12,
        },
        "php": {
            "sqli": 0.25,
            "xss": 0.30,
            "lfi": 0.20,
            "rce": 0.10,
            "type_juggling": 0.15,
            "deserialization": 0.08,
        },
        "java": {
            "deserialization": 0.15,
            "xxe": 0.12,
            "sqli": 0.10,
            "ssti": 0.08,
            "log4j_rce": 0.05,
            "spring_rce": 0.06,
        },
        "nodejs": {
            "prototype_pollution": 0.15,
            "ssrf": 0.12,
            "xss": 0.20,
            "nosql_injection": 0.10,
            "path_traversal": 0.08,
            "rce_eval": 0.05,
        },
        "python": {
            "ssti": 0.15,
            "ssrf": 0.10,
            "sqli": 0.08,
            "deserialization": 0.12,
            "command_injection": 0.07,
        },
        "wordpress": {
            "plugin_vuln": 0.40,
            "theme_vuln": 0.20,
            "xmlrpc_abuse": 0.35,
            "sqli": 0.15,
            "xss": 0.25,
            "file_upload": 0.10,
            "default_creds": 0.15,
        },
        "api_rest": {
            "broken_auth": 0.25,
            "idor": 0.20,
            "mass_assignment": 0.15,
            "rate_limit_missing": 0.30,
            "jwt_weakness": 0.12,
            "graphql_introspection": 0.18,
            "swagger_exposed": 0.22,
        },
        "docker": {
            "exposed_api": 0.15,
            "privileged_container": 0.10,
            "mount_escape": 0.08,
            "default_network": 0.20,
        },
        "mysql": {
            "default_creds": 0.10,
            "remote_access": 0.08,
            "privilege_escalation": 0.05,
        },
        "redis": {
            "no_auth": 0.30,
            "rce_via_config": 0.20,
            "data_exposure": 0.25,
        },
        "mongodb": {
            "no_auth": 0.25,
            "injection": 0.12,
            "data_exposure": 0.20,
        },
    }

    # Version-specific known CVE priors
    VERSION_CVE_PRIORS: Dict[str, Dict[str, float]] = {
        "apache/2.4.49": {"CVE-2021-41773": 0.95, "CVE-2021-42013": 0.85},
        "apache/2.4.50": {"CVE-2021-42013": 0.90},
        "log4j/2.14": {"CVE-2021-44228": 0.98},
        "log4j/2.15": {"CVE-2021-45046": 0.80},
        "spring/5.3": {"CVE-2022-22965": 0.70},
        "openssl/3.0": {"CVE-2022-3602": 0.65, "CVE-2022-3786": 0.60},
        "wordpress/6.0": {"plugin_vuln": 0.45},
    }

    @classmethod
    def get_priors(cls, technology: str, version: str = "") -> Dict[str, float]:
        """Get vulnerability priors for a given technology and version."""
        tech_lower = technology.lower().strip()
        priors: Dict[str, float] = {}

        # Base tech priors
        for tech_key, vuln_priors in cls.TECH_PRIORS.items():
            if tech_key in tech_lower:
                priors.update(vuln_priors)
                break

        # Version-specific CVE priors (override base)
        if version:
            version_key = f"{tech_lower}/{version}"
            for key, cve_priors in cls.VERSION_CVE_PRIORS.items():
                if key in version_key or version_key.startswith(key.split("/")[0]):
                    priors.update(cve_priors)

        return priors

    @classmethod
    def get_combined_prior(cls, technologies: List[Tuple[str, str]]) -> Dict[str, float]:
        """Get combined priors for a stack of technologies.

        Uses Noisy-OR combination: P(vuln) = 1 - product(1 - p_i)
        """
        all_vuln_priors: Dict[str, List[float]] = defaultdict(list)

        for tech, version in technologies:
            for vuln_type, prior in cls.get_priors(tech, version).items():
                all_vuln_priors[vuln_type].append(prior)

        combined: Dict[str, float] = {}
        for vuln_type, priors_list in all_vuln_priors.items():
            # Noisy-OR: P = 1 - product(1 - p_i)
            prob_none = 1.0
            for p in priors_list:
                prob_none *= (1.0 - p)
            combined[vuln_type] = 1.0 - prob_none

        return combined


# ════════════════════════════════════════════════════════════════════════════════
# SIREN BAYESIAN ENGINE — Main interface
# ════════════════════════════════════════════════════════════════════════════════


class SirenBayesianEngine:
    """The main Bayesian Cognitive Engine for SIREN.

    Orchestrates all components:
    - BayesianNetwork for probabilistic inference
    - BeliefState for working memory
    - EvidenceCollector for scan integration
    - PosteriorCalculator for real-time updates
    - HypothesisRanker for prioritization
    - VulnPriorDB for calibrated priors

    Thread-safe and async-compatible for use in the SIREN pipeline.
    """

    def __init__(self, target_id: str = "") -> None:
        self.belief = BeliefState(target_id=target_id)
        self.collector = EvidenceCollector()
        self.calculator = PosteriorCalculator(self.belief.network)
        self.ranker = HypothesisRanker()
        self._lock = threading.RLock()
        self._initialized = False

        logger.info(f"SirenBayesianEngine initialized for target: {target_id}")

    def initialize_from_tech_stack(self, technologies: List[Tuple[str, str]]) -> int:
        """Bootstrap the engine with technology stack detection.

        Creates vulnerability hypotheses with calibrated priors
        based on detected technologies.

        Args:
            technologies: List of (tech_name, version) tuples.

        Returns:
            Number of hypotheses created.
        """
        with self._lock:
            priors = VulnPriorDB.get_combined_prior(technologies)

            for vuln_type, prior in priors.items():
                hyp_id = f"hyp_{vuln_type}"
                node_id = f"vuln_{vuln_type}"

                hypothesis = Hypothesis(
                    hypothesis_id=hyp_id,
                    label=vuln_type.replace("_", " ").title(),
                    description=f"Potential {vuln_type} vulnerability based on technology stack",
                    prior=prior,
                    posterior=prior,
                    node_id=node_id,
                )

                self.belief.add_hypothesis(hypothesis)

            # Wire up technology evidence nodes to vulnerability nodes
            for tech, version in technologies:
                tech_priors = VulnPriorDB.get_priors(tech, version)
                tech_ev = self.collector.collect_technology(tech, version)

                # Create evidence node and link to relevant vulns
                ev_node = BayesianNode(
                    node_id=f"ev_{tech_ev.fingerprint()}",
                    category=NodeCategory.OBSERVABLE,
                    label=f"Tech: {tech} {version}",
                )
                ev_node.set_evidence(True, tech_ev.confidence)
                self.belief.network.add_node(ev_node)

                for vuln_type in tech_priors:
                    vuln_node_id = f"vuln_{vuln_type}"
                    if self.belief.network.get_node(vuln_node_id):
                        # Set up CPT with likelihood
                        ev_node.cpt = CPT.from_likelihood(
                            ev_node.node_id, vuln_node_id,
                            true_positive=0.80,
                            false_positive=0.10,
                        )
                        self.belief.network.add_edge(vuln_node_id, ev_node.node_id)

            self._initialized = True
            logger.info(f"Initialized {len(priors)} hypotheses from {len(technologies)} technologies")
            return len(priors)

    def process_evidence(self, evidence: Evidence) -> Dict[str, float]:
        """Process a single piece of evidence and update beliefs."""
        with self._lock:
            return self.belief.add_evidence(evidence)

    def process_scan_results(self, scan_results: Dict[str, Any]) -> Dict[str, float]:
        """Process bulk scan results (from scanner module).

        Expects format compatible with SIREN scanner output.
        """
        with self._lock:
            all_posteriors: Dict[str, float] = {}

            # Process ports
            for port_info in scan_results.get("open_ports", []):
                evidences = self.collector.collect_port_scan(
                    port=port_info.get("port", 0),
                    protocol=port_info.get("protocol", "tcp"),
                    service=port_info.get("service", ""),
                    version=port_info.get("version", ""),
                    source="scanner",
                )
                for ev in evidences:
                    posteriors = self.belief.add_evidence(ev)
                    all_posteriors.update(posteriors)

            # Process headers
            for header_info in scan_results.get("headers", []):
                ev = self.collector.collect_header(
                    header_name=header_info.get("name", ""),
                    header_value=header_info.get("value"),
                    url=header_info.get("url", ""),
                    source="scanner",
                )
                posteriors = self.belief.add_evidence(ev)
                all_posteriors.update(posteriors)

            # Process technologies
            for tech_info in scan_results.get("technologies", []):
                ev = self.collector.collect_technology(
                    tech_name=tech_info.get("name", ""),
                    version=tech_info.get("version", ""),
                    source="fingerprint",
                )
                posteriors = self.belief.add_evidence(ev)
                all_posteriors.update(posteriors)

            # Process findings
            for finding in scan_results.get("findings", []):
                ev = self.collector.collect_custom(
                    evidence_id=f"finding_{finding.get('id', 'unknown')}",
                    value=finding,
                    confidence=finding.get("confidence", 0.85),
                    source=finding.get("source", "scanner"),
                )
                posteriors = self.belief.add_evidence(ev)
                all_posteriors.update(posteriors)

            return all_posteriors

    def get_ranked_vulnerabilities(self, min_posterior: float = 0.1,
                                     top_n: int = 20) -> List[Dict[str, Any]]:
        """Get top vulnerability hypotheses ranked by composite score."""
        hypotheses = self.belief.get_ranked_hypotheses(min_posterior=min_posterior)
        ranked = self.ranker.rank(hypotheses)

        results: List[Dict[str, Any]] = []
        for hyp, score in ranked[:top_n]:
            explanation = self.ranker.explain(hyp)
            explanation["composite_score"] = score
            results.append(explanation)

        return results

    def recommend_next_tests(self, top_n: int = 5) -> List[Dict[str, Any]]:
        """Recommend what to test next based on information gain."""
        recommendations = self.belief.get_next_best_test(top_n=top_n)

        results: List[Dict[str, Any]] = []
        for node_id, info_gain in recommendations:
            node = self.belief.network.get_node(node_id)
            results.append({
                "test_id": node_id,
                "label": node.label if node else node_id,
                "information_gain": info_gain,
                "current_belief": node.posterior if node else 0.5,
                "recommendation": "HIGH PRIORITY" if info_gain > 0.5 else
                                  "MEDIUM PRIORITY" if info_gain > 0.2 else
                                  "LOW PRIORITY",
            })

        return results

    def get_state_summary(self) -> Dict[str, Any]:
        """Full engine state summary for dashboard/reporting."""
        summary = self.belief.summary()
        summary["engine"] = {
            "initialized": self._initialized,
            "network_nodes": self.belief.network.node_count,
            "network_edges": self.belief.network.edge_count,
            "total_evidence": len(self.collector.all_evidence),
            "update_count": self.calculator.update_count,
        }
        return summary

    def save_state(self, path: Union[str, Path]) -> None:
        """Persist engine state to disk."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        state = {
            "belief": self.belief.to_dict(),
            "evidence": [
                {"id": e.evidence_id, "type": e.evidence_type.value,
                 "value": str(e.value), "confidence": e.confidence,
                 "source": e.source, "timestamp": e.timestamp}
                for e in self.collector.all_evidence
            ],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2, ensure_ascii=False, default=str)

    @classmethod
    def load_state(cls, path: Union[str, Path]) -> "SirenBayesianEngine":
        """Load engine from persisted state."""
        with open(path, "r", encoding="utf-8") as f:
            state = json.load(f)

        target_id = state.get("belief", {}).get("target_id", "")
        engine = cls(target_id=target_id)

        # Restore network
        if "belief" in state and "network" in state["belief"]:
            engine.belief.network = BayesianNetwork.from_dict(state["belief"]["network"])
            engine.calculator = PosteriorCalculator(engine.belief.network)

        # Restore hypotheses
        for hid, hdata in state.get("belief", {}).get("hypotheses", {}).items():
            hyp = Hypothesis(
                hypothesis_id=hdata["hypothesis_id"],
                label=hdata["label"],
                description=hdata.get("description", ""),
                prior=hdata.get("prior", DEFAULT_PRIOR),
                posterior=hdata.get("posterior", DEFAULT_PRIOR),
                status=HypothesisStatus(hdata.get("status", "active")),
                node_id=hdata.get("node_id"),
                cve_ids=hdata.get("cve_ids", []),
                cwe_ids=hdata.get("cwe_ids", []),
                cvss_base=hdata.get("cvss_base"),
                mitre_techniques=hdata.get("mitre_techniques", []),
            )
            engine.belief.hypotheses[hid] = hyp

        engine._initialized = True
        return engine

    def __repr__(self) -> str:
        return (
            f"SirenBayesianEngine("
            f"target={self.belief.target_id!r}, "
            f"hypotheses={len(self.belief.hypotheses)}, "
            f"evidence={len(self.collector.all_evidence)}, "
            f"nodes={self.belief.network.node_count})"
        )
