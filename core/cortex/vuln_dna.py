#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  🧬  SIREN VULNERABILITY DNA — Genética de Vulnerabilidades  🧬              ██
██                                                                                ██
██  Cada vulnerabilidade é um organismo. Tem DNA (128-dim genome vector).         ██
██  Vulnerabilidades similares compartilham código genético. Novas mutações       ██
██  podem ser PREVISTAS analisando a linhagem evolutiva.                          ██
██                                                                                ██
██  Capacidades:                                                                  ██
██    • VulnGenome — vetor 128-dim que codifica {trigger, propagation, impact,    ██
██      evasion, persistence, complexity, prerequisites, exploit_maturity}        ██
██    • DNAExtractor — extrai genomas de scan results, CVEs, advisories           ██
██    • GeneticComparator — cosine similarity + phylogenetic distance             ██
██    • LineageTracker — árvore genealógica: RFI → LFI → Path Traversal → RCE   ██
██    • MutationAnalyzer — detecta mutações entre variantes (bypass WAF, etc)     ██
██    • PredictiveGenetics — prevê próximas mutações com Markov chains            ██
██                                                                                ██
██  Referências acadêmicas:                                                       ██
██    • Grieco et al. (2016) — Toward Large-Scale Vulnerability Discovery         ██
██    • Li et al. (2021) — VulDeePecker: Deep Learning Vuln Detection             ██
██    • Neuhaus et al. (2007) — Predicting Vulnerable Software Components         ██
██                                                                                ██
██  "Cada vuln conta uma história evolutiva. SIREN lê essa história."            ██
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
import random
import statistics
import struct
import threading
import time
from collections import Counter, OrderedDict, defaultdict, deque
from concurrent.futures import ThreadPoolExecutor

from core.shannon.constants import EPSILON
from dataclasses import dataclass, field
from enum import Enum, auto
from functools import lru_cache  # kept for potential use in hashable-context helpers
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
    Sequence,
    Set,
    Tuple,
    Union,
)

logger = logging.getLogger("siren.cortex.vuln_dna")


# ════════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════════════════════════════

GENOME_DIMENSIONS = 128           # Size of genome vector
GENE_BLOCK_SIZE = 16              # Genes per trait block (128/8 = 16 per block)
SIMILARITY_THRESHOLD = 0.85       # Cosine sim threshold for "same family"
# MUTATION_THRESHOLD = 1 - SIMILARITY_THRESHOLD.  The two thresholds are
# complementary: genomes within SIMILARITY_THRESHOLD are "same family",
# while genomes separated by at least MUTATION_THRESHOLD (in distance
# space, i.e. 1 - similarity) are considered distinct mutations.
MUTATION_THRESHOLD = 0.15         # Min distance to consider a mutation
LINEAGE_MAX_DEPTH = 50            # Max genealogy tree depth
PREDICTION_HORIZON = 5            # Markov chain prediction steps
MARKOV_ORDER = 3                  # Order of Markov chain
PHYLO_DISTANCE_CACHE = 4096      # LRU cache size for phylogenetic distances
THREAD_POOL_SIZE = 4              # Concurrent DNA extraction threads


# ════════════════════════════════════════════════════════════════════════════════
# ENUMS
# ════════════════════════════════════════════════════════════════════════════════


class GeneBlock(Enum):
    """The 8 trait blocks that compose a 128-dim genome.
    Each block = 16 dimensions encoding one aspect of the vuln."""
    TRIGGER = 0         # How the vuln is triggered (input type, vector, protocol)
    PROPAGATION = 1     # How it spreads/chains (lateral, vertical, network)
    IMPACT = 2          # Damage potential (CIA triad, blast radius, reversibility)
    EVASION = 3         # Detection avoidance (encoding, obfuscation, timing)
    PERSISTENCE = 4     # Durability (session-bound, permanent, reboot-survive)
    COMPLEXITY = 5      # Exploitation difficulty (auth needed, user interaction)
    PREREQUISITES = 6   # Required conditions (OS, service, config, network position)
    MATURITY = 7        # Exploit ecosystem (PoC exists, weaponized, in-the-wild)


class VulnFamily(Enum):
    """High-level vulnerability families for classification."""
    INJECTION = "injection"           # SQLi, XSS, XXE, SSTI, Command Injection
    AUTHENTICATION = "authentication" # Broken auth, credential stuffing, session
    AUTHORIZATION = "authorization"   # IDOR, privilege escalation, BOLA
    CRYPTOGRAPHIC = "cryptographic"   # Weak crypto, key exposure, padding oracle
    CONFIGURATION = "configuration"   # Misconfig, default creds, exposed admin
    INFORMATION = "information"       # Info leak, stack trace, directory listing
    BUSINESS_LOGIC = "business_logic" # Race condition, workflow bypass, price manip
    MEMORY = "memory"                 # Buffer overflow, UAF, format string
    DESERIALIZATION = "deserialization"  # Insecure deser, type confusion
    SSRF = "ssrf"                     # Server-side request forgery
    FILE_OPERATION = "file_operation" # Path traversal, file upload, LFI/RFI
    API = "api"                       # Mass assignment, rate limit, GraphQL
    SUPPLY_CHAIN = "supply_chain"     # Dependency confusion, typosquatting
    UNKNOWN = "unknown"


class MutationType(Enum):
    """Types of genetic mutations between vulnerability variants."""
    POINT = "point"           # Single gene change (e.g., ' → " in SQLi)
    BLOCK = "block"           # Entire trait block change (new evasion technique)
    CROSSOVER = "crossover"   # Genes from two different vulns combined
    DELETION = "deletion"     # Lost capability (simplified variant)
    INSERTION = "insertion"   # New capability gained (escalation)
    INVERSION = "inversion"   # Reversed approach (client→server or vice versa)
    DUPLICATION = "duplication"  # Repeated technique applied to new context
    FRAMESHIFT = "frameshift"   # Fundamental change in exploitation paradigm


class EvolutionPressure(Enum):
    """Environmental pressures driving vulnerability evolution."""
    WAF_EVASION = "waf_evasion"         # WAF forces encoding mutations
    PATCH_BYPASS = "patch_bypass"       # Patch forces exploit pivot
    VERSION_UPGRADE = "version_upgrade" # New version creates new surface
    TECHNOLOGY_SHIFT = "tech_shift"     # Platform change (PHP→Node, REST→GraphQL)
    DETECTION_AVOIDANCE = "detection"   # IDS/SIEM forces timing/stealth mutations
    FRAMEWORK_ADOPTION = "framework"    # Framework changes (jQuery→React)
    CLOUD_MIGRATION = "cloud"           # On-prem→cloud creates new vectors
    API_EVOLUTION = "api_evolution"     # REST→GraphQL→gRPC


class LineageRelation(Enum):
    """Evolutionary relationships between vulnerabilities."""
    PARENT = "parent"           # Direct ancestor
    CHILD = "child"             # Direct descendant
    SIBLING = "sibling"         # Same parent, different mutations
    COUSIN = "cousin"           # Shared grandparent
    CONVERGENT = "convergent"   # Similar phenotype, different lineage
    DIVERGENT = "divergent"     # Same lineage, different phenotype


# ════════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ════════════════════════════════════════════════════════════════════════════════


@dataclass
class Gene:
    """A single gene — one dimension of the genome vector."""
    index: int                          # Position in genome (0-127)
    value: float                        # Gene value [0.0, 1.0]
    block: GeneBlock                    # Which trait block this gene belongs to
    label: str = ""                     # Human-readable gene name
    confidence: float = 1.0             # How confident we are in this gene's value

    def distance(self, other: "Gene") -> float:
        """Absolute distance between two genes."""
        return abs(self.value - other.value)

    def mutate(self, delta: float) -> "Gene":
        """Create a mutated copy of this gene."""
        new_val = max(0.0, min(1.0, self.value + delta))
        return Gene(
            index=self.index,
            value=new_val,
            block=self.block,
            label=self.label,
            confidence=self.confidence * 0.9,  # Mutation reduces confidence
        )


@dataclass
class VulnGenome:
    """128-dimensional genome vector representing a vulnerability's DNA.

    The genome is divided into 8 blocks of 16 genes each:
      Block 0 (TRIGGER):        genes[0:16]   — How the vuln fires
      Block 1 (PROPAGATION):    genes[16:32]  — How it spreads
      Block 2 (IMPACT):         genes[32:48]  — What damage it causes
      Block 3 (EVASION):        genes[48:64]  — How it hides
      Block 4 (PERSISTENCE):    genes[64:80]  — How long it lasts
      Block 5 (COMPLEXITY):     genes[80:96]  — How hard to exploit
      Block 6 (PREREQUISITES):  genes[96:112] — What's needed first
      Block 7 (MATURITY):       genes[112:128] — Exploit ecosystem status
    """
    vuln_id: str                                # Unique identifier (CVE, CWE, custom)
    genes: List[Gene] = field(default_factory=list)
    family: VulnFamily = VulnFamily.UNKNOWN
    cwe_ids: List[str] = field(default_factory=list)
    cve_ids: List[str] = field(default_factory=list)
    cvss_score: float = 0.0
    epss_score: float = 0.0
    description: str = ""
    parent_id: Optional[str] = None             # ID of the parent genome
    generation: int = 0                          # How many mutations from original
    mutations: List["MutationRecord"] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.genes:
            self.genes = [
                Gene(index=i, value=0.0, block=GeneBlock(i // GENE_BLOCK_SIZE))
                for i in range(GENOME_DIMENSIONS)
            ]

    @property
    def vector(self) -> List[float]:
        """Get the raw float vector [128 dims]."""
        return [g.value for g in self.genes]

    @property
    def magnitude(self) -> float:
        """L2 norm of genome vector."""
        return math.sqrt(sum(v * v for v in self.vector))

    def get_block(self, block: GeneBlock) -> List[Gene]:
        """Get all 16 genes for a specific trait block."""
        start = block.value * GENE_BLOCK_SIZE
        return self.genes[start:start + GENE_BLOCK_SIZE]

    def get_block_vector(self, block: GeneBlock) -> List[float]:
        """Get float vector for a specific block [16 dims]."""
        return [g.value for g in self.get_block(block)]

    def set_block(self, block: GeneBlock, values: List[float]) -> None:
        """Set all 16 genes for a block at once."""
        if len(values) != GENE_BLOCK_SIZE:
            raise ValueError(f"Block requires {GENE_BLOCK_SIZE} values, got {len(values)}")
        start = block.value * GENE_BLOCK_SIZE
        for i, val in enumerate(values):
            self.genes[start + i].value = max(0.0, min(1.0, val))

    def fingerprint(self) -> str:
        """SHA256 fingerprint of the genome vector."""
        raw = struct.pack(f"{GENOME_DIMENSIONS}f", *self.vector)
        return hashlib.sha256(raw).hexdigest()[:32]

    def to_dict(self) -> Dict[str, Any]:
        """Serialize genome to dict."""
        return {
            "vuln_id": self.vuln_id,
            "vector": self.vector,
            "family": self.family.value,
            "cwe_ids": self.cwe_ids,
            "cve_ids": self.cve_ids,
            "cvss_score": self.cvss_score,
            "epss_score": self.epss_score,
            "description": self.description,
            "parent_id": self.parent_id,
            "generation": self.generation,
            "fingerprint": self.fingerprint(),
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VulnGenome":
        """Deserialize from dict."""
        genome = cls(
            vuln_id=data["vuln_id"],
            family=VulnFamily(data.get("family", "unknown")),
            cwe_ids=data.get("cwe_ids", []),
            cve_ids=data.get("cve_ids", []),
            cvss_score=data.get("cvss_score", 0.0),
            epss_score=data.get("epss_score", 0.0),
            description=data.get("description", ""),
            parent_id=data.get("parent_id"),
            generation=data.get("generation", 0),
            timestamp=data.get("timestamp", time.time()),
            metadata=data.get("metadata", {}),
        )
        if "vector" in data:
            for i, val in enumerate(data["vector"][:GENOME_DIMENSIONS]):
                genome.genes[i].value = float(val)
        return genome


@dataclass
class MutationRecord:
    """Records a single mutation event between two genomes."""
    source_id: str                        # Parent genome ID
    target_id: str                        # Child genome ID
    mutation_type: MutationType
    affected_blocks: List[GeneBlock]      # Which blocks were affected
    affected_genes: List[int]             # Gene indices that changed
    delta_vector: List[float]             # Change vector (target - source)
    pressure: Optional[EvolutionPressure] = None
    description: str = ""
    timestamp: float = field(default_factory=time.time)

    @property
    def intensity(self) -> float:
        """Mutation intensity = L2 norm of delta vector."""
        return math.sqrt(sum(d * d for d in self.delta_vector))

    @property
    def affected_block_set(self) -> Set[GeneBlock]:
        return set(self.affected_blocks)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "mutation_type": self.mutation_type.value,
            "affected_blocks": [b.value for b in self.affected_blocks],
            "affected_genes": self.affected_genes,
            "delta_vector": self.delta_vector,
            "pressure": self.pressure.value if self.pressure else None,
            "description": self.description,
            "intensity": self.intensity,
            "timestamp": self.timestamp,
        }


@dataclass
class PhylogeneticNode:
    """A node in the vulnerability phylogenetic tree."""
    genome_id: str
    genome: VulnGenome
    children: List["PhylogeneticNode"] = field(default_factory=list)
    parent: Optional["PhylogeneticNode"] = field(default=None, repr=False)
    branch_length: float = 0.0           # Genetic distance to parent
    bootstrap: float = 1.0               # Confidence in this branch [0-1]

    @property
    def is_leaf(self) -> bool:
        return len(self.children) == 0

    @property
    def depth(self) -> int:
        """Depth from root."""
        d = 0
        node = self.parent
        while node is not None:
            d += 1
            node = node.parent
        return d

    def get_descendants(self) -> List["PhylogeneticNode"]:
        """Get all descendants recursively."""
        result: List[PhylogeneticNode] = []
        stack = list(self.children)
        while stack:
            node = stack.pop()
            result.append(node)
            stack.extend(node.children)
        return result


@dataclass
class MarkovState:
    """State in the mutation Markov chain."""
    state_id: str                         # MutationType + GeneBlock combo
    mutation_type: MutationType
    affected_block: GeneBlock
    transitions: Dict[str, float] = field(default_factory=dict)  # next_state_id → prob

    def add_observation(self, next_state_id: str) -> None:
        """Record an observed transition."""
        self.transitions[next_state_id] = self.transitions.get(next_state_id, 0) + 1

    def normalize(self) -> None:
        """Convert counts to probabilities."""
        total = sum(self.transitions.values())
        if total > 0:
            self.transitions = {k: v / total for k, v in self.transitions.items()}


# ════════════════════════════════════════════════════════════════════════════════
# CWE → GENOME KNOWLEDGE BASE
# ════════════════════════════════════════════════════════════════════════════════

# Pre-calibrated genome templates for known CWE categories.
# Each maps to an 8-element tuple of block-level feature vectors (16 dims each).
# Values are [0.0-1.0] encoding the characteristic DNA of that vuln class.

CWE_GENOME_TEMPLATES: Dict[str, Dict[str, Any]] = {
    # ── INJECTION FAMILY ──────────────────────────────────────────────────
    "CWE-89": {
        "name": "SQL Injection",
        "family": VulnFamily.INJECTION,
        "trigger":       [0.9, 0.8, 0.7, 0.6, 0.3, 0.2, 0.1, 0.5, 0.9, 0.7, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0],
        "propagation":   [0.6, 0.7, 0.8, 0.5, 0.3, 0.4, 0.2, 0.1, 0.6, 0.5, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0],
        "impact":        [0.9, 0.9, 0.8, 0.7, 0.6, 0.5, 0.8, 0.9, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0],
        "evasion":       [0.7, 0.6, 0.5, 0.4, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2],
        "persistence":   [0.3, 0.2, 0.1, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "complexity":    [0.4, 0.3, 0.2, 0.5, 0.3, 0.2, 0.1, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "prerequisites": [0.3, 0.2, 0.1, 0.4, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "maturity":      [0.9, 0.9, 0.8, 0.9, 0.7, 0.8, 0.6, 0.5, 0.4, 0.3, 0.9, 0.8, 0.7, 0.6, 0.5, 0.4],
    },
    "CWE-79": {
        "name": "Cross-Site Scripting (XSS)",
        "family": VulnFamily.INJECTION,
        "trigger":       [0.9, 0.7, 0.5, 0.8, 0.6, 0.4, 0.3, 0.7, 0.8, 0.5, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0],
        "propagation":   [0.8, 0.7, 0.6, 0.9, 0.5, 0.4, 0.3, 0.2, 0.7, 0.6, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0],
        "impact":        [0.6, 0.5, 0.7, 0.4, 0.3, 0.8, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0],
        "evasion":       [0.8, 0.7, 0.9, 0.6, 0.5, 0.4, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0],
        "persistence":   [0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0],
        "complexity":    [0.3, 0.2, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "prerequisites": [0.2, 0.1, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "maturity":      [0.9, 0.8, 0.9, 0.7, 0.8, 0.6, 0.5, 0.4, 0.3, 0.9, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3],
    },
    "CWE-78": {
        "name": "OS Command Injection",
        "family": VulnFamily.INJECTION,
        "trigger":       [0.8, 0.7, 0.9, 0.5, 0.4, 0.3, 0.6, 0.8, 0.7, 0.5, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0],
        "propagation":   [0.5, 0.6, 0.7, 0.4, 0.3, 0.8, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0],
        "impact":        [1.0, 1.0, 0.9, 0.9, 0.8, 0.7, 0.9, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0],
        "evasion":       [0.6, 0.5, 0.4, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0],
        "persistence":   [0.2, 0.3, 0.4, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "complexity":    [0.5, 0.4, 0.3, 0.6, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "prerequisites": [0.4, 0.3, 0.5, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "maturity":      [0.8, 0.7, 0.8, 0.6, 0.7, 0.5, 0.4, 0.3, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1],
    },
    "CWE-611": {
        "name": "XXE (XML External Entity)",
        "family": VulnFamily.INJECTION,
        "trigger":       [0.7, 0.8, 0.6, 0.4, 0.3, 0.5, 0.7, 0.6, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0],
        "propagation":   [0.4, 0.5, 0.6, 0.7, 0.3, 0.2, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "impact":        [0.8, 0.7, 0.6, 0.9, 0.5, 0.4, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0],
        "evasion":       [0.5, 0.6, 0.4, 0.3, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0],
        "persistence":   [0.1, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "complexity":    [0.6, 0.5, 0.4, 0.7, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "prerequisites": [0.5, 0.4, 0.6, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "maturity":      [0.7, 0.6, 0.7, 0.5, 0.6, 0.4, 0.3, 0.2, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0],
    },
    "CWE-94": {
        "name": "Code Injection",
        "family": VulnFamily.INJECTION,
        "trigger":       [0.8, 0.9, 0.7, 0.6, 0.5, 0.4, 0.7, 0.8, 0.6, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0],
        "propagation":   [0.6, 0.7, 0.8, 0.5, 0.4, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0],
        "impact":        [1.0, 0.9, 0.9, 0.8, 0.7, 0.9, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0],
        "evasion":       [0.7, 0.6, 0.5, 0.8, 0.6, 0.5, 0.4, 0.3, 0.2, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0],
        "persistence":   [0.4, 0.3, 0.5, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "complexity":    [0.6, 0.5, 0.7, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "prerequisites": [0.5, 0.4, 0.6, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "maturity":      [0.7, 0.8, 0.7, 0.6, 0.7, 0.5, 0.4, 0.3, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0],
    },

    # ── AUTHENTICATION FAMILY ─────────────────────────────────────────────
    "CWE-287": {
        "name": "Improper Authentication",
        "family": VulnFamily.AUTHENTICATION,
        "trigger":       [0.6, 0.5, 0.4, 0.7, 0.8, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0],
        "propagation":   [0.7, 0.6, 0.5, 0.4, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0],
        "impact":        [0.8, 0.9, 0.7, 0.8, 0.6, 0.5, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0],
        "evasion":       [0.4, 0.3, 0.2, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0],
        "persistence":   [0.6, 0.5, 0.7, 0.4, 0.3, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "complexity":    [0.3, 0.2, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "prerequisites": [0.2, 0.1, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "maturity":      [0.8, 0.7, 0.8, 0.6, 0.7, 0.5, 0.4, 0.3, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1],
    },
    "CWE-798": {
        "name": "Hardcoded Credentials",
        "family": VulnFamily.AUTHENTICATION,
        "trigger":       [0.3, 0.2, 0.1, 0.4, 0.5, 0.6, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "propagation":   [0.5, 0.4, 0.3, 0.6, 0.7, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "impact":        [0.9, 0.8, 0.7, 0.8, 0.7, 0.6, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0],
        "evasion":       [0.2, 0.1, 0.0, 0.1, 0.2, 0.1, 0.0, 0.0, 0.0, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "persistence":   [0.9, 0.8, 0.9, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "complexity":    [0.1, 0.1, 0.0, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "prerequisites": [0.1, 0.1, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "maturity":      [0.8, 0.9, 0.7, 0.8, 0.6, 0.5, 0.4, 0.3, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1],
    },

    # ── AUTHORIZATION FAMILY ──────────────────────────────────────────────
    "CWE-639": {
        "name": "IDOR (Insecure Direct Object Reference)",
        "family": VulnFamily.AUTHORIZATION,
        "trigger":       [0.7, 0.6, 0.5, 0.8, 0.4, 0.3, 0.6, 0.7, 0.5, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0],
        "propagation":   [0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0],
        "impact":        [0.7, 0.8, 0.6, 0.7, 0.5, 0.4, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0],
        "evasion":       [0.3, 0.2, 0.1, 0.2, 0.3, 0.2, 0.1, 0.0, 0.0, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0],
        "persistence":   [0.1, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "complexity":    [0.2, 0.1, 0.2, 0.3, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "prerequisites": [0.4, 0.3, 0.5, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "maturity":      [0.7, 0.6, 0.7, 0.5, 0.6, 0.4, 0.3, 0.2, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0],
    },
    "CWE-269": {
        "name": "Privilege Escalation",
        "family": VulnFamily.AUTHORIZATION,
        "trigger":       [0.6, 0.7, 0.5, 0.4, 0.6, 0.7, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0],
        "propagation":   [0.9, 0.8, 0.7, 0.6, 0.5, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0],
        "impact":        [0.9, 0.9, 0.8, 0.9, 0.7, 0.6, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0],
        "evasion":       [0.5, 0.4, 0.3, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0],
        "persistence":   [0.5, 0.4, 0.6, 0.3, 0.2, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "complexity":    [0.7, 0.6, 0.5, 0.7, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "prerequisites": [0.6, 0.5, 0.7, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "maturity":      [0.7, 0.6, 0.7, 0.5, 0.6, 0.4, 0.3, 0.2, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0],
    },

    # ── FILE OPERATION FAMILY ─────────────────────────────────────────────
    "CWE-22": {
        "name": "Path Traversal",
        "family": VulnFamily.FILE_OPERATION,
        "trigger":       [0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.7, 0.8, 0.6, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0],
        "propagation":   [0.4, 0.5, 0.3, 0.4, 0.3, 0.2, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0],
        "impact":        [0.7, 0.6, 0.8, 0.5, 0.4, 0.3, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0],
        "evasion":       [0.6, 0.7, 0.5, 0.4, 0.6, 0.5, 0.4, 0.3, 0.2, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0],
        "persistence":   [0.1, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "complexity":    [0.3, 0.2, 0.3, 0.4, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "prerequisites": [0.2, 0.1, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "maturity":      [0.8, 0.7, 0.8, 0.6, 0.7, 0.5, 0.4, 0.3, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1],
    },
    "CWE-434": {
        "name": "Unrestricted File Upload",
        "family": VulnFamily.FILE_OPERATION,
        "trigger":       [0.7, 0.6, 0.8, 0.5, 0.4, 0.3, 0.6, 0.7, 0.5, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0],
        "propagation":   [0.5, 0.6, 0.7, 0.4, 0.3, 0.5, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0],
        "impact":        [0.9, 0.8, 0.9, 0.7, 0.6, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0],
        "evasion":       [0.7, 0.6, 0.5, 0.8, 0.6, 0.5, 0.4, 0.3, 0.2, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0],
        "persistence":   [0.7, 0.6, 0.8, 0.5, 0.4, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0],
        "complexity":    [0.4, 0.3, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "prerequisites": [0.3, 0.2, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "maturity":      [0.7, 0.6, 0.7, 0.5, 0.6, 0.4, 0.3, 0.2, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0],
    },

    # ── SSRF FAMILY ───────────────────────────────────────────────────────
    "CWE-918": {
        "name": "Server-Side Request Forgery (SSRF)",
        "family": VulnFamily.SSRF,
        "trigger":       [0.7, 0.8, 0.6, 0.5, 0.4, 0.3, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0],
        "propagation":   [0.7, 0.6, 0.8, 0.5, 0.4, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0],
        "impact":        [0.8, 0.7, 0.6, 0.9, 0.5, 0.4, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0],
        "evasion":       [0.6, 0.7, 0.5, 0.4, 0.6, 0.5, 0.4, 0.3, 0.2, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0],
        "persistence":   [0.1, 0.1, 0.0, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "complexity":    [0.5, 0.4, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "prerequisites": [0.3, 0.2, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "maturity":      [0.8, 0.7, 0.8, 0.6, 0.7, 0.5, 0.4, 0.3, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1],
    },

    # ── DESERIALIZATION FAMILY ────────────────────────────────────────────
    "CWE-502": {
        "name": "Insecure Deserialization",
        "family": VulnFamily.DESERIALIZATION,
        "trigger":       [0.6, 0.7, 0.8, 0.5, 0.4, 0.3, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0],
        "propagation":   [0.5, 0.6, 0.7, 0.4, 0.3, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "impact":        [1.0, 0.9, 0.9, 0.8, 0.7, 0.9, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0],
        "evasion":       [0.7, 0.6, 0.5, 0.8, 0.6, 0.5, 0.4, 0.3, 0.2, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0],
        "persistence":   [0.3, 0.2, 0.4, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "complexity":    [0.8, 0.7, 0.6, 0.8, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "prerequisites": [0.6, 0.5, 0.7, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "maturity":      [0.6, 0.5, 0.6, 0.4, 0.5, 0.3, 0.2, 0.1, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0],
    },

    # ── CRYPTOGRAPHIC FAMILY ──────────────────────────────────────────────
    "CWE-327": {
        "name": "Broken Cryptographic Algorithm",
        "family": VulnFamily.CRYPTOGRAPHIC,
        "trigger":       [0.4, 0.3, 0.2, 0.5, 0.6, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "propagation":   [0.3, 0.4, 0.2, 0.3, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "impact":        [0.8, 0.9, 0.7, 0.6, 0.5, 0.4, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0],
        "evasion":       [0.2, 0.1, 0.0, 0.1, 0.2, 0.1, 0.0, 0.0, 0.0, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "persistence":   [0.8, 0.7, 0.9, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "complexity":    [0.7, 0.6, 0.8, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "prerequisites": [0.5, 0.4, 0.6, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "maturity":      [0.6, 0.5, 0.6, 0.4, 0.5, 0.3, 0.2, 0.1, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0],
    },

    # ── CONFIGURATION FAMILY ──────────────────────────────────────────────
    "CWE-16": {
        "name": "Security Misconfiguration",
        "family": VulnFamily.CONFIGURATION,
        "trigger":       [0.3, 0.2, 0.1, 0.4, 0.5, 0.6, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "propagation":   [0.5, 0.4, 0.3, 0.6, 0.4, 0.3, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0],
        "impact":        [0.6, 0.5, 0.4, 0.7, 0.5, 0.4, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0],
        "evasion":       [0.1, 0.1, 0.0, 0.1, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "persistence":   [0.9, 0.8, 0.9, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "complexity":    [0.1, 0.1, 0.0, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "prerequisites": [0.1, 0.1, 0.0, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "maturity":      [0.9, 0.8, 0.9, 0.7, 0.8, 0.6, 0.5, 0.4, 0.9, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2],
    },

    # ── API FAMILY ────────────────────────────────────────────────────────
    "CWE-1321": {
        "name": "Mass Assignment / Prototype Pollution",
        "family": VulnFamily.API,
        "trigger":       [0.6, 0.7, 0.5, 0.8, 0.4, 0.3, 0.5, 0.6, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0],
        "propagation":   [0.7, 0.6, 0.5, 0.4, 0.3, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0],
        "impact":        [0.7, 0.8, 0.6, 0.7, 0.5, 0.4, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0],
        "evasion":       [0.4, 0.3, 0.2, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0],
        "persistence":   [0.3, 0.2, 0.4, 0.2, 0.1, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "complexity":    [0.4, 0.3, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "prerequisites": [0.3, 0.2, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "maturity":      [0.6, 0.5, 0.6, 0.4, 0.5, 0.3, 0.2, 0.1, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0],
    },

    # ── MEMORY FAMILY ─────────────────────────────────────────────────────
    "CWE-120": {
        "name": "Buffer Overflow",
        "family": VulnFamily.MEMORY,
        "trigger":       [0.6, 0.5, 0.7, 0.4, 0.3, 0.2, 0.5, 0.6, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0],
        "propagation":   [0.4, 0.3, 0.5, 0.6, 0.7, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "impact":        [1.0, 1.0, 0.9, 0.9, 0.8, 0.7, 0.9, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0],
        "evasion":       [0.5, 0.4, 0.3, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0],
        "persistence":   [0.2, 0.1, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "complexity":    [0.8, 0.7, 0.9, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "prerequisites": [0.7, 0.6, 0.8, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "maturity":      [0.7, 0.6, 0.7, 0.5, 0.6, 0.4, 0.3, 0.2, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0],
    },

    # ── BUSINESS LOGIC FAMILY ─────────────────────────────────────────────
    "CWE-362": {
        "name": "Race Condition",
        "family": VulnFamily.BUSINESS_LOGIC,
        "trigger":       [0.5, 0.6, 0.4, 0.3, 0.7, 0.8, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0],
        "propagation":   [0.4, 0.3, 0.5, 0.4, 0.3, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "impact":        [0.7, 0.6, 0.5, 0.8, 0.6, 0.5, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0],
        "evasion":       [0.8, 0.7, 0.6, 0.5, 0.7, 0.6, 0.5, 0.4, 0.3, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0],
        "persistence":   [0.1, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "complexity":    [0.8, 0.7, 0.9, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "prerequisites": [0.5, 0.4, 0.6, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "maturity":      [0.5, 0.4, 0.5, 0.3, 0.4, 0.2, 0.1, 0.0, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0],
    },

    # ── INFORMATION DISCLOSURE ────────────────────────────────────────────
    "CWE-200": {
        "name": "Information Exposure",
        "family": VulnFamily.INFORMATION,
        "trigger":       [0.4, 0.3, 0.2, 0.5, 0.6, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "propagation":   [0.3, 0.2, 0.4, 0.3, 0.2, 0.3, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "impact":        [0.4, 0.3, 0.5, 0.3, 0.2, 0.3, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "evasion":       [0.1, 0.1, 0.0, 0.1, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "persistence":   [0.8, 0.7, 0.8, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "complexity":    [0.1, 0.1, 0.0, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "prerequisites": [0.1, 0.1, 0.0, 0.1, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "maturity":      [0.9, 0.8, 0.9, 0.7, 0.8, 0.6, 0.5, 0.4, 0.9, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2],
    },
}

# Known evolutionary lineages: parent CWE → child CWE mutations
KNOWN_LINEAGES: Dict[str, List[Dict[str, Any]]] = {
    "CWE-89": [
        {"child": "CWE-89.blind", "mutation": MutationType.BLOCK, "pressure": EvolutionPressure.WAF_EVASION,
         "desc": "Blind SQLi: response-based detection removed, timing/boolean inference added"},
        {"child": "CWE-89.second_order", "mutation": MutationType.INSERTION, "pressure": EvolutionPressure.PATCH_BYPASS,
         "desc": "Second-order SQLi: payload stored, executed in different context"},
        {"child": "CWE-89.nosql", "mutation": MutationType.FRAMESHIFT, "pressure": EvolutionPressure.TECHNOLOGY_SHIFT,
         "desc": "NoSQL Injection: paradigm shift from SQL to document queries"},
    ],
    "CWE-79": [
        {"child": "CWE-79.stored", "mutation": MutationType.INSERTION, "pressure": EvolutionPressure.PATCH_BYPASS,
         "desc": "Stored XSS: persistence gene activated"},
        {"child": "CWE-79.dom", "mutation": MutationType.FRAMESHIFT, "pressure": EvolutionPressure.FRAMEWORK_ADOPTION,
         "desc": "DOM XSS: server-side → client-side paradigm shift"},
        {"child": "CWE-79.mutation", "mutation": MutationType.BLOCK, "pressure": EvolutionPressure.WAF_EVASION,
         "desc": "mXSS: browser mutation engine exploited for filter bypass"},
    ],
    "CWE-22": [
        {"child": "CWE-98", "mutation": MutationType.CROSSOVER, "pressure": EvolutionPressure.VERSION_UPGRADE,
         "desc": "RFI: path traversal crossed with remote inclusion"},
        {"child": "CWE-22.zip_slip", "mutation": MutationType.INSERTION, "pressure": EvolutionPressure.FRAMEWORK_ADOPTION,
         "desc": "Zip Slip: archive extraction path traversal variant"},
    ],
    "CWE-918": [
        {"child": "CWE-918.blind", "mutation": MutationType.BLOCK, "pressure": EvolutionPressure.WAF_EVASION,
         "desc": "Blind SSRF: no direct response, side-channel inference"},
        {"child": "CWE-918.cloud", "mutation": MutationType.CROSSOVER, "pressure": EvolutionPressure.CLOUD_MIGRATION,
         "desc": "Cloud SSRF: targeting metadata endpoints (169.254.169.254)"},
    ],
    "CWE-502": [
        {"child": "CWE-502.gadget_chain", "mutation": MutationType.CROSSOVER, "pressure": EvolutionPressure.PATCH_BYPASS,
         "desc": "Gadget chain: combining classes for arbitrary code execution"},
        {"child": "CWE-502.polyglot", "mutation": MutationType.INSERTION, "pressure": EvolutionPressure.WAF_EVASION,
         "desc": "Polyglot deserialization: valid in multiple formats simultaneously"},
    ],
}


# ════════════════════════════════════════════════════════════════════════════════
# CORE ENGINE: DNAExtractor
# ════════════════════════════════════════════════════════════════════════════════


class DNAExtractor:
    """Extracts VulnGenome vectors from various vulnerability data sources.

    Can extract DNA from:
    - CWE identifiers (using template KB)
    - CVE descriptions (NLP-free pattern matching)
    - Scan results (behavioral fingerprinting)
    - Raw exploit code (static analysis patterns)
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._extraction_count = 0
        self._custom_templates: Dict[str, Dict[str, Any]] = {}

    def extract_from_cwe(self, cwe_id: str, **overrides: Any) -> VulnGenome:
        """Extract genome from a known CWE template.

        Args:
            cwe_id: CWE identifier (e.g., 'CWE-89')
            **overrides: Override specific fields (cvss_score, epss_score, etc.)
        """
        template = CWE_GENOME_TEMPLATES.get(cwe_id) or self._custom_templates.get(cwe_id)
        if template is None:
            return self._extract_unknown_cwe(cwe_id, **overrides)

        genome = VulnGenome(
            vuln_id=f"{cwe_id}_{int(time.time() * 1000)}",
            family=template.get("family", VulnFamily.UNKNOWN),
            cwe_ids=[cwe_id],
            description=template.get("name", cwe_id),
        )

        # Load block vectors from template
        block_keys = ["trigger", "propagation", "impact", "evasion",
                      "persistence", "complexity", "prerequisites", "maturity"]
        for block_enum, key in zip(GeneBlock, block_keys):
            if key in template:
                genome.set_block(block_enum, template[key])

        # Apply overrides
        for attr, val in overrides.items():
            if hasattr(genome, attr):
                setattr(genome, attr, val)

        with self._lock:
            self._extraction_count += 1

        return genome

    def _extract_unknown_cwe(self, cwe_id: str, **overrides: Any) -> VulnGenome:
        """Generate a reasonable genome for an unknown CWE using heuristics."""
        genome = VulnGenome(
            vuln_id=f"{cwe_id}_{int(time.time() * 1000)}",
            family=VulnFamily.UNKNOWN,
            cwe_ids=[cwe_id],
            description=f"Unknown vulnerability class: {cwe_id}",
        )

        # Use CWE number as seed for deterministic but varied genome
        try:
            cwe_num = int(cwe_id.split("-")[1])
        except (IndexError, ValueError):
            cwe_num = hash(cwe_id) & 0xFFFF

        rng = random.Random(cwe_num)
        for i in range(GENOME_DIMENSIONS):
            genome.genes[i].value = rng.random() * 0.5  # Conservative values for unknown

        for attr, val in overrides.items():
            if hasattr(genome, attr):
                setattr(genome, attr, val)

        return genome

    def extract_from_scan_result(self, scan_data: Dict[str, Any]) -> VulnGenome:
        """Extract genome from a scan finding.

        Expects scan_data with keys like:
        - vuln_type, severity, confidence
        - evidence (list of indicators)
        - technology, version
        - cwe_id, cvss_score
        """
        cwe_id = scan_data.get("cwe_id", "")
        if cwe_id and cwe_id in CWE_GENOME_TEMPLATES:
            genome = self.extract_from_cwe(cwe_id)
        else:
            genome = VulnGenome(
                vuln_id=f"scan_{hashlib.sha256(json.dumps(scan_data, sort_keys=True, default=str).encode()).hexdigest()[:16]}",
                family=self._classify_family(scan_data),
            )

        # Modulate genome based on scan specifics
        genome.cvss_score = scan_data.get("cvss_score", 0.0)
        genome.epss_score = scan_data.get("epss_score", 0.0)
        genome.description = scan_data.get("description", scan_data.get("vuln_type", ""))

        if cwe_id:
            genome.cwe_ids = [cwe_id]

        # Adjust evasion block based on WAF/CDN detection
        if scan_data.get("waf_detected"):
            evasion = genome.get_block_vector(GeneBlock.EVASION)
            evasion = [min(1.0, v + 0.2) for v in evasion]
            genome.set_block(GeneBlock.EVASION, evasion)

        # Adjust complexity based on auth requirements
        if scan_data.get("auth_required"):
            complexity = genome.get_block_vector(GeneBlock.COMPLEXITY)
            complexity = [min(1.0, v + 0.15) for v in complexity]
            genome.set_block(GeneBlock.COMPLEXITY, complexity)

        # Adjust maturity based on known exploits
        if scan_data.get("exploit_available"):
            maturity = genome.get_block_vector(GeneBlock.MATURITY)
            maturity = [min(1.0, v + 0.3) for v in maturity]
            genome.set_block(GeneBlock.MATURITY, maturity)

        with self._lock:
            self._extraction_count += 1

        return genome

    def extract_from_description(self, description: str, cwe_id: str = "") -> VulnGenome:
        """Extract genome from a textual vulnerability description.

        Uses keyword pattern matching (no external NLP needed).
        """
        desc_lower = description.lower()

        # Pattern → family classification
        family_patterns: Dict[VulnFamily, List[str]] = {
            VulnFamily.INJECTION: ["inject", "sqli", "xss", "script", "command", "eval", "exec", "template"],
            VulnFamily.AUTHENTICATION: ["auth", "login", "password", "credential", "session", "token", "jwt"],
            VulnFamily.AUTHORIZATION: ["idor", "privilege", "escalat", "access control", "permission", "bola"],
            VulnFamily.CRYPTOGRAPHIC: ["crypt", "cipher", "hash", "encrypt", "ssl", "tls", "key", "padding"],
            VulnFamily.CONFIGURATION: ["misconfig", "default", "exposed", "debug", "verbose", "admin panel"],
            VulnFamily.INFORMATION: ["info", "leak", "disclosure", "stack trace", "error message", "directory"],
            VulnFamily.BUSINESS_LOGIC: ["race", "workflow", "logic", "price", "quantity", "bypass validation"],
            VulnFamily.MEMORY: ["buffer", "overflow", "heap", "stack", "use-after-free", "format string"],
            VulnFamily.DESERIALIZATION: ["deserializ", "pickle", "marshal", "gadget", "object injection"],
            VulnFamily.SSRF: ["ssrf", "server-side request", "internal", "metadata", "169.254"],
            VulnFamily.FILE_OPERATION: ["file", "upload", "path", "traversal", "include", "lfi", "rfi"],
            VulnFamily.API: ["api", "graphql", "mass assignment", "rate limit", "rest", "endpoint"],
            VulnFamily.SUPPLY_CHAIN: ["supply chain", "dependency", "package", "npm", "pip", "typosquat"],
        }

        detected_family = VulnFamily.UNKNOWN
        max_matches = 0
        for family, patterns in family_patterns.items():
            matches = sum(1 for p in patterns if p in desc_lower)
            if matches > max_matches:
                max_matches = matches
                detected_family = family

        # Try CWE template first
        if cwe_id and cwe_id in CWE_GENOME_TEMPLATES:
            genome = self.extract_from_cwe(cwe_id)
            genome.description = description
            return genome

        genome = VulnGenome(
            vuln_id=f"desc_{hashlib.sha256(description.encode()).hexdigest()[:16]}",
            family=detected_family,
            description=description,
            cwe_ids=[cwe_id] if cwe_id else [],
        )

        # Modulate blocks based on description keywords
        self._modulate_from_keywords(genome, desc_lower)

        with self._lock:
            self._extraction_count += 1

        return genome

    def _classify_family(self, scan_data: Dict[str, Any]) -> VulnFamily:
        """Classify vulnerability family from scan data."""
        vuln_type = scan_data.get("vuln_type", "").lower()
        family_map = {
            "sqli": VulnFamily.INJECTION, "xss": VulnFamily.INJECTION,
            "command": VulnFamily.INJECTION, "inject": VulnFamily.INJECTION,
            "auth": VulnFamily.AUTHENTICATION, "session": VulnFamily.AUTHENTICATION,
            "idor": VulnFamily.AUTHORIZATION, "privesc": VulnFamily.AUTHORIZATION,
            "crypto": VulnFamily.CRYPTOGRAPHIC, "ssl": VulnFamily.CRYPTOGRAPHIC,
            "misconfig": VulnFamily.CONFIGURATION, "default": VulnFamily.CONFIGURATION,
            "info": VulnFamily.INFORMATION, "leak": VulnFamily.INFORMATION,
            "race": VulnFamily.BUSINESS_LOGIC, "logic": VulnFamily.BUSINESS_LOGIC,
            "overflow": VulnFamily.MEMORY, "buffer": VulnFamily.MEMORY,
            "deserial": VulnFamily.DESERIALIZATION, "pickle": VulnFamily.DESERIALIZATION,
            "ssrf": VulnFamily.SSRF, "file": VulnFamily.FILE_OPERATION,
            "upload": VulnFamily.FILE_OPERATION, "traversal": VulnFamily.FILE_OPERATION,
            "api": VulnFamily.API, "graphql": VulnFamily.API,
        }
        for key, family in family_map.items():
            if key in vuln_type:
                return family
        return VulnFamily.UNKNOWN

    def _modulate_from_keywords(self, genome: VulnGenome, text: str) -> None:
        """Adjust genome blocks based on keyword presence in text."""
        # Impact signals
        impact_signals = {
            "rce": 0.9, "remote code": 0.9, "arbitrary code": 0.9,
            "data breach": 0.8, "exfiltrat": 0.8, "dump": 0.7,
            "denial of service": 0.6, "dos": 0.5, "crash": 0.4,
        }
        impact_boost = 0.0
        for kw, weight in impact_signals.items():
            if kw in text:
                impact_boost = max(impact_boost, weight)
        if impact_boost > 0:
            current = genome.get_block_vector(GeneBlock.IMPACT)
            genome.set_block(GeneBlock.IMPACT, [min(1.0, v + impact_boost * 0.3) for v in current])

        # Evasion signals
        evasion_signals = ["waf bypass", "filter evasion", "encoding", "obfuscat",
                           "polyglot", "double encoding", "null byte"]
        evasion_count = sum(1 for s in evasion_signals if s in text)
        if evasion_count > 0:
            current = genome.get_block_vector(GeneBlock.EVASION)
            boost = min(0.5, evasion_count * 0.1)
            genome.set_block(GeneBlock.EVASION, [min(1.0, v + boost) for v in current])

        # Complexity signals
        complexity_signals = ["authenticated", "admin access", "multi-step",
                              "chain", "prerequisite", "specific version"]
        complexity_count = sum(1 for s in complexity_signals if s in text)
        if complexity_count > 0:
            current = genome.get_block_vector(GeneBlock.COMPLEXITY)
            boost = min(0.5, complexity_count * 0.1)
            genome.set_block(GeneBlock.COMPLEXITY, [min(1.0, v + boost) for v in current])

    def register_custom_template(self, cwe_id: str, template: Dict[str, Any]) -> None:
        """Register a custom CWE genome template."""
        with self._lock:
            self._custom_templates[cwe_id] = template

    @property
    def extraction_count(self) -> int:
        with self._lock:
            return self._extraction_count


# ════════════════════════════════════════════════════════════════════════════════
# CORE ENGINE: GeneticComparator
# ════════════════════════════════════════════════════════════════════════════════


class GeneticComparator:
    """Compares vulnerability genomes to find families, variants, and relationships.

    Implements:
    - Cosine similarity (overall and per-block)
    - Euclidean distance
    - Phylogenetic distance (weighted block differences)
    - K-nearest neighbors in genome space
    - Cluster detection via DBSCAN-like algorithm
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # Manual LRU cache — VulnGenome is unhashable so we key on
        # fingerprint tuples and evict oldest entries beyond the limit.
        self._comparison_cache: OrderedDict[Tuple[str, str], float] = OrderedDict()
        self._phylo_cache: OrderedDict[Tuple[str, str], float] = OrderedDict()
        self._cache_max_size: int = PHYLO_DISTANCE_CACHE  # 4096

    # -- helpers for bounded OrderedDict caches --

    @staticmethod
    def _cache_get(
        cache: OrderedDict, key: Tuple[str, str]
    ) -> Optional[float]:
        """Retrieve from an OrderedDict LRU cache (moves key to end)."""
        if key in cache:
            cache.move_to_end(key)
            return cache[key]
        return None

    def _cache_put(
        self, cache: OrderedDict, key: Tuple[str, str], value: float
    ) -> None:
        """Insert into an OrderedDict LRU cache, evicting oldest if full."""
        cache[key] = value
        cache.move_to_end(key)
        while len(cache) > self._cache_max_size:
            cache.popitem(last=False)

    def cosine_similarity(self, a: VulnGenome, b: VulnGenome) -> float:
        """Cosine similarity between two genome vectors.

        Returns value in [0.0, 1.0] where 1.0 = identical DNA.
        Uses a manual dict-based LRU cache (max 4096 entries) keyed on
        genome fingerprints because VulnGenome dataclass instances are
        not hashable and therefore incompatible with functools.lru_cache.
        """
        cache_key = (a.fingerprint(), b.fingerprint())
        with self._lock:
            cached = self._cache_get(self._comparison_cache, cache_key)
            if cached is not None:
                return cached

        va, vb = a.vector, b.vector
        dot = sum(x * y for x, y in zip(va, vb))
        mag_a = math.sqrt(sum(x * x for x in va)) + EPSILON
        mag_b = math.sqrt(sum(x * x for x in vb)) + EPSILON
        sim = dot / (mag_a * mag_b)

        with self._lock:
            self._cache_put(self._comparison_cache, cache_key, sim)

        return sim

    def block_similarity(self, a: VulnGenome, b: VulnGenome, block: GeneBlock) -> float:
        """Cosine similarity for a specific gene block (16 dims)."""
        va = a.get_block_vector(block)
        vb = b.get_block_vector(block)
        dot = sum(x * y for x, y in zip(va, vb))
        mag_a = math.sqrt(sum(x * x for x in va)) + EPSILON
        mag_b = math.sqrt(sum(x * x for x in vb)) + EPSILON
        return dot / (mag_a * mag_b)

    def all_block_similarities(self, a: VulnGenome, b: VulnGenome) -> Dict[GeneBlock, float]:
        """Get similarity for every gene block."""
        return {block: self.block_similarity(a, b, block) for block in GeneBlock}

    def euclidean_distance(self, a: VulnGenome, b: VulnGenome) -> float:
        """Euclidean distance between genome vectors."""
        va, vb = a.vector, b.vector
        return math.sqrt(sum((x - y) ** 2 for x, y in zip(va, vb)))

    def phylogenetic_distance(self, a: VulnGenome, b: VulnGenome) -> float:
        """Weighted phylogenetic distance emphasizing functional blocks.

        Blocks are weighted by their importance for evolutionary analysis:
        TRIGGER and IMPACT are weighted highest as they define the vuln's "phenotype".

        Results are cached in a manual LRU dict (max 4096 entries) keyed on
        genome fingerprints because VulnGenome is not hashable.
        """
        cache_key = (a.fingerprint(), b.fingerprint())
        with self._lock:
            cached = self._cache_get(self._phylo_cache, cache_key)
            if cached is not None:
                return cached

        block_weights = {
            GeneBlock.TRIGGER: 2.0,
            GeneBlock.PROPAGATION: 1.5,
            GeneBlock.IMPACT: 2.0,
            GeneBlock.EVASION: 1.0,
            GeneBlock.PERSISTENCE: 0.8,
            GeneBlock.COMPLEXITY: 0.5,
            GeneBlock.PREREQUISITES: 0.5,
            GeneBlock.MATURITY: 0.3,
        }

        total_dist = 0.0
        total_weight = 0.0

        for block, weight in block_weights.items():
            sim = self.block_similarity(a, b, block)
            dist = 1.0 - sim
            total_dist += dist * weight
            total_weight += weight

        result = total_dist / total_weight if total_weight > 0 else 1.0

        with self._lock:
            self._cache_put(self._phylo_cache, cache_key, result)

        return result

    def is_same_family(self, a: VulnGenome, b: VulnGenome) -> bool:
        """Determine if two genomes belong to the same vulnerability family."""
        return self.cosine_similarity(a, b) >= SIMILARITY_THRESHOLD

    def is_variant(self, a: VulnGenome, b: VulnGenome) -> bool:
        """Determine if b is a variant (mutation) of a."""
        sim = self.cosine_similarity(a, b)
        return (1.0 - MUTATION_THRESHOLD) <= sim < SIMILARITY_THRESHOLD

    def find_nearest(
        self, target: VulnGenome, population: List[VulnGenome], k: int = 5
    ) -> List[Tuple[VulnGenome, float]]:
        """Find K nearest genomes by cosine similarity."""
        scored = [(g, self.cosine_similarity(target, g)) for g in population]
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:k]

    def cluster_genomes(
        self, genomes: List[VulnGenome], eps: float = 0.3, min_samples: int = 2
    ) -> Dict[int, List[VulnGenome]]:
        """DBSCAN-like clustering of genomes in DNA space.

        Args:
            genomes: Population to cluster
            eps: Maximum phylogenetic distance for neighborhood
            min_samples: Min genomes for a core point
        Returns:
            Dict mapping cluster_id → list of genomes. Cluster -1 = noise.
        """
        n = len(genomes)
        labels = [-1] * n  # -1 = unvisited/noise
        cluster_id = 0

        def neighborhood(idx: int) -> List[int]:
            return [
                j for j in range(n) if j != idx
                and self.phylogenetic_distance(genomes[idx], genomes[j]) <= eps
            ]

        visited = [False] * n

        for i in range(n):
            if visited[i]:
                continue
            visited[i] = True
            neighbors = neighborhood(i)

            if len(neighbors) < min_samples:
                labels[i] = -1  # Noise
                continue

            labels[i] = cluster_id
            seed_set = list(neighbors)

            while seed_set:
                q = seed_set.pop(0)
                if not visited[q]:
                    visited[q] = True
                    q_neighbors = neighborhood(q)
                    if len(q_neighbors) >= min_samples:
                        seed_set.extend(q_neighbors)
                if labels[q] == -1:
                    labels[q] = cluster_id

            cluster_id += 1

        clusters: Dict[int, List[VulnGenome]] = defaultdict(list)
        for i, label in enumerate(labels):
            clusters[label].append(genomes[i])

        return dict(clusters)


# ════════════════════════════════════════════════════════════════════════════════
# CORE ENGINE: LineageTracker
# ════════════════════════════════════════════════════════════════════════════════


class LineageTracker:
    """Tracks the evolutionary genealogy of vulnerabilities.

    Builds phylogenetic trees showing how vulns evolved:
    RFI → LFI → Path Traversal → Zip Slip → RCE
    SQLi → Blind SQLi → Time-based → NoSQL Injection
    """

    def __init__(self, comparator: Optional[GeneticComparator] = None) -> None:
        self._lock = threading.RLock()
        self._genomes: Dict[str, VulnGenome] = {}
        self._tree_roots: Dict[str, PhylogeneticNode] = {}
        self._nodes: Dict[str, PhylogeneticNode] = {}
        self._comparator = comparator or GeneticComparator()
        self._relationships: Dict[str, Dict[str, LineageRelation]] = defaultdict(dict)

    def register_genome(self, genome: VulnGenome) -> None:
        """Register a genome in the lineage tracker."""
        with self._lock:
            self._genomes[genome.vuln_id] = genome
            node = PhylogeneticNode(genome_id=genome.vuln_id, genome=genome)
            self._nodes[genome.vuln_id] = node

            if genome.parent_id and genome.parent_id in self._nodes:
                parent_node = self._nodes[genome.parent_id]
                node.parent = parent_node
                node.branch_length = self._comparator.phylogenetic_distance(
                    parent_node.genome, genome
                )
                parent_node.children.append(node)
                self._relationships[genome.parent_id][genome.vuln_id] = LineageRelation.CHILD
                self._relationships[genome.vuln_id][genome.parent_id] = LineageRelation.PARENT
            else:
                self._tree_roots[genome.vuln_id] = node

    def get_lineage(self, genome_id: str) -> List[VulnGenome]:
        """Get full ancestry chain from root to this genome."""
        with self._lock:
            node = self._nodes.get(genome_id)
            if not node:
                return []
            chain: List[VulnGenome] = []
            current = node
            while current is not None:
                chain.append(current.genome)
                current = current.parent
            chain.reverse()
            return chain

    def get_descendants(self, genome_id: str) -> List[VulnGenome]:
        """Get all descendants of a genome."""
        with self._lock:
            node = self._nodes.get(genome_id)
            if not node:
                return []
            return [d.genome for d in node.get_descendants()]

    def get_siblings(self, genome_id: str) -> List[VulnGenome]:
        """Get sibling genomes (same parent)."""
        with self._lock:
            node = self._nodes.get(genome_id)
            if not node or not node.parent:
                return []
            return [
                c.genome for c in node.parent.children
                if c.genome_id != genome_id
            ]

    def find_common_ancestor(self, id_a: str, id_b: str) -> Optional[VulnGenome]:
        """Find the most recent common ancestor of two genomes."""
        with self._lock:
            ancestors_a: Set[str] = set()
            node = self._nodes.get(id_a)
            while node:
                ancestors_a.add(node.genome_id)
                node = node.parent

            node = self._nodes.get(id_b)
            while node:
                if node.genome_id in ancestors_a:
                    return node.genome
                node = node.parent
            return None

    def infer_relationship(self, id_a: str, id_b: str) -> LineageRelation:
        """Infer the evolutionary relationship between two genomes."""
        with self._lock:
            # Check cached relationship
            if id_b in self._relationships.get(id_a, {}):
                return self._relationships[id_a][id_b]

            genome_a = self._genomes.get(id_a)
            genome_b = self._genomes.get(id_b)
            if not genome_a or not genome_b:
                return LineageRelation.DIVERGENT

            # Direct parent/child
            if genome_b.parent_id == id_a:
                return LineageRelation.CHILD
            if genome_a.parent_id == id_b:
                return LineageRelation.PARENT

            # Siblings (same parent)
            if genome_a.parent_id and genome_a.parent_id == genome_b.parent_id:
                return LineageRelation.SIBLING

            # Cousins (shared grandparent)
            common = self.find_common_ancestor(id_a, id_b)
            if common:
                return LineageRelation.COUSIN

            # Convergent evolution (similar DNA, no shared lineage)
            sim = self._comparator.cosine_similarity(genome_a, genome_b)
            if sim > SIMILARITY_THRESHOLD:
                return LineageRelation.CONVERGENT

            return LineageRelation.DIVERGENT

    def build_phylogenetic_tree(self, genomes: Optional[List[VulnGenome]] = None) -> List[PhylogeneticNode]:
        """Build phylogenetic tree from scratch using UPGMA-like algorithm.

        Uses pairwise phylogenetic distances to construct the tree.
        """
        targets = genomes or list(self._genomes.values())
        if len(targets) < 2:
            return [self._nodes[g.vuln_id] for g in targets if g.vuln_id in self._nodes]

        # Distance matrix
        n = len(targets)
        dist = [[0.0] * n for _ in range(n)]
        for i in range(n):
            for j in range(i + 1, n):
                d = self._comparator.phylogenetic_distance(targets[i], targets[j])
                dist[i][j] = d
                dist[j][i] = d

        # UPGMA clustering
        clusters: Dict[int, List[int]] = {i: [i] for i in range(n)}
        active = set(range(n))

        while len(active) > 1:
            # Find closest pair
            min_d = float("inf")
            ci, cj = -1, -1
            active_list = sorted(active)
            for idx_a in range(len(active_list)):
                for idx_b in range(idx_a + 1, len(active_list)):
                    a, b = active_list[idx_a], active_list[idx_b]
                    avg_dist = self._avg_cluster_distance(dist, clusters[a], clusters[b])
                    if avg_dist < min_d:
                        min_d = avg_dist
                        ci, cj = a, b

            if ci == -1:
                break

            # Merge clusters
            clusters[ci] = clusters[ci] + clusters[cj]
            del clusters[cj]
            active.discard(cj)

        # Register parent-child relationships
        for root_idx, members in clusters.items():
            if len(members) > 1:
                root_genome = targets[members[0]]
                for member_idx in members[1:]:
                    member_genome = targets[member_idx]
                    if member_genome.vuln_id not in self._nodes:
                        self.register_genome(member_genome)

        return list(self._tree_roots.values())

    def _avg_cluster_distance(
        self, dist: List[List[float]], cluster_a: List[int], cluster_b: List[int]
    ) -> float:
        """Average distance between two clusters."""
        total = 0.0
        count = 0
        for i in cluster_a:
            for j in cluster_b:
                total += dist[i][j]
                count += 1
        return total / count if count > 0 else float("inf")

    def to_dict(self) -> Dict[str, Any]:
        """Serialize lineage state."""
        return {
            "genomes": {gid: g.to_dict() for gid, g in self._genomes.items()},
            "relationships": {
                k: {kk: vv.value for kk, vv in v.items()}
                for k, v in self._relationships.items()
            },
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LineageTracker":
        """Deserialize lineage state."""
        tracker = cls()
        for gid, gdata in data.get("genomes", {}).items():
            genome = VulnGenome.from_dict(gdata)
            tracker.register_genome(genome)
        return tracker


# ════════════════════════════════════════════════════════════════════════════════
# CORE ENGINE: MutationAnalyzer
# ════════════════════════════════════════════════════════════════════════════════


class MutationAnalyzer:
    """Analyzes mutations between vulnerability variants.

    Given two genomes (parent and child), determines:
    - What type of mutation occurred
    - Which gene blocks were affected
    - What environmental pressure likely caused it
    - How significant the mutation is
    """

    def __init__(self, comparator: Optional[GeneticComparator] = None) -> None:
        self._comparator = comparator or GeneticComparator()
        self._mutation_history: List[MutationRecord] = []
        self._lock = threading.RLock()

    def analyze_mutation(self, parent: VulnGenome, child: VulnGenome) -> MutationRecord:
        """Analyze the mutation between parent and child genomes."""
        delta = [c - p for p, c in zip(parent.vector, child.vector)]

        # Identify affected genes (significant change)
        affected_genes = [i for i, d in enumerate(delta) if abs(d) > 0.05]

        # Identify affected blocks
        affected_blocks_set: Set[GeneBlock] = set()
        for idx in affected_genes:
            affected_blocks_set.add(GeneBlock(idx // GENE_BLOCK_SIZE))
        affected_blocks = sorted(affected_blocks_set, key=lambda b: b.value)

        # Classify mutation type
        mutation_type = self._classify_mutation(delta, affected_genes, affected_blocks)

        # Infer evolutionary pressure
        pressure = self._infer_pressure(parent, child, affected_blocks, delta)

        record = MutationRecord(
            source_id=parent.vuln_id,
            target_id=child.vuln_id,
            mutation_type=mutation_type,
            affected_blocks=affected_blocks,
            affected_genes=affected_genes,
            delta_vector=delta,
            pressure=pressure,
            description=self._describe_mutation(mutation_type, affected_blocks, pressure),
        )

        with self._lock:
            self._mutation_history.append(record)

        return record

    def _classify_mutation(
        self, delta: List[float], affected_genes: List[int],
        affected_blocks: List[GeneBlock]
    ) -> MutationType:
        """Classify the type of mutation based on the delta pattern."""
        n_affected = len(affected_genes)
        n_blocks = len(affected_blocks)

        if n_affected == 0:
            return MutationType.POINT  # No real change

        # Frameshift: many blocks, high overall delta
        if n_blocks >= 6 and sum(abs(d) for d in delta) > 5.0:
            return MutationType.FRAMESHIFT

        # Block mutation: concentrated in 1-2 blocks
        if n_blocks <= 2 and n_affected >= 8:
            return MutationType.BLOCK

        # Point mutation: very few genes changed
        if n_affected <= 3:
            return MutationType.POINT

        # Check for crossover (genes from multiple disparate blocks)
        if n_blocks >= 3 and n_affected < 20:
            return MutationType.CROSSOVER

        # Insertion: mostly positive deltas (new capabilities)
        positive_count = sum(1 for d in delta if d > 0.05)
        negative_count = sum(1 for d in delta if d < -0.05)

        if positive_count > negative_count * 2:
            return MutationType.INSERTION

        if negative_count > positive_count * 2:
            return MutationType.DELETION

        # Inversion: roughly equal positive and negative
        if abs(positive_count - negative_count) <= 3:
            return MutationType.INVERSION

        return MutationType.DUPLICATION

    def _infer_pressure(
        self, parent: VulnGenome, child: VulnGenome,
        affected_blocks: List[GeneBlock], delta: List[float]
    ) -> Optional[EvolutionPressure]:
        """Infer what environmental pressure caused the mutation."""
        # Major evasion changes → WAF evasion pressure
        if GeneBlock.EVASION in affected_blocks:
            evasion_delta = sum(abs(delta[i]) for i in range(48, 64))
            if evasion_delta > 1.0:
                return EvolutionPressure.WAF_EVASION

        # Trigger block changed significantly → patch bypass
        if GeneBlock.TRIGGER in affected_blocks:
            trigger_delta = sum(abs(delta[i]) for i in range(16))
            if trigger_delta > 1.5:
                return EvolutionPressure.PATCH_BYPASS

        # Prerequisites changed → version/platform upgrade
        if GeneBlock.PREREQUISITES in affected_blocks:
            prereq_delta = sum(abs(delta[i]) for i in range(96, 112))
            if prereq_delta > 0.8:
                return EvolutionPressure.VERSION_UPGRADE

        # Propagation paradigm shift → technology shift
        if GeneBlock.PROPAGATION in affected_blocks:
            prop_delta = sum(abs(delta[i]) for i in range(16, 32))
            if prop_delta > 1.5:
                return EvolutionPressure.TECHNOLOGY_SHIFT

        return None

    def _describe_mutation(
        self, mtype: MutationType, blocks: List[GeneBlock],
        pressure: Optional[EvolutionPressure]
    ) -> str:
        """Generate human-readable mutation description."""
        block_names = [b.name.lower() for b in blocks]
        desc = f"{mtype.value} mutation affecting {', '.join(block_names)}"
        if pressure:
            desc += f" (driven by {pressure.value})"
        return desc

    def get_mutation_frequency(self) -> Dict[MutationType, int]:
        """Get frequency of each mutation type in history."""
        with self._lock:
            counter = Counter(m.mutation_type for m in self._mutation_history)
            return dict(counter)

    def get_pressure_frequency(self) -> Dict[EvolutionPressure, int]:
        """Get frequency of each evolutionary pressure in history."""
        with self._lock:
            counter = Counter(
                m.pressure for m in self._mutation_history
                if m.pressure is not None
            )
            return dict(counter)

    @property
    def history(self) -> List[MutationRecord]:
        with self._lock:
            return list(self._mutation_history)


# ════════════════════════════════════════════════════════════════════════════════
# CORE ENGINE: PredictiveGenetics
# ════════════════════════════════════════════════════════════════════════════════


class PredictiveGenetics:
    """Predicts future vulnerability mutations using Markov chains.

    Learns mutation patterns from observed evolution history and predicts:
    - What mutation type is most likely next
    - Which gene blocks will be affected
    - What the resulting genome might look like
    """

    def __init__(self, order: int = MARKOV_ORDER) -> None:
        self._order = order
        self._lock = threading.RLock()
        # state_sequence → next_state → count
        self._transition_counts: Dict[Tuple[str, ...], Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._state_history: List[str] = []

    def observe_mutation(self, record: MutationRecord) -> None:
        """Record an observed mutation to learn transition patterns."""
        # Encode mutation as state string
        state = self._encode_state(record)

        with self._lock:
            self._state_history.append(state)

            # Update transition counts for all orders up to self._order
            for order in range(1, self._order + 1):
                if len(self._state_history) >= order + 1:
                    context = tuple(self._state_history[-(order + 1):-1])
                    self._transition_counts[context][state] += 1

    def predict_next_mutations(
        self, recent_mutations: List[MutationRecord], n: int = PREDICTION_HORIZON
    ) -> List[Dict[str, Any]]:
        """Predict the next N most likely mutations.

        Returns list of predictions with mutation_type, affected_block, probability.
        """
        if not recent_mutations:
            return []

        # Encode recent history as context
        recent_states = [self._encode_state(m) for m in recent_mutations]
        predictions: List[Dict[str, Any]] = []

        with self._lock:
            for step in range(n):
                best_prediction = self._predict_step(recent_states)
                if best_prediction is None:
                    break
                predictions.append({
                    "step": step + 1,
                    **best_prediction,
                })
                recent_states.append(best_prediction["state"])

        return predictions

    def _predict_step(self, history: List[str]) -> Optional[Dict[str, Any]]:
        """Predict the next state given history."""
        # Try highest order first, fall back to lower
        for order in range(min(self._order, len(history)), 0, -1):
            context = tuple(history[-order:])
            if context in self._transition_counts:
                counts = self._transition_counts[context]
                total = sum(counts.values())
                if total > 0:
                    # Get top prediction
                    best_state = max(counts, key=counts.get)  # type: ignore[arg-type]
                    probability = counts[best_state] / total
                    mtype, block = self._decode_state(best_state)
                    return {
                        "state": best_state,
                        "mutation_type": mtype.value,
                        "affected_block": block.name,
                        "probability": probability,
                        "order": order,
                        "sample_size": total,
                    }

        # Fallback: uniform prediction based on overall frequencies
        all_states: Dict[str, int] = defaultdict(int)
        for transitions in self._transition_counts.values():
            for state, count in transitions.items():
                all_states[state] += count

        if all_states:
            total = sum(all_states.values())
            best_state = max(all_states, key=all_states.get)  # type: ignore[arg-type]
            mtype, block = self._decode_state(best_state)
            return {
                "state": best_state,
                "mutation_type": mtype.value,
                "affected_block": block.name,
                "probability": all_states[best_state] / total,
                "order": 0,
                "sample_size": total,
            }

        return None

    def predict_genome(
        self, current: VulnGenome, mutation_type: MutationType,
        affected_block: GeneBlock, intensity: float = 0.2
    ) -> VulnGenome:
        """Synthesize a predicted genome given a mutation type and target block.

        Creates a child genome by applying the predicted mutation pattern.
        """
        child = VulnGenome(
            vuln_id=f"predicted_{current.vuln_id}_{int(time.time() * 1000)}",
            family=current.family,
            cwe_ids=list(current.cwe_ids),
            cve_ids=[],
            cvss_score=current.cvss_score,
            epss_score=current.epss_score,
            parent_id=current.vuln_id,
            generation=current.generation + 1,
        )

        # Copy current genome
        for i in range(GENOME_DIMENSIONS):
            child.genes[i].value = current.genes[i].value

        # Apply mutation
        rng = random.Random(hash((current.fingerprint(), mutation_type.value, affected_block.value)))
        block_start = affected_block.value * GENE_BLOCK_SIZE
        block_end = block_start + GENE_BLOCK_SIZE

        if mutation_type == MutationType.POINT:
            # Change 1-3 genes
            n_genes = rng.randint(1, 3)
            for _ in range(n_genes):
                idx = rng.randint(block_start, block_end - 1)
                delta = rng.gauss(0, intensity)
                child.genes[idx].value = max(0.0, min(1.0, child.genes[idx].value + delta))

        elif mutation_type == MutationType.BLOCK:
            # Change entire block
            for i in range(block_start, block_end):
                delta = rng.gauss(0, intensity)
                child.genes[i].value = max(0.0, min(1.0, child.genes[i].value + delta))

        elif mutation_type == MutationType.INSERTION:
            # Boost genes in block (new capability)
            for i in range(block_start, block_end):
                boost = abs(rng.gauss(0, intensity))
                child.genes[i].value = min(1.0, child.genes[i].value + boost)

        elif mutation_type == MutationType.DELETION:
            # Reduce genes in block
            for i in range(block_start, block_end):
                reduction = abs(rng.gauss(0, intensity))
                child.genes[i].value = max(0.0, child.genes[i].value - reduction)

        elif mutation_type == MutationType.CROSSOVER:
            # Mix with a random block from another part of genome
            donor_block = rng.choice([b for b in GeneBlock if b != affected_block])
            donor_start = donor_block.value * GENE_BLOCK_SIZE
            for i in range(GENE_BLOCK_SIZE):
                if rng.random() < 0.5:
                    child.genes[block_start + i].value = current.genes[donor_start + i].value

        elif mutation_type == MutationType.INVERSION:
            # Reverse the block values
            block_vals = [child.genes[i].value for i in range(block_start, block_end)]
            block_vals.reverse()
            for i, val in enumerate(block_vals):
                child.genes[block_start + i].value = val

        elif mutation_type == MutationType.FRAMESHIFT:
            # Radical change across multiple blocks
            for i in range(GENOME_DIMENSIONS):
                if rng.random() < 0.3:  # 30% of genes affected
                    delta = rng.gauss(0, intensity * 2)
                    child.genes[i].value = max(0.0, min(1.0, child.genes[i].value + delta))

        elif mutation_type == MutationType.DUPLICATION:
            # Copy block pattern to adjacent block
            next_block = GeneBlock((affected_block.value + 1) % 8)
            next_start = next_block.value * GENE_BLOCK_SIZE
            for i in range(GENE_BLOCK_SIZE):
                child.genes[next_start + i].value = current.genes[block_start + i].value

        return child

    def _encode_state(self, record: MutationRecord) -> str:
        """Encode a mutation record as a state string."""
        primary_block = record.affected_blocks[0] if record.affected_blocks else GeneBlock.TRIGGER
        return f"{record.mutation_type.value}:{primary_block.value}"

    def _decode_state(self, state: str) -> Tuple[MutationType, GeneBlock]:
        """Decode a state string back to mutation type and block."""
        parts = state.split(":")
        mtype = MutationType(parts[0])
        block = GeneBlock(int(parts[1]))
        return mtype, block

    def get_transition_matrix(self) -> Dict[str, Dict[str, float]]:
        """Get the full transition probability matrix."""
        matrix: Dict[str, Dict[str, float]] = {}
        with self._lock:
            for context, transitions in self._transition_counts.items():
                key = "|".join(context)
                total = sum(transitions.values())
                matrix[key] = {
                    state: count / total
                    for state, count in transitions.items()
                }
        return matrix


# ════════════════════════════════════════════════════════════════════════════════
# MAIN INTERFACE: SirenVulnDNA
# ════════════════════════════════════════════════════════════════════════════════


class SirenVulnDNA:
    """Main interface for the Vulnerability DNA system.

    Orchestrates extraction, comparison, lineage tracking, mutation analysis,
    and predictive genetics.

    Usage:
        dna = SirenVulnDNA()
        genome = dna.extract("CWE-89", cvss_score=9.8)
        similar = dna.find_similar(genome, top_k=5)
        lineage = dna.get_evolution_chain(genome.vuln_id)
        predictions = dna.predict_next_mutations(genome.vuln_id)
    """

    def __init__(self, markov_order: int = MARKOV_ORDER) -> None:
        self._lock = threading.RLock()
        self._extractor = DNAExtractor()
        self._comparator = GeneticComparator()
        self._lineage = LineageTracker(self._comparator)
        self._mutation_analyzer = MutationAnalyzer(self._comparator)
        self._predictor = PredictiveGenetics(order=markov_order)
        self._genome_db: Dict[str, VulnGenome] = {}
        self._executor = ThreadPoolExecutor(max_workers=THREAD_POOL_SIZE, thread_name_prefix="siren-dna")
        self._initialized = False

        logger.info("SirenVulnDNA engine initialized (markov_order=%d)", markov_order)

    def initialize(self) -> None:
        """Load known lineages from embedded KB."""
        for parent_cwe, children in KNOWN_LINEAGES.items():
            parent_genome = self._extractor.extract_from_cwe(parent_cwe)
            self._register(parent_genome)

            for child_info in children:
                child_id = child_info["child"]
                # Create child genome with mutation applied
                child_genome = self._predictor.predict_genome(
                    parent_genome,
                    child_info["mutation"],
                    GeneBlock.TRIGGER,  # Default block
                    intensity=0.25,
                )
                child_genome.vuln_id = child_id
                child_genome.parent_id = parent_genome.vuln_id
                child_genome.description = child_info.get("desc", "")

                self._register(child_genome)

                # Analyze and record the mutation
                record = self._mutation_analyzer.analyze_mutation(parent_genome, child_genome)
                self._predictor.observe_mutation(record)

        self._initialized = True
        logger.info(f"VulnDNA initialized with {len(self._genome_db)} genomes")

    def _register(self, genome: VulnGenome) -> None:
        """Register a genome in all subsystems."""
        with self._lock:
            self._genome_db[genome.vuln_id] = genome
            self._lineage.register_genome(genome)

    # ── Extraction ────────────────────────────────────────────────────────

    def extract(self, identifier: str, **kwargs: Any) -> VulnGenome:
        """Universal extraction: CWE, CVE, or description.

        Auto-detects input type:
        - 'CWE-89' → extract_from_cwe
        - 'CVE-2024-...' → extract from CVE (uses CWE mapping if available)
        - Anything else → extract_from_description
        """
        if identifier.upper().startswith("CWE-"):
            genome = self._extractor.extract_from_cwe(identifier.upper(), **kwargs)
        elif identifier.upper().startswith("CVE-"):
            genome = self._extract_from_cve(identifier.upper(), **kwargs)
        else:
            genome = self._extractor.extract_from_description(identifier, **kwargs)

        # ── Genome dimension validation ──────────────────────────────────
        n_genes = len(genome.genes)
        if n_genes != GENOME_DIMENSIONS:
            logger.warning(
                "Genome %s has %d dimensions (expected %d) — %s to %d",
                genome.vuln_id,
                n_genes,
                GENOME_DIMENSIONS,
                "padding" if n_genes < GENOME_DIMENSIONS else "truncating",
                GENOME_DIMENSIONS,
            )
            if n_genes < GENOME_DIMENSIONS:
                # Pad with zero-valued genes
                for i in range(n_genes, GENOME_DIMENSIONS):
                    genome.genes.append(
                        Gene(index=i, value=0.0, block=GeneBlock(i // GENE_BLOCK_SIZE))
                    )
            else:
                # Truncate to 128
                genome.genes = genome.genes[:GENOME_DIMENSIONS]

        self._register(genome)
        return genome

    def _extract_from_cve(self, cve_id: str, **kwargs: Any) -> VulnGenome:
        """Extract genome from a CVE ID."""
        # Map common CVE patterns to CWEs (embedded knowledge)
        # In real deployment, this would query a CVE database
        genome = VulnGenome(
            vuln_id=cve_id,
            cve_ids=[cve_id],
            description=f"CVE vulnerability: {cve_id}",
        )
        for attr, val in kwargs.items():
            if hasattr(genome, attr):
                setattr(genome, attr, val)
        return genome

    def extract_batch(self, identifiers: List[str], **kwargs: Any) -> List[VulnGenome]:
        """Extract multiple genomes concurrently."""
        futures = [
            self._executor.submit(self.extract, ident, **kwargs)
            for ident in identifiers
        ]
        return [f.result() for f in futures]

    # ── Comparison ────────────────────────────────────────────────────────

    def compare(self, id_a: str, id_b: str) -> Dict[str, Any]:
        """Full comparison between two genomes."""
        genome_a = self._genome_db.get(id_a)
        genome_b = self._genome_db.get(id_b)
        if not genome_a or not genome_b:
            return {"error": "genome not found"}

        block_sims = self._comparator.all_block_similarities(genome_a, genome_b)
        return {
            "cosine_similarity": self._comparator.cosine_similarity(genome_a, genome_b),
            "euclidean_distance": self._comparator.euclidean_distance(genome_a, genome_b),
            "phylogenetic_distance": self._comparator.phylogenetic_distance(genome_a, genome_b),
            "is_same_family": self._comparator.is_same_family(genome_a, genome_b),
            "is_variant": self._comparator.is_variant(genome_a, genome_b),
            "block_similarities": {b.name: s for b, s in block_sims.items()},
            "relationship": self._lineage.infer_relationship(id_a, id_b).value,
        }

    def find_similar(self, genome_or_id: Union[str, VulnGenome], top_k: int = 5) -> List[Dict[str, Any]]:
        """Find most similar genomes in the database."""
        if isinstance(genome_or_id, str):
            genome = self._genome_db.get(genome_or_id)
            if not genome:
                return []
        else:
            genome = genome_or_id

        population = [g for g in self._genome_db.values() if g.vuln_id != genome.vuln_id]
        nearest = self._comparator.find_nearest(genome, population, k=top_k)

        return [
            {
                "vuln_id": g.vuln_id,
                "similarity": sim,
                "family": g.family.value,
                "relationship": self._lineage.infer_relationship(genome.vuln_id, g.vuln_id).value,
            }
            for g, sim in nearest
        ]

    # ── Lineage ───────────────────────────────────────────────────────────

    def get_evolution_chain(self, genome_id: str) -> List[Dict[str, Any]]:
        """Get full evolution chain from root ancestor to current genome."""
        chain = self._lineage.get_lineage(genome_id)
        return [
            {
                "vuln_id": g.vuln_id,
                "family": g.family.value,
                "generation": g.generation,
                "description": g.description,
            }
            for g in chain
        ]

    # ── Mutation Analysis ─────────────────────────────────────────────────

    def analyze_evolution(self, parent_id: str, child_id: str) -> Dict[str, Any]:
        """Analyze the mutation between parent and child genomes."""
        parent = self._genome_db.get(parent_id)
        child = self._genome_db.get(child_id)
        if not parent or not child:
            return {"error": "genome not found"}

        record = self._mutation_analyzer.analyze_mutation(parent, child)
        self._predictor.observe_mutation(record)
        return record.to_dict()

    # ── Prediction ────────────────────────────────────────────────────────

    def predict_next_mutations(self, genome_id: str, steps: int = 5) -> List[Dict[str, Any]]:
        """Predict next likely mutations for a genome."""
        history = self._mutation_analyzer.history
        # Filter history relevant to this genome's lineage
        lineage_ids = {g.vuln_id for g in self._lineage.get_lineage(genome_id)}
        relevant = [m for m in history if m.source_id in lineage_ids or m.target_id in lineage_ids]

        if not relevant:
            relevant = history[-10:]  # Fallback to recent global history

        return self._predictor.predict_next_mutations(relevant, n=steps)

    def predict_variant(
        self, genome_id: str, mutation_type: str, target_block: str
    ) -> Optional[Dict[str, Any]]:
        """Generate a predicted variant genome."""
        genome = self._genome_db.get(genome_id)
        if not genome:
            return None

        try:
            mtype = MutationType(mutation_type)
            block = GeneBlock[target_block.upper()]
        except (ValueError, KeyError):
            return None

        predicted = self._predictor.predict_genome(genome, mtype, block)
        self._register(predicted)

        return {
            "predicted_genome": predicted.to_dict(),
            "parent_id": genome_id,
            "mutation_type": mutation_type,
            "target_block": target_block,
            "similarity_to_parent": self._comparator.cosine_similarity(genome, predicted),
        }

    # ── Clustering ────────────────────────────────────────────────────────

    def cluster_all(self, eps: float = 0.3, min_samples: int = 2) -> Dict[str, Any]:
        """Cluster all genomes in the database."""
        genomes = list(self._genome_db.values())
        clusters = self._comparator.cluster_genomes(genomes, eps, min_samples)
        return {
            "num_clusters": len([k for k in clusters if k != -1]),
            "noise_count": len(clusters.get(-1, [])),
            "clusters": {
                str(cid): [g.vuln_id for g in members]
                for cid, members in clusters.items()
            },
        }

    # ── Statistics ────────────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        """Get engine statistics."""
        return {
            "total_genomes": len(self._genome_db),
            "extraction_count": self._extractor.extraction_count,
            "mutation_history_size": len(self._mutation_analyzer.history),
            "mutation_frequencies": {
                k.value: v for k, v in self._mutation_analyzer.get_mutation_frequency().items()
            },
            "pressure_frequencies": {
                k.value: v for k, v in self._mutation_analyzer.get_pressure_frequency().items()
            },
            "families": dict(Counter(g.family.value for g in self._genome_db.values())),
        }

    # ── Persistence ───────────────────────────────────────────────────────

    def save_state(self, path: Union[str, Path]) -> None:
        """Save complete engine state to JSON."""
        state = {
            "genomes": {gid: g.to_dict() for gid, g in self._genome_db.items()},
            "lineage": self._lineage.to_dict(),
            "transition_matrix": self._predictor.get_transition_matrix(),
            "stats": self.get_stats(),
        }
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(state, indent=2, default=str), encoding="utf-8")
        logger.info(f"VulnDNA state saved to {path}")

    def load_state(self, path: Union[str, Path]) -> None:
        """Load engine state from JSON."""
        p = Path(path)
        if not p.exists():
            logger.warning(f"State file not found: {path}")
            return

        state = json.loads(p.read_text(encoding="utf-8"))

        # Restore genomes
        for gid, gdata in state.get("genomes", {}).items():
            genome = VulnGenome.from_dict(gdata)
            self._register(genome)

        logger.info(f"VulnDNA state loaded from {path}: {len(self._genome_db)} genomes")

    # ── Async interface ───────────────────────────────────────────────────

    async def async_extract(self, identifier: str, **kwargs: Any) -> VulnGenome:
        """Async wrapper for extraction."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self._executor, lambda: self.extract(identifier, **kwargs))

    async def async_find_similar(self, genome_id: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """Async wrapper for similarity search."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self._executor, lambda: self.find_similar(genome_id, top_k))

    async def async_predict(self, genome_id: str, steps: int = 5) -> List[Dict[str, Any]]:
        """Async wrapper for prediction."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self._executor, lambda: self.predict_next_mutations(genome_id, steps))

    def shutdown(self) -> None:
        """Shutdown thread pool."""
        self._executor.shutdown(wait=False)
        logger.info("SirenVulnDNA engine shutdown")

    def __del__(self) -> None:
        """Safety net to ensure thread pool is cleaned up."""
        self.shutdown()
