#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  🧠  SIREN STRATEGY DB — Persistent Strategy Intelligence Store  🧠           ██
██                                                                                ██
██  Armazena, busca e rankeia estratégias testadas em scans anteriores.           ██
██                                                                                ██
██  Capacidades:                                                                  ██
██    • Strategy persistence — salva cada estratégia com resultado                ██
██    • Similarity search — busca estratégias similares por alvo/tech            ██
██    • Success ranking — rankeia por taxa de sucesso ajustada                   ██
██    • Chain learning — aprende sequências que funcionam juntas                 ██
██    • Context matching — sugere baseado em contexto do alvo                    ██
██    • Decay weighting — estratégias mais recentes pesam mais                   ██
██    • Atomic persistence — JSON com crash recovery                             ██
██                                                                                ██
██  "SIREN nunca esquece o que funcionou — e nunca repete o que falhou."         ██
██                                                                                ██
████████████████████████████████████████████████████████████████████████████████████
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("siren.meta.strategy_db")


# ════════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════════════════════════════

STRATEGY_DECAY_HALF_LIFE_DAYS = 90
MIN_USES_FOR_RANKING = 3
SIMILARITY_THRESHOLD = 0.50
MAX_STRATEGIES = 50_000
MAX_CHAIN_LENGTH = 20
DEFAULT_DB_FILENAME = "siren_strategy_db.json"


# ════════════════════════════════════════════════════════════════════════════════
# ENUMS
# ════════════════════════════════════════════════════════════════════════════════

class StrategyType(Enum):
    """Category of strategy."""
    RECON = auto()
    ENUMERATION = auto()
    VULNERABILITY_SCAN = auto()
    EXPLOITATION = auto()
    POST_EXPLOITATION = auto()
    LATERAL_MOVEMENT = auto()
    PERSISTENCE = auto()
    EXFILTRATION = auto()
    EVASION = auto()
    SOCIAL_ENGINEERING = auto()
    FUZZING = auto()
    BRUTE_FORCE = auto()


class StrategyOutcome(Enum):
    """Outcome of a strategy execution."""
    SUCCESS = auto()        # Achieved objective
    PARTIAL = auto()        # Got partial results
    FAILURE = auto()        # Did not work
    BLOCKED = auto()        # Detected and blocked
    ERROR = auto()          # Technical error
    TIMEOUT = auto()        # Timed out
    NOT_APPLICABLE = auto() # Target not suitable


class TargetArchetype(Enum):
    """Target archetype for context matching."""
    WEB_APP_PHP = auto()
    WEB_APP_JAVA = auto()
    WEB_APP_PYTHON = auto()
    WEB_APP_NODE = auto()
    WEB_APP_DOTNET = auto()
    API_REST = auto()
    API_GRAPHQL = auto()
    CMS_WORDPRESS = auto()
    CMS_DRUPAL = auto()
    NETWORK_DEVICE = auto()
    CLOUD_AWS = auto()
    CLOUD_AZURE = auto()
    CLOUD_GCP = auto()
    CONTAINER_K8S = auto()
    MOBILE_ANDROID = auto()
    MOBILE_IOS = auto()
    IOT_DEVICE = auto()
    GENERIC = auto()


# ════════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class StrategyRecord:
    """A single strategy with its execution history and metadata."""
    strategy_id: str
    name: str
    strategy_type: StrategyType
    description: str = ""
    # Execution context
    target_archetypes: Set[TargetArchetype] = field(default_factory=set)
    required_techs: Set[str] = field(default_factory=set)     # Techs that must be present
    excluded_techs: Set[str] = field(default_factory=set)     # Techs that make this inapplicable
    required_conditions: Set[str] = field(default_factory=set) # e.g. "port_80_open", "waf_absent"
    # Performance stats
    total_uses: int = 0
    success_count: int = 0
    partial_count: int = 0
    failure_count: int = 0
    blocked_count: int = 0
    # Timing
    avg_execution_ms: float = 0.0
    first_used: float = 0.0
    last_used: float = 0.0
    # Metadata
    tags: Set[str] = field(default_factory=set)
    parameters: Dict[str, Any] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)

    @property
    def success_rate(self) -> float:
        if self.total_uses == 0:
            return 0.0
        return (self.success_count + 0.5 * self.partial_count) / self.total_uses

    @property
    def block_rate(self) -> float:
        if self.total_uses == 0:
            return 0.0
        return self.blocked_count / self.total_uses

    def record_outcome(self, outcome: StrategyOutcome, execution_ms: float = 0.0) -> None:
        """Record a new use of this strategy."""
        self.total_uses += 1
        self.last_used = time.time()
        if not self.first_used:
            self.first_used = self.last_used

        if outcome == StrategyOutcome.SUCCESS:
            self.success_count += 1
        elif outcome == StrategyOutcome.PARTIAL:
            self.partial_count += 1
        elif outcome == StrategyOutcome.FAILURE:
            self.failure_count += 1
        elif outcome == StrategyOutcome.BLOCKED:
            self.blocked_count += 1

        # Running average for execution time
        if execution_ms > 0:
            if self.avg_execution_ms == 0:
                self.avg_execution_ms = execution_ms
            else:
                self.avg_execution_ms = (
                    self.avg_execution_ms * (self.total_uses - 1) + execution_ms
                ) / self.total_uses

    def to_dict(self) -> Dict[str, Any]:
        return {
            "strategy_id": self.strategy_id,
            "name": self.name,
            "strategy_type": self.strategy_type.name,
            "description": self.description,
            "target_archetypes": [a.name for a in self.target_archetypes],
            "required_techs": list(self.required_techs),
            "excluded_techs": list(self.excluded_techs),
            "required_conditions": list(self.required_conditions),
            "total_uses": self.total_uses,
            "success_count": self.success_count,
            "partial_count": self.partial_count,
            "failure_count": self.failure_count,
            "blocked_count": self.blocked_count,
            "success_rate": round(self.success_rate, 4),
            "block_rate": round(self.block_rate, 4),
            "avg_execution_ms": round(self.avg_execution_ms, 2),
            "first_used": self.first_used,
            "last_used": self.last_used,
            "tags": list(self.tags),
            "parameters": self.parameters,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> StrategyRecord:
        return cls(
            strategy_id=d["strategy_id"],
            name=d["name"],
            strategy_type=StrategyType[d["strategy_type"]],
            description=d.get("description", ""),
            target_archetypes={TargetArchetype[a] for a in d.get("target_archetypes", [])},
            required_techs=set(d.get("required_techs", [])),
            excluded_techs=set(d.get("excluded_techs", [])),
            required_conditions=set(d.get("required_conditions", [])),
            total_uses=d.get("total_uses", 0),
            success_count=d.get("success_count", 0),
            partial_count=d.get("partial_count", 0),
            failure_count=d.get("failure_count", 0),
            blocked_count=d.get("blocked_count", 0),
            avg_execution_ms=d.get("avg_execution_ms", 0.0),
            first_used=d.get("first_used", 0.0),
            last_used=d.get("last_used", 0.0),
            tags=set(d.get("tags", [])),
            parameters=d.get("parameters", {}),
            notes=d.get("notes", []),
        )


@dataclass
class StrategyChain:
    """An ordered sequence of strategies that work well together."""
    chain_id: str
    name: str
    strategies: List[str] = field(default_factory=list)  # Ordered strategy_ids
    target_archetypes: Set[TargetArchetype] = field(default_factory=set)
    total_uses: int = 0
    success_count: int = 0
    avg_total_ms: float = 0.0
    notes: List[str] = field(default_factory=list)

    @property
    def success_rate(self) -> float:
        if self.total_uses == 0:
            return 0.0
        return self.success_count / self.total_uses

    def record_outcome(self, success: bool, total_ms: float = 0.0) -> None:
        self.total_uses += 1
        if success:
            self.success_count += 1
        if total_ms > 0:
            if self.avg_total_ms == 0:
                self.avg_total_ms = total_ms
            else:
                self.avg_total_ms = (
                    self.avg_total_ms * (self.total_uses - 1) + total_ms
                ) / self.total_uses

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "name": self.name,
            "strategies": self.strategies,
            "target_archetypes": [a.name for a in self.target_archetypes],
            "total_uses": self.total_uses,
            "success_count": self.success_count,
            "success_rate": round(self.success_rate, 4),
            "avg_total_ms": round(self.avg_total_ms, 2),
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> StrategyChain:
        return cls(
            chain_id=d["chain_id"],
            name=d["name"],
            strategies=d.get("strategies", []),
            target_archetypes={TargetArchetype[a] for a in d.get("target_archetypes", [])},
            total_uses=d.get("total_uses", 0),
            success_count=d.get("success_count", 0),
            avg_total_ms=d.get("avg_total_ms", 0.0),
            notes=d.get("notes", []),
        )


@dataclass
class StrategyRecommendation:
    """A recommended strategy with scoring."""
    strategy: StrategyRecord
    relevance_score: float = 0.0  # How relevant to current context [0, 1]
    success_score: float = 0.0    # Historical success rate adjusted [0, 1]
    recency_score: float = 0.0    # Decay-weighted recency [0, 1]
    composite_score: float = 0.0  # Final ranking score [0, 1]
    reasoning: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "strategy_id": self.strategy.strategy_id,
            "strategy_name": self.strategy.name,
            "strategy_type": self.strategy.strategy_type.name,
            "relevance_score": round(self.relevance_score, 4),
            "success_score": round(self.success_score, 4),
            "recency_score": round(self.recency_score, 4),
            "composite_score": round(self.composite_score, 4),
            "reasoning": self.reasoning,
        }


# ════════════════════════════════════════════════════════════════════════════════
# SIMILARITY ENGINE — Context-based strategy matching
# ════════════════════════════════════════════════════════════════════════════════

class SimilarityEngine:
    """
    Computes similarity between target context and strategy requirements.
    Uses Jaccard similarity on feature sets.
    """

    def compute(
        self,
        strategy: StrategyRecord,
        target_archetypes: Set[TargetArchetype],
        target_techs: Set[str],
        target_conditions: Set[str],
    ) -> Tuple[float, List[str]]:
        """
        Compute relevance score for a strategy given target context.
        Returns (score, reasoning_list).
        """
        score = 0.0
        reasons: List[str] = []

        # 1) Archetype match (Jaccard)
        if strategy.target_archetypes and target_archetypes:
            overlap = strategy.target_archetypes & target_archetypes
            union = strategy.target_archetypes | target_archetypes
            arch_sim = len(overlap) / len(union) if union else 0.0
            score += arch_sim * 0.40
            if overlap:
                reasons.append(f"Archetype match: {', '.join(a.name for a in overlap)}")
        elif not strategy.target_archetypes:
            score += 0.20  # Generic strategy applies everywhere
            reasons.append("Generic strategy (no archetype constraint)")

        # 2) Required tech match
        if strategy.required_techs:
            target_techs_lower = {t.lower() for t in target_techs}
            req_lower = {t.lower() for t in strategy.required_techs}
            met = req_lower & target_techs_lower
            if met == req_lower:
                score += 0.30
                reasons.append(f"All required techs present: {', '.join(met)}")
            elif met:
                partial = len(met) / len(req_lower)
                score += 0.15 * partial
                reasons.append(f"Partial tech match: {len(met)}/{len(req_lower)}")
            else:
                score -= 0.20
                reasons.append("Required techs not found")
        else:
            score += 0.15

        # 3) Excluded tech check (negative)
        if strategy.excluded_techs:
            target_techs_lower = {t.lower() for t in target_techs}
            excl_lower = {t.lower() for t in strategy.excluded_techs}
            conflict = excl_lower & target_techs_lower
            if conflict:
                score -= 0.40
                reasons.append(f"Excluded tech present: {', '.join(conflict)}")

        # 4) Condition match
        if strategy.required_conditions and target_conditions:
            cond_met = strategy.required_conditions & target_conditions
            if cond_met == strategy.required_conditions:
                score += 0.20
                reasons.append("All conditions met")
            elif cond_met:
                partial = len(cond_met) / len(strategy.required_conditions)
                score += 0.10 * partial
                reasons.append(f"Partial conditions: {len(cond_met)}/{len(strategy.required_conditions)}")

        return max(0.0, min(1.0, score)), reasons


# ════════════════════════════════════════════════════════════════════════════════
# PERSISTENCE LAYER — Atomic JSON persistence
# ════════════════════════════════════════════════════════════════════════════════

class StrategyPersistence:
    """Atomic JSON persistence with crash recovery."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self._db_path = db_path or Path(DEFAULT_DB_FILENAME)

    def save(self, strategies: Dict[str, StrategyRecord], chains: Dict[str, StrategyChain]) -> bool:
        """Save to JSON atomically (write to temp, then rename)."""
        data = {
            "version": 1,
            "timestamp": time.time(),
            "strategies": {k: v.to_dict() for k, v in strategies.items()},
            "chains": {k: v.to_dict() for k, v in chains.items()},
        }
        tmp_path = self._db_path.with_suffix(".tmp")
        try:
            tmp_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            # Atomic rename
            if self._db_path.exists():
                self._db_path.unlink()
            tmp_path.rename(self._db_path)
            return True
        except OSError as e:
            logger.error("Failed to save strategy DB: %s", e)
            return False

    def load(self) -> Tuple[Dict[str, StrategyRecord], Dict[str, StrategyChain]]:
        """Load from JSON."""
        strategies: Dict[str, StrategyRecord] = {}
        chains: Dict[str, StrategyChain] = {}

        if not self._db_path.exists():
            return strategies, chains

        try:
            data = json.loads(self._db_path.read_text(encoding="utf-8"))
            for sid, sdata in data.get("strategies", {}).items():
                strategies[sid] = StrategyRecord.from_dict(sdata)
            for cid, cdata in data.get("chains", {}).items():
                chains[cid] = StrategyChain.from_dict(cdata)
        except (json.JSONDecodeError, OSError, KeyError) as e:
            logger.error("Failed to load strategy DB: %s", e)

        return strategies, chains


# ════════════════════════════════════════════════════════════════════════════════
# SIREN STRATEGY DB — Main Orchestrator
# ════════════════════════════════════════════════════════════════════════════════

class SirenStrategyDB:
    """
    Main strategy database and recommendation engine.

    Stores strategies, tracks outcomes, computes similarity-based
    recommendations, and persists everything to disk.

    Usage:
        db = SirenStrategyDB()
        # Register a strategy
        db.register_strategy(StrategyRecord(...))
        # Record an outcome
        db.record_outcome("strategy_id", StrategyOutcome.SUCCESS, 150.0)
        # Get recommendations for a target
        recs = db.recommend(
            target_archetypes={TargetArchetype.WEB_APP_PHP},
            target_techs={"PHP", "WordPress", "MySQL"},
            target_conditions={"port_80_open", "waf_absent"},
            limit=10,
        )
    """

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self._lock = threading.RLock()
        self._persistence = StrategyPersistence(db_path)
        self._strategies: Dict[str, StrategyRecord] = {}
        self._chains: Dict[str, StrategyChain] = {}
        self._similarity = SimilarityEngine()
        self._dirty = False
        # Load existing data
        self._strategies, self._chains = self._persistence.load()
        # Load builtin strategies if empty
        if not self._strategies:
            self._load_builtins()
        logger.info(
            "SirenStrategyDB: %d strategies, %d chains loaded",
            len(self._strategies), len(self._chains),
        )

    def register_strategy(self, strategy: StrategyRecord) -> str:
        """Register a new strategy. Returns strategy_id."""
        with self._lock:
            self._strategies[strategy.strategy_id] = strategy
            self._dirty = True
            self._evict_if_needed()
            return strategy.strategy_id

    def _evict_if_needed(self) -> None:
        """LRU eviction: remove 10% oldest strategies when MAX_STRATEGIES is reached."""
        if len(self._strategies) <= MAX_STRATEGIES:
            return
        evict_count = MAX_STRATEGIES // 10  # 5000
        # Sort by last_used ascending (oldest first)
        sorted_ids = sorted(
            self._strategies,
            key=lambda sid: self._strategies[sid].last_used,
        )
        evicted = sorted_ids[:evict_count]
        for sid in evicted:
            del self._strategies[sid]
        logger.info(
            "LRU eviction: removed %d strategies (had %d, now %d)",
            len(evicted),
            len(evicted) + len(self._strategies),
            len(self._strategies),
        )

    def record_outcome(
        self, strategy_id: str, outcome: StrategyOutcome, execution_ms: float = 0.0,
    ) -> bool:
        """Record outcome for a strategy execution."""
        with self._lock:
            strategy = self._strategies.get(strategy_id)
            if not strategy:
                return False
            strategy.record_outcome(outcome, execution_ms)
            self._dirty = True
            return True

    def register_chain(self, chain: StrategyChain) -> str:
        """Register a strategy chain."""
        with self._lock:
            self._chains[chain.chain_id] = chain
            self._dirty = True
            return chain.chain_id

    def record_chain_outcome(
        self, chain_id: str, success: bool, total_ms: float = 0.0,
    ) -> bool:
        with self._lock:
            chain = self._chains.get(chain_id)
            if not chain:
                return False
            chain.record_outcome(success, total_ms)
            self._dirty = True
            return True

    def recommend(
        self,
        target_archetypes: Optional[Set[TargetArchetype]] = None,
        target_techs: Optional[Set[str]] = None,
        target_conditions: Optional[Set[str]] = None,
        strategy_type: Optional[StrategyType] = None,
        limit: int = 10,
        min_success_rate: float = 0.0,
    ) -> List[StrategyRecommendation]:
        """
        Get recommended strategies for a target context.
        Sorted by composite score (relevance * success * recency).
        """
        with self._lock:
            archetypes = target_archetypes or set()
            techs = target_techs or set()
            conditions = target_conditions or set()
            recommendations: List[StrategyRecommendation] = []

            for strategy in self._strategies.values():
                # Filter by type
                if strategy_type and strategy.strategy_type != strategy_type:
                    continue

                # Filter by min success rate
                if strategy.total_uses >= MIN_USES_FOR_RANKING:
                    if strategy.success_rate < min_success_rate:
                        continue

                # Compute relevance
                relevance, reasoning = self._similarity.compute(
                    strategy, archetypes, techs, conditions,
                )

                if relevance < SIMILARITY_THRESHOLD:
                    continue

                # Success score (Wilson lower bound for confidence)
                success_score = self._wilson_lower_bound(
                    strategy.success_count + strategy.partial_count * 0.5,
                    strategy.total_uses,
                )

                # Recency score (decay)
                recency = self._compute_recency(strategy.last_used)

                # Block penalty
                block_penalty = strategy.block_rate * 0.30

                # Composite
                composite = (
                    0.35 * relevance
                    + 0.35 * success_score
                    + 0.15 * recency
                    - block_penalty
                    + 0.15 * min(1.0, strategy.total_uses / 20.0)  # Experience bonus
                )
                composite = max(0.0, min(1.0, composite))

                rec = StrategyRecommendation(
                    strategy=strategy,
                    relevance_score=relevance,
                    success_score=success_score,
                    recency_score=recency,
                    composite_score=composite,
                    reasoning=reasoning,
                )
                recommendations.append(rec)

            recommendations.sort(key=lambda r: r.composite_score, reverse=True)
            return recommendations[:limit]

    def recommend_chain(
        self,
        target_archetypes: Optional[Set[TargetArchetype]] = None,
        limit: int = 5,
    ) -> List[StrategyChain]:
        """Recommend strategy chains for a target."""
        with self._lock:
            archetypes = target_archetypes or set()
            candidates: List[Tuple[float, StrategyChain]] = []

            for chain in self._chains.values():
                score = chain.success_rate
                if archetypes and chain.target_archetypes:
                    overlap = chain.target_archetypes & archetypes
                    if overlap:
                        score += 0.30 * (len(overlap) / len(chain.target_archetypes))
                candidates.append((score, chain))

            candidates.sort(key=lambda x: x[0], reverse=True)
            return [c for _, c in candidates[:limit]]

    def get_strategy(self, strategy_id: str) -> Optional[StrategyRecord]:
        with self._lock:
            return self._strategies.get(strategy_id)

    def get_all_strategies(self) -> List[StrategyRecord]:
        with self._lock:
            return list(self._strategies.values())

    def get_top_performers(
        self, strategy_type: Optional[StrategyType] = None, limit: int = 10,
    ) -> List[StrategyRecord]:
        """Get top performing strategies by success rate."""
        with self._lock:
            candidates = [
                s for s in self._strategies.values()
                if s.total_uses >= MIN_USES_FOR_RANKING
                and (strategy_type is None or s.strategy_type == strategy_type)
            ]
            candidates.sort(key=lambda s: s.success_rate, reverse=True)
            return candidates[:limit]

    def save(self) -> bool:
        """Persist to disk."""
        with self._lock:
            if self._dirty:
                result = self._persistence.save(self._strategies, self._chains)
                if result:
                    self._dirty = False
                return result
            return True

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            total_uses = sum(s.total_uses for s in self._strategies.values())
            return {
                "total_strategies": len(self._strategies),
                "total_chains": len(self._chains),
                "total_executions": total_uses,
                "strategies_by_type": {
                    t.name: len([s for s in self._strategies.values() if s.strategy_type == t])
                    for t in StrategyType
                },
            }

    # ── Private helpers ─────────────────────────────────────────────────────

    @staticmethod
    def _wilson_lower_bound(successes: float, total: int, z: float = 1.96) -> float:
        """Wilson score interval lower bound for success rate confidence."""
        if total == 0:
            return 0.0
        p = successes / total
        denominator = 1 + z * z / total
        center = p + z * z / (2 * total)
        spread = z * math.sqrt((p * (1 - p) + z * z / (4 * total)) / total)
        return max(0.0, (center - spread) / denominator)

    @staticmethod
    def _compute_recency(last_used: float) -> float:
        """Compute recency score with exponential decay."""
        if last_used <= 0:
            return 0.0
        days_since_last_use = (time.time() - last_used) / 86400
        return math.exp(-days_since_last_use / STRATEGY_DECAY_HALF_LIFE_DAYS * math.log(2))

    def _load_builtins(self) -> None:
        """Load built-in strategies."""
        builtins = [
            StrategyRecord(
                "recon_subdomain_enum", "Subdomain Enumeration", StrategyType.RECON,
                "Enumerate subdomains via DNS brute-force and cert transparency",
                target_archetypes={TargetArchetype.WEB_APP_PHP, TargetArchetype.WEB_APP_JAVA,
                                   TargetArchetype.WEB_APP_PYTHON, TargetArchetype.WEB_APP_NODE,
                                   TargetArchetype.API_REST, TargetArchetype.CMS_WORDPRESS},
                tags={"passive", "dns", "subdomain"},
            ),
            StrategyRecord(
                "recon_port_scan", "TCP Port Scan (Top 1000)", StrategyType.RECON,
                "SYN scan of top 1000 ports",
                tags={"active", "network", "ports"},
            ),
            StrategyRecord(
                "enum_dir_bruteforce", "Directory Brute-Force", StrategyType.ENUMERATION,
                "Common paths enumeration with status code analysis",
                required_conditions={"port_80_open"},
                tags={"active", "web", "directory"},
            ),
            StrategyRecord(
                "enum_vhost", "Virtual Host Discovery", StrategyType.ENUMERATION,
                "Discover virtual hosts via Host header fuzzing",
                required_conditions={"port_80_open"},
                tags={"active", "web", "vhost"},
            ),
            StrategyRecord(
                "vuln_sqli_basic", "Basic SQL Injection Scan", StrategyType.VULNERABILITY_SCAN,
                "Test common SQLi payloads on GET/POST parameters",
                required_techs={"MySQL", "PostgreSQL", "MSSQL"},
                tags={"active", "injection", "sqli"},
            ),
            StrategyRecord(
                "vuln_xss_reflected", "Reflected XSS Scan", StrategyType.VULNERABILITY_SCAN,
                "Test reflected XSS on all input points",
                required_conditions={"port_80_open"},
                tags={"active", "xss", "injection"},
            ),
            StrategyRecord(
                "vuln_ssrf_basic", "Basic SSRF Detection", StrategyType.VULNERABILITY_SCAN,
                "Test SSRF via URL parameters with callback",
                target_archetypes={TargetArchetype.WEB_APP_PYTHON, TargetArchetype.WEB_APP_NODE,
                                   TargetArchetype.API_REST},
                tags={"active", "ssrf"},
            ),
            StrategyRecord(
                "exploit_log4shell", "Log4Shell Exploitation", StrategyType.EXPLOITATION,
                "Exploit CVE-2021-44228 via JNDI injection",
                required_techs={"Java/Servlet", "log4j"},
                target_archetypes={TargetArchetype.WEB_APP_JAVA},
                tags={"critical", "rce", "log4j"},
            ),
            StrategyRecord(
                "exploit_spring4shell", "Spring4Shell Exploitation", StrategyType.EXPLOITATION,
                "Exploit CVE-2022-22965 via classLoader manipulation",
                required_techs={"Spring Boot"},
                target_archetypes={TargetArchetype.WEB_APP_JAVA},
                tags={"critical", "rce", "spring"},
            ),
            StrategyRecord(
                "exploit_wp_plugin", "WordPress Plugin Exploitation", StrategyType.EXPLOITATION,
                "Exploit known vulnerable WordPress plugins",
                required_techs={"WordPress"},
                target_archetypes={TargetArchetype.CMS_WORDPRESS},
                tags={"active", "wordpress", "plugin"},
            ),
            StrategyRecord(
                "evasion_waf_bypass", "WAF Bypass Techniques", StrategyType.EVASION,
                "Apply encoding and mutation techniques to bypass WAF rules",
                required_conditions={"waf_detected"},
                tags={"evasion", "waf", "encoding"},
            ),
            StrategyRecord(
                "fuzz_api_params", "API Parameter Fuzzing", StrategyType.FUZZING,
                "Fuzz API parameters with type confusion and boundary values",
                target_archetypes={TargetArchetype.API_REST, TargetArchetype.API_GRAPHQL},
                tags={"active", "api", "fuzzing"},
            ),
        ]
        for s in builtins:
            self._strategies[s.strategy_id] = s
