#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  🧠  SIREN COGNITIVE REASONER — Motor de Raciocinio Multi-Modal  🧠          ██
██                                                                                ██
██  Motor de raciocinio cognitivo NATIVO com 5 modalidades de inferencia:        ██
██  dedutivo, abdutivo, analogico, causal e contrafactual. UNICO no planeta     ██
██  em ferramentas de seguranca ofensiva.                                        ██
██                                                                                ██
██  Capacidades:                                                                  ██
██    • Raciocinio dedutivo: modus ponens, modus tollens, silogismos            ██
██    • Raciocinio abdutivo: melhor explicacao para observacoes anomalas         ██
██    • Raciocinio analogico: predicao cross-target por similaridade            ██
██    • Modelagem causal: redes Bayesianas de cadeias de ataque                 ██
██    • Analise contrafactual: "e se o firewall bloqueasse porta 443?"          ██
██    • 50+ regras de inferencia de seguranca pre-calibradas                    ██
██    • Navalha de Occam para selecao de hipoteses                              ██
██    • Banco de analogias target→vuln com scoring de similaridade              ██
██    • Rede causal com intervencoes e estimativa de forca causal               ██
██    • Geracao de relatorios explicaveis para cada conclusao                   ██
██    • Thread-safe com RLock para operacoes concorrentes                       ██
██    • Serializacao completa — cada estrutura tem .to_dict()                   ██
██                                                                                ██
██  Referências academicas:                                                       ██
██    • Pearl (2000) — Causality: Models, Reasoning, and Inference              ██
██    • Peirce (1903) — Abductive inference / inference to best explanation     ██
██    • Gentner (1983) — Structure-mapping theory of analogy                    ██
██    • Lewis (1973) — Counterfactuals                                          ██
██    • Halpern & Pearl (2005) — Causes and Explanations                        ██
██    • Shoham & Leyton-Brown (2009) — Multiagent Systems ch.13 (reasoning)    ██
██                                                                                ██
██  "A SIREN nao adivinha. Ela RACIOCINA em 5 dimensoes simultaneas."          ██
██                                                                                ██
████████████████████████████████████████████████████████████████████████████████████
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import math
import re
import statistics
import threading
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum, auto
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

logger = logging.getLogger("siren.cortex.cognitive_reasoner")


# ════════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════════════════════════════

EPSILON = 1e-12
MAX_CHAIN_DEPTH = 50
MAX_HYPOTHESES = 500
MAX_EVIDENCE_ITEMS = 10_000
MAX_RULES = 5_000
MAX_ANALOGIES = 2_000
MAX_CAUSAL_NODES = 1_000
SIMILARITY_THRESHOLD = 0.60
CONFIDENCE_DECAY_RATE = 0.05
OCCAM_COMPLEXITY_PENALTY = 0.10
DEFAULT_PRIOR = 0.01
DEFAULT_CAUSAL_STRENGTH = 0.5
COUNTERFACTUAL_BRANCH_LIMIT = 200
BAYESIAN_UPDATE_DAMPING = 0.85

_ANALOG_DIMENSION_WEIGHTS: Dict[str, float] = {
    "tech_stack": 0.25,
    "architecture": 0.10,
    "framework_versions": 0.15,
    "network_topology": 0.05,
    "auth_scheme": 0.10,
    "api_patterns": 0.10,
    "deployment_model": 0.05,
    "security_posture_score": 0.05,
    "industry": 0.05,
    "codebase_patterns": 0.10,
}


# ════════════════════════════════════════════════════════════════════════════════
# ENUMS
# ════════════════════════════════════════════════════════════════════════════════

class ReasoningMode(Enum):
    """Modalidades de raciocinio suportadas pelo motor cognitivo."""
    DEDUCTIVE = auto()
    ABDUCTIVE = auto()
    ANALOGICAL = auto()
    CAUSAL = auto()
    COUNTERFACTUAL = auto()


class EvidenceType(Enum):
    """Tipos de evidencia que alimentam o raciocinio."""
    SCAN_RESULT = auto()
    BANNER_GRAB = auto()
    PORT_STATE = auto()
    HTTP_RESPONSE = auto()
    HEADER_ANALYSIS = auto()
    CERTIFICATE_INFO = auto()
    DNS_RECORD = auto()
    WHOIS_DATA = auto()
    FINGERPRINT = auto()
    VULNERABILITY = auto()
    CONFIGURATION = auto()
    AUTHENTICATION = auto()
    ERROR_MESSAGE = auto()
    TIMING_OBSERVATION = auto()
    BEHAVIORAL = auto()
    NETWORK_TOPOLOGY = auto()
    VERSION_INFO = auto()
    TECHNOLOGY_STACK = auto()
    API_RESPONSE = auto()
    FUZZING_RESULT = auto()
    EXPLOIT_RESULT = auto()
    OSINT = auto()
    CVE_MATCH = auto()
    COMPLIANCE = auto()
    CUSTOM = auto()


class ConfidenceLevel(Enum):
    """Niveis de confianca discretizados para comunicacao humana."""
    CERTAIN = auto()       # 0.95 - 1.00
    HIGH = auto()          # 0.80 - 0.95
    MODERATE = auto()      # 0.60 - 0.80
    LOW = auto()           # 0.40 - 0.60
    SPECULATIVE = auto()   # 0.20 - 0.40
    NEGLIGIBLE = auto()    # 0.00 - 0.20


class HypothesisStatus(Enum):
    """Status do ciclo de vida de uma hipotese."""
    PROPOSED = auto()
    UNDER_EVALUATION = auto()
    SUPPORTED = auto()
    CONTRADICTED = auto()
    CONFIRMED = auto()
    REJECTED = auto()
    SUPERSEDED = auto()


class CausalRelationType(Enum):
    """Tipos de relacao causal entre nos do modelo."""
    ENABLES = auto()
    CAUSES = auto()
    PREVENTS = auto()
    MITIGATES = auto()
    AMPLIFIES = auto()
    REQUIRES = auto()
    CORRELATES = auto()


class AnalogySimilarityDimension(Enum):
    """Dimensoes de similaridade para raciocinio analogico."""
    TECH_STACK = auto()
    ARCHITECTURE = auto()
    FRAMEWORK_VERSION = auto()
    NETWORK_TOPOLOGY = auto()
    AUTHENTICATION_SCHEME = auto()
    API_PATTERN = auto()
    DEPLOYMENT_MODEL = auto()
    SECURITY_POSTURE = auto()
    INDUSTRY_SECTOR = auto()
    CODEBASE_PATTERN = auto()


class CounterfactualOutcome(Enum):
    """Resultado de uma analise contrafactual."""
    ATTACK_BLOCKED = auto()
    ATTACK_DEGRADED = auto()
    ATTACK_UNCHANGED = auto()
    ATTACK_REDIRECTED = auto()
    ATTACK_ESCALATED = auto()
    MITIGATED = auto()
    PARTIALLY_MITIGATED = auto()
    UNKNOWN = auto()


# ════════════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ════════════════════════════════════════════════════════════════════════════════

def _confidence_to_level(confidence: float) -> ConfidenceLevel:
    """Converte float de confianca para nivel discreto."""
    if confidence >= 0.95:
        return ConfidenceLevel.CERTAIN
    elif confidence >= 0.80:
        return ConfidenceLevel.HIGH
    elif confidence >= 0.60:
        return ConfidenceLevel.MODERATE
    elif confidence >= 0.40:
        return ConfidenceLevel.LOW
    elif confidence >= 0.20:
        return ConfidenceLevel.SPECULATIVE
    return ConfidenceLevel.NEGLIGIBLE


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    """Restringe valor ao intervalo [low, high]."""
    return max(low, min(high, value))


def _generate_id(prefix: str = "obj") -> str:
    """Gera ID unico com prefixo."""
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


def _hash_string(text: str) -> str:
    """Gera hash SHA-256 de uma string."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _weighted_average(values: List[Tuple[float, float]]) -> float:
    """Media ponderada de pares (valor, peso). Retorna 0.0 se vazio."""
    if not values:
        return 0.0
    total_weight = sum(w for _, w in values)
    if total_weight < EPSILON:
        return 0.0
    return sum(v * w for v, w in values) / total_weight


def _bayesian_update(prior: float, likelihood: float, evidence_strength: float) -> float:
    """Atualizacao Bayesiana simplificada: P(H|E) proporcional a P(E|H) * P(H)."""
    prior = _clamp(prior, EPSILON, 1.0 - EPSILON)
    likelihood = _clamp(likelihood, EPSILON, 1.0 - EPSILON)
    evidence_strength = _clamp(evidence_strength, 0.0, 1.0)

    p_e_given_h = likelihood * evidence_strength
    p_e_given_not_h = (1.0 - likelihood) * evidence_strength + (1.0 - evidence_strength) * 0.5
    p_e = p_e_given_h * prior + p_e_given_not_h * (1.0 - prior)

    if p_e < EPSILON:
        return prior

    posterior = (p_e_given_h * prior) / p_e
    # Damping to prevent oscillation
    damped = BAYESIAN_UPDATE_DAMPING * posterior + (1.0 - BAYESIAN_UPDATE_DAMPING) * prior
    return _clamp(damped)


def _jaccard_similarity(set_a: Set[str], set_b: Set[str]) -> float:
    """Coeficiente de Jaccard entre dois conjuntos."""
    if not set_a and not set_b:
        return 0.0
    intersection = len(set_a & set_b)
    union = len(set_a | set_b)
    return intersection / union if union > 0 else 0.0


def _cosine_similarity(vec_a: List[float], vec_b: List[float]) -> float:
    """Similaridade cosseno entre dois vetores."""
    if len(vec_a) != len(vec_b) or not vec_a:
        return 0.0
    dot = sum(a * b for a, b in zip(vec_a, vec_b))
    mag_a = math.sqrt(sum(a * a for a in vec_a))
    mag_b = math.sqrt(sum(b * b for b in vec_b))
    if mag_a < EPSILON or mag_b < EPSILON:
        return 0.0
    return _clamp(dot / (mag_a * mag_b), -1.0, 1.0)


def _timestamp() -> float:
    """Retorna timestamp atual."""
    return time.time()


def _normalize_fact(fact: str) -> str:
    """Normaliza string de fato para comparacao consistente."""
    return fact.strip().lower().replace(" ", "_")


def _stable_hash(s: str) -> float:
    """Hash estavel e deterministico para features categoricas."""
    return int(hashlib.sha256(s.encode("utf-8")).hexdigest()[:8], 16) / 0xFFFFFFFF


# ════════════════════════════════════════════════════════════════════════════════
# DATACLASSES
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class Evidence:
    """
    Peca de evidencia que alimenta o raciocinio cognitivo.

    Cada evidencia tem tipo, valor, fonte, confianca e timestamp.
    Multiplas evidencias sao combinadas para suportar ou contradizer hipoteses.
    """

    id: str = ""
    evidence_type: EvidenceType = EvidenceType.CUSTOM
    value: Any = None
    source: str = ""
    confidence: float = 0.5
    timestamp: float = 0.0
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    hash_digest: str = ""
    is_negation: bool = False
    corroborated_by: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.id:
            self.id = _generate_id("ev")
        if self.timestamp == 0.0:
            self.timestamp = _timestamp()
        if not self.hash_digest:
            raw = f"{self.evidence_type.name}:{self.value}:{self.source}"
            self.hash_digest = _hash_string(raw)
        self.confidence = _clamp(self.confidence)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "evidence_type": self.evidence_type.name,
            "value": self.value if not callable(self.value) else str(self.value),
            "source": self.source,
            "confidence": round(self.confidence, 4),
            "timestamp": self.timestamp,
            "tags": list(self.tags),
            "metadata": dict(self.metadata),
            "hash_digest": self.hash_digest,
            "is_negation": self.is_negation,
            "corroborated_by": list(self.corroborated_by),
            "confidence_level": _confidence_to_level(self.confidence).name,
        }

    def age_seconds(self) -> float:
        """Retorna idade da evidencia em segundos."""
        return _timestamp() - self.timestamp

    def decay_confidence(self, rate: float = CONFIDENCE_DECAY_RATE) -> float:
        """Aplica decaimento temporal a confianca."""
        age_hours = self.age_seconds() / 3600.0
        decayed = self.confidence * math.exp(-rate * age_hours)
        return _clamp(decayed)


@dataclass
class Hypothesis:
    """
    Hipotese a ser avaliada pelo motor de raciocinio.

    Mantém evidencias de suporte e contradicao, com status e confianca
    atualizados conforme novas evidencias chegam.
    """

    id: str = ""
    statement: str = ""
    confidence: float = DEFAULT_PRIOR
    supporting_evidence: List[str] = field(default_factory=list)
    contradicting_evidence: List[str] = field(default_factory=list)
    status: HypothesisStatus = HypothesisStatus.PROPOSED
    created_at: float = 0.0
    updated_at: float = 0.0
    reasoning_mode: ReasoningMode = ReasoningMode.DEDUCTIVE
    parent_hypothesis: Optional[str] = None
    child_hypotheses: List[str] = field(default_factory=list)
    complexity_score: float = 1.0
    domain: str = "security"
    tags: List[str] = field(default_factory=list)
    explanation: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.id:
            self.id = _generate_id("hyp")
        if self.created_at == 0.0:
            self.created_at = _timestamp()
        if self.updated_at == 0.0:
            self.updated_at = self.created_at
        self.confidence = _clamp(self.confidence)
        self.complexity_score = max(0.1, self.complexity_score)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "statement": self.statement,
            "confidence": round(self.confidence, 4),
            "supporting_evidence": list(self.supporting_evidence),
            "contradicting_evidence": list(self.contradicting_evidence),
            "status": self.status.name,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "reasoning_mode": self.reasoning_mode.name,
            "parent_hypothesis": self.parent_hypothesis,
            "child_hypotheses": list(self.child_hypotheses),
            "complexity_score": round(self.complexity_score, 4),
            "domain": self.domain,
            "tags": list(self.tags),
            "explanation": self.explanation,
            "confidence_level": _confidence_to_level(self.confidence).name,
            "metadata": dict(self.metadata),
        }

    def support_count(self) -> int:
        return len(self.supporting_evidence)

    def contradiction_count(self) -> int:
        return len(self.contradicting_evidence)

    def net_evidence_score(self) -> float:
        return float(self.support_count() - self.contradiction_count())


@dataclass
class InferenceRule:
    """
    Regra de inferencia: se antecedente, entao consequente, com confianca.

    Usada pelo motor dedutivo para modus ponens e modus tollens.
    Regras pre-calibradas cobrem cenarios comuns de seguranca.
    """

    id: str = ""
    name: str = ""
    antecedent: List[str] = field(default_factory=list)
    consequent: str = ""
    confidence: float = 0.8
    domain: str = "security"
    description: str = ""
    bidirectional: bool = False
    priority: int = 5
    tags: List[str] = field(default_factory=list)
    usage_count: int = 0
    success_rate: float = 1.0
    created_at: float = 0.0

    def __post_init__(self) -> None:
        if not self.id:
            self.id = _generate_id("rule")
        if self.created_at == 0.0:
            self.created_at = _timestamp()
        self.confidence = _clamp(self.confidence)
        self.priority = max(1, min(10, self.priority))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "antecedent": list(self.antecedent),
            "consequent": self.consequent,
            "confidence": round(self.confidence, 4),
            "domain": self.domain,
            "description": self.description,
            "bidirectional": self.bidirectional,
            "priority": self.priority,
            "tags": list(self.tags),
            "usage_count": self.usage_count,
            "success_rate": round(self.success_rate, 4),
            "created_at": self.created_at,
        }

    def matches_antecedent(self, facts: Set[str]) -> bool:
        """Verifica se todos os antecedentes estao presentes nos fatos."""
        return all(a in facts for a in self.antecedent)

    def record_usage(self, success: bool) -> None:
        """Registra uso da regra e atualiza success rate."""
        self.usage_count += 1
        if self.usage_count == 1:
            self.success_rate = 1.0 if success else 0.0
        else:
            alpha = 2.0 / (self.usage_count + 1)
            self.success_rate = alpha * (1.0 if success else 0.0) + (1.0 - alpha) * self.success_rate


@dataclass
class ReasoningStep:
    """Um passo individual numa cadeia de raciocinio."""

    step_number: int = 0
    mode: ReasoningMode = ReasoningMode.DEDUCTIVE
    premise: str = ""
    conclusion: str = ""
    rule_applied: str = ""
    confidence: float = 0.5
    evidence_used: List[str] = field(default_factory=list)
    explanation: str = ""
    timestamp: float = 0.0

    def __post_init__(self) -> None:
        if self.timestamp == 0.0:
            self.timestamp = _timestamp()
        self.confidence = _clamp(self.confidence)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_number": self.step_number,
            "mode": self.mode.name,
            "premise": self.premise,
            "conclusion": self.conclusion,
            "rule_applied": self.rule_applied,
            "confidence": round(self.confidence, 4),
            "evidence_used": list(self.evidence_used),
            "explanation": self.explanation,
            "timestamp": self.timestamp,
        }


@dataclass
class ReasoningChain:
    """
    Cadeia completa de raciocinio do inicio a conclusao.

    Encapsula passos sequenciais, conclusao final, confianca acumulada
    e o modo de raciocinio utilizado.
    """

    id: str = ""
    steps: List[ReasoningStep] = field(default_factory=list)
    conclusion: str = ""
    confidence: float = 0.0
    mode: ReasoningMode = ReasoningMode.DEDUCTIVE
    started_at: float = 0.0
    completed_at: float = 0.0
    premises: List[str] = field(default_factory=list)
    intermediate_conclusions: List[str] = field(default_factory=list)
    is_valid: bool = True
    invalidation_reason: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.id:
            self.id = _generate_id("chain")
        if self.started_at == 0.0:
            self.started_at = _timestamp()
        self.confidence = _clamp(self.confidence)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "steps": [s.to_dict() for s in self.steps],
            "conclusion": self.conclusion,
            "confidence": round(self.confidence, 4),
            "mode": self.mode.name,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "premises": list(self.premises),
            "intermediate_conclusions": list(self.intermediate_conclusions),
            "is_valid": self.is_valid,
            "invalidation_reason": self.invalidation_reason,
            "step_count": len(self.steps),
            "confidence_level": _confidence_to_level(self.confidence).name,
            "metadata": dict(self.metadata),
        }

    def add_step(self, step: ReasoningStep) -> None:
        """Adiciona passo a cadeia e recalcula confianca."""
        step.step_number = len(self.steps) + 1
        self.steps.append(step)
        self._recalculate_confidence()

    def _recalculate_confidence(self) -> None:
        """Confianca da cadeia = media geometrica das confiancas dos passos."""
        if not self.steps:
            self.confidence = 0.0
            return
        log_sum = sum(math.log(max(s.confidence, EPSILON)) for s in self.steps)
        self.confidence = _clamp(math.exp(log_sum / len(self.steps)))

    def finalize(self, conclusion: str) -> None:
        """Finaliza a cadeia com uma conclusao."""
        self.conclusion = conclusion
        self.completed_at = _timestamp()
        self._recalculate_confidence()


@dataclass
class ReasoningResult:
    """Resultado de uma operacao de raciocinio."""

    id: str = ""
    mode: ReasoningMode = ReasoningMode.DEDUCTIVE
    query: str = ""
    conclusion: str = ""
    confidence: float = 0.0
    chains: List[str] = field(default_factory=list)
    hypotheses_evaluated: int = 0
    rules_applied: int = 0
    evidence_considered: int = 0
    duration_ms: float = 0.0
    timestamp: float = 0.0
    explanation: str = ""
    alternatives: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.id:
            self.id = _generate_id("res")
        if self.timestamp == 0.0:
            self.timestamp = _timestamp()
        self.confidence = _clamp(self.confidence)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "mode": self.mode.name,
            "query": self.query,
            "conclusion": self.conclusion,
            "confidence": round(self.confidence, 4),
            "chains": list(self.chains),
            "hypotheses_evaluated": self.hypotheses_evaluated,
            "rules_applied": self.rules_applied,
            "evidence_considered": self.evidence_considered,
            "duration_ms": round(self.duration_ms, 2),
            "timestamp": self.timestamp,
            "explanation": self.explanation,
            "alternatives": list(self.alternatives),
            "warnings": list(self.warnings),
            "confidence_level": _confidence_to_level(self.confidence).name,
        }


@dataclass
class ReasoningReport:
    """Relatorio completo de sessao de raciocinio cognitivo."""

    id: str = ""
    title: str = ""
    target: str = ""
    created_at: float = 0.0
    results: List[ReasoningResult] = field(default_factory=list)
    total_evidence: int = 0
    total_hypotheses: int = 0
    total_rules: int = 0
    total_chains: int = 0
    modes_used: List[str] = field(default_factory=list)
    key_findings: List[str] = field(default_factory=list)
    risk_assessment: str = ""
    overall_confidence: float = 0.0
    recommendations: List[str] = field(default_factory=list)
    duration_ms: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.id:
            self.id = _generate_id("report")
        if self.created_at == 0.0:
            self.created_at = _timestamp()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "target": self.target,
            "created_at": self.created_at,
            "results": [r.to_dict() for r in self.results],
            "total_evidence": self.total_evidence,
            "total_hypotheses": self.total_hypotheses,
            "total_rules": self.total_rules,
            "total_chains": self.total_chains,
            "modes_used": list(self.modes_used),
            "key_findings": list(self.key_findings),
            "risk_assessment": self.risk_assessment,
            "overall_confidence": round(self.overall_confidence, 4),
            "recommendations": list(self.recommendations),
            "duration_ms": round(self.duration_ms, 2),
            "metadata": dict(self.metadata),
        }

    def add_result(self, result: ReasoningResult) -> None:
        """Adiciona resultado e recalcula metricas."""
        self.results.append(result)
        if result.mode.name not in self.modes_used:
            self.modes_used.append(result.mode.name)
        self._recalculate_overall()

    def _recalculate_overall(self) -> None:
        """Recalcula confianca geral como media ponderada dos resultados."""
        if not self.results:
            self.overall_confidence = 0.0
            return
        pairs = [(r.confidence, max(0.1, r.evidence_considered)) for r in self.results]
        self.overall_confidence = _clamp(_weighted_average(pairs))


@dataclass
class AnalogEntry:
    """Entrada no banco de analogias: target + vulnerabilidades associadas."""

    id: str = ""
    target_name: str = ""
    tech_stack: Set[str] = field(default_factory=set)
    architecture: str = ""
    framework_versions: Dict[str, str] = field(default_factory=dict)
    network_topology: str = ""
    auth_scheme: str = ""
    api_patterns: Set[str] = field(default_factory=set)
    deployment_model: str = ""
    security_posture_score: float = 0.5
    industry: str = ""
    codebase_patterns: Set[str] = field(default_factory=set)
    known_vulns: List[str] = field(default_factory=list)
    vuln_details: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    scan_date: float = 0.0

    def __post_init__(self) -> None:
        if not self.id:
            self.id = _generate_id("analog")
        if self.scan_date == 0.0:
            self.scan_date = _timestamp()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "target_name": self.target_name,
            "tech_stack": sorted(self.tech_stack),
            "architecture": self.architecture,
            "framework_versions": dict(self.framework_versions),
            "network_topology": self.network_topology,
            "auth_scheme": self.auth_scheme,
            "api_patterns": sorted(self.api_patterns),
            "deployment_model": self.deployment_model,
            "security_posture_score": round(self.security_posture_score, 4),
            "industry": self.industry,
            "codebase_patterns": sorted(self.codebase_patterns),
            "known_vulns": list(self.known_vulns),
            "vuln_details": dict(self.vuln_details),
            "scan_date": self.scan_date,
        }

    def feature_vector(self) -> List[float]:
        """Gera vetor numerico de features para comparacao."""
        vec: List[float] = []
        vec.append(len(self.tech_stack) / 20.0)
        vec.append(_stable_hash(self.architecture))
        vec.append(len(self.framework_versions) / 10.0)
        vec.append(_stable_hash(self.network_topology))
        vec.append(_stable_hash(self.auth_scheme))
        vec.append(len(self.api_patterns) / 20.0)
        vec.append(_stable_hash(self.deployment_model))
        vec.append(self.security_posture_score)
        vec.append(_stable_hash(self.industry))
        vec.append(len(self.codebase_patterns) / 20.0)
        vec.append(len(self.known_vulns) / 50.0)
        return vec

    def weighted_similarity(self, other: 'AnalogEntry') -> Tuple[float, Dict[str, float]]:
        """Calcula similaridade ponderada multi-dimensional."""
        dim_scores: Dict[str, float] = {}

        # Tech stack (Jaccard)
        dim_scores["tech_stack"] = _jaccard_similarity(self.tech_stack, other.tech_stack)
        # Architecture (exact match)
        dim_scores["architecture"] = 1.0 if self.architecture == other.architecture else 0.0
        # Framework versions (key overlap + version match)
        common_fw = set(self.framework_versions.keys()) & set(other.framework_versions.keys())
        all_fw = set(self.framework_versions.keys()) | set(other.framework_versions.keys())
        dim_scores["framework_versions"] = len(common_fw) / max(len(all_fw), 1)
        # Auth scheme
        dim_scores["auth_scheme"] = 1.0 if self.auth_scheme == other.auth_scheme else 0.0
        # API patterns (Jaccard)
        dim_scores["api_patterns"] = _jaccard_similarity(self.api_patterns, other.api_patterns)
        # Deployment model
        dim_scores["deployment_model"] = 1.0 if self.deployment_model == other.deployment_model else 0.0
        # Security posture (1 - abs diff)
        dim_scores["security_posture_score"] = 1.0 - abs(self.security_posture_score - other.security_posture_score)
        # Industry
        dim_scores["industry"] = 1.0 if self.industry == other.industry else 0.0
        # Codebase patterns (Jaccard)
        dim_scores["codebase_patterns"] = _jaccard_similarity(self.codebase_patterns, other.codebase_patterns)
        # Network topology
        dim_scores["network_topology"] = 1.0 if self.network_topology == other.network_topology else 0.0

        total = sum(
            _ANALOG_DIMENSION_WEIGHTS.get(dim, 0.1) * score
            for dim, score in dim_scores.items()
        )
        return total, dim_scores


@dataclass
class CausalNode:
    """No no modelo causal representando um evento ou condicao."""

    id: str = ""
    name: str = ""
    description: str = ""
    probability: float = DEFAULT_PRIOR
    is_observed: bool = False
    observed_value: Optional[bool] = None
    parents: List[str] = field(default_factory=list)
    children: List[str] = field(default_factory=list)
    conditional_probs: Dict[str, float] = field(default_factory=dict)
    node_type: str = "event"
    tags: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.id:
            self.id = _generate_id("cnode")
        self.probability = _clamp(self.probability)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "probability": round(self.probability, 4),
            "is_observed": self.is_observed,
            "observed_value": self.observed_value,
            "parents": list(self.parents),
            "children": list(self.children),
            "conditional_probs": dict(self.conditional_probs),
            "node_type": self.node_type,
            "tags": list(self.tags),
        }


@dataclass
class CausalEdge:
    """Aresta no modelo causal representando relacao entre nos."""

    id: str = ""
    source: str = ""
    target: str = ""
    relation: CausalRelationType = CausalRelationType.CAUSES
    strength: float = DEFAULT_CAUSAL_STRENGTH
    confidence: float = 0.7
    description: str = ""
    is_interventionable: bool = True

    def __post_init__(self) -> None:
        if not self.id:
            self.id = _generate_id("cedge")
        self.strength = _clamp(self.strength)
        self.confidence = _clamp(self.confidence)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source,
            "target": self.target,
            "relation": self.relation.name,
            "strength": round(self.strength, 4),
            "confidence": round(self.confidence, 4),
            "description": self.description,
            "is_interventionable": self.is_interventionable,
        }


@dataclass
class CounterfactualScenario:
    """Cenario contrafactual: 'e se X fosse diferente?'"""

    id: str = ""
    description: str = ""
    intervention: str = ""
    original_state: str = ""
    counterfactual_state: str = ""
    outcome: CounterfactualOutcome = CounterfactualOutcome.UNKNOWN
    confidence: float = 0.0
    risk_reduction: float = 0.0
    affected_facts: List[str] = field(default_factory=list)
    chain_broken_at: str = ""
    timestamp: float = 0.0

    def __post_init__(self) -> None:
        if not self.id:
            self.id = _generate_id("cf")
        if self.timestamp == 0.0:
            self.timestamp = _timestamp()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "description": self.description,
            "intervention": self.intervention,
            "original_state": self.original_state,
            "counterfactual_state": self.counterfactual_state,
            "outcome": self.outcome.name,
            "confidence": round(self.confidence, 4),
            "risk_reduction": round(self.risk_reduction, 4),
            "affected_facts": list(self.affected_facts),
            "chain_broken_at": self.chain_broken_at,
            "timestamp": self.timestamp,
        }


@dataclass
class AbductiveExplanation:
    """Explicacao candidata no raciocinio abdutivo."""

    id: str = ""
    observation: str = ""
    explanation: str = ""
    prior_probability: float = DEFAULT_PRIOR
    likelihood: float = 0.5
    posterior: float = 0.0
    complexity: float = 1.0
    occam_adjusted_score: float = 0.0
    supporting_facts: List[str] = field(default_factory=list)
    competing_explanations: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.id:
            self.id = _generate_id("abd")
        self.prior_probability = _clamp(self.prior_probability)
        self.likelihood = _clamp(self.likelihood)
        self._compute_posterior()

    def _compute_posterior(self) -> None:
        """Calcula posterior raw (sera normalizado externamente)."""
        self.posterior = self.prior_probability * self.likelihood
        penalty = OCCAM_COMPLEXITY_PENALTY * (self.complexity - 1.0)
        self.occam_adjusted_score = _clamp(self.posterior - penalty)

    @staticmethod
    def normalize_group(explanations: List['AbductiveExplanation']) -> None:
        """Normaliza posteriors de um grupo de explicacoes competidoras (Bayes completo)."""
        total = sum(e.posterior for e in explanations)
        if total > EPSILON:
            for e in explanations:
                e.posterior = e.posterior / total
                penalty = OCCAM_COMPLEXITY_PENALTY * (e.complexity - 1.0)
                e.occam_adjusted_score = _clamp(e.posterior - penalty)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "observation": self.observation,
            "explanation": self.explanation,
            "prior_probability": round(self.prior_probability, 4),
            "likelihood": round(self.likelihood, 4),
            "posterior": round(self.posterior, 4),
            "complexity": round(self.complexity, 4),
            "occam_adjusted_score": round(self.occam_adjusted_score, 4),
            "supporting_facts": list(self.supporting_facts),
            "competing_explanations": list(self.competing_explanations),
        }


@dataclass
class AnalogyResult:
    """Resultado de raciocinio analogico entre dois targets."""

    id: str = ""
    source_target: str = ""
    dest_target: str = ""
    similarity_score: float = 0.0
    dimension_scores: Dict[str, float] = field(default_factory=dict)
    predicted_vulns: List[str] = field(default_factory=list)
    prediction_confidence: Dict[str, float] = field(default_factory=dict)
    explanation: str = ""
    timestamp: float = 0.0

    def __post_init__(self) -> None:
        if not self.id:
            self.id = _generate_id("analogy")
        if self.timestamp == 0.0:
            self.timestamp = _timestamp()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "source_target": self.source_target,
            "dest_target": self.dest_target,
            "similarity_score": round(self.similarity_score, 4),
            "dimension_scores": {k: round(v, 4) for k, v in self.dimension_scores.items()},
            "predicted_vulns": list(self.predicted_vulns),
            "prediction_confidence": {k: round(v, 4) for k, v in self.prediction_confidence.items()},
            "explanation": self.explanation,
            "timestamp": self.timestamp,
        }


# ════════════════════════════════════════════════════════════════════════════════
# DEDUCTIVE ENGINE
# ════════════════════════════════════════════════════════════════════════════════

class DeductiveEngine:
    """
    Motor de raciocinio dedutivo com modus ponens, modus tollens e silogismos.

    Aplica regras de inferencia a fatos conhecidos para derivar novas conclusoes.
    Inclui 50+ regras de seguranca pre-calibradas para cenarios comuns.

    Usage:
        engine = DeductiveEngine()
        engine.add_fact("port_443_open")
        engine.add_fact("apache_2449")
        results = engine.forward_chain()
        # results contem "likely_cve_2021_41773"
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._facts: Set[str] = set()
        self._negated_facts: Set[str] = set()
        self._rules: List[InferenceRule] = []
        self._derived: Set[str] = set()
        self._derivation_trace: Dict[str, List[str]] = {}
        self._chains: List[ReasoningChain] = []
        self._inference_count: int = 0
        self._rule_index: Dict[str, List[int]] = defaultdict(list)
        self._load_security_rules()
        logger.info("DeductiveEngine initialized with %d security rules", len(self._rules))

    # ── Fact management ──────────────────────────────────────────────────────

    def add_fact(self, fact: str) -> None:
        """Adiciona fato ao banco de conhecimento."""
        with self._lock:
            normalized = _normalize_fact(fact)
            self._facts.add(normalized)
            logger.debug("Fact added: %s", normalized)

    def add_facts(self, facts: List[str]) -> None:
        """Adiciona multiplos fatos."""
        with self._lock:
            for f in facts:
                normalized = _normalize_fact(f)
                self._facts.add(normalized)

    def negate_fact(self, fact: str) -> None:
        """Registra negacao de um fato."""
        with self._lock:
            normalized = _normalize_fact(fact)
            self._negated_facts.add(normalized)
            self._facts.discard(normalized)

    def has_fact(self, fact: str) -> bool:
        """Verifica se fato existe."""
        normalized = _normalize_fact(fact)
        return normalized in self._facts or normalized in self._derived

    def get_all_facts(self) -> Set[str]:
        """Retorna todos os fatos (originais + derivados)."""
        with self._lock:
            return self._facts | self._derived

    def clear_facts(self) -> None:
        """Limpa todos os fatos e derivacoes."""
        with self._lock:
            self._facts.clear()
            self._negated_facts.clear()
            self._derived.clear()
            self._derivation_trace.clear()
            self._chains.clear()
            self._inference_count = 0

    # ── Rule management ──────────────────────────────────────────────────────

    def add_rule(self, rule: InferenceRule) -> None:
        """Adiciona regra de inferencia."""
        with self._lock:
            idx = len(self._rules)
            self._rules.append(rule)
            for ant in rule.antecedent:
                self._rule_index[_normalize_fact(ant)].append(idx)

    def add_rules(self, rules: List[InferenceRule]) -> None:
        """Adiciona multiplas regras."""
        for r in rules:
            self.add_rule(r)

    def get_rules(self) -> List[InferenceRule]:
        """Retorna todas as regras."""
        with self._lock:
            return list(self._rules)

    # ── Modus Ponens ─────────────────────────────────────────────────────────

    def modus_ponens(self, rule: InferenceRule, known_facts: Set[str]) -> Optional[str]:
        """
        Modus Ponens: Se A->B e A e verdade, entao B e verdade.

        Verifica se todos os antecedentes da regra estao nos fatos conhecidos.
        Se sim, retorna o consequente.
        """
        if rule.matches_antecedent(known_facts):
            rule.record_usage(True)
            self._inference_count += 1
            return rule.consequent
        return None

    # ── Modus Tollens ────────────────────────────────────────────────────────

    def modus_tollens(self, rule: InferenceRule, negated: Set[str]) -> Optional[List[str]]:
        """
        Modus Tollens: Se A->B e NOT B, entao NOT A (pelo menos um antecedente falso).

        Se o consequente esta negado, retorna os antecedentes como potencialmente falsos.
        """
        consequent_norm = _normalize_fact(rule.consequent)
        if consequent_norm in negated:
            rule.record_usage(True)
            self._inference_count += 1
            return list(rule.antecedent)
        return None

    # ── Hypothetical Syllogism ───────────────────────────────────────────────

    def hypothetical_syllogism(
        self, rule_a: InferenceRule, rule_b: InferenceRule
    ) -> Optional[InferenceRule]:
        """
        Silogismo hipotetico: Se A->B e B->C, entao A->C.

        Combina duas regras onde o consequente da primeira e antecedente da segunda.
        """
        consequent_a = _normalize_fact(rule_a.consequent)
        antecedents_b_norm = {_normalize_fact(a) for a in rule_b.antecedent}

        if consequent_a in antecedents_b_norm and len(antecedents_b_norm) == 1:
            combined_confidence = rule_a.confidence * rule_b.confidence
            return InferenceRule(
                name=f"syllogism({rule_a.name}+{rule_b.name})",
                antecedent=list(rule_a.antecedent),
                consequent=rule_b.consequent,
                confidence=combined_confidence,
                domain=rule_a.domain,
                description=f"Derived via hypothetical syllogism: {rule_a.name} + {rule_b.name}",
                tags=["derived", "syllogism"],
            )
        return None

    # ── Disjunctive Syllogism ────────────────────────────────────────────────

    def disjunctive_syllogism(
        self, options: List[str], negated: Set[str]
    ) -> Optional[str]:
        """
        Silogismo disjuntivo: Se A ou B, e NOT A, entao B.

        Dado um conjunto de opcoes disjuntas, elimina as negadas.
        """
        remaining = [o for o in options if _normalize_fact(o) not in negated]
        if len(remaining) == 1:
            return remaining[0]
        return None

    # ── Forward Chaining ─────────────────────────────────────────────────────

    def forward_chain(self, max_iterations: int = MAX_CHAIN_DEPTH) -> List[str]:
        """
        Encadeamento para frente: aplica regras repetidamente ate saturacao.

        Retorna lista de novos fatos derivados.
        """
        with self._lock:
            chain = ReasoningChain(mode=ReasoningMode.DEDUCTIVE, premises=list(self._facts))
            new_derived: List[str] = []
            all_known = self._facts | self._derived

            new_in_prev_round: List[str] = []

            for iteration in range(max_iterations):
                new_in_this_round: List[str] = []

                # Conflict resolution strategy: when multiple rules produce
                # contradictory conclusions (e.g. "X" vs "not_X"), we prefer
                # the rule with (1) higher confidence, then (2) more specific
                # conditions (more antecedents). Rules are sorted accordingly
                # so the first match for a given conclusion wins.

                # Gather candidate rules from index based on relevant facts
                candidate_rule_indices: Set[int] = set()
                facts_to_check = new_in_prev_round if iteration > 0 else all_known
                for fact in facts_to_check:
                    candidate_rule_indices.update(self._rule_index.get(fact, []))

                # Only check candidate rules, not all rules
                candidate_rules = [self._rules[i] for i in candidate_rule_indices]
                sorted_rules = sorted(
                    candidate_rules,
                    key=lambda r: (-r.confidence, -len(r.antecedent), -r.priority),
                )

                # Collect all candidate firings this round before committing
                candidates: Dict[str, Tuple[str, InferenceRule]] = {}
                for rule in sorted_rules:
                    result = self.modus_ponens(rule, all_known)
                    if result:
                        result_norm = _normalize_fact(result)
                        if result_norm not in all_known and result_norm not in self._negated_facts:
                            # Check for contradictory conclusions already queued
                            neg_key = f"not_{result_norm}"
                            pos_key = result_norm.replace("not_", "", 1) if result_norm.startswith("not_") else None
                            conflict_key = neg_key if neg_key in candidates else (
                                pos_key if pos_key and pos_key in candidates else None
                            )
                            if conflict_key is not None:
                                # A contradictory conclusion was already queued by a
                                # higher-confidence / more-specific rule — skip this one.
                                logger.debug(
                                    "Conflict resolution: '%s' from rule '%s' suppressed "
                                    "in favor of '%s' from rule '%s'",
                                    result_norm, rule.name,
                                    conflict_key, candidates[conflict_key][1].name,
                                )
                                continue
                            candidates[result_norm] = (result_norm, rule)

                # Commit the winning candidates
                for result_norm, rule in candidates.values():
                    self._derived.add(result_norm)
                    all_known.add(result_norm)
                    new_in_this_round.append(result_norm)
                    new_derived.append(result_norm)
                    self._derivation_trace[result_norm] = list(rule.antecedent)

                    step = ReasoningStep(
                        mode=ReasoningMode.DEDUCTIVE,
                        premise=" AND ".join(rule.antecedent),
                        conclusion=result_norm,
                        rule_applied=rule.name,
                        confidence=rule.confidence * rule.success_rate,
                        explanation=f"Modus ponens: {rule.description or rule.name}",
                    )
                    chain.add_step(step)

                # Modus tollens pass
                for rule in sorted_rules:
                    tollens_result = self.modus_tollens(rule, self._negated_facts)
                    if tollens_result:
                        for ant in tollens_result:
                            ant_norm = _normalize_fact(ant)
                            neg_key = f"not_{ant_norm}"
                            if neg_key not in all_known:
                                self._derived.add(neg_key)
                                all_known.add(neg_key)
                                new_in_this_round.append(neg_key)
                                new_derived.append(neg_key)

                                step = ReasoningStep(
                                    mode=ReasoningMode.DEDUCTIVE,
                                    premise=f"NOT {rule.consequent}",
                                    conclusion=f"NOT {ant_norm} (possible)",
                                    rule_applied=f"tollens({rule.name})",
                                    confidence=rule.confidence * 0.9,
                                    explanation=f"Modus tollens on {rule.name}",
                                )
                                chain.add_step(step)

                if not new_in_this_round:
                    break
                new_in_prev_round = new_in_this_round

            if new_derived:
                chain.finalize(f"Derived {len(new_derived)} new conclusions")
                chain.intermediate_conclusions = new_derived
            else:
                chain.finalize("No new conclusions derivable")

            self._chains.append(chain)
            logger.info(
                "Forward chain complete: %d new facts in %d inferences",
                len(new_derived),
                self._inference_count,
            )
            return new_derived

    # ── Backward Chaining ────────────────────────────────────────────────────

    def backward_chain(self, goal: str, max_depth: int = MAX_CHAIN_DEPTH) -> bool:
        """
        Encadeamento para tras: tenta provar um goal a partir dos fatos e regras.

        Uses a shared `visited` set to detect cycles across branches and a
        `max_depth` limit to prevent infinite recursion.

        Retorna True se o goal pode ser provado.
        """
        with self._lock:
            goal_norm = _normalize_fact(goal)
            visited: Set[str] = set()
            return self._backward_chain_recursive(goal_norm, visited, 0, max_depth)

    def _backward_chain_recursive(
        self, goal: str, visited: Set[str], depth: int, max_depth: int
    ) -> bool:
        """Recursao do encadeamento para tras com deteccao de ciclos."""
        if depth >= max_depth:
            logger.warning(
                "Backward chaining max depth (%d) reached for goal '%s' — "
                "terminating to prevent infinite recursion",
                max_depth, goal,
            )
            return False
        if goal in visited:
            logger.warning(
                "Cycle detected in backward chaining: goal '%s' already visited — "
                "terminating branch to avoid infinite loop",
                goal,
            )
            return False

        all_known = self._facts | self._derived
        if goal in all_known:
            return True

        visited.add(goal)

        for rule in self._rules:
            consequent_norm = _normalize_fact(rule.consequent)
            if consequent_norm == goal:
                all_proved = True
                for ant in rule.antecedent:
                    ant_norm = _normalize_fact(ant)
                    if not self._backward_chain_recursive(ant_norm, visited, depth + 1, max_depth):
                        all_proved = False
                        break
                if all_proved:
                    self._derived.add(goal)
                    self._derivation_trace[goal] = list(rule.antecedent)
                    rule.record_usage(True)
                    visited.discard(goal)
                    return True

        visited.discard(goal)
        return False

    # ── Syllogism Chain Builder ──────────────────────────────────────────────

    def build_syllogism_chains(self) -> List[InferenceRule]:
        """
        Constroi cadeias de silogismo combinando regras transitivas.

        A->B e B->C => A->C (com confianca combinada).
        """
        with self._lock:
            derived_rules: List[InferenceRule] = []
            rule_by_consequent: Dict[str, List[InferenceRule]] = defaultdict(list)

            for rule in self._rules:
                key = _normalize_fact(rule.consequent)
                rule_by_consequent[key].append(rule)

            for rule_b in self._rules:
                for ant in rule_b.antecedent:
                    ant_norm = _normalize_fact(ant)
                    if ant_norm in rule_by_consequent:
                        for rule_a in rule_by_consequent[ant_norm]:
                            combined = self.hypothetical_syllogism(rule_a, rule_b)
                            if combined:
                                derived_rules.append(combined)

            logger.info("Built %d syllogism chains", len(derived_rules))
            return derived_rules

    # ── Explanation / Trace ──────────────────────────────────────────────────

    def explain_derivation(self, fact: str) -> List[str]:
        """
        Explica como um fato foi derivado, retornando a cadeia de raciocinio.
        """
        with self._lock:
            fact_norm = _normalize_fact(fact)
            trace: List[str] = []
            self._trace_recursive(fact_norm, trace, set())
            return trace

    def _trace_recursive(self, fact: str, trace: List[str], visited: Set[str]) -> None:
        """Reconstroi trace de derivacao recursivamente."""
        if fact in visited:
            return
        visited.add(fact)

        if fact in self._derivation_trace:
            antecedents = self._derivation_trace[fact]
            rule_name = self._find_rule_for_derivation(antecedents, fact)
            trace.append(
                f"{' AND '.join(antecedents)} -> {fact} [rule: {rule_name}]"
            )
            for ant in antecedents:
                ant_norm = _normalize_fact(ant)
                self._trace_recursive(ant_norm, trace, visited)
        elif fact in self._facts:
            trace.append(f"{fact} [given fact]")

    def _find_rule_for_derivation(self, antecedents: List[str], consequent: str) -> str:
        """Encontra o nome da regra usada na derivacao."""
        ant_set = {_normalize_fact(a) for a in antecedents}
        for rule in self._rules:
            rule_ant_set = {_normalize_fact(a) for a in rule.antecedent}
            rule_cons = _normalize_fact(rule.consequent)
            if rule_ant_set == ant_set and rule_cons == consequent:
                return rule.name
        return "unknown"

    # ── Statistics ───────────────────────────────────────────────────────────

    def get_statistics(self) -> Dict[str, Any]:
        """Retorna estatisticas do motor dedutivo."""
        with self._lock:
            return {
                "total_facts": len(self._facts),
                "total_derived": len(self._derived),
                "total_negated": len(self._negated_facts),
                "total_rules": len(self._rules),
                "total_inferences": self._inference_count,
                "total_chains": len(self._chains),
                "rule_usage": {
                    r.name: {"count": r.usage_count, "success_rate": round(r.success_rate, 4)}
                    for r in self._rules if r.usage_count > 0
                },
            }

    def to_dict(self) -> Dict[str, Any]:
        """Serializa estado do motor."""
        with self._lock:
            return {
                "facts": sorted(self._facts),
                "derived": sorted(self._derived),
                "negated": sorted(self._negated_facts),
                "rules": [r.to_dict() for r in self._rules],
                "chains": [c.to_dict() for c in self._chains],
                "statistics": self.get_statistics(),
            }

    # ── Security Rules (50+) ────────────────────────────────────────────────

    def _load_security_rules(self) -> None:
        """Carrega regras de inferencia de seguranca pre-calibradas."""
        security_rules = [
            # ── Web Server / CVE Rules ───────────────────────────────────
            InferenceRule(
                name="apache_2449_path_traversal",
                antecedent=["port_443_open", "apache_2449"],
                consequent="likely_cve_2021_41773",
                confidence=0.92,
                description="Apache 2.4.49 path traversal CVE-2021-41773",
                tags=["web", "apache", "cve", "path_traversal"],
                priority=9,
            ),
            InferenceRule(
                name="apache_2450_rce",
                antecedent=["port_443_open", "apache_2450"],
                consequent="likely_cve_2021_42013",
                confidence=0.90,
                description="Apache 2.4.50 RCE CVE-2021-42013",
                tags=["web", "apache", "cve", "rce"],
                priority=9,
            ),
            InferenceRule(
                name="log4j_rce",
                antecedent=["java_application", "log4j_version_lt_2_17"],
                consequent="likely_cve_2021_44228_log4shell",
                confidence=0.95,
                description="Log4Shell RCE CVE-2021-44228",
                tags=["java", "log4j", "cve", "rce"],
                priority=10,
            ),
            InferenceRule(
                name="spring4shell",
                antecedent=["java_application", "spring_framework_lt_5_3_18", "jdk_9_or_higher"],
                consequent="likely_cve_2022_22965_spring4shell",
                confidence=0.88,
                description="Spring4Shell RCE CVE-2022-22965",
                tags=["java", "spring", "cve", "rce"],
                priority=10,
            ),
            InferenceRule(
                name="nginx_alias_traversal",
                antecedent=["nginx_server", "alias_misconfiguration"],
                consequent="nginx_alias_path_traversal",
                confidence=0.85,
                description="Nginx alias path traversal via misconfigured alias directive",
                tags=["web", "nginx", "path_traversal"],
                priority=8,
            ),

            # ── Authentication / JWT / Session ───────────────────────────
            InferenceRule(
                name="jwt_none_algorithm",
                antecedent=["jwt_none_alg_accepted"],
                consequent="auth_bypass_possible",
                confidence=0.95,
                description="JWT 'none' algorithm accepted = authentication bypass",
                tags=["auth", "jwt", "bypass"],
                priority=10,
            ),
            InferenceRule(
                name="jwt_weak_secret",
                antecedent=["jwt_hs256", "jwt_secret_crackable"],
                consequent="jwt_forgery_possible",
                confidence=0.90,
                description="JWT with weak HS256 secret allows token forgery",
                tags=["auth", "jwt", "crypto"],
                priority=9,
            ),
            InferenceRule(
                name="jwt_kid_injection",
                antecedent=["jwt_kid_parameter", "kid_value_controllable"],
                consequent="jwt_key_injection_possible",
                confidence=0.85,
                description="JWT kid parameter injection for key confusion",
                tags=["auth", "jwt", "injection"],
                priority=8,
            ),
            InferenceRule(
                name="jwt_alg_confusion",
                antecedent=["jwt_rs256", "server_accepts_hs256"],
                consequent="jwt_algorithm_confusion_attack",
                confidence=0.88,
                description="JWT RS256/HS256 algorithm confusion attack",
                tags=["auth", "jwt", "crypto"],
                priority=9,
            ),
            InferenceRule(
                name="session_fixation",
                antecedent=["session_id_in_url", "no_session_regeneration"],
                consequent="session_fixation_possible",
                confidence=0.80,
                description="Session fixation via URL-based session IDs",
                tags=["auth", "session"],
                priority=7,
            ),
            InferenceRule(
                name="default_credentials",
                antecedent=["admin_panel_exposed", "default_creds_work"],
                consequent="full_admin_access",
                confidence=0.98,
                description="Default credentials on exposed admin panel",
                tags=["auth", "credentials"],
                priority=10,
            ),
            InferenceRule(
                name="brute_force_possible",
                antecedent=["login_endpoint", "no_rate_limiting", "no_captcha"],
                consequent="brute_force_viable",
                confidence=0.85,
                description="No rate limiting or CAPTCHA on login",
                tags=["auth", "brute_force"],
                priority=7,
            ),
            InferenceRule(
                name="oauth_redirect_hijack",
                antecedent=["oauth_implementation", "open_redirect_in_callback"],
                consequent="oauth_token_theft_possible",
                confidence=0.82,
                description="OAuth redirect URI hijacking via open redirect",
                tags=["auth", "oauth", "redirect"],
                priority=8,
            ),

            # ── CORS / Headers ───────────────────────────────────────────
            InferenceRule(
                name="cors_wildcard_credentials",
                antecedent=["cors_wildcard", "credentials_true"],
                consequent="session_hijack_possible",
                confidence=0.88,
                description="CORS wildcard with credentials = session hijack",
                tags=["cors", "headers", "session"],
                priority=9,
            ),
            InferenceRule(
                name="cors_null_origin",
                antecedent=["cors_allows_null_origin", "credentials_true"],
                consequent="cors_null_origin_exploit",
                confidence=0.85,
                description="CORS null origin bypass with credentials",
                tags=["cors", "headers"],
                priority=8,
            ),
            InferenceRule(
                name="missing_csp",
                antecedent=["no_csp_header", "user_input_reflected"],
                consequent="xss_likely",
                confidence=0.75,
                description="Missing CSP with reflected input increases XSS risk",
                tags=["headers", "xss", "csp"],
                priority=7,
            ),
            InferenceRule(
                name="missing_hsts",
                antecedent=["no_hsts_header", "http_available"],
                consequent="ssl_stripping_possible",
                confidence=0.70,
                description="Missing HSTS allows SSL stripping attacks",
                tags=["headers", "ssl", "mitm"],
                priority=6,
            ),
            InferenceRule(
                name="clickjacking",
                antecedent=["no_x_frame_options", "no_csp_frame_ancestors"],
                consequent="clickjacking_possible",
                confidence=0.80,
                description="Missing frame protection allows clickjacking",
                tags=["headers", "clickjacking"],
                priority=6,
            ),

            # ── Injection ────────────────────────────────────────────────
            InferenceRule(
                name="sqli_error_based",
                antecedent=["sql_error_in_response", "user_input_in_query"],
                consequent="sql_injection_likely",
                confidence=0.90,
                description="SQL error messages + user input = SQLi likely",
                tags=["injection", "sqli"],
                priority=9,
            ),
            InferenceRule(
                name="sqli_time_based",
                antecedent=["response_time_anomaly", "parameterized_delay_correlation"],
                consequent="time_based_blind_sqli",
                confidence=0.85,
                description="Time-based blind SQL injection detected",
                tags=["injection", "sqli", "blind"],
                priority=9,
            ),
            InferenceRule(
                name="nosql_injection",
                antecedent=["mongodb_backend", "json_input_accepted", "operator_injection_works"],
                consequent="nosql_injection_confirmed",
                confidence=0.88,
                description="NoSQL injection in MongoDB via operator injection",
                tags=["injection", "nosql", "mongodb"],
                priority=9,
            ),
            InferenceRule(
                name="command_injection",
                antecedent=["user_input_in_command", "shell_metachar_not_filtered"],
                consequent="os_command_injection",
                confidence=0.90,
                description="OS command injection via unfiltered metacharacters",
                tags=["injection", "command", "rce"],
                priority=10,
            ),
            InferenceRule(
                name="ssti_detection",
                antecedent=["template_engine_detected", "math_expression_evaluated"],
                consequent="ssti_likely",
                confidence=0.88,
                description="Server-Side Template Injection detected",
                tags=["injection", "ssti", "rce"],
                priority=9,
            ),
            InferenceRule(
                name="xxe_injection",
                antecedent=["xml_input_accepted", "external_entity_processed"],
                consequent="xxe_confirmed",
                confidence=0.90,
                description="XML External Entity injection confirmed",
                tags=["injection", "xxe"],
                priority=9,
            ),
            InferenceRule(
                name="ldap_injection",
                antecedent=["ldap_backend", "user_input_in_filter", "special_chars_not_escaped"],
                consequent="ldap_injection_possible",
                confidence=0.82,
                description="LDAP injection via unescaped filter input",
                tags=["injection", "ldap"],
                priority=8,
            ),
            InferenceRule(
                name="xpath_injection",
                antecedent=["xml_data_store", "user_input_in_xpath"],
                consequent="xpath_injection_possible",
                confidence=0.80,
                description="XPath injection in XML data queries",
                tags=["injection", "xpath"],
                priority=7,
            ),
            InferenceRule(
                name="header_injection",
                antecedent=["user_input_in_header", "crlf_not_filtered"],
                consequent="http_header_injection",
                confidence=0.85,
                description="HTTP header injection via CRLF",
                tags=["injection", "headers", "crlf"],
                priority=8,
            ),

            # ── SSRF / File Inclusion ────────────────────────────────────
            InferenceRule(
                name="ssrf_basic",
                antecedent=["url_parameter_accepted", "internal_ip_accessible"],
                consequent="ssrf_confirmed",
                confidence=0.88,
                description="SSRF: internal resources accessible via URL param",
                tags=["ssrf"],
                priority=9,
            ),
            InferenceRule(
                name="ssrf_cloud_metadata",
                antecedent=["ssrf_confirmed", "cloud_environment"],
                consequent="cloud_metadata_exfil_possible",
                confidence=0.90,
                description="SSRF in cloud = metadata service exposure (169.254.169.254)",
                tags=["ssrf", "cloud", "metadata"],
                priority=10,
            ),
            InferenceRule(
                name="lfi_detection",
                antecedent=["file_path_in_parameter", "directory_traversal_works"],
                consequent="local_file_inclusion",
                confidence=0.90,
                description="Local File Inclusion via directory traversal",
                tags=["file_inclusion", "lfi"],
                priority=9,
            ),
            InferenceRule(
                name="lfi_to_rce",
                antecedent=["local_file_inclusion", "log_poisoning_possible"],
                consequent="lfi_to_rce_chain",
                confidence=0.80,
                description="LFI to RCE via log poisoning",
                tags=["file_inclusion", "lfi", "rce", "chain"],
                priority=9,
            ),
            InferenceRule(
                name="rfi_detection",
                antecedent=["file_path_in_parameter", "remote_url_accepted"],
                consequent="remote_file_inclusion",
                confidence=0.85,
                description="Remote File Inclusion detected",
                tags=["file_inclusion", "rfi", "rce"],
                priority=9,
            ),

            # ── Cryptography ─────────────────────────────────────────────
            InferenceRule(
                name="weak_tls",
                antecedent=["tls_1_0_supported"],
                consequent="weak_tls_downgrade_possible",
                confidence=0.75,
                description="TLS 1.0 supported enables downgrade attacks",
                tags=["crypto", "tls"],
                priority=6,
            ),
            InferenceRule(
                name="ssl_v3",
                antecedent=["ssl_v3_supported"],
                consequent="poodle_attack_possible",
                confidence=0.90,
                description="SSLv3 supported = POODLE attack vector",
                tags=["crypto", "ssl", "poodle"],
                priority=8,
            ),
            InferenceRule(
                name="weak_cipher_suites",
                antecedent=["rc4_cipher_supported"],
                consequent="weak_encryption_in_use",
                confidence=0.85,
                description="RC4 cipher still supported",
                tags=["crypto", "cipher"],
                priority=7,
            ),
            InferenceRule(
                name="self_signed_cert",
                antecedent=["self_signed_certificate", "production_environment"],
                consequent="mitm_risk_elevated",
                confidence=0.70,
                description="Self-signed cert in production = MITM risk",
                tags=["crypto", "certificate", "mitm"],
                priority=6,
            ),
            InferenceRule(
                name="expired_certificate",
                antecedent=["certificate_expired"],
                consequent="certificate_trust_broken",
                confidence=0.95,
                description="Expired certificate breaks trust chain",
                tags=["crypto", "certificate"],
                priority=7,
            ),

            # ── Deserialization / File Upload ────────────────────────────
            InferenceRule(
                name="java_deserialization",
                antecedent=["java_application", "serialized_object_accepted"],
                consequent="java_deserialization_rce",
                confidence=0.85,
                description="Java deserialization leading to RCE",
                tags=["deserialization", "java", "rce"],
                priority=9,
            ),
            InferenceRule(
                name="python_pickle",
                antecedent=["python_application", "pickle_deserialization"],
                consequent="python_pickle_rce",
                confidence=0.90,
                description="Python pickle deserialization = RCE",
                tags=["deserialization", "python", "rce"],
                priority=9,
            ),
            InferenceRule(
                name="unrestricted_upload",
                antecedent=["file_upload_endpoint", "no_extension_filter", "no_content_type_check"],
                consequent="webshell_upload_possible",
                confidence=0.88,
                description="Unrestricted file upload allows webshell",
                tags=["upload", "webshell", "rce"],
                priority=9,
            ),

            # ── Network / Infrastructure ─────────────────────────────────
            InferenceRule(
                name="open_redis",
                antecedent=["port_6379_open", "no_auth_required"],
                consequent="redis_unauthenticated_access",
                confidence=0.95,
                description="Redis exposed without authentication",
                tags=["network", "redis", "noauth"],
                priority=9,
            ),
            InferenceRule(
                name="open_mongodb",
                antecedent=["port_27017_open", "no_auth_required"],
                consequent="mongodb_unauthenticated_access",
                confidence=0.95,
                description="MongoDB exposed without authentication",
                tags=["network", "mongodb", "noauth"],
                priority=9,
            ),
            InferenceRule(
                name="open_elasticsearch",
                antecedent=["port_9200_open", "no_auth_required"],
                consequent="elasticsearch_unauthenticated_access",
                confidence=0.95,
                description="Elasticsearch exposed without authentication",
                tags=["network", "elasticsearch", "noauth"],
                priority=9,
            ),
            InferenceRule(
                name="smb_signing_disabled",
                antecedent=["port_445_open", "smb_signing_not_required"],
                consequent="smb_relay_possible",
                confidence=0.85,
                description="SMB signing not required = relay attacks viable",
                tags=["network", "smb", "relay"],
                priority=8,
            ),
            InferenceRule(
                name="dns_zone_transfer",
                antecedent=["port_53_open", "axfr_allowed"],
                consequent="dns_zone_transfer_info_leak",
                confidence=0.95,
                description="DNS zone transfer exposes internal records",
                tags=["network", "dns", "info_leak"],
                priority=8,
            ),
            InferenceRule(
                name="snmp_default_community",
                antecedent=["port_161_open", "snmp_public_community"],
                consequent="snmp_info_disclosure",
                confidence=0.90,
                description="SNMP with default 'public' community string",
                tags=["network", "snmp", "info_leak"],
                priority=7,
            ),

            # ── Privilege Escalation ─────────────────────────────────────
            InferenceRule(
                name="suid_binary_abuse",
                antecedent=["suid_binary_found", "binary_is_exploitable"],
                consequent="privilege_escalation_via_suid",
                confidence=0.85,
                description="SUID binary abuse for privilege escalation",
                tags=["privesc", "linux", "suid"],
                priority=8,
            ),
            InferenceRule(
                name="kernel_exploit",
                antecedent=["linux_kernel_vulnerable", "local_access_obtained"],
                consequent="kernel_privilege_escalation",
                confidence=0.80,
                description="Kernel exploit for root escalation",
                tags=["privesc", "linux", "kernel"],
                priority=9,
            ),
            InferenceRule(
                name="docker_escape",
                antecedent=["running_in_container", "privileged_container"],
                consequent="container_escape_possible",
                confidence=0.85,
                description="Privileged container allows host escape",
                tags=["privesc", "docker", "container"],
                priority=9,
            ),
            InferenceRule(
                name="idor_escalation",
                antecedent=["sequential_ids_used", "no_authorization_check"],
                consequent="idor_data_access",
                confidence=0.85,
                description="IDOR via sequential IDs without authz check",
                tags=["access_control", "idor"],
                priority=8,
            ),

            # ── Chain Rules (multi-step attacks) ─────────────────────────
            InferenceRule(
                name="sqli_to_db_access",
                antecedent=["sql_injection_likely"],
                consequent="database_access_possible",
                confidence=0.85,
                description="SQL injection leads to database access",
                tags=["chain", "sqli", "database"],
                priority=8,
            ),
            InferenceRule(
                name="db_access_to_data_exfil",
                antecedent=["database_access_possible"],
                consequent="data_exfiltration_risk",
                confidence=0.80,
                description="Database access enables data exfiltration",
                tags=["chain", "database", "exfil"],
                priority=8,
            ),
            InferenceRule(
                name="ssrf_to_internal_network",
                antecedent=["ssrf_confirmed"],
                consequent="internal_network_reachable",
                confidence=0.80,
                description="SSRF enables internal network scanning",
                tags=["chain", "ssrf", "network"],
                priority=8,
            ),
            InferenceRule(
                name="rce_to_persistence",
                antecedent=["os_command_injection"],
                consequent="persistence_mechanism_possible",
                confidence=0.75,
                description="RCE enables attacker persistence (cron, service, etc.)",
                tags=["chain", "rce", "persistence"],
                priority=8,
            ),
            InferenceRule(
                name="credential_theft_to_lateral",
                antecedent=["credentials_obtained", "network_access"],
                consequent="lateral_movement_possible",
                confidence=0.82,
                description="Stolen credentials enable lateral movement",
                tags=["chain", "credentials", "lateral"],
                priority=8,
            ),
            InferenceRule(
                name="xss_to_session_theft",
                antecedent=["xss_likely", "session_cookie_no_httponly"],
                consequent="session_theft_via_xss",
                confidence=0.85,
                description="XSS + missing HttpOnly = session cookie theft",
                tags=["chain", "xss", "session"],
                priority=8,
            ),
            InferenceRule(
                name="upload_to_rce",
                antecedent=["webshell_upload_possible", "uploaded_file_executable"],
                consequent="remote_code_execution_confirmed",
                confidence=0.90,
                description="Webshell upload + execution = RCE confirmed",
                tags=["chain", "upload", "rce"],
                priority=10,
            ),

            # ── Information Disclosure ───────────────────────────────────
            InferenceRule(
                name="git_exposed",
                antecedent=["git_directory_accessible"],
                consequent="source_code_disclosure",
                confidence=0.95,
                description="Exposed .git directory = source code disclosure",
                tags=["info_leak", "git"],
                priority=8,
            ),
            InferenceRule(
                name="env_file_exposed",
                antecedent=["env_file_accessible"],
                consequent="credential_disclosure",
                confidence=0.95,
                description="Exposed .env file = credential disclosure",
                tags=["info_leak", "credentials"],
                priority=9,
            ),
            InferenceRule(
                name="debug_mode_on",
                antecedent=["debug_mode_enabled", "production_environment"],
                consequent="debug_info_disclosure",
                confidence=0.85,
                description="Debug mode in production = information disclosure",
                tags=["info_leak", "debug"],
                priority=7,
            ),
            InferenceRule(
                name="stack_trace_exposed",
                antecedent=["stack_trace_in_response"],
                consequent="technology_fingerprint_leaked",
                confidence=0.80,
                description="Stack trace reveals technology and version info",
                tags=["info_leak", "fingerprint"],
                priority=6,
            ),
            InferenceRule(
                name="directory_listing",
                antecedent=["directory_listing_enabled"],
                consequent="file_enumeration_possible",
                confidence=0.85,
                description="Directory listing enables file enumeration",
                tags=["info_leak", "directory"],
                priority=6,
            ),
            InferenceRule(
                name="graphql_introspection",
                antecedent=["graphql_endpoint", "introspection_enabled"],
                consequent="graphql_schema_disclosed",
                confidence=0.90,
                description="GraphQL introspection exposes full API schema",
                tags=["info_leak", "graphql", "api"],
                priority=7,
            ),
        ]

        for rule in security_rules:
            idx = len(self._rules)
            self._rules.append(rule)
            for ant in rule.antecedent:
                self._rule_index[_normalize_fact(ant)].append(idx)

    def load_rules_from_file(self, path: str) -> int:
        """Carrega regras de um arquivo JSON. Retorna quantidade carregada."""
        import os
        if not os.path.isfile(path):
            logger.warning("Rules file not found: %s", path)
            return 0
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, list):
                logger.warning("Rules file must contain a JSON array: %s", path)
                return 0
            count = 0
            for entry in data:
                try:
                    rule = InferenceRule(
                        name=entry.get("name", ""),
                        antecedent=entry.get("antecedent", []),
                        consequent=entry.get("consequent", ""),
                        confidence=entry.get("confidence", 0.8),
                        domain=entry.get("domain", "security"),
                        description=entry.get("description", ""),
                        bidirectional=entry.get("bidirectional", False),
                        priority=entry.get("priority", 5),
                        tags=entry.get("tags", []),
                    )
                    self.add_rule(rule)
                    count += 1
                except (KeyError, TypeError, ValueError) as exc:
                    logger.warning("Skipping invalid rule entry: %s", exc)
            logger.info("Loaded %d rules from %s", count, path)
            return count
        except (json.JSONDecodeError, OSError) as exc:
            logger.error("Failed to load rules from %s: %s", path, exc)
            return 0


# ════════════════════════════════════════════════════════════════════════════════
# SIREN COGNITIVE REASONER — ORCHESTRATOR
# ════════════════════════════════════════════════════════════════════════════════


class SirenCognitiveReasoner:
    """
    Orchestrates multi-modal cognitive reasoning pipeline.

    Coordinates deductive, abductive, analogical, causal, and counterfactual
    reasoning modes for comprehensive security assessment intelligence.

    Pipeline:
        1. Evidence ingestion — facts, observations, scan results
        2. Deductive reasoning — forward/backward chaining with 50+ rules
        3. Abductive reasoning — best-explanation inference for anomalies
        4. Analogical reasoning — cross-target vulnerability prediction
        5. Causal reasoning — attack chain causal modeling
        6. Counterfactual analysis — "what if" scenario evaluation
        7. Report synthesis — multi-modal conclusions with confidence scoring

    Usage::

        reasoner = SirenCognitiveReasoner()

        # Add evidence
        reasoner.add_evidence([
            Evidence(evidence_type=EvidenceType.PORT_STATE, value="port_443_open"),
            Evidence(evidence_type=EvidenceType.HEADER_ANALYSIS, value="server_nginx"),
        ])

        # Full reasoning pipeline
        report = reasoner.full_reasoning(
            target="target.example.com",
            goals=["web_server_compromise", "data_exfiltration"],
        )
    """

    # ── Pretext Observation → Explanation Templates ──────────────────────

    OBSERVATION_EXPLANATIONS: Dict[str, List[Tuple[str, float, float]]] = {
        # observation → [(explanation, likelihood, complexity), ...]
        "unusual_port_open": [
            ("backdoor_installed", 0.60, 1.5),
            ("misconfigured_service", 0.85, 1.0),
            ("development_leftover", 0.70, 1.2),
        ],
        "auth_bypass_detected": [
            ("broken_access_control", 0.90, 1.0),
            ("session_fixation", 0.50, 1.8),
            ("default_credentials", 0.75, 1.1),
        ],
        "data_leak_in_response": [
            ("idor_vulnerability", 0.80, 1.2),
            ("error_handling_flaw", 0.70, 1.0),
            ("debug_mode_enabled", 0.85, 1.0),
        ],
        "anomalous_traffic_pattern": [
            ("c2_communication", 0.55, 2.0),
            ("automated_scanning", 0.80, 1.0),
            ("data_exfiltration", 0.45, 2.2),
        ],
        "crypto_weakness_found": [
            ("weak_cipher_suite", 0.85, 1.0),
            ("outdated_tls", 0.80, 1.0),
            ("key_reuse", 0.40, 1.5),
        ],
    }

    # ── Analogy Knowledge Base ───────────────────────────────────────────

    ANALOGY_ENTRIES: List[Dict[str, Any]] = [
        {
            "target": "nginx_1.x",
            "attributes": {"web_server": True, "reverse_proxy": True, "version": "1.x", "language": "c"},
            "known_vulns": ["path_traversal", "header_injection", "buffer_overflow", "request_smuggling", "alias_traversal"],
        },
        {
            "target": "apache_2.4",
            "attributes": {"web_server": True, "version": "2.4", "modular": True, "language": "c"},
            "known_vulns": ["ssrf_mod_proxy", "path_traversal", "cgi_rce", "mod_lua_abuse", "htaccess_bypass"],
        },
        {
            "target": "iis_10",
            "attributes": {"web_server": True, "windows": True, "version": "10", "language": "csharp"},
            "known_vulns": ["short_filename", "tilde_enum", "webdav_rce", "http_sys_rce", "auth_bypass"],
        },
        {
            "target": "php_app",
            "attributes": {"language": "php", "dynamic": True, "interpreted": True},
            "known_vulns": ["sqli", "rfi", "lfi", "deserialization", "type_juggling", "file_upload_bypass"],
        },
        {
            "target": "java_app",
            "attributes": {"language": "java", "enterprise": True, "compiled": True},
            "known_vulns": ["deserialization", "ssrf", "xxe", "log4shell", "ognl_injection", "jndi_injection"],
        },
        {
            "target": "nodejs_app",
            "attributes": {"language": "javascript", "event_driven": True, "runtime": "node"},
            "known_vulns": ["prototype_pollution", "ssrf", "nosql_injection", "rce_child_process", "path_traversal"],
        },
        {
            "target": "python_django",
            "attributes": {"language": "python", "framework": "django", "orm": True, "admin_panel": True},
            "known_vulns": ["sqli_orm_bypass", "xss", "csrf", "ssrf", "debug_info_leak", "secret_key_exposure", "mass_assignment"],
        },
        {
            "target": "python_flask",
            "attributes": {"language": "python", "framework": "flask", "micro_framework": True},
            "known_vulns": ["ssti", "xss", "debug_rce", "pickle_deserialization", "path_traversal", "insecure_session"],
        },
        {
            "target": "python_fastapi",
            "attributes": {"language": "python", "framework": "fastapi", "async": True, "api_first": True},
            "known_vulns": ["ssrf", "idor", "mass_assignment", "jwt_bypass", "dependency_injection_abuse", "openapi_info_leak"],
        },
        {
            "target": "ruby_rails",
            "attributes": {"language": "ruby", "framework": "rails", "orm": True, "convention_over_config": True},
            "known_vulns": ["sqli_arel", "xss", "csrf", "mass_assignment", "deserialization", "session_fixation", "open_redirect"],
        },
        {
            "target": "dotnet_aspnet",
            "attributes": {"language": "csharp", "framework": "aspnet", "windows": True, "enterprise": True},
            "known_vulns": ["viewstate_deserialization", "sqli", "xss", "xxe", "path_traversal", "padding_oracle", "request_smuggling"],
        },
        {
            "target": "go_api",
            "attributes": {"language": "go", "compiled": True, "static_typing": True, "api_first": True},
            "known_vulns": ["ssrf", "race_condition", "path_traversal", "integer_overflow", "improper_error_handling", "idor"],
        },
        {
            "target": "rust_api",
            "attributes": {"language": "rust", "compiled": True, "memory_safe": True, "api_first": True},
            "known_vulns": ["logic_bugs", "ssrf", "idor", "race_condition", "unsafe_ffi", "denial_of_service"],
        },
        {
            "target": "wordpress",
            "attributes": {"language": "php", "cms": True, "plugin_ecosystem": True, "admin_panel": True},
            "known_vulns": ["sqli", "xss", "rfi", "lfi", "plugin_rce", "xmlrpc_brute_force", "privilege_escalation", "file_upload_bypass"],
        },
        {
            "target": "drupal",
            "attributes": {"language": "php", "cms": True, "enterprise": True, "modular": True},
            "known_vulns": ["drupalgeddon_rce", "sqli", "xss", "deserialization", "access_bypass", "twig_ssti"],
        },
        {
            "target": "joomla",
            "attributes": {"language": "php", "cms": True, "plugin_ecosystem": True},
            "known_vulns": ["sqli", "xss", "object_injection", "directory_traversal", "privilege_escalation", "session_fixation"],
        },
        {
            "target": "spring_boot",
            "attributes": {"language": "java", "framework": "spring_boot", "enterprise": True, "auto_config": True},
            "known_vulns": ["spring4shell", "actuator_exposure", "spel_injection", "deserialization", "ssrf", "mass_assignment", "h2_console_rce"],
        },
        {
            "target": "express_app",
            "attributes": {"language": "javascript", "framework": "express", "runtime": "node", "middleware_based": True},
            "known_vulns": ["prototype_pollution", "xss", "nosql_injection", "ssrf", "path_traversal", "rce_child_process", "cors_misconfiguration"],
        },
        {
            "target": "laravel_app",
            "attributes": {"language": "php", "framework": "laravel", "orm": True, "artisan_cli": True},
            "known_vulns": ["sqli_eloquent_bypass", "xss", "csrf", "deserialization", "debug_rce", "env_exposure", "mass_assignment", "file_upload_bypass"],
        },
        {
            "target": "graphql_api",
            "attributes": {"api_type": "graphql", "introspection": True, "query_language": True},
            "known_vulns": ["introspection_info_leak", "query_depth_dos", "batching_brute_force", "idor", "sqli_resolver", "authorization_bypass", "field_suggestion_enum"],
        },
        {
            "target": "grpc_service",
            "attributes": {"api_type": "grpc", "protobuf": True, "http2": True, "binary_protocol": True},
            "known_vulns": ["reflection_info_leak", "deserialization", "auth_bypass", "resource_exhaustion", "metadata_injection", "tls_misconfiguration"],
        },
        {
            "target": "react_spa",
            "attributes": {"language": "javascript", "framework": "react", "spa": True, "client_side": True},
            "known_vulns": ["xss_dangerouslysetinnerhtml", "open_redirect", "sensitive_data_client", "jwt_client_storage", "cors_misconfiguration", "source_map_exposure"],
        },
        {
            "target": "angular_spa",
            "attributes": {"language": "typescript", "framework": "angular", "spa": True, "client_side": True},
            "known_vulns": ["xss_bypass_sanitizer", "open_redirect", "template_injection", "sensitive_data_client", "cors_misconfiguration", "source_map_exposure"],
        },
        {
            "target": "vue_spa",
            "attributes": {"language": "javascript", "framework": "vue", "spa": True, "client_side": True},
            "known_vulns": ["xss_v_html", "open_redirect", "sensitive_data_client", "jwt_client_storage", "cors_misconfiguration", "source_map_exposure"],
        },
        {
            "target": "mobile_api_backend",
            "attributes": {"api_first": True, "mobile_backend": True, "rest_api": True, "auth_token_based": True},
            "known_vulns": ["idor", "broken_auth", "rate_limiting_bypass", "jwt_bypass", "mass_assignment", "api_key_exposure", "certificate_pinning_bypass"],
        },
        {
            "target": "kubernetes_cluster",
            "attributes": {"orchestrator": True, "container": True, "cloud_native": True, "api_server": True},
            "known_vulns": ["rbac_misconfiguration", "container_escape", "etcd_exposure", "dashboard_unauthenticated", "pod_security_bypass", "secret_exposure", "service_account_abuse"],
        },
        {
            "target": "aws_lambda",
            "attributes": {"serverless": True, "cloud": "aws", "event_driven": True, "ephemeral": True},
            "known_vulns": ["function_injection", "iam_over_privilege", "env_var_secret_leak", "event_injection", "ssrf_metadata", "dependency_confusion", "cold_start_timing"],
        },
        {
            "target": "azure_functions",
            "attributes": {"serverless": True, "cloud": "azure", "event_driven": True, "ephemeral": True},
            "known_vulns": ["function_injection", "managed_identity_abuse", "env_var_secret_leak", "event_injection", "ssrf_imds", "dependency_confusion", "trigger_abuse"],
        },
    ]

    # ── Causal Attack Chain Templates ────────────────────────────────────

    CAUSAL_CHAINS: List[List[Tuple[str, str, float]]] = [
        # [(cause, effect, strength), ...]
        [
            ("sql_injection", "database_access", 0.90),
            ("database_access", "credential_dump", 0.85),
            ("credential_dump", "lateral_movement", 0.70),
            ("lateral_movement", "domain_admin", 0.50),
        ],
        [
            ("ssrf", "internal_service_access", 0.80),
            ("internal_service_access", "metadata_leak", 0.75),
            ("metadata_leak", "cloud_credential_theft", 0.85),
        ],
        [
            ("xss_stored", "session_hijack", 0.80),
            ("session_hijack", "account_takeover", 0.85),
            ("account_takeover", "privilege_escalation", 0.60),
        ],
        [
            ("rce", "shell_access", 0.95),
            ("shell_access", "persistence", 0.80),
            ("persistence", "data_exfiltration", 0.70),
        ],
        [
            ("lfi", "source_code_read", 0.85),
            ("source_code_read", "credential_extraction", 0.75),
            ("credential_extraction", "rce", 0.80),
            ("rce", "persistence", 0.80),
            ("persistence", "data_exfiltration", 0.70),
        ],
        [
            ("default_creds", "admin_access", 0.95),
            ("admin_access", "config_change", 0.90),
            ("config_change", "backdoor", 0.75),
        ],
        [
            ("open_redirect", "oauth_token_theft", 0.70),
            ("oauth_token_theft", "account_takeover", 0.85),
        ],
        [
            ("exposed_api", "idor", 0.75),
            ("idor", "mass_data_leak", 0.80),
        ],
        [
            ("weak_jwt", "token_forgery", 0.85),
            ("token_forgery", "privilege_escalation", 0.80),
            ("privilege_escalation", "admin_access", 0.75),
        ],
        [
            ("container_escape", "host_access", 0.90),
            ("host_access", "lateral_movement", 0.80),
            ("lateral_movement", "domain_admin", 0.50),
        ],
        [
            ("dns_zone_transfer", "internal_recon", 0.90),
            ("internal_recon", "targeted_attack", 0.65),
        ],
        [
            ("deserialization", "rce", 0.90),
            ("rce", "reverse_shell", 0.85),
            ("reverse_shell", "persistence", 0.80),
        ],
    ]

    # ── Mitigation Effectiveness Maps (Change #7) ────────────────────────

    WAF_EFFECTIVENESS: Dict[str, float] = {
        "sqli": 0.70, "sql_injection": 0.70, "xss": 0.65, "xss_stored": 0.65,
        "command_injection": 0.50, "os_command_injection": 0.50,
        "ssrf": 0.30, "lfi": 0.55, "local_file_inclusion": 0.55,
        "deserialization": 0.10, "xxe": 0.40, "ssti": 0.35,
        "header_injection": 0.60, "http_header_injection": 0.60,
        "rfi": 0.50, "remote_file_inclusion": 0.50,
        "path_traversal": 0.55, "prototype_pollution": 0.15,
    }

    MFA_EFFECTIVENESS: Dict[str, float] = {
        "brute_force": 0.90, "brute_force_viable": 0.90,
        "credential_theft": 0.80, "credential_dump": 0.80,
        "session_fixation": 0.60, "session_fixation_possible": 0.60,
        "phishing": 0.70, "default_creds": 0.85, "default_credentials": 0.85,
        "account_takeover": 0.75, "oauth_token_theft": 0.50,
    }

    PATCH_EFFECTIVENESS: Dict[str, float] = {
        "rce": 0.90, "deserialization": 0.85, "log4shell": 0.95,
        "spring4shell": 0.95, "buffer_overflow": 0.90,
        "path_traversal": 0.80, "sqli": 0.60, "xss": 0.55,
        "xxe": 0.80, "lfi": 0.75, "rfi": 0.80,
        "drupalgeddon_rce": 0.95, "container_escape": 0.80,
    }

    SEGMENTATION_EFFECTIVENESS: Dict[str, float] = {
        "lateral_movement": 0.80, "internal_service_access": 0.75,
        "ssrf": 0.50, "internal_recon": 0.70, "domain_admin": 0.60,
        "host_access": 0.65, "metadata_leak": 0.55,
        "cloud_credential_theft": 0.45, "targeted_attack": 0.50,
    }

    DEBUG_DISABLE_EFFECTIVENESS: Dict[str, float] = {
        "debug_info_leak": 0.95, "debug_info_disclosure": 0.95,
        "debug_rce": 0.95, "stack_trace_in_response": 0.90,
        "technology_fingerprint_leaked": 0.70, "source_map_exposure": 0.85,
        "env_exposure": 0.60, "actuator_exposure": 0.80,
    }

    _MITIGATION_MAPS: Dict[str, str] = {
        "deploy_waf": "WAF_EFFECTIVENESS",
        "enable_mfa": "MFA_EFFECTIVENESS",
        "patch_critical": "PATCH_EFFECTIVENESS",
        "segment_network": "SEGMENTATION_EFFECTIVENESS",
        "disable_debug": "DEBUG_DISABLE_EFFECTIVENESS",
    }

    def __init__(self) -> None:
        self._lock = threading.RLock()

        # Sub-engines
        self._deductive = DeductiveEngine()

        # State
        self._evidence: List[Evidence] = []
        self._results: List[ReasoningResult] = []
        self._abductive_explanations: List[AbductiveExplanation] = []
        self._analogy_results: List[AnalogyResult] = []
        self._counterfactual_scenarios: List[CounterfactualScenario] = []
        self._causal_chains_built: int = 0
        self._causal_nodes: Dict[str, CausalNode] = {}
        self._causal_edges: List[CausalEdge] = []
        self._scan_phases: List[Dict[str, Any]] = []
        self._scan_start: float = 0.0
        self._scan_end: float = 0.0

        logger.info("SirenCognitiveReasoner initialized with DeductiveEngine (%d rules)",
                     len(self._deductive.get_rules()))

    # ── Evidence Ingestion ───────────────────────────────────────────────

    def add_evidence(self, evidence: List[Evidence]) -> None:
        """Ingest evidence as facts for reasoning."""
        with self._lock:
            self._evidence.extend(evidence)
            facts = []
            for e in evidence:
                fact = e.value if isinstance(e.value, str) else str(e.value)
                fact_normalized = _normalize_fact(fact)
                facts.append(fact_normalized)
            self._deductive.add_facts(facts)
            logger.info("Ingested %d evidence items (%d total facts)",
                        len(evidence), len(self._deductive.get_all_facts()))

    # ── Phase 1: Deductive Reasoning ─────────────────────────────────────

    def reason_deductive(
        self, goals: Optional[List[str]] = None, max_iterations: int = 50
    ) -> ReasoningResult:
        """Execute deductive reasoning via forward and backward chaining."""
        with self._lock:
            t0 = time.time()

            # Forward chain: derive all reachable conclusions
            derived = self._deductive.forward_chain(max_iterations=max_iterations)

            # Backward chain for specific goals
            goals_reached: List[str] = []
            goals_unreached: List[str] = []
            if goals:
                for goal in goals:
                    g_norm = _normalize_fact(goal)
                    if self._deductive.backward_chain(g_norm):
                        goals_reached.append(goal)
                    else:
                        goals_unreached.append(goal)

            # Build syllogism chains for explainability
            syllogisms = self._deductive.build_syllogism_chains()

            result = ReasoningResult(
                mode=ReasoningMode.DEDUCTIVE,
                query=f"Forward chain + goals: {goals}" if goals else "Forward chain",
                conclusion=f"Derived {len(derived)} facts. Goals reached: {goals_reached}",
                confidence=0.85 if derived else 0.3,
                chains=[str(s.antecedent) + " → " + s.consequent for s in syllogisms[:10]],
                rules_applied=len(derived),
                evidence_considered=len(self._evidence),
                duration_ms=(time.time() - t0) * 1000,
                explanation=(
                    f"Forward chaining derived {len(derived)} new facts from "
                    f"{len(self._deductive.get_rules())} rules and "
                    f"{len(self._deductive.get_all_facts())} known facts."
                ),
            )

            if goals_unreached:
                result.warnings.append(f"Goals not reached: {goals_unreached}")

            self._results.append(result)
            self._scan_phases.append({
                "phase": "deductive",
                "duration": (time.time() - t0) * 1000,
                "derived_facts": len(derived),
                "goals_reached": len(goals_reached),
            })
            logger.info("Phase 1 (Deductive): %d derived, %d/%d goals",
                        len(derived), len(goals_reached), len(goals or []))
            return result

    # ── Phase 2: Abductive Reasoning ─────────────────────────────────────

    def reason_abductive(
        self, observations: Optional[List[str]] = None
    ) -> ReasoningResult:
        """Generate best-explanation inferences for observed anomalies."""
        with self._lock:
            t0 = time.time()
            explanations: List[AbductiveExplanation] = []

            obs_list = observations or [
                e.value for e in self._evidence
                if isinstance(e.value, str) and e.value in self.OBSERVATION_EXPLANATIONS
            ]

            for obs in obs_list:
                obs_norm = _normalize_fact(obs)
                templates = self.OBSERVATION_EXPLANATIONS.get(obs_norm, [])
                for expl_text, likelihood, complexity in templates:
                    # Use template likelihood as a rough proxy for prior
                    # (more likely explanations get higher prior)
                    prior = _clamp(likelihood * 0.6, 0.05, 0.90)
                    explanation = AbductiveExplanation(
                        observation=obs,
                        explanation=expl_text,
                        prior_probability=prior,
                        likelihood=likelihood,
                        complexity=complexity,
                        supporting_facts=[
                            f for f in self._deductive.get_all_facts()
                            if any(token in f for token in expl_text.split("_"))
                        ],
                    )
                    explanations.append(explanation)

            # Group explanations by observation and normalize (Bayes complete)
            by_obs: Dict[str, List[AbductiveExplanation]] = defaultdict(list)
            for expl in explanations:
                by_obs[expl.observation].append(expl)
            for obs_group in by_obs.values():
                AbductiveExplanation.normalize_group(obs_group)

            # Rank by Occam-adjusted score
            explanations.sort(key=lambda e: e.occam_adjusted_score, reverse=True)
            self._abductive_explanations.extend(explanations)

            best = explanations[0] if explanations else None
            result = ReasoningResult(
                mode=ReasoningMode.ABDUCTIVE,
                query=f"Explain observations: {obs_list}",
                conclusion=(
                    f"Best explanation: {best.explanation} (score={best.occam_adjusted_score:.3f})"
                    if best else "No explanations generated"
                ),
                confidence=best.occam_adjusted_score if best else 0.0,
                hypotheses_evaluated=len(explanations),
                evidence_considered=len(obs_list),
                duration_ms=(time.time() - t0) * 1000,
                explanation=f"Evaluated {len(explanations)} candidate explanations using Bayesian posterior + Occam penalty",
                alternatives=[
                    {"explanation": e.explanation, "score": round(e.occam_adjusted_score, 4)}
                    for e in explanations[1:5]
                ],
            )

            self._results.append(result)
            self._scan_phases.append({
                "phase": "abductive",
                "duration": (time.time() - t0) * 1000,
                "explanations": len(explanations),
            })
            logger.info("Phase 2 (Abductive): %d explanations, best=%s",
                        len(explanations), best.explanation if best else "none")
            return result

    # ── Phase 3: Analogical Reasoning ────────────────────────────────────

    def _entry_to_analog(self, entry: Dict[str, Any]) -> AnalogEntry:
        """Convert a raw ANALOGY_ENTRIES dict to an AnalogEntry dataclass."""
        attrs = entry.get("attributes", {})
        return AnalogEntry(
            target_name=entry.get("target", "unknown"),
            tech_stack=set(
                [attrs.get("language", ""), attrs.get("framework", ""),
                 attrs.get("runtime", ""), attrs.get("api_type", "")]
            ) - {""},
            architecture=attrs.get("architecture", "web" if attrs.get("web_server") else "api"),
            framework_versions={
                k: str(v) for k, v in attrs.items()
                if k == "version" and v
            },
            network_topology="cloud" if attrs.get("cloud") or attrs.get("serverless") else "standard",
            auth_scheme=attrs.get("auth_scheme", "token" if attrs.get("auth_token_based") else "standard"),
            api_patterns=set(
                [p for p in ["rest_api", "graphql", "grpc", "spa", "cms"]
                 if attrs.get(p) or attrs.get("api_type") == p or attrs.get(p.replace("_", ""))]
            ),
            deployment_model=(
                "serverless" if attrs.get("serverless")
                else "container" if attrs.get("container") or attrs.get("orchestrator")
                else "traditional"
            ),
            security_posture_score=attrs.get("security_posture_score", 0.5),
            industry=attrs.get("industry", "technology"),
            codebase_patterns=set(
                [p for p in ["orm", "admin_panel", "plugin_ecosystem", "modular",
                             "middleware_based", "event_driven", "async", "micro_framework"]
                 if attrs.get(p)]
            ),
            known_vulns=list(entry.get("known_vulns", [])),
        )

    def reason_analogical(
        self,
        target_attributes: Optional[Dict[str, Any]] = None,
        target_name: str = "",
    ) -> ReasoningResult:
        """Predict vulnerabilities by analogy with known targets using AnalogEntry + weighted_similarity."""
        with self._lock:
            t0 = time.time()
            results: List[AnalogyResult] = []

            attrs = target_attributes or {}
            facts = self._deductive.get_all_facts()

            # Build target AnalogEntry from provided attributes and known facts
            target_tech_stack: Set[str] = set()
            for key in ["language", "framework", "runtime", "api_type"]:
                if attrs.get(key):
                    target_tech_stack.add(str(attrs[key]))
            # Infer from facts
            for f in facts:
                for lang in ["python", "java", "php", "ruby", "javascript", "go", "rust", "csharp", "typescript"]:
                    if lang in f:
                        target_tech_stack.add(lang)

            target_entry = AnalogEntry(
                target_name=target_name or "current_target",
                tech_stack=target_tech_stack,
                architecture=attrs.get("architecture", "web"),
                framework_versions={
                    k: str(v) for k, v in attrs.items()
                    if k == "version" and v
                },
                network_topology=(
                    "cloud" if attrs.get("cloud") or attrs.get("serverless")
                    or any("cloud" in f for f in facts) else "standard"
                ),
                auth_scheme=attrs.get("auth_scheme", "standard"),
                api_patterns=set(
                    [p for p in ["rest_api", "graphql", "grpc", "spa"]
                     if attrs.get(p) or any(p.replace("_", "") in f for f in facts)]
                ),
                deployment_model=(
                    "serverless" if attrs.get("serverless")
                    else "container" if attrs.get("container")
                    else "traditional"
                ),
                security_posture_score=attrs.get("security_posture_score", 0.5),
                industry=attrs.get("industry", "technology"),
                codebase_patterns=set(
                    [p for p in ["orm", "admin_panel", "plugin_ecosystem", "modular",
                                 "middleware_based", "event_driven", "async"]
                     if attrs.get(p) or any(p in f for f in facts)]
                ),
            )

            for entry in self.ANALOGY_ENTRIES:
                source_entry = self._entry_to_analog(entry)

                # Use weighted_similarity from AnalogEntry
                sim, dim_scores = target_entry.weighted_similarity(source_entry)

                if sim > 0.10:
                    # Scale prediction confidence by similarity and per-dimension scores
                    pred_confidence: Dict[str, float] = {}
                    for v in source_entry.known_vulns:
                        pred_confidence[v] = round(_clamp(sim * 0.85), 4)

                    analogy = AnalogyResult(
                        source_target=entry["target"],
                        dest_target=target_name or "unknown",
                        similarity_score=round(sim, 4),
                        dimension_scores={k: round(v, 4) for k, v in dim_scores.items()},
                        predicted_vulns=source_entry.known_vulns,
                        prediction_confidence=pred_confidence,
                        explanation=(
                            f"Weighted multi-dimensional similarity={sim:.3f} with "
                            f"{entry['target']}; top dimensions: "
                            + ", ".join(
                                f"{k}={v:.2f}" for k, v in
                                sorted(dim_scores.items(), key=lambda x: x[1], reverse=True)[:3]
                            )
                        ),
                    )
                    results.append(analogy)

            results.sort(key=lambda r: r.similarity_score, reverse=True)
            self._analogy_results.extend(results)

            predicted_vulns: List[str] = []
            for r in results[:3]:
                predicted_vulns.extend(r.predicted_vulns)
            predicted_vulns = list(dict.fromkeys(predicted_vulns))  # dedupe preserving order

            result = ReasoningResult(
                mode=ReasoningMode.ANALOGICAL,
                query=f"Analogical prediction for {target_name}",
                conclusion=f"Predicted {len(predicted_vulns)} vulns from {len(results)} analogies",
                confidence=results[0].similarity_score if results else 0.0,
                hypotheses_evaluated=len(results),
                evidence_considered=len(self.ANALOGY_ENTRIES),
                duration_ms=(time.time() - t0) * 1000,
                explanation=f"Compared {target_name} with {len(self.ANALOGY_ENTRIES)} known targets using weighted multi-dimensional similarity",
                alternatives=[
                    {"source": r.source_target, "similarity": r.similarity_score,
                     "vulns": r.predicted_vulns, "dimensions": r.dimension_scores}
                    for r in results[:5]
                ],
            )

            self._results.append(result)
            self._scan_phases.append({
                "phase": "analogical",
                "duration": (time.time() - t0) * 1000,
                "analogies": len(results),
                "predicted_vulns": len(predicted_vulns),
            })
            logger.info("Phase 3 (Analogical): %d analogies, %d predicted vulns",
                        len(results), len(predicted_vulns))
            return result

    # ── Phase 4: Causal Reasoning ────────────────────────────────────────

    def _propagate_noisy_or(
        self, nodes: Dict[str, CausalNode], edges: List[CausalEdge]
    ) -> None:
        """
        Propagate probabilities through the causal graph using Noisy-OR.

        For each node with parents:
            P(node) = 1 - prod(1 - P(parent) * strength(parent->node))
        """
        # Build adjacency: target -> list of (source_name, strength)
        incoming: Dict[str, List[Tuple[str, float]]] = defaultdict(list)
        for edge in edges:
            incoming[edge.target].append((edge.source, edge.strength))

        # Topological-ish propagation: iterate until convergence
        for _pass in range(10):
            changed = False
            for node_name, parents_info in incoming.items():
                if node_name not in nodes or not parents_info:
                    continue
                node = nodes[node_name]
                if node.is_observed:
                    continue
                # Noisy-OR: P = 1 - prod(1 - P(parent)*strength)
                product = 1.0
                for parent_name, strength in parents_info:
                    if parent_name in nodes:
                        parent_p = nodes[parent_name].probability
                        product *= (1.0 - parent_p * strength)
                new_prob = _clamp(1.0 - product)
                if abs(new_prob - node.probability) > EPSILON:
                    node.probability = new_prob
                    changed = True
            if not changed:
                break

    def reason_causal(
        self, initial_vulns: Optional[List[str]] = None
    ) -> ReasoningResult:
        """Model causal attack chains from known vulnerabilities using CausalGraph."""
        with self._lock:
            t0 = time.time()
            facts = self._deductive.get_all_facts()
            vulns = initial_vulns or [
                f for f in facts
                if any(vuln_word in f for vuln_word in [
                    "injection", "ssrf", "xss", "rce", "sqli", "lfi",
                    "deserialization", "bypass", "overflow",
                ])
            ]

            # Build causal graph from templates + facts
            nodes: Dict[str, CausalNode] = {}
            edges: List[CausalEdge] = []
            chains_found: List[Dict[str, Any]] = []

            # Observational data confidence penalty
            OBSERVATIONAL_CONFIDENCE_PENALTY = 0.7

            for chain_template in self.CAUSAL_CHAINS:
                first_cause = chain_template[0][0]
                if any(first_cause in v or v in first_cause for v in vulns):
                    # Build graph nodes and edges for this chain
                    for cause, effect, strength in chain_template:
                        if cause not in nodes:
                            # Observed vulns get high probability, others get default
                            is_vuln = any(cause in v or v in cause for v in vulns)
                            nodes[cause] = CausalNode(
                                name=cause,
                                probability=0.9 if is_vuln else 0.5,
                                is_observed=is_vuln,
                                observed_value=True if is_vuln else None,
                                node_type="vulnerability" if is_vuln else "event",
                            )
                        if effect not in nodes:
                            nodes[effect] = CausalNode(
                                name=effect,
                                node_type="impact",
                            )
                        edge = CausalEdge(
                            source=cause,
                            target=effect,
                            strength=strength,
                        )
                        edges.append(edge)
                        if effect not in nodes[cause].children:
                            nodes[cause].children.append(effect)
                        if cause not in nodes[effect].parents:
                            nodes[effect].parents.append(cause)

                    # Also track the linear chain for reporting
                    cumulative_strength = 1.0
                    path: List[str] = []
                    for cause, effect, strength in chain_template:
                        cumulative_strength *= strength
                        path.append(f"{cause} ->({strength:.2f})-> {effect}")

                    cumulative_strength *= OBSERVATIONAL_CONFIDENCE_PENALTY

                    chains_found.append({
                        "trigger": first_cause,
                        "impact": chain_template[-1][1],
                        "path": path,
                        "cumulative_probability": round(cumulative_strength, 4),
                        "steps": len(chain_template),
                        "observational_penalty_applied": True,
                    })

            # Propagate probabilities through graph (Noisy-OR forward pass)
            if nodes and edges:
                self._propagate_noisy_or(nodes, edges)

            # Store graph state
            self._causal_nodes = nodes
            self._causal_edges = edges
            self._causal_chains_built += len(chains_found)
            chains_found.sort(key=lambda c: c["cumulative_probability"], reverse=True)

            # Enrich chain data with propagated node probabilities
            for chain_info in chains_found:
                impact_name = chain_info["impact"]
                if impact_name in nodes:
                    chain_info["propagated_impact_probability"] = round(
                        nodes[impact_name].probability, 4
                    )

            worst_impact = chains_found[0]["impact"] if chains_found else "none"
            worst_prob = chains_found[0]["cumulative_probability"] if chains_found else 0.0

            result = ReasoningResult(
                mode=ReasoningMode.CAUSAL,
                query=f"Causal chains from: {vulns}",
                conclusion=(
                    f"Found {len(chains_found)} causal chains across {len(nodes)} nodes. "
                    f"Worst impact: {worst_impact} (P={worst_prob:.3f})"
                ),
                confidence=worst_prob if chains_found else 0.0,
                chains=[str(c["path"]) for c in chains_found[:5]],
                evidence_considered=len(vulns),
                duration_ms=(time.time() - t0) * 1000,
                explanation=(
                    f"Built causal graph with {len(nodes)} nodes and {len(edges)} edges "
                    f"from {len(vulns)} initial vulnerabilities. "
                    f"Noisy-OR propagation applied."
                ),
                alternatives=[
                    {"impact": c["impact"], "probability": c["cumulative_probability"],
                     "propagated": c.get("propagated_impact_probability", 0.0)}
                    for c in chains_found
                ],
            )

            self._results.append(result)
            self._scan_phases.append({
                "phase": "causal",
                "duration": (time.time() - t0) * 1000,
                "chains_found": len(chains_found),
                "graph_nodes": len(nodes),
                "graph_edges": len(edges),
            })
            logger.info("Phase 4 (Causal): %d chains, %d nodes, %d edges, worst=%s (P=%.3f)",
                        len(chains_found), len(nodes), len(edges), worst_impact, worst_prob)
            return result

    # ── Phase 5: Counterfactual Reasoning ────────────────────────────────

    def _compute_contextual_reduction(
        self, action: str, derived_facts: Set[str]
    ) -> Tuple[float, List[str]]:
        """
        Compute context-aware risk reduction by matching derived facts
        against mitigation effectiveness maps.

        Returns (weighted_reduction, list_of_affected_facts).
        """
        effectiveness_map: Dict[str, float] = {}
        if action == "deploy_waf":
            effectiveness_map = self.WAF_EFFECTIVENESS
        elif action == "enable_mfa":
            effectiveness_map = self.MFA_EFFECTIVENESS
        elif action == "patch_critical":
            effectiveness_map = self.PATCH_EFFECTIVENESS
        elif action == "segment_network":
            effectiveness_map = self.SEGMENTATION_EFFECTIVENESS
        elif action == "disable_debug":
            effectiveness_map = self.DEBUG_DISABLE_EFFECTIVENESS

        if not effectiveness_map:
            # Fallback for unknown actions
            return 0.15, []

        matched_reductions: List[float] = []
        affected: List[str] = []

        for fact in derived_facts:
            for vuln_type, eff in effectiveness_map.items():
                if vuln_type in fact or fact in vuln_type:
                    matched_reductions.append(eff)
                    affected.append(fact)
                    break

        if not matched_reductions:
            # No specific matches — use a conservative default
            return 0.10, []

        # Weighted average of all matched reductions
        avg_reduction = sum(matched_reductions) / len(matched_reductions)
        # Scale slightly by coverage (more matches = more impactful)
        coverage_bonus = min(0.15, len(matched_reductions) * 0.02)
        return _clamp(avg_reduction + coverage_bonus, 0.05, 0.95), affected

    def reason_counterfactual(
        self, scenarios: Optional[List[Dict[str, str]]] = None
    ) -> ReasoningResult:
        """
        Evaluate 'what if' scenarios to assess impact of mitigations.

        Uses vuln-type-aware effectiveness maps for contextual risk reduction.

        scenarios: [{"action": "block_port_443", "description": "..."}, ...]
        """
        with self._lock:
            t0 = time.time()

            default_scenarios = [
                {"action": "deploy_waf", "description": "Deploy WAF with default rules"},
                {"action": "enable_mfa", "description": "Enable MFA on all accounts"},
                {"action": "patch_critical", "description": "Apply all critical patches"},
                {"action": "segment_network", "description": "Implement network segmentation"},
                {"action": "disable_debug", "description": "Disable debug mode in production"},
            ]
            scen_list = scenarios or default_scenarios

            cf_results: List[CounterfactualScenario] = []
            all_facts = self._deductive.get_all_facts()
            derived_facts = self._deductive._derived | self._deductive._facts

            for scen in scen_list:
                action = scen.get("action", "")

                # Contextual risk reduction based on vuln types present
                reduction, affected_facts = self._compute_contextual_reduction(
                    action, derived_facts
                )

                # Fallback: also check generic token matching for unknown actions
                if not affected_facts:
                    affected_facts = [
                        f for f in all_facts
                        if any(token in f for token in action.split("_"))
                    ]

                cf = CounterfactualScenario(
                    original_state=f"{len(all_facts)} known facts",
                    intervention=action,
                    counterfactual_state=f"{len(all_facts) - len(affected_facts)} facts remain",
                    outcome=(
                        CounterfactualOutcome.ATTACK_BLOCKED if reduction > 0.70
                        else CounterfactualOutcome.MITIGATED if reduction > 0.40
                        else CounterfactualOutcome.PARTIALLY_MITIGATED if reduction > 0.20
                        else CounterfactualOutcome.ATTACK_DEGRADED
                    ),
                    confidence=round(_clamp(0.5 + reduction * 0.5), 4),
                    risk_reduction=round(reduction, 4),
                    affected_facts=affected_facts[:10],
                    description=scen.get("description", action),
                )
                cf_results.append(cf)

            self._counterfactual_scenarios.extend(cf_results)

            best_action = max(cf_results, key=lambda c: c.risk_reduction) if cf_results else None

            result = ReasoningResult(
                mode=ReasoningMode.COUNTERFACTUAL,
                query=f"Counterfactual analysis: {len(scen_list)} scenarios",
                conclusion=(
                    f"Best mitigation: {best_action.intervention} "
                    f"(risk reduction: {best_action.risk_reduction:.0%})"
                    if best_action else "No scenarios evaluated"
                ),
                confidence=best_action.confidence if best_action else 0.0,
                hypotheses_evaluated=len(cf_results),
                duration_ms=(time.time() - t0) * 1000,
                explanation=f"Evaluated {len(cf_results)} counterfactual scenarios with vuln-type-aware effectiveness",
                alternatives=[
                    {
                        "action": c.intervention,
                        "reduction": c.risk_reduction,
                        "outcome": c.outcome.name,
                    }
                    for c in sorted(cf_results, key=lambda c: c.risk_reduction, reverse=True)
                ],
            )

            self._results.append(result)
            self._scan_phases.append({
                "phase": "counterfactual",
                "duration": (time.time() - t0) * 1000,
                "scenarios": len(cf_results),
            })
            logger.info("Phase 5 (Counterfactual): %d scenarios, best=%s",
                        len(cf_results),
                        best_action.intervention if best_action else "none")
            return result

    # ── Hypothesis Lifecycle (Change #9) ─────────────────────────────────

    def _create_hypotheses_from_findings(self) -> List[Hypothesis]:
        """Cria hipoteses estruturadas a partir dos findings de todas as fases."""
        hypotheses: List[Hypothesis] = []

        # From deductive: high-confidence hypotheses
        for fact in self._deductive._derived:
            h = Hypothesis(
                statement=fact,
                confidence=0.85,
                reasoning_mode=ReasoningMode.DEDUCTIVE,
                status=HypothesisStatus.SUPPORTED,
                explanation="Derived via forward chaining",
            )
            # Add supporting evidence from derivation trace
            if fact in self._deductive._derivation_trace:
                h.supporting_evidence = list(self._deductive._derivation_trace[fact])
            hypotheses.append(h)

        # From abductive: moderate-confidence
        for expl in self._abductive_explanations:
            h = Hypothesis(
                statement=expl.explanation,
                confidence=expl.occam_adjusted_score,
                reasoning_mode=ReasoningMode.ABDUCTIVE,
                status=HypothesisStatus.UNDER_EVALUATION,
                complexity_score=expl.complexity,
                explanation=f"Abductive explanation for '{expl.observation}' (posterior={expl.posterior:.3f})",
            )
            hypotheses.append(h)

        # From analogical: predicted vulnerabilities
        for ar in self._analogy_results:
            for vuln in ar.predicted_vulns:
                conf = ar.prediction_confidence.get(vuln, ar.similarity_score * 0.8)
                h = Hypothesis(
                    statement=f"predicted_vuln:{vuln} (from {ar.source_target})",
                    confidence=conf,
                    reasoning_mode=ReasoningMode.ANALOGICAL,
                    status=HypothesisStatus.PROPOSED,
                    explanation=f"Predicted by analogy with {ar.source_target} (sim={ar.similarity_score:.3f})",
                )
                hypotheses.append(h)

        # From causal: impact predictions
        for node_name, node in self._causal_nodes.items():
            if node.node_type == "impact" and node.probability > 0.1:
                h = Hypothesis(
                    statement=f"causal_impact:{node_name}",
                    confidence=node.probability,
                    reasoning_mode=ReasoningMode.CAUSAL,
                    status=HypothesisStatus.UNDER_EVALUATION,
                    explanation=f"Causal propagation (Noisy-OR) P={node.probability:.3f}",
                )
                hypotheses.append(h)

        return hypotheses

    # ── Report Generation ────────────────────────────────────────────────

    def generate_report(self, target: str = "", title: str = "") -> ReasoningReport:
        """Generate consolidated multi-modal reasoning report."""
        with self._lock:
            modes_used = list({r.mode.name for r in self._results})

            # Generate hypotheses from all findings
            hypotheses = self._create_hypotheses_from_findings()

            # Key findings from highest-confidence results
            key_findings = []
            for r in sorted(self._results, key=lambda x: x.confidence, reverse=True):
                if r.conclusion and r.confidence > 0.3:
                    key_findings.append(f"[{r.mode.name}] {r.conclusion}")

            # Risk assessment
            avg_conf = (
                sum(r.confidence for r in self._results) / len(self._results)
                if self._results else 0.0
            )
            if avg_conf > 0.7:
                risk = "HIGH — Multiple high-confidence attack paths identified"
            elif avg_conf > 0.4:
                risk = "MEDIUM — Several plausible attack vectors detected"
            else:
                risk = "LOW — Limited attack surface with low-confidence findings"

            # Recommendations
            recommendations = []

            # Recommendations from deductive findings (highest confidence)
            sorted_derived = sorted(self._deductive._derived)
            for fact in sorted_derived:
                if "rce" in fact or "injection" in fact:
                    recommendations.append(f"CRITICAL: Remediate {fact} immediately")
                elif "bypass" in fact or "access" in fact:
                    recommendations.append(f"HIGH: Fix access control issue: {fact}")

            if self._abductive_explanations:
                top_expl = max(self._abductive_explanations, key=lambda e: e.occam_adjusted_score)
                recommendations.append(f"Investigate: {top_expl.explanation} (abductive score={top_expl.occam_adjusted_score:.3f})")
            if self._counterfactual_scenarios:
                best_cf = max(self._counterfactual_scenarios, key=lambda c: c.risk_reduction)
                recommendations.append(f"Priority mitigation: {best_cf.intervention} (reduces risk by {best_cf.risk_reduction:.0%})")
            if self._analogy_results:
                top_analog = self._analogy_results[0]
                recommendations.append(f"Test for: {', '.join(top_analog.predicted_vulns[:5])} (by analogy with {top_analog.source_target})")

            total_duration = sum(p.get("duration", 0) for p in self._scan_phases)

            report = ReasoningReport(
                title=title or f"Cognitive Analysis: {target}",
                target=target,
                results=list(self._results),
                total_evidence=len(self._evidence),
                total_hypotheses=len(hypotheses),
                total_rules=len(self._deductive.get_rules()),
                total_chains=self._causal_chains_built,
                modes_used=modes_used,
                key_findings=key_findings[:15],
                risk_assessment=risk,
                overall_confidence=round(avg_conf, 4),
                recommendations=recommendations,
                duration_ms=round(total_duration, 2),
                metadata={
                    "phases": list(self._scan_phases),
                    "abductive_explanations": len(self._abductive_explanations),
                    "analogy_results": len(self._analogy_results),
                    "counterfactual_scenarios": len(self._counterfactual_scenarios),
                    "facts_in_knowledge_base": len(self._deductive.get_all_facts()),
                    "hypotheses_generated": len(hypotheses),
                    "causal_graph_nodes": len(self._causal_nodes),
                    "causal_graph_edges": len(self._causal_edges),
                },
            )

            logger.info(
                "Reasoning report: %d results, %d modes, %d hypotheses, confidence=%.2f, risk=%s",
                len(self._results), len(modes_used), len(hypotheses), avg_conf, risk[:30],
            )
            return report

    # ── Full Reasoning Pipeline (Change #8: Cross-modal fusion) ──────────

    def full_reasoning(
        self,
        target: str,
        goals: Optional[List[str]] = None,
        observations: Optional[List[str]] = None,
        target_attributes: Optional[Dict[str, Any]] = None,
        initial_vulns: Optional[List[str]] = None,
        counterfactual_scenarios: Optional[List[Dict[str, str]]] = None,
        title: str = "",
    ) -> ReasoningReport:
        """
        Execute complete multi-modal reasoning pipeline with cross-modal fusion.

        Each phase injects conclusions as new evidence for subsequent phases:
            1. Deductive reasoning — forward + backward chaining
            2. Abductive reasoning — best-explanation for anomalies
            3. Analogical reasoning — cross-target prediction
            4. Causal reasoning — attack chain modeling (uses deductive + analogical output)
            5. Counterfactual analysis — mitigation evaluation (informed by all phases)
            6. Report synthesis with hypothesis lifecycle
        """
        with self._lock:
            self._scan_start = time.time()
            initial_facts = set(self._deductive.get_all_facts())

        # Phase 1: Deductive
        deductive_result = self.reason_deductive(goals=goals)

        # Inject deductive conclusions as causal seeds
        with self._lock:
            derived_facts = self._deductive.get_all_facts() - initial_facts

        # Phase 2: Abductive
        abductive_result = self.reason_abductive(observations=observations)

        # Phase 3: Analogical
        analogical_result = self.reason_analogical(
            target_attributes=target_attributes,
            target_name=target,
        )

        # Inject predicted vulns as soft facts for causal analysis
        predicted_vulns: List[str] = []
        with self._lock:
            recent_analogies = self._analogy_results[-len(self.ANALOGY_ENTRIES):]
            for r in recent_analogies:
                predicted_vulns.extend(r.predicted_vulns)
            predicted_vulns = list(dict.fromkeys(predicted_vulns))

        # Phase 4: Causal — use derived facts + predicted vulns
        all_vulns = list(set(
            (initial_vulns or [])
            + predicted_vulns
            + [f for f in derived_facts if any(kw in f for kw in [
                "injection", "rce", "bypass", "sqli", "ssrf", "xss",
                "deserialization", "lfi", "rfi", "overflow",
            ])]
        ))
        self.reason_causal(initial_vulns=all_vulns if all_vulns else None)

        # Phase 5: Counterfactual — informed by all previous phases
        self.reason_counterfactual(scenarios=counterfactual_scenarios)

        with self._lock:
            self._scan_end = time.time()

        # Phase 6: Report (includes hypothesis lifecycle)
        return self.generate_report(target=target, title=title)

    # ── Register Analogy (Change #11) ────────────────────────────────────

    def register_analogy(self, entry: Dict[str, Any]) -> None:
        """Registra nova analogia no banco de conhecimento."""
        with self._lock:
            self.ANALOGY_ENTRIES.append(entry)
            logger.info("Registered new analogy: %s", entry.get("target", "unknown"))

    # ── Persistence Hooks (Change #12) ───────────────────────────────────

    def save_state(self) -> Dict[str, Any]:
        """Exporta estado completo para persistencia."""
        with self._lock:
            return {
                "evidence": [e.to_dict() for e in self._evidence],
                "results": [r.to_dict() for r in self._results],
                "deductive_state": self._deductive.to_dict(),
                "abductive_explanations": [e.to_dict() for e in self._abductive_explanations],
                "analogy_results": [r.to_dict() for r in self._analogy_results],
                "causal_chains_built": self._causal_chains_built,
                "causal_nodes": {k: v.to_dict() for k, v in self._causal_nodes.items()},
                "causal_edges": [e.to_dict() for e in self._causal_edges],
                "counterfactual_scenarios": [s.to_dict() for s in self._counterfactual_scenarios],
                "scan_phases": list(self._scan_phases),
                "scan_start": self._scan_start,
                "scan_end": self._scan_end,
            }

    def load_state(self, state: Dict[str, Any]) -> None:
        """Restaura estado a partir de dados serializados."""
        with self._lock:
            # Restore evidence
            self._evidence = []
            for ev_data in state.get("evidence", []):
                try:
                    ev_type = EvidenceType[ev_data.get("evidence_type", "CUSTOM")]
                except KeyError:
                    ev_type = EvidenceType.CUSTOM
                self._evidence.append(Evidence(
                    id=ev_data.get("id", ""),
                    evidence_type=ev_type,
                    value=ev_data.get("value"),
                    source=ev_data.get("source", ""),
                    confidence=ev_data.get("confidence", 0.5),
                    timestamp=ev_data.get("timestamp", 0.0),
                    tags=ev_data.get("tags", []),
                    metadata=ev_data.get("metadata", {}),
                ))

            # Restore deductive state (facts)
            deductive_state = state.get("deductive_state", {})
            self._deductive.clear_facts()
            for fact in deductive_state.get("facts", []):
                self._deductive.add_fact(fact)

            # Restore counters and phases
            self._causal_chains_built = state.get("causal_chains_built", 0)
            self._scan_phases = list(state.get("scan_phases", []))
            self._scan_start = state.get("scan_start", 0.0)
            self._scan_end = state.get("scan_end", 0.0)

            logger.info("State restored: %d evidence items, %d facts",
                        len(self._evidence),
                        len(self._deductive.get_all_facts()))

    # ── Accessors ────────────────────────────────────────────────────────

    def get_results(self) -> List[ReasoningResult]:
        with self._lock:
            return list(self._results)

    def get_deductive_engine(self) -> DeductiveEngine:
        return self._deductive

    def get_hypotheses(self) -> List[Hypothesis]:
        """Returns all hypotheses generated from current findings."""
        with self._lock:
            return self._create_hypotheses_from_findings()

    def reset(self) -> None:
        """Reset all reasoning state (keeps rules, clears facts/results)."""
        with self._lock:
            self._evidence.clear()
            self._results.clear()
            self._abductive_explanations.clear()
            self._analogy_results.clear()
            self._counterfactual_scenarios.clear()
            self._causal_chains_built = 0
            self._causal_nodes.clear()
            self._causal_edges.clear()
            self._scan_phases.clear()
            self._scan_start = 0.0
            self._scan_end = 0.0
            self._deductive.clear_facts()
            logger.info("SirenCognitiveReasoner state reset")

    def to_dict(self) -> Dict[str, Any]:
        """Serialize orchestrator state."""
        with self._lock:
            return {
                "evidence_count": len(self._evidence),
                "results_count": len(self._results),
                "modes_used": list({r.mode.name for r in self._results}),
                "abductive_explanations": len(self._abductive_explanations),
                "analogy_results": len(self._analogy_results),
                "counterfactual_scenarios": len(self._counterfactual_scenarios),
                "causal_chains": self._causal_chains_built,
                "causal_graph_nodes": len(self._causal_nodes),
                "causal_graph_edges": len(self._causal_edges),
                "rules_loaded": len(self._deductive.get_rules()),
                "facts_known": len(self._deductive.get_all_facts()),
                "phases": list(self._scan_phases),
                "duration": self._scan_end - self._scan_start if self._scan_end else 0.0,
            }
