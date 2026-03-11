#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  SIREN INFORMATION THEORY ENGINE — Claude Shannon Applied to Offense          ██
██                                                                                ██
██  The world's first offensive security engine built on information theory.      ██
██  Detects injection vulnerabilities WITHOUT malicious payloads using mutual     ██
██  information. Estimates exfiltration capacity via channel capacity theorem.    ██
██  Optimizes evasion via entropy matching. Minimizes requests via Fisher info.   ██
██                                                                                ██
██  Engines:                                                                      ██
██    1. ShannonEntropyAnalyzer   — entropy profiling, WAF evasion               ██
██    2. MutualInformationScanner — injection detection via benign probes         ██
██    3. KLDivergenceDetector     — behavioral anomaly via distribution shift     ██
██    4. FisherInformationProber  — optimal probe design, minimum requests        ██
██    5. ChannelCapacityEstimator — exfiltration bandwidth estimation             ██
██    6. KolmogorovComplexityEstimator — code-path & obfuscation detection       ██
██                                                                                ██
██  References:                                                                   ██
██    Shannon (1948) — A Mathematical Theory of Communication                    ██
██    Kullback & Leibler (1951) — On Information and Sufficiency                 ██
██    Fisher (1925) — Theory of Statistical Estimation                           ██
██    Kolmogorov (1965) — Three Approaches to the Definition of Complexity       ██
██                                                                                ██
██  "Information is the resolution of uncertainty." — Claude Shannon             ██
██                                                                                ██
████████████████████████████████████████████████████████████████████████████████████
"""

from __future__ import annotations

import collections
import hashlib
import html
import io
import json
import logging
import math
import random
import re
import string
import struct
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Optional,
    Set,
    Tuple,
    Union,
)

logger = logging.getLogger("siren.information_theory")

# ════════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════════════════════════════

EPSILON = 1e-12
LOG_FLOOR = 1e-300
DEFAULT_TIMEOUT = 10
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
MAX_RESPONSE_SIZE = 2 * 1024 * 1024  # 2 MB cap on response reads
HISTOGRAM_BINS = 256
SMOOTHING_ALPHA = 1e-6  # Laplace smoothing for probability distributions
MI_HIGH_THRESHOLD = 0.5  # bits — above this, strong input-output dependency
MI_MEDIUM_THRESHOLD = 0.15
KL_ANOMALY_THRESHOLD = 0.3
JS_ANOMALY_THRESHOLD = 0.15
ENTROPY_WAF_TOLERANCE = 0.5  # bits — how close payload entropy must match target
FISHER_STEP_SIZE = 0.01
CHANNEL_TRIAL_COUNT = 15
COMPLEXITY_CHANGE_THRESHOLD = 0.15  # relative change in NCD to flag code-path change
NCD_OBFUSCATION_THRESHOLD = 0.95  # high NCD + high entropy = obfuscated


# ════════════════════════════════════════════════════════════════════════════════
# ENUMS
# ════════════════════════════════════════════════════════════════════════════════


class VulnType(Enum):
    """Vulnerability type inferred from information-theoretic signatures."""
    UNKNOWN = "unknown"
    XSS_REFLECTED = "xss_reflected"
    XSS_STORED = "xss_stored"
    SQLI = "sqli"
    SSTI = "ssti"
    PATH_TRAVERSAL = "path_traversal"
    RCE = "rce"
    OPEN_REDIRECT = "open_redirect"
    HEADER_INJECTION = "header_injection"
    LDAP_INJECTION = "ldap_injection"


class EntropyZone(Enum):
    """Classification of entropy level."""
    VERY_LOW = "very_low"       # < 1.0 — highly structured / sparse
    LOW = "low"                 # 1.0–3.0 — natural text, HTML
    MEDIUM = "medium"           # 3.0–5.0 — mixed content
    HIGH = "high"               # 5.0–7.0 — compressed, encoded
    VERY_HIGH = "very_high"     # > 7.0 — encrypted / random


class ScanMode(Enum):
    FULL = "full"
    QUICK = "quick"
    STEALTH = "stealth"


class ReflectionType(Enum):
    NONE = "none"
    DIRECT = "direct"           # input echoed verbatim
    ENCODED = "encoded"         # input HTML/URL encoded
    PARTIAL = "partial"         # substring reflected
    STRUCTURAL = "structural"   # input alters page structure


class DataFlowType(Enum):
    NONE = "none"
    DATABASE = "database"
    TEMPLATE = "template"
    FILESYSTEM = "filesystem"
    COMMAND = "command"
    REDIRECT = "redirect"


# ════════════════════════════════════════════════════════════════════════════════
# DATACLASSES
# ════════════════════════════════════════════════════════════════════════════════


@dataclass
class EntropyProfile:
    """Entropy statistics for a data sample."""
    shannon_entropy: float = 0.0
    max_entropy: float = 0.0
    normalized_entropy: float = 0.0
    byte_distribution: Dict[int, float] = field(default_factory=dict)
    zone: EntropyZone = EntropyZone.LOW
    sample_size: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "shannon_entropy": round(self.shannon_entropy, 6),
            "max_entropy": round(self.max_entropy, 6),
            "normalized_entropy": round(self.normalized_entropy, 6),
            "zone": self.zone.value,
            "sample_size": self.sample_size,
        }


@dataclass
class EntropyClassification:
    """Result of classifying a payload's entropy against a baseline."""
    payload_entropy: float = 0.0
    baseline_entropy: float = 0.0
    deviation: float = 0.0
    likely_detected: bool = False
    confidence: float = 0.0
    recommendation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "payload_entropy": round(self.payload_entropy, 6),
            "baseline_entropy": round(self.baseline_entropy, 6),
            "deviation": round(self.deviation, 6),
            "likely_detected": self.likely_detected,
            "confidence": round(self.confidence, 4),
            "recommendation": self.recommendation,
        }


@dataclass
class EntropyReport:
    """Aggregate entropy analysis report."""
    profiles: List[EntropyProfile] = field(default_factory=list)
    relative_entropies: List[float] = field(default_factory=list)
    entropy_rate: float = 0.0
    classifications: List[EntropyClassification] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "profiles": [p.to_dict() for p in self.profiles],
            "relative_entropies": [round(r, 6) for r in self.relative_entropies],
            "entropy_rate": round(self.entropy_rate, 6),
            "classifications": [c.to_dict() for c in self.classifications],
            "timestamp": self.timestamp,
        }


@dataclass
class MutualInformationResult:
    """Result of mutual information measurement for one parameter."""
    param: str = ""
    mi_value: float = 0.0
    confidence: float = 0.0
    likely_vuln_type: VulnType = VulnType.UNKNOWN
    evidence: List[str] = field(default_factory=list)
    n_samples: int = 0
    response_entropy: float = 0.0
    conditional_entropy: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "param": self.param,
            "mi_value": round(self.mi_value, 6),
            "confidence": round(self.confidence, 4),
            "likely_vuln_type": self.likely_vuln_type.value,
            "evidence": self.evidence,
            "n_samples": self.n_samples,
            "response_entropy": round(self.response_entropy, 6),
            "conditional_entropy": round(self.conditional_entropy, 6),
        }


@dataclass
class ReflectionResult:
    """Result of reflection detection via mutual information."""
    param: str = ""
    reflected: bool = False
    reflection_type: ReflectionType = ReflectionType.NONE
    mi_value: float = 0.0
    reflection_contexts: List[str] = field(default_factory=list)
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "param": self.param,
            "reflected": self.reflected,
            "reflection_type": self.reflection_type.value,
            "mi_value": round(self.mi_value, 6),
            "reflection_contexts": self.reflection_contexts,
            "confidence": round(self.confidence, 4),
        }


@dataclass
class DataFlowResult:
    """Result of data flow detection via MI signature patterns."""
    param: str = ""
    flow_type: DataFlowType = DataFlowType.NONE
    mi_value: float = 0.0
    mi_pattern: Dict[str, float] = field(default_factory=dict)
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "param": self.param,
            "flow_type": self.flow_type.value,
            "mi_value": round(self.mi_value, 6),
            "mi_pattern": {k: round(v, 6) for k, v in self.mi_pattern.items()},
            "confidence": round(self.confidence, 4),
            "evidence": self.evidence,
        }


@dataclass
class ResponseDistribution:
    """Probability distribution built from baseline responses."""
    url: str = ""
    n_samples: int = 0
    status_distribution: Dict[int, float] = field(default_factory=dict)
    length_mean: float = 0.0
    length_std: float = 0.0
    token_distribution: Dict[str, float] = field(default_factory=dict)
    header_signature: Dict[str, int] = field(default_factory=dict)
    feature_vector: List[float] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "n_samples": self.n_samples,
            "status_distribution": self.status_distribution,
            "length_mean": round(self.length_mean, 2),
            "length_std": round(self.length_std, 2),
            "header_signature": self.header_signature,
            "timestamp": self.timestamp,
        }


@dataclass
class DivergenceResult:
    """Result of KL/JS divergence measurement."""
    kl_divergence: float = 0.0
    js_divergence: float = 0.0
    is_anomalous: bool = False
    anomaly_score: float = 0.0
    features_changed: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kl_divergence": round(self.kl_divergence, 6),
            "js_divergence": round(self.js_divergence, 6),
            "is_anomalous": self.is_anomalous,
            "anomaly_score": round(self.anomaly_score, 4),
            "features_changed": self.features_changed,
        }


@dataclass
class AnomalyResult:
    """Full anomaly detection result for a single payload."""
    param: str = ""
    payload: str = ""
    divergence: DivergenceResult = field(default_factory=DivergenceResult)
    baseline_samples: int = 0
    probe_status: int = 0
    classification: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "param": self.param,
            "payload": self.payload,
            "divergence": self.divergence.to_dict(),
            "baseline_samples": self.baseline_samples,
            "probe_status": self.probe_status,
            "classification": self.classification,
        }


@dataclass
class FisherResult:
    """Fisher information measurement for a parameter."""
    param: str = ""
    fisher_information: float = 0.0
    cramer_rao_bound: float = 0.0
    sensitivity: float = 0.0
    n_probes_used: int = 0
    optimal_probe: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "param": self.param,
            "fisher_information": round(self.fisher_information, 6),
            "cramer_rao_bound": round(self.cramer_rao_bound, 6),
            "sensitivity": round(self.sensitivity, 6),
            "n_probes_used": self.n_probes_used,
            "optimal_probe": self.optimal_probe,
        }


@dataclass
class ProbeDesign:
    """A single probe in an optimal sequence."""
    probe_value: str = ""
    expected_information_gain: float = 0.0
    actual_information_gain: float = 0.0
    cumulative_information: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "probe_value": self.probe_value,
            "expected_information_gain": round(self.expected_information_gain, 6),
            "actual_information_gain": round(self.actual_information_gain, 6),
            "cumulative_information": round(self.cumulative_information, 6),
        }


@dataclass
class AdaptiveScanResult:
    """Result of Fisher-optimal adaptive scanning."""
    param: str = ""
    probes: List[ProbeDesign] = field(default_factory=list)
    total_information: float = 0.0
    confidence_reached: float = 0.0
    n_requests: int = 0
    converged: bool = False
    estimated_vuln_type: VulnType = VulnType.UNKNOWN

    def to_dict(self) -> Dict[str, Any]:
        return {
            "param": self.param,
            "probes": [p.to_dict() for p in self.probes],
            "total_information": round(self.total_information, 6),
            "confidence_reached": round(self.confidence_reached, 4),
            "n_requests": self.n_requests,
            "converged": self.converged,
            "estimated_vuln_type": self.estimated_vuln_type.value,
        }


@dataclass
class ChannelCapacity:
    """Channel capacity estimation for an endpoint parameter."""
    param: str = ""
    bits_per_request: float = 0.0
    bits_per_second: float = 0.0
    noise_level: float = 0.0
    exfil_risk: str = "low"
    error_rate: float = 0.0
    capacity_binary: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "param": self.param,
            "bits_per_request": round(self.bits_per_request, 4),
            "bits_per_second": round(self.bits_per_second, 4),
            "noise_level": round(self.noise_level, 6),
            "exfil_risk": self.exfil_risk,
            "error_rate": round(self.error_rate, 6),
            "capacity_binary": round(self.capacity_binary, 6),
        }


@dataclass
class ComplexityProfile:
    """Kolmogorov complexity profile across inputs."""
    param: str = ""
    complexities: Dict[str, float] = field(default_factory=dict)
    mean_complexity: float = 0.0
    std_complexity: float = 0.0
    anomalous_inputs: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "param": self.param,
            "complexities": {k: round(v, 6) for k, v in self.complexities.items()},
            "mean_complexity": round(self.mean_complexity, 6),
            "std_complexity": round(self.std_complexity, 6),
            "anomalous_inputs": self.anomalous_inputs,
        }


@dataclass
class CodePathChange:
    """Detected change in server code path based on complexity shift."""
    input_a: str = ""
    input_b: str = ""
    complexity_a: float = 0.0
    complexity_b: float = 0.0
    ncd: float = 0.0
    complexity_delta: float = 0.0
    significant: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "input_a": self.input_a,
            "input_b": self.input_b,
            "complexity_a": round(self.complexity_a, 6),
            "complexity_b": round(self.complexity_b, 6),
            "ncd": round(self.ncd, 6),
            "complexity_delta": round(self.complexity_delta, 6),
            "significant": self.significant,
        }


@dataclass
class ObfuscationResult:
    """Detection of obfuscated or encrypted content."""
    entropy: float = 0.0
    compression_ratio: float = 0.0
    is_obfuscated: bool = False
    confidence: float = 0.0
    likely_type: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entropy": round(self.entropy, 6),
            "compression_ratio": round(self.compression_ratio, 6),
            "is_obfuscated": self.is_obfuscated,
            "confidence": round(self.confidence, 4),
            "likely_type": self.likely_type,
        }


@dataclass
class ITFinding:
    """A single finding from the information theory scan."""
    param: str = ""
    finding_type: str = ""
    vuln_type: VulnType = VulnType.UNKNOWN
    confidence: float = 0.0
    mi_value: float = 0.0
    kl_divergence: float = 0.0
    description: str = ""
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "param": self.param,
            "finding_type": self.finding_type,
            "vuln_type": self.vuln_type.value,
            "confidence": round(self.confidence, 4),
            "mi_value": round(self.mi_value, 6),
            "kl_divergence": round(self.kl_divergence, 6),
            "description": self.description,
            "evidence": self.evidence,
        }


@dataclass
class InformationTheoryReport:
    """Complete report from information theory scan."""
    target_url: str = ""
    scan_mode: str = "full"
    findings: List[ITFinding] = field(default_factory=list)
    entropy_profiles: Dict[str, EntropyProfile] = field(default_factory=dict)
    mi_results: List[MutualInformationResult] = field(default_factory=list)
    divergence_results: List[DivergenceResult] = field(default_factory=list)
    channel_capacities: List[ChannelCapacity] = field(default_factory=list)
    fisher_results: List[FisherResult] = field(default_factory=list)
    complexity_profiles: List[ComplexityProfile] = field(default_factory=list)
    total_requests_made: int = 0
    scan_duration: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_url": self.target_url,
            "scan_mode": self.scan_mode,
            "findings": [f.to_dict() for f in self.findings],
            "entropy_profiles": {k: v.to_dict() for k, v in self.entropy_profiles.items()},
            "mi_results": [m.to_dict() for m in self.mi_results],
            "divergence_results": [d.to_dict() for d in self.divergence_results],
            "channel_capacities": [c.to_dict() for c in self.channel_capacities],
            "fisher_results": [f.to_dict() for f in self.fisher_results],
            "complexity_profiles": [c.to_dict() for c in self.complexity_profiles],
            "total_requests_made": self.total_requests_made,
            "scan_duration": round(self.scan_duration, 3),
            "timestamp": self.timestamp,
        }


# ════════════════════════════════════════════════════════════════════════════════
# HTTP UTILITY
# ════════════════════════════════════════════════════════════════════════════════


class _HTTPClient:
    """Minimal thread-safe HTTP client wrapping urllib.request."""

    def __init__(self, timeout: float = DEFAULT_TIMEOUT, user_agent: str = DEFAULT_USER_AGENT):
        self._timeout = timeout
        self._user_agent = user_agent
        self._lock = threading.RLock()
        self._request_count = 0

    @property
    def request_count(self) -> int:
        with self._lock:
            return self._request_count

    def reset_count(self) -> None:
        with self._lock:
            self._request_count = 0

    def get(
        self,
        url: str,
        params: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[bytes, int, Dict[str, str]]:
        """Perform GET request. Returns (body, status_code, response_headers)."""
        if params:
            sep = "&" if "?" in url else "?"
            encoded = urllib.parse.urlencode(params)
            url = f"{url}{sep}{encoded}"
        req = urllib.request.Request(url, method="GET")
        return self._execute(req, headers)

    def post(
        self,
        url: str,
        data: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[bytes, int, Dict[str, str]]:
        """Perform POST request. Returns (body, status_code, response_headers)."""
        body = urllib.parse.urlencode(data).encode() if data else b""
        req = urllib.request.Request(url, data=body, method="POST")
        if data:
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
        return self._execute(req, headers)

    def _execute(
        self, req: urllib.request.Request, extra_headers: Optional[Dict[str, str]] = None
    ) -> Tuple[bytes, int, Dict[str, str]]:
        req.add_header("User-Agent", self._user_agent)
        if extra_headers:
            for k, v in extra_headers.items():
                req.add_header(k, v)
        with self._lock:
            self._request_count += 1
        try:
            resp = urllib.request.urlopen(req, timeout=self._timeout)
            body = resp.read(MAX_RESPONSE_SIZE)
            status = resp.getcode() or 200
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            return body, status, hdrs
        except urllib.error.HTTPError as exc:
            body = b""
            try:
                body = exc.read(MAX_RESPONSE_SIZE)
            except Exception:
                pass
            hdrs = {k.lower(): v for k, v in exc.headers.items()} if exc.headers else {}
            return body, exc.code, hdrs
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            logger.debug("HTTP request failed for %s: %s", req.full_url, exc)
            return b"", 0, {}


# ════════════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ════════════════════════════════════════════════════════════════════════════════


def _safe_log2(x: float) -> float:
    """Compute log2 safely, flooring at LOG_FLOOR."""
    if x <= 0:
        return math.log2(LOG_FLOOR)
    return math.log2(x)


def _normalize_distribution(counts: Dict[Any, int], smoothing: float = SMOOTHING_ALPHA) -> List[float]:
    """Convert counts dict to normalized probability list with Laplace smoothing."""
    total = sum(counts.values()) + smoothing * len(counts)
    if total <= 0:
        n = max(len(counts), 1)
        return [1.0 / n] * n
    return [(counts.get(k, 0) + smoothing) / total for k in counts]


def _make_probability_vector(raw: List[float], smoothing: float = SMOOTHING_ALPHA) -> List[float]:
    """Normalize a raw frequency list into a proper probability distribution."""
    total = sum(raw) + smoothing * len(raw)
    if total <= 0:
        n = max(len(raw), 1)
        return [1.0 / n] * n
    return [(v + smoothing) / total for v in raw]


def _generate_benign_strings(n: int, length_range: Tuple[int, int] = (3, 12)) -> List[str]:
    """Generate n random benign strings for probing."""
    results: List[str] = []
    charset = string.ascii_lowercase + string.digits
    for _ in range(n):
        ln = random.randint(length_range[0], length_range[1])
        results.append("".join(random.choices(charset, k=ln)))
    return results


def _generate_numeric_strings(n: int, low: int = 0, high: int = 999999) -> List[str]:
    """Generate n random numeric strings."""
    return [str(random.randint(low, high)) for _ in range(n)]


def _structural_hash(data: bytes, block_size: int = 256) -> List[int]:
    """Convert response bytes into a list of structural hash tokens.

    Divides the response into blocks, hashes each block to an 8-bit value.
    This captures structure without raw byte sensitivity.
    """
    if not data:
        return [0]
    tokens: List[int] = []
    for i in range(0, len(data), block_size):
        block = data[i : i + block_size]
        h = hashlib.md5(block).digest()
        tokens.append(h[0])
    return tokens


def _extract_html_structure(data: bytes) -> str:
    """Extract simplified HTML tag structure from response body."""
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        return ""
    tags = re.findall(r"</?[a-zA-Z][a-zA-Z0-9]*", text)
    return "|".join(tags[:200])


def _response_feature_vector(body: bytes, status: int, headers: Dict[str, str]) -> List[float]:
    """Extract a fixed-length feature vector from an HTTP response.

    Features (16-dimensional):
      0: status code / 600
      1: body length (log-scaled)
      2: body entropy (Shannon / 8)
      3: compression ratio
      4-7: byte quartile means
      8: number of HTML tags (log)
      9: content-type hash (mod 1.0)
     10: number of headers / 50
     11: presence of set-cookie (0/1)
     12: presence of location (0/1)
     13: ratio of printable ASCII
     14: number of unique bigrams (log / 16)
     15: structural hash variance
    """
    vec = [0.0] * 16

    # 0: status
    vec[0] = float(status) / 600.0

    # 1: length log-scaled
    blen = len(body)
    vec[1] = math.log2(blen + 1) / 25.0

    # 2: entropy
    if blen > 0:
        c = Counter(body)
        ent = 0.0
        for count in c.values():
            p = count / blen
            if p > 0:
                ent -= p * math.log2(p)
        vec[2] = ent / 8.0
    # 3: compression ratio
    if blen > 0:
        try:
            compressed = zlib.compress(body, 6)
            vec[3] = len(compressed) / blen
        except Exception:
            vec[3] = 1.0
    # 4-7: quartile byte means
    if blen >= 4:
        q = blen // 4
        for i in range(4):
            seg = body[i * q : (i + 1) * q]
            vec[4 + i] = (sum(seg) / len(seg)) / 255.0 if seg else 0.0
    # 8: HTML tag count
    try:
        tag_count = len(re.findall(rb"<[a-zA-Z]", body))
        vec[8] = math.log2(tag_count + 1) / 12.0
    except Exception:
        pass
    # 9: content-type hash
    ct = headers.get("content-type", "")
    vec[9] = (int(hashlib.md5(ct.encode()).hexdigest()[:4], 16) % 1000) / 1000.0
    # 10: header count
    vec[10] = min(len(headers) / 50.0, 1.0)
    # 11-12: cookie and redirect
    vec[11] = 1.0 if "set-cookie" in headers else 0.0
    vec[12] = 1.0 if "location" in headers else 0.0
    # 13: printable ratio
    if blen > 0:
        printable = sum(1 for b in body if 32 <= b <= 126)
        vec[13] = printable / blen
    # 14: unique bigrams
    if blen > 1:
        bigrams = set()
        for i in range(blen - 1):
            bigrams.add((body[i], body[i + 1]))
        vec[14] = math.log2(len(bigrams) + 1) / 16.0
    # 15: structural hash variance
    tokens = _structural_hash(body, 512)
    if len(tokens) > 1:
        mean_t = sum(tokens) / len(tokens)
        var_t = sum((t - mean_t) ** 2 for t in tokens) / len(tokens)
        vec[15] = min(var_t / 6500.0, 1.0)  # scale to ~[0,1]

    return vec


# ════════════════════════════════════════════════════════════════════════════════
# ENGINE 1: SHANNON ENTROPY ANALYZER
# ════════════════════════════════════════════════════════════════════════════════


class ShannonEntropyAnalyzer:
    """Shannon entropy computation engine for HTTP responses and payloads.

    Provides entropy profiling, relative/conditional/joint entropy, entropy
    rate analysis, and payload entropy optimization to evade entropy-based
    WAF detection.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._cache: Dict[bytes, float] = {}
        self._cache_max = 4096

    # ── Core entropy ──────────────────────────────────────────────────────────

    def entropy(self, data: bytes) -> float:
        """Shannon entropy H(X) = -SUM p(x) * log2(p(x)) for byte data."""
        if not data:
            return 0.0
        with self._lock:
            if data in self._cache:
                return self._cache[data]
        n = len(data)
        counts = Counter(data)
        h = 0.0
        for count in counts.values():
            p = count / n
            if p > 0:
                h -= p * math.log2(p)
        with self._lock:
            if len(self._cache) < self._cache_max:
                self._cache[data] = h
        return h

    def max_entropy(self, data: bytes) -> float:
        """Maximum possible entropy for the given data length (log2 of alphabet size)."""
        if not data:
            return 0.0
        unique = len(set(data))
        return math.log2(unique) if unique > 1 else 0.0

    def normalized_entropy(self, data: bytes) -> float:
        """Entropy normalized to [0, 1] range. H(X) / log2(n_unique_symbols)."""
        mx = self.max_entropy(data)
        if mx <= 0:
            return 0.0
        return self.entropy(data) / mx

    def profile(self, data: bytes) -> EntropyProfile:
        """Build full entropy profile for data."""
        h = self.entropy(data)
        mx = self.max_entropy(data)
        norm = h / mx if mx > 0 else 0.0
        n = len(data)
        counts = Counter(data)
        dist = {k: v / n for k, v in counts.items()} if n > 0 else {}

        if h < 1.0:
            zone = EntropyZone.VERY_LOW
        elif h < 3.0:
            zone = EntropyZone.LOW
        elif h < 5.0:
            zone = EntropyZone.MEDIUM
        elif h < 7.0:
            zone = EntropyZone.HIGH
        else:
            zone = EntropyZone.VERY_HIGH

        return EntropyProfile(
            shannon_entropy=h,
            max_entropy=mx,
            normalized_entropy=norm,
            byte_distribution=dist,
            zone=zone,
            sample_size=n,
        )

    # ── Relative entropy (KL divergence between byte distributions) ──────────

    def relative_entropy(self, baseline: bytes, sample: bytes) -> float:
        """KL divergence D_KL(P_sample || P_baseline) of byte distributions.

        Measures how much the sample distribution deviates from baseline.
        """
        if not baseline or not sample:
            return 0.0
        p_dist = self._byte_distribution(sample)
        q_dist = self._byte_distribution(baseline)
        kl = 0.0
        for byte_val in range(256):
            p = p_dist.get(byte_val, SMOOTHING_ALPHA)
            q = q_dist.get(byte_val, SMOOTHING_ALPHA)
            if p > EPSILON:
                kl += p * math.log2(p / q)
        return max(kl, 0.0)

    # ── Conditional entropy H(Y|X) ──────────────────────────────────────────

    def conditional_entropy(self, responses: List[bytes], inputs: List[str]) -> float:
        """Conditional entropy H(Y|X) — uncertainty about response given input.

        Groups responses by input, computes weighted average of per-group
        entropy. LOW value = server leaks information about internal state
        based on input.
        """
        if not responses or not inputs or len(responses) != len(inputs):
            return 0.0

        # Group responses by input
        groups: Dict[str, List[bytes]] = defaultdict(list)
        for inp, resp in zip(inputs, responses):
            groups[inp].append(resp)

        n_total = len(responses)
        h_y_given_x = 0.0

        for inp, resps in groups.items():
            p_x = len(resps) / n_total
            # Concatenate responses in this group and compute entropy
            concat = b"".join(resps)
            h_y_x = self.entropy(concat) if concat else 0.0
            h_y_given_x += p_x * h_y_x

        return h_y_given_x

    # ── Joint entropy H(X,Y) ───────────────────────────────────────────────

    def joint_entropy(self, x: bytes, y: bytes) -> float:
        """Joint entropy H(X,Y) of two byte sequences treated as paired symbols."""
        if not x or not y:
            return self.entropy(x) + self.entropy(y)
        # Use min length for pairing
        n = min(len(x), len(y))
        pairs = [(x[i], y[i]) for i in range(n)]
        counts = Counter(pairs)
        h = 0.0
        for count in counts.values():
            p = count / n
            if p > 0:
                h -= p * math.log2(p)
        return h

    # ── Entropy rate ──────────────────────────────────────────────────────────

    def entropy_rate(self, sequence: List[bytes]) -> float:
        """Entropy rate: entropy per symbol across a sequence of responses.

        Uses the block entropy approach: H_rate = H(X_n) - H(X_{n-1})
        approximated by computing bigram vs unigram entropy difference
        over the concatenated sequence.
        """
        if not sequence:
            return 0.0
        concat = b"".join(sequence)
        if len(concat) < 2:
            return self.entropy(concat)

        # Unigram entropy
        h1 = self.entropy(concat)

        # Bigram entropy
        n = len(concat)
        bigrams = [(concat[i], concat[i + 1]) for i in range(n - 1)]
        counts = Counter(bigrams)
        h2 = 0.0
        total = len(bigrams)
        for count in counts.values():
            p = count / total
            if p > 0:
                h2 -= p * math.log2(p)

        # Entropy rate approximation: H(X_n | X_{n-1}) = H(X_n, X_{n-1}) - H(X_{n-1})
        # Since h2 is H(bigrams) which encodes joint, and h1 is H(unigrams):
        rate = h2 - h1
        return max(rate, 0.0)

    # ── Payload classification ────────────────────────────────────────────────

    def classify_payload_entropy(
        self, payload: str, baseline_entropy: float
    ) -> EntropyClassification:
        """Classify a payload by comparing its entropy to baseline traffic.

        If the deviation is large, the payload is likely to be flagged by
        an entropy-based WAF.
        """
        payload_bytes = payload.encode("utf-8", errors="replace")
        pe = self.entropy(payload_bytes)
        deviation = abs(pe - baseline_entropy)

        # Confidence that WAF detects: sigmoid-based on deviation
        # At deviation=0, confidence=0; at deviation=ENTROPY_WAF_TOLERANCE, ~0.5
        if deviation < EPSILON:
            conf = 0.0
        else:
            conf = 1.0 / (1.0 + math.exp(-3.0 * (deviation - ENTROPY_WAF_TOLERANCE)))

        detected = conf > 0.5

        if detected:
            if pe > baseline_entropy:
                rec = (
                    "Payload entropy is %.2f bits above baseline (%.2f). "
                    "Add padding with low-entropy chars or reduce encoded content."
                    % (deviation, baseline_entropy)
                )
            else:
                rec = (
                    "Payload entropy is %.2f bits below baseline (%.2f). "
                    "Add some high-entropy noise or mixed-case characters."
                    % (deviation, baseline_entropy)
                )
        else:
            rec = "Payload entropy (%.2f) is within tolerance of baseline (%.2f)." % (pe, baseline_entropy)

        return EntropyClassification(
            payload_entropy=pe,
            baseline_entropy=baseline_entropy,
            deviation=deviation,
            likely_detected=detected,
            confidence=conf,
            recommendation=rec,
        )

    # ── Payload entropy optimization ──────────────────────────────────────────

    def optimize_payload_entropy(self, payload: str, target_entropy: float) -> str:
        """Transform payload to match target entropy profile.

        Techniques applied iteratively:
          1. Case variation (randomize upper/lower)
          2. Whitespace padding (spaces, tabs)
          3. Comment injection (HTML/SQL comments)
          4. URL-encode selective chars
          5. Add benign suffixes
        """
        current = payload
        max_iterations = 50

        for _ in range(max_iterations):
            current_bytes = current.encode("utf-8", errors="replace")
            current_entropy = self.entropy(current_bytes)
            deviation = current_entropy - target_entropy

            if abs(deviation) < 0.1:
                break

            if deviation > 0:
                # Entropy too high — add repetitive/predictable content
                pad_char = random.choice([" ", "\t", "a", "0"])
                pad_len = max(1, int(abs(deviation) * 3))
                insert_pos = random.randint(0, max(len(current) - 1, 0))
                current = current[:insert_pos] + (pad_char * pad_len) + current[insert_pos:]
            else:
                # Entropy too low — add diverse content
                techniques = [
                    self._apply_case_variation,
                    self._insert_comment_noise,
                    self._add_diverse_padding,
                ]
                technique = random.choice(techniques)
                current = technique(current)

        return current

    def _apply_case_variation(self, s: str) -> str:
        """Randomly change case of alphabetic chars to increase entropy."""
        chars = list(s)
        alpha_indices = [i for i, c in enumerate(chars) if c.isalpha()]
        if not alpha_indices:
            return s + random.choice(string.ascii_letters)
        n_flip = max(1, len(alpha_indices) // 4)
        for idx in random.sample(alpha_indices, min(n_flip, len(alpha_indices))):
            chars[idx] = chars[idx].swapcase()
        return "".join(chars)

    def _insert_comment_noise(self, s: str) -> str:
        """Insert HTML/SQL-style comments with diverse content."""
        comments = [
            "<!--%s-->" % "".join(random.choices(string.ascii_letters, k=4)),
            "/*%s*/" % "".join(random.choices(string.ascii_letters + string.digits, k=5)),
        ]
        comment = random.choice(comments)
        pos = random.randint(0, max(len(s) - 1, 0))
        return s[:pos] + comment + s[pos:]

    def _add_diverse_padding(self, s: str) -> str:
        """Add padding with high character diversity."""
        chars = random.choices(string.printable[:62], k=random.randint(2, 6))
        return s + "".join(chars)

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _byte_distribution(self, data: bytes) -> Dict[int, float]:
        """Compute probability distribution over byte values with smoothing."""
        n = len(data)
        counts = Counter(data)
        total = n + SMOOTHING_ALPHA * 256
        return {i: (counts.get(i, 0) + SMOOTHING_ALPHA) / total for i in range(256)}


# ════════════════════════════════════════════════════════════════════════════════
# ENGINE 2: MUTUAL INFORMATION SCANNER
# ════════════════════════════════════════════════════════════════════════════════


class MutualInformationScanner:
    """Detects injection vulnerabilities WITHOUT malicious payloads.

    Theory: If changing input X causes structured changes in output Y, there
    is high mutual information I(X;Y) = H(Y) - H(Y|X). This reveals injection
    points because the server incorporates user input into processing in a
    controllable way.

    All probes are BENIGN — random strings, numbers, slight variations.
    """

    def __init__(
        self,
        http_client: Optional[_HTTPClient] = None,
        entropy_analyzer: Optional[ShannonEntropyAnalyzer] = None,
    ) -> None:
        self._lock = threading.RLock()
        self._http = http_client or _HTTPClient()
        self._entropy = entropy_analyzer or ShannonEntropyAnalyzer()
        # Benign char sets that mimic injection syntax without being exploits
        self._benign_sqli_chars = ["'", '"', ";", "--", "()", "' '", "1 1", "a b"]
        self._benign_ssti_chars = ["{{", "}}", "<%", "%>", "${", "}", "#{"]
        self._benign_path_chars = ["/", "..", "./", "//", "\\", "..\\"]
        self._benign_rce_chars = ["|", ";", "&", "`", "$", "(", ")"]
        self._benign_xss_chars = ["<", ">", '"', "'", "&", "="]

    # ── Main MI measurement ───────────────────────────────────────────────────

    def measure_mutual_information(
        self,
        target_url: str,
        param: str,
        samples: int = 30,
    ) -> MutualInformationResult:
        """Measure mutual information I(X;Y) between input param and response.

        Sends benign inputs and statistically measures how much the response
        depends on the input.
        """
        logger.info("Measuring MI for param '%s' on %s with %d samples", param, target_url, samples)

        # Generate benign probe values
        x_samples = _generate_benign_strings(samples)
        y_samples: List[bytes] = []

        for val in x_samples:
            body, status, hdrs = self._http.get(target_url, params={param: val})
            # Combine status + body for richer signal
            combined = struct.pack(">H", status) + body
            y_samples.append(combined)

        if not y_samples or all(len(y) <= 2 for y in y_samples):
            return MutualInformationResult(param=param, n_samples=samples)

        mi = self._compute_mi(x_samples, y_samples)
        h_y = self._compute_response_entropy(y_samples)
        h_y_given_x = h_y - mi  # by definition: I(X;Y) = H(Y) - H(Y|X)

        confidence = self._mi_to_confidence(mi, samples)
        vuln_type = self._infer_vuln_type_from_mi(mi, x_samples, y_samples, param)
        evidence = self._collect_evidence(mi, h_y, h_y_given_x, samples)

        result = MutualInformationResult(
            param=param,
            mi_value=mi,
            confidence=confidence,
            likely_vuln_type=vuln_type,
            evidence=evidence,
            n_samples=samples,
            response_entropy=h_y,
            conditional_entropy=max(h_y_given_x, 0.0),
        )
        logger.info("MI result for '%s': %.4f bits, vuln_type=%s, confidence=%.2f",
                     param, mi, vuln_type.value, confidence)
        return result

    # ── Reflection detection ──────────────────────────────────────────────────

    def detect_reflection(self, target_url: str, param: str) -> ReflectionResult:
        """Detect if and how input is reflected in output, quantified by MI.

        Uses unique marker strings and checks for verbatim, encoded, or
        partial reflection.
        """
        markers: List[str] = []
        reflection_counts = {"direct": 0, "encoded": 0, "partial": 0}
        responses: List[bytes] = []

        for _ in range(10):
            marker = "srn" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
            markers.append(marker)
            body, status, hdrs = self._http.get(target_url, params={param: marker})
            responses.append(body)

            try:
                text = body.decode("utf-8", errors="replace")
            except Exception:
                text = ""

            if marker in text:
                reflection_counts["direct"] += 1
            elif html.escape(marker) in text:
                reflection_counts["encoded"] += 1
            elif urllib.parse.quote(marker) in text:
                reflection_counts["encoded"] += 1
            elif marker[:5] in text:
                reflection_counts["partial"] += 1

        total_reflections = sum(reflection_counts.values())
        y_samples = responses
        x_samples = markers
        mi = self._compute_mi(x_samples, y_samples) if len(y_samples) >= 2 else 0.0

        if reflection_counts["direct"] > 3:
            rtype = ReflectionType.DIRECT
        elif reflection_counts["encoded"] > 3:
            rtype = ReflectionType.ENCODED
        elif reflection_counts["partial"] > 3:
            rtype = ReflectionType.PARTIAL
        elif mi > MI_MEDIUM_THRESHOLD:
            rtype = ReflectionType.STRUCTURAL
        else:
            rtype = ReflectionType.NONE

        contexts: List[str] = []
        if reflection_counts["direct"] > 0:
            contexts.append("direct_echo")
        if reflection_counts["encoded"] > 0:
            contexts.append("html_or_url_encoded")
        if reflection_counts["partial"] > 0:
            contexts.append("partial_substring")

        confidence = min(total_reflections / 10.0, 1.0)
        if mi > MI_HIGH_THRESHOLD:
            confidence = max(confidence, 0.8)

        return ReflectionResult(
            param=param,
            reflected=rtype != ReflectionType.NONE,
            reflection_type=rtype,
            mi_value=mi,
            reflection_contexts=contexts,
            confidence=confidence,
        )

    # ── Data flow detection ───────────────────────────────────────────────────

    def detect_data_flow(self, target_url: str, param: str) -> DataFlowResult:
        """Detect if input flows through database, template, filesystem, or command.

        Sends BENIGN variations of syntax characters and measures MI patterns.
        Each data flow type has a distinct MI signature.
        """
        mi_pattern: Dict[str, float] = {}
        evidence: List[str] = []

        # Baseline: random alphanum strings
        baseline_mi = self._probe_char_class(target_url, param, _generate_benign_strings(10))
        mi_pattern["baseline"] = baseline_mi

        # SQLi signature: benign strings containing quote/semicolon chars
        sqli_probes = [
            "test" + c + "value" for c in self._benign_sqli_chars
        ] + _generate_benign_strings(4)
        mi_sqli = self._probe_char_class(target_url, param, sqli_probes)
        mi_pattern["sqli_chars"] = mi_sqli

        # SSTI signature: benign strings with template-like chars
        ssti_probes = [
            "test" + c + "value" for c in self._benign_ssti_chars
        ] + _generate_benign_strings(4)
        mi_ssti = self._probe_char_class(target_url, param, ssti_probes)
        mi_pattern["ssti_chars"] = mi_ssti

        # Path traversal signature
        path_probes = [
            "test" + c + "value" for c in self._benign_path_chars
        ] + _generate_benign_strings(4)
        mi_path = self._probe_char_class(target_url, param, path_probes)
        mi_pattern["path_chars"] = mi_path

        # RCE signature
        rce_probes = [
            "test" + c + "value" for c in self._benign_rce_chars
        ] + _generate_benign_strings(4)
        mi_rce = self._probe_char_class(target_url, param, rce_probes)
        mi_pattern["rce_chars"] = mi_rce

        # Determine flow type by which char class has highest MI spike above baseline
        spikes = {
            "sqli_chars": mi_sqli - baseline_mi,
            "ssti_chars": mi_ssti - baseline_mi,
            "path_chars": mi_path - baseline_mi,
            "rce_chars": mi_rce - baseline_mi,
        }
        max_spike_key = max(spikes, key=lambda k: spikes[k])
        max_spike = spikes[max_spike_key]

        flow_type = DataFlowType.NONE
        confidence = 0.0

        if max_spike > MI_MEDIUM_THRESHOLD:
            type_map = {
                "sqli_chars": DataFlowType.DATABASE,
                "ssti_chars": DataFlowType.TEMPLATE,
                "path_chars": DataFlowType.FILESYSTEM,
                "rce_chars": DataFlowType.COMMAND,
            }
            flow_type = type_map.get(max_spike_key, DataFlowType.NONE)
            confidence = min(max_spike / MI_HIGH_THRESHOLD, 1.0)
            evidence.append(
                f"MI spike of {max_spike:.4f} bits with {max_spike_key} "
                f"(baseline={baseline_mi:.4f})"
            )

            # Additional evidence: check if response structure changes
            for key, spike in spikes.items():
                if spike > MI_MEDIUM_THRESHOLD and key != max_spike_key:
                    evidence.append(f"Secondary MI spike: {key}={spike:.4f}")

        # Check for redirect-based flow
        redirect_probes = [
            "http://test" + str(i) + ".example.com" for i in range(8)
        ]
        mi_redirect = self._probe_char_class(target_url, param, redirect_probes)
        mi_pattern["redirect"] = mi_redirect
        if mi_redirect - baseline_mi > MI_MEDIUM_THRESHOLD and flow_type == DataFlowType.NONE:
            flow_type = DataFlowType.REDIRECT
            confidence = min((mi_redirect - baseline_mi) / MI_HIGH_THRESHOLD, 1.0)
            evidence.append(f"MI spike with URL-like inputs: {mi_redirect:.4f}")

        overall_mi = max(mi_pattern.values()) if mi_pattern else 0.0

        return DataFlowResult(
            param=param,
            flow_type=flow_type,
            mi_value=overall_mi,
            mi_pattern=mi_pattern,
            confidence=confidence,
            evidence=evidence,
        )

    # ── Endpoint scan ─────────────────────────────────────────────────────────

    def scan_endpoint(
        self, target_url: str, params: List[str], samples: int = 30
    ) -> List[MutualInformationResult]:
        """Full MI scan of all params on an endpoint."""
        results: List[MutualInformationResult] = []
        for param in params:
            try:
                result = self.measure_mutual_information(target_url, param, samples)
                results.append(result)
            except Exception as exc:
                logger.error("MI scan failed for param '%s': %s", param, exc)
                results.append(MutualInformationResult(param=param))
        # Sort by MI descending
        results.sort(key=lambda r: r.mi_value, reverse=True)
        return results

    # ── Core MI computation ───────────────────────────────────────────────────

    def _compute_mi(self, x_samples: List[str], y_samples: List[bytes]) -> float:
        """Compute mutual information I(X;Y) using histogram-based estimation.

        Discretizes Y into structural tokens, then computes:
          I(X;Y) = H(Y) - H(Y|X)
        where H(Y) is the entropy of the response token distribution and
        H(Y|X) is the conditional entropy given each unique input.
        """
        n = min(len(x_samples), len(y_samples))
        if n < 2:
            return 0.0

        # Discretize each response into a single hash bucket
        y_discrete = [self._discretize_response(y) for y in y_samples[:n]]

        # H(Y) — marginal entropy of response tokens
        all_tokens: List[int] = []
        for yd in y_discrete:
            all_tokens.extend(yd)
        h_y = self._token_entropy(all_tokens)

        # H(Y|X) — conditional entropy
        # Group by input
        groups: Dict[str, List[List[int]]] = defaultdict(list)
        for i in range(n):
            groups[x_samples[i]].append(y_discrete[i])

        h_y_given_x = 0.0
        for inp, token_lists in groups.items():
            p_x = len(token_lists) / n
            group_tokens: List[int] = []
            for tl in token_lists:
                group_tokens.extend(tl)
            h_y_x = self._token_entropy(group_tokens)
            h_y_given_x += p_x * h_y_x

        mi = h_y - h_y_given_x
        return max(mi, 0.0)

    def _discretize_response(self, response: bytes) -> List[int]:
        """Convert response to discrete tokens for MI calculation.

        Captures structural features rather than raw bytes:
        - Status code (first 2 bytes if packed)
        - Content length bucket
        - HTML tag structure hash
        - Byte distribution quintile
        - Compression ratio bucket
        """
        if not response:
            return [0]

        tokens: List[int] = []

        # Status (if packed at front)
        if len(response) >= 2:
            status = struct.unpack(">H", response[:2])[0]
            tokens.append(status % 256)
            body = response[2:]
        else:
            body = response
            tokens.append(0)

        # Length bucket (log scale, 0-15)
        blen = len(body)
        len_bucket = min(int(math.log2(blen + 1)), 15) if blen > 0 else 0
        tokens.append(len_bucket)

        # Structure hash — simplified HTML tag sequence
        structure = _extract_html_structure(body)
        struct_hash = int(hashlib.md5(structure.encode()).hexdigest()[:4], 16) % 256
        tokens.append(struct_hash)

        # Byte mean bucket
        if blen > 0:
            mean_byte = sum(body) / blen
            tokens.append(int(mean_byte) % 256)
        else:
            tokens.append(0)

        # Compression ratio bucket (0-15)
        if blen > 10:
            try:
                compressed = zlib.compress(body, 1)
                ratio = len(compressed) / blen
                tokens.append(min(int(ratio * 15), 15))
            except Exception:
                tokens.append(8)
        else:
            tokens.append(0)

        # First 32 bytes hash
        tokens.append(int(hashlib.md5(body[:32]).hexdigest()[:2], 16))

        # Last 32 bytes hash
        tokens.append(int(hashlib.md5(body[-32:]).hexdigest()[:2], 16))

        return tokens

    def _compute_response_entropy(self, y_samples: List[bytes]) -> float:
        """Compute H(Y) over discretized response set."""
        all_tokens: List[int] = []
        for y in y_samples:
            all_tokens.extend(self._discretize_response(y))
        return self._token_entropy(all_tokens)

    def _token_entropy(self, tokens: List[int]) -> float:
        """Shannon entropy of a list of integer tokens."""
        if not tokens:
            return 0.0
        n = len(tokens)
        counts = Counter(tokens)
        h = 0.0
        for count in counts.values():
            p = count / n
            if p > 0:
                h -= p * math.log2(p)
        return h

    def _probe_char_class(
        self, target_url: str, param: str, probes: List[str]
    ) -> float:
        """Send a list of probes and compute the resulting MI."""
        y_samples: List[bytes] = []
        for val in probes:
            body, status, hdrs = self._http.get(target_url, params={param: val})
            combined = struct.pack(">H", status) + body
            y_samples.append(combined)
        return self._compute_mi(probes, y_samples)

    def _mi_to_confidence(self, mi: float, n_samples: int) -> float:
        """Convert MI value to a confidence score [0, 1]."""
        if mi <= 0:
            return 0.0
        # Sample-size adjusted sigmoid
        sample_factor = min(n_samples / 20.0, 1.0)
        raw = 1.0 / (1.0 + math.exp(-5.0 * (mi - MI_MEDIUM_THRESHOLD)))
        return raw * sample_factor

    def _infer_vuln_type_from_mi(
        self,
        mi: float,
        x_samples: List[str],
        y_samples: List[bytes],
        param: str,
    ) -> VulnType:
        """Heuristic: infer likely vuln type from MI value and response patterns."""
        if mi < MI_MEDIUM_THRESHOLD:
            return VulnType.UNKNOWN

        # Check for direct reflection (XSS indicator)
        reflection_count = 0
        for x, y in zip(x_samples, y_samples):
            try:
                text = y.decode("utf-8", errors="replace")
                if x in text:
                    reflection_count += 1
            except Exception:
                pass

        if reflection_count > len(x_samples) * 0.5:
            return VulnType.XSS_REFLECTED

        # Check response variance pattern
        lengths = [len(y) for y in y_samples]
        if lengths:
            mean_len = sum(lengths) / len(lengths)
            variance = sum((l - mean_len) ** 2 for l in lengths) / len(lengths)
            cv = math.sqrt(variance) / (mean_len + EPSILON)

            # High CV with high MI = structured response variation = likely SQLi or SSTI
            if cv > 0.3 and mi > MI_HIGH_THRESHOLD:
                return VulnType.SQLI
            if cv > 0.1 and mi > MI_MEDIUM_THRESHOLD:
                return VulnType.SSTI

        # Check param name heuristics
        param_lower = param.lower()
        if any(kw in param_lower for kw in ("url", "redirect", "next", "return", "goto", "dest")):
            return VulnType.OPEN_REDIRECT
        if any(kw in param_lower for kw in ("file", "path", "dir", "doc", "page", "include")):
            return VulnType.PATH_TRAVERSAL
        if any(kw in param_lower for kw in ("cmd", "exec", "command", "run", "shell")):
            return VulnType.RCE
        if any(kw in param_lower for kw in ("query", "search", "q", "id", "user", "name", "select")):
            return VulnType.SQLI
        if any(kw in param_lower for kw in ("template", "tpl", "view", "render")):
            return VulnType.SSTI

        return VulnType.UNKNOWN

    def _collect_evidence(
        self, mi: float, h_y: float, h_y_given_x: float, n_samples: int
    ) -> List[str]:
        """Collect human-readable evidence strings."""
        evidence: List[str] = []
        evidence.append(f"I(X;Y) = {mi:.4f} bits ({n_samples} samples)")
        evidence.append(f"H(Y) = {h_y:.4f} bits")
        evidence.append(f"H(Y|X) = {h_y_given_x:.4f} bits")

        if mi > MI_HIGH_THRESHOLD:
            evidence.append("HIGH mutual information: strong input-output dependency")
        elif mi > MI_MEDIUM_THRESHOLD:
            evidence.append("MEDIUM mutual information: moderate input-output dependency")
        else:
            evidence.append("LOW mutual information: weak or no dependency")

        info_leakage_ratio = 1.0 - (h_y_given_x / (h_y + EPSILON))
        evidence.append(f"Information leakage ratio: {info_leakage_ratio:.2%}")

        return evidence

    # ── MI bias correction ────────────────────────────────────────────────────

    def _miller_madow_correction(self, mi_raw: float, n_samples: int, n_bins_x: int, n_bins_y: int) -> float:
        """Apply Miller-Madow bias correction to mutual information estimate.

        MI estimators are positively biased in finite samples. The correction:
          I_corrected = I_raw - (n_bins - 1) / (2 * N * ln(2))
        where n_bins is the number of non-empty bins in the joint distribution.
        """
        if n_samples <= 1:
            return mi_raw
        # Approximate number of non-empty joint bins
        n_joint_bins = min(n_bins_x * n_bins_y, n_samples)
        correction = (n_joint_bins - 1) / (2.0 * n_samples * math.log(2))
        corrected = mi_raw - correction
        return max(corrected, 0.0)

    def _compute_mi_ksg(self, x_features: List[List[float]], y_features: List[List[float]], k: int = 3) -> float:
        """KSG (Kraskov-Stogbauer-Grassberger) MI estimator for continuous variables.

        Uses k-nearest-neighbor distances in joint and marginal spaces.
        This avoids histogram binning artifacts for continuous-valued features.

        I(X;Y) ≈ psi(k) - <psi(n_x + 1) + psi(n_y + 1)> + psi(N)
        where psi is the digamma function.
        """
        n = min(len(x_features), len(y_features))
        if n < k + 1:
            return 0.0

        # Chebyshev (L-inf) distance
        def _chebyshev(a: List[float], b: List[float]) -> float:
            return max(abs(ai - bi) for ai, bi in zip(a, b))

        # Build joint space: concatenate x and y features
        joint = [x_features[i] + y_features[i] for i in range(n)]

        # For each point, find the k-th nearest neighbor distance in joint space
        psi_sum_nx = 0.0
        psi_sum_ny = 0.0

        for i in range(n):
            # Compute distances to all other points in joint space
            joint_dists = []
            for j in range(n):
                if i != j:
                    joint_dists.append((_chebyshev(joint[i], joint[j]), j))
            joint_dists.sort(key=lambda t: t[0])

            if len(joint_dists) < k:
                continue

            # k-th NN distance in joint space (Chebyshev)
            eps_i = joint_dists[k - 1][0]
            if eps_i <= 0:
                eps_i = EPSILON

            # Count points within eps_i in marginal X space
            n_x = 0
            for j in range(n):
                if i != j and _chebyshev(x_features[i], x_features[j]) < eps_i:
                    n_x += 1

            # Count points within eps_i in marginal Y space
            n_y = 0
            for j in range(n):
                if i != j and _chebyshev(y_features[i], y_features[j]) < eps_i:
                    n_y += 1

            psi_sum_nx += self._digamma(n_x + 1)
            psi_sum_ny += self._digamma(n_y + 1)

        avg_psi_nx = psi_sum_nx / n
        avg_psi_ny = psi_sum_ny / n

        mi = self._digamma(k) - avg_psi_nx - avg_psi_ny + self._digamma(n)
        return max(mi / math.log(2), 0.0)  # Convert nats to bits

    @staticmethod
    def _digamma(x: float) -> float:
        """Digamma function psi(x) = d/dx ln(Gamma(x)).

        Uses the asymptotic expansion for large x, and the recurrence
        psi(x+1) = psi(x) + 1/x for small x.
        """
        if x <= 0:
            return -1e10
        result = 0.0
        # Use recurrence to shift x to a large value
        while x < 6.0:
            result -= 1.0 / x
            x += 1.0
        # Asymptotic expansion
        x_inv = 1.0 / x
        x_inv2 = x_inv * x_inv
        result += (
            math.log(x)
            - 0.5 * x_inv
            - x_inv2 * (1.0 / 12.0 - x_inv2 * (1.0 / 120.0 - x_inv2 / 252.0))
        )
        return result

    # ── Timing-based MI ───────────────────────────────────────────────────────

    def measure_timing_mi(
        self, target_url: str, param: str, samples: int = 20
    ) -> float:
        """Measure mutual information between input and response TIMING.

        Timing side-channels can reveal injection points even when the response
        body is identical. If I(X; T) is high (where T is response time), the
        server processing time depends on input — a classic blind injection signal.
        """
        x_samples = _generate_benign_strings(samples)
        timings: List[float] = []

        for val in x_samples:
            t0 = time.monotonic()
            self._http.get(target_url, params={param: val})
            elapsed = time.monotonic() - t0
            timings.append(elapsed)

        if len(timings) < 2:
            return 0.0

        # Discretize timings into bins (10 bins over the range)
        t_min = min(timings)
        t_max = max(timings)
        t_range = t_max - t_min
        if t_range < 1e-6:
            return 0.0  # All timings identical — no MI

        n_bins = min(10, len(timings) // 2)
        bin_width = t_range / n_bins + EPSILON

        # Convert timings to bin indices
        timing_bins = [min(int((t - t_min) / bin_width), n_bins - 1) for t in timings]

        # Convert inputs to hash bins
        input_bins = [hash(x) % n_bins for x in x_samples]

        # Compute MI between input bins and timing bins
        n = len(timing_bins)
        joint_counts: Dict[Tuple[int, int], int] = Counter()
        x_counts: Dict[int, int] = Counter()
        y_counts: Dict[int, int] = Counter()

        for i in range(n):
            joint_counts[(input_bins[i], timing_bins[i])] += 1
            x_counts[input_bins[i]] += 1
            y_counts[timing_bins[i]] += 1

        mi = 0.0
        for (xb, yb), count in joint_counts.items():
            p_xy = count / n
            p_x = x_counts[xb] / n
            p_y = y_counts[yb] / n
            if p_xy > 0 and p_x > 0 and p_y > 0:
                mi += p_xy * math.log2(p_xy / (p_x * p_y))

        return max(mi, 0.0)

    # ── Response structure analysis ───────────────────────────────────────────

    def _analyze_response_structure(self, responses: List[bytes]) -> Dict[str, Any]:
        """Analyze structural properties across a set of responses.

        Returns statistics useful for vulnerability classification:
        - length variance
        - structural similarity (via NCD)
        - DOM depth variation (for HTML)
        - unique status codes
        - content-type consistency
        """
        if not responses:
            return {"empty": True}

        lengths = [len(r) for r in responses]
        mean_len = sum(lengths) / len(lengths)
        var_len = sum((l - mean_len) ** 2 for l in lengths) / len(lengths)

        # Pairwise NCD for structural similarity
        ncds: List[float] = []
        sample_size = min(len(responses), 10)
        sampled = random.sample(responses, sample_size) if len(responses) > sample_size else responses
        for i in range(len(sampled)):
            for j in range(i + 1, len(sampled)):
                if sampled[i] and sampled[j]:
                    try:
                        cx = len(zlib.compress(sampled[i], 1))
                        cy = len(zlib.compress(sampled[j], 1))
                        cxy = len(zlib.compress(sampled[i] + sampled[j], 1))
                        min_c = min(cx, cy)
                        max_c = max(cx, cy)
                        if max_c > 0:
                            ncds.append((cxy - min_c) / max_c)
                    except Exception:
                        pass

        mean_ncd = sum(ncds) / len(ncds) if ncds else 0.0

        # Count unique HTML structures
        structures = set()
        for r in responses:
            s = _extract_html_structure(r)
            structures.add(s)

        return {
            "mean_length": mean_len,
            "length_variance": var_len,
            "length_cv": math.sqrt(var_len) / (mean_len + EPSILON),
            "mean_ncd": mean_ncd,
            "unique_structures": len(structures),
            "n_responses": len(responses),
        }

    # ── Information gain per probe ────────────────────────────────────────────

    def _incremental_mi(
        self,
        previous_y: List[bytes],
        previous_x: List[str],
        new_y: bytes,
        new_x: str,
    ) -> float:
        """Compute the incremental MI gain from adding one new observation.

        This is used for sequential probe optimization: after N probes,
        how much information does the (N+1)-th probe add?

        Uses: I_new = I(X_{1:n+1}; Y_{1:n+1}) - I(X_{1:n}; Y_{1:n})
        """
        if not previous_y:
            return 0.0

        mi_before = self._compute_mi(previous_x, previous_y)
        mi_after = self._compute_mi(
            previous_x + [new_x],
            previous_y + [new_y],
        )
        return max(mi_after - mi_before, 0.0)

    # ── Conditional MI for multi-param analysis ───────────────────────────────

    def measure_conditional_mi(
        self,
        target_url: str,
        param_a: str,
        param_b: str,
        samples: int = 20,
    ) -> float:
        """Measure I(Y; X_a | X_b) — MI between response and param_a GIVEN param_b.

        This reveals if param_a provides ADDITIONAL information about the response
        beyond what param_b already tells us. Useful for finding the most
        informative parameter when multiple params exist.

        I(Y; X_a | X_b) = H(Y | X_b) - H(Y | X_a, X_b)
        """
        # Fix param_b to a constant, vary param_a
        fixed_b = "constant_value"
        x_a_samples = _generate_benign_strings(samples)
        y_given_b: List[bytes] = []

        for val_a in x_a_samples:
            body, status, _ = self._http.get(target_url, params={param_a: val_a, param_b: fixed_b})
            y_given_b.append(struct.pack(">H", status) + body)

        # I(Y; X_a | X_b=fixed) = I(Y; X_a) when X_b is held constant
        mi_a_given_b = self._compute_mi(x_a_samples, y_given_b)

        # Compare with unconditional MI(Y; X_a)
        y_unconditional: List[bytes] = []
        for val_a in x_a_samples:
            body, status, _ = self._http.get(target_url, params={param_a: val_a})
            y_unconditional.append(struct.pack(">H", status) + body)
        mi_a = self._compute_mi(x_a_samples, y_unconditional)

        # The conditional MI is approximated by how much MI changes when B is fixed
        # If I(Y;A|B) ≈ I(Y;A), then B doesn't mediate A's effect on Y
        return mi_a_given_b


# ════════════════════════════════════════════════════════════════════════════════
# ENGINE 3: KL DIVERGENCE DETECTOR
# ════════════════════════════════════════════════════════════════════════════════


class KLDivergenceDetector:
    """Uses Kullback-Leibler divergence to detect if a payload changed server behavior.

    Collects a baseline response distribution P, sends a probe, measures
    response distribution Q, and computes D_KL(P||Q). High divergence
    indicates the payload triggered anomalous server behavior.
    """

    def __init__(
        self,
        http_client: Optional[_HTTPClient] = None,
    ) -> None:
        self._lock = threading.RLock()
        self._http = http_client or _HTTPClient()
        self._baseline_cache: Dict[str, ResponseDistribution] = {}

    # ── Baseline construction ─────────────────────────────────────────────────

    def build_baseline(
        self, target_url: str, n_samples: int = 20
    ) -> ResponseDistribution:
        """Collect N normal responses and build a probability distribution.

        Extracts: status codes, response lengths, header patterns, content
        structure tokens, and a 16-D feature vector.
        """
        with self._lock:
            cache_key = f"{target_url}:{n_samples}"
            if cache_key in self._baseline_cache:
                return self._baseline_cache[cache_key]

        logger.info("Building baseline for %s with %d samples", target_url, n_samples)

        status_counts: Dict[int, int] = defaultdict(int)
        lengths: List[int] = []
        header_counts: Dict[str, int] = defaultdict(int)
        feature_vectors: List[List[float]] = []

        for _ in range(n_samples):
            body, status, hdrs = self._http.get(target_url)
            status_counts[status] += 1
            lengths.append(len(body))
            for hk in hdrs:
                header_counts[hk] += 1
            fv = _response_feature_vector(body, status, hdrs)
            feature_vectors.append(fv)

        # Aggregate status distribution
        status_dist = {k: v / n_samples for k, v in status_counts.items()}

        # Length statistics
        mean_len = sum(lengths) / n_samples if n_samples > 0 else 0.0
        var_len = sum((l - mean_len) ** 2 for l in lengths) / max(n_samples, 1)
        std_len = math.sqrt(var_len)

        # Mean feature vector (centroid)
        dim = len(feature_vectors[0]) if feature_vectors else 16
        mean_fv = [0.0] * dim
        for fv in feature_vectors:
            for i in range(dim):
                mean_fv[i] += fv[i]
        if feature_vectors:
            mean_fv = [x / len(feature_vectors) for x in mean_fv]

        dist = ResponseDistribution(
            url=target_url,
            n_samples=n_samples,
            status_distribution=status_dist,
            length_mean=mean_len,
            length_std=std_len,
            header_signature=dict(header_counts),
            feature_vector=mean_fv,
        )

        with self._lock:
            self._baseline_cache[cache_key] = dist

        return dist

    # ── Divergence measurement ────────────────────────────────────────────────

    def measure_divergence(
        self,
        baseline: ResponseDistribution,
        probe_response: bytes,
        probe_status: int,
        probe_headers: Dict[str, str],
    ) -> DivergenceResult:
        """Compute KL and JS divergence between baseline and probe response."""
        probe_fv = _response_feature_vector(probe_response, probe_status, probe_headers)
        baseline_fv = baseline.feature_vector

        if not baseline_fv or not probe_fv:
            return DivergenceResult()

        # Convert feature vectors to distributions for KL
        p = _make_probability_vector(baseline_fv)
        q = _make_probability_vector(probe_fv)

        kl = self._kl_divergence(p, q)
        js = self._js_divergence(p, q)

        # Identify which features changed most
        features_changed: List[str] = []
        feature_names = [
            "status", "body_length", "body_entropy", "compression_ratio",
            "quartile_0", "quartile_1", "quartile_2", "quartile_3",
            "html_tags", "content_type", "header_count", "has_cookie",
            "has_redirect", "printable_ratio", "unique_bigrams", "structural_variance",
        ]
        for i in range(min(len(baseline_fv), len(probe_fv))):
            delta = abs(baseline_fv[i] - probe_fv[i])
            if delta > 0.1 and i < len(feature_names):
                features_changed.append(f"{feature_names[i]} (delta={delta:.3f})")

        # Status code change is always significant
        if probe_status not in baseline.status_distribution:
            features_changed.append(f"new_status_code={probe_status}")

        # Length anomaly
        if baseline.length_std > 0:
            z_score = abs(len(probe_response) - baseline.length_mean) / (baseline.length_std + EPSILON)
            if z_score > 3.0:
                features_changed.append(f"length_z_score={z_score:.1f}")

        is_anomalous = js > JS_ANOMALY_THRESHOLD or kl > KL_ANOMALY_THRESHOLD
        anomaly_score = min((js / JS_ANOMALY_THRESHOLD + kl / KL_ANOMALY_THRESHOLD) / 2.0, 1.0)

        return DivergenceResult(
            kl_divergence=kl,
            js_divergence=js,
            is_anomalous=is_anomalous,
            anomaly_score=anomaly_score,
            features_changed=features_changed,
        )

    # ── Full anomaly detection pipeline ───────────────────────────────────────

    def detect_anomaly(
        self, target_url: str, payload: str, param: str
    ) -> AnomalyResult:
        """Build baseline -> send payload -> measure divergence -> classify."""
        baseline = self.build_baseline(target_url)
        body, status, hdrs = self._http.get(target_url, params={param: payload})
        divergence = self.measure_divergence(baseline, body, status, hdrs)

        if divergence.anomaly_score > 0.8:
            classification = "high_anomaly"
        elif divergence.anomaly_score > 0.4:
            classification = "moderate_anomaly"
        elif divergence.anomaly_score > 0.1:
            classification = "low_anomaly"
        else:
            classification = "normal"

        return AnomalyResult(
            param=param,
            payload=payload,
            divergence=divergence,
            baseline_samples=baseline.n_samples,
            probe_status=status,
            classification=classification,
        )

    # ── KL divergence ─────────────────────────────────────────────────────────

    def _kl_divergence(self, p: List[float], q: List[float]) -> float:
        """D_KL(P||Q) = SUM p(x) * log2(p(x) / q(x)) with Laplace smoothing."""
        if len(p) != len(q):
            n = max(len(p), len(q))
            p = p + [SMOOTHING_ALPHA] * (n - len(p))
            q = q + [SMOOTHING_ALPHA] * (n - len(q))

        kl = 0.0
        for pi, qi in zip(p, q):
            pi = max(pi, SMOOTHING_ALPHA)
            qi = max(qi, SMOOTHING_ALPHA)
            if pi > EPSILON:
                kl += pi * math.log2(pi / qi)
        return max(kl, 0.0)

    # ── Jensen-Shannon divergence ─────────────────────────────────────────────

    def _js_divergence(self, p: List[float], q: List[float]) -> float:
        """Jensen-Shannon divergence: JSD(P||Q) = 0.5*D_KL(P||M) + 0.5*D_KL(Q||M)
        where M = 0.5*(P+Q). Symmetric, bounded in [0, 1] for log2.
        """
        if len(p) != len(q):
            n = max(len(p), len(q))
            p = p + [SMOOTHING_ALPHA] * (n - len(p))
            q = q + [SMOOTHING_ALPHA] * (n - len(q))

        m = [(pi + qi) / 2.0 for pi, qi in zip(p, q)]
        return 0.5 * self._kl_divergence(p, m) + 0.5 * self._kl_divergence(q, m)

    # ── Hellinger distance ────────────────────────────────────────────────────

    def _hellinger_distance(self, p: List[float], q: List[float]) -> float:
        """Hellinger distance: H(P,Q) = (1/sqrt(2)) * sqrt(SUM (sqrt(p_i) - sqrt(q_i))^2).

        Bounded in [0, 1], related to but different from JS divergence.
        More robust to tail distribution differences.
        """
        if len(p) != len(q):
            n = max(len(p), len(q))
            p = p + [SMOOTHING_ALPHA] * (n - len(p))
            q = q + [SMOOTHING_ALPHA] * (n - len(q))

        s = sum((math.sqrt(max(pi, 0)) - math.sqrt(max(qi, 0))) ** 2 for pi, qi in zip(p, q))
        return math.sqrt(s / 2.0)

    # ── Batch anomaly detection ───────────────────────────────────────────────

    def batch_detect_anomaly(
        self,
        target_url: str,
        payloads: List[str],
        param: str,
    ) -> List[AnomalyResult]:
        """Run anomaly detection for multiple payloads against a single baseline.

        More efficient than calling detect_anomaly repeatedly since the
        baseline is built once.
        """
        baseline = self.build_baseline(target_url)
        results: List[AnomalyResult] = []

        for payload in payloads:
            try:
                body, status, hdrs = self._http.get(target_url, params={param: payload})
                divergence = self.measure_divergence(baseline, body, status, hdrs)

                if divergence.anomaly_score > 0.8:
                    classification = "high_anomaly"
                elif divergence.anomaly_score > 0.4:
                    classification = "moderate_anomaly"
                elif divergence.anomaly_score > 0.1:
                    classification = "low_anomaly"
                else:
                    classification = "normal"

                results.append(AnomalyResult(
                    param=param,
                    payload=payload,
                    divergence=divergence,
                    baseline_samples=baseline.n_samples,
                    probe_status=status,
                    classification=classification,
                ))
            except Exception as exc:
                logger.error("Batch anomaly detection error for payload '%s': %s", payload[:50], exc)
                results.append(AnomalyResult(param=param, payload=payload))

        return results

    # ── Temporal divergence tracking ──────────────────────────────────────────

    def track_temporal_divergence(
        self,
        target_url: str,
        n_intervals: int = 10,
        interval_sec: float = 1.0,
    ) -> List[DivergenceResult]:
        """Track how server responses diverge over time.

        Useful for detecting state-dependent behavior: if the server's response
        distribution drifts over time, it may indicate session-dependent
        processing, caching effects, or rate limiting.
        """
        logger.info("Tracking temporal divergence for %s over %d intervals", target_url, n_intervals)

        # First interval becomes the baseline
        body0, status0, hdrs0 = self._http.get(target_url)
        baseline_fv = _response_feature_vector(body0, status0, hdrs0)
        baseline_dist = _make_probability_vector(baseline_fv)

        divergences: List[DivergenceResult] = []

        for i in range(n_intervals):
            if interval_sec > 0 and i > 0:
                time.sleep(interval_sec)

            body, status, hdrs = self._http.get(target_url)
            probe_fv = _response_feature_vector(body, status, hdrs)
            probe_dist = _make_probability_vector(probe_fv)

            kl = self._kl_divergence(baseline_dist, probe_dist)
            js = self._js_divergence(baseline_dist, probe_dist)

            features_changed: List[str] = []
            for j in range(min(len(baseline_fv), len(probe_fv))):
                if abs(baseline_fv[j] - probe_fv[j]) > 0.05:
                    features_changed.append(f"feature_{j}")

            is_anomalous = js > JS_ANOMALY_THRESHOLD
            anomaly_score = min(js / JS_ANOMALY_THRESHOLD, 1.0)

            divergences.append(DivergenceResult(
                kl_divergence=kl,
                js_divergence=js,
                is_anomalous=is_anomalous,
                anomaly_score=anomaly_score,
                features_changed=features_changed,
            ))

        return divergences

    # ── Renyi divergence ──────────────────────────────────────────────────────

    def _renyi_divergence(self, p: List[float], q: List[float], alpha: float = 2.0) -> float:
        """Renyi divergence of order alpha.

        D_alpha(P||Q) = (1/(alpha-1)) * log2(SUM p_i^alpha / q_i^(alpha-1))

        Alpha=1 recovers KL divergence (in the limit).
        Alpha=2 gives chi-squared divergence connection.
        Alpha=0.5 gives Hellinger affinity connection.
        """
        if abs(alpha - 1.0) < EPSILON:
            return self._kl_divergence(p, q)

        if len(p) != len(q):
            n = max(len(p), len(q))
            p = p + [SMOOTHING_ALPHA] * (n - len(p))
            q = q + [SMOOTHING_ALPHA] * (n - len(q))

        s = 0.0
        for pi, qi in zip(p, q):
            pi = max(pi, SMOOTHING_ALPHA)
            qi = max(qi, SMOOTHING_ALPHA)
            s += (pi ** alpha) / (qi ** (alpha - 1.0))

        if s <= 0:
            return 0.0
        return math.log2(s) / (alpha - 1.0)

    def _response_to_distribution(
        self, response: bytes, status: int, headers: Dict[str, str]
    ) -> List[float]:
        """Extract feature vector from response (delegates to shared utility)."""
        return _response_feature_vector(response, status, headers)


# ════════════════════════════════════════════════════════════════════════════════
# ENGINE 4: FISHER INFORMATION PROBER
# ════════════════════════════════════════════════════════════════════════════════


class FisherInformationProber:
    """Optimal experimental design for vulnerability scanning.

    Fisher Information I(theta) measures how much information a single
    measurement gives about an unknown server parameter. The Cramer-Rao
    bound gives the minimum variance of any estimator, allowing us to
    determine the MINIMUM number of requests needed.
    """

    def __init__(
        self,
        http_client: Optional[_HTTPClient] = None,
        entropy_analyzer: Optional[ShannonEntropyAnalyzer] = None,
    ) -> None:
        self._lock = threading.RLock()
        self._http = http_client or _HTTPClient()
        self._entropy = entropy_analyzer or ShannonEntropyAnalyzer()

    # ── Fisher information estimation ─────────────────────────────────────────

    def estimate_fisher_information(
        self, target_url: str, param: str, probes: List[str]
    ) -> FisherResult:
        """Estimate Fisher information by measuring response sensitivity to input changes.

        Uses numerical differentiation: send probe x, then x+delta, measure
        how much the response log-likelihood changes. Average over all probes.

        I(theta) ≈ E[ (d/dtheta log f(Y|theta))^2 ]
        Approximated by: Var of response feature changes per unit input change.
        """
        if not probes:
            return FisherResult(param=param)

        logger.info("Estimating Fisher information for '%s' with %d probes", param, len(probes))

        # Collect response features for each probe
        features: List[List[float]] = []
        for probe in probes:
            body, status, hdrs = self._http.get(target_url, params={param: probe})
            fv = _response_feature_vector(body, status, hdrs)
            features.append(fv)

        if len(features) < 2:
            return FisherResult(param=param, n_probes_used=len(probes))

        # Compute score function approximation
        # For adjacent probes, compute derivative of log-likelihood approximation
        dim = len(features[0])
        score_sq_sum = [0.0] * dim
        n_diffs = 0

        for i in range(len(features) - 1):
            f_curr = features[i]
            f_next = features[i + 1]
            for d in range(dim):
                diff = f_next[d] - f_curr[d]
                # Score ≈ d/dtheta log f = (change in feature) / (feature + epsilon)
                base = (f_curr[d] + f_next[d]) / 2.0 + EPSILON
                score = diff / base
                score_sq_sum[d] += score * score
            n_diffs += 1

        if n_diffs == 0:
            return FisherResult(param=param, n_probes_used=len(probes))

        # Fisher information = mean of squared score across dimensions and probes
        fisher_per_dim = [ssq / n_diffs for ssq in score_sq_sum]
        fisher_total = sum(fisher_per_dim) / dim  # Average across dimensions

        # Find the probe that produced the largest score (most informative)
        max_sensitivity = 0.0
        optimal_probe = probes[0]
        for i in range(len(features) - 1):
            sensitivity = sum(
                abs(features[i + 1][d] - features[i][d]) for d in range(dim)
            ) / dim
            if sensitivity > max_sensitivity:
                max_sensitivity = sensitivity
                optimal_probe = probes[i]

        crb = 1.0 / (fisher_total + EPSILON) if fisher_total > 0 else float("inf")

        return FisherResult(
            param=param,
            fisher_information=fisher_total,
            cramer_rao_bound=crb,
            sensitivity=max_sensitivity,
            n_probes_used=len(probes),
            optimal_probe=optimal_probe,
        )

    # ── Optimal probe sequence ────────────────────────────────────────────────

    def optimal_probe_sequence(
        self, target_url: str, param: str, budget: int
    ) -> List[str]:
        """Design the N probes that maximize total Fisher information.

        Uses sequential optimal design:
        1. Start with a diverse initial set
        2. For each slot, pick the probe that maximizes expected info gain
           based on how different the response is from previous responses.
        """
        if budget <= 0:
            return []

        logger.info("Designing optimal probe sequence: budget=%d, param='%s'", budget, param)

        # Start with diverse probe categories
        candidates = self._generate_probe_candidates()
        selected: List[str] = []
        seen_features: List[List[float]] = []

        for step in range(budget):
            best_probe = ""
            best_gain = -1.0

            # Evaluate each candidate
            sample_candidates = candidates
            if len(candidates) > 50:
                sample_candidates = random.sample(candidates, 50)

            for candidate in sample_candidates:
                body, status, hdrs = self._http.get(target_url, params={param: candidate})
                fv = _response_feature_vector(body, status, hdrs)

                # Expected information gain: distance from centroid of seen features
                if not seen_features:
                    gain = sum(abs(x) for x in fv)
                else:
                    centroid = [
                        sum(sf[d] for sf in seen_features) / len(seen_features)
                        for d in range(len(fv))
                    ]
                    gain = sum(abs(fv[d] - centroid[d]) for d in range(len(fv)))

                if gain > best_gain:
                    best_gain = gain
                    best_probe = candidate
                    best_fv = fv

            selected.append(best_probe)
            seen_features.append(best_fv)

            # Remove selected from candidates to avoid repetition
            if best_probe in candidates:
                candidates.remove(best_probe)

            # Early stop if no information gain
            if best_gain < EPSILON:
                logger.debug("Stopping early at step %d: no information gain", step)
                break

        return selected

    # ── Cramer-Rao bound ──────────────────────────────────────────────────────

    def cramer_rao_bound(self, fisher_info: float) -> float:
        """Minimum variance achievable = 1 / I(theta).

        Tells you the theoretical limit on parameter estimation precision.
        """
        if fisher_info <= 0:
            return float("inf")
        return 1.0 / fisher_info

    # ── Adaptive scan ─────────────────────────────────────────────────────────

    def adaptive_scan(
        self,
        target_url: str,
        param: str,
        confidence_target: float = 0.95,
        max_requests: int = 50,
    ) -> AdaptiveScanResult:
        """Adaptively probe until confidence target is reached.

        Uses Fisher information to choose each probe optimally. After each
        probe, updates the cumulative information and checks if the
        Cramer-Rao bound is below the confidence threshold.
        """
        logger.info(
            "Starting adaptive scan for '%s', confidence_target=%.2f",
            param, confidence_target,
        )

        probes: List[ProbeDesign] = []
        cumulative_info = 0.0
        candidates = self._generate_probe_candidates()
        seen_features: List[List[float]] = []
        converged = False
        vuln_type = VulnType.UNKNOWN

        # Collect a single baseline response
        baseline_body, baseline_status, baseline_hdrs = self._http.get(target_url)
        baseline_fv = _response_feature_vector(baseline_body, baseline_status, baseline_hdrs)

        for step in range(max_requests):
            # Choose the probe expected to give the most information
            if not candidates:
                break

            best_probe = candidates[0]
            best_expected_gain = 0.0

            for candidate in candidates[:30]:  # Limit evaluation
                # Expected gain based on diversity from baseline
                expected_fv = baseline_fv  # crude prior: expect baseline-like response
                if seen_features:
                    centroid = [
                        sum(sf[d] for sf in seen_features) / len(seen_features)
                        for d in range(len(baseline_fv))
                    ]
                    # Probes that differ from centroid are more informative
                    diversity = sum(abs(baseline_fv[d] - centroid[d]) for d in range(len(baseline_fv)))
                else:
                    diversity = 1.0

                # Weight candidate by how different it is from already-tried probes
                candidate_novelty = 1.0
                for prev in probes:
                    if candidate == prev.probe_value:
                        candidate_novelty = 0.0
                        break
                expected = diversity * candidate_novelty
                if expected > best_expected_gain:
                    best_expected_gain = expected
                    best_probe = candidate

            # Send the probe
            body, status, hdrs = self._http.get(target_url, params={param: best_probe})
            probe_fv = _response_feature_vector(body, status, hdrs)
            seen_features.append(probe_fv)

            # Compute actual information gain
            if seen_features and len(seen_features) > 1:
                prev_fv = seen_features[-2]
                actual_gain = sum(
                    abs(probe_fv[d] - prev_fv[d]) for d in range(len(probe_fv))
                ) / len(probe_fv)
            else:
                actual_gain = sum(
                    abs(probe_fv[d] - baseline_fv[d]) for d in range(len(probe_fv))
                ) / len(probe_fv)

            cumulative_info += actual_gain

            pd = ProbeDesign(
                probe_value=best_probe,
                expected_information_gain=best_expected_gain,
                actual_information_gain=actual_gain,
                cumulative_information=cumulative_info,
            )
            probes.append(pd)

            # Remove used candidate
            if best_probe in candidates:
                candidates.remove(best_probe)

            # Check convergence: confidence = 1 - CRB/cum_info
            if cumulative_info > 0:
                crb = 1.0 / cumulative_info
                confidence = 1.0 / (1.0 + crb)
                if confidence >= confidence_target:
                    converged = True
                    logger.info(
                        "Adaptive scan converged at step %d with confidence %.3f",
                        step + 1, confidence,
                    )
                    break
            else:
                confidence = 0.0

        # Determine vuln type from response patterns
        if cumulative_info > MI_HIGH_THRESHOLD:
            # Check for reflection
            for pd in probes:
                body, status, hdrs = self._http.get(target_url, params={param: pd.probe_value})
                try:
                    text = body.decode("utf-8", errors="replace")
                    if pd.probe_value in text:
                        vuln_type = VulnType.XSS_REFLECTED
                        break
                except Exception:
                    pass
            if vuln_type == VulnType.UNKNOWN and cumulative_info > MI_HIGH_THRESHOLD * 2:
                vuln_type = VulnType.SQLI

        final_confidence = 0.0
        if cumulative_info > 0:
            crb = 1.0 / cumulative_info
            final_confidence = 1.0 / (1.0 + crb)

        return AdaptiveScanResult(
            param=param,
            probes=probes,
            total_information=cumulative_info,
            confidence_reached=final_confidence,
            n_requests=len(probes),
            converged=converged,
            estimated_vuln_type=vuln_type,
        )

    # ── Probe candidate generation ────────────────────────────────────────────

    def _generate_probe_candidates(self) -> List[str]:
        """Generate a diverse set of probe candidates.

        Includes: random strings, numbers, special chars (benign usage),
        varying lengths, common param values.
        """
        candidates: List[str] = []

        # Random alpha strings of varying lengths
        for ln in [1, 3, 5, 8, 12, 20, 50]:
            for _ in range(3):
                candidates.append("".join(random.choices(string.ascii_lowercase, k=ln)))

        # Numeric values
        for val in [0, 1, -1, 100, 999, 1000000, 2147483647]:
            candidates.append(str(val))

        # Common test values
        candidates.extend([
            "", " ", "null", "undefined", "true", "false", "None",
            "test", "admin", "user", "1", "0", "-1",
            "a" * 100, "a" * 500,
        ])

        # Benign special char strings
        for ch in ["'", '"', "<", ">", "&", ";", "|", "/", "\\", "..", "${", "{{", "(", ")"]:
            candidates.append("test" + ch + "value")

        # Mixed content
        candidates.extend([
            "Hello World", "foo bar baz", "test@example.com",
            "http://example.com", "C:\\Windows\\System32",
            "SELECT name", "{{7*7}}", "<b>test</b>",
        ])

        random.shuffle(candidates)
        return candidates


# ════════════════════════════════════════════════════════════════════════════════
# ENGINE 5: CHANNEL CAPACITY ESTIMATOR
# ════════════════════════════════════════════════════════════════════════════════


class ChannelCapacityEstimator:
    """Estimates data exfiltration capacity of each endpoint.

    Shannon's channel capacity theorem: C = max I(X;Y) gives the maximum
    rate at which information can be reliably transmitted through a noisy
    channel. An endpoint that reflects/processes user input IS a channel.
    """

    def __init__(
        self,
        http_client: Optional[_HTTPClient] = None,
        mi_scanner: Optional[MutualInformationScanner] = None,
    ) -> None:
        self._lock = threading.RLock()
        self._http = http_client or _HTTPClient()
        self._mi = mi_scanner or MutualInformationScanner(http_client=self._http)

    # ── Capacity estimation ───────────────────────────────────────────────────

    def estimate_capacity(self, target_url: str, param: str) -> ChannelCapacity:
        """Estimate bits per request of exfiltration capacity.

        Method:
        1. Measure noise by sending identical inputs and measuring variance
        2. Measure signal by sending diverse inputs and measuring MI
        3. Compute binary symmetric channel capacity
        4. Estimate bits/request as min(MI, channel_capacity)
        """
        logger.info("Estimating channel capacity for '%s' on %s", param, target_url)

        # Step 1: Measure noise
        error_rate = self._estimate_noise(target_url, param, n_trials=CHANNEL_TRIAL_COUNT)

        # Step 2: Measure MI (signal)
        mi_result = self._mi.measure_mutual_information(target_url, param, samples=20)
        mi_value = mi_result.mi_value

        # Step 3: Binary symmetric channel capacity
        bsc_capacity = self._binary_channel_capacity(error_rate)

        # Step 4: Effective capacity = min of MI and BSC capacity
        # The MI gives the actual measured information transfer; BSC gives theoretical max
        bits_per_request = min(mi_value, bsc_capacity) if mi_value > 0 else 0.0

        # Determine risk level
        if bits_per_request > 3.0:
            exfil_risk = "critical"
        elif bits_per_request > 1.0:
            exfil_risk = "high"
        elif bits_per_request > 0.3:
            exfil_risk = "medium"
        elif bits_per_request > 0.05:
            exfil_risk = "low"
        else:
            exfil_risk = "negligible"

        return ChannelCapacity(
            param=param,
            bits_per_request=bits_per_request,
            bits_per_second=0.0,  # Requires bandwidth estimation
            noise_level=error_rate,
            exfil_risk=exfil_risk,
            error_rate=error_rate,
            capacity_binary=bsc_capacity,
        )

    # ── Bandwidth estimation ──────────────────────────────────────────────────

    def estimate_bandwidth(
        self, target_url: str, param: str, request_rate: float
    ) -> float:
        """Bits per second = bits_per_request * requests_per_second.

        Also factors in request timing to estimate achievable request rate
        if not provided.
        """
        cap = self.estimate_capacity(target_url, param)

        if request_rate <= 0:
            # Estimate by timing a few requests
            times: List[float] = []
            for _ in range(5):
                t0 = time.monotonic()
                self._http.get(target_url, params={param: "timing_probe"})
                times.append(time.monotonic() - t0)
            avg_time = sum(times) / len(times) if times else 1.0
            request_rate = 1.0 / max(avg_time, 0.01)

        bps = cap.bits_per_request * request_rate
        return bps

    # ── Rank channels ─────────────────────────────────────────────────────────

    def rank_exfil_channels(
        self, target_url: str, params: List[str]
    ) -> List[ChannelCapacity]:
        """Rank all params by exfiltration capacity, highest first."""
        results: List[ChannelCapacity] = []
        for param in params:
            try:
                cap = self.estimate_capacity(target_url, param)
                results.append(cap)
            except Exception as exc:
                logger.error("Channel capacity estimation failed for '%s': %s", param, exc)
                results.append(ChannelCapacity(param=param))
        results.sort(key=lambda c: c.bits_per_request, reverse=True)
        return results

    # ── Binary symmetric channel capacity ─────────────────────────────────────

    def _binary_channel_capacity(self, error_rate: float) -> float:
        """C = 1 - H(p) for binary symmetric channel.

        Where H(p) = -p*log2(p) - (1-p)*log2(1-p) is the binary entropy function.
        """
        p = max(min(error_rate, 1.0 - EPSILON), EPSILON)
        h_p = -p * math.log2(p) - (1.0 - p) * math.log2(1.0 - p)
        return max(1.0 - h_p, 0.0)

    # ── Noise estimation ──────────────────────────────────────────────────────

    def _estimate_noise(self, target_url: str, param: str, n_trials: int) -> float:
        """Measure channel noise by sending the same input multiple times
        and measuring response variance.

        Returns: estimated error rate in [0, 0.5].
        A perfectly deterministic server has error_rate ≈ 0.
        """
        fixed_input = "noise_estimation_probe_" + "".join(random.choices(string.ascii_lowercase, k=6))
        responses: List[bytes] = []

        for _ in range(n_trials):
            body, status, hdrs = self._http.get(target_url, params={param: fixed_input})
            responses.append(struct.pack(">H", status) + body)

        if len(responses) < 2:
            return 0.5  # Maximum uncertainty

        # Compute pairwise disagreement rate
        n_pairs = 0
        n_disagreements = 0
        reference = responses[0]
        ref_hash = hashlib.sha256(reference).digest()

        for i in range(1, len(responses)):
            n_pairs += 1
            curr_hash = hashlib.sha256(responses[i]).digest()
            if curr_hash != ref_hash:
                n_disagreements += 1

        if n_pairs == 0:
            return 0.0

        raw_error = n_disagreements / n_pairs

        # Also measure structural noise (responses might differ in trivial ways like timestamps)
        # Use feature vector distance
        fvs: List[List[float]] = []
        for resp in responses:
            if len(resp) > 2:
                status = struct.unpack(">H", resp[:2])[0]
                fvs.append(_response_feature_vector(resp[2:], status, {}))

        if len(fvs) >= 2:
            dim = len(fvs[0])
            # Average pairwise L1 distance normalized
            total_dist = 0.0
            pair_count = 0
            for i in range(len(fvs)):
                for j in range(i + 1, len(fvs)):
                    dist = sum(abs(fvs[i][d] - fvs[j][d]) for d in range(dim)) / dim
                    total_dist += dist
                    pair_count += 1
            avg_dist = total_dist / pair_count if pair_count > 0 else 0.0
            # Convert distance to error rate (sigmoid mapping)
            structural_error = 1.0 / (1.0 + math.exp(-10.0 * (avg_dist - 0.05)))
        else:
            structural_error = raw_error

        # Combine: take the more conservative (higher) estimate
        error_rate = max(raw_error, structural_error)
        return min(error_rate, 0.5)  # Cap at 0.5 (maximum for BSC)

    # ── AWGN channel capacity ─────────────────────────────────────────────────

    def _awgn_channel_capacity(self, snr_linear: float) -> float:
        """Additive White Gaussian Noise channel capacity.

        C = 0.5 * log2(1 + SNR) bits per channel use.

        More appropriate than BSC when responses have continuous-valued noise
        (e.g., timing jitter, varying content length).
        """
        if snr_linear <= 0:
            return 0.0
        return 0.5 * math.log2(1.0 + snr_linear)

    def _estimate_snr(self, target_url: str, param: str, n_trials: int = 15) -> float:
        """Estimate signal-to-noise ratio for the channel.

        Signal power: variance of response features across DIFFERENT inputs.
        Noise power: variance of response features for the SAME input.
        SNR = signal_power / noise_power.
        """
        # Noise: repeated same input
        fixed_input = "snr_fixed_" + "".join(random.choices(string.ascii_lowercase, k=5))
        noise_fvs: List[List[float]] = []
        for _ in range(n_trials):
            body, status, hdrs = self._http.get(target_url, params={param: fixed_input})
            noise_fvs.append(_response_feature_vector(body, status, hdrs))

        # Signal: different inputs
        signal_fvs: List[List[float]] = []
        for val in _generate_benign_strings(n_trials):
            body, status, hdrs = self._http.get(target_url, params={param: val})
            signal_fvs.append(_response_feature_vector(body, status, hdrs))

        if len(noise_fvs) < 2 or len(signal_fvs) < 2:
            return 0.0

        dim = len(noise_fvs[0])

        # Noise power: average variance across dimensions for fixed input
        noise_power = 0.0
        for d in range(dim):
            vals = [fv[d] for fv in noise_fvs]
            mean_v = sum(vals) / len(vals)
            noise_power += sum((v - mean_v) ** 2 for v in vals) / len(vals)
        noise_power /= dim

        # Signal power: average variance across dimensions for varied inputs
        signal_power = 0.0
        for d in range(dim):
            vals = [fv[d] for fv in signal_fvs]
            mean_v = sum(vals) / len(vals)
            signal_power += sum((v - mean_v) ** 2 for v in vals) / len(vals)
        signal_power /= dim

        if noise_power < EPSILON:
            return 1000.0  # Nearly noiseless channel

        return signal_power / noise_power

    # ── Discrete memoryless channel capacity (Blahut-Arimoto) ────────────────

    def _blahut_arimoto(
        self,
        transition_matrix: List[List[float]],
        max_iter: int = 100,
        tol: float = 1e-8,
    ) -> float:
        """Blahut-Arimoto algorithm for computing the capacity of a discrete
        memoryless channel defined by transition probability matrix P(y|x).

        transition_matrix[x][y] = P(y|x)

        Returns channel capacity in bits.
        """
        n_x = len(transition_matrix)
        if n_x == 0:
            return 0.0
        n_y = len(transition_matrix[0])
        if n_y == 0:
            return 0.0

        # Initialize uniform input distribution
        q = [1.0 / n_x] * n_x

        for _ in range(max_iter):
            # Compute output distribution r(y) = SUM_x q(x) * P(y|x)
            r = [0.0] * n_y
            for x in range(n_x):
                for y in range(n_y):
                    r[y] += q[x] * transition_matrix[x][y]

            # Compute the auxiliary distribution c(x) = exp(SUM_y P(y|x) * log(P(y|x)/r(y)))
            c = [0.0] * n_x
            for x in range(n_x):
                exponent = 0.0
                for y in range(n_y):
                    p_yx = transition_matrix[x][y]
                    if p_yx > EPSILON and r[y] > EPSILON:
                        exponent += p_yx * math.log(p_yx / r[y])
                c[x] = math.exp(exponent)

            # Update input distribution
            c_sum = sum(c)
            if c_sum <= 0:
                break
            q_new = [ci / c_sum for ci in c]

            # Check convergence
            delta = sum(abs(q_new[x] - q[x]) for x in range(n_x))
            q = q_new
            if delta < tol:
                break

        # Compute final capacity
        capacity = 0.0
        r = [0.0] * n_y
        for x in range(n_x):
            for y in range(n_y):
                r[y] += q[x] * transition_matrix[x][y]

        for x in range(n_x):
            for y in range(n_y):
                p_yx = transition_matrix[x][y]
                if p_yx > EPSILON and r[y] > EPSILON and q[x] > EPSILON:
                    capacity += q[x] * p_yx * math.log2(p_yx / r[y])

        return max(capacity, 0.0)

    def estimate_dmc_capacity(self, target_url: str, param: str, alphabet_size: int = 8) -> float:
        """Estimate discrete memoryless channel capacity via Blahut-Arimoto.

        Builds an empirical transition matrix P(Y|X) by sending inputs from
        a discrete alphabet and categorizing responses, then runs BA.
        """
        # Build discrete input alphabet
        inputs = _generate_benign_strings(alphabet_size, length_range=(4, 8))

        # Collect multiple responses per input to estimate P(Y|X)
        n_repeats = 5
        response_bins = 8  # discretize responses into this many bins
        transition: List[List[float]] = []

        for inp in inputs:
            y_counts = [0] * response_bins
            for _ in range(n_repeats):
                body, status, hdrs = self._http.get(target_url, params={param: inp})
                fv = _response_feature_vector(body, status, hdrs)
                # Hash feature vector to bin
                fv_hash = hash(tuple(round(f, 2) for f in fv))
                y_bin = abs(fv_hash) % response_bins
                y_counts[y_bin] += 1
            # Normalize to probabilities
            total = sum(y_counts) + SMOOTHING_ALPHA * response_bins
            row = [(c + SMOOTHING_ALPHA) / total for c in y_counts]
            transition.append(row)

        return self._blahut_arimoto(transition)


# ════════════════════════════════════════════════════════════════════════════════
# ENGINE 6: KOLMOGOROV COMPLEXITY ESTIMATOR
# ════════════════════════════════════════════════════════════════════════════════


class KolmogorovComplexityEstimator:
    """Estimates computational complexity of server-side processing.

    K(x) is approximated via compression ratio: K(x) ≈ len(compress(x)) / len(x).
    Responses with unexpectedly high or low complexity indicate anomalous behavior.
    """

    def __init__(
        self,
        http_client: Optional[_HTTPClient] = None,
    ) -> None:
        self._lock = threading.RLock()
        self._http = http_client or _HTTPClient()

    # ── Complexity estimation ─────────────────────────────────────────────────

    def estimate_complexity(self, data: bytes) -> float:
        """Estimate Kolmogorov complexity via compression ratio.

        K(x) ≈ len(zlib.compress(x)) / len(x)

        Returns value in (0, 1+] where:
        - Low values (~0.0-0.3) = highly compressible, repetitive, low complexity
        - Medium values (~0.3-0.7) = structured content, moderate complexity
        - High values (~0.7-1.0) = incompressible, random/encrypted, high complexity
        - Values > 1.0 possible for very short strings (compression overhead)
        """
        if not data:
            return 0.0
        if len(data) < 2:
            return 1.0  # Trivially incompressible

        try:
            compressed = zlib.compress(data, 9)  # Max compression
            return len(compressed) / len(data)
        except Exception:
            return 1.0

    # ── Complexity profile ────────────────────────────────────────────────────

    def complexity_profile(
        self, target_url: str, inputs: List[str], param: str
    ) -> ComplexityProfile:
        """Measure how complexity changes with different inputs.

        Sudden jumps in complexity = different server code paths triggered.
        """
        complexities: Dict[str, float] = {}

        for inp in inputs:
            body, status, hdrs = self._http.get(target_url, params={param: inp})
            c = self.estimate_complexity(body)
            complexities[inp] = c

        values = list(complexities.values())
        if not values:
            return ComplexityProfile(param=param)

        mean_c = sum(values) / len(values)
        var_c = sum((v - mean_c) ** 2 for v in values) / len(values)
        std_c = math.sqrt(var_c)

        # Flag inputs whose complexity deviates > 2 std from mean
        anomalous: List[str] = []
        threshold = mean_c + 2.0 * std_c if std_c > 0 else mean_c + COMPLEXITY_CHANGE_THRESHOLD
        for inp, c in complexities.items():
            if abs(c - mean_c) > max(2.0 * std_c, COMPLEXITY_CHANGE_THRESHOLD):
                anomalous.append(inp)

        return ComplexityProfile(
            param=param,
            complexities=complexities,
            mean_complexity=mean_c,
            std_complexity=std_c,
            anomalous_inputs=anomalous,
        )

    # ── Code path change detection ────────────────────────────────────────────

    def detect_code_path_changes(
        self, target_url: str, param: str, probes: List[str]
    ) -> List[CodePathChange]:
        """Detect when different inputs trigger different server code paths.

        For each consecutive pair of probes, measures NCD and complexity delta.
        Large deltas indicate the server branched into a different code path.
        """
        if len(probes) < 2:
            return []

        # Fetch all responses
        responses: Dict[str, bytes] = {}
        complexities: Dict[str, float] = {}

        for probe in probes:
            body, status, hdrs = self._http.get(target_url, params={param: probe})
            responses[probe] = body
            complexities[probe] = self.estimate_complexity(body)

        changes: List[CodePathChange] = []

        for i in range(len(probes) - 1):
            a = probes[i]
            b = probes[i + 1]
            ra = responses.get(a, b"")
            rb = responses.get(b, b"")
            ca = complexities.get(a, 0.0)
            cb = complexities.get(b, 0.0)

            ncd = self.normalized_compression_distance(ra, rb)
            delta = abs(ca - cb)

            significant = (
                ncd > COMPLEXITY_CHANGE_THRESHOLD or
                delta > COMPLEXITY_CHANGE_THRESHOLD
            )

            changes.append(CodePathChange(
                input_a=a,
                input_b=b,
                complexity_a=ca,
                complexity_b=cb,
                ncd=ncd,
                complexity_delta=delta,
                significant=significant,
            ))

        return changes

    # ── Normalized Compression Distance ───────────────────────────────────────

    def normalized_compression_distance(self, x: bytes, y: bytes) -> float:
        """NCD(x,y) = (C(xy) - min(C(x), C(y))) / max(C(x), C(y))

        Measures similarity via compression. Values near 0 = very similar,
        near 1 = very different.
        """
        if not x and not y:
            return 0.0
        if not x or not y:
            return 1.0

        try:
            cx = len(zlib.compress(x, 9))
            cy = len(zlib.compress(y, 9))
            cxy = len(zlib.compress(x + y, 9))
        except Exception:
            return 1.0

        min_c = min(cx, cy)
        max_c = max(cx, cy)

        if max_c == 0:
            return 0.0

        ncd = (cxy - min_c) / max_c
        return max(min(ncd, 1.0), 0.0)

    # ── Obfuscation detection ─────────────────────────────────────────────────

    def detect_obfuscated_content(self, data: bytes) -> ObfuscationResult:
        """Detect obfuscated or encrypted content in response.

        High entropy + high compression ratio (near 1.0) = likely obfuscated.
        Compressed/encrypted data doesn't compress further.
        Normal high-entropy content (e.g., base64) compresses well.
        """
        if not data:
            return ObfuscationResult()

        n = len(data)
        # Shannon entropy
        counts = Counter(data)
        entropy = 0.0
        for count in counts.values():
            p = count / n
            if p > 0:
                entropy -= p * math.log2(p)

        compression_ratio = self.estimate_complexity(data)

        # Classification logic:
        # - Encrypted/random: entropy > 7.5, compression_ratio > 0.95
        # - Obfuscated JS/code: entropy > 5.5, compression_ratio > 0.7
        # - Base64 data: entropy > 5.5, compression_ratio < 0.5 (compresses well)
        # - Normal text: entropy < 5.0, compression_ratio < 0.5

        is_obfuscated = False
        confidence = 0.0
        likely_type = "normal"

        if entropy > 7.5 and compression_ratio > NCD_OBFUSCATION_THRESHOLD:
            is_obfuscated = True
            confidence = 0.95
            likely_type = "encrypted_or_random"
        elif entropy > 7.0 and compression_ratio > 0.85:
            is_obfuscated = True
            confidence = 0.85
            likely_type = "encrypted"
        elif entropy > 5.5 and compression_ratio > 0.7:
            # Could be obfuscated code
            # Additional check: look for JavaScript patterns
            try:
                text = data.decode("utf-8", errors="replace")
                js_indicators = sum(1 for p in [
                    r"eval\s*\(", r"\\x[0-9a-fA-F]{2}", r"String\.fromCharCode",
                    r"atob\s*\(", r"unescape\s*\(", r"\\u[0-9a-fA-F]{4}",
                    r"document\[", r"window\[",
                ] if re.search(p, text))
                if js_indicators >= 2:
                    is_obfuscated = True
                    confidence = min(0.5 + js_indicators * 0.1, 0.9)
                    likely_type = "obfuscated_javascript"
                elif entropy > 6.5:
                    is_obfuscated = True
                    confidence = 0.6
                    likely_type = "obfuscated_code"
            except Exception:
                if entropy > 6.5:
                    is_obfuscated = True
                    confidence = 0.55
                    likely_type = "obfuscated_binary"
        elif entropy > 5.5 and compression_ratio < 0.5:
            # High entropy but compresses well: likely base64
            likely_type = "base64_encoded"
            confidence = 0.4
        elif entropy > 4.0 and compression_ratio > 0.8:
            # Moderate entropy, poor compression: packed binary
            likely_type = "packed_binary"
            confidence = 0.3

        return ObfuscationResult(
            entropy=entropy,
            compression_ratio=compression_ratio,
            is_obfuscated=is_obfuscated,
            confidence=confidence,
            likely_type=likely_type,
        )

    # ── Information distance ──────────────────────────────────────────────────

    def information_distance(self, x: bytes, y: bytes) -> float:
        """Normalized information distance (NID).

        NID(x,y) = max(K(x|y), K(y|x)) / max(K(x), K(y))

        Approximated via: NID ≈ 1 - (C(x) + C(y) - C(xy)) / max(C(x), C(y))
        where C(.) is compressed length.

        This is the universal metric: it minorizes every computable distance.
        """
        if not x and not y:
            return 0.0
        if not x or not y:
            return 1.0

        try:
            cx = len(zlib.compress(x, 9))
            cy = len(zlib.compress(y, 9))
            cxy = len(zlib.compress(x + y, 9))
        except Exception:
            return 1.0

        max_c = max(cx, cy)
        if max_c == 0:
            return 0.0

        # NID ≈ 1 - (C(x) + C(y) - C(xy)) / max(C(x), C(y))
        overlap = cx + cy - cxy
        nid = 1.0 - (overlap / max_c)
        return max(min(nid, 1.0), 0.0)

    # ── Conditional complexity ────────────────────────────────────────────────

    def conditional_complexity(self, x: bytes, y: bytes) -> float:
        """Estimate K(x|y) — complexity of x given y.

        K(x|y) ≈ C(yx) - C(y)
        How much additional information x adds beyond what y already contains.
        """
        if not x:
            return 0.0
        if not y:
            return self.estimate_complexity(x) * len(x)

        try:
            cy = len(zlib.compress(y, 9))
            cyx = len(zlib.compress(y + x, 9))
        except Exception:
            return self.estimate_complexity(x) * len(x)

        return max(cyx - cy, 0) / max(len(x), 1)

    # ── Clustering via NCD ────────────────────────────────────────────────────

    def cluster_responses(
        self,
        responses: Dict[str, bytes],
        threshold: float = 0.3,
    ) -> List[List[str]]:
        """Cluster responses by Normalized Compression Distance.

        Uses single-linkage agglomerative clustering: two responses are in the
        same cluster if their NCD is below threshold. This groups responses
        that came from the same server code path.
        """
        keys = list(responses.keys())
        n = len(keys)
        if n == 0:
            return []

        # Build NCD matrix
        ncd_matrix: Dict[Tuple[str, str], float] = {}
        for i in range(n):
            for j in range(i + 1, n):
                ncd = self.normalized_compression_distance(
                    responses[keys[i]], responses[keys[j]]
                )
                ncd_matrix[(keys[i], keys[j])] = ncd
                ncd_matrix[(keys[j], keys[i])] = ncd

        # Union-Find for clustering
        parent: Dict[str, str] = {k: k for k in keys}

        def find(x: str) -> str:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a: str, b: str) -> None:
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[ra] = rb

        for i in range(n):
            for j in range(i + 1, n):
                if ncd_matrix[(keys[i], keys[j])] < threshold:
                    union(keys[i], keys[j])

        # Collect clusters
        clusters: Dict[str, List[str]] = defaultdict(list)
        for k in keys:
            clusters[find(k)].append(k)

        return list(clusters.values())

    # ── Lempel-Ziv complexity ─────────────────────────────────────────────────

    def lempel_ziv_complexity(self, data: bytes) -> int:
        """Compute Lempel-Ziv complexity: count of distinct substrings
        in the LZ76 factorization.

        This is another approximation to Kolmogorov complexity, independent
        of compression algorithm. It counts the number of new patterns
        encountered when scanning left to right.
        """
        if not data:
            return 0

        n = len(data)
        i = 0
        complexity = 0
        seen: Set[bytes] = set()

        while i < n:
            # Find the longest substring starting at i that we haven't seen
            length = 1
            while i + length <= n:
                substring = bytes(data[i : i + length])
                if substring not in seen:
                    seen.add(substring)
                    complexity += 1
                    break
                length += 1
            else:
                # Reached end of data
                complexity += 1
            i += length

        return complexity

    def normalized_lz_complexity(self, data: bytes) -> float:
        """Normalized Lempel-Ziv complexity in [0, 1].

        c(data) / (len(data) / log2(len(data)))

        Values near 1.0 indicate random/incompressible data.
        """
        if len(data) < 2:
            return 1.0

        c = self.lempel_ziv_complexity(data)
        n = len(data)
        # Theoretical maximum for random sequence
        max_c = n / max(math.log2(n), 1.0)
        return min(c / max_c, 1.0) if max_c > 0 else 0.0


# ════════════════════════════════════════════════════════════════════════════════
# MAIN ORCHESTRATOR: SirenInformationTheory
# ════════════════════════════════════════════════════════════════════════════════


class SirenInformationTheory:
    """Master orchestrator combining all six information theory engines.

    Provides full_scan, quick_scan, and stealth_scan modes, correlating
    results across engines to produce a unified InformationTheoryReport.
    """

    def __init__(self, timeout: float = DEFAULT_TIMEOUT, user_agent: str = DEFAULT_USER_AGENT) -> None:
        self._lock = threading.RLock()
        self._http = _HTTPClient(timeout=timeout, user_agent=user_agent)
        self._entropy_analyzer = ShannonEntropyAnalyzer()
        self._mi_scanner = MutualInformationScanner(
            http_client=self._http,
            entropy_analyzer=self._entropy_analyzer,
        )
        self._kl_detector = KLDivergenceDetector(http_client=self._http)
        self._fisher_prober = FisherInformationProber(
            http_client=self._http,
            entropy_analyzer=self._entropy_analyzer,
        )
        self._channel_estimator = ChannelCapacityEstimator(
            http_client=self._http,
            mi_scanner=self._mi_scanner,
        )
        self._complexity_estimator = KolmogorovComplexityEstimator(http_client=self._http)

    # ── Full scan ─────────────────────────────────────────────────────────────

    def full_scan(
        self, target_url: str, params: List[str]
    ) -> InformationTheoryReport:
        """Run all engines, correlate results into a unified report.

        Pipeline:
        1. Entropy profiling of baseline responses
        2. MI scanning of all params
        3. KL divergence detection
        4. Fisher information probing
        5. Channel capacity estimation
        6. Kolmogorov complexity profiling
        7. Correlation and finding generation
        """
        logger.info("Starting FULL information theory scan on %s with params %s", target_url, params)
        start_time = time.monotonic()
        self._http.reset_count()

        report = InformationTheoryReport(target_url=target_url, scan_mode="full")

        # 1. Baseline entropy profiling
        baseline_body, baseline_status, baseline_hdrs = self._http.get(target_url)
        baseline_profile = self._entropy_analyzer.profile(baseline_body)
        report.entropy_profiles["__baseline__"] = baseline_profile

        # 2. MI scanning
        for param in params:
            try:
                mi_result = self._mi_scanner.measure_mutual_information(target_url, param, samples=30)
                report.mi_results.append(mi_result)
                # Per-param entropy profile
                body, status, hdrs = self._http.get(target_url, params={param: "entropy_probe"})
                report.entropy_profiles[param] = self._entropy_analyzer.profile(body)
            except Exception as exc:
                logger.error("MI scan error for '%s': %s", param, exc)
                report.mi_results.append(MutualInformationResult(param=param))

        # 3. KL divergence for params with high MI
        for mi_r in report.mi_results:
            if mi_r.mi_value > MI_MEDIUM_THRESHOLD:
                try:
                    anomaly = self._kl_detector.detect_anomaly(
                        target_url, "test'value", mi_r.param
                    )
                    report.divergence_results.append(anomaly.divergence)
                except Exception as exc:
                    logger.error("KL divergence error for '%s': %s", mi_r.param, exc)

        # 4. Fisher information
        probe_candidates = _generate_benign_strings(15)
        for param in params:
            try:
                fisher = self._fisher_prober.estimate_fisher_information(
                    target_url, param, probe_candidates
                )
                report.fisher_results.append(fisher)
            except Exception as exc:
                logger.error("Fisher info error for '%s': %s", param, exc)

        # 5. Channel capacity
        for param in params:
            try:
                cap = self._channel_estimator.estimate_capacity(target_url, param)
                report.channel_capacities.append(cap)
            except Exception as exc:
                logger.error("Channel capacity error for '%s': %s", param, exc)

        # 6. Kolmogorov complexity
        complexity_probes = _generate_benign_strings(8) + ["test'val", "test<val", "test..val"]
        for param in params:
            try:
                cp = self._complexity_estimator.complexity_profile(
                    target_url, complexity_probes, param
                )
                report.complexity_profiles.append(cp)
            except Exception as exc:
                logger.error("Complexity profile error for '%s': %s", param, exc)

        # 7. Generate findings
        report.findings = self._correlate_findings(report)
        report.total_requests_made = self._http.request_count
        report.scan_duration = time.monotonic() - start_time

        logger.info(
            "Full scan complete: %d findings, %d requests, %.1fs",
            len(report.findings), report.total_requests_made, report.scan_duration,
        )
        return report

    # ── Quick scan ────────────────────────────────────────────────────────────

    def quick_scan(
        self, target_url: str, params: List[str]
    ) -> InformationTheoryReport:
        """MI scanner + entropy analysis only (fast)."""
        logger.info("Starting QUICK scan on %s", target_url)
        start_time = time.monotonic()
        self._http.reset_count()

        report = InformationTheoryReport(target_url=target_url, scan_mode="quick")

        # Baseline entropy
        baseline_body, _, _ = self._http.get(target_url)
        report.entropy_profiles["__baseline__"] = self._entropy_analyzer.profile(baseline_body)

        # MI scanning with fewer samples
        for param in params:
            try:
                mi_result = self._mi_scanner.measure_mutual_information(target_url, param, samples=15)
                report.mi_results.append(mi_result)
            except Exception as exc:
                logger.error("Quick MI scan error for '%s': %s", param, exc)
                report.mi_results.append(MutualInformationResult(param=param))

        report.findings = self._correlate_findings(report)
        report.total_requests_made = self._http.request_count
        report.scan_duration = time.monotonic() - start_time
        return report

    # ── Stealth scan ──────────────────────────────────────────────────────────

    def stealth_scan(
        self, target_url: str, params: List[str]
    ) -> InformationTheoryReport:
        """Fisher-optimized minimum requests scan."""
        logger.info("Starting STEALTH scan on %s", target_url)
        start_time = time.monotonic()
        self._http.reset_count()

        report = InformationTheoryReport(target_url=target_url, scan_mode="stealth")

        for param in params:
            try:
                adaptive = self._fisher_prober.adaptive_scan(
                    target_url, param, confidence_target=0.90, max_requests=20,
                )

                # Convert adaptive result to MI-like result for correlation
                mi_result = MutualInformationResult(
                    param=param,
                    mi_value=adaptive.total_information,
                    confidence=adaptive.confidence_reached,
                    likely_vuln_type=adaptive.estimated_vuln_type,
                    n_samples=adaptive.n_requests,
                    evidence=[
                        f"Adaptive scan: {adaptive.n_requests} requests, "
                        f"converged={adaptive.converged}"
                    ],
                )
                report.mi_results.append(mi_result)

                fisher = FisherResult(
                    param=param,
                    fisher_information=adaptive.total_information,
                    cramer_rao_bound=self._fisher_prober.cramer_rao_bound(adaptive.total_information),
                    n_probes_used=adaptive.n_requests,
                )
                report.fisher_results.append(fisher)
            except Exception as exc:
                logger.error("Stealth scan error for '%s': %s", param, exc)

        report.findings = self._correlate_findings(report)
        report.total_requests_made = self._http.request_count
        report.scan_duration = time.monotonic() - start_time
        return report

    # ── Finding correlation ───────────────────────────────────────────────────

    def _correlate_findings(self, report: InformationTheoryReport) -> List[ITFinding]:
        """Cross-reference all engine results to produce final findings."""
        findings: List[ITFinding] = []

        mi_by_param: Dict[str, MutualInformationResult] = {
            r.param: r for r in report.mi_results
        }
        cap_by_param: Dict[str, ChannelCapacity] = {
            c.param: c for c in report.channel_capacities
        }
        fisher_by_param: Dict[str, FisherResult] = {
            f.param: f for f in report.fisher_results
        }
        complexity_by_param: Dict[str, ComplexityProfile] = {
            c.param: c for c in report.complexity_profiles
        }

        all_params: Set[str] = set()
        all_params.update(mi_by_param.keys())
        all_params.update(cap_by_param.keys())

        for param in all_params:
            mi_r = mi_by_param.get(param)
            cap_r = cap_by_param.get(param)
            fisher_r = fisher_by_param.get(param)
            complex_r = complexity_by_param.get(param)

            if not mi_r or mi_r.mi_value < MI_MEDIUM_THRESHOLD * 0.5:
                continue

            evidence: List[str] = []
            confidence = mi_r.confidence
            vuln_type = mi_r.likely_vuln_type
            kl_val = 0.0

            # MI evidence
            evidence.append(f"MI={mi_r.mi_value:.4f} bits")

            # Channel capacity evidence
            if cap_r and cap_r.bits_per_request > 0.1:
                evidence.append(f"Channel capacity={cap_r.bits_per_request:.3f} bits/req")
                evidence.append(f"Exfil risk: {cap_r.exfil_risk}")
                # Boost confidence if channel capacity confirms MI finding
                confidence = min(confidence + 0.1, 1.0)

            # Fisher information evidence
            if fisher_r and fisher_r.fisher_information > 0:
                evidence.append(f"Fisher info={fisher_r.fisher_information:.4f}")
                evidence.append(f"Cramer-Rao bound={fisher_r.cramer_rao_bound:.4f}")

            # Complexity evidence
            if complex_r and complex_r.anomalous_inputs:
                evidence.append(
                    f"Complexity anomalies in {len(complex_r.anomalous_inputs)} inputs"
                )
                confidence = min(confidence + 0.05, 1.0)

            # KL divergence from report-level
            if report.divergence_results:
                for div_r in report.divergence_results:
                    if div_r.is_anomalous:
                        kl_val = max(kl_val, div_r.kl_divergence)
                        evidence.append(f"KL divergence={div_r.kl_divergence:.4f} (anomalous)")
                        confidence = min(confidence + 0.1, 1.0)
                        break

            # Description
            if vuln_type == VulnType.UNKNOWN and mi_r.mi_value > MI_MEDIUM_THRESHOLD:
                description = (
                    f"Parameter '{param}' shows significant input-output dependency "
                    f"(MI={mi_r.mi_value:.3f} bits). Server behavior is influenced by "
                    f"user input in a structured way, indicating a potential injection point."
                )
            elif vuln_type != VulnType.UNKNOWN:
                description = (
                    f"Parameter '{param}' is a likely {vuln_type.value} candidate. "
                    f"Mutual information analysis shows {mi_r.mi_value:.3f} bits of "
                    f"input-output dependency with {vuln_type.value}-consistent patterns."
                )
            else:
                description = f"Parameter '{param}' shows low MI ({mi_r.mi_value:.3f} bits)."

            finding_type = "injection_candidate" if mi_r.mi_value > MI_MEDIUM_THRESHOLD else "informational"

            findings.append(ITFinding(
                param=param,
                finding_type=finding_type,
                vuln_type=vuln_type,
                confidence=confidence,
                mi_value=mi_r.mi_value,
                kl_divergence=kl_val,
                description=description,
                evidence=evidence,
            ))

        # Sort by confidence descending
        findings.sort(key=lambda f: f.confidence, reverse=True)
        return findings

    # ── Direct engine access ──────────────────────────────────────────────────

    @property
    def entropy(self) -> ShannonEntropyAnalyzer:
        return self._entropy_analyzer

    @property
    def mi(self) -> MutualInformationScanner:
        return self._mi_scanner

    @property
    def kl(self) -> KLDivergenceDetector:
        return self._kl_detector

    @property
    def fisher(self) -> FisherInformationProber:
        return self._fisher_prober

    @property
    def channel(self) -> ChannelCapacityEstimator:
        return self._channel_estimator

    @property
    def complexity(self) -> KolmogorovComplexityEstimator:
        return self._complexity_estimator
