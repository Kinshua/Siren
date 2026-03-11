"""
██████████████████████████████████████████████████████████████████████████████████
██                                                                            ██
██   ███████╗██╗██████╗ ███████╗███╗   ██╗                                    ██
██   ██╔════╝██║██╔══██╗██╔════╝████╗  ██║                                    ██
██   ███████╗██║██████╔╝█████╗  ██╔██╗ ██║                                    ██
██   ╚════██║██║██╔══██╗██╔══╝  ██║╚██╗██║                                    ██
██   ███████║██║██║  ██║███████╗██║ ╚████║                                    ██
██   ╚══════╝╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝                                    ██
██                                                                            ██
██   RESULT CORRELATOR - Cross-Scan Finding Correlation & Deduplication       ██
██   "A persistencia transforma fracasso em conquista extraordinaria."        ██
██                                                                            ██
██   Cross-scan correlation, intelligent deduplication, trend analysis,       ██
██   systemic weakness detection, and risk amplification engine.              ██
██                                                                            ██
██████████████████████████████████████████████████████████████████████████████████
"""
from __future__ import annotations

import collections
import copy
import dataclasses
import difflib
import enum
import hashlib
import json
import logging
import math
import re
import struct
import threading
import time
import uuid
from typing import (
    Any,
    Callable,
    Counter,
    DefaultDict,
    Deque,
    Dict,
    FrozenSet,
    Iterable,
    List,
    Optional,
    Set,
    Tuple,
    Type,
    Union,
)
from urllib.parse import urlparse, urlunparse

logger = logging.getLogger("siren.automation.result_correlator")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_SIMILARITY_THRESHOLD: float = 0.70
_DEFAULT_SYSTEMIC_THRESHOLD: float = 0.60
_FLAPPING_WINDOW: int = 4
_FLAPPING_MIN_FLIPS: int = 3
_DNA_HASH_ALGO: str = "sha256"
_MAX_EVIDENCE_COMPARE_LEN: int = 4096
_REPORT_SEPARATOR: str = "---"
_RISK_AMPLIFICATION_MAP: List[Tuple[int, float]] = [
    (10, 3.0),
    (6, 2.0),
    (3, 1.5),
    (2, 1.2),
    (1, 1.0),
]

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class FindingTrend(enum.Enum):
    """Trend classification for a correlated finding across scans."""

    NEW = "NEW"
    PERSISTENT = "PERSISTENT"
    REGRESSED = "REGRESSED"
    FIXED = "FIXED"
    FLAPPING = "FLAPPING"
    UNKNOWN = "UNKNOWN"


class CorrelationRuleType(enum.Enum):
    """Type of matching strategy used by a CorrelationRule."""

    EXACT = "EXACT"
    FUZZY = "FUZZY"
    SEMANTIC = "SEMANTIC"
    REGEX = "REGEX"


class CrossScanPatternType(enum.Enum):
    """Classification of patterns detected across scans."""

    RECURRING_VULN = "RECURRING_VULN"
    SPREADING_VULN = "SPREADING_VULN"
    REGRESSION = "REGRESSION"
    FIX_CONFIRMED = "FIX_CONFIRMED"
    SYSTEMIC_WEAKNESS = "SYSTEMIC_WEAKNESS"


class MergeStrategy(enum.Enum):
    """Strategy for merging duplicate findings."""

    KEEP_MOST_DETAILED = "KEEP_MOST_DETAILED"
    KEEP_MOST_RECENT = "KEEP_MOST_RECENT"
    KEEP_ALL_EVIDENCE = "KEEP_ALL_EVIDENCE"


class SeverityLevel(enum.Enum):
    """Standard severity levels for vulnerability findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def numeric(self) -> float:
        _map = {
            "CRITICAL": 10.0,
            "HIGH": 8.0,
            "MEDIUM": 5.0,
            "LOW": 2.0,
            "INFO": 0.5,
        }
        return _map.get(self.value, 0.0)


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------


def _normalize_url(url: str) -> str:
    """Normalize a URL for stable comparison: lowercase, strip query params,
    remove trailing slash, remove default ports."""
    if not url:
        return ""
    url = url.strip()
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url_lower = url.lower().rstrip("/")
        url_lower = re.sub(r"\s+", "", url_lower)
        return url_lower
    parsed = urlparse(url.lower())
    scheme = parsed.scheme
    netloc = parsed.hostname or ""
    port = parsed.port
    if port:
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            port = None
    if port:
        netloc = f"{netloc}:{port}"
    path = parsed.path.rstrip("/") or "/"
    normalized = urlunparse((scheme, netloc, path, "", "", ""))
    return normalized


def _normalize_text(text: str) -> str:
    """Normalize text for comparison: lowercase, collapse whitespace, strip."""
    if not text:
        return ""
    text = text.lower().strip()
    text = re.sub(r"\s+", " ", text)
    return text


def _compute_dna_hash(
    endpoint: str,
    vuln_type: str,
    title: str,
    extra_fields: Optional[Dict[str, str]] = None,
) -> str:
    """Create a stable content-based fingerprint (DNA hash) for a finding."""
    norm_endpoint = _normalize_url(endpoint)
    norm_title = _normalize_text(title)
    norm_vuln = _normalize_text(vuln_type)
    payload = f"{norm_endpoint}:{norm_vuln}:{norm_title}"
    if extra_fields:
        for key in sorted(extra_fields.keys()):
            payload += f":{_normalize_text(str(extra_fields[key]))}"
    return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()


def _fuzzy_ratio(a: str, b: str) -> float:
    """Compute similarity ratio between two strings using SequenceMatcher."""
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a, b).ratio()


def _severity_from_str(val: str) -> SeverityLevel:
    """Parse a severity string into SeverityLevel enum."""
    if isinstance(val, SeverityLevel):
        return val
    mapping = {
        "critical": SeverityLevel.CRITICAL,
        "high": SeverityLevel.HIGH,
        "medium": SeverityLevel.MEDIUM,
        "med": SeverityLevel.MEDIUM,
        "low": SeverityLevel.LOW,
        "info": SeverityLevel.INFO,
        "informational": SeverityLevel.INFO,
    }
    return mapping.get(str(val).strip().lower(), SeverityLevel.INFO)


def _risk_amplification_factor(target_count: int) -> float:
    """Return risk amplification factor based on how many targets are affected."""
    for threshold, factor in _RISK_AMPLIFICATION_MAP:
        if target_count >= threshold:
            return factor
    return 1.0


def _current_timestamp() -> float:
    """Return current UTC timestamp."""
    return time.time()


def _generate_uuid() -> str:
    """Generate a new UUID4 string."""
    return str(uuid.uuid4())


def _truncate(text: str, max_len: int = 120) -> str:
    """Truncate text with ellipsis if too long."""
    if not text or len(text) <= max_len:
        return text or ""
    return text[: max_len - 3] + "..."


def _safe_get(data: Dict[str, Any], key: str, default: Any = "") -> Any:
    """Safely retrieve a value from a dict."""
    if not isinstance(data, dict):
        return default
    return data.get(key, default)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class CorrelatedFinding:
    """A finding matched and tracked across multiple scans.

    Attributes:
        correlation_id: Stable identifier across scans.
        title: Human-readable vulnerability title.
        severity: Severity level of the finding.
        endpoint: Affected endpoint / URL / target.
        vuln_type: Vulnerability type/class (e.g. XSS, SQLi).
        evidence: Evidence snippets supporting the finding.
        scan_ids: Ordered list of scan IDs where this finding appeared.
        first_seen: Timestamp of earliest detection.
        last_seen: Timestamp of most recent detection.
        trend: Trend classification (NEW, PERSISTENT, etc.).
        confidence: Confidence score of the correlation (0.0-1.0).
        dna_hash: Content-based fingerprint for matching.
        original_findings: Raw finding dicts from each scan.
        tags: Arbitrary tags / labels.
        remediation_notes: Accumulated remediation guidance.
        risk_score: Computed risk score after amplification.
        amplification_factor: Risk amplification multiplier.
        affected_targets: Distinct targets where this finding appeared.
        metadata: Arbitrary extra metadata.
    """

    correlation_id: str = dataclasses.field(default_factory=_generate_uuid)
    title: str = ""
    severity: str = "INFO"
    endpoint: str = ""
    vuln_type: str = ""
    evidence: List[str] = dataclasses.field(default_factory=list)
    scan_ids: List[str] = dataclasses.field(default_factory=list)
    first_seen: float = 0.0
    last_seen: float = 0.0
    trend: str = FindingTrend.UNKNOWN.value
    confidence: float = 0.0
    dna_hash: str = ""
    original_findings: List[Dict[str, Any]] = dataclasses.field(default_factory=list)
    tags: List[str] = dataclasses.field(default_factory=list)
    remediation_notes: str = ""
    risk_score: float = 0.0
    amplification_factor: float = 1.0
    affected_targets: List[str] = dataclasses.field(default_factory=list)
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.dna_hash and (self.endpoint or self.vuln_type or self.title):
            self.dna_hash = _compute_dna_hash(self.endpoint, self.vuln_type, self.title)
        if not self.first_seen:
            self.first_seen = _current_timestamp()
        if not self.last_seen:
            self.last_seen = self.first_seen
        if isinstance(self.severity, SeverityLevel):
            self.severity = self.severity.value
        self._recompute_risk_score()

    def _recompute_risk_score(self) -> None:
        """Recalculate risk score from severity and amplification factor."""
        sev = _severity_from_str(self.severity)
        target_count = len(set(self.affected_targets)) if self.affected_targets else 1
        self.amplification_factor = _risk_amplification_factor(target_count)
        self.risk_score = round(sev.numeric * self.amplification_factor, 2)

    def add_scan(self, scan_id: str, timestamp: Optional[float] = None) -> None:
        """Register that this finding appeared in *scan_id*."""
        if scan_id not in self.scan_ids:
            self.scan_ids.append(scan_id)
        ts = timestamp or _current_timestamp()
        if ts < self.first_seen or self.first_seen == 0.0:
            self.first_seen = ts
        if ts > self.last_seen:
            self.last_seen = ts

    def add_evidence(self, snippet: str) -> None:
        """Append a unique evidence snippet."""
        if snippet and snippet not in self.evidence:
            self.evidence.append(snippet)

    def add_target(self, target: str) -> None:
        """Register a distinct affected target."""
        if target and target not in self.affected_targets:
            self.affected_targets.append(target)
            self._recompute_risk_score()

    def merge_from(self, other: CorrelatedFinding) -> None:
        """Merge data from *other* into this finding (union of evidence, scans, etc.)."""
        for sid in other.scan_ids:
            self.add_scan(sid)
        for ev in other.evidence:
            self.add_evidence(ev)
        for tgt in other.affected_targets:
            self.add_target(tgt)
        for tag in other.tags:
            if tag not in self.tags:
                self.tags.append(tag)
        for orig in other.original_findings:
            self.original_findings.append(orig)
        if other.first_seen < self.first_seen:
            self.first_seen = other.first_seen
        if other.last_seen > self.last_seen:
            self.last_seen = other.last_seen
        if other.confidence > self.confidence:
            self.confidence = other.confidence
        if other.remediation_notes and other.remediation_notes not in self.remediation_notes:
            if self.remediation_notes:
                self.remediation_notes += "\n" + other.remediation_notes
            else:
                self.remediation_notes = other.remediation_notes
        self._recompute_risk_score()

    @property
    def scan_count(self) -> int:
        return len(self.scan_ids)

    @property
    def age_seconds(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)

    @property
    def target_count(self) -> int:
        return len(set(self.affected_targets))

    @property
    def is_systemic(self) -> bool:
        return self.target_count >= 3

    def to_dict(self) -> Dict[str, Any]:
        return {
            "correlation_id": self.correlation_id,
            "title": self.title,
            "severity": self.severity,
            "endpoint": self.endpoint,
            "vuln_type": self.vuln_type,
            "evidence": list(self.evidence),
            "scan_ids": list(self.scan_ids),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "trend": self.trend,
            "confidence": self.confidence,
            "dna_hash": self.dna_hash,
            "original_findings_count": len(self.original_findings),
            "tags": list(self.tags),
            "remediation_notes": self.remediation_notes,
            "risk_score": self.risk_score,
            "amplification_factor": self.amplification_factor,
            "affected_targets": list(self.affected_targets),
            "scan_count": self.scan_count,
            "age_seconds": self.age_seconds,
            "target_count": self.target_count,
            "is_systemic": self.is_systemic,
            "metadata": dict(self.metadata),
        }

    def __repr__(self) -> str:
        return (
            f"CorrelatedFinding(id={self.correlation_id!r}, title={_truncate(self.title, 50)!r}, "
            f"trend={self.trend}, scans={self.scan_count}, risk={self.risk_score})"
        )


@dataclasses.dataclass
class CorrelationRule:
    """Defines how to match findings across scans.

    Attributes:
        rule_id: Unique rule identifier.
        name: Human-readable rule name.
        description: Description of what this rule matches.
        match_fields: List of finding attribute names to compare.
        similarity_threshold: Minimum combined score to consider a match (0.0-1.0).
        field_weights: Per-field weight for the combined similarity score.
        rule_type: Matching strategy type.
        enabled: Whether this rule is active.
        priority: Higher priority rules are evaluated first.
        tags: Arbitrary labels for categorization.
        metadata: Extra rule configuration.
    """

    rule_id: str = dataclasses.field(default_factory=_generate_uuid)
    name: str = ""
    description: str = ""
    match_fields: List[str] = dataclasses.field(default_factory=list)
    similarity_threshold: float = _DEFAULT_SIMILARITY_THRESHOLD
    field_weights: Dict[str, float] = dataclasses.field(default_factory=dict)
    rule_type: str = CorrelationRuleType.FUZZY.value
    enabled: bool = True
    priority: int = 0
    tags: List[str] = dataclasses.field(default_factory=list)
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        if isinstance(self.rule_type, CorrelationRuleType):
            self.rule_type = self.rule_type.value
        if not self.match_fields:
            self.match_fields = ["endpoint", "vuln_type", "title", "evidence"]
        if not self.field_weights:
            self.field_weights = {
                "endpoint": 0.4,
                "vuln_type": 0.3,
                "evidence": 0.2,
                "title": 0.1,
            }
        self._normalize_weights()

    def _normalize_weights(self) -> None:
        """Ensure field weights sum to 1.0."""
        total = sum(self.field_weights.get(f, 0.0) for f in self.match_fields)
        if total > 0.0 and abs(total - 1.0) > 1e-6:
            for field in self.match_fields:
                if field in self.field_weights:
                    self.field_weights[field] = self.field_weights[field] / total

    def compute_similarity(
        self, finding_a: Dict[str, Any], finding_b: Dict[str, Any]
    ) -> float:
        """Compute weighted similarity between two finding dicts using this rule.

        Returns:
            Combined similarity score in [0.0, 1.0].
        """
        if self.rule_type == CorrelationRuleType.EXACT.value:
            return self._exact_match(finding_a, finding_b)
        elif self.rule_type == CorrelationRuleType.REGEX.value:
            return self._regex_match(finding_a, finding_b)
        elif self.rule_type == CorrelationRuleType.SEMANTIC.value:
            return self._semantic_match(finding_a, finding_b)
        else:
            return self._fuzzy_match(finding_a, finding_b)

    def _extract_field(self, finding: Dict[str, Any], field: str) -> str:
        """Extract and normalize a field value from a finding dict."""
        raw = _safe_get(finding, field, "")
        if isinstance(raw, list):
            raw = " ".join(str(item) for item in raw)
        elif not isinstance(raw, str):
            raw = str(raw) if raw is not None else ""
        if field == "endpoint":
            return _normalize_url(raw)
        return _normalize_text(raw)

    def _fuzzy_match(self, a: Dict[str, Any], b: Dict[str, Any]) -> float:
        """Weighted fuzzy matching across configured fields."""
        total_score = 0.0
        for field in self.match_fields:
            weight = self.field_weights.get(field, 0.0)
            if weight <= 0.0:
                continue
            val_a = self._extract_field(a, field)
            val_b = self._extract_field(b, field)
            if field == "evidence":
                val_a = val_a[:_MAX_EVIDENCE_COMPARE_LEN]
                val_b = val_b[:_MAX_EVIDENCE_COMPARE_LEN]
            ratio = _fuzzy_ratio(val_a, val_b)
            total_score += ratio * weight
        return min(1.0, max(0.0, total_score))

    def _exact_match(self, a: Dict[str, Any], b: Dict[str, Any]) -> float:
        """All configured fields must match exactly (after normalization)."""
        matched = 0
        total = len(self.match_fields) or 1
        for field in self.match_fields:
            val_a = self._extract_field(a, field)
            val_b = self._extract_field(b, field)
            if val_a == val_b:
                matched += 1
        return matched / total

    def _regex_match(self, a: Dict[str, Any], b: Dict[str, Any]) -> float:
        """Treat field values of *a* as regex patterns; match against *b* values."""
        total_score = 0.0
        for field in self.match_fields:
            weight = self.field_weights.get(field, 0.0)
            if weight <= 0.0:
                continue
            pattern_str = self._extract_field(a, field)
            target_str = self._extract_field(b, field)
            if not pattern_str or not target_str:
                continue
            try:
                if re.search(pattern_str, target_str, re.IGNORECASE):
                    total_score += weight
            except re.error:
                ratio = _fuzzy_ratio(pattern_str, target_str)
                total_score += ratio * weight
        return min(1.0, max(0.0, total_score))

    def _semantic_match(self, a: Dict[str, Any], b: Dict[str, Any]) -> float:
        """Approximate semantic similarity via token-overlap + fuzzy fallback.

        True semantic matching requires embeddings; we approximate with
        Jaccard similarity on word tokens plus fuzzy ratio, weighted 50/50.
        """
        total_score = 0.0
        for field in self.match_fields:
            weight = self.field_weights.get(field, 0.0)
            if weight <= 0.0:
                continue
            val_a = self._extract_field(a, field)
            val_b = self._extract_field(b, field)
            tokens_a = set(re.findall(r"\w+", val_a))
            tokens_b = set(re.findall(r"\w+", val_b))
            if tokens_a or tokens_b:
                intersection = tokens_a & tokens_b
                union = tokens_a | tokens_b
                jaccard = len(intersection) / len(union) if union else 0.0
            else:
                jaccard = 1.0 if (not val_a and not val_b) else 0.0
            fuzzy = _fuzzy_ratio(val_a, val_b)
            combined = 0.5 * jaccard + 0.5 * fuzzy
            total_score += combined * weight
        return min(1.0, max(0.0, total_score))

    def is_match(self, finding_a: Dict[str, Any], finding_b: Dict[str, Any]) -> bool:
        """Return True if two findings match according to this rule."""
        return self.compute_similarity(finding_a, finding_b) >= self.similarity_threshold

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "match_fields": list(self.match_fields),
            "similarity_threshold": self.similarity_threshold,
            "field_weights": dict(self.field_weights),
            "rule_type": self.rule_type,
            "enabled": self.enabled,
            "priority": self.priority,
            "tags": list(self.tags),
            "metadata": dict(self.metadata),
        }

    def __repr__(self) -> str:
        return (
            f"CorrelationRule(id={self.rule_id!r}, name={self.name!r}, "
            f"type={self.rule_type}, threshold={self.similarity_threshold})"
        )


@dataclasses.dataclass
class CrossScanPattern:
    """A pattern detected across multiple scans.

    Attributes:
        pattern_id: Unique pattern identifier.
        pattern_type: Classification of the pattern.
        description: Human-readable description.
        affected_findings: CorrelatedFinding instances that form this pattern.
        affected_finding_ids: Correlation IDs of the affected findings.
        first_occurrence: Timestamp of earliest finding in this pattern.
        last_occurrence: Timestamp of latest finding in this pattern.
        occurrence_count: Number of times the pattern was observed.
        frequency: Average occurrences per scan.
        risk_amplification: Aggregate risk amplification factor.
        remediation_urgency: Urgency score (0.0-10.0).
        scan_ids: Scans that contributed to this pattern.
        targets: Distinct targets involved.
        vuln_types: Distinct vulnerability types involved.
        metadata: Extra metadata.
    """

    pattern_id: str = dataclasses.field(default_factory=_generate_uuid)
    pattern_type: str = CrossScanPatternType.RECURRING_VULN.value
    description: str = ""
    affected_findings: List[CorrelatedFinding] = dataclasses.field(default_factory=list)
    affected_finding_ids: List[str] = dataclasses.field(default_factory=list)
    first_occurrence: float = 0.0
    last_occurrence: float = 0.0
    occurrence_count: int = 0
    frequency: float = 0.0
    risk_amplification: float = 1.0
    remediation_urgency: float = 0.0
    scan_ids: List[str] = dataclasses.field(default_factory=list)
    targets: List[str] = dataclasses.field(default_factory=list)
    vuln_types: List[str] = dataclasses.field(default_factory=list)
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        if isinstance(self.pattern_type, CrossScanPatternType):
            self.pattern_type = self.pattern_type.value

    def add_finding(self, finding: CorrelatedFinding) -> None:
        """Add a correlated finding to this pattern and update metrics."""
        if finding.correlation_id not in self.affected_finding_ids:
            self.affected_finding_ids.append(finding.correlation_id)
            self.affected_findings.append(finding)
        for sid in finding.scan_ids:
            if sid not in self.scan_ids:
                self.scan_ids.append(sid)
        for tgt in finding.affected_targets:
            if tgt not in self.targets:
                self.targets.append(tgt)
        if finding.vuln_type and finding.vuln_type not in self.vuln_types:
            self.vuln_types.append(finding.vuln_type)
        if finding.first_seen and (
            self.first_occurrence == 0.0 or finding.first_seen < self.first_occurrence
        ):
            self.first_occurrence = finding.first_seen
        if finding.last_seen > self.last_occurrence:
            self.last_occurrence = finding.last_seen
        self._recompute_metrics()

    def _recompute_metrics(self) -> None:
        """Recalculate pattern frequency, risk amplification, and urgency."""
        self.occurrence_count = len(self.affected_finding_ids)
        num_scans = len(self.scan_ids) or 1
        self.frequency = round(self.occurrence_count / num_scans, 4)
        target_count = len(self.targets)
        self.risk_amplification = _risk_amplification_factor(target_count)
        max_severity = 0.0
        for f in self.affected_findings:
            sev = _severity_from_str(f.severity)
            if sev.numeric > max_severity:
                max_severity = sev.numeric
        urgency = max_severity * self.risk_amplification * min(self.frequency, 1.0)
        self.remediation_urgency = round(min(10.0, urgency), 2)

    @property
    def duration_seconds(self) -> float:
        return max(0.0, self.last_occurrence - self.first_occurrence)

    @property
    def target_count(self) -> int:
        return len(set(self.targets))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pattern_id": self.pattern_id,
            "pattern_type": self.pattern_type,
            "description": self.description,
            "affected_finding_ids": list(self.affected_finding_ids),
            "first_occurrence": self.first_occurrence,
            "last_occurrence": self.last_occurrence,
            "occurrence_count": self.occurrence_count,
            "frequency": self.frequency,
            "risk_amplification": self.risk_amplification,
            "remediation_urgency": self.remediation_urgency,
            "scan_ids": list(self.scan_ids),
            "targets": list(self.targets),
            "vuln_types": list(self.vuln_types),
            "duration_seconds": self.duration_seconds,
            "target_count": self.target_count,
            "metadata": dict(self.metadata),
        }

    def __repr__(self) -> str:
        return (
            f"CrossScanPattern(id={self.pattern_id!r}, type={self.pattern_type}, "
            f"findings={self.occurrence_count}, urgency={self.remediation_urgency})"
        )


# ---------------------------------------------------------------------------
# Deduplication Engine
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class _DeduplicationStats:
    """Internal statistics tracker for the deduplication engine."""

    total_input: int = 0
    unique_output: int = 0
    duplicates_removed: int = 0
    merge_count: int = 0
    processing_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_input": self.total_input,
            "unique_output": self.unique_output,
            "duplicates_removed": self.duplicates_removed,
            "merge_count": self.merge_count,
            "processing_time_ms": round(self.processing_time_ms, 2),
        }


class DeduplicationEngine:
    """Intelligent finding deduplication engine.

    Combines content-based hashing with fuzzy matching to identify duplicate
    findings, then merges them according to a configurable strategy.

    Thread-safe: all public methods acquire the internal RLock.
    """

    def __init__(
        self,
        similarity_threshold: float = _DEFAULT_SIMILARITY_THRESHOLD,
        merge_strategy: Union[str, MergeStrategy] = MergeStrategy.KEEP_ALL_EVIDENCE,
    ) -> None:
        self._lock = threading.RLock()
        self._similarity_threshold = similarity_threshold
        if isinstance(merge_strategy, MergeStrategy):
            self._merge_strategy = merge_strategy
        else:
            self._merge_strategy = MergeStrategy(merge_strategy)
        self._stats = _DeduplicationStats()
        self._hash_index: Dict[str, List[Dict[str, Any]]] = {}
        logger.debug(
            "DeduplicationEngine initialized (threshold=%.2f, strategy=%s)",
            self._similarity_threshold,
            self._merge_strategy.value,
        )

    @property
    def similarity_threshold(self) -> float:
        return self._similarity_threshold

    @similarity_threshold.setter
    def similarity_threshold(self, value: float) -> None:
        with self._lock:
            self._similarity_threshold = max(0.0, min(1.0, value))

    @property
    def merge_strategy(self) -> MergeStrategy:
        return self._merge_strategy

    @merge_strategy.setter
    def merge_strategy(self, value: Union[str, MergeStrategy]) -> None:
        with self._lock:
            if isinstance(value, str):
                self._merge_strategy = MergeStrategy(value)
            else:
                self._merge_strategy = value

    def _compute_finding_hash(self, finding: Dict[str, Any]) -> str:
        """Compute DNA hash for a raw finding dict."""
        endpoint = str(_safe_get(finding, "endpoint", ""))
        vuln_type = str(_safe_get(finding, "vuln_type", ""))
        title = str(_safe_get(finding, "title", ""))
        return _compute_dna_hash(endpoint, vuln_type, title)

    def _findings_are_similar(
        self, a: Dict[str, Any], b: Dict[str, Any]
    ) -> Tuple[bool, float]:
        """Check if two findings are fuzzy-similar; returns (is_dup, score)."""
        endpoint_a = _normalize_url(str(_safe_get(a, "endpoint", "")))
        endpoint_b = _normalize_url(str(_safe_get(b, "endpoint", "")))
        endpoint_ratio = _fuzzy_ratio(endpoint_a, endpoint_b)

        vuln_a = _normalize_text(str(_safe_get(a, "vuln_type", "")))
        vuln_b = _normalize_text(str(_safe_get(b, "vuln_type", "")))
        vuln_ratio = _fuzzy_ratio(vuln_a, vuln_b)

        title_a = _normalize_text(str(_safe_get(a, "title", "")))
        title_b = _normalize_text(str(_safe_get(b, "title", "")))
        title_ratio = _fuzzy_ratio(title_a, title_b)

        evidence_a = _normalize_text(str(_safe_get(a, "evidence", "")))[:_MAX_EVIDENCE_COMPARE_LEN]
        evidence_b = _normalize_text(str(_safe_get(b, "evidence", "")))[:_MAX_EVIDENCE_COMPARE_LEN]
        evidence_ratio = _fuzzy_ratio(evidence_a, evidence_b)

        score = (
            endpoint_ratio * 0.4
            + vuln_ratio * 0.3
            + evidence_ratio * 0.2
            + title_ratio * 0.1
        )
        return score >= self._similarity_threshold, score

    def _merge_findings(
        self, primary: Dict[str, Any], duplicate: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Merge *duplicate* into *primary* according to the merge strategy."""
        merged = copy.deepcopy(primary)

        if self._merge_strategy == MergeStrategy.KEEP_MOST_DETAILED:
            primary_detail = sum(
                len(str(v)) for v in primary.values() if v is not None
            )
            dup_detail = sum(
                len(str(v)) for v in duplicate.values() if v is not None
            )
            if dup_detail > primary_detail:
                merged = copy.deepcopy(duplicate)
                merged.setdefault("_merged_from", [])
                merged["_merged_from"].append(copy.deepcopy(primary))
            else:
                merged.setdefault("_merged_from", [])
                merged["_merged_from"].append(copy.deepcopy(duplicate))

        elif self._merge_strategy == MergeStrategy.KEEP_MOST_RECENT:
            primary_ts = _safe_get(primary, "timestamp", 0)
            dup_ts = _safe_get(duplicate, "timestamp", 0)
            try:
                primary_ts = float(primary_ts) if primary_ts else 0.0
                dup_ts = float(dup_ts) if dup_ts else 0.0
            except (ValueError, TypeError):
                primary_ts = 0.0
                dup_ts = 0.0
            if dup_ts > primary_ts:
                merged = copy.deepcopy(duplicate)
                merged.setdefault("_merged_from", [])
                merged["_merged_from"].append(copy.deepcopy(primary))
            else:
                merged.setdefault("_merged_from", [])
                merged["_merged_from"].append(copy.deepcopy(duplicate))

        elif self._merge_strategy == MergeStrategy.KEEP_ALL_EVIDENCE:
            primary_evidence = _safe_get(primary, "evidence", "")
            dup_evidence = _safe_get(duplicate, "evidence", "")
            if isinstance(primary_evidence, list) and isinstance(dup_evidence, list):
                combined = list(primary_evidence)
                for item in dup_evidence:
                    if item not in combined:
                        combined.append(item)
                merged["evidence"] = combined
            elif isinstance(primary_evidence, list):
                if dup_evidence and dup_evidence not in primary_evidence:
                    merged["evidence"] = list(primary_evidence) + [dup_evidence]
            elif isinstance(dup_evidence, list):
                if primary_evidence:
                    combined = [primary_evidence]
                    for item in dup_evidence:
                        if item not in combined:
                            combined.append(item)
                    merged["evidence"] = combined
                else:
                    merged["evidence"] = list(dup_evidence)
            else:
                if primary_evidence and dup_evidence and primary_evidence != dup_evidence:
                    merged["evidence"] = [primary_evidence, dup_evidence]
                elif dup_evidence and not primary_evidence:
                    merged["evidence"] = dup_evidence

            primary_scans = _safe_get(primary, "scan_ids", [])
            dup_scans = _safe_get(duplicate, "scan_ids", [])
            if isinstance(primary_scans, list) and isinstance(dup_scans, list):
                combined_scans = list(primary_scans)
                for s in dup_scans:
                    if s not in combined_scans:
                        combined_scans.append(s)
                merged["scan_ids"] = combined_scans

            merged.setdefault("_merged_from", [])
            merged["_merged_from"].append(copy.deepcopy(duplicate))

        merged["_merge_count"] = merged.get("_merge_count", 0) + 1
        return merged

    def deduplicate(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Deduplicate a list of finding dicts.

        Args:
            findings: Raw finding dicts to deduplicate.

        Returns:
            Deduplicated list of finding dicts.
        """
        with self._lock:
            start_time = time.monotonic()
            self._stats.total_input += len(findings)
            self._hash_index.clear()

            if not findings:
                logger.debug("DeduplicationEngine: empty input, nothing to deduplicate")
                return []

            logger.info(
                "DeduplicationEngine: deduplicating %d findings (threshold=%.2f, strategy=%s)",
                len(findings),
                self._similarity_threshold,
                self._merge_strategy.value,
            )

            # Phase 1: exact hash grouping
            for finding in findings:
                h = self._compute_finding_hash(finding)
                if h not in self._hash_index:
                    self._hash_index[h] = []
                self._hash_index[h].append(finding)

            # Phase 2: merge exact duplicates within each hash bucket
            phase1_results: List[Dict[str, Any]] = []
            exact_merges = 0
            for h, group in self._hash_index.items():
                if len(group) == 1:
                    phase1_results.append(group[0])
                else:
                    merged = group[0]
                    for dup in group[1:]:
                        merged = self._merge_findings(merged, dup)
                        exact_merges += 1
                    phase1_results.append(merged)

            # Phase 3: fuzzy deduplication across remaining findings
            fuzzy_merges = 0
            deduplicated: List[Dict[str, Any]] = []
            used: List[bool] = [False] * len(phase1_results)

            for i in range(len(phase1_results)):
                if used[i]:
                    continue
                current = copy.deepcopy(phase1_results[i])
                for j in range(i + 1, len(phase1_results)):
                    if used[j]:
                        continue
                    is_dup, score = self._findings_are_similar(current, phase1_results[j])
                    if is_dup:
                        current = self._merge_findings(current, phase1_results[j])
                        used[j] = True
                        fuzzy_merges += 1
                deduplicated.append(current)

            total_merges = exact_merges + fuzzy_merges
            duplicates_removed = len(findings) - len(deduplicated)

            self._stats.unique_output += len(deduplicated)
            self._stats.duplicates_removed += duplicates_removed
            self._stats.merge_count += total_merges
            elapsed = (time.monotonic() - start_time) * 1000.0
            self._stats.processing_time_ms += elapsed

            logger.info(
                "DeduplicationEngine: %d -> %d findings (removed %d duplicates, "
                "%d exact merges, %d fuzzy merges, %.1fms)",
                len(findings),
                len(deduplicated),
                duplicates_removed,
                exact_merges,
                fuzzy_merges,
                elapsed,
            )

            return deduplicated

    def get_stats(self) -> Dict[str, Any]:
        """Return deduplication statistics."""
        with self._lock:
            return self._stats.to_dict()

    def reset_stats(self) -> None:
        """Reset all deduplication statistics."""
        with self._lock:
            self._stats = _DeduplicationStats()
            self._hash_index.clear()
            logger.debug("DeduplicationEngine: stats reset")

    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "similarity_threshold": self._similarity_threshold,
                "merge_strategy": self._merge_strategy.value,
                "stats": self._stats.to_dict(),
                "hash_index_size": len(self._hash_index),
            }

    def __repr__(self) -> str:
        return (
            f"DeduplicationEngine(threshold={self._similarity_threshold}, "
            f"strategy={self._merge_strategy.value}, "
            f"stats={self._stats.to_dict()})"
        )


# ---------------------------------------------------------------------------
# Built-in Correlation Rules
# ---------------------------------------------------------------------------


def _create_builtin_rules() -> List[CorrelationRule]:
    """Create the set of built-in correlation rules."""
    rules = []

    # Rule 1: Same endpoint, same vulnerability type (exact)
    rules.append(
        CorrelationRule(
            rule_id="builtin-same-endpoint-same-vuln",
            name="same_endpoint_same_vuln",
            description=(
                "Matches findings that target the exact same endpoint with the "
                "same vulnerability type. Strongest correlation signal."
            ),
            match_fields=["endpoint", "vuln_type"],
            similarity_threshold=0.90,
            field_weights={"endpoint": 0.5, "vuln_type": 0.5},
            rule_type=CorrelationRuleType.EXACT.value,
            enabled=True,
            priority=100,
            tags=["builtin", "exact", "high-confidence"],
        )
    )

    # Rule 2: Similar payload, different endpoint (fuzzy)
    rules.append(
        CorrelationRule(
            rule_id="builtin-similar-payload-diff-endpoint",
            name="similar_payload_different_endpoint",
            description=(
                "Matches findings with similar evidence/payload across different "
                "endpoints. Indicates a class of vulnerability or reused technique."
            ),
            match_fields=["evidence", "vuln_type", "title"],
            similarity_threshold=0.65,
            field_weights={"evidence": 0.5, "vuln_type": 0.35, "title": 0.15},
            rule_type=CorrelationRuleType.FUZZY.value,
            enabled=True,
            priority=50,
            tags=["builtin", "fuzzy", "payload-based"],
        )
    )

    # Rule 3: Same vulnerability family across targets (semantic)
    rules.append(
        CorrelationRule(
            rule_id="builtin-same-vuln-family-across-targets",
            name="same_vuln_family_across_targets",
            description=(
                "Matches findings of the same vulnerability family/class across "
                "multiple targets. Detects systemic weaknesses."
            ),
            match_fields=["vuln_type", "title", "endpoint"],
            similarity_threshold=0.55,
            field_weights={"vuln_type": 0.6, "title": 0.3, "endpoint": 0.1},
            rule_type=CorrelationRuleType.SEMANTIC.value,
            enabled=True,
            priority=30,
            tags=["builtin", "semantic", "systemic"],
        )
    )

    # Rule 4: Exact title match across endpoints (exact)
    rules.append(
        CorrelationRule(
            rule_id="builtin-exact-title-match",
            name="exact_title_across_endpoints",
            description=(
                "Matches findings with identical titles across different endpoints. "
                "Useful for detecting vulnerability scanners reporting the same issue."
            ),
            match_fields=["title", "vuln_type"],
            similarity_threshold=0.95,
            field_weights={"title": 0.7, "vuln_type": 0.3},
            rule_type=CorrelationRuleType.EXACT.value,
            enabled=True,
            priority=80,
            tags=["builtin", "exact", "title-based"],
        )
    )

    # Rule 5: Regex-based CVE correlation
    rules.append(
        CorrelationRule(
            rule_id="builtin-cve-regex-correlation",
            name="cve_regex_correlation",
            description=(
                "Matches findings referencing the same CVE identifiers via regex "
                "extraction from titles and evidence."
            ),
            match_fields=["title", "evidence"],
            similarity_threshold=0.80,
            field_weights={"title": 0.5, "evidence": 0.5},
            rule_type=CorrelationRuleType.REGEX.value,
            enabled=True,
            priority=70,
            tags=["builtin", "regex", "cve"],
        )
    )

    return rules


# ---------------------------------------------------------------------------
# SirenResultCorrelator — Main Orchestrator
# ---------------------------------------------------------------------------


class SirenResultCorrelator:
    """Cross-scan finding correlation, deduplication, and trend analysis engine.

    This is the main orchestrator that ties together the correlation rules,
    deduplication engine, and pattern detection to provide a comprehensive
    view of how vulnerabilities evolve across pentest scans.

    Thread-safe: all public methods acquire the internal RLock.

    Usage::

        correlator = SirenResultCorrelator()
        correlator.ingest_scan("scan-001", [
            {"title": "XSS in /login", "endpoint": "/login",
             "vuln_type": "XSS", "severity": "HIGH", "evidence": "<script>alert(1)</script>"},
        ])
        correlator.ingest_scan("scan-002", [
            {"title": "XSS in /login", "endpoint": "/login",
             "vuln_type": "XSS", "severity": "HIGH", "evidence": "<script>alert(2)</script>"},
        ])
        correlator.correlate()
        patterns = correlator.detect_patterns()
        report = correlator.generate_correlation_report()
    """

    def __init__(
        self,
        similarity_threshold: float = _DEFAULT_SIMILARITY_THRESHOLD,
        merge_strategy: Union[str, MergeStrategy] = MergeStrategy.KEEP_ALL_EVIDENCE,
        systemic_threshold: float = _DEFAULT_SYSTEMIC_THRESHOLD,
        custom_rules: Optional[List[CorrelationRule]] = None,
        enable_builtin_rules: bool = True,
    ) -> None:
        self._lock = threading.RLock()
        self._similarity_threshold = similarity_threshold
        self._systemic_threshold = systemic_threshold
        self._dedup_engine = DeduplicationEngine(
            similarity_threshold=similarity_threshold,
            merge_strategy=merge_strategy,
        )

        # Scan storage: scan_id -> (timestamp, list of finding dicts)
        self._scans: Dict[str, Tuple[float, List[Dict[str, Any]]]] = {}
        self._scan_order: List[str] = []  # preserves ingestion order

        # Correlation results
        self._correlated_findings: Dict[str, CorrelatedFinding] = {}
        self._patterns: List[CrossScanPattern] = []

        # Correlation rules
        self._rules: List[CorrelationRule] = []
        if enable_builtin_rules:
            self._rules.extend(_create_builtin_rules())
        if custom_rules:
            self._rules.extend(custom_rules)
        self._rules.sort(key=lambda r: r.priority, reverse=True)

        # State tracking
        self._is_correlated = False
        self._last_correlation_time: float = 0.0
        self._correlation_count: int = 0

        logger.info(
            "SirenResultCorrelator initialized (threshold=%.2f, systemic=%.2f, "
            "rules=%d, builtin=%s)",
            self._similarity_threshold,
            self._systemic_threshold,
            len(self._rules),
            enable_builtin_rules,
        )

    # ------------------------------------------------------------------
    # Rule management
    # ------------------------------------------------------------------

    def add_rule(self, rule: CorrelationRule) -> None:
        """Add a correlation rule and re-sort by priority."""
        with self._lock:
            self._rules.append(rule)
            self._rules.sort(key=lambda r: r.priority, reverse=True)
            self._is_correlated = False
            logger.info("Added correlation rule: %s (priority=%d)", rule.name, rule.priority)

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a correlation rule by ID. Returns True if found and removed."""
        with self._lock:
            before = len(self._rules)
            self._rules = [r for r in self._rules if r.rule_id != rule_id]
            removed = len(self._rules) < before
            if removed:
                self._is_correlated = False
                logger.info("Removed correlation rule: %s", rule_id)
            return removed

    def get_rules(self) -> List[CorrelationRule]:
        """Return a copy of the current rule list."""
        with self._lock:
            return list(self._rules)

    def enable_rule(self, rule_id: str) -> bool:
        """Enable a rule by ID. Returns True if found."""
        with self._lock:
            for rule in self._rules:
                if rule.rule_id == rule_id:
                    rule.enabled = True
                    self._is_correlated = False
                    logger.debug("Enabled rule: %s", rule_id)
                    return True
            return False

    def disable_rule(self, rule_id: str) -> bool:
        """Disable a rule by ID. Returns True if found."""
        with self._lock:
            for rule in self._rules:
                if rule.rule_id == rule_id:
                    rule.enabled = False
                    self._is_correlated = False
                    logger.debug("Disabled rule: %s", rule_id)
                    return True
            return False

    # ------------------------------------------------------------------
    # Scan ingestion
    # ------------------------------------------------------------------

    def ingest_scan(
        self,
        scan_id: str,
        findings: List[Dict[str, Any]],
        timestamp: Optional[float] = None,
        deduplicate: bool = True,
    ) -> int:
        """Ingest a scan's findings into the correlation pool.

        Args:
            scan_id: Unique identifier for this scan.
            findings: List of finding dicts. Each should have at minimum
                ``title``, ``endpoint``, ``vuln_type``, ``severity``.
            timestamp: Scan timestamp (defaults to current time).
            deduplicate: Whether to deduplicate findings before ingestion.

        Returns:
            Number of findings ingested (after optional deduplication).
        """
        with self._lock:
            ts = timestamp or _current_timestamp()
            if not findings:
                logger.warning("ingest_scan: scan '%s' has no findings, skipping", scan_id)
                return 0

            # Stamp each finding with scan metadata
            stamped: List[Dict[str, Any]] = []
            for idx, finding in enumerate(findings):
                f = copy.deepcopy(finding)
                f.setdefault("_scan_id", scan_id)
                f.setdefault("_scan_timestamp", ts)
                f.setdefault("_finding_index", idx)
                # Compute DNA hash if not present
                if "_dna_hash" not in f:
                    f["_dna_hash"] = _compute_dna_hash(
                        str(_safe_get(f, "endpoint", "")),
                        str(_safe_get(f, "vuln_type", "")),
                        str(_safe_get(f, "title", "")),
                    )
                stamped.append(f)

            if deduplicate:
                stamped = self._dedup_engine.deduplicate(stamped)

            # Store or append
            if scan_id in self._scans:
                existing_ts, existing_findings = self._scans[scan_id]
                existing_findings.extend(stamped)
                self._scans[scan_id] = (min(existing_ts, ts), existing_findings)
                logger.info(
                    "ingest_scan: appended %d findings to existing scan '%s' (total=%d)",
                    len(stamped),
                    scan_id,
                    len(existing_findings),
                )
            else:
                self._scans[scan_id] = (ts, stamped)
                self._scan_order.append(scan_id)
                logger.info(
                    "ingest_scan: ingested %d findings for new scan '%s'",
                    len(stamped),
                    scan_id,
                )

            self._is_correlated = False
            return len(stamped)

    def remove_scan(self, scan_id: str) -> bool:
        """Remove a scan from the correlation pool."""
        with self._lock:
            if scan_id in self._scans:
                del self._scans[scan_id]
                if scan_id in self._scan_order:
                    self._scan_order.remove(scan_id)
                self._is_correlated = False
                logger.info("Removed scan '%s' from correlation pool", scan_id)
                return True
            return False

    def get_scan_ids(self) -> List[str]:
        """Return ordered list of ingested scan IDs."""
        with self._lock:
            return list(self._scan_order)

    def get_scan_count(self) -> int:
        """Return number of ingested scans."""
        with self._lock:
            return len(self._scans)

    def get_total_finding_count(self) -> int:
        """Return total number of findings across all scans."""
        with self._lock:
            return sum(len(findings) for _, findings in self._scans.values())

    # ------------------------------------------------------------------
    # Correlation engine
    # ------------------------------------------------------------------

    def correlate(self) -> List[CorrelatedFinding]:
        """Run correlation across all ingested scans.

        Processes all findings through the enabled correlation rules to
        identify matching findings across scans, compute DNA hashes, and
        build the correlated finding registry.

        Returns:
            List of all correlated findings.
        """
        with self._lock:
            start_time = time.monotonic()
            logger.info(
                "correlate: starting correlation across %d scans (%d total findings)",
                len(self._scans),
                self.get_total_finding_count(),
            )

            self._correlated_findings.clear()
            self._patterns.clear()

            # Collect all findings with scan context
            all_findings: List[Tuple[str, float, Dict[str, Any]]] = []
            for scan_id in self._scan_order:
                if scan_id not in self._scans:
                    continue
                ts, findings = self._scans[scan_id]
                for f in findings:
                    all_findings.append((scan_id, ts, f))

            if not all_findings:
                logger.warning("correlate: no findings to correlate")
                self._is_correlated = True
                return []

            # Get enabled rules sorted by priority
            active_rules = [r for r in self._rules if r.enabled]
            if not active_rules:
                logger.warning("correlate: no enabled correlation rules")
                # Fall back to DNA hash correlation only
                active_rules = []

            # Build DNA hash index for fast exact matching
            dna_index: DefaultDict[str, List[int]] = collections.defaultdict(list)
            for idx, (scan_id, ts, finding) in enumerate(all_findings):
                dna = finding.get("_dna_hash", "")
                if not dna:
                    dna = _compute_dna_hash(
                        str(_safe_get(finding, "endpoint", "")),
                        str(_safe_get(finding, "vuln_type", "")),
                        str(_safe_get(finding, "title", "")),
                    )
                dna_index[dna].append(idx)

            # Phase 1: Group by exact DNA hash
            correlation_groups: List[List[int]] = []
            grouped_indices: Set[int] = set()

            for dna, indices in dna_index.items():
                if len(indices) > 1:
                    correlation_groups.append(indices)
                    grouped_indices.update(indices)

            # Phase 2: Fuzzy correlation for ungrouped findings
            ungrouped = [
                i for i in range(len(all_findings)) if i not in grouped_indices
            ]

            if active_rules and ungrouped:
                fuzzy_groups = self._fuzzy_correlate(
                    all_findings, ungrouped, active_rules
                )
                for group in fuzzy_groups:
                    correlation_groups.append(group)
                    grouped_indices.update(group)

            # Phase 3: Create CorrelatedFinding for each group
            for group in correlation_groups:
                if not group:
                    continue
                correlated = self._build_correlated_finding(all_findings, group, active_rules)
                self._correlated_findings[correlated.correlation_id] = correlated

            # Phase 4: Create singleton CorrelatedFinding for unmatched findings
            for idx in range(len(all_findings)):
                if idx not in grouped_indices:
                    scan_id, ts, finding = all_findings[idx]
                    correlated = self._build_singleton_finding(scan_id, ts, finding)
                    self._correlated_findings[correlated.correlation_id] = correlated

            # Phase 5: Compute trends
            self._compute_trends()

            elapsed = (time.monotonic() - start_time) * 1000.0
            self._is_correlated = True
            self._last_correlation_time = _current_timestamp()
            self._correlation_count += 1

            logger.info(
                "correlate: completed in %.1fms — %d correlated findings from "
                "%d groups + %d singletons",
                elapsed,
                len(self._correlated_findings),
                len(correlation_groups),
                len(self._correlated_findings) - len(correlation_groups),
            )

            return list(self._correlated_findings.values())

    def _fuzzy_correlate(
        self,
        all_findings: List[Tuple[str, float, Dict[str, Any]]],
        ungrouped: List[int],
        rules: List[CorrelationRule],
    ) -> List[List[int]]:
        """Fuzzy-correlate ungrouped findings using active rules.

        Uses a union-find approach: if finding A matches B and B matches C,
        then {A, B, C} form one group.
        """
        n = len(ungrouped)
        if n <= 1:
            return []

        # Union-find
        parent: Dict[int, int] = {idx: idx for idx in ungrouped}

        def find(x: int) -> int:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a: int, b: int) -> None:
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[ra] = rb

        # Compare all pairs using best-matching rule
        for i_pos in range(n):
            idx_a = ungrouped[i_pos]
            _, _, finding_a = all_findings[idx_a]
            for j_pos in range(i_pos + 1, n):
                idx_b = ungrouped[j_pos]
                _, _, finding_b = all_findings[idx_b]

                best_score = 0.0
                for rule in rules:
                    score = rule.compute_similarity(finding_a, finding_b)
                    if score > best_score:
                        best_score = score
                    if best_score >= rule.similarity_threshold:
                        break

                if best_score >= self._similarity_threshold:
                    union(idx_a, idx_b)

        # Collect groups
        groups_map: DefaultDict[int, List[int]] = collections.defaultdict(list)
        for idx in ungrouped:
            root = find(idx)
            groups_map[root].append(idx)

        # Only return groups with more than one member
        return [g for g in groups_map.values() if len(g) > 1]

    def _build_correlated_finding(
        self,
        all_findings: List[Tuple[str, float, Dict[str, Any]]],
        group: List[int],
        rules: List[CorrelationRule],
    ) -> CorrelatedFinding:
        """Build a CorrelatedFinding from a group of correlated finding indices."""
        # Use first finding as seed
        first_scan_id, first_ts, first_finding = all_findings[group[0]]

        title = str(_safe_get(first_finding, "title", ""))
        severity = str(_safe_get(first_finding, "severity", "INFO"))
        endpoint = str(_safe_get(first_finding, "endpoint", ""))
        vuln_type = str(_safe_get(first_finding, "vuln_type", ""))
        evidence_raw = _safe_get(first_finding, "evidence", "")

        correlated = CorrelatedFinding(
            title=title,
            severity=severity,
            endpoint=endpoint,
            vuln_type=vuln_type,
            dna_hash=first_finding.get("_dna_hash", _compute_dna_hash(endpoint, vuln_type, title)),
        )

        # Accumulate data from all findings in the group
        confidence_scores: List[float] = []
        for idx in group:
            scan_id, ts, finding = all_findings[idx]
            correlated.add_scan(scan_id, ts)
            correlated.original_findings.append(copy.deepcopy(finding))

            # Evidence
            ev = _safe_get(finding, "evidence", "")
            if isinstance(ev, list):
                for snippet in ev:
                    correlated.add_evidence(str(snippet))
            elif ev:
                correlated.add_evidence(str(ev))

            # Target extraction
            target = _safe_get(finding, "target", "") or _safe_get(finding, "host", "")
            if not target:
                parsed_endpoint = _safe_get(finding, "endpoint", "")
                if isinstance(parsed_endpoint, str) and re.match(
                    r"^https?://", parsed_endpoint, re.IGNORECASE
                ):
                    parsed = urlparse(parsed_endpoint)
                    target = parsed.hostname or ""
            if target:
                correlated.add_target(str(target))

            # Tags
            tags = _safe_get(finding, "tags", [])
            if isinstance(tags, list):
                for tag in tags:
                    if tag and tag not in correlated.tags:
                        correlated.tags.append(str(tag))

            # Remediation
            remediation = _safe_get(finding, "remediation", "")
            if remediation:
                if correlated.remediation_notes:
                    if str(remediation) not in correlated.remediation_notes:
                        correlated.remediation_notes += "\n" + str(remediation)
                else:
                    correlated.remediation_notes = str(remediation)

            # Severity: keep highest
            finding_sev = _severity_from_str(str(_safe_get(finding, "severity", "INFO")))
            current_sev = _severity_from_str(correlated.severity)
            if finding_sev.numeric > current_sev.numeric:
                correlated.severity = finding_sev.value

            # Compute pairwise confidence against the seed finding
            if idx != group[0] and rules:
                best = 0.0
                for rule in rules:
                    score = rule.compute_similarity(first_finding, finding)
                    if score > best:
                        best = score
                confidence_scores.append(best)

        if confidence_scores:
            correlated.confidence = round(
                sum(confidence_scores) / len(confidence_scores), 4
            )
        else:
            correlated.confidence = 1.0

        correlated._recompute_risk_score()
        return correlated

    def _build_singleton_finding(
        self, scan_id: str, ts: float, finding: Dict[str, Any]
    ) -> CorrelatedFinding:
        """Build a CorrelatedFinding from a single unmatched finding."""
        title = str(_safe_get(finding, "title", ""))
        severity = str(_safe_get(finding, "severity", "INFO"))
        endpoint = str(_safe_get(finding, "endpoint", ""))
        vuln_type = str(_safe_get(finding, "vuln_type", ""))

        correlated = CorrelatedFinding(
            title=title,
            severity=severity,
            endpoint=endpoint,
            vuln_type=vuln_type,
            dna_hash=finding.get("_dna_hash", _compute_dna_hash(endpoint, vuln_type, title)),
            confidence=1.0,
        )
        correlated.add_scan(scan_id, ts)
        correlated.original_findings.append(copy.deepcopy(finding))

        ev = _safe_get(finding, "evidence", "")
        if isinstance(ev, list):
            for snippet in ev:
                correlated.add_evidence(str(snippet))
        elif ev:
            correlated.add_evidence(str(ev))

        target = _safe_get(finding, "target", "") or _safe_get(finding, "host", "")
        if not target and isinstance(endpoint, str) and re.match(
            r"^https?://", endpoint, re.IGNORECASE
        ):
            parsed = urlparse(endpoint)
            target = parsed.hostname or ""
        if target:
            correlated.add_target(str(target))

        tags = _safe_get(finding, "tags", [])
        if isinstance(tags, list):
            for tag in tags:
                if tag:
                    correlated.tags.append(str(tag))

        remediation = _safe_get(finding, "remediation", "")
        if remediation:
            correlated.remediation_notes = str(remediation)

        correlated._recompute_risk_score()
        return correlated

    # ------------------------------------------------------------------
    # Trend detection
    # ------------------------------------------------------------------

    def _compute_trends(self) -> None:
        """Compute trend classification for each correlated finding.

        Compares finding presence across ordered scans to classify each
        finding as NEW, PERSISTENT, FIXED, REGRESSED, or FLAPPING.
        """
        if len(self._scan_order) < 2:
            for cf in self._correlated_findings.values():
                cf.trend = FindingTrend.NEW.value
            return

        # Build per-scan DNA sets for quick lookup
        scan_dna_sets: Dict[str, Set[str]] = {}
        for scan_id in self._scan_order:
            if scan_id not in self._scans:
                continue
            _, findings = self._scans[scan_id]
            dna_set: Set[str] = set()
            for f in findings:
                dna = f.get("_dna_hash", "")
                if dna:
                    dna_set.add(dna)
            scan_dna_sets[scan_id] = dna_set

        ordered_scans = [s for s in self._scan_order if s in scan_dna_sets]
        if len(ordered_scans) < 2:
            for cf in self._correlated_findings.values():
                cf.trend = FindingTrend.NEW.value
            return

        for cf in self._correlated_findings.values():
            dna = cf.dna_hash
            if not dna:
                cf.trend = FindingTrend.UNKNOWN.value
                continue

            # Build presence timeline
            presence: List[bool] = []
            for scan_id in ordered_scans:
                present = dna in scan_dna_sets.get(scan_id, set())
                presence.append(present)

            trend = self._classify_trend(presence)
            cf.trend = trend.value

    def _classify_trend(self, presence: List[bool]) -> FindingTrend:
        """Classify trend from a boolean presence timeline.

        Args:
            presence: Ordered list of booleans indicating presence in each scan.

        Returns:
            FindingTrend classification.
        """
        if not presence:
            return FindingTrend.UNKNOWN

        if len(presence) == 1:
            return FindingTrend.NEW if presence[0] else FindingTrend.UNKNOWN

        # Check for flapping: count state transitions
        transitions = 0
        for i in range(1, len(presence)):
            if presence[i] != presence[i - 1]:
                transitions += 1

        window = min(len(presence), _FLAPPING_WINDOW)
        recent = presence[-window:]
        recent_transitions = sum(
            1 for i in range(1, len(recent)) if recent[i] != recent[i - 1]
        )

        if recent_transitions >= _FLAPPING_MIN_FLIPS or (
            len(presence) >= 4 and transitions >= _FLAPPING_MIN_FLIPS
        ):
            return FindingTrend.FLAPPING

        last = presence[-1]
        second_last = presence[-2]

        if last and not second_last:
            # Was absent, now present: could be NEW or REGRESSED
            any_previous = any(presence[:-1])
            if any_previous:
                return FindingTrend.REGRESSED
            else:
                return FindingTrend.NEW

        if last and second_last:
            return FindingTrend.PERSISTENT

        if not last and second_last:
            return FindingTrend.FIXED

        if not last and not second_last:
            # Not present in recent scans
            any_previous = any(presence)
            if any_previous:
                return FindingTrend.FIXED
            return FindingTrend.UNKNOWN

        return FindingTrend.UNKNOWN

    # ------------------------------------------------------------------
    # Pattern detection
    # ------------------------------------------------------------------

    def detect_patterns(self) -> List[CrossScanPattern]:
        """Detect cross-scan patterns from correlated findings.

        Must be called after ``correlate()``. Detects recurring vulns,
        spreading vulns, regressions, confirmed fixes, and systemic
        weaknesses.

        Returns:
            List of detected CrossScanPattern instances.
        """
        with self._lock:
            if not self._is_correlated:
                logger.warning("detect_patterns: must call correlate() first")
                return []

            start_time = time.monotonic()
            logger.info("detect_patterns: analyzing %d correlated findings", len(self._correlated_findings))

            self._patterns.clear()
            findings_list = list(self._correlated_findings.values())

            # Detect each pattern type
            self._detect_recurring_vulns(findings_list)
            self._detect_spreading_vulns(findings_list)
            self._detect_regressions(findings_list)
            self._detect_confirmed_fixes(findings_list)
            self._detect_systemic_weaknesses(findings_list)

            elapsed = (time.monotonic() - start_time) * 1000.0
            logger.info(
                "detect_patterns: found %d patterns in %.1fms",
                len(self._patterns),
                elapsed,
            )
            return list(self._patterns)

    def _detect_recurring_vulns(self, findings: List[CorrelatedFinding]) -> None:
        """Detect findings that recur across multiple scans."""
        for cf in findings:
            if cf.scan_count >= 2 and cf.trend == FindingTrend.PERSISTENT.value:
                pattern = CrossScanPattern(
                    pattern_type=CrossScanPatternType.RECURRING_VULN.value,
                    description=(
                        f"Recurring vulnerability: '{_truncate(cf.title, 80)}' "
                        f"detected in {cf.scan_count} consecutive scans"
                    ),
                )
                pattern.add_finding(cf)
                self._patterns.append(pattern)

    def _detect_spreading_vulns(self, findings: List[CorrelatedFinding]) -> None:
        """Detect vulnerabilities spreading to new targets over time."""
        # Group by vuln_type
        vuln_groups: DefaultDict[str, List[CorrelatedFinding]] = collections.defaultdict(list)
        for cf in findings:
            if cf.vuln_type:
                vuln_groups[_normalize_text(cf.vuln_type)].append(cf)

        for vuln_type, group in vuln_groups.items():
            if len(group) < 2:
                continue

            # Check if the set of affected targets is growing
            all_targets: Set[str] = set()
            for cf in group:
                all_targets.update(cf.affected_targets)

            if len(all_targets) >= 2:
                # Check temporal spread: are findings in later scans hitting new targets?
                sorted_by_first_seen = sorted(group, key=lambda f: f.first_seen)
                targets_over_time: List[Set[str]] = []
                seen_targets: Set[str] = set()
                is_spreading = False

                for cf in sorted_by_first_seen:
                    new_targets = set(cf.affected_targets) - seen_targets
                    if new_targets and seen_targets:
                        is_spreading = True
                    seen_targets.update(cf.affected_targets)
                    targets_over_time.append(set(cf.affected_targets))

                if is_spreading:
                    pattern = CrossScanPattern(
                        pattern_type=CrossScanPatternType.SPREADING_VULN.value,
                        description=(
                            f"Spreading vulnerability: '{vuln_type}' expanded from "
                            f"initial targets to {len(all_targets)} total targets"
                        ),
                    )
                    for cf in group:
                        pattern.add_finding(cf)
                    self._patterns.append(pattern)

    def _detect_regressions(self, findings: List[CorrelatedFinding]) -> None:
        """Detect findings that were fixed but reappeared (REGRESSED)."""
        for cf in findings:
            if cf.trend == FindingTrend.REGRESSED.value:
                pattern = CrossScanPattern(
                    pattern_type=CrossScanPatternType.REGRESSION.value,
                    description=(
                        f"Regression detected: '{_truncate(cf.title, 80)}' was "
                        f"previously fixed but has reappeared"
                    ),
                )
                pattern.add_finding(cf)
                self._patterns.append(pattern)

    def _detect_confirmed_fixes(self, findings: List[CorrelatedFinding]) -> None:
        """Detect findings confirmed as fixed (present then absent)."""
        for cf in findings:
            if cf.trend == FindingTrend.FIXED.value and cf.scan_count >= 2:
                pattern = CrossScanPattern(
                    pattern_type=CrossScanPatternType.FIX_CONFIRMED.value,
                    description=(
                        f"Fix confirmed: '{_truncate(cf.title, 80)}' was present "
                        f"in {cf.scan_count} scan(s) and is now resolved"
                    ),
                )
                pattern.add_finding(cf)
                self._patterns.append(pattern)

    def _detect_systemic_weaknesses(self, findings: List[CorrelatedFinding]) -> None:
        """Detect vulnerability types that appear across a high percentage of targets.

        If the same vuln_type appears in > systemic_threshold fraction of all
        scanned targets, it is flagged as a systemic weakness.
        """
        # Collect all distinct targets
        all_targets: Set[str] = set()
        for cf in findings:
            all_targets.update(cf.affected_targets)

        if not all_targets:
            # Fall back to using scan count
            total_scans = len(self._scan_order)
            if total_scans < 2:
                return

            vuln_scan_sets: DefaultDict[str, Set[str]] = collections.defaultdict(set)
            for cf in findings:
                if cf.vuln_type:
                    key = _normalize_text(cf.vuln_type)
                    vuln_scan_sets[key].update(cf.scan_ids)

            for vuln_type, scan_set in vuln_scan_sets.items():
                ratio = len(scan_set) / total_scans
                if ratio >= self._systemic_threshold:
                    related = [
                        cf
                        for cf in findings
                        if _normalize_text(cf.vuln_type) == vuln_type
                    ]
                    pattern = CrossScanPattern(
                        pattern_type=CrossScanPatternType.SYSTEMIC_WEAKNESS.value,
                        description=(
                            f"Systemic weakness: '{vuln_type}' detected in "
                            f"{len(scan_set)}/{total_scans} scans "
                            f"({ratio:.0%} prevalence)"
                        ),
                    )
                    for cf in related:
                        pattern.add_finding(cf)
                    pattern.metadata["prevalence_ratio"] = round(ratio, 4)
                    pattern.metadata["detection_basis"] = "scan_coverage"
                    self._patterns.append(pattern)
            return

        total_targets = len(all_targets)
        if total_targets < 2:
            return

        # Group findings by normalized vuln_type
        vuln_target_sets: DefaultDict[str, Set[str]] = collections.defaultdict(set)
        vuln_findings: DefaultDict[str, List[CorrelatedFinding]] = collections.defaultdict(list)

        for cf in findings:
            if cf.vuln_type:
                key = _normalize_text(cf.vuln_type)
                vuln_target_sets[key].update(cf.affected_targets)
                vuln_findings[key].append(cf)

        for vuln_type, target_set in vuln_target_sets.items():
            ratio = len(target_set) / total_targets
            if ratio >= self._systemic_threshold:
                pattern = CrossScanPattern(
                    pattern_type=CrossScanPatternType.SYSTEMIC_WEAKNESS.value,
                    description=(
                        f"Systemic weakness: '{vuln_type}' affects "
                        f"{len(target_set)}/{total_targets} targets "
                        f"({ratio:.0%} prevalence)"
                    ),
                )
                for cf in vuln_findings[vuln_type]:
                    pattern.add_finding(cf)
                pattern.metadata["prevalence_ratio"] = round(ratio, 4)
                pattern.metadata["affected_target_count"] = len(target_set)
                pattern.metadata["total_target_count"] = total_targets
                pattern.metadata["detection_basis"] = "target_coverage"
                self._patterns.append(pattern)

    # ------------------------------------------------------------------
    # Query methods
    # ------------------------------------------------------------------

    def get_correlated_findings(self) -> List[CorrelatedFinding]:
        """Return all correlated findings."""
        with self._lock:
            return list(self._correlated_findings.values())

    def get_correlated_finding_by_id(
        self, correlation_id: str
    ) -> Optional[CorrelatedFinding]:
        """Retrieve a single correlated finding by its correlation ID."""
        with self._lock:
            return self._correlated_findings.get(correlation_id)

    def get_findings_by_trend(self, trend: Union[str, FindingTrend]) -> List[CorrelatedFinding]:
        """Return all correlated findings matching a given trend."""
        with self._lock:
            if isinstance(trend, FindingTrend):
                trend_val = trend.value
            else:
                trend_val = trend.upper()
            return [
                cf
                for cf in self._correlated_findings.values()
                if cf.trend == trend_val
            ]

    def get_findings_by_severity(
        self, severity: Union[str, SeverityLevel]
    ) -> List[CorrelatedFinding]:
        """Return all correlated findings matching a given severity."""
        with self._lock:
            if isinstance(severity, SeverityLevel):
                sev_val = severity.value
            else:
                sev_val = severity.upper()
            return [
                cf
                for cf in self._correlated_findings.values()
                if cf.severity.upper() == sev_val
            ]

    def get_findings_by_vuln_type(self, vuln_type: str) -> List[CorrelatedFinding]:
        """Return all correlated findings of a given vulnerability type."""
        with self._lock:
            norm = _normalize_text(vuln_type)
            return [
                cf
                for cf in self._correlated_findings.values()
                if _normalize_text(cf.vuln_type) == norm
            ]

    def get_patterns(self) -> List[CrossScanPattern]:
        """Return all detected cross-scan patterns."""
        with self._lock:
            return list(self._patterns)

    def get_patterns_by_type(
        self, pattern_type: Union[str, CrossScanPatternType]
    ) -> List[CrossScanPattern]:
        """Return patterns of a specific type."""
        with self._lock:
            if isinstance(pattern_type, CrossScanPatternType):
                pt_val = pattern_type.value
            else:
                pt_val = pattern_type.upper()
            return [p for p in self._patterns if p.pattern_type == pt_val]

    def get_systemic_weaknesses(self) -> List[CrossScanPattern]:
        """Return all patterns classified as systemic weaknesses."""
        with self._lock:
            return [
                p
                for p in self._patterns
                if p.pattern_type == CrossScanPatternType.SYSTEMIC_WEAKNESS.value
            ]

    def get_regressions(self) -> List[CorrelatedFinding]:
        """Return all findings that have regressed (were fixed, reappeared)."""
        with self._lock:
            return self.get_findings_by_trend(FindingTrend.REGRESSED)

    def get_fixed_findings(self) -> List[CorrelatedFinding]:
        """Return all findings confirmed as fixed."""
        with self._lock:
            return self.get_findings_by_trend(FindingTrend.FIXED)

    def get_new_findings(self) -> List[CorrelatedFinding]:
        """Return all findings classified as new."""
        with self._lock:
            return self.get_findings_by_trend(FindingTrend.NEW)

    def get_persistent_findings(self) -> List[CorrelatedFinding]:
        """Return all findings that persist across scans."""
        with self._lock:
            return self.get_findings_by_trend(FindingTrend.PERSISTENT)

    def get_flapping_findings(self) -> List[CorrelatedFinding]:
        """Return all findings with a flapping trend."""
        with self._lock:
            return self.get_findings_by_trend(FindingTrend.FLAPPING)

    # ------------------------------------------------------------------
    # Deduplication pass-through
    # ------------------------------------------------------------------

    def deduplicate(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Deduplicate a list of raw finding dicts using the internal engine.

        Args:
            findings: List of finding dicts.

        Returns:
            Deduplicated list.
        """
        with self._lock:
            return self._dedup_engine.deduplicate(findings)

    def get_deduplication_stats(self) -> Dict[str, Any]:
        """Return deduplication engine statistics."""
        with self._lock:
            return self._dedup_engine.get_stats()

    # ------------------------------------------------------------------
    # Trend analysis
    # ------------------------------------------------------------------

    def get_trend_analysis(self) -> Dict[str, Any]:
        """Produce a comprehensive trend analysis across all correlated findings.

        Returns a dict with trend distribution, severity breakdown, timeline,
        risk summary, and actionable insights.
        """
        with self._lock:
            if not self._is_correlated:
                logger.warning("get_trend_analysis: must call correlate() first")
                return {"error": "Correlation not yet performed. Call correlate() first."}

            findings = list(self._correlated_findings.values())
            total = len(findings)

            if total == 0:
                return {
                    "total_findings": 0,
                    "trend_distribution": {},
                    "severity_distribution": {},
                    "risk_summary": {},
                    "insights": [],
                }

            # Trend distribution
            trend_dist: Counter[str] = collections.Counter()
            for cf in findings:
                trend_dist[cf.trend] += 1

            # Severity distribution
            sev_dist: Counter[str] = collections.Counter()
            for cf in findings:
                sev_dist[cf.severity] += 1

            # Severity x Trend matrix
            sev_trend_matrix: DefaultDict[str, Counter[str]] = collections.defaultdict(
                collections.Counter
            )
            for cf in findings:
                sev_trend_matrix[cf.severity][cf.trend] += 1

            # Risk summary
            total_risk = sum(cf.risk_score for cf in findings)
            avg_risk = total_risk / total if total else 0.0
            max_risk_finding = max(findings, key=lambda f: f.risk_score) if findings else None
            amplified_count = sum(1 for cf in findings if cf.amplification_factor > 1.0)

            # Timeline: findings per scan
            scan_timeline: List[Dict[str, Any]] = []
            for scan_id in self._scan_order:
                scan_findings = [cf for cf in findings if scan_id in cf.scan_ids]
                scan_sev: Counter[str] = collections.Counter()
                for cf in scan_findings:
                    scan_sev[cf.severity] += 1
                ts = self._scans[scan_id][0] if scan_id in self._scans else 0.0
                scan_timeline.append(
                    {
                        "scan_id": scan_id,
                        "timestamp": ts,
                        "finding_count": len(scan_findings),
                        "severity_breakdown": dict(scan_sev),
                    }
                )

            # Top vulnerability types
            vuln_counter: Counter[str] = collections.Counter()
            for cf in findings:
                if cf.vuln_type:
                    vuln_counter[_normalize_text(cf.vuln_type)] += 1

            # Generate insights
            insights: List[str] = []
            persistent_count = trend_dist.get(FindingTrend.PERSISTENT.value, 0)
            if persistent_count > 0:
                insights.append(
                    f"{persistent_count} finding(s) persist across multiple scans and "
                    f"require immediate remediation attention."
                )
            regressed_count = trend_dist.get(FindingTrend.REGRESSED.value, 0)
            if regressed_count > 0:
                insights.append(
                    f"{regressed_count} finding(s) have regressed — previously fixed "
                    f"vulnerabilities have reappeared. Review deployment/patching pipeline."
                )
            flapping_count = trend_dist.get(FindingTrend.FLAPPING.value, 0)
            if flapping_count > 0:
                insights.append(
                    f"{flapping_count} finding(s) are flapping (intermittent). This may "
                    f"indicate unstable fixes or environment-dependent issues."
                )
            fixed_count = trend_dist.get(FindingTrend.FIXED.value, 0)
            if fixed_count > 0:
                insights.append(
                    f"{fixed_count} finding(s) have been confirmed fixed. Good progress."
                )
            new_count = trend_dist.get(FindingTrend.NEW.value, 0)
            if new_count > 0:
                insights.append(
                    f"{new_count} new finding(s) detected in the latest scan(s)."
                )
            if amplified_count > 0:
                insights.append(
                    f"{amplified_count} finding(s) have amplified risk scores due to "
                    f"multi-target presence."
                )

            critical_persistent = sum(
                1
                for cf in findings
                if cf.severity == SeverityLevel.CRITICAL.value
                and cf.trend == FindingTrend.PERSISTENT.value
            )
            if critical_persistent > 0:
                insights.append(
                    f"URGENT: {critical_persistent} CRITICAL finding(s) remain unresolved "
                    f"across multiple scans."
                )

            systemic_patterns = self.get_systemic_weaknesses()
            if systemic_patterns:
                insights.append(
                    f"{len(systemic_patterns)} systemic weakness pattern(s) detected. "
                    f"Organization-wide remediation recommended."
                )

            return {
                "total_findings": total,
                "total_scans": len(self._scan_order),
                "trend_distribution": dict(trend_dist),
                "severity_distribution": dict(sev_dist),
                "severity_trend_matrix": {
                    sev: dict(trends) for sev, trends in sev_trend_matrix.items()
                },
                "risk_summary": {
                    "total_risk_score": round(total_risk, 2),
                    "average_risk_score": round(avg_risk, 2),
                    "max_risk_score": round(max_risk_finding.risk_score, 2) if max_risk_finding else 0.0,
                    "max_risk_finding_title": max_risk_finding.title if max_risk_finding else "",
                    "amplified_finding_count": amplified_count,
                },
                "scan_timeline": scan_timeline,
                "top_vulnerability_types": vuln_counter.most_common(10),
                "insights": insights,
                "last_correlation_time": self._last_correlation_time,
                "correlation_count": self._correlation_count,
            }

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def generate_correlation_report(self) -> str:
        """Generate a Markdown report of all correlations, trends, and patterns.

        Returns:
            Markdown-formatted report string.
        """
        with self._lock:
            if not self._is_correlated:
                return "# Correlation Report\n\n**Error:** Correlation has not been performed. Call `correlate()` first.\n"

            lines: List[str] = []
            lines.append("# SIREN Result Correlation Report")
            lines.append("")
            lines.append(f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
            lines.append(f"**Scans Analyzed:** {len(self._scan_order)}")
            lines.append(f"**Total Correlated Findings:** {len(self._correlated_findings)}")
            lines.append(f"**Patterns Detected:** {len(self._patterns)}")
            lines.append("")
            lines.append(_REPORT_SEPARATOR)
            lines.append("")

            # Executive Summary
            analysis = self.get_trend_analysis()
            lines.append("## Executive Summary")
            lines.append("")
            trend_dist = analysis.get("trend_distribution", {})
            for trend_name in [
                FindingTrend.NEW.value,
                FindingTrend.PERSISTENT.value,
                FindingTrend.REGRESSED.value,
                FindingTrend.FIXED.value,
                FindingTrend.FLAPPING.value,
            ]:
                count = trend_dist.get(trend_name, 0)
                if count > 0:
                    lines.append(f"- **{trend_name}**: {count} finding(s)")
            lines.append("")

            risk_summary = analysis.get("risk_summary", {})
            if risk_summary:
                lines.append(f"- **Total Risk Score:** {risk_summary.get('total_risk_score', 0)}")
                lines.append(f"- **Average Risk Score:** {risk_summary.get('average_risk_score', 0)}")
                lines.append(f"- **Max Risk Score:** {risk_summary.get('max_risk_score', 0)}")
                if risk_summary.get("max_risk_finding_title"):
                    lines.append(
                        f"  - Finding: {_truncate(risk_summary['max_risk_finding_title'], 80)}"
                    )
                lines.append("")

            # Insights
            insights = analysis.get("insights", [])
            if insights:
                lines.append("### Key Insights")
                lines.append("")
                for insight in insights:
                    lines.append(f"- {insight}")
                lines.append("")

            lines.append(_REPORT_SEPARATOR)
            lines.append("")

            # Severity breakdown
            lines.append("## Severity Distribution")
            lines.append("")
            sev_dist = analysis.get("severity_distribution", {})
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                count = sev_dist.get(sev, 0)
                if count > 0:
                    lines.append(f"- **{sev}**: {count}")
            lines.append("")

            lines.append(_REPORT_SEPARATOR)
            lines.append("")

            # Correlated Findings Table
            lines.append("## Correlated Findings")
            lines.append("")

            # Sort by risk score descending
            sorted_findings = sorted(
                self._correlated_findings.values(),
                key=lambda f: f.risk_score,
                reverse=True,
            )

            if sorted_findings:
                lines.append(
                    "| # | Title | Severity | Trend | Scans | Targets | Risk | Confidence |"
                )
                lines.append(
                    "|---|-------|----------|-------|-------|---------|------|------------|"
                )
                for idx, cf in enumerate(sorted_findings, 1):
                    title_short = _truncate(cf.title, 40)
                    lines.append(
                        f"| {idx} | {title_short} | {cf.severity} | {cf.trend} | "
                        f"{cf.scan_count} | {cf.target_count} | {cf.risk_score} | "
                        f"{cf.confidence:.2f} |"
                    )
                lines.append("")
            else:
                lines.append("*No correlated findings.*")
                lines.append("")

            lines.append(_REPORT_SEPARATOR)
            lines.append("")

            # Findings detail sections by trend
            for trend in [
                FindingTrend.REGRESSED,
                FindingTrend.PERSISTENT,
                FindingTrend.FLAPPING,
                FindingTrend.NEW,
                FindingTrend.FIXED,
            ]:
                trend_findings = [
                    cf for cf in sorted_findings if cf.trend == trend.value
                ]
                if not trend_findings:
                    continue

                lines.append(f"### {trend.value} Findings ({len(trend_findings)})")
                lines.append("")
                for cf in trend_findings:
                    lines.append(f"#### {_truncate(cf.title, 80)}")
                    lines.append("")
                    lines.append(f"- **Correlation ID:** `{cf.correlation_id}`")
                    lines.append(f"- **Severity:** {cf.severity}")
                    lines.append(f"- **Vulnerability Type:** {cf.vuln_type or 'N/A'}")
                    lines.append(f"- **Endpoint:** `{cf.endpoint or 'N/A'}`")
                    lines.append(f"- **Risk Score:** {cf.risk_score} (amplification: {cf.amplification_factor}x)")
                    lines.append(f"- **Confidence:** {cf.confidence:.2f}")
                    lines.append(f"- **Seen in Scans:** {', '.join(cf.scan_ids)}")
                    if cf.affected_targets:
                        lines.append(f"- **Affected Targets:** {', '.join(cf.affected_targets)}")
                    if cf.evidence:
                        lines.append(f"- **Evidence Snippets:** {len(cf.evidence)}")
                        for ev_idx, ev in enumerate(cf.evidence[:5], 1):
                            lines.append(f"  {ev_idx}. `{_truncate(str(ev), 100)}`")
                    if cf.remediation_notes:
                        lines.append(f"- **Remediation:** {_truncate(cf.remediation_notes, 200)}")
                    lines.append("")
                lines.append("")

            lines.append(_REPORT_SEPARATOR)
            lines.append("")

            # Cross-Scan Patterns
            lines.append("## Cross-Scan Patterns")
            lines.append("")
            if self._patterns:
                for idx, pattern in enumerate(self._patterns, 1):
                    lines.append(f"### Pattern {idx}: {pattern.pattern_type}")
                    lines.append("")
                    lines.append(f"- **Description:** {pattern.description}")
                    lines.append(f"- **Affected Findings:** {pattern.occurrence_count}")
                    lines.append(f"- **Risk Amplification:** {pattern.risk_amplification}x")
                    lines.append(f"- **Remediation Urgency:** {pattern.remediation_urgency}/10.0")
                    lines.append(f"- **Frequency:** {pattern.frequency:.4f}")
                    if pattern.targets:
                        lines.append(f"- **Targets:** {', '.join(pattern.targets[:10])}")
                    if pattern.vuln_types:
                        lines.append(f"- **Vuln Types:** {', '.join(pattern.vuln_types)}")
                    lines.append("")
            else:
                lines.append("*No cross-scan patterns detected.*")
                lines.append("")

            lines.append(_REPORT_SEPARATOR)
            lines.append("")

            # Scan Timeline
            lines.append("## Scan Timeline")
            lines.append("")
            timeline = analysis.get("scan_timeline", [])
            if timeline:
                lines.append("| Scan ID | Timestamp | Findings | Severities |")
                lines.append("|---------|-----------|----------|------------|")
                for entry in timeline:
                    ts_str = time.strftime(
                        "%Y-%m-%d %H:%M",
                        time.gmtime(entry.get("timestamp", 0)),
                    )
                    sev_parts = []
                    for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                        c = entry.get("severity_breakdown", {}).get(s, 0)
                        if c > 0:
                            sev_parts.append(f"{s}:{c}")
                    sev_str = ", ".join(sev_parts) if sev_parts else "N/A"
                    lines.append(
                        f"| {_truncate(entry['scan_id'], 30)} | {ts_str} | "
                        f"{entry.get('finding_count', 0)} | {sev_str} |"
                    )
                lines.append("")
            else:
                lines.append("*No scan timeline data available.*")
                lines.append("")

            lines.append(_REPORT_SEPARATOR)
            lines.append("")

            # Top vulnerability types
            top_vulns = analysis.get("top_vulnerability_types", [])
            if top_vulns:
                lines.append("## Top Vulnerability Types")
                lines.append("")
                for vt, count in top_vulns:
                    lines.append(f"- **{vt}**: {count} occurrence(s)")
                lines.append("")

            # Deduplication stats
            dedup_stats = self._dedup_engine.get_stats()
            lines.append("## Deduplication Statistics")
            lines.append("")
            lines.append(f"- **Total Input:** {dedup_stats.get('total_input', 0)}")
            lines.append(f"- **Unique Output:** {dedup_stats.get('unique_output', 0)}")
            lines.append(f"- **Duplicates Removed:** {dedup_stats.get('duplicates_removed', 0)}")
            lines.append(f"- **Merge Count:** {dedup_stats.get('merge_count', 0)}")
            lines.append(
                f"- **Processing Time:** {dedup_stats.get('processing_time_ms', 0):.1f}ms"
            )
            lines.append("")

            lines.append(_REPORT_SEPARATOR)
            lines.append("")
            lines.append(
                "*Report generated by SIREN Result Correlator — "
                "cross-scan correlation and trend analysis engine.*"
            )

            report = "\n".join(lines)
            logger.info(
                "generate_correlation_report: produced %d-line report",
                len(lines),
            )
            return report

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_json(self) -> str:
        """Export the full correlation state as a JSON string.

        Includes all correlated findings, patterns, trend analysis,
        rules, deduplication stats, and scan metadata.
        """
        with self._lock:
            data: Dict[str, Any] = {
                "export_timestamp": _current_timestamp(),
                "export_timestamp_iso": time.strftime(
                    "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
                ),
                "engine_version": "1.0.0",
                "is_correlated": self._is_correlated,
                "correlation_count": self._correlation_count,
                "last_correlation_time": self._last_correlation_time,
                "scan_count": len(self._scan_order),
                "scan_ids": list(self._scan_order),
                "total_finding_count": self.get_total_finding_count(),
                "correlated_finding_count": len(self._correlated_findings),
                "pattern_count": len(self._patterns),
                "configuration": {
                    "similarity_threshold": self._similarity_threshold,
                    "systemic_threshold": self._systemic_threshold,
                    "merge_strategy": self._dedup_engine.merge_strategy.value,
                },
                "rules": [r.to_dict() for r in self._rules],
                "correlated_findings": [
                    cf.to_dict() for cf in self._correlated_findings.values()
                ],
                "patterns": [p.to_dict() for p in self._patterns],
                "deduplication_stats": self._dedup_engine.get_stats(),
            }

            if self._is_correlated:
                data["trend_analysis"] = self.get_trend_analysis()

            # Scan metadata (without raw findings to keep export manageable)
            scan_meta: List[Dict[str, Any]] = []
            for scan_id in self._scan_order:
                if scan_id in self._scans:
                    ts, findings = self._scans[scan_id]
                    scan_meta.append(
                        {
                            "scan_id": scan_id,
                            "timestamp": ts,
                            "finding_count": len(findings),
                        }
                    )
            data["scan_metadata"] = scan_meta

            json_str = json.dumps(data, indent=2, default=str, ensure_ascii=False)
            logger.info(
                "export_json: exported %d bytes (%d findings, %d patterns)",
                len(json_str),
                len(self._correlated_findings),
                len(self._patterns),
            )
            return json_str

    # ------------------------------------------------------------------
    # Internal state / diagnostics
    # ------------------------------------------------------------------

    def get_stats(self) -> Dict[str, Any]:
        """Return engine statistics and diagnostics."""
        with self._lock:
            findings = list(self._correlated_findings.values())
            trend_dist: Counter[str] = collections.Counter()
            sev_dist: Counter[str] = collections.Counter()
            for cf in findings:
                trend_dist[cf.trend] += 1
                sev_dist[cf.severity] += 1

            return {
                "scan_count": len(self._scan_order),
                "total_raw_findings": self.get_total_finding_count(),
                "correlated_finding_count": len(self._correlated_findings),
                "pattern_count": len(self._patterns),
                "is_correlated": self._is_correlated,
                "correlation_count": self._correlation_count,
                "last_correlation_time": self._last_correlation_time,
                "rule_count": len(self._rules),
                "enabled_rule_count": sum(1 for r in self._rules if r.enabled),
                "trend_distribution": dict(trend_dist),
                "severity_distribution": dict(sev_dist),
                "deduplication_stats": self._dedup_engine.get_stats(),
                "similarity_threshold": self._similarity_threshold,
                "systemic_threshold": self._systemic_threshold,
            }

    def reset(self) -> None:
        """Reset all state: scans, findings, patterns, stats."""
        with self._lock:
            self._scans.clear()
            self._scan_order.clear()
            self._correlated_findings.clear()
            self._patterns.clear()
            self._dedup_engine.reset_stats()
            self._is_correlated = False
            self._last_correlation_time = 0.0
            self._correlation_count = 0
            logger.info("SirenResultCorrelator: full reset performed")

    def to_dict(self) -> Dict[str, Any]:
        """Serialize engine state to a dict (without raw scan data)."""
        with self._lock:
            return {
                "class": "SirenResultCorrelator",
                "stats": self.get_stats(),
                "rules": [r.to_dict() for r in self._rules],
                "correlated_findings": [
                    cf.to_dict() for cf in self._correlated_findings.values()
                ],
                "patterns": [p.to_dict() for p in self._patterns],
                "scan_ids": list(self._scan_order),
                "deduplication_engine": self._dedup_engine.to_dict(),
            }

    def __repr__(self) -> str:
        return (
            f"SirenResultCorrelator(scans={len(self._scan_order)}, "
            f"findings={len(self._correlated_findings)}, "
            f"patterns={len(self._patterns)}, "
            f"rules={len(self._rules)}, "
            f"correlated={self._is_correlated})"
        )

    def __len__(self) -> int:
        return len(self._correlated_findings)

    def __contains__(self, correlation_id: str) -> bool:
        return correlation_id in self._correlated_findings

    def __iter__(self):
        return iter(self._correlated_findings.values())


# ---------------------------------------------------------------------------
# Module-level exports
# ---------------------------------------------------------------------------

__all__ = [
    "CorrelatedFinding",
    "CorrelationRule",
    "CrossScanPattern",
    "DeduplicationEngine",
    "SirenResultCorrelator",
    "FindingTrend",
    "CorrelationRuleType",
    "CrossScanPatternType",
    "MergeStrategy",
    "SeverityLevel",
]
