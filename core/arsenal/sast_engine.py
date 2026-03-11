#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  🔬 SIREN SAST ENGINE — Static Application Security Testing               🔬 ██
██                                                                                ██
██  Pattern-based source code analysis for vulnerability detection.              ██
██                                                                                ██
██  Capacidades:                                                                  ██
██    • Multi-language source detection — Python, JS, Java, C#, PHP, Go, Ruby   ██
██    • Taint analysis — source-to-sink data flow tracking                       ██
██    • Sink detection — SQLi, XSS, CMDi, path traversal, SSRF, deserialization ██
██    • Pattern matching — 200+ regex patterns organized by vulnerability type   ██
██    • Data flow graphs — call graph construction & tainted variable tracking   ██
██    • False positive reduction — sanitizer detection between source and sink   ██
██    • SAST findings — severity scoring, code location, remediation guidance    ██
██    • Report generation — aggregated findings with statistics & export         ██
██                                                                                ██
██  "SIREN le o codigo-fonte — e encontra o que o dev escondeu."               ██
██                                                                                ██
████████████████████████████████████████████████████████████████████████████████████
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import threading
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("siren.arsenal.sast_engine")


# ════════════════════════════════════════════════════════════════════════════════
# ENUMS
# ════════════════════════════════════════════════════════════════════════════════

class Language(Enum):
    """Supported programming languages for static analysis."""
    PYTHON = auto()
    JAVASCRIPT = auto()
    JAVA = auto()
    CSHARP = auto()
    PHP = auto()
    GO = auto()
    RUBY = auto()
    UNKNOWN = auto()


class VulnType(Enum):
    """Vulnerability types detectable by SAST."""
    SQL_INJECTION = auto()
    CROSS_SITE_SCRIPTING = auto()
    COMMAND_INJECTION = auto()
    PATH_TRAVERSAL = auto()
    SSRF = auto()
    DESERIALIZATION = auto()
    OPEN_REDIRECT = auto()
    LDAP_INJECTION = auto()
    XPATH_INJECTION = auto()
    XML_INJECTION = auto()
    TEMPLATE_INJECTION = auto()
    HEADER_INJECTION = auto()
    LOG_INJECTION = auto()
    CODE_INJECTION = auto()
    REGEX_DOS = auto()
    HARDCODED_SECRET = auto()
    WEAK_CRYPTO = auto()
    INSECURE_RANDOM = auto()
    MISSING_AUTH = auto()
    BROKEN_ACCESS_CONTROL = auto()
    MASS_ASSIGNMENT = auto()
    PROTOTYPE_POLLUTION = auto()
    RACE_CONDITION = auto()
    INFORMATION_DISCLOSURE = auto()
    UNSAFE_REFLECTION = auto()
    UNVALIDATED_REDIRECT = auto()
    INSECURE_COOKIE = auto()
    MISSING_CSRF = auto()
    INSECURE_TLS = auto()
    BUFFER_OVERFLOW = auto()


class Severity(Enum):
    """Finding severity levels."""
    CRITICAL = auto()
    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()
    INFO = auto()


class FlowStatus(Enum):
    """Status of a taint flow analysis."""
    CONFIRMED = auto()
    POTENTIAL = auto()
    SANITIZED = auto()
    FALSE_POSITIVE = auto()
    UNKNOWN = auto()


class ScanStatus(Enum):
    """Status of a SAST scan."""
    PENDING = auto()
    RUNNING = auto()
    COMPLETED = auto()
    FAILED = auto()
    CANCELLED = auto()


class ConfidenceLevel(Enum):
    """Confidence in a finding's validity."""
    DEFINITE = auto()
    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()
    TENTATIVE = auto()


# ════════════════════════════════════════════════════════════════════════════════
# CONSTANTS — Language extensions & detection mappings
# ════════════════════════════════════════════════════════════════════════════════

LANGUAGE_EXTENSIONS: Dict[str, Language] = {
    ".py": Language.PYTHON,
    ".pyw": Language.PYTHON,
    ".pyx": Language.PYTHON,
    ".js": Language.JAVASCRIPT,
    ".jsx": Language.JAVASCRIPT,
    ".ts": Language.JAVASCRIPT,
    ".tsx": Language.JAVASCRIPT,
    ".mjs": Language.JAVASCRIPT,
    ".cjs": Language.JAVASCRIPT,
    ".java": Language.JAVA,
    ".kt": Language.JAVA,
    ".scala": Language.JAVA,
    ".cs": Language.CSHARP,
    ".vb": Language.CSHARP,
    ".fs": Language.CSHARP,
    ".php": Language.PHP,
    ".phtml": Language.PHP,
    ".php3": Language.PHP,
    ".php4": Language.PHP,
    ".php5": Language.PHP,
    ".php7": Language.PHP,
    ".phps": Language.PHP,
    ".go": Language.GO,
    ".rb": Language.RUBY,
    ".erb": Language.RUBY,
    ".rake": Language.RUBY,
}

VULN_SEVERITY_MAP: Dict[VulnType, Severity] = {
    VulnType.SQL_INJECTION: Severity.CRITICAL,
    VulnType.COMMAND_INJECTION: Severity.CRITICAL,
    VulnType.DESERIALIZATION: Severity.CRITICAL,
    VulnType.CODE_INJECTION: Severity.CRITICAL,
    VulnType.BUFFER_OVERFLOW: Severity.CRITICAL,
    VulnType.CROSS_SITE_SCRIPTING: Severity.HIGH,
    VulnType.PATH_TRAVERSAL: Severity.HIGH,
    VulnType.SSRF: Severity.HIGH,
    VulnType.TEMPLATE_INJECTION: Severity.HIGH,
    VulnType.LDAP_INJECTION: Severity.HIGH,
    VulnType.XPATH_INJECTION: Severity.HIGH,
    VulnType.XML_INJECTION: Severity.HIGH,
    VulnType.UNSAFE_REFLECTION: Severity.HIGH,
    VulnType.PROTOTYPE_POLLUTION: Severity.HIGH,
    VulnType.BROKEN_ACCESS_CONTROL: Severity.HIGH,
    VulnType.OPEN_REDIRECT: Severity.MEDIUM,
    VulnType.HEADER_INJECTION: Severity.MEDIUM,
    VulnType.LOG_INJECTION: Severity.MEDIUM,
    VulnType.MISSING_CSRF: Severity.MEDIUM,
    VulnType.MASS_ASSIGNMENT: Severity.MEDIUM,
    VulnType.RACE_CONDITION: Severity.MEDIUM,
    VulnType.UNVALIDATED_REDIRECT: Severity.MEDIUM,
    VulnType.REGEX_DOS: Severity.MEDIUM,
    VulnType.HARDCODED_SECRET: Severity.MEDIUM,
    VulnType.WEAK_CRYPTO: Severity.MEDIUM,
    VulnType.INSECURE_RANDOM: Severity.MEDIUM,
    VulnType.INSECURE_TLS: Severity.MEDIUM,
    VulnType.INSECURE_COOKIE: Severity.LOW,
    VulnType.MISSING_AUTH: Severity.LOW,
    VulnType.INFORMATION_DISCLOSURE: Severity.LOW,
}


# ════════════════════════════════════════════════════════════════════════════════
# DATACLASSES
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class CodeLocation:
    """Pinpoints a location in source code."""
    file_path: str = ""
    line_number: int = 0
    column: int = 0
    end_line: int = 0
    end_column: int = 0
    snippet: str = ""
    context_before: str = ""
    context_after: str = ""
    function_name: str = ""
    class_name: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "column": self.column,
            "end_line": self.end_line,
            "end_column": self.end_column,
            "snippet": self.snippet,
            "context_before": self.context_before,
            "context_after": self.context_after,
            "function_name": self.function_name,
            "class_name": self.class_name,
        }


@dataclass
class TaintFlow:
    """Represents a single taint propagation path from source to sink."""
    flow_id: str = ""
    source_location: CodeLocation = field(default_factory=CodeLocation)
    sink_location: CodeLocation = field(default_factory=CodeLocation)
    intermediate_nodes: List[CodeLocation] = field(default_factory=list)
    source_type: str = ""
    sink_type: str = ""
    vuln_type: VulnType = VulnType.SQL_INJECTION
    tainted_variable: str = ""
    propagation_chain: List[str] = field(default_factory=list)
    sanitizers_found: List[str] = field(default_factory=list)
    is_sanitized: bool = False
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    status: FlowStatus = FlowStatus.UNKNOWN

    def __post_init__(self) -> None:
        if not self.flow_id:
            self.flow_id = str(uuid.uuid4())[:12]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "source_location": self.source_location.to_dict(),
            "sink_location": self.sink_location.to_dict(),
            "intermediate_nodes": [n.to_dict() for n in self.intermediate_nodes],
            "source_type": self.source_type,
            "sink_type": self.sink_type,
            "vuln_type": self.vuln_type.name,
            "tainted_variable": self.tainted_variable,
            "propagation_chain": self.propagation_chain,
            "sanitizers_found": self.sanitizers_found,
            "is_sanitized": self.is_sanitized,
            "confidence": self.confidence.name,
            "status": self.status.name,
        }


@dataclass
class SASTFinding:
    """A single SAST finding with full context."""
    finding_id: str = ""
    title: str = ""
    description: str = ""
    vuln_type: VulnType = VulnType.SQL_INJECTION
    severity: Severity = Severity.MEDIUM
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    language: Language = Language.UNKNOWN
    location: CodeLocation = field(default_factory=CodeLocation)
    taint_flow: Optional[TaintFlow] = None
    cwe_id: int = 0
    owasp_category: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    matched_pattern: str = ""
    raw_match: str = ""
    false_positive_reason: str = ""
    is_false_positive: bool = False
    timestamp: float = 0.0

    def __post_init__(self) -> None:
        if not self.finding_id:
            self.finding_id = f"SAST-{uuid.uuid4().hex[:10].upper()}"
        if self.timestamp == 0.0:
            self.timestamp = time.time()
        if self.severity == Severity.MEDIUM and self.vuln_type in VULN_SEVERITY_MAP:
            self.severity = VULN_SEVERITY_MAP[self.vuln_type]

    def fingerprint(self) -> str:
        """Generate a stable fingerprint for deduplication."""
        raw = f"{self.vuln_type.name}:{self.location.file_path}:{self.location.line_number}:{self.matched_pattern}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "description": self.description,
            "vuln_type": self.vuln_type.name,
            "severity": self.severity.name,
            "confidence": self.confidence.name,
            "language": self.language.name,
            "location": self.location.to_dict(),
            "taint_flow": self.taint_flow.to_dict() if self.taint_flow else None,
            "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category,
            "remediation": self.remediation,
            "references": self.references,
            "tags": self.tags,
            "matched_pattern": self.matched_pattern,
            "raw_match": self.raw_match,
            "false_positive_reason": self.false_positive_reason,
            "is_false_positive": self.is_false_positive,
            "fingerprint": self.fingerprint(),
            "timestamp": self.timestamp,
        }


@dataclass
class SASTReport:
    """Aggregated SAST scan report."""
    report_id: str = ""
    scan_start: float = 0.0
    scan_end: float = 0.0
    scan_duration: float = 0.0
    status: ScanStatus = ScanStatus.PENDING
    target_path: str = ""
    files_scanned: int = 0
    files_skipped: int = 0
    lines_analyzed: int = 0
    languages_detected: Dict[str, int] = field(default_factory=dict)
    findings: List[SASTFinding] = field(default_factory=list)
    findings_by_severity: Dict[str, int] = field(default_factory=dict)
    findings_by_vuln_type: Dict[str, int] = field(default_factory=dict)
    findings_by_language: Dict[str, int] = field(default_factory=dict)
    false_positives_filtered: int = 0
    taint_flows_traced: int = 0
    total_sources: int = 0
    total_sinks: int = 0
    scan_errors: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.report_id:
            self.report_id = f"SAST-RPT-{uuid.uuid4().hex[:8].upper()}"

    def compute_stats(self) -> None:
        """Recompute aggregated statistics from findings."""
        self.findings_by_severity = defaultdict(int)
        self.findings_by_vuln_type = defaultdict(int)
        self.findings_by_language = defaultdict(int)
        active = [f for f in self.findings if not f.is_false_positive]
        for f in active:
            self.findings_by_severity[f.severity.name] += 1
            self.findings_by_vuln_type[f.vuln_type.name] += 1
            self.findings_by_language[f.language.name] += 1
        self.findings_by_severity = dict(self.findings_by_severity)
        self.findings_by_vuln_type = dict(self.findings_by_vuln_type)
        self.findings_by_language = dict(self.findings_by_language)
        self.false_positives_filtered = sum(1 for f in self.findings if f.is_false_positive)

    def to_dict(self) -> Dict[str, Any]:
        self.compute_stats()
        return {
            "report_id": self.report_id,
            "scan_start": self.scan_start,
            "scan_end": self.scan_end,
            "scan_duration": self.scan_duration,
            "status": self.status.name,
            "target_path": self.target_path,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "lines_analyzed": self.lines_analyzed,
            "languages_detected": self.languages_detected,
            "findings_count": len([f for f in self.findings if not f.is_false_positive]),
            "findings": [f.to_dict() for f in self.findings if not f.is_false_positive],
            "findings_by_severity": self.findings_by_severity,
            "findings_by_vuln_type": self.findings_by_vuln_type,
            "findings_by_language": self.findings_by_language,
            "false_positives_filtered": self.false_positives_filtered,
            "taint_flows_traced": self.taint_flows_traced,
            "total_sources": self.total_sources,
            "total_sinks": self.total_sinks,
            "scan_errors": self.scan_errors,
        }


@dataclass
class SourceHit:
    """A detected taint source in code."""
    location: CodeLocation = field(default_factory=CodeLocation)
    source_pattern: str = ""
    variable_name: str = ""
    language: Language = Language.UNKNOWN
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "location": self.location.to_dict(),
            "source_pattern": self.source_pattern,
            "variable_name": self.variable_name,
            "language": self.language.name,
            "description": self.description,
        }


@dataclass
class SinkHit:
    """A detected dangerous sink in code."""
    location: CodeLocation = field(default_factory=CodeLocation)
    sink_pattern: str = ""
    vuln_type: VulnType = VulnType.SQL_INJECTION
    language: Language = Language.UNKNOWN
    description: str = ""
    cwe_id: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "location": self.location.to_dict(),
            "sink_pattern": self.sink_pattern,
            "vuln_type": self.vuln_type.name,
            "language": self.language.name,
            "description": self.description,
            "cwe_id": self.cwe_id,
        }


@dataclass
class PatternRule:
    """A single regex pattern rule for matching vulnerabilities."""
    rule_id: str = ""
    name: str = ""
    pattern: str = ""
    vuln_type: VulnType = VulnType.SQL_INJECTION
    severity: Severity = Severity.MEDIUM
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    languages: List[Language] = field(default_factory=list)
    cwe_id: int = 0
    owasp: str = ""
    description: str = ""
    remediation: str = ""
    false_positive_patterns: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "pattern": self.pattern,
            "vuln_type": self.vuln_type.name,
            "severity": self.severity.name,
            "confidence": self.confidence.name,
            "languages": [l.name for l in self.languages],
            "cwe_id": self.cwe_id,
            "owasp": self.owasp,
            "description": self.description,
            "remediation": self.remediation,
        }


@dataclass
class CallGraphNode:
    """Node in a call graph representing a function/method."""
    node_id: str = ""
    name: str = ""
    file_path: str = ""
    line_start: int = 0
    line_end: int = 0
    class_name: str = ""
    parameters: List[str] = field(default_factory=list)
    calls: List[str] = field(default_factory=list)
    called_by: List[str] = field(default_factory=list)
    tainted_params: Set[str] = field(default_factory=set)
    tainted_locals: Set[str] = field(default_factory=set)
    contains_source: bool = False
    contains_sink: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "name": self.name,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "class_name": self.class_name,
            "parameters": self.parameters,
            "calls": self.calls,
            "called_by": self.called_by,
            "tainted_params": list(self.tainted_params),
            "tainted_locals": list(self.tainted_locals),
            "contains_source": self.contains_source,
            "contains_sink": self.contains_sink,
        }


@dataclass
class ScanConfig:
    """Configuration for a SAST scan."""
    max_file_size: int = 1_000_000
    max_files: int = 10_000
    max_line_length: int = 5_000
    max_findings_per_file: int = 100
    max_total_findings: int = 5_000
    enable_taint_analysis: bool = True
    enable_false_positive_reduction: bool = True
    enable_data_flow: bool = True
    excluded_dirs: List[str] = field(default_factory=lambda: [
        "node_modules", ".git", "__pycache__", "venv", ".venv",
        "vendor", "dist", "build", ".next", ".nuxt", "target",
        "bin", "obj", ".tox", ".mypy_cache", ".pytest_cache",
        "coverage", ".coverage", "htmlcov", ".eggs", "*.egg-info",
    ])
    excluded_files: List[str] = field(default_factory=lambda: [
        "*.min.js", "*.min.css", "*.map", "*.lock",
        "package-lock.json", "yarn.lock", "Gemfile.lock",
        "*.pyc", "*.pyo", "*.class", "*.dll", "*.exe",
    ])
    severity_threshold: Severity = Severity.INFO
    target_languages: List[Language] = field(default_factory=list)
    custom_patterns: List[PatternRule] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "max_file_size": self.max_file_size,
            "max_files": self.max_files,
            "max_line_length": self.max_line_length,
            "max_findings_per_file": self.max_findings_per_file,
            "max_total_findings": self.max_total_findings,
            "enable_taint_analysis": self.enable_taint_analysis,
            "enable_false_positive_reduction": self.enable_false_positive_reduction,
            "enable_data_flow": self.enable_data_flow,
            "excluded_dirs": self.excluded_dirs,
            "excluded_files": self.excluded_files,
            "severity_threshold": self.severity_threshold.name,
            "target_languages": [l.name for l in self.target_languages],
        }


# ════════════════════════════════════════════════════════════════════════════════
# CWE MAPPINGS
# ════════════════════════════════════════════════════════════════════════════════

VULN_CWE_MAP: Dict[VulnType, int] = {
    VulnType.SQL_INJECTION: 89,
    VulnType.CROSS_SITE_SCRIPTING: 79,
    VulnType.COMMAND_INJECTION: 78,
    VulnType.PATH_TRAVERSAL: 22,
    VulnType.SSRF: 918,
    VulnType.DESERIALIZATION: 502,
    VulnType.OPEN_REDIRECT: 601,
    VulnType.LDAP_INJECTION: 90,
    VulnType.XPATH_INJECTION: 643,
    VulnType.XML_INJECTION: 611,
    VulnType.TEMPLATE_INJECTION: 1336,
    VulnType.HEADER_INJECTION: 113,
    VulnType.LOG_INJECTION: 117,
    VulnType.CODE_INJECTION: 94,
    VulnType.REGEX_DOS: 1333,
    VulnType.HARDCODED_SECRET: 798,
    VulnType.WEAK_CRYPTO: 327,
    VulnType.INSECURE_RANDOM: 330,
    VulnType.MISSING_AUTH: 306,
    VulnType.BROKEN_ACCESS_CONTROL: 284,
    VulnType.MASS_ASSIGNMENT: 915,
    VulnType.PROTOTYPE_POLLUTION: 1321,
    VulnType.RACE_CONDITION: 362,
    VulnType.INFORMATION_DISCLOSURE: 200,
    VulnType.UNSAFE_REFLECTION: 470,
    VulnType.UNVALIDATED_REDIRECT: 601,
    VulnType.INSECURE_COOKIE: 614,
    VulnType.MISSING_CSRF: 352,
    VulnType.INSECURE_TLS: 295,
    VulnType.BUFFER_OVERFLOW: 120,
}

VULN_OWASP_MAP: Dict[VulnType, str] = {
    VulnType.SQL_INJECTION: "A03:2021-Injection",
    VulnType.CROSS_SITE_SCRIPTING: "A03:2021-Injection",
    VulnType.COMMAND_INJECTION: "A03:2021-Injection",
    VulnType.PATH_TRAVERSAL: "A01:2021-Broken Access Control",
    VulnType.SSRF: "A10:2021-SSRF",
    VulnType.DESERIALIZATION: "A08:2021-Software and Data Integrity Failures",
    VulnType.OPEN_REDIRECT: "A01:2021-Broken Access Control",
    VulnType.LDAP_INJECTION: "A03:2021-Injection",
    VulnType.XPATH_INJECTION: "A03:2021-Injection",
    VulnType.XML_INJECTION: "A05:2021-Security Misconfiguration",
    VulnType.TEMPLATE_INJECTION: "A03:2021-Injection",
    VulnType.HEADER_INJECTION: "A03:2021-Injection",
    VulnType.LOG_INJECTION: "A09:2021-Security Logging and Monitoring Failures",
    VulnType.CODE_INJECTION: "A03:2021-Injection",
    VulnType.HARDCODED_SECRET: "A02:2021-Cryptographic Failures",
    VulnType.WEAK_CRYPTO: "A02:2021-Cryptographic Failures",
    VulnType.INSECURE_RANDOM: "A02:2021-Cryptographic Failures",
    VulnType.MISSING_AUTH: "A07:2021-Identification and Authentication Failures",
    VulnType.BROKEN_ACCESS_CONTROL: "A01:2021-Broken Access Control",
    VulnType.MASS_ASSIGNMENT: "A04:2021-Insecure Design",
    VulnType.INSECURE_COOKIE: "A05:2021-Security Misconfiguration",
    VulnType.MISSING_CSRF: "A01:2021-Broken Access Control",
    VulnType.INSECURE_TLS: "A02:2021-Cryptographic Failures",
}


# ════════════════════════════════════════════════════════════════════════════════
# SOURCE DETECTOR — Per-Language User Input Sources
# ════════════════════════════════════════════════════════════════════════════════

class SourceDetector:
    """
    Detects taint sources (user-controlled input) across multiple languages.

    Each language has its own set of patterns that identify where user input
    enters the application. These are the starting points for taint analysis.

    Usage:
        detector = SourceDetector()
        sources = detector.detect_sources(code, Language.PYTHON, "app.py")
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._source_patterns: Dict[Language, List[Tuple[str, str, str]]] = {}
        self._compiled_patterns: Dict[Language, List[Tuple[re.Pattern, str, str]]] = {}
        self._stats: Dict[str, int] = defaultdict(int)
        self._build_source_patterns()
        logger.info("SourceDetector initialized with %d languages", len(self._source_patterns))

    def _build_source_patterns(self) -> None:
        """Build all source patterns for every supported language."""
        self._source_patterns = {
            Language.PYTHON: self._python_sources(),
            Language.JAVASCRIPT: self._javascript_sources(),
            Language.JAVA: self._java_sources(),
            Language.CSHARP: self._csharp_sources(),
            Language.PHP: self._php_sources(),
            Language.GO: self._go_sources(),
            Language.RUBY: self._ruby_sources(),
        }
        for lang, patterns in self._source_patterns.items():
            compiled = []
            for pattern, name, desc in patterns:
                try:
                    compiled.append((re.compile(pattern, re.IGNORECASE), name, desc))
                except re.error as e:
                    logger.warning("Failed to compile source pattern %s for %s: %s", name, lang.name, e)
            self._compiled_patterns[lang] = compiled

    # ── Python Sources ──────────────────────────────────────────────────────

    def _python_sources(self) -> List[Tuple[str, str, str]]:
        """Python taint sources — Flask, Django, FastAPI, stdlib."""
        return [
            # Flask request sources
            (r"request\.args\b", "flask.request.args", "Flask query string parameters"),
            (r"request\.args\.get\s*\(", "flask.request.args.get", "Flask query string get()"),
            (r"request\.args\.getlist\s*\(", "flask.request.args.getlist", "Flask query string getlist()"),
            (r"request\.form\b", "flask.request.form", "Flask form data"),
            (r"request\.form\.get\s*\(", "flask.request.form.get", "Flask form data get()"),
            (r"request\.json\b", "flask.request.json", "Flask JSON body"),
            (r"request\.get_json\s*\(", "flask.request.get_json", "Flask JSON body method"),
            (r"request\.data\b", "flask.request.data", "Flask raw request data"),
            (r"request\.values\b", "flask.request.values", "Flask combined args+form"),
            (r"request\.files\b", "flask.request.files", "Flask uploaded files"),
            (r"request\.headers\b", "flask.request.headers", "Flask request headers"),
            (r"request\.cookies\b", "flask.request.cookies", "Flask cookies"),
            (r"request\.url\b", "flask.request.url", "Flask full URL"),
            (r"request\.path\b", "flask.request.path", "Flask request path"),
            (r"request\.host\b", "flask.request.host", "Flask request host"),
            (r"request\.referrer\b", "flask.request.referrer", "Flask request referrer"),
            (r"request\.user_agent\b", "flask.request.user_agent", "Flask user agent"),
            # Django sources
            (r"request\.GET\b", "django.request.GET", "Django GET parameters"),
            (r"request\.POST\b", "django.request.POST", "Django POST parameters"),
            (r"request\.FILES\b", "django.request.FILES", "Django uploaded files"),
            (r"request\.COOKIES\b", "django.request.COOKIES", "Django cookies"),
            (r"request\.META\b", "django.request.META", "Django request metadata"),
            (r"request\.body\b", "django.request.body", "Django raw request body"),
            (r"request\.content_type\b", "django.request.content_type", "Django content type"),
            # FastAPI / Starlette
            (r"request\.query_params\b", "fastapi.request.query_params", "FastAPI query params"),
            (r"request\.path_params\b", "fastapi.request.path_params", "FastAPI path params"),
            (r"await\s+request\.json\s*\(", "fastapi.request.json", "FastAPI async JSON body"),
            (r"await\s+request\.body\s*\(", "fastapi.request.body", "FastAPI async body"),
            (r"await\s+request\.form\s*\(", "fastapi.request.form", "FastAPI async form"),
            # Python stdlib sources
            (r"\binput\s*\(", "stdlib.input", "Python builtin input()"),
            (r"sys\.argv\b", "stdlib.sys.argv", "Command line arguments"),
            (r"sys\.stdin\b", "stdlib.sys.stdin", "Standard input stream"),
            (r"os\.environ\b", "stdlib.os.environ", "Environment variables"),
            (r"os\.environ\.get\s*\(", "stdlib.os.environ.get", "Environment variable get()"),
            (r"os\.getenv\s*\(", "stdlib.os.getenv", "Environment variable getenv()"),
            # URL / file reading
            (r"urllib\.request\.urlopen\s*\(", "stdlib.urllib.urlopen", "URL fetch via urllib"),
            (r"urlparse\s*\(", "stdlib.urlparse", "URL parsing"),
            (r"cgi\.FieldStorage\b", "stdlib.cgi.FieldStorage", "CGI form data"),
        ]

    # ── JavaScript Sources ──────────────────────────────────────────────────

    def _javascript_sources(self) -> List[Tuple[str, str, str]]:
        """JavaScript/TypeScript taint sources — Express, browser APIs."""
        return [
            # Express.js request sources
            (r"req\.body\b", "express.req.body", "Express request body"),
            (r"req\.params\b", "express.req.params", "Express route parameters"),
            (r"req\.params\.\w+", "express.req.params.x", "Express specific route param"),
            (r"req\.query\b", "express.req.query", "Express query string"),
            (r"req\.query\.\w+", "express.req.query.x", "Express specific query param"),
            (r"req\.headers\b", "express.req.headers", "Express request headers"),
            (r"req\.headers\[", "express.req.headers[]", "Express header by name"),
            (r"req\.cookies\b", "express.req.cookies", "Express cookies"),
            (r"req\.files?\b", "express.req.files", "Express uploaded files"),
            (r"req\.hostname\b", "express.req.hostname", "Express hostname"),
            (r"req\.ip\b", "express.req.ip", "Express client IP"),
            (r"req\.path\b", "express.req.path", "Express request path"),
            (r"req\.url\b", "express.req.url", "Express request URL"),
            (r"req\.originalUrl\b", "express.req.originalUrl", "Express original URL"),
            (r"req\.get\s*\(", "express.req.get", "Express get header"),
            (r"req\.header\s*\(", "express.req.header", "Express header()"),
            (r"req\.param\s*\(", "express.req.param", "Express param()"),
            # Browser DOM sources
            (r"document\.location\b", "browser.document.location", "Document location object"),
            (r"document\.URL\b", "browser.document.URL", "Document URL string"),
            (r"document\.referrer\b", "browser.document.referrer", "Document referrer"),
            (r"document\.cookie\b", "browser.document.cookie", "Document cookies"),
            (r"document\.documentURI\b", "browser.document.documentURI", "Document URI"),
            (r"window\.location\b", "browser.window.location", "Window location"),
            (r"window\.name\b", "browser.window.name", "Window name (attacker-controlled)"),
            (r"location\.hash\b", "browser.location.hash", "URL hash fragment"),
            (r"location\.search\b", "browser.location.search", "URL query string"),
            (r"location\.href\b", "browser.location.href", "Full URL href"),
            (r"location\.pathname\b", "browser.location.pathname", "URL pathname"),
            # Web API sources
            (r"URLSearchParams\b", "browser.URLSearchParams", "URL search params API"),
            (r"FormData\b", "browser.FormData", "FormData API"),
            (r"localStorage\.getItem\s*\(", "browser.localStorage", "Local storage read"),
            (r"sessionStorage\.getItem\s*\(", "browser.sessionStorage", "Session storage read"),
            (r"postMessage\b", "browser.postMessage", "Cross-origin message"),
            (r"addEventListener\s*\(\s*['\"]message['\"]", "browser.message.event", "Message event listener"),
            # Next.js / Nuxt.js
            (r"useRouter\s*\(\s*\)", "nextjs.useRouter", "Next.js router hook"),
            (r"useSearchParams\s*\(\s*\)", "nextjs.useSearchParams", "Next.js search params hook"),
            (r"\$route\.params\b", "nuxtjs.route.params", "Nuxt.js route params"),
            (r"\$route\.query\b", "nuxtjs.route.query", "Nuxt.js route query"),
        ]

    # ── Java Sources ────────────────────────────────────────────────────────

    def _java_sources(self) -> List[Tuple[str, str, str]]:
        """Java taint sources — Servlet, Spring, JAX-RS."""
        return [
            # Servlet API
            (r"request\.getParameter\s*\(", "servlet.getParameter", "Servlet query/form parameter"),
            (r"request\.getParameterValues\s*\(", "servlet.getParameterValues", "Servlet parameter values array"),
            (r"request\.getParameterMap\s*\(", "servlet.getParameterMap", "Servlet all parameters map"),
            (r"request\.getHeader\s*\(", "servlet.getHeader", "Servlet request header"),
            (r"request\.getHeaders\s*\(", "servlet.getHeaders", "Servlet request headers enumeration"),
            (r"request\.getHeaderNames\s*\(", "servlet.getHeaderNames", "Servlet header names"),
            (r"request\.getInputStream\s*\(", "servlet.getInputStream", "Servlet raw input stream"),
            (r"request\.getReader\s*\(", "servlet.getReader", "Servlet buffered reader"),
            (r"request\.getPathInfo\s*\(", "servlet.getPathInfo", "Servlet path info"),
            (r"request\.getQueryString\s*\(", "servlet.getQueryString", "Servlet raw query string"),
            (r"request\.getRequestURI\s*\(", "servlet.getRequestURI", "Servlet request URI"),
            (r"request\.getRequestURL\s*\(", "servlet.getRequestURL", "Servlet request URL"),
            (r"request\.getCookies\s*\(", "servlet.getCookies", "Servlet cookies array"),
            (r"request\.getRemoteAddr\s*\(", "servlet.getRemoteAddr", "Servlet remote address"),
            (r"request\.getRemoteHost\s*\(", "servlet.getRemoteHost", "Servlet remote host"),
            (r"request\.getServletPath\s*\(", "servlet.getServletPath", "Servlet path"),
            (r"request\.getContentType\s*\(", "servlet.getContentType", "Servlet content type"),
            (r"request\.getPart\s*\(", "servlet.getPart", "Servlet multipart file upload"),
            (r"request\.getParts\s*\(", "servlet.getParts", "Servlet multipart all parts"),
            # Spring MVC
            (r"@RequestParam\b", "spring.RequestParam", "Spring request parameter binding"),
            (r"@PathVariable\b", "spring.PathVariable", "Spring path variable binding"),
            (r"@RequestBody\b", "spring.RequestBody", "Spring request body binding"),
            (r"@RequestHeader\b", "spring.RequestHeader", "Spring header binding"),
            (r"@CookieValue\b", "spring.CookieValue", "Spring cookie binding"),
            (r"@MatrixVariable\b", "spring.MatrixVariable", "Spring matrix variable"),
            (r"@ModelAttribute\b", "spring.ModelAttribute", "Spring model attribute binding"),
            # JAX-RS
            (r"@QueryParam\b", "jaxrs.QueryParam", "JAX-RS query parameter"),
            (r"@PathParam\b", "jaxrs.PathParam", "JAX-RS path parameter"),
            (r"@HeaderParam\b", "jaxrs.HeaderParam", "JAX-RS header parameter"),
            (r"@FormParam\b", "jaxrs.FormParam", "JAX-RS form parameter"),
            (r"@CookieParam\b", "jaxrs.CookieParam", "JAX-RS cookie parameter"),
            (r"@BeanParam\b", "jaxrs.BeanParam", "JAX-RS bean parameter"),
            # Scanner / BufferedReader
            (r"new\s+Scanner\s*\(\s*System\.in\s*\)", "stdlib.Scanner.stdin", "Stdin via Scanner"),
            (r"new\s+BufferedReader\s*\(\s*new\s+InputStreamReader\s*\(\s*System\.in", "stdlib.BufferedReader.stdin", "Stdin via BufferedReader"),
        ]

    # ── C# Sources ──────────────────────────────────────────────────────────

    def _csharp_sources(self) -> List[Tuple[str, str, str]]:
        """C# taint sources — ASP.NET Core, MVC."""
        return [
            # ASP.NET Core
            (r"Request\.Query\b", "aspnet.Request.Query", "ASP.NET query string"),
            (r"Request\.Query\[", "aspnet.Request.Query[]", "ASP.NET query param by key"),
            (r"Request\.Form\b", "aspnet.Request.Form", "ASP.NET form data"),
            (r"Request\.Form\[", "aspnet.Request.Form[]", "ASP.NET form field by key"),
            (r"Request\.Body\b", "aspnet.Request.Body", "ASP.NET request body stream"),
            (r"Request\.Headers\b", "aspnet.Request.Headers", "ASP.NET request headers"),
            (r"Request\.Headers\[", "aspnet.Request.Headers[]", "ASP.NET header by key"),
            (r"Request\.Cookies\b", "aspnet.Request.Cookies", "ASP.NET cookies"),
            (r"Request\.Cookies\[", "aspnet.Request.Cookies[]", "ASP.NET cookie by key"),
            (r"Request\.Path\b", "aspnet.Request.Path", "ASP.NET request path"),
            (r"Request\.RouteValues\b", "aspnet.Request.RouteValues", "ASP.NET route values"),
            (r"Request\.QueryString\b", "aspnet.Request.QueryString", "ASP.NET raw query string"),
            (r"Request\.ContentType\b", "aspnet.Request.ContentType", "ASP.NET content type"),
            (r"Request\.Host\b", "aspnet.Request.Host", "ASP.NET host header"),
            (r"Request\.Files\b", "aspnet.Request.Files", "ASP.NET uploaded files"),
            # MVC binding
            (r"\[FromQuery\]", "aspnet.FromQuery", "ASP.NET query binding attribute"),
            (r"\[FromBody\]", "aspnet.FromBody", "ASP.NET body binding attribute"),
            (r"\[FromForm\]", "aspnet.FromForm", "ASP.NET form binding attribute"),
            (r"\[FromHeader\]", "aspnet.FromHeader", "ASP.NET header binding attribute"),
            (r"\[FromRoute\]", "aspnet.FromRoute", "ASP.NET route binding attribute"),
            # Environment
            (r"Environment\.GetEnvironmentVariable\s*\(", "dotnet.Environment.GetEnv", "Environment variable read"),
            (r"Console\.ReadLine\s*\(", "dotnet.Console.ReadLine", "Console input"),
            (r"Console\.Read\s*\(", "dotnet.Console.Read", "Console character input"),
            (r"args\b", "dotnet.args", "Command line args"),
        ]

    # ── PHP Sources ─────────────────────────────────────────────────────────

    def _php_sources(self) -> List[Tuple[str, str, str]]:
        """PHP taint sources — superglobals, Laravel, Symfony."""
        return [
            # Superglobals
            (r"\$_GET\b", "php.$_GET", "PHP GET superglobal"),
            (r"\$_GET\s*\[", "php.$_GET[]", "PHP GET parameter by key"),
            (r"\$_POST\b", "php.$_POST", "PHP POST superglobal"),
            (r"\$_POST\s*\[", "php.$_POST[]", "PHP POST parameter by key"),
            (r"\$_REQUEST\b", "php.$_REQUEST", "PHP REQUEST superglobal"),
            (r"\$_REQUEST\s*\[", "php.$_REQUEST[]", "PHP REQUEST parameter by key"),
            (r"\$_COOKIE\b", "php.$_COOKIE", "PHP COOKIE superglobal"),
            (r"\$_COOKIE\s*\[", "php.$_COOKIE[]", "PHP cookie by key"),
            (r"\$_FILES\b", "php.$_FILES", "PHP FILES superglobal"),
            (r"\$_FILES\s*\[", "php.$_FILES[]", "PHP uploaded file by key"),
            (r"\$_SERVER\b", "php.$_SERVER", "PHP SERVER superglobal"),
            (r"\$_SERVER\s*\[\s*['\"]HTTP_", "php.$_SERVER[HTTP_*]", "PHP HTTP header via SERVER"),
            (r"\$_SERVER\s*\[\s*['\"]REQUEST_URI", "php.$_SERVER[REQUEST_URI]", "PHP request URI"),
            (r"\$_SERVER\s*\[\s*['\"]QUERY_STRING", "php.$_SERVER[QUERY_STRING]", "PHP query string"),
            (r"\$_SERVER\s*\[\s*['\"]PATH_INFO", "php.$_SERVER[PATH_INFO]", "PHP path info"),
            (r"\$_SERVER\s*\[\s*['\"]REMOTE_ADDR", "php.$_SERVER[REMOTE_ADDR]", "PHP remote address"),
            (r"\$_ENV\b", "php.$_ENV", "PHP ENV superglobal"),
            (r"\$_SESSION\b", "php.$_SESSION", "PHP SESSION superglobal"),
            # PHP input functions
            (r"file_get_contents\s*\(\s*['\"]php://input['\"]", "php.php_input", "PHP raw input stream"),
            (r"getenv\s*\(", "php.getenv", "PHP environment variable"),
            (r"php_sapi_name\s*\(", "php.sapi_name", "PHP SAPI name"),
            # Laravel
            (r"\$request->input\s*\(", "laravel.request.input", "Laravel request input"),
            (r"\$request->get\s*\(", "laravel.request.get", "Laravel request get"),
            (r"\$request->query\s*\(", "laravel.request.query", "Laravel query parameter"),
            (r"\$request->post\s*\(", "laravel.request.post", "Laravel POST parameter"),
            (r"\$request->all\s*\(", "laravel.request.all", "Laravel all input"),
            (r"\$request->file\s*\(", "laravel.request.file", "Laravel uploaded file"),
            (r"\$request->header\s*\(", "laravel.request.header", "Laravel request header"),
            (r"\$request->cookie\s*\(", "laravel.request.cookie", "Laravel cookie"),
            # Symfony
            (r"\$request->query->get\s*\(", "symfony.request.query", "Symfony query parameter"),
            (r"\$request->request->get\s*\(", "symfony.request.post", "Symfony POST parameter"),
            (r"\$request->headers->get\s*\(", "symfony.request.header", "Symfony request header"),
            (r"\$request->files->get\s*\(", "symfony.request.file", "Symfony uploaded file"),
            (r"\$request->cookies->get\s*\(", "symfony.request.cookie", "Symfony cookie"),
            (r"\$request->getContent\s*\(", "symfony.request.content", "Symfony raw content"),
        ]

    # ── Go Sources ──────────────────────────────────────────────────────────

    def _go_sources(self) -> List[Tuple[str, str, str]]:
        """Go taint sources — net/http, Gin, Echo."""
        return [
            # net/http
            (r"r\.URL\.Query\s*\(", "go.r.URL.Query", "Go URL query parameters"),
            (r"r\.FormValue\s*\(", "go.r.FormValue", "Go form value"),
            (r"r\.PostFormValue\s*\(", "go.r.PostFormValue", "Go POST form value"),
            (r"r\.Header\.Get\s*\(", "go.r.Header.Get", "Go request header"),
            (r"r\.Header\.Values\s*\(", "go.r.Header.Values", "Go header values"),
            (r"r\.Body\b", "go.r.Body", "Go request body reader"),
            (r"r\.Form\b", "go.r.Form", "Go parsed form data"),
            (r"r\.PostForm\b", "go.r.PostForm", "Go POST form data"),
            (r"r\.MultipartForm\b", "go.r.MultipartForm", "Go multipart form data"),
            (r"r\.URL\.Path\b", "go.r.URL.Path", "Go URL path"),
            (r"r\.URL\.RawQuery\b", "go.r.URL.RawQuery", "Go raw query string"),
            (r"r\.Host\b", "go.r.Host", "Go request host"),
            (r"r\.RemoteAddr\b", "go.r.RemoteAddr", "Go remote address"),
            (r"r\.Referer\s*\(", "go.r.Referer", "Go referrer"),
            (r"r\.UserAgent\s*\(", "go.r.UserAgent", "Go user agent"),
            (r"r\.Cookie\s*\(", "go.r.Cookie", "Go request cookie"),
            (r"r\.Cookies\s*\(", "go.r.Cookies", "Go all cookies"),
            # Gin framework
            (r"c\.Query\s*\(", "gin.c.Query", "Gin query parameter"),
            (r"c\.DefaultQuery\s*\(", "gin.c.DefaultQuery", "Gin query with default"),
            (r"c\.Param\s*\(", "gin.c.Param", "Gin path parameter"),
            (r"c\.PostForm\s*\(", "gin.c.PostForm", "Gin POST form value"),
            (r"c\.GetHeader\s*\(", "gin.c.GetHeader", "Gin request header"),
            (r"c\.Cookie\s*\(", "gin.c.Cookie", "Gin cookie"),
            (r"c\.Request\b", "gin.c.Request", "Gin raw request"),
            # Echo framework
            (r"c\.QueryParam\s*\(", "echo.c.QueryParam", "Echo query parameter"),
            (r"c\.FormValue\s*\(", "echo.c.FormValue", "Echo form value"),
            (r"c\.Param\s*\(", "echo.c.Param", "Echo path parameter"),
            # os / env
            (r"os\.Getenv\s*\(", "go.os.Getenv", "Go environment variable"),
            (r"os\.Args\b", "go.os.Args", "Go command line arguments"),
            (r"os\.Stdin\b", "go.os.Stdin", "Go standard input"),
            (r"flag\.String\s*\(", "go.flag.String", "Go command line flag"),
            (r"flag\.Arg\s*\(", "go.flag.Arg", "Go command line argument"),
        ]

    # ── Ruby Sources ────────────────────────────────────────────────────────

    def _ruby_sources(self) -> List[Tuple[str, str, str]]:
        """Ruby taint sources — Rails, Sinatra."""
        return [
            # Rails / Sinatra params
            (r"params\b", "rails.params", "Rails/Sinatra params hash"),
            (r"params\[", "rails.params[]", "Rails params by key"),
            (r"params\.fetch\s*\(", "rails.params.fetch", "Rails params fetch"),
            (r"params\.permit\s*\(", "rails.params.permit", "Rails strong params permit"),
            (r"params\.require\s*\(", "rails.params.require", "Rails strong params require"),
            # Request object
            (r"request\.env\b", "rails.request.env", "Rails request environment"),
            (r"request\.body\b", "rails.request.body", "Rails request body"),
            (r"request\.headers\b", "rails.request.headers", "Rails request headers"),
            (r"request\.url\b", "rails.request.url", "Rails request URL"),
            (r"request\.path\b", "rails.request.path", "Rails request path"),
            (r"request\.host\b", "rails.request.host", "Rails request host"),
            (r"request\.referrer\b", "rails.request.referrer", "Rails referrer"),
            (r"request\.user_agent\b", "rails.request.user_agent", "Rails user agent"),
            (r"request\.query_string\b", "rails.request.query_string", "Rails query string"),
            (r"request\.raw_post\b", "rails.request.raw_post", "Rails raw POST body"),
            (r"request\.ip\b", "rails.request.ip", "Rails client IP"),
            # Cookies
            (r"cookies\[", "rails.cookies[]", "Rails cookie by key"),
            (r"session\[", "rails.session[]", "Rails session by key"),
            # Environment
            (r"ENV\[", "ruby.ENV[]", "Ruby environment variable"),
            (r"ENV\.fetch\s*\(", "ruby.ENV.fetch", "Ruby env fetch"),
            (r"ARGV\b", "ruby.ARGV", "Ruby command line arguments"),
            (r"STDIN\b", "ruby.STDIN", "Ruby standard input"),
            (r"gets\b", "ruby.gets", "Ruby gets() stdin read"),
            (r"readline\b", "ruby.readline", "Ruby readline() stdin read"),
        ]

    # ── Detection Entry Point ───────────────────────────────────────────────

    def detect_sources(
        self,
        code: str,
        language: Language,
        file_path: str = "",
        context_lines: int = 2,
    ) -> List[SourceHit]:
        """
        Detect all taint sources in the given code for the specified language.

        Args:
            code: Source code to analyze.
            language: Programming language of the code.
            file_path: Path to the file (for location info).
            context_lines: Number of lines of context to include.

        Returns:
            List of SourceHit objects with locations and metadata.
        """
        with self._lock:
            if language not in self._compiled_patterns:
                return []

            hits: List[SourceHit] = []
            lines = code.split("\n")
            patterns = self._compiled_patterns[language]

            for line_idx, line in enumerate(lines):
                stripped = line.lstrip()
                if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                    continue
                # Skip comment blocks
                if stripped.startswith("/*") or stripped.startswith("*"):
                    continue
                # Skip string-only lines (documentation)
                if stripped.startswith('"""') or stripped.startswith("'''"):
                    continue

                for compiled_re, name, desc in patterns:
                    try:
                        matches = list(compiled_re.finditer(line))
                    except (re.error, TypeError) as exc:
                        logger.warning("Regex match error for pattern '%s' in %s: %s", name, file_path, exc)
                        continue
                    for match in matches:
                        # Extract variable name from assignment context
                        var_name = self._extract_variable_name(line, match.start())

                        # Build context
                        ctx_before = "\n".join(
                            lines[max(0, line_idx - context_lines):line_idx]
                        )
                        ctx_after = "\n".join(
                            lines[line_idx + 1:min(len(lines), line_idx + context_lines + 1)]
                        )

                        # Determine enclosing function/class
                        func_name = self._find_enclosing_function(lines, line_idx, language)
                        cls_name = self._find_enclosing_class(lines, line_idx, language)

                        location = CodeLocation(
                            file_path=file_path,
                            line_number=line_idx + 1,
                            column=match.start(),
                            end_line=line_idx + 1,
                            end_column=match.end(),
                            snippet=line.rstrip(),
                            context_before=ctx_before,
                            context_after=ctx_after,
                            function_name=func_name,
                            class_name=cls_name,
                        )

                        hit = SourceHit(
                            location=location,
                            source_pattern=name,
                            variable_name=var_name,
                            language=language,
                            description=desc,
                        )
                        hits.append(hit)
                        self._stats["sources_detected"] += 1

            self._stats["files_analyzed"] += 1
            return hits

    def _extract_variable_name(self, line: str, match_pos: int) -> str:
        """Try to extract the variable name from an assignment on this line."""
        # Pattern: var_name = <source>
        before = line[:match_pos].rstrip()
        # Check for assignment operators
        for op in ("=", ":=", "var ", "let ", "const ", "val "):
            if op in before:
                parts = before.split(op)
                if parts:
                    candidate = parts[0].strip().split()[-1] if parts[0].strip() else ""
                    # Clean up type annotations
                    if ":" in candidate:
                        candidate = candidate.split(":")[0]
                    return candidate.strip()
        return ""

    def _find_enclosing_function(
        self, lines: List[str], current_line: int, language: Language
    ) -> str:
        """Walk backwards to find the enclosing function name."""
        func_patterns = {
            Language.PYTHON: re.compile(r"^\s*(?:async\s+)?def\s+(\w+)\s*\("),
            Language.JAVASCRIPT: re.compile(
                r"(?:(?:async\s+)?function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\(?|(\w+)\s*\(.*\)\s*\{)"
            ),
            Language.JAVA: re.compile(
                r"(?:public|private|protected|static|\s)+[\w<>\[\]]+\s+(\w+)\s*\("
            ),
            Language.CSHARP: re.compile(
                r"(?:public|private|protected|internal|static|async|\s)+[\w<>\[\]]+\s+(\w+)\s*\("
            ),
            Language.PHP: re.compile(
                r"(?:public|private|protected|static|\s)*function\s+(\w+)\s*\("
            ),
            Language.GO: re.compile(r"func\s+(?:\([^)]+\)\s+)?(\w+)\s*\("),
            Language.RUBY: re.compile(r"def\s+(\w+)"),
        }

        pattern = func_patterns.get(language)
        if not pattern:
            return ""

        for i in range(current_line - 1, max(-1, current_line - 200), -1):
            if i < 0:
                break
            m = pattern.search(lines[i])
            if m:
                # Return first non-None group
                for g in m.groups():
                    if g:
                        return g
        return ""

    def _find_enclosing_class(
        self, lines: List[str], current_line: int, language: Language
    ) -> str:
        """Walk backwards to find the enclosing class name."""
        class_patterns = {
            Language.PYTHON: re.compile(r"^\s*class\s+(\w+)"),
            Language.JAVASCRIPT: re.compile(r"class\s+(\w+)"),
            Language.JAVA: re.compile(r"(?:public|private|protected|\s)*class\s+(\w+)"),
            Language.CSHARP: re.compile(r"(?:public|private|protected|internal|\s)*class\s+(\w+)"),
            Language.PHP: re.compile(r"class\s+(\w+)"),
            Language.GO: re.compile(r"type\s+(\w+)\s+struct\b"),
            Language.RUBY: re.compile(r"class\s+(\w+)"),
        }

        pattern = class_patterns.get(language)
        if not pattern:
            return ""

        for i in range(current_line - 1, max(-1, current_line - 500), -1):
            if i < 0:
                break
            m = pattern.search(lines[i])
            if m:
                return m.group(1)
        return ""

    def get_stats(self) -> Dict[str, Any]:
        """Return detection statistics."""
        with self._lock:
            return dict(self._stats)

    def get_supported_languages(self) -> List[Language]:
        """Return list of languages with source patterns."""
        return list(self._source_patterns.keys())

    def get_pattern_count(self, language: Optional[Language] = None) -> int:
        """Return number of source patterns, optionally for a specific language."""
        if language:
            return len(self._source_patterns.get(language, []))
        return sum(len(p) for p in self._source_patterns.values())


# ════════════════════════════════════════════════════════════════════════════════
# SIREN SAST ENGINE — ORCHESTRATOR
# ════════════════════════════════════════════════════════════════════════════════


class SirenSASTEngine:
    """
    Orchestrates end-to-end Static Application Security Testing.

    Coordinates SourceDetector with taint flow analysis, sink detection,
    false-positive filtering, and report generation for comprehensive
    multi-language source code analysis.

    Usage::

        engine = SirenSASTEngine()

        # Full scan of a directory
        report = engine.full_scan("/path/to/source")

        # Scan with custom config
        config = ScanConfig(enable_taint_analysis=True, severity_threshold=Severity.MEDIUM)
        report = engine.full_scan("/path/to/source", config=config)

        # Scan a single file
        findings = engine.scan_file("app.py", code_content)

        # Report
        report = engine.generate_report()
    """

    # ── Sink Patterns (dangerous function calls per language) ────────────

    SINK_PATTERNS: Dict[Language, List[Tuple[str, VulnType, str]]] = {
        Language.PYTHON: [
            (r"cursor\.execute\s*\(.*%s|cursor\.execute\s*\(.*\.format\(|cursor\.execute\s*\(.*\+",
             VulnType.SQL_INJECTION, "Direct string interpolation in SQL query"),
            (r"os\.system\s*\(|os\.popen\s*\(|subprocess\.call\s*\(.*shell\s*=\s*True|subprocess\.Popen\s*\(.*shell\s*=\s*True",
             VulnType.COMMAND_INJECTION, "Shell command execution with potential user input"),
            (r"eval\s*\(|exec\s*\(|compile\s*\(",
             VulnType.CODE_INJECTION, "Dynamic code evaluation"),
            (r"open\s*\(.*\+|open\s*\(.*format|os\.path\.join\s*\(.*\+",
             VulnType.PATH_TRAVERSAL, "File path construction with potential traversal"),
            (r"requests\.get\s*\(|requests\.post\s*\(|urllib\.request\.urlopen\s*\(|httpx\.",
             VulnType.SSRF, "HTTP request with potentially user-controlled URL"),
            (r"pickle\.loads?\s*\(|yaml\.load\s*\(|yaml\.unsafe_load\s*\(",
             VulnType.DESERIALIZATION, "Deserialization of untrusted data"),
            (r"render_template_string\s*\(|Template\s*\(",
             VulnType.TEMPLATE_INJECTION, "Server-side template injection"),
            (r"redirect\s*\(.*request\.|redirect\s*\(.*url_for",
             VulnType.OPEN_REDIRECT, "Redirect with user-controlled destination"),
            (r"flask\.make_response\(.*\<|Markup\s*\(.*\+|\.html\s*=",
             VulnType.CROSS_SITE_SCRIPTING, "Unsanitized HTML output"),
            (r"hashlib\.md5\s*\(|hashlib\.sha1\s*\(",
             VulnType.WEAK_CRYPTO, "Usage of weak cryptographic hash"),
            (r"random\.random\s*\(|random\.randint\s*\(",
             VulnType.INSECURE_RANDOM, "Non-cryptographic random for security-sensitive use"),
        ],
        Language.JAVASCRIPT: [
            (r"\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(",
             VulnType.CROSS_SITE_SCRIPTING, "DOM XSS through innerHTML/document.write"),
            (r"eval\s*\(|Function\s*\(|setTimeout\s*\(\s*['\"]|setInterval\s*\(\s*['\"]",
             VulnType.CODE_INJECTION, "Dynamic code evaluation"),
            (r"child_process\.exec\s*\(|child_process\.execSync\s*\(",
             VulnType.COMMAND_INJECTION, "Shell command execution"),
            (r"\.query\s*\(.*\+|\.query\s*\(.*`",
             VulnType.SQL_INJECTION, "SQL query with string concatenation"),
            (r"fetch\s*\(|axios\.\w+\s*\(|XMLHttpRequest",
             VulnType.SSRF, "HTTP request with potential user-controlled URL"),
            (r"path\.join\s*\(.*\+|fs\.(readFile|writeFile|unlink)\s*\(",
             VulnType.PATH_TRAVERSAL, "File system operation with user input"),
            (r"res\.redirect\s*\(.*req\.",
             VulnType.OPEN_REDIRECT, "Redirect with user-controlled URL"),
            (r"JSON\.parse\s*\(.*req\.",
             VulnType.DESERIALIZATION, "JSON parse of user-controlled data"),
        ],
        Language.JAVA: [
            (r"Statement\.execute\w*\s*\(.*\+|PreparedStatement.*\+.*\"",
             VulnType.SQL_INJECTION, "SQL query with string concatenation"),
            (r"Runtime\.getRuntime\(\)\.exec\s*\(|ProcessBuilder\s*\(",
             VulnType.COMMAND_INJECTION, "Process execution"),
            (r"ScriptEngine.*eval\s*\(",
             VulnType.CODE_INJECTION, "Script engine evaluation"),
            (r"ObjectInputStream\.readObject\s*\(|XMLDecoder",
             VulnType.DESERIALIZATION, "Java deserialization"),
            (r"new\s+URL\s*\(.*request\.|HttpURLConnection.*request\.",
             VulnType.SSRF, "HTTP connection with user-controlled URL"),
            (r"new\s+File\s*\(.*request\.|Paths\.get\s*\(.*request\.",
             VulnType.PATH_TRAVERSAL, "File path with user input"),
            (r"response\.sendRedirect\s*\(.*request\.",
             VulnType.OPEN_REDIRECT, "Redirect with user-controlled parameter"),
        ],
        Language.PHP: [
            (r"mysql_query\s*\(.*\$|mysqli_query\s*\(.*\$|->query\s*\(.*\$",
             VulnType.SQL_INJECTION, "SQL query with variable interpolation"),
            (r"system\s*\(|exec\s*\(|passthru\s*\(|shell_exec\s*\(|`.*\$",
             VulnType.COMMAND_INJECTION, "Shell command execution"),
            (r"eval\s*\(|assert\s*\(|preg_replace\s*\(.*e['\"]",
             VulnType.CODE_INJECTION, "Dynamic code evaluation"),
            (r"unserialize\s*\(",
             VulnType.DESERIALIZATION, "PHP object deserialization"),
            (r"file_get_contents\s*\(.*\$|curl_exec\s*\(",
             VulnType.SSRF, "HTTP request with user-controlled URL"),
            (r"include\s*\(.*\$|require\s*\(.*\$|include_once\s*\(.*\$",
             VulnType.PATH_TRAVERSAL, "File inclusion with user input (LFI/RFI)"),
            (r"echo\s+\$|print\s+\$|<\?=\s*\$",
             VulnType.CROSS_SITE_SCRIPTING, "Direct output of user variable"),
            (r"header\s*\(\s*['\"]Location:.*\$",
             VulnType.OPEN_REDIRECT, "Redirect with user-controlled header"),
        ],
    }

    # ── Sanitizer Patterns ──────────────────────────────────────────────

    SANITIZER_PATTERNS: Dict[VulnType, List[str]] = {
        VulnType.SQL_INJECTION: [
            r"parameterized|prepared|placeholder|\?\s*,|\%s\s*,\s*\(",
            r"\.escape\s*\(|escape_string|quote_literal",
            r"ORM|Model\.|filter\(|where\(",
        ],
        VulnType.CROSS_SITE_SCRIPTING: [
            r"escape\s*\(|html\.escape|cgi\.escape|bleach\.clean",
            r"sanitize|DOMPurify|xss_clean|htmlspecialchars",
            r"Content-Security-Policy|CSP",
        ],
        VulnType.COMMAND_INJECTION: [
            r"shlex\.quote|shlex\.split|escapeshellarg|escapeshellcmd",
            r"whitelist|allowlist|re\.match\(",
            r"shell\s*=\s*False",
        ],
        VulnType.PATH_TRAVERSAL: [
            r"os\.path\.abspath|os\.path\.realpath|secure_filename",
            r"\.replace\s*\(\s*['\"]\.\.['\"]\s*,|normpath",
            r"whitelist|allowlist|ALLOWED_EXTENSIONS",
        ],
        VulnType.SSRF: [
            r"allowlist|whitelist|ALLOWED_HOSTS|ALLOWED_URLS",
            r"urlparse\(.*\.netloc|validate_url",
            r"internal|private|blocked|denied",
        ],
    }

    def __init__(self, config: Optional[ScanConfig] = None) -> None:
        self._lock = threading.RLock()
        self._config = config or ScanConfig()

        # Sub-engines
        self._source_detector = SourceDetector()

        # State
        self._findings: List[SASTFinding] = []
        self._files_scanned: int = 0
        self._files_skipped: int = 0
        self._lines_analyzed: int = 0
        self._languages_detected: Dict[str, int] = defaultdict(int)
        self._taint_flows_traced: int = 0
        self._total_sources: int = 0
        self._total_sinks: int = 0
        self._scan_errors: List[str] = []
        self._scan_start: float = 0.0
        self._scan_end: float = 0.0

        logger.info("SirenSASTEngine initialized (taint=%s, fp_reduction=%s)",
                     self._config.enable_taint_analysis,
                     self._config.enable_false_positive_reduction)

    # ── Language Detection ──────────────────────────────────────────────

    def _detect_language(self, file_path: str) -> Language:
        """Detect programming language from file extension."""
        ext_map = {
            ".py": Language.PYTHON,
            ".js": Language.JAVASCRIPT, ".jsx": Language.JAVASCRIPT,
            ".ts": Language.JAVASCRIPT, ".tsx": Language.JAVASCRIPT,
            ".mjs": Language.JAVASCRIPT, ".cjs": Language.JAVASCRIPT,
            ".java": Language.JAVA,
            ".cs": Language.CSHARP,
            ".php": Language.PHP,
            ".go": Language.GO,
            ".rb": Language.RUBY, ".erb": Language.RUBY,
        }
        ext = os.path.splitext(file_path)[1].lower()
        return ext_map.get(ext, Language.UNKNOWN)

    def _should_skip_file(self, file_path: str) -> bool:
        """Check if file should be excluded from scan."""
        parts = file_path.replace("\\", "/").split("/")
        for part in parts:
            if part in self._config.excluded_dirs:
                return True
        filename = os.path.basename(file_path)
        for pattern in self._config.excluded_files:
            if pattern.startswith("*"):
                if filename.endswith(pattern[1:]):
                    return True
            elif filename == pattern:
                return True
        return False

    # ── Sink Detection ──────────────────────────────────────────────────

    def _detect_sinks(
        self, lines: List[str], language: Language, file_path: str
    ) -> List[SinkHit]:
        """Detect dangerous sinks in source code."""
        sinks: List[SinkHit] = []
        patterns = self.SINK_PATTERNS.get(language, [])
        if not patterns:
            return sinks

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                continue
            for pattern_str, vuln_type, description in patterns:
                try:
                    if re.search(pattern_str, stripped, re.IGNORECASE):
                        func_name = self._source_detector._find_enclosing_function(
                            lines, i, language
                        ) if hasattr(self._source_detector, '_find_enclosing_function') else ""
                        class_name = self._source_detector._find_enclosing_class(
                            lines, i, language
                        ) if hasattr(self._source_detector, '_find_enclosing_class') else ""
                        sinks.append(SinkHit(
                            location=CodeLocation(
                                file_path=file_path,
                                line_number=i,
                                column=0,
                                function_name=func_name,
                                class_name=class_name,
                                code_snippet=stripped[:200],
                            ),
                            sink_pattern=pattern_str[:80],
                            vuln_type=vuln_type,
                            language=language,
                            description=description,
                        ))
                except re.error:
                    pass

        return sinks

    # ── Taint Flow Analysis ─────────────────────────────────────────────

    def _trace_taint_flow(
        self, sources: List[SourceHit], sinks: List[SinkHit], lines: List[str], language: Language
    ) -> List[TaintFlow]:
        """Trace taint flows from sources to sinks within the same scope."""
        flows: List[TaintFlow] = []

        for source in sources:
            src_func = source.location.function_name
            src_var = source.variable_name

            for sink in sinks:
                sink_func = sink.location.function_name

                # Same function scope check
                if src_func and sink_func and src_func == sink_func:
                    # Check if source variable appears in sink line
                    sink_line = lines[sink.location.line_number - 1] if sink.location.line_number <= len(lines) else ""
                    if src_var and src_var in sink_line:
                        # Check for sanitizers between source and sink
                        status = FlowStatus.CONFIRMED
                        sanitizer = ""

                        if self._config.enable_false_positive_reduction:
                            san = self._check_sanitizer(
                                lines, source.location.line_number,
                                sink.location.line_number, sink.vuln_type,
                            )
                            if san:
                                status = FlowStatus.SANITIZED
                                sanitizer = san

                        flows.append(TaintFlow(
                            source=source.location,
                            sink=sink.location,
                            via_path=[source.location, sink.location],
                            tainted_variable=src_var,
                            vuln_type=sink.vuln_type,
                            status=status,
                            sanitizer_applied=sanitizer,
                            confidence=0.85 if status == FlowStatus.CONFIRMED else 0.3,
                        ))
                        self._taint_flows_traced += 1

                # Cross-function (lower confidence)
                elif source.location.line_number < sink.location.line_number:
                    if src_var and src_var in (lines[sink.location.line_number - 1] if sink.location.line_number <= len(lines) else ""):
                        flows.append(TaintFlow(
                            source=source.location,
                            sink=sink.location,
                            via_path=[source.location, sink.location],
                            tainted_variable=src_var,
                            vuln_type=sink.vuln_type,
                            status=FlowStatus.POTENTIAL,
                            confidence=0.5,
                        ))
                        self._taint_flows_traced += 1

        return flows

    def _check_sanitizer(
        self, lines: List[str], source_line: int, sink_line: int, vuln_type: VulnType
    ) -> str:
        """Check for sanitizer patterns between source and sink lines."""
        sanitizer_pats = self.SANITIZER_PATTERNS.get(vuln_type, [])
        if not sanitizer_pats:
            return ""

        for i in range(source_line, min(sink_line, len(lines))):
            line = lines[i]
            for san_pattern in sanitizer_pats:
                try:
                    if re.search(san_pattern, line, re.IGNORECASE):
                        return san_pattern[:60]
                except re.error:
                    pass
        return ""

    # ── Finding Generation ──────────────────────────────────────────────

    def _create_finding_from_flow(self, flow: TaintFlow, language: Language) -> SASTFinding:
        """Create a SASTFinding from a traced taint flow."""
        cwe = VULN_CWE_MAP.get(flow.vuln_type, 0)
        owasp = VULN_OWASP_MAP.get(flow.vuln_type, "")
        severity = VULN_SEVERITY_MAP.get(flow.vuln_type, Severity.MEDIUM)

        if flow.status == FlowStatus.SANITIZED:
            severity = Severity.INFO

        confidence = ConfidenceLevel.HIGH if flow.confidence > 0.75 else (
            ConfidenceLevel.MEDIUM if flow.confidence > 0.4 else ConfidenceLevel.LOW
        )

        return SASTFinding(
            title=f"{flow.vuln_type.name} — tainted data flow",
            description=(
                f"Tainted data from '{flow.tainted_variable}' flows from "
                f"line {flow.source.line_number} to sink at line {flow.sink.line_number}. "
                f"Status: {flow.status.name}."
            ),
            vuln_type=flow.vuln_type,
            severity=severity,
            confidence=confidence,
            language=language,
            location=flow.sink,
            taint_flow=flow,
            cwe_id=cwe,
            owasp_category=owasp,
            remediation=self._get_remediation(flow.vuln_type),
            tags=["taint-flow", flow.vuln_type.name.lower()],
            is_false_positive=(flow.status == FlowStatus.SANITIZED),
            false_positive_reason=f"Sanitizer detected: {flow.sanitizer_applied}" if flow.sanitizer_applied else "",
        )

    def _create_finding_from_sink(self, sink: SinkHit) -> SASTFinding:
        """Create a SASTFinding from an unmatched dangerous sink (no taint tracing)."""
        cwe = VULN_CWE_MAP.get(sink.vuln_type, 0)
        owasp = VULN_OWASP_MAP.get(sink.vuln_type, "")
        severity = VULN_SEVERITY_MAP.get(sink.vuln_type, Severity.MEDIUM)

        return SASTFinding(
            title=f"{sink.vuln_type.name} — dangerous sink",
            description=f"{sink.description} at {sink.location.file_path}:{sink.location.line_number}",
            vuln_type=sink.vuln_type,
            severity=severity,
            confidence=ConfidenceLevel.LOW,
            language=sink.language,
            location=sink.location,
            cwe_id=cwe,
            owasp_category=owasp,
            remediation=self._get_remediation(sink.vuln_type),
            matched_pattern=sink.sink_pattern,
            raw_match=sink.location.code_snippet[:120],
            tags=["pattern-match", sink.vuln_type.name.lower()],
        )

    @staticmethod
    def _get_remediation(vuln_type: VulnType) -> str:
        """Return remediation guidance for a vulnerability type."""
        remediations: Dict[VulnType, str] = {
            VulnType.SQL_INJECTION: "Use parameterized queries or ORM. Never concatenate user input into SQL strings.",
            VulnType.CROSS_SITE_SCRIPTING: "HTML-encode all output. Use Content-Security-Policy headers. Sanitize with DOMPurify.",
            VulnType.COMMAND_INJECTION: "Avoid shell=True. Use shlex.quote() or subprocess with arg lists. Whitelist allowed commands.",
            VulnType.PATH_TRAVERSAL: "Use os.path.abspath() + prefix check. Whitelist allowed paths. Use secure_filename().",
            VulnType.SSRF: "Whitelist allowed hosts/IPs. Block internal/private ranges. Validate URLs before requests.",
            VulnType.DESERIALIZATION: "Never deserialize untrusted data. Use JSON instead of pickle/yaml.load. Validate types.",
            VulnType.CODE_INJECTION: "Avoid eval/exec. Use AST parsing or safe expression evaluators. Sandbox execution.",
            VulnType.TEMPLATE_INJECTION: "Use auto-escaping templates. Never pass user input to template constructors.",
            VulnType.OPEN_REDIRECT: "Whitelist redirect destinations. Validate URLs against allowed domains.",
            VulnType.WEAK_CRYPTO: "Use SHA-256+ for hashing, AES-256-GCM for encryption. Avoid MD5/SHA1.",
            VulnType.INSECURE_RANDOM: "Use secrets module (Python) or crypto.getRandomValues() for security-sensitive randomness.",
            VulnType.HARDCODED_SECRET: "Move secrets to environment variables or a secrets manager (Vault, AWS SM, etc.).",
            VulnType.LDAP_INJECTION: "Use parameterized LDAP filters. Escape special characters in user input.",
        }
        return remediations.get(vuln_type, "Review and remediate according to OWASP guidelines.")

    # ── File Scanning ───────────────────────────────────────────────────

    def scan_file(self, file_path: str, content: str) -> List[SASTFinding]:
        """Scan a single file for vulnerabilities."""
        if not content:
            logger.warning("Empty or None content for file: %s", file_path)
            return []

        # Skip likely binary files (contain null bytes)
        if "\x00" in content[:8192]:
            logger.warning("Skipping likely binary file: %s", file_path)
            with self._lock:
                self._files_skipped += 1
            return []

        with self._lock:
            language = self._detect_language(file_path)
            if language == Language.UNKNOWN:
                self._files_skipped += 1
                return []

            lines = content.split("\n")
            self._lines_analyzed += len(lines)
            self._languages_detected[language.name] += 1

            # Detect sources (taint origins)
            try:
                sources = self._source_detector.detect_sources(content, language, file_path)
            except Exception as exc:
                logger.warning("Source detection failed for %s: %s", file_path, exc)
                sources = []
            self._total_sources += len(sources)

            # Detect sinks (dangerous calls)
            try:
                sinks = self._detect_sinks(lines, language, file_path)
            except Exception as exc:
                logger.warning("Sink detection failed for %s: %s", file_path, exc)
                sinks = []
            self._total_sinks += len(sinks)

            findings: List[SASTFinding] = []

            # Taint flow analysis: match sources → sinks
            if self._config.enable_taint_analysis and sources and sinks:
                flows = self._trace_taint_flow(sources, sinks, lines, language)
                matched_sinks: Set[int] = set()
                for flow in flows:
                    finding = self._create_finding_from_flow(flow, language)
                    findings.append(finding)
                    matched_sinks.add(flow.sink.line_number)

                # Unmatched sinks still get reported (lower confidence)
                for sink in sinks:
                    if sink.location.line_number not in matched_sinks:
                        findings.append(self._create_finding_from_sink(sink))
            else:
                # No taint analysis — report all sinks as pattern matches
                for sink in sinks:
                    findings.append(self._create_finding_from_sink(sink))

            # Hardcoded secret detection (standalone — not taint-flow)
            findings.extend(self._detect_hardcoded_secrets(lines, file_path, language))

            # Deduplicate by fingerprint
            seen: Set[str] = set()
            deduped: List[SASTFinding] = []
            for f in findings:
                fp = f.fingerprint()
                if fp not in seen:
                    seen.add(fp)
                    deduped.append(f)

            # Apply severity threshold
            if self._config.severity_threshold != Severity.INFO:
                severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
                threshold_idx = severity_order.index(self._config.severity_threshold)
                deduped = [f for f in deduped if severity_order.index(f.severity) <= threshold_idx]

            # Enforce per-file limit
            deduped = deduped[:self._config.max_findings_per_file]

            self._findings.extend(deduped)
            self._files_scanned += 1

            return deduped

    def _detect_hardcoded_secrets(
        self, lines: List[str], file_path: str, language: Language
    ) -> List[SASTFinding]:
        """Detect hardcoded secrets, API keys, and passwords in source code."""
        findings: List[SASTFinding] = []
        secret_patterns = [
            (r"['\"](?:password|passwd|pwd)\s*['\"]?\s*[:=]\s*['\"][^'\"]{4,}['\"]",
             "Hardcoded password"),
            (r"(?:api_?key|apikey|api_?secret)\s*[:=]\s*['\"][A-Za-z0-9+/=_-]{16,}['\"]",
             "Hardcoded API key"),
            (r"(?:AKIA|ASIA)[A-Z0-9]{16}",
             "AWS Access Key ID"),
            (r"(?:secret_?key|SECRET_KEY)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
             "Hardcoded secret key"),
            (r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
             "Embedded private key"),
            (r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}",
             "GitHub personal access token"),
            (r"sk-[A-Za-z0-9]{32,}",
             "OpenAI/Stripe secret key"),
            (r"Bearer\s+[A-Za-z0-9._~+/=-]{20,}",
             "Hardcoded bearer token"),
        ]

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*"):
                continue
            for pattern, description in secret_patterns:
                try:
                    m = re.search(pattern, stripped, re.IGNORECASE)
                    if m:
                        findings.append(SASTFinding(
                            title=f"HARDCODED_SECRET — {description}",
                            description=f"{description} at {file_path}:{i}",
                            vuln_type=VulnType.HARDCODED_SECRET,
                            severity=Severity.HIGH,
                            confidence=ConfidenceLevel.HIGH,
                            language=language,
                            location=CodeLocation(
                                file_path=file_path,
                                line_number=i,
                                code_snippet=stripped[:120],
                            ),
                            cwe_id=798,
                            owasp_category="A02:2021-Cryptographic Failures",
                            remediation="Move secrets to environment variables or a secrets manager.",
                            matched_pattern=pattern[:60],
                            raw_match=m.group(0)[:40] + "...",
                            tags=["hardcoded-secret"],
                        ))
                        break  # One finding per line
                except re.error:
                    pass

        return findings

    # ── Directory Scanning ──────────────────────────────────────────────

    def full_scan(self, target_path: str, config: Optional[ScanConfig] = None) -> SASTReport:
        """
        Execute a full SAST scan on a directory or single file.

        Walks the target path, detects languages, scans each file for
        sources/sinks, traces taint flows, and generates a consolidated report.
        """
        with self._lock:
            if config:
                self._config = config
            self._scan_start = time.time()
            logger.info("Starting SAST scan: %s", target_path)

        target = Path(target_path)

        if target.is_file():
            try:
                content = target.read_text(encoding="utf-8", errors="ignore")
                self.scan_file(str(target), content)
            except Exception as exc:
                with self._lock:
                    self._scan_errors.append(f"{target}: {exc}")
        elif target.is_dir():
            file_count = 0
            for root, dirs, files in os.walk(str(target)):
                # Prune excluded dirs (in-place modification)
                dirs[:] = [d for d in dirs if d not in self._config.excluded_dirs]

                for fname in sorted(files):
                    fpath = os.path.join(root, fname)

                    if self._should_skip_file(fpath):
                        with self._lock:
                            self._files_skipped += 1
                        continue

                    # Size check
                    try:
                        fsize = os.path.getsize(fpath)
                        if fsize > self._config.max_file_size:
                            with self._lock:
                                self._files_skipped += 1
                            continue
                    except OSError:
                        continue

                    try:
                        with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                            content = fh.read()
                        self.scan_file(fpath, content)
                    except Exception as exc:
                        with self._lock:
                            self._scan_errors.append(f"{fpath}: {exc}")

                    file_count += 1
                    if file_count >= self._config.max_files:
                        logger.warning("Max files limit reached (%d)", self._config.max_files)
                        break
                else:
                    continue
                break
        else:
            with self._lock:
                self._scan_errors.append(f"Target not found: {target_path}")

        with self._lock:
            self._scan_end = time.time()

        return self.generate_report(target_path)

    # ── Report Generation ───────────────────────────────────────────────

    def generate_report(self, target_path: str = "") -> SASTReport:
        """Generate a consolidated SAST report."""
        with self._lock:
            report = SASTReport(
                scan_start=self._scan_start,
                scan_end=self._scan_end,
                scan_duration=self._scan_end - self._scan_start if self._scan_end else 0.0,
                status=ScanStatus.COMPLETED,
                target_path=target_path,
                files_scanned=self._files_scanned,
                files_skipped=self._files_skipped,
                lines_analyzed=self._lines_analyzed,
                languages_detected=dict(self._languages_detected),
                findings=list(self._findings),
                taint_flows_traced=self._taint_flows_traced,
                total_sources=self._total_sources,
                total_sinks=self._total_sinks,
                scan_errors=list(self._scan_errors),
            )
            report.compute_stats()

            logger.info(
                "SAST report: %d findings (%d FP filtered), %d files, %d lines in %.1fs",
                len(report.findings) - report.false_positives_filtered,
                report.false_positives_filtered,
                report.files_scanned,
                report.lines_analyzed,
                report.scan_duration,
            )
            return report

    # ── Accessors ───────────────────────────────────────────────────────

    def get_findings(self) -> List[SASTFinding]:
        with self._lock:
            return list(self._findings)

    def reset(self) -> None:
        """Reset all scan state."""
        with self._lock:
            self._findings.clear()
            self._files_scanned = 0
            self._files_skipped = 0
            self._lines_analyzed = 0
            self._languages_detected.clear()
            self._taint_flows_traced = 0
            self._total_sources = 0
            self._total_sinks = 0
            self._scan_errors.clear()
            self._scan_start = 0.0
            self._scan_end = 0.0
            logger.info("SirenSASTEngine state reset")

    def to_dict(self) -> Dict[str, Any]:
        """Serialize engine state."""
        with self._lock:
            return {
                "files_scanned": self._files_scanned,
                "files_skipped": self._files_skipped,
                "lines_analyzed": self._lines_analyzed,
                "languages_detected": dict(self._languages_detected),
                "total_findings": len(self._findings),
                "taint_flows_traced": self._taint_flows_traced,
                "total_sources": self._total_sources,
                "total_sinks": self._total_sinks,
                "scan_errors": len(self._scan_errors),
                "config": self._config.to_dict(),
            }
