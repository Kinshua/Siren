#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  🎯  SIREN THREAT HUNTING — Proactive Threat Detection & IOC Analysis  🎯     ██
██                                                                                ██
██  SIREN nao espera o ataque — ela CACA as ameacas antes que ataquem.            ██
██                                                                                ██
██  Capacidades:                                                                  ██
██    * IOC Extraction   — IPs, domains, URLs, hashes, emails, JA3, certs       ██
██    * SIGMA Rules      — 30+ detection rules in valid YAML format             ██
██    * YARA Rules       — 20+ rules for malware/webshell/RAT detection         ██
██    * Hunt Queries     — Splunk SPL, ELK KQL, Sentinel KQL, QRadar AQL       ██
██    * Hunt Playbooks   — 10+ pre-built investigation workflows                ██
██    * STIX 2.1 Export  — Full bundle export for threat intel sharing          ██
██    * Coverage Report  — MITRE ATT&CK detection coverage analysis            ██
██                                                                                ██
██  "A SIREN nao reage ao perigo — ela o persegue ate o fim do abismo."          ██
██                                                                                ██
████████████████████████████████████████████████████████████████████████████████████
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import math
import re
import struct
import textwrap
import threading
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

logger = logging.getLogger("siren.intelligence.threat_hunting")


# ════════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════════════════════════════

STIX_SPEC_VERSION = "2.1"
STIX_BUNDLE_TYPE = "bundle"
IOC_CONFIDENCE_HIGH = 0.85
IOC_CONFIDENCE_MEDIUM = 0.60
IOC_CONFIDENCE_LOW = 0.35
MAX_HUNT_DEPTH = 10
DEFAULT_LOOKBACK_DAYS = 30
MITRE_TACTIC_IDS = {
    "reconnaissance": "TA0043",
    "resource_development": "TA0042",
    "initial_access": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilege_escalation": "TA0004",
    "defense_evasion": "TA0005",
    "credential_access": "TA0006",
    "discovery": "TA0007",
    "lateral_movement": "TA0008",
    "collection": "TA0009",
    "command_and_control": "TA0011",
    "exfiltration": "TA0010",
    "impact": "TA0040",
}


# ════════════════════════════════════════════════════════════════════════════════
# ENUMS
# ════════════════════════════════════════════════════════════════════════════════


class IOCType(Enum):
    """Types of Indicators of Compromise."""
    IP_ADDRESS = auto()
    DOMAIN = auto()
    URL = auto()
    EMAIL = auto()
    HASH_MD5 = auto()
    HASH_SHA1 = auto()
    HASH_SHA256 = auto()
    HASH_SHA512 = auto()
    USER_AGENT = auto()
    FILE_PATH = auto()
    REGISTRY_KEY = auto()
    CVE_ID = auto()
    MITRE_TECHNIQUE = auto()
    JA3_FINGERPRINT = auto()
    CERTIFICATE_SERIAL = auto()
    MUTEX = auto()
    PIPE_NAME = auto()
    SERVICE_NAME = auto()


class ThreatSeverity(Enum):
    """Threat severity levels."""
    CRITICAL = auto()
    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()
    INFORMATIONAL = auto()


class HuntStatus(Enum):
    """Status of a threat hunt."""
    PENDING = auto()
    RUNNING = auto()
    COMPLETED = auto()
    FAILED = auto()
    CANCELLED = auto()


class RuleFormat(Enum):
    """Detection rule output formats."""
    SIGMA = auto()
    YARA = auto()
    SPLUNK_SPL = auto()
    ELK_KQL = auto()
    SENTINEL_KQL = auto()
    QRADAR_AQL = auto()
    SNORT = auto()
    SURICATA = auto()


class PlaybookPhase(Enum):
    """Phases of a threat hunt playbook."""
    HYPOTHESIS = auto()
    DATA_COLLECTION = auto()
    INVESTIGATION = auto()
    ANALYSIS = auto()
    RESPONSE = auto()
    DOCUMENTATION = auto()


class ThreatCategory(Enum):
    """Categories of threats for rule generation."""
    WEB_ATTACK = auto()
    AUTH_ANOMALY = auto()
    DATA_EXFILTRATION = auto()
    LATERAL_MOVEMENT = auto()
    PRIVILEGE_ESCALATION = auto()
    PERSISTENCE = auto()
    COMMAND_AND_CONTROL = auto()
    MALWARE = auto()
    INSIDER_THREAT = auto()
    RECONNAISSANCE = auto()


class StixObjectType(Enum):
    """STIX 2.1 object types."""
    INDICATOR = "indicator"
    MALWARE = "malware"
    ATTACK_PATTERN = "attack-pattern"
    THREAT_ACTOR = "threat-actor"
    CAMPAIGN = "campaign"
    RELATIONSHIP = "relationship"
    SIGHTING = "sighting"
    OBSERVED_DATA = "observed-data"
    IDENTITY = "identity"
    VULNERABILITY = "vulnerability"
    TOOL = "tool"
    INFRASTRUCTURE = "infrastructure"


# ════════════════════════════════════════════════════════════════════════════════
# REGEX PATTERNS
# ════════════════════════════════════════════════════════════════════════════════

_RE_IPV4 = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b'
)
_RE_IPV6 = re.compile(
    r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
    r'|'
    r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b'
    r'|'
    r'\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b'
    r'|'
    r'\b::(?:[fF]{4}:)?(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b'
)
_RE_DOMAIN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
    r'+(?:com|net|org|edu|gov|mil|io|co|us|uk|de|fr|ru|cn|jp|br|'
    r'info|biz|xyz|top|online|site|club|app|dev|tech|cloud|security|'
    r'onion|bit|cc|tv|me|pro|name|museum|aero|coop|int)\b'
)
_RE_URL = re.compile(
    r'https?://[^\s<>"\'`,;)\]}{|\\^~\x00-\x1f]{3,2048}'
)
_RE_EMAIL = re.compile(
    r'\b[a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'
)
_RE_MD5 = re.compile(r'\b[0-9a-fA-F]{32}\b')
_RE_SHA1 = re.compile(r'\b[0-9a-fA-F]{40}\b')
_RE_SHA256 = re.compile(r'\b[0-9a-fA-F]{64}\b')
_RE_SHA512 = re.compile(r'\b[0-9a-fA-F]{128}\b')
_RE_USER_AGENT = re.compile(
    r'(?:Mozilla|Opera|curl|wget|python-requests|Java|Apache-HttpClient|'
    r'Go-http-client|Ruby|PHP|Dalvik|okhttp|PostmanRuntime|Googlebot|'
    r'Bingbot|Baiduspider|YandexBot|DotBot|AhrefsBot|SemrushBot)'
    r'[^\r\n]{5,256}'
)
_RE_WIN_PATH = re.compile(
    r'[A-Z]:\\(?:[^\\\/:*?"<>|\r\n]+\\)*[^\\\/:*?"<>|\r\n]*'
)
_RE_UNIX_PATH = re.compile(
    r'(?:/(?:tmp|var|etc|usr|opt|home|root|proc|sys|dev|bin|sbin|lib|mnt|'
    r'media|srv|boot|run|snap)(?:/[^\s:*?"<>|;,\r\n]+)+)'
)
_RE_REGISTRY = re.compile(
    r'(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|'
    r'HKEY_USERS|HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR|HKU|HKCC)'
    r'\\[^\s;,\r\n]{3,512}'
)
_RE_CVE = re.compile(r'\bCVE-\d{4}-\d{4,7}\b')
_RE_MITRE = re.compile(r'\bT\d{4}(?:\.\d{3})?\b')
_RE_JA3 = re.compile(r'\b[0-9a-fA-F]{32}\b')
_RE_CERT_SERIAL = re.compile(
    r'\b(?:[0-9a-fA-F]{2}:){7,31}[0-9a-fA-F]{2}\b'
    r'|'
    r'\b0[xX][0-9a-fA-F]{8,64}\b'
)


# ════════════════════════════════════════════════════════════════════════════════
# DATACLASSES
# ════════════════════════════════════════════════════════════════════════════════


@dataclass
class IOCEntry:
    """A single Indicator of Compromise."""
    ioc_type: IOCType
    value: str
    confidence: float = IOC_CONFIDENCE_MEDIUM
    source: str = ""
    context: str = ""
    first_seen: float = 0.0
    last_seen: float = 0.0
    tags: List[str] = field(default_factory=list)
    related_iocs: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    severity: ThreatSeverity = ThreatSeverity.MEDIUM
    ioc_id: str = ""

    def __post_init__(self) -> None:
        if not self.ioc_id:
            self.ioc_id = hashlib.sha256(
                f"{self.ioc_type.name}:{self.value}".encode()
            ).hexdigest()[:16]
        if self.first_seen == 0.0:
            self.first_seen = time.time()
        if self.last_seen == 0.0:
            self.last_seen = self.first_seen

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ioc_id": self.ioc_id,
            "ioc_type": self.ioc_type.name,
            "value": self.value,
            "confidence": self.confidence,
            "source": self.source,
            "context": self.context,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "tags": self.tags,
            "related_iocs": self.related_iocs,
            "mitre_techniques": self.mitre_techniques,
            "severity": self.severity.name,
        }


@dataclass
class DetectionRule:
    """A detection rule in any supported format."""
    rule_id: str = ""
    name: str = ""
    description: str = ""
    rule_format: RuleFormat = RuleFormat.SIGMA
    content: str = ""
    severity: ThreatSeverity = ThreatSeverity.MEDIUM
    category: ThreatCategory = ThreatCategory.WEB_ATTACK
    mitre_techniques: List[str] = field(default_factory=list)
    mitre_tactics: List[str] = field(default_factory=list)
    false_positive_rate: float = 0.1
    data_sources: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    created_at: float = 0.0
    author: str = "SIREN Threat Hunter"
    enabled: bool = True

    def __post_init__(self) -> None:
        if not self.rule_id:
            self.rule_id = str(uuid.uuid4())
        if self.created_at == 0.0:
            self.created_at = time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "rule_format": self.rule_format.name,
            "content": self.content,
            "severity": self.severity.name,
            "category": self.category.name,
            "mitre_techniques": self.mitre_techniques,
            "mitre_tactics": self.mitre_tactics,
            "false_positive_rate": self.false_positive_rate,
            "data_sources": self.data_sources,
            "tags": self.tags,
            "references": self.references,
            "created_at": self.created_at,
            "author": self.author,
            "enabled": self.enabled,
        }


@dataclass
class IOCBundle:
    """Collection of related IOCs from an analysis."""
    bundle_id: str = ""
    name: str = ""
    description: str = ""
    iocs: List[IOCEntry] = field(default_factory=list)
    source_data: str = ""
    analysis_timestamp: float = 0.0
    total_extracted: int = 0
    by_type: Dict[str, int] = field(default_factory=dict)
    high_confidence_count: int = 0
    tags: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.bundle_id:
            self.bundle_id = str(uuid.uuid4())
        if self.analysis_timestamp == 0.0:
            self.analysis_timestamp = time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bundle_id": self.bundle_id,
            "name": self.name,
            "description": self.description,
            "iocs": [i.to_dict() for i in self.iocs],
            "analysis_timestamp": self.analysis_timestamp,
            "total_extracted": self.total_extracted,
            "by_type": self.by_type,
            "high_confidence_count": self.high_confidence_count,
            "tags": self.tags,
        }


@dataclass
class HuntResult:
    """Result of a single threat hunt operation."""
    result_id: str = ""
    hunt_name: str = ""
    status: HuntStatus = HuntStatus.PENDING
    findings: List[Dict[str, Any]] = field(default_factory=list)
    iocs_found: List[IOCEntry] = field(default_factory=list)
    rules_generated: List[DetectionRule] = field(default_factory=list)
    queries_generated: List[str] = field(default_factory=list)
    start_time: float = 0.0
    end_time: float = 0.0
    duration_seconds: float = 0.0
    data_sources_queried: List[str] = field(default_factory=list)
    hypothesis: str = ""
    conclusion: str = ""
    confidence: float = 0.0
    severity: ThreatSeverity = ThreatSeverity.MEDIUM
    mitre_coverage: Dict[str, List[str]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.result_id:
            self.result_id = str(uuid.uuid4())
        if self.start_time == 0.0:
            self.start_time = time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "result_id": self.result_id,
            "hunt_name": self.hunt_name,
            "status": self.status.name,
            "findings": self.findings,
            "iocs_found": [i.to_dict() for i in self.iocs_found],
            "rules_generated": [r.to_dict() for r in self.rules_generated],
            "queries_generated": self.queries_generated,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": self.duration_seconds,
            "data_sources_queried": self.data_sources_queried,
            "hypothesis": self.hypothesis,
            "conclusion": self.conclusion,
            "confidence": self.confidence,
            "severity": self.severity.name,
            "mitre_coverage": self.mitre_coverage,
        }


@dataclass
class ThreatHuntReport:
    """Complete threat hunt report."""
    report_id: str = ""
    title: str = ""
    executive_summary: str = ""
    hunt_results: List[HuntResult] = field(default_factory=list)
    ioc_bundle: Optional[IOCBundle] = None
    detection_rules: List[DetectionRule] = field(default_factory=list)
    total_iocs: int = 0
    total_rules: int = 0
    total_queries: int = 0
    mitre_coverage_pct: float = 0.0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    recommendations: List[str] = field(default_factory=list)
    generated_at: float = 0.0
    analyst: str = "SIREN Threat Hunter"
    version: str = "1.0.0"

    def __post_init__(self) -> None:
        if not self.report_id:
            self.report_id = str(uuid.uuid4())
        if self.generated_at == 0.0:
            self.generated_at = time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "title": self.title,
            "executive_summary": self.executive_summary,
            "hunt_results": [h.to_dict() for h in self.hunt_results],
            "ioc_bundle": self.ioc_bundle.to_dict() if self.ioc_bundle else None,
            "detection_rules": [r.to_dict() for r in self.detection_rules],
            "total_iocs": self.total_iocs,
            "total_rules": self.total_rules,
            "total_queries": self.total_queries,
            "mitre_coverage_pct": self.mitre_coverage_pct,
            "critical_findings": self.critical_findings,
            "high_findings": self.high_findings,
            "medium_findings": self.medium_findings,
            "low_findings": self.low_findings,
            "recommendations": self.recommendations,
            "generated_at": self.generated_at,
            "analyst": self.analyst,
            "version": self.version,
        }


# ════════════════════════════════════════════════════════════════════════════════
# IOC EXTRACTOR
# ════════════════════════════════════════════════════════════════════════════════


class IOCExtractor:
    """
    Extracts Indicators of Compromise from raw text, logs, or structured data.

    Supports extraction of:
        - IPv4 and IPv6 addresses (with validation and private/reserved filtering)
        - Domain names (with TLD validation)
        - URLs (with scheme validation)
        - Email addresses
        - File hashes (MD5, SHA1, SHA256, SHA512)
        - User-Agent strings
        - File paths (Windows and Unix)
        - Windows registry keys
        - CVE identifiers
        - MITRE ATT&CK technique IDs
        - JA3/JA3S fingerprints
        - Certificate serial numbers

    Usage:
        extractor = IOCExtractor()
        bundle = extractor.extract_all("Suspicious traffic from 192.168.1.100 to evil.com")
        print(bundle.to_dict())
    """

    # Known benign IPs and domains to filter out
    _BENIGN_IPS: Set[str] = {
        "0.0.0.0", "127.0.0.1", "255.255.255.255",
        "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
    }
    _BENIGN_DOMAINS: Set[str] = {
        "localhost", "example.com", "example.org", "example.net",
        "test.com", "google.com", "microsoft.com", "apple.com",
        "schema.org", "w3.org", "iana.org",
    }
    _PRIVATE_RANGES = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("169.254.0.0/16"),
        ipaddress.ip_network("100.64.0.0/10"),
    ]

    def __init__(
        self,
        filter_private_ips: bool = False,
        filter_benign: bool = True,
        min_confidence: float = IOC_CONFIDENCE_LOW,
    ) -> None:
        self._lock = threading.RLock()
        self._filter_private = filter_private_ips
        self._filter_benign = filter_benign
        self._min_confidence = min_confidence
        self._extraction_count = 0
        self._seen_iocs: Dict[str, IOCEntry] = {}
        logger.info("IOCExtractor initialized (filter_private=%s, filter_benign=%s)",
                     filter_private_ips, filter_benign)

    def extract_all(
        self,
        text: str,
        source: str = "raw_input",
        tags: Optional[List[str]] = None,
    ) -> IOCBundle:
        """Extract all IOC types from text and return an IOCBundle."""
        with self._lock:
            self._extraction_count += 1
            _tags = tags or []
            all_iocs: List[IOCEntry] = []

            extractors: List[Tuple[str, Callable]] = [
                ("ip_addresses", lambda: self.extract_ips(text, source)),
                ("domains", lambda: self.extract_domains(text, source)),
                ("urls", lambda: self.extract_urls(text, source)),
                ("emails", lambda: self.extract_emails(text, source)),
                ("hashes", lambda: self.extract_hashes(text, source)),
                ("user_agents", lambda: self.extract_user_agents(text, source)),
                ("file_paths", lambda: self.extract_file_paths(text, source)),
                ("registry_keys", lambda: self.extract_registry_keys(text, source)),
                ("cve_ids", lambda: self.extract_cve_ids(text, source)),
                ("mitre_techniques", lambda: self.extract_mitre_techniques(text, source)),
                ("ja3_fingerprints", lambda: self.extract_ja3_fingerprints(text, source)),
                ("cert_serials", lambda: self.extract_certificate_serials(text, source)),
            ]

            by_type: Dict[str, int] = {}
            for name, extractor_fn in extractors:
                try:
                    results = extractor_fn()
                    for ioc in results:
                        ioc.tags.extend(_tags)
                    all_iocs.extend(results)
                    by_type[name] = len(results)
                except Exception as exc:
                    logger.warning("IOC extraction failed for %s: %s", name, exc)
                    by_type[name] = 0

            # Dedup
            seen: Dict[str, IOCEntry] = {}
            for ioc in all_iocs:
                key = f"{ioc.ioc_type.name}:{ioc.value}"
                if key not in seen:
                    seen[key] = ioc
                else:
                    existing = seen[key]
                    existing.confidence = max(existing.confidence, ioc.confidence)
                    existing.last_seen = max(existing.last_seen, ioc.last_seen)

            deduped = list(seen.values())
            high_conf = sum(1 for i in deduped if i.confidence >= IOC_CONFIDENCE_HIGH)

            bundle = IOCBundle(
                name=f"IOC extraction #{self._extraction_count}",
                description=f"Automated IOC extraction from {source}",
                iocs=deduped,
                source_data=text[:500] if len(text) > 500 else text,
                total_extracted=len(deduped),
                by_type=by_type,
                high_confidence_count=high_conf,
                tags=_tags,
            )

            # Update global seen cache
            for ioc in deduped:
                self._seen_iocs[ioc.ioc_id] = ioc

            logger.info("Extracted %d IOCs (%d high confidence) from %s",
                        len(deduped), high_conf, source)
            return bundle

    def extract_ips(self, text: str, source: str = "") -> List[IOCEntry]:
        """Extract and validate IPv4 and IPv6 addresses."""
        results: List[IOCEntry] = []
        # IPv4
        for match in _RE_IPV4.finditer(text):
            ip_str = match.group()
            try:
                ip_obj = ipaddress.ip_address(ip_str)
            except ValueError:
                continue
            if self._filter_benign and ip_str in self._BENIGN_IPS:
                continue
            if self._filter_private and any(
                ip_obj in net for net in self._PRIVATE_RANGES
            ):
                continue
            if ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified:
                continue
            confidence = IOC_CONFIDENCE_HIGH
            if ip_obj.is_private:
                confidence = IOC_CONFIDENCE_LOW
            elif ip_obj.is_global:
                confidence = IOC_CONFIDENCE_HIGH
            results.append(IOCEntry(
                ioc_type=IOCType.IP_ADDRESS,
                value=ip_str,
                confidence=confidence,
                source=source,
                context=self._get_context(text, match.start(), match.end()),
                severity=ThreatSeverity.MEDIUM,
            ))
        # IPv6
        for match in _RE_IPV6.finditer(text):
            ip_str = match.group()
            try:
                ip_obj = ipaddress.ip_address(ip_str)
            except ValueError:
                continue
            if ip_obj.is_loopback or ip_obj.is_multicast or ip_obj.is_reserved:
                continue
            results.append(IOCEntry(
                ioc_type=IOCType.IP_ADDRESS,
                value=str(ip_obj),
                confidence=IOC_CONFIDENCE_MEDIUM,
                source=source,
                context=self._get_context(text, match.start(), match.end()),
                severity=ThreatSeverity.MEDIUM,
            ))
        return results

    def extract_domains(self, text: str, source: str = "") -> List[IOCEntry]:
        """Extract and validate domain names."""
        results: List[IOCEntry] = []
        for match in _RE_DOMAIN.finditer(text):
            domain = match.group().lower()
            if self._filter_benign and domain in self._BENIGN_DOMAINS:
                continue
            if len(domain) < 4 or len(domain) > 253:
                continue
            parts = domain.split(".")
            if any(len(p) > 63 for p in parts):
                continue
            if len(parts) < 2:
                continue
            # Entropy check for DGA detection
            entropy = self._calculate_entropy(parts[0])
            confidence = IOC_CONFIDENCE_MEDIUM
            severity = ThreatSeverity.LOW
            if entropy > 3.5 and len(parts[0]) > 10:
                confidence = IOC_CONFIDENCE_HIGH
                severity = ThreatSeverity.HIGH
                tags = ["possible_dga"]
            elif entropy > 3.0:
                confidence = IOC_CONFIDENCE_MEDIUM
                tags = ["moderate_entropy"]
            else:
                tags = []
            results.append(IOCEntry(
                ioc_type=IOCType.DOMAIN,
                value=domain,
                confidence=confidence,
                source=source,
                context=self._get_context(text, match.start(), match.end()),
                severity=severity,
                tags=tags,
            ))
        return results

    def extract_urls(self, text: str, source: str = "") -> List[IOCEntry]:
        """Extract and validate URLs."""
        results: List[IOCEntry] = []
        for match in _RE_URL.finditer(text):
            url = match.group().rstrip(".,;:!?)")
            try:
                parsed = urlparse(url)
                if not parsed.scheme or not parsed.netloc:
                    continue
            except Exception:
                continue
            confidence = IOC_CONFIDENCE_HIGH
            severity = ThreatSeverity.MEDIUM
            tags: List[str] = []
            path_lower = (parsed.path or "").lower()
            query_lower = (parsed.query or "").lower()
            # Suspicious patterns
            if any(s in path_lower for s in [
                "/wp-admin", "/phpmyadmin", "/.env", "/shell",
                "/cmd", "/exec", "/eval", "/upload",
                "/backdoor", "/c99", "/r57", "/webshell",
            ]):
                severity = ThreatSeverity.HIGH
                tags.append("suspicious_path")
            if any(s in query_lower for s in [
                "union+select", "' or '", "<script>", "cmd=",
                "exec=", "base64", "../", "passwd",
            ]):
                severity = ThreatSeverity.HIGH
                tags.append("suspicious_query")
            if parsed.port and parsed.port not in (80, 443, 8080, 8443):
                tags.append("unusual_port")
            if any(parsed.netloc.endswith(tld) for tld in [
                ".onion", ".bit", ".cc", ".top", ".xyz",
            ]):
                tags.append("suspicious_tld")
                severity = ThreatSeverity.HIGH
            results.append(IOCEntry(
                ioc_type=IOCType.URL,
                value=url,
                confidence=confidence,
                source=source,
                context=self._get_context(text, match.start(), match.end()),
                severity=severity,
                tags=tags,
            ))
        return results

    def extract_emails(self, text: str, source: str = "") -> List[IOCEntry]:
        """Extract email addresses."""
        results: List[IOCEntry] = []
        for match in _RE_EMAIL.finditer(text):
            email = match.group().lower()
            if self._filter_benign and email.endswith(
                ("@example.com", "@test.com", "@localhost")
            ):
                continue
            confidence = IOC_CONFIDENCE_MEDIUM
            tags: List[str] = []
            local_part = email.split("@")[0]
            domain_part = email.split("@")[1]
            if any(s in local_part for s in ["admin", "root", "postmaster"]):
                tags.append("admin_account")
            if domain_part.endswith((".ru", ".cn", ".onion")):
                tags.append("suspicious_domain")
                confidence = IOC_CONFIDENCE_HIGH
            results.append(IOCEntry(
                ioc_type=IOCType.EMAIL,
                value=email,
                confidence=confidence,
                source=source,
                context=self._get_context(text, match.start(), match.end()),
                severity=ThreatSeverity.LOW,
                tags=tags,
            ))
        return results

    def extract_hashes(self, text: str, source: str = "") -> List[IOCEntry]:
        """Extract MD5, SHA1, SHA256, SHA512 file hashes."""
        results: List[IOCEntry] = []
        seen_values: Set[str] = set()

        # SHA512 first (longest)
        for match in _RE_SHA512.finditer(text):
            val = match.group().lower()
            if val not in seen_values and not self._is_all_same_char(val):
                seen_values.add(val)
                results.append(IOCEntry(
                    ioc_type=IOCType.HASH_SHA512,
                    value=val,
                    confidence=IOC_CONFIDENCE_HIGH,
                    source=source,
                    context=self._get_context(text, match.start(), match.end()),
                    severity=ThreatSeverity.MEDIUM,
                    tags=["sha512"],
                ))

        # SHA256
        for match in _RE_SHA256.finditer(text):
            val = match.group().lower()
            if val not in seen_values and not self._is_all_same_char(val):
                # Ensure not substring of sha512
                start, end = match.start(), match.end()
                full_hex = text[max(0, start - 1):end + 1]
                if re.match(r'[0-9a-fA-F]', full_hex[0:1] if start > 0 else ''):
                    if len(full_hex) > 65:
                        continue
                seen_values.add(val)
                results.append(IOCEntry(
                    ioc_type=IOCType.HASH_SHA256,
                    value=val,
                    confidence=IOC_CONFIDENCE_HIGH,
                    source=source,
                    context=self._get_context(text, match.start(), match.end()),
                    severity=ThreatSeverity.MEDIUM,
                    tags=["sha256"],
                ))

        # SHA1
        for match in _RE_SHA1.finditer(text):
            val = match.group().lower()
            if val not in seen_values and not self._is_all_same_char(val):
                if not any(val in s for s in seen_values if len(s) > 40):
                    seen_values.add(val)
                    results.append(IOCEntry(
                        ioc_type=IOCType.HASH_SHA1,
                        value=val,
                        confidence=IOC_CONFIDENCE_HIGH,
                        source=source,
                        context=self._get_context(text, match.start(), match.end()),
                        severity=ThreatSeverity.MEDIUM,
                        tags=["sha1"],
                    ))

        # MD5
        for match in _RE_MD5.finditer(text):
            val = match.group().lower()
            if val not in seen_values and not self._is_all_same_char(val):
                if not any(val in s for s in seen_values if len(s) > 32):
                    seen_values.add(val)
                    results.append(IOCEntry(
                        ioc_type=IOCType.HASH_MD5,
                        value=val,
                        confidence=IOC_CONFIDENCE_MEDIUM,
                        source=source,
                        context=self._get_context(text, match.start(), match.end()),
                        severity=ThreatSeverity.MEDIUM,
                        tags=["md5"],
                    ))
        return results

    def extract_user_agents(self, text: str, source: str = "") -> List[IOCEntry]:
        """Extract User-Agent strings."""
        results: List[IOCEntry] = []
        seen: Set[str] = set()
        for match in _RE_USER_AGENT.finditer(text):
            ua = match.group().strip()
            if ua in seen:
                continue
            seen.add(ua)
            confidence = IOC_CONFIDENCE_MEDIUM
            tags: List[str] = []
            severity = ThreatSeverity.LOW
            ua_lower = ua.lower()
            if any(s in ua_lower for s in [
                "sqlmap", "nikto", "nmap", "masscan", "zgrab",
                "gobuster", "dirbuster", "wpscan", "nuclei",
                "burp", "owasp", "hydra", "metasploit",
            ]):
                confidence = IOC_CONFIDENCE_HIGH
                severity = ThreatSeverity.HIGH
                tags.append("attack_tool")
            elif any(s in ua_lower for s in [
                "bot", "spider", "crawler", "scraper",
            ]):
                tags.append("bot_crawler")
            elif any(s in ua_lower for s in [
                "curl", "wget", "python-requests", "go-http-client",
                "java/", "ruby", "php/",
            ]):
                tags.append("scripted_client")
                confidence = IOC_CONFIDENCE_MEDIUM
            results.append(IOCEntry(
                ioc_type=IOCType.USER_AGENT,
                value=ua,
                confidence=confidence,
                source=source,
                context=self._get_context(text, match.start(), match.end()),
                severity=severity,
                tags=tags,
            ))
        return results

    def extract_file_paths(self, text: str, source: str = "") -> List[IOCEntry]:
        """Extract Windows and Unix file paths."""
        results: List[IOCEntry] = []
        seen: Set[str] = set()
        # Windows paths
        for match in _RE_WIN_PATH.finditer(text):
            path = match.group()
            if path in seen or len(path) < 5:
                continue
            seen.add(path)
            confidence = IOC_CONFIDENCE_MEDIUM
            tags: List[str] = ["windows_path"]
            severity = ThreatSeverity.LOW
            path_lower = path.lower()
            if any(s in path_lower for s in [
                "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp",
                "\\programdata\\", "\\windows\\temp",
            ]):
                tags.append("temp_directory")
                severity = ThreatSeverity.MEDIUM
            if any(s in path_lower for s in [
                ".exe", ".dll", ".bat", ".cmd", ".ps1",
                ".vbs", ".js", ".wsf", ".scr",
            ]):
                tags.append("executable")
                severity = ThreatSeverity.MEDIUM
                confidence = IOC_CONFIDENCE_HIGH
            if any(s in path_lower for s in [
                "\\system32\\", "\\syswow64\\", "\\drivers\\",
            ]):
                tags.append("system_directory")
                severity = ThreatSeverity.HIGH
            results.append(IOCEntry(
                ioc_type=IOCType.FILE_PATH,
                value=path,
                confidence=confidence,
                source=source,
                context=self._get_context(text, match.start(), match.end()),
                severity=severity,
                tags=tags,
            ))
        # Unix paths
        for match in _RE_UNIX_PATH.finditer(text):
            path = match.group()
            if path in seen or len(path) < 5:
                continue
            seen.add(path)
            confidence = IOC_CONFIDENCE_MEDIUM
            tags = ["unix_path"]
            severity = ThreatSeverity.LOW
            if any(s in path for s in ["/tmp/", "/var/tmp/", "/dev/shm/"]):
                tags.append("temp_directory")
                severity = ThreatSeverity.MEDIUM
            if any(s in path for s in [
                "/etc/shadow", "/etc/passwd", "/etc/crontab",
                "/etc/sudoers", "/root/.ssh",
            ]):
                tags.append("sensitive_file")
                severity = ThreatSeverity.HIGH
                confidence = IOC_CONFIDENCE_HIGH
            if path.endswith((".sh", ".py", ".pl", ".rb", ".elf")):
                tags.append("script_or_binary")
            results.append(IOCEntry(
                ioc_type=IOCType.FILE_PATH,
                value=path,
                confidence=confidence,
                source=source,
                context=self._get_context(text, match.start(), match.end()),
                severity=severity,
                tags=tags,
            ))
        return results

    def extract_registry_keys(self, text: str, source: str = "") -> List[IOCEntry]:
        """Extract Windows registry keys."""
        results: List[IOCEntry] = []
        seen: Set[str] = set()
        for match in _RE_REGISTRY.finditer(text):
            key = match.group()
            if key in seen:
                continue
            seen.add(key)
            confidence = IOC_CONFIDENCE_HIGH
            tags: List[str] = ["registry"]
            severity = ThreatSeverity.MEDIUM
            key_lower = key.lower()
            if any(s in key_lower for s in [
                "\\run\\", "\\runonce\\", "\\currentversion\\run",
                "\\explorer\\shell folders",
            ]):
                tags.append("persistence_key")
                severity = ThreatSeverity.HIGH
            if any(s in key_lower for s in [
                "\\services\\", "\\drivers\\",
            ]):
                tags.append("service_key")
                severity = ThreatSeverity.HIGH
            if "\\policies\\" in key_lower:
                tags.append("policy_key")
            if any(s in key_lower for s in [
                "\\winlogon\\", "\\lsa\\", "\\security\\",
            ]):
                tags.append("security_key")
                severity = ThreatSeverity.CRITICAL
            results.append(IOCEntry(
                ioc_type=IOCType.REGISTRY_KEY,
                value=key,
                confidence=confidence,
                source=source,
                context=self._get_context(text, match.start(), match.end()),
                severity=severity,
                tags=tags,
            ))
        return results

    def extract_cve_ids(self, text: str, source: str = "") -> List[IOCEntry]:
        """Extract CVE identifiers."""
        results: List[IOCEntry] = []
        seen: Set[str] = set()
        for match in _RE_CVE.finditer(text):
            cve = match.group().upper()
            if cve in seen:
                continue
            seen.add(cve)
            year = int(cve.split("-")[1])
            confidence = IOC_CONFIDENCE_HIGH
            severity = ThreatSeverity.HIGH
            tags: List[str] = ["cve"]
            current_year = 2026
            if year >= current_year - 1:
                tags.append("recent_cve")
                severity = ThreatSeverity.CRITICAL
            elif year >= current_year - 3:
                tags.append("moderately_recent")
            else:
                tags.append("older_cve")
                severity = ThreatSeverity.MEDIUM
            results.append(IOCEntry(
                ioc_type=IOCType.CVE_ID,
                value=cve,
                confidence=confidence,
                source=source,
                context=self._get_context(text, match.start(), match.end()),
                severity=severity,
                tags=tags,
            ))
        return results

    def extract_mitre_techniques(self, text: str, source: str = "") -> List[IOCEntry]:
        """Extract MITRE ATT&CK technique IDs."""
        results: List[IOCEntry] = []
        seen: Set[str] = set()
        for match in _RE_MITRE.finditer(text):
            technique = match.group()
            if technique in seen:
                continue
            seen.add(technique)
            results.append(IOCEntry(
                ioc_type=IOCType.MITRE_TECHNIQUE,
                value=technique,
                confidence=IOC_CONFIDENCE_HIGH,
                source=source,
                context=self._get_context(text, match.start(), match.end()),
                severity=ThreatSeverity.MEDIUM,
                tags=["mitre_attack"],
            ))
        return results

    def extract_ja3_fingerprints(
        self, text: str, source: str = ""
    ) -> List[IOCEntry]:
        """Extract JA3/JA3S TLS fingerprints (MD5 hashes in JA3 context)."""
        results: List[IOCEntry] = []
        ja3_pattern = re.compile(
            r'(?:ja3[s]?[_\s:=]+)([0-9a-fA-F]{32})', re.IGNORECASE
        )
        seen: Set[str] = set()
        for match in ja3_pattern.finditer(text):
            fp = match.group(1).lower()
            if fp in seen:
                continue
            seen.add(fp)
            results.append(IOCEntry(
                ioc_type=IOCType.JA3_FINGERPRINT,
                value=fp,
                confidence=IOC_CONFIDENCE_HIGH,
                source=source,
                context=self._get_context(text, match.start(), match.end()),
                severity=ThreatSeverity.MEDIUM,
                tags=["ja3_fingerprint", "tls"],
            ))
        return results

    def extract_certificate_serials(
        self, text: str, source: str = ""
    ) -> List[IOCEntry]:
        """Extract X.509 certificate serial numbers."""
        results: List[IOCEntry] = []
        seen: Set[str] = set()
        for match in _RE_CERT_SERIAL.finditer(text):
            serial = match.group()
            normalized = serial.replace(":", "").replace("0x", "").replace("0X", "").lower()
            if normalized in seen or len(normalized) < 8:
                continue
            seen.add(normalized)
            results.append(IOCEntry(
                ioc_type=IOCType.CERTIFICATE_SERIAL,
                value=serial,
                confidence=IOC_CONFIDENCE_MEDIUM,
                source=source,
                context=self._get_context(text, match.start(), match.end()),
                severity=ThreatSeverity.LOW,
                tags=["certificate", "x509"],
            ))
        return results

    # ── Helper methods ─────────────────────────────────────────────────────

    @staticmethod
    def _get_context(text: str, start: int, end: int, window: int = 60) -> str:
        """Get surrounding text context for an IOC match."""
        ctx_start = max(0, start - window)
        ctx_end = min(len(text), end + window)
        ctx = text[ctx_start:ctx_end].replace("\n", " ").replace("\r", "").strip()
        if ctx_start > 0:
            ctx = "..." + ctx
        if ctx_end < len(text):
            ctx = ctx + "..."
        return ctx

    @staticmethod
    def _calculate_entropy(s: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not s:
            return 0.0
        freq: Dict[str, int] = defaultdict(int)
        for c in s:
            freq[c] += 1
        length = len(s)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def _is_all_same_char(s: str) -> bool:
        """Check if string is all the same character (e.g., '0000...0000')."""
        return len(set(s)) <= 1

    def get_stats(self) -> Dict[str, Any]:
        """Get extraction statistics."""
        with self._lock:
            type_counts: Dict[str, int] = defaultdict(int)
            for ioc in self._seen_iocs.values():
                type_counts[ioc.ioc_type.name] += 1
            return {
                "total_extractions": self._extraction_count,
                "unique_iocs_seen": len(self._seen_iocs),
                "by_type": dict(type_counts),
            }

    def clear_cache(self) -> None:
        """Clear the seen IOC cache."""
        with self._lock:
            self._seen_iocs.clear()
            logger.info("IOC cache cleared")


# ════════════════════════════════════════════════════════════════════════════════
# STIX 2.1 EXPORTER
# ════════════════════════════════════════════════════════════════════════════════


class STIXExporter:
    """
    Exports IOCs and threat data in STIX 2.1 bundle format.

    Creates standards-compliant STIX bundles with:
        - Indicators (from IOCs)
        - Attack Patterns (from MITRE techniques)
        - Relationships between objects
        - Identity objects for attribution
        - Observed Data containers

    Usage:
        exporter = STIXExporter()
        bundle = exporter.create_bundle(ioc_bundle, rules)
        print(json.dumps(bundle, indent=2))
    """

    _IOC_TO_STIX_PATTERN: Dict[IOCType, str] = {
        IOCType.IP_ADDRESS: "[ipv4-addr:value = '{value}']",
        IOCType.DOMAIN: "[domain-name:value = '{value}']",
        IOCType.URL: "[url:value = '{value}']",
        IOCType.EMAIL: "[email-addr:value = '{value}']",
        IOCType.HASH_MD5: "[file:hashes.'MD5' = '{value}']",
        IOCType.HASH_SHA1: "[file:hashes.'SHA-1' = '{value}']",
        IOCType.HASH_SHA256: "[file:hashes.'SHA-256' = '{value}']",
        IOCType.HASH_SHA512: "[file:hashes.'SHA-512' = '{value}']",
        IOCType.FILE_PATH: "[file:name = '{value}']",
        IOCType.REGISTRY_KEY: "[windows-registry-key:key = '{value}']",
        IOCType.USER_AGENT: "[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = '{value}']",
        IOCType.CERTIFICATE_SERIAL: "[x509-certificate:serial_number = '{value}']",
    }

    def __init__(self, identity_name: str = "SIREN Threat Hunter") -> None:
        self._lock = threading.RLock()
        self._identity_name = identity_name
        self._identity_id = f"identity--{uuid.uuid4()}"
        logger.info("STIXExporter initialized (identity=%s)", identity_name)

    def create_bundle(
        self,
        ioc_bundle: Optional[IOCBundle] = None,
        rules: Optional[List[DetectionRule]] = None,
        extra_objects: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Create a STIX 2.1 bundle from IOCs and detection rules."""
        with self._lock:
            objects: List[Dict[str, Any]] = []

            # Identity
            identity = self._create_identity()
            objects.append(identity)

            # IOC indicators
            if ioc_bundle:
                for ioc in ioc_bundle.iocs:
                    indicator = self._ioc_to_indicator(ioc)
                    if indicator:
                        objects.append(indicator)
                        # Relationship to identity
                        rel = self._create_relationship(
                            indicator["id"], self._identity_id,
                            "created-by"
                        )
                        objects.append(rel)

            # Rules as indicators
            if rules:
                for rule in rules:
                    indicator = self._rule_to_indicator(rule)
                    if indicator:
                        objects.append(indicator)

            # Attack patterns from MITRE techniques
            mitre_ids: Set[str] = set()
            if ioc_bundle:
                for ioc in ioc_bundle.iocs:
                    if ioc.ioc_type == IOCType.MITRE_TECHNIQUE:
                        mitre_ids.add(ioc.value)
                    mitre_ids.update(ioc.mitre_techniques)
            if rules:
                for rule in rules:
                    mitre_ids.update(rule.mitre_techniques)

            for tid in mitre_ids:
                ap = self._create_attack_pattern(tid)
                objects.append(ap)

            # Extra objects
            if extra_objects:
                objects.extend(extra_objects)

            bundle = {
                "type": STIX_BUNDLE_TYPE,
                "id": f"bundle--{uuid.uuid4()}",
                "spec_version": STIX_SPEC_VERSION,
                "created": self._timestamp_to_stix(time.time()),
                "objects": objects,
            }

            logger.info("STIX bundle created with %d objects", len(objects))
            return bundle

    def _create_identity(self) -> Dict[str, Any]:
        """Create STIX Identity object."""
        return {
            "type": "identity",
            "spec_version": STIX_SPEC_VERSION,
            "id": self._identity_id,
            "created": self._timestamp_to_stix(time.time()),
            "modified": self._timestamp_to_stix(time.time()),
            "name": self._identity_name,
            "identity_class": "system",
            "description": "SIREN Threat Hunting - automated IOC and threat analysis",
        }

    def _ioc_to_indicator(self, ioc: IOCEntry) -> Optional[Dict[str, Any]]:
        """Convert an IOC to a STIX Indicator."""
        pattern_template = self._IOC_TO_STIX_PATTERN.get(ioc.ioc_type)
        if not pattern_template:
            return None
        pattern = pattern_template.format(value=self._escape_stix(ioc.value))
        severity_map = {
            ThreatSeverity.CRITICAL: "anomalous-activity",
            ThreatSeverity.HIGH: "anomalous-activity",
            ThreatSeverity.MEDIUM: "anomalous-activity",
            ThreatSeverity.LOW: "benign",
            ThreatSeverity.INFORMATIONAL: "benign",
        }
        return {
            "type": "indicator",
            "spec_version": STIX_SPEC_VERSION,
            "id": f"indicator--{uuid.uuid4()}",
            "created": self._timestamp_to_stix(ioc.first_seen),
            "modified": self._timestamp_to_stix(ioc.last_seen),
            "name": f"{ioc.ioc_type.name}: {ioc.value[:64]}",
            "description": ioc.context[:256] if ioc.context else "",
            "indicator_types": [severity_map.get(ioc.severity, "anomalous-activity")],
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": self._timestamp_to_stix(ioc.first_seen),
            "confidence": int(ioc.confidence * 100),
            "labels": ioc.tags[:10],
            "created_by_ref": self._identity_id,
        }

    def _rule_to_indicator(self, rule: DetectionRule) -> Optional[Dict[str, Any]]:
        """Convert a detection rule to a STIX Indicator (as custom pattern)."""
        return {
            "type": "indicator",
            "spec_version": STIX_SPEC_VERSION,
            "id": f"indicator--{uuid.uuid4()}",
            "created": self._timestamp_to_stix(rule.created_at),
            "modified": self._timestamp_to_stix(rule.created_at),
            "name": rule.name,
            "description": rule.description,
            "indicator_types": ["anomalous-activity"],
            "pattern": f"[x-siren-rule:format = '{rule.rule_format.name}']",
            "pattern_type": "stix",
            "valid_from": self._timestamp_to_stix(rule.created_at),
            "labels": rule.tags[:10],
            "created_by_ref": self._identity_id,
            "external_references": [
                {"source_name": "mitre-attack", "external_id": tid}
                for tid in rule.mitre_techniques[:5]
            ],
        }

    def _create_attack_pattern(self, technique_id: str) -> Dict[str, Any]:
        """Create STIX Attack Pattern from MITRE technique ID."""
        return {
            "type": "attack-pattern",
            "spec_version": STIX_SPEC_VERSION,
            "id": f"attack-pattern--{uuid.uuid4()}",
            "created": self._timestamp_to_stix(time.time()),
            "modified": self._timestamp_to_stix(time.time()),
            "name": f"MITRE ATT&CK {technique_id}",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": technique_id,
                    "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
                }
            ],
        }

    def _create_relationship(
        self, source_id: str, target_id: str, relationship_type: str
    ) -> Dict[str, Any]:
        """Create STIX Relationship."""
        return {
            "type": "relationship",
            "spec_version": STIX_SPEC_VERSION,
            "id": f"relationship--{uuid.uuid4()}",
            "created": self._timestamp_to_stix(time.time()),
            "modified": self._timestamp_to_stix(time.time()),
            "relationship_type": relationship_type,
            "source_ref": source_id,
            "target_ref": target_id,
        }

    @staticmethod
    def _timestamp_to_stix(ts: float) -> str:
        """Convert Unix timestamp to STIX datetime string."""
        t = time.gmtime(ts)
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", t)

    @staticmethod
    def _escape_stix(value: str) -> str:
        """Escape special characters for STIX patterns."""
        return value.replace("\\", "\\\\").replace("'", "\\'")


# ════════════════════════════════════════════════════════════════════════════════
# SIGMA RULE GENERATOR
# ════════════════════════════════════════════════════════════════════════════════


class SIGMARuleGenerator:
    """
    Generates SIGMA detection rules in valid YAML format.

    Produces 30+ rule templates across 6 threat categories:
        - Web attacks (SQLi, XSS, path traversal, command injection)
        - Auth anomalies (brute force, credential stuffing, MFA bypass)
        - Data exfiltration (large downloads, DNS tunneling, encoded data)
        - Lateral movement (pass-the-hash, PsExec, WMI)
        - Privilege escalation (sudo abuse, token manipulation)
        - Persistence (scheduled tasks, registry run keys, cron jobs)

    Usage:
        gen = SIGMARuleGenerator()
        rules = gen.generate_all()
        for rule in rules:
            print(rule.content)
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._rule_count = 0
        self._generated_rules: List[DetectionRule] = []
        logger.info("SIGMARuleGenerator initialized")

    def generate_all(self) -> List[DetectionRule]:
        """Generate all SIGMA rule templates."""
        with self._lock:
            rules: List[DetectionRule] = []
            rules.extend(self._web_attack_rules())
            rules.extend(self._auth_anomaly_rules())
            rules.extend(self._data_exfil_rules())
            rules.extend(self._lateral_movement_rules())
            rules.extend(self._privilege_escalation_rules())
            rules.extend(self._persistence_rules())
            self._generated_rules = rules
            logger.info("Generated %d SIGMA rules total", len(rules))
            return rules

    def generate_by_category(self, category: ThreatCategory) -> List[DetectionRule]:
        """Generate SIGMA rules for a specific threat category."""
        with self._lock:
            dispatch = {
                ThreatCategory.WEB_ATTACK: self._web_attack_rules,
                ThreatCategory.AUTH_ANOMALY: self._auth_anomaly_rules,
                ThreatCategory.DATA_EXFILTRATION: self._data_exfil_rules,
                ThreatCategory.LATERAL_MOVEMENT: self._lateral_movement_rules,
                ThreatCategory.PRIVILEGE_ESCALATION: self._privilege_escalation_rules,
                ThreatCategory.PERSISTENCE: self._persistence_rules,
            }
            gen_fn = dispatch.get(category)
            if not gen_fn:
                logger.warning("No SIGMA rules for category: %s", category.name)
                return []
            rules = gen_fn()
            self._generated_rules.extend(rules)
            return rules

    def generate_for_iocs(self, ioc_bundle: IOCBundle) -> List[DetectionRule]:
        """Generate custom SIGMA rules based on extracted IOCs."""
        with self._lock:
            rules: List[DetectionRule] = []
            ips = [i for i in ioc_bundle.iocs if i.ioc_type == IOCType.IP_ADDRESS]
            domains = [i for i in ioc_bundle.iocs if i.ioc_type == IOCType.DOMAIN]
            hashes = [i for i in ioc_bundle.iocs if i.ioc_type in (
                IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256
            )]
            if ips:
                ip_values = [i.value for i in ips[:50]]
                rules.append(self._make_rule(
                    name="SIREN - Suspicious IP Communication",
                    description="Network traffic to/from IOC-flagged IP addresses",
                    category=ThreatCategory.COMMAND_AND_CONTROL,
                    severity=ThreatSeverity.HIGH,
                    mitre_techniques=["T1071"],
                    mitre_tactics=["command_and_control"],
                    logsource_category="firewall",
                    logsource_product="",
                    detection={
                        "selection": {"dst_ip": ip_values},
                        "condition": "selection",
                    },
                    falsepositives=["Legitimate services using flagged IPs"],
                ))
            if domains:
                domain_values = [i.value for i in domains[:50]]
                rules.append(self._make_rule(
                    name="SIREN - Suspicious Domain Resolution",
                    description="DNS queries for IOC-flagged domains",
                    category=ThreatCategory.COMMAND_AND_CONTROL,
                    severity=ThreatSeverity.HIGH,
                    mitre_techniques=["T1071.004"],
                    mitre_tactics=["command_and_control"],
                    logsource_category="dns",
                    logsource_product="",
                    detection={
                        "selection": {"query": domain_values},
                        "condition": "selection",
                    },
                    falsepositives=["Legitimate domain lookups"],
                ))
            if hashes:
                hash_values = [i.value for i in hashes[:50]]
                rules.append(self._make_rule(
                    name="SIREN - Malicious File Hash Detected",
                    description="File with IOC-flagged hash detected on system",
                    category=ThreatCategory.MALWARE,
                    severity=ThreatSeverity.CRITICAL,
                    mitre_techniques=["T1204"],
                    mitre_tactics=["execution"],
                    logsource_category="file_event",
                    logsource_product="windows",
                    detection={
                        "selection": {"Hashes|contains": hash_values},
                        "condition": "selection",
                    },
                    falsepositives=["Hash collision (extremely unlikely)"],
                ))
            self._generated_rules.extend(rules)
            return rules

    # ── Web Attack Rules ───────────────────────────────────────────────────

    def _web_attack_rules(self) -> List[DetectionRule]:
        """Generate SIGMA rules for web-based attacks."""
        rules: List[DetectionRule] = []

        # Rule 1: SQL Injection in URL
        rules.append(self._make_rule(
            name="SIREN - SQL Injection Attempt in URL",
            description="Detects SQL injection patterns in HTTP request URLs including UNION SELECT, OR 1=1, and comment-based evasion",
            category=ThreatCategory.WEB_ATTACK,
            severity=ThreatSeverity.HIGH,
            mitre_techniques=["T1190"],
            mitre_tactics=["initial_access"],
            logsource_category="webserver",
            logsource_product="",
            detection={
                "selection_union": {"cs-uri-query|contains": [
                    "UNION SELECT", "UNION%20SELECT", "UNION+SELECT",
                    "union select", "union%20select",
                ]},
                "selection_boolean": {"cs-uri-query|contains": [
                    "' OR '1'='1", "' OR 1=1", "' OR ''='",
                    "\" OR \"1\"=\"1", "OR 1=1--", "OR 1=1#",
                ]},
                "selection_comment": {"cs-uri-query|contains": [
                    "/**/", "--+", "#--", "';--",
                ]},
                "selection_stacked": {"cs-uri-query|contains": [
                    "; DROP TABLE", "; DELETE FROM", ";DROP TABLE",
                    "; INSERT INTO", "; UPDATE ",
                ]},
                "condition": "selection_union or selection_boolean or selection_comment or selection_stacked",
            },
            falsepositives=["Web scanners", "Legitimate SQL-like content in URLs"],
            references=["https://owasp.org/www-community/attacks/SQL_Injection"],
        ))

        # Rule 2: SQL Injection in POST body
        rules.append(self._make_rule(
            name="SIREN - SQL Injection in POST Body",
            description="Detects SQL injection patterns in HTTP POST request bodies",
            category=ThreatCategory.WEB_ATTACK,
            severity=ThreatSeverity.HIGH,
            mitre_techniques=["T1190"],
            mitre_tactics=["initial_access"],
            logsource_category="webserver",
            logsource_product="",
            detection={
                "selection_sqli": {"cs-body|contains": [
                    "' OR '1'='1", "UNION SELECT", "1; DROP TABLE",
                    "' AND '1'='1", "WAITFOR DELAY", "SLEEP(",
                    "BENCHMARK(", "EXTRACTVALUE(", "UPDATEXML(",
                ]},
                "condition": "selection_sqli",
            },
            falsepositives=["Application testing"],
        ))

        # Rule 3: XSS - Reflected
        rules.append(self._make_rule(
            name="SIREN - Reflected XSS Attempt",
            description="Detects reflected cross-site scripting attack patterns in URLs",
            category=ThreatCategory.WEB_ATTACK,
            severity=ThreatSeverity.HIGH,
            mitre_techniques=["T1189"],
            mitre_tactics=["initial_access"],
            logsource_category="webserver",
            logsource_product="",
            detection={
                "selection_script": {"cs-uri-query|contains": [
                    "<script>", "<script ", "%3Cscript%3E",
                    "<script%20", "javascript:", "vbscript:",
                ]},
                "selection_event": {"cs-uri-query|contains": [
                    "onerror=", "onload=", "onmouseover=",
                    "onfocus=", "onblur=", "onclick=",
                    "onsubmit=", "onchange=",
                ]},
                "selection_tag": {"cs-uri-query|contains": [
                    "<img src=", "<svg onload", "<body onload",
                    "<iframe src=", "<object data=",
                    "<embed src=", "<marquee onstart=",
                ]},
                "condition": "selection_script or selection_event or selection_tag",
            },
            falsepositives=["Web development tools", "Legitimate JavaScript content"],
            references=["https://owasp.org/www-community/attacks/xss/"],
        ))

        # Rule 4: XSS - Stored (POST)
        rules.append(self._make_rule(
            name="SIREN - Stored XSS Attempt in POST",
            description="Detects stored cross-site scripting attempts in form submissions",
            category=ThreatCategory.WEB_ATTACK,
            severity=ThreatSeverity.CRITICAL,
            mitre_techniques=["T1189"],
            mitre_tactics=["initial_access"],
            logsource_category="webserver",
            logsource_product="",
            detection={
                "selection_method": {"cs-method": "POST"},
                "selection_xss": {"cs-body|contains": [
                    "<script>", "javascript:", "onerror=",
                    "<svg/onload=", "<img/src/onerror=",
                    "document.cookie", "document.location",
                ]},
                "condition": "selection_method and selection_xss",
            },
            falsepositives=["CMS editors", "Rich text inputs"],
        ))

        # Rule 5: Path Traversal
        rules.append(self._make_rule(
            name="SIREN - Path Traversal Attack",
            description="Detects directory traversal attempts to access files outside webroot",
            category=ThreatCategory.WEB_ATTACK,
            severity=ThreatSeverity.HIGH,
            mitre_techniques=["T1083"],
            mitre_tactics=["discovery"],
            logsource_category="webserver",
            logsource_product="",
            detection={
                "selection_traversal": {"cs-uri|contains": [
                    "../", "..\\", "%2e%2e/", "%2e%2e%2f",
                    "..%2f", "%2e%2e\\", "..%5c", "%2e%2e%5c",
                    "....//", "....\\\\",
                ]},
                "selection_targets": {"cs-uri|contains": [
                    "/etc/passwd", "/etc/shadow", "/etc/hosts",
                    "win.ini", "boot.ini", "web.config",
                    "/proc/self/", "wp-config.php",
                ]},
                "condition": "selection_traversal or selection_targets",
            },
            falsepositives=["Relative path references in legitimate apps"],
            references=["https://owasp.org/www-community/attacks/Path_Traversal"],
        ))

        # Rule 6: Command Injection
        rules.append(self._make_rule(
            name="SIREN - OS Command Injection",
            description="Detects OS command injection patterns in HTTP requests",
            category=ThreatCategory.WEB_ATTACK,
            severity=ThreatSeverity.CRITICAL,
            mitre_techniques=["T1059"],
            mitre_tactics=["execution"],
            logsource_category="webserver",
            logsource_product="",
            detection={
                "selection_cmd": {"cs-uri-query|contains": [
                    ";ls", "|ls", "$(ls)", "`ls`",
                    ";cat ", "|cat ", ";id", "|id",
                    ";whoami", "|whoami", "$(whoami)",
                    ";uname", "|uname", "$(uname)",
                    ";ping ", "|ping ", ";nslookup",
                    "& ping ", "&& ping ",
                ]},
                "selection_win_cmd": {"cs-uri-query|contains": [
                    "cmd.exe", "cmd /c", "powershell",
                    "cmd%20/c", "powershell%20",
                    "& dir", "&& dir", "| dir",
                    "& type ", "| type ",
                ]},
                "condition": "selection_cmd or selection_win_cmd",
            },
            falsepositives=["System monitoring pages"],
        ))

        # Rule 7: SSRF
        rules.append(self._make_rule(
            name="SIREN - Server-Side Request Forgery",
            description="Detects SSRF attempts targeting internal services and cloud metadata",
            category=ThreatCategory.WEB_ATTACK,
            severity=ThreatSeverity.HIGH,
            mitre_techniques=["T1090"],
            mitre_tactics=["command_and_control"],
            logsource_category="webserver",
            logsource_product="",
            detection={
                "selection_internal": {"cs-uri-query|contains": [
                    "127.0.0.1", "localhost", "0.0.0.0",
                    "169.254.169.254", "metadata.google",
                    "[::1]", "10.0.0.", "172.16.", "192.168.",
                ]},
                "selection_schemes": {"cs-uri-query|contains": [
                    "file://", "gopher://", "dict://",
                    "ftp://", "ldap://", "tftp://",
                ]},
                "condition": "selection_internal or selection_schemes",
            },
            falsepositives=["Health check pages referencing localhost"],
        ))

        # Rule 8: Web Shell Upload
        rules.append(self._make_rule(
            name="SIREN - Web Shell Upload Attempt",
            description="Detects attempts to upload web shell files via HTTP",
            category=ThreatCategory.WEB_ATTACK,
            severity=ThreatSeverity.CRITICAL,
            mitre_techniques=["T1505.003"],
            mitre_tactics=["persistence"],
            logsource_category="webserver",
            logsource_product="",
            detection={
                "selection_method": {"cs-method": "POST"},
                "selection_uri": {"cs-uri|contains": [
                    "upload", "file_upload", "fileupload",
                    "attach", "import",
                ]},
                "selection_payload": {"cs-body|contains": [
                    "<?php", "<%@ ", "<jsp:", "system(",
                    "exec(", "shell_exec(", "passthru(",
                    "eval(base64_decode", "cmd.exe",
                ]},
                "condition": "selection_method and selection_uri and selection_payload",
            },
            falsepositives=["Legitimate PHP file uploads in CMS"],
        ))

        return rules

    # ── Auth Anomaly Rules ─────────────────────────────────────────────────

    def _auth_anomaly_rules(self) -> List[DetectionRule]:
        """Generate SIGMA rules for authentication anomalies."""
        rules: List[DetectionRule] = []

        # Rule 9: Brute Force Login
        rules.append(self._make_rule(
            name="SIREN - Brute Force Login Detected",
            description="Detects multiple failed login attempts from same source indicating brute force attack",
            category=ThreatCategory.AUTH_ANOMALY,
            severity=ThreatSeverity.HIGH,
            mitre_techniques=["T1110.001"],
            mitre_tactics=["credential_access"],
            logsource_category="authentication",
            logsource_product="windows",
            detection={
                "selection": {
                    "EventID": [4625],
                    "LogonType": [2, 3, 10],
                },
                "timeframe": "5m",
                "condition": "selection | count(TargetUserName) by IpAddress > 10",
            },
            falsepositives=["Misconfigured service accounts", "Password change scripts"],
        ))

        # Rule 10: Credential Stuffing
        rules.append(self._make_rule(
            name="SIREN - Credential Stuffing Attack",
            description="Detects credential stuffing via multiple failed logins with different usernames from same IP",
            category=ThreatCategory.AUTH_ANOMALY,
            severity=ThreatSeverity.HIGH,
            mitre_techniques=["T1110.004"],
            mitre_tactics=["credential_access"],
            logsource_category="authentication",
            logsource_product="windows",
            detection={
                "selection": {"EventID": [4625]},
                "timeframe": "10m",
                "condition": "selection | count(TargetUserName) by IpAddress > 20",
            },
            falsepositives=["Bulk user migration", "Automated testing"],
        ))

        # Rule 11: MFA Bypass Attempt
        rules.append(self._make_rule(
            name="SIREN - MFA Bypass Attempt",
            description="Detects successful authentication bypassing multi-factor authentication",
            category=ThreatCategory.AUTH_ANOMALY,
            severity=ThreatSeverity.CRITICAL,
            mitre_techniques=["T1556.006"],
            mitre_tactics=["credential_access", "defense_evasion"],
            logsource_category="authentication",
            logsource_product="",
            detection={
                "selection_success": {"EventType": "AuthenticationSuccess"},
                "filter_mfa": {"MFACompleted": True},
                "condition": "selection_success and not filter_mfa",
            },
            falsepositives=["Legacy authentication protocols", "Service accounts without MFA"],
        ))

        # Rule 12: Password Spray
        rules.append(self._make_rule(
            name="SIREN - Password Spray Attack",
            description="Detects password spray attacks with single password attempted against many accounts",
            category=ThreatCategory.AUTH_ANOMALY,
            severity=ThreatSeverity.HIGH,
            mitre_techniques=["T1110.003"],
            mitre_tactics=["credential_access"],
            logsource_category="authentication",
            logsource_product="windows",
            detection={
                "selection": {"EventID": [4625], "Status": "0xC000006D"},
                "timeframe": "30m",
                "condition": "selection | count(TargetUserName) by IpAddress > 25",
            },
            falsepositives=["Mass password resets"],
        ))

        # Rule 13: Account Lockout Surge
        rules.append(self._make_rule(
            name="SIREN - Mass Account Lockout",
            description="Detects mass account lockout events indicating possible brute force or DoS attack",
            category=ThreatCategory.AUTH_ANOMALY,
            severity=ThreatSeverity.HIGH,
            mitre_techniques=["T1110"],
            mitre_tactics=["credential_access"],
            logsource_category="authentication",
            logsource_product="windows",
            detection={
                "selection": {"EventID": [4740]},
                "timeframe": "15m",
                "condition": "selection | count() > 10",
            },
            falsepositives=["Domain policy enforcement"],
        ))

        # Rule 14: Impossible Travel Login
        rules.append(self._make_rule(
            name="SIREN - Impossible Travel Authentication",
            description="Detects logins from geographically distant locations within short timeframe",
            category=ThreatCategory.AUTH_ANOMALY,
            severity=ThreatSeverity.HIGH,
            mitre_techniques=["T1078"],
            mitre_tactics=["initial_access"],
            logsource_category="authentication",
            logsource_product="",
            detection={
                "selection": {
                    "EventType": "AuthenticationSuccess",
                    "RiskLevel|contains": ["impossible_travel", "unfamiliar_location"],
                },
                "condition": "selection",
            },
            falsepositives=["VPN usage", "Corporate travel"],
        ))

        return rules

    # ── Data Exfiltration Rules ────────────────────────────────────────────

    def _data_exfil_rules(self) -> List[DetectionRule]:
        """Generate SIGMA rules for data exfiltration detection."""
        rules: List[DetectionRule] = []

        # Rule 15: Large Data Download
        rules.append(self._make_rule(
            name="SIREN - Anomalous Large Data Transfer",
            description="Detects unusually large outbound data transfers that may indicate data exfiltration",
            category=ThreatCategory.DATA_EXFILTRATION,
            severity=ThreatSeverity.HIGH,
            mitre_techniques=["T1048"],
            mitre_tactics=["exfiltration"],
            logsource_category="proxy",
            logsource_product="",
            detection={
                "selection": {"sc-bytes|gt": 104857600},
                "filter_allowed": {"cs-host|endswith": [
                    ".microsoft.com", ".windowsupdate.com",
                    ".googleapis.com",
                ]},
                "condition": "selection and not filter_allowed",
            },
            falsepositives=["Large software downloads", "Cloud backups"],
        ))

        # Rule 16: DNS Tunneling
        rules.append(self._make_rule(
            name="SIREN - DNS Tunneling Detection",
            description="Detects DNS queries with unusually long subdomain labels indicating DNS tunneling",
            category=ThreatCategory.DATA_EXFILTRATION,
            severity=ThreatSeverity.HIGH,
            mitre_techniques=["T1048.003"],
            mitre_tactics=["exfiltration"],
            logsource_category="dns",
            logsource_product="",
            detection={
                "selection_long": {"query|re": r"^[a-zA-Z0-9]{30,}\."},
                "selection_many_labels": {"query|re": r"^([^.]+\.){5,}"},
                "selection_txt": {"record_type": "TXT"},
                "condition": "selection_long or (selection_many_labels and selection_txt)",
            },
            falsepositives=["CDN hostnames", "Anti-spam DKIM records"],
        ))

        # Rule 17: Base64 Encoded Data Exfil
        rules.append(self._make_rule(
            name="SIREN - Base64 Encoded Exfiltration",
            description="Detects large amounts of base64-encoded data in HTTP requests suggesting encoded exfiltration",
            category=ThreatCategory.DATA_EXFILTRATION,
            severity=ThreatSeverity.MEDIUM,
            mitre_techniques=["T1132.001"],
            mitre_tactics=["command_and_control"],
            logsource_category="webserver",
            logsource_product="",
            detection={
                "selection": {
                    "cs-uri-query|re": r"[A-Za-z0-9+/=]{100,}",
                },
                "condition": "selection",
            },
            falsepositives=["JWT tokens", "File upload APIs"],
        ))

        # Rule 18: Cloud Storage Exfil
        rules.append(self._make_rule(
            name="SIREN - Cloud Storage Exfiltration",
            description="Detects uploads to personal cloud storage services during business hours",
            category=ThreatCategory.DATA_EXFILTRATION,
            severity=ThreatSeverity.MEDIUM,
            mitre_techniques=["T1567.002"],
            mitre_tactics=["exfiltration"],
            logsource_category="proxy",
            logsource_product="",
            detection={
                "selection_upload": {"cs-method": ["POST", "PUT"]},
                "selection_cloud": {"cs-host|contains": [
                    "dropbox.com", "drive.google.com", "onedrive.live.com",
                    "mega.nz", "mediafire.com", "sendspace.com",
                    "wetransfer.com", "pastebin.com",
                ]},
                "condition": "selection_upload and selection_cloud",
            },
            falsepositives=["Authorized cloud storage usage"],
        ))

        # Rule 19: Encrypted Channel Exfil
        rules.append(self._make_rule(
            name="SIREN - Suspicious Encrypted Channel",
            description="Detects outbound connections on unusual ports with high data volume suggesting encrypted exfiltration",
            category=ThreatCategory.DATA_EXFILTRATION,
            severity=ThreatSeverity.MEDIUM,
            mitre_techniques=["T1573"],
            mitre_tactics=["command_and_control"],
            logsource_category="firewall",
            logsource_product="",
            detection={
                "selection": {
                    "dst_port|gt": 1024,
                    "bytes_out|gt": 52428800,
                    "protocol": "TCP",
                },
                "filter_known": {"dst_port": [
                    8080, 8443, 3389, 5985, 5986,
                ]},
                "condition": "selection and not filter_known",
            },
            falsepositives=["VPN connections", "Tunneled protocols"],
        ))

        return rules

    # ── Lateral Movement Rules ─────────────────────────────────────────────

    def _lateral_movement_rules(self) -> List[DetectionRule]:
        """Generate SIGMA rules for lateral movement detection."""
        rules: List[DetectionRule] = []

        # Rule 20: Pass-the-Hash
        rules.append(self._make_rule(
            name="SIREN - Pass-the-Hash Detected",
            description="Detects NTLM authentication with pass-the-hash indicators in logon events",
            category=ThreatCategory.LATERAL_MOVEMENT,
            severity=ThreatSeverity.CRITICAL,
            mitre_techniques=["T1550.002"],
            mitre_tactics=["lateral_movement"],
            logsource_category="authentication",
            logsource_product="windows",
            detection={
                "selection": {
                    "EventID": [4624],
                    "LogonType": 3,
                    "LogonProcessName": "NtLmSsp",
                    "KeyLength": 0,
                },
                "filter_anonymous": {"TargetUserName": "ANONYMOUS LOGON"},
                "condition": "selection and not filter_anonymous",
            },
            falsepositives=["Legacy NTLM authentication"],
        ))

        # Rule 21: PsExec Usage
        rules.append(self._make_rule(
            name="SIREN - PsExec Remote Execution",
            description="Detects PsExec or similar remote execution tool usage via named pipe and service creation",
            category=ThreatCategory.LATERAL_MOVEMENT,
            severity=ThreatSeverity.HIGH,
            mitre_techniques=["T1569.002"],
            mitre_tactics=["execution", "lateral_movement"],
            logsource_category="process_creation",
            logsource_product="windows",
            detection={
                "selection_process": {"Image|endswith": [
                    "\\PsExec.exe", "\\PsExec64.exe",
                    "\\PSEXESVC.exe",
                ]},
                "selection_pipe": {"PipeName|contains": [
                    "\\PSEXESVC", "\\psexec",
                ]},
                "selection_service": {
                    "EventID": [7045],
                    "ServiceName|contains": ["PSEXESVC"],
                },
                "condition": "selection_process or selection_pipe or selection_service",
            },
            falsepositives=["Legitimate admin remote management"],
        ))

        # Rule 22: WMI Remote Execution
        rules.append(self._make_rule(
            name="SIREN - WMI Remote Process Creation",
            description="Detects remote process creation via Windows Management Instrumentation",
            category=ThreatCategory.LATERAL_MOVEMENT,
            severity=ThreatSeverity.HIGH,
            mitre_techniques=["T1047"],
            mitre_tactics=["execution", "lateral_movement"],
            logsource_category="process_creation",
            logsource_product="windows",
            detection={
                "selection": {
                    "ParentImage|endswith": "\\WmiPrvSE.exe",
                    "Image|endswith": [
                        "\\cmd.exe", "\\powershell.exe",
                        "\\mshta.exe", "\\cscript.exe",
                        "\\wscript.exe", "\\rundll32.exe",
                    ],
                },
                "condition": "selection",
            },
            falsepositives=["WMI-based monitoring tools"],
        ))

        # Rule 23: SMB Lateral Movement
        rules.append(self._make_rule(
            name="SIREN - SMB Lateral Movement",
            description="Detects suspicious SMB file copy to admin shares indicating lateral movement",
            category=ThreatCategory.LATERAL_MOVEMENT,
            severity=ThreatSeverity.HIGH,
            mitre_techniques=["T1021.002"],
            mitre_tactics=["lateral_movement"],
            logsource_category="file_event",
            logsource_product="windows",
            detection={
                "selection": {
                    "ShareName|contains": ["\\C$", "\\ADMIN$", "\\IPC$"],
                    "TargetFilename|endswith": [
                        ".exe", ".dll", ".bat", ".ps1",
                        ".vbs", ".js",
                    ],
                },
                "condition": "selection",
            },
            falsepositives=["Software deployment tools", "SCCM"],
        ))

        # Rule 24: RDP Lateral Movement
        rules.append(self._make_rule(
            name="SIREN - Suspicious RDP Lateral Movement",
            description="Detects RDP connections from unusual internal sources indicating lateral movement",
            category=ThreatCategory.LATERAL_MOVEMENT,
            severity=ThreatSeverity.MEDIUM,
            mitre_techniques=["T1021.001"],
            mitre_tactics=["lateral_movement"],
            logsource_category="authentication",
            logsource_product="windows",
            detection={
                "selection": {
                    "EventID": [4624],
                    "LogonType": 10,
                },
                "filter_known": {"IpAddress|startswith": [
                    "10.0.0.", "192.168.1.",
                ]},
                "condition": "selection and not filter_known",
            },
            falsepositives=["Legitimate remote admin sessions"],
        ))

        return rules

    # ── Privilege Escalation Rules ─────────────────────────────────────────

    def _privilege_escalation_rules(self) -> List[DetectionRule]:
        """Generate SIGMA rules for privilege escalation detection."""
        rules: List[DetectionRule] = []

        # Rule 25: Sudo Abuse
        rules.append(self._make_rule(
            name="SIREN - Sudo Privilege Escalation",
            description="Detects suspicious sudo usage patterns including sudo to root shell",
            category=ThreatCategory.PRIVILEGE_ESCALATION,
            severity=ThreatSeverity.HIGH,
            mitre_techniques=["T1548.003"],
            mitre_tactics=["privilege_escalation"],
            logsource_category="process_creation",
            logsource_product="linux",
            detection={
                "selection_sudo_shell": {
                    "Image|endswith": ["/sudo"],
                    "CommandLine|contains": [
                        "sudo su", "sudo -i", "sudo /bin/bash",
                        "sudo /bin/sh", "sudo -s",
                    ],
                },
                "selection_sudo_vuln": {
                    "CommandLine|contains": [
                        "sudo -u#-1", "sudo -u#4294967295",
                        "sudoedit -s", "sudo NOPASSWD",
                    ],
                },
                "condition": "selection_sudo_shell or selection_sudo_vuln",
            },
            falsepositives=["System administrators using sudo"],
        ))

        # Rule 26: Token Manipulation
        rules.append(self._make_rule(
            name="SIREN - Access Token Manipulation",
            description="Detects Windows access token manipulation for privilege escalation",
            category=ThreatCategory.PRIVILEGE_ESCALATION,
            severity=ThreatSeverity.CRITICAL,
            mitre_techniques=["T1134"],
            mitre_tactics=["privilege_escalation", "defense_evasion"],
            logsource_category="process_creation",
            logsource_product="windows",
            detection={
                "selection_tools": {"Image|endswith": [
                    "\\incognito.exe", "\\tokenvator.exe",
                ]},
                "selection_api": {"CommandLine|contains": [
                    "ImpersonateLoggedOnUser", "DuplicateTokenEx",
                    "SetThreadToken", "CreateProcessWithTokenW",
                    "AdjustTokenPrivileges",
                ]},
                "condition": "selection_tools or selection_api",
            },
            falsepositives=["Security testing tools"],
        ))

        # Rule 27: SUID/SGID Abuse
        rules.append(self._make_rule(
            name="SIREN - SUID Binary Exploitation",
            description="Detects execution of SUID/SGID binaries commonly abused for privilege escalation",
            category=ThreatCategory.PRIVILEGE_ESCALATION,
            severity=ThreatSeverity.HIGH,
            mitre_techniques=["T1548.001"],
            mitre_tactics=["privilege_escalation"],
            logsource_category="process_creation",
            logsource_product="linux",
            detection={
                "selection": {
                    "Image|endswith": [
                        "/find", "/vim", "/nmap", "/python",
                        "/perl", "/ruby", "/gcc", "/gdb",
                        "/strace", "/ltrace",
                    ],
                    "User": "root",
                    "ParentUser|ne": "root",
                },
                "condition": "selection",
            },
            falsepositives=["Legitimate SUID usage"],
        ))

        # Rule 28: UAC Bypass
        rules.append(self._make_rule(
            name="SIREN - UAC Bypass Attempt",
            description="Detects User Account Control bypass techniques on Windows",
            category=ThreatCategory.PRIVILEGE_ESCALATION,
            severity=ThreatSeverity.HIGH,
            mitre_techniques=["T1548.002"],
            mitre_tactics=["privilege_escalation", "defense_evasion"],
            logsource_category="process_creation",
            logsource_product="windows",
            detection={
                "selection_fodhelper": {
                    "ParentImage|endswith": "\\fodhelper.exe",
                    "Image|endswith": [
                        "\\cmd.exe", "\\powershell.exe",
                    ],
                },
                "selection_eventvwr": {
                    "ParentImage|endswith": "\\eventvwr.exe",
                    "Image|endswith": [
                        "\\cmd.exe", "\\powershell.exe",
                    ],
                },
                "selection_sdclt": {
                    "ParentImage|endswith": "\\sdclt.exe",
                    "Image|endswith": [
                        "\\cmd.exe", "\\powershell.exe",
                    ],
                },
                "condition": "selection_fodhelper or selection_eventvwr or selection_sdclt",
            },
            falsepositives=["Legitimate auto-elevated processes"],
        ))

        return rules

    # ── Persistence Rules ──────────────────────────────────────────────────

    def _persistence_rules(self) -> List[DetectionRule]:
        """Generate SIGMA rules for persistence mechanism detection."""
        rules: List[DetectionRule] = []

        # Rule 29: Scheduled Task Creation
        rules.append(self._make_rule(
            name="SIREN - Suspicious Scheduled Task Creation",
            description="Detects creation of scheduled tasks with suspicious characteristics",
            category=ThreatCategory.PERSISTENCE,
            severity=ThreatSeverity.HIGH,
            mitre_techniques=["T1053.005"],
            mitre_tactics=["persistence", "execution"],
            logsource_category="process_creation",
            logsource_product="windows",
            detection={
                "selection_cmd": {
                    "Image|endswith": "\\schtasks.exe",
                    "CommandLine|contains": "/create",
                },
                "selection_suspicious": {"CommandLine|contains": [
                    "powershell", "cmd /c", "mshta",
                    "rundll32", "regsvr32", "cscript",
                    "wscript", "certutil", "bitsadmin",
                    "AppData", "Temp", "ProgramData",
                ]},
                "condition": "selection_cmd and selection_suspicious",
            },
            falsepositives=["Software installation", "System maintenance scripts"],
        ))

        # Rule 30: Registry Run Key Modification
        rules.append(self._make_rule(
            name="SIREN - Registry Run Key Persistence",
            description="Detects modification of registry Run/RunOnce keys for persistence",
            category=ThreatCategory.PERSISTENCE,
            severity=ThreatSeverity.HIGH,
            mitre_techniques=["T1547.001"],
            mitre_tactics=["persistence"],
            logsource_category="registry_event",
            logsource_product="windows",
            detection={
                "selection": {"TargetObject|contains": [
                    "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\",
                    "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\",
                    "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices\\",
                    "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\",
                    "\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run\\",
                ]},
                "filter_legit": {"Image|endswith": [
                    "\\msiexec.exe", "\\setup.exe",
                ]},
                "condition": "selection and not filter_legit",
            },
            falsepositives=["Software installation creating startup entries"],
        ))

        # Rule 31: Cron Job Persistence
        rules.append(self._make_rule(
            name="SIREN - Suspicious Cron Job Creation",
            description="Detects creation or modification of cron jobs for persistence on Linux",
            category=ThreatCategory.PERSISTENCE,
            severity=ThreatSeverity.HIGH,
            mitre_techniques=["T1053.003"],
            mitre_tactics=["persistence", "execution"],
            logsource_category="file_event",
            logsource_product="linux",
            detection={
                "selection_crontab": {"TargetFilename|contains": [
                    "/etc/crontab", "/etc/cron.d/",
                    "/var/spool/cron/", "/etc/cron.hourly/",
                    "/etc/cron.daily/", "/etc/cron.weekly/",
                    "/etc/cron.monthly/",
                ]},
                "selection_content": {"CommandLine|contains": [
                    "curl ", "wget ", "python ", "bash -c",
                    "nc ", "ncat ", "/dev/tcp/",
                ]},
                "condition": "selection_crontab or selection_content",
            },
            falsepositives=["System administration cron jobs"],
        ))

        # Rule 32: Startup Folder Persistence
        rules.append(self._make_rule(
            name="SIREN - Startup Folder Modification",
            description="Detects files dropped in Windows startup folders for persistence",
            category=ThreatCategory.PERSISTENCE,
            severity=ThreatSeverity.HIGH,
            mitre_techniques=["T1547.001"],
            mitre_tactics=["persistence"],
            logsource_category="file_event",
            logsource_product="windows",
            detection={
                "selection": {"TargetFilename|contains": [
                    "\\Start Menu\\Programs\\Startup\\",
                    "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\",
                ]},
                "selection_ext": {"TargetFilename|endswith": [
                    ".exe", ".dll", ".bat", ".cmd",
                    ".vbs", ".js", ".ps1", ".lnk",
                    ".hta", ".scr",
                ]},
                "condition": "selection and selection_ext",
            },
            falsepositives=["Legitimate software adding startup entries"],
        ))

        # Rule 33: Systemd Service Persistence
        rules.append(self._make_rule(
            name="SIREN - Systemd Service Persistence",
            description="Detects creation of systemd service units for persistence on Linux",
            category=ThreatCategory.PERSISTENCE,
            severity=ThreatSeverity.HIGH,
            mitre_techniques=["T1543.002"],
            mitre_tactics=["persistence"],
            logsource_category="file_event",
            logsource_product="linux",
            detection={
                "selection": {"TargetFilename|contains": [
                    "/etc/systemd/system/",
                    "/usr/lib/systemd/system/",
                    "/run/systemd/system/",
                    "/.config/systemd/user/",
                ]},
                "selection_ext": {"TargetFilename|endswith": [".service", ".timer"]},
                "condition": "selection and selection_ext",
            },
            falsepositives=["Package installation", "System configuration"],
        ))

        # Rule 34: WMI Event Subscription Persistence
        rules.append(self._make_rule(
            name="SIREN - WMI Event Subscription Persistence",
            description="Detects WMI event subscription creation for persistent execution",
            category=ThreatCategory.PERSISTENCE,
            severity=ThreatSeverity.HIGH,
            mitre_techniques=["T1546.003"],
            mitre_tactics=["persistence"],
            logsource_category="wmi_event",
            logsource_product="windows",
            detection={
                "selection_event": {"EventID": [19, 20, 21]},
                "selection_consumer": {"Consumer|contains": [
                    "CommandLineEventConsumer",
                    "ActiveScriptEventConsumer",
                ]},
                "condition": "selection_event or selection_consumer",
            },
            falsepositives=["Legitimate WMI monitoring solutions"],
        ))

        return rules

    # ── SIGMA YAML Builder ─────────────────────────────────────────────────

    def _make_rule(
        self,
        name: str,
        description: str,
        category: ThreatCategory,
        severity: ThreatSeverity,
        mitre_techniques: List[str],
        mitre_tactics: List[str],
        logsource_category: str,
        logsource_product: str,
        detection: Dict[str, Any],
        falsepositives: Optional[List[str]] = None,
        references: Optional[List[str]] = None,
    ) -> DetectionRule:
        """Build a DetectionRule with valid SIGMA YAML content."""
        self._rule_count += 1
        rule_id = str(uuid.uuid4())
        severity_map = {
            ThreatSeverity.CRITICAL: "critical",
            ThreatSeverity.HIGH: "high",
            ThreatSeverity.MEDIUM: "medium",
            ThreatSeverity.LOW: "low",
            ThreatSeverity.INFORMATIONAL: "informational",
        }
        level = severity_map.get(severity, "medium")
        tags = [f"attack.{t}" for t in mitre_tactics]
        tags.extend(f"attack.{t.lower()}" for t in mitre_techniques)

        # Build YAML manually (stdlib only)
        lines: List[str] = [
            f"title: {name}",
            f"id: {rule_id}",
            f"status: experimental",
            f"description: {description}",
            f"author: SIREN Threat Hunter",
            f"date: {time.strftime('%Y/%m/%d')}",
        ]
        if references:
            lines.append("references:")
            for ref in references:
                lines.append(f"    - {ref}")
        lines.append("tags:")
        for tag in tags:
            lines.append(f"    - {tag}")
        lines.append("logsource:")
        lines.append(f"    category: {logsource_category}")
        if logsource_product:
            lines.append(f"    product: {logsource_product}")
        lines.append("detection:")
        for key, value in detection.items():
            if key == "condition":
                continue
            if key == "timeframe":
                lines.append(f"    timeframe: {value}")
                continue
            lines.append(f"    {key}:")
            if isinstance(value, dict):
                for field_name, field_val in value.items():
                    if isinstance(field_val, list):
                        lines.append(f"        {field_name}:")
                        for item in field_val:
                            lines.append(f"            - '{item}'")
                    elif isinstance(field_val, bool):
                        lines.append(f"        {field_name}: {str(field_val).lower()}")
                    elif isinstance(field_val, (int, float)):
                        lines.append(f"        {field_name}: {field_val}")
                    else:
                        lines.append(f"        {field_name}: '{field_val}'")
        # Condition always last in detection
        if "condition" in detection:
            lines.append(f"    condition: {detection['condition']}")
        if falsepositives:
            lines.append("falsepositives:")
            for fp in falsepositives:
                lines.append(f"    - {fp}")
        lines.append(f"level: {level}")

        content = "\n".join(lines)

        return DetectionRule(
            rule_id=rule_id,
            name=name,
            description=description,
            rule_format=RuleFormat.SIGMA,
            content=content,
            severity=severity,
            category=category,
            mitre_techniques=mitre_techniques,
            mitre_tactics=mitre_tactics,
            false_positive_rate=0.05 if severity in (
                ThreatSeverity.CRITICAL, ThreatSeverity.HIGH
            ) else 0.15,
            data_sources=[logsource_category],
            tags=tags,
            references=references or [],
            author="SIREN Threat Hunter",
        )

    def get_stats(self) -> Dict[str, Any]:
        """Get generation statistics."""
        with self._lock:
            cat_counts: Dict[str, int] = defaultdict(int)
            for rule in self._generated_rules:
                cat_counts[rule.category.name] += 1
            return {
                "total_rules_generated": self._rule_count,
                "rules_by_category": dict(cat_counts),
                "stored_rules": len(self._generated_rules),
            }


# ════════════════════════════════════════════════════════════════════════════════
# YARA RULE GENERATOR
# ════════════════════════════════════════════════════════════════════════════════


class YARARuleGenerator:
    """
    Generates YARA rules for file-based threat detection.

    Produces 20+ rules across categories:
        - Web shell detection
        - Exploit payloads
        - Credential harvesters
        - Crypto miners
        - RAT signatures
        - Obfuscation detection

    Usage:
        gen = YARARuleGenerator()
        rules = gen.generate_all()
        for rule in rules:
            print(rule.content)
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._rule_count = 0
        self._generated_rules: List[DetectionRule] = []
        logger.info("YARARuleGenerator initialized")

    def generate_all(self) -> List[DetectionRule]:
        """Generate all YARA rules."""
        with self._lock:
            rules: List[DetectionRule] = []
            rules.extend(self._webshell_rules())
            rules.extend(self._exploit_payload_rules())
            rules.extend(self._credential_harvester_rules())
            rules.extend(self._crypto_miner_rules())
            rules.extend(self._rat_signature_rules())
            rules.extend(self._obfuscation_rules())
            self._generated_rules = rules
            logger.info("Generated %d YARA rules total", len(rules))
            return rules

    def _webshell_rules(self) -> List[DetectionRule]:
        """Generate YARA rules for webshell detection."""
        rules: List[DetectionRule] = []

        # YARA Rule 1: PHP Webshell
        rules.append(self._make_yara_rule(
            name="SIREN_PHP_Webshell_Generic",
            description="Detects generic PHP webshells with command execution capabilities",
            tags=["webshell", "php", "backdoor"],
            mitre_techniques=["T1505.003"],
            strings=[
                ('$exec1', '"system("', 'ascii'),
                ('$exec2', '"passthru("', 'ascii'),
                ('$exec3', '"shell_exec("', 'ascii'),
                ('$exec4', '"popen("', 'ascii'),
                ('$exec5', '"proc_open("', 'ascii'),
                ('$exec6', '"pcntl_exec("', 'ascii'),
                ('$eval1', '"eval(base64_decode("', 'ascii'),
                ('$eval2', '"eval(gzinflate("', 'ascii'),
                ('$eval3', '"eval(str_rot13("', 'ascii'),
                ('$eval4', '"assert(base64_decode("', 'ascii'),
                ('$input1', '"$_GET[', 'ascii'),
                ('$input2', '"$_POST[', 'ascii'),
                ('$input3', '"$_REQUEST[', 'ascii'),
                ('$input4', '"$_FILES[', 'ascii'),
            ],
            condition="(any of ($exec*) and any of ($input*)) or any of ($eval*)",
            severity=ThreatSeverity.CRITICAL,
        ))

        # YARA Rule 2: JSP Webshell
        rules.append(self._make_yara_rule(
            name="SIREN_JSP_Webshell",
            description="Detects JSP-based webshells with runtime execution",
            tags=["webshell", "jsp", "java"],
            mitre_techniques=["T1505.003"],
            strings=[
                ('$rt1', '"Runtime.getRuntime().exec("', 'ascii'),
                ('$rt2', '"ProcessBuilder"', 'ascii'),
                ('$cmd1', '"request.getParameter("', 'ascii'),
                ('$cmd2', '"<%@ page import=\\"java.io.*\\"', 'ascii'),
                ('$cmd3', '"new BufferedReader(new InputStreamReader"', 'ascii'),
                ('$b64', '"sun.misc.BASE64Decoder"', 'ascii'),
            ],
            condition="($rt1 or $rt2) and any of ($cmd*)",
            severity=ThreatSeverity.CRITICAL,
        ))

        # YARA Rule 3: ASPX Webshell
        rules.append(self._make_yara_rule(
            name="SIREN_ASPX_Webshell",
            description="Detects ASPX/ASP.NET webshells",
            tags=["webshell", "aspx", "dotnet"],
            mitre_techniques=["T1505.003"],
            strings=[
                ('$proc1', '"System.Diagnostics.Process"', 'ascii'),
                ('$proc2', '"ProcessStartInfo"', 'ascii'),
                ('$cmd1', '"cmd.exe"', 'ascii nocase'),
                ('$cmd2', '"/c "', 'ascii'),
                ('$io1', '"Request.Form["', 'ascii'),
                ('$io2', '"Request.QueryString["', 'ascii'),
                ('$io3', '"Request.Params["', 'ascii'),
                ('$compile', '"CompileAssemblyFromSource"', 'ascii'),
            ],
            condition="(any of ($proc*) and any of ($io*)) or $compile",
            severity=ThreatSeverity.CRITICAL,
        ))

        # YARA Rule 4: Python Webshell
        rules.append(self._make_yara_rule(
            name="SIREN_Python_Webshell",
            description="Detects Python-based webshells and reverse shells",
            tags=["webshell", "python", "reverse_shell"],
            mitre_techniques=["T1505.003"],
            strings=[
                ('$os1', '"os.system("', 'ascii'),
                ('$os2', '"os.popen("', 'ascii'),
                ('$sub1', '"subprocess.call("', 'ascii'),
                ('$sub2', '"subprocess.Popen("', 'ascii'),
                ('$sub3', '"subprocess.check_output("', 'ascii'),
                ('$sock1', '"socket.socket("', 'ascii'),
                ('$sock2', '"pty.spawn("', 'ascii'),
                ('$exec1', '"exec(compile("', 'ascii'),
                ('$exec2', '"__import__(\'os\').system"', 'ascii'),
            ],
            condition="any of ($os*) or any of ($sub*) or ($sock1 and $sock2) or any of ($exec*)",
            severity=ThreatSeverity.HIGH,
        ))

        return rules

    def _exploit_payload_rules(self) -> List[DetectionRule]:
        """Generate YARA rules for exploit payload detection."""
        rules: List[DetectionRule] = []

        # YARA Rule 5: Shellcode Patterns
        rules.append(self._make_yara_rule(
            name="SIREN_Shellcode_Patterns",
            description="Detects common shellcode byte patterns used in exploits",
            tags=["exploit", "shellcode"],
            mitre_techniques=["T1203"],
            strings=[
                ('$nop_sled', '{ 90 90 90 90 90 90 90 90 90 90 }', 'hex'),
                ('$x86_exec', '{ 31 c0 50 68 2f 2f 73 68 68 2f 62 69 6e }', 'hex'),
                ('$win_exec', '{ 68 63 6d 64 00 }', 'hex'),
                ('$msfvenom1', '"EXITFUNC"', 'ascii'),
                ('$msfvenom2', '"meterpreter"', 'ascii nocase'),
                ('$cobalt1', '{ 4d 5a 41 52 55 48 89 e5 }', 'hex'),
            ],
            condition="$nop_sled or $x86_exec or ($win_exec and filesize < 100KB) or any of ($msfvenom*) or $cobalt1",
            severity=ThreatSeverity.CRITICAL,
        ))

        # YARA Rule 6: Log4Shell Payload
        rules.append(self._make_yara_rule(
            name="SIREN_Log4Shell_Payload",
            description="Detects Log4Shell (CVE-2021-44228) exploitation patterns",
            tags=["exploit", "log4j", "cve_2021_44228"],
            mitre_techniques=["T1190"],
            strings=[
                ('$jndi1', '"${jndi:ldap://"', 'ascii nocase'),
                ('$jndi2', '"${jndi:rmi://"', 'ascii nocase'),
                ('$jndi3', '"${jndi:dns://"', 'ascii nocase'),
                ('$jndi4', '"${jndi:iiop://"', 'ascii nocase'),
                ('$obf1', '"${${lower:j}ndi:"', 'ascii nocase'),
                ('$obf2', '"${${upper:j}${upper:n}${upper:d}${upper:i}:"', 'ascii nocase'),
                ('$obf3', '"${j${::-n}di:"', 'ascii nocase'),
                ('$obf4', '"${${env:BARFOO:-j}ndi"', 'ascii nocase'),
            ],
            condition="any of them",
            severity=ThreatSeverity.CRITICAL,
        ))

        # YARA Rule 7: Deserialization Exploit
        rules.append(self._make_yara_rule(
            name="SIREN_Deserialization_Exploit",
            description="Detects Java/PHP/.NET deserialization exploit payloads",
            tags=["exploit", "deserialization"],
            mitre_techniques=["T1190"],
            strings=[
                ('$java1', '{ ac ed 00 05 }', 'hex'),
                ('$java2', '"ysoserial"', 'ascii nocase'),
                ('$java3', '"CommonsCollections"', 'ascii'),
                ('$java4', '"org.apache.commons.collections.Transformer"', 'ascii'),
                ('$php1', '"O:8:\\"stdClass\\""', 'ascii'),
                ('$php2', '"unserialize("', 'ascii'),
                ('$dotnet1', '"ObjectStateFormatter"', 'ascii'),
                ('$dotnet2', '"LosFormatter"', 'ascii'),
                ('$dotnet3', '"TypeConfuseDelegate"', 'ascii'),
            ],
            condition="any of ($java*) or (any of ($php*) and filesize < 50KB) or any of ($dotnet*)",
            severity=ThreatSeverity.HIGH,
        ))

        # YARA Rule 8: Buffer Overflow Strings
        rules.append(self._make_yara_rule(
            name="SIREN_Buffer_Overflow_Pattern",
            description="Detects buffer overflow exploit patterns and NOP sleds",
            tags=["exploit", "buffer_overflow"],
            mitre_techniques=["T1203"],
            strings=[
                ('$pattern1', '{ 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 }', 'hex'),
                ('$eip_overwrite', '{ 42 42 42 42 43 43 43 43 44 44 44 44 }', 'hex'),
                ('$seh_chain', '"\\xff\\xff\\xff\\xff"', 'ascii'),
                ('$egghunter', '{ 66 81 ca ff 0f 42 52 6a 02 58 cd 2e 3c 05 5a 74 }', 'hex'),
            ],
            condition="$pattern1 and ($eip_overwrite or $seh_chain or $egghunter)",
            severity=ThreatSeverity.HIGH,
        ))

        return rules

    def _credential_harvester_rules(self) -> List[DetectionRule]:
        """Generate YARA rules for credential harvester detection."""
        rules: List[DetectionRule] = []

        # YARA Rule 9: Mimikatz
        rules.append(self._make_yara_rule(
            name="SIREN_Mimikatz_Indicators",
            description="Detects Mimikatz credential dumping tool artifacts",
            tags=["credential_theft", "mimikatz"],
            mitre_techniques=["T1003.001"],
            strings=[
                ('$str1', '"sekurlsa::logonPasswords"', 'ascii nocase'),
                ('$str2', '"sekurlsa::wdigest"', 'ascii nocase'),
                ('$str3', '"lsadump::sam"', 'ascii nocase'),
                ('$str4', '"lsadump::dcsync"', 'ascii nocase'),
                ('$str5', '"kerberos::golden"', 'ascii nocase'),
                ('$str6', '"privilege::debug"', 'ascii nocase'),
                ('$str7', '"token::elevate"', 'ascii nocase'),
                ('$bin1', '"gentilkiwi"', 'ascii'),
                ('$bin2', '"mimikatz"', 'ascii nocase'),
                ('$bin3', '"mimilib"', 'ascii nocase'),
            ],
            condition="any of ($str*) or 2 of ($bin*)",
            severity=ThreatSeverity.CRITICAL,
        ))

        # YARA Rule 10: LaZagne
        rules.append(self._make_yara_rule(
            name="SIREN_LaZagne_Credential_Stealer",
            description="Detects LaZagne credential recovery tool",
            tags=["credential_theft", "lazagne"],
            mitre_techniques=["T1555"],
            strings=[
                ('$s1', '"lazagne"', 'ascii nocase'),
                ('$s2', '"AlessandroZ"', 'ascii'),
                ('$s3', '"softwares.browsers"', 'ascii'),
                ('$s4', '"softwares.sysadmin"', 'ascii'),
                ('$s5', '"softwares.wifi"', 'ascii'),
                ('$fn1', '"chrome_passwords"', 'ascii'),
                ('$fn2', '"firefox_passwords"', 'ascii'),
            ],
            condition="($s1 or $s2) and any of ($s3, $s4, $s5, $fn1, $fn2)",
            severity=ThreatSeverity.HIGH,
        ))

        # YARA Rule 11: Credential Phishing Kit
        rules.append(self._make_yara_rule(
            name="SIREN_Phishing_Kit",
            description="Detects credential phishing kits and fake login pages",
            tags=["phishing", "credential_theft"],
            mitre_techniques=["T1598.003"],
            strings=[
                ('$form1', '"<form.*action=.*\\.php.*method=.*post"', 'ascii nocase'),
                ('$input1', '"type=\\"password\\""', 'ascii nocase'),
                ('$submit1', '"type=\\"submit\\""', 'ascii nocase'),
                ('$exfil1', '"file_put_contents("', 'ascii'),
                ('$exfil2', '"mail("', 'ascii'),
                ('$exfil3', '"fwrite($file"', 'ascii'),
                ('$brand1', '"Sign in to your account"', 'ascii nocase'),
                ('$brand2', '"Verify your identity"', 'ascii nocase'),
                ('$brand3', '"Session expired"', 'ascii nocase'),
            ],
            condition="($form1 and $input1) and any of ($exfil*) and any of ($brand*)",
            severity=ThreatSeverity.HIGH,
        ))

        # YARA Rule 12: Keylogger
        rules.append(self._make_yara_rule(
            name="SIREN_Keylogger_Generic",
            description="Detects generic keylogger functionality in binaries",
            tags=["keylogger", "spyware"],
            mitre_techniques=["T1056.001"],
            strings=[
                ('$api1', '"GetAsyncKeyState"', 'ascii'),
                ('$api2', '"SetWindowsHookEx"', 'ascii'),
                ('$api3', '"GetKeyboardState"', 'ascii'),
                ('$api4', '"GetForegroundWindow"', 'ascii'),
                ('$api5', '"GetWindowText"', 'ascii'),
                ('$log1', '"keylog"', 'ascii nocase'),
                ('$log2', '"keystroke"', 'ascii nocase'),
                ('$log3', '"keypress"', 'ascii nocase'),
            ],
            condition="3 of ($api*) or (any of ($api*) and any of ($log*))",
            severity=ThreatSeverity.HIGH,
        ))

        return rules

    def _crypto_miner_rules(self) -> List[DetectionRule]:
        """Generate YARA rules for cryptocurrency miner detection."""
        rules: List[DetectionRule] = []

        # YARA Rule 13: XMRig Miner
        rules.append(self._make_yara_rule(
            name="SIREN_XMRig_Cryptominer",
            description="Detects XMRig and similar Monero cryptocurrency miners",
            tags=["cryptominer", "xmrig", "monero"],
            mitre_techniques=["T1496"],
            strings=[
                ('$s1', '"xmrig"', 'ascii nocase'),
                ('$s2', '"stratum+tcp://"', 'ascii'),
                ('$s3', '"stratum+ssl://"', 'ascii'),
                ('$s4', '"--donate-level"', 'ascii'),
                ('$s5', '"randomx"', 'ascii nocase'),
                ('$s6', '"cryptonight"', 'ascii nocase'),
                ('$pool1', '"pool.minexmr.com"', 'ascii'),
                ('$pool2', '"xmrpool.eu"', 'ascii'),
                ('$pool3', '"monerohash.com"', 'ascii'),
                ('$pool4', '"moneroocean.stream"', 'ascii'),
                ('$wallet', '{ 34 [40-100] }', 'hex'),
            ],
            condition="any of ($s*) or any of ($pool*)",
            severity=ThreatSeverity.HIGH,
        ))

        # YARA Rule 14: Browser-Based Miner
        rules.append(self._make_yara_rule(
            name="SIREN_Browser_Cryptominer",
            description="Detects browser-based cryptocurrency mining scripts",
            tags=["cryptominer", "browser", "javascript"],
            mitre_techniques=["T1496"],
            strings=[
                ('$s1', '"coinhive"', 'ascii nocase'),
                ('$s2', '"CoinHive.Anonymous"', 'ascii'),
                ('$s3', '"deepMiner"', 'ascii'),
                ('$s4', '"cryptonight.wasm"', 'ascii'),
                ('$s5', '"miner.start("', 'ascii'),
                ('$s6', '"CryptoNight"', 'ascii'),
                ('$s7', '"crypto-loot"', 'ascii nocase'),
                ('$s8', '"minero.cc"', 'ascii'),
            ],
            condition="any of them",
            severity=ThreatSeverity.MEDIUM,
        ))

        # YARA Rule 15: Mining Config File
        rules.append(self._make_yara_rule(
            name="SIREN_Mining_Config",
            description="Detects cryptocurrency mining configuration files",
            tags=["cryptominer", "config"],
            mitre_techniques=["T1496"],
            strings=[
                ('$j1', '"algo"', 'ascii'),
                ('$j2', '"pool"', 'ascii'),
                ('$j3', '"wallet"', 'ascii'),
                ('$j4', '"coin"', 'ascii'),
                ('$j5', '"threads"', 'ascii'),
                ('$j6', '"donate-level"', 'ascii'),
                ('$j7', '"max-cpu-usage"', 'ascii'),
                ('$j8', '"background"', 'ascii'),
            ],
            condition="4 of them and filesize < 10KB",
            severity=ThreatSeverity.MEDIUM,
        ))

        return rules

    def _rat_signature_rules(self) -> List[DetectionRule]:
        """Generate YARA rules for Remote Access Trojan detection."""
        rules: List[DetectionRule] = []

        # YARA Rule 16: Cobalt Strike Beacon
        rules.append(self._make_yara_rule(
            name="SIREN_CobaltStrike_Beacon",
            description="Detects Cobalt Strike beacon payloads and artifacts",
            tags=["rat", "cobalt_strike", "c2"],
            mitre_techniques=["T1071.001"],
            strings=[
                ('$cs1', '"%s as %s\\\\%s: %d:%d"', 'ascii'),
                ('$cs2', '"beacon.dll"', 'ascii'),
                ('$cs3', '"beacon.x64.dll"', 'ascii'),
                ('$cs4', '"ReflectiveLoader"', 'ascii'),
                ('$cs5', '{ 2e 2f 2e 2f 2e 2c 2e 2f }', 'hex'),
                ('$cfg1', '{ 00 01 00 01 00 02 }', 'hex'),
                ('$pipe1', '"\\\\.\\pipe\\msagent_"', 'ascii'),
                ('$pipe2', '"\\\\.\\pipe\\MSSE-"', 'ascii'),
            ],
            condition="any of ($cs*) or any of ($cfg*) or any of ($pipe*)",
            severity=ThreatSeverity.CRITICAL,
        ))

        # YARA Rule 17: Metasploit Meterpreter
        rules.append(self._make_yara_rule(
            name="SIREN_Meterpreter_Payload",
            description="Detects Metasploit Meterpreter reverse shell payloads",
            tags=["rat", "metasploit", "meterpreter"],
            mitre_techniques=["T1059.006"],
            strings=[
                ('$s1', '"metsrv"', 'ascii'),
                ('$s2', '"meterpreter"', 'ascii nocase'),
                ('$s3', '"stdapi"', 'ascii'),
                ('$s4', '"ext_server_stdapi"', 'ascii'),
                ('$s5', '"reverse_tcp"', 'ascii'),
                ('$s6', '"reverse_https"', 'ascii'),
                ('$stager1', '{ fc e8 82 00 00 00 60 89 e5 }', 'hex'),
                ('$stager2', '{ fc 48 83 e4 f0 e8 c0 00 00 00 }', 'hex'),
            ],
            condition="any of ($s*) or any of ($stager*)",
            severity=ThreatSeverity.CRITICAL,
        ))

        # YARA Rule 18: Generic RAT Indicators
        rules.append(self._make_yara_rule(
            name="SIREN_Generic_RAT",
            description="Detects generic Remote Access Trojan behaviors and artifacts",
            tags=["rat", "backdoor"],
            mitre_techniques=["T1219"],
            strings=[
                ('$cmd1', '"cmd.exe /c"', 'ascii nocase'),
                ('$cmd2', '"powershell -enc"', 'ascii nocase'),
                ('$cmd3', '"powershell -nop -w hidden"', 'ascii nocase'),
                ('$net1', '"CONNECT %s:%d"', 'ascii'),
                ('$net2', '"User-Agent: Mozilla"', 'ascii'),
                ('$persist1', '"SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"', 'ascii'),
                ('$persist2', '"schtasks /create"', 'ascii nocase'),
                ('$screen1', '"GetDesktopWindow"', 'ascii'),
                ('$screen2', '"BitBlt"', 'ascii'),
                ('$screen3', '"capCreateCaptureWindow"', 'ascii'),
            ],
            condition="2 of ($cmd*) and any of ($net*) and (any of ($persist*) or any of ($screen*))",
            severity=ThreatSeverity.HIGH,
        ))

        # YARA Rule 19: njRAT
        rules.append(self._make_yara_rule(
            name="SIREN_njRAT_Indicators",
            description="Detects njRAT remote access trojan signatures",
            tags=["rat", "njrat"],
            mitre_techniques=["T1219"],
            strings=[
                ('$s1', '"njRAT"', 'ascii nocase'),
                ('$s2', '"im523"', 'ascii'),
                ('$s3', '"|\'|\'|"', 'ascii'),
                ('$s4', '"netsh firewall add allowedprogram"', 'ascii'),
                ('$s5', '"SEE_MASK_NOZONECHECKS"', 'ascii'),
                ('$s6', '"tmp.exe"', 'ascii'),
            ],
            condition="3 of them",
            severity=ThreatSeverity.CRITICAL,
        ))

        # YARA Rule 20: AsyncRAT
        rules.append(self._make_yara_rule(
            name="SIREN_AsyncRAT_Indicators",
            description="Detects AsyncRAT remote access trojan signatures",
            tags=["rat", "asyncrat"],
            mitre_techniques=["T1219"],
            strings=[
                ('$s1', '"AsyncClient"', 'ascii'),
                ('$s2', '"AsyncRAT"', 'ascii nocase'),
                ('$s3', '"Asynchronous"', 'ascii'),
                ('$s4', '"pastebin"', 'ascii nocase'),
                ('$s5', '"Certificates"', 'ascii'),
                ('$s6', '"ServerCertificate"', 'ascii'),
                ('$cfg1', '"Hwid"', 'ascii'),
                ('$cfg2', '"Serversignature"', 'ascii'),
                ('$cfg3', '"Anti"', 'ascii'),
            ],
            condition="($s1 or $s2) and 2 of ($cfg*)",
            severity=ThreatSeverity.CRITICAL,
        ))

        return rules

    def _obfuscation_rules(self) -> List[DetectionRule]:
        """Generate YARA rules for code obfuscation detection."""
        rules: List[DetectionRule] = []

        # YARA Rule 21: PowerShell Obfuscation
        rules.append(self._make_yara_rule(
            name="SIREN_PowerShell_Obfuscation",
            description="Detects obfuscated PowerShell commands commonly used in attacks",
            tags=["obfuscation", "powershell"],
            mitre_techniques=["T1027"],
            strings=[
                ('$enc1', '"-EncodedCommand"', 'ascii nocase'),
                ('$enc2', '"-enc "', 'ascii nocase'),
                ('$enc3', '"-e "', 'ascii nocase'),
                ('$obf1', '"[Convert]::FromBase64String"', 'ascii nocase'),
                ('$obf2', '"[System.Text.Encoding]::UTF8.GetString"', 'ascii nocase'),
                ('$obf3', '"IEX("', 'ascii nocase'),
                ('$obf4', '"Invoke-Expression"', 'ascii nocase'),
                ('$obf5', '"-join[char[]]("', 'ascii nocase'),
                ('$bypass1', '"-ExecutionPolicy Bypass"', 'ascii nocase'),
                ('$bypass2', '"-nop -w hidden"', 'ascii nocase'),
            ],
            condition="any of ($enc*) and any of ($obf*) or any of ($bypass*)",
            severity=ThreatSeverity.HIGH,
        ))

        # YARA Rule 22: Base64 Encoded Executable
        rules.append(self._make_yara_rule(
            name="SIREN_Base64_Encoded_PE",
            description="Detects base64-encoded PE executables embedded in files",
            tags=["obfuscation", "base64", "pe"],
            mitre_techniques=["T1027"],
            strings=[
                ('$b64_mz', '"TVqQAAMAAAAE"', 'ascii'),
                ('$b64_mz2', '"TVpQAAIAAAAE"', 'ascii'),
                ('$b64_mz3', '"TVoAAAAAAAAA"', 'ascii'),
                ('$b64_elf', '"f0VMRg"', 'ascii'),
            ],
            condition="any of them",
            severity=ThreatSeverity.HIGH,
        ))

        # YARA Rule 23: Packed/Encrypted Payload
        rules.append(self._make_yara_rule(
            name="SIREN_Packed_Payload",
            description="Detects indicators of packed or encrypted malware payloads",
            tags=["obfuscation", "packer", "crypter"],
            mitre_techniques=["T1027.002"],
            strings=[
                ('$upx1', '"UPX0"', 'ascii'),
                ('$upx2', '"UPX1"', 'ascii'),
                ('$upx3', '"UPX!"', 'ascii'),
                ('$vmp1', '".vmp0"', 'ascii'),
                ('$vmp2', '".vmp1"', 'ascii'),
                ('$themida', '"Themida"', 'ascii'),
                ('$vmprotect', '"VMProtect"', 'ascii'),
                ('$aspack', '".aspack"', 'ascii'),
                ('$high_entropy', '"This program cannot be run in DOS mode"', 'ascii'),
            ],
            condition="any of ($upx*) or any of ($vmp*) or $themida or $vmprotect or $aspack",
            severity=ThreatSeverity.MEDIUM,
        ))

        return rules

    # ── YARA Builder ───────────────────────────────────────────────────────

    def _make_yara_rule(
        self,
        name: str,
        description: str,
        tags: List[str],
        mitre_techniques: List[str],
        strings: List[Tuple[str, str, str]],
        condition: str,
        severity: ThreatSeverity = ThreatSeverity.HIGH,
    ) -> DetectionRule:
        """Build a DetectionRule with valid YARA rule content."""
        self._rule_count += 1
        tag_str = " ".join(tags)
        lines: List[str] = [
            f"rule {name} : {tag_str} {{",
            "    meta:",
            f'        description = "{description}"',
            f'        author = "SIREN Threat Hunter"',
            f'        date = "{time.strftime("%Y-%m-%d")}"',
            f'        severity = "{severity.name.lower()}"',
        ]
        for tid in mitre_techniques:
            lines.append(f'        mitre_attack = "{tid}"')
        lines.append("")
        lines.append("    strings:")
        for var_name, pattern, modifiers in strings:
            if modifiers == "hex":
                lines.append(f"        {var_name} = {pattern}")
            else:
                lines.append(f"        {var_name} = {pattern} {modifiers}")
        lines.append("")
        lines.append("    condition:")
        lines.append(f"        {condition}")
        lines.append("}")

        content = "\n".join(lines)

        return DetectionRule(
            rule_id=str(uuid.uuid4()),
            name=name,
            description=description,
            rule_format=RuleFormat.YARA,
            content=content,
            severity=severity,
            category=ThreatCategory.MALWARE,
            mitre_techniques=mitre_techniques,
            tags=tags,
            author="SIREN Threat Hunter",
        )

    def get_stats(self) -> Dict[str, Any]:
        """Get generation statistics."""
        with self._lock:
            return {
                "total_yara_rules": self._rule_count,
                "stored_rules": len(self._generated_rules),
            }


# ════════════════════════════════════════════════════════════════════════════════
# THREAT HUNT QUERY GENERATOR
# ════════════════════════════════════════════════════════════════════════════════


class ThreatHuntQuery:
    """
    Generates threat hunting queries for multiple SIEM platforms.

    Supported platforms:
        - Splunk SPL
        - ELK/OpenSearch KQL
        - Microsoft Sentinel KQL
        - QRadar AQL

    Usage:
        gen = ThreatHuntQuery()
        queries = gen.generate_queries("lateral_movement")
        for platform, query in queries.items():
            print(f"{platform}: {query}")
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._query_count = 0
        logger.info("ThreatHuntQuery initialized")

    def generate_queries(self, hunt_type: str) -> Dict[str, str]:
        """Generate queries for all platforms for a given hunt type."""
        with self._lock:
            self._query_count += 1
            dispatch: Dict[str, Callable[[], Dict[str, str]]] = {
                "brute_force": self._brute_force_queries,
                "lateral_movement": self._lateral_movement_queries,
                "data_exfiltration": self._data_exfil_queries,
                "privilege_escalation": self._priv_esc_queries,
                "persistence": self._persistence_queries,
                "command_and_control": self._c2_queries,
                "reconnaissance": self._recon_queries,
                "credential_access": self._credential_queries,
                "web_attack": self._web_attack_queries,
                "dns_anomaly": self._dns_anomaly_queries,
            }
            gen_fn = dispatch.get(hunt_type)
            if gen_fn:
                return gen_fn()
            logger.warning("Unknown hunt type: %s", hunt_type)
            return {}

    def generate_ioc_queries(self, ioc_bundle: IOCBundle) -> Dict[str, List[str]]:
        """Generate IOC-based hunting queries for all platforms."""
        with self._lock:
            results: Dict[str, List[str]] = {
                "splunk_spl": [], "elk_kql": [],
                "sentinel_kql": [], "qradar_aql": [],
            }
            for ioc in ioc_bundle.iocs:
                if ioc.ioc_type == IOCType.IP_ADDRESS:
                    results["splunk_spl"].append(
                        f'index=* (src_ip="{ioc.value}" OR dest_ip="{ioc.value}") | stats count by src_ip, dest_ip, action'
                    )
                    results["elk_kql"].append(
                        f'source.ip: "{ioc.value}" OR destination.ip: "{ioc.value}"'
                    )
                    results["sentinel_kql"].append(
                        f'union * | where SrcIP == "{ioc.value}" or DstIP == "{ioc.value}" | summarize count() by Type'
                    )
                    results["qradar_aql"].append(
                        f"SELECT * FROM events WHERE sourceip = '{ioc.value}' OR destinationip = '{ioc.value}' LAST 7 DAYS"
                    )
                elif ioc.ioc_type == IOCType.DOMAIN:
                    results["splunk_spl"].append(
                        f'index=dns query="{ioc.value}" | stats count by src_ip, query, answer'
                    )
                    results["elk_kql"].append(
                        f'dns.question.name: "{ioc.value}"'
                    )
                    results["sentinel_kql"].append(
                        f'DnsEvents | where Name contains "{ioc.value}" | summarize count() by ClientIP, Name'
                    )
                    results["qradar_aql"].append(
                        f"SELECT * FROM events WHERE DOMAINNAME(dns) = '{ioc.value}' LAST 7 DAYS"
                    )
                elif ioc.ioc_type in (IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256):
                    results["splunk_spl"].append(
                        f'index=endpoint file_hash="{ioc.value}" | stats count by host, file_path, action'
                    )
                    results["elk_kql"].append(
                        f'file.hash.sha256: "{ioc.value}" OR file.hash.md5: "{ioc.value}"'
                    )
                    results["sentinel_kql"].append(
                        f'DeviceFileEvents | where SHA256 == "{ioc.value}" or MD5 == "{ioc.value}" | project Timestamp, DeviceName, FileName'
                    )
                    results["qradar_aql"].append(
                        f"SELECT * FROM events WHERE filehash = '{ioc.value}' LAST 7 DAYS"
                    )
            return results

    def _brute_force_queries(self) -> Dict[str, str]:
        return {
            "splunk_spl": (
                'index=auth action=failure | stats count by src_ip, user, dest '
                '| where count > 10 | sort -count '
                '| rename src_ip as "Source IP", count as "Failed Attempts"'
            ),
            "elk_kql": (
                'event.category: "authentication" AND event.outcome: "failure"'
            ),
            "sentinel_kql": (
                'SecurityEvent\n| where EventID == 4625\n'
                '| summarize FailedAttempts = count() by IpAddress, TargetAccount, bin(TimeGenerated, 5m)\n'
                '| where FailedAttempts > 10\n| sort by FailedAttempts desc'
            ),
            "qradar_aql": (
                "SELECT sourceip, username, COUNT(*) as attempts "
                "FROM events WHERE category = 'Authentication' AND outcome = 'Failure' "
                "GROUP BY sourceip, username HAVING attempts > 10 LAST 24 HOURS"
            ),
        }

    def _lateral_movement_queries(self) -> Dict[str, str]:
        return {
            "splunk_spl": (
                'index=wineventlog (EventCode=4624 LogonType=3) OR (EventCode=4648) '
                '| stats dc(dest) as unique_targets by src_ip, user '
                '| where unique_targets > 3 | sort -unique_targets'
            ),
            "elk_kql": (
                'event.code: ("4624" OR "4648") AND winlog.event_data.LogonType: "3"'
            ),
            "sentinel_kql": (
                'SecurityEvent\n| where EventID in (4624, 4648) and LogonType == 3\n'
                '| summarize UniqueTargets = dcount(Computer) by IpAddress, Account, bin(TimeGenerated, 1h)\n'
                '| where UniqueTargets > 3\n| sort by UniqueTargets desc'
            ),
            "qradar_aql": (
                "SELECT sourceip, username, COUNT(DISTINCT destinationip) as targets "
                "FROM events WHERE EventID IN (4624, 4648) AND logontype = 3 "
                "GROUP BY sourceip, username HAVING targets > 3 LAST 24 HOURS"
            ),
        }

    def _data_exfil_queries(self) -> Dict[str, str]:
        return {
            "splunk_spl": (
                'index=proxy action=allowed | stats sum(bytes_out) as total_bytes by src_ip, dest_host '
                '| where total_bytes > 104857600 | eval MB=round(total_bytes/1048576,2) '
                '| sort -total_bytes'
            ),
            "elk_kql": (
                'event.category: "network" AND network.bytes > 104857600'
            ),
            "sentinel_kql": (
                'CommonSecurityLog\n| where SentBytes > 104857600\n'
                '| summarize TotalBytes = sum(SentBytes) by SourceIP, DestinationHostName, bin(TimeGenerated, 1h)\n'
                '| extend MB = TotalBytes / 1048576\n| sort by TotalBytes desc'
            ),
            "qradar_aql": (
                "SELECT sourceip, destinationip, SUM(bytesout) as total_bytes "
                "FROM flows WHERE bytesout > 104857600 "
                "GROUP BY sourceip, destinationip LAST 24 HOURS"
            ),
        }

    def _priv_esc_queries(self) -> Dict[str, str]:
        return {
            "splunk_spl": (
                'index=wineventlog (EventCode=4672 OR EventCode=4673 OR EventCode=4674) '
                '| stats count by SubjectUserName, PrivilegeList '
                '| where count > 5 | sort -count'
            ),
            "elk_kql": (
                'event.code: ("4672" OR "4673" OR "4674")'
            ),
            "sentinel_kql": (
                'SecurityEvent\n| where EventID in (4672, 4673, 4674)\n'
                '| summarize count() by Account, Activity, bin(TimeGenerated, 1h)\n'
                '| sort by count_ desc'
            ),
            "qradar_aql": (
                "SELECT username, COUNT(*) as priv_events "
                "FROM events WHERE EventID IN (4672, 4673, 4674) "
                "GROUP BY username HAVING priv_events > 5 LAST 24 HOURS"
            ),
        }

    def _persistence_queries(self) -> Dict[str, str]:
        return {
            "splunk_spl": (
                'index=wineventlog (EventCode=4698 OR EventCode=7045 OR EventCode=13) '
                '| table _time, ComputerName, EventCode, TaskName, ServiceName, TargetObject'
            ),
            "elk_kql": (
                'event.code: ("4698" OR "7045" OR "13") AND '
                '(winlog.event_data.TargetObject: "*CurrentVersion\\\\Run*" OR '
                'winlog.event_data.ServiceName: *)'
            ),
            "sentinel_kql": (
                'SecurityEvent\n| where EventID in (4698, 7045)\n'
                '| union (Event | where EventID == 13 and Source == "Microsoft-Windows-Sysmon")\n'
                '| project TimeGenerated, Computer, EventID, RenderedDescription'
            ),
            "qradar_aql": (
                "SELECT starttime, sourceip, EventID, message "
                "FROM events WHERE EventID IN (4698, 7045, 13) LAST 7 DAYS"
            ),
        }

    def _c2_queries(self) -> Dict[str, str]:
        return {
            "splunk_spl": (
                'index=proxy | stats count dc(dest_port) as unique_ports avg(bytes) as avg_bytes by src_ip, dest_host '
                '| where (count > 100 AND unique_ports < 3) OR avg_bytes < 500 '
                '| sort -count'
            ),
            "elk_kql": (
                'event.category: "network" AND network.protocol: ("http" OR "https" OR "dns") '
                'AND NOT destination.domain: ("*.microsoft.com" OR "*.google.com")'
            ),
            "sentinel_kql": (
                'CommonSecurityLog\n| summarize Beacons = count(), AvgBytes = avg(SentBytes) '
                'by SourceIP, DestinationHostName, bin(TimeGenerated, 1h)\n'
                '| where Beacons > 100 and AvgBytes < 500\n| sort by Beacons desc'
            ),
            "qradar_aql": (
                "SELECT sourceip, destinationip, destinationport, COUNT(*) as connections "
                "FROM flows WHERE protocolid = 6 "
                "GROUP BY sourceip, destinationip, destinationport "
                "HAVING connections > 100 LAST 24 HOURS"
            ),
        }

    def _recon_queries(self) -> Dict[str, str]:
        return {
            "splunk_spl": (
                'index=network action=allowed | stats dc(dest_port) as port_count dc(dest_ip) as ip_count by src_ip '
                '| where port_count > 50 OR ip_count > 100 '
                '| sort -port_count'
            ),
            "elk_kql": (
                'event.category: "network" AND event.action: "allowed"'
            ),
            "sentinel_kql": (
                'CommonSecurityLog\n| summarize UniquePorts = dcount(DestinationPort), '
                'UniqueIPs = dcount(DestinationIP) by SourceIP, bin(TimeGenerated, 1h)\n'
                '| where UniquePorts > 50 or UniqueIPs > 100\n| sort by UniquePorts desc'
            ),
            "qradar_aql": (
                "SELECT sourceip, COUNT(DISTINCT destinationport) as ports, "
                "COUNT(DISTINCT destinationip) as ips FROM flows "
                "GROUP BY sourceip HAVING ports > 50 OR ips > 100 LAST 24 HOURS"
            ),
        }

    def _credential_queries(self) -> Dict[str, str]:
        return {
            "splunk_spl": (
                'index=wineventlog (EventCode=4648 OR EventCode=4768 OR EventCode=4769) '
                '| stats count by SubjectUserName, TargetServerName, IpAddress '
                '| where count > 5 | sort -count'
            ),
            "elk_kql": (
                'event.code: ("4648" OR "4768" OR "4769")'
            ),
            "sentinel_kql": (
                'SecurityEvent\n| where EventID in (4648, 4768, 4769)\n'
                '| summarize count() by Account, IpAddress, bin(TimeGenerated, 1h)\n'
                '| sort by count_ desc'
            ),
            "qradar_aql": (
                "SELECT sourceip, username, EventID, COUNT(*) as events "
                "FROM events WHERE EventID IN (4648, 4768, 4769) "
                "GROUP BY sourceip, username, EventID LAST 24 HOURS"
            ),
        }

    def _web_attack_queries(self) -> Dict[str, str]:
        return {
            "splunk_spl": (
                'index=web (uri_query="*UNION SELECT*" OR uri_query="*<script>*" '
                'OR uri_query="*../*" OR uri_query="*;ls*" OR uri_query="*cmd.exe*") '
                '| stats count by src_ip, uri_path, status | sort -count'
            ),
            "elk_kql": (
                'url.query: (*UNION* OR *script* OR *..%2f* OR *cmd.exe*)'
            ),
            "sentinel_kql": (
                'W3CIISLog\n| where csUriQuery contains "UNION SELECT" '
                'or csUriQuery contains "<script>" or csUriQuery contains "../"\n'
                '| summarize count() by cIP, csUriStem, scStatus, bin(TimeGenerated, 1h)\n'
                '| sort by count_ desc'
            ),
            "qradar_aql": (
                "SELECT sourceip, url, COUNT(*) as hits "
                "FROM events WHERE LOGSOURCETYPENAME(logsourceid) = 'Apache' "
                "AND (url LIKE '%UNION SELECT%' OR url LIKE '%<script>%' OR url LIKE '%../%') "
                "GROUP BY sourceip, url LAST 24 HOURS"
            ),
        }

    def _dns_anomaly_queries(self) -> Dict[str, str]:
        return {
            "splunk_spl": (
                'index=dns | eval label_count=mvcount(split(query, ".")) '
                '| eval query_length=len(query) '
                '| where query_length > 50 OR label_count > 5 '
                '| stats count by src_ip, query | sort -count'
            ),
            "elk_kql": (
                'dns.question.name: * AND dns.question.type: "TXT"'
            ),
            "sentinel_kql": (
                'DnsEvents\n| extend QueryLength = strlen(Name), '
                'LabelCount = countof(Name, ".")\n'
                '| where QueryLength > 50 or LabelCount > 5\n'
                '| summarize count() by ClientIP, Name, QueryType\n| sort by count_ desc'
            ),
            "qradar_aql": (
                "SELECT sourceip, DOMAINNAME(dns) as domain, COUNT(*) as queries "
                "FROM events WHERE category = 'DNS' AND LENGTH(DOMAINNAME(dns)) > 50 "
                "GROUP BY sourceip, domain LAST 24 HOURS"
            ),
        }


# ════════════════════════════════════════════════════════════════════════════════
# HUNT PLAYBOOK
# ════════════════════════════════════════════════════════════════════════════════


@dataclass
class PlaybookStep:
    """A single step within a hunt playbook."""
    step_number: int = 0
    phase: PlaybookPhase = PlaybookPhase.HYPOTHESIS
    title: str = ""
    description: str = ""
    actions: List[str] = field(default_factory=list)
    data_sources: List[str] = field(default_factory=list)
    queries: Dict[str, str] = field(default_factory=dict)
    expected_output: str = ""
    decision_criteria: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_number": self.step_number,
            "phase": self.phase.name,
            "title": self.title,
            "description": self.description,
            "actions": self.actions,
            "data_sources": self.data_sources,
            "queries": self.queries,
            "expected_output": self.expected_output,
            "decision_criteria": self.decision_criteria,
        }


@dataclass
class HuntPlaybook:
    """A complete threat hunt playbook."""
    playbook_id: str = ""
    name: str = ""
    description: str = ""
    category: ThreatCategory = ThreatCategory.WEB_ATTACK
    severity: ThreatSeverity = ThreatSeverity.MEDIUM
    hypothesis: str = ""
    steps: List[PlaybookStep] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    mitre_tactics: List[str] = field(default_factory=list)
    required_data_sources: List[str] = field(default_factory=list)
    estimated_duration_minutes: int = 60
    tags: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.playbook_id:
            self.playbook_id = str(uuid.uuid4())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "playbook_id": self.playbook_id,
            "name": self.name,
            "description": self.description,
            "category": self.category.name,
            "severity": self.severity.name,
            "hypothesis": self.hypothesis,
            "steps": [s.to_dict() for s in self.steps],
            "mitre_techniques": self.mitre_techniques,
            "mitre_tactics": self.mitre_tactics,
            "required_data_sources": self.required_data_sources,
            "estimated_duration_minutes": self.estimated_duration_minutes,
            "tags": self.tags,
        }


class PlaybookLibrary:
    """
    Library of pre-built threat hunting playbooks.

    Contains 10+ playbooks covering common threat scenarios:
        - Brute force investigation
        - Lateral movement tracing
        - Data exfiltration detection
        - C2 beacon hunting
        - Insider threat investigation
        - Malware outbreak response
        - Phishing campaign analysis
        - Privilege escalation review
        - Persistence mechanism audit
        - Ransomware precursor detection
        - Supply chain compromise check

    Usage:
        library = PlaybookLibrary()
        playbook = library.get_playbook("brute_force")
        for step in playbook.steps:
            print(step.to_dict())
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._playbooks: Dict[str, HuntPlaybook] = {}
        self._build_playbooks()
        logger.info("PlaybookLibrary initialized with %d playbooks", len(self._playbooks))

    def get_playbook(self, name: str) -> Optional[HuntPlaybook]:
        """Retrieve a playbook by name."""
        with self._lock:
            return self._playbooks.get(name)

    def list_playbooks(self) -> List[Dict[str, Any]]:
        """List all available playbooks."""
        with self._lock:
            return [
                {"name": k, "description": v.description, "category": v.category.name}
                for k, v in self._playbooks.items()
            ]

    def _build_playbooks(self) -> None:
        """Build all pre-defined playbooks."""
        self._playbooks["brute_force"] = HuntPlaybook(
            name="Brute Force Investigation",
            description="Investigate potential brute force or credential stuffing attacks",
            category=ThreatCategory.AUTH_ANOMALY,
            severity=ThreatSeverity.HIGH,
            hypothesis="An attacker is attempting to gain access via repeated authentication attempts",
            mitre_techniques=["T1110.001", "T1110.003", "T1110.004"],
            mitre_tactics=["credential_access"],
            required_data_sources=["authentication_logs", "firewall_logs"],
            estimated_duration_minutes=45,
            steps=[
                PlaybookStep(step_number=1, phase=PlaybookPhase.DATA_COLLECTION, title="Collect failed auth events",
                    actions=["Query authentication logs for failed login events", "Filter by timeframe and threshold"],
                    data_sources=["windows_security", "linux_auth"],
                    expected_output="List of source IPs with failed login counts"),
                PlaybookStep(step_number=2, phase=PlaybookPhase.INVESTIGATION, title="Identify attack patterns",
                    actions=["Check if single IP targets many accounts (spray)", "Check if many IPs target single account (distributed brute force)"],
                    expected_output="Classification of attack type"),
                PlaybookStep(step_number=3, phase=PlaybookPhase.ANALYSIS, title="Check for successful compromise",
                    actions=["Correlate with successful logins from same source", "Check post-auth activity for anomalies"],
                    decision_criteria="If successful login found after failures, escalate to incident"),
                PlaybookStep(step_number=4, phase=PlaybookPhase.RESPONSE, title="Containment actions",
                    actions=["Block offending IP addresses", "Force password reset for targeted accounts", "Enable MFA if not already active"]),
            ],
            tags=["brute_force", "credential_stuffing", "authentication"],
        )

        self._playbooks["lateral_movement"] = HuntPlaybook(
            name="Lateral Movement Tracing",
            description="Trace and map lateral movement activity within the network",
            category=ThreatCategory.LATERAL_MOVEMENT,
            severity=ThreatSeverity.CRITICAL,
            hypothesis="An attacker has established a foothold and is moving laterally through the network",
            mitre_techniques=["T1021.001", "T1021.002", "T1047", "T1550.002"],
            mitre_tactics=["lateral_movement"],
            required_data_sources=["windows_eventlog", "network_flows", "endpoint_detection"],
            estimated_duration_minutes=90,
            steps=[
                PlaybookStep(step_number=1, phase=PlaybookPhase.DATA_COLLECTION, title="Map authentication events",
                    actions=["Query logon events (4624 type 3,10)", "Query explicit credential use (4648)"],
                    data_sources=["windows_security"]),
                PlaybookStep(step_number=2, phase=PlaybookPhase.INVESTIGATION, title="Build movement graph",
                    actions=["Map source-to-destination connections", "Identify unusual paths and hop chains"],
                    expected_output="Network graph of lateral movement"),
                PlaybookStep(step_number=3, phase=PlaybookPhase.ANALYSIS, title="Identify techniques used",
                    actions=["Check for PsExec artifacts", "Check for WMI remote execution", "Check for pass-the-hash"],
                    decision_criteria="Determine attack sophistication and tools used"),
                PlaybookStep(step_number=4, phase=PlaybookPhase.RESPONSE, title="Contain and remediate",
                    actions=["Isolate compromised hosts", "Reset compromised credentials", "Block lateral movement paths"]),
            ],
            tags=["lateral_movement", "psexec", "wmi", "pass_the_hash"],
        )

        self._playbooks["data_exfiltration"] = HuntPlaybook(
            name="Data Exfiltration Detection",
            description="Detect and investigate potential data exfiltration activities",
            category=ThreatCategory.DATA_EXFILTRATION,
            severity=ThreatSeverity.CRITICAL,
            hypothesis="Sensitive data is being exfiltrated from the network via covert channels",
            mitre_techniques=["T1048", "T1567", "T1041"],
            mitre_tactics=["exfiltration"],
            required_data_sources=["proxy_logs", "dns_logs", "dlp_logs", "network_flows"],
            estimated_duration_minutes=120,
            steps=[
                PlaybookStep(step_number=1, phase=PlaybookPhase.DATA_COLLECTION, title="Baseline data transfers",
                    actions=["Establish normal data transfer volumes", "Identify top talkers by bytes out"]),
                PlaybookStep(step_number=2, phase=PlaybookPhase.INVESTIGATION, title="Detect anomalous transfers",
                    actions=["Find transfers exceeding baseline", "Check DNS for tunneling indicators", "Review cloud storage uploads"]),
                PlaybookStep(step_number=3, phase=PlaybookPhase.ANALYSIS, title="Classify data at risk",
                    actions=["Correlate with DLP alerts", "Identify sensitive file access preceding transfer"],
                    decision_criteria="Determine if sensitive data was actually exfiltrated"),
                PlaybookStep(step_number=4, phase=PlaybookPhase.RESPONSE, title="Stop the bleed",
                    actions=["Block exfiltration channels", "Revoke compromised credentials", "Notify data owners"]),
            ],
            tags=["exfiltration", "dns_tunneling", "cloud_storage"],
        )

        self._playbooks["c2_beacon"] = HuntPlaybook(
            name="C2 Beacon Hunting",
            description="Hunt for command and control beaconing activity",
            category=ThreatCategory.COMMAND_AND_CONTROL,
            severity=ThreatSeverity.CRITICAL,
            hypothesis="Malware is communicating with a command and control server using periodic beacons",
            mitre_techniques=["T1071.001", "T1573", "T1095"],
            mitre_tactics=["command_and_control"],
            required_data_sources=["proxy_logs", "firewall_logs", "dns_logs"],
            estimated_duration_minutes=90,
            steps=[
                PlaybookStep(step_number=1, phase=PlaybookPhase.DATA_COLLECTION, title="Collect connection metadata",
                    actions=["Extract outbound connection logs", "Focus on periodic connections"]),
                PlaybookStep(step_number=2, phase=PlaybookPhase.INVESTIGATION, title="Detect beaconing patterns",
                    actions=["Calculate connection intervals (jitter analysis)", "Look for consistent small data transfers"]),
                PlaybookStep(step_number=3, phase=PlaybookPhase.ANALYSIS, title="Validate C2 indicators",
                    actions=["Check destination reputation", "Analyze JA3 fingerprints", "Review certificate details"],
                    decision_criteria="Confirm malicious C2 activity vs legitimate periodic connections"),
                PlaybookStep(step_number=4, phase=PlaybookPhase.RESPONSE, title="Sinkhole and contain",
                    actions=["Block C2 domains/IPs at perimeter", "Isolate affected endpoints", "Collect forensic evidence"]),
            ],
            tags=["c2", "beaconing", "cobalt_strike", "malware"],
        )

        self._playbooks["insider_threat"] = HuntPlaybook(
            name="Insider Threat Investigation",
            description="Investigate potential insider threat activities and policy violations",
            category=ThreatCategory.INSIDER_THREAT,
            severity=ThreatSeverity.HIGH,
            hypothesis="An insider is abusing legitimate access to steal data or sabotage systems",
            mitre_techniques=["T1078", "T1567.002", "T1530"],
            mitre_tactics=["initial_access", "exfiltration", "collection"],
            required_data_sources=["authentication_logs", "file_access_logs", "email_logs", "proxy_logs"],
            estimated_duration_minutes=180,
            steps=[
                PlaybookStep(step_number=1, phase=PlaybookPhase.DATA_COLLECTION, title="Profile user activity",
                    actions=["Collect login times and locations", "Map file access patterns", "Review email sending behavior"]),
                PlaybookStep(step_number=2, phase=PlaybookPhase.INVESTIGATION, title="Identify anomalous behavior",
                    actions=["Compare against peer group baseline", "Check for off-hours access", "Review USB device usage"]),
                PlaybookStep(step_number=3, phase=PlaybookPhase.ANALYSIS, title="Assess risk and impact",
                    actions=["Determine data sensitivity accessed", "Check for policy violations"],
                    decision_criteria="Determine intent: negligence vs malicious"),
                PlaybookStep(step_number=4, phase=PlaybookPhase.RESPONSE, title="Coordinate response",
                    actions=["Engage HR and legal", "Preserve evidence", "Adjust access permissions"]),
            ],
            tags=["insider_threat", "data_theft", "policy_violation"],
        )

        self._playbooks["malware_outbreak"] = HuntPlaybook(
            name="Malware Outbreak Response",
            description="Respond to and contain a malware outbreak across the environment",
            category=ThreatCategory.MALWARE,
            severity=ThreatSeverity.CRITICAL,
            hypothesis="Malware has spread to multiple systems and requires immediate containment",
            mitre_techniques=["T1204", "T1059", "T1055"],
            mitre_tactics=["execution", "persistence"],
            required_data_sources=["endpoint_detection", "antivirus_logs", "network_flows"],
            estimated_duration_minutes=60,
            steps=[
                PlaybookStep(step_number=1, phase=PlaybookPhase.DATA_COLLECTION, title="Identify patient zero",
                    actions=["Find earliest detection", "Map infection timeline"]),
                PlaybookStep(step_number=2, phase=PlaybookPhase.INVESTIGATION, title="Scope the outbreak",
                    actions=["Search for IOCs across all endpoints", "Map communication to C2 infrastructure"]),
                PlaybookStep(step_number=3, phase=PlaybookPhase.RESPONSE, title="Contain and eradicate",
                    actions=["Isolate infected systems", "Push IOC blocklists", "Deploy cleanup scripts"]),
                PlaybookStep(step_number=4, phase=PlaybookPhase.DOCUMENTATION, title="Document and improve",
                    actions=["Write incident report", "Update detection rules", "Conduct lessons learned"]),
            ],
            tags=["malware", "outbreak", "incident_response"],
        )

        self._playbooks["phishing_campaign"] = HuntPlaybook(
            name="Phishing Campaign Analysis",
            description="Analyze and respond to a phishing campaign targeting the organization",
            category=ThreatCategory.RECONNAISSANCE,
            severity=ThreatSeverity.HIGH,
            hypothesis="A coordinated phishing campaign is targeting employees to steal credentials or deliver malware",
            mitre_techniques=["T1566.001", "T1566.002", "T1598"],
            mitre_tactics=["initial_access"],
            required_data_sources=["email_gateway", "proxy_logs", "authentication_logs"],
            estimated_duration_minutes=90,
            steps=[
                PlaybookStep(step_number=1, phase=PlaybookPhase.DATA_COLLECTION, title="Collect phishing indicators",
                    actions=["Extract sender addresses, domains, URLs from reported emails", "Search email gateway for similar messages"]),
                PlaybookStep(step_number=2, phase=PlaybookPhase.INVESTIGATION, title="Assess click-through rate",
                    actions=["Check proxy logs for URL visits", "Check auth logs for credential submissions"]),
                PlaybookStep(step_number=3, phase=PlaybookPhase.RESPONSE, title="Remediate and protect",
                    actions=["Block phishing domains and sender IPs", "Reset credentials for affected users", "Send awareness notification"]),
            ],
            tags=["phishing", "email", "social_engineering"],
        )

        self._playbooks["privilege_escalation"] = HuntPlaybook(
            name="Privilege Escalation Review",
            description="Hunt for privilege escalation attempts across Windows and Linux systems",
            category=ThreatCategory.PRIVILEGE_ESCALATION,
            severity=ThreatSeverity.HIGH,
            hypothesis="An attacker is escalating privileges to gain administrative access",
            mitre_techniques=["T1548", "T1134", "T1068"],
            mitre_tactics=["privilege_escalation"],
            required_data_sources=["windows_eventlog", "linux_auditd", "endpoint_detection"],
            estimated_duration_minutes=60,
            steps=[
                PlaybookStep(step_number=1, phase=PlaybookPhase.DATA_COLLECTION, title="Collect privilege events",
                    actions=["Query special privilege assignments (4672)", "Query sudo events on Linux"]),
                PlaybookStep(step_number=2, phase=PlaybookPhase.INVESTIGATION, title="Identify escalation attempts",
                    actions=["Check for UAC bypasses", "Check for token manipulation", "Review SUID binary usage"]),
                PlaybookStep(step_number=3, phase=PlaybookPhase.RESPONSE, title="Remediate",
                    actions=["Remove unnecessary privileges", "Patch exploited vulnerabilities", "Harden configurations"]),
            ],
            tags=["privilege_escalation", "uac_bypass", "sudo"],
        )

        self._playbooks["persistence_audit"] = HuntPlaybook(
            name="Persistence Mechanism Audit",
            description="Audit systems for unauthorized persistence mechanisms",
            category=ThreatCategory.PERSISTENCE,
            severity=ThreatSeverity.MEDIUM,
            hypothesis="An attacker has established persistence mechanisms to survive reboots and maintain access",
            mitre_techniques=["T1547.001", "T1053", "T1543.002", "T1546.003"],
            mitre_tactics=["persistence"],
            required_data_sources=["windows_eventlog", "linux_auditd", "file_integrity"],
            estimated_duration_minutes=120,
            steps=[
                PlaybookStep(step_number=1, phase=PlaybookPhase.DATA_COLLECTION, title="Enumerate persistence points",
                    actions=["Check registry Run keys", "List scheduled tasks and cron jobs", "Review systemd services", "Check startup folders"]),
                PlaybookStep(step_number=2, phase=PlaybookPhase.INVESTIGATION, title="Validate legitimacy",
                    actions=["Compare against known-good baseline", "Hash check binaries referenced", "Review creation timestamps"]),
                PlaybookStep(step_number=3, phase=PlaybookPhase.RESPONSE, title="Clean up",
                    actions=["Remove unauthorized persistence", "Monitor for re-creation", "Update detection rules"]),
            ],
            tags=["persistence", "registry", "scheduled_tasks", "cron"],
        )

        self._playbooks["ransomware_precursor"] = HuntPlaybook(
            name="Ransomware Precursor Detection",
            description="Hunt for early indicators of ransomware deployment before encryption begins",
            category=ThreatCategory.MALWARE,
            severity=ThreatSeverity.CRITICAL,
            hypothesis="An attacker is preparing to deploy ransomware and early indicators can be detected",
            mitre_techniques=["T1486", "T1490", "T1489"],
            mitre_tactics=["impact"],
            required_data_sources=["endpoint_detection", "windows_eventlog", "backup_logs"],
            estimated_duration_minutes=45,
            steps=[
                PlaybookStep(step_number=1, phase=PlaybookPhase.DATA_COLLECTION, title="Check for precursor activities",
                    actions=["Search for shadow copy deletion (vssadmin, wmic)", "Check for backup service disruption",
                             "Look for encryption utility downloads"]),
                PlaybookStep(step_number=2, phase=PlaybookPhase.INVESTIGATION, title="Identify staging behavior",
                    actions=["Check for mass file enumeration", "Look for network share mapping", "Review PowerShell script execution"]),
                PlaybookStep(step_number=3, phase=PlaybookPhase.RESPONSE, title="Prevent encryption",
                    actions=["Isolate at-risk systems immediately", "Verify backup integrity", "Deploy anti-ransomware controls"]),
            ],
            tags=["ransomware", "encryption", "shadow_copy", "backup"],
        )

        self._playbooks["supply_chain"] = HuntPlaybook(
            name="Supply Chain Compromise Check",
            description="Investigate potential supply chain compromises in software and dependencies",
            category=ThreatCategory.MALWARE,
            severity=ThreatSeverity.HIGH,
            hypothesis="A trusted software component or update has been compromised to deliver malware",
            mitre_techniques=["T1195.001", "T1195.002"],
            mitre_tactics=["initial_access"],
            required_data_sources=["endpoint_detection", "software_inventory", "network_flows"],
            estimated_duration_minutes=120,
            steps=[
                PlaybookStep(step_number=1, phase=PlaybookPhase.DATA_COLLECTION, title="Inventory affected software",
                    actions=["Identify systems running potentially compromised software", "Check software hash against known-good values"]),
                PlaybookStep(step_number=2, phase=PlaybookPhase.INVESTIGATION, title="Analyze post-update behavior",
                    actions=["Check for unusual network connections post-update", "Review process execution from update paths",
                             "Compare behavior across installations"]),
                PlaybookStep(step_number=3, phase=PlaybookPhase.RESPONSE, title="Contain and recover",
                    actions=["Rollback to known-good versions", "Block communication to suspicious infrastructure",
                             "Engage vendor for confirmation"]),
            ],
            tags=["supply_chain", "software_update", "dependency"],
        )


# ════════════════════════════════════════════════════════════════════════════════
# SIREN THREAT HUNTER — MAIN ORCHESTRATOR
# ════════════════════════════════════════════════════════════════════════════════


class SirenThreatHunter:
    """
    Main orchestrator for SIREN threat hunting operations.

    Coordinates all threat hunting components:
        - IOC extraction and analysis
        - SIGMA rule generation
        - YARA rule generation
        - Hunt query generation for multiple SIEMs
        - Playbook execution
        - STIX 2.1 bundle export
        - Detection coverage reporting

    Usage:
        hunter = SirenThreatHunter()
        iocs = hunter.extract_iocs("Suspicious traffic from 10.0.0.5 to evil.com")
        sigma_rules = hunter.generate_sigma_rules()
        yara_rules = hunter.generate_yara_rules()
        queries = hunter.generate_hunt_queries("lateral_movement")
        report = hunter.generate_report()
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._ioc_extractor = IOCExtractor()
        self._sigma_generator = SIGMARuleGenerator()
        self._yara_generator = YARARuleGenerator()
        self._query_generator = ThreatHuntQuery()
        self._stix_exporter = STIXExporter()
        self._playbook_library = PlaybookLibrary()

        self._ioc_bundles: List[IOCBundle] = []
        self._sigma_rules: List[DetectionRule] = []
        self._yara_rules: List[DetectionRule] = []
        self._hunt_results: List[HuntResult] = []
        self._all_queries: Dict[str, List[str]] = defaultdict(list)

        logger.info("SirenThreatHunter initialized")

    def extract_iocs(
        self,
        text: str,
        source: str = "manual_input",
        tags: Optional[List[str]] = None,
    ) -> IOCBundle:
        """Extract IOCs from raw text data."""
        with self._lock:
            bundle = self._ioc_extractor.extract_all(text, source, tags)
            self._ioc_bundles.append(bundle)
            logger.info("Extracted %d IOCs from %s", bundle.total_extracted, source)
            return bundle

    def generate_sigma_rules(
        self,
        category: Optional[ThreatCategory] = None,
        ioc_bundle: Optional[IOCBundle] = None,
    ) -> List[DetectionRule]:
        """Generate SIGMA detection rules."""
        with self._lock:
            rules: List[DetectionRule] = []
            if category:
                rules = self._sigma_generator.generate_by_category(category)
            else:
                rules = self._sigma_generator.generate_all()
            if ioc_bundle:
                ioc_rules = self._sigma_generator.generate_for_iocs(ioc_bundle)
                rules.extend(ioc_rules)
            self._sigma_rules.extend(rules)
            logger.info("Generated %d SIGMA rules", len(rules))
            return rules

    def generate_yara_rules(self) -> List[DetectionRule]:
        """Generate YARA detection rules."""
        with self._lock:
            rules = self._yara_generator.generate_all()
            self._yara_rules.extend(rules)
            logger.info("Generated %d YARA rules", len(rules))
            return rules

    def generate_hunt_queries(
        self,
        hunt_type: str,
        ioc_bundle: Optional[IOCBundle] = None,
    ) -> Dict[str, Any]:
        """Generate threat hunting queries for all SIEM platforms."""
        with self._lock:
            result: Dict[str, Any] = {}
            # Type-based queries
            type_queries = self._query_generator.generate_queries(hunt_type)
            result["type_queries"] = type_queries
            for platform, query in type_queries.items():
                self._all_queries[platform].append(query)
            # IOC-based queries
            if ioc_bundle:
                ioc_queries = self._query_generator.generate_ioc_queries(ioc_bundle)
                result["ioc_queries"] = ioc_queries
                for platform, queries in ioc_queries.items():
                    self._all_queries[platform].extend(queries)
            logger.info("Generated hunt queries for type: %s", hunt_type)
            return result

    def create_playbook(self, playbook_name: str) -> Optional[HuntPlaybook]:
        """Retrieve a pre-built hunt playbook."""
        with self._lock:
            playbook = self._playbook_library.get_playbook(playbook_name)
            if playbook:
                logger.info("Retrieved playbook: %s", playbook_name)
            else:
                logger.warning("Playbook not found: %s", playbook_name)
            return playbook

    def list_playbooks(self) -> List[Dict[str, Any]]:
        """List all available hunt playbooks."""
        with self._lock:
            return self._playbook_library.list_playbooks()

    def generate_detection_coverage_report(self) -> Dict[str, Any]:
        """Generate a MITRE ATT&CK detection coverage report."""
        with self._lock:
            all_rules = self._sigma_rules + self._yara_rules
            technique_coverage: Dict[str, List[str]] = defaultdict(list)
            tactic_coverage: Dict[str, List[str]] = defaultdict(list)

            for rule in all_rules:
                for tech in rule.mitre_techniques:
                    technique_coverage[tech].append(rule.name)
                for tac in rule.mitre_tactics:
                    tactic_coverage[tac].append(rule.name)

            # Calculate coverage percentage against known MITRE techniques
            known_techniques = {
                "T1190", "T1189", "T1059", "T1203", "T1505.003", "T1110.001",
                "T1110.003", "T1110.004", "T1556.006", "T1078", "T1048",
                "T1048.003", "T1132.001", "T1567.002", "T1573", "T1550.002",
                "T1569.002", "T1047", "T1021.001", "T1021.002", "T1548.001",
                "T1548.002", "T1548.003", "T1134", "T1053.003", "T1053.005",
                "T1547.001", "T1543.002", "T1546.003", "T1071.001", "T1071.004",
                "T1090", "T1083", "T1003.001", "T1555", "T1598.003",
                "T1056.001", "T1496", "T1219", "T1027", "T1027.002",
                "T1204", "T1055", "T1566.001", "T1566.002", "T1598",
                "T1068", "T1486", "T1490", "T1489", "T1195.001", "T1195.002",
                "T1530", "T1041", "T1095", "T1059.006",
            }
            covered = set(technique_coverage.keys())
            coverage_pct = (len(covered & known_techniques) / max(len(known_techniques), 1)) * 100

            # Category breakdown
            category_counts: Dict[str, int] = defaultdict(int)
            for rule in all_rules:
                category_counts[rule.category.name] += 1

            report = {
                "total_detection_rules": len(all_rules),
                "sigma_rules": len(self._sigma_rules),
                "yara_rules": len(self._yara_rules),
                "techniques_covered": len(covered),
                "techniques_total_known": len(known_techniques),
                "coverage_percentage": round(coverage_pct, 2),
                "technique_coverage": {k: v for k, v in sorted(technique_coverage.items())},
                "tactic_coverage": {k: v for k, v in sorted(tactic_coverage.items())},
                "rules_by_category": dict(category_counts),
                "uncovered_techniques": sorted(known_techniques - covered),
                "generated_at": time.time(),
            }

            logger.info("Detection coverage report: %.1f%% (%d/%d techniques)",
                        coverage_pct, len(covered & known_techniques), len(known_techniques))
            return report

    def export_stix_bundle(
        self,
        ioc_bundle: Optional[IOCBundle] = None,
        include_rules: bool = True,
    ) -> Dict[str, Any]:
        """Export all threat intelligence as a STIX 2.1 bundle."""
        with self._lock:
            target_bundle = ioc_bundle
            if not target_bundle and self._ioc_bundles:
                # Merge all bundles
                all_iocs: List[IOCEntry] = []
                for b in self._ioc_bundles:
                    all_iocs.extend(b.iocs)
                target_bundle = IOCBundle(
                    name="Merged IOC Bundle",
                    description="Combined IOCs from all extractions",
                    iocs=all_iocs,
                    total_extracted=len(all_iocs),
                )

            rules = None
            if include_rules:
                rules = self._sigma_rules + self._yara_rules

            bundle = self._stix_exporter.create_bundle(target_bundle, rules)
            logger.info("STIX 2.1 bundle exported with %d objects",
                        len(bundle.get("objects", [])))
            return bundle

    def generate_report(self, title: str = "SIREN Threat Hunt Report") -> ThreatHuntReport:
        """Generate a comprehensive threat hunt report."""
        with self._lock:
            all_iocs: List[IOCEntry] = []
            for bundle in self._ioc_bundles:
                all_iocs.extend(bundle.iocs)

            all_rules = self._sigma_rules + self._yara_rules
            total_queries = sum(len(q) for q in self._all_queries.values())

            # Count severities
            critical = sum(1 for i in all_iocs if i.severity == ThreatSeverity.CRITICAL)
            high = sum(1 for i in all_iocs if i.severity == ThreatSeverity.HIGH)
            medium = sum(1 for i in all_iocs if i.severity == ThreatSeverity.MEDIUM)
            low = sum(1 for i in all_iocs if i.severity == ThreatSeverity.LOW)

            # Coverage
            covered_techs: Set[str] = set()
            for rule in all_rules:
                covered_techs.update(rule.mitre_techniques)

            # Recommendations
            recommendations: List[str] = []
            if critical > 0:
                recommendations.append(
                    f"URGENT: {critical} critical IOCs detected - immediate investigation required"
                )
            if high > 5:
                recommendations.append(
                    f"High priority: {high} high-severity IOCs require triage within 24 hours"
                )
            if len(self._sigma_rules) == 0:
                recommendations.append(
                    "Generate SIGMA rules to improve SIEM detection coverage"
                )
            if len(self._yara_rules) == 0:
                recommendations.append(
                    "Generate YARA rules to improve file-based detection"
                )
            if total_queries == 0:
                recommendations.append(
                    "Generate hunt queries to proactively search for threats"
                )
            recommendations.append(
                "Review detection coverage report to identify gaps in MITRE ATT&CK coverage"
            )
            recommendations.append(
                "Schedule recurring threat hunts based on available playbooks"
            )

            # Build merged IOC bundle for report
            merged_bundle = IOCBundle(
                name="Report IOC Bundle",
                iocs=all_iocs,
                total_extracted=len(all_iocs),
            ) if all_iocs else None

            # Executive summary
            summary_parts: List[str] = [
                f"SIREN Threat Hunt completed at {time.strftime('%Y-%m-%d %H:%M:%S')}.",
                f"Total IOCs extracted: {len(all_iocs)}.",
                f"Detection rules generated: {len(all_rules)} ({len(self._sigma_rules)} SIGMA, {len(self._yara_rules)} YARA).",
                f"Hunt queries generated: {total_queries}.",
                f"MITRE ATT&CK techniques covered: {len(covered_techs)}.",
            ]
            if critical > 0:
                summary_parts.append(f"CRITICAL: {critical} critical severity findings require immediate action.")

            report = ThreatHuntReport(
                title=title,
                executive_summary=" ".join(summary_parts),
                hunt_results=self._hunt_results,
                ioc_bundle=merged_bundle,
                detection_rules=all_rules,
                total_iocs=len(all_iocs),
                total_rules=len(all_rules),
                total_queries=total_queries,
                mitre_coverage_pct=round(
                    (len(covered_techs) / max(55, 1)) * 100, 2
                ),
                critical_findings=critical,
                high_findings=high,
                medium_findings=medium,
                low_findings=low,
                recommendations=recommendations,
            )

            logger.info("Threat hunt report generated: %s (%d IOCs, %d rules)",
                        title, len(all_iocs), len(all_rules))
            return report

    def run_full_hunt(
        self,
        text: str,
        source: str = "full_hunt",
        hunt_types: Optional[List[str]] = None,
    ) -> ThreatHuntReport:
        """Run a complete threat hunt pipeline: extract, generate rules, queries, and report."""
        with self._lock:
            logger.info("Starting full threat hunt from source: %s", source)
            start = time.time()

            # Step 1: Extract IOCs
            ioc_bundle = self.extract_iocs(text, source)

            # Step 2: Generate all rules
            sigma_rules = self.generate_sigma_rules(ioc_bundle=ioc_bundle)
            yara_rules = self.generate_yara_rules()

            # Step 3: Generate queries
            types = hunt_types or [
                "brute_force", "lateral_movement", "data_exfiltration",
                "c2_beacon", "web_attack", "dns_anomaly",
            ]
            for ht in types:
                # Map playbook names to query types
                query_type = ht.replace("c2_beacon", "command_and_control")
                self.generate_hunt_queries(query_type, ioc_bundle)

            # Step 4: Generate report
            report = self.generate_report(
                title=f"SIREN Full Threat Hunt - {source}"
            )

            elapsed = time.time() - start
            logger.info("Full threat hunt completed in %.2f seconds", elapsed)
            return report

    def get_stats(self) -> Dict[str, Any]:
        """Get overall threat hunter statistics."""
        with self._lock:
            return {
                "ioc_bundles": len(self._ioc_bundles),
                "total_iocs": sum(b.total_extracted for b in self._ioc_bundles),
                "sigma_rules": len(self._sigma_rules),
                "yara_rules": len(self._yara_rules),
                "total_queries": sum(len(q) for q in self._all_queries.values()),
                "hunt_results": len(self._hunt_results),
                "available_playbooks": len(self._playbook_library.list_playbooks()),
                "extractor_stats": self._ioc_extractor.get_stats(),
                "sigma_stats": self._sigma_generator.get_stats(),
                "yara_stats": self._yara_generator.get_stats(),
            }

    def reset(self) -> None:
        """Reset all accumulated state."""
        with self._lock:
            self._ioc_bundles.clear()
            self._sigma_rules.clear()
            self._yara_rules.clear()
            self._hunt_results.clear()
            self._all_queries.clear()
            self._ioc_extractor.clear_cache()
            logger.info("SirenThreatHunter state reset")