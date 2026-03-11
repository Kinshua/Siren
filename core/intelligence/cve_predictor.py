#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  🎯  SIREN CVE PREDICTOR — Vulnerability Prediction & Prioritization  🎯     ██
██                                                                                ██
██  Predição de CVEs e priorização baseada em contexto real do alvo.             ██
██                                                                                ██
██  Abordagem:                                                                   ██
██    1. Inventário de tecnologias → mapeamento para CVEs conhecidos             ██
██    2. Análise de padrões históricos → predição de vulns prováveis            ██
██    3. Exploitability scoring → probabilidade de exploração real               ██
██    4. Context-aware ranking → ordena por relevância ao alvo                   ██
██    5. Temporal decay → CVEs mais recentes têm mais peso                       ██
██    6. Dependency chain → vulns transitivas via supply chain                   ██
██                                                                                ██
██  "SIREN prevê onde o próximo CVE vai aparecer."                              ██
██                                                                                ██
████████████████████████████████████████████████████████████████████████████████████
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import re
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("siren.intelligence.cve_predictor")


# ════════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════════════════════════════

EPSS_DECAY_HALF_LIFE_DAYS = 180
MAX_CVE_CACHE = 100_000
EXPLOIT_MATURITY_WEIGHT = 0.35
TEMPORAL_DECAY_WEIGHT = 0.20
ATTACK_SURFACE_WEIGHT = 0.25
BUSINESS_IMPACT_WEIGHT = 0.20
TEMPORAL_DECAY_RATE = 0.5  # Half-life of ~2 years for CVE exploit likelihood


# ════════════════════════════════════════════════════════════════════════════════
# ENUMS
# ════════════════════════════════════════════════════════════════════════════════

class CVSSVersion(Enum):
    V2 = auto()
    V3 = auto()
    V31 = auto()
    V4 = auto()


class ExploitMaturity(Enum):
    """Exploit maturity levels (CVSS temporal metric aligned)."""
    NOT_DEFINED = auto()
    UNPROVEN = auto()
    PROOF_OF_CONCEPT = auto()
    FUNCTIONAL = auto()
    HIGH = auto()          # Weaponized / in-the-wild


class AttackVector(Enum):
    NETWORK = auto()
    ADJACENT = auto()
    LOCAL = auto()
    PHYSICAL = auto()


class AttackComplexity(Enum):
    LOW = auto()
    HIGH = auto()


class PrivilegesRequired(Enum):
    NONE = auto()
    LOW = auto()
    HIGH = auto()


class UserInteraction(Enum):
    NONE = auto()
    REQUIRED = auto()


class CWECategory(Enum):
    """Top CWE categories for classification."""
    INJECTION = auto()           # CWE-79, CWE-89, CWE-78
    BROKEN_AUTH = auto()         # CWE-287, CWE-384
    SENSITIVE_DATA = auto()      # CWE-200, CWE-312
    XXE = auto()                 # CWE-611
    BROKEN_ACCESS = auto()       # CWE-862, CWE-863
    MISCONFIG = auto()           # CWE-16
    XSS = auto()                 # CWE-79
    DESERIALIZATION = auto()     # CWE-502
    VULN_COMPONENTS = auto()     # CWE-1035
    LOGGING_FAILURE = auto()     # CWE-778
    SSRF = auto()                # CWE-918
    MEMORY_CORRUPTION = auto()   # CWE-119, CWE-120, CWE-787
    PATH_TRAVERSAL = auto()      # CWE-22
    RACE_CONDITION = auto()      # CWE-362
    CRYPTO_FAILURE = auto()      # CWE-327, CWE-330
    OTHER = auto()


class PredictionBasis(Enum):
    """Why a CVE was predicted/included."""
    EXACT_VERSION_MATCH = auto()
    VERSION_RANGE_MATCH = auto()
    TECHNOLOGY_FAMILY = auto()
    HISTORICAL_PATTERN = auto()   # Similar tech had similar CVEs
    DEPENDENCY_CHAIN = auto()     # Transitive vuln
    CONFIGURATION_BASED = auto()  # Misconfiguration-derived
    BEHAVIORAL_SIGNAL = auto()    # Behavior suggests vulnerability


# ════════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class CVERecord:
    """A CVE entry with full metadata."""
    cve_id: str
    description: str = ""
    cvss_score: float = 0.0
    cvss_version: CVSSVersion = CVSSVersion.V31
    attack_vector: AttackVector = AttackVector.NETWORK
    attack_complexity: AttackComplexity = AttackComplexity.LOW
    privileges_required: PrivilegesRequired = PrivilegesRequired.NONE
    user_interaction: UserInteraction = UserInteraction.NONE
    cwe_id: str = ""
    cwe_category: CWECategory = CWECategory.OTHER
    affected_products: List[str] = field(default_factory=list)
    affected_versions: Dict[str, str] = field(default_factory=dict)  # product → version range
    exploit_maturity: ExploitMaturity = ExploitMaturity.NOT_DEFINED
    published_date: str = ""
    last_modified: str = ""
    references: List[str] = field(default_factory=list)
    epss_score: float = 0.0   # EPSS (Exploit Prediction Scoring System) [0,1]
    is_kev: bool = False       # In CISA KEV (Known Exploited Vulnerabilities) catalog
    tags: Set[str] = field(default_factory=set)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "description": self.description[:200],
            "cvss_score": self.cvss_score,
            "cvss_version": self.cvss_version.name,
            "attack_vector": self.attack_vector.name,
            "attack_complexity": self.attack_complexity.name,
            "privileges_required": self.privileges_required.name,
            "user_interaction": self.user_interaction.name,
            "cwe_id": self.cwe_id,
            "cwe_category": self.cwe_category.name,
            "exploit_maturity": self.exploit_maturity.name,
            "published_date": self.published_date,
            "epss_score": self.epss_score,
            "is_kev": self.is_kev,
            "tags": list(self.tags),
        }


@dataclass
class PredictedVuln:
    """A predicted/confirmed vulnerability for a target."""
    cve: CVERecord
    prediction_basis: PredictionBasis
    target_tech: str             # The technology this applies to
    target_version: str = ""
    siren_score: float = 0.0     # SIREN's composite risk score [0, 1]
    exploitability: float = 0.0  # How likely exploitation is [0, 1]
    temporal_relevance: float = 0.0  # Decay-adjusted relevance [0, 1]
    context_notes: List[str] = field(default_factory=list)
    remediation_hint: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve.cve_id,
            "cvss_score": self.cve.cvss_score,
            "siren_score": round(self.siren_score, 4),
            "exploitability": round(self.exploitability, 4),
            "temporal_relevance": round(self.temporal_relevance, 4),
            "prediction_basis": self.prediction_basis.name,
            "target_tech": self.target_tech,
            "target_version": self.target_version,
            "cwe_category": self.cve.cwe_category.name,
            "exploit_maturity": self.cve.exploit_maturity.name,
            "publication_date": self.cve.published_date,
            "is_kev": self.cve.is_kev,
            "context_notes": self.context_notes,
            "remediation_hint": self.remediation_hint,
        }


@dataclass
class TechProfile:
    """Technology profile for CVE matching."""
    name: str
    version: str = ""
    vendor: str = ""
    category: str = ""
    dependencies: List[str] = field(default_factory=list)
    config_flags: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PredictionReport:
    """Complete CVE prediction report for a target."""
    target: str
    timestamp: float = field(default_factory=time.time)
    tech_profiles: List[TechProfile] = field(default_factory=list)
    predictions: List[PredictedVuln] = field(default_factory=list)
    total_cves: int = 0
    critical_count: int = 0
    high_count: int = 0
    kev_count: int = 0
    average_siren_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "timestamp": self.timestamp,
            "tech_count": len(self.tech_profiles),
            "total_cves": self.total_cves,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "kev_count": self.kev_count,
            "average_siren_score": round(self.average_siren_score, 4),
            "predictions": [p.to_dict() for p in self.predictions],
        }

    def get_critical(self) -> List[PredictedVuln]:
        return [p for p in self.predictions if p.cve.cvss_score >= 9.0]

    def get_kev(self) -> List[PredictedVuln]:
        return [p for p in self.predictions if p.cve.is_kev]

    def get_exploitable(self, threshold: float = 0.7) -> List[PredictedVuln]:
        return [p for p in self.predictions if p.exploitability >= threshold]


# ════════════════════════════════════════════════════════════════════════════════
# CVE DATABASE — Built-in known vulnerabilities
# ════════════════════════════════════════════════════════════════════════════════

class CVEDatabase:
    """
    Local CVE database for offline operation.
    Contains high-impact CVEs across common technologies.
    Thread-safe, extensible.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._cves: Dict[str, CVERecord] = {}
        self._product_index: Dict[str, List[str]] = defaultdict(list)  # product → [cve_ids]
        self._cwe_index: Dict[str, List[str]] = defaultdict(list)      # cwe → [cve_ids]
        self._load_builtin()

    def _load_builtin(self) -> None:
        """Load high-impact built-in CVEs."""
        entries = [
            # ── Critical Web Server CVEs ───────────────────────────
            CVERecord("CVE-2021-44228", "Apache Log4j RCE (Log4Shell)", 10.0, CVSSVersion.V31,
                      AttackVector.NETWORK, AttackComplexity.LOW, PrivilegesRequired.NONE, UserInteraction.NONE,
                      "CWE-917", CWECategory.INJECTION, ["log4j", "java"],
                      {"log4j": "< 2.17.0"}, ExploitMaturity.HIGH, "2021-12-10", epss_score=0.975, is_kev=True),
            CVERecord("CVE-2022-22965", "Spring4Shell RCE", 9.8, CVSSVersion.V31,
                      AttackVector.NETWORK, AttackComplexity.LOW, PrivilegesRequired.NONE, UserInteraction.NONE,
                      "CWE-94", CWECategory.INJECTION, ["spring-framework", "spring-boot"],
                      {"spring-framework": "< 5.3.18"}, ExploitMaturity.HIGH, "2022-03-31", epss_score=0.974, is_kev=True),
            CVERecord("CVE-2023-44487", "HTTP/2 Rapid Reset DoS", 7.5, CVSSVersion.V31,
                      AttackVector.NETWORK, AttackComplexity.LOW, PrivilegesRequired.NONE, UserInteraction.NONE,
                      "CWE-400", CWECategory.OTHER, ["nginx", "apache", "envoy"],
                      {"nginx": "< 1.25.3"}, ExploitMaturity.HIGH, "2023-10-10", epss_score=0.82, is_kev=True),
            CVERecord("CVE-2024-3094", "XZ Utils Backdoor", 10.0, CVSSVersion.V31,
                      AttackVector.NETWORK, AttackComplexity.LOW, PrivilegesRequired.NONE, UserInteraction.NONE,
                      "CWE-506", CWECategory.OTHER, ["xz-utils", "liblzma"],
                      {"xz-utils": ">= 5.6.0"}, ExploitMaturity.HIGH, "2024-03-29", epss_score=0.95, is_kev=True),
            # ── PHP ────────────────────────────────────────────────
            CVERecord("CVE-2019-11043", "PHP-FPM RCE (Nginx config)", 9.8, CVSSVersion.V31,
                      AttackVector.NETWORK, AttackComplexity.LOW, PrivilegesRequired.NONE, UserInteraction.NONE,
                      "CWE-787", CWECategory.MEMORY_CORRUPTION, ["php"],
                      {"php": "< 7.4.0"}, ExploitMaturity.HIGH, "2019-10-28", epss_score=0.97, is_kev=True),
            CVERecord("CVE-2024-2756", "PHP Cookie Bypass", 6.5, CVSSVersion.V31,
                      AttackVector.NETWORK, AttackComplexity.LOW, PrivilegesRequired.NONE, UserInteraction.NONE,
                      "CWE-284", CWECategory.BROKEN_ACCESS, ["php"],
                      {"php": "< 8.3.4"}, ExploitMaturity.PROOF_OF_CONCEPT, "2024-04-12", epss_score=0.45),
            # ── WordPress ──────────────────────────────────────────
            CVERecord("CVE-2024-1071", "WordPress Ultimate Member SQLi", 9.8, CVSSVersion.V31,
                      AttackVector.NETWORK, AttackComplexity.LOW, PrivilegesRequired.NONE, UserInteraction.NONE,
                      "CWE-89", CWECategory.INJECTION, ["wordpress"],
                      {"wordpress": "< 6.4.3"}, ExploitMaturity.FUNCTIONAL, "2024-01-30", epss_score=0.68),
            # ── Apache ─────────────────────────────────────────────
            CVERecord("CVE-2021-41773", "Apache Path Traversal & RCE", 9.8, CVSSVersion.V31,
                      AttackVector.NETWORK, AttackComplexity.LOW, PrivilegesRequired.NONE, UserInteraction.NONE,
                      "CWE-22", CWECategory.PATH_TRAVERSAL, ["apache"],
                      {"apache": ">= 2.4.49"}, ExploitMaturity.HIGH, "2021-10-05", epss_score=0.97, is_kev=True),
            CVERecord("CVE-2023-25690", "Apache mod_proxy HTTP Request Smuggling", 9.8, CVSSVersion.V31,
                      AttackVector.NETWORK, AttackComplexity.LOW, PrivilegesRequired.NONE, UserInteraction.NONE,
                      "CWE-444", CWECategory.INJECTION, ["apache"],
                      {"apache": "< 2.4.56"}, ExploitMaturity.PROOF_OF_CONCEPT, "2023-03-07", epss_score=0.55),
            # ── ASP.NET / IIS ──────────────────────────────────────
            CVERecord("CVE-2021-31166", "HTTP Protocol Stack RCE (IIS)", 9.8, CVSSVersion.V31,
                      AttackVector.NETWORK, AttackComplexity.LOW, PrivilegesRequired.NONE, UserInteraction.NONE,
                      "CWE-787", CWECategory.MEMORY_CORRUPTION, ["iis"],
                      {"iis": "< 10.0.20348"}, ExploitMaturity.FUNCTIONAL, "2021-05-11", epss_score=0.90, is_kev=True),
            # ── Node.js / Express ──────────────────────────────────
            CVERecord("CVE-2022-21824", "Node.js Prototype Pollution", 8.2, CVSSVersion.V31,
                      AttackVector.NETWORK, AttackComplexity.LOW, PrivilegesRequired.NONE, UserInteraction.NONE,
                      "CWE-1321", CWECategory.INJECTION, ["node.js"],
                      {"node.js": "< 16.13.2"}, ExploitMaturity.PROOF_OF_CONCEPT, "2022-01-10", epss_score=0.42),
            # ── Django ─────────────────────────────────────────────
            CVERecord("CVE-2023-36053", "Django ReDoS in EmailValidator", 7.5, CVSSVersion.V31,
                      AttackVector.NETWORK, AttackComplexity.LOW, PrivilegesRequired.NONE, UserInteraction.NONE,
                      "CWE-1333", CWECategory.OTHER, ["django"],
                      {"django": "< 4.2.3"}, ExploitMaturity.PROOF_OF_CONCEPT, "2023-07-03", epss_score=0.35),
            # ── Drupal ─────────────────────────────────────────────
            CVERecord("CVE-2018-7600", "Drupalgeddon2 RCE", 9.8, CVSSVersion.V31,
                      AttackVector.NETWORK, AttackComplexity.LOW, PrivilegesRequired.NONE, UserInteraction.NONE,
                      "CWE-20", CWECategory.INJECTION, ["drupal"],
                      {"drupal": "< 7.58"}, ExploitMaturity.HIGH, "2018-03-28", epss_score=0.97, is_kev=True),
            # ── Kubernetes / Container ─────────────────────────────
            CVERecord("CVE-2022-0185", "Linux Kernel Container Escape", 8.4, CVSSVersion.V31,
                      AttackVector.LOCAL, AttackComplexity.LOW, PrivilegesRequired.NONE, UserInteraction.NONE,
                      "CWE-190", CWECategory.MEMORY_CORRUPTION, ["linux-kernel", "kubernetes"],
                      {"linux-kernel": "< 5.16.2"}, ExploitMaturity.FUNCTIONAL, "2022-01-18", epss_score=0.65, is_kev=True),
            CVERecord("CVE-2021-25741", "Kubernetes Symlink Exchange", 8.8, CVSSVersion.V31,
                      AttackVector.NETWORK, AttackComplexity.LOW, PrivilegesRequired.LOW, UserInteraction.NONE,
                      "CWE-59", CWECategory.PATH_TRAVERSAL, ["kubernetes"],
                      {"kubernetes": "< 1.22.2"}, ExploitMaturity.PROOF_OF_CONCEPT, "2021-09-20", epss_score=0.45),
            # ── Java/Tomcat ────────────────────────────────────────
            CVERecord("CVE-2023-46589", "Apache Tomcat HTTP Request Smuggling", 7.5, CVSSVersion.V31,
                      AttackVector.NETWORK, AttackComplexity.LOW, PrivilegesRequired.NONE, UserInteraction.NONE,
                      "CWE-444", CWECategory.INJECTION, ["tomcat"],
                      {"tomcat": "< 10.1.16"}, ExploitMaturity.PROOF_OF_CONCEPT, "2023-11-28", epss_score=0.40),
            # ── Cloudflare WAF bypass patterns ─────────────────────
            CVERecord("CVE-2023-22515", "Atlassian Confluence Broken Access Control", 10.0, CVSSVersion.V31,
                      AttackVector.NETWORK, AttackComplexity.LOW, PrivilegesRequired.NONE, UserInteraction.NONE,
                      "CWE-862", CWECategory.BROKEN_ACCESS, ["confluence"],
                      {"confluence": "< 8.5.2"}, ExploitMaturity.HIGH, "2023-10-04", epss_score=0.96, is_kev=True),
            # ── MongoDB ────────────────────────────────────────────
            CVERecord("CVE-2021-20736", "MongoDB Wire Protocol Injection", 7.5, CVSSVersion.V31,
                      AttackVector.NETWORK, AttackComplexity.LOW, PrivilegesRequired.NONE, UserInteraction.NONE,
                      "CWE-943", CWECategory.INJECTION, ["mongodb"],
                      {"mongodb": "< 5.0.3"}, ExploitMaturity.PROOF_OF_CONCEPT, "2021-09-01", epss_score=0.30),
        ]
        for cve in entries:
            self._cves[cve.cve_id] = cve
            for product in cve.affected_products:
                self._product_index[product.lower()].append(cve.cve_id)
            if cve.cwe_id:
                self._cwe_index[cve.cwe_id].append(cve.cve_id)

    def add(self, cve: CVERecord) -> None:
        with self._lock:
            self._cves[cve.cve_id] = cve
            for product in cve.affected_products:
                self._product_index[product.lower()].append(cve.cve_id)
            if cve.cwe_id:
                self._cwe_index[cve.cwe_id].append(cve.cve_id)

    def get(self, cve_id: str) -> Optional[CVERecord]:
        with self._lock:
            return self._cves.get(cve_id)

    def search_by_product(self, product: str) -> List[CVERecord]:
        with self._lock:
            cve_ids = self._product_index.get(product.lower(), [])
            return [self._cves[cid] for cid in cve_ids if cid in self._cves]

    def search_by_cwe(self, cwe_id: str) -> List[CVERecord]:
        with self._lock:
            cve_ids = self._cwe_index.get(cwe_id, [])
            return [self._cves[cid] for cid in cve_ids if cid in self._cves]

    def get_kev_list(self) -> List[CVERecord]:
        with self._lock:
            return [c for c in self._cves.values() if c.is_kev]

    def count(self) -> int:
        with self._lock:
            return len(self._cves)


# ════════════════════════════════════════════════════════════════════════════════
# EXPLOITABILITY CALCULATOR
# ════════════════════════════════════════════════════════════════════════════════

class ExploitabilityCalculator:
    """
    Calculates real-world exploitability score.
    Goes beyond CVSS by incorporating EPSS, KEV status, maturity, and context.
    """

    # CVSS base metric weights for exploitability subscore
    AV_WEIGHTS = {AttackVector.NETWORK: 0.85, AttackVector.ADJACENT: 0.62, AttackVector.LOCAL: 0.55, AttackVector.PHYSICAL: 0.20}
    AC_WEIGHTS = {AttackComplexity.LOW: 0.77, AttackComplexity.HIGH: 0.44}
    PR_WEIGHTS = {PrivilegesRequired.NONE: 0.85, PrivilegesRequired.LOW: 0.62, PrivilegesRequired.HIGH: 0.27}
    UI_WEIGHTS = {UserInteraction.NONE: 0.85, UserInteraction.REQUIRED: 0.62}
    MATURITY_WEIGHTS = {
        ExploitMaturity.NOT_DEFINED: 0.50,
        ExploitMaturity.UNPROVEN: 0.30,
        ExploitMaturity.PROOF_OF_CONCEPT: 0.60,
        ExploitMaturity.FUNCTIONAL: 0.85,
        ExploitMaturity.HIGH: 1.00,
    }

    def calculate(self, cve: CVERecord) -> float:
        """Calculate exploitability score [0, 1]."""
        # CVSS exploitability subscore (normalized 0-1)
        av = self.AV_WEIGHTS.get(cve.attack_vector, 0.5)
        ac = self.AC_WEIGHTS.get(cve.attack_complexity, 0.5)
        pr = self.PR_WEIGHTS.get(cve.privileges_required, 0.5)
        ui = self.UI_WEIGHTS.get(cve.user_interaction, 0.5)
        cvss_exploit = av * ac * pr * ui

        # Maturity factor
        maturity = self.MATURITY_WEIGHTS.get(cve.exploit_maturity, 0.5)

        # EPSS score (already 0-1)
        epss = cve.epss_score

        # KEV bonus (CISA says it's exploited in the wild)
        kev_bonus = 0.15 if cve.is_kev else 0.0

        # Weighted combination
        score = (
            EXPLOIT_MATURITY_WEIGHT * maturity
            + TEMPORAL_DECAY_WEIGHT * epss
            + ATTACK_SURFACE_WEIGHT * cvss_exploit
            + BUSINESS_IMPACT_WEIGHT * (cve.cvss_score / 10.0)
            + kev_bonus
        )
        return min(1.0, score)


# ════════════════════════════════════════════════════════════════════════════════
# TEMPORAL ANALYZER — Time-based relevance scoring
# ════════════════════════════════════════════════════════════════════════════════

class TemporalAnalyzer:
    """
    Scores CVE relevance based on temporal factors.
    Recent CVEs and actively exploited issues score higher.
    """

    def calculate_relevance(self, cve: CVERecord) -> float:
        """Calculate temporal relevance [0, 1]."""
        # Parse published date
        age_days = self._days_since(cve.published_date)
        if age_days < 0:
            age_days = 365  # Default for unparseable dates

        # Exponential decay
        decay = math.exp(-0.693 * age_days / EPSS_DECAY_HALF_LIFE_DAYS)

        # KEV keeps relevance high regardless of age
        if cve.is_kev:
            decay = max(decay, 0.80)

        # Active exploitation keeps relevance high
        if cve.exploit_maturity == ExploitMaturity.HIGH:
            decay = max(decay, 0.70)

        return min(1.0, decay)

    @staticmethod
    def _days_since(date_str: str) -> int:
        """Parse date string and return days since."""
        if not date_str:
            return -1
        try:
            parts = date_str.split("-")
            if len(parts) >= 3:
                year, month, day = int(parts[0]), int(parts[1]), int(parts[2])
                # Approximate days calculation
                now = time.time()
                then = time.mktime((year, month, day, 0, 0, 0, 0, 0, 0))
                return int((now - then) / 86400)
        except (ValueError, OverflowError, OSError):
            pass
        return -1


# ════════════════════════════════════════════════════════════════════════════════
# PATTERN PREDICTOR — Predicts likely CVE categories from tech stack
# ════════════════════════════════════════════════════════════════════════════════

class PatternPredictor:
    """
    Predicts likely vulnerability categories based on technology stack.
    Uses historical patterns: "PHP apps tend to have injection vulns",
    "Java apps tend to have deserialization issues", etc.
    """

    # Technology → likely CWE categories (based on historical data)
    TECH_PATTERNS: Dict[str, List[Tuple[CWECategory, float]]] = {
        "php": [
            (CWECategory.INJECTION, 0.85),
            (CWECategory.XSS, 0.80),
            (CWECategory.PATH_TRAVERSAL, 0.65),
            (CWECategory.DESERIALIZATION, 0.50),
            (CWECategory.BROKEN_AUTH, 0.60),
        ],
        "java": [
            (CWECategory.DESERIALIZATION, 0.85),
            (CWECategory.INJECTION, 0.70),
            (CWECategory.MEMORY_CORRUPTION, 0.40),
            (CWECategory.BROKEN_ACCESS, 0.60),
            (CWECategory.XXE, 0.65),
        ],
        "python": [
            (CWECategory.INJECTION, 0.65),
            (CWECategory.DESERIALIZATION, 0.55),
            (CWECategory.SSRF, 0.50),
            (CWECategory.PATH_TRAVERSAL, 0.45),
        ],
        "node.js": [
            (CWECategory.INJECTION, 0.75),
            (CWECategory.XSS, 0.70),
            (CWECategory.DESERIALIZATION, 0.60),
            (CWECategory.SSRF, 0.50),
        ],
        "wordpress": [
            (CWECategory.INJECTION, 0.90),
            (CWECategory.XSS, 0.85),
            (CWECategory.BROKEN_AUTH, 0.70),
            (CWECategory.PATH_TRAVERSAL, 0.65),
            (CWECategory.BROKEN_ACCESS, 0.75),
        ],
        "drupal": [
            (CWECategory.INJECTION, 0.85),
            (CWECategory.XSS, 0.80),
            (CWECategory.BROKEN_ACCESS, 0.70),
        ],
        "nginx": [
            (CWECategory.MISCONFIG, 0.70),
            (CWECategory.PATH_TRAVERSAL, 0.50),
            (CWECategory.MEMORY_CORRUPTION, 0.40),
        ],
        "apache": [
            (CWECategory.MISCONFIG, 0.65),
            (CWECategory.PATH_TRAVERSAL, 0.60),
            (CWECategory.INJECTION, 0.50),
        ],
        "mongodb": [
            (CWECategory.INJECTION, 0.80),
            (CWECategory.BROKEN_AUTH, 0.70),
            (CWECategory.MISCONFIG, 0.65),
        ],
        "kubernetes": [
            (CWECategory.MISCONFIG, 0.85),
            (CWECategory.BROKEN_ACCESS, 0.80),
            (CWECategory.PATH_TRAVERSAL, 0.55),
        ],
    }

    def predict_categories(self, tech_name: str) -> List[Tuple[CWECategory, float]]:
        """Predict likely vulnerability categories for a technology."""
        return self.TECH_PATTERNS.get(tech_name.lower(), [])


# ════════════════════════════════════════════════════════════════════════════════
# VERSION MATCHER — Match tech versions against CVE ranges
# ════════════════════════════════════════════════════════════════════════════════

class VersionMatcher:
    """Matches technology versions against CVE affected version ranges."""

    def match(self, product: str, version: str, cve: CVERecord) -> Optional[PredictionBasis]:
        """Check if product@version is affected by this CVE."""
        product_lower = product.lower()

        # Direct product match
        affected = [p.lower() for p in cve.affected_products]
        if product_lower not in affected:
            # Fuzzy match
            for ap in affected:
                if product_lower in ap or ap in product_lower:
                    break
            else:
                return None

        # Version range check
        version_range = cve.affected_versions.get(product_lower, "")
        if not version_range:
            # Product matches but no version constraint
            return PredictionBasis.TECHNOLOGY_FAMILY

        if not version:
            # No version known — still a technology family match
            return PredictionBasis.TECHNOLOGY_FAMILY

        if self._version_matches_range(version, version_range):
            return PredictionBasis.VERSION_RANGE_MATCH

        return None

    @staticmethod
    def _version_matches_range(version: str, range_str: str) -> bool:
        """Check if version matches a range like '< 2.4.58' or '>= 5.6.0'."""
        range_str = range_str.strip()
        parts = range_str.split(None, 1)
        if len(parts) != 2:
            return False
        op, target = parts

        try:
            v = [int(x) for x in re.split(r'[.\-]', version) if x.isdigit()]
            t = [int(x) for x in re.split(r'[.\-]', target) if x.isdigit()]
        except ValueError:
            return False

        max_len = max(len(v), len(t))
        v.extend([0] * (max_len - len(v)))
        t.extend([0] * (max_len - len(t)))

        if op == "<":
            return v < t
        elif op == "<=":
            return v <= t
        elif op == ">":
            return v > t
        elif op == ">=":
            return v >= t
        elif op == "==":
            return v == t
        return False


# ════════════════════════════════════════════════════════════════════════════════
# SIREN CVE PREDICTOR — Main Orchestrator
# ════════════════════════════════════════════════════════════════════════════════

class SirenCVEPredictor:
    """
    Main CVE prediction engine.

    Takes technology profiles from deep_fingerprint and produces
    prioritized, context-aware vulnerability predictions.

    Usage:
        predictor = SirenCVEPredictor()
        report = predictor.predict(
            target="example.com",
            techs=[
                TechProfile("nginx", "1.24.0"),
                TechProfile("PHP", "8.2.5"),
                TechProfile("WordPress", "6.3.0"),
            ],
        )
        for vuln in report.get_critical():
            print(f"{vuln.cve.cve_id} CVSS:{vuln.cve.cvss_score} SIREN:{vuln.siren_score:.2f}")
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._db = CVEDatabase()
        self._exploit_calc = ExploitabilityCalculator()
        self._temporal = TemporalAnalyzer()
        self._pattern_predictor = PatternPredictor()
        self._version_matcher = VersionMatcher()
        self._reports: Dict[str, PredictionReport] = {}
        logger.info("SirenCVEPredictor initialized with %d CVEs", self._db.count())

    def predict(
        self, target: str, techs: List[TechProfile],
    ) -> PredictionReport:
        """
        Generate CVE predictions for a target given its tech stack.
        """
        with self._lock:
            report = PredictionReport(target=target, tech_profiles=techs)
            seen_cves: Set[str] = set()

            for tech in techs:
                # 1) Direct CVE matching by product
                product_cves = self._db.search_by_product(tech.name)
                for cve in product_cves:
                    if cve.cve_id in seen_cves:
                        continue
                    basis = self._version_matcher.match(tech.name, tech.version, cve)
                    if basis is not None:
                        seen_cves.add(cve.cve_id)
                        pred = self._build_prediction(cve, tech, basis)
                        report.predictions.append(pred)

                # 2) Dependency-chain CVEs
                for dep in tech.dependencies:
                    dep_cves = self._db.search_by_product(dep)
                    for cve in dep_cves:
                        if cve.cve_id in seen_cves:
                            continue
                        seen_cves.add(cve.cve_id)
                        pred = self._build_prediction(
                            cve, tech, PredictionBasis.DEPENDENCY_CHAIN,
                        )
                        pred.context_notes.append(f"Transitive via dependency: {dep}")
                        report.predictions.append(pred)

                # 3) Pattern-based predictions (likely categories)
                patterns = self._pattern_predictor.predict_categories(tech.name)
                for category, likelihood in patterns:
                    # Find CVEs matching this category for similar tech
                    for cwe_id, cve_ids in self._db._cwe_index.items():
                        for cve_id in cve_ids:
                            if cve_id in seen_cves:
                                continue
                            cve = self._db.get(cve_id)
                            if cve and cve.cwe_category == category:
                                # Only include if high-confidence pattern
                                if likelihood >= 0.70:
                                    seen_cves.add(cve_id)
                                    pred = self._build_prediction(
                                        cve, tech, PredictionBasis.HISTORICAL_PATTERN,
                                    )
                                    pred.context_notes.append(
                                        f"Historical pattern: {tech.name} → {category.name} ({likelihood:.0%})"
                                    )
                                    pred.siren_score *= likelihood
                                    report.predictions.append(pred)

            # Correlate predictions with detected tech stack
            detected_techs = [t.name for t in techs]
            report.predictions = self._correlate_with_tech_stack(
                report.predictions, detected_techs,
            )

            # Sort by SIREN score (highest first)
            report.predictions.sort(key=lambda p: p.siren_score, reverse=True)

            # Compute report stats
            report.total_cves = len(report.predictions)
            report.critical_count = len([p for p in report.predictions if p.cve.cvss_score >= 9.0])
            report.high_count = len([p for p in report.predictions if 7.0 <= p.cve.cvss_score < 9.0])
            report.kev_count = len([p for p in report.predictions if p.cve.is_kev])
            if report.predictions:
                report.average_siren_score = sum(
                    p.siren_score for p in report.predictions
                ) / len(report.predictions)

            self._reports[target] = report
            logger.info(
                "CVE prediction for %s: %d vulns (%d critical, %d KEV)",
                target, report.total_cves, report.critical_count, report.kev_count,
            )
            return report

    def get_report(self, target: str) -> Optional[PredictionReport]:
        with self._lock:
            return self._reports.get(target)

    def add_cve(self, cve: CVERecord) -> None:
        """Add a CVE to the local database."""
        self._db.add(cve)

    def cve_count(self) -> int:
        return self._db.count()

    def _correlate_with_tech_stack(
        self, predictions: List[PredictedVuln], detected_techs: List[str],
    ) -> List[PredictedVuln]:
        """
        Filter and boost CVE predictions based on the detected tech stack.

        CVEs whose affected products match detected technologies get a score
        boost; unrelated CVEs are penalised so they rank lower.

        Args:
            predictions: Current list of predicted vulnerabilities.
            detected_techs: Lowercase names of technologies found on the target.

        Returns:
            The same list with adjusted siren_score values.
        """
        tech_set = {t.lower() for t in detected_techs}
        for pred in predictions:
            affected_lower = {p.lower() for p in pred.cve.affected_products}
            # Direct match between CVE products and detected tech
            if affected_lower & tech_set:
                pred.siren_score = min(1.0, pred.siren_score * 1.25)
                pred.context_notes.append("Tech stack match: boosted score")
            else:
                # Check partial / substring overlap
                partial = any(
                    tech in affected or affected in tech
                    for tech in tech_set
                    for affected in affected_lower
                )
                if partial:
                    pred.siren_score = min(1.0, pred.siren_score * 1.10)
                    pred.context_notes.append("Tech stack partial match: slight boost")
                else:
                    pred.siren_score *= 0.80
                    pred.context_notes.append("No tech stack match: score reduced")
        return predictions

    def _build_prediction(
        self, cve: CVERecord, tech: TechProfile, basis: PredictionBasis,
    ) -> PredictedVuln:
        """Build a scored prediction."""
        exploitability = self._exploit_calc.calculate(cve)
        temporal = self._temporal.calculate_relevance(cve)

        # Temporal decay — older CVEs have lower exploit likelihood
        age_days = self._temporal._days_since(cve.published_date)
        if age_days < 0:
            age_days = 365  # Default for unparseable dates
        temporal_weight = math.exp(-age_days / 365.0 * TEMPORAL_DECAY_RATE)
        exploitability *= temporal_weight

        # SIREN composite score
        siren_score = (
            0.35 * exploitability
            + 0.30 * (cve.cvss_score / 10.0)
            + 0.20 * temporal
            + 0.15 * (1.0 if cve.is_kev else 0.0)
        )

        # Basis adjustments
        if basis == PredictionBasis.EXACT_VERSION_MATCH:
            siren_score *= 1.0
        elif basis == PredictionBasis.VERSION_RANGE_MATCH:
            siren_score *= 0.95
        elif basis == PredictionBasis.TECHNOLOGY_FAMILY:
            siren_score *= 0.70
        elif basis == PredictionBasis.HISTORICAL_PATTERN:
            siren_score *= 0.50
        elif basis == PredictionBasis.DEPENDENCY_CHAIN:
            siren_score *= 0.80

        siren_score = min(1.0, siren_score)

        return PredictedVuln(
            cve=cve,
            prediction_basis=basis,
            target_tech=tech.name,
            target_version=tech.version,
            siren_score=siren_score,
            exploitability=exploitability,
            temporal_relevance=temporal,
            remediation_hint=self._generate_remediation(cve, tech),
        )

    @staticmethod
    def _generate_remediation(cve: CVERecord, tech: TechProfile) -> str:
        """Generate remediation hint for a CVE."""
        hints: List[str] = []
        for product, version_range in cve.affected_versions.items():
            if "<" in version_range:
                target_version = version_range.replace("<", "").replace("=", "").strip()
                hints.append(f"Upgrade {product} to >= {target_version}")
            elif ">=" in version_range:
                hints.append(f"Downgrade {product} from affected range or apply vendor patch")
        if cve.is_kev:
            hints.append("CISA KEV: Patch immediately (active exploitation confirmed)")
        if not hints:
            hints.append(f"Apply vendor patch for {cve.cve_id}")
        return "; ".join(hints)
