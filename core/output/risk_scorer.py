"""
████████████████████████████████████████████████████████████████████████████████
██                                                                            ██
██   ███████╗██╗██████╗ ███████╗███╗   ██╗                                    ██
██   ██╔════╝██║██╔══██╗██╔════╝████╗  ██║                                    ██
██   ███████╗██║██████╔╝█████╗  ██╔██╗ ██║                                    ██
██   ╚════██║██║██╔══██╗██╔══╝  ██║╚██╗██║                                    ██
██   ███████║██║██║  ██║███████╗██║ ╚████║                                    ██
██   ╚══════╝╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝                                    ██
██                                                                            ██
██   SIREN Risk Scorer -- Contextual Risk Intelligence Engine                 ██
██   "O risco que voce ignora hoje e a brecha que te derruba amanha."         ██
██                                                                            ██
██   Beyond CVSS: business-aware, regulation-conscious, financially-grounded  ██
██   risk scoring for the real world.                                         ██
██                                                                            ██
████████████████████████████████████████████████████████████████████████████████
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import re
import threading
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

logger = logging.getLogger("siren.output.risk_scorer")

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class IndustryVertical(str, Enum):
    """Industry verticals with associated risk profiles."""
    FINANCE = "FINANCE"
    HEALTHCARE = "HEALTHCARE"
    E_COMMERCE = "E_COMMERCE"
    GOVERNMENT = "GOVERNMENT"
    TECH = "TECH"
    GAMING = "GAMING"
    EDUCATION = "EDUCATION"
    CRITICAL_INFRASTRUCTURE = "CRITICAL_INFRASTRUCTURE"


class DataClassification(str, Enum):
    """Data classification tiers ordered by sensitivity."""
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"
    TOP_SECRET = "TOP_SECRET"


class ThreatLandscape(str, Enum):
    """Threat landscape assessment for the organization's industry."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskLevel(str, Enum):
    """Qualitative risk levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class RiskFactorCategory(str, Enum):
    """Categories of risk factors."""
    TECHNICAL = "TECHNICAL"
    BUSINESS = "BUSINESS"
    REGULATORY = "REGULATORY"
    REPUTATIONAL = "REPUTATIONAL"
    OPERATIONAL = "OPERATIONAL"


class LikelihoodLevel(str, Enum):
    """Likelihood axis for the risk matrix."""
    RARE = "RARE"
    UNLIKELY = "UNLIKELY"
    POSSIBLE = "POSSIBLE"
    LIKELY = "LIKELY"
    ALMOST_CERTAIN = "ALMOST_CERTAIN"


class ImpactLevel(str, Enum):
    """Impact axis for the risk matrix."""
    NEGLIGIBLE = "NEGLIGIBLE"
    MINOR = "MINOR"
    MODERATE = "MODERATE"
    MAJOR = "MAJOR"
    CATASTROPHIC = "CATASTROPHIC"


class Severity(str, Enum):
    """Finding severity levels (CVSS-aligned)."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


# ---------------------------------------------------------------------------
# Constants -- Industry data (Ponemon / IBM Data Breach Report calibrated)
# ---------------------------------------------------------------------------

# Average cost per compromised record (USD) by industry
COST_PER_RECORD: Dict[str, float] = {
    IndustryVertical.HEALTHCARE.value: 180.0,
    IndustryVertical.FINANCE.value: 188.0,
    IndustryVertical.E_COMMERCE.value: 170.0,
    IndustryVertical.GOVERNMENT.value: 146.0,
    IndustryVertical.TECH.value: 175.0,
    IndustryVertical.GAMING.value: 155.0,
    IndustryVertical.EDUCATION.value: 142.0,
    IndustryVertical.CRITICAL_INFRASTRUCTURE.value: 190.0,
}
DEFAULT_COST_PER_RECORD: float = 164.0

# Regulatory fine multipliers (fraction of annual revenue for worst case)
REGULATORY_FINE_MULTIPLIERS: Dict[str, Dict[str, float]] = {
    "GDPR": {"min_pct": 0.02, "max_pct": 0.04, "base_fine_eur": 20_000_000.0},
    "HIPAA": {"min_fine": 100.0, "max_fine": 1_920_000.0, "annual_cap": 1_920_000.0},
    "PCI_DSS": {"min_fine": 5_000.0, "max_fine": 100_000.0, "monthly": True},
    "SOX": {"min_fine": 1_000_000.0, "max_fine": 5_000_000.0, "imprisonment_years": 20},
    "CCPA": {"per_violation": 7_500.0, "per_unintentional": 2_500.0},
    "LGPD": {"min_pct": 0.02, "max_pct": 0.02, "base_fine_brl": 50_000_000.0},
    "NIST": {"min_fine": 0.0, "max_fine": 0.0, "reputational_only": True},
    "ISO_27001": {"min_fine": 0.0, "max_fine": 0.0, "certification_loss": True},
    "FISMA": {"min_fine": 0.0, "max_fine": 0.0, "contract_loss": True},
    "FERPA": {"min_fine": 0.0, "max_fine": 58_000.0, "funding_loss": True},
}

# Severity to CVSS base mapping (midpoints)
SEVERITY_CVSS_MAP: Dict[str, float] = {
    Severity.CRITICAL.value: 9.5,
    Severity.HIGH.value: 7.5,
    Severity.MEDIUM.value: 5.5,
    Severity.LOW.value: 3.0,
    Severity.INFORMATIONAL.value: 0.5,
}

# Data classification sensitivity multiplier
DATA_SENSITIVITY_MULTIPLIER: Dict[str, float] = {
    DataClassification.PUBLIC.value: 0.2,
    DataClassification.INTERNAL.value: 0.4,
    DataClassification.CONFIDENTIAL.value: 0.6,
    DataClassification.RESTRICTED.value: 0.8,
    DataClassification.TOP_SECRET.value: 1.0,
}

# Threat landscape multiplier applied to composite score
THREAT_LANDSCAPE_MULTIPLIER: Dict[str, float] = {
    ThreatLandscape.LOW.value: 0.8,
    ThreatLandscape.MEDIUM.value: 1.0,
    ThreatLandscape.HIGH.value: 1.2,
    ThreatLandscape.CRITICAL.value: 1.5,
}

# Industry default threat landscape
INDUSTRY_DEFAULT_THREAT: Dict[str, ThreatLandscape] = {
    IndustryVertical.FINANCE.value: ThreatLandscape.HIGH,
    IndustryVertical.HEALTHCARE.value: ThreatLandscape.HIGH,
    IndustryVertical.E_COMMERCE.value: ThreatLandscape.MEDIUM,
    IndustryVertical.GOVERNMENT.value: ThreatLandscape.HIGH,
    IndustryVertical.TECH.value: ThreatLandscape.MEDIUM,
    IndustryVertical.GAMING.value: ThreatLandscape.MEDIUM,
    IndustryVertical.EDUCATION.value: ThreatLandscape.LOW,
    IndustryVertical.CRITICAL_INFRASTRUCTURE.value: ThreatLandscape.CRITICAL,
}

# Average remediation effort in hours by severity
REMEDIATION_EFFORT_HOURS: Dict[str, float] = {
    Severity.CRITICAL.value: 80.0,
    Severity.HIGH.value: 40.0,
    Severity.MEDIUM.value: 20.0,
    Severity.LOW.value: 8.0,
    Severity.INFORMATIONAL.value: 2.0,
}

# Default hourly rate for security engineer (USD)
DEFAULT_HOURLY_RATE: float = 175.0

# Breach cost multipliers beyond record cost
BREACH_COST_COMPONENTS: Dict[str, float] = {
    "detection_escalation": 0.29,
    "notification": 0.06,
    "post_breach_response": 0.27,
    "lost_business": 0.38,
}

# Records-at-risk estimates by user base size brackets
def _estimate_records_at_risk(user_base: int, data_classification: str) -> int:
    """Estimate number of records at risk based on user base and classification."""
    sensitivity = DATA_SENSITIVITY_MULTIPLIER.get(data_classification, 0.5)
    # Assume a breach compromises between 1% and 30% of records
    # depending on data sensitivity
    exposure_rate = 0.01 + (sensitivity * 0.29)
    records = int(user_base * exposure_rate)
    return max(records, 1)


# Likelihood numeric mapping
LIKELIHOOD_NUMERIC: Dict[str, int] = {
    LikelihoodLevel.RARE.value: 1,
    LikelihoodLevel.UNLIKELY.value: 2,
    LikelihoodLevel.POSSIBLE.value: 3,
    LikelihoodLevel.LIKELY.value: 4,
    LikelihoodLevel.ALMOST_CERTAIN.value: 5,
}

# Impact numeric mapping
IMPACT_NUMERIC: Dict[str, int] = {
    ImpactLevel.NEGLIGIBLE.value: 1,
    ImpactLevel.MINOR.value: 2,
    ImpactLevel.MODERATE.value: 3,
    ImpactLevel.MAJOR.value: 4,
    ImpactLevel.CATASTROPHIC.value: 5,
}

# 5x5 Risk matrix cell -> RiskLevel mapping
# Matrix[likelihood_idx][impact_idx] where idx 0=lowest, 4=highest
RISK_MATRIX_GRID: List[List[RiskLevel]] = [
    # L\I        NEGLIGIBLE            MINOR                MODERATE             MAJOR                CATASTROPHIC
    [RiskLevel.INFORMATIONAL, RiskLevel.INFORMATIONAL, RiskLevel.LOW,    RiskLevel.LOW,    RiskLevel.MEDIUM],   # RARE
    [RiskLevel.INFORMATIONAL, RiskLevel.LOW,           RiskLevel.LOW,    RiskLevel.MEDIUM, RiskLevel.MEDIUM],   # UNLIKELY
    [RiskLevel.LOW,           RiskLevel.LOW,           RiskLevel.MEDIUM, RiskLevel.MEDIUM, RiskLevel.HIGH],     # POSSIBLE
    [RiskLevel.LOW,           RiskLevel.MEDIUM,        RiskLevel.MEDIUM, RiskLevel.HIGH,   RiskLevel.HIGH],     # LIKELY
    [RiskLevel.MEDIUM,        RiskLevel.MEDIUM,        RiskLevel.HIGH,   RiskLevel.HIGH,   RiskLevel.CRITICAL], # ALMOST_CERTAIN
]

# Numeric score per matrix cell (likelihood * impact)
RISK_MATRIX_SCORES: List[List[int]] = [
    [1,  2,  3,  4,  5],
    [2,  4,  6,  8,  10],
    [3,  6,  9,  12, 15],
    [4,  8,  12, 16, 20],
    [5,  10, 15, 20, 25],
]

# Security controls and their effectiveness at reducing risk
CONTROL_EFFECTIVENESS: Dict[str, float] = {
    "waf": 0.15,
    "ids_ips": 0.12,
    "siem": 0.08,
    "mfa": 0.20,
    "network_segmentation": 0.18,
    "encryption_at_rest": 0.10,
    "encryption_in_transit": 0.10,
    "dlp": 0.12,
    "edr": 0.14,
    "vulnerability_scanning": 0.06,
    "patch_management": 0.10,
    "security_awareness_training": 0.05,
    "incident_response_plan": 0.08,
    "backup_recovery": 0.07,
    "access_control": 0.15,
    "code_review": 0.10,
    "penetration_testing": 0.08,
    "zero_trust": 0.20,
    "soc": 0.12,
    "threat_intelligence": 0.08,
}


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _clamp(value: float, lo: float, hi: float) -> float:
    """Clamp *value* between *lo* and *hi* inclusive."""
    if value < lo:
        return lo
    if value > hi:
        return hi
    return value


def _cvss_roundup(value: float) -> float:
    """CVSS v3.1 round-up function: smallest 0.1 >= value."""
    rounded = math.ceil(value * 10.0) / 10.0
    return rounded


def _generate_id() -> str:
    """Generate a short deterministic-looking hex ID."""
    return uuid.uuid4().hex[:12]


def _severity_from_cvss(score: float) -> Severity:
    """Map a CVSS score to a severity enum."""
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score >= 0.1:
        return Severity.LOW
    return Severity.INFORMATIONAL


def _risk_level_from_composite(score: float) -> RiskLevel:
    """Map composite risk score (0-100) to a risk level."""
    if score >= 80.0:
        return RiskLevel.CRITICAL
    if score >= 60.0:
        return RiskLevel.HIGH
    if score >= 35.0:
        return RiskLevel.MEDIUM
    if score >= 15.0:
        return RiskLevel.LOW
    return RiskLevel.INFORMATIONAL


def _likelihood_from_score(score: float) -> LikelihoodLevel:
    """Map a 0-10 likelihood score to a likelihood level."""
    if score >= 8.5:
        return LikelihoodLevel.ALMOST_CERTAIN
    if score >= 6.5:
        return LikelihoodLevel.LIKELY
    if score >= 4.5:
        return LikelihoodLevel.POSSIBLE
    if score >= 2.5:
        return LikelihoodLevel.UNLIKELY
    return LikelihoodLevel.RARE


def _impact_from_score(score: float) -> ImpactLevel:
    """Map a 0-10 impact score to an impact level."""
    if score >= 8.5:
        return ImpactLevel.CATASTROPHIC
    if score >= 6.5:
        return ImpactLevel.MAJOR
    if score >= 4.5:
        return ImpactLevel.MODERATE
    if score >= 2.5:
        return ImpactLevel.MINOR
    return ImpactLevel.NEGLIGIBLE


def _format_usd(value: float) -> str:
    """Format a float as USD currency string."""
    if value >= 1_000_000_000:
        return f"${value / 1_000_000_000:.2f}B"
    if value >= 1_000_000:
        return f"${value / 1_000_000:.2f}M"
    if value >= 1_000:
        return f"${value / 1_000:.1f}K"
    return f"${value:.2f}"


def _now_iso() -> str:
    """Return current UTC time as ISO 8601 string."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class BusinessContext:
    """
    Describes the target organization's business environment.

    This context drives all risk adjustments: financial impact estimation,
    regulatory penalty calculation, blast radius assessment, and
    reputational damage modelling.
    """

    organization_name: str = "Unknown Organization"
    industry: IndustryVertical = IndustryVertical.TECH
    annual_revenue: float = 0.0
    data_classification: DataClassification = DataClassification.INTERNAL
    user_base_size: int = 0
    is_internet_facing: bool = True
    has_pii: bool = False
    has_phi: bool = False
    has_pci: bool = False
    has_financial_data: bool = False
    regulatory_frameworks: List[str] = field(default_factory=list)
    asset_criticality: int = 5
    brand_sensitivity: int = 5
    existing_controls: List[str] = field(default_factory=list)
    threat_landscape: ThreatLandscape = ThreatLandscape.MEDIUM
    _context_id: str = field(default_factory=_generate_id, repr=False)

    def __post_init__(self) -> None:
        """Validate and normalize fields after initialization."""
        # Coerce enums from strings
        if isinstance(self.industry, str):
            self.industry = IndustryVertical(self.industry)
        if isinstance(self.data_classification, str):
            self.data_classification = DataClassification(self.data_classification)
        if isinstance(self.threat_landscape, str):
            self.threat_landscape = ThreatLandscape(self.threat_landscape)

        # Clamp numeric ranges
        self.asset_criticality = int(_clamp(self.asset_criticality, 1, 10))
        self.brand_sensitivity = int(_clamp(self.brand_sensitivity, 1, 10))
        self.annual_revenue = max(0.0, float(self.annual_revenue))
        self.user_base_size = max(0, int(self.user_base_size))

        # Normalize controls to lowercase
        self.existing_controls = [c.lower().strip() for c in self.existing_controls]

        # Auto-detect regulatory frameworks from data types if none provided
        if not self.regulatory_frameworks:
            self.regulatory_frameworks = self._infer_regulatory_frameworks()

        logger.debug(
            "BusinessContext created: org=%s industry=%s classification=%s",
            self.organization_name, self.industry.value,
            self.data_classification.value,
        )

    def _infer_regulatory_frameworks(self) -> List[str]:
        """Infer applicable regulatory frameworks from data flags and industry."""
        frameworks: List[str] = []
        if self.has_pii:
            frameworks.append("GDPR")
            frameworks.append("CCPA")
        if self.has_phi:
            frameworks.append("HIPAA")
        if self.has_pci:
            frameworks.append("PCI_DSS")
        if self.has_financial_data:
            frameworks.append("SOX")
        if self.industry == IndustryVertical.GOVERNMENT:
            frameworks.append("FISMA")
            frameworks.append("NIST")
        if self.industry == IndustryVertical.EDUCATION:
            frameworks.append("FERPA")
        if self.industry == IndustryVertical.HEALTHCARE and "HIPAA" not in frameworks:
            frameworks.append("HIPAA")
        if self.industry == IndustryVertical.FINANCE and "PCI_DSS" not in frameworks:
            frameworks.append("PCI_DSS")
        return frameworks

    @property
    def data_sensitivity_score(self) -> float:
        """Return numeric sensitivity score 0.0 -- 1.0."""
        return DATA_SENSITIVITY_MULTIPLIER.get(
            self.data_classification.value, 0.5
        )

    @property
    def control_effectiveness_total(self) -> float:
        """
        Calculate cumulative control effectiveness (diminishing returns).

        Uses the formula: 1 - product(1 - eff_i) for each control present.
        This models overlapping controls with diminishing marginal benefit.
        """
        if not self.existing_controls:
            return 0.0
        residual = 1.0
        for control in self.existing_controls:
            eff = CONTROL_EFFECTIVENESS.get(control, 0.03)
            residual *= (1.0 - eff)
        return 1.0 - residual

    @property
    def exposure_factor(self) -> float:
        """
        Calculate exposure factor (0.0 -- 1.0) based on internet-facing
        status, user base, and data classification.
        """
        base = 0.5 if self.is_internet_facing else 0.2

        # User base contribution (log scale)
        if self.user_base_size > 0:
            user_factor = min(1.0, math.log10(max(self.user_base_size, 1)) / 8.0)
        else:
            user_factor = 0.1

        sensitivity = self.data_sensitivity_score

        exposure = (base * 0.4) + (user_factor * 0.3) + (sensitivity * 0.3)
        return _clamp(exposure, 0.0, 1.0)

    @property
    def estimated_records_at_risk(self) -> int:
        """Estimate total records at risk in a breach scenario."""
        return _estimate_records_at_risk(
            self.user_base_size, self.data_classification.value
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "context_id": self._context_id,
            "organization_name": self.organization_name,
            "industry": self.industry.value,
            "annual_revenue": self.annual_revenue,
            "data_classification": self.data_classification.value,
            "user_base_size": self.user_base_size,
            "is_internet_facing": self.is_internet_facing,
            "has_pii": self.has_pii,
            "has_phi": self.has_phi,
            "has_pci": self.has_pci,
            "has_financial_data": self.has_financial_data,
            "regulatory_frameworks": list(self.regulatory_frameworks),
            "asset_criticality": self.asset_criticality,
            "brand_sensitivity": self.brand_sensitivity,
            "existing_controls": list(self.existing_controls),
            "threat_landscape": self.threat_landscape.value,
            "computed": {
                "data_sensitivity_score": round(self.data_sensitivity_score, 4),
                "control_effectiveness_total": round(self.control_effectiveness_total, 4),
                "exposure_factor": round(self.exposure_factor, 4),
                "estimated_records_at_risk": self.estimated_records_at_risk,
            },
        }


@dataclass
class RiskFactor:
    """
    An individual factor contributing to the overall risk of a finding.

    Each factor has a raw value (0-10), a weight (0-1), and a justification
    explaining why this particular score was assigned.
    """

    factor_id: str = field(default_factory=_generate_id)
    name: str = ""
    category: RiskFactorCategory = RiskFactorCategory.TECHNICAL
    raw_value: float = 0.0
    weight: float = 0.0
    justification: str = ""
    evidence: str = ""

    def __post_init__(self) -> None:
        if isinstance(self.category, str):
            self.category = RiskFactorCategory(self.category)
        self.raw_value = _clamp(float(self.raw_value), 0.0, 10.0)
        self.weight = _clamp(float(self.weight), 0.0, 1.0)

    @property
    def weighted_value(self) -> float:
        """Compute weighted contribution: raw_value * weight."""
        return self.raw_value * self.weight

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "factor_id": self.factor_id,
            "name": self.name,
            "category": self.category.value,
            "raw_value": round(self.raw_value, 4),
            "weight": round(self.weight, 4),
            "weighted_value": round(self.weighted_value, 4),
            "justification": self.justification,
            "evidence": self.evidence,
        }


@dataclass
class RiskScore:
    """
    Calculated contextual risk score for a single security finding.

    Combines technical CVSS scoring with business impact, regulatory,
    and reputational dimensions to produce a composite risk score on
    a 0-100 scale.
    """

    score_id: str = field(default_factory=_generate_id)
    timestamp: str = field(default_factory=_now_iso)
    finding_reference: Dict[str, Any] = field(default_factory=dict)
    cvss_base: float = 0.0
    cvss_environmental: float = 0.0
    business_impact_score: float = 0.0
    likelihood_score: float = 0.0
    composite_risk_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.INFORMATIONAL
    financial_impact_estimate: Dict[str, float] = field(default_factory=dict)
    risk_factors: List[RiskFactor] = field(default_factory=list)
    remediation_roi: Dict[str, Any] = field(default_factory=dict)
    priority_rank: int = 0
    _likelihood_level: LikelihoodLevel = field(
        default=LikelihoodLevel.RARE, repr=False
    )
    _impact_level: ImpactLevel = field(
        default=ImpactLevel.NEGLIGIBLE, repr=False
    )

    def __post_init__(self) -> None:
        self.cvss_base = _clamp(float(self.cvss_base), 0.0, 10.0)
        self.cvss_environmental = _clamp(float(self.cvss_environmental), 0.0, 10.0)
        self.business_impact_score = _clamp(float(self.business_impact_score), 0.0, 10.0)
        self.likelihood_score = _clamp(float(self.likelihood_score), 0.0, 10.0)
        self.composite_risk_score = _clamp(float(self.composite_risk_score), 0.0, 100.0)
        if isinstance(self.risk_level, str):
            self.risk_level = RiskLevel(self.risk_level)

    @property
    def likelihood_level(self) -> LikelihoodLevel:
        return self._likelihood_level

    @property
    def impact_level(self) -> ImpactLevel:
        return self._impact_level

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "score_id": self.score_id,
            "timestamp": self.timestamp,
            "finding_reference": dict(self.finding_reference),
            "cvss_base": round(self.cvss_base, 1),
            "cvss_environmental": round(self.cvss_environmental, 1),
            "business_impact_score": round(self.business_impact_score, 2),
            "likelihood_score": round(self.likelihood_score, 2),
            "composite_risk_score": round(self.composite_risk_score, 2),
            "risk_level": self.risk_level.value,
            "likelihood_level": self._likelihood_level.value,
            "impact_level": self._impact_level.value,
            "financial_impact_estimate": {
                k: round(v, 2) if isinstance(v, float) else v
                for k, v in self.financial_impact_estimate.items()
            },
            "risk_factors": [rf.to_dict() for rf in self.risk_factors],
            "remediation_roi": {
                k: round(v, 2) if isinstance(v, float) else v
                for k, v in self.remediation_roi.items()
            },
            "priority_rank": self.priority_rank,
        }

    def to_markdown(self) -> str:
        """Render this risk score as a Markdown section."""
        lines: List[str] = []
        title = self.finding_reference.get("title", "Untitled Finding")
        sev = self.finding_reference.get("severity", "UNKNOWN")
        endpoint = self.finding_reference.get("endpoint", "N/A")

        risk_badge = {
            RiskLevel.CRITICAL: "[!!!] CRITICAL",
            RiskLevel.HIGH: "[!!] HIGH",
            RiskLevel.MEDIUM: "[!] MEDIUM",
            RiskLevel.LOW: "[-] LOW",
            RiskLevel.INFORMATIONAL: "[i] INFO",
        }.get(self.risk_level, "[?] UNKNOWN")

        lines.append(f"### {risk_badge} -- {title}")
        lines.append("")
        lines.append(f"- **Endpoint:** `{endpoint}`")
        lines.append(f"- **Base Severity:** {sev}")
        lines.append(f"- **CVSS Base:** {self.cvss_base:.1f}")
        lines.append(f"- **CVSS Environmental:** {self.cvss_environmental:.1f}")
        lines.append(f"- **Business Impact:** {self.business_impact_score:.2f} / 10.0")
        lines.append(f"- **Likelihood:** {self.likelihood_score:.2f} / 10.0 ({self._likelihood_level.value})")
        lines.append(f"- **Composite Risk Score:** {self.composite_risk_score:.2f} / 100.0")
        lines.append(f"- **Risk Level:** **{self.risk_level.value}**")
        lines.append(f"- **Priority Rank:** #{self.priority_rank}")
        lines.append("")

        # Financial impact
        fi = self.financial_impact_estimate
        if fi:
            lines.append("**Financial Impact Estimate:**")
            lines.append("")
            lines.append(f"| Metric | Value |")
            lines.append(f"|--------|-------|")
            lines.append(f"| Minimum | {_format_usd(fi.get('min', 0))} |")
            lines.append(f"| Expected | {_format_usd(fi.get('expected', 0))} |")
            lines.append(f"| Maximum | {_format_usd(fi.get('max', 0))} |")
            if "annual_loss_expectancy" in fi:
                lines.append(f"| Annual Loss Expectancy | {_format_usd(fi['annual_loss_expectancy'])} |")
            lines.append("")

        # Remediation ROI
        roi = self.remediation_roi
        if roi:
            lines.append("**Remediation ROI:**")
            lines.append("")
            lines.append(f"| Metric | Value |")
            lines.append(f"|--------|-------|")
            lines.append(f"| Estimated Fix Cost | {_format_usd(roi.get('remediation_cost', 0))} |")
            lines.append(f"| Annual Loss Expectancy | {_format_usd(roi.get('annual_loss_expectancy', 0))} |")
            lines.append(f"| ROI | {roi.get('roi_percentage', 0):.1f}% |")
            lines.append(f"| Payback Period | {roi.get('payback_period_days', 'N/A')} days |")
            lines.append(f"| Recommendation | {roi.get('recommendation', 'N/A')} |")
            lines.append("")

        # Risk factors
        if self.risk_factors:
            lines.append("**Risk Factors:**")
            lines.append("")
            lines.append("| Factor | Category | Raw | Weight | Weighted | Justification |")
            lines.append("|--------|----------|-----|--------|----------|---------------|")
            for rf in self.risk_factors:
                lines.append(
                    f"| {rf.name} | {rf.category.value} "
                    f"| {rf.raw_value:.1f} | {rf.weight:.2f} "
                    f"| {rf.weighted_value:.2f} | {rf.justification} |"
                )
            lines.append("")

        return "\n".join(lines)


@dataclass
class RiskMatrix:
    """
    Aggregated 5x5 risk matrix providing a bird's-eye view of all
    scored findings mapped to likelihood vs. impact cells.
    """

    matrix_id: str = field(default_factory=_generate_id)
    timestamp: str = field(default_factory=_now_iso)
    likelihood_axis: List[str] = field(default_factory=lambda: [
        ll.value for ll in LikelihoodLevel
    ])
    impact_axis: List[str] = field(default_factory=lambda: [
        il.value for il in ImpactLevel
    ])
    matrix_cells: List[List[str]] = field(default_factory=lambda: [
        [RISK_MATRIX_GRID[li][ii].value for ii in range(5)]
        for li in range(5)
    ])
    matrix_scores: List[List[int]] = field(default_factory=lambda: [
        list(row) for row in RISK_MATRIX_SCORES
    ])
    findings_per_cell: Dict[str, List[Dict[str, Any]]] = field(
        default_factory=dict
    )
    aggregate_risk_level: RiskLevel = RiskLevel.INFORMATIONAL
    risk_distribution: Dict[str, int] = field(default_factory=dict)
    top_risks: List[Dict[str, Any]] = field(default_factory=list)
    total_estimated_exposure: float = 0.0
    _all_scores: List[RiskScore] = field(default_factory=list, repr=False)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "matrix_id": self.matrix_id,
            "timestamp": self.timestamp,
            "likelihood_axis": list(self.likelihood_axis),
            "impact_axis": list(self.impact_axis),
            "matrix_cells": [list(row) for row in self.matrix_cells],
            "matrix_scores": [list(row) for row in self.matrix_scores],
            "findings_per_cell": {
                k: list(v) for k, v in self.findings_per_cell.items()
            },
            "aggregate_risk_level": self.aggregate_risk_level.value,
            "risk_distribution": dict(self.risk_distribution),
            "top_risks": list(self.top_risks),
            "total_estimated_exposure": round(self.total_estimated_exposure, 2),
        }

    def to_markdown(self) -> str:
        """Render the risk matrix as a Markdown table."""
        lines: List[str] = []
        lines.append("## Risk Matrix (Likelihood x Impact)")
        lines.append("")

        # Header row
        header = "| Likelihood \\ Impact |"
        for il in ImpactLevel:
            header += f" {il.value} |"
        lines.append(header)

        separator = "|" + "---|" * (len(ImpactLevel) + 1)
        lines.append(separator)

        # Count findings in each cell
        cell_counts: Dict[str, int] = defaultdict(int)
        for key, findings_list in self.findings_per_cell.items():
            cell_counts[key] = len(findings_list)

        # Data rows (top to bottom = ALMOST_CERTAIN to RARE)
        for li in reversed(list(LikelihoodLevel)):
            li_idx = list(LikelihoodLevel).index(li)
            row = f"| **{li.value}** |"
            for ii_idx, ii in enumerate(ImpactLevel):
                cell_key = f"{li.value}:{ii.value}"
                level = RISK_MATRIX_GRID[li_idx][ii_idx].value
                count = cell_counts.get(cell_key, 0)
                cell_text = f" {level}"
                if count > 0:
                    cell_text += f" ({count})"
                cell_text += " |"
                row += cell_text
            lines.append(row)

        lines.append("")

        # Distribution
        lines.append("### Risk Distribution")
        lines.append("")
        for level in RiskLevel:
            count = self.risk_distribution.get(level.value, 0)
            bar = "#" * count
            lines.append(f"- **{level.value}**: {count} {bar}")
        lines.append("")

        # Total exposure
        lines.append(f"**Total Estimated Financial Exposure:** {_format_usd(self.total_estimated_exposure)}")
        lines.append(f"**Aggregate Risk Level:** {self.aggregate_risk_level.value}")
        lines.append("")

        # Top risks
        if self.top_risks:
            lines.append("### Top Risks")
            lines.append("")
            lines.append("| # | Finding | Score | Level | Expected Impact |")
            lines.append("|---|---------|-------|-------|-----------------|")
            for i, tr in enumerate(self.top_risks, 1):
                lines.append(
                    f"| {i} | {tr.get('title', 'N/A')} "
                    f"| {tr.get('composite_score', 0):.1f} "
                    f"| {tr.get('risk_level', 'N/A')} "
                    f"| {_format_usd(tr.get('expected_impact', 0))} |"
                )
            lines.append("")

        return "\n".join(lines)

    def to_ascii_art(self) -> str:
        """
        Render a visual 5x5 ASCII art risk matrix with color-coded cells.

        Uses text markers to indicate severity:
          [!!!!] = CRITICAL
          [!!! ] = HIGH
          [!!  ] = MEDIUM
          [!   ] = LOW
          [    ] = INFO
        """
        cell_icons: Dict[str, str] = {
            RiskLevel.CRITICAL.value: "[!!!!]",
            RiskLevel.HIGH.value: "[!!! ]",
            RiskLevel.MEDIUM.value: "[!!  ]",
            RiskLevel.LOW.value: "[!   ]",
            RiskLevel.INFORMATIONAL.value: "[    ]",
        }

        cell_counts: Dict[str, int] = defaultdict(int)
        for key, findings_list in self.findings_per_cell.items():
            cell_counts[key] = len(findings_list)

        lines: List[str] = []
        lines.append("")
        lines.append("  SIREN RISK MATRIX -- Likelihood vs. Impact")
        lines.append("  " + "=" * 66)

        col_width = 12
        # Header
        header_line = "  {:>16s}".format("")
        for il in ImpactLevel:
            label = il.value[:col_width].center(col_width)
            header_line += f" {label}"
        lines.append(header_line)
        lines.append("  " + "-" * 76)

        # Rows (top = ALMOST_CERTAIN)
        for li in reversed(list(LikelihoodLevel)):
            li_idx = list(LikelihoodLevel).index(li)
            label = li.value[:16].rjust(16)
            row = f"  {label} |"
            for ii_idx, ii in enumerate(ImpactLevel):
                cell_key = f"{li.value}:{ii.value}"
                level = RISK_MATRIX_GRID[li_idx][ii_idx].value
                icon = cell_icons.get(level, "[    ]")
                count = cell_counts.get(cell_key, 0)
                if count > 0:
                    cell_str = f"{icon}{count:>2d}".center(col_width)
                else:
                    cell_str = f"{icon}  ".center(col_width)
                row += f" {cell_str}"
            lines.append(row)

        lines.append("  " + "-" * 76)
        lines.append(f"  {'':>16s}   {'NEGLIGIBLE':^12s} {'MINOR':^12s} "
                      f"{'MODERATE':^12s} {'MAJOR':^12s} {'CATASTROPHIC':^12s}")
        lines.append(f"  {'':>16s}   {'<--- IMPACT --->':^60s}")
        lines.append("")

        # Legend
        lines.append("  Legend:  [!!!!] = CRITICAL   [!!! ] = HIGH   "
                      "[!!  ] = MEDIUM   [!   ] = LOW   [    ] = INFO")
        lines.append("")

        # Summary bar
        lines.append("  Risk Distribution:")
        max_bar = 40
        total_findings = sum(self.risk_distribution.values()) if self.risk_distribution else 1
        for level in RiskLevel:
            count = self.risk_distribution.get(level.value, 0)
            bar_len = int((count / max(total_findings, 1)) * max_bar)
            bar = "#" * bar_len
            lines.append(f"    {level.value:>15s}: [{bar:<{max_bar}s}] {count}")

        lines.append("")
        lines.append(f"  Total Exposure: {_format_usd(self.total_estimated_exposure)}")
        lines.append(f"  Aggregate Risk: {self.aggregate_risk_level.value}")
        lines.append("  " + "=" * 66)
        lines.append("")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main engine
# ---------------------------------------------------------------------------

class SirenRiskScorer:
    """
    Contextual risk scoring engine that combines CVSS technical scores
    with business context, regulatory requirements, and financial impact
    to produce actionable, prioritized risk assessments.

    Thread-safe: all mutation is protected by an RLock.

    Usage::

        scorer = SirenRiskScorer()
        scorer.set_context(BusinessContext(
            organization_name="Acme Corp",
            industry=IndustryVertical.FINANCE,
            annual_revenue=500_000_000,
            data_classification=DataClassification.CONFIDENTIAL,
            user_base_size=2_000_000,
            has_pii=True, has_pci=True,
        ))
        findings = [
            {"title": "SQL Injection", "severity": "CRITICAL",
             "endpoint": "/api/users", "cvss": 9.8},
        ]
        scores = scorer.score_findings(findings)
        matrix = scorer.build_risk_matrix(scores)
        print(matrix.to_ascii_art())
        print(scorer.generate_executive_summary())
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._context: Optional[BusinessContext] = None
        self._scores: List[RiskScore] = []
        self._matrix: Optional[RiskMatrix] = None
        self._session_id: str = _generate_id()
        self._created_at: str = _now_iso()
        logger.info("SirenRiskScorer initialized (session=%s)", self._session_id)

    # ------------------------------------------------------------------
    # Context management
    # ------------------------------------------------------------------

    def set_context(self, business_context: BusinessContext) -> None:
        """
        Set the business context for all subsequent scoring operations.

        This resets any previously computed scores and matrix.
        """
        with self._lock:
            if not isinstance(business_context, BusinessContext):
                raise TypeError(
                    f"Expected BusinessContext, got {type(business_context).__name__}"
                )
            self._context = business_context
            self._scores = []
            self._matrix = None
            logger.info(
                "Context set: org=%s industry=%s",
                business_context.organization_name,
                business_context.industry.value,
            )

    def _require_context(self) -> BusinessContext:
        """Return the current context or raise if not set."""
        if self._context is None:
            raise RuntimeError(
                "Business context not set. Call set_context() first."
            )
        return self._context

    # ------------------------------------------------------------------
    # CVSS v3.1 Environmental Adjustment
    # ------------------------------------------------------------------

    def calculate_cvss_environmental(
        self,
        base_cvss: float,
        context: Optional[BusinessContext] = None,
    ) -> float:
        """
        Calculate CVSS v3.1 environmental score by adjusting the base
        score with environmental metrics derived from the business context.

        The environmental score modifies the base score based on:
        - Modified Attack Complexity (existing security controls)
        - Modified Scope (network segmentation)
        - Confidentiality Requirement (data classification)
        - Integrity Requirement (asset criticality)
        - Availability Requirement (user base / internet-facing)

        Returns a score in [0.0, 10.0].
        """
        with self._lock:
            ctx = context or self._require_context()
            base = _clamp(float(base_cvss), 0.0, 10.0)

            if base == 0.0:
                return 0.0

            # --- Modified Attack Complexity ---
            # Higher control effectiveness -> harder to exploit
            control_eff = ctx.control_effectiveness_total
            # MAC adjusts exploitability: ranges from 1.0 (no controls) to 0.5 (strong controls)
            mac_factor = 1.0 - (control_eff * 0.5)

            # --- Modified Scope ---
            # Network segmentation reduces scope change impact
            has_segmentation = "network_segmentation" in ctx.existing_controls
            has_zero_trust = "zero_trust" in ctx.existing_controls
            scope_factor = 1.0
            if has_segmentation:
                scope_factor -= 0.15
            if has_zero_trust:
                scope_factor -= 0.10
            scope_factor = max(scope_factor, 0.6)

            # --- Confidentiality Requirement (CR) ---
            # Based on data classification
            cr_map: Dict[str, float] = {
                DataClassification.PUBLIC.value: 0.5,       # Low
                DataClassification.INTERNAL.value: 1.0,     # Medium
                DataClassification.CONFIDENTIAL.value: 1.22, # High (adjusted upward)
                DataClassification.RESTRICTED.value: 1.44,
                DataClassification.TOP_SECRET.value: 1.51,  # Maximum
            }
            cr = cr_map.get(ctx.data_classification.value, 1.0)

            # --- Integrity Requirement (IR) ---
            # Based on asset criticality (1-10 mapped to 0.5-1.51)
            ir = 0.5 + (ctx.asset_criticality / 10.0) * 1.01

            # --- Availability Requirement (AR) ---
            # Based on internet-facing status and user base
            if ctx.is_internet_facing:
                ar_base = 1.22
            else:
                ar_base = 0.8
            if ctx.user_base_size > 1_000_000:
                ar_base = min(ar_base + 0.29, 1.51)
            elif ctx.user_base_size > 100_000:
                ar_base = min(ar_base + 0.15, 1.51)
            elif ctx.user_base_size > 10_000:
                ar_base = min(ar_base + 0.08, 1.51)
            ar = ar_base

            # --- Environmental score computation ---
            # We model this as modifying the base score by the combined
            # environmental metric factors.

            # CVSS v3.1 ISS (Impact Sub-Score) contribution from requirements
            # ISS_modified = 1 - [(1 - CR*conf_impact) * (1 - IR*integ_impact) * (1 - AR*avail_impact)]
            # We approximate C/I/A impact from the base score:
            # A base score of 10.0 implies max C+I+A impact
            normalized_base = base / 10.0
            conf_impact = normalized_base * 0.56   # CVSS C weight
            integ_impact = normalized_base * 0.56  # CVSS I weight
            avail_impact = normalized_base * 0.56  # CVSS A weight

            iss_modified = 1.0 - (
                (1.0 - _clamp(cr * conf_impact, 0.0, 0.915))
                * (1.0 - _clamp(ir * integ_impact, 0.0, 0.915))
                * (1.0 - _clamp(ar * avail_impact, 0.0, 0.915))
            )

            if iss_modified <= 0:
                return 0.0

            # Impact sub-score (scope unchanged)
            if scope_factor < 0.85:
                # Changed scope
                impact = 7.52 * (iss_modified - 0.029) - 3.25 * ((iss_modified - 0.02) ** 15)
            else:
                impact = 6.42 * iss_modified

            impact = max(impact, 0.0)

            # Exploitability sub-score modification
            # Base exploitability ~ base * 0.395 (rough average)
            base_exploitability = base * 0.395
            modified_exploitability = base_exploitability * mac_factor

            # Combine
            if impact <= 0:
                env_score = 0.0
            elif scope_factor < 0.85:
                env_score = _cvss_roundup(
                    min(1.08 * (impact + modified_exploitability), 10.0)
                )
            else:
                env_score = _cvss_roundup(
                    min(impact + modified_exploitability, 10.0)
                )

            # Apply scope factor as final adjustment
            env_score = env_score * scope_factor

            env_score = _clamp(_cvss_roundup(env_score), 0.0, 10.0)

            logger.debug(
                "CVSS environmental: base=%.1f -> env=%.1f "
                "(mac=%.2f scope=%.2f cr=%.2f ir=%.2f ar=%.2f)",
                base, env_score, mac_factor, scope_factor, cr, ir, ar,
            )

            return env_score

    # ------------------------------------------------------------------
    # Financial impact estimation
    # ------------------------------------------------------------------

    def estimate_financial_impact(
        self,
        finding: Dict[str, Any],
        context: Optional[BusinessContext] = None,
    ) -> Dict[str, float]:
        """
        Estimate financial impact of a finding in USD.

        Uses Ponemon/IBM Cost of Data Breach methodology:
        - Base: records_at_risk * cost_per_record (industry-specific)
        - Component multipliers: detection, notification, response, lost business
        - Regulatory fines: GDPR (4% revenue), HIPAA, PCI, SOX, etc.
        - Legal costs: estimated as 15-30% of breach cost
        - Brand damage: proportional to brand sensitivity

        Returns dict with min, max, expected, and component breakdown.
        """
        with self._lock:
            ctx = context or self._require_context()

            severity = finding.get("severity", "MEDIUM")
            if isinstance(severity, Severity):
                severity = severity.value

            cvss = float(finding.get("cvss", SEVERITY_CVSS_MAP.get(severity, 5.0)))

            # --- Records at risk ---
            records = ctx.estimated_records_at_risk

            # Scale records by severity (critical findings expose more)
            severity_record_multiplier: Dict[str, float] = {
                "CRITICAL": 1.0,
                "HIGH": 0.6,
                "MEDIUM": 0.3,
                "LOW": 0.1,
                "INFORMATIONAL": 0.01,
            }
            records_exposed = int(
                records * severity_record_multiplier.get(severity, 0.3)
            )
            records_exposed = max(records_exposed, 1)

            # --- Cost per record ---
            cpr = COST_PER_RECORD.get(ctx.industry.value, DEFAULT_COST_PER_RECORD)

            # Adjust for data type
            if ctx.has_phi:
                cpr *= 1.15  # PHI records cost more
            if ctx.has_pci:
                cpr *= 1.10  # Payment card data
            if ctx.has_financial_data:
                cpr *= 1.08

            # --- Base breach cost ---
            base_cost = records_exposed * cpr

            # --- Component costs ---
            detection_cost = base_cost * BREACH_COST_COMPONENTS["detection_escalation"]
            notification_cost = base_cost * BREACH_COST_COMPONENTS["notification"]
            response_cost = base_cost * BREACH_COST_COMPONENTS["post_breach_response"]
            lost_business_cost = base_cost * BREACH_COST_COMPONENTS["lost_business"]

            total_breach_cost = (
                detection_cost + notification_cost + response_cost + lost_business_cost
            )

            # --- Regulatory fines ---
            total_regulatory_fines = 0.0
            fine_details: Dict[str, float] = {}

            for framework in ctx.regulatory_frameworks:
                fine_data = REGULATORY_FINE_MULTIPLIERS.get(framework, {})
                fine = 0.0

                if "max_pct" in fine_data and ctx.annual_revenue > 0:
                    # GDPR / LGPD style: percentage of revenue
                    pct_fine = ctx.annual_revenue * fine_data["max_pct"]
                    base_fine = fine_data.get(
                        "base_fine_eur",
                        fine_data.get("base_fine_brl", 0.0),
                    )
                    fine = max(pct_fine, base_fine)
                    # Scale by severity
                    fine *= (cvss / 10.0)
                elif "max_fine" in fine_data:
                    fine = fine_data["max_fine"]
                    if fine_data.get("monthly"):
                        fine *= 12  # Annualize monthly PCI fines
                    fine *= (cvss / 10.0)
                elif "per_violation" in fine_data:
                    # CCPA style: per-violation fines
                    estimated_violations = min(records_exposed, 100_000)
                    fine = estimated_violations * fine_data["per_violation"]
                    fine *= (cvss / 10.0)

                if fine > 0:
                    fine_details[framework] = fine
                    total_regulatory_fines += fine

            # --- Legal costs ---
            legal_cost = total_breach_cost * 0.22  # ~22% of breach cost

            # --- Brand / reputational damage ---
            brand_damage_factor = ctx.brand_sensitivity / 10.0
            user_base_factor = min(1.0, math.log10(max(ctx.user_base_size, 1)) / 7.0)
            brand_damage = total_breach_cost * brand_damage_factor * user_base_factor * 0.5

            # --- Control reduction ---
            # Existing controls reduce expected impact
            control_reduction = ctx.control_effectiveness_total * 0.3
            reduction_factor = 1.0 - control_reduction

            # --- Total expected impact ---
            total_raw = (
                total_breach_cost
                + total_regulatory_fines
                + legal_cost
                + brand_damage
            )

            expected = total_raw * reduction_factor

            # Min and max with confidence interval
            min_impact = expected * 0.4
            max_impact = expected * 2.5

            # Ensure ordering
            if min_impact > expected:
                min_impact = expected * 0.5
            if max_impact < expected:
                max_impact = expected * 1.5

            # Annual loss expectancy
            likelihood = self._calculate_raw_likelihood(finding, ctx)
            breach_probability = likelihood / 10.0
            annual_loss_expectancy = expected * breach_probability

            result: Dict[str, float] = {
                "min": round(min_impact, 2),
                "max": round(max_impact, 2),
                "expected": round(expected, 2),
                "annual_loss_expectancy": round(annual_loss_expectancy, 2),
                "records_exposed": float(records_exposed),
                "cost_per_record": round(cpr, 2),
                "base_breach_cost": round(base_cost, 2),
                "detection_cost": round(detection_cost, 2),
                "notification_cost": round(notification_cost, 2),
                "response_cost": round(response_cost, 2),
                "lost_business_cost": round(lost_business_cost, 2),
                "regulatory_fines_total": round(total_regulatory_fines, 2),
                "legal_cost": round(legal_cost, 2),
                "brand_damage": round(brand_damage, 2),
                "control_reduction_pct": round(control_reduction * 100, 2),
                "breach_probability": round(breach_probability, 4),
            }

            # Add per-framework fines
            for fw, fine in fine_details.items():
                result[f"fine_{fw.lower()}"] = round(fine, 2)

            logger.debug(
                "Financial impact estimated: finding=%s expected=%s",
                finding.get("title", "?"),
                _format_usd(expected),
            )

            return result

    # ------------------------------------------------------------------
    # Remediation ROI
    # ------------------------------------------------------------------

    def calculate_remediation_roi(
        self,
        finding: Dict[str, Any],
        context: Optional[BusinessContext] = None,
    ) -> Dict[str, Any]:
        """
        Calculate the return on investment for remediating a finding.

        Formula:
            breach_probability = likelihood_score / 10
            annual_loss_expectancy = financial_impact * breach_probability
            remediation_cost = estimated_fix_hours * hourly_rate
            roi = (ALE - remediation_cost) / remediation_cost * 100

        Returns dict with all components and a human-readable recommendation.
        """
        with self._lock:
            ctx = context or self._require_context()

            severity = finding.get("severity", "MEDIUM")
            if isinstance(severity, Severity):
                severity = severity.value

            # Remediation cost
            fix_hours = float(finding.get(
                "estimated_fix_hours",
                REMEDIATION_EFFORT_HOURS.get(severity, 20.0),
            ))
            hourly_rate = float(finding.get("hourly_rate", DEFAULT_HOURLY_RATE))
            remediation_cost = fix_hours * hourly_rate

            # Financial impact
            financial_impact = self.estimate_financial_impact(finding, ctx)
            expected_impact = financial_impact.get("expected", 0.0)

            # Likelihood
            likelihood = self._calculate_raw_likelihood(finding, ctx)
            breach_probability = likelihood / 10.0

            # Annual loss expectancy
            ale = expected_impact * breach_probability

            # ROI
            if remediation_cost > 0:
                roi_pct = ((ale - remediation_cost) / remediation_cost) * 100.0
            else:
                roi_pct = float("inf") if ale > 0 else 0.0

            # Payback period (days)
            if ale > 0:
                payback_days = int((remediation_cost / ale) * 365)
            else:
                payback_days = 99999

            # Net benefit over 1 year
            net_benefit_1yr = ale - remediation_cost

            # Net benefit over 3 years
            net_benefit_3yr = (ale * 3) - remediation_cost

            # Recommendation
            if roi_pct >= 500:
                recommendation = "IMMEDIATE: Extremely high ROI. Remediate immediately."
                priority = "P0"
            elif roi_pct >= 200:
                recommendation = "URGENT: Very strong ROI. Prioritize for this sprint."
                priority = "P1"
            elif roi_pct >= 50:
                recommendation = "RECOMMENDED: Good ROI. Schedule in current cycle."
                priority = "P2"
            elif roi_pct >= 0:
                recommendation = "CONSIDER: Marginal ROI. Evaluate with other priorities."
                priority = "P3"
            else:
                recommendation = "DEFER: Negative ROI. Accept risk or find cheaper fix."
                priority = "P4"

            result: Dict[str, Any] = {
                "finding_title": finding.get("title", "Unknown"),
                "severity": severity,
                "remediation_cost": round(remediation_cost, 2),
                "fix_hours": fix_hours,
                "hourly_rate": hourly_rate,
                "expected_breach_impact": round(expected_impact, 2),
                "breach_probability": round(breach_probability, 4),
                "annual_loss_expectancy": round(ale, 2),
                "roi_percentage": round(roi_pct, 2),
                "net_benefit_1yr": round(net_benefit_1yr, 2),
                "net_benefit_3yr": round(net_benefit_3yr, 2),
                "payback_period_days": payback_days,
                "recommendation": recommendation,
                "priority": priority,
            }

            logger.debug(
                "Remediation ROI: finding=%s roi=%.1f%% recommendation=%s",
                finding.get("title", "?"), roi_pct, priority,
            )

            return result

    # ------------------------------------------------------------------
    # Internal scoring helpers
    # ------------------------------------------------------------------

    def _calculate_raw_likelihood(
        self,
        finding: Dict[str, Any],
        ctx: BusinessContext,
    ) -> float:
        """
        Calculate raw likelihood score (0-10) for a finding.

        Factors:
        - CVSS exploitability metrics (attack vector, complexity)
        - Internet-facing exposure
        - Existing controls (reduce likelihood)
        - Threat landscape (industry-specific)
        - Known exploit availability
        """
        severity = finding.get("severity", "MEDIUM")
        if isinstance(severity, Severity):
            severity = severity.value
        cvss = float(finding.get("cvss", SEVERITY_CVSS_MAP.get(severity, 5.0)))

        # Base likelihood from CVSS (exploitability approximation)
        base_likelihood = cvss * 0.7

        # Internet-facing increases likelihood
        if ctx.is_internet_facing:
            base_likelihood += 1.5
        else:
            base_likelihood += 0.3

        # Known exploit availability
        has_exploit = finding.get("has_exploit", False)
        has_public_poc = finding.get("has_public_poc", False)
        if has_exploit:
            base_likelihood += 2.0
        elif has_public_poc:
            base_likelihood += 1.2

        # Active exploitation in the wild
        if finding.get("actively_exploited", False):
            base_likelihood += 2.5

        # Threat landscape multiplier
        threat_mult: Dict[str, float] = {
            ThreatLandscape.LOW.value: 0.7,
            ThreatLandscape.MEDIUM.value: 0.9,
            ThreatLandscape.HIGH.value: 1.1,
            ThreatLandscape.CRITICAL.value: 1.3,
        }
        base_likelihood *= threat_mult.get(ctx.threat_landscape.value, 1.0)

        # Existing controls reduce likelihood
        control_reduction = ctx.control_effectiveness_total
        base_likelihood *= (1.0 - control_reduction * 0.5)

        return _clamp(base_likelihood, 0.0, 10.0)

    def _calculate_business_impact(
        self,
        finding: Dict[str, Any],
        ctx: BusinessContext,
    ) -> float:
        """
        Calculate business impact score (0-10) for a finding.

        Combines asset criticality, data sensitivity, user base blast
        radius, and regulatory exposure.
        """
        severity = finding.get("severity", "MEDIUM")
        if isinstance(severity, Severity):
            severity = severity.value
        cvss = float(finding.get("cvss", SEVERITY_CVSS_MAP.get(severity, 5.0)))

        # Asset criticality contribution (0-10 mapped to 0-3)
        asset_score = (ctx.asset_criticality / 10.0) * 3.0

        # Data sensitivity contribution (0-1 mapped to 0-2.5)
        data_score = ctx.data_sensitivity_score * 2.5

        # User base / blast radius (log scale, 0-2)
        if ctx.user_base_size > 0:
            blast = min(2.0, math.log10(max(ctx.user_base_size, 1)) / 4.0)
        else:
            blast = 0.2

        # Regulatory exposure (count of frameworks, each adds ~0.3, max 2.5)
        reg_count = len(ctx.regulatory_frameworks)
        reg_score = min(2.5, reg_count * 0.35)

        # Data type sensitivity bonus
        data_type_bonus = 0.0
        if ctx.has_phi:
            data_type_bonus += 0.5
        if ctx.has_pci:
            data_type_bonus += 0.4
        if ctx.has_pii:
            data_type_bonus += 0.3
        if ctx.has_financial_data:
            data_type_bonus += 0.3
        data_type_bonus = min(data_type_bonus, 1.0)

        total = asset_score + data_score + blast + reg_score + data_type_bonus

        # Weight by CVSS (a low-severity finding in critical context is still not 10.0)
        cvss_weight = 0.5 + (cvss / 10.0) * 0.5
        total *= cvss_weight

        return _clamp(total, 0.0, 10.0)

    def _build_risk_factors(
        self,
        finding: Dict[str, Any],
        ctx: BusinessContext,
        cvss_env: float,
        business_impact: float,
        likelihood: float,
    ) -> List[RiskFactor]:
        """Build the list of risk factors that contributed to the score."""
        factors: List[RiskFactor] = []
        severity = finding.get("severity", "MEDIUM")
        if isinstance(severity, Severity):
            severity = severity.value
        cvss = float(finding.get("cvss", SEVERITY_CVSS_MAP.get(severity, 5.0)))

        # 1. Technical: CVSS Environmental Score
        factors.append(RiskFactor(
            name="CVSS Environmental Score",
            category=RiskFactorCategory.TECHNICAL,
            raw_value=cvss_env,
            weight=0.35,
            justification=(
                f"Base CVSS {cvss:.1f} adjusted to {cvss_env:.1f} after "
                f"environmental metrics (controls, scope, requirements)"
            ),
            evidence=f"base_cvss={cvss}, environmental_cvss={cvss_env}",
        ))

        # 2. Technical: Exploitability
        exploit_score = likelihood * 0.8
        has_exploit = finding.get("has_exploit", False)
        exploit_text = "Known exploit exists" if has_exploit else "No known public exploit"
        factors.append(RiskFactor(
            name="Exploitability",
            category=RiskFactorCategory.TECHNICAL,
            raw_value=_clamp(exploit_score, 0, 10),
            weight=0.15,
            justification=f"Likelihood-derived exploitability. {exploit_text}.",
            evidence=f"likelihood={likelihood:.2f}, has_exploit={has_exploit}",
        ))

        # 3. Business: Asset Criticality
        factors.append(RiskFactor(
            name="Asset Criticality",
            category=RiskFactorCategory.BUSINESS,
            raw_value=float(ctx.asset_criticality),
            weight=0.12,
            justification=(
                f"Asset criticality rated {ctx.asset_criticality}/10 for "
                f"{ctx.organization_name}"
            ),
            evidence=f"asset_criticality={ctx.asset_criticality}",
        ))

        # 4. Business: Data Sensitivity
        sensitivity_10 = ctx.data_sensitivity_score * 10.0
        factors.append(RiskFactor(
            name="Data Sensitivity",
            category=RiskFactorCategory.BUSINESS,
            raw_value=_clamp(sensitivity_10, 0, 10),
            weight=0.10,
            justification=(
                f"Data classified as {ctx.data_classification.value}. "
                f"PII={ctx.has_pii}, PHI={ctx.has_phi}, PCI={ctx.has_pci}."
            ),
            evidence=f"classification={ctx.data_classification.value}",
        ))

        # 5. Business: Exposure / Blast Radius
        exposure = ctx.exposure_factor * 10.0
        factors.append(RiskFactor(
            name="Exposure / Blast Radius",
            category=RiskFactorCategory.BUSINESS,
            raw_value=_clamp(exposure, 0, 10),
            weight=0.08,
            justification=(
                f"Internet-facing={ctx.is_internet_facing}, "
                f"user_base={ctx.user_base_size:,}, "
                f"estimated records at risk={ctx.estimated_records_at_risk:,}"
            ),
            evidence=f"exposure_factor={ctx.exposure_factor:.3f}",
        ))

        # 6. Regulatory: Compliance Exposure
        reg_count = len(ctx.regulatory_frameworks)
        reg_score = min(10.0, reg_count * 1.8)
        frameworks_str = ", ".join(ctx.regulatory_frameworks) if ctx.regulatory_frameworks else "None"
        factors.append(RiskFactor(
            name="Regulatory Compliance Exposure",
            category=RiskFactorCategory.REGULATORY,
            raw_value=reg_score,
            weight=0.10,
            justification=(
                f"{reg_count} applicable framework(s): {frameworks_str}. "
                f"Potential fines and sanctions apply."
            ),
            evidence=f"frameworks={ctx.regulatory_frameworks}",
        ))

        # 7. Regulatory: Industry-specific penalty risk
        industry_penalty_map: Dict[str, float] = {
            IndustryVertical.FINANCE.value: 8.5,
            IndustryVertical.HEALTHCARE.value: 9.0,
            IndustryVertical.GOVERNMENT.value: 7.5,
            IndustryVertical.CRITICAL_INFRASTRUCTURE.value: 9.5,
            IndustryVertical.E_COMMERCE.value: 6.5,
            IndustryVertical.TECH.value: 5.5,
            IndustryVertical.GAMING.value: 4.5,
            IndustryVertical.EDUCATION.value: 5.0,
        }
        penalty_score = industry_penalty_map.get(ctx.industry.value, 5.0)
        factors.append(RiskFactor(
            name="Industry Regulatory Penalty Risk",
            category=RiskFactorCategory.REGULATORY,
            raw_value=penalty_score,
            weight=0.10,
            justification=(
                f"{ctx.industry.value} industry carries "
                f"{'heightened' if penalty_score >= 7 else 'moderate'} "
                f"regulatory scrutiny and penalty exposure."
            ),
            evidence=f"industry={ctx.industry.value}, penalty_score={penalty_score}",
        ))

        # 8. Reputational: Brand Sensitivity
        factors.append(RiskFactor(
            name="Brand Sensitivity",
            category=RiskFactorCategory.REPUTATIONAL,
            raw_value=float(ctx.brand_sensitivity),
            weight=0.05,
            justification=(
                f"Brand sensitivity rated {ctx.brand_sensitivity}/10. "
                f"A breach would {'significantly' if ctx.brand_sensitivity >= 7 else 'moderately'} "
                f"impact brand reputation."
            ),
            evidence=f"brand_sensitivity={ctx.brand_sensitivity}",
        ))

        # 9. Reputational: User Base Impact
        if ctx.user_base_size > 0:
            ub_score = min(10.0, math.log10(max(ctx.user_base_size, 1)) * 1.4)
        else:
            ub_score = 1.0
        factors.append(RiskFactor(
            name="User Base Impact",
            category=RiskFactorCategory.REPUTATIONAL,
            raw_value=_clamp(ub_score, 0, 10),
            weight=0.05,
            justification=(
                f"User base of {ctx.user_base_size:,} users. "
                f"Media exposure risk is "
                f"{'high' if ctx.user_base_size > 1_000_000 else 'moderate' if ctx.user_base_size > 10_000 else 'low'}."
            ),
            evidence=f"user_base_size={ctx.user_base_size}",
        ))

        # 10. Operational: Threat Landscape
        threat_score_map: Dict[str, float] = {
            ThreatLandscape.LOW.value: 3.0,
            ThreatLandscape.MEDIUM.value: 5.0,
            ThreatLandscape.HIGH.value: 7.5,
            ThreatLandscape.CRITICAL.value: 9.5,
        }
        threat_score = threat_score_map.get(ctx.threat_landscape.value, 5.0)
        factors.append(RiskFactor(
            name="Threat Landscape",
            category=RiskFactorCategory.OPERATIONAL,
            raw_value=threat_score,
            weight=0.05,
            justification=(
                f"Threat landscape for {ctx.industry.value} assessed as "
                f"{ctx.threat_landscape.value}."
            ),
            evidence=f"threat_landscape={ctx.threat_landscape.value}",
        ))

        # 11. Operational: Existing Controls Effectiveness
        control_raw = (1.0 - ctx.control_effectiveness_total) * 10.0
        factors.append(RiskFactor(
            name="Control Gap",
            category=RiskFactorCategory.OPERATIONAL,
            raw_value=_clamp(control_raw, 0, 10),
            weight=0.05,
            justification=(
                f"Existing controls provide {ctx.control_effectiveness_total * 100:.0f}% "
                f"cumulative effectiveness. Gap: {(1.0 - ctx.control_effectiveness_total) * 100:.0f}%."
            ),
            evidence=(
                f"controls={ctx.existing_controls}, "
                f"effectiveness={ctx.control_effectiveness_total:.3f}"
            ),
        ))

        return factors

    def _calculate_composite_score(
        self,
        cvss_env: float,
        business_impact: float,
        likelihood: float,
        ctx: BusinessContext,
        risk_factors: List[RiskFactor],
    ) -> float:
        """
        Calculate the SIREN composite risk score (0-100).

        Formula:
            technical_score = cvss_environmental * 0.35
            business_score = (asset_criticality * data_sensitivity * exposure) * 0.30
            regulatory_score = (frameworks_violated * regulatory_penalty_factor) * 0.20
            reputational_score = (brand_sensitivity * user_base_factor * media_factor) * 0.15
            composite = (technical + business + regulatory + reputational) * threat_landscape_multiplier

        All sub-scores are normalized to 0-10 before weighting, then the
        weighted sum is scaled to 0-100.
        """
        # Technical score: based on environmental CVSS and exploitability
        technical_score = cvss_env  # already 0-10

        # Business score: asset criticality * data sensitivity * exposure
        asset_norm = ctx.asset_criticality / 10.0
        data_sens = ctx.data_sensitivity_score
        exposure = ctx.exposure_factor
        business_score = (asset_norm * data_sens * exposure)
        # Scale to 0-10 (the product of three 0-1 values is at most 1.0)
        business_score = business_score * 10.0

        # Boost with the computed business_impact to avoid too-low scores
        business_score = (business_score * 0.4) + (business_impact * 0.6)

        # Regulatory score
        reg_count = len(ctx.regulatory_frameworks)
        # Penalty factor based on industry
        industry_penalty_base: Dict[str, float] = {
            IndustryVertical.FINANCE.value: 1.4,
            IndustryVertical.HEALTHCARE.value: 1.5,
            IndustryVertical.GOVERNMENT.value: 1.3,
            IndustryVertical.CRITICAL_INFRASTRUCTURE.value: 1.6,
            IndustryVertical.E_COMMERCE.value: 1.1,
            IndustryVertical.TECH.value: 1.0,
            IndustryVertical.GAMING.value: 0.9,
            IndustryVertical.EDUCATION.value: 0.8,
        }
        penalty_factor = industry_penalty_base.get(ctx.industry.value, 1.0)
        regulatory_score = min(10.0, reg_count * 1.5 * penalty_factor)

        # Reputational score
        brand_norm = ctx.brand_sensitivity / 10.0
        if ctx.user_base_size > 0:
            user_base_factor = min(1.0, math.log10(max(ctx.user_base_size, 1)) / 7.0)
        else:
            user_base_factor = 0.1

        # Media factor: internet-facing + large user base + data sensitivity
        media_factor = 0.3
        if ctx.is_internet_facing:
            media_factor += 0.3
        if ctx.user_base_size > 100_000:
            media_factor += 0.2
        if ctx.data_sensitivity_score >= 0.6:
            media_factor += 0.2
        media_factor = min(media_factor, 1.0)

        reputational_score = (brand_norm * user_base_factor * media_factor) * 10.0

        # Weighted combination (sub-scores are 0-10)
        weighted_sum = (
            technical_score * 0.35
            + business_score * 0.30
            + regulatory_score * 0.20
            + reputational_score * 0.15
        )

        # Scale to 0-100
        composite = weighted_sum * 10.0

        # Apply threat landscape multiplier
        tlm = THREAT_LANDSCAPE_MULTIPLIER.get(ctx.threat_landscape.value, 1.0)
        composite *= tlm

        # Apply likelihood modifier (high likelihood amplifies, low dampens)
        likelihood_mod = 0.7 + (likelihood / 10.0) * 0.6  # range 0.7 -- 1.3
        composite *= likelihood_mod

        composite = _clamp(composite, 0.0, 100.0)

        logger.debug(
            "Composite score: tech=%.2f biz=%.2f reg=%.2f rep=%.2f "
            "-> raw=%.2f * tlm=%.2f * lmod=%.2f -> %.2f",
            technical_score, business_score, regulatory_score,
            reputational_score, weighted_sum * 10.0, tlm,
            likelihood_mod, composite,
        )

        return composite

    # ------------------------------------------------------------------
    # Public scoring methods
    # ------------------------------------------------------------------

    def score_finding(self, finding: Dict[str, Any]) -> RiskScore:
        """
        Score a single security finding with full contextual risk analysis.

        The finding dict should contain at minimum:
          - title (str)
          - severity (str: CRITICAL/HIGH/MEDIUM/LOW/INFORMATIONAL)
          - endpoint (str, optional)
          - cvss (float, optional -- inferred from severity if missing)

        Optional enrichment fields:
          - has_exploit (bool)
          - has_public_poc (bool)
          - actively_exploited (bool)
          - estimated_fix_hours (float)
          - affected_component (str)
          - cwe_id (str)
          - cve_id (str)

        Returns a fully populated RiskScore.
        """
        with self._lock:
            ctx = self._require_context()
            start_time = time.monotonic()

            severity = finding.get("severity", "MEDIUM")
            if isinstance(severity, Severity):
                severity = severity.value
            title = finding.get("title", "Untitled Finding")
            endpoint = finding.get("endpoint", "N/A")
            cvss_base = float(finding.get(
                "cvss", SEVERITY_CVSS_MAP.get(severity, 5.0)
            ))
            cvss_base = _clamp(cvss_base, 0.0, 10.0)

            # Step 1: Environmental CVSS
            cvss_env = self.calculate_cvss_environmental(cvss_base, ctx)

            # Step 2: Likelihood
            likelihood = self._calculate_raw_likelihood(finding, ctx)

            # Step 3: Business impact
            business_impact = self._calculate_business_impact(finding, ctx)

            # Step 4: Risk factors
            risk_factors = self._build_risk_factors(
                finding, ctx, cvss_env, business_impact, likelihood
            )

            # Step 5: Composite score
            composite = self._calculate_composite_score(
                cvss_env, business_impact, likelihood, ctx, risk_factors
            )

            # Step 6: Risk level
            risk_level = _risk_level_from_composite(composite)

            # Step 7: Financial impact
            financial_impact = self.estimate_financial_impact(finding, ctx)

            # Step 8: Remediation ROI
            remediation_roi = self.calculate_remediation_roi(finding, ctx)

            # Step 9: Likelihood and impact levels for matrix placement
            likelihood_level = _likelihood_from_score(likelihood)
            impact_level = _impact_from_score(business_impact)

            score = RiskScore(
                finding_reference={
                    "title": title,
                    "severity": severity,
                    "endpoint": endpoint,
                    "cvss_original": cvss_base,
                    "cve_id": finding.get("cve_id", ""),
                    "cwe_id": finding.get("cwe_id", ""),
                    "affected_component": finding.get("affected_component", ""),
                },
                cvss_base=cvss_base,
                cvss_environmental=cvss_env,
                business_impact_score=business_impact,
                likelihood_score=likelihood,
                composite_risk_score=composite,
                risk_level=risk_level,
                financial_impact_estimate=financial_impact,
                risk_factors=risk_factors,
                remediation_roi=remediation_roi,
                _likelihood_level=likelihood_level,
                _impact_level=impact_level,
            )

            self._scores.append(score)

            elapsed = time.monotonic() - start_time
            logger.info(
                "Scored finding: '%s' -> composite=%.1f (%s) in %.3fs",
                title, composite, risk_level.value, elapsed,
            )

            return score

    def score_findings(
        self, findings: Sequence[Dict[str, Any]]
    ) -> List[RiskScore]:
        """
        Batch-score multiple findings and assign priority ranks.

        Returns a list of RiskScore objects sorted by composite score
        (highest risk first), with priority_rank populated.
        """
        with self._lock:
            scores: List[RiskScore] = []
            for finding in findings:
                score = self.score_finding(finding)
                scores.append(score)

            # Sort by composite score descending
            scores.sort(key=lambda s: s.composite_risk_score, reverse=True)

            # Assign priority ranks
            for rank, score in enumerate(scores, 1):
                score.priority_rank = rank

            logger.info(
                "Batch scored %d findings. Top risk: %s (%.1f)",
                len(scores),
                scores[0].finding_reference.get("title", "?") if scores else "N/A",
                scores[0].composite_risk_score if scores else 0.0,
            )

            return scores

    # ------------------------------------------------------------------
    # Risk matrix
    # ------------------------------------------------------------------

    def build_risk_matrix(self, scores: List[RiskScore]) -> RiskMatrix:
        """
        Build a 5x5 risk matrix from a list of scored findings.

        Each finding is placed in the appropriate (likelihood, impact) cell.
        Aggregate statistics are computed including risk distribution,
        top risks, and total financial exposure.
        """
        with self._lock:
            matrix = RiskMatrix()
            matrix._all_scores = list(scores)

            # Place findings in cells
            findings_per_cell: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
            risk_dist: Dict[str, int] = defaultdict(int)
            total_exposure = 0.0

            for score in scores:
                ll = score.likelihood_level.value
                il = score.impact_level.value
                cell_key = f"{ll}:{il}"
                findings_per_cell[cell_key].append({
                    "score_id": score.score_id,
                    "title": score.finding_reference.get("title", "?"),
                    "composite_score": score.composite_risk_score,
                    "risk_level": score.risk_level.value,
                    "expected_impact": score.financial_impact_estimate.get(
                        "expected", 0.0
                    ),
                })
                risk_dist[score.risk_level.value] += 1
                total_exposure += score.financial_impact_estimate.get(
                    "expected", 0.0
                )

            matrix.findings_per_cell = dict(findings_per_cell)
            matrix.risk_distribution = dict(risk_dist)
            matrix.total_estimated_exposure = total_exposure

            # Top 10 risks
            sorted_scores = sorted(
                scores, key=lambda s: s.composite_risk_score, reverse=True
            )
            matrix.top_risks = [
                {
                    "score_id": s.score_id,
                    "title": s.finding_reference.get("title", "?"),
                    "severity": s.finding_reference.get("severity", "?"),
                    "composite_score": s.composite_risk_score,
                    "risk_level": s.risk_level.value,
                    "expected_impact": s.financial_impact_estimate.get(
                        "expected", 0.0
                    ),
                    "likelihood": s.likelihood_level.value,
                    "impact": s.impact_level.value,
                }
                for s in sorted_scores[:10]
            ]

            # Aggregate risk level: determined by the highest concentration
            # of findings. If any CRITICAL exists, aggregate is CRITICAL, etc.
            if risk_dist.get(RiskLevel.CRITICAL.value, 0) > 0:
                matrix.aggregate_risk_level = RiskLevel.CRITICAL
            elif risk_dist.get(RiskLevel.HIGH.value, 0) > 0:
                matrix.aggregate_risk_level = RiskLevel.HIGH
            elif risk_dist.get(RiskLevel.MEDIUM.value, 0) > 0:
                matrix.aggregate_risk_level = RiskLevel.MEDIUM
            elif risk_dist.get(RiskLevel.LOW.value, 0) > 0:
                matrix.aggregate_risk_level = RiskLevel.LOW
            else:
                matrix.aggregate_risk_level = RiskLevel.INFORMATIONAL

            self._matrix = matrix

            logger.info(
                "Risk matrix built: %d findings, aggregate=%s, exposure=%s",
                len(scores), matrix.aggregate_risk_level.value,
                _format_usd(total_exposure),
            )

            return matrix

    # ------------------------------------------------------------------
    # Retrieval / query methods
    # ------------------------------------------------------------------

    def get_prioritized_findings(self) -> List[RiskScore]:
        """
        Return all scored findings sorted by composite risk score
        (highest first) with priority ranks assigned.
        """
        with self._lock:
            sorted_scores = sorted(
                self._scores,
                key=lambda s: s.composite_risk_score,
                reverse=True,
            )
            for rank, score in enumerate(sorted_scores, 1):
                score.priority_rank = rank
            return sorted_scores

    def get_aggregate_exposure(self) -> float:
        """
        Return the total estimated financial exposure across all
        scored findings (sum of expected impacts).
        """
        with self._lock:
            return sum(
                s.financial_impact_estimate.get("expected", 0.0)
                for s in self._scores
            )

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------

    def generate_executive_summary(self) -> str:
        """
        Generate a concise executive-level markdown summary suitable
        for C-level stakeholders.

        Includes:
        - Organization context snapshot
        - Aggregate risk posture
        - Total financial exposure
        - Top 5 critical risks
        - Immediate action items
        """
        with self._lock:
            ctx = self._require_context()
            scores = self.get_prioritized_findings()

            if not scores:
                return "# Executive Summary\n\nNo findings have been scored yet.\n"

            total_exposure = self.get_aggregate_exposure()

            # Risk distribution
            dist: Dict[str, int] = defaultdict(int)
            for s in scores:
                dist[s.risk_level.value] += 1

            # Aggregate level
            if dist.get(RiskLevel.CRITICAL.value, 0) > 0:
                agg = RiskLevel.CRITICAL
            elif dist.get(RiskLevel.HIGH.value, 0) > 0:
                agg = RiskLevel.HIGH
            elif dist.get(RiskLevel.MEDIUM.value, 0) > 0:
                agg = RiskLevel.MEDIUM
            elif dist.get(RiskLevel.LOW.value, 0) > 0:
                agg = RiskLevel.LOW
            else:
                agg = RiskLevel.INFORMATIONAL

            # Posture description
            posture_desc: Dict[RiskLevel, str] = {
                RiskLevel.CRITICAL: (
                    "The organization faces CRITICAL risk exposure. "
                    "Immediate executive attention and emergency remediation "
                    "are required. Current vulnerabilities, if exploited, could "
                    "result in catastrophic financial and operational impact."
                ),
                RiskLevel.HIGH: (
                    "The organization has HIGH risk exposure. Several findings "
                    "require urgent remediation within the current sprint cycle. "
                    "Exploitation of these vulnerabilities could result in "
                    "significant financial loss and regulatory action."
                ),
                RiskLevel.MEDIUM: (
                    "The organization has MODERATE risk exposure. Findings should "
                    "be scheduled for remediation in the current quarter. "
                    "While not immediately critical, these vulnerabilities "
                    "increase cumulative breach risk."
                ),
                RiskLevel.LOW: (
                    "The organization has LOW risk exposure. Findings represent "
                    "minor gaps that should be addressed through normal "
                    "maintenance cycles."
                ),
                RiskLevel.INFORMATIONAL: (
                    "The organization has MINIMAL risk exposure. Only informational "
                    "findings were identified with no immediate remediation required."
                ),
            }

            lines: List[str] = []
            lines.append("# SIREN Risk Assessment -- Executive Summary")
            lines.append("")
            lines.append(f"**Organization:** {ctx.organization_name}")
            lines.append(f"**Industry:** {ctx.industry.value}")
            lines.append(f"**Assessment Date:** {_now_iso()}")
            lines.append(f"**Aggregate Risk Posture:** **{agg.value}**")
            lines.append("")
            lines.append("---")
            lines.append("")

            # Risk posture
            lines.append("## Risk Posture Assessment")
            lines.append("")
            lines.append(posture_desc.get(agg, "Risk posture could not be determined."))
            lines.append("")

            # Key metrics
            lines.append("## Key Metrics")
            lines.append("")
            lines.append(f"| Metric | Value |")
            lines.append(f"|--------|-------|")
            lines.append(f"| Total Findings Assessed | {len(scores)} |")
            lines.append(f"| Critical Findings | {dist.get(RiskLevel.CRITICAL.value, 0)} |")
            lines.append(f"| High Findings | {dist.get(RiskLevel.HIGH.value, 0)} |")
            lines.append(f"| Medium Findings | {dist.get(RiskLevel.MEDIUM.value, 0)} |")
            lines.append(f"| Low Findings | {dist.get(RiskLevel.LOW.value, 0)} |")
            lines.append(f"| Informational | {dist.get(RiskLevel.INFORMATIONAL.value, 0)} |")
            lines.append(f"| **Total Financial Exposure** | **{_format_usd(total_exposure)}** |")
            lines.append(f"| Applicable Regulatory Frameworks | {', '.join(ctx.regulatory_frameworks) or 'None'} |")
            lines.append(f"| Existing Control Effectiveness | {ctx.control_effectiveness_total * 100:.0f}% |")
            lines.append("")

            # Top 5 critical risks
            top5 = scores[:5]
            lines.append("## Top Critical Risks Requiring Immediate Action")
            lines.append("")
            lines.append("| Priority | Finding | Risk Score | Level | Expected Impact | ROI |")
            lines.append("|----------|---------|------------|-------|-----------------|-----|")
            for s in top5:
                title = s.finding_reference.get("title", "N/A")
                expected = s.financial_impact_estimate.get("expected", 0)
                roi = s.remediation_roi.get("roi_percentage", 0)
                lines.append(
                    f"| #{s.priority_rank} | {title} | {s.composite_risk_score:.1f}/100 "
                    f"| {s.risk_level.value} | {_format_usd(expected)} | {roi:.0f}% |"
                )
            lines.append("")

            # Action items
            lines.append("## Recommended Immediate Actions")
            lines.append("")
            action_num = 1
            critical_scores = [s for s in scores if s.risk_level == RiskLevel.CRITICAL]
            high_scores = [s for s in scores if s.risk_level == RiskLevel.HIGH]

            if critical_scores:
                lines.append(
                    f"{action_num}. **EMERGENCY:** Remediate {len(critical_scores)} "
                    f"CRITICAL finding(s) within 24-48 hours. Combined exposure: "
                    f"{_format_usd(sum(s.financial_impact_estimate.get('expected', 0) for s in critical_scores))}"
                )
                action_num += 1

            if high_scores:
                lines.append(
                    f"{action_num}. **URGENT:** Address {len(high_scores)} HIGH "
                    f"finding(s) within the current sprint (1-2 weeks)."
                )
                action_num += 1

            if ctx.regulatory_frameworks:
                lines.append(
                    f"{action_num}. **COMPLIANCE:** Review findings against "
                    f"{', '.join(ctx.regulatory_frameworks)} requirements. "
                    f"Total regulatory fine exposure: "
                    f"{_format_usd(sum(s.financial_impact_estimate.get('regulatory_fines_total', 0) for s in scores))}"
                )
                action_num += 1

            if ctx.control_effectiveness_total < 0.5:
                lines.append(
                    f"{action_num}. **CONTROLS:** Current security control "
                    f"effectiveness is {ctx.control_effectiveness_total * 100:.0f}%. "
                    f"Recommend implementing additional controls (WAF, MFA, "
                    f"network segmentation) to reduce overall exposure."
                )
                action_num += 1

            lines.append(
                f"{action_num}. **MONITORING:** Establish continuous monitoring "
                f"for the top {min(5, len(scores))} findings with highest "
                f"composite risk scores."
            )
            lines.append("")

            # Total remediation investment
            total_fix_cost = sum(
                s.remediation_roi.get("remediation_cost", 0) for s in scores
            )
            total_ale = sum(
                s.remediation_roi.get("annual_loss_expectancy", 0) for s in scores
            )
            lines.append("## Investment Recommendation")
            lines.append("")
            lines.append(
                f"- **Total Remediation Investment Required:** {_format_usd(total_fix_cost)}"
            )
            lines.append(
                f"- **Total Annual Loss Expectancy (if unaddressed):** {_format_usd(total_ale)}"
            )
            if total_fix_cost > 0:
                overall_roi = ((total_ale - total_fix_cost) / total_fix_cost) * 100
                lines.append(
                    f"- **Overall Remediation ROI:** {overall_roi:.0f}%"
                )
            lines.append(
                f"- **Maximum Single-Event Exposure:** {_format_usd(total_exposure)}"
            )
            lines.append("")
            lines.append("---")
            lines.append("")
            lines.append(
                "*Report generated by SIREN Risk Scorer. Figures are "
                "estimates based on industry data (Ponemon/IBM Cost of Data Breach "
                "methodology) and should be validated against organization-specific "
                "actuarial data.*"
            )
            lines.append("")

            return "\n".join(lines)

    def generate_risk_report(self) -> str:
        """
        Generate a comprehensive markdown risk report including:
        - Executive summary
        - Risk matrix visualization
        - Detailed per-finding analysis
        - Financial impact analysis
        - Remediation roadmap
        - Methodology notes
        """
        with self._lock:
            ctx = self._require_context()
            scores = self.get_prioritized_findings()

            lines: List[str] = []

            # Title
            lines.append("# SIREN Contextual Risk Assessment Report")
            lines.append("")
            lines.append(f"**Organization:** {ctx.organization_name}")
            lines.append(f"**Industry:** {ctx.industry.value}")
            lines.append(f"**Data Classification:** {ctx.data_classification.value}")
            lines.append(f"**Assessment Date:** {_now_iso()}")
            lines.append(f"**Session ID:** {self._session_id}")
            lines.append("")
            lines.append("---")
            lines.append("")

            # Executive summary
            lines.append(self.generate_executive_summary())
            lines.append("")
            lines.append("---")
            lines.append("")

            # Risk matrix
            if scores:
                matrix = self.build_risk_matrix(scores)
                lines.append(matrix.to_markdown())
                lines.append("")
                lines.append("### ASCII Risk Matrix")
                lines.append("")
                lines.append("```")
                lines.append(matrix.to_ascii_art())
                lines.append("```")
                lines.append("")
                lines.append("---")
                lines.append("")

            # Context details
            lines.append("## Business Context")
            lines.append("")
            lines.append(f"| Parameter | Value |")
            lines.append(f"|-----------|-------|")
            lines.append(f"| Organization | {ctx.organization_name} |")
            lines.append(f"| Industry | {ctx.industry.value} |")
            lines.append(f"| Annual Revenue | {_format_usd(ctx.annual_revenue)} |")
            lines.append(f"| Data Classification | {ctx.data_classification.value} |")
            lines.append(f"| User Base | {ctx.user_base_size:,} |")
            lines.append(f"| Internet Facing | {'Yes' if ctx.is_internet_facing else 'No'} |")
            lines.append(f"| PII Data | {'Yes' if ctx.has_pii else 'No'} |")
            lines.append(f"| PHI Data | {'Yes' if ctx.has_phi else 'No'} |")
            lines.append(f"| PCI Data | {'Yes' if ctx.has_pci else 'No'} |")
            lines.append(f"| Financial Data | {'Yes' if ctx.has_financial_data else 'No'} |")
            lines.append(f"| Asset Criticality | {ctx.asset_criticality}/10 |")
            lines.append(f"| Brand Sensitivity | {ctx.brand_sensitivity}/10 |")
            lines.append(f"| Threat Landscape | {ctx.threat_landscape.value} |")
            lines.append(f"| Regulatory Frameworks | {', '.join(ctx.regulatory_frameworks) or 'None'} |")
            lines.append(f"| Security Controls | {', '.join(ctx.existing_controls) or 'None'} |")
            lines.append(f"| Control Effectiveness | {ctx.control_effectiveness_total * 100:.1f}% |")
            lines.append(f"| Exposure Factor | {ctx.exposure_factor:.3f} |")
            lines.append(f"| Estimated Records at Risk | {ctx.estimated_records_at_risk:,} |")
            lines.append("")
            lines.append("---")
            lines.append("")

            # Detailed findings
            lines.append("## Detailed Finding Analysis")
            lines.append("")

            for score in scores:
                lines.append(score.to_markdown())
                lines.append("---")
                lines.append("")

            # Financial summary
            lines.append("## Financial Impact Summary")
            lines.append("")
            total_min = sum(
                s.financial_impact_estimate.get("min", 0) for s in scores
            )
            total_exp = sum(
                s.financial_impact_estimate.get("expected", 0) for s in scores
            )
            total_max = sum(
                s.financial_impact_estimate.get("max", 0) for s in scores
            )
            total_ale = sum(
                s.financial_impact_estimate.get("annual_loss_expectancy", 0)
                for s in scores
            )
            total_reg = sum(
                s.financial_impact_estimate.get("regulatory_fines_total", 0)
                for s in scores
            )

            lines.append("| Metric | Value |")
            lines.append("|--------|-------|")
            lines.append(f"| Minimum Total Impact | {_format_usd(total_min)} |")
            lines.append(f"| Expected Total Impact | {_format_usd(total_exp)} |")
            lines.append(f"| Maximum Total Impact | {_format_usd(total_max)} |")
            lines.append(f"| Annual Loss Expectancy | {_format_usd(total_ale)} |")
            lines.append(f"| Regulatory Fine Exposure | {_format_usd(total_reg)} |")
            lines.append("")

            # Remediation roadmap
            lines.append("## Remediation Roadmap")
            lines.append("")
            lines.append("| Priority | Finding | Fix Cost | ALE | ROI | Timeline |")
            lines.append("|----------|---------|----------|-----|-----|----------|")

            timeline_map: Dict[str, str] = {
                "P0": "Immediate (24-48h)",
                "P1": "Urgent (1-2 weeks)",
                "P2": "This quarter",
                "P3": "Next quarter",
                "P4": "Backlog / accept risk",
            }

            for s in scores:
                title = s.finding_reference.get("title", "N/A")
                fix_cost = s.remediation_roi.get("remediation_cost", 0)
                ale = s.remediation_roi.get("annual_loss_expectancy", 0)
                roi = s.remediation_roi.get("roi_percentage", 0)
                priority = s.remediation_roi.get("priority", "P3")
                timeline = timeline_map.get(priority, "TBD")
                lines.append(
                    f"| {priority} | {title} | {_format_usd(fix_cost)} "
                    f"| {_format_usd(ale)} | {roi:.0f}% | {timeline} |"
                )
            lines.append("")
            lines.append("---")
            lines.append("")

            # Methodology
            lines.append("## Methodology")
            lines.append("")
            lines.append(
                "This risk assessment uses the **SIREN Composite Risk Scoring** "
                "methodology, which extends CVSS v3.1 with business context:"
            )
            lines.append("")
            lines.append("1. **Technical Score (35%):** CVSS v3.1 environmental adjustment "
                         "accounting for existing security controls, network architecture, "
                         "and data sensitivity requirements.")
            lines.append("2. **Business Score (30%):** Asset criticality, data classification, "
                         "exposure factor, and blast radius analysis.")
            lines.append("3. **Regulatory Score (20%):** Applicable regulatory frameworks, "
                         "industry-specific penalty factors, and compliance gap analysis.")
            lines.append("4. **Reputational Score (15%):** Brand sensitivity, user base "
                         "impact, media exposure risk, and public trust considerations.")
            lines.append("")
            lines.append(
                "Financial estimates are calibrated against Ponemon Institute / IBM "
                "Cost of a Data Breach Report data with industry-specific cost-per-record "
                "figures and regulatory fine schedules."
            )
            lines.append("")
            lines.append(
                "**Composite Risk Score** = (Technical x 0.35 + Business x 0.30 + "
                "Regulatory x 0.20 + Reputational x 0.15) x Threat Landscape Multiplier "
                "x Likelihood Modifier"
            )
            lines.append("")
            lines.append("---")
            lines.append("")
            lines.append(
                "*Generated by SIREN Risk Scorer | "
                "Framework: SIREN Contextual Risk Intelligence Engine*"
            )
            lines.append("")

            return "\n".join(lines)

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_json(self) -> str:
        """
        Export the complete risk assessment as a JSON string.

        Includes: context, all scores, risk matrix, aggregate stats,
        and metadata.
        """
        with self._lock:
            ctx = self._require_context()
            scores = self.get_prioritized_findings()

            # Build matrix if we have scores
            matrix_data: Optional[Dict[str, Any]] = None
            if scores:
                matrix = self.build_risk_matrix(scores)
                matrix_data = matrix.to_dict()

            # Risk distribution
            dist: Dict[str, int] = defaultdict(int)
            for s in scores:
                dist[s.risk_level.value] += 1

            total_exposure = self.get_aggregate_exposure()

            payload: Dict[str, Any] = {
                "metadata": {
                    "session_id": self._session_id,
                    "created_at": self._created_at,
                    "exported_at": _now_iso(),
                    "scorer_version": "1.0.0",
                    "framework": "SIREN Contextual Risk Intelligence Engine",
                    "methodology": "SIREN Composite Risk Scoring v1",
                },
                "business_context": ctx.to_dict(),
                "summary": {
                    "total_findings": len(scores),
                    "risk_distribution": dict(dist),
                    "aggregate_risk_level": (
                        RiskLevel.CRITICAL.value if dist.get(RiskLevel.CRITICAL.value, 0)
                        else RiskLevel.HIGH.value if dist.get(RiskLevel.HIGH.value, 0)
                        else RiskLevel.MEDIUM.value if dist.get(RiskLevel.MEDIUM.value, 0)
                        else RiskLevel.LOW.value if dist.get(RiskLevel.LOW.value, 0)
                        else RiskLevel.INFORMATIONAL.value
                    ),
                    "total_financial_exposure": round(total_exposure, 2),
                    "total_annual_loss_expectancy": round(
                        sum(s.financial_impact_estimate.get(
                            "annual_loss_expectancy", 0
                        ) for s in scores), 2
                    ),
                    "total_remediation_cost": round(
                        sum(s.remediation_roi.get(
                            "remediation_cost", 0
                        ) for s in scores), 2
                    ),
                },
                "scores": [s.to_dict() for s in scores],
                "risk_matrix": matrix_data,
            }

            return json.dumps(payload, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Module-level exports
# ---------------------------------------------------------------------------

__all__ = [
    "BusinessContext",
    "RiskFactor",
    "RiskScore",
    "RiskMatrix",
    "SirenRiskScorer",
    # Supporting enums (available but not in the mandatory export list)
    "IndustryVertical",
    "DataClassification",
    "ThreatLandscape",
    "RiskLevel",
    "RiskFactorCategory",
    "LikelihoodLevel",
    "ImpactLevel",
    "Severity",
]
