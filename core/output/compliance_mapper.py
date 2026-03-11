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
██   SIREN Compliance Mapper -- Regulatory Intelligence Engine                ██
██   "Compliance nao e checkbox; e a armadura que segura o caos."             ██
██                                                                            ██
██   Maps security findings to 10 regulatory frameworks with surgical         ██
██   precision.  Gap analysis, audit evidence, remediation priorities.        ██
██                                                                            ██
██   Capabilities:                                                            ██
██     * PCI-DSS v4.0          -- Payment card industry                       ██
██     * OWASP Top 10 2021     -- Web application risks                       ██
██     * OWASP API Top 10 2023 -- API-specific risks                          ██
██     * NIST SP 800-53 Rev 5  -- Federal security controls                   ██
██     * CIS Controls v8       -- Prescriptive security                       ██
██     * ISO 27001:2022        -- Information security management             ██
██     * HIPAA                 -- Healthcare data protection                  ██
██     * SOC 2 Type II         -- Service organization controls               ██
██     * LGPD                  -- Brazilian data protection                   ██
██     * GDPR                  -- EU data protection regulation               ██
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
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

logger = logging.getLogger("siren.output.compliance_mapper")

# ═══════════════════════════════════════════════════════════════════════════════
# Enumerations
# ═══════════════════════════════════════════════════════════════════════════════


class FrameworkID(str, Enum):
    """Identifiers for supported compliance frameworks."""
    PCI_DSS_4 = "PCI-DSS-v4.0"
    OWASP_TOP10_2021 = "OWASP-Top10-2021"
    OWASP_API_2023 = "OWASP-API-Top10-2023"
    NIST_800_53 = "NIST-800-53-r5"
    CIS_V8 = "CIS-Controls-v8"
    ISO_27001 = "ISO-27001-2022"
    HIPAA = "HIPAA"
    SOC2 = "SOC2-Type-II"
    LGPD = "LGPD"
    GDPR = "GDPR"


class Severity(str, Enum):
    """Finding severity aligned with CVSS qualitative ratings."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class ComplianceStatus(str, Enum):
    """Status of a control within compliance assessment."""
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    PARTIALLY_COMPLIANT = "PARTIALLY_COMPLIANT"
    NOT_ASSESSED = "NOT_ASSESSED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class GapSeverity(str, Enum):
    """Severity classification for compliance gaps."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class RemediationEffort(str, Enum):
    """Estimated effort to remediate a compliance gap."""
    TRIVIAL = "TRIVIAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    VERY_HIGH = "VERY_HIGH"


class VulnType(str, Enum):
    """Vulnerability type taxonomy used across SIREN."""
    SQL_INJECTION = "SQL_INJECTION"
    XSS_REFLECTED = "XSS_REFLECTED"
    XSS_STORED = "XSS_STORED"
    XSS_DOM = "XSS_DOM"
    CSRF = "CSRF"
    SSRF = "SSRF"
    XXE = "XXE"
    IDOR = "IDOR"
    BROKEN_AUTH = "BROKEN_AUTH"
    SESSION_FIXATION = "SESSION_FIXATION"
    WEAK_PASSWORD = "WEAK_PASSWORD"
    SENSITIVE_DATA_EXPOSURE = "SENSITIVE_DATA_EXPOSURE"
    INSECURE_DESERIALIZATION = "INSECURE_DESERIALIZATION"
    SECURITY_MISCONFIGURATION = "SECURITY_MISCONFIGURATION"
    BROKEN_ACCESS_CONTROL = "BROKEN_ACCESS_CONTROL"
    MISSING_ENCRYPTION = "MISSING_ENCRYPTION"
    WEAK_CRYPTO = "WEAK_CRYPTO"
    DIRECTORY_TRAVERSAL = "DIRECTORY_TRAVERSAL"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    FILE_UPLOAD = "FILE_UPLOAD"
    OPEN_REDIRECT = "OPEN_REDIRECT"
    CORS_MISCONFIGURATION = "CORS_MISCONFIGURATION"
    HTTP_HEADER_MISSING = "HTTP_HEADER_MISSING"
    INFORMATION_DISCLOSURE = "INFORMATION_DISCLOSURE"
    RATE_LIMITING_ABSENT = "RATE_LIMITING_ABSENT"
    MASS_ASSIGNMENT = "MASS_ASSIGNMENT"
    BOLA = "BOLA"
    EXCESSIVE_DATA_EXPOSURE = "EXCESSIVE_DATA_EXPOSURE"
    INSUFFICIENT_LOGGING = "INSUFFICIENT_LOGGING"
    SUPPLY_CHAIN = "SUPPLY_CHAIN"


# ═══════════════════════════════════════════════════════════════════════════════
# Severity weight tables
# ═══════════════════════════════════════════════════════════════════════════════

_SEVERITY_WEIGHT: Dict[str, float] = {
    Severity.CRITICAL.value: 10.0,
    Severity.HIGH.value: 7.5,
    Severity.MEDIUM.value: 5.0,
    Severity.LOW.value: 2.5,
    Severity.INFORMATIONAL.value: 0.5,
}

_GAP_SEVERITY_WEIGHT: Dict[str, float] = {
    GapSeverity.CRITICAL.value: 10.0,
    GapSeverity.HIGH.value: 7.0,
    GapSeverity.MEDIUM.value: 4.0,
    GapSeverity.LOW.value: 1.5,
}

_EFFORT_HOURS: Dict[str, Tuple[float, float]] = {
    RemediationEffort.TRIVIAL.value: (0.5, 4.0),
    RemediationEffort.LOW.value: (4.0, 16.0),
    RemediationEffort.MEDIUM.value: (16.0, 40.0),
    RemediationEffort.HIGH.value: (40.0, 120.0),
    RemediationEffort.VERY_HIGH.value: (120.0, 480.0),
}

# ═══════════════════════════════════════════════════════════════════════════════
# Dataclasses
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass
class ComplianceControl:
    """
    Represents a single control within a compliance framework.

    Attributes:
        control_id:     Unique control identifier (e.g., "6.2.4" for PCI-DSS).
        framework_id:   Parent framework identifier.
        title:          Short human-readable title.
        description:    Full description of the control requirement.
        category:       Logical grouping / domain within the framework.
        sub_category:   Optional sub-grouping for hierarchical frameworks.
        severity:       How critical a failure of this control is.
        status:         Current compliance status.
        related_vulns:  Vulnerability types that can violate this control.
        evidence:       Evidence items collected for audit purposes.
        remediation:    Suggested remediation text.
        references:     External reference URLs or document identifiers.
        last_assessed:  Timestamp of last assessment.
        assessor:       Identifier of the assessor (human or automated).
        notes:          Free-form notes attached during assessment.
    """
    control_id: str = ""
    framework_id: str = ""
    title: str = ""
    description: str = ""
    category: str = ""
    sub_category: str = ""
    severity: str = Severity.MEDIUM.value
    status: str = ComplianceStatus.NOT_ASSESSED.value
    related_vulns: List[str] = field(default_factory=list)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    last_assessed: float = 0.0
    assessor: str = ""
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Serialize control to dictionary."""
        return {
            "control_id": self.control_id,
            "framework_id": self.framework_id,
            "title": self.title,
            "description": self.description,
            "category": self.category,
            "sub_category": self.sub_category,
            "severity": self.severity,
            "status": self.status,
            "related_vulns": list(self.related_vulns),
            "evidence": list(self.evidence),
            "remediation": self.remediation,
            "references": list(self.references),
            "last_assessed": self.last_assessed,
            "assessor": self.assessor,
            "notes": self.notes,
        }

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> ComplianceControl:
        """Deserialize control from dictionary."""
        return ComplianceControl(
            control_id=data.get("control_id", ""),
            framework_id=data.get("framework_id", ""),
            title=data.get("title", ""),
            description=data.get("description", ""),
            category=data.get("category", ""),
            sub_category=data.get("sub_category", ""),
            severity=data.get("severity", Severity.MEDIUM.value),
            status=data.get("status", ComplianceStatus.NOT_ASSESSED.value),
            related_vulns=data.get("related_vulns", []),
            evidence=data.get("evidence", []),
            remediation=data.get("remediation", ""),
            references=data.get("references", []),
            last_assessed=data.get("last_assessed", 0.0),
            assessor=data.get("assessor", ""),
            notes=data.get("notes", ""),
        )

    def is_violated(self) -> bool:
        """Return True if control is non-compliant."""
        return self.status == ComplianceStatus.NON_COMPLIANT.value

    def add_evidence(self, evidence_type: str, content: str,
                     source: str = "siren") -> None:
        """Attach an evidence item to this control."""
        self.evidence.append({
            "id": uuid.uuid4().hex[:12],
            "type": evidence_type,
            "content": content,
            "source": source,
            "timestamp": time.time(),
        })


@dataclass
class ComplianceStandard:
    """
    Represents a complete compliance framework/standard.

    Attributes:
        framework_id:   Unique framework identifier.
        name:           Full name of the standard.
        version:        Version string.
        description:    Brief description of the framework scope.
        authority:      Issuing authority / organization.
        url:            Official URL for the standard.
        controls:       All controls in this framework.
        categories:     Logical groupings of controls.
        total_controls: Total number of controls defined.
        applicable:     Whether this framework is applicable to the target.
        scope_notes:    Notes about applicability scope.
        last_updated:   When the standard DB was last refreshed.
    """
    framework_id: str = ""
    name: str = ""
    version: str = ""
    description: str = ""
    authority: str = ""
    url: str = ""
    controls: List[ComplianceControl] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    total_controls: int = 0
    applicable: bool = True
    scope_notes: str = ""
    last_updated: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Serialize standard to dictionary."""
        return {
            "framework_id": self.framework_id,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "authority": self.authority,
            "url": self.url,
            "controls": [c.to_dict() for c in self.controls],
            "categories": list(self.categories),
            "total_controls": self.total_controls,
            "applicable": self.applicable,
            "scope_notes": self.scope_notes,
            "last_updated": self.last_updated,
        }

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> ComplianceStandard:
        """Deserialize standard from dictionary."""
        return ComplianceStandard(
            framework_id=data.get("framework_id", ""),
            name=data.get("name", ""),
            version=data.get("version", ""),
            description=data.get("description", ""),
            authority=data.get("authority", ""),
            url=data.get("url", ""),
            controls=[ComplianceControl.from_dict(c) for c in data.get("controls", [])],
            categories=data.get("categories", []),
            total_controls=data.get("total_controls", 0),
            applicable=data.get("applicable", True),
            scope_notes=data.get("scope_notes", ""),
            last_updated=data.get("last_updated", 0.0),
        )

    def get_control(self, control_id: str) -> Optional[ComplianceControl]:
        """Lookup a control by its ID."""
        for ctrl in self.controls:
            if ctrl.control_id == control_id:
                return ctrl
        return None

    def get_controls_by_category(self, category: str) -> List[ComplianceControl]:
        """Return all controls in a given category."""
        return [c for c in self.controls if c.category == category]

    def get_violated_controls(self) -> List[ComplianceControl]:
        """Return controls marked as non-compliant."""
        return [c for c in self.controls if c.is_violated()]

    def get_compliance_percentage(self) -> float:
        """Calculate percentage of compliant controls."""
        assessed = [c for c in self.controls
                    if c.status not in (ComplianceStatus.NOT_ASSESSED.value,
                                        ComplianceStatus.NOT_APPLICABLE.value)]
        if not assessed:
            return 0.0
        compliant = sum(1 for c in assessed
                        if c.status == ComplianceStatus.COMPLIANT.value)
        return round((compliant / len(assessed)) * 100.0, 2)


@dataclass
class ComplianceGap:
    """
    Represents a gap between current security posture and compliance requirements.

    Attributes:
        gap_id:             Unique gap identifier (auto-generated hash).
        control:            The violated control.
        framework_id:       Framework this gap belongs to.
        finding_ids:        IDs of findings that caused this gap.
        vuln_types:         Vulnerability types that triggered the gap.
        severity:           Gap severity classification.
        title:              Human-readable gap title.
        description:        Detailed gap description.
        business_impact:    Expected business impact of the gap.
        remediation:        Recommended remediation steps.
        effort:             Estimated remediation effort.
        effort_hours_min:   Minimum estimated hours to remediate.
        effort_hours_max:   Maximum estimated hours to remediate.
        priority_score:     Computed priority score (higher = more urgent).
        deadline:           Recommended remediation deadline (timestamp).
        status:             Current gap status (open / remediated / accepted).
        assigned_to:        Team or person assigned.
        created_at:         When the gap was identified.
        updated_at:         Last update timestamp.
        evidence:           Audit evidence for this gap.
    """
    gap_id: str = ""
    control: Optional[ComplianceControl] = None
    framework_id: str = ""
    finding_ids: List[str] = field(default_factory=list)
    vuln_types: List[str] = field(default_factory=list)
    severity: str = GapSeverity.MEDIUM.value
    title: str = ""
    description: str = ""
    business_impact: str = ""
    remediation: str = ""
    effort: str = RemediationEffort.MEDIUM.value
    effort_hours_min: float = 16.0
    effort_hours_max: float = 40.0
    priority_score: float = 0.0
    deadline: float = 0.0
    status: str = "open"
    assigned_to: str = ""
    created_at: float = 0.0
    updated_at: float = 0.0
    evidence: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.gap_id:
            raw = f"{self.framework_id}:{self.title}:{time.time()}"
            self.gap_id = hashlib.sha256(raw.encode()).hexdigest()[:16]
        if not self.created_at:
            self.created_at = time.time()
        if not self.updated_at:
            self.updated_at = self.created_at
        self._compute_priority()

    def _compute_priority(self) -> None:
        """Calculate priority score based on severity and effort."""
        sev_w = _GAP_SEVERITY_WEIGHT.get(self.severity, 4.0)
        effort_range = _EFFORT_HOURS.get(self.effort, (16.0, 40.0))
        self.effort_hours_min = effort_range[0]
        self.effort_hours_max = effort_range[1]
        avg_effort = (effort_range[0] + effort_range[1]) / 2.0
        # Priority = severity / log2(effort+1) -- higher severity, lower effort = higher priority
        self.priority_score = round(sev_w / max(math.log2(avg_effort + 1), 0.1), 4)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize gap to dictionary."""
        return {
            "gap_id": self.gap_id,
            "control": self.control.to_dict() if self.control else None,
            "framework_id": self.framework_id,
            "finding_ids": list(self.finding_ids),
            "vuln_types": list(self.vuln_types),
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "business_impact": self.business_impact,
            "remediation": self.remediation,
            "effort": self.effort,
            "effort_hours_min": self.effort_hours_min,
            "effort_hours_max": self.effort_hours_max,
            "priority_score": self.priority_score,
            "deadline": self.deadline,
            "status": self.status,
            "assigned_to": self.assigned_to,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "evidence": list(self.evidence),
        }

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> ComplianceGap:
        """Deserialize gap from dictionary."""
        ctrl_data = data.get("control")
        ctrl = ComplianceControl.from_dict(ctrl_data) if ctrl_data else None
        gap = ComplianceGap(
            gap_id=data.get("gap_id", ""),
            control=ctrl,
            framework_id=data.get("framework_id", ""),
            finding_ids=data.get("finding_ids", []),
            vuln_types=data.get("vuln_types", []),
            severity=data.get("severity", GapSeverity.MEDIUM.value),
            title=data.get("title", ""),
            description=data.get("description", ""),
            business_impact=data.get("business_impact", ""),
            remediation=data.get("remediation", ""),
            effort=data.get("effort", RemediationEffort.MEDIUM.value),
            priority_score=data.get("priority_score", 0.0),
            deadline=data.get("deadline", 0.0),
            status=data.get("status", "open"),
            assigned_to=data.get("assigned_to", ""),
            created_at=data.get("created_at", 0.0),
            updated_at=data.get("updated_at", 0.0),
            evidence=data.get("evidence", []),
        )
        return gap


@dataclass
class ComplianceReport:
    """
    Aggregated compliance report across one or more frameworks.

    Attributes:
        report_id:          Unique report identifier.
        title:              Report title.
        target:             Target system / application name.
        scope:              Assessment scope description.
        generated_at:       Report generation timestamp.
        frameworks:         Frameworks included in this report.
        gaps:               All identified compliance gaps.
        findings_mapped:    Total findings mapped to controls.
        findings_unmapped:  Findings with no control mapping.
        overall_score:      Weighted overall compliance score (0-100).
        framework_scores:   Per-framework compliance scores.
        executive_summary:  Auto-generated executive summary.
        methodology:        Assessment methodology description.
        assessor:           Assessor identity.
        metadata:           Additional metadata.
    """
    report_id: str = ""
    title: str = ""
    target: str = ""
    scope: str = ""
    generated_at: float = 0.0
    frameworks: List[ComplianceStandard] = field(default_factory=list)
    gaps: List[ComplianceGap] = field(default_factory=list)
    findings_mapped: int = 0
    findings_unmapped: int = 0
    overall_score: float = 0.0
    framework_scores: Dict[str, float] = field(default_factory=dict)
    executive_summary: str = ""
    methodology: str = ""
    assessor: str = "SIREN Compliance Mapper"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.report_id:
            self.report_id = uuid.uuid4().hex[:16]
        if not self.generated_at:
            self.generated_at = time.time()

    def to_dict(self) -> Dict[str, Any]:
        """Serialize report to dictionary."""
        return {
            "report_id": self.report_id,
            "title": self.title,
            "target": self.target,
            "scope": self.scope,
            "generated_at": self.generated_at,
            "frameworks": [f.to_dict() for f in self.frameworks],
            "gaps": [g.to_dict() for g in self.gaps],
            "findings_mapped": self.findings_mapped,
            "findings_unmapped": self.findings_unmapped,
            "overall_score": self.overall_score,
            "framework_scores": dict(self.framework_scores),
            "executive_summary": self.executive_summary,
            "methodology": self.methodology,
            "assessor": self.assessor,
            "metadata": dict(self.metadata),
        }

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> ComplianceReport:
        """Deserialize report from dictionary."""
        return ComplianceReport(
            report_id=data.get("report_id", ""),
            title=data.get("title", ""),
            target=data.get("target", ""),
            scope=data.get("scope", ""),
            generated_at=data.get("generated_at", 0.0),
            frameworks=[ComplianceStandard.from_dict(f) for f in data.get("frameworks", [])],
            gaps=[ComplianceGap.from_dict(g) for g in data.get("gaps", [])],
            findings_mapped=data.get("findings_mapped", 0),
            findings_unmapped=data.get("findings_unmapped", 0),
            overall_score=data.get("overall_score", 0.0),
            framework_scores=data.get("framework_scores", {}),
            executive_summary=data.get("executive_summary", ""),
            methodology=data.get("methodology", ""),
            assessor=data.get("assessor", "SIREN Compliance Mapper"),
            metadata=data.get("metadata", {}),
        )

    def get_critical_gaps(self) -> List[ComplianceGap]:
        """Return only critical-severity gaps."""
        return [g for g in self.gaps if g.severity == GapSeverity.CRITICAL.value]

    def get_high_gaps(self) -> List[ComplianceGap]:
        """Return only high-severity gaps."""
        return [g for g in self.gaps if g.severity == GapSeverity.HIGH.value]

    def get_gaps_by_framework(self, framework_id: str) -> List[ComplianceGap]:
        """Return gaps for a specific framework."""
        return [g for g in self.gaps if g.framework_id == framework_id]

    def get_open_gaps(self) -> List[ComplianceGap]:
        """Return only open (unremediated) gaps."""
        return [g for g in self.gaps if g.status == "open"]

    def count_by_severity(self) -> Dict[str, int]:
        """Count gaps grouped by severity."""
        counts: Dict[str, int] = defaultdict(int)
        for gap in self.gaps:
            counts[gap.severity] += 1
        return dict(counts)

    def total_effort_hours(self) -> Tuple[float, float]:
        """Calculate total remediation effort range across all open gaps."""
        min_h = sum(g.effort_hours_min for g in self.gaps if g.status == "open")
        max_h = sum(g.effort_hours_max for g in self.gaps if g.status == "open")
        return (round(min_h, 1), round(max_h, 1))

    def to_markdown(self) -> str:
        """Generate a full Markdown compliance report."""
        lines: List[str] = []

        # Header
        lines.append("# SIREN Compliance Report")
        lines.append("")
        lines.append(f"**Report ID:** `{self.report_id}`")
        lines.append(f"**Target:** {self.target}")
        lines.append(f"**Scope:** {self.scope}")
        lines.append(f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(self.generated_at))}")
        lines.append(f"**Assessor:** {self.assessor}")
        lines.append("")

        # Executive summary
        lines.append("## Executive Summary")
        lines.append("")
        if self.executive_summary:
            lines.append(self.executive_summary)
        else:
            lines.append("_No executive summary generated._")
        lines.append("")

        # Overall score
        lines.append("## Overall Compliance Score")
        lines.append("")
        lines.append(f"**Overall Score: {self.overall_score:.1f}%**")
        lines.append("")

        # Framework scores table
        if self.framework_scores:
            lines.append("### Per-Framework Scores")
            lines.append("")
            lines.append("| Framework | Score | Status |")
            lines.append("|-----------|-------|--------|")
            for fw_id, score in sorted(self.framework_scores.items()):
                status_icon = "PASS" if score >= 80.0 else ("WARN" if score >= 50.0 else "FAIL")
                lines.append(f"| {fw_id} | {score:.1f}% | {status_icon} |")
            lines.append("")

        # Gap summary
        sev_counts = self.count_by_severity()
        lines.append("## Gap Summary")
        lines.append("")
        lines.append(f"- **Total Gaps:** {len(self.gaps)}")
        lines.append(f"- **Critical:** {sev_counts.get(GapSeverity.CRITICAL.value, 0)}")
        lines.append(f"- **High:** {sev_counts.get(GapSeverity.HIGH.value, 0)}")
        lines.append(f"- **Medium:** {sev_counts.get(GapSeverity.MEDIUM.value, 0)}")
        lines.append(f"- **Low:** {sev_counts.get(GapSeverity.LOW.value, 0)}")
        lines.append(f"- **Findings Mapped:** {self.findings_mapped}")
        lines.append(f"- **Findings Unmapped:** {self.findings_unmapped}")
        effort = self.total_effort_hours()
        lines.append(f"- **Estimated Remediation Effort:** {effort[0]:.0f} - {effort[1]:.0f} hours")
        lines.append("")

        # Detailed gaps by framework
        lines.append("## Detailed Gaps by Framework")
        lines.append("")

        frameworks_with_gaps: Dict[str, List[ComplianceGap]] = defaultdict(list)
        for gap in self.gaps:
            frameworks_with_gaps[gap.framework_id].append(gap)

        for fw_id in sorted(frameworks_with_gaps.keys()):
            fw_gaps = frameworks_with_gaps[fw_id]
            fw_gaps.sort(key=lambda g: _GAP_SEVERITY_WEIGHT.get(g.severity, 0), reverse=True)
            lines.append(f"### {fw_id}")
            lines.append("")
            lines.append("| # | Severity | Control | Title | Effort | Priority |")
            lines.append("|---|----------|---------|-------|--------|----------|")
            for idx, gap in enumerate(fw_gaps, 1):
                ctrl_id = gap.control.control_id if gap.control else "N/A"
                lines.append(
                    f"| {idx} | {gap.severity} | {ctrl_id} | "
                    f"{gap.title[:60]} | {gap.effort} | {gap.priority_score:.2f} |"
                )
            lines.append("")

        # Critical gaps detail
        critical = self.get_critical_gaps()
        if critical:
            lines.append("## Critical Gaps -- Immediate Action Required")
            lines.append("")
            for gap in critical:
                ctrl_id = gap.control.control_id if gap.control else "N/A"
                lines.append(f"### [{ctrl_id}] {gap.title}")
                lines.append("")
                lines.append(f"**Framework:** {gap.framework_id}")
                lines.append(f"**Severity:** {gap.severity}")
                lines.append(f"**Status:** {gap.status}")
                lines.append("")
                lines.append(f"**Description:** {gap.description}")
                lines.append("")
                lines.append(f"**Business Impact:** {gap.business_impact}")
                lines.append("")
                lines.append(f"**Remediation:** {gap.remediation}")
                lines.append("")
                lines.append(f"**Effort:** {gap.effort} ({gap.effort_hours_min:.0f}-{gap.effort_hours_max:.0f} hours)")
                lines.append("")
                if gap.finding_ids:
                    lines.append(f"**Related Findings:** {', '.join(gap.finding_ids[:10])}")
                    lines.append("")
                lines.append("---")
                lines.append("")

        # Methodology
        lines.append("## Methodology")
        lines.append("")
        if self.methodology:
            lines.append(self.methodology)
        else:
            lines.append(
                "This compliance assessment was performed by SIREN Compliance Mapper "
                "using automated vulnerability-to-control mapping across the selected "
                "regulatory frameworks.  Each finding is matched against the internal "
                "vulnerability-control knowledge base to identify violated controls "
                "and produce gap analysis with prioritized remediation guidance."
            )
        lines.append("")

        # Footer
        lines.append("---")
        lines.append("")
        lines.append("*Generated by SIREN Compliance Mapper -- Shannon Intelligence Recon & Exploitation Nexus*")

        return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# Vulnerability-to-Control Mapping Database
# ═══════════════════════════════════════════════════════════════════════════════
# Maps 30 vulnerability types to specific control IDs across 10 frameworks.
# Each entry: VulnType -> { FrameworkID -> [control_ids] }
# ═══════════════════════════════════════════════════════════════════════════════

_VULN_CONTROL_MAP: Dict[str, Dict[str, List[str]]] = {
    # -----------------------------------------------------------------------
    # 1. SQL_INJECTION
    # -----------------------------------------------------------------------
    VulnType.SQL_INJECTION.value: {
        FrameworkID.PCI_DSS_4.value: ["6.2.4", "6.3.1", "6.3.2", "11.3.1"],
        FrameworkID.OWASP_TOP10_2021.value: ["A03:2021"],
        FrameworkID.OWASP_API_2023.value: ["API8:2023"],
        FrameworkID.NIST_800_53.value: ["SI-10", "SI-16", "SA-11", "CA-8"],
        FrameworkID.CIS_V8.value: ["16.1", "16.2", "16.12"],
        FrameworkID.ISO_27001.value: ["A.8.26", "A.8.28"],
        FrameworkID.HIPAA.value: ["164.312(a)(1)", "164.312(a)(2)(iv)"],
        FrameworkID.SOC2.value: ["CC6.1", "CC7.1", "CC8.1"],
        FrameworkID.LGPD.value: ["Art.46", "Art.47"],
        FrameworkID.GDPR.value: ["Art.32(1)(a)", "Art.32(1)(b)"],
    },
    # -----------------------------------------------------------------------
    # 2. XSS_REFLECTED
    # -----------------------------------------------------------------------
    VulnType.XSS_REFLECTED.value: {
        FrameworkID.PCI_DSS_4.value: ["6.2.4", "6.3.2", "11.3.1"],
        FrameworkID.OWASP_TOP10_2021.value: ["A03:2021"],
        FrameworkID.OWASP_API_2023.value: ["API8:2023"],
        FrameworkID.NIST_800_53.value: ["SI-10", "SI-3", "SA-11"],
        FrameworkID.CIS_V8.value: ["16.1", "16.2"],
        FrameworkID.ISO_27001.value: ["A.8.26", "A.8.28"],
        FrameworkID.HIPAA.value: ["164.312(a)(1)"],
        FrameworkID.SOC2.value: ["CC6.1", "CC7.1"],
        FrameworkID.LGPD.value: ["Art.46"],
        FrameworkID.GDPR.value: ["Art.32(1)(a)"],
    },
    # -----------------------------------------------------------------------
    # 3. XSS_STORED
    # -----------------------------------------------------------------------
    VulnType.XSS_STORED.value: {
        FrameworkID.PCI_DSS_4.value: ["6.2.4", "6.3.2", "6.4.1", "11.3.1"],
        FrameworkID.OWASP_TOP10_2021.value: ["A03:2021"],
        FrameworkID.OWASP_API_2023.value: ["API8:2023"],
        FrameworkID.NIST_800_53.value: ["SI-10", "SI-3", "SA-11"],
        FrameworkID.CIS_V8.value: ["16.1", "16.2", "16.12"],
        FrameworkID.ISO_27001.value: ["A.8.26", "A.8.28"],
        FrameworkID.HIPAA.value: ["164.312(a)(1)", "164.312(e)(1)"],
        FrameworkID.SOC2.value: ["CC6.1", "CC7.1", "CC8.1"],
        FrameworkID.LGPD.value: ["Art.46", "Art.47"],
        FrameworkID.GDPR.value: ["Art.32(1)(a)", "Art.32(1)(b)"],
    },
    # -----------------------------------------------------------------------
    # 4. XSS_DOM
    # -----------------------------------------------------------------------
    VulnType.XSS_DOM.value: {
        FrameworkID.PCI_DSS_4.value: ["6.2.4", "6.3.2", "6.4.2"],
        FrameworkID.OWASP_TOP10_2021.value: ["A03:2021"],
        FrameworkID.OWASP_API_2023.value: ["API8:2023"],
        FrameworkID.NIST_800_53.value: ["SI-10", "SA-11"],
        FrameworkID.CIS_V8.value: ["16.1", "16.2"],
        FrameworkID.ISO_27001.value: ["A.8.26"],
        FrameworkID.HIPAA.value: ["164.312(a)(1)"],
        FrameworkID.SOC2.value: ["CC6.1", "CC7.1"],
        FrameworkID.LGPD.value: ["Art.46"],
        FrameworkID.GDPR.value: ["Art.32(1)(a)"],
    },
    # -----------------------------------------------------------------------
    # 5. CSRF
    # -----------------------------------------------------------------------
    VulnType.CSRF.value: {
        FrameworkID.PCI_DSS_4.value: ["6.2.4", "6.3.2"],
        FrameworkID.OWASP_TOP10_2021.value: ["A01:2021"],
        FrameworkID.OWASP_API_2023.value: ["API2:2023"],
        FrameworkID.NIST_800_53.value: ["SC-23", "SI-10"],
        FrameworkID.CIS_V8.value: ["16.1", "16.6"],
        FrameworkID.ISO_27001.value: ["A.8.26"],
        FrameworkID.HIPAA.value: ["164.312(a)(1)", "164.312(d)"],
        FrameworkID.SOC2.value: ["CC6.1"],
        FrameworkID.LGPD.value: ["Art.46"],
        FrameworkID.GDPR.value: ["Art.32(1)(a)"],
    },
    # -----------------------------------------------------------------------
    # 6. SSRF
    # -----------------------------------------------------------------------
    VulnType.SSRF.value: {
        FrameworkID.PCI_DSS_4.value: ["6.2.4", "6.3.1", "1.3.1"],
        FrameworkID.OWASP_TOP10_2021.value: ["A10:2021"],
        FrameworkID.OWASP_API_2023.value: ["API7:2023"],
        FrameworkID.NIST_800_53.value: ["SC-7", "SI-10", "CA-8"],
        FrameworkID.CIS_V8.value: ["13.4", "16.1"],
        FrameworkID.ISO_27001.value: ["A.8.20", "A.8.26"],
        FrameworkID.HIPAA.value: ["164.312(a)(1)", "164.312(e)(1)"],
        FrameworkID.SOC2.value: ["CC6.1", "CC6.6"],
        FrameworkID.LGPD.value: ["Art.46"],
        FrameworkID.GDPR.value: ["Art.32(1)(a)", "Art.32(1)(b)"],
    },
    # -----------------------------------------------------------------------
    # 7. XXE
    # -----------------------------------------------------------------------
    VulnType.XXE.value: {
        FrameworkID.PCI_DSS_4.value: ["6.2.4", "6.3.1"],
        FrameworkID.OWASP_TOP10_2021.value: ["A05:2021"],
        FrameworkID.OWASP_API_2023.value: ["API8:2023"],
        FrameworkID.NIST_800_53.value: ["SI-10", "SC-4"],
        FrameworkID.CIS_V8.value: ["16.1", "16.2"],
        FrameworkID.ISO_27001.value: ["A.8.26", "A.8.28"],
        FrameworkID.HIPAA.value: ["164.312(a)(1)"],
        FrameworkID.SOC2.value: ["CC6.1", "CC7.1"],
        FrameworkID.LGPD.value: ["Art.46"],
        FrameworkID.GDPR.value: ["Art.32(1)(a)"],
    },
    # -----------------------------------------------------------------------
    # 8. IDOR
    # -----------------------------------------------------------------------
    VulnType.IDOR.value: {
        FrameworkID.PCI_DSS_4.value: ["7.2.1", "7.2.2", "6.2.4"],
        FrameworkID.OWASP_TOP10_2021.value: ["A01:2021"],
        FrameworkID.OWASP_API_2023.value: ["API1:2023"],
        FrameworkID.NIST_800_53.value: ["AC-3", "AC-6", "AC-4"],
        FrameworkID.CIS_V8.value: ["3.3", "6.8"],
        FrameworkID.ISO_27001.value: ["A.8.3", "A.8.4"],
        FrameworkID.HIPAA.value: ["164.312(a)(1)", "164.312(d)"],
        FrameworkID.SOC2.value: ["CC6.1", "CC6.3"],
        FrameworkID.LGPD.value: ["Art.46", "Art.47"],
        FrameworkID.GDPR.value: ["Art.32(1)(b)", "Art.25(1)"],
    },
    # -----------------------------------------------------------------------
    # 9. BROKEN_AUTH
    # -----------------------------------------------------------------------
    VulnType.BROKEN_AUTH.value: {
        FrameworkID.PCI_DSS_4.value: ["8.2.1", "8.3.1", "8.3.6", "8.6.1"],
        FrameworkID.OWASP_TOP10_2021.value: ["A07:2021"],
        FrameworkID.OWASP_API_2023.value: ["API2:2023"],
        FrameworkID.NIST_800_53.value: ["IA-2", "IA-5", "IA-8", "AC-7"],
        FrameworkID.CIS_V8.value: ["5.2", "5.3", "5.4", "6.3"],
        FrameworkID.ISO_27001.value: ["A.8.5", "A.5.17"],
        FrameworkID.HIPAA.value: ["164.312(a)(2)(i)", "164.312(d)"],
        FrameworkID.SOC2.value: ["CC6.1", "CC6.2", "CC6.3"],
        FrameworkID.LGPD.value: ["Art.46", "Art.47"],
        FrameworkID.GDPR.value: ["Art.32(1)(a)", "Art.32(1)(d)"],
    },
    # -----------------------------------------------------------------------
    # 10. SESSION_FIXATION
    # -----------------------------------------------------------------------
    VulnType.SESSION_FIXATION.value: {
        FrameworkID.PCI_DSS_4.value: ["8.2.1", "6.2.4"],
        FrameworkID.OWASP_TOP10_2021.value: ["A07:2021"],
        FrameworkID.OWASP_API_2023.value: ["API2:2023"],
        FrameworkID.NIST_800_53.value: ["SC-23", "AC-12", "IA-5"],
        FrameworkID.CIS_V8.value: ["16.1", "16.6"],
        FrameworkID.ISO_27001.value: ["A.8.5", "A.8.26"],
        FrameworkID.HIPAA.value: ["164.312(a)(2)(i)", "164.312(d)"],
        FrameworkID.SOC2.value: ["CC6.1"],
        FrameworkID.LGPD.value: ["Art.46"],
        FrameworkID.GDPR.value: ["Art.32(1)(a)"],
    },
    # -----------------------------------------------------------------------
    # 11. WEAK_PASSWORD
    # -----------------------------------------------------------------------
    VulnType.WEAK_PASSWORD.value: {
        FrameworkID.PCI_DSS_4.value: ["8.3.6", "8.3.7", "8.3.9"],
        FrameworkID.OWASP_TOP10_2021.value: ["A07:2021"],
        FrameworkID.OWASP_API_2023.value: ["API2:2023"],
        FrameworkID.NIST_800_53.value: ["IA-5", "IA-5(1)"],
        FrameworkID.CIS_V8.value: ["5.2", "5.3"],
        FrameworkID.ISO_27001.value: ["A.5.17", "A.8.5"],
        FrameworkID.HIPAA.value: ["164.312(a)(2)(i)", "164.312(d)"],
        FrameworkID.SOC2.value: ["CC6.1", "CC6.2"],
        FrameworkID.LGPD.value: ["Art.46"],
        FrameworkID.GDPR.value: ["Art.32(1)(a)"],
    },
    # -----------------------------------------------------------------------
    # 12. SENSITIVE_DATA_EXPOSURE
    # -----------------------------------------------------------------------
    VulnType.SENSITIVE_DATA_EXPOSURE.value: {
        FrameworkID.PCI_DSS_4.value: ["3.4.1", "3.5.1", "4.2.1", "6.2.4"],
        FrameworkID.OWASP_TOP10_2021.value: ["A02:2021"],
        FrameworkID.OWASP_API_2023.value: ["API3:2023"],
        FrameworkID.NIST_800_53.value: ["SC-8", "SC-28", "MP-4", "SI-12"],
        FrameworkID.CIS_V8.value: ["3.6", "3.7", "3.10"],
        FrameworkID.ISO_27001.value: ["A.8.10", "A.8.11", "A.8.24"],
        FrameworkID.HIPAA.value: ["164.312(a)(2)(iv)", "164.312(e)(2)(ii)", "164.530(c)"],
        FrameworkID.SOC2.value: ["CC6.1", "CC6.5", "CC6.7"],
        FrameworkID.LGPD.value: ["Art.46", "Art.47", "Art.48"],
        FrameworkID.GDPR.value: ["Art.32(1)(a)", "Art.5(1)(f)", "Art.25(1)"],
    },
    # -----------------------------------------------------------------------
    # 13. INSECURE_DESERIALIZATION
    # -----------------------------------------------------------------------
    VulnType.INSECURE_DESERIALIZATION.value: {
        FrameworkID.PCI_DSS_4.value: ["6.2.4", "6.3.1", "6.3.2"],
        FrameworkID.OWASP_TOP10_2021.value: ["A08:2021"],
        FrameworkID.OWASP_API_2023.value: ["API8:2023"],
        FrameworkID.NIST_800_53.value: ["SI-10", "SI-7", "SA-11"],
        FrameworkID.CIS_V8.value: ["16.1", "16.12"],
        FrameworkID.ISO_27001.value: ["A.8.26", "A.8.28"],
        FrameworkID.HIPAA.value: ["164.312(a)(1)"],
        FrameworkID.SOC2.value: ["CC6.1", "CC8.1"],
        FrameworkID.LGPD.value: ["Art.46"],
        FrameworkID.GDPR.value: ["Art.32(1)(a)"],
    },
    # -----------------------------------------------------------------------
    # 14. SECURITY_MISCONFIGURATION
    # -----------------------------------------------------------------------
    VulnType.SECURITY_MISCONFIGURATION.value: {
        FrameworkID.PCI_DSS_4.value: ["2.2.1", "2.2.2", "6.2.4", "6.3.2"],
        FrameworkID.OWASP_TOP10_2021.value: ["A05:2021"],
        FrameworkID.OWASP_API_2023.value: ["API8:2023"],
        FrameworkID.NIST_800_53.value: ["CM-6", "CM-7", "CM-2", "SC-8"],
        FrameworkID.CIS_V8.value: ["4.1", "4.6", "4.8"],
        FrameworkID.ISO_27001.value: ["A.8.9", "A.8.19"],
        FrameworkID.HIPAA.value: ["164.312(a)(1)", "164.310(d)(1)"],
        FrameworkID.SOC2.value: ["CC6.1", "CC6.6", "CC7.1"],
        FrameworkID.LGPD.value: ["Art.46"],
        FrameworkID.GDPR.value: ["Art.32(1)(a)", "Art.32(1)(d)"],
    },
    # -----------------------------------------------------------------------
    # 15. BROKEN_ACCESS_CONTROL
    # -----------------------------------------------------------------------
    VulnType.BROKEN_ACCESS_CONTROL.value: {
        FrameworkID.PCI_DSS_4.value: ["7.2.1", "7.2.2", "7.2.5", "6.2.4"],
        FrameworkID.OWASP_TOP10_2021.value: ["A01:2021"],
        FrameworkID.OWASP_API_2023.value: ["API1:2023", "API5:2023"],
        FrameworkID.NIST_800_53.value: ["AC-3", "AC-6", "AC-2", "AC-4"],
        FrameworkID.CIS_V8.value: ["3.3", "5.4", "6.8"],
        FrameworkID.ISO_27001.value: ["A.5.15", "A.8.3", "A.8.4"],
        FrameworkID.HIPAA.value: ["164.312(a)(1)", "164.312(a)(2)(i)", "164.312(d)"],
        FrameworkID.SOC2.value: ["CC6.1", "CC6.2", "CC6.3"],
        FrameworkID.LGPD.value: ["Art.46", "Art.47"],
        FrameworkID.GDPR.value: ["Art.32(1)(b)", "Art.25(1)", "Art.25(2)"],
    },
    # -----------------------------------------------------------------------
    # 16. MISSING_ENCRYPTION
    # -----------------------------------------------------------------------
    VulnType.MISSING_ENCRYPTION.value: {
        FrameworkID.PCI_DSS_4.value: ["3.5.1", "4.2.1", "4.2.2"],
        FrameworkID.OWASP_TOP10_2021.value: ["A02:2021"],
        FrameworkID.OWASP_API_2023.value: ["API8:2023"],
        FrameworkID.NIST_800_53.value: ["SC-8", "SC-8(1)", "SC-13", "SC-28"],
        FrameworkID.CIS_V8.value: ["3.6", "3.7", "3.10"],
        FrameworkID.ISO_27001.value: ["A.8.24"],
        FrameworkID.HIPAA.value: ["164.312(a)(2)(iv)", "164.312(e)(2)(ii)"],
        FrameworkID.SOC2.value: ["CC6.1", "CC6.7"],
        FrameworkID.LGPD.value: ["Art.46", "Art.47"],
        FrameworkID.GDPR.value: ["Art.32(1)(a)", "Art.5(1)(f)"],
    },
    # -----------------------------------------------------------------------
    # 17. WEAK_CRYPTO
    # -----------------------------------------------------------------------
    VulnType.WEAK_CRYPTO.value: {
        FrameworkID.PCI_DSS_4.value: ["3.5.1", "4.2.1", "6.2.4"],
        FrameworkID.OWASP_TOP10_2021.value: ["A02:2021"],
        FrameworkID.OWASP_API_2023.value: ["API8:2023"],
        FrameworkID.NIST_800_53.value: ["SC-13", "SC-12", "SC-8"],
        FrameworkID.CIS_V8.value: ["3.6", "3.10"],
        FrameworkID.ISO_27001.value: ["A.8.24"],
        FrameworkID.HIPAA.value: ["164.312(a)(2)(iv)", "164.312(e)(2)(ii)"],
        FrameworkID.SOC2.value: ["CC6.1", "CC6.7"],
        FrameworkID.LGPD.value: ["Art.46"],
        FrameworkID.GDPR.value: ["Art.32(1)(a)"],
    },
    # -----------------------------------------------------------------------
    # 18. DIRECTORY_TRAVERSAL
    # -----------------------------------------------------------------------
    VulnType.DIRECTORY_TRAVERSAL.value: {
        FrameworkID.PCI_DSS_4.value: ["6.2.4", "6.3.1", "6.3.2"],
        FrameworkID.OWASP_TOP10_2021.value: ["A01:2021"],
        FrameworkID.OWASP_API_2023.value: ["API8:2023"],
        FrameworkID.NIST_800_53.value: ["AC-3", "SI-10", "CM-7"],
        FrameworkID.CIS_V8.value: ["3.3", "16.1"],
        FrameworkID.ISO_27001.value: ["A.8.3", "A.8.26"],
        FrameworkID.HIPAA.value: ["164.312(a)(1)"],
        FrameworkID.SOC2.value: ["CC6.1"],
        FrameworkID.LGPD.value: ["Art.46"],
        FrameworkID.GDPR.value: ["Art.32(1)(a)"],
    },
    # -----------------------------------------------------------------------
    # 19. COMMAND_INJECTION
    # -----------------------------------------------------------------------
    VulnType.COMMAND_INJECTION.value: {
        FrameworkID.PCI_DSS_4.value: ["6.2.4", "6.3.1", "6.3.2", "11.3.1"],
        FrameworkID.OWASP_TOP10_2021.value: ["A03:2021"],
        FrameworkID.OWASP_API_2023.value: ["API8:2023"],
        FrameworkID.NIST_800_53.value: ["SI-10", "SI-3", "SA-11", "CA-8"],
        FrameworkID.CIS_V8.value: ["16.1", "16.2", "16.12"],
        FrameworkID.ISO_27001.value: ["A.8.26", "A.8.28"],
        FrameworkID.HIPAA.value: ["164.312(a)(1)", "164.312(a)(2)(iv)"],
        FrameworkID.SOC2.value: ["CC6.1", "CC7.1", "CC8.1"],
        FrameworkID.LGPD.value: ["Art.46", "Art.47"],
        FrameworkID.GDPR.value: ["Art.32(1)(a)", "Art.32(1)(b)"],
    },
    # -----------------------------------------------------------------------
    # 20. FILE_UPLOAD
    # -----------------------------------------------------------------------
    VulnType.FILE_UPLOAD.value: {
        FrameworkID.PCI_DSS_4.value: ["6.2.4", "6.3.1"],
        FrameworkID.OWASP_TOP10_2021.value: ["A04:2021"],
        FrameworkID.OWASP_API_2023.value: ["API4:2023", "API8:2023"],
        FrameworkID.NIST_800_53.value: ["SI-3", "SI-10", "CM-7"],
        FrameworkID.CIS_V8.value: ["16.1", "10.1"],
        FrameworkID.ISO_27001.value: ["A.8.23", "A.8.26"],
        FrameworkID.HIPAA.value: ["164.312(a)(1)"],
        FrameworkID.SOC2.value: ["CC6.1", "CC7.1"],
        FrameworkID.LGPD.value: ["Art.46"],
        FrameworkID.GDPR.value: ["Art.32(1)(a)"],
    },
    # -----------------------------------------------------------------------
    # 21. OPEN_REDIRECT
    # -----------------------------------------------------------------------
    VulnType.OPEN_REDIRECT.value: {
        FrameworkID.PCI_DSS_4.value: ["6.2.4"],
        FrameworkID.OWASP_TOP10_2021.value: ["A01:2021"],
        FrameworkID.OWASP_API_2023.value: ["API8:2023"],
        FrameworkID.NIST_800_53.value: ["SI-10", "SC-23"],
        FrameworkID.CIS_V8.value: ["16.1"],
        FrameworkID.ISO_27001.value: ["A.8.26"],
        FrameworkID.HIPAA.value: ["164.312(a)(1)"],
        FrameworkID.SOC2.value: ["CC6.1"],
        FrameworkID.LGPD.value: ["Art.46"],
        FrameworkID.GDPR.value: ["Art.32(1)(a)"],
    },
    # -----------------------------------------------------------------------
    # 22. CORS_MISCONFIGURATION
    # -----------------------------------------------------------------------
    VulnType.CORS_MISCONFIGURATION.value: {
        FrameworkID.PCI_DSS_4.value: ["6.2.4", "6.4.1"],
        FrameworkID.OWASP_TOP10_2021.value: ["A05:2021"],
        FrameworkID.OWASP_API_2023.value: ["API8:2023"],
        FrameworkID.NIST_800_53.value: ["SC-7", "AC-4"],
        FrameworkID.CIS_V8.value: ["4.8", "16.1"],
        FrameworkID.ISO_27001.value: ["A.8.9", "A.8.20"],
        FrameworkID.HIPAA.value: ["164.312(e)(1)"],
        FrameworkID.SOC2.value: ["CC6.1", "CC6.6"],
        FrameworkID.LGPD.value: ["Art.46"],
        FrameworkID.GDPR.value: ["Art.32(1)(a)"],
    },
    # -----------------------------------------------------------------------
    # 23. HTTP_HEADER_MISSING
    # -----------------------------------------------------------------------
    VulnType.HTTP_HEADER_MISSING.value: {
        FrameworkID.PCI_DSS_4.value: ["6.2.4", "6.4.2"],
        FrameworkID.OWASP_TOP10_2021.value: ["A05:2021"],
        FrameworkID.OWASP_API_2023.value: ["API8:2023"],
        FrameworkID.NIST_800_53.value: ["CM-6", "SC-8"],
        FrameworkID.CIS_V8.value: ["4.1", "4.8"],
        FrameworkID.ISO_27001.value: ["A.8.9"],
        FrameworkID.HIPAA.value: ["164.312(a)(1)"],
        FrameworkID.SOC2.value: ["CC6.1"],
        FrameworkID.LGPD.value: ["Art.46"],
        FrameworkID.GDPR.value: ["Art.32(1)(a)"],
    },
    # -----------------------------------------------------------------------
    # 24. INFORMATION_DISCLOSURE
    # -----------------------------------------------------------------------
    VulnType.INFORMATION_DISCLOSURE.value: {
        FrameworkID.PCI_DSS_4.value: ["3.4.1", "6.2.4", "6.5.4"],
        FrameworkID.OWASP_TOP10_2021.value: ["A01:2021"],
        FrameworkID.OWASP_API_2023.value: ["API3:2023"],
        FrameworkID.NIST_800_53.value: ["AC-3", "SI-11", "SC-28"],
        FrameworkID.CIS_V8.value: ["3.3", "3.12"],
        FrameworkID.ISO_27001.value: ["A.8.10", "A.8.11"],
        FrameworkID.HIPAA.value: ["164.312(a)(1)", "164.530(c)"],
        FrameworkID.SOC2.value: ["CC6.1", "CC6.5"],
        FrameworkID.LGPD.value: ["Art.46", "Art.48"],
        FrameworkID.GDPR.value: ["Art.5(1)(f)", "Art.32(1)(a)"],
    },
    # -----------------------------------------------------------------------
    # 25. RATE_LIMITING_ABSENT
    # -----------------------------------------------------------------------
    VulnType.RATE_LIMITING_ABSENT.value: {
        FrameworkID.PCI_DSS_4.value: ["6.2.4", "8.3.4"],
        FrameworkID.OWASP_TOP10_2021.value: ["A04:2021"],
        FrameworkID.OWASP_API_2023.value: ["API4:2023"],
        FrameworkID.NIST_800_53.value: ["SC-5", "AC-7", "SI-4"],
        FrameworkID.CIS_V8.value: ["13.8", "16.1"],
        FrameworkID.ISO_27001.value: ["A.8.16"],
        FrameworkID.HIPAA.value: ["164.312(a)(1)"],
        FrameworkID.SOC2.value: ["CC6.1", "CC7.2"],
        FrameworkID.LGPD.value: ["Art.46"],
        FrameworkID.GDPR.value: ["Art.32(1)(a)"],
    },
    # -----------------------------------------------------------------------
    # 26. MASS_ASSIGNMENT
    # -----------------------------------------------------------------------
    VulnType.MASS_ASSIGNMENT.value: {
        FrameworkID.PCI_DSS_4.value: ["6.2.4", "6.3.1"],
        FrameworkID.OWASP_TOP10_2021.value: ["A04:2021"],
        FrameworkID.OWASP_API_2023.value: ["API6:2023"],
        FrameworkID.NIST_800_53.value: ["AC-3", "SI-10", "CM-7"],
        FrameworkID.CIS_V8.value: ["16.1", "16.2"],
        FrameworkID.ISO_27001.value: ["A.8.26"],
        FrameworkID.HIPAA.value: ["164.312(a)(1)"],
        FrameworkID.SOC2.value: ["CC6.1"],
        FrameworkID.LGPD.value: ["Art.46"],
        FrameworkID.GDPR.value: ["Art.32(1)(a)"],
    },
    # -----------------------------------------------------------------------
    # 27. BOLA (Broken Object Level Authorization)
    # -----------------------------------------------------------------------
    VulnType.BOLA.value: {
        FrameworkID.PCI_DSS_4.value: ["7.2.1", "7.2.2", "6.2.4"],
        FrameworkID.OWASP_TOP10_2021.value: ["A01:2021"],
        FrameworkID.OWASP_API_2023.value: ["API1:2023"],
        FrameworkID.NIST_800_53.value: ["AC-3", "AC-6"],
        FrameworkID.CIS_V8.value: ["3.3", "6.8"],
        FrameworkID.ISO_27001.value: ["A.8.3", "A.8.4"],
        FrameworkID.HIPAA.value: ["164.312(a)(1)", "164.312(d)"],
        FrameworkID.SOC2.value: ["CC6.1", "CC6.3"],
        FrameworkID.LGPD.value: ["Art.46", "Art.47"],
        FrameworkID.GDPR.value: ["Art.32(1)(b)", "Art.25(1)"],
    },
    # -----------------------------------------------------------------------
    # 28. EXCESSIVE_DATA_EXPOSURE
    # -----------------------------------------------------------------------
    VulnType.EXCESSIVE_DATA_EXPOSURE.value: {
        FrameworkID.PCI_DSS_4.value: ["3.4.1", "3.5.1", "6.2.4"],
        FrameworkID.OWASP_TOP10_2021.value: ["A02:2021", "A01:2021"],
        FrameworkID.OWASP_API_2023.value: ["API3:2023"],
        FrameworkID.NIST_800_53.value: ["AC-3", "AC-4", "SC-28"],
        FrameworkID.CIS_V8.value: ["3.3", "3.12"],
        FrameworkID.ISO_27001.value: ["A.8.10", "A.8.11"],
        FrameworkID.HIPAA.value: ["164.312(a)(1)", "164.530(c)"],
        FrameworkID.SOC2.value: ["CC6.1", "CC6.5"],
        FrameworkID.LGPD.value: ["Art.46", "Art.47", "Art.48"],
        FrameworkID.GDPR.value: ["Art.5(1)(c)", "Art.5(1)(f)", "Art.25(2)"],
    },
    # -----------------------------------------------------------------------
    # 29. INSUFFICIENT_LOGGING
    # -----------------------------------------------------------------------
    VulnType.INSUFFICIENT_LOGGING.value: {
        FrameworkID.PCI_DSS_4.value: ["10.2.1", "10.2.2", "10.3.1", "10.4.1"],
        FrameworkID.OWASP_TOP10_2021.value: ["A09:2021"],
        FrameworkID.OWASP_API_2023.value: ["API9:2023"],
        FrameworkID.NIST_800_53.value: ["AU-2", "AU-3", "AU-6", "AU-12", "SI-4"],
        FrameworkID.CIS_V8.value: ["8.2", "8.5", "8.9"],
        FrameworkID.ISO_27001.value: ["A.8.15", "A.8.16"],
        FrameworkID.HIPAA.value: ["164.312(b)", "164.308(a)(1)(ii)(D)"],
        FrameworkID.SOC2.value: ["CC7.1", "CC7.2", "CC7.3"],
        FrameworkID.LGPD.value: ["Art.46", "Art.50"],
        FrameworkID.GDPR.value: ["Art.5(2)", "Art.30", "Art.33"],
    },
    # -----------------------------------------------------------------------
    # 30. SUPPLY_CHAIN
    # -----------------------------------------------------------------------
    VulnType.SUPPLY_CHAIN.value: {
        FrameworkID.PCI_DSS_4.value: ["6.3.2", "6.3.3", "12.8.1"],
        FrameworkID.OWASP_TOP10_2021.value: ["A06:2021"],
        FrameworkID.OWASP_API_2023.value: ["API10:2023"],
        FrameworkID.NIST_800_53.value: ["SA-12", "SR-3", "SR-5", "SA-11"],
        FrameworkID.CIS_V8.value: ["16.4", "16.5", "2.1"],
        FrameworkID.ISO_27001.value: ["A.5.19", "A.5.20", "A.5.21"],
        FrameworkID.HIPAA.value: ["164.308(b)(1)", "164.314(a)(1)"],
        FrameworkID.SOC2.value: ["CC3.4", "CC9.2"],
        FrameworkID.LGPD.value: ["Art.46", "Art.39"],
        FrameworkID.GDPR.value: ["Art.28", "Art.32(1)(a)"],
    },
}


# ═══════════════════════════════════════════════════════════════════════════════
# Standards Database -- Real control definitions
# ═══════════════════════════════════════════════════════════════════════════════
# _STANDARDS_DB: Dict[FrameworkID, dict]
# Each framework has: name, version, authority, url, description, categories,
# and controls dict mapping control_id -> { title, description, category,
#   sub_category, severity, remediation, references }
# ═══════════════════════════════════════════════════════════════════════════════

_STANDARDS_DB: Dict[str, Dict[str, Any]] = {}

# ---------------------------------------------------------------------------
# PCI-DSS v4.0
# ---------------------------------------------------------------------------
_STANDARDS_DB[FrameworkID.PCI_DSS_4.value] = {
    "name": "Payment Card Industry Data Security Standard",
    "version": "4.0",
    "authority": "PCI Security Standards Council",
    "url": "https://www.pcisecuritystandards.org/document_library/",
    "description": (
        "PCI DSS v4.0 provides the baseline of technical and operational "
        "requirements designed to protect payment account data."
    ),
    "categories": [
        "Build and Maintain a Secure Network",
        "Protect Account Data",
        "Maintain a Vulnerability Management Program",
        "Implement Strong Access Control",
        "Regularly Monitor and Test Networks",
        "Maintain an Information Security Policy",
    ],
    "controls": {
        "1.3.1": {
            "title": "Restrict inbound traffic to cardholder data environment",
            "description": (
                "Inbound traffic to the CDE is restricted to only necessary "
                "and authorized traffic, and all other traffic is denied."
            ),
            "category": "Build and Maintain a Secure Network",
            "sub_category": "Network Security Controls",
            "severity": Severity.HIGH.value,
            "remediation": (
                "Configure firewall and network ACLs to allow only authorized "
                "inbound connections. Deny all other traffic by default."
            ),
            "references": ["PCI DSS v4.0 Req 1.3.1"],
        },
        "2.2.1": {
            "title": "System configuration standards are maintained",
            "description": (
                "Configuration standards are developed, documented, and maintained "
                "for all system components, consistent with industry-accepted "
                "hardening standards."
            ),
            "category": "Build and Maintain a Secure Network",
            "sub_category": "Secure Configurations",
            "severity": Severity.MEDIUM.value,
            "remediation": (
                "Develop and apply CIS Benchmark hardening guides or equivalent "
                "for all system components. Review quarterly."
            ),
            "references": ["PCI DSS v4.0 Req 2.2.1"],
        },
        "2.2.2": {
            "title": "Vendor default accounts are managed",
            "description": (
                "Vendor default accounts are managed: removed, disabled, or "
                "changed before systems are deployed into production."
            ),
            "category": "Build and Maintain a Secure Network",
            "sub_category": "Secure Configurations",
            "severity": Severity.HIGH.value,
            "remediation": (
                "Disable or remove all vendor-supplied default accounts. Change "
                "default passwords on any account that cannot be removed."
            ),
            "references": ["PCI DSS v4.0 Req 2.2.2"],
        },
        "3.4.1": {
            "title": "PAN is rendered unreadable anywhere it is stored",
            "description": (
                "PAN is rendered unreadable using any of the approaches: one-way "
                "hashes, truncation, index tokens and pads, or strong cryptography."
            ),
            "category": "Protect Account Data",
            "sub_category": "Stored Account Data Protection",
            "severity": Severity.CRITICAL.value,
            "remediation": (
                "Encrypt all stored PAN with AES-256 or equivalent. Implement "
                "key management procedures per PCI DSS Requirement 3.6."
            ),
            "references": ["PCI DSS v4.0 Req 3.4.1"],
        },
        "3.5.1": {
            "title": "PAN is secured with strong cryptography during storage",
            "description": (
                "PAN is secured with strong cryptography wherever it is stored."
            ),
            "category": "Protect Account Data",
            "sub_category": "Stored Account Data Protection",
            "severity": Severity.CRITICAL.value,
            "remediation": (
                "Use AES-256, RSA-2048+, or equivalent to encrypt stored PAN. "
                "Ensure encryption keys are managed per industry standards."
            ),
            "references": ["PCI DSS v4.0 Req 3.5.1"],
        },
        "4.2.1": {
            "title": "Strong cryptography protects PAN during transmission",
            "description": (
                "PAN is protected with strong cryptography during transmission "
                "over open, public networks."
            ),
            "category": "Protect Account Data",
            "sub_category": "Encryption in Transit",
            "severity": Severity.CRITICAL.value,
            "remediation": (
                "Enforce TLS 1.2+ for all transmissions of PAN. Disable SSL and "
                "early TLS. Validate certificates."
            ),
            "references": ["PCI DSS v4.0 Req 4.2.1"],
        },
        "4.2.2": {
            "title": "PAN protected when transmitted via end-user messaging",
            "description": (
                "PAN is protected with strong cryptography when transmitted "
                "via end-user messaging technologies."
            ),
            "category": "Protect Account Data",
            "sub_category": "Encryption in Transit",
            "severity": Severity.HIGH.value,
            "remediation": (
                "Never transmit PAN via unencrypted messaging channels. "
                "Implement encryption or tokenization for messaging."
            ),
            "references": ["PCI DSS v4.0 Req 4.2.2"],
        },
        "6.2.4": {
            "title": "Software engineering techniques prevent common vulnerabilities",
            "description": (
                "Software engineering techniques or other methods are defined and "
                "in use to prevent or mitigate common software attacks and related "
                "vulnerabilities: injection, buffer overflow, insecure crypto, etc."
            ),
            "category": "Maintain a Vulnerability Management Program",
            "sub_category": "Secure Development",
            "severity": Severity.HIGH.value,
            "remediation": (
                "Implement secure coding standards addressing OWASP Top 10. "
                "Use parameterized queries, output encoding, and CSRF tokens."
            ),
            "references": ["PCI DSS v4.0 Req 6.2.4"],
        },
        "6.3.1": {
            "title": "Known security vulnerabilities are identified and managed",
            "description": (
                "Security vulnerabilities are identified and managed through "
                "a defined vulnerability management process."
            ),
            "category": "Maintain a Vulnerability Management Program",
            "sub_category": "Vulnerability Management",
            "severity": Severity.HIGH.value,
            "remediation": (
                "Establish a vulnerability identification program with regular "
                "scanning and patch management within defined SLAs."
            ),
            "references": ["PCI DSS v4.0 Req 6.3.1"],
        },
        "6.3.2": {
            "title": "Inventory of custom and third-party software is maintained",
            "description": (
                "An inventory of bespoke and custom software, and third-party "
                "software incorporated into bespoke and custom software, is "
                "maintained to facilitate vulnerability and patch management."
            ),
            "category": "Maintain a Vulnerability Management Program",
            "sub_category": "Software Inventory",
            "severity": Severity.MEDIUM.value,
            "remediation": (
                "Maintain an SBOM (Software Bill of Materials) for all custom "
                "applications. Monitor for new CVEs on all dependencies."
            ),
            "references": ["PCI DSS v4.0 Req 6.3.2"],
        },
        "6.3.3": {
            "title": "Security patches installed in a timely manner",
            "description": (
                "All applicable security patches and updates are installed "
                "within defined timeframes."
            ),
            "category": "Maintain a Vulnerability Management Program",
            "sub_category": "Patch Management",
            "severity": Severity.HIGH.value,
            "remediation": (
                "Apply critical patches within 30 days. Establish a patch "
                "management policy with documented exceptions."
            ),
            "references": ["PCI DSS v4.0 Req 6.3.3"],
        },
        "6.4.1": {
            "title": "Public-facing web apps protected against attacks",
            "description": (
                "For public-facing web applications, new threats and vulnerabilities "
                "are addressed on an ongoing basis and these applications are "
                "protected against known attacks."
            ),
            "category": "Maintain a Vulnerability Management Program",
            "sub_category": "Web Application Protection",
            "severity": Severity.HIGH.value,
            "remediation": (
                "Deploy a WAF in front of all public-facing web applications. "
                "Update WAF rules regularly to address new threats."
            ),
            "references": ["PCI DSS v4.0 Req 6.4.1"],
        },
        "6.4.2": {
            "title": "Public-facing web apps are reviewed with automated tools",
            "description": (
                "For public-facing web applications, an automated technical "
                "solution is deployed that continually detects and prevents "
                "web-based attacks."
            ),
            "category": "Maintain a Vulnerability Management Program",
            "sub_category": "Web Application Protection",
            "severity": Severity.MEDIUM.value,
            "remediation": (
                "Deploy DAST tools for regular automated scanning. Configure "
                "security headers and content security policies."
            ),
            "references": ["PCI DSS v4.0 Req 6.4.2"],
        },
        "6.5.4": {
            "title": "Roles and functions are separated in development environments",
            "description": (
                "Roles and functions are separated between production and "
                "pre-production environments to provide accountability."
            ),
            "category": "Maintain a Vulnerability Management Program",
            "sub_category": "Separation of Environments",
            "severity": Severity.MEDIUM.value,
            "remediation": (
                "Separate development, test, and production environments. Enforce "
                "access controls between environments."
            ),
            "references": ["PCI DSS v4.0 Req 6.5.4"],
        },
        "7.2.1": {
            "title": "Access control model is defined and includes all components",
            "description": (
                "An access control model is defined and includes granting access "
                "based on job classification and function."
            ),
            "category": "Implement Strong Access Control",
            "sub_category": "Access Control",
            "severity": Severity.HIGH.value,
            "remediation": (
                "Implement RBAC. Define and document access roles based on "
                "job functions. Apply principle of least privilege."
            ),
            "references": ["PCI DSS v4.0 Req 7.2.1"],
        },
        "7.2.2": {
            "title": "Access is assigned to users based on job classification",
            "description": (
                "Access is assigned to users, including privileged users, "
                "based on job classification and function."
            ),
            "category": "Implement Strong Access Control",
            "sub_category": "Access Control",
            "severity": Severity.HIGH.value,
            "remediation": (
                "Ensure all user accounts are provisioned based on documented "
                "role definitions. Review access quarterly."
            ),
            "references": ["PCI DSS v4.0 Req 7.2.2"],
        },
        "7.2.5": {
            "title": "All user accounts reviewed at least every six months",
            "description": (
                "All application and system accounts and related access "
                "privileges are reviewed at least every six months."
            ),
            "category": "Implement Strong Access Control",
            "sub_category": "Access Control",
            "severity": Severity.MEDIUM.value,
            "remediation": (
                "Conduct semi-annual access reviews. Remove or disable inactive "
                "and unnecessary accounts. Document review results."
            ),
            "references": ["PCI DSS v4.0 Req 7.2.5"],
        },
        "8.2.1": {
            "title": "All users are assigned a unique ID",
            "description": (
                "All users are assigned a unique ID before being allowed "
                "to access system components or cardholder data."
            ),
            "category": "Implement Strong Access Control",
            "sub_category": "Identification and Authentication",
            "severity": Severity.HIGH.value,
            "remediation": (
                "Assign unique user IDs. Prohibit shared/group accounts. "
                "Implement audit logging per user identity."
            ),
            "references": ["PCI DSS v4.0 Req 8.2.1"],
        },
        "8.3.1": {
            "title": "All user access authenticated with at least one factor",
            "description": (
                "All user access to system components is authenticated with "
                "at least one authentication factor: something you know, "
                "something you have, or something you are."
            ),
            "category": "Implement Strong Access Control",
            "sub_category": "Identification and Authentication",
            "severity": Severity.HIGH.value,
            "remediation": (
                "Enforce authentication for all system access. Implement MFA "
                "for remote access and administrative access."
            ),
            "references": ["PCI DSS v4.0 Req 8.3.1"],
        },
        "8.3.4": {
            "title": "Lockout mechanisms protect against brute force",
            "description": (
                "Invalid authentication attempts are limited by locking out "
                "the user ID after no more than 10 attempts."
            ),
            "category": "Implement Strong Access Control",
            "sub_category": "Identification and Authentication",
            "severity": Severity.MEDIUM.value,
            "remediation": (
                "Configure account lockout after 10 failed attempts. "
                "Set lockout duration to at least 30 minutes or until admin unlock."
            ),
            "references": ["PCI DSS v4.0 Req 8.3.4"],
        },
        "8.3.6": {
            "title": "Passwords/passphrases meet minimum complexity",
            "description": (
                "If passwords/passphrases are used as authentication factors, "
                "they meet minimum length of 12 characters (or 8 if the system "
                "does not support 12) and contain both numeric and alphabetic characters."
            ),
            "category": "Implement Strong Access Control",
            "sub_category": "Identification and Authentication",
            "severity": Severity.MEDIUM.value,
            "remediation": (
                "Enforce password policies: minimum 12 characters, "
                "mix of alphanumeric, no common patterns."
            ),
            "references": ["PCI DSS v4.0 Req 8.3.6"],
        },
        "8.3.7": {
            "title": "Password history prevents reuse of last four passwords",
            "description": (
                "Individuals are not allowed to submit a new password/passphrase "
                "that is the same as any of the last four used."
            ),
            "category": "Implement Strong Access Control",
            "sub_category": "Identification and Authentication",
            "severity": Severity.LOW.value,
            "remediation": "Configure password history to remember at least 4 passwords.",
            "references": ["PCI DSS v4.0 Req 8.3.7"],
        },
        "8.3.9": {
            "title": "Passwords changed at least once every 90 days",
            "description": (
                "If passwords/passphrases are used, they are changed at least "
                "once every 90 days, OR access is dynamically analyzed."
            ),
            "category": "Implement Strong Access Control",
            "sub_category": "Identification and Authentication",
            "severity": Severity.LOW.value,
            "remediation": (
                "Enforce 90-day password rotation or implement dynamic analysis "
                "of account activity to determine access in real time."
            ),
            "references": ["PCI DSS v4.0 Req 8.3.9"],
        },
        "8.6.1": {
            "title": "System and application accounts managed interactively",
            "description": (
                "If accounts used by systems or applications can be used for "
                "interactive login, they are managed as follows: interactive "
                "use is prevented unless needed for exceptional circumstances."
            ),
            "category": "Implement Strong Access Control",
            "sub_category": "System Accounts",
            "severity": Severity.MEDIUM.value,
            "remediation": (
                "Disable interactive login for service accounts. Use sudo or "
                "PAM for necessary interactive access with logging."
            ),
            "references": ["PCI DSS v4.0 Req 8.6.1"],
        },
        "10.2.1": {
            "title": "Audit logs capture all individual user access",
            "description": (
                "Audit logs are enabled and active for all system components "
                "to capture all individual user accesses to cardholder data."
            ),
            "category": "Regularly Monitor and Test Networks",
            "sub_category": "Logging and Monitoring",
            "severity": Severity.HIGH.value,
            "remediation": (
                "Enable audit logging on all systems. Capture user ID, timestamp, "
                "event type, origination, and affected resource."
            ),
            "references": ["PCI DSS v4.0 Req 10.2.1"],
        },
        "10.2.2": {
            "title": "Audit logs capture all actions by privileged users",
            "description": (
                "Audit logs capture all actions taken by any individual with "
                "administrative access, including any interactive use of "
                "application or system accounts."
            ),
            "category": "Regularly Monitor and Test Networks",
            "sub_category": "Logging and Monitoring",
            "severity": Severity.HIGH.value,
            "remediation": (
                "Ensure all administrative actions are logged in tamper-resistant "
                "audit logs. Review admin activity daily."
            ),
            "references": ["PCI DSS v4.0 Req 10.2.2"],
        },
        "10.3.1": {
            "title": "Audit log entries include required information",
            "description": (
                "All audit log entries include: user identification, type of "
                "event, date and time, success or failure indication, origination "
                "of event, and identity or name of affected data/resource."
            ),
            "category": "Regularly Monitor and Test Networks",
            "sub_category": "Logging and Monitoring",
            "severity": Severity.MEDIUM.value,
            "remediation": (
                "Configure logging to include all required fields. Validate "
                "log format with sample entries across all systems."
            ),
            "references": ["PCI DSS v4.0 Req 10.3.1"],
        },
        "10.4.1": {
            "title": "Audit logs are reviewed at least once daily",
            "description": (
                "Audit logs are reviewed at least once daily to identify "
                "anomalies or suspicious activity."
            ),
            "category": "Regularly Monitor and Test Networks",
            "sub_category": "Logging and Monitoring",
            "severity": Severity.MEDIUM.value,
            "remediation": (
                "Implement automated log analysis with SIEM. Configure alerts "
                "for suspicious patterns. Conduct manual daily review."
            ),
            "references": ["PCI DSS v4.0 Req 10.4.1"],
        },
        "11.3.1": {
            "title": "Internal vulnerability scans performed quarterly",
            "description": (
                "Internal vulnerability scans are performed at least once "
                "every three months and after any significant change."
            ),
            "category": "Regularly Monitor and Test Networks",
            "sub_category": "Vulnerability Scanning",
            "severity": Severity.HIGH.value,
            "remediation": (
                "Schedule quarterly internal vulnerability scans. Rescan after "
                "significant changes. Remediate all high and critical findings."
            ),
            "references": ["PCI DSS v4.0 Req 11.3.1"],
        },
        "12.8.1": {
            "title": "List of TPSPs with which data is shared is maintained",
            "description": (
                "A list of all third-party service providers (TPSPs) with which "
                "account data is shared or that could affect the security of "
                "account data is maintained."
            ),
            "category": "Maintain an Information Security Policy",
            "sub_category": "Third-Party Management",
            "severity": Severity.MEDIUM.value,
            "remediation": (
                "Maintain a TPSP inventory. Conduct due diligence before "
                "onboarding. Review TPSPs annually."
            ),
            "references": ["PCI DSS v4.0 Req 12.8.1"],
        },
    },
}

# ---------------------------------------------------------------------------
# OWASP Top 10 2021
# ---------------------------------------------------------------------------
_STANDARDS_DB[FrameworkID.OWASP_TOP10_2021.value] = {
    "name": "OWASP Top 10 Web Application Security Risks",
    "version": "2021",
    "authority": "OWASP Foundation",
    "url": "https://owasp.org/Top10/",
    "description": (
        "The OWASP Top 10 is a standard awareness document representing a "
        "broad consensus about the most critical security risks to web applications."
    ),
    "categories": [
        "Access Control",
        "Cryptography",
        "Injection",
        "Insecure Design",
        "Security Misconfiguration",
        "Vulnerable Components",
        "Identification and Authentication",
        "Software and Data Integrity",
        "Logging and Monitoring",
        "Server-Side Request Forgery",
    ],
    "controls": {
        "A01:2021": {
            "title": "Broken Access Control",
            "description": (
                "Moving up from the fifth position, 94% of applications were "
                "tested for some form of broken access control with the average "
                "incidence rate of 3.81%."
            ),
            "category": "Access Control",
            "sub_category": "",
            "severity": Severity.CRITICAL.value,
            "remediation": (
                "Implement proper access controls: deny by default, enforce "
                "record ownership, disable directory listing, log failures, "
                "rate limit API, invalidate JWT after logout, apply CORS."
            ),
            "references": ["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],
        },
        "A02:2021": {
            "title": "Cryptographic Failures",
            "description": (
                "Shifting up one position, previously known as Sensitive Data "
                "Exposure.  Focus on failures related to cryptography (or lack thereof) "
                "which often lead to sensitive data exposure."
            ),
            "category": "Cryptography",
            "sub_category": "",
            "severity": Severity.CRITICAL.value,
            "remediation": (
                "Classify data; apply controls per classification. Do not store "
                "sensitive data unnecessarily. Encrypt all data in transit and at "
                "rest with strong algorithms. Disable caching for sensitive data."
            ),
            "references": ["https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"],
        },
        "A03:2021": {
            "title": "Injection",
            "description": (
                "Injection slides down to the third position. 94% of the "
                "applications were tested for some form of injection.  Includes "
                "SQL, NoSQL, OS, LDAP injection, XSS, and more."
            ),
            "category": "Injection",
            "sub_category": "",
            "severity": Severity.CRITICAL.value,
            "remediation": (
                "Use parameterized queries / prepared statements. Apply server-side "
                "input validation. Escape special characters. Use LIMIT in SQL "
                "to prevent mass disclosure. Use safe APIs."
            ),
            "references": ["https://owasp.org/Top10/A03_2021-Injection/"],
        },
        "A04:2021": {
            "title": "Insecure Design",
            "description": (
                "A new category for 2021 focusing on risks related to design "
                "and architectural flaws.  Calls for more use of threat modeling, "
                "secure design patterns, and reference architectures."
            ),
            "category": "Insecure Design",
            "sub_category": "",
            "severity": Severity.HIGH.value,
            "remediation": (
                "Establish secure development lifecycle. Use threat modeling. "
                "Integrate security in design phase.  Implement rate limiting, "
                "resource quotas, and plausibility checks."
            ),
            "references": ["https://owasp.org/Top10/A04_2021-Insecure_Design/"],
        },
        "A05:2021": {
            "title": "Security Misconfiguration",
            "description": (
                "Moving up from #6, 90% of applications were tested for some "
                "form of misconfiguration. With more shifts into highly "
                "configurable software, this category moves up."
            ),
            "category": "Security Misconfiguration",
            "sub_category": "",
            "severity": Severity.HIGH.value,
            "remediation": (
                "Implement repeatable hardening processes. Minimal platform "
                "without unnecessary features. Review and update configurations. "
                "Segmented application architecture. Send security directives."
            ),
            "references": ["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"],
        },
        "A06:2021": {
            "title": "Vulnerable and Outdated Components",
            "description": (
                "Previously titled Using Components with Known Vulnerabilities. "
                "Moved up from #9. Known issue with difficulty in testing and "
                "assessing risk. Only category without CVEs mapped to CWEs."
            ),
            "category": "Vulnerable Components",
            "sub_category": "",
            "severity": Severity.HIGH.value,
            "remediation": (
                "Remove unused dependencies and features. Continuously inventory "
                "component versions. Monitor CVE databases. Obtain components "
                "from official sources only. Monitor unmaintained libraries."
            ),
            "references": ["https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"],
        },
        "A07:2021": {
            "title": "Identification and Authentication Failures",
            "description": (
                "Previously Broken Authentication, this category slid down "
                "from the second position. Includes CWEs related to "
                "identification failures."
            ),
            "category": "Identification and Authentication",
            "sub_category": "",
            "severity": Severity.HIGH.value,
            "remediation": (
                "Implement MFA. Do not deploy with default credentials. "
                "Implement weak password checks. Harden password recovery. "
                "Limit failed login attempts. Use server-side session manager."
            ),
            "references": ["https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"],
        },
        "A08:2021": {
            "title": "Software and Data Integrity Failures",
            "description": (
                "A new category focusing on making assumptions related to "
                "software updates, critical data, and CI/CD pipelines without "
                "verifying integrity."
            ),
            "category": "Software and Data Integrity",
            "sub_category": "",
            "severity": Severity.HIGH.value,
            "remediation": (
                "Use digital signatures to verify software/data integrity. "
                "Ensure libraries are from trusted repos. Use SCA tools. "
                "Review CI/CD pipeline security."
            ),
            "references": ["https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"],
        },
        "A09:2021": {
            "title": "Security Logging and Monitoring Failures",
            "description": (
                "Previously Insufficient Logging & Monitoring, moved up "
                "from #10. This category helps detect, escalate, and "
                "respond to active breaches."
            ),
            "category": "Logging and Monitoring",
            "sub_category": "",
            "severity": Severity.MEDIUM.value,
            "remediation": (
                "Log all login, access control, and server-side validation "
                "failures with sufficient context. Ensure logs are in a format "
                "consumable by log management solutions. Set up alerting."
            ),
            "references": ["https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/"],
        },
        "A10:2021": {
            "title": "Server-Side Request Forgery (SSRF)",
            "description": (
                "Added from the Top 10 community survey (#1). SSRF flaws "
                "occur whenever a web application fetches a remote resource "
                "without validating the user-supplied URL."
            ),
            "category": "Server-Side Request Forgery",
            "sub_category": "",
            "severity": Severity.HIGH.value,
            "remediation": (
                "Sanitize and validate all client-supplied URLs. Enforce URL "
                "schemas, ports, and destinations with an allow list. Disable "
                "HTTP redirections. Do not send raw responses to clients."
            ),
            "references": ["https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"],
        },
    },
}

# ---------------------------------------------------------------------------
# OWASP API Security Top 10 2023
# ---------------------------------------------------------------------------
_STANDARDS_DB[FrameworkID.OWASP_API_2023.value] = {
    "name": "OWASP API Security Top 10",
    "version": "2023",
    "authority": "OWASP Foundation",
    "url": "https://owasp.org/API-Security/",
    "description": (
        "The OWASP API Security Top 10 focuses on the unique risks "
        "associated with APIs and microservices."
    ),
    "categories": [
        "Authorization",
        "Authentication",
        "Data Exposure",
        "Resource Consumption",
        "Function Level Authorization",
        "Mass Assignment",
        "Security Misconfiguration",
        "Injection",
        "Improper Asset Management",
        "Unsafe API Consumption",
    ],
    "controls": {
        "API1:2023": {
            "title": "Broken Object Level Authorization (BOLA)",
            "description": (
                "APIs tend to expose endpoints that handle object identifiers, "
                "creating a wide attack surface of object level access control issues."
            ),
            "category": "Authorization",
            "sub_category": "",
            "severity": Severity.CRITICAL.value,
            "remediation": (
                "Implement authorization checks at the object level for every "
                "function that accesses a data source using user input. Use "
                "random non-guessable IDs (UUIDs)."
            ),
            "references": ["https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"],
        },
        "API2:2023": {
            "title": "Broken Authentication",
            "description": (
                "Authentication mechanisms are often implemented incorrectly, "
                "allowing attackers to compromise authentication tokens or "
                "exploit flaws to assume other identities."
            ),
            "category": "Authentication",
            "sub_category": "",
            "severity": Severity.CRITICAL.value,
            "remediation": (
                "Use standard authentication mechanisms. Implement anti-brute "
                "force mechanisms.  Use short-lived tokens.  Implement MFA."
            ),
            "references": ["https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"],
        },
        "API3:2023": {
            "title": "Broken Object Property Level Authorization",
            "description": (
                "Lack of or improper authorization validation at the object "
                "property level. Leads to excessive data exposure or mass assignment."
            ),
            "category": "Data Exposure",
            "sub_category": "",
            "severity": Severity.HIGH.value,
            "remediation": (
                "Validate that the user has access to the specific object "
                "properties returned/modified. Return only necessary properties. "
                "Avoid generic to_json() or to_string() methods."
            ),
            "references": ["https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"],
        },
        "API4:2023": {
            "title": "Unrestricted Resource Consumption",
            "description": (
                "APIs do not restrict the size or number of resources that "
                "can be requested by the client, leading to DoS and cost overruns."
            ),
            "category": "Resource Consumption",
            "sub_category": "",
            "severity": Severity.HIGH.value,
            "remediation": (
                "Implement rate limiting and throttling. Set maximum data size "
                "for request parameters. Limit resource allocations per request."
            ),
            "references": ["https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/"],
        },
        "API5:2023": {
            "title": "Broken Function Level Authorization",
            "description": (
                "Complex access control policies with different hierarchies, "
                "groups, and roles, and an unclear separation between "
                "administrative and regular functions, tend to lead to flaws."
            ),
            "category": "Function Level Authorization",
            "sub_category": "",
            "severity": Severity.HIGH.value,
            "remediation": (
                "Enforce consistent authorization module. Deny all access by "
                "default. Ensure administrative endpoints enforce role checks."
            ),
            "references": ["https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/"],
        },
        "API6:2023": {
            "title": "Unrestricted Access to Sensitive Business Flows",
            "description": (
                "APIs vulnerable to this risk expose a business flow without "
                "compensating for the damage it would cause if used excessively "
                "in an automated manner."
            ),
            "category": "Mass Assignment",
            "sub_category": "",
            "severity": Severity.HIGH.value,
            "remediation": (
                "Identify business flows that could be abused. Implement "
                "device fingerprinting, CAPTCHA, and business-logic rate limiting."
            ),
            "references": ["https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/"],
        },
        "API7:2023": {
            "title": "Server Side Request Forgery",
            "description": (
                "SSRF flaws can occur when an API fetches a remote resource "
                "without validating the user-supplied URL."
            ),
            "category": "Security Misconfiguration",
            "sub_category": "",
            "severity": Severity.HIGH.value,
            "remediation": (
                "Validate and sanitize all user-supplied URLs. Use allow lists "
                "for remote resources. Disable unnecessary URL schemes."
            ),
            "references": ["https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/"],
        },
        "API8:2023": {
            "title": "Security Misconfiguration",
            "description": (
                "The API and supporting systems typically contain complex "
                "configurations meant to make them more customizable. "
                "Misconfigurations commonly happen at all levels."
            ),
            "category": "Security Misconfiguration",
            "sub_category": "",
            "severity": Severity.HIGH.value,
            "remediation": (
                "Implement repeatable hardening. Ensure proper CORS config. "
                "Disable unnecessary HTTP methods. Enforce TLS everywhere."
            ),
            "references": ["https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/"],
        },
        "API9:2023": {
            "title": "Improper Inventory Management",
            "description": (
                "APIs tend to expose more endpoints than traditional web apps, "
                "making proper documentation and inventory very important. "
                "Hosts and deployed API versions play a significant role."
            ),
            "category": "Improper Asset Management",
            "sub_category": "",
            "severity": Severity.MEDIUM.value,
            "remediation": (
                "Inventory all API hosts. Limit access to anything that should "
                "not be public. Retire old API versions. Document all endpoints."
            ),
            "references": ["https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"],
        },
        "API10:2023": {
            "title": "Unsafe Consumption of APIs",
            "description": (
                "Developers tend to trust data received from third-party APIs "
                "more than user input. Attackers target integrated third-party "
                "services to compromise APIs."
            ),
            "category": "Unsafe API Consumption",
            "sub_category": "",
            "severity": Severity.HIGH.value,
            "remediation": (
                "Validate data received from integrated APIs. Ensure interactions "
                "happen over encrypted channels. Apply the same input validation "
                "for third-party data as for user input."
            ),
            "references": ["https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/"],
        },
    },
}

# ---------------------------------------------------------------------------
# NIST SP 800-53 Rev 5 (selected controls)
# ---------------------------------------------------------------------------
_STANDARDS_DB[FrameworkID.NIST_800_53.value] = {
    "name": "NIST Special Publication 800-53 Revision 5",
    "version": "Rev 5",
    "authority": "National Institute of Standards and Technology",
    "url": "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
    "description": (
        "Security and Privacy Controls for Information Systems and Organizations. "
        "Comprehensive catalog of security and privacy controls for federal "
        "information systems."
    ),
    "categories": [
        "Access Control (AC)",
        "Audit and Accountability (AU)",
        "Configuration Management (CM)",
        "Identification and Authentication (IA)",
        "System and Communications Protection (SC)",
        "System and Information Integrity (SI)",
        "System and Services Acquisition (SA)",
        "Security Assessment and Authorization (CA)",
        "Supply Chain Risk Management (SR)",
        "Media Protection (MP)",
    ],
    "controls": {
        "AC-2": {
            "title": "Account Management",
            "description": "Define and enforce account management procedures including account types, conditions, and access authorization.",
            "category": "Access Control (AC)", "sub_category": "Account Management",
            "severity": Severity.HIGH.value,
            "remediation": "Implement automated account provisioning and deprovisioning. Enforce periodic access reviews.",
            "references": ["NIST SP 800-53 Rev 5 AC-2"],
        },
        "AC-3": {
            "title": "Access Enforcement",
            "description": "Enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.",
            "category": "Access Control (AC)", "sub_category": "Access Enforcement",
            "severity": Severity.CRITICAL.value,
            "remediation": "Implement RBAC/ABAC. Enforce authorization on every request. Apply least privilege principle.",
            "references": ["NIST SP 800-53 Rev 5 AC-3"],
        },
        "AC-4": {
            "title": "Information Flow Enforcement",
            "description": "Enforce approved authorizations for controlling the flow of information within the system and between connected systems.",
            "category": "Access Control (AC)", "sub_category": "Information Flow",
            "severity": Severity.HIGH.value,
            "remediation": "Implement network segmentation and data flow controls. Use DLP tools to prevent unauthorized data exfiltration.",
            "references": ["NIST SP 800-53 Rev 5 AC-4"],
        },
        "AC-6": {
            "title": "Least Privilege",
            "description": "Employ the principle of least privilege, allowing only authorized accesses for users (or processes) which are necessary to accomplish assigned organizational tasks.",
            "category": "Access Control (AC)", "sub_category": "Least Privilege",
            "severity": Severity.HIGH.value,
            "remediation": "Grant minimum required permissions. Review privilege assignments regularly. Use just-in-time access.",
            "references": ["NIST SP 800-53 Rev 5 AC-6"],
        },
        "AC-7": {
            "title": "Unsuccessful Logon Attempts",
            "description": "Enforce a limit of consecutive invalid logon attempts by a user during a defined time period and automatically lock the account.",
            "category": "Access Control (AC)", "sub_category": "Authentication",
            "severity": Severity.MEDIUM.value,
            "remediation": "Configure account lockout after repeated failed logins. Implement progressive delays.",
            "references": ["NIST SP 800-53 Rev 5 AC-7"],
        },
        "AC-12": {
            "title": "Session Termination",
            "description": "Automatically terminate a user session after defined conditions such as inactivity timeout.",
            "category": "Access Control (AC)", "sub_category": "Session Management",
            "severity": Severity.MEDIUM.value,
            "remediation": "Set session inactivity timeouts. Force re-authentication for sensitive operations.",
            "references": ["NIST SP 800-53 Rev 5 AC-12"],
        },
        "AU-2": {
            "title": "Event Logging",
            "description": "Identify events that the system is capable of logging in support of the audit function.",
            "category": "Audit and Accountability (AU)", "sub_category": "Event Logging",
            "severity": Severity.HIGH.value,
            "remediation": "Define auditable events. Enable logging for authentication, access control, and administrative actions.",
            "references": ["NIST SP 800-53 Rev 5 AU-2"],
        },
        "AU-3": {
            "title": "Content of Audit Records",
            "description": "Ensure audit records contain sufficient information to establish what occurred, when, where, the source, and outcome.",
            "category": "Audit and Accountability (AU)", "sub_category": "Audit Content",
            "severity": Severity.MEDIUM.value,
            "remediation": "Configure logs to include timestamp, source, event type, user identity, and outcome.",
            "references": ["NIST SP 800-53 Rev 5 AU-3"],
        },
        "AU-6": {
            "title": "Audit Record Review, Analysis, and Reporting",
            "description": "Review and analyze system audit records for indications of inappropriate or unusual activity and report findings.",
            "category": "Audit and Accountability (AU)", "sub_category": "Audit Analysis",
            "severity": Severity.MEDIUM.value,
            "remediation": "Implement SIEM. Set up automated alerting for anomalous patterns. Conduct regular log reviews.",
            "references": ["NIST SP 800-53 Rev 5 AU-6"],
        },
        "AU-12": {
            "title": "Audit Record Generation",
            "description": "Provide audit record generation capability for the set of auditable events at all system components.",
            "category": "Audit and Accountability (AU)", "sub_category": "Audit Generation",
            "severity": Severity.HIGH.value,
            "remediation": "Enable audit logging on all system components. Centralize log collection.",
            "references": ["NIST SP 800-53 Rev 5 AU-12"],
        },
        "CM-2": {
            "title": "Baseline Configuration",
            "description": "Develop, document, and maintain baseline configurations for the information system under configuration control.",
            "category": "Configuration Management (CM)", "sub_category": "Baseline",
            "severity": Severity.MEDIUM.value,
            "remediation": "Document system baselines. Use configuration management tools. Enforce drift detection.",
            "references": ["NIST SP 800-53 Rev 5 CM-2"],
        },
        "CM-6": {
            "title": "Configuration Settings",
            "description": "Establish and document configuration settings for IT products using security configuration checklists.",
            "category": "Configuration Management (CM)", "sub_category": "Settings",
            "severity": Severity.MEDIUM.value,
            "remediation": "Apply CIS Benchmarks or DISA STIGs. Automate configuration compliance checking.",
            "references": ["NIST SP 800-53 Rev 5 CM-6"],
        },
        "CM-7": {
            "title": "Least Functionality",
            "description": "Configure the system to provide only mission-essential capabilities and prohibit or restrict the use of non-essential functions.",
            "category": "Configuration Management (CM)", "sub_category": "Functionality",
            "severity": Severity.MEDIUM.value,
            "remediation": "Disable unnecessary services, ports, and protocols. Remove unused software.",
            "references": ["NIST SP 800-53 Rev 5 CM-7"],
        },
        "IA-2": {
            "title": "Identification and Authentication (Organizational Users)",
            "description": "Uniquely identify and authenticate organizational users and associate that identity with processes acting on behalf of those users.",
            "category": "Identification and Authentication (IA)", "sub_category": "User Authentication",
            "severity": Severity.HIGH.value,
            "remediation": "Enforce unique user IDs with MFA. Use centralized identity management (LDAP/SAML/OIDC).",
            "references": ["NIST SP 800-53 Rev 5 IA-2"],
        },
        "IA-5": {
            "title": "Authenticator Management",
            "description": "Manage system authenticators by verifying identity before issuing, establishing restrictions, and enforcing lifecycle management.",
            "category": "Identification and Authentication (IA)", "sub_category": "Authenticator Management",
            "severity": Severity.HIGH.value,
            "remediation": "Enforce strong password policies. Use credential vaults. Rotate secrets regularly.",
            "references": ["NIST SP 800-53 Rev 5 IA-5"],
        },
        "IA-5(1)": {
            "title": "Authenticator Management -- Password-Based Authentication",
            "description": "For password-based authentication, enforce minimum password complexity and change requirements.",
            "category": "Identification and Authentication (IA)", "sub_category": "Password Policy",
            "severity": Severity.MEDIUM.value,
            "remediation": "Enforce minimum 12-character passwords with complexity. Check against breached password databases.",
            "references": ["NIST SP 800-53 Rev 5 IA-5(1)"],
        },
        "IA-8": {
            "title": "Identification and Authentication (Non-Organizational Users)",
            "description": "Uniquely identify and authenticate non-organizational users or processes acting on behalf of non-organizational users.",
            "category": "Identification and Authentication (IA)", "sub_category": "External Auth",
            "severity": Severity.HIGH.value,
            "remediation": "Implement API key management, OAuth 2.0, or certificate-based auth for external users and services.",
            "references": ["NIST SP 800-53 Rev 5 IA-8"],
        },
        "MP-4": {
            "title": "Media Storage",
            "description": "Physically control and securely store system media within controlled areas and protect until destroyed or sanitized.",
            "category": "Media Protection (MP)", "sub_category": "Storage",
            "severity": Severity.MEDIUM.value,
            "remediation": "Encrypt stored media containing sensitive data. Implement physical access controls for media storage.",
            "references": ["NIST SP 800-53 Rev 5 MP-4"],
        },
        "SA-11": {
            "title": "Developer Testing and Evaluation",
            "description": "Require the developer to create and implement a security assessment plan including SAST, DAST, and penetration testing.",
            "category": "System and Services Acquisition (SA)", "sub_category": "Security Testing",
            "severity": Severity.HIGH.value,
            "remediation": "Integrate SAST/DAST into CI/CD pipeline. Conduct penetration tests before deployment.",
            "references": ["NIST SP 800-53 Rev 5 SA-11"],
        },
        "SA-12": {
            "title": "Supply Chain Protection",
            "description": "Protect against supply chain threats by employing security safeguards to manage supply chain risks.",
            "category": "System and Services Acquisition (SA)", "sub_category": "Supply Chain",
            "severity": Severity.HIGH.value,
            "remediation": "Verify integrity of software supply chain. Use SBOM. Validate third-party components.",
            "references": ["NIST SP 800-53 Rev 5 SA-12"],
        },
        "SC-4": {
            "title": "Information in Shared System Resources",
            "description": "Prevent unauthorized and unintended information transfer via shared system resources.",
            "category": "System and Communications Protection (SC)", "sub_category": "Shared Resources",
            "severity": Severity.MEDIUM.value,
            "remediation": "Clear shared memory after use. Implement process isolation. Use containers for workload separation.",
            "references": ["NIST SP 800-53 Rev 5 SC-4"],
        },
        "SC-5": {
            "title": "Denial-of-Service Protection",
            "description": "Protect against or limit the effects of denial-of-service attacks.",
            "category": "System and Communications Protection (SC)", "sub_category": "DoS Protection",
            "severity": Severity.MEDIUM.value,
            "remediation": "Implement rate limiting, load balancing, and CDN. Configure resource quotas.",
            "references": ["NIST SP 800-53 Rev 5 SC-5"],
        },
        "SC-7": {
            "title": "Boundary Protection",
            "description": "Monitor and control communications at external managed interfaces and key internal boundaries.",
            "category": "System and Communications Protection (SC)", "sub_category": "Boundary",
            "severity": Severity.HIGH.value,
            "remediation": "Deploy firewalls and IDS/IPS at network boundaries. Implement DMZ for public-facing services.",
            "references": ["NIST SP 800-53 Rev 5 SC-7"],
        },
        "SC-8": {
            "title": "Transmission Confidentiality and Integrity",
            "description": "Protect the confidentiality and integrity of transmitted information.",
            "category": "System and Communications Protection (SC)", "sub_category": "Transmission",
            "severity": Severity.HIGH.value,
            "remediation": "Enforce TLS 1.2+ for all transmissions. Use HSTS. Validate certificates.",
            "references": ["NIST SP 800-53 Rev 5 SC-8"],
        },
        "SC-8(1)": {
            "title": "Transmission Confidentiality -- Cryptographic Protection",
            "description": "Implement cryptographic mechanisms to prevent unauthorized disclosure during transmission.",
            "category": "System and Communications Protection (SC)", "sub_category": "Crypto in Transit",
            "severity": Severity.HIGH.value,
            "remediation": "Use TLS 1.2+ with strong cipher suites. Disable weak protocols.",
            "references": ["NIST SP 800-53 Rev 5 SC-8(1)"],
        },
        "SC-12": {
            "title": "Cryptographic Key Establishment and Management",
            "description": "Establish and manage cryptographic keys when cryptography is employed within the system.",
            "category": "System and Communications Protection (SC)", "sub_category": "Key Management",
            "severity": Severity.HIGH.value,
            "remediation": "Use HSMs or KMS for key storage. Rotate keys on schedule. Document key management procedures.",
            "references": ["NIST SP 800-53 Rev 5 SC-12"],
        },
        "SC-13": {
            "title": "Cryptographic Protection",
            "description": "Determine the required cryptographic protections and implement cryptography in accordance with applicable laws and policies.",
            "category": "System and Communications Protection (SC)", "sub_category": "Cryptography",
            "severity": Severity.HIGH.value,
            "remediation": "Use FIPS 140-validated cryptographic modules. Use AES-256, SHA-256+, RSA-2048+.",
            "references": ["NIST SP 800-53 Rev 5 SC-13"],
        },
        "SC-23": {
            "title": "Session Authenticity",
            "description": "Protect the authenticity of communications sessions to prevent hijacking, replay, and forgery.",
            "category": "System and Communications Protection (SC)", "sub_category": "Session",
            "severity": Severity.MEDIUM.value,
            "remediation": "Use anti-CSRF tokens. Implement secure session management. Rotate session IDs after login.",
            "references": ["NIST SP 800-53 Rev 5 SC-23"],
        },
        "SC-28": {
            "title": "Protection of Information at Rest",
            "description": "Protect the confidentiality and integrity of information at rest.",
            "category": "System and Communications Protection (SC)", "sub_category": "Data at Rest",
            "severity": Severity.HIGH.value,
            "remediation": "Encrypt sensitive data at rest with AES-256. Use full-disk encryption for storage media.",
            "references": ["NIST SP 800-53 Rev 5 SC-28"],
        },
        "SI-3": {
            "title": "Malicious Code Protection",
            "description": "Implement malicious code protection mechanisms at system entry and exit points.",
            "category": "System and Information Integrity (SI)", "sub_category": "Malware",
            "severity": Severity.HIGH.value,
            "remediation": "Deploy antimalware solutions. Scan uploads and downloads. Block execution from temp directories.",
            "references": ["NIST SP 800-53 Rev 5 SI-3"],
        },
        "SI-4": {
            "title": "System Monitoring",
            "description": "Monitor the system to detect attacks, unauthorized connections, and indicators of compromise.",
            "category": "System and Information Integrity (SI)", "sub_category": "Monitoring",
            "severity": Severity.HIGH.value,
            "remediation": "Deploy IDS/IPS, SIEM, and EDR. Monitor network traffic, system logs, and user activity.",
            "references": ["NIST SP 800-53 Rev 5 SI-4"],
        },
        "SI-7": {
            "title": "Software, Firmware, and Information Integrity",
            "description": "Employ integrity verification tools to detect unauthorized changes to software, firmware, and information.",
            "category": "System and Information Integrity (SI)", "sub_category": "Integrity",
            "severity": Severity.HIGH.value,
            "remediation": "Use file integrity monitoring (FIM). Verify checksums/signatures for software updates.",
            "references": ["NIST SP 800-53 Rev 5 SI-7"],
        },
        "SI-10": {
            "title": "Information Input Validation",
            "description": "Check the validity of information inputs to the system, including syntax, semantics, and data types.",
            "category": "System and Information Integrity (SI)", "sub_category": "Input Validation",
            "severity": Severity.HIGH.value,
            "remediation": "Implement server-side input validation. Use allow lists. Reject unexpected input types.",
            "references": ["NIST SP 800-53 Rev 5 SI-10"],
        },
        "SI-11": {
            "title": "Error Handling",
            "description": "Generate error messages that provide information necessary for corrective actions without revealing exploitable information.",
            "category": "System and Information Integrity (SI)", "sub_category": "Error Handling",
            "severity": Severity.MEDIUM.value,
            "remediation": "Implement generic error pages for users. Log detailed errors server-side only.",
            "references": ["NIST SP 800-53 Rev 5 SI-11"],
        },
        "SI-12": {
            "title": "Information Management and Retention",
            "description": "Manage and retain information within the system and information output in accordance with organizational policy.",
            "category": "System and Information Integrity (SI)", "sub_category": "Retention",
            "severity": Severity.MEDIUM.value,
            "remediation": "Define data retention policies. Implement automatic purging of expired data.",
            "references": ["NIST SP 800-53 Rev 5 SI-12"],
        },
        "SI-16": {
            "title": "Memory Protection",
            "description": "Implement security safeguards to protect the system memory from unauthorized code execution.",
            "category": "System and Information Integrity (SI)", "sub_category": "Memory",
            "severity": Severity.HIGH.value,
            "remediation": "Enable ASLR, DEP/NX, stack canaries. Use memory-safe languages where possible.",
            "references": ["NIST SP 800-53 Rev 5 SI-16"],
        },
        "SR-3": {
            "title": "Supply Chain Controls and Processes",
            "description": "Establish a process for identifying and addressing weaknesses or deficiencies in the supply chain.",
            "category": "Supply Chain Risk Management (SR)", "sub_category": "Controls",
            "severity": Severity.MEDIUM.value,
            "remediation": "Implement supply chain risk assessments. Verify component provenance and integrity.",
            "references": ["NIST SP 800-53 Rev 5 SR-3"],
        },
        "SR-5": {
            "title": "Acquisition Strategies, Tools, and Methods",
            "description": "Employ acquisition strategies, contract tools, and procurement methods to protect against supply chain risks.",
            "category": "Supply Chain Risk Management (SR)", "sub_category": "Acquisition",
            "severity": Severity.MEDIUM.value,
            "remediation": "Include security requirements in procurement contracts. Require vendor security assessments.",
            "references": ["NIST SP 800-53 Rev 5 SR-5"],
        },
        "CA-8": {
            "title": "Penetration Testing",
            "description": "Conduct penetration testing on defined systems at a defined frequency.",
            "category": "Security Assessment and Authorization (CA)", "sub_category": "Penetration Testing",
            "severity": Severity.HIGH.value,
            "remediation": "Conduct annual penetration tests. Retest after significant changes. Remediate all critical findings.",
            "references": ["NIST SP 800-53 Rev 5 CA-8"],
        },
    },
}

# ---------------------------------------------------------------------------
# CIS Controls v8
# ---------------------------------------------------------------------------
_STANDARDS_DB[FrameworkID.CIS_V8.value] = {
    "name": "CIS Critical Security Controls",
    "version": "8.0",
    "authority": "Center for Internet Security",
    "url": "https://www.cisecurity.org/controls/v8",
    "description": (
        "The CIS Controls are a prioritized set of actions that collectively "
        "form a defense-in-depth set of best practices to mitigate the most "
        "common attacks against systems and networks."
    ),
    "categories": [
        "Inventory and Control of Enterprise Assets",
        "Inventory and Control of Software Assets",
        "Data Protection",
        "Secure Configuration",
        "Account Management",
        "Access Control Management",
        "Continuous Vulnerability Management",
        "Audit Log Management",
        "Email and Web Browser Protections",
        "Malware Defenses",
        "Data Recovery",
        "Network Infrastructure Management",
        "Network Monitoring and Defense",
        "Security Awareness and Skills Training",
        "Service Provider Management",
        "Application Software Security",
        "Incident Response Management",
        "Penetration Testing",
    ],
    "controls": {
        "2.1": {
            "title": "Establish and Maintain a Software Inventory",
            "description": "Establish and maintain a detailed inventory of all licensed software installed on enterprise assets.",
            "category": "Inventory and Control of Software Assets", "sub_category": "Software Inventory",
            "severity": Severity.MEDIUM.value,
            "remediation": "Deploy software inventory tools. Maintain SBOM for custom applications.",
            "references": ["CIS Controls v8 2.1"],
        },
        "3.3": {
            "title": "Configure Data Access Control Lists",
            "description": "Configure data access control lists based on a user's need to know, applying least privilege.",
            "category": "Data Protection", "sub_category": "Access Control",
            "severity": Severity.HIGH.value,
            "remediation": "Implement RBAC. Apply least privilege. Review ACLs quarterly.",
            "references": ["CIS Controls v8 3.3"],
        },
        "3.6": {
            "title": "Encrypt Data on End-User Devices",
            "description": "Encrypt data on end-user devices containing sensitive data.",
            "category": "Data Protection", "sub_category": "Encryption",
            "severity": Severity.HIGH.value,
            "remediation": "Enable full-disk encryption (BitLocker, FileVault, LUKS). Encrypt sensitive files.",
            "references": ["CIS Controls v8 3.6"],
        },
        "3.7": {
            "title": "Establish and Maintain a Data Classification Scheme",
            "description": "Establish and maintain an overall data classification scheme for the enterprise.",
            "category": "Data Protection", "sub_category": "Classification",
            "severity": Severity.MEDIUM.value,
            "remediation": "Define classification tiers (Public, Internal, Confidential, Restricted). Label data accordingly.",
            "references": ["CIS Controls v8 3.7"],
        },
        "3.10": {
            "title": "Encrypt Sensitive Data in Transit",
            "description": "Encrypt sensitive data in transit using TLS 1.2 or higher.",
            "category": "Data Protection", "sub_category": "Encryption in Transit",
            "severity": Severity.HIGH.value,
            "remediation": "Enforce TLS 1.2+ everywhere. Use HSTS. Disable legacy SSL/TLS.",
            "references": ["CIS Controls v8 3.10"],
        },
        "3.12": {
            "title": "Segment Data Processing and Storage Based on Sensitivity",
            "description": "Segment data processing and storage based on the sensitivity of the data.",
            "category": "Data Protection", "sub_category": "Segmentation",
            "severity": Severity.MEDIUM.value,
            "remediation": "Isolate sensitive data in separate network segments. Apply encryption at storage level.",
            "references": ["CIS Controls v8 3.12"],
        },
        "4.1": {
            "title": "Establish and Maintain a Secure Configuration Process",
            "description": "Establish and maintain a secure configuration process for enterprise assets and software.",
            "category": "Secure Configuration", "sub_category": "Configuration Process",
            "severity": Severity.MEDIUM.value,
            "remediation": "Document secure baselines. Use CIS Benchmarks. Automate configuration compliance.",
            "references": ["CIS Controls v8 4.1"],
        },
        "4.6": {
            "title": "Securely Manage Enterprise Assets and Software",
            "description": "Securely manage enterprise assets and software including secure defaults and removal of unnecessary features.",
            "category": "Secure Configuration", "sub_category": "Hardening",
            "severity": Severity.MEDIUM.value,
            "remediation": "Remove unnecessary software and services. Disable default accounts. Apply hardening guides.",
            "references": ["CIS Controls v8 4.6"],
        },
        "4.8": {
            "title": "Uninstall or Disable Unnecessary Services",
            "description": "Uninstall or disable unnecessary services on enterprise assets and software.",
            "category": "Secure Configuration", "sub_category": "Service Hardening",
            "severity": Severity.MEDIUM.value,
            "remediation": "Audit running services. Disable unnecessary services. Close unused ports.",
            "references": ["CIS Controls v8 4.8"],
        },
        "5.2": {
            "title": "Use Unique Passwords",
            "description": "Use unique passwords for all enterprise assets. Do not share credentials across systems.",
            "category": "Account Management", "sub_category": "Password Management",
            "severity": Severity.HIGH.value,
            "remediation": "Enforce unique passwords per system. Deploy enterprise password manager.",
            "references": ["CIS Controls v8 5.2"],
        },
        "5.3": {
            "title": "Disable Dormant Accounts",
            "description": "Delete or disable any dormant accounts after a period of 45 days of inactivity.",
            "category": "Account Management", "sub_category": "Account Lifecycle",
            "severity": Severity.MEDIUM.value,
            "remediation": "Implement automated dormant account detection. Disable after 45 days inactivity.",
            "references": ["CIS Controls v8 5.3"],
        },
        "5.4": {
            "title": "Restrict Administrator Privileges to Dedicated Admin Accounts",
            "description": "Restrict administrator privileges to dedicated administrator accounts on enterprise assets.",
            "category": "Account Management", "sub_category": "Privileged Access",
            "severity": Severity.HIGH.value,
            "remediation": "Separate admin and regular user accounts. Use PAM solutions. Enforce just-in-time access.",
            "references": ["CIS Controls v8 5.4"],
        },
        "6.3": {
            "title": "Require MFA for Externally-Exposed Applications",
            "description": "Require all externally-exposed enterprise or third-party applications to enforce MFA.",
            "category": "Access Control Management", "sub_category": "MFA",
            "severity": Severity.HIGH.value,
            "remediation": "Enable MFA on all external-facing applications. Use TOTP, FIDO2, or push notifications.",
            "references": ["CIS Controls v8 6.3"],
        },
        "6.8": {
            "title": "Define and Maintain Role-Based Access Control",
            "description": "Define and maintain role-based access control for managing access to enterprise assets.",
            "category": "Access Control Management", "sub_category": "RBAC",
            "severity": Severity.HIGH.value,
            "remediation": "Document role definitions. Map roles to minimum required permissions. Review quarterly.",
            "references": ["CIS Controls v8 6.8"],
        },
        "8.2": {
            "title": "Collect Audit Logs",
            "description": "Collect audit logs. Ensure that logging is enabled for all enterprise assets.",
            "category": "Audit Log Management", "sub_category": "Log Collection",
            "severity": Severity.HIGH.value,
            "remediation": "Enable audit logging on all systems. Centralize with SIEM. Ensure tamper-proof storage.",
            "references": ["CIS Controls v8 8.2"],
        },
        "8.5": {
            "title": "Collect Detailed Audit Logs",
            "description": "Configure detailed audit logging for enterprise assets containing sensitive data.",
            "category": "Audit Log Management", "sub_category": "Detailed Logging",
            "severity": Severity.MEDIUM.value,
            "remediation": "Log all access to sensitive data. Include user, action, resource, timestamp.",
            "references": ["CIS Controls v8 8.5"],
        },
        "8.9": {
            "title": "Centralize Audit Logs",
            "description": "Centralize audit logs for review, storage, and analysis on security monitoring infrastructure.",
            "category": "Audit Log Management", "sub_category": "Centralization",
            "severity": Severity.MEDIUM.value,
            "remediation": "Forward all logs to a central SIEM. Retain for at least 90 days online, 1 year archived.",
            "references": ["CIS Controls v8 8.9"],
        },
        "10.1": {
            "title": "Deploy and Maintain Anti-Malware Software",
            "description": "Deploy and maintain anti-malware software on all enterprise assets.",
            "category": "Malware Defenses", "sub_category": "Anti-Malware",
            "severity": Severity.HIGH.value,
            "remediation": "Deploy EDR on all endpoints. Keep signatures current. Enable real-time scanning.",
            "references": ["CIS Controls v8 10.1"],
        },
        "13.4": {
            "title": "Perform Traffic Filtering Between Network Segments",
            "description": "Perform traffic filtering between network segments as appropriate.",
            "category": "Network Monitoring and Defense", "sub_category": "Traffic Filtering",
            "severity": Severity.HIGH.value,
            "remediation": "Implement firewall rules between segments. Apply default-deny policies.",
            "references": ["CIS Controls v8 13.4"],
        },
        "13.8": {
            "title": "Deploy a Network Intrusion Prevention Solution",
            "description": "Deploy a network intrusion prevention solution.",
            "category": "Network Monitoring and Defense", "sub_category": "IPS",
            "severity": Severity.MEDIUM.value,
            "remediation": "Deploy IPS inline on critical segments. Keep signatures current. Tune for false positives.",
            "references": ["CIS Controls v8 13.8"],
        },
        "16.1": {
            "title": "Establish and Maintain a Secure Application Development Process",
            "description": "Establish and maintain a secure application development process addressing secure coding, SAST/DAST, and code review.",
            "category": "Application Software Security", "sub_category": "Secure SDLC",
            "severity": Severity.HIGH.value,
            "remediation": "Implement SSDLC. Train developers. Integrate SAST/DAST in CI/CD.",
            "references": ["CIS Controls v8 16.1"],
        },
        "16.2": {
            "title": "Establish and Maintain a Process to Accept and Address Software Vulnerabilities",
            "description": "Establish and maintain a process to accept and address reports of software vulnerabilities.",
            "category": "Application Software Security", "sub_category": "Vulnerability Acceptance",
            "severity": Severity.MEDIUM.value,
            "remediation": "Publish vulnerability disclosure policy. Implement responsible disclosure program.",
            "references": ["CIS Controls v8 16.2"],
        },
        "16.4": {
            "title": "Establish and Manage an Inventory of Third-Party Software Components",
            "description": "Establish and manage an updated inventory of third-party components used in development.",
            "category": "Application Software Security", "sub_category": "Third-Party Components",
            "severity": Severity.MEDIUM.value,
            "remediation": "Generate and maintain SBOM. Scan dependencies with SCA tools.",
            "references": ["CIS Controls v8 16.4"],
        },
        "16.5": {
            "title": "Use Up-to-Date and Trusted Third-Party Software Components",
            "description": "Use up-to-date and trusted third-party software components and verify their integrity.",
            "category": "Application Software Security", "sub_category": "Component Integrity",
            "severity": Severity.HIGH.value,
            "remediation": "Pin dependency versions. Verify checksums. Monitor for CVEs in dependencies.",
            "references": ["CIS Controls v8 16.5"],
        },
        "16.6": {
            "title": "Establish and Maintain a Severity Rating System for Vulnerabilities",
            "description": "Establish and maintain a severity rating system and process for application vulnerabilities using CVSS or similar.",
            "category": "Application Software Security", "sub_category": "Severity Rating",
            "severity": Severity.MEDIUM.value,
            "remediation": "Use CVSS for severity ratings. Define SLAs per severity. Track remediation times.",
            "references": ["CIS Controls v8 16.6"],
        },
        "16.12": {
            "title": "Implement Code-Level Security Checks",
            "description": "Implement code-level security checks including static and dynamic analysis.",
            "category": "Application Software Security", "sub_category": "Code Analysis",
            "severity": Severity.HIGH.value,
            "remediation": "Run SAST in CI/CD pipeline. Conduct DAST on staging. Fix all critical/high findings before release.",
            "references": ["CIS Controls v8 16.12"],
        },
    },
}

# ---------------------------------------------------------------------------
# ISO 27001:2022
# ---------------------------------------------------------------------------
_STANDARDS_DB[FrameworkID.ISO_27001.value] = {
    "name": "ISO/IEC 27001:2022 Information Security Management",
    "version": "2022",
    "authority": "International Organization for Standardization",
    "url": "https://www.iso.org/standard/27001",
    "description": (
        "ISO 27001 specifies requirements for establishing, implementing, "
        "maintaining and continually improving an information security "
        "management system (ISMS)."
    ),
    "categories": [
        "Organizational Controls",
        "People Controls",
        "Physical Controls",
        "Technological Controls",
    ],
    "controls": {
        "A.5.15": {
            "title": "Access Control",
            "description": "Rules to control physical and logical access to information and other associated assets shall be established and implemented based on business and information security requirements.",
            "category": "Organizational Controls", "sub_category": "Access",
            "severity": Severity.HIGH.value,
            "remediation": "Define and enforce access control policy. Implement RBAC with least privilege. Review access rights periodically.",
            "references": ["ISO 27001:2022 A.5.15"],
        },
        "A.5.17": {
            "title": "Authentication Information",
            "description": "Allocation and management of authentication information shall be controlled by a management process including advising users on appropriate handling.",
            "category": "Organizational Controls", "sub_category": "Authentication",
            "severity": Severity.HIGH.value,
            "remediation": "Enforce strong password policies. Implement MFA. Use centralized credential management.",
            "references": ["ISO 27001:2022 A.5.17"],
        },
        "A.5.19": {
            "title": "Information Security in Supplier Relationships",
            "description": "Processes and procedures shall be defined and implemented to manage the information security risks associated with the use of supplier products or services.",
            "category": "Organizational Controls", "sub_category": "Supplier Management",
            "severity": Severity.MEDIUM.value,
            "remediation": "Establish supplier security requirements. Conduct vendor risk assessments. Include security clauses in contracts.",
            "references": ["ISO 27001:2022 A.5.19"],
        },
        "A.5.20": {
            "title": "Addressing Information Security Within Supplier Agreements",
            "description": "Relevant information security requirements shall be established and agreed with each supplier based on the type of supplier relationship.",
            "category": "Organizational Controls", "sub_category": "Supplier Agreements",
            "severity": Severity.MEDIUM.value,
            "remediation": "Include data protection clauses, audit rights, and incident notification requirements in supplier agreements.",
            "references": ["ISO 27001:2022 A.5.20"],
        },
        "A.5.21": {
            "title": "Managing Information Security in the ICT Supply Chain",
            "description": "Processes and procedures shall be defined and implemented to manage information security risks associated with the ICT products and services supply chain.",
            "category": "Organizational Controls", "sub_category": "ICT Supply Chain",
            "severity": Severity.MEDIUM.value,
            "remediation": "Verify ICT component integrity. Maintain SBOM. Monitor supply chain threat intelligence.",
            "references": ["ISO 27001:2022 A.5.21"],
        },
        "A.8.3": {
            "title": "Information Access Restriction",
            "description": "Access to information and other associated assets shall be restricted in accordance with the established topic-specific policy on access control.",
            "category": "Technological Controls", "sub_category": "Access Restriction",
            "severity": Severity.HIGH.value,
            "remediation": "Implement object-level authorization. Validate user permissions on every data access request.",
            "references": ["ISO 27001:2022 A.8.3"],
        },
        "A.8.4": {
            "title": "Access to Source Code",
            "description": "Read and write access to source code, development tools and software libraries shall be appropriately managed.",
            "category": "Technological Controls", "sub_category": "Source Code",
            "severity": Severity.MEDIUM.value,
            "remediation": "Restrict repository access to authorized developers. Enforce code review before merge. Use branch protection rules.",
            "references": ["ISO 27001:2022 A.8.4"],
        },
        "A.8.5": {
            "title": "Secure Authentication",
            "description": "Secure authentication technologies and procedures shall be established and implemented based on information access restrictions and the topic-specific policy on access control.",
            "category": "Technological Controls", "sub_category": "Authentication",
            "severity": Severity.HIGH.value,
            "remediation": "Enforce MFA for all sensitive systems. Use OAuth 2.0/OIDC for federated auth. Implement session management best practices.",
            "references": ["ISO 27001:2022 A.8.5"],
        },
        "A.8.9": {
            "title": "Configuration Management",
            "description": "Configurations, including security configurations, of hardware, software, services and networks shall be established, documented, implemented, monitored and reviewed.",
            "category": "Technological Controls", "sub_category": "Configuration",
            "severity": Severity.MEDIUM.value,
            "remediation": "Document and enforce secure baselines. Use configuration management tools. Monitor for drift.",
            "references": ["ISO 27001:2022 A.8.9"],
        },
        "A.8.10": {
            "title": "Information Deletion",
            "description": "Information stored in information systems, devices or in any other storage media shall be deleted when no longer required.",
            "category": "Technological Controls", "sub_category": "Data Deletion",
            "severity": Severity.MEDIUM.value,
            "remediation": "Implement data retention and deletion policies. Automate deletion of expired data. Use secure erasure methods.",
            "references": ["ISO 27001:2022 A.8.10"],
        },
        "A.8.11": {
            "title": "Data Masking",
            "description": "Data masking shall be used in accordance with the topic-specific policy on access control and other related policies, and business requirements, taking into consideration applicable legislation.",
            "category": "Technological Controls", "sub_category": "Data Masking",
            "severity": Severity.MEDIUM.value,
            "remediation": "Mask sensitive data in non-production environments. Apply dynamic masking for limited-access views.",
            "references": ["ISO 27001:2022 A.8.11"],
        },
        "A.8.15": {
            "title": "Logging",
            "description": "Logs that record activities, exceptions, faults and other relevant events shall be produced, stored, protected and analysed.",
            "category": "Technological Controls", "sub_category": "Logging",
            "severity": Severity.HIGH.value,
            "remediation": "Enable comprehensive logging. Protect logs from tampering. Retain for compliance period. Analyze with SIEM.",
            "references": ["ISO 27001:2022 A.8.15"],
        },
        "A.8.16": {
            "title": "Monitoring Activities",
            "description": "Networks, systems and applications shall be monitored for anomalous behaviour and appropriate actions taken to evaluate potential information security incidents.",
            "category": "Technological Controls", "sub_category": "Monitoring",
            "severity": Severity.HIGH.value,
            "remediation": "Deploy IDS/IPS and SIEM. Set up anomaly detection alerts. Establish incident response procedures.",
            "references": ["ISO 27001:2022 A.8.16"],
        },
        "A.8.19": {
            "title": "Installation of Software on Operational Systems",
            "description": "Procedures and measures shall be implemented to securely manage software installation on operational systems.",
            "category": "Technological Controls", "sub_category": "Software Installation",
            "severity": Severity.MEDIUM.value,
            "remediation": "Restrict software installation to approved lists. Validate integrity before installation. Log all installations.",
            "references": ["ISO 27001:2022 A.8.19"],
        },
        "A.8.20": {
            "title": "Networks Security",
            "description": "Networks and network devices shall be secured, managed and controlled to protect information in systems and applications.",
            "category": "Technological Controls", "sub_category": "Network Security",
            "severity": Severity.HIGH.value,
            "remediation": "Segment networks. Apply firewall rules. Monitor network traffic. Use VPN for remote access.",
            "references": ["ISO 27001:2022 A.8.20"],
        },
        "A.8.23": {
            "title": "Web Filtering",
            "description": "Access to external websites shall be managed to reduce exposure to malicious content.",
            "category": "Technological Controls", "sub_category": "Web Filtering",
            "severity": Severity.MEDIUM.value,
            "remediation": "Deploy web proxy with URL filtering. Block known malicious categories. Monitor web traffic.",
            "references": ["ISO 27001:2022 A.8.23"],
        },
        "A.8.24": {
            "title": "Use of Cryptography",
            "description": "Rules for the effective use of cryptography, including cryptographic key management, shall be defined and implemented.",
            "category": "Technological Controls", "sub_category": "Cryptography",
            "severity": Severity.HIGH.value,
            "remediation": "Use approved algorithms (AES-256, RSA-2048+, SHA-256+). Implement key management lifecycle. Disable weak ciphers.",
            "references": ["ISO 27001:2022 A.8.24"],
        },
        "A.8.26": {
            "title": "Application Security Requirements",
            "description": "Information security requirements shall be identified, specified and approved when developing or acquiring applications.",
            "category": "Technological Controls", "sub_category": "Application Security",
            "severity": Severity.HIGH.value,
            "remediation": "Define security requirements in user stories. Conduct threat modeling. Integrate SAST/DAST in CI/CD pipeline.",
            "references": ["ISO 27001:2022 A.8.26"],
        },
        "A.8.28": {
            "title": "Secure Coding",
            "description": "Secure coding principles shall be applied to software development.",
            "category": "Technological Controls", "sub_category": "Secure Coding",
            "severity": Severity.HIGH.value,
            "remediation": "Follow OWASP secure coding guidelines. Use parameterized queries. Implement output encoding. Conduct code reviews.",
            "references": ["ISO 27001:2022 A.8.28"],
        },
    },
}

# ---------------------------------------------------------------------------
# HIPAA
# ---------------------------------------------------------------------------
_STANDARDS_DB[FrameworkID.HIPAA.value] = {
    "name": "Health Insurance Portability and Accountability Act",
    "version": "2013 Omnibus Rule",
    "authority": "U.S. Department of Health and Human Services",
    "url": "https://www.hhs.gov/hipaa/index.html",
    "description": (
        "HIPAA Security Rule establishes national standards to protect "
        "individuals' electronic personal health information (ePHI) that is "
        "created, received, used, or maintained by a covered entity."
    ),
    "categories": [
        "Administrative Safeguards",
        "Physical Safeguards",
        "Technical Safeguards",
        "Organizational Requirements",
        "Policies and Documentation",
    ],
    "controls": {
        "164.308(a)(1)(ii)(D)": {
            "title": "Information System Activity Review",
            "description": "Implement procedures to regularly review records of information system activity, such as audit logs, access reports, and security incident tracking reports.",
            "category": "Administrative Safeguards", "sub_category": "Activity Review",
            "severity": Severity.HIGH.value,
            "remediation": "Implement automated log review. Set up SIEM alerting. Conduct weekly audit log reviews.",
            "references": ["45 CFR 164.308(a)(1)(ii)(D)"],
        },
        "164.308(b)(1)": {
            "title": "Business Associate Contracts",
            "description": "A covered entity may permit a business associate to create, receive, maintain, or transmit ePHI on the covered entity's behalf only if the covered entity obtains satisfactory assurances that the BA will appropriately safeguard the information.",
            "category": "Organizational Requirements", "sub_category": "Business Associates",
            "severity": Severity.HIGH.value,
            "remediation": "Execute BAAs with all vendors handling ePHI. Include breach notification, security requirements, and audit provisions.",
            "references": ["45 CFR 164.308(b)(1)"],
        },
        "164.310(d)(1)": {
            "title": "Device and Media Controls",
            "description": "Implement policies and procedures that govern the receipt and removal of hardware and electronic media that contain ePHI.",
            "category": "Physical Safeguards", "sub_category": "Device Controls",
            "severity": Severity.MEDIUM.value,
            "remediation": "Track all devices containing ePHI. Encrypt portable devices. Sanitize media before disposal.",
            "references": ["45 CFR 164.310(d)(1)"],
        },
        "164.312(a)(1)": {
            "title": "Access Control",
            "description": "Implement technical policies and procedures for electronic information systems that maintain ePHI to allow access only to authorized persons or software programs.",
            "category": "Technical Safeguards", "sub_category": "Access Control",
            "severity": Severity.CRITICAL.value,
            "remediation": "Implement RBAC for ePHI systems. Enforce unique user IDs. Apply least privilege. Review access quarterly.",
            "references": ["45 CFR 164.312(a)(1)"],
        },
        "164.312(a)(2)(i)": {
            "title": "Unique User Identification",
            "description": "Assign a unique name and/or number for identifying and tracking user identity.",
            "category": "Technical Safeguards", "sub_category": "User Identification",
            "severity": Severity.HIGH.value,
            "remediation": "Assign unique user IDs to all users. Prohibit shared accounts for ePHI systems.",
            "references": ["45 CFR 164.312(a)(2)(i)"],
        },
        "164.312(a)(2)(iv)": {
            "title": "Encryption and Decryption",
            "description": "Implement a mechanism to encrypt and decrypt electronic protected health information.",
            "category": "Technical Safeguards", "sub_category": "Encryption",
            "severity": Severity.HIGH.value,
            "remediation": "Encrypt all ePHI at rest and in transit with AES-256. Implement key management procedures.",
            "references": ["45 CFR 164.312(a)(2)(iv)"],
        },
        "164.312(b)": {
            "title": "Audit Controls",
            "description": "Implement hardware, software, and/or procedural mechanisms that record and examine activity in information systems that contain or use ePHI.",
            "category": "Technical Safeguards", "sub_category": "Audit Controls",
            "severity": Severity.HIGH.value,
            "remediation": "Enable audit logging on all ePHI systems. Capture who, what, when, where for all access. Retain logs per policy.",
            "references": ["45 CFR 164.312(b)"],
        },
        "164.312(d)": {
            "title": "Person or Entity Authentication",
            "description": "Implement procedures to verify that a person or entity seeking access to ePHI is the one claimed.",
            "category": "Technical Safeguards", "sub_category": "Authentication",
            "severity": Severity.HIGH.value,
            "remediation": "Enforce MFA for ePHI access. Use certificate-based auth for system-to-system. Verify identity before granting access.",
            "references": ["45 CFR 164.312(d)"],
        },
        "164.312(e)(1)": {
            "title": "Transmission Security",
            "description": "Implement technical security measures to guard against unauthorized access to ePHI being transmitted over an electronic communications network.",
            "category": "Technical Safeguards", "sub_category": "Transmission Security",
            "severity": Severity.HIGH.value,
            "remediation": "Encrypt all ePHI in transit with TLS 1.2+. Use VPN for remote access. Disable legacy protocols.",
            "references": ["45 CFR 164.312(e)(1)"],
        },
        "164.312(e)(2)(ii)": {
            "title": "Encryption During Transmission",
            "description": "Implement a mechanism to encrypt electronic protected health information whenever deemed appropriate during transmission.",
            "category": "Technical Safeguards", "sub_category": "Encryption in Transit",
            "severity": Severity.HIGH.value,
            "remediation": "Use TLS 1.2+ for all ePHI transmissions. Disable SSLv3, TLS 1.0, TLS 1.1.",
            "references": ["45 CFR 164.312(e)(2)(ii)"],
        },
        "164.314(a)(1)": {
            "title": "Business Associate Contracts or Other Arrangements",
            "description": "The contract between covered entity and business associate must meet HIPAA requirements regarding use, disclosure, and safeguarding of ePHI.",
            "category": "Organizational Requirements", "sub_category": "BA Contracts",
            "severity": Severity.MEDIUM.value,
            "remediation": "Review all BA contracts for HIPAA compliance. Include breach notification, security requirements, and termination clauses.",
            "references": ["45 CFR 164.314(a)(1)"],
        },
        "164.530(c)": {
            "title": "Safeguards",
            "description": "A covered entity must have in place appropriate administrative, technical, and physical safeguards to protect the privacy of protected health information.",
            "category": "Policies and Documentation", "sub_category": "Privacy Safeguards",
            "severity": Severity.HIGH.value,
            "remediation": "Implement layered security controls. Conduct risk assessments annually. Train workforce on PHI handling.",
            "references": ["45 CFR 164.530(c)"],
        },
    },
}

# ---------------------------------------------------------------------------
# SOC 2 Type II
# ---------------------------------------------------------------------------
_STANDARDS_DB[FrameworkID.SOC2.value] = {
    "name": "SOC 2 Type II Trust Services Criteria",
    "version": "2017 (AICPA)",
    "authority": "American Institute of Certified Public Accountants",
    "url": "https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/sorhome",
    "description": (
        "SOC 2 evaluates an organization's information systems relevant "
        "to security, availability, processing integrity, confidentiality, "
        "and privacy based on the Trust Services Criteria."
    ),
    "categories": [
        "Common Criteria (CC)",
        "Availability",
        "Processing Integrity",
        "Confidentiality",
        "Privacy",
    ],
    "controls": {
        "CC3.4": {
            "title": "Risk Assessment -- Changes in External Environment",
            "description": "The entity identifies and assesses changes in the external environment that may impact the system of internal controls, including regulatory, economic, and physical environment changes.",
            "category": "Common Criteria (CC)", "sub_category": "Risk Assessment",
            "severity": Severity.MEDIUM.value,
            "remediation": "Conduct periodic external threat assessments. Monitor regulatory changes. Update risk register quarterly.",
            "references": ["SOC 2 CC3.4"],
        },
        "CC6.1": {
            "title": "Logical and Physical Access Controls",
            "description": "The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events.",
            "category": "Common Criteria (CC)", "sub_category": "Access Control",
            "severity": Severity.CRITICAL.value,
            "remediation": "Implement layered access controls: network segmentation, application-level RBAC, database-level permissions, and endpoint protection.",
            "references": ["SOC 2 CC6.1"],
        },
        "CC6.2": {
            "title": "User Authentication and Access Provisioning",
            "description": "Prior to issuing system credentials and granting system access, the entity registers and authorizes new internal and external users.",
            "category": "Common Criteria (CC)", "sub_category": "User Provisioning",
            "severity": Severity.HIGH.value,
            "remediation": "Implement formal user provisioning process. Require manager approval. Enforce MFA from first login.",
            "references": ["SOC 2 CC6.2"],
        },
        "CC6.3": {
            "title": "Role-Based Access and Least Privilege",
            "description": "The entity authorizes, modifies, or removes access to data, software, functions, and other protected information assets based on roles and responsibilities.",
            "category": "Common Criteria (CC)", "sub_category": "RBAC",
            "severity": Severity.HIGH.value,
            "remediation": "Implement RBAC with documented role definitions. Conduct quarterly access reviews. Enforce separation of duties.",
            "references": ["SOC 2 CC6.3"],
        },
        "CC6.5": {
            "title": "Restriction of Data to Authorized Users",
            "description": "The entity discontinues logical and physical protections over physical assets only after the ability to read or recover data and software from those assets has been diminished.",
            "category": "Common Criteria (CC)", "sub_category": "Data Restriction",
            "severity": Severity.MEDIUM.value,
            "remediation": "Sanitize media before disposal. Encrypt stored data. Implement DLP for data exfiltration prevention.",
            "references": ["SOC 2 CC6.5"],
        },
        "CC6.6": {
            "title": "Security Measures Against Threats Outside System Boundaries",
            "description": "The entity implements boundary protection mechanisms to protect against threats outside the system boundaries.",
            "category": "Common Criteria (CC)", "sub_category": "Boundary Protection",
            "severity": Severity.HIGH.value,
            "remediation": "Deploy firewalls, IDS/IPS, and WAFs at network boundaries. Implement DMZ architecture. Monitor boundary traffic.",
            "references": ["SOC 2 CC6.6"],
        },
        "CC6.7": {
            "title": "Data Transmission and Movement Restriction",
            "description": "The entity restricts the transmission, movement, and removal of information to authorized internal and external users and processes.",
            "category": "Common Criteria (CC)", "sub_category": "Data Transmission",
            "severity": Severity.HIGH.value,
            "remediation": "Encrypt data in transit with TLS 1.2+. Implement DLP. Restrict data export capabilities to authorized roles.",
            "references": ["SOC 2 CC6.7"],
        },
        "CC7.1": {
            "title": "Detection and Monitoring of Security Events",
            "description": "To meet its objectives, the entity uses detection and monitoring procedures to identify changes to configurations that result in new vulnerabilities.",
            "category": "Common Criteria (CC)", "sub_category": "Detection",
            "severity": Severity.HIGH.value,
            "remediation": "Deploy SIEM with real-time alerting. Implement vulnerability scanning. Monitor configuration changes.",
            "references": ["SOC 2 CC7.1"],
        },
        "CC7.2": {
            "title": "Monitoring of System Components for Anomalies",
            "description": "The entity monitors system components for anomalies that are indicative of malicious acts, natural disasters, and errors affecting the entity's ability to meet its objectives.",
            "category": "Common Criteria (CC)", "sub_category": "Anomaly Detection",
            "severity": Severity.MEDIUM.value,
            "remediation": "Implement behavioral analytics. Set baseline metrics. Alert on anomalous patterns. Deploy EDR on endpoints.",
            "references": ["SOC 2 CC7.2"],
        },
        "CC7.3": {
            "title": "Evaluation of Security Events",
            "description": "The entity evaluates security events to determine whether they could or have resulted in a failure of the entity to meet its objectives.",
            "category": "Common Criteria (CC)", "sub_category": "Event Evaluation",
            "severity": Severity.MEDIUM.value,
            "remediation": "Establish incident classification criteria. Define escalation procedures. Conduct post-incident reviews.",
            "references": ["SOC 2 CC7.3"],
        },
        "CC8.1": {
            "title": "Change Management",
            "description": "The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes to infrastructure, data, software, and procedures to meet its objectives.",
            "category": "Common Criteria (CC)", "sub_category": "Change Management",
            "severity": Severity.MEDIUM.value,
            "remediation": "Implement formal change management process. Require testing, approval, and rollback plan for all changes.",
            "references": ["SOC 2 CC8.1"],
        },
        "CC9.2": {
            "title": "Risk Mitigation Through Vendor Management",
            "description": "The entity assesses and manages risks associated with vendors and business partners.",
            "category": "Common Criteria (CC)", "sub_category": "Vendor Management",
            "severity": Severity.MEDIUM.value,
            "remediation": "Conduct vendor risk assessments. Include security requirements in contracts. Monitor vendor security posture.",
            "references": ["SOC 2 CC9.2"],
        },
    },
}

# ---------------------------------------------------------------------------
# LGPD (Lei Geral de Protecao de Dados)
# ---------------------------------------------------------------------------
_STANDARDS_DB[FrameworkID.LGPD.value] = {
    "name": "Lei Geral de Protecao de Dados Pessoais",
    "version": "Lei 13.709/2018",
    "authority": "Autoridade Nacional de Protecao de Dados (ANPD)",
    "url": "https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709.htm",
    "description": (
        "A LGPD regula o tratamento de dados pessoais, inclusive nos meios "
        "digitais, por pessoa natural ou por pessoa juridica de direito "
        "publico ou privado, com o objetivo de proteger os direitos "
        "fundamentais de liberdade e de privacidade."
    ),
    "categories": [
        "Principios de Tratamento",
        "Direitos do Titular",
        "Seguranca e Boas Praticas",
        "Transferencia Internacional",
        "Agentes de Tratamento",
    ],
    "controls": {
        "Art.39": {
            "title": "Responsabilidade do Operador",
            "description": "O operador devera realizar o tratamento segundo as instrucoes fornecidas pelo controlador, que verificara a observancia das proprias instrucoes e das normas sobre a materia.",
            "category": "Agentes de Tratamento", "sub_category": "Operador",
            "severity": Severity.MEDIUM.value,
            "remediation": "Document data processing instructions. Ensure third-party processors comply. Conduct periodic audits of processors.",
            "references": ["LGPD Art. 39"],
        },
        "Art.46": {
            "title": "Medidas de Seguranca",
            "description": "Os agentes de tratamento devem adotar medidas de seguranca, tecnicas e administrativas aptas a proteger os dados pessoais de acessos nao autorizados e de situacoes acidentais ou ilicitas.",
            "category": "Seguranca e Boas Praticas", "sub_category": "Seguranca Tecnica",
            "severity": Severity.CRITICAL.value,
            "remediation": "Implement encryption, access controls, vulnerability management, and incident response. Conduct regular security assessments.",
            "references": ["LGPD Art. 46"],
        },
        "Art.47": {
            "title": "Responsabilidade por Danos",
            "description": "Os agentes de tratamento ou qualquer outra pessoa que intervenha em uma das fases do tratamento obriga-se a garantir a seguranca da informacao prevista nesta Lei em relacao aos dados pessoais.",
            "category": "Seguranca e Boas Praticas", "sub_category": "Responsabilidade",
            "severity": Severity.HIGH.value,
            "remediation": "Ensure all participants in data processing chain maintain security. Document responsibilities. Implement security controls at each stage.",
            "references": ["LGPD Art. 47"],
        },
        "Art.48": {
            "title": "Comunicacao de Incidente de Seguranca",
            "description": "O controlador devera comunicar a autoridade nacional e ao titular a ocorrencia de incidente de seguranca que possa acarretar risco ou dano relevante aos titulares.",
            "category": "Seguranca e Boas Praticas", "sub_category": "Notificacao de Incidentes",
            "severity": Severity.HIGH.value,
            "remediation": "Establish incident response plan with ANPD notification procedures. Define severity criteria for breach disclosure. Train staff on incident handling.",
            "references": ["LGPD Art. 48"],
        },
        "Art.50": {
            "title": "Boas Praticas e Governanca",
            "description": "Os controladores e operadores, no ambito de suas competencias, pelo tratamento de dados pessoais, individualmente ou por meio de associacoes, poderao formular regras de boas praticas e de governanca.",
            "category": "Seguranca e Boas Praticas", "sub_category": "Governanca",
            "severity": Severity.MEDIUM.value,
            "remediation": "Develop privacy governance framework. Establish data protection policies. Conduct Data Protection Impact Assessments (DPIAs).",
            "references": ["LGPD Art. 50"],
        },
    },
}

# ---------------------------------------------------------------------------
# GDPR (General Data Protection Regulation)
# ---------------------------------------------------------------------------
_STANDARDS_DB[FrameworkID.GDPR.value] = {
    "name": "General Data Protection Regulation",
    "version": "EU 2016/679",
    "authority": "European Data Protection Board",
    "url": "https://gdpr.eu/",
    "description": (
        "The GDPR is a regulation on data protection and privacy for all "
        "individuals within the EU and EEA.  It addresses the transfer of "
        "personal data outside the EU and EEA areas."
    ),
    "categories": [
        "Principles of Processing",
        "Rights of Data Subjects",
        "Controller and Processor",
        "Security of Processing",
        "Data Protection by Design",
        "Records and Accountability",
        "Breach Notification",
    ],
    "controls": {
        "Art.5(1)(c)": {
            "title": "Data Minimization",
            "description": "Personal data shall be adequate, relevant and limited to what is necessary in relation to the purposes for which they are processed.",
            "category": "Principles of Processing", "sub_category": "Minimization",
            "severity": Severity.HIGH.value,
            "remediation": "Review data collected. Remove unnecessary fields. Apply purpose limitation. Return only required data in API responses.",
            "references": ["GDPR Art. 5(1)(c)"],
        },
        "Art.5(1)(f)": {
            "title": "Integrity and Confidentiality",
            "description": "Personal data shall be processed in a manner that ensures appropriate security of the personal data, including protection against unauthorized or unlawful processing and against accidental loss, destruction or damage, using appropriate technical or organizational measures.",
            "category": "Principles of Processing", "sub_category": "Integrity",
            "severity": Severity.CRITICAL.value,
            "remediation": "Implement encryption, access controls, and integrity verification. Conduct regular security assessments.",
            "references": ["GDPR Art. 5(1)(f)"],
        },
        "Art.5(2)": {
            "title": "Accountability",
            "description": "The controller shall be responsible for, and be able to demonstrate compliance with, the principles relating to processing of personal data.",
            "category": "Records and Accountability", "sub_category": "Accountability",
            "severity": Severity.MEDIUM.value,
            "remediation": "Maintain records of processing activities. Document compliance measures. Conduct regular audits.",
            "references": ["GDPR Art. 5(2)"],
        },
        "Art.25(1)": {
            "title": "Data Protection by Design",
            "description": "The controller shall implement appropriate technical and organizational measures designed to implement data-protection principles effectively and integrate safeguards into processing.",
            "category": "Data Protection by Design", "sub_category": "By Design",
            "severity": Severity.HIGH.value,
            "remediation": "Incorporate privacy into system design. Conduct DPIAs. Apply pseudonymization and encryption by default.",
            "references": ["GDPR Art. 25(1)"],
        },
        "Art.25(2)": {
            "title": "Data Protection by Default",
            "description": "The controller shall implement appropriate measures for ensuring that, by default, only personal data which are necessary for each specific purpose of the processing are processed.",
            "category": "Data Protection by Design", "sub_category": "By Default",
            "severity": Severity.HIGH.value,
            "remediation": "Set most privacy-protective settings as defaults. Limit data access, retention, and processing scope by default.",
            "references": ["GDPR Art. 25(2)"],
        },
        "Art.28": {
            "title": "Processor",
            "description": "Where processing is to be carried out on behalf of a controller, the controller shall use only processors providing sufficient guarantees to implement appropriate technical and organizational measures.",
            "category": "Controller and Processor", "sub_category": "Processor Selection",
            "severity": Severity.MEDIUM.value,
            "remediation": "Evaluate processor security posture. Include data processing agreements (DPAs). Audit processors regularly.",
            "references": ["GDPR Art. 28"],
        },
        "Art.30": {
            "title": "Records of Processing Activities",
            "description": "Each controller and processor shall maintain a record of processing activities under its responsibility.",
            "category": "Records and Accountability", "sub_category": "Records",
            "severity": Severity.MEDIUM.value,
            "remediation": "Maintain up-to-date Records of Processing Activities (RoPA). Include purposes, categories, recipients, and retention periods.",
            "references": ["GDPR Art. 30"],
        },
        "Art.32(1)(a)": {
            "title": "Encryption and Pseudonymization",
            "description": "Implement appropriate technical measures including the pseudonymization and encryption of personal data.",
            "category": "Security of Processing", "sub_category": "Encryption",
            "severity": Severity.HIGH.value,
            "remediation": "Encrypt personal data at rest and in transit. Apply pseudonymization where possible. Use strong cryptographic standards.",
            "references": ["GDPR Art. 32(1)(a)"],
        },
        "Art.32(1)(b)": {
            "title": "Confidentiality, Integrity, Availability, Resilience",
            "description": "Ensure the ongoing confidentiality, integrity, availability and resilience of processing systems and services.",
            "category": "Security of Processing", "sub_category": "CIA+R",
            "severity": Severity.HIGH.value,
            "remediation": "Implement defense-in-depth. Deploy redundancy and backups. Conduct regular DR testing. Patch systems promptly.",
            "references": ["GDPR Art. 32(1)(b)"],
        },
        "Art.32(1)(d)": {
            "title": "Testing and Evaluation of Security Measures",
            "description": "Implement a process for regularly testing, assessing and evaluating the effectiveness of technical and organizational measures for ensuring the security of the processing.",
            "category": "Security of Processing", "sub_category": "Testing",
            "severity": Severity.MEDIUM.value,
            "remediation": "Conduct regular penetration tests. Perform vulnerability assessments. Review security controls annually.",
            "references": ["GDPR Art. 32(1)(d)"],
        },
        "Art.33": {
            "title": "Notification of Personal Data Breach to Authority",
            "description": "In the case of a personal data breach, the controller shall without undue delay (within 72 hours) notify the supervisory authority.",
            "category": "Breach Notification", "sub_category": "Authority Notification",
            "severity": Severity.HIGH.value,
            "remediation": "Establish breach detection and notification procedures. Train staff. Prepare notification templates. Define 72-hour response plan.",
            "references": ["GDPR Art. 33"],
        },
    },
}


# ═══════════════════════════════════════════════════════════════════════════════
# SirenComplianceMapper -- Main Orchestrator
# ═══════════════════════════════════════════════════════════════════════════════


class SirenComplianceMapper:
    """
    Maps security findings to compliance frameworks, generates gap analysis,
    and produces audit-ready compliance reports.

    Supports 10 regulatory frameworks: PCI-DSS v4.0, OWASP Top 10 2021,
    OWASP API Top 10 2023, NIST 800-53, CIS v8, ISO 27001, HIPAA, SOC2,
    LGPD, and GDPR.

    Usage:
        mapper = SirenComplianceMapper()
        mapper.load_standards()

        # Map individual findings
        gaps = mapper.map_finding({
            "id": "FIND-001",
            "vuln_type": "SQL_INJECTION",
            "severity": "CRITICAL",
            "title": "SQL Injection in login endpoint",
            "target": "https://example.com/api/login",
        })

        # Map a batch of findings
        all_gaps = mapper.map_findings(findings_list)

        # Generate full report
        report = mapper.generate_report(
            target="example.com",
            scope="Full web application assessment",
        )

        # Export
        md = mapper.generate_markdown()
        json_str = mapper.export_json()
    """

    def __init__(
        self,
        frameworks: Optional[List[str]] = None,
        auto_load: bool = True,
    ) -> None:
        """
        Initialize the compliance mapper.

        Args:
            frameworks:  List of FrameworkID values to load.  None = all.
            auto_load:   Automatically load standards on init.
        """
        self._lock = threading.RLock()

        # Standards loaded into memory
        self._standards: Dict[str, ComplianceStandard] = {}

        # All mapped gaps
        self._gaps: List[ComplianceGap] = []

        # Finding tracking
        self._mapped_findings: List[Dict[str, Any]] = []
        self._unmapped_findings: List[Dict[str, Any]] = []

        # Framework filter
        self._framework_filter: Optional[List[str]] = frameworks

        # Statistics
        self._stats: Dict[str, Any] = {
            "findings_processed": 0,
            "findings_mapped": 0,
            "findings_unmapped": 0,
            "gaps_created": 0,
            "controls_violated": 0,
            "start_time": time.time(),
        }

        # Report cache
        self._report: Optional[ComplianceReport] = None

        if auto_load:
            self.load_standards()

        logger.info("SirenComplianceMapper initialized with %d frameworks",
                     len(self._standards))

    # -------------------------------------------------------------------
    # Standard loading
    # -------------------------------------------------------------------

    def load_standards(self) -> None:
        """Load compliance standards from the internal database."""
        with self._lock:
            filter_set: Optional[Set[str]] = None
            if self._framework_filter:
                filter_set = set(self._framework_filter)

            for fw_id, fw_data in _STANDARDS_DB.items():
                if filter_set and fw_id not in filter_set:
                    continue
                controls: List[ComplianceControl] = []
                for ctrl_id, ctrl_data in fw_data.get("controls", {}).items():
                    # Collect related vuln types for this control
                    related_vulns: List[str] = []
                    for vtype, fw_map in _VULN_CONTROL_MAP.items():
                        if fw_id in fw_map and ctrl_id in fw_map[fw_id]:
                            related_vulns.append(vtype)

                    ctrl = ComplianceControl(
                        control_id=ctrl_id,
                        framework_id=fw_id,
                        title=ctrl_data.get("title", ""),
                        description=ctrl_data.get("description", ""),
                        category=ctrl_data.get("category", ""),
                        sub_category=ctrl_data.get("sub_category", ""),
                        severity=ctrl_data.get("severity", Severity.MEDIUM.value),
                        status=ComplianceStatus.NOT_ASSESSED.value,
                        related_vulns=related_vulns,
                        remediation=ctrl_data.get("remediation", ""),
                        references=ctrl_data.get("references", []),
                    )
                    controls.append(ctrl)

                standard = ComplianceStandard(
                    framework_id=fw_id,
                    name=fw_data.get("name", ""),
                    version=fw_data.get("version", ""),
                    description=fw_data.get("description", ""),
                    authority=fw_data.get("authority", ""),
                    url=fw_data.get("url", ""),
                    controls=controls,
                    categories=fw_data.get("categories", []),
                    total_controls=len(controls),
                    last_updated=time.time(),
                )
                self._standards[fw_id] = standard
                logger.debug("Loaded standard %s with %d controls",
                             fw_id, len(controls))

    # -------------------------------------------------------------------
    # Finding mapping
    # -------------------------------------------------------------------

    def map_finding(self, finding: Dict[str, Any]) -> List[ComplianceGap]:
        """
        Map a single finding to compliance controls and produce gaps.

        Args:
            finding:  Dict with at least: id, vuln_type, severity, title.
                      Optional: description, target, evidence, remediation.

        Returns:
            List of ComplianceGap objects created by this finding.
        """
        with self._lock:
            self._stats["findings_processed"] += 1
            finding_id = finding.get("id", uuid.uuid4().hex[:12])
            vuln_type = finding.get("vuln_type", "")
            severity = finding.get("severity", Severity.MEDIUM.value)
            title = finding.get("title", "Unknown finding")
            description = finding.get("description", "")
            target = finding.get("target", "")

            # Lookup control mappings for this vuln type
            control_map = _VULN_CONTROL_MAP.get(vuln_type, {})
            if not control_map:
                self._unmapped_findings.append(finding)
                self._stats["findings_unmapped"] += 1
                logger.warning("No control mapping for vuln_type=%s (finding=%s)",
                               vuln_type, finding_id)
                return []

            self._stats["findings_mapped"] += 1
            self._mapped_findings.append(finding)

            new_gaps: List[ComplianceGap] = []

            for fw_id, control_ids in control_map.items():
                if fw_id not in self._standards:
                    continue

                standard = self._standards[fw_id]
                for ctrl_id in control_ids:
                    ctrl = standard.get_control(ctrl_id)
                    if ctrl is None:
                        continue

                    # Mark control as non-compliant
                    ctrl.status = ComplianceStatus.NON_COMPLIANT.value
                    ctrl.last_assessed = time.time()
                    ctrl.assessor = "SIREN Compliance Mapper"

                    # Add evidence
                    ctrl.add_evidence(
                        evidence_type="finding",
                        content=(
                            f"Finding [{finding_id}]: {title} -- "
                            f"Vuln type: {vuln_type}, Severity: {severity}"
                            f"{(', Target: ' + target) if target else ''}"
                        ),
                        source="siren.compliance_mapper",
                    )

                    # Check if we already have a gap for this control
                    existing_gap = self._find_existing_gap(fw_id, ctrl_id)
                    if existing_gap:
                        # Append finding to existing gap
                        if finding_id not in existing_gap.finding_ids:
                            existing_gap.finding_ids.append(finding_id)
                        if vuln_type not in existing_gap.vuln_types:
                            existing_gap.vuln_types.append(vuln_type)
                        existing_gap.updated_at = time.time()
                        # Escalate severity if finding is worse
                        existing_gap.severity = self._max_gap_severity(
                            existing_gap.severity,
                            self._finding_severity_to_gap_severity(severity),
                        )
                        continue

                    # Create new gap
                    gap_severity = self._finding_severity_to_gap_severity(severity)
                    effort = self._estimate_effort(ctrl, severity)
                    business_impact = self._assess_business_impact(
                        ctrl, vuln_type, severity
                    )

                    gap = ComplianceGap(
                        control=ctrl,
                        framework_id=fw_id,
                        finding_ids=[finding_id],
                        vuln_types=[vuln_type],
                        severity=gap_severity,
                        title=f"[{ctrl_id}] {ctrl.title}",
                        description=(
                            f"Control {ctrl_id} ({ctrl.title}) is violated by "
                            f"finding '{title}' (type: {vuln_type}).  "
                            f"{ctrl.description}"
                        ),
                        business_impact=business_impact,
                        remediation=ctrl.remediation or (
                            f"Address the {vuln_type} vulnerability to "
                            f"restore compliance with {fw_id} control {ctrl_id}."
                        ),
                        effort=effort,
                    )
                    self._gaps.append(gap)
                    new_gaps.append(gap)
                    self._stats["gaps_created"] += 1
                    self._stats["controls_violated"] += 1

            # Invalidate cached report
            self._report = None
            return new_gaps

    def map_findings(self, findings: List[Dict[str, Any]]) -> List[ComplianceGap]:
        """
        Map multiple findings to compliance controls.

        Args:
            findings:  List of finding dicts.

        Returns:
            Aggregated list of all new gaps created.
        """
        all_gaps: List[ComplianceGap] = []
        for finding in findings:
            gaps = self.map_finding(finding)
            all_gaps.extend(gaps)
        logger.info("Mapped %d findings -> %d new gaps",
                     len(findings), len(all_gaps))
        return all_gaps

    # -------------------------------------------------------------------
    # Report generation
    # -------------------------------------------------------------------

    def generate_report(
        self,
        target: str = "",
        scope: str = "",
        title: str = "SIREN Compliance Assessment Report",
    ) -> ComplianceReport:
        """
        Generate a comprehensive compliance report.

        Args:
            target:  Target system name.
            scope:   Assessment scope description.
            title:   Report title.

        Returns:
            ComplianceReport object with all data.
        """
        with self._lock:
            # Compute per-framework scores
            framework_scores: Dict[str, float] = {}
            for fw_id, standard in self._standards.items():
                score = standard.get_compliance_percentage()
                framework_scores[fw_id] = score

            # Mark un-assessed controls as compliant for scoring
            # (only controls that have related vulns but no violations)
            for fw_id, standard in self._standards.items():
                for ctrl in standard.controls:
                    if ctrl.status == ComplianceStatus.NOT_ASSESSED.value:
                        ctrl.status = ComplianceStatus.COMPLIANT.value
                        ctrl.last_assessed = time.time()
                        ctrl.assessor = "SIREN Compliance Mapper (inferred)"
                # Recalculate after updating
                framework_scores[fw_id] = standard.get_compliance_percentage()

            # Overall score (weighted by number of controls)
            total_weight = 0.0
            weighted_sum = 0.0
            for fw_id, score in framework_scores.items():
                ctrl_count = self._standards[fw_id].total_controls
                weighted_sum += score * ctrl_count
                total_weight += ctrl_count
            overall_score = round(weighted_sum / max(total_weight, 1), 2)

            # Executive summary
            executive_summary = self._generate_executive_summary(
                target, overall_score, framework_scores
            )

            report = ComplianceReport(
                title=title,
                target=target,
                scope=scope,
                frameworks=list(self._standards.values()),
                gaps=list(self._gaps),
                findings_mapped=self._stats["findings_mapped"],
                findings_unmapped=self._stats["findings_unmapped"],
                overall_score=overall_score,
                framework_scores=framework_scores,
                executive_summary=executive_summary,
                metadata={
                    "total_findings_processed": self._stats["findings_processed"],
                    "total_gaps_created": self._stats["gaps_created"],
                    "total_controls_violated": self._stats["controls_violated"],
                    "frameworks_assessed": len(self._standards),
                    "processing_time_seconds": round(
                        time.time() - self._stats["start_time"], 3
                    ),
                },
            )
            self._report = report
            logger.info(
                "Report generated: overall_score=%.1f%%, gaps=%d, "
                "frameworks=%d",
                overall_score, len(self._gaps), len(self._standards),
            )
            return report

    # -------------------------------------------------------------------
    # Scoring and analysis
    # -------------------------------------------------------------------

    def get_compliance_score(
        self, framework_id: Optional[str] = None
    ) -> Dict[str, float]:
        """
        Get compliance score(s).

        Args:
            framework_id:  Specific framework or None for all.

        Returns:
            Dict of framework_id -> score (0-100).
        """
        with self._lock:
            if framework_id:
                std = self._standards.get(framework_id)
                if std:
                    return {framework_id: std.get_compliance_percentage()}
                return {framework_id: 0.0}
            return {
                fw_id: std.get_compliance_percentage()
                for fw_id, std in self._standards.items()
            }

    def get_gaps(
        self,
        framework_id: Optional[str] = None,
        severity: Optional[str] = None,
        status: str = "open",
    ) -> List[ComplianceGap]:
        """
        Retrieve gaps with optional filtering.

        Args:
            framework_id:  Filter by framework.
            severity:      Filter by gap severity.
            status:        Filter by status (default: open).

        Returns:
            Filtered list of ComplianceGap objects.
        """
        with self._lock:
            result = list(self._gaps)
            if framework_id:
                result = [g for g in result if g.framework_id == framework_id]
            if severity:
                result = [g for g in result if g.severity == severity]
            if status:
                result = [g for g in result if g.status == status]
            return result

    def get_critical_gaps(self) -> List[ComplianceGap]:
        """Return all critical-severity gaps."""
        return self.get_gaps(severity=GapSeverity.CRITICAL.value)

    def get_remediation_priorities(
        self, top_n: int = 20
    ) -> List[Dict[str, Any]]:
        """
        Get prioritized remediation list sorted by priority score.

        Args:
            top_n:  Maximum number of items to return.

        Returns:
            List of dicts with gap details and priority info.
        """
        with self._lock:
            open_gaps = [g for g in self._gaps if g.status == "open"]
            open_gaps.sort(key=lambda g: g.priority_score, reverse=True)
            priorities: List[Dict[str, Any]] = []
            for rank, gap in enumerate(open_gaps[:top_n], 1):
                ctrl_id = gap.control.control_id if gap.control else "N/A"
                priorities.append({
                    "rank": rank,
                    "gap_id": gap.gap_id,
                    "framework": gap.framework_id,
                    "control_id": ctrl_id,
                    "title": gap.title,
                    "severity": gap.severity,
                    "priority_score": gap.priority_score,
                    "effort": gap.effort,
                    "effort_hours": f"{gap.effort_hours_min:.0f}-{gap.effort_hours_max:.0f}",
                    "vuln_types": gap.vuln_types,
                    "finding_count": len(gap.finding_ids),
                    "remediation": gap.remediation,
                })
            return priorities

    # -------------------------------------------------------------------
    # Export methods
    # -------------------------------------------------------------------

    def export_audit_evidence(
        self, framework_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Export audit-ready evidence for compliance review.

        Args:
            framework_id:  Specific framework or None for all.

        Returns:
            Dict with structured audit evidence.
        """
        with self._lock:
            evidence: Dict[str, Any] = {
                "export_timestamp": time.time(),
                "export_id": uuid.uuid4().hex[:16],
                "assessor": "SIREN Compliance Mapper",
                "frameworks": {},
            }

            targets = (
                {framework_id: self._standards[framework_id]}
                if framework_id and framework_id in self._standards
                else self._standards
            )

            for fw_id, standard in targets.items():
                fw_evidence: Dict[str, Any] = {
                    "framework": standard.name,
                    "version": standard.version,
                    "compliance_score": standard.get_compliance_percentage(),
                    "total_controls": standard.total_controls,
                    "violated_controls": len(standard.get_violated_controls()),
                    "controls": {},
                }

                for ctrl in standard.controls:
                    fw_evidence["controls"][ctrl.control_id] = {
                        "title": ctrl.title,
                        "status": ctrl.status,
                        "severity": ctrl.severity,
                        "evidence_items": ctrl.evidence,
                        "last_assessed": ctrl.last_assessed,
                        "assessor": ctrl.assessor,
                        "notes": ctrl.notes,
                    }

                # Attach gaps for this framework
                fw_gaps = [g for g in self._gaps if g.framework_id == fw_id]
                fw_evidence["gaps"] = [g.to_dict() for g in fw_gaps]

                evidence["frameworks"][fw_id] = fw_evidence

            return evidence

    def generate_markdown(self) -> str:
        """
        Generate a Markdown compliance report.

        Returns:
            Complete Markdown report string.
        """
        with self._lock:
            if self._report is None:
                self.generate_report()
            assert self._report is not None
            return self._report.to_markdown()

    def export_json(self, indent: int = 2) -> str:
        """
        Export full compliance data as JSON.

        Args:
            indent:  JSON indentation level.

        Returns:
            JSON string of the full report.
        """
        with self._lock:
            if self._report is None:
                self.generate_report()
            assert self._report is not None
            return json.dumps(self._report.to_dict(), indent=indent,
                              ensure_ascii=False, default=str)

    # -------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------

    def _find_existing_gap(
        self, framework_id: str, control_id: str
    ) -> Optional[ComplianceGap]:
        """Find an existing gap for a specific framework/control pair."""
        for gap in self._gaps:
            if (gap.framework_id == framework_id
                    and gap.control is not None
                    and gap.control.control_id == control_id):
                return gap
        return None

    @staticmethod
    def _finding_severity_to_gap_severity(severity: str) -> str:
        """Convert a finding severity to a gap severity."""
        mapping: Dict[str, str] = {
            Severity.CRITICAL.value: GapSeverity.CRITICAL.value,
            Severity.HIGH.value: GapSeverity.HIGH.value,
            Severity.MEDIUM.value: GapSeverity.MEDIUM.value,
            Severity.LOW.value: GapSeverity.LOW.value,
            Severity.INFORMATIONAL.value: GapSeverity.LOW.value,
        }
        return mapping.get(severity, GapSeverity.MEDIUM.value)

    @staticmethod
    def _max_gap_severity(a: str, b: str) -> str:
        """Return the higher of two gap severities."""
        order = [
            GapSeverity.LOW.value,
            GapSeverity.MEDIUM.value,
            GapSeverity.HIGH.value,
            GapSeverity.CRITICAL.value,
        ]
        idx_a = order.index(a) if a in order else 1
        idx_b = order.index(b) if b in order else 1
        return order[max(idx_a, idx_b)]

    @staticmethod
    def _estimate_effort(ctrl: ComplianceControl, severity: str) -> str:
        """Estimate remediation effort based on control and severity."""
        # High/critical severity + complex categories -> higher effort
        complex_categories = {
            "Access Control", "Cryptography", "Access Control (AC)",
            "System and Communications Protection (SC)",
            "Implement Strong Access Control",
            "Protect Account Data",
        }
        is_complex = ctrl.category in complex_categories

        if severity in (Severity.CRITICAL.value, Severity.HIGH.value):
            return RemediationEffort.HIGH.value if is_complex else RemediationEffort.MEDIUM.value
        elif severity == Severity.MEDIUM.value:
            return RemediationEffort.MEDIUM.value if is_complex else RemediationEffort.LOW.value
        else:
            return RemediationEffort.LOW.value if is_complex else RemediationEffort.TRIVIAL.value

    @staticmethod
    def _assess_business_impact(
        ctrl: ComplianceControl, vuln_type: str, severity: str
    ) -> str:
        """Generate business impact description for a gap."""
        impacts: List[str] = []

        # Severity-based impact
        if severity == Severity.CRITICAL.value:
            impacts.append(
                "CRITICAL: Immediate risk of data breach, regulatory fines, "
                "and significant reputational damage."
            )
        elif severity == Severity.HIGH.value:
            impacts.append(
                "HIGH: Significant risk of unauthorized access or data "
                "exposure with potential regulatory consequences."
            )
        elif severity == Severity.MEDIUM.value:
            impacts.append(
                "MEDIUM: Moderate risk that could lead to partial data "
                "exposure or compliance audit findings."
            )
        else:
            impacts.append(
                "LOW: Minor risk with limited direct business impact, "
                "but contributes to overall compliance posture."
            )

        # Framework-specific impacts
        fw = ctrl.framework_id
        if fw == FrameworkID.PCI_DSS_4.value:
            impacts.append(
                "PCI-DSS non-compliance may result in fines of $5,000-$100,000 "
                "per month, increased transaction fees, or loss of card "
                "processing privileges."
            )
        elif fw == FrameworkID.HIPAA.value:
            impacts.append(
                "HIPAA violations can result in fines from $100 to $50,000 "
                "per violation (up to $1.5M annually per category), "
                "criminal penalties, and mandatory corrective action plans."
            )
        elif fw == FrameworkID.GDPR.value:
            impacts.append(
                "GDPR violations can result in fines up to 20M EUR or 4% "
                "of annual global turnover, whichever is higher, plus "
                "potential lawsuits from affected data subjects."
            )
        elif fw == FrameworkID.LGPD.value:
            impacts.append(
                "LGPD violations can result in fines up to 2% of revenue "
                "in Brazil (limited to R$50M per infraction), plus "
                "public disclosure of the violation by ANPD."
            )
        elif fw == FrameworkID.SOC2.value:
            impacts.append(
                "SOC 2 audit failures can result in loss of customer "
                "trust, contract violations, and inability to serve "
                "enterprise clients requiring SOC 2 compliance."
            )

        return " ".join(impacts)

    def _generate_executive_summary(
        self,
        target: str,
        overall_score: float,
        framework_scores: Dict[str, float],
    ) -> str:
        """Generate an executive summary for the compliance report."""
        lines: List[str] = []

        # Overall assessment
        if overall_score >= 90:
            posture = "strong"
        elif overall_score >= 70:
            posture = "moderate"
        elif overall_score >= 50:
            posture = "weak"
        else:
            posture = "critically deficient"

        lines.append(
            f"The compliance assessment of **{target or 'the target system'}** "
            f"reveals a **{posture}** security posture with an overall "
            f"compliance score of **{overall_score:.1f}%** across "
            f"{len(framework_scores)} regulatory frameworks."
        )

        # Gap summary
        critical_count = len(self.get_critical_gaps())
        high_count = len(self.get_gaps(severity=GapSeverity.HIGH.value))
        total_gaps = len([g for g in self._gaps if g.status == "open"])

        if critical_count > 0:
            lines.append(
                f"\n**{critical_count} CRITICAL** compliance gap(s) require "
                f"immediate attention.  These represent the highest-risk "
                f"deviations from regulatory requirements."
            )

        lines.append(
            f"\nA total of **{total_gaps} open gaps** were identified "
            f"({critical_count} Critical, {high_count} High, "
            f"{total_gaps - critical_count - high_count} Medium/Low)."
        )

        # Worst frameworks
        worst = sorted(framework_scores.items(), key=lambda x: x[1])
        if worst and worst[0][1] < 80:
            lines.append(
                f"\nThe framework with lowest compliance is "
                f"**{worst[0][0]}** at **{worst[0][1]:.1f}%**, "
                f"requiring focused remediation effort."
            )

        # Effort estimate
        effort_min = sum(g.effort_hours_min for g in self._gaps if g.status == "open")
        effort_max = sum(g.effort_hours_max for g in self._gaps if g.status == "open")
        if effort_max > 0:
            lines.append(
                f"\nEstimated total remediation effort: "
                f"**{effort_min:.0f} - {effort_max:.0f} hours** "
                f"({effort_min / 40:.1f} - {effort_max / 40:.1f} person-weeks)."
            )

        return "\n".join(lines)
