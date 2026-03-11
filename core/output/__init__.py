"""
╔══════════════════════════════════════════════════════════════════════════════════╗
║                                                                                  ║
║  📊  SIREN OUTPUT — Compliance, Risk & Remediation                              ║
║                                                                                  ║
║  TIER 4 modules — transform findings into actionable business intelligence.      ║
║                                                                                  ║
║  • compliance_mapper       — PCI-DSS, HIPAA, SOC2, ISO 27001 mapping            ║
║  • risk_scorer             — CVSS recalculation with business context            ║
║  • remediation_generator   — Automated fix generation per framework              ║
║                                                                                  ║
╚══════════════════════════════════════════════════════════════════════════════════╝
"""

from .compliance_mapper import (
    ComplianceControl,
    ComplianceGap,
    ComplianceReport,
    ComplianceStandard,
    SirenComplianceMapper,
)
from .remediation_generator import (
    FixTemplate,
    PriorityQueue,
    RemediationPlan,
    RemediationStep,
    SirenRemediationGenerator,
)
from .risk_scorer import (
    BusinessContext,
    RiskFactor,
    RiskMatrix,
    RiskScore,
    SirenRiskScorer,
)

__all__ = [
    # Compliance Mapper
    "ComplianceStandard", "ComplianceControl", "ComplianceGap",
    "ComplianceReport", "SirenComplianceMapper",
    # Risk Scorer
    "BusinessContext", "RiskFactor", "RiskScore",
    "RiskMatrix", "SirenRiskScorer",
    # Remediation Generator
    "RemediationStep", "RemediationPlan", "FixTemplate",
    "PriorityQueue", "SirenRemediationGenerator",
]
