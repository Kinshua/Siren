#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  🛡️  SIREN THREAT INTEL — Vulnerability-to-Threat Correlation Engine  🛡️     ██
██                                                                                ██
██  UNICO NO MERCADO — Correlaciona vulnerabilidades com inteligencia real:        ██
██                                                                                ██
██    • Mapeamento automatico para MITRE ATT&CK (Tactics + Techniques)            ██
██    • Correlacao CWE → CVE → Exploits conhecidos → APT groups                  ██
██    • Scoring preditivo: "quais threat actors miram essa stack?"                ██
██    • Kill chain mapping: posicao de cada vuln na kill chain                    ██
██    • Deteccao de padroes de ataque (recon → weaponize → deliver → exploit)    ██
██    • Priorizacao baseada em ameacas reais (EPSS-like scoring)                  ██
██    • Compliance mapping (PCI-DSS, OWASP, NIST, HIPAA, GDPR)                   ██
██    • Geopolitical risk overlay (threat actors por regiao/industria)             ██
██    • Threat hunt queries geradas automaticamente (SIEM/SOAR)                   ██
██    • Integration-ready com STIX/TAXII formats                                  ██
██                                                                                ██
██  "Saber a vulnerabilidade é o começo. Saber quem a explora é sabedoria."      ██
██                                                                                ██
████████████████████████████████████████████████████████████████████████████████████
"""

from __future__ import annotations

import json
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

logger = logging.getLogger("siren.threat_intel")


# ════════════════════════════════════════════════════════════════════════════
# ENUMS
# ════════════════════════════════════════════════════════════════════════════


class KillChainPhase(Enum):
    """Lockheed Martin Cyber Kill Chain phases."""

    RECONNAISSANCE = "reconnaissance"
    WEAPONIZATION = "weaponization"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    COMMAND_CONTROL = "command_and_control"
    ACTIONS_ON_OBJECTIVES = "actions_on_objectives"


class ThreatLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class ComplianceFramework(Enum):
    PCI_DSS = "pci_dss"
    OWASP_TOP10 = "owasp_top10"
    NIST_CSF = "nist_csf"
    HIPAA = "hipaa"
    GDPR = "gdpr"
    SOC2 = "soc2"
    ISO27001 = "iso27001"


class IndustryVertical(Enum):
    FINANCE = "finance"
    HEALTHCARE = "healthcare"
    GOVERNMENT = "government"
    TECHNOLOGY = "technology"
    RETAIL = "retail"
    ENERGY = "energy"
    EDUCATION = "education"
    GAMING = "gaming"


# ════════════════════════════════════════════════════════════════════════════
# MITRE ATT&CK KNOWLEDGE BASE (Embedded – no external deps)
# ════════════════════════════════════════════════════════════════════════════

# Tactic → Technique mappings with IDs
MITRE_TACTICS: Dict[str, Dict[str, Any]] = {
    "TA0001": {
        "name": "Initial Access",
        "kill_chain": KillChainPhase.DELIVERY,
        "techniques": {
            "T1190": "Exploit Public-Facing Application",
            "T1133": "External Remote Services",
            "T1566": "Phishing",
            "T1078": "Valid Accounts",
            "T1195": "Supply Chain Compromise",
            "T1189": "Drive-by Compromise",
        },
    },
    "TA0002": {
        "name": "Execution",
        "kill_chain": KillChainPhase.EXPLOITATION,
        "techniques": {
            "T1059": "Command and Scripting Interpreter",
            "T1203": "Exploitation for Client Execution",
            "T1047": "Windows Management Instrumentation",
            "T1053": "Scheduled Task/Job",
            "T1204": "User Execution",
        },
    },
    "TA0003": {
        "name": "Persistence",
        "kill_chain": KillChainPhase.INSTALLATION,
        "techniques": {
            "T1098": "Account Manipulation",
            "T1136": "Create Account",
            "T1505": "Server Software Component",
            "T1078": "Valid Accounts",
            "T1053": "Scheduled Task/Job",
        },
    },
    "TA0004": {
        "name": "Privilege Escalation",
        "kill_chain": KillChainPhase.EXPLOITATION,
        "techniques": {
            "T1068": "Exploitation for Privilege Escalation",
            "T1078": "Valid Accounts",
            "T1548": "Abuse Elevation Control Mechanism",
            "T1134": "Access Token Manipulation",
        },
    },
    "TA0005": {
        "name": "Defense Evasion",
        "kill_chain": KillChainPhase.EXPLOITATION,
        "techniques": {
            "T1140": "Deobfuscate/Decode Files",
            "T1027": "Obfuscated Files or Information",
            "T1562": "Impair Defenses",
            "T1070": "Indicator Removal",
        },
    },
    "TA0006": {
        "name": "Credential Access",
        "kill_chain": KillChainPhase.EXPLOITATION,
        "techniques": {
            "T1110": "Brute Force",
            "T1557": "Adversary-in-the-Middle",
            "T1539": "Steal Web Session Cookie",
            "T1552": "Unsecured Credentials",
            "T1555": "Credentials from Password Stores",
            "T1111": "Multi-Factor Authentication Interception",
        },
    },
    "TA0007": {
        "name": "Discovery",
        "kill_chain": KillChainPhase.RECONNAISSANCE,
        "techniques": {
            "T1087": "Account Discovery",
            "T1046": "Network Service Discovery",
            "T1082": "System Information Discovery",
            "T1083": "File and Directory Discovery",
            "T1518": "Software Discovery",
        },
    },
    "TA0008": {
        "name": "Lateral Movement",
        "kill_chain": KillChainPhase.ACTIONS_ON_OBJECTIVES,
        "techniques": {
            "T1210": "Exploitation of Remote Services",
            "T1021": "Remote Services",
            "T1550": "Use Alternate Authentication Material",
        },
    },
    "TA0009": {
        "name": "Collection",
        "kill_chain": KillChainPhase.ACTIONS_ON_OBJECTIVES,
        "techniques": {
            "T1005": "Data from Local System",
            "T1039": "Data from Network Shared Drive",
            "T1114": "Email Collection",
            "T1213": "Data from Information Repositories",
        },
    },
    "TA0010": {
        "name": "Exfiltration",
        "kill_chain": KillChainPhase.ACTIONS_ON_OBJECTIVES,
        "techniques": {
            "T1041": "Exfiltration Over C2 Channel",
            "T1567": "Exfiltration Over Web Service",
            "T1048": "Exfiltration Over Alternative Protocol",
        },
    },
    "TA0011": {
        "name": "Command and Control",
        "kill_chain": KillChainPhase.COMMAND_CONTROL,
        "techniques": {
            "T1071": "Application Layer Protocol",
            "T1573": "Encrypted Channel",
            "T1105": "Ingress Tool Transfer",
            "T1572": "Protocol Tunneling",
        },
    },
    "TA0040": {
        "name": "Impact",
        "kill_chain": KillChainPhase.ACTIONS_ON_OBJECTIVES,
        "techniques": {
            "T1485": "Data Destruction",
            "T1486": "Data Encrypted for Impact",
            "T1499": "Endpoint Denial of Service",
            "T1491": "Defacement",
            "T1565": "Data Manipulation",
        },
    },
}

# CWE → ATT&CK Technique mapping
CWE_TO_ATTACK: Dict[str, List[str]] = {
    "CWE-89": ["T1190", "T1059"],  # SQL Injection
    "CWE-79": ["T1189", "T1059"],  # XSS
    "CWE-78": ["T1059", "T1190"],  # OS Command Injection
    "CWE-22": ["T1083", "T1005"],  # Path Traversal
    "CWE-611": ["T1190", "T1005"],  # XXE
    "CWE-918": ["T1190", "T1046"],  # SSRF
    "CWE-502": ["T1190", "T1059"],  # Deserialization
    "CWE-287": ["T1078", "T1110"],  # Auth Bypass
    "CWE-306": ["T1078"],  # Missing Auth
    "CWE-269": ["T1068", "T1548"],  # Improper Privilege Mgmt
    "CWE-200": ["T1005", "T1552"],  # Info Disclosure
    "CWE-522": ["T1552", "T1555"],  # Insecure Credentials
    "CWE-798": ["T1078", "T1552"],  # Hardcoded Credentials
    "CWE-327": ["T1557", "T1040"],  # Broken Crypto
    "CWE-295": ["T1557"],  # Cert Validation
    "CWE-352": ["T1189"],  # CSRF
    "CWE-434": ["T1505", "T1190"],  # Unrestricted Upload
    "CWE-601": ["T1566"],  # Open Redirect
    "CWE-94": ["T1059", "T1190"],  # Code Injection
    "CWE-917": ["T1059", "T1190"],  # Expression Language Injection
    "CWE-639": ["T1078", "T1068"],  # IDOR
    "CWE-312": ["T1552"],  # Cleartext Storage
    "CWE-319": ["T1557", "T1040"],  # Cleartext Transmission
    "CWE-384": ["T1539"],  # Session Fixation
    "CWE-613": ["T1539"],  # Session Expiration
    "CWE-863": ["T1068", "T1548"],  # Incorrect Authorization
    "CWE-862": ["T1078"],  # Missing Authorization
    "CWE-942": ["T1189"],  # CORS Misconfiguration
    "CWE-1021": ["T1189"],  # Clickjacking
    "CWE-1104": ["T1195"],  # Unmaintained Component
    "CWE-400": ["T1499"],  # Resource Exhaustion
    "CWE-770": ["T1499"],  # No Rate Limiting
}

# Known threat actor profiles mapped to vuln types they typically exploit
APT_PROFILES: Dict[str, Dict[str, Any]] = {
    "APT28": {
        "aliases": ["Fancy Bear", "Sofacy", "Strontium"],
        "origin": "Russia",
        "targets": [IndustryVertical.GOVERNMENT, IndustryVertical.ENERGY],
        "preferred_techniques": ["T1190", "T1566", "T1078", "T1059"],
        "preferred_cwes": ["CWE-89", "CWE-78", "CWE-287"],
        "sophistication": 0.95,
    },
    "APT29": {
        "aliases": ["Cozy Bear", "Nobelium", "Midnight Blizzard"],
        "origin": "Russia",
        "targets": [IndustryVertical.GOVERNMENT, IndustryVertical.TECHNOLOGY],
        "preferred_techniques": ["T1195", "T1078", "T1550"],
        "preferred_cwes": ["CWE-287", "CWE-798", "CWE-502"],
        "sophistication": 0.98,
    },
    "APT41": {
        "aliases": ["Winnti", "Barium", "Wicked Panda"],
        "origin": "China",
        "targets": [
            IndustryVertical.GAMING,
            IndustryVertical.TECHNOLOGY,
            IndustryVertical.HEALTHCARE,
        ],
        "preferred_techniques": ["T1190", "T1059", "T1505"],
        "preferred_cwes": ["CWE-89", "CWE-502", "CWE-434"],
        "sophistication": 0.90,
    },
    "Lazarus": {
        "aliases": ["Hidden Cobra", "Zinc", "Labyrinth Chollima"],
        "origin": "North Korea",
        "targets": [IndustryVertical.FINANCE, IndustryVertical.TECHNOLOGY],
        "preferred_techniques": ["T1190", "T1566", "T1059", "T1486"],
        "preferred_cwes": ["CWE-89", "CWE-78", "CWE-502"],
        "sophistication": 0.88,
    },
    "FIN7": {
        "aliases": ["Carbanak", "Navigator Group"],
        "origin": "Russia",
        "targets": [IndustryVertical.RETAIL, IndustryVertical.FINANCE],
        "preferred_techniques": ["T1190", "T1566", "T1059", "T1041"],
        "preferred_cwes": ["CWE-89", "CWE-79", "CWE-287"],
        "sophistication": 0.85,
    },
    "OceanLotus": {
        "aliases": ["APT32", "SeaLotus"],
        "origin": "Vietnam",
        "targets": [IndustryVertical.GOVERNMENT, IndustryVertical.TECHNOLOGY],
        "preferred_techniques": ["T1190", "T1059", "T1505"],
        "preferred_cwes": ["CWE-78", "CWE-434", "CWE-502"],
        "sophistication": 0.80,
    },
    "Scattered_Spider": {
        "aliases": ["Roasted 0ktapus", "UNC3944"],
        "origin": "International",
        "targets": [IndustryVertical.TECHNOLOGY, IndustryVertical.FINANCE],
        "preferred_techniques": ["T1078", "T1110", "T1111", "T1539"],
        "preferred_cwes": ["CWE-287", "CWE-522", "CWE-384"],
        "sophistication": 0.82,
    },
    "Cl0p": {
        "aliases": ["TA505 associate", "FIN11"],
        "origin": "Russia",
        "targets": [
            IndustryVertical.FINANCE,
            IndustryVertical.HEALTHCARE,
            IndustryVertical.GOVERNMENT,
        ],
        "preferred_techniques": ["T1190", "T1486", "T1567"],
        "preferred_cwes": ["CWE-89", "CWE-22", "CWE-502"],
        "sophistication": 0.87,
    },
}

# Compliance framework → CWE mapping
COMPLIANCE_CWE_MAP: Dict[ComplianceFramework, Dict[str, List[str]]] = {
    ComplianceFramework.PCI_DSS: {
        "Req 6.5.1": ["CWE-89"],  # SQL Injection
        "Req 6.5.4": ["CWE-22"],  # Path Traversal
        "Req 6.5.7": ["CWE-79"],  # XSS
        "Req 6.5.8": ["CWE-863", "CWE-862"],  # Access Control
        "Req 6.5.9": ["CWE-352"],  # CSRF
        "Req 6.5.10": ["CWE-287", "CWE-384"],  # Broken Auth
        "Req 6.6": ["CWE-89", "CWE-79", "CWE-22"],  # WAF Coverage
        "Req 8.2": ["CWE-522", "CWE-798"],  # Password Requirements
        "Req 4.1": ["CWE-319", "CWE-295"],  # Encryption in Transit
    },
    ComplianceFramework.OWASP_TOP10: {
        "A01:2021 Broken Access Control": ["CWE-639", "CWE-863", "CWE-862", "CWE-22"],
        "A02:2021 Cryptographic Failures": ["CWE-327", "CWE-312", "CWE-319", "CWE-295"],
        "A03:2021 Injection": ["CWE-89", "CWE-79", "CWE-78", "CWE-611", "CWE-917"],
        "A04:2021 Insecure Design": ["CWE-352", "CWE-1021"],
        "A05:2021 Security Misconfiguration": ["CWE-942", "CWE-200"],
        "A06:2021 Vulnerable Components": ["CWE-1104"],
        "A07:2021 Identification Failures": [
            "CWE-287",
            "CWE-306",
            "CWE-522",
            "CWE-798",
        ],
        "A08:2021 Data Integrity Failures": ["CWE-502"],
        "A09:2021 Logging Failures": ["CWE-778"],
        "A10:2021 SSRF": ["CWE-918"],
    },
    ComplianceFramework.NIST_CSF: {
        "PR.AC-1 Identity Management": ["CWE-287", "CWE-306"],
        "PR.AC-4 Access Control": ["CWE-863", "CWE-862", "CWE-639"],
        "PR.DS-1 Data-at-Rest": ["CWE-312"],
        "PR.DS-2 Data-in-Transit": ["CWE-319", "CWE-295"],
        "PR.DS-5 Leak Protection": ["CWE-200", "CWE-918"],
        "PR.IP-12 Vulnerability Management": ["CWE-1104"],
        "DE.CM-8 Vulnerability Scan": ["CWE-89", "CWE-79", "CWE-78"],
    },
    ComplianceFramework.GDPR: {
        "Art 25 Data Protection by Design": ["CWE-312", "CWE-319", "CWE-200"],
        "Art 32 Security of Processing": ["CWE-327", "CWE-295", "CWE-522"],
        "Art 33 Breach Notification": ["CWE-778"],
        "Art 5(1)(f) Integrity & Confidentiality": ["CWE-89", "CWE-22", "CWE-918"],
    },
    ComplianceFramework.HIPAA: {
        "§164.312(a)(1) Access Control": ["CWE-287", "CWE-863", "CWE-862"],
        "§164.312(c)(1) Integrity": ["CWE-89", "CWE-502"],
        "§164.312(e)(1) Transmission Security": ["CWE-319", "CWE-295"],
        "§164.312(d) Authentication": ["CWE-287", "CWE-522", "CWE-798"],
    },
}

# Vuln type to CWE reverse-map
VULN_TYPE_CWE: Dict[str, str] = {
    "sqli": "CWE-89",
    "xss": "CWE-79",
    "cmdi": "CWE-78",
    "lfi": "CWE-22",
    "xxe": "CWE-611",
    "ssrf": "CWE-918",
    "rce": "CWE-94",
    "auth_bypass": "CWE-287",
    "idor": "CWE-639",
    "deserialization": "CWE-502",
    "ssti": "CWE-917",
    "jwt_weakness": "CWE-287",
    "cors_misconfiguration": "CWE-942",
    "open_redirect": "CWE-601",
    "csrf": "CWE-352",
    "file_upload": "CWE-434",
    "info_disclosure": "CWE-200",
    "hardcoded_creds": "CWE-798",
    "weak_crypto": "CWE-327",
    "session_fixation": "CWE-384",
    "privilege_escalation": "CWE-269",
}


# ════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ════════════════════════════════════════════════════════════════════════════


@dataclass
class ATTACKMapping:
    """MITRE ATT&CK mapping for a finding."""

    tactic_id: str = ""
    tactic_name: str = ""
    technique_id: str = ""
    technique_name: str = ""
    kill_chain_phase: KillChainPhase = KillChainPhase.EXPLOITATION
    confidence: float = 0.0


@dataclass
class ThreatActorCorrelation:
    """Correlation between findings and a threat actor."""

    actor_name: str = ""
    aliases: List[str] = field(default_factory=list)
    origin: str = ""
    correlation_score: float = 0.0  # 0-1.0
    matching_techniques: List[str] = field(default_factory=list)
    matching_cwes: List[str] = field(default_factory=list)
    description: str = ""


@dataclass
class ComplianceViolation:
    """A compliance framework violation."""

    framework: ComplianceFramework = ComplianceFramework.OWASP_TOP10
    requirement: str = ""
    violated_by: List[str] = field(default_factory=list)  # Finding IDs/names
    cwes_matched: List[str] = field(default_factory=list)
    severity: ThreatLevel = ThreatLevel.MEDIUM


@dataclass
class ExploitPrediction:
    """Predictive exploit scoring for a vulnerability."""

    finding_name: str = ""
    cwe: str = ""
    epss_like_score: float = 0.0  # 0-1.0, probability of exploitation in 30 days
    weaponization_score: float = 0.0  # 0-1.0, ease of weaponization
    factors: List[str] = field(default_factory=list)


@dataclass
class ThreatHuntQuery:
    """Auto-generated threat hunt query for SIEM/SOAR."""

    name: str = ""
    description: str = ""
    query_type: str = ""  # splunk, elastic, sigma
    query: str = ""
    related_techniques: List[str] = field(default_factory=list)
    severity: ThreatLevel = ThreatLevel.MEDIUM


@dataclass
class ThreatIntelReport:
    """Complete threat intelligence correlation report."""

    attack_mappings: List[ATTACKMapping] = field(default_factory=list)
    actor_correlations: List[ThreatActorCorrelation] = field(default_factory=list)
    compliance_violations: Dict[str, List[ComplianceViolation]] = field(
        default_factory=dict
    )
    exploit_predictions: List[ExploitPrediction] = field(default_factory=list)
    hunt_queries: List[ThreatHuntQuery] = field(default_factory=list)
    kill_chain_coverage: Dict[str, List[str]] = field(default_factory=dict)
    overall_threat_level: ThreatLevel = ThreatLevel.MEDIUM
    generation_time: float = 0.0

    @property
    def critical_actors(self) -> List[ThreatActorCorrelation]:
        return [a for a in self.actor_correlations if a.correlation_score >= 0.6]

    @property
    def compliance_summary(self) -> Dict[str, int]:
        return {
            fw: len(violations) for fw, violations in self.compliance_violations.items()
        }


# ════════════════════════════════════════════════════════════════════════════
# SIREN THREAT INTEL ENGINE
# ════════════════════════════════════════════════════════════════════════════


class SirenThreatIntel:
    """Threat Intelligence Correlation Engine.

    Transforms raw vulnerability findings into actionable threat intelligence:
    1. Maps findings to MITRE ATT&CK tactics and techniques
    2. Correlates with known threat actor profiles
    3. Checks compliance framework violations
    4. Predicts exploitation probability (EPSS-like)
    5. Generates threat hunt queries for SIEM/SOAR
    6. Maps to Lockheed Martin Cyber Kill Chain
    7. Produces geopolitical risk assessment

    No external APIs required — all intelligence is embedded.
    """

    VERSION = "1.0.0"

    def __init__(
        self,
        industry: IndustryVertical = IndustryVertical.TECHNOLOGY,
        compliance_frameworks: Optional[List[ComplianceFramework]] = None,
    ) -> None:
        self.industry = industry
        self.frameworks = compliance_frameworks or [
            ComplianceFramework.OWASP_TOP10,
            ComplianceFramework.PCI_DSS,
        ]
        self._findings: List[Dict[str, Any]] = []

    def ingest_findings(self, findings: List[Dict[str, Any]]) -> None:
        """Ingest vulnerability findings for correlation."""
        self._findings = findings
        logger.info("Ingested %d findings for threat intel analysis", len(findings))

    def analyze(self) -> ThreatIntelReport:
        """Run complete threat intelligence analysis."""
        start_time = time.monotonic()
        report = ThreatIntelReport()

        # 1. MITRE ATT&CK mapping
        report.attack_mappings = self._map_to_attack()

        # 2. Kill chain coverage
        report.kill_chain_coverage = self._map_kill_chain(report.attack_mappings)

        # 3. Threat actor correlation
        report.actor_correlations = self._correlate_actors(report.attack_mappings)

        # 4. Compliance violations
        for framework in self.frameworks:
            violations = self._check_compliance(framework)
            if violations:
                report.compliance_violations[framework.value] = violations

        # 5. Exploit predictions
        report.exploit_predictions = self._predict_exploitation()

        # 6. Threat hunt queries
        report.hunt_queries = self._generate_hunt_queries(report.attack_mappings)

        # 7. Overall threat level
        report.overall_threat_level = self._assess_threat_level(report)

        report.generation_time = time.monotonic() - start_time
        logger.info(
            "Threat intel analysis complete in %.3fs: %d ATT&CK mappings, "
            "%d actor correlations, %d compliance violations",
            report.generation_time,
            len(report.attack_mappings),
            len(report.actor_correlations),
            sum(len(v) for v in report.compliance_violations.values()),
        )

        return report

    def _map_to_attack(self) -> List[ATTACKMapping]:
        """Map findings to MITRE ATT&CK tactics and techniques."""
        mappings: List[ATTACKMapping] = []

        for finding in self._findings:
            cwe = self._extract_cwe(finding)
            if not cwe:
                continue

            technique_ids = CWE_TO_ATTACK.get(cwe, [])
            for tech_id in technique_ids:
                # Find which tactic contains this technique
                for tactic_id, tactic_data in MITRE_TACTICS.items():
                    if tech_id in tactic_data["techniques"]:
                        mappings.append(
                            ATTACKMapping(
                                tactic_id=tactic_id,
                                tactic_name=tactic_data["name"],
                                technique_id=tech_id,
                                technique_name=tactic_data["techniques"][tech_id],
                                kill_chain_phase=tactic_data["kill_chain"],
                                confidence=self._calc_mapping_confidence(finding, cwe),
                            )
                        )

        return mappings

    def _map_kill_chain(self, mappings: List[ATTACKMapping]) -> Dict[str, List[str]]:
        """Map findings to Kill Chain phases."""
        coverage: Dict[str, List[str]] = defaultdict(list)
        for mapping in mappings:
            phase = mapping.kill_chain_phase.value
            entry = f"{mapping.technique_id}: {mapping.technique_name}"
            if entry not in coverage[phase]:
                coverage[phase].append(entry)
        return dict(coverage)

    def _correlate_actors(
        self, mappings: List[ATTACKMapping]
    ) -> List[ThreatActorCorrelation]:
        """Correlate findings with known threat actor profiles."""
        found_techniques = {m.technique_id for m in mappings}
        found_cwes = {
            self._extract_cwe(f) for f in self._findings if self._extract_cwe(f)
        }

        correlations: List[ThreatActorCorrelation] = []

        for actor_name, profile in APT_PROFILES.items():
            # Check industry targeting
            targets_our_industry = self.industry in profile.get("targets", [])

            # Technique overlap
            actor_techniques = set(profile.get("preferred_techniques", []))
            technique_overlap = found_techniques & actor_techniques
            technique_score = len(technique_overlap) / max(len(actor_techniques), 1)

            # CWE overlap
            actor_cwes = set(profile.get("preferred_cwes", []))
            cwe_overlap = found_cwes & actor_cwes
            cwe_score = len(cwe_overlap) / max(len(actor_cwes), 1)

            # Composite score
            base_score = technique_score * 0.5 + cwe_score * 0.5
            industry_bonus = 0.2 if targets_our_industry else 0.0
            sophistication = profile.get("sophistication", 0.5)

            correlation_score = min(
                base_score * sophistication + industry_bonus,
                1.0,
            )

            if correlation_score > 0.1:
                correlations.append(
                    ThreatActorCorrelation(
                        actor_name=actor_name,
                        aliases=profile.get("aliases", []),
                        origin=profile.get("origin", "Unknown"),
                        correlation_score=correlation_score,
                        matching_techniques=list(technique_overlap),
                        matching_cwes=list(cwe_overlap),
                        description=(
                            f"{actor_name} ({', '.join(profile.get('aliases', [])[:2])}) — "
                            f"{profile.get('origin', 'Unknown')} origin, targets "
                            f"{', '.join(t.value for t in profile.get('targets', []))}"
                        ),
                    )
                )

        correlations.sort(key=lambda c: c.correlation_score, reverse=True)
        return correlations

    def _check_compliance(
        self, framework: ComplianceFramework
    ) -> List[ComplianceViolation]:
        """Check findings against a compliance framework."""
        violations: List[ComplianceViolation] = []
        framework_map = COMPLIANCE_CWE_MAP.get(framework, {})

        found_cwes = {self._extract_cwe(f) for f in self._findings}
        finding_by_cwe: Dict[str, List[str]] = defaultdict(list)
        for finding in self._findings:
            cwe = self._extract_cwe(finding)
            if cwe:
                finding_by_cwe[cwe].append(finding.get("title", "Unknown"))

        for requirement, req_cwes in framework_map.items():
            matched_cwes = [c for c in req_cwes if c in found_cwes]
            if matched_cwes:
                violated_findings = []
                for cwe in matched_cwes:
                    violated_findings.extend(finding_by_cwe.get(cwe, []))

                severity = (
                    ThreatLevel.HIGH if len(matched_cwes) >= 2 else ThreatLevel.MEDIUM
                )
                violations.append(
                    ComplianceViolation(
                        framework=framework,
                        requirement=requirement,
                        violated_by=violated_findings,
                        cwes_matched=matched_cwes,
                        severity=severity,
                    )
                )

        return violations

    def _predict_exploitation(self) -> List[ExploitPrediction]:
        """Predict exploitation probability for each finding (EPSS-like)."""
        predictions: List[ExploitPrediction] = []

        for finding in self._findings:
            cwe = self._extract_cwe(finding)
            cvss = finding.get("cvss_score", 5.0)
            severity = finding.get("severity", "medium").lower()

            factors: List[str] = []
            score = 0.0

            # Factor 1: CVSS score (normalized 0-1)
            cvss_factor = min(cvss / 10.0, 1.0)
            score += cvss_factor * 0.3
            if cvss >= 9.0:
                factors.append("Critical CVSS (9.0+)")
            elif cvss >= 7.0:
                factors.append("High CVSS (7.0+)")

            # Factor 2: Known weaponized CWEs
            high_weaponization_cwes = {
                "CWE-89",
                "CWE-78",
                "CWE-502",
                "CWE-434",
                "CWE-94",
                "CWE-917",
                "CWE-798",
            }
            if cwe in high_weaponization_cwes:
                score += 0.25
                factors.append(f"Known weaponized CWE ({cwe})")

            # Factor 3: Network-accessible (most web vulns are)
            if finding.get("url"):
                score += 0.15
                factors.append("Network-accessible")

            # Factor 4: ATT&CK technique coverage
            techniques = CWE_TO_ATTACK.get(cwe or "", [])
            if techniques:
                score += 0.1
                factors.append(f"Maps to {len(techniques)} ATT&CK techniques")

            # Factor 5: Industry-targeted
            relevant_actors = sum(
                1
                for profile in APT_PROFILES.values()
                if self.industry in profile.get("targets", [])
                and cwe in profile.get("preferred_cwes", [])
            )
            if relevant_actors > 0:
                score += 0.1 * min(relevant_actors, 3)
                factors.append(f"Targeted by {relevant_actors} threat actor(s)")

            # Factor 6: Confirmed vs suspected
            confidence = finding.get("confidence", "").lower()
            if confidence == "confirmed":
                score += 0.1
                factors.append("Confirmed vulnerability")

            # Weaponization score
            weaponization = 0.0
            if cwe in high_weaponization_cwes:
                weaponization = 0.9
            elif cvss >= 7.0:
                weaponization = 0.7
            elif cvss >= 4.0:
                weaponization = 0.4
            else:
                weaponization = 0.2

            predictions.append(
                ExploitPrediction(
                    finding_name=finding.get("title", "Unknown"),
                    cwe=cwe or "",
                    epss_like_score=min(score, 1.0),
                    weaponization_score=weaponization,
                    factors=factors,
                )
            )

        predictions.sort(key=lambda p: p.epss_like_score, reverse=True)
        return predictions

    def _generate_hunt_queries(
        self, mappings: List[ATTACKMapping]
    ) -> List[ThreatHuntQuery]:
        """Generate threat hunt queries for SIEM/SOAR platforms."""
        queries: List[ThreatHuntQuery] = []
        seen_techniques: Set[str] = set()

        # Technique-specific hunt queries
        hunt_templates: Dict[str, Dict[str, str]] = {
            "T1190": {
                "name": "Exploit Public-Facing Application",
                "splunk": (
                    "index=web sourcetype=access_combined "
                    "(status=500 OR status=400) "
                    "| stats count by src_ip, uri_path, status "
                    "| where count > 50 "
                    "| sort -count"
                ),
                "elastic": (
                    '{"query":{"bool":{"must":[{"range":{"http.response.status_code":{"gte":400}}}],'
                    '"filter":[{"range":{"@timestamp":{"gte":"now-24h"}}}]}},'
                    '"aggs":{"by_ip":{"terms":{"field":"source.ip","size":20}}}}'
                ),
                "sigma": (
                    "title: Potential Web Application Exploit\n"
                    "status: experimental\n"
                    "logsource:\n"
                    "    category: webserver\n"
                    "detection:\n"
                    "    selection:\n"
                    "        sc-status|startswith:\n"
                    '            - "50"\n'
                    '            - "40"\n'
                    "    condition: selection | count() by c-ip > 50"
                ),
            },
            "T1059": {
                "name": "Command and Scripting Interpreter",
                "splunk": (
                    "index=web "
                    '(uri_query="*;*" OR uri_query="*|*" OR uri_query="*`*" '
                    'OR uri_query="*$(*" OR uri_query="*%0a*") '
                    "| table _time, src_ip, uri_path, uri_query"
                ),
                "sigma": (
                    "title: Command Injection Attempt\n"
                    "status: experimental\n"
                    "logsource:\n"
                    "    category: webserver\n"
                    "detection:\n"
                    "    selection:\n"
                    "        cs-uri-query|contains:\n"
                    '            - ";"\n'
                    '            - "|"\n'
                    '            - "`"\n'
                    '            - "$("\n'
                    "    condition: selection"
                ),
            },
            "T1110": {
                "name": "Brute Force",
                "splunk": (
                    "index=auth action=failure "
                    "| stats count by src_ip, user "
                    "| where count > 10 "
                    "| sort -count"
                ),
                "sigma": (
                    "title: Brute Force Authentication\n"
                    "status: experimental\n"
                    "logsource:\n"
                    "    category: authentication\n"
                    "detection:\n"
                    "    selection:\n"
                    "        action: failure\n"
                    "    condition: selection | count() by src_ip > 10"
                ),
            },
            "T1552": {
                "name": "Unsecured Credentials",
                "splunk": (
                    "index=* sourcetype=* "
                    '("password" OR "api_key" OR "secret" OR "token") '
                    "NOT (sourcetype=auth OR sourcetype=access_) "
                    "| table _time, source, _raw"
                ),
                "sigma": (
                    "title: Credential Exposure in Logs\n"
                    "status: experimental\n"
                    "logsource:\n"
                    "    category: application\n"
                    "detection:\n"
                    "    keywords:\n"
                    '        - "password="\n'
                    '        - "api_key="\n'
                    '        - "secret="\n'
                    '        - "token="\n'
                    "    condition: keywords"
                ),
            },
            "T1078": {
                "name": "Valid Accounts",
                "splunk": (
                    "index=auth action=success "
                    "| stats dc(src_ip) as unique_ips, values(src_ip) as ips by user "
                    "| where unique_ips > 5 "
                    "| sort -unique_ips"
                ),
                "sigma": (
                    "title: Account Used from Multiple IPs\n"
                    "status: experimental\n"
                    "logsource:\n"
                    "    category: authentication\n"
                    "detection:\n"
                    "    selection:\n"
                    "        action: success\n"
                    "    condition: selection | count(src_ip) by user > 5"
                ),
            },
            "T1539": {
                "name": "Steal Web Session Cookie",
                "splunk": (
                    "index=web "
                    '(uri_query="*document.cookie*" OR uri_query="*<script>*") '
                    "| table _time, src_ip, uri_path, uri_query"
                ),
                "sigma": (
                    "title: Session Cookie Theft Attempt\n"
                    "status: experimental\n"
                    "logsource:\n"
                    "    category: webserver\n"
                    "detection:\n"
                    "    selection:\n"
                    "        cs-uri-query|contains:\n"
                    '            - "document.cookie"\n'
                    '            - "<script>"\n'
                    "    condition: selection"
                ),
            },
        }

        for mapping in mappings:
            if mapping.technique_id in seen_techniques:
                continue
            seen_techniques.add(mapping.technique_id)

            templates = hunt_templates.get(mapping.technique_id)
            if not templates:
                continue

            for query_type in ("splunk", "elastic", "sigma"):
                if query_type in templates:
                    queries.append(
                        ThreatHuntQuery(
                            name=f"Hunt: {templates['name']} ({mapping.technique_id})",
                            description=(
                                f"Detect indicators of {templates['name']} "
                                f"({mapping.tactic_name})"
                            ),
                            query_type=query_type,
                            query=templates[query_type],
                            related_techniques=[mapping.technique_id],
                            severity=(
                                ThreatLevel.HIGH
                                if mapping.confidence > 0.7
                                else ThreatLevel.MEDIUM
                            ),
                        )
                    )

        return queries

    def _assess_threat_level(self, report: ThreatIntelReport) -> ThreatLevel:
        """Assess overall threat level based on all analysis."""
        score = 0.0

        # Factor 1: High-confidence ATT&CK mappings
        high_conf = sum(1 for m in report.attack_mappings if m.confidence > 0.7)
        score += min(high_conf * 5, 25)

        # Factor 2: Threat actor correlations
        if report.critical_actors:
            score += min(len(report.critical_actors) * 15, 30)

        # Factor 3: Kill chain coverage (more phases = more complete attack)
        covered_phases = len(report.kill_chain_coverage)
        score += covered_phases * 5

        # Factor 4: Compliance violations
        total_violations = sum(len(v) for v in report.compliance_violations.values())
        score += min(total_violations * 3, 20)

        # Factor 5: Exploit predictions
        high_epss = sum(
            1 for p in report.exploit_predictions if p.epss_like_score > 0.7
        )
        score += min(high_epss * 5, 15)

        if score >= 70:
            return ThreatLevel.CRITICAL
        if score >= 50:
            return ThreatLevel.HIGH
        if score >= 30:
            return ThreatLevel.MEDIUM
        if score >= 10:
            return ThreatLevel.LOW
        return ThreatLevel.INFORMATIONAL

    def _extract_cwe(self, finding: Dict[str, Any]) -> Optional[str]:
        """Extract CWE from a finding dict."""
        # Direct CWE field
        cwe = finding.get("cwe", "") or finding.get("cwe_id", "")
        if cwe:
            cwe_str = str(cwe)
            if cwe_str.startswith("CWE-"):
                return cwe_str
            if cwe_str.isdigit():
                return f"CWE-{cwe_str}"
            return cwe_str

        # From vuln type
        vuln_type = finding.get("vuln_type", "") or finding.get("category", "")
        if vuln_type:
            return VULN_TYPE_CWE.get(vuln_type.lower())

        # From title keywords
        title = finding.get("title", "").lower()
        for vtype, cwe_val in VULN_TYPE_CWE.items():
            if vtype.replace("_", " ") in title:
                return cwe_val

        return None

    def _calc_mapping_confidence(self, finding: Dict[str, Any], cwe: str) -> float:
        """Calculate confidence of ATT&CK mapping."""
        confidence = 0.5

        # Confirmed findings get higher confidence
        if finding.get("confidence", "").lower() == "confirmed":
            confidence += 0.2
        elif finding.get("confidence", "").lower() == "high":
            confidence += 0.1

        # High CVSS = more likely mapped correctly
        cvss = finding.get("cvss_score", 0)
        if cvss >= 7.0:
            confidence += 0.15
        elif cvss >= 4.0:
            confidence += 0.05

        # Known weaponized CWEs have higher confidence
        if cwe in CWE_TO_ATTACK:
            confidence += 0.1

        return min(confidence, 1.0)

    def generate_report(self, report: ThreatIntelReport) -> str:
        """Generate a comprehensive threat intelligence report."""
        lines: List[str] = [
            "# 🛡️ SIREN Threat Intelligence Correlation Report",
            "",
            f"**Overall Threat Level: {report.overall_threat_level.value.upper()}**",
            f"**Analysis Time: {report.generation_time:.3f}s**",
            f"**Findings Analyzed: {len(self._findings)}**",
            f"**Industry: {self.industry.value}**",
            "",
        ]

        # ATT&CK Coverage
        if report.attack_mappings:
            unique_tactics = {m.tactic_name for m in report.attack_mappings}
            unique_techniques = {m.technique_id for m in report.attack_mappings}
            lines.append(f"## 🎯 MITRE ATT&CK Coverage")
            lines.append(
                f"**{len(unique_tactics)} Tactics, {len(unique_techniques)} Techniques**"
            )
            lines.append("")
            lines.append("| Tactic | Technique | Confidence |")
            lines.append("|--------|-----------|------------|")
            seen = set()
            for m in sorted(
                report.attack_mappings, key=lambda x: x.confidence, reverse=True
            ):
                key = f"{m.tactic_id}:{m.technique_id}"
                if key in seen:
                    continue
                seen.add(key)
                lines.append(
                    f"| {m.tactic_name} | {m.technique_id}: {m.technique_name} | "
                    f"{m.confidence:.0%} |"
                )
            lines.append("")

        # Kill Chain Coverage
        if report.kill_chain_coverage:
            lines.append("## ⛓️ Kill Chain Coverage")
            lines.append("")
            for phase in KillChainPhase:
                techs = report.kill_chain_coverage.get(phase.value, [])
                icon = "🔴" if techs else "⚪"
                lines.append(
                    f"- {icon} **{phase.value.replace('_', ' ').title()}**: "
                    f"{len(techs)} techniques"
                )
            lines.append("")

        # Threat Actors
        if report.actor_correlations:
            lines.append("## 🕵️ Threat Actor Correlations")
            lines.append("")
            for actor in report.actor_correlations[:5]:
                bar = "█" * int(actor.correlation_score * 20)
                lines.append(
                    f"### {actor.actor_name} ({actor.origin}) — "
                    f"{actor.correlation_score:.0%}"
                )
                lines.append(f"**{bar}** {actor.correlation_score:.0%}")
                lines.append(f"- Aliases: {', '.join(actor.aliases)}")
                if actor.matching_techniques:
                    lines.append(
                        f"- Matching techniques: {', '.join(actor.matching_techniques)}"
                    )
                if actor.matching_cwes:
                    lines.append(f"- Matching CWEs: {', '.join(actor.matching_cwes)}")
                lines.append("")

        # Exploit Predictions
        if report.exploit_predictions:
            lines.append("## 🎲 Exploit Prediction (EPSS-like Scoring)")
            lines.append("")
            lines.append("| Finding | EPSS Score | Weaponization | Key Factors |")
            lines.append("|---------|-----------|---------------|-------------|")
            for pred in report.exploit_predictions[:15]:
                factors_str = "; ".join(pred.factors[:3])
                lines.append(
                    f"| {pred.finding_name[:40]} | {pred.epss_like_score:.0%} | "
                    f"{pred.weaponization_score:.0%} | {factors_str} |"
                )
            lines.append("")

        # Compliance Violations
        if report.compliance_violations:
            lines.append("## 📋 Compliance Violations")
            lines.append("")
            for fw_name, violations in report.compliance_violations.items():
                lines.append(f"### {fw_name.upper()}: {len(violations)} violations")
                for v in violations:
                    lines.append(
                        f"- **{v.requirement}** — "
                        f"CWEs: {', '.join(v.cwes_matched)} — "
                        f"Affected: {len(v.violated_by)} findings"
                    )
                lines.append("")

        # Hunt Queries
        if report.hunt_queries:
            lines.append("## 🔍 Threat Hunt Queries")
            lines.append("")
            for query in report.hunt_queries[:10]:
                lines.append(f"### {query.name} ({query.query_type})")
                lines.append(f"```{query.query_type}")
                lines.append(query.query)
                lines.append("```")
                lines.append("")

        return "\n".join(lines)
