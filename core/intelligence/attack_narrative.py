#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  📖  SIREN ATTACK NARRATIVE — Storytelling Engine de Segurança  📖            ██
██                                                                                ██
██  Transforma findings técnicos em narrativas compreensíveis para QUALQUER      ██
██  audiência — do CISO ao dev junior ao board executivo.                         ██
██                                                                                ██
██  Capacidades:                                                                  ██
██    • Timeline chapters — reconstrução cronológica do ataque                   ██
██    • Multi-audience adaptation — técnico / executivo / compliance              ██
██    • Risk quantification — traduz CVSS em impacto financeiro                  ██
██    • Kill chain mapping — narrativa segue MITRE ATT&CK phases                 ██
██    • Evidence linking — cada afirmação tem prova técnica                       ██
██    • Analogias intuitivas — explica SQLi como "arrombamento"                  ██
██    • Compliance mapping — OWASP/PCI-DSS/GDPR/HIPAA/SOC2                      ██
██    • Markdown/HTML/PDF-ready output                                           ██
██                                                                                ██
██  "SIREN não gera relatórios — ela conta HISTÓRIAS que movem pessoas."         ██
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
from collections import OrderedDict, defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

logger = logging.getLogger("siren.intelligence.attack_narrative")


# ════════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════════════════════════════

MAX_CHAPTERS = 50
MAX_FINDINGS_PER_CHAPTER = 25
DEFAULT_HOURLY_RATE_USD = 150.0  # Average incident response cost
DEFAULT_BREACH_COST_PER_RECORD = 164.0  # IBM Cost of Data Breach 2025


# ════════════════════════════════════════════════════════════════════════════════
# ENUMS
# ════════════════════════════════════════════════════════════════════════════════


class Audience(Enum):
    """Target audience for the narrative."""
    TECHNICAL = "technical"        # Devs, SREs, pentesters
    EXECUTIVE = "executive"        # C-suite, board, investors
    COMPLIANCE = "compliance"      # Auditors, legal, GRC
    DEVELOPER = "developer"        # Specific dev team
    MANAGEMENT = "management"      # Middle management, team leads
    INCIDENT_RESPONSE = "ir"       # SOC analysts, CSIRT


class NarrativeTone(Enum):
    """Tone of the generated narrative."""
    FORMAL = "formal"
    URGENT = "urgent"
    EDUCATIONAL = "educational"
    FORENSIC = "forensic"
    PERSUASIVE = "persuasive"


class ChapterType(Enum):
    """Types of narrative chapters."""
    EXECUTIVE_SUMMARY = "executive_summary"
    ATTACK_SURFACE = "attack_surface"
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXPLOITATION = "exploitation"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    PERSISTENCE = "persistence"
    IMPACT_ANALYSIS = "impact_analysis"
    RISK_QUANTIFICATION = "risk_quantification"
    REMEDIATION = "remediation"
    COMPLIANCE_MAPPING = "compliance_mapping"
    TIMELINE = "timeline"
    LESSONS_LEARNED = "lessons_learned"


class OutputFormat(Enum):
    """Supported output formats."""
    MARKDOWN = "markdown"
    HTML = "html"
    JSON = "json"
    PLAIN_TEXT = "plain_text"


class RiskLevel(Enum):
    """Qualitative risk levels with financial multipliers."""
    CRITICAL = ("critical", 1.0)
    HIGH = ("high", 0.7)
    MEDIUM = ("medium", 0.3)
    LOW = ("low", 0.1)
    INFO = ("info", 0.0)

    def __init__(self, label: str, multiplier: float):
        self.label = label
        self.multiplier = multiplier


class ComplianceFramework(Enum):
    """Compliance frameworks for mapping."""
    OWASP_TOP10 = "owasp_top10"
    PCI_DSS = "pci_dss"
    GDPR = "gdpr"
    HIPAA = "hipaa"
    SOC2 = "soc2"
    NIST_CSF = "nist_csf"
    ISO_27001 = "iso_27001"
    CIS_CONTROLS = "cis_controls"


class KillChainPhase(Enum):
    """MITRE ATT&CK Kill Chain phases."""
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource_development"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    COMMAND_AND_CONTROL = "command_and_control"
    IMPACT = "impact"


# ════════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ════════════════════════════════════════════════════════════════════════════════


@dataclass
class Finding:
    """A single security finding to be narrated."""
    finding_id: str
    title: str
    description: str
    severity: RiskLevel = RiskLevel.MEDIUM
    cvss_score: float = 0.0
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None
    affected_component: str = ""
    evidence: str = ""
    reproduction_steps: List[str] = field(default_factory=list)
    kill_chain_phase: Optional[KillChainPhase] = None
    remediation: str = ""
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def risk_score(self) -> float:
        """Combined risk score from severity and CVSS."""
        cvss_norm = self.cvss_score / 10.0 if self.cvss_score > 0 else self.severity.multiplier
        return cvss_norm * 100.0


@dataclass
class NarrativeChapter:
    """A single chapter in the attack narrative."""
    chapter_id: str
    chapter_type: ChapterType
    title: str
    content: str = ""
    findings: List[Finding] = field(default_factory=list)
    order: int = 0
    audience: Audience = Audience.TECHNICAL
    risk_level: RiskLevel = RiskLevel.INFO
    metadata: Dict[str, Any] = field(default_factory=dict)
    subsections: List[Dict[str, str]] = field(default_factory=list)

    @property
    def word_count(self) -> int:
        return len(self.content.split())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "chapter_id": self.chapter_id,
            "chapter_type": self.chapter_type.value,
            "title": self.title,
            "content": self.content,
            "findings_count": len(self.findings),
            "order": self.order,
            "audience": self.audience.value,
            "risk_level": self.risk_level.label,
            "word_count": self.word_count,
            "subsections": self.subsections,
        }


@dataclass
class AttackTimeline:
    """Chronological reconstruction of the attack flow."""
    timeline_id: str
    target: str = ""
    start_time: float = 0.0
    end_time: float = 0.0
    events: List[TimelineEvent] = field(default_factory=list)
    phases_detected: List[KillChainPhase] = field(default_factory=list)
    total_findings: int = 0
    critical_path: List[str] = field(default_factory=list)

    def duration_seconds(self) -> float:
        if self.start_time > 0 and self.end_time > 0:
            return self.end_time - self.start_time
        return 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timeline_id": self.timeline_id,
            "target": self.target,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": self.duration_seconds(),
            "events": [e.to_dict() for e in self.events],
            "phases_detected": [p.value for p in self.phases_detected],
            "total_findings": self.total_findings,
            "critical_path": self.critical_path,
        }


@dataclass
class TimelineEvent:
    """A single event in the attack timeline."""
    event_id: str
    timestamp: float
    phase: KillChainPhase
    description: str
    finding_ids: List[str] = field(default_factory=list)
    severity: RiskLevel = RiskLevel.INFO
    technique_id: str = ""  # MITRE ATT&CK technique ID
    success: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "phase": self.phase.value,
            "description": self.description,
            "finding_ids": self.finding_ids,
            "severity": self.severity.label,
            "technique_id": self.technique_id,
            "success": self.success,
        }


@dataclass
class RiskQuantification:
    """Financial and operational risk quantification."""
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    estimated_breach_cost_usd: float = 0.0
    estimated_remediation_hours: float = 0.0
    estimated_remediation_cost_usd: float = 0.0
    records_at_risk: int = 0
    compliance_violations: Dict[str, List[str]] = field(default_factory=dict)
    risk_score_overall: float = 0.0  # 0-100
    annualized_loss_expectancy: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_findings": self.total_findings,
            "severity_breakdown": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
            },
            "financial_impact": {
                "estimated_breach_cost_usd": round(self.estimated_breach_cost_usd, 2),
                "estimated_remediation_hours": round(self.estimated_remediation_hours, 1),
                "estimated_remediation_cost_usd": round(self.estimated_remediation_cost_usd, 2),
                "annualized_loss_expectancy": round(self.annualized_loss_expectancy, 2),
            },
            "records_at_risk": self.records_at_risk,
            "compliance_violations": self.compliance_violations,
            "risk_score_overall": round(self.risk_score_overall, 1),
        }


# ════════════════════════════════════════════════════════════════════════════════
# COMPLIANCE KNOWLEDGE BASE
# ════════════════════════════════════════════════════════════════════════════════

# Maps CWE IDs to compliance framework violations
CWE_COMPLIANCE_MAP: Dict[str, Dict[str, List[str]]] = {
    "CWE-89": {
        ComplianceFramework.OWASP_TOP10.value: ["A03:2021 - Injection"],
        ComplianceFramework.PCI_DSS.value: ["6.5.1 - SQL Injection"],
        ComplianceFramework.GDPR.value: ["Art.32 - Security of processing"],
        ComplianceFramework.NIST_CSF.value: ["PR.DS-5 - Data leak protection"],
        ComplianceFramework.SOC2.value: ["CC6.1 - Logical access security"],
    },
    "CWE-79": {
        ComplianceFramework.OWASP_TOP10.value: ["A03:2021 - Injection"],
        ComplianceFramework.PCI_DSS.value: ["6.5.7 - XSS"],
        ComplianceFramework.NIST_CSF.value: ["PR.DS-5 - Data leak protection"],
    },
    "CWE-287": {
        ComplianceFramework.OWASP_TOP10.value: ["A07:2021 - Auth Failures"],
        ComplianceFramework.PCI_DSS.value: ["8.2 - Authentication management"],
        ComplianceFramework.HIPAA.value: ["164.312(d) - Person authentication"],
        ComplianceFramework.SOC2.value: ["CC6.1 - Logical access security"],
    },
    "CWE-862": {
        ComplianceFramework.OWASP_TOP10.value: ["A01:2021 - Broken Access Control"],
        ComplianceFramework.PCI_DSS.value: ["7.1 - Restrict access by need to know"],
        ComplianceFramework.GDPR.value: ["Art.25 - Data protection by design"],
    },
    "CWE-798": {
        ComplianceFramework.OWASP_TOP10.value: ["A07:2021 - Auth Failures"],
        ComplianceFramework.PCI_DSS.value: ["2.1 - Change vendor defaults"],
        ComplianceFramework.NIST_CSF.value: ["PR.AC-1 - Credential management"],
    },
    "CWE-22": {
        ComplianceFramework.OWASP_TOP10.value: ["A01:2021 - Broken Access Control"],
        ComplianceFramework.PCI_DSS.value: ["6.5.8 - Improper access control"],
    },
    "CWE-611": {
        ComplianceFramework.OWASP_TOP10.value: ["A05:2021 - Security Misconfiguration"],
        ComplianceFramework.PCI_DSS.value: ["6.5.1 - Injection flaws"],
    },
    "CWE-918": {
        ComplianceFramework.OWASP_TOP10.value: ["A10:2021 - SSRF"],
        ComplianceFramework.NIST_CSF.value: ["PR.AC-5 - Network integrity"],
    },
    "CWE-502": {
        ComplianceFramework.OWASP_TOP10.value: ["A08:2021 - Software/Data Integrity"],
        ComplianceFramework.PCI_DSS.value: ["6.5.1 - Injection flaws"],
    },
    "CWE-327": {
        ComplianceFramework.OWASP_TOP10.value: ["A02:2021 - Cryptographic Failures"],
        ComplianceFramework.PCI_DSS.value: ["4.1 - Strong cryptography"],
        ComplianceFramework.GDPR.value: ["Art.32 - Encryption"],
        ComplianceFramework.HIPAA.value: ["164.312(a)(2)(iv) - Encryption"],
    },
    "CWE-200": {
        ComplianceFramework.OWASP_TOP10.value: ["A01:2021 - Broken Access Control"],
        ComplianceFramework.GDPR.value: ["Art.5(1)(f) - Confidentiality"],
        ComplianceFramework.HIPAA.value: ["164.312(a)(1) - Access control"],
    },
    "CWE-434": {
        ComplianceFramework.OWASP_TOP10.value: ["A04:2021 - Insecure Design"],
        ComplianceFramework.PCI_DSS.value: ["6.5.8 - Improper access control"],
    },
}


# ════════════════════════════════════════════════════════════════════════════════
# ANALOGY ENGINE — Makes technical concepts accessible
# ════════════════════════════════════════════════════════════════════════════════

VULNERABILITY_ANALOGIES: Dict[str, Dict[str, str]] = {
    "CWE-89": {
        "executive": "É como se alguém pudesse entrar no seu banco e alterar registros "
                     "simplesmente escrevendo comandos num formulário de papel.",
        "compliance": "Falha de validação de entrada permite manipulação direta "
                      "do banco de dados através de parâmetros não sanitizados.",
        "developer": "Input do usuário concatenado diretamente em queries SQL "
                     "sem prepared statements ou parametrização.",
    },
    "CWE-79": {
        "executive": "Um atacante pode injetar código malicioso que roda no "
                     "navegador dos seus clientes, roubando senhas e dados.",
        "compliance": "Falha de sanitização de saída permite execução de "
                      "scripts arbitrários no contexto do navegador do usuário.",
        "developer": "Output não escapado permite injeção de <script> tags. "
                     "Use encoding contextual (HTML/JS/URL) em toda saída.",
    },
    "CWE-287": {
        "executive": "A porta da frente do seu sistema está destrancada — "
                     "qualquer pessoa pode entrar sem se identificar.",
        "compliance": "Mecanismo de autenticação bypass permite acesso "
                      "não autorizado a recursos protegidos.",
        "developer": "Falha no fluxo de autenticação: verificação de "
                     "credenciais pode ser contornada.",
    },
    "CWE-862": {
        "executive": "Uma vez dentro do prédio, qualquer pessoa pode abrir "
                     "qualquer gaveta — não há controle de quem acessa o quê.",
        "compliance": "Ausência de verificação de autorização em endpoints "
                      "críticos permite escalada horizontal/vertical.",
        "developer": "Missing authorization checks — verifique permissões "
                     "em CADA endpoint, não apenas na autenticação.",
    },
    "CWE-798": {
        "executive": "A senha do cofre está escrita num post-it colado na parede "
                     "— qualquer um que olhar o código fonte encontra.",
        "compliance": "Credenciais codificadas no código-fonte permitem "
                      "acesso não autorizado após vazamento de código.",
        "developer": "Hard-coded credentials detectadas. Use variáveis de "
                     "ambiente ou secrets manager (Vault, AWS SSM, etc).",
    },
    "CWE-22": {
        "executive": "Um invasor pode navegar livremente pelos arquivos do "
                     "servidor, como alguém que entra no seu escritório e "
                     "abre todas as pastas do arquivo morto.",
        "compliance": "Path traversal permite leitura/escrita arbitrária "
                      "no sistema de arquivos do servidor.",
        "developer": "Input com ../ não sanitizado. Canonicalize paths e "
                     "valide contra um diretório base (chroot-like).",
    },
    "CWE-918": {
        "executive": "O atacante pode fazer seu servidor acessar sistemas "
                     "internos da empresa — como convencer um funcionário "
                     "a clicar em links internos.",
        "compliance": "Server-Side Request Forgery permite que atacantes "
                      "acessem recursos internos através do servidor.",
        "developer": "SSRF: valide URLs de destino com allowlist, bloqueie "
                     "endereços internos (10.x, 172.16.x, 169.254.x).",
    },
    "CWE-327": {
        "executive": "Seus dados confidenciais estão protegidos por um "
                     "cadeado enferrujado que qualquer um pode abrir.",
        "compliance": "Uso de algoritmos criptográficos obsoletos/fracos "
                      "compromete a confidencialidade dos dados.",
        "developer": "Algoritmo fraco detectado. Migre para AES-256-GCM, "
                     "ChaCha20-Poly1305, ou RSA-4096+ com OAEP padding.",
    },
}


# ════════════════════════════════════════════════════════════════════════════════
# REMEDIATION TIME ESTIMATES (hours)
# ════════════════════════════════════════════════════════════════════════════════

REMEDIATION_HOURS: Dict[str, float] = {
    "CWE-89": 8.0,    # SQLi — prepared statements throughout
    "CWE-79": 12.0,   # XSS — output encoding audit
    "CWE-287": 24.0,   # Auth bypass — redesign auth flow
    "CWE-862": 16.0,   # Broken access — add authorization layer
    "CWE-798": 4.0,    # Hardcoded creds — move to env/vault
    "CWE-22": 6.0,     # Path traversal — canonicalize
    "CWE-611": 2.0,    # XXE — disable DTD
    "CWE-918": 8.0,    # SSRF — URL allowlist
    "CWE-502": 16.0,   # Deserialization — safe alternatives
    "CWE-327": 20.0,   # Weak crypto — algorithm migration
    "CWE-200": 4.0,    # Info disclosure — error handling
    "CWE-434": 8.0,    # File upload — content validation
    "CWE-352": 6.0,    # CSRF — token implementation
    "CWE-306": 16.0,   # Missing auth — add auth middleware
    "CWE-732": 4.0,    # Incorrect permissions — fix ACLs
}

DEFAULT_REMEDIATION_HOURS = 8.0


# ════════════════════════════════════════════════════════════════════════════════
# NARRATIVE ENGINE — Core generation
# ════════════════════════════════════════════════════════════════════════════════


class NarrativeEngine:
    """
    Core engine that transforms technical findings into narrative chapters.

    Thread-safe. Supports multiple audiences and output formats.
    Each chapter is generated algorithmically without LLM dependency.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._findings: List[Finding] = []
        self._chapters: OrderedDict[str, NarrativeChapter] = OrderedDict()
        self._timeline: Optional[AttackTimeline] = None
        self._risk: Optional[RiskQuantification] = None
        self._chapter_counter = 0

    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the narrative pool."""
        with self._lock:
            self._findings.append(finding)

    def add_findings(self, findings: List[Finding]) -> None:
        """Add multiple findings."""
        with self._lock:
            self._findings.extend(findings)

    def clear(self) -> None:
        """Reset all state."""
        with self._lock:
            self._findings.clear()
            self._chapters.clear()
            self._timeline = None
            self._risk = None
            self._chapter_counter = 0

    # ── Chapter Generation ──────────────────────────────────────────────────

    def generate_narrative(
        self,
        target: str,
        audience: Audience = Audience.TECHNICAL,
        include_chapters: Optional[List[ChapterType]] = None,
    ) -> List[NarrativeChapter]:
        """
        Generate the full narrative from accumulated findings.

        Args:
            target: Target name/URL for context
            audience: Target audience
            include_chapters: Specific chapters to include, or None for auto

        Returns:
            Ordered list of narrative chapters
        """
        with self._lock:
            if not self._findings:
                return []

            # Build timeline first
            self._timeline = self._build_timeline(target)

            # Quantify risk
            self._risk = self._quantify_risk()

            # Determine chapters to generate
            chapter_types = include_chapters or self._auto_chapter_selection()

            chapters = []
            for ct in chapter_types:
                chapter = self._generate_chapter(ct, target, audience)
                if chapter and chapter.content:
                    chapters.append(chapter)

            # Sort by order
            chapters.sort(key=lambda c: c.order)
            self._chapters = OrderedDict(
                (c.chapter_id, c) for c in chapters
            )
            return chapters

    def _auto_chapter_selection(self) -> List[ChapterType]:
        """Automatically select chapters based on findings."""
        chapters = [ChapterType.EXECUTIVE_SUMMARY]

        # Map findings to kill chain phases
        phases_found: Set[KillChainPhase] = set()
        for f in self._findings:
            if f.kill_chain_phase:
                phases_found.add(f.kill_chain_phase)

        # Add phase-specific chapters
        phase_to_chapter = {
            KillChainPhase.RECONNAISSANCE: ChapterType.RECONNAISSANCE,
            KillChainPhase.INITIAL_ACCESS: ChapterType.INITIAL_ACCESS,
            KillChainPhase.EXECUTION: ChapterType.EXPLOITATION,
            KillChainPhase.PRIVILEGE_ESCALATION: ChapterType.PRIVILEGE_ESCALATION,
            KillChainPhase.LATERAL_MOVEMENT: ChapterType.LATERAL_MOVEMENT,
            KillChainPhase.EXFILTRATION: ChapterType.DATA_EXFILTRATION,
            KillChainPhase.PERSISTENCE: ChapterType.PERSISTENCE,
        }
        for phase, chapter_type in phase_to_chapter.items():
            if phase in phases_found:
                chapters.append(chapter_type)

        # Always include these
        chapters.extend([
            ChapterType.IMPACT_ANALYSIS,
            ChapterType.RISK_QUANTIFICATION,
            ChapterType.REMEDIATION,
        ])

        # Add compliance if any CWEs mapped
        has_compliance = any(
            f.cwe_id and f.cwe_id in CWE_COMPLIANCE_MAP
            for f in self._findings
        )
        if has_compliance:
            chapters.append(ChapterType.COMPLIANCE_MAPPING)

        chapters.append(ChapterType.TIMELINE)
        return chapters

    def _generate_chapter(
        self,
        chapter_type: ChapterType,
        target: str,
        audience: Audience,
    ) -> Optional[NarrativeChapter]:
        """Generate a single chapter."""
        self._chapter_counter += 1
        cid = f"ch-{self._chapter_counter:03d}-{chapter_type.value}"

        generators = {
            ChapterType.EXECUTIVE_SUMMARY: self._gen_executive_summary,
            ChapterType.ATTACK_SURFACE: self._gen_attack_surface,
            ChapterType.RECONNAISSANCE: self._gen_recon,
            ChapterType.INITIAL_ACCESS: self._gen_initial_access,
            ChapterType.EXPLOITATION: self._gen_exploitation,
            ChapterType.PRIVILEGE_ESCALATION: self._gen_privesc,
            ChapterType.LATERAL_MOVEMENT: self._gen_lateral,
            ChapterType.DATA_EXFILTRATION: self._gen_exfiltration,
            ChapterType.PERSISTENCE: self._gen_persistence,
            ChapterType.IMPACT_ANALYSIS: self._gen_impact,
            ChapterType.RISK_QUANTIFICATION: self._gen_risk_quant,
            ChapterType.REMEDIATION: self._gen_remediation,
            ChapterType.COMPLIANCE_MAPPING: self._gen_compliance,
            ChapterType.TIMELINE: self._gen_timeline_chapter,
            ChapterType.LESSONS_LEARNED: self._gen_lessons,
        }

        gen_fn = generators.get(chapter_type)
        if not gen_fn:
            return None

        title, content, findings, subs = gen_fn(target, audience)

        order_map = {ct: i for i, ct in enumerate(ChapterType)}

        max_risk = RiskLevel.INFO
        for f in findings:
            if f.severity.multiplier > max_risk.multiplier:
                max_risk = f.severity

        return NarrativeChapter(
            chapter_id=cid,
            chapter_type=chapter_type,
            title=title,
            content=content,
            findings=findings,
            order=order_map.get(chapter_type, 99),
            audience=audience,
            risk_level=max_risk,
            subsections=subs,
        )

    # ── Chapter Generators ──────────────────────────────────────────────────

    def _gen_executive_summary(
        self, target: str, audience: Audience
    ) -> Tuple[str, str, List[Finding], List[Dict[str, str]]]:
        """Executive summary — high-level overview."""
        risk = self._risk or self._quantify_risk()
        findings = self._findings

        severity_counts = {
            "critical": risk.critical_count,
            "high": risk.high_count,
            "medium": risk.medium_count,
            "low": risk.low_count,
        }

        if audience == Audience.EXECUTIVE:
            content = self._exec_summary_executive(target, risk, severity_counts)
        elif audience == Audience.COMPLIANCE:
            content = self._exec_summary_compliance(target, risk, severity_counts)
        else:
            content = self._exec_summary_technical(target, risk, severity_counts)

        return "Sumário Executivo", content, findings, []

    def _exec_summary_executive(
        self, target: str, risk: RiskQuantification, counts: Dict[str, int]
    ) -> str:
        """Executive-friendly summary focused on business impact."""
        lines = [
            f"## Sumário Executivo — {target}\n",
            f"A avaliação de segurança de **{target}** identificou "
            f"**{risk.total_findings} vulnerabilidades**, das quais "
            f"**{counts['critical']} são críticas** e "
            f"**{counts['high']} são de alto risco**.\n",
        ]

        if risk.estimated_breach_cost_usd > 0:
            lines.append(
                f"**Impacto financeiro estimado em caso de exploração:** "
                f"US$ {risk.estimated_breach_cost_usd:,.0f}\n"
            )

        if risk.records_at_risk > 0:
            lines.append(
                f"**Registros em risco:** {risk.records_at_risk:,} registros "
                f"de dados sensíveis potencialmente expostos.\n"
            )

        lines.append(
            f"**Custo estimado de remediação:** "
            f"US$ {risk.estimated_remediation_cost_usd:,.0f} "
            f"({risk.estimated_remediation_hours:.0f} horas de trabalho)\n"
        )

        if risk.risk_score_overall >= 80:
            lines.append(
                "⚠️ **RECOMENDAÇÃO URGENTE:** O nível de risco atual é CRÍTICO. "
                "Ação imediata é necessária para prevenir uma violação de dados.\n"
            )
        elif risk.risk_score_overall >= 50:
            lines.append(
                "⚠️ **ATENÇÃO:** O nível de risco é ALTO. Plano de remediação "
                "deve ser iniciado nas próximas 2 semanas.\n"
            )

        return "\n".join(lines)

    def _exec_summary_technical(
        self, target: str, risk: RiskQuantification, counts: Dict[str, int]
    ) -> str:
        """Technical summary with details."""
        lines = [
            f"## Relatório de Segurança — {target}\n",
            f"**Findings:** {risk.total_findings} total "
            f"(🔴 {counts['critical']} critical | 🟠 {counts['high']} high | "
            f"🟡 {counts['medium']} medium | 🟢 {counts['low']} low)\n",
            f"**Risk Score:** {risk.risk_score_overall:.1f}/100\n",
        ]

        # Top 5 most severe findings
        sorted_findings = sorted(
            self._findings, key=lambda f: f.risk_score, reverse=True
        )[:5]

        if sorted_findings:
            lines.append("### Top Findings\n")
            for i, f in enumerate(sorted_findings, 1):
                cwe = f" [{f.cwe_id}]" if f.cwe_id else ""
                lines.append(
                    f"{i}. **{f.title}**{cwe} — "
                    f"CVSS {f.cvss_score:.1f} | {f.severity.label.upper()}\n"
                    f"   {f.description[:200]}\n"
                )

        return "\n".join(lines)

    def _exec_summary_compliance(
        self, target: str, risk: RiskQuantification, counts: Dict[str, int]
    ) -> str:
        """Compliance-focused summary."""
        lines = [
            f"## Relatório de Conformidade — {target}\n",
            f"Foram identificadas **{risk.total_findings} não-conformidades** "
            f"durante a avaliação de segurança.\n",
        ]

        if risk.compliance_violations:
            lines.append("### Violações por Framework\n")
            for framework, violations in risk.compliance_violations.items():
                lines.append(f"**{framework.upper()}:** {len(violations)} violações")
                for v in violations[:5]:
                    lines.append(f"  - {v}")
                lines.append("")

        return "\n".join(lines)

    def _gen_attack_surface(
        self, target: str, audience: Audience
    ) -> Tuple[str, str, List[Finding], List[Dict[str, str]]]:
        """Attack surface analysis chapter."""
        findings = [
            f for f in self._findings
            if f.kill_chain_phase in (
                KillChainPhase.RECONNAISSANCE,
                KillChainPhase.DISCOVERY,
            )
        ]

        components: Dict[str, List[Finding]] = defaultdict(list)
        for f in self._findings:
            if f.affected_component:
                components[f.affected_component].append(f)

        lines = [f"## Superfície de Ataque — {target}\n"]

        if components:
            lines.append(f"**{len(components)} componentes** expostos:\n")
            for comp, comp_findings in sorted(
                components.items(),
                key=lambda x: max(f.risk_score for f in x[1]),
                reverse=True,
            ):
                max_sev = max(f.severity.multiplier for f in comp_findings)
                icon = "🔴" if max_sev >= 0.9 else "🟠" if max_sev >= 0.6 else "🟡"
                lines.append(
                    f"- {icon} **{comp}** — {len(comp_findings)} findings"
                )

        return "Superfície de Ataque", "\n".join(lines), findings, []

    def _gen_phase_chapter(
        self,
        target: str,
        audience: Audience,
        title: str,
        phases: List[KillChainPhase],
        intro_template: str,
    ) -> Tuple[str, str, List[Finding], List[Dict[str, str]]]:
        """Generic phase-based chapter generator."""
        findings = [
            f for f in self._findings
            if f.kill_chain_phase in phases
        ]

        if not findings:
            return title, "", [], []

        lines = [f"## {title}\n", intro_template.format(count=len(findings)), ""]

        adapter = AudienceAdapter()
        for f in sorted(findings, key=lambda x: x.risk_score, reverse=True):
            adapted = adapter.adapt_finding(f, audience)
            lines.append(adapted)
            lines.append("")

        return title, "\n".join(lines), findings, []

    def _gen_recon(
        self, target: str, audience: Audience
    ) -> Tuple[str, str, List[Finding], List[Dict[str, str]]]:
        return self._gen_phase_chapter(
            target, audience,
            "Reconhecimento",
            [KillChainPhase.RECONNAISSANCE, KillChainPhase.RESOURCE_DEVELOPMENT],
            "Foram identificados **{count} indicadores** durante a fase de reconhecimento.",
        )

    def _gen_initial_access(
        self, target: str, audience: Audience
    ) -> Tuple[str, str, List[Finding], List[Dict[str, str]]]:
        return self._gen_phase_chapter(
            target, audience,
            "Acesso Inicial",
            [KillChainPhase.INITIAL_ACCESS],
            "**{count} vetores** de acesso inicial foram identificados.",
        )

    def _gen_exploitation(
        self, target: str, audience: Audience
    ) -> Tuple[str, str, List[Finding], List[Dict[str, str]]]:
        return self._gen_phase_chapter(
            target, audience,
            "Exploração",
            [KillChainPhase.EXECUTION],
            "**{count} vulnerabilidades** foram exploradas com sucesso.",
        )

    def _gen_privesc(
        self, target: str, audience: Audience
    ) -> Tuple[str, str, List[Finding], List[Dict[str, str]]]:
        return self._gen_phase_chapter(
            target, audience,
            "Escalada de Privilégios",
            [KillChainPhase.PRIVILEGE_ESCALATION],
            "**{count} caminhos** de escalada de privilégios identificados.",
        )

    def _gen_lateral(
        self, target: str, audience: Audience
    ) -> Tuple[str, str, List[Finding], List[Dict[str, str]]]:
        return self._gen_phase_chapter(
            target, audience,
            "Movimentação Lateral",
            [KillChainPhase.LATERAL_MOVEMENT],
            "**{count} possibilidades** de movimentação lateral detectadas.",
        )

    def _gen_exfiltration(
        self, target: str, audience: Audience
    ) -> Tuple[str, str, List[Finding], List[Dict[str, str]]]:
        return self._gen_phase_chapter(
            target, audience,
            "Exfiltração de Dados",
            [KillChainPhase.EXFILTRATION, KillChainPhase.COLLECTION],
            "**{count} vetores** de exfiltração de dados identificados.",
        )

    def _gen_persistence(
        self, target: str, audience: Audience
    ) -> Tuple[str, str, List[Finding], List[Dict[str, str]]]:
        return self._gen_phase_chapter(
            target, audience,
            "Persistência",
            [KillChainPhase.PERSISTENCE],
            "**{count} mecanismos** de persistência possíveis detectados.",
        )

    def _gen_impact(
        self, target: str, audience: Audience
    ) -> Tuple[str, str, List[Finding], List[Dict[str, str]]]:
        """Impact analysis chapter."""
        risk = self._risk or self._quantify_risk()
        findings = sorted(self._findings, key=lambda f: f.risk_score, reverse=True)

        lines = [
            f"## Análise de Impacto\n",
            f"A exploração das vulnerabilidades identificadas pode resultar em:\n",
        ]

        impacts = []
        for f in findings:
            if f.severity in (RiskLevel.CRITICAL, RiskLevel.HIGH):
                if f.cwe_id in ("CWE-89", "CWE-502"):
                    impacts.append("Comprometimento completo do banco de dados")
                elif f.cwe_id == "CWE-287":
                    impacts.append("Acesso não autorizado a contas de usuários")
                elif f.cwe_id == "CWE-862":
                    impacts.append("Escalada de privilégios para nível administrativo")
                elif f.cwe_id == "CWE-22":
                    impacts.append("Leitura arbitrária de arquivos do servidor")
                elif f.cwe_id == "CWE-918":
                    impacts.append("Acesso a serviços internos e infraestrutura")
                elif f.cwe_id == "CWE-798":
                    impacts.append("Comprometimento de credenciais de serviço")
                else:
                    impacts.append(f"Exploração de {f.title}")

        for impact in dict.fromkeys(impacts):  # Dedupe preserving order
            lines.append(f"- 💥 {impact}")

        lines.extend([
            "",
            f"**Score de risco geral:** {risk.risk_score_overall:.1f}/100",
            f"**Classificação:** {'CRÍTICO' if risk.risk_score_overall >= 80 else 'ALTO' if risk.risk_score_overall >= 50 else 'MÉDIO' if risk.risk_score_overall >= 30 else 'BAIXO'}",
        ])

        return "Análise de Impacto", "\n".join(lines), findings, []

    def _gen_risk_quant(
        self, target: str, audience: Audience
    ) -> Tuple[str, str, List[Finding], List[Dict[str, str]]]:
        """Risk quantification chapter."""
        risk = self._risk or self._quantify_risk()

        lines = [
            "## Quantificação de Risco\n",
            "### Distribuição por Severidade\n",
            f"| Severidade | Quantidade | % do Total |",
            f"|------------|-----------|------------|",
        ]

        total = max(risk.total_findings, 1)
        for label, count in [
            ("🔴 Crítico", risk.critical_count),
            ("🟠 Alto", risk.high_count),
            ("🟡 Médio", risk.medium_count),
            ("🟢 Baixo", risk.low_count),
        ]:
            pct = (count / total) * 100
            lines.append(f"| {label} | {count} | {pct:.0f}% |")

        lines.extend([
            "",
            "### Impacto Financeiro Estimado\n",
        ])

        if audience == Audience.EXECUTIVE:
            lines.extend([
                f"- **Custo estimado de uma violação:** US$ {risk.estimated_breach_cost_usd:,.0f}",
                f"- **Perda anualizada esperada (ALE):** US$ {risk.annualized_loss_expectancy:,.0f}",
                f"- **Custo de remediação:** US$ {risk.estimated_remediation_cost_usd:,.0f}",
                f"- **ROI da remediação:** {self._calc_remediation_roi(risk):.0f}x",
                "",
                "💡 **Para cada US$ 1 investido em remediação, evita-se "
                f"US$ {self._calc_remediation_roi(risk):.0f} em potenciais perdas.**",
            ])
        else:
            lines.extend([
                f"- Breach cost estimate: US$ {risk.estimated_breach_cost_usd:,.0f}",
                f"- Remediation: {risk.estimated_remediation_hours:.0f}h "
                f"(US$ {risk.estimated_remediation_cost_usd:,.0f})",
                f"- ALE: US$ {risk.annualized_loss_expectancy:,.0f}",
            ])

        return "Quantificação de Risco", "\n".join(lines), self._findings, []

    def _gen_remediation(
        self, target: str, audience: Audience
    ) -> Tuple[str, str, List[Finding], List[Dict[str, str]]]:
        """Remediation roadmap chapter."""
        findings = sorted(self._findings, key=lambda f: f.risk_score, reverse=True)

        lines = [
            "## Plano de Remediação\n",
            "### Priorização (por risco)\n",
        ]

        # Group by priority
        immediate = [f for f in findings if f.severity == RiskLevel.CRITICAL]
        short_term = [f for f in findings if f.severity == RiskLevel.HIGH]
        medium_term = [f for f in findings if f.severity == RiskLevel.MEDIUM]
        long_term = [f for f in findings if f.severity in (RiskLevel.LOW, RiskLevel.INFO)]

        priority_groups = [
            ("🔴 IMEDIATO (0-48h)", immediate),
            ("🟠 CURTO PRAZO (1-2 semanas)", short_term),
            ("🟡 MÉDIO PRAZO (1-3 meses)", medium_term),
            ("🟢 LONGO PRAZO (backlog)", long_term),
        ]

        for group_name, group_findings in priority_groups:
            if not group_findings:
                continue

            total_hours = sum(
                REMEDIATION_HOURS.get(f.cwe_id or "", DEFAULT_REMEDIATION_HOURS)
                for f in group_findings
            )

            lines.append(f"\n#### {group_name}")
            lines.append(f"*Estimativa: {total_hours:.0f} horas*\n")

            for f in group_findings:
                hours = REMEDIATION_HOURS.get(f.cwe_id or "", DEFAULT_REMEDIATION_HOURS)
                lines.append(f"- **{f.title}** (~{hours:.0f}h)")
                if f.remediation:
                    lines.append(f"  - Fix: {f.remediation}")
                elif f.cwe_id and audience == Audience.DEVELOPER:
                    analogy = VULNERABILITY_ANALOGIES.get(f.cwe_id, {})
                    dev_tip = analogy.get("developer", "")
                    if dev_tip:
                        lines.append(f"  - 💡 {dev_tip}")

        return "Plano de Remediação", "\n".join(lines), findings, []

    def _gen_compliance(
        self, target: str, audience: Audience
    ) -> Tuple[str, str, List[Finding], List[Dict[str, str]]]:
        """Compliance mapping chapter."""
        risk = self._risk or self._quantify_risk()

        lines = [
            "## Mapeamento de Conformidade\n",
            "Mapeamento das vulnerabilidades contra frameworks regulatórios:\n",
        ]

        # Aggregate all violations
        all_violations: Dict[str, Set[str]] = defaultdict(set)
        for f in self._findings:
            if f.cwe_id and f.cwe_id in CWE_COMPLIANCE_MAP:
                for framework, items in CWE_COMPLIANCE_MAP[f.cwe_id].items():
                    for item in items:
                        all_violations[framework].add(
                            f"{item} (via {f.cwe_id}: {f.title})"
                        )

        for framework in sorted(all_violations.keys()):
            violations = sorted(all_violations[framework])
            lines.append(f"\n### {framework.upper().replace('_', ' ')}")
            lines.append(f"**{len(violations)} violações identificadas:**\n")
            for v in violations:
                lines.append(f"- ❌ {v}")

        if not all_violations:
            lines.append(
                "Nenhuma violação de conformidade mapeada para as "
                "vulnerabilidades encontradas."
            )

        return "Mapeamento de Conformidade", "\n".join(lines), self._findings, []

    def _gen_timeline_chapter(
        self, target: str, audience: Audience
    ) -> Tuple[str, str, List[Finding], List[Dict[str, str]]]:
        """Timeline visualization chapter."""
        timeline = self._timeline
        if not timeline or not timeline.events:
            return "Timeline", "", [], []

        lines = [
            "## Timeline do Ataque\n",
            f"**Alvo:** {target}",
            f"**Duração:** {timeline.duration_seconds():.1f}s",
            f"**Fases detectadas:** {len(timeline.phases_detected)}",
            f"**Eventos:** {len(timeline.events)}\n",
        ]

        # Group events by phase
        phase_events: Dict[str, List[TimelineEvent]] = defaultdict(list)
        for event in timeline.events:
            phase_events[event.phase.value].append(event)

        for phase in KillChainPhase:
            events = phase_events.get(phase.value, [])
            if not events:
                continue

            lines.append(f"\n### {phase.value.replace('_', ' ').title()}")
            for evt in sorted(events, key=lambda e: e.timestamp):
                icon = "✅" if evt.success else "❌"
                sev = evt.severity.label[0].upper()
                tech = f" [{evt.technique_id}]" if evt.technique_id else ""
                lines.append(
                    f"- {icon} `[{sev}]`{tech} {evt.description}"
                )

        if timeline.critical_path:
            lines.extend([
                "\n### Caminho Crítico",
                "A sequência mais provável de exploração:",
                "",
            ])
            for i, step in enumerate(timeline.critical_path, 1):
                lines.append(f"{i}. {step}")

        return "Timeline do Ataque", "\n".join(lines), self._findings, []

    def _gen_lessons(
        self, target: str, audience: Audience
    ) -> Tuple[str, str, List[Finding], List[Dict[str, str]]]:
        """Lessons learned chapter."""
        lines = [
            "## Lições Aprendidas\n",
        ]

        # Analyze patterns
        cwe_counts: Dict[str, int] = defaultdict(int)
        for f in self._findings:
            if f.cwe_id:
                cwe_counts[f.cwe_id] += 1

        if cwe_counts:
            top_cwe = sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True)[:5]
            lines.append("### Padrões Recorrentes\n")
            for cwe, count in top_cwe:
                lines.append(f"- **{cwe}** apareceu {count}x — indica problema sistêmico")

        lines.extend([
            "",
            "### Recomendações Estratégicas\n",
            "1. **Security by Design** — Integrar segurança desde o design",
            "2. **SAST/DAST no CI/CD** — Automatizar detecção",
            "3. **Security Champions** — Treinar desenvolvedores",
            "4. **Threat Modeling** — Mapear ameaças antes de codificar",
            "5. **Incident Response Plan** — Preparar resposta a incidentes",
        ])

        return "Lições Aprendidas", "\n".join(lines), self._findings, []

    # ── Internal Helpers ────────────────────────────────────────────────────

    def _build_timeline(self, target: str) -> AttackTimeline:
        """Build chronological timeline from findings."""
        tid = hashlib.md5(target.encode()).hexdigest()[:12]
        timeline = AttackTimeline(
            timeline_id=f"tl-{tid}",
            target=target,
        )

        events = []
        phases_seen: Set[KillChainPhase] = set()

        for f in sorted(self._findings, key=lambda x: x.timestamp):
            phase = f.kill_chain_phase or KillChainPhase.DISCOVERY
            phases_seen.add(phase)

            event = TimelineEvent(
                event_id=f"evt-{f.finding_id}",
                timestamp=f.timestamp,
                phase=phase,
                description=f.title,
                finding_ids=[f.finding_id],
                severity=f.severity,
                technique_id=f.metadata.get("technique_id", ""),
                success=True,
            )
            events.append(event)

        timeline.events = events
        timeline.phases_detected = sorted(phases_seen, key=lambda p: list(KillChainPhase).index(p))
        timeline.total_findings = len(self._findings)

        if events:
            timeline.start_time = events[0].timestamp
            timeline.end_time = events[-1].timestamp

        # Build critical path (most severe findings in order)
        critical_findings = sorted(
            [f for f in self._findings if f.severity in (RiskLevel.CRITICAL, RiskLevel.HIGH)],
            key=lambda x: x.timestamp,
        )
        timeline.critical_path = [f.title for f in critical_findings[:10]]

        return timeline

    def _quantify_risk(self) -> RiskQuantification:
        """Calculate risk quantification from findings."""
        risk = RiskQuantification()
        risk.total_findings = len(self._findings)

        for f in self._findings:
            if f.severity == RiskLevel.CRITICAL:
                risk.critical_count += 1
            elif f.severity == RiskLevel.HIGH:
                risk.high_count += 1
            elif f.severity == RiskLevel.MEDIUM:
                risk.medium_count += 1
            else:
                risk.low_count += 1

        # Estimate records at risk (conservative)
        has_data_vuln = any(
            f.cwe_id in ("CWE-89", "CWE-502", "CWE-22", "CWE-200", "CWE-862")
            for f in self._findings if f.cwe_id
        )
        if has_data_vuln:
            risk.records_at_risk = 10000  # Conservative baseline

        # Financial estimates
        risk.estimated_breach_cost_usd = (
            risk.records_at_risk * DEFAULT_BREACH_COST_PER_RECORD
            if risk.records_at_risk > 0
            else (risk.critical_count * 500_000 + risk.high_count * 100_000)
        )

        # Remediation estimates
        total_hours = 0.0
        for f in self._findings:
            total_hours += REMEDIATION_HOURS.get(
                f.cwe_id or "", DEFAULT_REMEDIATION_HOURS
            )
        risk.estimated_remediation_hours = total_hours
        risk.estimated_remediation_cost_usd = total_hours * DEFAULT_HOURLY_RATE_USD

        # Overall risk score (0-100)
        score = min(100.0, (
            risk.critical_count * 25.0
            + risk.high_count * 15.0
            + risk.medium_count * 5.0
            + risk.low_count * 1.0
        ))
        risk.risk_score_overall = score

        # Annualized Loss Expectancy
        # ALE = SLE × ARO (Single Loss Expectancy × Annual Rate of Occurrence)
        breach_probability = min(0.95, 0.05 + risk.critical_count * 0.15 + risk.high_count * 0.08)
        risk.annualized_loss_expectancy = risk.estimated_breach_cost_usd * breach_probability

        # Compliance violations
        violations: Dict[str, List[str]] = defaultdict(list)
        for f in self._findings:
            if f.cwe_id and f.cwe_id in CWE_COMPLIANCE_MAP:
                for framework, items in CWE_COMPLIANCE_MAP[f.cwe_id].items():
                    violations[framework].extend(items)
        risk.compliance_violations = {k: list(set(v)) for k, v in violations.items()}

        return risk

    @staticmethod
    def _calc_remediation_roi(risk: RiskQuantification) -> float:
        """Calculate ROI of remediation investment."""
        if risk.estimated_remediation_cost_usd <= 0:
            return 0.0
        return risk.annualized_loss_expectancy / max(
            risk.estimated_remediation_cost_usd, 1.0
        )


# ════════════════════════════════════════════════════════════════════════════════
# AUDIENCE ADAPTER — Translates findings for different audiences
# ════════════════════════════════════════════════════════════════════════════════


class AudienceAdapter:
    """
    Adapts technical findings for different audiences.

    Uses the analogy engine to make findings accessible to non-technical
    stakeholders, while preserving full detail for technical audiences.
    """

    def adapt_finding(self, finding: Finding, audience: Audience) -> str:
        """Adapt a single finding for the target audience."""
        if audience == Audience.EXECUTIVE:
            return self._adapt_executive(finding)
        elif audience == Audience.COMPLIANCE:
            return self._adapt_compliance(finding)
        elif audience == Audience.DEVELOPER:
            return self._adapt_developer(finding)
        elif audience == Audience.INCIDENT_RESPONSE:
            return self._adapt_ir(finding)
        else:
            return self._adapt_technical(finding)

    def _adapt_executive(self, f: Finding) -> str:
        """Executive: business impact, no jargon."""
        lines = [f"### {f.title}"]
        lines.append(f"**Risco:** {f.severity.label.upper()} | **Impacto:** ", )

        analogy = VULNERABILITY_ANALOGIES.get(f.cwe_id or "", {})
        exec_analogy = analogy.get("executive", "")

        if exec_analogy:
            lines.append(f"\n> 💡 {exec_analogy}\n")
        else:
            lines.append(f"\n{f.description[:300]}\n")

        return "\n".join(lines)

    def _adapt_compliance(self, f: Finding) -> str:
        """Compliance: framework mappings, control references."""
        lines = [f"### {f.title}"]
        lines.append(f"**CWE:** {f.cwe_id or 'N/A'} | **CVSS:** {f.cvss_score:.1f}")

        analogy = VULNERABILITY_ANALOGIES.get(f.cwe_id or "", {})
        comp_desc = analogy.get("compliance", f.description[:300])
        lines.append(f"\n{comp_desc}\n")

        # Add compliance mappings
        if f.cwe_id and f.cwe_id in CWE_COMPLIANCE_MAP:
            lines.append("**Frameworks afetados:**")
            for framework, items in CWE_COMPLIANCE_MAP[f.cwe_id].items():
                for item in items:
                    lines.append(f"- {framework}: {item}")

        return "\n".join(lines)

    def _adapt_developer(self, f: Finding) -> str:
        """Developer: technical details, fix code."""
        lines = [
            f"### {f.title}",
            f"**CWE:** {f.cwe_id or 'N/A'} | **Componente:** {f.affected_component}",
        ]

        analogy = VULNERABILITY_ANALOGIES.get(f.cwe_id or "", {})
        dev_desc = analogy.get("developer", "")
        if dev_desc:
            lines.append(f"\n⚠️ {dev_desc}\n")

        if f.evidence:
            lines.append(f"**Evidência:**\n```\n{f.evidence[:500]}\n```\n")

        if f.reproduction_steps:
            lines.append("**Reprodução:**")
            for i, step in enumerate(f.reproduction_steps, 1):
                lines.append(f"{i}. {step}")

        if f.remediation:
            lines.append(f"\n**Fix:** {f.remediation}")

        return "\n".join(lines)

    def _adapt_ir(self, f: Finding) -> str:
        """Incident Response: IOCs, timeline, detection."""
        lines = [
            f"### {f.title}",
            f"**Severidade:** {f.severity.label.upper()} | "
            f"**CVSS:** {f.cvss_score:.1f}",
        ]

        if f.kill_chain_phase:
            lines.append(
                f"**Kill Chain Phase:** {f.kill_chain_phase.value.replace('_', ' ').title()}"
            )

        technique = f.metadata.get("technique_id", "")
        if technique:
            lines.append(f"**MITRE ATT&CK:** {technique}")

        lines.append(f"\n{f.description}\n")

        if f.evidence:
            lines.append(f"**IOCs/Evidência:**\n```\n{f.evidence[:500]}\n```")

        return "\n".join(lines)

    def _adapt_technical(self, f: Finding) -> str:
        """Full technical detail."""
        lines = [
            f"### {f.title}",
            f"**ID:** {f.finding_id} | **CWE:** {f.cwe_id or 'N/A'} | "
            f"**CVSS:** {f.cvss_score:.1f} | **Sev:** {f.severity.label.upper()}",
            f"**Componente:** {f.affected_component}",
            f"\n{f.description}\n",
        ]

        if f.evidence:
            lines.append(f"**Evidência:**\n```\n{f.evidence}\n```\n")

        if f.reproduction_steps:
            lines.append("**Passos de Reprodução:**")
            for i, step in enumerate(f.reproduction_steps, 1):
                lines.append(f"{i}. {step}")

        if f.remediation:
            lines.append(f"\n**Remediação:** {f.remediation}")

        if f.cve_id:
            lines.append(f"**CVE:** {f.cve_id}")

        return "\n".join(lines)


# ════════════════════════════════════════════════════════════════════════════════
# FORMAT RENDERER — Output in multiple formats
# ════════════════════════════════════════════════════════════════════════════════


class FormatRenderer:
    """Renders narrative chapters into different output formats."""

    def render(
        self,
        chapters: List[NarrativeChapter],
        output_format: OutputFormat = OutputFormat.MARKDOWN,
        title: str = "SIREN Security Assessment",
    ) -> str:
        """Render chapters to the specified format."""
        renderers = {
            OutputFormat.MARKDOWN: self._render_markdown,
            OutputFormat.HTML: self._render_html,
            OutputFormat.JSON: self._render_json,
            OutputFormat.PLAIN_TEXT: self._render_plain,
        }
        renderer = renderers.get(output_format, self._render_markdown)
        return renderer(chapters, title)

    def _render_markdown(
        self, chapters: List[NarrativeChapter], title: str
    ) -> str:
        """Full markdown document."""
        lines = [
            f"# {title}",
            f"*Gerado por SIREN — Shannon Intelligence Recon & Exploitation Nexus*",
            f"*Data: {time.strftime('%Y-%m-%d %H:%M:%S')}*\n",
            "---\n",
            "## Índice\n",
        ]

        for i, ch in enumerate(chapters, 1):
            anchor = ch.title.lower().replace(" ", "-").replace("/", "")
            lines.append(f"{i}. [{ch.title}](#{anchor})")

        lines.append("\n---\n")

        for ch in chapters:
            if ch.content:
                lines.append(ch.content)
                lines.append("\n---\n")

        return "\n".join(lines)

    def _render_html(
        self, chapters: List[NarrativeChapter], title: str
    ) -> str:
        """HTML document with basic styling."""
        html_parts = [
            "<!DOCTYPE html>",
            "<html lang='pt-BR'>",
            "<head>",
            f"  <title>{self._html_escape(title)}</title>",
            "  <meta charset='utf-8'>",
            "  <style>",
            "    body { font-family: 'Segoe UI', sans-serif; max-width: 900px; margin: 0 auto; padding: 2em; line-height: 1.6; }",
            "    h1 { color: #1a1a2e; border-bottom: 3px solid #e94560; }",
            "    h2 { color: #0f3460; margin-top: 2em; }",
            "    h3 { color: #16213e; }",
            "    .critical { color: #e94560; font-weight: bold; }",
            "    .high { color: #f77f00; font-weight: bold; }",
            "    .medium { color: #fcbf49; }",
            "    .low { color: #2a9d8f; }",
            "    table { border-collapse: collapse; width: 100%; margin: 1em 0; }",
            "    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }",
            "    th { background: #0f3460; color: white; }",
            "    code { background: #f0f0f0; padding: 2px 6px; border-radius: 3px; }",
            "    pre { background: #1a1a2e; color: #eee; padding: 1em; border-radius: 6px; overflow-x: auto; }",
            "    blockquote { border-left: 4px solid #e94560; margin: 1em 0; padding: 0.5em 1em; background: #fff3f3; }",
            "  </style>",
            "</head>",
            "<body>",
            f"  <h1>{self._html_escape(title)}</h1>",
            f"  <p><em>Gerado por SIREN — {time.strftime('%Y-%m-%d %H:%M:%S')}</em></p>",
        ]

        for ch in chapters:
            if ch.content:
                html_parts.append(f"  <section id='{ch.chapter_id}'>")
                html_parts.append(self._markdown_to_basic_html(ch.content))
                html_parts.append("  </section>")
                html_parts.append("  <hr>")

        html_parts.extend(["</body>", "</html>"])
        return "\n".join(html_parts)

    def _render_json(
        self, chapters: List[NarrativeChapter], title: str
    ) -> str:
        """JSON structured output."""
        doc = {
            "title": title,
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "generator": "SIREN Attack Narrative Engine",
            "chapters": [ch.to_dict() for ch in chapters],
            "total_chapters": len(chapters),
        }
        return json.dumps(doc, indent=2, ensure_ascii=False)

    def _render_plain(
        self, chapters: List[NarrativeChapter], title: str
    ) -> str:
        """Plain text output (strip markdown)."""
        lines = [
            title.upper(),
            "=" * len(title),
            f"Generated by SIREN — {time.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
        ]

        for ch in chapters:
            if ch.content:
                # Strip basic markdown
                clean = re.sub(r'[#*`>|]', '', ch.content)
                clean = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', clean)
                clean = re.sub(r'---+', '-' * 60, clean)
                lines.append(clean)
                lines.append("")

        return "\n".join(lines)

    @staticmethod
    def _html_escape(text: str) -> str:
        """Escape HTML special characters."""
        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )

    def _markdown_to_basic_html(self, md: str) -> str:
        """Very basic markdown to HTML conversion (no external deps)."""
        lines = md.split("\n")
        html_lines = []
        in_code = False
        in_list = False

        for line in lines:
            stripped = line.strip()

            # Code blocks
            if stripped.startswith("```"):
                if in_code:
                    html_lines.append("</pre>")
                    in_code = False
                else:
                    html_lines.append("<pre><code>")
                    in_code = True
                continue

            if in_code:
                html_lines.append(self._html_escape(line))
                continue

            # Headers
            if stripped.startswith("### "):
                html_lines.append(f"<h3>{self._html_escape(stripped[4:])}</h3>")
            elif stripped.startswith("## "):
                html_lines.append(f"<h2>{self._html_escape(stripped[3:])}</h2>")
            elif stripped.startswith("# "):
                html_lines.append(f"<h1>{self._html_escape(stripped[2:])}</h1>")
            # List items
            elif stripped.startswith("- "):
                if not in_list:
                    html_lines.append("<ul>")
                    in_list = True
                html_lines.append(f"<li>{self._html_escape(stripped[2:])}</li>")
            # Table rows (basic)
            elif stripped.startswith("|") and stripped.endswith("|"):
                cells = [c.strip() for c in stripped.split("|")[1:-1]]
                if all(set(c) <= {'-', ' ', ':'} for c in cells):
                    continue  # Skip separator rows
                row = "".join(f"<td>{self._html_escape(c)}</td>" for c in cells)
                html_lines.append(f"<tr>{row}</tr>")
            # Blockquote
            elif stripped.startswith("> "):
                html_lines.append(
                    f"<blockquote>{self._html_escape(stripped[2:])}</blockquote>"
                )
            # Empty line
            elif not stripped:
                if in_list:
                    html_lines.append("</ul>")
                    in_list = False
                html_lines.append("<br>")
            # Paragraph
            else:
                if in_list:
                    html_lines.append("</ul>")
                    in_list = False
                # Bold
                processed = re.sub(
                    r'\*\*(.+?)\*\*',
                    r'<strong>\1</strong>',
                    self._html_escape(stripped),
                )
                # Inline code
                processed = re.sub(r'`(.+?)`', r'<code>\1</code>', processed)
                html_lines.append(f"<p>{processed}</p>")

        if in_list:
            html_lines.append("</ul>")
        if in_code:
            html_lines.append("</pre>")

        return "\n".join(html_lines)


# ════════════════════════════════════════════════════════════════════════════════
# SIREN ATTACK NARRATIVE — Main Interface
# ════════════════════════════════════════════════════════════════════════════════


class SirenAttackNarrative:
    """
    Main interface for SIREN's Attack Narrative engine.

    Usage:
        narrative = SirenAttackNarrative()
        narrative.add_finding(Finding(...))
        report = narrative.generate_report(
            target="https://example.com",
            audience=Audience.EXECUTIVE,
            output_format=OutputFormat.MARKDOWN,
        )
    """

    def __init__(self) -> None:
        self._engine = NarrativeEngine()
        self._renderer = FormatRenderer()
        self._adapter = AudienceAdapter()
        self._lock = threading.RLock()
        self._generated_reports: Dict[str, str] = {}
        logger.info("SirenAttackNarrative initialized")

    def add_finding(self, finding: Finding) -> None:
        """Add a security finding."""
        with self._lock:
            self._engine.add_finding(finding)

    def add_findings(self, findings: List[Finding]) -> None:
        """Add multiple findings at once."""
        with self._lock:
            self._engine.add_findings(findings)

    def add_finding_raw(
        self,
        title: str,
        description: str,
        severity: str = "medium",
        cvss: float = 0.0,
        cwe: Optional[str] = None,
        component: str = "",
        evidence: str = "",
        kill_chain: Optional[str] = None,
        remediation: str = "",
        **kwargs: Any,
    ) -> Finding:
        """Add a finding from raw parameters (convenience method)."""
        sev_map = {
            "critical": RiskLevel.CRITICAL,
            "high": RiskLevel.HIGH,
            "medium": RiskLevel.MEDIUM,
            "low": RiskLevel.LOW,
            "info": RiskLevel.INFO,
        }
        kc_map = {kc.value: kc for kc in KillChainPhase}

        fid = hashlib.md5(f"{title}{time.time()}".encode()).hexdigest()[:12]

        finding = Finding(
            finding_id=f"f-{fid}",
            title=title,
            description=description,
            severity=sev_map.get(severity.lower(), RiskLevel.MEDIUM),
            cvss_score=cvss,
            cwe_id=cwe,
            affected_component=component,
            evidence=evidence,
            kill_chain_phase=kc_map.get(kill_chain) if kill_chain else None,
            remediation=remediation,
            metadata=kwargs,
        )

        self.add_finding(finding)
        return finding

    def generate_report(
        self,
        target: str,
        audience: Audience = Audience.TECHNICAL,
        output_format: OutputFormat = OutputFormat.MARKDOWN,
        title: Optional[str] = None,
        include_chapters: Optional[List[ChapterType]] = None,
    ) -> str:
        """
        Generate the full narrative report.

        Args:
            target: Target name/URL
            audience: Target audience
            output_format: Output format (markdown/html/json/plain)
            title: Custom report title
            include_chapters: Specific chapters to include

        Returns:
            Formatted report string
        """
        with self._lock:
            report_title = title or f"SIREN Security Assessment — {target}"

            chapters = self._engine.generate_narrative(
                target=target,
                audience=audience,
                include_chapters=include_chapters,
            )

            if not chapters:
                return f"# {report_title}\n\nNo findings to report."

            report = self._renderer.render(
                chapters=chapters,
                output_format=output_format,
                title=report_title,
            )

            # Cache the report
            cache_key = f"{target}:{audience.value}:{output_format.value}"
            self._generated_reports[cache_key] = report

            logger.info(
                "Generated %s report for %s: %d chapters, %d chars",
                audience.value, target, len(chapters), len(report),
            )
            return report

    def generate_multi_audience(
        self,
        target: str,
        audiences: Optional[List[Audience]] = None,
        output_format: OutputFormat = OutputFormat.MARKDOWN,
    ) -> Dict[str, str]:
        """
        Generate reports for multiple audiences at once.

        Returns:
            Dict mapping audience name to report content
        """
        if audiences is None:
            audiences = [Audience.EXECUTIVE, Audience.TECHNICAL, Audience.DEVELOPER]

        reports = {}
        for aud in audiences:
            reports[aud.value] = self.generate_report(
                target=target,
                audience=aud,
                output_format=output_format,
            )

        return reports

    def get_risk_quantification(self) -> Optional[RiskQuantification]:
        """Get the risk quantification from the last generation."""
        with self._lock:
            return self._engine._risk

    def get_timeline(self) -> Optional[AttackTimeline]:
        """Get the attack timeline from the last generation."""
        with self._lock:
            return self._engine._timeline

    def export_state(self) -> Dict[str, Any]:
        """Export full state for serialization."""
        with self._lock:
            return {
                "findings": [
                    {
                        "finding_id": f.finding_id,
                        "title": f.title,
                        "description": f.description,
                        "severity": f.severity.label,
                        "cvss_score": f.cvss_score,
                        "cwe_id": f.cwe_id,
                        "cve_id": f.cve_id,
                        "affected_component": f.affected_component,
                        "evidence": f.evidence,
                        "reproduction_steps": f.reproduction_steps,
                        "kill_chain_phase": f.kill_chain_phase.value if f.kill_chain_phase else None,
                        "remediation": f.remediation,
                        "timestamp": f.timestamp,
                        "metadata": f.metadata,
                    }
                    for f in self._engine._findings
                ],
                "generated_reports": self._generated_reports,
            }

    def import_state(self, state: Dict[str, Any]) -> None:
        """Import state from serialized data."""
        sev_map = {rl.label: rl for rl in RiskLevel}
        kc_map = {kc.value: kc for kc in KillChainPhase}

        with self._lock:
            self._engine.clear()
            for fd in state.get("findings", []):
                finding = Finding(
                    finding_id=fd["finding_id"],
                    title=fd["title"],
                    description=fd["description"],
                    severity=sev_map.get(fd.get("severity", "medium"), RiskLevel.MEDIUM),
                    cvss_score=fd.get("cvss_score", 0.0),
                    cwe_id=fd.get("cwe_id"),
                    cve_id=fd.get("cve_id"),
                    affected_component=fd.get("affected_component", ""),
                    evidence=fd.get("evidence", ""),
                    reproduction_steps=fd.get("reproduction_steps", []),
                    kill_chain_phase=kc_map.get(fd.get("kill_chain_phase")),
                    remediation=fd.get("remediation", ""),
                    timestamp=fd.get("timestamp", time.time()),
                    metadata=fd.get("metadata", {}),
                )
                self._engine.add_finding(finding)

    def clear(self) -> None:
        """Reset all state."""
        with self._lock:
            self._engine.clear()
            self._generated_reports.clear()
