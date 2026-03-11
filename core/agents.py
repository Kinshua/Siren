#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  🔱  ABYSSAL AGENT REGISTRY — Shannon × SIREN Neural Mesh  🔱             ██
██                                                                                ██
██  13 agentes autonomos organizados em 5 fases de ataque.                        ██
██  Cada agente e uma entidade cognitiva que combina:                              ██
██    - O raciocinio profundo do Shannon (AI reasoning)                            ██
██    - O arsenal brutal do SIREN (704+ tools)                                ██
██    - A evasao semantica do Kraken Engine (640+ rules)                           ██
██                                                                                ██
██  Pipeline: PRE-RECON → RECON → VULN ANALYSIS → EXPLOITATION → REPORTING        ██
██                                                                                ██
██  Inspirado pela arquitetura multi-agente do Shannon (KeygraphHQ)                ██
██  Adaptado para o ecossistema SIREN                                      ██
██                                                                                ██
██  "Cada agente e um tentaculo. Juntos, eles envolvem o alvo por completo."      ██
██                                                                                ██
████████████████████████████████████████████████████████████████████████████████████
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Literal, Optional

# ════════════════════════════════════════════════════════════════════════════
# TYPE DEFINITIONS
# ════════════════════════════════════════════════════════════════════════════

VulnType = Literal["injection", "xss", "auth", "ssrf", "authz"]
ALL_VULN_TYPES: List[VulnType] = ["injection", "xss", "auth", "ssrf", "authz"]

PhaseName = Literal[
    "pre-recon",
    "recon",
    "vulnerability-analysis",
    "exploitation",
    "reporting",
]

AgentName = Literal[
    "pre-recon",
    "recon",
    "injection-vuln",
    "xss-vuln",
    "auth-vuln",
    "ssrf-vuln",
    "authz-vuln",
    "injection-exploit",
    "xss-exploit",
    "auth-exploit",
    "ssrf-exploit",
    "authz-exploit",
    "report",
]

ModelTier = Literal["small", "medium", "large"]


# ════════════════════════════════════════════════════════════════════════════
# AGENT STATUS
# ════════════════════════════════════════════════════════════════════════════


class AgentStatus(enum.Enum):
    """Estado de vida de cada agente no pipeline."""

    DORMANT = "dormant"  # Aguardando prerequisites
    QUEUED = "queued"  # Prerequisites satisfeitos, aguardando execucao
    RUNNING = "running"  # Em execucao ativa
    COMPLETED = "completed"  # Concluido com sucesso
    FAILED = "failed"  # Falhou (pode ser retried)
    SKIPPED = "skipped"  # Pulado (vuln não encontrada, não precisa exploit)


# ════════════════════════════════════════════════════════════════════════════
# AGENT DEFINITION
# ════════════════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class AgentDefinition:
    """Definicao imutavel de um agente do pipeline.

    Cada agente mapeia para:
    - Um conjunto de ferramentas SIREN (MCP tools)
    - Um template de prompt (para o modelo AI)
    - Um deliverable esperado (arquivo de saida)
    - Dependencias de prerequisitos
    - Tier de modelo AI (small/medium/large)
    """

    name: str
    display_name: str
    prerequisites: FrozenSet[str]
    prompt_template: str
    deliverable_filename: str
    model_tier: ModelTier = "medium"
    vuln_type: Optional[VulnType] = None
    phase: PhaseName = "recon"

    # SIREN-specific: quais dominios MCP este agente pode usar
    attack_domains: FrozenSet[str] = frozenset()

    # Ferramentas SIREN preferidas para este agente
    preferred_tools: FrozenSet[str] = frozenset()

    @property
    def is_exploit_agent(self) -> bool:
        return "exploit" in self.name and self.name != "report"

    @property
    def is_vuln_agent(self) -> bool:
        return "vuln" in self.name

    @property
    def is_parallel(self) -> bool:
        """Agentes de vuln-analysis e exploitation rodam em paralelo."""
        return self.phase in ("vulnerability-analysis", "exploitation")


# ════════════════════════════════════════════════════════════════════════════
# AGENT REGISTRY — 13 AGENTES DO ABISMO
# ════════════════════════════════════════════════════════════════════════════

AGENTS: Dict[str, AgentDefinition] = {
    # ── Phase 1: Pre-Reconnaissance ──────────────────────────────────────
    "pre-recon": AgentDefinition(
        name="pre-recon",
        display_name="🔍 DEEP SCAN — Analise Estatica de Codigo",
        prerequisites=frozenset(),
        prompt_template="pre-recon-code",
        deliverable_filename="code_analysis_deliverable.md",
        model_tier="large",
        phase="pre-recon",
        attack_domains=frozenset(
            {"DEAD_CODE_ORACLE", "BONE_READER", "ALL_SEEING_EYE"}
        ),
        preferred_tools=frozenset(
            {
                "analyze_binary",
                "decompile",
                "find_strings",
                "list_functions",
                "analyze_imports",
                "search_vulnerabilities",
            }
        ),
    ),
    # ── Phase 2: Reconnaissance ──────────────────────────────────────────
    "recon": AgentDefinition(
        name="recon",
        display_name="🌊 SONAR SWEEP — Reconhecimento Ativo",
        prerequisites=frozenset({"pre-recon"}),
        prompt_template="recon",
        deliverable_filename="recon_deliverable.md",
        model_tier="medium",
        phase="recon",
        attack_domains=frozenset(
            {
                "ALL_SEEING_EYE",
                "DEEP_CURRENT",
                "SURFACE_BREAKER",
                "TENTACLE_PROTOCOL",
            }
        ),
        preferred_tools=frozenset(
            {
                "nmap_scan",
                "port_scan",
                "subdomain_enum",
                "whatweb",
                "dir_bruteforce",
                "tech_detect",
                "ssl_scan",
                "dns_enum",
            }
        ),
    ),
    # ── Phase 3: Vulnerability Analysis (5 parallel agents) ─────────────
    "injection-vuln": AgentDefinition(
        name="injection-vuln",
        display_name="💉 VENOM ANALYSIS — Injection Hunting",
        prerequisites=frozenset({"recon"}),
        prompt_template="vuln-injection",
        deliverable_filename="injection_analysis_deliverable.md",
        vuln_type="injection",
        phase="vulnerability-analysis",
        attack_domains=frozenset(
            {
                "SURFACE_BREAKER",
                "PRESSURE_FORGE",
                "DEAD_CODE_ORACLE",
            }
        ),
        preferred_tools=frozenset(
            {
                "sqli_scan",
                "nosql_inject",
                "ldap_inject",
                "xpath_inject",
                "cmd_inject",
                "ssti_scan",
                "header_inject",
            }
        ),
    ),
    "xss-vuln": AgentDefinition(
        name="xss-vuln",
        display_name="⚡ ELECTRIC EEL — XSS Detection",
        prerequisites=frozenset({"recon"}),
        prompt_template="vuln-xss",
        deliverable_filename="xss_analysis_deliverable.md",
        vuln_type="xss",
        phase="vulnerability-analysis",
        attack_domains=frozenset({"SURFACE_BREAKER", "PRESSURE_FORGE"}),
        preferred_tools=frozenset(
            {
                "xss_scan",
                "dom_xss",
                "reflected_xss",
                "stored_xss",
                "csp_bypass",
                "js_analysis",
            }
        ),
    ),
    "auth-vuln": AgentDefinition(
        name="auth-vuln",
        display_name="🔐 LOCK BREAKER — Auth Bypass Analysis",
        prerequisites=frozenset({"recon"}),
        prompt_template="vuln-auth",
        deliverable_filename="auth_analysis_deliverable.md",
        vuln_type="auth",
        phase="vulnerability-analysis",
        attack_domains=frozenset(
            {
                "SURFACE_BREAKER",
                "PRESSURE_FORGE",
                "DOMAIN_CRUSHER",
            }
        ),
        preferred_tools=frozenset(
            {
                "jwt_crack",
                "session_hijack",
                "brute_force",
                "credential_stuff",
                "oauth_abuse",
                "saml_attack",
                "totp_bypass",
            }
        ),
    ),
    "ssrf-vuln": AgentDefinition(
        name="ssrf-vuln",
        display_name="🕳️ BLACK HOLE — SSRF Discovery",
        prerequisites=frozenset({"recon"}),
        prompt_template="vuln-ssrf",
        deliverable_filename="ssrf_analysis_deliverable.md",
        vuln_type="ssrf",
        phase="vulnerability-analysis",
        attack_domains=frozenset(
            {
                "SURFACE_BREAKER",
                "DEEP_CURRENT",
                "CLOUD_DEVOURER",
            }
        ),
        preferred_tools=frozenset(
            {
                "ssrf_scan",
                "dns_rebind",
                "cloud_metadata",
                "internal_scan",
                "protocol_smuggle",
            }
        ),
    ),
    "authz-vuln": AgentDefinition(
        name="authz-vuln",
        display_name="👑 CROWN THIEF — Authorization Flaw Analysis",
        prerequisites=frozenset({"recon"}),
        prompt_template="vuln-authz",
        deliverable_filename="authz_analysis_deliverable.md",
        vuln_type="authz",
        phase="vulnerability-analysis",
        attack_domains=frozenset(
            {
                "SURFACE_BREAKER",
                "PRESSURE_FORGE",
                "SHADOW_PUPPETEER",
            }
        ),
        preferred_tools=frozenset(
            {
                "idor_scan",
                "privilege_esc",
                "role_bypass",
                "api_abuse",
                "mass_assignment",
                "path_traversal",
            }
        ),
    ),
    # ── Phase 4: Exploitation (5 parallel agents) ───────────────────────
    "injection-exploit": AgentDefinition(
        name="injection-exploit",
        display_name="💀 DEPTH CHARGE — Injection Exploitation",
        prerequisites=frozenset({"injection-vuln"}),
        prompt_template="exploit-injection",
        deliverable_filename="injection_exploitation_evidence.md",
        vuln_type="injection",
        phase="exploitation",
        attack_domains=frozenset(
            {
                "PRESSURE_FORGE",
                "SURFACE_BREAKER",
                "SHADOW_PUPPETEER",
            }
        ),
        preferred_tools=frozenset(
            {
                "sqlmap",
                "exploit_sqli",
                "dump_database",
                "os_command",
                "reverse_shell",
                "data_exfil",
            }
        ),
    ),
    "xss-exploit": AgentDefinition(
        name="xss-exploit",
        display_name="⚡ THUNDERBOLT — XSS Exploitation",
        prerequisites=frozenset({"xss-vuln"}),
        prompt_template="exploit-xss",
        deliverable_filename="xss_exploitation_evidence.md",
        vuln_type="xss",
        phase="exploitation",
        attack_domains=frozenset({"PRESSURE_FORGE", "SURFACE_BREAKER"}),
        preferred_tools=frozenset(
            {
                "xss_exploit",
                "cookie_steal",
                "keylogger_inject",
                "phishing_page",
                "dom_manipulate",
            }
        ),
    ),
    "auth-exploit": AgentDefinition(
        name="auth-exploit",
        display_name="🗝️ SKELETON KEY — Auth Exploitation",
        prerequisites=frozenset({"auth-vuln"}),
        prompt_template="exploit-auth",
        deliverable_filename="auth_exploitation_evidence.md",
        vuln_type="auth",
        phase="exploitation",
        attack_domains=frozenset(
            {
                "PRESSURE_FORGE",
                "DOMAIN_CRUSHER",
                "SHADOW_PUPPETEER",
            }
        ),
        preferred_tools=frozenset(
            {
                "token_forge",
                "session_fixation",
                "account_takeover",
                "password_spray",
                "mfa_bypass",
            }
        ),
    ),
    "ssrf-exploit": AgentDefinition(
        name="ssrf-exploit",
        display_name="🌀 MAELSTROM — SSRF Exploitation",
        prerequisites=frozenset({"ssrf-vuln"}),
        prompt_template="exploit-ssrf",
        deliverable_filename="ssrf_exploitation_evidence.md",
        vuln_type="ssrf",
        phase="exploitation",
        attack_domains=frozenset(
            {
                "PRESSURE_FORGE",
                "DEEP_CURRENT",
                "CLOUD_DEVOURER",
            }
        ),
        preferred_tools=frozenset(
            {
                "ssrf_exploit",
                "cloud_pivot",
                "internal_access",
                "metadata_extract",
                "service_scan",
            }
        ),
    ),
    "authz-exploit": AgentDefinition(
        name="authz-exploit",
        display_name="🏴‍☠️ MUTINY — Authorization Exploitation",
        prerequisites=frozenset({"authz-vuln"}),
        prompt_template="exploit-authz",
        deliverable_filename="authz_exploitation_evidence.md",
        vuln_type="authz",
        phase="exploitation",
        attack_domains=frozenset(
            {
                "PRESSURE_FORGE",
                "SHADOW_PUPPETEER",
                "SURFACE_BREAKER",
            }
        ),
        preferred_tools=frozenset(
            {
                "priv_escalate",
                "idor_exploit",
                "role_impersonate",
                "admin_access",
                "data_breach",
            }
        ),
    ),
    # ── Phase 3.5: API Security (parallel with vuln-analysis) ──────────
    "api-security-vuln": AgentDefinition(
        name="api-security-vuln",
        display_name="🔒 SIREN GUARD — API Security Analysis (Kippu Pattern)",
        prerequisites=frozenset({"recon"}),
        prompt_template="vuln-api-security",
        deliverable_filename="api_security_analysis_deliverable.md",
        vuln_type="authz",
        phase="vulnerability-analysis",
        attack_domains=frozenset(
            {
                "SURFACE_BREAKER",
                "PRESSURE_FORGE",
                "SIREN_ENGINE",
            }
        ),
        preferred_tools=frozenset(
            {
                "api_audit_full",
                "api_scan_access",
                "api_scan_exposure",
                "api_scan_jwt",
                "api_scan_idor",
                "api_scan_ratelimit",
                "api_scan_enum",
                "api_scan_cors",
                "api_scan_headers",
                "api_scan_privesc",
                "api_scan_methods",
            }
        ),
    ),
    # ── Phase 4.5: API Security Exploitation ────────────────────────────
    "api-security-exploit": AgentDefinition(
        name="api-security-exploit",
        display_name="🏴 SIREN STRIKE — API Security Exploitation",
        prerequisites=frozenset({"api-security-vuln"}),
        prompt_template="exploit-api-security",
        deliverable_filename="api_security_exploitation_evidence.md",
        vuln_type="authz",
        phase="exploitation",
        attack_domains=frozenset(
            {
                "PRESSURE_FORGE",
                "SURFACE_BREAKER",
                "SIREN_ENGINE",
            }
        ),
        preferred_tools=frozenset(
            {
                "api_audit_full",
                "api_scan_access",
                "api_scan_idor",
                "api_scan_privesc",
                "api_generate_report",
            }
        ),
    ),
    # ── Phase 5: Reporting ──────────────────────────────────────────────
    "report": AgentDefinition(
        name="report",
        display_name="📜 CHRONICLES — Pentest Report Generation",
        prerequisites=frozenset(
            {
                "injection-exploit",
                "xss-exploit",
                "auth-exploit",
                "ssrf-exploit",
                "authz-exploit",
                "api-security-exploit",
            }
        ),
        prompt_template="report-executive",
        deliverable_filename="comprehensive_security_assessment_report.md",
        model_tier="small",
        phase="reporting",
        attack_domains=frozenset({"TENTACLE_PROTOCOL"}),
        preferred_tools=frozenset({"generate_report", "compile_evidence"}),
    ),
}


# ════════════════════════════════════════════════════════════════════════════
# AGENT → PHASE MAP
# ════════════════════════════════════════════════════════════════════════════

AGENT_PHASE_MAP: Dict[str, PhaseName] = {
    agent.name: agent.phase for agent in AGENTS.values()
}


# ════════════════════════════════════════════════════════════════════════════
# PHASE ORDERING — A sequencia do ataque
# ════════════════════════════════════════════════════════════════════════════

PHASE_ORDER: List[PhaseName] = [
    "pre-recon",
    "recon",
    "vulnerability-analysis",
    "exploitation",
    "reporting",
]

# Agents agrupados por fase
AGENTS_BY_PHASE: Dict[PhaseName, List[str]] = {}
for _name, _agent in AGENTS.items():
    AGENTS_BY_PHASE.setdefault(_agent.phase, []).append(_name)


# ════════════════════════════════════════════════════════════════════════════
# VULN TYPE → AGENT MAP
# ════════════════════════════════════════════════════════════════════════════

VULN_AGENTS: Dict[VulnType, str] = {
    "injection": "injection-vuln",
    "xss": "xss-vuln",
    "auth": "auth-vuln",
    "ssrf": "ssrf-vuln",
    "authz": "authz-vuln",
}

EXPLOIT_AGENTS: Dict[VulnType, str] = {
    "injection": "injection-exploit",
    "xss": "xss-exploit",
    "auth": "auth-exploit",
    "ssrf": "ssrf-exploit",
    "authz": "authz-exploit",
}


def get_agent(name: str) -> AgentDefinition:
    """Obtem um agente pelo nome. Raises KeyError se não existir."""
    if name not in AGENTS:
        raise KeyError(
            f"Agente '{name}' nao existe no registro. "
            f"Agentes disponiveis: {list(AGENTS.keys())}"
        )
    return AGENTS[name]


def get_agents_for_phase(phase: PhaseName) -> List[AgentDefinition]:
    """Retorna todos os agentes de uma fase especifica."""
    return [AGENTS[n] for n in AGENTS_BY_PHASE.get(phase, [])]


def get_exploit_agent_for_vuln(vuln_type: VulnType) -> AgentDefinition:
    """Retorna o agente de exploitation correspondente a um tipo de vuln."""
    return AGENTS[EXPLOIT_AGENTS[vuln_type]]
