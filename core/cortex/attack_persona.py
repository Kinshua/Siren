#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  🎭  SIREN ATTACK PERSONA — Behavioral Attacker Simulation  🎭               ██
██                                                                                ██
██  Cada atacante pensa diferente. SIREN modela COMO eles pensam.                ██
██                                                                                ██
██  Script kiddies não usam zero-days.                                           ██
██  APT groups não fazem barulho.                                                ██
██  Insiders já têm acesso.                                                      ██
██                                                                                ██
██  Este módulo simula perfis de atacantes reais com:                             ██
██    • AttackPersona — perfil completo: skill, motivação, recursos, TTP         ██
██    • PersonaLibrary — 8+ personas calibradas com dados de threat intel        ██
██    • BehaviorSimulator — simula decisões baseado no perfil                    ██
██    • PersonaStrategySelector — dado perfil + vulns, escolhe a melhor chain    ██
██                                                                                ██
██  "SIREN não pergunta 'existe vuln?' Ela pergunta: 'QUEM atacaria isso        ██
██   e COMO?'"                                                                   ██
██                                                                                ██
████████████████████████████████████████████████████████████████████████████████████
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import random
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

logger = logging.getLogger("siren.cortex.attack_persona")


# ════════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════════════════════════════

THREAD_POOL_SIZE = 4
MAX_SIMULATION_STEPS = 100
DECISION_EPSILON = 1e-9


# ════════════════════════════════════════════════════════════════════════════════
# ENUMS
# ════════════════════════════════════════════════════════════════════════════════


class SkillLevel(Enum):
    """Technical skill levels based on MITRE ATT&CK proficiency."""
    NOVICE = 1           # Copy-paste exploits, public tools only
    INTERMEDIATE = 2     # Can modify exploits, basic custom tooling
    ADVANCED = 3         # Custom exploit dev, evasion techniques
    EXPERT = 4           # Zero-day research, advanced persistent ops
    ELITE = 5            # Nation-state capability, supply chain attacks


class Motivation(Enum):
    """Primary motivation of the attacker."""
    FINANCIAL = "financial"               # Ransomware, cryptomining, fraud
    ESPIONAGE = "espionage"               # Nation-state intelligence gathering
    HACKTIVISM = "hacktivism"             # Ideological, defacement, DoS
    DESTRUCTION = "destruction"           # Wiper malware, sabotage
    REPUTATION = "reputation"             # Bug bounties, CVE collection
    CURIOSITY = "curiosity"              # Script kiddies, exploration
    INSIDER_REVENGE = "insider_revenge"   # Disgruntled employee


class ResourceLevel(Enum):
    """Attacker resource availability."""
    MINIMAL = 1      # Single person, free tools, shared hosting
    LOW = 2          # Small team, basic infrastructure
    MODERATE = 3     # Funded group, dedicated C2, custom tools
    HIGH = 4         # Well-funded org, botnet access, 0-day budget
    UNLIMITED = 5    # Nation-state, offensive cyber units


class Patience(Enum):
    """How long the attacker is willing to wait/persist."""
    IMPATIENT = 1     # Minutes to hours (smash & grab)
    SHORT_TERM = 2    # Hours to days
    MEDIUM_TERM = 3   # Days to weeks
    LONG_TERM = 4     # Weeks to months
    INDEFINITE = 5    # Months to years (APT dwell time)


class NoisePreference(Enum):
    """How much noise the attacker tolerates."""
    SILENT = 5       # Zero detection tolerance — abort if detected
    STEALTHY = 4     # Minimal footprint, slow-and-low
    CAUTIOUS = 3     # Some scanning, avoids obvious triggers
    MODERATE = 2     # Doesn't care much about detection
    LOUD = 1         # Doesn't care at all (DDoS, defacement)


class TTPCategory(Enum):
    """MITRE ATT&CK tactic categories the persona prefers."""
    RECON = "reconnaissance"
    RESOURCE_DEV = "resource_development"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIV_ESC = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CRED_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"
    C2 = "command_and_control"


class DecisionType(Enum):
    """Types of decisions an attacker makes during engagement."""
    CHOOSE_TARGET = "choose_target"
    CHOOSE_TECHNIQUE = "choose_technique"
    ESCALATE_OR_RETREAT = "escalate_or_retreat"
    PERSIST_OR_EXFIL = "persist_or_exfil"
    EXPLOIT_OR_ENUMERATE = "exploit_or_enumerate"
    PIVOT_OR_DEEPEN = "pivot_or_deepen"


# ════════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ════════════════════════════════════════════════════════════════════════════════


@dataclass
class ThreatCapability:
    """A specific capability or technique the persona can use."""
    technique_id: str                # MITRE ATT&CK technique ID (e.g. T1190)
    technique_name: str
    category: TTPCategory
    proficiency: float = 0.5         # [0-1] how good they are at this
    preference: float = 0.5          # [0-1] how much they prefer it
    required_skill: SkillLevel = SkillLevel.INTERMEDIATE
    noise_level: float = 0.5         # [0-1] how much noise it generates


@dataclass
class AttackPersona:
    """A complete attacker profile.

    Each persona encodes HOW an attacker thinks:
    - What they prefer to attack
    - How patient they are
    - How much noise they tolerate
    - Which techniques they favor
    - How they make decisions under uncertainty
    """
    persona_id: str
    name: str
    description: str = ""
    skill: SkillLevel = SkillLevel.INTERMEDIATE
    motivation: Motivation = Motivation.FINANCIAL
    resources: ResourceLevel = ResourceLevel.MODERATE
    patience: Patience = Patience.MEDIUM_TERM
    noise_pref: NoisePreference = NoisePreference.CAUTIOUS
    risk_tolerance: float = 0.5      # [0-1] willingness to take risks
    adaptability: float = 0.5        # [0-1] ability to change tactics
    capabilities: List[ThreatCapability] = field(default_factory=list)
    preferred_ttps: List[TTPCategory] = field(default_factory=list)
    preferred_targets: List[str] = field(default_factory=list)   # e.g. "web_app", "database"
    known_tools: List[str] = field(default_factory=list)
    cwe_affinity: Dict[str, float] = field(default_factory=dict)  # CWE → preference
    typical_chain_depth: int = 3     # Average chain length
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def effectiveness(self) -> float:
        """Overall effectiveness estimate based on skill and resources."""
        return (self.skill.value / 5.0 * 0.6) + (self.resources.value / 5.0 * 0.4)

    @property
    def stealth_factor(self) -> float:
        """How stealthy this persona tends to be."""
        return self.noise_pref.value / 5.0

    @property
    def persistence_factor(self) -> float:
        """How persistent this persona is."""
        return self.patience.value / 5.0

    def get_technique_proficiency(self, technique_id: str) -> float:
        """Get proficiency for a specific technique."""
        for cap in self.capabilities:
            if cap.technique_id == technique_id:
                return cap.proficiency
        return 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "persona_id": self.persona_id,
            "name": self.name,
            "description": self.description,
            "skill": self.skill.value,
            "motivation": self.motivation.value,
            "resources": self.resources.value,
            "patience": self.patience.value,
            "noise_pref": self.noise_pref.value,
            "risk_tolerance": self.risk_tolerance,
            "adaptability": self.adaptability,
            "effectiveness": self.effectiveness,
            "stealth_factor": self.stealth_factor,
            "persistence_factor": self.persistence_factor,
            "preferred_ttps": [t.value for t in self.preferred_ttps],
            "known_tools": self.known_tools,
            "typical_chain_depth": self.typical_chain_depth,
        }


@dataclass
class SimulationState:
    """State of a behavioral simulation."""
    step: int = 0
    conditions: Set[str] = field(default_factory=set)
    actions_taken: List[Dict[str, Any]] = field(default_factory=list)
    detected: bool = False
    detection_risk: float = 0.0
    objective_progress: float = 0.0   # [0-1]
    time_elapsed_hours: float = 0.0
    noise_accumulated: float = 0.0


@dataclass
class PersonaDecision:
    """A decision made by a simulated persona."""
    decision_type: DecisionType
    chosen_action: str
    reasoning: str
    confidence: float = 0.0
    alternatives: List[Tuple[str, float]] = field(default_factory=list)


# ════════════════════════════════════════════════════════════════════════════════
# PERSONA LIBRARY — Pre-built profiles from real threat intelligence
# ════════════════════════════════════════════════════════════════════════════════


_SCRIPT_KIDDIE_CAPS = [
    ThreatCapability("T1190", "Exploit Public-Facing Application", TTPCategory.INITIAL_ACCESS, 0.4, 0.9, SkillLevel.NOVICE, 0.7),
    ThreatCapability("T1059", "Command and Scripting Interpreter", TTPCategory.EXECUTION, 0.3, 0.5, SkillLevel.NOVICE, 0.6),
    ThreatCapability("T1110", "Brute Force", TTPCategory.CRED_ACCESS, 0.5, 0.8, SkillLevel.NOVICE, 0.9),
    ThreatCapability("T1595", "Active Scanning", TTPCategory.RECON, 0.5, 0.9, SkillLevel.NOVICE, 0.8),
]

_APT_NATION_STATE_CAPS = [
    ThreatCapability("T1190", "Exploit Public-Facing Application", TTPCategory.INITIAL_ACCESS, 0.95, 0.7, SkillLevel.ELITE, 0.2),
    ThreatCapability("T1195", "Supply Chain Compromise", TTPCategory.INITIAL_ACCESS, 0.8, 0.5, SkillLevel.ELITE, 0.1),
    ThreatCapability("T1210", "Exploitation of Remote Services", TTPCategory.LATERAL_MOVEMENT, 0.9, 0.8, SkillLevel.EXPERT, 0.2),
    ThreatCapability("T1055", "Process Injection", TTPCategory.DEFENSE_EVASION, 0.95, 0.9, SkillLevel.EXPERT, 0.1),
    ThreatCapability("T1003", "OS Credential Dumping", TTPCategory.CRED_ACCESS, 0.9, 0.8, SkillLevel.EXPERT, 0.3),
    ThreatCapability("T1071", "Application Layer Protocol", TTPCategory.C2, 0.95, 0.9, SkillLevel.ELITE, 0.1),
    ThreatCapability("T1048", "Exfiltration Over Alternative Protocol", TTPCategory.EXFILTRATION, 0.9, 0.8, SkillLevel.EXPERT, 0.2),
    ThreatCapability("T1027", "Obfuscated Files or Information", TTPCategory.DEFENSE_EVASION, 0.9, 0.9, SkillLevel.EXPERT, 0.1),
    ThreatCapability("T1053", "Scheduled Task/Job", TTPCategory.PERSISTENCE, 0.85, 0.7, SkillLevel.ADVANCED, 0.2),
]

_RANSOMWARE_CAPS = [
    ThreatCapability("T1190", "Exploit Public-Facing Application", TTPCategory.INITIAL_ACCESS, 0.7, 0.9, SkillLevel.ADVANCED, 0.5),
    ThreatCapability("T1566", "Phishing", TTPCategory.INITIAL_ACCESS, 0.8, 0.9, SkillLevel.INTERMEDIATE, 0.3),
    ThreatCapability("T1486", "Data Encrypted for Impact", TTPCategory.IMPACT, 0.9, 1.0, SkillLevel.ADVANCED, 0.9),
    ThreatCapability("T1003", "OS Credential Dumping", TTPCategory.CRED_ACCESS, 0.7, 0.8, SkillLevel.ADVANCED, 0.4),
    ThreatCapability("T1021", "Remote Services", TTPCategory.LATERAL_MOVEMENT, 0.75, 0.8, SkillLevel.ADVANCED, 0.4),
    ThreatCapability("T1490", "Inhibit System Recovery", TTPCategory.IMPACT, 0.8, 0.9, SkillLevel.ADVANCED, 0.8),
]

_INSIDER_CAPS = [
    ThreatCapability("T1078", "Valid Accounts", TTPCategory.INITIAL_ACCESS, 0.95, 1.0, SkillLevel.NOVICE, 0.05),
    ThreatCapability("T1530", "Data from Cloud Storage", TTPCategory.COLLECTION, 0.8, 0.9, SkillLevel.INTERMEDIATE, 0.1),
    ThreatCapability("T1567", "Exfiltration Over Web Service", TTPCategory.EXFILTRATION, 0.7, 0.8, SkillLevel.INTERMEDIATE, 0.2),
    ThreatCapability("T1552", "Unsecured Credentials", TTPCategory.CRED_ACCESS, 0.8, 0.7, SkillLevel.NOVICE, 0.1),
    ThreatCapability("T1098", "Account Manipulation", TTPCategory.PERSISTENCE, 0.6, 0.5, SkillLevel.INTERMEDIATE, 0.3),
]

_PENTESTER_CAPS = [
    ThreatCapability("T1190", "Exploit Public-Facing Application", TTPCategory.INITIAL_ACCESS, 0.85, 0.9, SkillLevel.ADVANCED, 0.5),
    ThreatCapability("T1059", "Command and Scripting Interpreter", TTPCategory.EXECUTION, 0.85, 0.8, SkillLevel.ADVANCED, 0.4),
    ThreatCapability("T1003", "OS Credential Dumping", TTPCategory.CRED_ACCESS, 0.8, 0.7, SkillLevel.ADVANCED, 0.5),
    ThreatCapability("T1068", "Exploitation for Privilege Escalation", TTPCategory.PRIV_ESC, 0.75, 0.8, SkillLevel.ADVANCED, 0.4),
    ThreatCapability("T1046", "Network Service Discovery", TTPCategory.DISCOVERY, 0.9, 0.9, SkillLevel.INTERMEDIATE, 0.6),
]

_BUG_BOUNTY_CAPS = [
    ThreatCapability("T1190", "Exploit Public-Facing Application", TTPCategory.INITIAL_ACCESS, 0.8, 1.0, SkillLevel.ADVANCED, 0.3),
    ThreatCapability("T1595", "Active Scanning", TTPCategory.RECON, 0.85, 0.9, SkillLevel.INTERMEDIATE, 0.5),
    ThreatCapability("T1059", "Command and Scripting Interpreter", TTPCategory.EXECUTION, 0.7, 0.6, SkillLevel.ADVANCED, 0.3),
]

_CRYPTOMINER_CAPS = [
    ThreatCapability("T1190", "Exploit Public-Facing Application", TTPCategory.INITIAL_ACCESS, 0.6, 0.9, SkillLevel.INTERMEDIATE, 0.6),
    ThreatCapability("T1496", "Resource Hijacking", TTPCategory.IMPACT, 0.8, 1.0, SkillLevel.INTERMEDIATE, 0.4),
    ThreatCapability("T1059", "Command and Scripting Interpreter", TTPCategory.EXECUTION, 0.6, 0.7, SkillLevel.INTERMEDIATE, 0.5),
    ThreatCapability("T1053", "Scheduled Task/Job", TTPCategory.PERSISTENCE, 0.5, 0.6, SkillLevel.INTERMEDIATE, 0.3),
]

_HACKTIVIST_CAPS = [
    ThreatCapability("T1190", "Exploit Public-Facing Application", TTPCategory.INITIAL_ACCESS, 0.5, 0.9, SkillLevel.INTERMEDIATE, 0.8),
    ThreatCapability("T1491", "Defacement", TTPCategory.IMPACT, 0.7, 1.0, SkillLevel.INTERMEDIATE, 1.0),
    ThreatCapability("T1498", "Network Denial of Service", TTPCategory.IMPACT, 0.6, 0.8, SkillLevel.INTERMEDIATE, 1.0),
    ThreatCapability("T1530", "Data from Cloud Storage", TTPCategory.COLLECTION, 0.4, 0.6, SkillLevel.INTERMEDIATE, 0.5),
]


class PersonaLibrary:
    """Pre-built persona library calibrated from real threat intelligence.

    Contains 8 distinct attacker archetypes covering the full spectrum
    from opportunistic script kiddies to nation-state APT groups.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._personas: Dict[str, AttackPersona] = {}
        self._load_builtin_personas()

    def _load_builtin_personas(self) -> None:
        """Load built-in personas."""
        builtins = [
            AttackPersona(
                persona_id="script_kiddie",
                name="Script Kiddie",
                description="Opportunistic attacker using public tools and known exploits. "
                            "Low skill, impatient, loud. Targets low-hanging fruit.",
                skill=SkillLevel.NOVICE,
                motivation=Motivation.CURIOSITY,
                resources=ResourceLevel.MINIMAL,
                patience=Patience.IMPATIENT,
                noise_pref=NoisePreference.LOUD,
                risk_tolerance=0.8,
                adaptability=0.2,
                capabilities=_SCRIPT_KIDDIE_CAPS,
                preferred_ttps=[TTPCategory.RECON, TTPCategory.INITIAL_ACCESS],
                preferred_targets=["web_app", "default_credentials"],
                known_tools=["nmap", "sqlmap", "metasploit", "nikto"],
                cwe_affinity={"CWE-89": 0.9, "CWE-79": 0.7, "CWE-798": 0.8, "CWE-16": 0.6},
                typical_chain_depth=2,
            ),
            AttackPersona(
                persona_id="apt_nation_state",
                name="APT / Nation-State",
                description="Advanced persistent threat backed by nation-state resources. "
                            "Maximum skill, unlimited patience, zero noise. Targets high-value "
                            "assets with custom tools and zero-days.",
                skill=SkillLevel.ELITE,
                motivation=Motivation.ESPIONAGE,
                resources=ResourceLevel.UNLIMITED,
                patience=Patience.INDEFINITE,
                noise_pref=NoisePreference.SILENT,
                risk_tolerance=0.2,
                adaptability=0.95,
                capabilities=_APT_NATION_STATE_CAPS,
                preferred_ttps=[
                    TTPCategory.INITIAL_ACCESS, TTPCategory.DEFENSE_EVASION,
                    TTPCategory.LATERAL_MOVEMENT, TTPCategory.EXFILTRATION,
                    TTPCategory.PERSISTENCE, TTPCategory.C2,
                ],
                preferred_targets=["critical_infrastructure", "government", "defense", "ip"],
                known_tools=["cobalt_strike", "custom_implants", "0day_exploits"],
                cwe_affinity={"CWE-502": 0.8, "CWE-94": 0.9, "CWE-287": 0.7, "CWE-918": 0.6},
                typical_chain_depth=8,
            ),
            AttackPersona(
                persona_id="ransomware_operator",
                name="Ransomware Operator",
                description="Financially motivated group deploying ransomware. "
                            "Moderate to high skill. Targets entire networks for maximum "
                            "encryption coverage. Double/triple extortion model.",
                skill=SkillLevel.ADVANCED,
                motivation=Motivation.FINANCIAL,
                resources=ResourceLevel.HIGH,
                patience=Patience.MEDIUM_TERM,
                noise_pref=NoisePreference.MODERATE,
                risk_tolerance=0.6,
                adaptability=0.7,
                capabilities=_RANSOMWARE_CAPS,
                preferred_ttps=[
                    TTPCategory.INITIAL_ACCESS, TTPCategory.CRED_ACCESS,
                    TTPCategory.LATERAL_MOVEMENT, TTPCategory.IMPACT,
                ],
                preferred_targets=["enterprise", "healthcare", "education"],
                known_tools=["conti", "lockbit", "mimikatz", "psexec"],
                cwe_affinity={"CWE-78": 0.8, "CWE-287": 0.7, "CWE-269": 0.8, "CWE-798": 0.6},
                typical_chain_depth=5,
            ),
            AttackPersona(
                persona_id="insider_threat",
                name="Insider Threat",
                description="Malicious insider with legitimate access. "
                            "Doesn't need to break in — already has keys. "
                            "Focuses on data exfiltration and privilege abuse.",
                skill=SkillLevel.INTERMEDIATE,
                motivation=Motivation.INSIDER_REVENGE,
                resources=ResourceLevel.LOW,
                patience=Patience.LONG_TERM,
                noise_pref=NoisePreference.STEALTHY,
                risk_tolerance=0.3,
                adaptability=0.4,
                capabilities=_INSIDER_CAPS,
                preferred_ttps=[
                    TTPCategory.COLLECTION, TTPCategory.EXFILTRATION,
                    TTPCategory.CRED_ACCESS,
                ],
                preferred_targets=["internal_app", "database", "file_share", "cloud_storage"],
                known_tools=["browser", "curl", "cloud_cli"],
                cwe_affinity={"CWE-639": 0.9, "CWE-269": 0.8, "CWE-200": 0.7, "CWE-16": 0.5},
                typical_chain_depth=3,
            ),
            AttackPersona(
                persona_id="pentester",
                name="Professional Pentester",
                description="Authorized security tester. Methodical, thorough, follows a "
                            "structured approach. High skill, moderate noise tolerance. "
                            "Explores everything systematically.",
                skill=SkillLevel.ADVANCED,
                motivation=Motivation.REPUTATION,
                resources=ResourceLevel.MODERATE,
                patience=Patience.MEDIUM_TERM,
                noise_pref=NoisePreference.CAUTIOUS,
                risk_tolerance=0.7,
                adaptability=0.8,
                capabilities=_PENTESTER_CAPS,
                preferred_ttps=[
                    TTPCategory.RECON, TTPCategory.INITIAL_ACCESS,
                    TTPCategory.PRIV_ESC, TTPCategory.DISCOVERY,
                ],
                preferred_targets=["web_app", "api", "network", "cloud"],
                known_tools=["burp_suite", "nmap", "gobuster", "nuclei", "ffuf"],
                cwe_affinity={"CWE-89": 0.8, "CWE-79": 0.8, "CWE-22": 0.7, "CWE-918": 0.8, "CWE-502": 0.6},
                typical_chain_depth=4,
            ),
            AttackPersona(
                persona_id="bug_bounty_hunter",
                name="Bug Bounty Hunter",
                description="Focused on finding and reporting vulnerabilities for bounty. "
                            "Creative, fast, targets web applications. Aims for maximum "
                            "impact with minimum effort for highest payout.",
                skill=SkillLevel.ADVANCED,
                motivation=Motivation.FINANCIAL,
                resources=ResourceLevel.LOW,
                patience=Patience.SHORT_TERM,
                noise_pref=NoisePreference.CAUTIOUS,
                risk_tolerance=0.5,
                adaptability=0.85,
                capabilities=_BUG_BOUNTY_CAPS,
                preferred_ttps=[TTPCategory.RECON, TTPCategory.INITIAL_ACCESS],
                preferred_targets=["web_app", "api", "mobile_app"],
                known_tools=["burp_suite", "subfinder", "nuclei", "httpx"],
                cwe_affinity={"CWE-89": 0.7, "CWE-918": 0.9, "CWE-639": 0.8, "CWE-22": 0.7, "CWE-79": 0.5},
                typical_chain_depth=3,
            ),
            AttackPersona(
                persona_id="cryptominer",
                name="Cryptominer",
                description="Financially motivated attacker deploying cryptocurrency mining. "
                            "Low to moderate skill. Wants persistence and stealth to maximize "
                            "mining time without detection.",
                skill=SkillLevel.INTERMEDIATE,
                motivation=Motivation.FINANCIAL,
                resources=ResourceLevel.LOW,
                patience=Patience.LONG_TERM,
                noise_pref=NoisePreference.STEALTHY,
                risk_tolerance=0.4,
                adaptability=0.3,
                capabilities=_CRYPTOMINER_CAPS,
                preferred_ttps=[
                    TTPCategory.INITIAL_ACCESS, TTPCategory.EXECUTION,
                    TTPCategory.PERSISTENCE, TTPCategory.IMPACT,
                ],
                preferred_targets=["web_server", "cloud_instance", "container"],
                known_tools=["xmrig", "coinhive", "monero_miner"],
                cwe_affinity={"CWE-78": 0.9, "CWE-94": 0.7, "CWE-434": 0.6, "CWE-798": 0.5},
                typical_chain_depth=3,
            ),
            AttackPersona(
                persona_id="hacktivist",
                name="Hacktivist",
                description="Ideologically motivated attacker. Targets specific orgs for "
                            "political/social reasons. Wants visible impact: defacement, "
                            "data leaks, service disruption.",
                skill=SkillLevel.INTERMEDIATE,
                motivation=Motivation.HACKTIVISM,
                resources=ResourceLevel.MODERATE,
                patience=Patience.SHORT_TERM,
                noise_pref=NoisePreference.LOUD,
                risk_tolerance=0.9,
                adaptability=0.4,
                capabilities=_HACKTIVIST_CAPS,
                preferred_ttps=[
                    TTPCategory.INITIAL_ACCESS, TTPCategory.IMPACT,
                    TTPCategory.COLLECTION,
                ],
                preferred_targets=["web_app", "public_facing", "social_media"],
                known_tools=["loic", "sqlmap", "defacement_tools"],
                cwe_affinity={"CWE-89": 0.8, "CWE-79": 0.7, "CWE-434": 0.6, "CWE-78": 0.5},
                typical_chain_depth=2,
            ),
        ]

        for persona in builtins:
            self._personas[persona.persona_id] = persona

    def get(self, persona_id: str) -> Optional[AttackPersona]:
        """Get a persona by ID."""
        with self._lock:
            return self._personas.get(persona_id)

    def get_all(self) -> List[AttackPersona]:
        """Get all personas."""
        with self._lock:
            return list(self._personas.values())

    def register(self, persona: AttackPersona) -> None:
        """Register a custom persona."""
        with self._lock:
            self._personas[persona.persona_id] = persona

    def get_most_likely_attackers(
        self, target_type: str, vulns_present: List[str]
    ) -> List[Tuple[AttackPersona, float]]:
        """Given a target profile, rank which personas are most likely to attack it.

        Args:
            target_type: Type of target (e.g., "web_app", "enterprise")
            vulns_present: List of CWE IDs present
        Returns:
            List of (persona, likelihood_score) sorted by likelihood descending
        """
        with self._lock:
            personas = list(self._personas.values())

        scores: List[Tuple[AttackPersona, float]] = []

        for persona in personas:
            score = 0.0

            # Target affinity
            if target_type in persona.preferred_targets:
                score += 0.3

            # CWE overlap: how many present vulns match persona preferences?
            if vulns_present:
                affinities = [
                    persona.cwe_affinity.get(cwe, 0.0)
                    for cwe in vulns_present
                ]
                if affinities:
                    score += 0.4 * (sum(affinities) / len(affinities))

            # Motivation alignment: financial attackers prefer rich targets
            if persona.motivation in (Motivation.FINANCIAL, Motivation.ESPIONAGE):
                score += 0.15
            elif persona.motivation == Motivation.CURIOSITY:
                score += 0.05

            # Skill-adjusted: more skilled = more likely to attempt complex targets
            score += 0.15 * (persona.skill.value / 5.0)

            scores.append((persona, min(1.0, score)))

        scores.sort(key=lambda x: x[1], reverse=True)
        return scores


# ════════════════════════════════════════════════════════════════════════════════
# BEHAVIOR SIMULATOR
# ════════════════════════════════════════════════════════════════════════════════


class BehaviorSimulator:
    """Simulates attacker behavior based on persona profile.

    Given a persona and a set of available actions, simulates the decision-making
    process: what would this attacker do next? Uses a weighted utility model
    that accounts for the persona's preferences, risk tolerance, stealth needs,
    and current state.
    """

    def __init__(self, persona: AttackPersona) -> None:
        self._persona = persona
        self._state = SimulationState()
        self._rng = random.Random(hash(persona.persona_id))
        self._decision_history: List[PersonaDecision] = []
        self._lock = threading.RLock()

    def decide(
        self,
        decision_type: DecisionType,
        options: List[Dict[str, Any]],
    ) -> PersonaDecision:
        """Make a decision based on persona profile and current state.

        Each option dict should have:
            - "id": unique identifier
            - "name": human-readable name
            - "probability": success probability [0-1]
            - "impact": potential impact [0-1]
            - "noise": noise level [0-1]
            - "required_skill": SkillLevel value (int 1-5)
            - "cwe_id": optional CWE association
        """
        if not options:
            return PersonaDecision(
                decision_type=decision_type,
                chosen_action="none",
                reasoning="No options available",
                confidence=0.0,
            )

        scored: List[Tuple[Dict[str, Any], float]] = []
        for opt in options:
            utility = self._calculate_utility(opt)
            scored.append((opt, utility))

        scored.sort(key=lambda x: x[1], reverse=True)

        # Introduce controlled randomness based on adaptability
        # More adaptable personas are more likely to explore suboptimal choices
        if len(scored) > 1 and self._rng.random() < self._persona.adaptability * 0.3:
            # Weighted random from top candidates
            top_n = min(3, len(scored))
            weights = [s[1] + DECISION_EPSILON for _, s in zip(range(top_n), scored)]
            total = sum(weights)
            probs = [w / total for w in weights]
            choice_idx = self._weighted_choice(probs)
            chosen = scored[choice_idx]
        else:
            chosen = scored[0]

        best_opt, best_score = chosen
        alternatives = [(s[0].get("name", s[0]["id"]), s[1]) for s in scored[1:4]]

        decision = PersonaDecision(
            decision_type=decision_type,
            chosen_action=best_opt.get("name", best_opt["id"]),
            reasoning=self._generate_reasoning(decision_type, best_opt),
            confidence=best_score,
            alternatives=alternatives,
        )

        with self._lock:
            self._decision_history.append(decision)
            self._state.step += 1

        return decision

    def _calculate_utility(self, option: Dict[str, Any]) -> float:
        """Calculate utility of an option for this persona."""
        prob = option.get("probability", 0.5)
        impact = option.get("impact", 0.5)
        noise = option.get("noise", 0.5)
        req_skill = option.get("required_skill", 3)

        # Can this persona even use this technique?
        if req_skill > self._persona.skill.value:
            return 0.0  # Skill gate

        # Base utility: expected value
        expected_value = prob * impact

        # Stealth penalty: high-stealth personas hate noisy options
        noise_penalty = noise * (1.0 - self._persona.stealth_factor)
        # Invert: stealthier personas incur higher penalty for noisy ops
        stealth_penalty = noise * self._persona.stealth_factor

        # Risk factor: risk-tolerant personas accept lower-probability options
        risk_bonus = (1.0 - prob) * self._persona.risk_tolerance * 0.2

        # CWE affinity bonus
        cwe_id = option.get("cwe_id", "")
        cwe_bonus = self._persona.cwe_affinity.get(cwe_id, 0.0) * 0.15

        # Patience factor: impatient personas prefer fast options
        time_cost = option.get("time_hours", 0.0)
        patience_penalty = 0.0
        if time_cost > 0 and self._persona.patience.value < 3:
            patience_penalty = min(0.3, time_cost / 24.0)

        # Detection risk: have we been detected? If so, stealthy personas abort
        if self._state.detected and self._persona.noise_pref.value >= 4:
            return 0.0  # Abort — too risky after detection

        utility = (
            expected_value * 0.45
            + risk_bonus
            + cwe_bonus
            - stealth_penalty * 0.25
            - patience_penalty
        )

        return max(0.0, utility)

    def _weighted_choice(self, weights: List[float]) -> int:
        """Weighted random selection."""
        r = self._rng.random()
        cumulative = 0.0
        for i, w in enumerate(weights):
            cumulative += w
            if r <= cumulative:
                return i
        return len(weights) - 1

    def _generate_reasoning(self, dtype: DecisionType, option: Dict[str, Any]) -> str:
        """Generate reasoning for a decision (human-readable insight)."""
        persona = self._persona
        name = option.get("name", option.get("id", "unknown"))
        prob = option.get("probability", 0)
        noise = option.get("noise", 0)

        parts: List[str] = []

        if dtype == DecisionType.CHOOSE_TARGET:
            parts.append(f"Selected '{name}' as target")
            if persona.motivation == Motivation.FINANCIAL:
                parts.append("— high financial value expected")
            elif persona.motivation == Motivation.ESPIONAGE:
                parts.append("— intelligence value prioritized")

        elif dtype == DecisionType.CHOOSE_TECHNIQUE:
            parts.append(f"Chose technique '{name}'")
            if prob > 0.7:
                parts.append(f"(high success rate: {prob:.0%})")
            if noise < 0.3 and persona.stealth_factor > 0.6:
                parts.append("— low noise aligns with stealth preference")
            elif noise > 0.7:
                parts.append("— noise acceptable for this persona")

        elif dtype == DecisionType.ESCALATE_OR_RETREAT:
            parts.append(f"Decision: {name}")
            if persona.risk_tolerance > 0.6:
                parts.append("— risk-tolerant, pushing forward")
            else:
                parts.append("— conservative, evaluating escape routes")

        else:
            parts.append(f"Action: {name}")

        return " ".join(parts)

    @property
    def state(self) -> SimulationState:
        return self._state

    @property
    def decision_history(self) -> List[PersonaDecision]:
        with self._lock:
            return list(self._decision_history)

    def reset(self) -> None:
        with self._lock:
            self._state = SimulationState()
            self._decision_history.clear()


# ════════════════════════════════════════════════════════════════════════════════
# STRATEGY SELECTOR
# ════════════════════════════════════════════════════════════════════════════════


class PersonaStrategySelector:
    """Given a persona and available exploit chains, selects the optimal strategy.

    Different personas prefer different chains:
    - Script kiddie: shortest chain, highest probability
    - APT: stealthiest chain, maximum impact
    - Ransomware: fastest to full compromise, lateral movement emphasis
    - Insider: chains using existing access, data-focused
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._strategy_functions: Dict[str, Callable] = {
            "script_kiddie": self._score_for_script_kiddie,
            "apt_nation_state": self._score_for_apt,
            "ransomware_operator": self._score_for_ransomware,
            "insider_threat": self._score_for_insider,
            "pentester": self._score_for_pentester,
            "bug_bounty_hunter": self._score_for_bug_bounty,
            "cryptominer": self._score_for_cryptominer,
            "hacktivist": self._score_for_hacktivist,
        }

    def select_chains(
        self,
        persona: AttackPersona,
        chains: List[Dict[str, Any]],
        top_k: int = 5,
    ) -> List[Tuple[Dict[str, Any], float, str]]:
        """Score and rank chains for a specific persona.

        Args:
            persona: The attacker persona
            chains: List of chain dicts (from ChainCandidate.to_dict())
            top_k: Number of top chains to return
        Returns:
            List of (chain_dict, persona_score, reasoning) tuples
        """
        scorer = self._strategy_functions.get(
            persona.persona_id, self._score_generic
        )

        results: List[Tuple[Dict[str, Any], float, str]] = []
        for chain in chains:
            score, reasoning = scorer(persona, chain)
            results.append((chain, score, reasoning))

        results.sort(key=lambda x: x[1], reverse=True)
        return results[:top_k]

    def _score_for_script_kiddie(
        self, persona: AttackPersona, chain: Dict[str, Any]
    ) -> Tuple[float, str]:
        """Script kiddies: high probability, short chains, known techniques."""
        prob = chain.get("total_probability", 0)
        depth = chain.get("depth", 10)
        score = prob * 0.5 + (1.0 / max(1, depth)) * 0.4 + 0.1
        reasoning = f"Simple chain ({depth} steps), {prob:.0%} success"
        return (score, reasoning)

    def _score_for_apt(
        self, persona: AttackPersona, chain: Dict[str, Any]
    ) -> Tuple[float, str]:
        """APT: maximum stealth, high impact, patience for deep chains."""
        stealth = chain.get("stealth_score", 0)
        impact = chain.get("total_impact", 0)
        prob = chain.get("total_probability", 0)
        score = stealth * 0.4 + impact * 0.35 + prob * 0.25
        reasoning = f"Stealth: {stealth:.2f}, Impact: {impact:.2f}"
        return (score, reasoning)

    def _score_for_ransomware(
        self, persona: AttackPersona, chain: Dict[str, Any]
    ) -> Tuple[float, str]:
        """Ransomware: fast compromise, lateral movement, high impact."""
        impact = chain.get("total_impact", 0)
        prob = chain.get("total_probability", 0)
        time_ms = chain.get("estimated_time_ms", 999999)
        time_score = 1.0 / (1.0 + time_ms / 10000.0)
        score = impact * 0.35 + prob * 0.35 + time_score * 0.3
        reasoning = f"Impact: {impact:.2f}, Speed: {time_score:.2f}"
        return (score, reasoning)

    def _score_for_insider(
        self, persona: AttackPersona, chain: Dict[str, Any]
    ) -> Tuple[float, str]:
        """Insider: stealth, data access focus, minimal technical steps."""
        stealth = chain.get("stealth_score", 0)
        depth = chain.get("depth", 10)
        prob = chain.get("total_probability", 0)
        short_bonus = 1.0 / max(1, depth)
        score = stealth * 0.4 + prob * 0.3 + short_bonus * 0.3
        reasoning = f"Stealth: {stealth:.2f}, Short path ({depth} steps)"
        return (score, reasoning)

    def _score_for_pentester(
        self, persona: AttackPersona, chain: Dict[str, Any]
    ) -> Tuple[float, str]:
        """Pentester: balanced approach, thorough coverage, documented."""
        prob = chain.get("total_probability", 0)
        impact = chain.get("total_impact", 0)
        depth = chain.get("depth", 1)
        coverage = min(1.0, depth / 5.0)
        score = prob * 0.3 + impact * 0.3 + coverage * 0.2 + 0.2
        reasoning = f"Prob: {prob:.0%}, Impact: {impact:.2f}, Coverage: {depth} steps"
        return (score, reasoning)

    def _score_for_bug_bounty(
        self, persona: AttackPersona, chain: Dict[str, Any]
    ) -> Tuple[float, str]:
        """Bug bounty: maximum impact with minimum steps = highest payout/effort."""
        impact = chain.get("total_impact", 0)
        depth = chain.get("depth", 10)
        efficiency = impact / max(1, depth)
        prob = chain.get("total_probability", 0)
        score = efficiency * 0.5 + prob * 0.3 + impact * 0.2
        reasoning = f"Efficiency: {efficiency:.2f} (impact/steps), Impact: {impact:.2f}"
        return (score, reasoning)

    def _score_for_cryptominer(
        self, persona: AttackPersona, chain: Dict[str, Any]
    ) -> Tuple[float, str]:
        """Cryptominer: needs execution + persistence, stealth for longevity."""
        stealth = chain.get("stealth_score", 0)
        prob = chain.get("total_probability", 0)
        # Check for persistence-related steps
        steps = chain.get("steps", [])
        has_exec = any("exec" in s.get("type", "") for s in steps)
        exec_bonus = 0.3 if has_exec else 0.0
        score = stealth * 0.3 + prob * 0.3 + exec_bonus + 0.1
        reasoning = f"Stealth: {stealth:.2f}, Exec: {'yes' if has_exec else 'no'}"
        return (score, reasoning)

    def _score_for_hacktivist(
        self, persona: AttackPersona, chain: Dict[str, Any]
    ) -> Tuple[float, str]:
        """Hacktivist: maximum visibility, fast, doesn't care about stealth."""
        impact = chain.get("total_impact", 0)
        prob = chain.get("total_probability", 0)
        depth = chain.get("depth", 10)
        speed = 1.0 / max(1, depth)
        score = impact * 0.4 + prob * 0.3 + speed * 0.3
        reasoning = f"Impact: {impact:.2f}, Speed: {speed:.2f}"
        return (score, reasoning)

    def _score_generic(
        self, persona: AttackPersona, chain: Dict[str, Any]
    ) -> Tuple[float, str]:
        """Generic scoring for custom personas."""
        prob = chain.get("total_probability", 0)
        impact = chain.get("total_impact", 0)
        stealth = chain.get("stealth_score", 0)
        score = (
            prob * 0.3
            + impact * 0.3
            + stealth * persona.stealth_factor * 0.2
            + (1.0 / max(1, chain.get("depth", 5))) * 0.2
        )
        reasoning = f"Generic: prob={prob:.2f}, impact={impact:.2f}, stealth={stealth:.2f}"
        return (score, reasoning)


# ════════════════════════════════════════════════════════════════════════════════
# MAIN INTERFACE: SirenAttackPersonaEngine
# ════════════════════════════════════════════════════════════════════════════════


class SirenAttackPersonaEngine:
    """Main interface for persona-driven attack simulation.

    Usage:
        engine = SirenAttackPersonaEngine()

        # Who would attack this target?
        likely = engine.get_likely_attackers("web_app", ["CWE-89", "CWE-22"])

        # Simulate an APT's decision-making
        decisions = engine.simulate_engagement("apt_nation_state", vulns_available)

        # Rank chains per persona
        ranked = engine.rank_chains_for_persona("ransomware_operator", chains)
    """

    def __init__(self) -> None:
        self._library = PersonaLibrary()
        self._selector = PersonaStrategySelector()
        self._simulators: Dict[str, BehaviorSimulator] = {}
        self._pool = ThreadPoolExecutor(
            max_workers=THREAD_POOL_SIZE, thread_name_prefix="siren-persona"
        )
        self._lock = threading.RLock()

        # Threat matrix cache: (key, timestamp, result)
        self._threat_matrix_cache: Optional[Tuple[str, float, Dict[str, Any]]] = None
        self._threat_matrix_cache_ttl: float = 60.0  # seconds

        logger.info("SirenAttackPersonaEngine initialized with %d personas",
                     len(self._library.get_all()))

    def get_likely_attackers(
        self, target_type: str, vulns_present: List[str], top_k: int = 5
    ) -> List[Dict[str, Any]]:
        """Get ranked list of most likely attacker personas."""
        ranked = self._library.get_most_likely_attackers(target_type, vulns_present)
        return [
            {
                "persona": p.to_dict(),
                "likelihood": score,
            }
            for p, score in ranked[:top_k]
        ]

    def simulate_decisions(
        self,
        persona_id: str,
        decisions: List[Tuple[DecisionType, List[Dict[str, Any]]]],
    ) -> List[PersonaDecision]:
        """Simulate a sequence of decisions for a persona.

        Args:
            persona_id: ID of the persona to simulate
            decisions: List of (decision_type, options) tuples
        Returns:
            List of PersonaDecision objects
        """
        persona = self._library.get(persona_id)
        if not persona:
            return []

        sim = self._get_or_create_simulator(persona)
        sim.reset()

        results: List[PersonaDecision] = []
        for dtype, options in decisions:
            decision = sim.decide(dtype, options)
            results.append(decision)

        return results

    def rank_chains_for_persona(
        self,
        persona_id: str,
        chains: List[Dict[str, Any]],
        top_k: int = 5,
    ) -> List[Dict[str, Any]]:
        """Rank exploit chains for a specific persona."""
        persona = self._library.get(persona_id)
        if not persona:
            return []

        results = self._selector.select_chains(persona, chains, top_k)
        return [
            {
                "chain": chain,
                "persona_score": score,
                "reasoning": reasoning,
                "persona": persona.name,
            }
            for chain, score, reasoning in results
        ]

    def rank_chains_all_personas(
        self, chains: List[Dict[str, Any]], top_k: int = 3
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Rank chains across ALL personas."""
        results: Dict[str, List[Dict[str, Any]]] = {}
        for persona in self._library.get_all():
            ranked = self.rank_chains_for_persona(persona.persona_id, chains, top_k)
            if ranked:
                results[persona.persona_id] = ranked
        return results

    def get_persona(self, persona_id: str) -> Optional[Dict[str, Any]]:
        """Get persona details."""
        persona = self._library.get(persona_id)
        return persona.to_dict() if persona else None

    def list_personas(self) -> List[Dict[str, Any]]:
        """List all available personas."""
        return [p.to_dict() for p in self._library.get_all()]

    def register_persona(self, persona: AttackPersona) -> None:
        """Register a custom persona."""
        self._library.register(persona)
        with self._lock:
            self._threat_matrix_cache = None

    def _get_or_create_simulator(self, persona: AttackPersona) -> BehaviorSimulator:
        """Get or create a BehaviorSimulator for a persona."""
        with self._lock:
            if persona.persona_id not in self._simulators:
                self._simulators[persona.persona_id] = BehaviorSimulator(persona)
            return self._simulators[persona.persona_id]

    def get_threat_matrix(
        self, target_type: str, vulns: List[str]
    ) -> Dict[str, Any]:
        """Generate complete threat matrix: personas × vulns × strategy.

        Returns a comprehensive view of how each persona would approach
        the given target.  Results are cached for up to 60 seconds and
        automatically invalidated when personas change.
        """
        cache_key = f"{target_type}:{','.join(sorted(vulns))}"
        now = time.time()

        with self._lock:
            if (self._threat_matrix_cache is not None
                    and self._threat_matrix_cache[0] == cache_key
                    and now - self._threat_matrix_cache[1] < self._threat_matrix_cache_ttl):
                return self._threat_matrix_cache[2]

        likely = self._library.get_most_likely_attackers(target_type, vulns)

        matrix: Dict[str, Any] = {
            "target_type": target_type,
            "vulnerabilities": vulns,
            "threat_actors": [],
        }

        for persona, likelihood in likely:
            actor = {
                "persona": persona.to_dict(),
                "likelihood": likelihood,
                "preferred_vulns": [
                    cwe for cwe in vulns
                    if persona.cwe_affinity.get(cwe, 0) > 0.5
                ],
                "expected_ttps": [t.value for t in persona.preferred_ttps],
                "dwell_time_estimate": self._estimate_dwell_time(persona),
                "detectable": persona.noise_pref.value <= 2,
                "risk_level": "critical" if likelihood > 0.7 and persona.effectiveness > 0.6
                              else "high" if likelihood > 0.5
                              else "medium" if likelihood > 0.3
                              else "low",
            }
            matrix["threat_actors"].append(actor)

        with self._lock:
            self._threat_matrix_cache = (cache_key, time.time(), matrix)

        return matrix

    def _estimate_dwell_time(self, persona: AttackPersona) -> str:
        """Estimate how long this persona would dwell in a compromised system."""
        patience_map = {
            Patience.IMPATIENT: "< 1 hour",
            Patience.SHORT_TERM: "1-24 hours",
            Patience.MEDIUM_TERM: "1-7 days",
            Patience.LONG_TERM: "1-4 weeks",
            Patience.INDEFINITE: "months to years",
        }
        return patience_map.get(persona.patience, "unknown")

    def save_state(self, path: Union[str, Path]) -> None:
        """Save engine state."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        state = {
            "personas": {pid: p.to_dict() for pid, p in
                         {pe.persona_id: pe for pe in self._library.get_all()}.items()},
            "simulation_count": sum(
                len(s.decision_history) for s in self._simulators.values()
            ),
        }
        p.write_text(json.dumps(state, indent=2, default=str), encoding="utf-8")

    def shutdown(self) -> None:
        """Shutdown thread pool."""
        self._pool.shutdown(wait=False)
        logger.info("SirenAttackPersonaEngine shutdown")

    def __del__(self) -> None:
        """Safety net to ensure thread pool is cleaned up."""
        self.shutdown()
