#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  SIREN ATTACK PLANNER — Planejamento PDDL de Ataques Ofensivos               ██
██                                                                                ██
██  O primeiro motor de planejamento estilo PDDL para pentest do mundo.          ██
██                                                                                ██
██  Define estados do mundo, acoes com pre-condicoes/efeitos, e busca            ██
██  caminhos otimos de ataque via A* com heuristica de fatos faltantes.          ██
██  Nenhum framework — comercial ou open-source — tem isso.                      ██
██                                                                                ██
██  Capacidades:                                                                  ██
██    * PlanState — estado corrente do alvo (fatos + recursos)                   ██
██    * AttackPrecondition — guarda logica de pre-requisitos                      ██
██    * AttackEffect — mutacao de estado (add/remove fatos, recursos, custo)     ██
██    * AttackAction — passo atomico com MITRE T-code                            ██
██    * ActionLibrary — 100+ acoes predefinidas cobrindo kill chain completa     ██
██    * AttackGoal — objetivo final (exfiltracao, root, takeover)                ██
██    * PlanSearchEngine — A* + beam search para planos otimos                   ██
██    * AttackPlan — sequencia ordenada com metricas                             ██
██    * PlanOptimizer — minimiza deteccao, tempo, paraleliza                     ██
██    * SirenAttackPlanner — orquestrador principal                              ██
██                                                                                ██
██  "SIREN nao improvisa ataques. Ela os PLANEJA como um general."               ██
██                                                                                ██
████████████████████████████████████████████████████████████████████████████████████
"""

from __future__ import annotations

import copy
import hashlib
import heapq
import json
import logging
import math
import threading
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    Any,
    Callable,
    Dict,
    FrozenSet,
    Iterator,
    List,
    Optional,
    Set,
    Tuple,
    Union,
)

logger = logging.getLogger("siren.cortex.attack_planner")


# ════════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════════════════════════════

MAX_PLAN_DEPTH = 20
BEAM_WIDTH = 64
MAX_CANDIDATES = 2048
DEFAULT_ACTION_COST = 1.0
DEFAULT_DETECTION_RISK = 0.1
DEFAULT_TIME_MINUTES = 5
DETECTION_RISK_PENALTY_WEIGHT = 5.0
PARALLEL_INDEPENDENCE_THRESHOLD = 0.0
EPSILON = 1e-12


# ════════════════════════════════════════════════════════════════════════════════
# ENUMS
# ════════════════════════════════════════════════════════════════════════════════


class ActionCategory(Enum):
    """Kill-chain phase categories for attack actions."""
    RECON = auto()
    ENUMERATION = auto()
    EXPLOITATION = auto()
    PRIVILEGE_ESCALATION = auto()
    LATERAL_MOVEMENT = auto()
    PERSISTENCE = auto()
    EXFILTRATION = auto()
    CLEANUP = auto()


class GoalType(Enum):
    """Predefined strategic goal archetypes."""
    DATA_EXFILTRATION = auto()
    FULL_COMPROMISE = auto()
    ACCOUNT_TAKEOVER = auto()
    NETWORK_PIVOT = auto()
    PERSISTENCE_ESTABLISHMENT = auto()
    CREDENTIAL_HARVEST = auto()
    DENIAL_OF_SERVICE = auto()
    SUPPLY_CHAIN_ATTACK = auto()
    CUSTOM = auto()


class PlanStatus(Enum):
    """Status of a computed attack plan."""
    PENDING = auto()
    FEASIBLE = auto()
    OPTIMAL = auto()
    PARTIAL = auto()
    INFEASIBLE = auto()


# ════════════════════════════════════════════════════════════════════════════════
# PlanState
# ════════════════════════════════════════════════════════════════════════════════


@dataclass
class PlanState:
    """Represents the current state of knowledge about a target.

    A state consists of a set of boolean *facts* (things we know to be true)
    and a dictionary of *resources* we have collected (tokens, creds, endpoints).

    Usage::

        state = PlanState(
            facts={"has_network_access", "has_target_ip"},
            resources={"target_ip": "10.0.0.1"},
        )
    """

    facts: Set[str] = field(default_factory=set)
    resources: Dict[str, Any] = field(default_factory=dict)

    # ── serialization ──

    def to_dict(self) -> Dict[str, Any]:
        return {
            "facts": sorted(self.facts),
            "resources": dict(self.resources),
        }

    # ── hashing / equality ──

    def __hash__(self) -> int:
        # Convert mutable containers to immutable equivalents so PlanState
        # can be stored in sets and used as dict keys (required by A* visited set).
        return hash((
            frozenset(self.facts),
            frozenset(sorted(self.resources.items())),
        ))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PlanState):
            return NotImplemented
        return self.facts == other.facts and self.resources == other.resources

    # ── convenience ──

    def copy(self) -> PlanState:
        return PlanState(
            facts=set(self.facts),
            resources=dict(self.resources),
        )

    def has_fact(self, fact: str) -> bool:
        return fact in self.facts

    def has_resource(self, key: str) -> bool:
        return key in self.resources

    def add_fact(self, fact: str) -> None:
        self.facts.add(fact)

    def remove_fact(self, fact: str) -> None:
        self.facts.discard(fact)

    def set_resource(self, key: str, value: Any) -> None:
        self.resources[key] = value

    def missing_facts(self, required: Set[str]) -> Set[str]:
        return required - self.facts

    def missing_resources(self, required: Set[str]) -> Set[str]:
        return required - set(self.resources.keys())

    def merge(self, other: PlanState) -> PlanState:
        merged = self.copy()
        merged.facts |= other.facts
        merged.resources.update(other.resources)
        return merged

    def fact_count(self) -> int:
        return len(self.facts)

    def __repr__(self) -> str:
        return f"PlanState(facts={len(self.facts)}, resources={len(self.resources)})"


# ════════════════════════════════════════════════════════════════════════════════
# AttackPrecondition
# ════════════════════════════════════════════════════════════════════════════════


@dataclass
class AttackPrecondition:
    """Logical guard that must be satisfied before an action can execute.

    * ``required_facts`` — facts that MUST be present.
    * ``forbidden_facts`` — facts that MUST NOT be present.
    * ``required_resources`` — resource keys that MUST exist.
    """

    required_facts: Set[str] = field(default_factory=set)
    forbidden_facts: Set[str] = field(default_factory=set)
    required_resources: Set[str] = field(default_factory=set)

    def is_satisfied(self, state: PlanState) -> bool:
        if not self.required_facts.issubset(state.facts):
            return False
        if self.forbidden_facts & state.facts:
            return False
        if not self.required_resources.issubset(set(state.resources.keys())):
            return False
        return True

    def missing_facts(self, state: PlanState) -> Set[str]:
        return self.required_facts - state.facts

    def blocking_facts(self, state: PlanState) -> Set[str]:
        return self.forbidden_facts & state.facts

    def missing_resources(self, state: PlanState) -> Set[str]:
        return self.required_resources - set(state.resources.keys())

    def distance(self, state: PlanState) -> int:
        """How many requirements are unsatisfied."""
        return (
            len(self.missing_facts(state))
            + len(self.blocking_facts(state))
            + len(self.missing_resources(state))
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "required_facts": sorted(self.required_facts),
            "forbidden_facts": sorted(self.forbidden_facts),
            "required_resources": sorted(self.required_resources),
        }

    def __repr__(self) -> str:
        return (
            f"Precondition(req={len(self.required_facts)}, "
            f"forbid={len(self.forbidden_facts)}, "
            f"res={len(self.required_resources)})"
        )


# ════════════════════════════════════════════════════════════════════════════════
# AttackEffect
# ════════════════════════════════════════════════════════════════════════════════


@dataclass
class AttackEffect:
    """Describes what changes when an action executes.

    * ``add_facts`` — facts gained.
    * ``remove_facts`` — facts lost.
    * ``add_resources`` — new resources acquired (key -> description).
    * ``cost`` — abstract effort/time cost.
    * ``detection_risk`` — probability of triggering defenses (0.0–1.0).
    """

    add_facts: Set[str] = field(default_factory=set)
    remove_facts: Set[str] = field(default_factory=set)
    add_resources: Dict[str, str] = field(default_factory=dict)
    cost: float = DEFAULT_ACTION_COST
    detection_risk: float = DEFAULT_DETECTION_RISK

    def apply(self, state: PlanState) -> PlanState:
        new_state = state.copy()
        new_state.facts |= self.add_facts
        new_state.facts -= self.remove_facts
        for k, v in self.add_resources.items():
            new_state.resources[k] = v
        return new_state

    def net_facts(self) -> Set[str]:
        return self.add_facts - self.remove_facts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "add_facts": sorted(self.add_facts),
            "remove_facts": sorted(self.remove_facts),
            "add_resources": dict(self.add_resources),
            "cost": self.cost,
            "detection_risk": self.detection_risk,
        }

    def __repr__(self) -> str:
        return (
            f"Effect(+{len(self.add_facts)}/-{len(self.remove_facts)} facts, "
            f"cost={self.cost:.1f}, risk={self.detection_risk:.2f})"
        )


# ════════════════════════════════════════════════════════════════════════════════
# AttackAction
# ════════════════════════════════════════════════════════════════════════════════


@dataclass
class AttackAction:
    """A single atomic attack step with PDDL-style preconditions and effects.

    Each action maps to a MITRE ATT&CK technique and belongs to a kill-chain
    category. The planner composes these into multi-step attack plans.
    """

    action_id: str = ""
    name: str = ""
    description: str = ""
    category: ActionCategory = ActionCategory.RECON
    preconditions: AttackPrecondition = field(default_factory=AttackPrecondition)
    effects: AttackEffect = field(default_factory=AttackEffect)
    mitre_technique: str = ""
    estimated_time_minutes: int = DEFAULT_TIME_MINUTES

    def __post_init__(self) -> None:
        if not self.action_id:
            self.action_id = str(uuid.uuid4())[:8]

    def is_applicable(self, state: PlanState) -> bool:
        return self.preconditions.is_satisfied(state)

    def apply(self, state: PlanState) -> PlanState:
        if not self.is_applicable(state):
            raise ValueError(
                f"Action '{self.name}' preconditions not met in state"
            )
        return self.effects.apply(state)

    def contributes_toward(self, goal_facts: Set[str], state: PlanState) -> bool:
        """Does this action add at least one fact needed for the goal?"""
        missing = goal_facts - state.facts
        return bool(self.effects.add_facts & missing)

    def relevance_score(self, goal_facts: Set[str], state: PlanState) -> float:
        missing = goal_facts - state.facts
        if not missing:
            return 0.0
        contributed = self.effects.add_facts & missing
        return len(contributed) / (len(missing) + EPSILON)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_id": self.action_id,
            "name": self.name,
            "description": self.description,
            "category": self.category.name,
            "preconditions": self.preconditions.to_dict(),
            "effects": self.effects.to_dict(),
            "mitre_technique": self.mitre_technique,
            "estimated_time_minutes": self.estimated_time_minutes,
        }

    def __repr__(self) -> str:
        return f"Action({self.name} [{self.category.name}])"


# ════════════════════════════════════════════════════════════════════════════════
# AttackGoal
# ════════════════════════════════════════════════════════════════════════════════


@dataclass
class AttackGoal:
    """Strategic objective the planner tries to achieve.

    A goal is satisfied when all ``required_facts`` are present in the state
    and all ``target_resources`` have been collected.
    """

    goal_id: str = ""
    name: str = ""
    description: str = ""
    goal_type: GoalType = GoalType.CUSTOM
    required_facts: Set[str] = field(default_factory=set)
    target_resources: Set[str] = field(default_factory=set)
    priority: float = 1.0

    def __post_init__(self) -> None:
        if not self.goal_id:
            self.goal_id = str(uuid.uuid4())[:8]

    def is_achieved(self, state: PlanState) -> bool:
        if not self.required_facts.issubset(state.facts):
            return False
        # Validate resource constraints: keys must exist AND values must be
        # non-None / non-empty so that a placeholder key without a real
        # value does not falsely satisfy the goal.
        for res_key in self.target_resources:
            if res_key not in state.resources:
                return False
            val = state.resources[res_key]
            if val is None or val == "":
                return False
        return True

    def distance(self, state: PlanState) -> int:
        missing_facts = len(self.required_facts - state.facts)
        missing_res = len(self.target_resources - set(state.resources.keys()))
        return missing_facts + missing_res

    def missing_facts(self, state: PlanState) -> Set[str]:
        return self.required_facts - state.facts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "goal_id": self.goal_id,
            "name": self.name,
            "description": self.description,
            "goal_type": self.goal_type.name,
            "required_facts": sorted(self.required_facts),
            "target_resources": sorted(self.target_resources),
            "priority": self.priority,
        }

    def __repr__(self) -> str:
        return f"Goal({self.name}, facts={len(self.required_facts)})"


# ════════════════════════════════════════════════════════════════════════════════
# PREDEFINED GOALS
# ════════════════════════════════════════════════════════════════════════════════

PREDEFINED_GOALS: Dict[str, AttackGoal] = {
    "data_exfiltration": AttackGoal(
        goal_id="goal_exfil",
        name="Data Exfiltration",
        description="Exfiltrate sensitive data from the target",
        goal_type=GoalType.DATA_EXFILTRATION,
        required_facts={"data_exfiltrated"},
        priority=1.0,
    ),
    "full_compromise": AttackGoal(
        goal_id="goal_full",
        name="Full Compromise",
        description="Achieve root/admin access with persistent backdoor",
        goal_type=GoalType.FULL_COMPROMISE,
        required_facts={"has_root_access", "has_persistent_access"},
        priority=1.0,
    ),
    "account_takeover": AttackGoal(
        goal_id="goal_ato",
        name="Account Takeover",
        description="Take over an administrator account",
        goal_type=GoalType.ACCOUNT_TAKEOVER,
        required_facts={"has_admin_access"},
        priority=0.9,
    ),
    "network_pivot": AttackGoal(
        goal_id="goal_pivot",
        name="Network Pivot",
        description="Gain access to internal network from external position",
        goal_type=GoalType.NETWORK_PIVOT,
        required_facts={"has_internal_access"},
        priority=0.8,
    ),
    "persistence": AttackGoal(
        goal_id="goal_persist",
        name="Persistence Establishment",
        description="Establish persistent backdoor access",
        goal_type=GoalType.PERSISTENCE_ESTABLISHMENT,
        required_facts={"has_persistent_access"},
        priority=0.85,
    ),
    "credential_harvest": AttackGoal(
        goal_id="goal_creds",
        name="Credential Harvest",
        description="Harvest credentials for further attacks",
        goal_type=GoalType.CREDENTIAL_HARVEST,
        required_facts={"has_admin_credentials"},
        priority=0.75,
    ),
}


# ════════════════════════════════════════════════════════════════════════════════
# ActionLibrary — 100+ predefined attack actions
# ════════════════════════════════════════════════════════════════════════════════


def _a(
    action_id: str,
    name: str,
    desc: str,
    cat: ActionCategory,
    req_facts: Set[str],
    add_facts: Set[str],
    mitre: str,
    time_min: int = 5,
    cost: float = 1.0,
    risk: float = 0.1,
    forbid: Optional[Set[str]] = None,
    rm_facts: Optional[Set[str]] = None,
    req_res: Optional[Set[str]] = None,
    add_res: Optional[Dict[str, str]] = None,
) -> AttackAction:
    """Shorthand factory for action definitions."""
    return AttackAction(
        action_id=action_id,
        name=name,
        description=desc,
        category=cat,
        preconditions=AttackPrecondition(
            required_facts=set(req_facts),
            forbidden_facts=set(forbid) if forbid else set(),
            required_resources=set(req_res) if req_res else set(),
        ),
        effects=AttackEffect(
            add_facts=set(add_facts),
            remove_facts=set(rm_facts) if rm_facts else set(),
            add_resources=dict(add_res) if add_res else {},
            cost=cost,
            detection_risk=risk,
        ),
        mitre_technique=mitre,
        estimated_time_minutes=time_min,
    )


class ActionLibrary:
    """Registry of 100+ predefined PDDL attack actions covering the full kill chain.

    Usage::

        lib = ActionLibrary()
        lib.load_defaults()
        recon_actions = lib.get_by_category(ActionCategory.RECON)
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._actions: Dict[str, AttackAction] = {}
        self._by_category: Dict[ActionCategory, List[AttackAction]] = defaultdict(list)
        self._fact_providers: Dict[str, List[AttackAction]] = defaultdict(list)

    # ── registration ──

    def register(self, action: AttackAction) -> None:
        with self._lock:
            self._actions[action.action_id] = action
            self._by_category[action.category].append(action)
            for fact in action.effects.add_facts:
                self._fact_providers[fact].append(action)

    def register_many(self, actions: List[AttackAction]) -> None:
        for a in actions:
            self.register(a)

    # ── queries ──

    def get(self, action_id: str) -> Optional[AttackAction]:
        with self._lock:
            return self._actions.get(action_id)

    def get_all(self) -> List[AttackAction]:
        with self._lock:
            return list(self._actions.values())

    def get_by_category(self, cat: ActionCategory) -> List[AttackAction]:
        with self._lock:
            return list(self._by_category.get(cat, []))

    def get_applicable(self, state: PlanState) -> List[AttackAction]:
        with self._lock:
            return [a for a in self._actions.values() if a.is_applicable(state)]

    def get_providers(self, fact: str) -> List[AttackAction]:
        """Return all actions whose effects add the given fact."""
        with self._lock:
            return list(self._fact_providers.get(fact, []))

    def count(self) -> int:
        with self._lock:
            return len(self._actions)

    def categories_summary(self) -> Dict[str, int]:
        with self._lock:
            return {c.name: len(acts) for c, acts in self._by_category.items()}

    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "total_actions": len(self._actions),
                "by_category": self.categories_summary(),
                "actions": [a.to_dict() for a in self._actions.values()],
            }

    # ── JSON loading ──

    def load_from_json(self, path: str) -> int:
        """Load actions from a JSON file.

        Returns the number of actions loaded.  Logs an error and returns 0
        if the file does not exist or contains malformed data instead of
        silently failing.
        """
        import os

        if not os.path.isfile(path):
            logger.error(
                "ActionLibrary: JSON file not found: %s", path,
            )
            return 0

        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except json.JSONDecodeError as exc:
            logger.error(
                "ActionLibrary: malformed JSON in %s: %s", path, exc,
            )
            return 0
        except OSError as exc:
            logger.error(
                "ActionLibrary: could not read %s: %s", path, exc,
            )
            return 0

        if not isinstance(data, list):
            logger.error(
                "ActionLibrary: expected a JSON array in %s, got %s",
                path, type(data).__name__,
            )
            return 0

        loaded = 0
        for idx, entry in enumerate(data):
            try:
                cat_name = entry.get("category", "RECON")
                category = ActionCategory[cat_name.upper()]
                action = _a(
                    action_id=entry.get("action_id", ""),
                    name=entry.get("name", ""),
                    desc=entry.get("description", ""),
                    cat=category,
                    req_facts=set(entry.get("required_facts", [])),
                    add_facts=set(entry.get("add_facts", [])),
                    mitre=entry.get("mitre_technique", ""),
                    time_min=int(entry.get("estimated_time_minutes", DEFAULT_TIME_MINUTES)),
                    cost=float(entry.get("cost", DEFAULT_ACTION_COST)),
                    risk=float(entry.get("detection_risk", DEFAULT_DETECTION_RISK)),
                    forbid=set(entry.get("forbidden_facts", [])) or None,
                    rm_facts=set(entry.get("remove_facts", [])) or None,
                    req_res=set(entry.get("required_resources", [])) or None,
                    add_res=entry.get("add_resources") or None,
                )
                self.register(action)
                loaded += 1
            except (KeyError, TypeError, ValueError) as exc:
                logger.warning(
                    "ActionLibrary: skipping malformed entry #%d in %s: %s",
                    idx, path, exc,
                )

        logger.info("ActionLibrary loaded %d actions from %s", loaded, path)
        return loaded

    # ── default library ──

    def load_defaults(self) -> None:
        """Load all 100+ predefined attack actions."""
        R = ActionCategory.RECON
        E = ActionCategory.ENUMERATION
        X = ActionCategory.EXPLOITATION
        P = ActionCategory.PRIVILEGE_ESCALATION
        L = ActionCategory.LATERAL_MOVEMENT
        S = ActionCategory.PERSISTENCE
        F = ActionCategory.EXFILTRATION
        C = ActionCategory.CLEANUP

        actions = [
            # ══════════════════════════════════════════════════════════════
            # RECON (20 actions)
            # ══════════════════════════════════════════════════════════════
            _a("recon_port_scan", "Port Scan", "TCP/UDP port scan of target",
               R, {"has_target_ip"}, {"port_map_available"},
               "T1046", 10, 1.0, 0.15),
            _a("recon_subdomain_enum", "Subdomain Enumeration",
               "Enumerate subdomains via DNS brute and certificate transparency",
               R, {"has_target_domain"}, {"subdomains_found"},
               "T1590.002", 15, 1.0, 0.05),
            _a("recon_tech_fingerprint", "Technology Fingerprint",
               "Identify web frameworks, servers, languages",
               R, {"has_target_url"}, {"tech_stack_known"},
               "T1592.004", 5, 0.5, 0.05),
            _a("recon_waf_detection", "WAF Detection",
               "Detect Web Application Firewall presence and type",
               R, {"has_target_url"}, {"waf_status_known"},
               "T1595.002", 3, 0.5, 0.10),
            _a("recon_whois_lookup", "WHOIS Lookup",
               "Retrieve domain registration information",
               R, {"has_target_domain"}, {"whois_info_available"},
               "T1596.002", 2, 0.3, 0.01),
            _a("recon_dns_zone_transfer", "DNS Zone Transfer",
               "Attempt AXFR zone transfer on name servers",
               R, {"has_target_domain"}, {"dns_records_found"},
               "T1590.002", 3, 0.5, 0.08),
            _a("recon_ssl_cert_analysis", "SSL Certificate Analysis",
               "Analyze SSL/TLS certificates for hostnames and weaknesses",
               R, {"has_target_url"}, {"ssl_info_available"},
               "T1590.001", 3, 0.3, 0.02),
            _a("recon_email_harvest", "Email Harvesting",
               "Harvest email addresses from public sources",
               R, {"has_target_domain"}, {"emails_harvested"},
               "T1589.002", 10, 0.8, 0.02),
            _a("recon_social_media_recon", "Social Media Recon",
               "Gather employee info from LinkedIn/Twitter/GitHub",
               R, {"has_target_domain"}, {"employee_info_found"},
               "T1593", 20, 1.0, 0.01),
            _a("recon_google_dorking", "Google Dorking",
               "Use search engine dorks to find exposed data",
               R, {"has_target_domain"}, {"google_dork_results_found"},
               "T1593.002", 10, 0.5, 0.01),
            _a("recon_shodan_search", "Shodan/Censys Search",
               "Query Shodan/Censys for exposed services",
               R, {"has_target_ip"}, {"shodan_results_found"},
               "T1596", 5, 0.5, 0.01),
            _a("recon_github_leak_search", "GitHub Leak Search",
               "Search GitHub for leaked credentials or secrets",
               R, {"has_target_domain"}, {"github_leaks_found"},
               "T1593.003", 15, 0.8, 0.01),
            _a("recon_js_analysis", "JavaScript Analysis",
               "Analyze JS files for endpoints, keys, secrets",
               R, {"has_target_url"}, {"js_endpoints_found", "js_secrets_checked"},
               "T1592.004", 10, 0.7, 0.03),
            _a("recon_service_version_detect", "Service Version Detection",
               "Detect exact versions of running services",
               R, {"port_map_available"}, {"service_versions_known"},
               "T1592.002", 8, 0.6, 0.12),
            _a("recon_os_fingerprint", "OS Fingerprint",
               "Determine target operating system via TCP/IP stack analysis",
               R, {"has_target_ip"}, {"os_type_known"},
               "T1592.004", 5, 0.5, 0.10),
            _a("recon_traceroute_map", "Network Traceroute",
               "Map network path and intermediate hops",
               R, {"has_target_ip"}, {"network_path_mapped"},
               "T1590", 5, 0.3, 0.05),
            _a("recon_cloud_enum", "Cloud Asset Enumeration",
               "Enumerate S3 buckets, Azure blobs, GCP storage",
               R, {"has_target_domain"}, {"cloud_assets_found"},
               "T1580", 10, 0.7, 0.03),
            _a("recon_wappalyzer_scan", "Wappalyzer Technology Scan",
               "Passive tech fingerprint via HTTP headers and HTML",
               R, {"has_target_url"}, {"cms_detected"},
               "T1592.004", 3, 0.3, 0.02),
            _a("recon_robots_sitemap", "Robots/Sitemap Parsing",
               "Parse robots.txt and sitemap.xml for hidden paths",
               R, {"has_target_url"}, {"sitemap_parsed"},
               "T1595.003", 2, 0.2, 0.02),
            _a("recon_virtual_host_enum", "Virtual Host Enumeration",
               "Discover virtual hosts on same IP",
               R, {"has_target_ip"}, {"virtual_hosts_found"},
               "T1590.005", 10, 0.6, 0.05),

            # ══════════════════════════════════════════════════════════════
            # ENUMERATION (20 actions)
            # ══════════════════════════════════════════════════════════════
            _a("enum_directory_bruteforce", "Directory Bruteforce",
               "Discover hidden directories and files via wordlist",
               E, {"has_target_url"}, {"hidden_paths_found"},
               "T1595.003", 15, 1.2, 0.20),
            _a("enum_parameter_discovery", "Parameter Discovery",
               "Discover hidden GET/POST parameters",
               E, {"has_target_url"}, {"parameters_found"},
               "T1595.003", 10, 0.8, 0.10),
            _a("enum_api_endpoint_enum", "API Endpoint Enumeration",
               "Discover REST/GraphQL API endpoints",
               E, {"has_target_url"}, {"api_endpoints_found"},
               "T1595.003", 12, 0.9, 0.10),
            _a("enum_user_enumeration", "User Enumeration",
               "Enumerate valid usernames via login/register/reset",
               E, {"has_login_url"}, {"valid_usernames_found"},
               "T1589.001", 10, 0.8, 0.25),
            _a("enum_vhost_enum", "VHost Enumeration",
               "Brute force virtual hostnames",
               E, {"has_target_ip"}, {"vhosts_found"},
               "T1595.003", 15, 0.8, 0.10),
            _a("enum_smb_shares", "SMB Share Enumeration",
               "List accessible SMB/CIFS shares",
               E, {"has_target_ip", "port_map_available"}, {"smb_shares_found"},
               "T1135", 5, 0.6, 0.20),
            _a("enum_snmp_walk", "SNMP Walk",
               "Extract SNMP MIB information",
               E, {"has_target_ip", "port_map_available"}, {"snmp_info_found"},
               "T1602.001", 5, 0.5, 0.15),
            _a("enum_ldap_enum", "LDAP Enumeration",
               "Query LDAP for users, groups, OUs",
               E, {"has_target_ip", "port_map_available"}, {"ldap_info_found"},
               "T1087.002", 10, 0.7, 0.20),
            _a("enum_dns_enum", "DNS Record Enumeration",
               "Enumerate all DNS record types (A, AAAA, MX, TXT, SRV)",
               E, {"has_target_domain"}, {"dns_records_enumerated"},
               "T1590.002", 5, 0.4, 0.03),
            _a("enum_wordpress_enum", "WordPress Enumeration",
               "Enumerate WP users, plugins, themes, versions",
               E, {"has_target_url", "cms_detected"}, {"wp_details_found"},
               "T1595.002", 10, 0.7, 0.15),
            _a("enum_graphql_introspection", "GraphQL Introspection",
               "Dump full GraphQL schema via introspection",
               E, {"api_endpoints_found"}, {"graphql_schema_found"},
               "T1595.003", 3, 0.4, 0.10),
            _a("enum_swagger_discovery", "Swagger/OpenAPI Discovery",
               "Find and parse Swagger/OpenAPI docs",
               E, {"has_target_url"}, {"api_docs_found"},
               "T1595.003", 3, 0.3, 0.05),
            _a("enum_s3_bucket_enum", "S3 Bucket Enumeration",
               "Check for publicly accessible S3 buckets",
               E, {"cloud_assets_found"}, {"s3_buckets_accessible"},
               "T1530", 8, 0.6, 0.05),
            _a("enum_cors_check", "CORS Misconfiguration Check",
               "Test CORS headers for permissive config",
               E, {"has_target_url"}, {"cors_status_known"},
               "T1189", 3, 0.3, 0.05),
            _a("enum_header_analysis", "HTTP Header Analysis",
               "Analyze security headers (CSP, HSTS, X-Frame-Options)",
               E, {"has_target_url"}, {"security_headers_analyzed"},
               "T1592.004", 2, 0.2, 0.02),
            _a("enum_cookie_analysis", "Cookie Security Analysis",
               "Check cookie flags (Secure, HttpOnly, SameSite)",
               E, {"has_target_url"}, {"cookie_security_known"},
               "T1539", 2, 0.2, 0.02),
            _a("enum_error_page_analysis", "Error Page Analysis",
               "Trigger errors to extract stack traces and version info",
               E, {"has_target_url"}, {"error_info_found"},
               "T1592.004", 5, 0.5, 0.10),
            _a("enum_login_page_discovery", "Login Page Discovery",
               "Find login and admin panel pages",
               E, {"has_target_url"}, {"has_login_url"},
               "T1595.003", 5, 0.4, 0.05),
            _a("enum_form_analysis", "Form Analysis",
               "Analyze HTML forms for hidden fields and CSRF tokens",
               E, {"has_target_url"}, {"forms_analyzed"},
               "T1595.003", 5, 0.4, 0.05),
            _a("enum_websocket_discovery", "WebSocket Discovery",
               "Discover and enumerate WebSocket endpoints",
               E, {"has_target_url"}, {"websocket_endpoints_found"},
               "T1595.003", 5, 0.4, 0.05),

            # ══════════════════════════════════════════════════════════════
            # EXPLOITATION (30 actions)
            # ══════════════════════════════════════════════════════════════
            _a("exploit_sqli", "SQL Injection Exploitation",
               "Exploit SQL injection for data access",
               X, {"found_sqli_endpoint"}, {"has_db_access", "has_db_credentials"},
               "T1190", 15, 2.0, 0.35,
               add_res={"db_credentials": "extracted_via_sqli"}),
            _a("exploit_xss_stored", "Stored XSS Exploitation",
               "Plant stored XSS payload for session stealing",
               X, {"found_xss_endpoint"}, {"can_steal_sessions"},
               "T1189", 10, 1.5, 0.25),
            _a("exploit_ssrf", "SSRF Exploitation",
               "Exploit SSRF to reach internal services",
               X, {"found_ssrf_endpoint"}, {"can_reach_internal_network"},
               "T1190", 10, 2.0, 0.30),
            _a("exploit_rce", "Remote Code Execution",
               "Exploit RCE vulnerability for shell access",
               X, {"found_rce_endpoint"}, {"has_shell_access"},
               "T1059", 10, 3.0, 0.50),
            _a("exploit_auth_bypass", "Authentication Bypass",
               "Bypass authentication mechanism",
               X, {"found_auth_weakness"}, {"has_authenticated_access"},
               "T1078", 10, 2.0, 0.30),
            _a("exploit_idor", "IDOR Exploitation",
               "Access other users data via IDOR",
               X, {"found_idor_endpoint", "has_authenticated_access"},
               {"can_access_other_users_data"},
               "T1078", 8, 1.5, 0.20),
            _a("exploit_file_upload", "Malicious File Upload",
               "Upload webshell via insecure file upload",
               X, {"found_upload_endpoint"}, {"can_upload_webshell"},
               "T1190", 10, 2.5, 0.40),
            _a("exploit_jwt_forge", "JWT Token Forgery",
               "Forge JWT token with admin privileges",
               X, {"found_jwt_weakness"}, {"has_admin_jwt"},
               "T1134.001", 8, 2.0, 0.20,
               add_res={"admin_jwt": "forged_jwt_token"}),
            _a("exploit_deserialization", "Deserialization Attack",
               "Exploit insecure deserialization for code execution",
               X, {"found_deser_endpoint"}, {"has_shell_access"},
               "T1059", 12, 3.0, 0.45),
            _a("exploit_lfi", "Local File Inclusion",
               "Read arbitrary files via LFI",
               X, {"found_lfi_endpoint"}, {"can_read_local_files"},
               "T1005", 8, 1.5, 0.25),
            _a("exploit_rfi", "Remote File Inclusion",
               "Include remote malicious file",
               X, {"found_rfi_endpoint"}, {"has_shell_access"},
               "T1059", 10, 2.5, 0.40),
            _a("exploit_xxe", "XXE Injection",
               "Exploit XML External Entity for file read or SSRF",
               X, {"found_xxe_endpoint"}, {"can_read_local_files", "can_reach_internal_network"},
               "T1190", 10, 2.0, 0.30),
            _a("exploit_ssti", "Server Side Template Injection",
               "Exploit SSTI for remote code execution",
               X, {"found_ssti_endpoint"}, {"has_shell_access"},
               "T1059", 10, 2.5, 0.40),
            _a("exploit_command_injection", "OS Command Injection",
               "Inject OS commands through vulnerable parameter",
               X, {"found_cmdi_endpoint"}, {"has_shell_access"},
               "T1059", 8, 2.5, 0.40),
            _a("exploit_csrf", "CSRF Exploitation",
               "Forge cross-site requests to perform privileged actions",
               X, {"found_csrf_weakness", "can_steal_sessions"},
               {"can_perform_actions_as_user"},
               "T1189", 8, 1.5, 0.15),
            _a("exploit_open_redirect", "Open Redirect",
               "Exploit open redirect for phishing",
               X, {"found_open_redirect"}, {"can_phish_users"},
               "T1566.002", 5, 0.8, 0.10),
            _a("exploit_cors_hijack", "CORS Hijacking",
               "Exploit permissive CORS to steal data cross-origin",
               X, {"cors_status_known", "found_cors_misconfig"},
               {"can_steal_data_cross_origin"},
               "T1189", 8, 1.5, 0.20),
            _a("exploit_websocket_hijack", "WebSocket Hijacking",
               "Hijack WebSocket connection for data theft",
               X, {"websocket_endpoints_found", "found_ws_weakness"},
               {"can_hijack_websocket"},
               "T1557", 10, 2.0, 0.25),
            _a("exploit_prototype_pollution", "Prototype Pollution",
               "Exploit JS prototype pollution for code execution",
               X, {"found_proto_pollution"}, {"can_execute_client_code"},
               "T1059.007", 10, 2.0, 0.20),
            _a("exploit_nosqli", "NoSQL Injection",
               "Exploit NoSQL injection for data access",
               X, {"found_nosqli_endpoint"}, {"has_db_access"},
               "T1190", 10, 2.0, 0.30),
            _a("exploit_graphql_injection", "GraphQL Injection",
               "Exploit GraphQL for unauthorized data access",
               X, {"graphql_schema_found", "found_graphql_weakness"},
               {"has_db_access"},
               "T1190", 10, 2.0, 0.25),
            _a("exploit_race_condition", "Race Condition",
               "Exploit TOCTOU race condition",
               X, {"found_race_condition"}, {"can_bypass_checks"},
               "T1068", 15, 2.5, 0.20),
            _a("exploit_session_fixation", "Session Fixation",
               "Fix session ID to hijack user session",
               X, {"found_session_weakness"}, {"can_steal_sessions"},
               "T1563", 8, 1.5, 0.20),
            _a("exploit_password_spray", "Password Spraying",
               "Spray common passwords against known users",
               X, {"valid_usernames_found", "has_login_url"},
               {"has_authenticated_access"},
               "T1110.003", 20, 2.0, 0.40,
               add_res={"user_credentials": "sprayed_password"}),
            _a("exploit_credential_stuffing", "Credential Stuffing",
               "Use leaked credentials to authenticate",
               X, {"valid_usernames_found", "has_login_url", "github_leaks_found"},
               {"has_authenticated_access"},
               "T1110.004", 15, 1.5, 0.35,
               add_res={"user_credentials": "stuffed_credentials"}),
            _a("exploit_brute_force_login", "Brute Force Login",
               "Brute force login credentials",
               X, {"has_login_url"}, {"has_authenticated_access"},
               "T1110.001", 30, 3.0, 0.60,
               forbid={"account_lockout_enabled"}),
            _a("exploit_default_creds", "Default Credentials",
               "Try default/common credentials on services",
               X, {"service_versions_known"}, {"has_authenticated_access"},
               "T1078.001", 5, 0.5, 0.15,
               add_res={"default_credentials": "factory_default"}),
            _a("exploit_s3_public_access", "S3 Public Access Exploitation",
               "Access publicly readable S3 buckets",
               X, {"s3_buckets_accessible"}, {"data_exfiltrated"},
               "T1530", 5, 1.0, 0.05),
            _a("exploit_wordpress_vuln", "WordPress Vulnerability Exploit",
               "Exploit known WP plugin/theme vulnerability",
               X, {"wp_details_found", "found_wp_vuln"}, {"has_shell_access"},
               "T1190", 10, 2.0, 0.35),
            _a("exploit_cve_known", "Known CVE Exploitation",
               "Exploit a known CVE in identified service",
               X, {"service_versions_known", "found_known_cve"},
               {"has_shell_access"},
               "T1190", 10, 2.5, 0.40),

            # ══════════════════════════════════════════════════════════════
            # PRIVILEGE ESCALATION (15 actions)
            # ══════════════════════════════════════════════════════════════
            _a("privesc_to_admin", "Escalate to Admin",
               "Escalate privileges to admin via application logic flaw",
               P, {"has_authenticated_access", "found_privesc_path"},
               {"has_admin_access"},
               "T1068", 10, 2.0, 0.35),
            _a("privesc_via_sqli", "Escalate via SQLi",
               "Extract admin credentials from database",
               P, {"has_db_access"}, {"has_admin_credentials"},
               "T1078", 10, 2.0, 0.30,
               add_res={"admin_credentials": "extracted_from_db"}),
            _a("privesc_kernel_exploit", "Kernel Exploit",
               "Exploit kernel vulnerability for root",
               P, {"has_shell_access", "kernel_version_known"},
               {"has_root_access"},
               "T1068", 15, 3.0, 0.50),
            _a("privesc_suid_abuse", "SUID Binary Abuse",
               "Abuse misconfigured SUID binaries",
               P, {"has_shell_access"}, {"has_root_access"},
               "T1548.001", 10, 2.0, 0.25),
            _a("privesc_sudo_misconfig", "Sudo Misconfiguration",
               "Exploit sudo misconfiguration for root",
               P, {"has_shell_access"}, {"has_root_access"},
               "T1548.003", 8, 1.5, 0.20),
            _a("privesc_cron_exploit", "Cron Job Exploitation",
               "Exploit writable cron jobs for root",
               P, {"has_shell_access"}, {"has_root_access"},
               "T1053.003", 10, 2.0, 0.25),
            _a("privesc_docker_escape", "Docker Container Escape",
               "Escape Docker container to host",
               P, {"has_shell_access", "inside_container"},
               {"has_root_access", "escaped_container"},
               "T1611", 15, 3.0, 0.45),
            _a("privesc_path_hijack", "PATH Hijacking",
               "Hijack PATH to escalate privileges",
               P, {"has_shell_access"}, {"has_root_access"},
               "T1574.007", 8, 1.5, 0.20),
            _a("privesc_writable_service", "Writable Service Exploit",
               "Modify writable service binary or config",
               P, {"has_shell_access"}, {"has_root_access"},
               "T1574.010", 10, 2.0, 0.30),
            _a("privesc_token_impersonation", "Token Impersonation",
               "Impersonate privileged token on Windows",
               P, {"has_shell_access", "os_type_known"},
               {"has_admin_access"},
               "T1134.001", 10, 2.5, 0.35),
            _a("privesc_dll_hijack", "DLL Hijacking",
               "Plant malicious DLL for privilege escalation",
               P, {"has_shell_access", "os_type_known"},
               {"has_admin_access"},
               "T1574.001", 12, 2.5, 0.35),
            _a("privesc_jwt_to_admin", "JWT Privilege Escalation",
               "Use forged admin JWT for admin access",
               P, {"has_admin_jwt"}, {"has_admin_access"},
               "T1134", 3, 1.0, 0.15),
            _a("privesc_password_reuse", "Password Reuse Escalation",
               "Reuse found credentials for higher-priv accounts",
               P, {"has_db_credentials"}, {"has_admin_credentials"},
               "T1078", 5, 1.0, 0.15,
               add_res={"admin_credentials": "reused_from_db"}),
            _a("privesc_admin_creds_login", "Admin Credential Login",
               "Use found admin credentials to authenticate",
               P, {"has_admin_credentials", "has_login_url"},
               {"has_admin_access"},
               "T1078", 2, 0.5, 0.10),
            _a("privesc_lfi_to_rce", "LFI to RCE Escalation",
               "Chain LFI with log poisoning for code execution",
               P, {"can_read_local_files"}, {"has_shell_access"},
               "T1059", 15, 2.5, 0.40),

            # ══════════════════════════════════════════════════════════════
            # LATERAL MOVEMENT (12 actions)
            # ══════════════════════════════════════════════════════════════
            _a("lateral_pivot_ssrf", "SSRF Pivot",
               "Pivot to internal network via SSRF",
               L, {"can_reach_internal_network"},
               {"has_internal_access"},
               "T1090", 10, 2.0, 0.30),
            _a("lateral_pass_the_hash", "Pass the Hash",
               "Authenticate to another host using NTLM hash",
               L, {"has_ntlm_hash"}, {"has_access_to_other_host"},
               "T1550.002", 8, 2.0, 0.40),
            _a("lateral_ssh_pivot", "SSH Pivot",
               "SSH to another host with stolen credentials",
               L, {"has_ssh_credentials"}, {"has_access_to_other_host"},
               "T1021.004", 5, 1.0, 0.20),
            _a("lateral_rdp_pivot", "RDP Pivot",
               "RDP to another host with stolen credentials",
               L, {"has_admin_credentials", "has_internal_access"},
               {"has_access_to_other_host"},
               "T1021.001", 5, 1.5, 0.30),
            _a("lateral_wmi_exec", "WMI Execution",
               "Execute commands on remote host via WMI",
               L, {"has_admin_credentials", "has_internal_access"},
               {"has_access_to_other_host"},
               "T1047", 5, 1.5, 0.35),
            _a("lateral_psexec", "PsExec Lateral Move",
               "Use PsExec for remote execution",
               L, {"has_admin_credentials", "has_internal_access"},
               {"has_access_to_other_host"},
               "T1569.002", 5, 1.5, 0.40),
            _a("lateral_smb_relay", "SMB Relay Attack",
               "Relay NTLM authentication to another host",
               L, {"has_internal_access", "smb_shares_found"},
               {"has_access_to_other_host", "has_ntlm_hash"},
               "T1557.001", 10, 2.5, 0.45),
            _a("lateral_kerberoasting", "Kerberoasting",
               "Extract service tickets for offline cracking",
               L, {"has_authenticated_access", "ldap_info_found"},
               {"has_service_ticket_hashes"},
               "T1558.003", 10, 2.0, 0.30),
            _a("lateral_golden_ticket", "Golden Ticket",
               "Forge Kerberos TGT for domain-wide access",
               L, {"has_root_access", "has_krbtgt_hash"},
               {"has_domain_admin_access"},
               "T1558.001", 15, 3.0, 0.50),
            _a("lateral_dcsync", "DCSync Attack",
               "Replicate AD credentials via DCSync",
               L, {"has_domain_admin_access"},
               {"has_all_domain_hashes"},
               "T1003.006", 10, 3.0, 0.50),
            _a("lateral_port_forward", "Port Forwarding",
               "Set up port forwarding for pivoting",
               L, {"has_shell_access"}, {"port_forwarding_established"},
               "T1090.001", 5, 1.0, 0.15),
            _a("lateral_vpn_hijack", "VPN Hijack",
               "Hijack VPN session or credentials for lateral access",
               L, {"has_admin_access", "has_internal_access"},
               {"has_vpn_access"},
               "T1133", 10, 2.0, 0.30),

            # ══════════════════════════════════════════════════════════════
            # PERSISTENCE (10 actions)
            # ══════════════════════════════════════════════════════════════
            _a("persist_webshell", "Install Webshell",
               "Upload and activate a web shell for persistent access",
               S, {"can_upload_webshell"}, {"has_persistent_access"},
               "T1505.003", 5, 1.5, 0.40),
            _a("persist_backdoor_account", "Create Backdoor Account",
               "Create hidden admin account for persistent access",
               S, {"has_admin_access"}, {"has_persistent_access"},
               "T1136.001", 5, 1.5, 0.45),
            _a("persist_cron_job", "Install Cron Job",
               "Install persistent cron/scheduled task",
               S, {"has_root_access"}, {"has_persistent_access"},
               "T1053.003", 5, 1.0, 0.30),
            _a("persist_ssh_key", "Plant SSH Key",
               "Add SSH public key to authorized_keys",
               S, {"has_shell_access"}, {"has_persistent_access", "has_ssh_credentials"},
               "T1098.004", 3, 0.8, 0.20,
               add_res={"ssh_credentials": "planted_key"}),
            _a("persist_startup_script", "Startup Script",
               "Install script in startup/init.d for persistence",
               S, {"has_root_access"}, {"has_persistent_access"},
               "T1037", 5, 1.0, 0.30),
            _a("persist_registry_run_key", "Registry Run Key",
               "Add Windows registry run key for persistence",
               S, {"has_admin_access", "os_type_known"},
               {"has_persistent_access"},
               "T1547.001", 3, 1.0, 0.35),
            _a("persist_systemd_service", "Systemd Service",
               "Create malicious systemd service",
               S, {"has_root_access"}, {"has_persistent_access"},
               "T1543.002", 5, 1.0, 0.30),
            _a("persist_web_config_backdoor", "Web Config Backdoor",
               "Modify web server config for persistent access",
               S, {"has_admin_access"}, {"has_persistent_access"},
               "T1505.003", 5, 1.0, 0.35),
            _a("persist_git_hook", "Git Hook Persistence",
               "Install malicious Git hook for persistence",
               S, {"has_shell_access"}, {"has_persistent_access"},
               "T1546", 5, 0.8, 0.15),
            _a("persist_docker_image_backdoor", "Docker Image Backdoor",
               "Backdoor Docker image for container persistence",
               S, {"has_root_access", "escaped_container"},
               {"has_persistent_access"},
               "T1525", 10, 2.0, 0.35),

            # ══════════════════════════════════════════════════════════════
            # EXFILTRATION (10 actions)
            # ══════════════════════════════════════════════════════════════
            _a("exfil_dump_database", "Database Dump",
               "Dump entire database contents",
               F, {"has_db_access"}, {"data_exfiltrated"},
               "T1005", 15, 2.0, 0.40),
            _a("exfil_download_files", "Download Sensitive Files",
               "Download sensitive files from compromised host",
               F, {"has_shell_access"}, {"data_exfiltrated"},
               "T1005", 10, 1.5, 0.35),
            _a("exfil_steal_secrets", "Steal Application Secrets",
               "Extract API keys, tokens, and secrets from config files",
               F, {"can_read_local_files"}, {"data_exfiltrated"},
               "T1552.001", 8, 1.5, 0.25,
               add_res={"stolen_secrets": "extracted_from_config"}),
            _a("exfil_steal_sessions", "Session Hijacking",
               "Steal active user sessions via XSS or cookie theft",
               F, {"can_steal_sessions"}, {"has_authenticated_access"},
               "T1539", 5, 1.0, 0.25,
               add_res={"stolen_sessions": "hijacked_cookies"}),
            _a("exfil_dns_tunnel", "DNS Tunneling Exfiltration",
               "Exfiltrate data via DNS queries",
               F, {"has_shell_access"}, {"data_exfiltrated"},
               "T1048.001", 20, 2.5, 0.15),
            _a("exfil_http_exfil", "HTTP Exfiltration",
               "Exfiltrate data via HTTP/HTTPS requests",
               F, {"has_shell_access"}, {"data_exfiltrated"},
               "T1048.002", 10, 1.5, 0.30),
            _a("exfil_cloud_storage", "Cloud Storage Exfiltration",
               "Exfiltrate data to attacker-controlled cloud storage",
               F, {"has_shell_access"}, {"data_exfiltrated"},
               "T1567.002", 10, 1.5, 0.20),
            _a("exfil_email_exfil", "Email Exfiltration",
               "Exfiltrate data via email",
               F, {"has_shell_access"}, {"data_exfiltrated"},
               "T1048.003", 10, 1.5, 0.25),
            _a("exfil_clipboard_steal", "Clipboard Data Theft",
               "Steal clipboard contents from compromised host",
               F, {"has_shell_access"}, {"clipboard_data_stolen"},
               "T1115", 3, 0.5, 0.10),
            _a("exfil_screenshot_capture", "Screenshot Capture",
               "Capture screenshots from compromised host",
               F, {"has_shell_access"}, {"screenshots_captured"},
               "T1113", 3, 0.5, 0.15),

            # ══════════════════════════════════════════════════════════════
            # CLEANUP (8 actions)
            # ══════════════════════════════════════════════════════════════
            _a("cleanup_clear_logs", "Clear System Logs",
               "Clear system/application logs to hide activity",
               C, {"has_root_access"}, set(),
               "T1070.002", 5, 1.0, 0.10,
               rm_facts={"evidence_exists"}),
            _a("cleanup_remove_artifacts", "Remove Artifacts",
               "Remove tools, scripts, and other artifacts",
               C, {"has_shell_access"}, set(),
               "T1070.004", 5, 0.8, 0.05,
               rm_facts={"artifacts_exist"}),
            _a("cleanup_clear_bash_history", "Clear Bash History",
               "Clear shell command history",
               C, {"has_shell_access"}, set(),
               "T1070.003", 2, 0.3, 0.05,
               rm_facts={"shell_history_exists"}),
            _a("cleanup_timestomp", "Timestomp Files",
               "Modify file timestamps to avoid detection",
               C, {"has_shell_access"}, {"timestamps_modified"},
               "T1070.006", 5, 0.8, 0.10),
            _a("cleanup_clear_event_log", "Clear Windows Event Log",
               "Clear Windows event logs",
               C, {"has_admin_access", "os_type_known"}, set(),
               "T1070.001", 3, 0.5, 0.10,
               rm_facts={"evidence_exists"}),
            _a("cleanup_rotate_ip", "Rotate Attack IP",
               "Switch to different source IP/proxy",
               C, set(), {"ip_rotated"},
               "T1090.003", 2, 0.3, 0.01),
            _a("cleanup_defang_webshell", "Remove Webshell",
               "Remove installed webshell after operation",
               C, {"has_persistent_access"}, set(),
               "T1070.004", 3, 0.5, 0.05,
               rm_facts={"artifacts_exist"}),
            _a("cleanup_restore_configs", "Restore Configurations",
               "Restore modified configurations to original state",
               C, {"has_admin_access"}, {"configs_restored"},
               "T1070", 5, 0.8, 0.05),

            # ══════════════════════════════════════════════════════════════
            # VULNERABILITY DISCOVERY (bridges recon → exploitation)
            # ══════════════════════════════════════════════════════════════
            _a("vuln_sqli_scan", "SQL Injection Scanner",
               "Scan parameters for SQL injection vulnerabilities",
               E, {"parameters_found"}, {"found_sqli_endpoint"},
               "T1190", 15, 1.5, 0.25),
            _a("vuln_xss_scan", "XSS Scanner",
               "Scan inputs for Cross-Site Scripting",
               E, {"parameters_found"}, {"found_xss_endpoint"},
               "T1189", 15, 1.5, 0.20),
            _a("vuln_ssrf_scan", "SSRF Scanner",
               "Test parameters for Server-Side Request Forgery",
               E, {"parameters_found"}, {"found_ssrf_endpoint"},
               "T1190", 10, 1.5, 0.20),
            _a("vuln_rce_scan", "RCE Scanner",
               "Test for remote code execution vulnerabilities",
               E, {"parameters_found"}, {"found_rce_endpoint"},
               "T1059", 15, 2.0, 0.30),
            _a("vuln_auth_weakness_scan", "Auth Weakness Scanner",
               "Test for authentication bypasses and weaknesses",
               E, {"has_login_url"}, {"found_auth_weakness"},
               "T1078", 10, 1.0, 0.20),
            _a("vuln_idor_scan", "IDOR Scanner",
               "Test for Insecure Direct Object References",
               E, {"has_authenticated_access", "api_endpoints_found"},
               {"found_idor_endpoint"},
               "T1078", 10, 1.0, 0.15),
            _a("vuln_upload_scan", "File Upload Scanner",
               "Test file upload for bypass techniques",
               E, {"has_target_url", "forms_analyzed"}, {"found_upload_endpoint"},
               "T1190", 10, 1.0, 0.20),
            _a("vuln_jwt_weakness_scan", "JWT Weakness Scanner",
               "Test JWT implementation for weaknesses (none alg, weak key)",
               E, {"has_authenticated_access"}, {"found_jwt_weakness"},
               "T1134", 8, 1.0, 0.10),
            _a("vuln_deser_scan", "Deserialization Scanner",
               "Test for insecure deserialization",
               E, {"parameters_found"}, {"found_deser_endpoint"},
               "T1059", 12, 1.5, 0.25),
            _a("vuln_lfi_scan", "LFI Scanner",
               "Test for Local File Inclusion",
               E, {"parameters_found"}, {"found_lfi_endpoint"},
               "T1005", 10, 1.0, 0.20),
            _a("vuln_ssti_scan", "SSTI Scanner",
               "Test for Server-Side Template Injection",
               E, {"parameters_found"}, {"found_ssti_endpoint"},
               "T1059", 10, 1.5, 0.25),
            _a("vuln_cmdi_scan", "Command Injection Scanner",
               "Test for OS command injection",
               E, {"parameters_found"}, {"found_cmdi_endpoint"},
               "T1059", 10, 1.5, 0.25),
            _a("vuln_csrf_scan", "CSRF Scanner",
               "Test for Cross-Site Request Forgery",
               E, {"forms_analyzed"}, {"found_csrf_weakness"},
               "T1189", 8, 0.8, 0.10),
            _a("vuln_open_redirect_scan", "Open Redirect Scanner",
               "Test for open redirect vulnerabilities",
               E, {"parameters_found"}, {"found_open_redirect"},
               "T1566.002", 8, 0.8, 0.10),
            _a("vuln_xxe_scan", "XXE Scanner",
               "Test for XML External Entity injection",
               E, {"has_target_url"}, {"found_xxe_endpoint"},
               "T1190", 10, 1.5, 0.20),
            _a("vuln_nosqli_scan", "NoSQL Injection Scanner",
               "Test for NoSQL injection vulnerabilities",
               E, {"parameters_found"}, {"found_nosqli_endpoint"},
               "T1190", 10, 1.5, 0.20),
            _a("vuln_cors_scan", "CORS Misconfiguration Scanner",
               "Test for exploitable CORS misconfigurations",
               E, {"cors_status_known"}, {"found_cors_misconfig"},
               "T1189", 5, 0.5, 0.05),
            _a("vuln_ws_scan", "WebSocket Vulnerability Scanner",
               "Test WebSocket endpoints for vulnerabilities",
               E, {"websocket_endpoints_found"}, {"found_ws_weakness"},
               "T1557", 10, 1.0, 0.15),
            _a("vuln_privesc_scan", "Privilege Escalation Path Scanner",
               "Scan for privilege escalation vectors",
               E, {"has_authenticated_access"}, {"found_privesc_path"},
               "T1068", 10, 1.0, 0.15),
            _a("vuln_kernel_version_check", "Kernel Version Check",
               "Check kernel version for known exploits",
               E, {"has_shell_access"}, {"kernel_version_known"},
               "T1082", 2, 0.3, 0.05),
            _a("vuln_wp_vuln_scan", "WordPress Vulnerability Scanner",
               "Scan WordPress for known vulnerabilities",
               E, {"wp_details_found"}, {"found_wp_vuln"},
               "T1190", 10, 1.0, 0.15),
            _a("vuln_cve_lookup", "CVE Lookup",
               "Look up known CVEs for identified service versions",
               E, {"service_versions_known"}, {"found_known_cve"},
               "T1190", 5, 0.5, 0.02),
            _a("vuln_graphql_vuln_scan", "GraphQL Vulnerability Scanner",
               "Scan GraphQL for injection and authorization flaws",
               E, {"graphql_schema_found"}, {"found_graphql_weakness"},
               "T1190", 10, 1.0, 0.15),
            _a("vuln_race_condition_scan", "Race Condition Scanner",
               "Test for TOCTOU and race condition vulnerabilities",
               E, {"api_endpoints_found"}, {"found_race_condition"},
               "T1068", 15, 1.5, 0.15),
            _a("vuln_session_weakness_scan", "Session Management Scanner",
               "Test for session fixation and management weaknesses",
               E, {"has_target_url"}, {"found_session_weakness"},
               "T1563", 8, 0.8, 0.10),
            _a("vuln_proto_pollution_scan", "Prototype Pollution Scanner",
               "Scan for JavaScript prototype pollution",
               E, {"js_endpoints_found"}, {"found_proto_pollution"},
               "T1059.007", 10, 1.0, 0.10),
            _a("vuln_rfi_scan", "RFI Scanner",
               "Test for Remote File Inclusion",
               E, {"parameters_found"}, {"found_rfi_endpoint"},
               "T1059", 10, 1.0, 0.20),
        ]

        self.register_many(actions)
        logger.info("ActionLibrary loaded %d default actions", len(actions))


# ════════════════════════════════════════════════════════════════════════════════
# AttackPlan
# ════════════════════════════════════════════════════════════════════════════════


@dataclass
class AttackPlan:
    """An ordered sequence of attack actions forming a complete plan.

    Tracks total cost, time, detection risk, and MITRE technique coverage.
    """

    plan_id: str = ""
    actions: List[AttackAction] = field(default_factory=list)
    initial_state: PlanState = field(default_factory=PlanState)
    final_state: PlanState = field(default_factory=PlanState)
    goal: Optional[AttackGoal] = None
    status: PlanStatus = PlanStatus.PENDING
    created_at: float = 0.0
    search_nodes_expanded: int = 0
    search_time_seconds: float = 0.0

    def __post_init__(self) -> None:
        if not self.plan_id:
            self.plan_id = str(uuid.uuid4())[:12]
        if not self.created_at:
            self.created_at = time.time()

    # ── computed metrics ──

    @property
    def total_cost(self) -> float:
        return sum(a.effects.cost for a in self.actions)

    @property
    def total_time_minutes(self) -> int:
        return sum(a.estimated_time_minutes for a in self.actions)

    @property
    def max_detection_risk(self) -> float:
        if not self.actions:
            return 0.0
        return max(a.effects.detection_risk for a in self.actions)

    @property
    def cumulative_detection_risk(self) -> float:
        """Probability of being detected at any step: 1 - product(1 - r_i)."""
        if not self.actions:
            return 0.0
        prob_undetected = 1.0
        for a in self.actions:
            prob_undetected *= (1.0 - a.effects.detection_risk)
        return 1.0 - prob_undetected

    @property
    def mitre_techniques(self) -> List[str]:
        seen: Set[str] = set()
        result: List[str] = []
        for a in self.actions:
            if a.mitre_technique and a.mitre_technique not in seen:
                seen.add(a.mitre_technique)
                result.append(a.mitre_technique)
        return result

    @property
    def step_count(self) -> int:
        return len(self.actions)

    @property
    def is_complete(self) -> bool:
        if self.goal is None:
            return len(self.actions) > 0
        return self.goal.is_achieved(self.final_state)

    # ── simulation ──

    def simulate(self) -> PlanState:
        """Re-simulate the plan from initial_state, return final state."""
        state = self.initial_state.copy()
        for action in self.actions:
            if not action.is_applicable(state):
                raise ValueError(
                    f"Action '{action.name}' not applicable at step — "
                    f"missing: {action.preconditions.missing_facts(state)}"
                )
            state = action.apply(state)
        return state

    def validate(self) -> Tuple[bool, str]:
        """Validate that the plan is executable end-to-end."""
        try:
            final = self.simulate()
            if self.goal and not self.goal.is_achieved(final):
                return False, "Plan does not achieve goal"
            return True, "Plan is valid"
        except ValueError as exc:
            return False, str(exc)

    # ── serialization ──

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "status": self.status.name,
            "step_count": self.step_count,
            "total_cost": round(self.total_cost, 2),
            "total_time_minutes": self.total_time_minutes,
            "max_detection_risk": round(self.max_detection_risk, 3),
            "cumulative_detection_risk": round(self.cumulative_detection_risk, 3),
            "mitre_techniques": self.mitre_techniques,
            "initial_state": self.initial_state.to_dict(),
            "final_state": self.final_state.to_dict(),
            "goal": self.goal.to_dict() if self.goal else None,
            "actions": [a.to_dict() for a in self.actions],
            "search_nodes_expanded": self.search_nodes_expanded,
            "search_time_seconds": round(self.search_time_seconds, 4),
            "created_at": self.created_at,
        }

    def to_markdown(self) -> str:
        """Render plan as a Markdown report."""
        lines: List[str] = []
        lines.append(f"# Attack Plan: {self.plan_id}")
        lines.append("")
        if self.goal:
            lines.append(f"**Goal:** {self.goal.name} — {self.goal.description}")
        lines.append(f"**Status:** {self.status.name}")
        lines.append(f"**Steps:** {self.step_count}")
        lines.append(f"**Total Cost:** {self.total_cost:.2f}")
        lines.append(f"**Estimated Time:** {self.total_time_minutes} min")
        lines.append(
            f"**Detection Risk:** {self.cumulative_detection_risk:.1%} cumulative"
        )
        lines.append(f"**MITRE Techniques:** {', '.join(self.mitre_techniques)}")
        lines.append("")
        lines.append("## Steps")
        lines.append("")
        for i, action in enumerate(self.actions, 1):
            lines.append(
                f"### Step {i}: {action.name} "
                f"[{action.category.name}] ({action.mitre_technique})"
            )
            lines.append(f"  {action.description}")
            lines.append(
                f"  - Cost: {action.effects.cost:.1f} | "
                f"Time: {action.estimated_time_minutes}min | "
                f"Risk: {action.effects.detection_risk:.0%}"
            )
            if action.effects.add_facts:
                lines.append(
                    f"  - Gains: {', '.join(sorted(action.effects.add_facts))}"
                )
            lines.append("")
        lines.append("## Final State Facts")
        lines.append("")
        for fact in sorted(self.final_state.facts):
            lines.append(f"- {fact}")
        return "\n".join(lines)

    def to_ascii_tree(self) -> str:
        """Render plan as an ASCII tree diagram."""
        lines: List[str] = []
        width = 72
        lines.append("+" + "-" * (width - 2) + "+")
        title = f"ATTACK PLAN: {self.plan_id}"
        lines.append("|" + title.center(width - 2) + "|")
        if self.goal:
            g = f"Goal: {self.goal.name}"
            lines.append("|" + g.center(width - 2) + "|")
        lines.append("+" + "-" * (width - 2) + "+")
        lines.append("")

        for i, action in enumerate(self.actions):
            is_last = i == len(self.actions) - 1
            prefix = "    " if i > 0 else ""
            connector = "`-- " if is_last else "|-- "

            box_line = f"[{i + 1}] {action.name} ({action.category.name})"
            lines.append(f"  {connector}{box_line}")

            detail_prefix = "        " if is_last else "  |     "
            lines.append(
                f"{detail_prefix}MITRE: {action.mitre_technique} | "
                f"Cost: {action.effects.cost:.1f} | "
                f"Risk: {action.effects.detection_risk:.0%}"
            )
            if action.effects.add_facts:
                facts_str = ", ".join(sorted(action.effects.add_facts))
                lines.append(f"{detail_prefix}+Facts: {facts_str}")
            if not is_last:
                lines.append("  |")

        lines.append("")
        stats = (
            f"Steps: {self.step_count} | "
            f"Cost: {self.total_cost:.1f} | "
            f"Time: {self.total_time_minutes}min | "
            f"Risk: {self.cumulative_detection_risk:.1%}"
        )
        lines.append("  " + "=" * len(stats))
        lines.append("  " + stats)
        lines.append("  " + "=" * len(stats))
        return "\n".join(lines)

    def __repr__(self) -> str:
        return (
            f"AttackPlan({self.plan_id}, steps={self.step_count}, "
            f"cost={self.total_cost:.1f}, risk={self.cumulative_detection_risk:.1%})"
        )


# ════════════════════════════════════════════════════════════════════════════════
# PlanSearchEngine — A* with beam search
# ════════════════════════════════════════════════════════════════════════════════


class _SearchNode:
    """Internal node for A* search."""

    __slots__ = (
        "state", "actions", "g_cost", "h_cost", "f_cost",
        "depth", "parent_hash",
    )

    def __init__(
        self,
        state: PlanState,
        actions: List[AttackAction],
        g_cost: float,
        h_cost: float,
        depth: int,
    ) -> None:
        self.state = state
        self.actions = actions
        self.g_cost = g_cost
        self.h_cost = h_cost
        self.f_cost = g_cost + h_cost
        self.depth = depth
        self.parent_hash = hash(state)

    def __lt__(self, other: _SearchNode) -> bool:
        return self.f_cost < other.f_cost


class PlanSearchEngine:
    """A* search engine with beam pruning for PDDL-style attack planning.

    Finds optimal (or near-optimal) attack plans by searching the state space
    defined by available actions, starting from an initial state toward a goal.

    Usage::

        engine = PlanSearchEngine()
        plan = engine.search(initial_state, goal, action_library.get_all())
    """

    def __init__(
        self,
        max_depth: int = MAX_PLAN_DEPTH,
        beam_width: int = BEAM_WIDTH,
        max_candidates: int = MAX_CANDIDATES,
        detection_penalty_weight: float = DETECTION_RISK_PENALTY_WEIGHT,
    ) -> None:
        self._lock = threading.RLock()
        self._max_depth = max_depth
        self._beam_width = beam_width
        self._max_candidates = max_candidates
        self._detection_penalty = detection_penalty_weight
        self._nodes_expanded = 0
        self._start_time = 0.0

    # ── heuristic ──

    def _heuristic(
        self,
        state: PlanState,
        goal: AttackGoal,
        min_cost: float = DEFAULT_ACTION_COST,
    ) -> float:
        """Admissible heuristic: unsatisfied goals * minimum action cost.

        This never overestimates the true remaining cost because each
        unsatisfied requirement needs at least one action whose cost is
        >= ``min_cost``.  Admissibility guarantees A* returns an optimal
        plan when the open set is not aggressively pruned.
        """
        missing_f = len(goal.required_facts - state.facts)
        missing_r = len(goal.target_resources - set(state.resources.keys()))
        return float(missing_f + missing_r) * min_cost

    # ── cost function ──

    def _action_cost(self, action: AttackAction) -> float:
        """Combined cost: base cost + detection risk penalty."""
        return (
            action.effects.cost
            + action.effects.detection_risk * self._detection_penalty
        )

    # ── relevance pruning ──

    def _is_relevant(
        self,
        action: AttackAction,
        state: PlanState,
        goal: AttackGoal,
        all_needed: Set[str],
    ) -> bool:
        """Check if action moves us closer to the goal or enables other actions."""
        if not action.is_applicable(state):
            return False
        new_facts = action.effects.add_facts - state.facts
        if not new_facts:
            return False
        # Direct contribution: adds a goal fact
        if new_facts & goal.required_facts:
            return True
        # Indirect contribution: adds a fact needed by other actions
        if new_facts & all_needed:
            return True
        # Resource contribution
        if action.effects.add_resources:
            needed_res = goal.target_resources - set(state.resources.keys())
            if set(action.effects.add_resources.keys()) & needed_res:
                return True
        return True  # be inclusive — beam search will prune

    # ── main search ──

    def search(
        self,
        initial_state: PlanState,
        goal: AttackGoal,
        actions: List[AttackAction],
        max_depth: Optional[int] = None,
        max_time_seconds: float = 30.0,
    ) -> AttackPlan:
        """Find optimal attack plan via A* search with beam pruning.

        Returns the best plan found, or a partial plan if the goal is unreachable.
        """
        with self._lock:
            return self._search_impl(
                initial_state, goal, actions,
                max_depth or self._max_depth,
                max_time_seconds,
            )

    def _search_impl(
        self,
        initial_state: PlanState,
        goal: AttackGoal,
        actions: List[AttackAction],
        max_depth: int,
        max_time_seconds: float,
    ) -> AttackPlan:
        self._nodes_expanded = 0
        self._start_time = time.time()

        # precompute all facts needed by any action's preconditions
        all_needed_facts: Set[str] = set()
        for a in actions:
            all_needed_facts |= a.preconditions.required_facts

        # precompute minimum action cost for admissible heuristic
        min_action_cost = (
            min(self._action_cost(a) for a in actions)
            if actions else DEFAULT_ACTION_COST
        )

        if goal.is_achieved(initial_state):
            return AttackPlan(
                actions=[],
                initial_state=initial_state,
                final_state=initial_state.copy(),
                goal=goal,
                status=PlanStatus.OPTIMAL,
                search_nodes_expanded=0,
                search_time_seconds=0.0,
            )

        h0 = self._heuristic(initial_state, goal, min_action_cost)
        start_node = _SearchNode(initial_state, [], 0.0, h0, 0)

        open_heap: List[_SearchNode] = [start_node]
        visited: Set[int] = set()
        best_partial: Optional[_SearchNode] = None
        best_partial_distance = float("inf")

        while open_heap:
            # time check
            elapsed = time.time() - self._start_time
            if elapsed > max_time_seconds:
                logger.warning(
                    "Search timeout after %.1fs, %d nodes expanded",
                    elapsed, self._nodes_expanded,
                )
                break

            node = heapq.heappop(open_heap)
            self._nodes_expanded += 1

            state_hash = hash(node.state)
            if state_hash in visited:
                continue
            visited.add(state_hash)

            # goal check
            if goal.is_achieved(node.state):
                elapsed = time.time() - self._start_time
                plan = AttackPlan(
                    actions=list(node.actions),
                    initial_state=initial_state,
                    final_state=node.state.copy(),
                    goal=goal,
                    status=PlanStatus.OPTIMAL,
                    search_nodes_expanded=self._nodes_expanded,
                    search_time_seconds=elapsed,
                )
                logger.info(
                    "Plan found: %d steps, cost=%.2f, %d nodes, %.3fs",
                    plan.step_count, plan.total_cost,
                    self._nodes_expanded, elapsed,
                )
                return plan

            # track best partial
            dist = goal.distance(node.state)
            if dist < best_partial_distance:
                best_partial_distance = dist
                best_partial = node

            # depth limit
            if node.depth >= max_depth:
                continue

            # expand
            candidates: List[_SearchNode] = []
            for action in actions:
                if not self._is_relevant(action, node.state, goal, all_needed_facts):
                    continue

                new_state = action.effects.apply(node.state)
                new_hash = hash(new_state)
                if new_hash in visited:
                    continue

                g = node.g_cost + self._action_cost(action)
                h = self._heuristic(new_state, goal, min_action_cost)
                new_actions = node.actions + [action]
                child = _SearchNode(new_state, new_actions, g, h, node.depth + 1)
                candidates.append(child)

            # beam pruning: keep top-K candidates
            candidates.sort(key=lambda n: n.f_cost)
            for child in candidates[: self._beam_width]:
                heapq.heappush(open_heap, child)

            # cap total open set
            if len(open_heap) > self._max_candidates:
                open_heap = heapq.nsmallest(self._max_candidates, open_heap)
                heapq.heapify(open_heap)

        # no solution — return best partial
        elapsed = time.time() - self._start_time
        if best_partial and best_partial.actions:
            plan = AttackPlan(
                actions=list(best_partial.actions),
                initial_state=initial_state,
                final_state=best_partial.state.copy(),
                goal=goal,
                status=PlanStatus.PARTIAL,
                search_nodes_expanded=self._nodes_expanded,
                search_time_seconds=elapsed,
            )
            logger.warning(
                "No complete plan found. Best partial: %d steps, "
                "distance=%d from goal",
                plan.step_count, int(best_partial_distance),
            )
            return plan

        return AttackPlan(
            actions=[],
            initial_state=initial_state,
            final_state=initial_state.copy(),
            goal=goal,
            status=PlanStatus.INFEASIBLE,
            search_nodes_expanded=self._nodes_expanded,
            search_time_seconds=elapsed,
        )

    # ── multi-plan search ──

    def search_top_n(
        self,
        initial_state: PlanState,
        goal: AttackGoal,
        actions: List[AttackAction],
        n: int = 5,
        max_depth: Optional[int] = None,
        max_time_seconds: float = 60.0,
    ) -> List[AttackPlan]:
        """Find top-N distinct plans via iterated A* with action exclusion.

        After finding each plan, the highest-risk action is excluded to
        force exploration of alternative paths.
        """
        plans: List[AttackPlan] = []
        excluded_ids: Set[str] = set()
        remaining_time = max_time_seconds

        for _ in range(n):
            if remaining_time <= 0:
                break

            available = [a for a in actions if a.action_id not in excluded_ids]
            if not available:
                break

            t0 = time.time()
            plan = self.search(
                initial_state, goal, available,
                max_depth=max_depth,
                max_time_seconds=min(remaining_time, max_time_seconds / n),
            )
            remaining_time -= (time.time() - t0)

            if plan.status == PlanStatus.INFEASIBLE:
                break

            plans.append(plan)

            # exclude the riskiest action to force different paths
            if plan.actions:
                riskiest = max(plan.actions, key=lambda a: a.effects.detection_risk)
                excluded_ids.add(riskiest.action_id)

        plans.sort(key=lambda p: p.total_cost)
        return plans

    def to_dict(self) -> Dict[str, Any]:
        return {
            "max_depth": self._max_depth,
            "beam_width": self._beam_width,
            "max_candidates": self._max_candidates,
            "detection_penalty_weight": self._detection_penalty,
        }


# ════════════════════════════════════════════════════════════════════════════════
# PlanOptimizer
# ════════════════════════════════════════════════════════════════════════════════


class PlanOptimizer:
    """Optimizes attack plans for stealth, speed, and parallelism.

    Usage::

        optimizer = PlanOptimizer(library, search_engine)
        stealthy = optimizer.minimize_detection(plan)
        fast = optimizer.minimize_time(plan)
        parallel = optimizer.parallelize(plan)
    """

    def __init__(
        self,
        library: ActionLibrary,
        engine: PlanSearchEngine,
    ) -> None:
        self._lock = threading.RLock()
        self._library = library
        self._engine = engine

    # ── minimize detection ──

    def minimize_detection(self, plan: AttackPlan) -> AttackPlan:
        """Re-plan with heavy detection penalty to find stealthier path."""
        with self._lock:
            if not plan.goal or not plan.actions:
                return plan

            stealth_engine = PlanSearchEngine(
                max_depth=self._engine._max_depth,
                beam_width=self._engine._beam_width,
                max_candidates=self._engine._max_candidates,
                detection_penalty_weight=self._engine._detection_penalty * 3.0,
            )

            new_plan = stealth_engine.search(
                plan.initial_state,
                plan.goal,
                self._library.get_all(),
            )

            if new_plan.status in (PlanStatus.OPTIMAL, PlanStatus.FEASIBLE):
                if new_plan.cumulative_detection_risk < plan.cumulative_detection_risk:
                    logger.info(
                        "Detection optimized: %.1f%% -> %.1f%%",
                        plan.cumulative_detection_risk * 100,
                        new_plan.cumulative_detection_risk * 100,
                    )
                    return new_plan

            return plan

    # ── minimize time ──

    def minimize_time(self, plan: AttackPlan) -> AttackPlan:
        """Re-plan with time as primary cost to find fastest path."""
        with self._lock:
            if not plan.goal or not plan.actions:
                return plan

            # Create time-weighted copies of all actions
            time_actions: List[AttackAction] = []
            for a in self._library.get_all():
                ta = copy.deepcopy(a)
                ta.effects.cost = float(ta.estimated_time_minutes)
                time_actions.append(ta)

            time_engine = PlanSearchEngine(
                max_depth=self._engine._max_depth,
                beam_width=self._engine._beam_width,
                detection_penalty_weight=0.0,  # ignore detection
            )

            new_plan = time_engine.search(
                plan.initial_state,
                plan.goal,
                time_actions,
            )

            if new_plan.status in (PlanStatus.OPTIMAL, PlanStatus.FEASIBLE):
                if new_plan.total_time_minutes < plan.total_time_minutes:
                    logger.info(
                        "Time optimized: %dmin -> %dmin",
                        plan.total_time_minutes,
                        new_plan.total_time_minutes,
                    )
                    return new_plan

            return plan

    # ── parallelism detection ──

    def parallelize(self, plan: AttackPlan) -> Dict[str, Any]:
        """Identify actions in the plan that can execute in parallel.

        Two actions can run in parallel if neither's preconditions depend
        on the other's effects, i.e., they are independent.

        Returns a schedule: list of stages, each stage being a list of
        actions that can run concurrently.
        """
        with self._lock:
            if not plan.actions:
                return {"stages": [], "speedup_factor": 1.0}

            n = len(plan.actions)
            # dependency[i] = set of indices that must complete before i
            dependencies: List[Set[int]] = [set() for _ in range(n)]

            for i in range(n):
                needed_facts = plan.actions[i].preconditions.required_facts
                needed_res = plan.actions[i].preconditions.required_resources
                for j in range(i):
                    provides_facts = plan.actions[j].effects.add_facts
                    provides_res = set(plan.actions[j].effects.add_resources.keys())
                    removes_facts = plan.actions[j].effects.remove_facts

                    # j must precede i if j provides something i needs
                    if provides_facts & needed_facts:
                        dependencies[i].add(j)
                    if provides_res & needed_res:
                        dependencies[i].add(j)
                    # j must precede i if j removes a fact i needs
                    if removes_facts & needed_facts:
                        dependencies[i].add(j)

            # topological layering
            scheduled: Set[int] = set()
            stages: List[List[Dict[str, Any]]] = []

            while len(scheduled) < n:
                stage: List[int] = []
                for i in range(n):
                    if i in scheduled:
                        continue
                    if dependencies[i].issubset(scheduled):
                        stage.append(i)
                if not stage:
                    # cycle — shouldn't happen but break gracefully
                    remaining = [i for i in range(n) if i not in scheduled]
                    stage = remaining
                    logger.warning("Dependency cycle detected in plan parallelization")

                stage_info = []
                for idx in stage:
                    a = plan.actions[idx]
                    stage_info.append({
                        "step": idx + 1,
                        "action": a.name,
                        "category": a.category.name,
                        "time_minutes": a.estimated_time_minutes,
                    })
                    scheduled.add(idx)
                stages.append(stage_info)

            # compute speedup
            serial_time = plan.total_time_minutes
            parallel_time = sum(
                max((s["time_minutes"] for s in stage), default=0)
                for stage in stages
            )
            speedup = serial_time / max(parallel_time, 1)

            return {
                "stages": stages,
                "total_stages": len(stages),
                "serial_time_minutes": serial_time,
                "parallel_time_minutes": parallel_time,
                "speedup_factor": round(speedup, 2),
            }

    # ── generate alternatives ──

    def generate_alternatives(
        self,
        plan: AttackPlan,
        n: int = 5,
    ) -> List[AttackPlan]:
        """Generate N alternative plans for the same goal."""
        with self._lock:
            if not plan.goal:
                return [plan]

            return self._engine.search_top_n(
                plan.initial_state,
                plan.goal,
                self._library.get_all(),
                n=n,
            )


# ════════════════════════════════════════════════════════════════════════════════
# SirenAttackPlanner — Main orchestrator
# ════════════════════════════════════════════════════════════════════════════════


class SirenAttackPlanner:
    """SIREN's PDDL-style attack planner — the strategic brain.

    Combines an action library, A* search engine, and plan optimizer to
    produce optimal multi-step attack plans from reconnaissance data.

    Usage::

        planner = SirenAttackPlanner()

        # Set what we know from recon
        planner.set_initial_state(PlanState(
            facts={"has_target_url", "has_target_ip", "has_target_domain"},
            resources={"target_url": "https://example.com"},
        ))

        # Plan an attack
        plan = planner.plan_attack(PREDEFINED_GOALS["data_exfiltration"])
        print(plan.to_ascii_tree())

        # Get alternatives
        alts = planner.get_all_plans(PREDEFINED_GOALS["full_compromise"], max_plans=5)

        # Export MITRE ATT&CK Navigator layer
        layer = planner.export_mitre_navigator(plan)
    """

    def __init__(
        self,
        max_depth: int = MAX_PLAN_DEPTH,
        beam_width: int = BEAM_WIDTH,
    ) -> None:
        self._lock = threading.RLock()
        self._library = ActionLibrary()
        self._engine = PlanSearchEngine(
            max_depth=max_depth,
            beam_width=beam_width,
        )
        self._optimizer = PlanOptimizer(self._library, self._engine)
        self._initial_state = PlanState()
        self._plans: List[AttackPlan] = []
        self._initialized = False
        logger.info("SirenAttackPlanner initialized")

    # ── setup ──

    def load_action_library(self) -> int:
        """Load the default 100+ action library. Returns action count."""
        with self._lock:
            self._library.load_defaults()
            self._initialized = True
            count = self._library.count()
            logger.info("Action library loaded: %d actions", count)
            return count

    def set_initial_state(self, state: PlanState) -> None:
        """Set the starting state (from recon results)."""
        with self._lock:
            self._initial_state = state.copy()
            logger.info(
                "Initial state set: %d facts, %d resources",
                len(state.facts), len(state.resources),
            )

    def add_fact(self, fact: str) -> None:
        """Add a single fact to the initial state."""
        with self._lock:
            self._initial_state.add_fact(fact)

    def add_resource(self, key: str, value: Any) -> None:
        """Add a single resource to the initial state."""
        with self._lock:
            self._initial_state.set_resource(key, value)

    def register_custom_action(self, action: AttackAction) -> None:
        """Register a custom action into the library."""
        with self._lock:
            self._library.register(action)

    # ── planning ──

    def plan_attack(self, goal: AttackGoal) -> AttackPlan:
        """Compute an optimal attack plan for the given goal."""
        with self._lock:
            self._ensure_initialized()
            plan = self._engine.search(
                self._initial_state,
                goal,
                self._library.get_all(),
            )
            self._plans.append(plan)
            logger.info(
                "Attack plan computed: %s — %d steps, status=%s",
                goal.name, plan.step_count, plan.status.name,
            )
            return plan

    def plan_multi_goal(self, goals: List[AttackGoal]) -> AttackPlan:
        """Combine multiple goals into a single comprehensive plan.

        Merges required_facts and target_resources from all goals, then
        plans once for the combined super-goal.
        """
        with self._lock:
            self._ensure_initialized()
            if not goals:
                return AttackPlan(
                    initial_state=self._initial_state.copy(),
                    final_state=self._initial_state.copy(),
                    status=PlanStatus.INFEASIBLE,
                )

            combined_facts: Set[str] = set()
            combined_resources: Set[str] = set()
            names: List[str] = []
            max_priority = 0.0

            for g in goals:
                combined_facts |= g.required_facts
                combined_resources |= g.target_resources
                names.append(g.name)
                max_priority = max(max_priority, g.priority)

            super_goal = AttackGoal(
                goal_id="multi_" + str(uuid.uuid4())[:6],
                name="Multi-Goal: " + " + ".join(names),
                description="Combined goal from multiple objectives",
                goal_type=GoalType.CUSTOM,
                required_facts=combined_facts,
                target_resources=combined_resources,
                priority=max_priority,
            )

            plan = self._engine.search(
                self._initial_state,
                super_goal,
                self._library.get_all(),
            )
            self._plans.append(plan)
            logger.info(
                "Multi-goal plan: %d goals combined, %d steps, status=%s",
                len(goals), plan.step_count, plan.status.name,
            )
            return plan

    def get_all_plans(
        self,
        goal: AttackGoal,
        max_plans: int = 10,
    ) -> List[AttackPlan]:
        """Get multiple alternative plans ranked by cost."""
        with self._lock:
            self._ensure_initialized()
            plans = self._engine.search_top_n(
                self._initial_state,
                goal,
                self._library.get_all(),
                n=max_plans,
            )
            self._plans.extend(plans)
            return plans

    # ── suggestions ──

    def suggest_next_action(self, current_state: PlanState) -> Optional[AttackAction]:
        """Suggest the single best next action from the current state.

        Evaluates all applicable actions and returns the one with the best
        ratio of new facts gained to cost.
        """
        with self._lock:
            self._ensure_initialized()
            applicable = self._library.get_applicable(current_state)
            if not applicable:
                return None

            def score(a: AttackAction) -> float:
                new_facts = a.effects.add_facts - current_state.facts
                if not new_facts:
                    return -1.0
                return len(new_facts) / (a.effects.cost + EPSILON)

            best = max(applicable, key=score)
            if score(best) <= 0:
                return None
            return best

    def suggest_actions(
        self,
        current_state: PlanState,
        top_k: int = 5,
    ) -> List[Tuple[AttackAction, float]]:
        """Return top-K applicable actions with their utility scores."""
        with self._lock:
            self._ensure_initialized()
            applicable = self._library.get_applicable(current_state)

            scored: List[Tuple[AttackAction, float]] = []
            for a in applicable:
                new_facts = a.effects.add_facts - current_state.facts
                if not new_facts:
                    continue
                utility = len(new_facts) / (
                    a.effects.cost + a.effects.detection_risk * 2.0 + EPSILON
                )
                scored.append((a, utility))

            scored.sort(key=lambda x: x[1], reverse=True)
            return scored[:top_k]

    # ── optimization ──

    def optimize_for_stealth(self, plan: AttackPlan) -> AttackPlan:
        """Return a plan optimized for minimal detection risk."""
        return self._optimizer.minimize_detection(plan)

    def optimize_for_speed(self, plan: AttackPlan) -> AttackPlan:
        """Return a plan optimized for minimal time."""
        return self._optimizer.minimize_time(plan)

    def parallelize_plan(self, plan: AttackPlan) -> Dict[str, Any]:
        """Identify parallelizable stages in the plan."""
        return self._optimizer.parallelize(plan)

    def generate_alternatives(
        self,
        plan: AttackPlan,
        n: int = 5,
    ) -> List[AttackPlan]:
        """Generate N alternative plans for the same goal."""
        return self._optimizer.generate_alternatives(plan, n)

    # ── visualization ──

    def visualize_plan(self, plan: AttackPlan) -> str:
        """Render an ASCII attack tree for the plan."""
        return plan.to_ascii_tree()

    def visualize_plan_markdown(self, plan: AttackPlan) -> str:
        """Render plan as Markdown."""
        return plan.to_markdown()

    # ── MITRE ATT&CK Navigator export ──

    def export_mitre_navigator(self, plan: AttackPlan) -> Dict[str, Any]:
        """Export plan as a MITRE ATT&CK Navigator layer JSON.

        Compatible with https://mitre-attack.github.io/attack-navigator/
        """
        techniques: List[Dict[str, Any]] = []
        technique_counts: Dict[str, int] = defaultdict(int)

        for action in plan.actions:
            if action.mitre_technique:
                technique_counts[action.mitre_technique] += 1

        max_count = max(technique_counts.values()) if technique_counts else 1

        for tid, count in technique_counts.items():
            score = min(100, int((count / max_count) * 100))
            techniques.append({
                "techniqueID": tid,
                "score": score,
                "color": self._risk_color(count / max_count),
                "comment": f"Used {count} time(s) in plan {plan.plan_id}",
                "enabled": True,
                "metadata": [],
                "showSubtechniques": True,
            })

        layer: Dict[str, Any] = {
            "name": f"SIREN Plan: {plan.plan_id}",
            "versions": {
                "attack": "14",
                "navigator": "4.9.1",
                "layer": "4.5",
            },
            "domain": "enterprise-attack",
            "description": (
                f"Attack plan generated by SIREN Attack Planner. "
                f"Goal: {plan.goal.name if plan.goal else 'N/A'}. "
                f"Steps: {plan.step_count}. "
                f"Risk: {plan.cumulative_detection_risk:.1%}."
            ),
            "filters": {"platforms": ["Linux", "Windows", "macOS"]},
            "sorting": 3,
            "layout": {"layout": "side", "showID": True, "showName": True},
            "hideDisabled": False,
            "techniques": techniques,
            "gradient": {
                "colors": ["#ffffff", "#ff6666"],
                "minValue": 0,
                "maxValue": 100,
            },
            "legendItems": [
                {"label": "Used in plan", "color": "#ff6666"},
            ],
            "metadata": [
                {"name": "plan_id", "value": plan.plan_id},
                {"name": "total_steps", "value": str(plan.step_count)},
                {"name": "total_cost", "value": f"{plan.total_cost:.2f}"},
                {"name": "detection_risk", "value": f"{plan.cumulative_detection_risk:.1%}"},
            ],
            "showTacticRowBackground": True,
            "tacticRowBackground": "#dddddd",
            "selectTechniquesAcrossTactics": True,
            "selectSubtechniquesWithParent": False,
        }

        return layer

    # ── introspection ──

    def get_library_stats(self) -> Dict[str, Any]:
        """Return statistics about the loaded action library."""
        with self._lock:
            return {
                "total_actions": self._library.count(),
                "by_category": self._library.categories_summary(),
                "initial_state": self._initial_state.to_dict(),
                "applicable_now": len(
                    self._library.get_applicable(self._initial_state)
                ),
                "plans_computed": len(self._plans),
            }

    def get_action_library(self) -> ActionLibrary:
        """Return the action library instance."""
        return self._library

    def get_initial_state(self) -> PlanState:
        """Return a copy of the current initial state."""
        with self._lock:
            return self._initial_state.copy()

    def get_computed_plans(self) -> List[AttackPlan]:
        """Return all plans computed so far."""
        with self._lock:
            return list(self._plans)

    def reset(self) -> None:
        """Reset planner state (keeps library)."""
        with self._lock:
            self._initial_state = PlanState()
            self._plans.clear()
            logger.info("SirenAttackPlanner reset")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "library": self._library.to_dict(),
            "search_engine": self._engine.to_dict(),
            "initial_state": self._initial_state.to_dict(),
            "plans_computed": len(self._plans),
            "initialized": self._initialized,
        }

    # ── internals ──

    def _ensure_initialized(self) -> None:
        if not self._initialized:
            self.load_action_library()

    @staticmethod
    def _risk_color(intensity: float) -> str:
        """Map intensity 0-1 to a red hex color."""
        r = 255
        g = int(255 * (1.0 - intensity * 0.7))
        b = int(255 * (1.0 - intensity * 0.7))
        return f"#{r:02x}{g:02x}{b:02x}"

    def __repr__(self) -> str:
        return (
            f"SirenAttackPlanner(actions={self._library.count()}, "
            f"state_facts={len(self._initial_state.facts)}, "
            f"plans={len(self._plans)})"
        )


# ════════════════════════════════════════════════════════════════════════════════
# MODULE-LEVEL CONVENIENCE
# ════════════════════════════════════════════════════════════════════════════════


def create_planner(**kwargs: Any) -> SirenAttackPlanner:
    """Factory: create and initialize a planner in one call."""
    planner = SirenAttackPlanner(**kwargs)
    planner.load_action_library()
    return planner


def quick_plan(
    initial_facts: Set[str],
    goal_name: str,
    resources: Optional[Dict[str, Any]] = None,
) -> AttackPlan:
    """One-shot planning: provide initial facts and a predefined goal name.

    Usage::

        plan = quick_plan(
            {"has_target_url", "has_target_ip"},
            "data_exfiltration",
        )
        print(plan.to_ascii_tree())
    """
    planner = create_planner()
    state = PlanState(facts=set(initial_facts), resources=dict(resources or {}))
    planner.set_initial_state(state)

    goal = PREDEFINED_GOALS.get(goal_name)
    if goal is None:
        raise ValueError(
            f"Unknown predefined goal '{goal_name}'. "
            f"Available: {list(PREDEFINED_GOALS.keys())}"
        )

    return planner.plan_attack(goal)
