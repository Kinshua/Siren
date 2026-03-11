#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  🎯 SIREN CAMPAIGN MANAGER — Orchestrated Attack Campaign Engine  🎯        ██
██                                                                                ██
██  Orquestração de campanhas de teste completas com fases, gates e rollback.   ██
██                                                                                ██
██  Capacidades:                                                                  ██
██    • Campaign lifecycle — plan→execute→evaluate→report                       ██
██    • Phase management — ordered phases with gate conditions                   ██
██    • Task scheduling — parallel & sequential task execution                   ██
██    • Target management — scope, exclusions, asset inventory                   ██
██    • Gate conditions — pass/fail criteria between phases                      ██
██    • Campaign templates — reusable pentest methodologies                      ██
██    • State persistence — resume after interruption                            ██
██    • Rate limiting — respect target capacity and rules of engagement          ██
██                                                                                ██
██  "SIREN orquestra o caos — com precisão cirúrgica."                          ██
██                                                                                ██
████████████████████████████████████████████████████████████████████████████████████
"""

from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("siren.automation.campaign_manager")


# ════════════════════════════════════════════════════════════════════════════════
# ENUMS
# ════════════════════════════════════════════════════════════════════════════════

class CampaignStatus(Enum):
    DRAFT = auto()
    READY = auto()
    RUNNING = auto()
    PAUSED = auto()
    GATE_HOLD = auto()
    COMPLETED = auto()
    ABORTED = auto()
    FAILED = auto()


class PhaseType(Enum):
    """Standard pentest phases."""
    RECONNAISSANCE = auto()
    ENUMERATION = auto()
    VULNERABILITY_SCAN = auto()
    EXPLOITATION = auto()
    POST_EXPLOITATION = auto()
    LATERAL_MOVEMENT = auto()
    REPORTING = auto()
    CUSTOM = auto()


class TaskStatus(Enum):
    PENDING = auto()
    QUEUED = auto()
    RUNNING = auto()
    COMPLETED = auto()
    FAILED = auto()
    SKIPPED = auto()
    TIMEOUT = auto()


class TaskPriority(Enum):
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4


class GateType(Enum):
    """Gate condition types."""
    ALL_TASKS_PASS = auto()
    MIN_SUCCESS_RATE = auto()
    FINDING_THRESHOLD = auto()
    MANUAL_APPROVAL = auto()
    TIME_LIMIT = auto()
    CUSTOM = auto()


class ScopeAction(Enum):
    INCLUDE = auto()
    EXCLUDE = auto()


# ════════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class ScopeRule:
    """Defines what is in/out of scope."""
    action: ScopeAction
    target_pattern: str  # IP, CIDR, hostname, URL pattern
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action.name,
            "pattern": self.target_pattern,
            "description": self.description,
        }


@dataclass
class RateLimit:
    """Rate limiting configuration."""
    max_requests_per_second: float = 10.0
    max_concurrent: int = 5
    cooldown_on_error_s: float = 5.0
    backoff_multiplier: float = 2.0
    max_backoff_s: float = 300.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "max_rps": self.max_requests_per_second,
            "max_concurrent": self.max_concurrent,
            "cooldown_on_error_s": self.cooldown_on_error_s,
        }


@dataclass
class CampaignTask:
    """A single task within a phase."""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    name: str = ""
    description: str = ""
    task_type: str = ""
    priority: TaskPriority = TaskPriority.MEDIUM
    status: TaskStatus = TaskStatus.PENDING
    target: str = ""
    config: Dict[str, Any] = field(default_factory=dict)
    depends_on: List[str] = field(default_factory=list)  # Task IDs
    start_time: float = 0.0
    end_time: float = 0.0
    result: Dict[str, Any] = field(default_factory=dict)
    error: str = ""
    retries: int = 0
    max_retries: int = 3
    timeout_s: float = 300.0

    @property
    def duration_s(self) -> float:
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return 0.0

    @property
    def is_terminal(self) -> bool:
        return self.status in (TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.SKIPPED, TaskStatus.TIMEOUT)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "type": self.task_type,
            "priority": self.priority.name,
            "status": self.status.name,
            "target": self.target,
            "duration_s": round(self.duration_s, 2),
            "retries": self.retries,
            "error": self.error,
        }


@dataclass
class GateCondition:
    """A gate condition between phases."""
    gate_type: GateType
    threshold: float = 0.0   # e.g., 0.8 for 80% success rate
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.gate_type.name,
            "threshold": self.threshold,
            "description": self.description,
        }


@dataclass
class CampaignPhase:
    """A phase in the campaign lifecycle."""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    name: str = ""
    phase_type: PhaseType = PhaseType.CUSTOM
    description: str = ""
    tasks: List[CampaignTask] = field(default_factory=list)
    gate: Optional[GateCondition] = None
    order: int = 0
    status: CampaignStatus = CampaignStatus.DRAFT
    start_time: float = 0.0
    end_time: float = 0.0
    parallel: bool = False  # Run tasks in parallel within this phase

    @property
    def task_count(self) -> int:
        return len(self.tasks)

    @property
    def completed_count(self) -> int:
        return sum(1 for t in self.tasks if t.status == TaskStatus.COMPLETED)

    @property
    def failed_count(self) -> int:
        return sum(1 for t in self.tasks if t.status == TaskStatus.FAILED)

    @property
    def success_rate(self) -> float:
        terminal = sum(1 for t in self.tasks if t.is_terminal)
        if terminal == 0:
            return 0.0
        return self.completed_count / terminal

    @property
    def is_complete(self) -> bool:
        return all(t.is_terminal for t in self.tasks)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "type": self.phase_type.name,
            "status": self.status.name,
            "tasks_total": self.task_count,
            "tasks_completed": self.completed_count,
            "tasks_failed": self.failed_count,
            "success_rate": round(self.success_rate, 3),
            "parallel": self.parallel,
            "gate": self.gate.to_dict() if self.gate else None,
            "tasks": [t.to_dict() for t in self.tasks],
        }


@dataclass
class Campaign:
    """A complete attack campaign."""
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    name: str = ""
    description: str = ""
    status: CampaignStatus = CampaignStatus.DRAFT
    phases: List[CampaignPhase] = field(default_factory=list)
    scope: List[ScopeRule] = field(default_factory=list)
    rate_limit: RateLimit = field(default_factory=RateLimit)
    created_at: float = field(default_factory=time.time)
    started_at: float = 0.0
    completed_at: float = 0.0
    current_phase_idx: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def total_tasks(self) -> int:
        return sum(p.task_count for p in self.phases)

    @property
    def completed_tasks(self) -> int:
        return sum(p.completed_count for p in self.phases)

    @property
    def progress(self) -> float:
        total = self.total_tasks
        if total == 0:
            return 0.0
        return self.completed_tasks / total

    @property
    def current_phase(self) -> Optional[CampaignPhase]:
        if 0 <= self.current_phase_idx < len(self.phases):
            return self.phases[self.current_phase_idx]
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "status": self.status.name,
            "progress": round(self.progress, 3),
            "total_tasks": self.total_tasks,
            "completed_tasks": self.completed_tasks,
            "current_phase": self.current_phase.name if self.current_phase else None,
            "phases": [p.to_dict() for p in self.phases],
            "scope": [s.to_dict() for s in self.scope],
            "rate_limit": self.rate_limit.to_dict(),
        }


# ════════════════════════════════════════════════════════════════════════════════
# CAMPAIGN TEMPLATES — Reusable methodologies
# ════════════════════════════════════════════════════════════════════════════════

class CampaignTemplates:
    """Pre-built campaign templates."""

    @staticmethod
    def web_application_pentest(target: str) -> Campaign:
        """Standard web application penetration test template."""
        campaign = Campaign(
            name=f"Web App Pentest — {target}",
            description="Comprehensive web application security assessment",
        )

        # Phase 1: Reconnaissance
        recon = CampaignPhase(
            name="Reconnaissance",
            phase_type=PhaseType.RECONNAISSANCE,
            order=0,
            parallel=True,
            gate=GateCondition(GateType.MIN_SUCCESS_RATE, 0.5, "At least 50% recon tasks must succeed"),
        )
        recon.tasks = [
            CampaignTask(name="DNS Enumeration", task_type="dns_enum", target=target, priority=TaskPriority.HIGH),
            CampaignTask(name="Subdomain Discovery", task_type="subdomain_enum", target=target),
            CampaignTask(name="Technology Fingerprint", task_type="deep_fingerprint", target=target, priority=TaskPriority.HIGH),
            CampaignTask(name="OSINT Correlation", task_type="osint_correlate", target=target),
            CampaignTask(name="SSL/TLS Audit", task_type="tls_audit", target=target),
        ]
        campaign.phases.append(recon)

        # Phase 2: Enumeration
        enum_phase = CampaignPhase(
            name="Enumeration",
            phase_type=PhaseType.ENUMERATION,
            order=1,
            parallel=True,
            gate=GateCondition(GateType.ALL_TASKS_PASS),
        )
        enum_phase.tasks = [
            CampaignTask(name="Directory Bruteforce", task_type="dir_brute", target=target),
            CampaignTask(name="API Endpoint Discovery", task_type="api_discovery", target=target),
            CampaignTask(name="GraphQL Introspection", task_type="graphql_introspect", target=target),
            CampaignTask(name="WebSocket Probe", task_type="ws_probe", target=target),
            CampaignTask(name="Parameter Mining", task_type="param_mine", target=target),
        ]
        campaign.phases.append(enum_phase)

        # Phase 3: Vulnerability Scanning
        vuln_phase = CampaignPhase(
            name="Vulnerability Scan",
            phase_type=PhaseType.VULNERABILITY_SCAN,
            order=2,
            parallel=True,
        )
        vuln_phase.tasks = [
            CampaignTask(name="SQL Injection Scan", task_type="sqli_scan", target=target, priority=TaskPriority.CRITICAL),
            CampaignTask(name="XSS Scan", task_type="xss_scan", target=target, priority=TaskPriority.HIGH),
            CampaignTask(name="SSTI Scan", task_type="ssti_scan", target=target),
            CampaignTask(name="Auth Bypass Tests", task_type="auth_bypass", target=target, priority=TaskPriority.CRITICAL),
            CampaignTask(name="Supply Chain Audit", task_type="supply_chain", target=target),
            CampaignTask(name="CVE Prediction", task_type="cve_predict", target=target),
        ]
        campaign.phases.append(vuln_phase)

        # Phase 4: Exploitation
        exploit_phase = CampaignPhase(
            name="Exploitation",
            phase_type=PhaseType.EXPLOITATION,
            order=3,
            parallel=False,  # Sequential for safety
        )
        exploit_phase.tasks = [
            CampaignTask(name="Exploit Synthesis", task_type="exploit_synth", target=target, priority=TaskPriority.CRITICAL),
            CampaignTask(name="Chain Exploitation", task_type="chain_exploit", target=target),
        ]
        campaign.phases.append(exploit_phase)

        # Phase 5: Reporting
        report_phase = CampaignPhase(
            name="Reporting",
            phase_type=PhaseType.REPORTING,
            order=4,
        )
        report_phase.tasks = [
            CampaignTask(name="Generate Narrative", task_type="attack_narrative", target=target),
            CampaignTask(name="Compliance Mapping", task_type="compliance_map", target=target),
            CampaignTask(name="Risk Scoring", task_type="risk_score", target=target),
            CampaignTask(name="Remediation Guide", task_type="remediation_gen", target=target),
        ]
        campaign.phases.append(report_phase)

        return campaign

    @staticmethod
    def api_security_audit(target: str) -> Campaign:
        """API-focused security audit template."""
        campaign = Campaign(
            name=f"API Security Audit — {target}",
            description="Focused API security assessment (REST/GraphQL/WebSocket)",
        )

        recon = CampaignPhase(name="API Discovery", phase_type=PhaseType.RECONNAISSANCE, order=0, parallel=True)
        recon.tasks = [
            CampaignTask(name="OpenAPI/Swagger Discovery", task_type="openapi_discover", target=target),
            CampaignTask(name="GraphQL Schema Extract", task_type="graphql_introspect", target=target),
            CampaignTask(name="API Fingerprint", task_type="api_fingerprint", target=target),
        ]

        test = CampaignPhase(name="API Testing", phase_type=PhaseType.VULNERABILITY_SCAN, order=1, parallel=True)
        test.tasks = [
            CampaignTask(name="BOLA/IDOR Testing", task_type="bola_test", target=target, priority=TaskPriority.CRITICAL),
            CampaignTask(name="Auth Token Analysis", task_type="token_analysis", target=target),
            CampaignTask(name="Rate Limit Testing", task_type="rate_limit_test", target=target),
            CampaignTask(name="Mass Assignment", task_type="mass_assignment", target=target),
            CampaignTask(name="Injection Testing", task_type="injection_suite", target=target),
        ]

        campaign.phases.extend([recon, test])
        return campaign

    @staticmethod
    def container_audit(target: str) -> Campaign:
        """Container/K8s security audit template."""
        campaign = Campaign(
            name=f"Container Audit — {target}",
            description="Container infrastructure security assessment",
        )

        phase = CampaignPhase(name="Container Analysis", phase_type=PhaseType.VULNERABILITY_SCAN, order=0, parallel=True)
        phase.tasks = [
            CampaignTask(name="Dockerfile Audit", task_type="dockerfile_audit", target=target),
            CampaignTask(name="K8s Manifest Audit", task_type="k8s_audit", target=target),
            CampaignTask(name="Image Layer Analysis", task_type="image_layers", target=target),
            CampaignTask(name="Supply Chain Check", task_type="supply_chain", target=target),
        ]

        campaign.phases.append(phase)
        return campaign


# ════════════════════════════════════════════════════════════════════════════════
# GATE EVALUATOR — Evaluates phase gate conditions
# ════════════════════════════════════════════════════════════════════════════════

class GateEvaluator:
    """Evaluates gate conditions between phases."""

    def evaluate(self, gate: GateCondition, phase: CampaignPhase) -> Tuple[bool, str]:
        """Evaluate a gate condition. Returns (passed, reason)."""
        if gate.gate_type == GateType.ALL_TASKS_PASS:
            if phase.failed_count > 0:
                return False, f"{phase.failed_count} tasks failed in phase '{phase.name}'"
            return True, "All tasks passed"

        elif gate.gate_type == GateType.MIN_SUCCESS_RATE:
            rate = phase.success_rate
            if rate < gate.threshold:
                return False, f"Success rate {rate:.1%} below threshold {gate.threshold:.1%}"
            return True, f"Success rate {rate:.1%} meets threshold"

        elif gate.gate_type == GateType.FINDING_THRESHOLD:
            # Count findings in task results
            finding_count = sum(
                len(t.result.get("findings", []))
                for t in phase.tasks
                if t.status == TaskStatus.COMPLETED
            )
            if finding_count < gate.threshold:
                return False, f"Only {finding_count} findings (need {gate.threshold})"
            return True, f"Found {finding_count} findings"

        elif gate.gate_type == GateType.MANUAL_APPROVAL:
            return False, "Awaiting manual approval"

        elif gate.gate_type == GateType.TIME_LIMIT:
            elapsed = phase.end_time - phase.start_time if phase.end_time else 0
            if elapsed > gate.threshold:
                return False, f"Phase exceeded time limit ({elapsed:.0f}s > {gate.threshold:.0f}s)"
            return True, "Phase completed within time limit"

        return True, "No gate condition"


# ════════════════════════════════════════════════════════════════════════════════
# SCOPE CHECKER — Validates targets against scope rules
# ════════════════════════════════════════════════════════════════════════════════

class ScopeChecker:
    """Validates targets against scope rules."""

    def is_in_scope(self, target: str, rules: List[ScopeRule]) -> bool:
        """Check if a target is within scope."""
        if not rules:
            return True

        in_scope = False
        for rule in rules:
            if self._matches(target, rule.target_pattern):
                if rule.action == ScopeAction.INCLUDE:
                    in_scope = True
                elif rule.action == ScopeAction.EXCLUDE:
                    return False

        return in_scope

    @staticmethod
    def _matches(target: str, pattern: str) -> bool:
        """Check if target matches a scope pattern."""
        target_lower = target.lower()
        pattern_lower = pattern.lower()

        # Exact match
        if target_lower == pattern_lower:
            return True

        # Wildcard matching
        if "*" in pattern_lower:
            import fnmatch
            return fnmatch.fnmatch(target_lower, pattern_lower)

        # Substring match (for domains)
        if target_lower.endswith("." + pattern_lower) or target_lower == pattern_lower:
            return True

        return False


# ════════════════════════════════════════════════════════════════════════════════
# CAMPAIGN PERSISTENCE — Save/load campaign state
# ════════════════════════════════════════════════════════════════════════════════

class CampaignPersistence:
    """Persists campaign state to JSON for resume capability."""

    @staticmethod
    def serialize(campaign: Campaign) -> str:
        """Serialize campaign to JSON string."""
        return json.dumps(campaign.to_dict(), indent=2, default=str)

    @staticmethod
    def save(campaign: Campaign, filepath: str) -> None:
        """Save campaign state to file atomically."""
        tmp_path = filepath + ".tmp"
        data = CampaignPersistence.serialize(campaign)
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(data)
        import os
        os.replace(tmp_path, filepath)

    @staticmethod
    def load(filepath: str) -> Dict[str, Any]:
        """Load campaign state from file."""
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)


# ════════════════════════════════════════════════════════════════════════════════
# SIREN CAMPAIGN MANAGER — Main Orchestrator
# ════════════════════════════════════════════════════════════════════════════════

class SirenCampaignManager:
    """
    Main campaign management engine.

    Orchestrates campaign lifecycle, phase execution, gate evaluation,
    scope checking, and state persistence.

    Usage:
        manager = SirenCampaignManager()

        # Create from template
        campaign = manager.create_from_template("web_pentest", "https://target.com")

        # Start campaign
        manager.start_campaign(campaign.id)

        # Get status
        status = manager.get_campaign_status(campaign.id)
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._campaigns: Dict[str, Campaign] = {}
        self._gate_evaluator = GateEvaluator()
        self._scope_checker = ScopeChecker()
        self._stats: Dict[str, int] = defaultdict(int)
        logger.info("SirenCampaignManager initialized")

    def create_campaign(self, name: str, description: str = "") -> Campaign:
        """Create a new empty campaign."""
        campaign = Campaign(name=name, description=description)
        with self._lock:
            self._campaigns[campaign.id] = campaign
            self._stats["campaigns_created"] += 1
        return campaign

    def create_from_template(self, template_name: str, target: str) -> Campaign:
        """Create a campaign from a template."""
        templates = {
            "web_pentest": CampaignTemplates.web_application_pentest,
            "api_audit": CampaignTemplates.api_security_audit,
            "container_audit": CampaignTemplates.container_audit,
        }
        factory = templates.get(template_name)
        if not factory:
            raise ValueError(f"Unknown template: {template_name}. Available: {list(templates.keys())}")

        campaign = factory(target)
        with self._lock:
            self._campaigns[campaign.id] = campaign
            self._stats["campaigns_created"] += 1
        return campaign

    def add_phase(self, campaign_id: str, phase: CampaignPhase) -> None:
        """Add a phase to a campaign."""
        with self._lock:
            campaign = self._campaigns.get(campaign_id)
            if not campaign:
                raise ValueError(f"Campaign not found: {campaign_id}")
            phase.order = len(campaign.phases)
            campaign.phases.append(phase)

    def start_campaign(self, campaign_id: str) -> bool:
        """Start a campaign."""
        with self._lock:
            campaign = self._campaigns.get(campaign_id)
            if not campaign:
                return False
            if campaign.status not in (CampaignStatus.DRAFT, CampaignStatus.READY, CampaignStatus.PAUSED):
                return False
            campaign.status = CampaignStatus.RUNNING
            campaign.started_at = time.time()
            campaign.current_phase_idx = 0
            if campaign.phases:
                campaign.phases[0].status = CampaignStatus.RUNNING
                campaign.phases[0].start_time = time.time()
            self._stats["campaigns_started"] += 1
            return True

    def complete_task(self, campaign_id: str, task_id: str, result: Dict[str, Any],
                       success: bool = True) -> None:
        """Mark a task as completed with results."""
        with self._lock:
            campaign = self._campaigns.get(campaign_id)
            if not campaign:
                return

            for phase in campaign.phases:
                for task in phase.tasks:
                    if task.id == task_id:
                        task.status = TaskStatus.COMPLETED if success else TaskStatus.FAILED
                        task.end_time = time.time()
                        task.result = result
                        self._stats["tasks_completed"] += 1

                        # Check if phase is complete
                        if phase.is_complete:
                            phase.status = CampaignStatus.COMPLETED
                            phase.end_time = time.time()
                            self._try_advance_phase(campaign)
                        return

    def is_in_scope(self, campaign_id: str, target: str) -> bool:
        """Check if a target is in campaign scope."""
        with self._lock:
            campaign = self._campaigns.get(campaign_id)
            if not campaign:
                return False
            return self._scope_checker.is_in_scope(target, campaign.scope)

    def get_campaign(self, campaign_id: str) -> Optional[Campaign]:
        with self._lock:
            return self._campaigns.get(campaign_id)

    def get_campaign_status(self, campaign_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            campaign = self._campaigns.get(campaign_id)
            return campaign.to_dict() if campaign else None

    def get_next_tasks(self, campaign_id: str) -> List[CampaignTask]:
        """Get the next tasks ready for execution."""
        with self._lock:
            campaign = self._campaigns.get(campaign_id)
            if not campaign or campaign.status != CampaignStatus.RUNNING:
                return []

            phase = campaign.current_phase
            if not phase:
                return []

            ready: List[CampaignTask] = []
            for task in phase.tasks:
                if task.status != TaskStatus.PENDING:
                    continue
                # Check dependencies
                deps_met = all(
                    any(t.id == dep and t.status == TaskStatus.COMPLETED
                        for t in phase.tasks)
                    for dep in task.depends_on
                )
                if deps_met:
                    ready.append(task)
                    if not phase.parallel:
                        break  # Sequential: one at a time

            return ready

    def get_stats(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._stats)

    # ── Private ─────────────────────────────────────────────────────────────

    def _try_advance_phase(self, campaign: Campaign) -> None:
        """Try to advance to the next phase, checking gates."""
        current = campaign.current_phase
        if not current:
            return

        # Check gate condition
        if current.gate:
            passed, reason = self._gate_evaluator.evaluate(current.gate, current)
            if not passed:
                campaign.status = CampaignStatus.GATE_HOLD
                logger.warning("Campaign %s held at gate: %s", campaign.id, reason)
                return

        # Advance to next phase
        next_idx = campaign.current_phase_idx + 1
        if next_idx < len(campaign.phases):
            campaign.current_phase_idx = next_idx
            next_phase = campaign.phases[next_idx]
            next_phase.status = CampaignStatus.RUNNING
            next_phase.start_time = time.time()
            logger.info("Campaign %s advanced to phase: %s", campaign.id, next_phase.name)
        else:
            # All phases complete
            campaign.status = CampaignStatus.COMPLETED
            campaign.completed_at = time.time()
            self._stats["campaigns_completed"] += 1
            logger.info("Campaign %s completed", campaign.id)
