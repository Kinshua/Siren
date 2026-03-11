"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  SIREN — Workspace, Git Checkpoints, Session State, Config & Audit         ║
║                                                                              ║
║  This module closes the critical infrastructure gaps between SIREN and       ║
║  the original Shannon architecture:                                          ║
║                                                                              ║
║  • WorkspaceManager    — discovery, creation, status, listing                ║
║  • GitCheckpointManager — init, checkpoint, rollback, restore                ║
║  • SessionStateMachine  — full save/load/update with resume detection        ║
║  • ConfigFileLoader     — YAML/JSON config discovery + schema validation     ║
║  • AuditLogger          — structured activity stream, per-agent logs         ║
║  • DeliverableManager   — 17 typed deliverables, validation, merge           ║
║                                                                              ║
║  Shannon provides the BRAIN. SIREN provides the BODY.                    ║
║  Together they are SIREN — the perfect predator.                             ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import asyncio
import copy
import datetime
import enum
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Optional,
    Set,
    Tuple,
    Union,
)

logger = logging.getLogger("siren.workspace")


# ════════════════════════════════════════════════════════════════════════
#  Section 1: Enums & Constants
# ════════════════════════════════════════════════════════════════════════


class DeliverableType(enum.Enum):
    """All 17 deliverable types from Shannon's architecture."""

    CODE_ANALYSIS = "code_analysis_deliverable.md"
    RECON = "recon_deliverable.md"
    INJECTION_ANALYSIS = "injection_vulnerability_analysis.md"
    INJECTION_QUEUE = "injection_exploitation_queue.json"
    XSS_ANALYSIS = "xss_vulnerability_analysis.md"
    XSS_QUEUE = "xss_exploitation_queue.json"
    AUTH_ANALYSIS = "auth_vulnerability_analysis.md"
    AUTH_QUEUE = "auth_exploitation_queue.json"
    SSRF_ANALYSIS = "ssrf_vulnerability_analysis.md"
    SSRF_QUEUE = "ssrf_exploitation_queue.json"
    AUTHZ_ANALYSIS = "authz_vulnerability_analysis.md"
    AUTHZ_QUEUE = "authz_exploitation_queue.json"
    INJECTION_EVIDENCE = "injection_exploitation_evidence.md"
    XSS_EVIDENCE = "xss_exploitation_evidence.md"
    AUTH_EVIDENCE = "auth_exploitation_evidence.md"
    SSRF_EVIDENCE = "ssrf_exploitation_evidence.md"
    AUTHZ_EVIDENCE = "authz_exploitation_evidence.md"

    @classmethod
    def queues(cls) -> List["DeliverableType"]:
        return [d for d in cls if d.value.endswith("_queue.json")]

    @classmethod
    def evidence(cls) -> List["DeliverableType"]:
        return [d for d in cls if d.value.endswith("_evidence.md")]

    @classmethod
    def analyses(cls) -> List["DeliverableType"]:
        return [d for d in cls if d.value.endswith("_analysis.md")]

    @classmethod
    def for_agent(cls, agent_name: str) -> Optional["DeliverableType"]:
        """Map an agent name to its primary deliverable type."""
        _map = {
            "pre-recon": cls.CODE_ANALYSIS,
            "recon": cls.RECON,
            "injection-vuln": cls.INJECTION_ANALYSIS,
            "xss-vuln": cls.XSS_ANALYSIS,
            "auth-vuln": cls.AUTH_ANALYSIS,
            "ssrf-vuln": cls.SSRF_ANALYSIS,
            "authz-vuln": cls.AUTHZ_ANALYSIS,
            "injection-exploit": cls.INJECTION_EVIDENCE,
            "xss-exploit": cls.XSS_EVIDENCE,
            "auth-exploit": cls.AUTH_EVIDENCE,
            "ssrf-exploit": cls.SSRF_EVIDENCE,
            "authz-exploit": cls.AUTHZ_EVIDENCE,
        }
        return _map.get(agent_name)

    @classmethod
    def queue_for_vuln_type(cls, vuln_type: str) -> Optional["DeliverableType"]:
        """Get the queue deliverable for a vulnerability type."""
        _qmap = {
            "injection": cls.INJECTION_QUEUE,
            "xss": cls.XSS_QUEUE,
            "auth": cls.AUTH_QUEUE,
            "ssrf": cls.SSRF_QUEUE,
            "authz": cls.AUTHZ_QUEUE,
        }
        return _qmap.get(vuln_type)


class WorkspaceStatus(enum.Enum):
    """Workspace lifecycle status."""

    CREATED = "created"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    RESUMED = "resumed"
    ABORTED = "aborted"


class CheckpointAction(enum.Enum):
    """Git checkpoint action types."""

    PHASE_START = "phase_start"
    PHASE_COMPLETE = "phase_complete"
    AGENT_START = "agent_start"
    AGENT_COMPLETE = "agent_complete"
    DELIVERABLE_SAVED = "deliverable_saved"
    ROLLBACK = "rollback"
    MANUAL = "manual"


class AuditEventType(enum.Enum):
    """Structured audit event types."""

    PIPELINE_START = "pipeline_start"
    PIPELINE_COMPLETE = "pipeline_complete"
    PIPELINE_FAIL = "pipeline_fail"
    PIPELINE_ABORT = "pipeline_abort"
    PHASE_START = "phase_start"
    PHASE_COMPLETE = "phase_complete"
    PHASE_FAIL = "phase_fail"
    AGENT_START = "agent_start"
    AGENT_COMPLETE = "agent_complete"
    AGENT_FAIL = "agent_fail"
    AGENT_SKIP = "agent_skip"
    AGENT_RETRY = "agent_retry"
    CHECKPOINT_CREATE = "checkpoint_create"
    CHECKPOINT_ROLLBACK = "checkpoint_rollback"
    DELIVERABLE_SAVE = "deliverable_save"
    DELIVERABLE_VALIDATE = "deliverable_validate"
    CONFIG_LOAD = "config_load"
    CREDENTIAL_CHECK = "credential_check"
    EXPLOIT_QUEUE_CHECK = "exploit_queue_check"
    TOTP_GENERATE = "totp_generate"
    ERROR_CLASSIFY = "error_classify"
    RESUME_DETECT = "resume_detect"
    RESUME_RESTORE = "resume_restore"
    WORKSPACE_CREATE = "workspace_create"
    WORKSPACE_LIST = "workspace_list"
    PROMPT_BUILD = "prompt_build"
    METRICS_UPDATE = "metrics_update"
    CUSTOM = "custom"


# ════════════════════════════════════════════════════════════════════════
#  Section 2: Data Classes
# ════════════════════════════════════════════════════════════════════════


@dataclass
class AuditEvent:
    """A single structured audit event in the activity stream."""

    timestamp: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    event_type: str = ""
    agent: Optional[str] = None
    phase: Optional[str] = None
    message: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    duration_ms: Optional[float] = None
    success: Optional[bool] = None
    error: Optional[str] = None
    severity: str = "info"

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return {k: v for k, v in d.items() if v is not None}


@dataclass
class CheckpointInfo:
    """Info about a git checkpoint."""

    commit_hash: str = ""
    tag: str = ""
    agent: str = ""
    phase: str = ""
    action: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    files_staged: int = 0
    message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SessionState:
    """Complete session state for save/load/resume."""

    session_id: str = field(default_factory=lambda: f"siren-{int(time.time() * 1000)}")
    workspace_name: str = ""
    workspace_path: str = ""
    target_url: str = ""
    repo_path: str = ""
    status: str = WorkspaceStatus.CREATED.value
    pipeline_state: str = "IDLE"
    created_at: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    updated_at: str = ""
    completed_at: Optional[str] = None
    # Agent tracking
    agent_statuses: Dict[str, str] = field(default_factory=dict)
    agent_metrics: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    completed_agents: List[str] = field(default_factory=list)
    failed_agents: List[str] = field(default_factory=list)
    skipped_agents: List[str] = field(default_factory=list)
    # Deliverables
    deliverables: Dict[str, str] = field(default_factory=dict)
    # Checkpoints
    checkpoints: List[Dict[str, Any]] = field(default_factory=list)
    last_checkpoint: Optional[str] = None
    # Resume
    resume_count: int = 0
    resume_history: List[Dict[str, Any]] = field(default_factory=list)
    # Config
    config_file: Optional[str] = None
    config_hash: Optional[str] = None
    # Model info
    model_tiers: Dict[str, str] = field(default_factory=dict)
    provider: str = "unknown"
    # Totals
    total_tokens: int = 0
    total_cost_usd: float = 0.0
    total_duration_s: float = 0.0
    total_findings: int = 0
    # Events
    events: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def update_timestamp(self) -> None:
        self.updated_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SessionState":
        known = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in known}
        return cls(**filtered)


@dataclass
class WorkspaceInfo:
    """Metadata about a workspace."""

    name: str = ""
    path: str = ""
    status: str = ""
    target_url: str = ""
    session_id: str = ""
    created_at: str = ""
    updated_at: str = ""
    completed_agents: int = 0
    total_agents: int = 13
    total_findings: int = 0
    has_report: bool = False
    size_bytes: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @property
    def progress_pct(self) -> float:
        if self.total_agents == 0:
            return 0.0
        return round((self.completed_agents / self.total_agents) * 100, 1)


@dataclass
class DeliverableInfo:
    """Metadata about a deliverable file."""

    dtype: str = ""
    filename: str = ""
    path: str = ""
    size_bytes: int = 0
    created_at: str = ""
    checksum: str = ""
    agent: Optional[str] = None
    is_valid: bool = False
    validation_errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ConfigSchema:
    """Validated configuration loaded from YAML/JSON."""

    # Authentication
    login_type: str = "none"  # none, form, sso, api, basic
    login_url: str = ""
    username: str = ""
    password: str = ""
    totp_secret: str = ""
    login_flow: List[str] = field(default_factory=list)
    success_condition_type: str = ""  # url_contains, element_present, etc.
    success_condition_value: str = ""
    # Rules
    avoid_rules: List[Dict[str, str]] = field(default_factory=list)
    focus_rules: List[Dict[str, str]] = field(default_factory=list)
    # Pipeline
    retry_preset: str = "production"
    max_concurrent_pipelines: int = 5
    # Target
    target_url: str = ""
    repo_path: str = ""
    output_dir: str = ""
    workspace: str = ""
    # Model overrides
    small_model: str = ""
    medium_model: str = ""
    large_model: str = ""
    # SIREN-specific
    attack_domains: List[str] = field(default_factory=list)
    mcp_servers: List[str] = field(default_factory=list)
    evasion_level: str = "maximum"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ConfigSchema":
        known = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in known}
        return cls(**filtered)


# ════════════════════════════════════════════════════════════════════════
#  Section 3: DeliverableManager
# ════════════════════════════════════════════════════════════════════════


class DeliverableValidator:
    """Validates deliverables by type with structural checks."""

    # Queue schema: must have {"vulnerabilities": [...]}
    QUEUE_SCHEMA_KEYS = {"vulnerabilities"}

    # Vuln entry schema: minimum required fields
    VULN_ENTRY_KEYS = {"title", "description"}

    @classmethod
    def validate(
        cls, dtype: DeliverableType, content: str, strict: bool = False
    ) -> Tuple[bool, List[str]]:
        """Validate deliverable content. Returns (is_valid, errors)."""
        errors: List[str] = []

        if not content or not content.strip():
            errors.append("Deliverable content is empty")
            return False, errors

        # Queue files must be valid JSON with vulnerabilities array
        if dtype in DeliverableType.queues():
            return cls._validate_queue(content, strict)

        # Evidence files must have proof-of-concept sections
        if dtype in DeliverableType.evidence():
            return cls._validate_evidence(content, strict)

        # Analysis files must have findings sections
        if dtype in DeliverableType.analyses():
            return cls._validate_analysis(content, strict)

        # Code analysis & recon: basic markdown checks
        if dtype in (DeliverableType.CODE_ANALYSIS, DeliverableType.RECON):
            return cls._validate_markdown(content, strict)

        return True, []

    @classmethod
    def _validate_queue(cls, content: str, strict: bool) -> Tuple[bool, List[str]]:
        errors: List[str] = []
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            errors.append(f"Invalid JSON: {e}")
            return False, errors

        if not isinstance(data, dict):
            errors.append("Queue must be a JSON object")
            return False, errors

        if "vulnerabilities" not in data:
            errors.append("Queue missing 'vulnerabilities' key")
            return False, errors

        vulns = data["vulnerabilities"]
        if not isinstance(vulns, list):
            errors.append("'vulnerabilities' must be an array")
            return False, errors

        if strict:
            for i, v in enumerate(vulns):
                if not isinstance(v, dict):
                    errors.append(f"Entry {i}: must be object")
                    continue
                missing = cls.VULN_ENTRY_KEYS - set(v.keys())
                if missing:
                    errors.append(f"Entry {i}: missing keys {missing}")

        return len(errors) == 0, errors

    @classmethod
    def _validate_evidence(cls, content: str, strict: bool) -> Tuple[bool, List[str]]:
        errors: List[str] = []

        if len(content) < 100:
            errors.append("Evidence too short (min 100 chars)")

        # Must have at least one proof-of-concept or finding section
        poc_patterns = [
            r"(?i)proof[- ]of[- ]concept",
            r"(?i)exploit(ation)?",
            r"(?i)finding",
            r"(?i)vulnerability",
            r"(?i)impact",
        ]
        found_any = any(re.search(p, content) for p in poc_patterns)
        if not found_any and strict:
            errors.append("Evidence lacks PoC/finding sections")

        return len(errors) == 0, errors

    @classmethod
    def _validate_analysis(cls, content: str, strict: bool) -> Tuple[bool, List[str]]:
        errors: List[str] = []

        if len(content) < 50:
            errors.append("Analysis too short (min 50 chars)")

        if strict:
            headers = re.findall(r"^#+\s+.+$", content, re.MULTILINE)
            if len(headers) < 2:
                errors.append("Analysis should have at least 2 markdown headers")

        return len(errors) == 0, errors

    @classmethod
    def _validate_markdown(cls, content: str, strict: bool) -> Tuple[bool, List[str]]:
        errors: List[str] = []

        if len(content) < 50:
            errors.append("Document too short (min 50 chars)")

        return len(errors) == 0, errors


class DeliverableManager:
    """Manages deliverable lifecycle: save, load, validate, merge."""

    def __init__(self, deliverables_dir: Union[str, Path]) -> None:
        self.deliverables_dir = Path(deliverables_dir)
        self.deliverables_dir.mkdir(parents=True, exist_ok=True)
        self._checksums: Dict[str, str] = {}

    def save(
        self,
        dtype: DeliverableType,
        content: str,
        validate: bool = True,
        strict: bool = False,
    ) -> DeliverableInfo:
        """Save a deliverable with optional validation."""
        info = DeliverableInfo(
            dtype=dtype.name,
            filename=dtype.value,
            path=str(self.deliverables_dir / dtype.value),
            agent=None,
            created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        )

        if validate:
            is_valid, errors = DeliverableValidator.validate(dtype, content, strict)
            info.is_valid = is_valid
            info.validation_errors = errors
            if not is_valid and strict:
                logger.warning(
                    "Deliverable %s failed strict validation: %s", dtype.name, errors
                )
                return info
        else:
            info.is_valid = True

        path = self.deliverables_dir / dtype.value
        path.write_text(content, encoding="utf-8")
        info.size_bytes = len(content.encode("utf-8"))
        info.checksum = hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]
        self._checksums[dtype.name] = info.checksum

        logger.info("Saved deliverable %s (%d bytes)", dtype.name, info.size_bytes)
        return info

    def load(self, dtype: DeliverableType) -> Optional[str]:
        """Load a deliverable's content."""
        path = self.deliverables_dir / dtype.value
        if not path.exists():
            return None
        return path.read_text(encoding="utf-8")

    def exists(self, dtype: DeliverableType) -> bool:
        """Check if a deliverable exists on disk."""
        return (self.deliverables_dir / dtype.value).exists()

    def list_all(self) -> List[DeliverableInfo]:
        """List all deliverables with metadata."""
        results: List[DeliverableInfo] = []
        for dtype in DeliverableType:
            path = self.deliverables_dir / dtype.value
            if path.exists():
                stat = path.stat()
                content = path.read_text(encoding="utf-8")
                is_valid, errors = DeliverableValidator.validate(dtype, content)
                results.append(
                    DeliverableInfo(
                        dtype=dtype.name,
                        filename=dtype.value,
                        path=str(path),
                        size_bytes=stat.st_size,
                        created_at=datetime.datetime.fromtimestamp(
                            stat.st_ctime, tz=datetime.timezone.utc
                        ).isoformat(),
                        checksum=hashlib.sha256(content.encode("utf-8")).hexdigest()[
                            :16
                        ],
                        is_valid=is_valid,
                        validation_errors=errors,
                    )
                )
        return results

    def merge_evidence(self) -> str:
        """Merge all exploitation evidence files into one report section."""
        parts: List[str] = []
        for dtype in DeliverableType.evidence():
            content = self.load(dtype)
            if content and content.strip():
                vuln_type = (
                    dtype.name.replace("_EVIDENCE", "").replace("_", " ").title()
                )
                parts.append(f"\n## {vuln_type} Exploitation Evidence\n\n{content}")

        if not parts:
            return "No exploitation evidence found."
        return "\n---\n".join(parts)

    def get_queue_vulns(self, vuln_type: str) -> List[Dict[str, Any]]:
        """Extract vulnerabilities from a queue file. Returns empty list if none."""
        queue_dtype = DeliverableType.queue_for_vuln_type(vuln_type)
        if not queue_dtype:
            return []

        content = self.load(queue_dtype)
        if not content:
            return []

        try:
            data = json.loads(content)
            vulns = data.get("vulnerabilities", [])
            return vulns if isinstance(vulns, list) else []
        except (json.JSONDecodeError, TypeError):
            return []

    def should_exploit(self, vuln_type: str) -> Tuple[bool, str]:
        """Determine if exploitation should run for a vuln type. Shannon queue gating."""
        vulns = self.get_queue_vulns(vuln_type)
        if not vulns:
            # Check if analysis deliverable exists but found nothing
            queue_dtype = DeliverableType.queue_for_vuln_type(vuln_type)
            if queue_dtype and self.exists(queue_dtype):
                return (
                    False,
                    f"Queue file exists but has 0 vulnerabilities for {vuln_type}",
                )
            # Check if analysis ran at all
            analysis_map = {
                "injection": DeliverableType.INJECTION_ANALYSIS,
                "xss": DeliverableType.XSS_ANALYSIS,
                "auth": DeliverableType.AUTH_ANALYSIS,
                "ssrf": DeliverableType.SSRF_ANALYSIS,
                "authz": DeliverableType.AUTHZ_ANALYSIS,
            }
            analysis_dtype = analysis_map.get(vuln_type)
            if analysis_dtype and not self.exists(analysis_dtype):
                return False, f"Analysis not yet complete for {vuln_type}"
            return False, f"No exploitable vulnerabilities found for {vuln_type}"

        return True, f"Found {len(vulns)} exploitable vulnerabilities for {vuln_type}"

    def clean_partial(self, agent_name: str) -> bool:
        """Clean up partial deliverables from a failed agent."""
        dtype = DeliverableType.for_agent(agent_name)
        if not dtype:
            return False
        path = self.deliverables_dir / dtype.value
        if path.exists():
            path.unlink()
            logger.info("Cleaned partial deliverable for %s", agent_name)
            return True
        return False


# ════════════════════════════════════════════════════════════════════════
#  Section 4: GitCheckpointManager
# ════════════════════════════════════════════════════════════════════════


class GitCheckpointManager:
    """Git-based checkpoint/rollback system for pipeline resilience."""

    def __init__(self, repo_path: Union[str, Path]) -> None:
        self.repo_path = Path(repo_path)
        self._initialized = False
        self._checkpoints: List[CheckpointInfo] = []

    def _run_git(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        """Execute a git command in the repo."""
        cmd = ["git"] + list(args)
        return subprocess.run(
            cmd,
            cwd=str(self.repo_path),
            capture_output=True,
            text=True,
            check=check,
            timeout=30,
        )

    def is_git_repo(self) -> bool:
        """Check if the path is a git repository."""
        try:
            result = self._run_git("rev-parse", "--is-inside-work-tree", check=False)
            return result.returncode == 0 and "true" in result.stdout.strip()
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

    def init(self) -> bool:
        """Initialize git if needed. Returns True if initialized."""
        if self.is_git_repo():
            self._initialized = True
            return True

        try:
            self._run_git("init")
            self._run_git("config", "user.email", "siren@siren.dev")
            self._run_git("config", "user.name", "SIREN Pipeline")
            # Initial commit
            self._run_git("add", "-A")
            self._run_git(
                "commit", "-m", "SIREN: Initial pipeline state", "--allow-empty"
            )
            self._initialized = True
            logger.info("Git repository initialized at %s", self.repo_path)
            return True
        except subprocess.SubprocessError as e:
            logger.error("Failed to initialize git: %s", e)
            return False

    def checkpoint(
        self,
        agent: str,
        phase: str,
        action: CheckpointAction = CheckpointAction.AGENT_COMPLETE,
        message: Optional[str] = None,
    ) -> Optional[CheckpointInfo]:
        """Create a git checkpoint after agent/phase completion."""
        if not self._initialized:
            if not self.init():
                return None

        try:
            # Stage all changes
            self._run_git("add", "-A")

            # Check if there are changes to commit
            status = self._run_git("status", "--porcelain", check=False)
            if not status.stdout.strip():
                logger.debug("No changes to checkpoint for %s", agent)
                return None

            # Count staged files
            staged = len([line for line in status.stdout.strip().split("\n") if line])

            # Create commit
            commit_msg = (
                message or f"SIREN checkpoint: {action.value} [{agent}] in {phase}"
            )
            self._run_git("commit", "-m", commit_msg)

            # Get commit hash
            result = self._run_git("rev-parse", "HEAD")
            commit_hash = result.stdout.strip()

            # Create tag
            tag = f"siren/{phase}/{agent}/{int(time.time())}"
            self._run_git("tag", tag, check=False)

            info = CheckpointInfo(
                commit_hash=commit_hash,
                tag=tag,
                agent=agent,
                phase=phase,
                action=action.value,
                files_staged=staged,
                message=commit_msg,
            )
            self._checkpoints.append(info)

            logger.info(
                "Checkpoint created: %s (%s, %d files)", commit_hash[:8], agent, staged
            )
            return info

        except subprocess.SubprocessError as e:
            logger.error("Checkpoint failed for %s: %s", agent, e)
            return None

    def rollback(self, checkpoint: CheckpointInfo) -> bool:
        """Rollback to a specific checkpoint."""
        if not self._initialized:
            return False

        try:
            target = checkpoint.tag or checkpoint.commit_hash
            self._run_git("reset", "--hard", target)
            self._run_git("clean", "-fd")
            logger.info("Rolled back to checkpoint: %s", target)
            return True
        except subprocess.SubprocessError as e:
            logger.error("Rollback failed: %s", e)
            return False

    def rollback_to_last(self) -> bool:
        """Rollback to the most recent checkpoint."""
        if not self._checkpoints:
            return False
        return self.rollback(self._checkpoints[-1])

    def rollback_to_phase(self, phase: str) -> bool:
        """Rollback to the last checkpoint of a given phase."""
        phase_checkpoints = [cp for cp in self._checkpoints if cp.phase == phase]
        if not phase_checkpoints:
            return False
        return self.rollback(phase_checkpoints[-1])

    def get_checkpoints(self) -> List[CheckpointInfo]:
        """Get all checkpoints."""
        return list(self._checkpoints)

    def get_last_checkpoint(self) -> Optional[CheckpointInfo]:
        """Get the most recent checkpoint."""
        return self._checkpoints[-1] if self._checkpoints else None

    def get_diff_since(self, checkpoint: CheckpointInfo) -> str:
        """Get diff since a specific checkpoint."""
        try:
            target = checkpoint.tag or checkpoint.commit_hash
            result = self._run_git("diff", target, "--stat", check=False)
            return result.stdout.strip()
        except subprocess.SubprocessError:
            return ""

    def get_log(self, max_entries: int = 20) -> List[Dict[str, str]]:
        """Get recent git log entries."""
        try:
            fmt = "--format=%H|%s|%aI"
            result = self._run_git("log", fmt, f"-{max_entries}", check=False)
            entries = []
            for line in result.stdout.strip().split("\n"):
                if "|" in line:
                    parts = line.split("|", 2)
                    entries.append(
                        {
                            "hash": parts[0],
                            "message": parts[1] if len(parts) > 1 else "",
                            "date": parts[2] if len(parts) > 2 else "",
                        }
                    )
            return entries
        except subprocess.SubprocessError:
            return []


# ════════════════════════════════════════════════════════════════════════
#  Section 5: AuditLogger
# ════════════════════════════════════════════════════════════════════════


class AuditLogger:
    """Structured activity stream with per-agent logs and chronological events."""

    def __init__(self, audit_dir: Union[str, Path]) -> None:
        self.audit_dir = Path(audit_dir)
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        self._agents_dir = self.audit_dir / "agents"
        self._agents_dir.mkdir(exist_ok=True)
        self._prompts_dir = self.audit_dir / "prompts"
        self._prompts_dir.mkdir(exist_ok=True)
        self._events: List[AuditEvent] = []
        self._agent_logs: Dict[str, List[Dict[str, Any]]] = {}
        self._workflow_log_path = self.audit_dir / "workflow.log"
        self._start_time = time.time()

    def emit(
        self,
        event_type: AuditEventType,
        message: str,
        agent: Optional[str] = None,
        phase: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
        duration_ms: Optional[float] = None,
        success: Optional[bool] = None,
        error: Optional[str] = None,
        severity: str = "info",
    ) -> AuditEvent:
        """Emit a structured audit event."""
        event = AuditEvent(
            event_type=event_type.value,
            agent=agent,
            phase=phase,
            message=message,
            data=data or {},
            duration_ms=duration_ms,
            success=success,
            error=error,
            severity=severity,
        )
        self._events.append(event)

        # Per-agent log
        if agent:
            if agent not in self._agent_logs:
                self._agent_logs[agent] = []
            self._agent_logs[agent].append(event.to_dict())

        # Workflow log (append line)
        elapsed = time.time() - self._start_time
        with open(self._workflow_log_path, "a", encoding="utf-8") as f:
            f.write(
                f"[{event.timestamp}] [{elapsed:.1f}s] "
                f"[{severity.upper()}] [{event_type.value}] "
                f"{message}\n"
            )

        return event

    def log_agent_start(self, agent: str, phase: str) -> AuditEvent:
        return self.emit(
            AuditEventType.AGENT_START,
            f"Agent '{agent}' starting in phase '{phase}'",
            agent=agent,
            phase=phase,
        )

    def log_agent_complete(
        self, agent: str, phase: str, duration_ms: float, metrics: Optional[Dict] = None
    ) -> AuditEvent:
        return self.emit(
            AuditEventType.AGENT_COMPLETE,
            f"Agent '{agent}' completed in {duration_ms:.0f}ms",
            agent=agent,
            phase=phase,
            duration_ms=duration_ms,
            success=True,
            data=metrics or {},
        )

    def log_agent_fail(
        self, agent: str, phase: str, error: str, duration_ms: float
    ) -> AuditEvent:
        return self.emit(
            AuditEventType.AGENT_FAIL,
            f"Agent '{agent}' failed: {error}",
            agent=agent,
            phase=phase,
            error=error,
            duration_ms=duration_ms,
            success=False,
            severity="error",
        )

    def log_agent_skip(self, agent: str, phase: str, reason: str) -> AuditEvent:
        return self.emit(
            AuditEventType.AGENT_SKIP,
            f"Agent '{agent}' skipped: {reason}",
            agent=agent,
            phase=phase,
            severity="warn",
        )

    def log_agent_retry(
        self, agent: str, phase: str, attempt: int, error: str
    ) -> AuditEvent:
        return self.emit(
            AuditEventType.AGENT_RETRY,
            f"Agent '{agent}' retry #{attempt}: {error}",
            agent=agent,
            phase=phase,
            severity="warn",
            data={"attempt": attempt},
        )

    def log_phase_start(self, phase: str, agents: List[str]) -> AuditEvent:
        return self.emit(
            AuditEventType.PHASE_START,
            f"Phase '{phase}' starting with {len(agents)} agents",
            phase=phase,
            data={"agents": agents},
        )

    def log_phase_complete(
        self, phase: str, duration_ms: float, agents_completed: int
    ) -> AuditEvent:
        return self.emit(
            AuditEventType.PHASE_COMPLETE,
            f"Phase '{phase}' completed ({agents_completed} agents, {duration_ms:.0f}ms)",
            phase=phase,
            duration_ms=duration_ms,
            success=True,
            data={"agents_completed": agents_completed},
        )

    def log_exploit_queue_check(
        self, vuln_type: str, should_exploit: bool, reason: str
    ) -> AuditEvent:
        return self.emit(
            AuditEventType.EXPLOIT_QUEUE_CHECK,
            f"Exploit queue check for '{vuln_type}': {'PROCEED' if should_exploit else 'SKIP'} — {reason}",
            data={
                "vuln_type": vuln_type,
                "should_exploit": should_exploit,
                "reason": reason,
            },
        )

    def save_agent_prompt(self, agent: str, prompt: str) -> Path:
        """Save the prompt used for an agent execution."""
        path = self._prompts_dir / f"{agent}_prompt.md"
        path.write_text(prompt, encoding="utf-8")
        self.emit(
            AuditEventType.PROMPT_BUILD,
            f"Saved prompt for '{agent}' ({len(prompt)} chars)",
            agent=agent,
        )
        return path

    def save_agent_execution(self, agent: str, data: Dict[str, Any]) -> Path:
        """Save agent execution details (metrics, output, etc)."""
        path = self._agents_dir / f"{agent}_execution.json"
        path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        return path

    def get_events(
        self,
        event_type: Optional[AuditEventType] = None,
        agent: Optional[str] = None,
        phase: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
    ) -> List[AuditEvent]:
        """Filter events by criteria."""
        filtered = self._events
        if event_type:
            filtered = [e for e in filtered if e.event_type == event_type.value]
        if agent:
            filtered = [e for e in filtered if e.agent == agent]
        if phase:
            filtered = [e for e in filtered if e.phase == phase]
        if severity:
            filtered = [e for e in filtered if e.severity == severity]
        return filtered[-limit:]

    def get_agent_log(self, agent: str) -> List[Dict[str, Any]]:
        """Get all events for a specific agent."""
        return self._agent_logs.get(agent, [])

    def get_timeline(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get chronological event timeline."""
        return [e.to_dict() for e in self._events[-limit:]]

    def get_summary(self) -> Dict[str, Any]:
        """Get audit summary statistics."""
        elapsed = time.time() - self._start_time
        by_type: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        agents_seen: Set[str] = set()
        errors: List[str] = []

        for e in self._events:
            by_type[e.event_type] = by_type.get(e.event_type, 0) + 1
            by_severity[e.severity] = by_severity.get(e.severity, 0) + 1
            if e.agent:
                agents_seen.add(e.agent)
            if e.error:
                errors.append(f"[{e.agent or 'system'}] {e.error}")

        return {
            "total_events": len(self._events),
            "elapsed_s": round(elapsed, 1),
            "events_by_type": by_type,
            "events_by_severity": by_severity,
            "agents_seen": sorted(agents_seen),
            "error_count": len(errors),
            "recent_errors": errors[-5:],
        }

    def flush_all(self) -> None:
        """Flush all logs to disk."""
        # Save per-agent logs
        for agent, logs in self._agent_logs.items():
            path = self._agents_dir / f"{agent}_audit.json"
            path.write_text(json.dumps(logs, indent=2, default=str), encoding="utf-8")

        # Save full event stream
        events_path = self.audit_dir / "events.json"
        events_path.write_text(
            json.dumps([e.to_dict() for e in self._events], indent=2, default=str),
            encoding="utf-8",
        )

        # Save summary
        summary_path = self.audit_dir / "audit_summary.json"
        summary_path.write_text(
            json.dumps(self.get_summary(), indent=2, default=str),
            encoding="utf-8",
        )


# ════════════════════════════════════════════════════════════════════════
#  Section 6: SessionStateMachine
# ════════════════════════════════════════════════════════════════════════


class SessionStateMachine:
    """Full save/load/update session state with resume detection."""

    SESSION_FILE = "session.json"

    def __init__(self, workspace_path: Union[str, Path]) -> None:
        self.workspace_path = Path(workspace_path)
        self._session_file = self.workspace_path / self.SESSION_FILE
        self._state: Optional[SessionState] = None
        self._dirty = False

    @property
    def state(self) -> Optional[SessionState]:
        return self._state

    def create(
        self,
        target_url: str = "",
        repo_path: str = "",
        workspace_name: str = "",
    ) -> SessionState:
        """Create a new session state."""
        self._state = SessionState(
            workspace_name=workspace_name or self.workspace_path.name,
            workspace_path=str(self.workspace_path),
            target_url=target_url,
            repo_path=repo_path,
        )
        self._dirty = True
        return self._state

    def load(self) -> Optional[SessionState]:
        """Load session state from disk. Returns None if file doesn't exist."""
        if not self._session_file.exists():
            return None

        try:
            data = json.loads(self._session_file.read_text(encoding="utf-8"))
            self._state = SessionState.from_dict(data)
            self._dirty = False
            logger.info(
                "Loaded session state: %s (status=%s, completed=%d agents)",
                self._state.session_id,
                self._state.status,
                len(self._state.completed_agents),
            )
            return self._state
        except (json.JSONDecodeError, TypeError, KeyError) as e:
            logger.error("Failed to load session state: %s", e)
            return None

    def save(self) -> bool:
        """Save current session state to disk."""
        if not self._state:
            return False

        self._state.update_timestamp()
        self.workspace_path.mkdir(parents=True, exist_ok=True)

        try:
            self._session_file.write_text(
                json.dumps(self._state.to_dict(), indent=2, default=str),
                encoding="utf-8",
            )
            self._dirty = False
            return True
        except OSError as e:
            logger.error("Failed to save session state: %s", e)
            return False

    def update_agent_status(
        self,
        agent: str,
        status: str,
        metrics: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Update an agent's status in the session state."""
        if not self._state:
            return

        self._state.agent_statuses[agent] = status
        if metrics:
            self._state.agent_metrics[agent] = metrics

        if status == "completed" and agent not in self._state.completed_agents:
            self._state.completed_agents.append(agent)
        elif status == "failed" and agent not in self._state.failed_agents:
            self._state.failed_agents.append(agent)
        elif status == "skipped" and agent not in self._state.skipped_agents:
            self._state.skipped_agents.append(agent)

        self._dirty = True

    def update_pipeline_state(self, pipeline_state: str) -> None:
        """Update the pipeline state."""
        if not self._state:
            return
        self._state.pipeline_state = pipeline_state
        self._dirty = True

    def update_status(self, status: WorkspaceStatus) -> None:
        """Update workspace status."""
        if not self._state:
            return
        self._state.status = status.value
        self._dirty = True

    def add_checkpoint(self, checkpoint: CheckpointInfo) -> None:
        """Record a checkpoint in the session."""
        if not self._state:
            return
        self._state.checkpoints.append(checkpoint.to_dict())
        self._state.last_checkpoint = checkpoint.commit_hash
        self._dirty = True

    def add_deliverable(self, dtype: DeliverableType, path: str) -> None:
        """Record a deliverable in the session."""
        if not self._state:
            return
        self._state.deliverables[dtype.name] = path
        self._dirty = True

    def add_event(self, event: AuditEvent) -> None:
        """Record an audit event in the session."""
        if not self._state:
            return
        self._state.events.append(event.to_dict())
        self._dirty = True

    def record_resume(self, reason: str = "") -> None:
        """Record a resume attempt."""
        if not self._state:
            return
        self._state.resume_count += 1
        self._state.resume_history.append(
            {
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "resume_number": self._state.resume_count,
                "reason": reason,
                "completed_agents_at_resume": list(self._state.completed_agents),
            }
        )
        self._state.status = WorkspaceStatus.RESUMED.value
        self._dirty = True

    def detect_resume(self) -> Tuple[bool, Dict[str, Any]]:
        """Detect if this is a resume scenario. Returns (is_resume, resume_info)."""
        loaded = self.load()
        if not loaded:
            return False, {}

        # A resume is detected if there's a previous session with completed agents
        if loaded.completed_agents:
            resume_info = {
                "session_id": loaded.session_id,
                "previous_status": loaded.status,
                "completed_agents": loaded.completed_agents,
                "failed_agents": loaded.failed_agents,
                "skipped_agents": loaded.skipped_agents,
                "resume_count": loaded.resume_count + 1,
                "last_checkpoint": loaded.last_checkpoint,
                "pipeline_state": loaded.pipeline_state,
            }
            return True, resume_info

        return False, {}

    def get_agents_to_skip(self) -> Set[str]:
        """Get set of agents that should be skipped on resume (already completed)."""
        if not self._state:
            return set()
        return set(self._state.completed_agents)

    def mark_complete(self, total_findings: int = 0) -> None:
        """Mark the session as complete."""
        if not self._state:
            return
        self._state.status = WorkspaceStatus.COMPLETED.value
        self._state.completed_at = datetime.datetime.now(
            datetime.timezone.utc
        ).isoformat()
        self._state.total_findings = total_findings
        self._dirty = True
        self.save()

    def mark_failed(self, error: str = "") -> None:
        """Mark the session as failed."""
        if not self._state:
            return
        self._state.status = WorkspaceStatus.FAILED.value
        self._state.events.append(
            {
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "event_type": "pipeline_fail",
                "message": f"Pipeline failed: {error}",
                "severity": "error",
            }
        )
        self._dirty = True
        self.save()

    def auto_save(self) -> None:
        """Save if dirty."""
        if self._dirty:
            self.save()


# ════════════════════════════════════════════════════════════════════════
#  Section 7: ConfigFileLoader
# ════════════════════════════════════════════════════════════════════════


class ConfigFileLoader:
    """YAML/JSON config file discovery, loading, and schema validation."""

    CONFIG_FILENAMES = [
        "siren.config.yaml",
        "siren.config.yml",
        "siren.config.json",
        "shannon.config.yaml",
        "shannon.config.yml",
        "shannon.config.json",
        "siren.config.yaml",
        "siren.config.yml",
        "siren.config.json",
        ".siren.yaml",
        ".siren.yml",
        ".siren.json",
    ]

    # JSON Schema for config validation (draft-07 compatible)
    SCHEMA = {
        "type": "object",
        "properties": {
            "authentication": {
                "type": "object",
                "properties": {
                    "login_type": {
                        "type": "string",
                        "enum": ["none", "form", "sso", "api", "basic"],
                    },
                    "login_url": {"type": "string", "format": "uri"},
                    "credentials": {
                        "type": "object",
                        "properties": {
                            "username": {"type": "string"},
                            "password": {"type": "string"},
                            "totp_secret": {"type": "string"},
                        },
                    },
                    "login_flow": {
                        "type": "array",
                        "items": {"type": "string"},
                        "maxItems": 20,
                    },
                    "success_condition": {
                        "type": "object",
                        "properties": {
                            "type": {
                                "type": "string",
                                "enum": [
                                    "url_contains",
                                    "element_present",
                                    "url_equals_exactly",
                                    "text_contains",
                                ],
                            },
                            "value": {"type": "string"},
                        },
                    },
                },
            },
            "rules": {
                "type": "object",
                "properties": {
                    "avoid": {
                        "type": "array",
                        "maxItems": 50,
                        "items": {
                            "type": "object",
                            "properties": {
                                "description": {"type": "string", "maxLength": 200},
                                "type": {
                                    "type": "string",
                                    "enum": [
                                        "path",
                                        "subdomain",
                                        "domain",
                                        "method",
                                        "header",
                                        "parameter",
                                    ],
                                },
                                "url_path": {"type": "string", "maxLength": 1000},
                            },
                            "required": ["description", "type"],
                        },
                    },
                    "focus": {
                        "type": "array",
                        "maxItems": 50,
                        "items": {
                            "type": "object",
                            "properties": {
                                "description": {"type": "string", "maxLength": 200},
                                "type": {
                                    "type": "string",
                                    "enum": [
                                        "path",
                                        "subdomain",
                                        "domain",
                                        "method",
                                        "header",
                                        "parameter",
                                    ],
                                },
                                "url_path": {"type": "string", "maxLength": 1000},
                            },
                            "required": ["description", "type"],
                        },
                    },
                },
            },
            "pipeline": {
                "type": "object",
                "properties": {
                    "retry_preset": {
                        "type": "string",
                        "enum": ["production", "testing", "subscription", "preflight"],
                    },
                    "max_concurrent_pipelines": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 5,
                    },
                },
            },
            "target": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "format": "uri"},
                    "repo": {"type": "string"},
                    "output": {"type": "string"},
                    "workspace": {"type": "string"},
                },
            },
            "models": {
                "type": "object",
                "properties": {
                    "small": {"type": "string"},
                    "medium": {"type": "string"},
                    "large": {"type": "string"},
                },
            },
            "siren": {
                "type": "object",
                "properties": {
                    "domains": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "mcp_servers": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "evasion_level": {
                        "type": "string",
                        "enum": ["none", "basic", "moderate", "aggressive", "maximum"],
                    },
                },
            },
        },
    }

    @classmethod
    def discover(cls, search_paths: Optional[List[str]] = None) -> Optional[Path]:
        """Auto-discover config file. Searches current dir, project root, configs/."""
        dirs_to_search: List[Path] = []

        if search_paths:
            dirs_to_search.extend(Path(p) for p in search_paths)

        # Default search locations
        dirs_to_search.extend(
            [
                Path.cwd(),
                Path.cwd() / "configs",
                Path.cwd().parent,
            ]
        )

        for search_dir in dirs_to_search:
            if not search_dir.is_dir():
                continue
            for filename in cls.CONFIG_FILENAMES:
                candidate = search_dir / filename
                if candidate.is_file():
                    logger.info("Discovered config: %s", candidate)
                    return candidate

        return None

    @classmethod
    def load(
        cls,
        path: Optional[Union[str, Path]] = None,
        search_paths: Optional[List[str]] = None,
    ) -> Tuple[Optional[ConfigSchema], List[str]]:
        """Load and validate a config file. Returns (config, errors)."""
        errors: List[str] = []

        # Discover if no path given
        if path is None:
            path = cls.discover(search_paths)
            if path is None:
                return None, ["No config file found"]
        else:
            path = Path(path)

        if not path.is_file():
            return None, [f"Config file not found: {path}"]

        # Load based on extension
        try:
            content = path.read_text(encoding="utf-8")
            ext = path.suffix.lower()

            if ext in (".yaml", ".yml"):
                data = cls._parse_yaml(content)
            elif ext == ".json":
                data = json.loads(content)
            else:
                return None, [f"Unsupported config format: {ext}"]
        except Exception as e:
            return None, [f"Failed to parse config: {e}"]

        if not isinstance(data, dict):
            return None, ["Config must be a JSON/YAML object"]

        # Validate
        validation_errors = cls._validate(data)
        if validation_errors:
            errors.extend(validation_errors)

        # Map to ConfigSchema
        try:
            config = cls._map_to_schema(data)
            logger.info("Config loaded from %s", path)
            return config, errors
        except Exception as e:
            return None, [f"Failed to map config: {e}"]

    @classmethod
    def _parse_yaml(cls, content: str) -> Dict[str, Any]:
        """Parse YAML content. Falls back to basic parser if PyYAML not available."""
        try:
            import yaml

            return yaml.safe_load(content) or {}
        except ImportError:
            # Fallback: basic YAML-like parser for simple flat structures
            return cls._basic_yaml_parse(content)

    @classmethod
    def _basic_yaml_parse(cls, content: str) -> Dict[str, Any]:
        """Minimal YAML parser for basic key-value configs (fallback)."""
        result: Dict[str, Any] = {}
        current_section: Optional[str] = None
        current_subsection: Optional[str] = None

        for line in content.split("\n"):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            indent = len(line) - len(line.lstrip())

            if indent == 0 and ":" in stripped:
                key, _, val = stripped.partition(":")
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if val:
                    result[key] = val
                else:
                    result[key] = {}
                    current_section = key
                    current_subsection = None

            elif indent == 2 and current_section and ":" in stripped:
                key, _, val = stripped.partition(":")
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if not isinstance(result.get(current_section), dict):
                    result[current_section] = {}
                if val:
                    result[current_section][key] = val
                else:
                    result[current_section][key] = {}
                    current_subsection = key

            elif (
                indent == 4
                and current_section
                and current_subsection
                and ":" in stripped
            ):
                key, _, val = stripped.partition(":")
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                section = result.get(current_section, {})
                if isinstance(section, dict):
                    subsec = section.get(current_subsection, {})
                    if isinstance(subsec, dict):
                        subsec[key] = val
                        section[current_subsection] = subsec
                        result[current_section] = section

            elif stripped.startswith("- "):
                item = stripped[2:].strip().strip('"').strip("'")
                if current_subsection and current_section:
                    section = result.get(current_section, {})
                    if isinstance(section, dict):
                        target = section.get(current_subsection)
                        if not isinstance(target, list):
                            target = []
                        target.append(item)
                        section[current_subsection] = target
                        result[current_section] = section
                elif current_section:
                    section = result.get(current_section)
                    if not isinstance(section, list):
                        section = []
                    section.append(item)
                    result[current_section] = section

        return result

    @classmethod
    def _validate(cls, data: Dict[str, Any]) -> List[str]:
        """Validate config against schema. Returns list of errors."""
        errors: List[str] = []

        # Auth validation
        auth = data.get("authentication", {})
        if isinstance(auth, dict):
            login_type = auth.get("login_type", "none")
            valid_types = ["none", "form", "sso", "api", "basic"]
            if login_type not in valid_types:
                errors.append(f"Invalid login_type: {login_type}")

            if login_type != "none":
                creds = auth.get("credentials", {})
                if not creds.get("username") and not creds.get("password"):
                    errors.append("Non-none login_type requires credentials")

            flow = auth.get("login_flow", [])
            if isinstance(flow, list) and len(flow) > 20:
                errors.append("login_flow exceeds 20 steps")

        # Rules validation
        rules = data.get("rules", {})
        if isinstance(rules, dict):
            for rule_type in ("avoid", "focus"):
                rule_list = rules.get(rule_type, [])
                if isinstance(rule_list, list):
                    if len(rule_list) > 50:
                        errors.append(f"rules.{rule_type} exceeds 50 entries")
                    for i, rule in enumerate(rule_list):
                        if isinstance(rule, dict):
                            if "description" not in rule:
                                errors.append(
                                    f"rules.{rule_type}[{i}]: missing description"
                                )
                            rule_subtype = rule.get("type", "")
                            valid_rule_types = [
                                "path",
                                "subdomain",
                                "domain",
                                "method",
                                "header",
                                "parameter",
                            ]
                            if rule_subtype and rule_subtype not in valid_rule_types:
                                errors.append(
                                    f"rules.{rule_type}[{i}]: invalid type '{rule_subtype}'"
                                )

        # Pipeline validation
        pipeline = data.get("pipeline", {})
        if isinstance(pipeline, dict):
            preset = pipeline.get("retry_preset")
            if preset and preset not in [
                "production",
                "testing",
                "subscription",
                "preflight",
            ]:
                errors.append(f"Invalid retry_preset: {preset}")

            concurrency = pipeline.get("max_concurrent_pipelines")
            if concurrency is not None:
                try:
                    c = int(concurrency)
                    if c < 1 or c > 5:
                        errors.append("max_concurrent_pipelines must be 1-5")
                except (TypeError, ValueError):
                    errors.append("max_concurrent_pipelines must be integer")

        return errors

    @classmethod
    def _map_to_schema(cls, data: Dict[str, Any]) -> ConfigSchema:
        """Map raw config dict to ConfigSchema dataclass."""
        config = ConfigSchema()

        # Authentication
        auth = data.get("authentication", {})
        if isinstance(auth, dict):
            config.login_type = auth.get("login_type", "none")
            config.login_url = auth.get("login_url", "")
            creds = auth.get("credentials", {})
            if isinstance(creds, dict):
                config.username = creds.get("username", "")
                config.password = creds.get("password", "")
                config.totp_secret = creds.get("totp_secret", "")
            flow = auth.get("login_flow", [])
            if isinstance(flow, list):
                config.login_flow = flow
            sc = auth.get("success_condition", {})
            if isinstance(sc, dict):
                config.success_condition_type = sc.get("type", "")
                config.success_condition_value = sc.get("value", "")

        # Rules
        rules = data.get("rules", {})
        if isinstance(rules, dict):
            config.avoid_rules = rules.get("avoid", [])
            config.focus_rules = rules.get("focus", [])

        # Pipeline
        pipeline = data.get("pipeline", {})
        if isinstance(pipeline, dict):
            config.retry_preset = pipeline.get("retry_preset", "production")
            config.max_concurrent_pipelines = int(
                pipeline.get("max_concurrent_pipelines", 5)
            )

        # Target
        target = data.get("target", {})
        if isinstance(target, dict):
            config.target_url = target.get("url", "")
            config.repo_path = target.get("repo", "")
            config.output_dir = target.get("output", "")
            config.workspace = target.get("workspace", "")

        # Models
        models = data.get("models", {})
        if isinstance(models, dict):
            config.small_model = models.get("small", "")
            config.medium_model = models.get("medium", "")
            config.large_model = models.get("large", "")

        # SIREN
        lev = data.get("siren", {})
        if isinstance(lev, dict):
            config.attack_domains = lev.get("domains", [])
            config.mcp_servers = lev.get("mcp_servers", [])
            config.evasion_level = lev.get("evasion_level", "maximum")

        return config

    @classmethod
    def generate_example(cls) -> str:
        """Generate an example config file."""
        return """# SIREN Configuration File
# Shannon Intelligence Recon & Exploitation Nexus
# ──────────────────────────────────────────────

authentication:
  login_type: form  # none, form, sso, api, basic
  login_url: "https://your-app.com/login"
  credentials:
    username: "test@example.com"
    password: "yourpassword"
    totp_secret: ""  # Base32 TOTP secret for 2FA

  login_flow:
    - "Type $username into the email field"
    - "Type $password into the password field"
    - "Click the 'Sign In' button"

  success_condition:
    type: url_contains  # url_contains, element_present, url_equals_exactly, text_contains
    value: "/dashboard"

rules:
  avoid:
    - description: "Skip logout endpoints"
      type: path
      url_path: "/logout"
    - description: "Skip admin deletion"
      type: path
      url_path: "/admin/delete"

  focus:
    - description: "Focus on API endpoints"
      type: path
      url_path: "/api"
    - description: "Focus on authentication"
      type: path
      url_path: "/auth"

pipeline:
  retry_preset: production  # production, testing, subscription, preflight
  max_concurrent_pipelines: 5  # 1-5

target:
  url: "https://your-app.com"
  repo: "your-repo"
  output: "./audit-logs"
  workspace: ""  # auto-generated if empty

models:
  small: ""   # Override: claude-haiku-4-5-20251001
  medium: ""  # Override: claude-sonnet-4-6
  large: ""   # Override: claude-opus-4-6

siren:
  domains:
    - "web_exploitation"
    - "network_ops"
    - "crypto_warfare"
    - "social_engineering"
  mcp_servers: []  # Override MCP servers
  evasion_level: maximum  # none, basic, moderate, aggressive, maximum
"""


# ════════════════════════════════════════════════════════════════════════
#  Section 8: WorkspaceManager
# ════════════════════════════════════════════════════════════════════════


class WorkspaceManager:
    """Workspace lifecycle: create, discover, list, status, cleanup."""

    DEFAULT_AUDIT_DIR = "audit-logs"

    def __init__(self, base_dir: Optional[Union[str, Path]] = None) -> None:
        self.base_dir = (
            Path(base_dir) if base_dir else Path.cwd() / self.DEFAULT_AUDIT_DIR
        )
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def create(
        self,
        target_url: str,
        workspace_name: Optional[str] = None,
    ) -> Tuple[Path, SessionStateMachine]:
        """Create a new workspace. Returns (workspace_path, session_machine)."""
        if workspace_name:
            name = workspace_name
        else:
            # Auto-generate: hostname_session-id
            from urllib.parse import urlparse

            hostname = urlparse(target_url).hostname or "unknown"
            hostname = re.sub(r"[^a-zA-Z0-9.-]", "_", hostname)
            name = f"{hostname}_siren-{int(time.time() * 1000)}"

        workspace_path = self.base_dir / name
        workspace_path.mkdir(parents=True, exist_ok=True)

        # Create standard subdirectories
        (workspace_path / "deliverables").mkdir(exist_ok=True)
        (workspace_path / "agents").mkdir(exist_ok=True)
        (workspace_path / "prompts").mkdir(exist_ok=True)

        # Initialize session
        session = SessionStateMachine(workspace_path)
        session.create(
            target_url=target_url,
            workspace_name=name,
        )
        session.save()

        logger.info("Created workspace: %s", workspace_path)
        return workspace_path, session

    def find(self, workspace_name: str) -> Optional[Path]:
        """Find a workspace by name."""
        candidate = self.base_dir / workspace_name
        if candidate.is_dir():
            return candidate
        return None

    def resume(
        self,
        workspace_name: str,
        target_url: Optional[str] = None,
    ) -> Tuple[Optional[Path], Optional[SessionStateMachine], Dict[str, Any]]:
        """Resume a workspace. Returns (path, session, resume_info)."""
        workspace_path = self.find(workspace_name)
        if not workspace_path:
            return None, None, {"error": f"Workspace not found: {workspace_name}"}

        session = SessionStateMachine(workspace_path)
        is_resume, resume_info = session.detect_resume()

        if not is_resume:
            return workspace_path, session, {"error": "No previous session to resume"}

        # Cross-check target URL
        if target_url and session.state:
            if session.state.target_url and session.state.target_url != target_url:
                return (
                    None,
                    None,
                    {
                        "error": (
                            f"URL mismatch: workspace has '{session.state.target_url}' "
                            f"but got '{target_url}'"
                        )
                    },
                )

        session.record_resume()
        session.save()

        return workspace_path, session, resume_info

    def list_all(self) -> List[WorkspaceInfo]:
        """List all workspaces with metadata."""
        workspaces: List[WorkspaceInfo] = []

        if not self.base_dir.is_dir():
            return workspaces

        for item in sorted(self.base_dir.iterdir()):
            if not item.is_dir():
                continue

            info = WorkspaceInfo(
                name=item.name,
                path=str(item),
            )

            # Try to load session
            session_file = item / "session.json"
            if session_file.is_file():
                try:
                    data = json.loads(session_file.read_text(encoding="utf-8"))
                    info.session_id = data.get("session_id", "")
                    info.status = data.get("status", "unknown")
                    info.target_url = data.get("target_url", "")
                    info.created_at = data.get("created_at", "")
                    info.updated_at = data.get("updated_at", "")
                    info.completed_agents = len(data.get("completed_agents", []))
                    info.total_findings = data.get("total_findings", 0)
                except (json.JSONDecodeError, TypeError):
                    info.status = "corrupted"

            # Check for report
            report_path = item / "deliverables" / "ABYSSAL_REPORT.md"
            info.has_report = report_path.exists()

            # Calculate size
            try:
                info.size_bytes = sum(
                    f.stat().st_size for f in item.rglob("*") if f.is_file()
                )
            except OSError:
                info.size_bytes = 0

            workspaces.append(info)

        return workspaces

    def cleanup(self, workspace_name: str, force: bool = False) -> bool:
        """Remove a workspace. Only removes failed/completed unless force=True."""
        workspace_path = self.find(workspace_name)
        if not workspace_path:
            return False

        if not force:
            session_file = workspace_path / "session.json"
            if session_file.is_file():
                try:
                    data = json.loads(session_file.read_text(encoding="utf-8"))
                    status = data.get("status", "")
                    if status not in ("completed", "failed", "aborted"):
                        logger.warning(
                            "Cannot cleanup workspace '%s' with status '%s' "
                            "(use force=True)",
                            workspace_name,
                            status,
                        )
                        return False
                except (json.JSONDecodeError, TypeError):
                    pass

        shutil.rmtree(workspace_path, ignore_errors=True)
        logger.info("Cleaned up workspace: %s", workspace_name)
        return True

    def get_status(self, workspace_name: str) -> Dict[str, Any]:
        """Get detailed status of a workspace."""
        workspace_path = self.find(workspace_name)
        if not workspace_path:
            return {"error": f"Workspace not found: {workspace_name}"}

        session = SessionStateMachine(workspace_path)
        state = session.load()
        if not state:
            return {"error": "No session state found", "path": str(workspace_path)}

        # Deliverable inventory
        deliverables_dir = workspace_path / "deliverables"
        deliverable_status: Dict[str, str] = {}
        for dtype in DeliverableType:
            path = deliverables_dir / dtype.value
            if path.exists():
                content = path.read_text(encoding="utf-8")
                is_valid, _ = DeliverableValidator.validate(dtype, content)
                deliverable_status[dtype.name] = "valid" if is_valid else "invalid"
            else:
                deliverable_status[dtype.name] = "missing"

        return {
            "session_id": state.session_id,
            "workspace_name": state.workspace_name,
            "status": state.status,
            "pipeline_state": state.pipeline_state,
            "target_url": state.target_url,
            "created_at": state.created_at,
            "updated_at": state.updated_at,
            "completed_at": state.completed_at,
            "agents": {
                "completed": state.completed_agents,
                "failed": state.failed_agents,
                "skipped": state.skipped_agents,
                "total_completed": len(state.completed_agents),
                "total_failed": len(state.failed_agents),
                "total_skipped": len(state.skipped_agents),
                "statuses": state.agent_statuses,
            },
            "deliverables": deliverable_status,
            "checkpoints": len(state.checkpoints),
            "resume_count": state.resume_count,
            "totals": {
                "tokens": state.total_tokens,
                "cost_usd": state.total_cost_usd,
                "duration_s": state.total_duration_s,
                "findings": state.total_findings,
            },
            "model_tiers": state.model_tiers,
            "provider": state.provider,
        }
