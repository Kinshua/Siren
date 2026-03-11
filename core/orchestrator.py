"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  SIREN — Advanced Orchestrator, Error Classification & Smart Pipeline      ║
║                                                                              ║
║  This module completes the Shannon → SIREN integration with:                 ║
║                                                                              ║
║  • ErrorClassifier       — retryable vs non-retryable error taxonomy         ║
║  • ExploitationGate      — queue-based vuln→exploit gating                   ║
║  • PromptManager         — template engine with token budget & context       ║
║  • TOTPGenerator         — RFC 6238/4226 TOTP code generation                ║
║  • ActivityStream        — real-time event bus with progress & ETA           ║
║  • ProgressTracker       — live percentage, throughput, ETA estimation        ║
║  • SirenOrchestrator     — master controller combining ALL systems           ║
║                                                                              ║
║  Shannon provides the BRAIN. SIREN provides the BODY.                    ║
║  Together they are SIREN — the perfect predator.                             ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import asyncio
import base64
import datetime
import enum
import hashlib
import hmac
import json
import logging
import os
import re
import struct
import time
import traceback
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import (
    Any,
    Callable,
    Coroutine,
    Dict,
    List,
    Optional,
    Set,
    Tuple,
    Union,
)

from .workspace import (
    AuditEvent,
    AuditEventType,
    AuditLogger,
    CheckpointAction,
    ConfigFileLoader,
    ConfigSchema,
    DeliverableManager,
    DeliverableType,
    DeliverableValidator,
    GitCheckpointManager,
    SessionState,
    SessionStateMachine,
    WorkspaceManager,
    WorkspaceStatus,
)

logger = logging.getLogger("siren.orchestrator")


# ════════════════════════════════════════════════════════════════════════
#  Section 1: Error Classification
# ════════════════════════════════════════════════════════════════════════


class ErrorCode(enum.Enum):
    """Comprehensive error taxonomy from Shannon's architecture."""

    # Configuration
    CONFIG_NOT_FOUND = "config_not_found"
    CONFIG_VALIDATION_FAILED = "config_validation_failed"
    CONFIG_PARSE_ERROR = "config_parse_error"
    # Agent execution
    AGENT_EXECUTION_FAILED = "agent_execution_failed"
    AGENT_TIMEOUT = "agent_timeout"
    OUTPUT_VALIDATION_FAILED = "output_validation_failed"
    # API / Provider
    API_RATE_LIMITED = "api_rate_limited"
    API_OVERLOADED = "api_overloaded"
    SPENDING_CAP_REACHED = "spending_cap_reached"
    INSUFFICIENT_CREDITS = "insufficient_credits"
    BILLING_ERROR = "billing_error"
    # Auth
    AUTH_FAILED = "auth_failed"
    PERMISSION_DENIED = "permission_denied"
    # Request
    INVALID_REQUEST = "invalid_request"
    REQUEST_TOO_LARGE = "request_too_large"
    # Git
    GIT_CHECKPOINT_FAILED = "git_checkpoint_failed"
    GIT_ROLLBACK_FAILED = "git_rollback_failed"
    # Resources
    PROMPT_LOAD_FAILED = "prompt_load_failed"
    DELIVERABLE_NOT_FOUND = "deliverable_not_found"
    REPO_NOT_FOUND = "repo_not_found"
    # Execution
    EXECUTION_LIMIT = "execution_limit"
    NETWORK_ERROR = "network_error"
    TIMEOUT = "timeout"
    # Internal
    INTERNAL_ERROR = "internal_error"
    UNKNOWN = "unknown"


class ErrorSeverity(enum.Enum):
    """Error severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    FATAL = "fatal"


@dataclass
class ClassifiedError:
    """A classified error with retry/severity metadata."""

    code: ErrorCode
    message: str
    severity: ErrorSeverity
    retryable: bool
    suggested_delay_s: float = 0.0
    max_retries: int = 0
    original_error: Optional[str] = None
    traceback_str: Optional[str] = None
    context: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code.value,
            "message": self.message,
            "severity": self.severity.value,
            "retryable": self.retryable,
            "suggested_delay_s": self.suggested_delay_s,
            "max_retries": self.max_retries,
            "original_error": self.original_error,
            "context": self.context,
        }


class ErrorClassifier:
    """Classifies exceptions into retryable vs non-retryable categories.

    This implements Shannon's error classification system that decides
    whether to retry, abort, or skip based on error type.
    """

    # Pattern → (ErrorCode, retryable, severity, delay_s, max_retries)
    _PATTERNS: List[Tuple[str, ErrorCode, bool, ErrorSeverity, float, int]] = [
        # API Rate Limiting (retryable, long delay)
        (
            r"(?i)rate.?limit|429|too many requests|throttled",
            ErrorCode.API_RATE_LIMITED,
            True,
            ErrorSeverity.MEDIUM,
            60.0,
            50,
        ),
        (
            r"(?i)overloaded|503|service unavailable|capacity",
            ErrorCode.API_OVERLOADED,
            True,
            ErrorSeverity.MEDIUM,
            30.0,
            20,
        ),
        # Billing / Spending (non-retryable)
        (
            r"(?i)spending.?cap|budget.?exceeded|credit.?limit",
            ErrorCode.SPENDING_CAP_REACHED,
            False,
            ErrorSeverity.FATAL,
            0,
            0,
        ),
        (
            r"(?i)insufficient.?credits|no.?credits|payment.?required",
            ErrorCode.INSUFFICIENT_CREDITS,
            False,
            ErrorSeverity.FATAL,
            0,
            0,
        ),
        (
            r"(?i)billing|subscription.?expired",
            ErrorCode.BILLING_ERROR,
            False,
            ErrorSeverity.FATAL,
            0,
            0,
        ),
        # Authentication (non-retryable)
        (
            r"(?i)auth(entication)?.?(failed|error|invalid)|401|unauthorized",
            ErrorCode.AUTH_FAILED,
            False,
            ErrorSeverity.CRITICAL,
            0,
            0,
        ),
        (
            r"(?i)permission.?(denied|error)|403|forbidden",
            ErrorCode.PERMISSION_DENIED,
            False,
            ErrorSeverity.CRITICAL,
            0,
            0,
        ),
        # Request issues (non-retryable)
        (
            r"(?i)invalid.?request|400|bad request|malformed",
            ErrorCode.INVALID_REQUEST,
            False,
            ErrorSeverity.HIGH,
            0,
            0,
        ),
        (
            r"(?i)too.?large|413|payload|content.?length",
            ErrorCode.REQUEST_TOO_LARGE,
            False,
            ErrorSeverity.HIGH,
            0,
            0,
        ),
        # Timeout (retryable, moderate delay)
        (
            r"(?i)timeout|timed?.?out|deadline.?exceeded",
            ErrorCode.TIMEOUT,
            True,
            ErrorSeverity.MEDIUM,
            10.0,
            5,
        ),
        # Network (retryable, short delay)
        (
            r"(?i)connect(ion)?.?(refused|reset|error|failed)|ECONNR|network",
            ErrorCode.NETWORK_ERROR,
            True,
            ErrorSeverity.MEDIUM,
            5.0,
            10,
        ),
        # Git (retryable once)
        (
            r"(?i)git.?(checkpoint|commit|add).?(failed|error)",
            ErrorCode.GIT_CHECKPOINT_FAILED,
            True,
            ErrorSeverity.HIGH,
            2.0,
            2,
        ),
        (
            r"(?i)git.?(rollback|reset).?(failed|error)",
            ErrorCode.GIT_ROLLBACK_FAILED,
            True,
            ErrorSeverity.HIGH,
            2.0,
            1,
        ),
        # Config (non-retryable)
        (
            r"(?i)config.?(not.?found|missing)",
            ErrorCode.CONFIG_NOT_FOUND,
            False,
            ErrorSeverity.CRITICAL,
            0,
            0,
        ),
        (
            r"(?i)config.?(validation|invalid|schema)",
            ErrorCode.CONFIG_VALIDATION_FAILED,
            False,
            ErrorSeverity.CRITICAL,
            0,
            0,
        ),
        (
            r"(?i)config.?(parse|syntax|yaml|json).?(error|failed)",
            ErrorCode.CONFIG_PARSE_ERROR,
            False,
            ErrorSeverity.CRITICAL,
            0,
            0,
        ),
        # Resources (non-retryable)
        (
            r"(?i)prompt.?(load|file|template).?(failed|error|missing)",
            ErrorCode.PROMPT_LOAD_FAILED,
            False,
            ErrorSeverity.HIGH,
            0,
            0,
        ),
        (
            r"(?i)deliverable.?(not.?found|missing)",
            ErrorCode.DELIVERABLE_NOT_FOUND,
            False,
            ErrorSeverity.HIGH,
            0,
            0,
        ),
        (
            r"(?i)repo(sitory)?.?(not.?found|missing|invalid)",
            ErrorCode.REPO_NOT_FOUND,
            False,
            ErrorSeverity.CRITICAL,
            0,
            0,
        ),
        # Agent execution (retryable)
        (
            r"(?i)agent.?(execution|run).?(failed|error|crashed)",
            ErrorCode.AGENT_EXECUTION_FAILED,
            True,
            ErrorSeverity.HIGH,
            15.0,
            3,
        ),
        (
            r"(?i)output.?(validation|format).?(failed|error|invalid)",
            ErrorCode.OUTPUT_VALIDATION_FAILED,
            True,
            ErrorSeverity.MEDIUM,
            5.0,
            2,
        ),
    ]

    @classmethod
    def classify(
        cls,
        error: Union[Exception, str],
        context: Optional[Dict[str, Any]] = None,
    ) -> ClassifiedError:
        """Classify an error into a structured category with retry guidance."""
        error_str = str(error)
        tb_str = None

        if isinstance(error, Exception):
            tb_str = traceback.format_exception(type(error), error, error.__traceback__)
            tb_str = "".join(tb_str) if tb_str else None

        # Match against patterns
        for pattern, code, retryable, severity, delay, max_ret in cls._PATTERNS:
            if re.search(pattern, error_str):
                return ClassifiedError(
                    code=code,
                    message=error_str,
                    severity=severity,
                    retryable=retryable,
                    suggested_delay_s=delay,
                    max_retries=max_ret,
                    original_error=error_str,
                    traceback_str=tb_str,
                    context=context or {},
                )

        # Default: internal error, retryable once
        return ClassifiedError(
            code=ErrorCode.UNKNOWN,
            message=error_str,
            severity=ErrorSeverity.HIGH,
            retryable=True,
            suggested_delay_s=10.0,
            max_retries=1,
            original_error=error_str,
            traceback_str=tb_str,
            context=context or {},
        )

    @classmethod
    def is_retryable(cls, error: Union[Exception, str]) -> bool:
        """Quick check: is this error retryable?"""
        return cls.classify(error).retryable

    @classmethod
    def get_delay(cls, error: Union[Exception, str], attempt: int = 1) -> float:
        """Get suggested delay with exponential backoff for retries."""
        classified = cls.classify(error)
        if not classified.retryable:
            return 0.0
        # Exponential backoff with jitter
        base = classified.suggested_delay_s
        delay = base * (2 ** (attempt - 1))
        # Cap at 30 minutes
        delay = min(delay, 1800)
        # Add 10% jitter
        import random

        jitter = delay * 0.1 * random.random()
        return delay + jitter

    @classmethod
    def should_retry(
        cls,
        error: Union[Exception, str],
        attempt: int,
    ) -> Tuple[bool, float]:
        """Should we retry? Returns (should_retry, delay_seconds)."""
        classified = cls.classify(error)
        if not classified.retryable:
            return False, 0.0
        if attempt > classified.max_retries:
            return False, 0.0
        delay = cls.get_delay(error, attempt)
        return True, delay


# ════════════════════════════════════════════════════════════════════════
#  Section 2: Exploitation Gate (Queue-based vuln→exploit gating)
# ════════════════════════════════════════════════════════════════════════


@dataclass
class ExploitDecision:
    """Decision about whether to proceed with exploitation."""

    vuln_type: str
    should_exploit: bool
    reason: str
    vuln_count: int = 0
    high_severity_count: int = 0
    queue_path: Optional[str] = None
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # Don't include full vulns in summary
        d["vulnerabilities"] = len(self.vulnerabilities)
        return d


class ExploitationGate:
    """Queue-based gating: only exploit if vuln analysis found actual vulns.

    Shannon's core insight: don't waste time/money running exploit agents
    when the vuln analysis agent found nothing exploitable.
    """

    VULN_TYPES = ["injection", "xss", "auth", "ssrf", "authz"]

    def __init__(self, deliverable_mgr: DeliverableManager) -> None:
        self._dm = deliverable_mgr
        self._decisions: Dict[str, ExploitDecision] = {}

    def check(self, vuln_type: str) -> ExploitDecision:
        """Check if exploitation should proceed for a vuln type."""
        if vuln_type not in self.VULN_TYPES:
            decision = ExploitDecision(
                vuln_type=vuln_type,
                should_exploit=False,
                reason=f"Unknown vulnerability type: {vuln_type}",
            )
            self._decisions[vuln_type] = decision
            return decision

        should, reason = self._dm.should_exploit(vuln_type)
        vulns = self._dm.get_queue_vulns(vuln_type)

        # Count high severity
        high_sev = sum(
            1
            for v in vulns
            if isinstance(v, dict)
            and v.get("severity", "").lower() in ("critical", "high")
        )

        decision = ExploitDecision(
            vuln_type=vuln_type,
            should_exploit=should,
            reason=reason,
            vuln_count=len(vulns),
            high_severity_count=high_sev,
            queue_path=str(
                self._dm.deliverables_dir
                / (
                    DeliverableType.queue_for_vuln_type(vuln_type)
                    or DeliverableType.INJECTION_QUEUE
                ).value
            ),
            vulnerabilities=vulns,
        )
        self._decisions[vuln_type] = decision

        logger.info(
            "Exploitation gate for '%s': %s (%d vulns, %d high severity)",
            vuln_type,
            "PROCEED" if should else "SKIP",
            len(vulns),
            high_sev,
        )
        return decision

    def check_all(self) -> Dict[str, ExploitDecision]:
        """Check all vuln types at once."""
        return {vt: self.check(vt) for vt in self.VULN_TYPES}

    def get_decisions(self) -> Dict[str, ExploitDecision]:
        """Get all decisions made so far."""
        return dict(self._decisions)

    def get_exploitable_types(self) -> List[str]:
        """Get list of vuln types that should be exploited."""
        return [vt for vt, d in self._decisions.items() if d.should_exploit]

    def get_skipped_types(self) -> List[str]:
        """Get list of vuln types that should be skipped."""
        return [vt for vt, d in self._decisions.items() if not d.should_exploit]

    def get_summary(self) -> Dict[str, Any]:
        """Summary of all exploitation decisions."""
        return {
            "total_checked": len(self._decisions),
            "proceed": len(self.get_exploitable_types()),
            "skip": len(self.get_skipped_types()),
            "decisions": {vt: d.to_dict() for vt, d in self._decisions.items()},
        }


# ════════════════════════════════════════════════════════════════════════
#  Section 3: TOTP Generator
# ════════════════════════════════════════════════════════════════════════


class TOTPGenerator:
    """RFC 6238/4226 TOTP code generation for 2FA bypass testing.

    Pure Python implementation — no external dependencies.
    Generates time-based one-time passwords from Base32 secrets.
    """

    DEFAULT_DIGITS = 6
    DEFAULT_PERIOD = 30
    DEFAULT_ALGORITHM = "sha1"

    @classmethod
    def generate(
        cls,
        secret: str,
        digits: int = DEFAULT_DIGITS,
        period: int = DEFAULT_PERIOD,
        algorithm: str = DEFAULT_ALGORITHM,
        timestamp: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Generate a TOTP code.

        Args:
            secret: Base32-encoded TOTP secret
            digits: Number of digits (default 6)
            period: Time step in seconds (default 30)
            algorithm: Hash algorithm (sha1, sha256, sha512)
            timestamp: Override current time (for testing)

        Returns:
            Dict with 'code', 'expires_in', 'period', 'valid_until'
        """
        # Validate and decode secret
        secret_bytes = cls._decode_secret(secret)

        # Get current time counter
        now = timestamp or time.time()
        counter = int(now) // period

        # Generate HOTP
        code = cls._hotp(secret_bytes, counter, digits, algorithm)

        # Calculate expiry
        expires_in = period - (int(now) % period)

        return {
            "code": code,
            "expires_in": expires_in,
            "period": period,
            "valid_until": datetime.datetime.fromtimestamp(
                (counter + 1) * period, tz=datetime.timezone.utc
            ).isoformat(),
            "algorithm": algorithm,
            "digits": digits,
        }

    @classmethod
    def generate_code(cls, secret: str) -> str:
        """Simple interface: just get the 6-digit code string."""
        result = cls.generate(secret)
        return result["code"]

    @classmethod
    def generate_with_window(
        cls,
        secret: str,
        window: int = 1,
        digits: int = DEFAULT_DIGITS,
        period: int = DEFAULT_PERIOD,
        algorithm: str = DEFAULT_ALGORITHM,
    ) -> List[Dict[str, Any]]:
        """Generate codes for current time ± window steps.

        Useful for tolerating clock skew between server and client.
        """
        now = time.time()
        counter = int(now) // period
        results = []

        for offset in range(-window, window + 1):
            ts = (counter + offset) * period
            result = cls.generate(secret, digits, period, algorithm, ts + 1)
            result["offset"] = offset
            result["counter"] = counter + offset
            results.append(result)

        return results

    @classmethod
    def verify(
        cls,
        secret: str,
        code: str,
        window: int = 1,
        digits: int = DEFAULT_DIGITS,
        period: int = DEFAULT_PERIOD,
        algorithm: str = DEFAULT_ALGORITHM,
    ) -> bool:
        """Verify a TOTP code with clock skew tolerance."""
        codes = cls.generate_with_window(secret, window, digits, period, algorithm)
        return any(c["code"] == code for c in codes)

    @classmethod
    def validate_secret(cls, secret: str) -> Tuple[bool, str]:
        """Validate that a string is a valid Base32 TOTP secret."""
        if not secret:
            return False, "Secret is empty"

        # Remove spaces and convert to uppercase
        cleaned = secret.replace(" ", "").upper()

        # Add padding if needed
        padding = len(cleaned) % 8
        if padding:
            cleaned += "=" * (8 - padding)

        # Check Base32 characters
        valid_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=")
        invalid = set(cleaned) - valid_chars
        if invalid:
            return False, f"Invalid Base32 characters: {invalid}"

        try:
            decoded = base64.b32decode(cleaned)
            if len(decoded) < 10:
                return False, f"Secret too short ({len(decoded)} bytes, minimum 10)"
            return True, f"Valid ({len(decoded)} bytes)"
        except Exception as e:
            return False, f"Base32 decode failed: {e}"

    @classmethod
    def _decode_secret(cls, secret: str) -> bytes:
        """Decode a Base32 secret, handling common formatting issues."""
        cleaned = secret.replace(" ", "").replace("-", "").upper()
        # Add padding
        padding = len(cleaned) % 8
        if padding:
            cleaned += "=" * (8 - padding)
        return base64.b32decode(cleaned)

    @classmethod
    def _hotp(
        cls,
        secret: bytes,
        counter: int,
        digits: int,
        algorithm: str,
    ) -> str:
        """Generate HOTP code (RFC 4226)."""
        # Pack counter as 8-byte big-endian
        counter_bytes = struct.pack(">Q", counter)

        # HMAC
        algo_map = {
            "sha1": "sha1",
            "sha256": "sha256",
            "sha512": "sha512",
        }
        algo = algo_map.get(algorithm, "sha1")
        mac = hmac.new(secret, counter_bytes, algo).digest()

        # Dynamic truncation
        offset = mac[-1] & 0x0F
        code_int = struct.unpack(">I", mac[offset : offset + 4])[0]
        code_int &= 0x7FFFFFFF
        code_int %= 10**digits

        return str(code_int).zfill(digits)

    @classmethod
    def generate_secret(cls, length: int = 20) -> str:
        """Generate a random Base32 TOTP secret."""
        random_bytes = os.urandom(length)
        return base64.b32encode(random_bytes).decode("ascii").rstrip("=")


# ════════════════════════════════════════════════════════════════════════
#  Section 4: Prompt Manager
# ════════════════════════════════════════════════════════════════════════


@dataclass
class PromptContext:
    """All context available for prompt template interpolation."""

    # Target
    target_url: str = ""
    repo_path: str = ""
    # Authentication
    login_type: str = "none"
    login_url: str = ""
    username: str = ""
    password: str = ""
    totp_secret: str = ""
    login_flow: List[str] = field(default_factory=list)
    success_condition: str = ""
    # Rules
    avoid_rules: List[Dict[str, str]] = field(default_factory=list)
    focus_rules: List[Dict[str, str]] = field(default_factory=list)
    # Prior deliverables
    code_analysis: str = ""
    recon_data: str = ""
    vuln_analysis: str = ""
    exploitation_queue: str = ""
    evidence_files: Dict[str, str] = field(default_factory=dict)
    # SIREN context
    attack_domains: List[str] = field(default_factory=list)
    mcp_servers: List[str] = field(default_factory=list)
    evasion_level: str = "maximum"
    available_tools: List[str] = field(default_factory=list)
    # Agent info
    agent_name: str = ""
    agent_phase: str = ""
    vuln_type: str = ""
    model_tier: str = "medium"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class PromptManager:
    """Advanced prompt template engine with token budget management.

    Features:
    - External template files (optional) or inline defaults
    - Variable interpolation with $variable and {{variable}} syntax
    - Token budget estimation and context window management
    - Shared partial templates (_rules, _target, _exploit-scope, etc.)
    - Context-aware truncation to fit model limits
    """

    # Token limits per model tier (approximate)
    TOKEN_LIMITS = {
        "small": 200_000,  # Haiku
        "medium": 200_000,  # Sonnet
        "large": 200_000,  # Opus
    }

    # Max output tokens per tier
    MAX_OUTPUT_TOKENS = {
        "small": 8_192,
        "medium": 64_000,
        "large": 64_000,
    }

    # Shared template parts
    SHARED_TARGET = """
## Target Information
- **URL**: {target_url}
- **Repository**: {repo_path}
"""

    SHARED_RULES = """
## Testing Rules

### Areas to Avoid
{avoid_rules_text}

### Areas to Focus
{focus_rules_text}
"""

    SHARED_AUTH = """
## Authentication Context
- **Login Type**: {login_type}
- **Login URL**: {login_url}
- **Username**: {username}
- **Login Flow**:
{login_flow_text}
- **Success Condition**: {success_condition}
"""

    SHARED_EXPLOIT_SCOPE = """
## Exploitation Scope
- Only exploit vulnerabilities identified in the vulnerability analysis phase
- Provide reproducible, copy-and-paste Proof-of-Concepts
- If a hypothesis cannot be exploited, discard it as a false positive
- Focus on demonstrating real impact, not theoretical risk
"""

    SHARED_VULN_SCOPE = """
## Vulnerability Analysis Scope
- Perform structured data flow analysis: trace user input to dangerous sinks
- For each potential vulnerability, document:
  - Entry point (source)
  - Processing path
  - Dangerous function (sink)
  - Exploitability assessment
- Output a queue of hypothesized exploitable paths
"""

    SHARED_ARSENAL = """
## SIREN Integration
- **Available Domains**: {domains_text}
- **MCP Servers**: {mcp_count} servers available
- **Evasion Level**: {evasion_level}
- **Available Tools**: {tools_text}
"""

    def __init__(
        self,
        templates_dir: Optional[Union[str, Path]] = None,
    ) -> None:
        self._templates_dir = Path(templates_dir) if templates_dir else None
        self._cache: Dict[str, str] = {}

    def build_prompt(
        self,
        agent_name: str,
        context: PromptContext,
    ) -> str:
        """Build a complete prompt for an agent with full context."""
        # Try external template first
        template = self._load_external_template(agent_name)
        if not template:
            template = self._get_default_template(agent_name)

        # Build shared sections
        sections = self._build_sections(context)

        # Interpolate
        prompt = self._interpolate(template, context, sections)

        # Token budget check
        prompt = self._enforce_token_budget(prompt, context.model_tier, agent_name)

        return prompt

    def estimate_tokens(self, text: str) -> int:
        """Estimate token count with content-type-aware heuristics.

        Uses different chars-per-token ratios based on content analysis:
        - Code (lots of symbols/braces): ~3.2 chars/token
        - JSON: ~3.0 chars/token
        - Markdown w/ code blocks: ~3.5 chars/token
        - Plain English: ~4.0 chars/token
        - Mixed: ~3.7 chars/token
        """
        if not text:
            return 0

        length = len(text)

        # Detect content type from heuristics
        code_indicators = (
            text.count("{") + text.count("}") + text.count("(") + text.count(")")
        )
        code_ratio = code_indicators / max(length, 1)

        json_ratio = text.count('":') / max(length, 1)
        code_block_count = text.count("```")

        if json_ratio > 0.005:
            chars_per_token = 3.0
        elif code_ratio > 0.03 or code_block_count > 4:
            chars_per_token = 3.2
        elif code_block_count > 0:
            chars_per_token = 3.5
        elif any(c in text for c in ("#", "**", "- ", "| ")):
            chars_per_token = 3.8
        else:
            chars_per_token = 4.0

        # Adjust for non-ASCII (non-English text uses more tokens)
        non_ascii = sum(1 for c in text if ord(c) > 127)
        non_ascii_ratio = non_ascii / max(length, 1)
        if non_ascii_ratio > 0.1:
            chars_per_token *= 0.6  # Non-Latin chars ≈ more tokens

        return max(1, int(length / chars_per_token))

    def get_remaining_budget(self, current_prompt: str, model_tier: str) -> int:
        """How many tokens are left for the model to use."""
        used = self.estimate_tokens(current_prompt)
        limit = self.TOKEN_LIMITS.get(model_tier, 200_000)
        output_reserve = self.MAX_OUTPUT_TOKENS.get(model_tier, 64_000)
        return max(0, limit - used - output_reserve)

    def _load_external_template(self, agent_name: str) -> Optional[str]:
        """Load template from external file if available."""
        if not self._templates_dir:
            return None

        # Map agent names to template filenames (Shannon convention)
        file_map = {
            "pre-recon": "pre-recon-code.txt",
            "recon": "recon.txt",
            "injection-vuln": "vuln-injection.txt",
            "xss-vuln": "vuln-xss.txt",
            "auth-vuln": "vuln-auth.txt",
            "ssrf-vuln": "vuln-ssrf.txt",
            "authz-vuln": "vuln-authz.txt",
            "injection-exploit": "exploit-injection.txt",
            "xss-exploit": "exploit-xss.txt",
            "auth-exploit": "exploit-auth.txt",
            "ssrf-exploit": "exploit-ssrf.txt",
            "authz-exploit": "exploit-authz.txt",
            "report": "report-executive.txt",
        }

        filename = file_map.get(agent_name)
        if not filename:
            return None

        path = self._templates_dir / filename
        if path.is_file():
            if agent_name not in self._cache:
                self._cache[agent_name] = path.read_text(encoding="utf-8")
            return self._cache[agent_name]
        return None

    def _get_default_template(self, agent_name: str) -> str:
        """Get default inline template for an agent."""
        templates = {
            "pre-recon": """# SIREN Pre-Reconnaissance — Code Analysis

You are an expert security analyst performing white-box code analysis.

{shared_target}
{shared_rules}
{shared_siren}

## Objectives
1. Map the complete application architecture
2. Identify all entry points (API endpoints, forms, WebSocket handlers)
3. Document the technology stack and frameworks
4. Identify authentication mechanisms
5. Map data flows from input sources to sensitive sinks
6. Note any security-relevant configurations or patterns

## Output
Produce a comprehensive code analysis deliverable in Markdown format.
""",
            "recon": """# SIREN Reconnaissance — Live Application Exploration

You are an expert penetration tester performing active reconnaissance.

{shared_target}
{shared_auth}
{shared_rules}
{shared_siren}

## Prior Work
{code_analysis}

## Objectives
1. Navigate the live application via browser automation
2. Identify all accessible endpoints and functionality
3. Map authentication flows and session management
4. Fingerprint technologies (web server, framework, WAF)
5. Discover hidden paths, admin panels, debug endpoints
6. Document the complete attack surface

## Output
Produce a reconnaissance deliverable in Markdown format.
""",
            "injection-vuln": """# SIREN Vulnerability Analysis — Injection

You are an expert security analyst hunting for injection vulnerabilities.

{shared_target}
{shared_rules}
{shared_vuln_scope}
{shared_siren}

## Prior Work
{code_analysis}
{recon_data}

## Injection Types to Analyze
- SQL Injection (SQLi) — all variants (Union, Boolean, Time-based, Error-based)
- Command Injection (OS command injection, shell injection)
- Code Injection (eval, exec, template injection)
- SSTI (Server-Side Template Injection)
- NoSQL Injection
- LDAP Injection
- XPath Injection

## Output
1. Vulnerability analysis report (Markdown)
2. Exploitation queue (JSON): {{"vulnerabilities": [...]}}
""",
            "xss-vuln": """# SIREN Vulnerability Analysis — Cross-Site Scripting (XSS)

You are an expert security analyst hunting for XSS vulnerabilities.

{shared_target}
{shared_rules}
{shared_vuln_scope}
{shared_siren}

## Prior Work
{code_analysis}
{recon_data}

## XSS Types to Analyze
- Reflected XSS
- Stored XSS
- DOM-based XSS
- Self-XSS (note but lower priority)
- Context-specific: HTML, attribute, JavaScript, URL, CSS

## Output
1. Vulnerability analysis report (Markdown)
2. Exploitation queue (JSON): {{"vulnerabilities": [...]}}
""",
            "auth-vuln": """# SIREN Vulnerability Analysis — Authentication & Authorization

You are an expert security analyst hunting for auth vulnerabilities.

{shared_target}
{shared_auth}
{shared_rules}
{shared_vuln_scope}
{shared_siren}

## Prior Work
{code_analysis}
{recon_data}

## Auth Vulnerability Types
- Default/weak credentials
- Credential stuffing potential
- Account enumeration via timing or response differences
- Session fixation and prediction
- JWT vulnerabilities (alg:none, weak keys, algorithm confusion)
- CSRF in state-changing operations
- Broken access control / IDOR
- OAuth/SSO vulnerabilities
- MFA bypass techniques
- Password reset poisoning

## Output
1. Vulnerability analysis report (Markdown)
2. Exploitation queue (JSON): {{"vulnerabilities": [...]}}
""",
            "ssrf-vuln": """# SIREN Vulnerability Analysis — Server-Side Request Forgery (SSRF)

You are an expert security analyst hunting for SSRF vulnerabilities.

{shared_target}
{shared_rules}
{shared_vuln_scope}
{shared_siren}

## Prior Work
{code_analysis}
{recon_data}

## SSRF Analysis Scope
- Direct SSRF (user-controlled URL in server request)
- Blind SSRF (no direct response, use out-of-band detection)
- SSRF via redirects and URL parsing inconsistencies
- SSRF in PDF generation, image processing, webhooks
- Protocol smuggling (file://, gopher://, dict://)
- Cloud metadata endpoints (169.254.169.254, etc.)
- Internal service discovery

## Output
1. Vulnerability analysis report (Markdown)
2. Exploitation queue (JSON): {{"vulnerabilities": [...]}}
""",
            "authz-vuln": """# SIREN Vulnerability Analysis — Authorization

You are an expert security analyst hunting for authorization flaws.

{shared_target}
{shared_auth}
{shared_rules}
{shared_vuln_scope}
{shared_siren}

## Prior Work
{code_analysis}
{recon_data}

## Authorization Analysis Scope
- IDOR (Insecure Direct Object References)
- Horizontal privilege escalation (user A accessing user B data)
- Vertical privilege escalation (user → admin)
- Force browsing / path traversal for authorization bypass
- Mass assignment in update operations
- API endpoint authorization bypass
- GraphQL authorization issues
- Role-based access control (RBAC) bypass

## Output
1. Vulnerability analysis report (Markdown)
2. Exploitation queue (JSON): {{"vulnerabilities": [...]}}
""",
        }

        # Exploitation agent templates
        for vtype in ["injection", "xss", "auth", "ssrf", "authz"]:
            templates[
                f"{vtype}-exploit"
            ] = f"""# SIREN Exploitation — {vtype.upper()}

You are an expert penetration tester executing exploitation attacks.

{{shared_target}}
{{shared_auth}}
{{shared_exploit_scope}}
{{shared_siren}}

## Vulnerability Queue
{{exploitation_queue}}

## Objectives
1. For each vulnerability in the queue, attempt real exploitation
2. Use browser automation and command-line tools
3. Provide copy-and-paste Proof-of-Concept for each confirmed vulnerability
4. Record all evidence (screenshots, HTTP requests/responses, extracted data)
5. If a vulnerability cannot be exploited, discard it — "No Exploit, No Report"

## Output
Produce an exploitation evidence report in Markdown format with:
- Vulnerability title + severity
- Step-by-step exploitation steps
- Proof-of-Concept (curl commands, scripts, payloads)
- Impact demonstration (data extracted, access gained)
"""

        templates[
            "report"
        ] = """# SIREN Reporting — Executive Security Assessment

You are compiling the final penetration test report.

{shared_target}

## Exploitation Evidence
{evidence_files_text}

## Objectives
1. Compile all validated findings into a professional report
2. Only include vulnerabilities with confirmed exploitation
3. For each finding, include:
   - Title and CVSS score
   - Description and impact
   - Proof-of-Concept (copy-and-paste ready)
   - Remediation guidance
4. Executive summary with risk overview
5. Severity distribution chart

## Output
Produce a comprehensive security assessment report in Markdown.
"""

        return templates.get(
            agent_name, f"# Agent: {agent_name}\n\nNo template available."
        )

    def _build_sections(self, ctx: PromptContext) -> Dict[str, str]:
        """Build reusable prompt sections from context."""
        # Avoid rules text
        avoid_text = "None specified"
        if ctx.avoid_rules:
            avoid_text = "\n".join(
                f"- {r.get('description', 'N/A')} (type: {r.get('type', 'path')}, "
                f"path: {r.get('url_path', 'N/A')})"
                for r in ctx.avoid_rules
            )

        # Focus rules text
        focus_text = "None specified"
        if ctx.focus_rules:
            focus_text = "\n".join(
                f"- {r.get('description', 'N/A')} (type: {r.get('type', 'path')}, "
                f"path: {r.get('url_path', 'N/A')})"
                for r in ctx.focus_rules
            )

        # Login flow text
        login_flow_text = "N/A"
        if ctx.login_flow:
            login_flow_text = "\n".join(
                f"  {i+1}. {step}" for i, step in enumerate(ctx.login_flow)
            )

        # Evidence files text
        evidence_text = "No evidence files yet."
        if ctx.evidence_files:
            parts = []
            for name, content in ctx.evidence_files.items():
                parts.append(f"\n### {name}\n\n{content}")
            evidence_text = "\n".join(parts)

        # Domains text
        domains_text = (
            ", ".join(ctx.attack_domains) if ctx.attack_domains else "All"
        )
        tools_text = (
            ", ".join(ctx.available_tools[:20]) if ctx.available_tools else "711+ tools"
        )
        mcp_count = len(ctx.mcp_servers) if ctx.mcp_servers else 50

        return {
            "shared_target": self.SHARED_TARGET.format(
                target_url=ctx.target_url, repo_path=ctx.repo_path
            ),
            "shared_rules": self.SHARED_RULES.format(
                avoid_rules_text=avoid_text, focus_rules_text=focus_text
            ),
            "shared_auth": self.SHARED_AUTH.format(
                login_type=ctx.login_type,
                login_url=ctx.login_url,
                username=ctx.username or "N/A",
                login_flow_text=login_flow_text,
                success_condition=ctx.success_condition or "N/A",
            ),
            "shared_exploit_scope": self.SHARED_EXPLOIT_SCOPE,
            "shared_vuln_scope": self.SHARED_VULN_SCOPE,
            "shared_siren": self.SHARED_ARSENAL.format(
                domains_text=domains_text,
                mcp_count=mcp_count,
                evasion_level=ctx.evasion_level,
                tools_text=tools_text,
            ),
            "code_analysis": ctx.code_analysis or "Not available yet.",
            "recon_data": ctx.recon_data or "Not available yet.",
            "vuln_analysis": ctx.vuln_analysis or "Not available yet.",
            "exploitation_queue": ctx.exploitation_queue or '{"vulnerabilities": []}',
            "evidence_files_text": evidence_text,
        }

    def _interpolate(
        self,
        template: str,
        ctx: PromptContext,
        sections: Dict[str, str],
    ) -> str:
        """Interpolate template with context and sections."""
        result = template

        # Replace {section_name} references
        for key, value in sections.items():
            result = result.replace(f"{{{key}}}", value)

        # Replace remaining context variables
        ctx_dict = ctx.to_dict()
        for key, value in ctx_dict.items():
            if isinstance(value, str):
                result = result.replace(f"{{{key}}}", value)
                result = result.replace(f"${key}", value)
                result = result.replace(f"{{{{{key}}}}}", value)

        return result

    def _enforce_token_budget(
        self,
        prompt: str,
        model_tier: str,
        agent_name: str,
    ) -> str:
        """Truncate prompt if it exceeds token budget."""
        tokens = self.estimate_tokens(prompt)
        limit = self.TOKEN_LIMITS.get(model_tier, 200_000)
        output_reserve = self.MAX_OUTPUT_TOKENS.get(model_tier, 64_000)
        budget = limit - output_reserve

        if tokens <= budget:
            return prompt

        # Need to truncate
        excess = tokens - budget
        logger.warning(
            "Prompt for '%s' exceeds budget by ~%d tokens. Truncating.",
            agent_name,
            excess,
        )

        # Truncate from the end of the largest section
        target_chars = budget * 4  # approximate
        if len(prompt) > target_chars:
            prompt = prompt[:target_chars]
            prompt += "\n\n[... content truncated to fit context window ...]\n"

        return prompt


# ════════════════════════════════════════════════════════════════════════
#  Section 5: Activity Stream & Progress Tracker
# ════════════════════════════════════════════════════════════════════════


@dataclass
class ProgressSnapshot:
    """Live progress snapshot."""

    timestamp: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )
    phase: str = ""
    current_agent: Optional[str] = None
    # Counts
    agents_completed: int = 0
    agents_failed: int = 0
    agents_skipped: int = 0
    agents_running: int = 0
    agents_pending: int = 0
    agents_total: int = 13
    # Progress
    percent_complete: float = 0.0
    # Timing
    elapsed_s: float = 0.0
    estimated_remaining_s: float = 0.0
    estimated_total_s: float = 0.0
    # Throughput
    agents_per_minute: float = 0.0
    # Cost
    total_cost_usd: float = 0.0
    total_tokens: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ProgressTracker:
    """Real-time progress tracking with ETA estimation."""

    def __init__(self, total_agents: int = 13) -> None:
        self.total_agents = total_agents
        self._start_time = time.time()
        self._phase = "idle"
        self._current_agent: Optional[str] = None
        self._completed: Set[str] = set()
        self._failed: Set[str] = set()
        self._skipped: Set[str] = set()
        self._running: Set[str] = set()
        self._agent_durations: Dict[str, float] = {}
        self._total_cost = 0.0
        self._total_tokens = 0
        self._callbacks: List[Callable[[ProgressSnapshot], None]] = []

    def on_progress(self, callback: Callable[[ProgressSnapshot], None]) -> None:
        """Register a progress callback."""
        self._callbacks.append(callback)

    def set_phase(self, phase: str) -> None:
        self._phase = phase

    def agent_start(self, agent: str) -> None:
        self._current_agent = agent
        self._running.add(agent)
        self._notify()

    def agent_complete(
        self, agent: str, duration_s: float, cost_usd: float = 0, tokens: int = 0
    ) -> None:
        self._running.discard(agent)
        self._completed.add(agent)
        self._agent_durations[agent] = duration_s
        self._total_cost += cost_usd
        self._total_tokens += tokens
        if self._current_agent == agent:
            self._current_agent = None
        self._notify()

    def agent_fail(self, agent: str, duration_s: float) -> None:
        self._running.discard(agent)
        self._failed.add(agent)
        self._agent_durations[agent] = duration_s
        if self._current_agent == agent:
            self._current_agent = None
        self._notify()

    def agent_skip(self, agent: str) -> None:
        self._running.discard(agent)
        self._skipped.add(agent)
        self._notify()

    def snapshot(self) -> ProgressSnapshot:
        """Get current progress snapshot."""
        elapsed = time.time() - self._start_time
        done = len(self._completed) + len(self._failed) + len(self._skipped)
        pending = self.total_agents - done - len(self._running)

        # ETA estimation
        pct = (done / self.total_agents * 100) if self.total_agents > 0 else 0
        throughput = done / (elapsed / 60) if elapsed > 0 else 0

        if done > 0 and done < self.total_agents:
            avg_duration = (
                sum(self._agent_durations.values()) / len(self._agent_durations)
                if self._agent_durations
                else 60
            )
            remaining_agents = self.total_agents - done
            est_remaining = avg_duration * remaining_agents
        else:
            est_remaining = 0

        return ProgressSnapshot(
            phase=self._phase,
            current_agent=self._current_agent,
            agents_completed=len(self._completed),
            agents_failed=len(self._failed),
            agents_skipped=len(self._skipped),
            agents_running=len(self._running),
            agents_pending=max(0, pending),
            agents_total=self.total_agents,
            percent_complete=round(pct, 1),
            elapsed_s=round(elapsed, 1),
            estimated_remaining_s=round(est_remaining, 1),
            estimated_total_s=round(elapsed + est_remaining, 1),
            agents_per_minute=round(throughput, 2),
            total_cost_usd=round(self._total_cost, 4),
            total_tokens=self._total_tokens,
        )

    def _notify(self) -> None:
        """Notify all callbacks with current snapshot."""
        snap = self.snapshot()
        for cb in self._callbacks:
            try:
                cb(snap)
            except Exception as e:
                logger.debug("Progress callback error: %s", e)


class ActivityStream:
    """Real-time event bus for pipeline activity.

    Subscribers receive events as they happen — for UI, logging,
    webhooks, and any other consumer.
    """

    def __init__(self) -> None:
        self._subscribers: List[Callable[[Dict[str, Any]], None]] = []
        self._async_subscribers: List[
            Callable[[Dict[str, Any]], Coroutine[Any, Any, None]]
        ] = []
        self._history: List[Dict[str, Any]] = []
        self._max_history = 10000

    def subscribe(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Register a synchronous event subscriber."""
        self._subscribers.append(callback)

    def subscribe_async(
        self,
        callback: Callable[[Dict[str, Any]], Coroutine[Any, Any, None]],
    ) -> None:
        """Register an async event subscriber."""
        self._async_subscribers.append(callback)

    def emit(self, event: Dict[str, Any]) -> None:
        """Emit an event to all subscribers."""
        event.setdefault(
            "timestamp",
            datetime.datetime.now(datetime.timezone.utc).isoformat(),
        )
        self._history.append(event)
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history :]

        for sub in self._subscribers:
            try:
                sub(event)
            except Exception as e:
                logger.debug("Subscriber error: %s", e)

    async def emit_async(self, event: Dict[str, Any]) -> None:
        """Emit an event to all subscribers (including async ones)."""
        self.emit(event)
        for sub in self._async_subscribers:
            try:
                await sub(event)
            except Exception as e:
                logger.debug("Async subscriber error: %s", e)

    def get_history(
        self,
        event_type: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Get event history, optionally filtered."""
        events = self._history
        if event_type:
            events = [e for e in events if e.get("event_type") == event_type]
        return events[-limit:]


# ════════════════════════════════════════════════════════════════════════
#  Section 6: SirenOrchestrator — Master Controller
# ════════════════════════════════════════════════════════════════════════


class SirenOrchestrator:
    """Master orchestrator that combines ALL SIREN systems.

    This is the single entry point for running a full SIREN pipeline
    with all advanced features:

    - Workspace management (create, resume, list)
    - Git checkpoints (save, rollback)
    - Session state machine (save, load, resume)
    - Config file loading (YAML/JSON)
    - Error classification (retry vs abort)
    - Exploitation queue gating (skip empty vulns)
    - Prompt management (templates, interpolation, token budget)
    - TOTP generation (2FA bypass)
    - Activity stream (real-time events)
    - Progress tracking (ETA, throughput)
    - Audit logging (structured events, per-agent logs)
    - Deliverable management (17 types, validation, merge)
    """

    def __init__(
        self,
        target_url: str = "",
        repo_path: str = "",
        config_path: Optional[str] = None,
        workspace_name: Optional[str] = None,
        output_dir: Optional[str] = None,
        templates_dir: Optional[str] = None,
    ) -> None:
        self.target_url = target_url
        self.repo_path = repo_path

        # Load config
        self.config: Optional[ConfigSchema] = None
        self.config_errors: List[str] = []
        if config_path:
            self.config, self.config_errors = ConfigFileLoader.load(config_path)
        elif target_url:
            self.config, self.config_errors = ConfigFileLoader.load()
            if not self.config:
                self.config = ConfigSchema(
                    target_url=target_url,
                    repo_path=repo_path,
                )

        # Apply config overrides
        if self.config:
            if not self.target_url and self.config.target_url:
                self.target_url = self.config.target_url
            if not self.repo_path and self.config.repo_path:
                self.repo_path = self.config.repo_path

        # Workspace
        base_dir = output_dir or (self.config.output_dir if self.config else None)
        self.workspace_mgr = WorkspaceManager(base_dir)
        self._workspace_path: Optional[Path] = None
        self._workspace_name = workspace_name

        # Session
        self._session: Optional[SessionStateMachine] = None

        # Subsystems (initialized in setup())
        self._git: Optional[GitCheckpointManager] = None
        self._deliverables: Optional[DeliverableManager] = None
        self._audit: Optional[AuditLogger] = None
        self._exploit_gate: Optional[ExploitationGate] = None
        self._prompt_mgr = PromptManager(templates_dir)
        self._progress = ProgressTracker()
        self._stream = ActivityStream()

        # State
        self._is_resume = False
        self._resume_info: Dict[str, Any] = {}
        self._initialized = False

    async def setup(self) -> Dict[str, Any]:
        """Initialize all subsystems. Must be called before run().

        Returns setup report with any warnings/errors.
        """
        report: Dict[str, Any] = {
            "status": "ok",
            "warnings": [],
            "errors": [],
        }

        # 1. Config validation
        if self.config_errors:
            report["warnings"].extend(f"Config: {e}" for e in self.config_errors)
        report["config_loaded"] = self.config is not None

        # 2. Workspace creation or resume
        if self._workspace_name:
            # Try resume first
            path, session, info = self.workspace_mgr.resume(
                self._workspace_name,
                self.target_url,
            )
            if path and session:
                self._workspace_path = path
                self._session = session
                self._is_resume = True
                self._resume_info = info
                report["mode"] = "resume"
                report["resume_info"] = info
            elif "error" in info and "not found" in info["error"].lower():
                # Create new
                path, session = self.workspace_mgr.create(
                    self.target_url,
                    self._workspace_name,
                )
                self._workspace_path = path
                self._session = session
                report["mode"] = "new"
            else:
                report["errors"].append(info.get("error", "Unknown workspace error"))
        else:
            # Auto-create
            path, session = self.workspace_mgr.create(self.target_url)
            self._workspace_path = path
            self._session = session
            report["mode"] = "new"

        if not self._workspace_path:
            report["status"] = "error"
            return report

        report["workspace"] = str(self._workspace_path)

        # 3. Init subsystems
        deliverables_dir = self._workspace_path / "deliverables"
        self._deliverables = DeliverableManager(deliverables_dir)
        self._audit = AuditLogger(self._workspace_path)
        self._exploit_gate = ExploitationGate(self._deliverables)

        if self.repo_path:
            self._git = GitCheckpointManager(self.repo_path)
            git_ok = self._git.init()
            report["git_initialized"] = git_ok
            if not git_ok:
                report["warnings"].append("Git checkpoint system unavailable")
        else:
            report["git_initialized"] = False
            report["warnings"].append("No repo_path — git checkpoints disabled")

        # 4. Log setup
        self._audit.emit(
            (
                AuditEventType.WORKSPACE_CREATE
                if not self._is_resume
                else AuditEventType.RESUME_DETECT
            ),
            f"{'Resumed' if self._is_resume else 'Created'} workspace: {self._workspace_path.name}",
            data={"target_url": self.target_url, "repo_path": self.repo_path},
        )

        # 5. Update session
        if self._session and self._session.state:
            self._session.update_status(
                WorkspaceStatus.RESUMED if self._is_resume else WorkspaceStatus.RUNNING
            )
            self._session.update_pipeline_state("SETUP")
            self._session.save()

        self._initialized = True
        report["status"] = "ok" if not report["errors"] else "error"
        return report

    async def preflight(self) -> Dict[str, Any]:
        """Run preflight validation checks."""
        checks: Dict[str, Any] = {
            "target_url": bool(self.target_url),
            "repo_path": bool(self.repo_path) and Path(self.repo_path).is_dir(),
            "config": self.config is not None,
            "workspace": self._workspace_path is not None,
            "git": (
                self._git is not None and self._git.is_git_repo()
                if self._git
                else False
            ),
        }

        # Credential check
        from .models import validate_credentials

        cred_result = validate_credentials()
        checks["credentials"] = cred_result

        # TOTP check
        if self.config and self.config.totp_secret:
            valid, msg = TOTPGenerator.validate_secret(self.config.totp_secret)
            checks["totp_secret"] = {"valid": valid, "message": msg}

        all_ok = all(
            v if isinstance(v, bool) else v.get("valid", True)
            for v in checks.values()
            if isinstance(v, (bool, dict))
        )
        checks["all_ok"] = all_ok

        if self._audit:
            self._audit.emit(
                AuditEventType.CREDENTIAL_CHECK,
                f"Preflight: {'PASS' if all_ok else 'FAIL'}",
                data=checks,
                success=all_ok,
            )

        return checks

    def build_prompt(self, agent_name: str) -> str:
        """Build a prompt for an agent using the prompt manager."""
        ctx = PromptContext(
            target_url=self.target_url,
            repo_path=self.repo_path,
        )

        # Fill from config
        if self.config:
            ctx.login_type = self.config.login_type
            ctx.login_url = self.config.login_url
            ctx.username = self.config.username
            ctx.password = self.config.password
            ctx.totp_secret = self.config.totp_secret
            ctx.login_flow = self.config.login_flow
            ctx.success_condition = (
                f"{self.config.success_condition_type}: "
                f"{self.config.success_condition_value}"
            )
            ctx.avoid_rules = self.config.avoid_rules
            ctx.focus_rules = self.config.focus_rules
            ctx.attack_domains = self.config.attack_domains
            ctx.mcp_servers = self.config.mcp_servers
            ctx.evasion_level = self.config.evasion_level

        # Fill prior deliverables
        if self._deliverables:
            ca = self._deliverables.load(DeliverableType.CODE_ANALYSIS)
            if ca:
                ctx.code_analysis = ca
            recon = self._deliverables.load(DeliverableType.RECON)
            if recon:
                ctx.recon_data = recon

            # Agent-specific queue/analysis
            from .agents import get_agent

            agent_def = get_agent(agent_name)
            if agent_def and agent_def.vuln_type:
                vt = agent_def.vuln_type
                queue_dtype = DeliverableType.queue_for_vuln_type(vt)
                if queue_dtype:
                    q = self._deliverables.load(queue_dtype)
                    if q:
                        ctx.exploitation_queue = q

            # Evidence files for report agent
            if agent_name == "report":
                for dtype in DeliverableType.evidence():
                    content = self._deliverables.load(dtype)
                    if content:
                        name = (
                            dtype.name.replace("_EVIDENCE", "")
                            .replace("_", " ")
                            .title()
                        )
                        ctx.evidence_files[name] = content

        ctx.agent_name = agent_name
        prompt = self._prompt_mgr.build_prompt(agent_name, ctx)

        # Save prompt to audit
        if self._audit:
            self._audit.save_agent_prompt(agent_name, prompt)

        return prompt

    def should_exploit(self, vuln_type: str) -> ExploitDecision:
        """Check exploitation gate for a vuln type."""
        if not self._exploit_gate:
            return ExploitDecision(
                vuln_type=vuln_type,
                should_exploit=True,
                reason="Exploit gate not initialized — proceeding by default",
            )

        decision = self._exploit_gate.check(vuln_type)

        if self._audit:
            self._audit.log_exploit_queue_check(
                vuln_type, decision.should_exploit, decision.reason
            )

        return decision

    def classify_error(
        self,
        error: Union[Exception, str],
        context: Optional[Dict[str, Any]] = None,
    ) -> ClassifiedError:
        """Classify an error with retry guidance."""
        classified = ErrorClassifier.classify(error, context)

        if self._audit:
            self._audit.emit(
                AuditEventType.ERROR_CLASSIFY,
                f"Error classified: {classified.code.value} "
                f"(retryable={classified.retryable})",
                data=classified.to_dict(),
                severity="warn" if classified.retryable else "error",
            )

        return classified

    def generate_totp(self) -> Optional[Dict[str, Any]]:
        """Generate TOTP code if secret is configured."""
        secret = ""
        if self.config:
            secret = self.config.totp_secret
        if not secret:
            return None

        result = TOTPGenerator.generate(secret)

        if self._audit:
            self._audit.emit(
                AuditEventType.TOTP_GENERATE,
                f"Generated TOTP code (expires in {result['expires_in']}s)",
            )

        return result

    def save_deliverable(
        self,
        agent_name: str,
        content: str,
        validate: bool = True,
    ) -> Optional[Dict[str, Any]]:
        """Save a deliverable from an agent."""
        if not self._deliverables:
            return None

        dtype = DeliverableType.for_agent(agent_name)
        if not dtype:
            return None

        info = self._deliverables.save(dtype, content, validate=validate)

        if self._session:
            self._session.add_deliverable(dtype, info.path)

        if self._audit:
            self._audit.emit(
                AuditEventType.DELIVERABLE_SAVE,
                f"Saved deliverable for '{agent_name}': {dtype.value} "
                f"({info.size_bytes} bytes, valid={info.is_valid})",
                agent=agent_name,
                data=info.to_dict(),
            )

        # Git checkpoint
        if self._git and info.is_valid:
            self._git.checkpoint(
                agent_name,
                self._progress._phase,
                CheckpointAction.DELIVERABLE_SAVED,
            )

        return info.to_dict()

    def get_progress(self) -> ProgressSnapshot:
        """Get current progress snapshot."""
        return self._progress.snapshot()

    def get_activity_stream(self) -> ActivityStream:
        """Get the activity stream for subscribing to events."""
        return self._stream

    async def finalize(self) -> Dict[str, Any]:
        """Finalize the pipeline: merge evidence, generate final report data."""
        report: Dict[str, Any] = {}

        if self._deliverables:
            report["evidence_summary"] = self._deliverables.merge_evidence()
            report["deliverables"] = [
                d.to_dict() for d in self._deliverables.list_all()
            ]

        if self._exploit_gate:
            report["exploitation_decisions"] = self._exploit_gate.get_summary()

        if self._audit:
            report["audit_summary"] = self._audit.get_summary()
            self._audit.flush_all()

        if self._session:
            snap = self._progress.snapshot()
            self._session.state.total_tokens = snap.total_tokens
            self._session.state.total_cost_usd = snap.total_cost_usd
            self._session.state.total_duration_s = snap.elapsed_s
            self._session.mark_complete(total_findings=report.get("total_findings", 0))

        report["progress"] = self._progress.snapshot().to_dict()
        return report

    def get_workspace_status(self) -> Dict[str, Any]:
        """Get detailed workspace status."""
        if self._workspace_path:
            return self.workspace_mgr.get_status(self._workspace_path.name)
        return {"error": "No workspace initialized"}

    def list_workspaces(self) -> List[Dict[str, Any]]:
        """List all workspaces."""
        return [w.to_dict() for w in self.workspace_mgr.list_all()]
