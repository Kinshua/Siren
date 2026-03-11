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
██   SIREN Remediation Generator -- Automated Fix Synthesis Engine            ██
██   "A defesa perfeita nasce do conhecimento cirurgico de cada ataque."      ██
██                                                                            ██
██   Generates SPECIFIC, WORKING code fixes per vulnerability type and        ██
██   language/framework combination. 50 battle-tested fix templates.          ██
██                                                                            ██
██   Capabilities:                                                            ██
██     [01] 50 fix templates across 14 vulnerability categories               ██
██     [02] Real code snippets -- not generic advice                          ██
██     [03] Priority queue: severity x (1/effort) x impact                    ██
██     [04] Dependency-aware remediation ordering                             ██
██     [05] Phase-based remediation plans (IMMEDIATE..LONG_TERM)              ██
██     [06] WAF rule generation (ModSecurity, Cloudflare, AWS WAF)            ██
██     [07] Security header configs per framework                             ██
██     [08] Effort estimation with hourly rate costing                        ██
██     [09] Quick-win identification for maximum ROI                          ██
██     [10] Full Markdown and JSON export                                     ██
██                                                                            ██
████████████████████████████████████████████████████████████████████████████████
"""
from __future__ import annotations

import hashlib
import heapq
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
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("siren.output.remediation_generator")

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class VulnType(str, Enum):
    """Vulnerability type categories aligned with OWASP Top 10."""
    SQLI = "SQLI"
    XSS = "XSS"
    AUTH = "AUTH"
    IDOR = "IDOR"
    RATE_LIMIT = "RATE_LIMIT"
    CORS = "CORS"
    HEADERS = "HEADERS"
    WAF = "WAF"
    TLS = "TLS"
    SSRF = "SSRF"
    CMDI = "CMDI"
    FILE_UPLOAD = "FILE_UPLOAD"
    DESERIALIZATION = "DESERIALIZATION"
    CSRF = "CSRF"


class EffortLevel(str, Enum):
    """Effort required to implement a fix."""
    TRIVIAL = "TRIVIAL"      # < 1 hour
    LOW = "LOW"              # 1-4 hours
    MEDIUM = "MEDIUM"        # 4-16 hours
    HIGH = "HIGH"            # 16-40 hours
    COMPLEX = "COMPLEX"      # 40+ hours


class FixType(str, Enum):
    """Type of remediation fix."""
    CODE_CHANGE = "CODE_CHANGE"
    CONFIG_CHANGE = "CONFIG_CHANGE"
    WAF_RULE = "WAF_RULE"
    INFRASTRUCTURE = "INFRASTRUCTURE"
    ARCHITECTURE = "ARCHITECTURE"
    DEPENDENCY_UPDATE = "DEPENDENCY_UPDATE"
    POLICY = "POLICY"


class Severity(str, Enum):
    """Finding severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class RemediationPhase(str, Enum):
    """Phases of remediation timeline."""
    IMMEDIATE = "IMMEDIATE"        # 0-24 hours
    SHORT_TERM = "SHORT_TERM"      # 1-7 days
    MEDIUM_TERM = "MEDIUM_TERM"    # 1-4 weeks
    LONG_TERM = "LONG_TERM"        # 1-3 months


# ---------------------------------------------------------------------------
# Severity / effort numeric mappings
# ---------------------------------------------------------------------------

SEVERITY_SCORES: Dict[str, float] = {
    "CRITICAL": 10.0,
    "HIGH": 8.0,
    "MEDIUM": 5.0,
    "LOW": 3.0,
    "INFO": 1.0,
}

EFFORT_HOURS: Dict[str, float] = {
    "TRIVIAL": 0.5,
    "LOW": 2.0,
    "MEDIUM": 8.0,
    "HIGH": 24.0,
    "COMPLEX": 60.0,
}

PHASE_ORDER: Dict[str, int] = {
    "IMMEDIATE": 0,
    "SHORT_TERM": 1,
    "MEDIUM_TERM": 2,
    "LONG_TERM": 3,
}


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class FixTemplate:
    """A concrete fix template for a specific vuln/language/framework combo.

    Each template contains REAL, WORKING code -- not generic guidance.
    Templates are indexed by (vuln_type, language, framework).
    """
    template_id: str = ""
    vuln_type: str = ""
    language: str = ""
    framework: str = ""
    code_template: str = ""
    config_template: str = ""
    description: str = ""
    effort: str = "MEDIUM"
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "template_id": self.template_id,
            "vuln_type": self.vuln_type,
            "language": self.language,
            "framework": self.framework,
            "code_template": self.code_template,
            "config_template": self.config_template,
            "description": self.description,
            "effort": self.effort,
            "tags": list(self.tags),
        }


@dataclass
class RemediationStep:
    """A single actionable remediation step with code, config, and commands.

    Contains everything a developer needs to fix a specific vulnerability:
    real code snippets, config changes, CLI commands, verification steps,
    and rollback instructions.
    """
    step_id: str = ""
    title: str = ""
    description: str = ""
    vuln_type: str = ""
    effort_level: str = "MEDIUM"
    effort_hours: float = 8.0
    fix_type: str = "CODE_CHANGE"
    code_snippets: Dict[str, str] = field(default_factory=dict)
    config_changes: List[str] = field(default_factory=list)
    commands: List[str] = field(default_factory=list)
    verification_steps: List[str] = field(default_factory=list)
    rollback_steps: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    severity: str = "MEDIUM"
    phase: str = "SHORT_TERM"
    impact_score: float = 5.0
    created_at: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        if not self.step_id:
            self.step_id = f"REM-{uuid.uuid4().hex[:12].upper()}"

    def priority_score(self) -> float:
        """Compute priority = severity * (1/effort) * impact."""
        sev = SEVERITY_SCORES.get(self.severity, 5.0)
        eff = EFFORT_HOURS.get(self.effort_level, 8.0)
        return sev * (1.0 / max(eff, 0.1)) * self.impact_score

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_id": self.step_id,
            "title": self.title,
            "description": self.description,
            "vuln_type": self.vuln_type,
            "effort_level": self.effort_level,
            "effort_hours": self.effort_hours,
            "fix_type": self.fix_type,
            "code_snippets": dict(self.code_snippets),
            "config_changes": list(self.config_changes),
            "commands": list(self.commands),
            "verification_steps": list(self.verification_steps),
            "rollback_steps": list(self.rollback_steps),
            "references": list(self.references),
            "dependencies": list(self.dependencies),
            "severity": self.severity,
            "phase": self.phase,
            "impact_score": self.impact_score,
            "priority_score": self.priority_score(),
            "created_at": self.created_at,
        }


@dataclass
class RemediationPlan:
    """A complete remediation plan organized into time-phased stages.

    Phases:
      - IMMEDIATE   (0-24h): Critical vulns, quick config fixes, WAF rules
      - SHORT_TERM  (1-7d):  High-severity code changes, auth hardening
      - MEDIUM_TERM (1-4w):  Architectural improvements, refactoring
      - LONG_TERM   (1-3mo): Strategic security improvements, policy

    Usage::

        plan = RemediationPlan()
        plan.add_step(step, "IMMEDIATE")
        print(plan.to_markdown())
    """
    plan_id: str = ""
    target: str = ""
    created_at: float = field(default_factory=time.time)
    phases: Dict[str, List[RemediationStep]] = field(default_factory=lambda: {
        "IMMEDIATE": [],
        "SHORT_TERM": [],
        "MEDIUM_TERM": [],
        "LONG_TERM": [],
    })
    total_effort_hours: float = 0.0
    total_cost: float = 0.0
    hourly_rate: float = 150.0
    quick_wins: List[RemediationStep] = field(default_factory=list)
    critical_path: List[RemediationStep] = field(default_factory=list)
    risk_reduction_per_phase: Dict[str, float] = field(default_factory=lambda: {
        "IMMEDIATE": 0.0,
        "SHORT_TERM": 0.0,
        "MEDIUM_TERM": 0.0,
        "LONG_TERM": 0.0,
    })
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.plan_id:
            self.plan_id = f"PLAN-{uuid.uuid4().hex[:12].upper()}"

    def add_step(self, step: RemediationStep, phase: str) -> None:
        """Add a remediation step to the specified phase."""
        if phase not in self.phases:
            self.phases[phase] = []
        self.phases[phase].append(step)
        self.total_effort_hours += step.effort_hours
        self.total_cost = self.total_effort_hours * self.hourly_rate
        sev_score = SEVERITY_SCORES.get(step.severity, 5.0)
        self.risk_reduction_per_phase[phase] = (
            self.risk_reduction_per_phase.get(phase, 0.0) + sev_score * step.impact_score
        )

    def steps_per_phase(self) -> Dict[str, int]:
        """Return count of steps per phase."""
        return {phase: len(steps) for phase, steps in self.phases.items()}

    def all_steps(self) -> List[RemediationStep]:
        """Return all steps across all phases in phase order."""
        result: List[RemediationStep] = []
        for phase in ("IMMEDIATE", "SHORT_TERM", "MEDIUM_TERM", "LONG_TERM"):
            result.extend(self.phases.get(phase, []))
        return result

    def to_markdown(self) -> str:
        """Export full plan as Markdown document."""
        lines: List[str] = []
        lines.append("# SIREN Remediation Plan")
        lines.append(f"\n**Plan ID**: {self.plan_id}")
        lines.append(f"**Target**: {self.target}")
        lines.append(f"**Generated**: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.created_at))}")
        lines.append(f"**Total Effort**: {self.total_effort_hours:.1f} hours")
        lines.append(f"**Estimated Cost**: ${self.total_cost:,.2f} (@ ${self.hourly_rate:.0f}/hr)")
        lines.append("")

        # Executive summary
        lines.append("## Executive Summary\n")
        spp = self.steps_per_phase()
        total_steps = sum(spp.values())
        lines.append(f"This plan contains **{total_steps} remediation steps** across 4 phases:\n")
        phase_labels = {
            "IMMEDIATE": "Immediate (0-24h)",
            "SHORT_TERM": "Short Term (1-7 days)",
            "MEDIUM_TERM": "Medium Term (1-4 weeks)",
            "LONG_TERM": "Long Term (1-3 months)",
        }
        for phase_key, label in phase_labels.items():
            count = spp.get(phase_key, 0)
            risk_red = self.risk_reduction_per_phase.get(phase_key, 0.0)
            lines.append(f"- **{label}**: {count} steps (risk reduction: {risk_red:.1f} pts)")
        lines.append("")

        # Quick wins
        if self.quick_wins:
            lines.append("## Quick Wins\n")
            lines.append("High-impact, low-effort fixes to implement first:\n")
            for i, step in enumerate(self.quick_wins, 1):
                lines.append(f"{i}. **{step.title}** -- {step.effort_level} effort, "
                             f"{step.severity} severity ({step.effort_hours:.1f}h)")
            lines.append("")

        # Phase details
        for phase_key, label in phase_labels.items():
            steps = self.phases.get(phase_key, [])
            if not steps:
                continue
            lines.append(f"## Phase: {label}\n")
            phase_hours = sum(s.effort_hours for s in steps)
            lines.append(f"**Phase effort**: {phase_hours:.1f} hours | "
                         f"**Phase cost**: ${phase_hours * self.hourly_rate:,.2f}\n")

            for step in steps:
                lines.append(f"### {step.step_id}: {step.title}\n")
                lines.append(f"- **Vulnerability**: {step.vuln_type}")
                lines.append(f"- **Severity**: {step.severity}")
                lines.append(f"- **Effort**: {step.effort_level} ({step.effort_hours:.1f}h)")
                lines.append(f"- **Fix Type**: {step.fix_type}")
                lines.append(f"- **Priority Score**: {step.priority_score():.2f}")
                lines.append(f"\n{step.description}\n")

                if step.code_snippets:
                    lines.append("**Code Changes:**\n")
                    for filename, code in step.code_snippets.items():
                        lines.append(f"*{filename}*:")
                        lang = _guess_lang(filename)
                        lines.append(f"```{lang}")
                        lines.append(code)
                        lines.append("```\n")

                if step.config_changes:
                    lines.append("**Configuration Changes:**\n")
                    for cfg in step.config_changes:
                        lines.append(f"- {cfg}")
                    lines.append("")

                if step.commands:
                    lines.append("**Commands:**\n")
                    lines.append("```bash")
                    for cmd in step.commands:
                        lines.append(cmd)
                    lines.append("```\n")

                if step.verification_steps:
                    lines.append("**Verification:**\n")
                    for v in step.verification_steps:
                        lines.append(f"- [ ] {v}")
                    lines.append("")

                if step.rollback_steps:
                    lines.append("**Rollback:**\n")
                    for r in step.rollback_steps:
                        lines.append(f"- {r}")
                    lines.append("")

                if step.references:
                    lines.append("**References:**\n")
                    for ref in step.references:
                        lines.append(f"- {ref}")
                    lines.append("")

        # Critical path
        if self.critical_path:
            lines.append("## Critical Path\n")
            lines.append("Steps that must be executed in order due to dependencies:\n")
            for i, step in enumerate(self.critical_path, 1):
                deps = ", ".join(step.dependencies) if step.dependencies else "none"
                lines.append(f"{i}. **{step.step_id}**: {step.title} (depends on: {deps})")
            lines.append("")

        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "target": self.target,
            "created_at": self.created_at,
            "phases": {
                phase: [s.to_dict() for s in steps]
                for phase, steps in self.phases.items()
            },
            "steps_per_phase": self.steps_per_phase(),
            "total_effort_hours": self.total_effort_hours,
            "total_cost": self.total_cost,
            "hourly_rate": self.hourly_rate,
            "quick_wins": [s.to_dict() for s in self.quick_wins],
            "critical_path": [s.to_dict() for s in self.critical_path],
            "risk_reduction_per_phase": dict(self.risk_reduction_per_phase),
            "metadata": dict(self.metadata),
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _guess_lang(filename: str) -> str:
    """Guess language from filename for Markdown code fences."""
    ext_map = {
        ".py": "python", ".js": "javascript", ".ts": "typescript",
        ".java": "java", ".cs": "csharp", ".php": "php", ".go": "go",
        ".rb": "ruby", ".rs": "rust", ".html": "html", ".xml": "xml",
        ".yaml": "yaml", ".yml": "yaml", ".json": "json", ".sql": "sql",
        ".sh": "bash", ".conf": "nginx", ".ini": "ini", ".toml": "toml",
    }
    for ext, lang in ext_map.items():
        if filename.endswith(ext):
            return lang
    return ""


def _make_template_id(vuln_type: str, language: str, framework: str) -> str:
    """Generate deterministic template ID."""
    raw = f"{vuln_type}:{language}:{framework}"
    h = hashlib.sha256(raw.encode()).hexdigest()[:10]
    return f"TPL-{vuln_type[:4].upper()}-{h.upper()}"


# ---------------------------------------------------------------------------
# Fix Template Registry -- 50 real-world templates
# ---------------------------------------------------------------------------

_BUILTIN_TEMPLATES: List[FixTemplate] = []


def _register(*args: Any, **kwargs: Any) -> FixTemplate:
    """Create and register a template."""
    tpl = FixTemplate(*args, **kwargs)
    if not tpl.template_id:
        tpl.template_id = _make_template_id(tpl.vuln_type, tpl.language, tpl.framework)
    _BUILTIN_TEMPLATES.append(tpl)
    return tpl


# ===== SQLi Templates (8) =====

_register(
    template_id="TPL-SQLI-PYTHON-SQLALCHEMY",
    vuln_type="SQLI",
    language="python",
    framework="sqlalchemy",
    description="Replace raw SQL with SQLAlchemy parameterized queries using text() bindings.",
    effort="LOW",
    tags=["sqli", "python", "orm", "parameterized"],
    code_template='''\
# BEFORE (vulnerable):
# result = db.execute(f"SELECT * FROM users WHERE id = {user_id}")

# AFTER (safe -- parameterized query with SQLAlchemy text()):
from sqlalchemy import text

def get_user_by_id(db_session, user_id: int):
    """Fetch user by ID using parameterized query."""
    stmt = text("SELECT * FROM users WHERE id = :uid")
    result = db_session.execute(stmt, {"uid": user_id})
    return result.fetchone()

def search_users(db_session, name_pattern: str):
    """Search users with LIKE using parameterized query."""
    stmt = text("SELECT * FROM users WHERE name LIKE :pattern")
    result = db_session.execute(stmt, {"pattern": f"%{name_pattern}%"})
    return result.fetchall()

# For ORM-style (even safer):
from sqlalchemy.orm import Session
from models import User

def get_user_orm(session: Session, user_id: int):
    """ORM query -- inherently parameterized."""
    return session.query(User).filter(User.id == user_id).first()
''',
    config_template="",
)

_register(
    template_id="TPL-SQLI-PYTHON-DJANGO",
    vuln_type="SQLI",
    language="python",
    framework="django",
    description="Replace raw SQL with Django ORM queries or parameterized raw().",
    effort="LOW",
    tags=["sqli", "python", "django", "orm"],
    code_template='''\
# BEFORE (vulnerable):
# User.objects.raw(f"SELECT * FROM auth_user WHERE username = '{name}'")

# AFTER (safe -- Django ORM):
from django.contrib.auth.models import User

def get_user_safe(username: str):
    """Use Django ORM -- inherently parameterized."""
    return User.objects.filter(username=username).first()

def search_users_safe(query: str):
    """Safe search with Django ORM Q objects."""
    from django.db.models import Q
    return User.objects.filter(
        Q(username__icontains=query) | Q(email__icontains=query)
    )

# If raw SQL is absolutely needed:
def raw_query_safe(user_id: int):
    """Parameterized raw query."""
    return User.objects.raw(
        "SELECT * FROM auth_user WHERE id = %s", [user_id]
    )

# For extra() calls -- use params:
def extra_safe(status: str):
    """Safe extra() with params."""
    return User.objects.extra(
        where=["status = %s"],
        params=[status],
    )
''',
    config_template="",
)

_register(
    template_id="TPL-SQLI-NODE-PG",
    vuln_type="SQLI",
    language="javascript",
    framework="express+pg",
    description="Replace string concatenation with pg parameterized queries ($1, $2).",
    effort="LOW",
    tags=["sqli", "node", "express", "postgresql", "parameterized"],
    code_template='''\
// BEFORE (vulnerable):
// const result = await pool.query(`SELECT * FROM users WHERE id = ${userId}`);

// AFTER (safe -- parameterized query with node-pg):
const { Pool } = require('pg');
const pool = new Pool();

async function getUserById(userId) {
    // $1 placeholder -- value passed as second argument array
    const query = 'SELECT * FROM users WHERE id = $1';
    const result = await pool.query(query, [userId]);
    return result.rows[0];
}

async function searchUsers(namePattern) {
    // Parameterized LIKE query
    const query = 'SELECT * FROM users WHERE name ILIKE $1';
    const result = await pool.query(query, [`%${namePattern}%`]);
    return result.rows;
}

async function insertUser(name, email) {
    // Parameterized INSERT with RETURNING
    const query = 'INSERT INTO users (name, email) VALUES ($1, $2) RETURNING id';
    const result = await pool.query(query, [name, email]);
    return result.rows[0].id;
}
''',
    config_template="",
)

_register(
    template_id="TPL-SQLI-JAVA-SPRING",
    vuln_type="SQLI",
    language="java",
    framework="spring-jpa",
    description="Replace JPQL string concat with Spring Data JPA named parameters.",
    effort="LOW",
    tags=["sqli", "java", "spring", "jpa", "parameterized"],
    code_template='''\
// BEFORE (vulnerable):
// @Query("SELECT u FROM User u WHERE u.name = '" + name + "'")

// AFTER (safe -- Spring Data JPA with named parameters):
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import java.util.List;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    // Method-name derived query (safest):
    Optional<User> findByUsername(String username);

    // Named parameter binding:
    @Query("SELECT u FROM User u WHERE u.email = :email")
    Optional<User> findByEmailSafe(@Param("email") String email);

    // Native query with positional params:
    @Query(value = "SELECT * FROM users WHERE status = ?1", nativeQuery = true)
    List<User> findByStatusNative(String status);

    // LIKE with named parameter:
    @Query("SELECT u FROM User u WHERE u.name LIKE %:pattern%")
    List<User> searchByName(@Param("pattern") String pattern);
}

// For JdbcTemplate:
import org.springframework.jdbc.core.JdbcTemplate;

public class UserDao {
    private final JdbcTemplate jdbc;

    public User getUser(Long id) {
        return jdbc.queryForObject(
            "SELECT * FROM users WHERE id = ?",
            new Object[]{id},
            new UserRowMapper()
        );
    }
}
''',
    config_template="",
)

_register(
    template_id="TPL-SQLI-CSHARP-EF",
    vuln_type="SQLI",
    language="csharp",
    framework="entity-framework",
    description="Replace raw SQL with Entity Framework LINQ or FromSqlInterpolated.",
    effort="LOW",
    tags=["sqli", "csharp", "ef", "linq", "parameterized"],
    code_template='''\
// BEFORE (vulnerable):
// var user = db.Users.FromSqlRaw($"SELECT * FROM Users WHERE Id = {id}");

// AFTER (safe -- EF Core LINQ):
using Microsoft.EntityFrameworkCore;
using System.Linq;

public class UserService
{
    private readonly AppDbContext _db;

    // LINQ query (safest -- inherently parameterized):
    public User GetUserById(int id)
    {
        return _db.Users.FirstOrDefault(u => u.Id == id);
    }

    // If raw SQL is required, use FromSqlInterpolated (auto-parameterizes):
    public User GetUserRaw(int id)
    {
        return _db.Users
            .FromSqlInterpolated($"SELECT * FROM Users WHERE Id = {id}")
            .FirstOrDefault();
    }

    // For complex queries, use SqlParameter explicitly:
    public List<User> SearchUsers(string name)
    {
        var param = new Microsoft.Data.SqlClient.SqlParameter("@name", $"%{name}%");
        return _db.Users
            .FromSqlRaw("SELECT * FROM Users WHERE Name LIKE @name", param)
            .ToList();
    }
}
''',
    config_template="",
)

_register(
    template_id="TPL-SQLI-PHP-PDO",
    vuln_type="SQLI",
    language="php",
    framework="pdo",
    description="Replace mysqli string concat with PDO prepared statements.",
    effort="LOW",
    tags=["sqli", "php", "pdo", "prepared-statements"],
    code_template='''\
<?php
// BEFORE (vulnerable):
// $result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET['id']);

// AFTER (safe -- PDO prepared statements):
class UserRepository {
    private PDO $pdo;

    public function __construct(string $dsn, string $user, string $pass) {
        $this->pdo = new PDO($dsn, $user, $pass, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,  // CRITICAL: use real prepared stmts
        ]);
    }

    public function findById(int $id): ?array {
        $stmt = $this->pdo->prepare("SELECT * FROM users WHERE id = :id");
        $stmt->execute(['id' => $id]);
        return $stmt->fetch() ?: null;
    }

    public function searchByName(string $name): array {
        $stmt = $this->pdo->prepare("SELECT * FROM users WHERE name LIKE :name");
        $stmt->execute(['name' => "%{$name}%"]);
        return $stmt->fetchAll();
    }

    public function insertUser(string $name, string $email): int {
        $stmt = $this->pdo->prepare(
            "INSERT INTO users (name, email) VALUES (:name, :email)"
        );
        $stmt->execute(['name' => $name, 'email' => $email]);
        return (int) $this->pdo->lastInsertId();
    }
}
?>
''',
    config_template="",
)

_register(
    template_id="TPL-SQLI-GO-DBSQL",
    vuln_type="SQLI",
    language="go",
    framework="database-sql",
    description="Replace fmt.Sprintf SQL with database/sql placeholders.",
    effort="LOW",
    tags=["sqli", "go", "database-sql", "parameterized"],
    code_template='''\
// BEFORE (vulnerable):
// query := fmt.Sprintf("SELECT * FROM users WHERE id = %d", userID)
// rows, err := db.Query(query)

// AFTER (safe -- database/sql parameterized queries):
package repository

import (
    "context"
    "database/sql"
)

type UserRepo struct {
    db *sql.DB
}

func (r *UserRepo) GetByID(ctx context.Context, id int64) (*User, error) {
    // Use $1 for PostgreSQL, ? for MySQL/SQLite
    row := r.db.QueryRowContext(ctx, "SELECT id, name, email FROM users WHERE id = $1", id)
    var u User
    err := row.Scan(&u.ID, &u.Name, &u.Email)
    if err != nil {
        return nil, err
    }
    return &u, nil
}

func (r *UserRepo) Search(ctx context.Context, pattern string) ([]*User, error) {
    rows, err := r.db.QueryContext(ctx,
        "SELECT id, name, email FROM users WHERE name ILIKE $1",
        "%"+pattern+"%",
    )
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var users []*User
    for rows.Next() {
        var u User
        if err := rows.Scan(&u.ID, &u.Name, &u.Email); err != nil {
            return nil, err
        }
        users = append(users, &u)
    }
    return users, rows.Err()
}
''',
    config_template="",
)

_register(
    template_id="TPL-SQLI-RUBY-RAILS",
    vuln_type="SQLI",
    language="ruby",
    framework="rails",
    description="Replace string interpolation with ActiveRecord parameterized finders.",
    effort="LOW",
    tags=["sqli", "ruby", "rails", "activerecord"],
    code_template='''\
# BEFORE (vulnerable):
# User.where("name = '#{params[:name]}'")

# AFTER (safe -- ActiveRecord parameterized queries):
class UsersController < ApplicationController
  def show
    # Hash conditions (safest):
    @user = User.find_by(id: params[:id])
  end

  def search
    # Array conditions with placeholder:
    @users = User.where("name LIKE ?", "%#{params[:q]}%")
  end

  def advanced_search
    # Named placeholders:
    @users = User.where(
      "email = :email AND status = :status",
      email: params[:email],
      status: params[:status]
    )
  end

  def bulk_lookup
    # Safe IN query:
    @users = User.where(id: params[:ids])
  end
end

# For complex queries, use Arel:
# users = User.arel_table
# query = users[:name].matches("%#{sanitize_sql_like(term)}%")
# User.where(query)
''',
    config_template="",
)

# ===== XSS Templates (6) =====

_register(
    template_id="TPL-XSS-REACT-DOMPURIFY",
    vuln_type="XSS",
    language="javascript",
    framework="react",
    description="Sanitize dynamic HTML with DOMPurify; avoid dangerouslySetInnerHTML.",
    effort="LOW",
    tags=["xss", "react", "dompurify", "sanitization"],
    code_template='''\
// BEFORE (vulnerable):
// <div dangerouslySetInnerHTML={{__html: userInput}} />

// AFTER (safe -- DOMPurify sanitization):
import DOMPurify from 'dompurify';

// Option 1: Sanitize before rendering
function SafeHtml({ content }) {
    const sanitized = DOMPurify.sanitize(content, {
        ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br', 'ul', 'li'],
        ALLOWED_ATTR: ['href', 'title', 'target'],
        ALLOW_DATA_ATTR: false,
    });
    return <div dangerouslySetInnerHTML={{__html: sanitized}} />;
}

// Option 2: Prefer React's built-in escaping (best):
function SafeText({ text }) {
    // React auto-escapes content in JSX expressions
    return <div>{text}</div>;
}

// Option 3: Custom hook for repeated use:
function useSanitizedHtml(dirty) {
    return React.useMemo(
        () => DOMPurify.sanitize(dirty, {
            USE_PROFILES: { html: true },
            FORBID_TAGS: ['script', 'style', 'iframe', 'object', 'embed'],
            FORBID_ATTR: ['onerror', 'onload', 'onclick', 'onmouseover'],
        }),
        [dirty]
    );
}
''',
    config_template="",
)

_register(
    template_id="TPL-XSS-ANGULAR-SANITIZER",
    vuln_type="XSS",
    language="typescript",
    framework="angular",
    description="Use Angular DomSanitizer with bypassSecurityTrust* only when validated.",
    effort="LOW",
    tags=["xss", "angular", "domsanitizer"],
    code_template='''\
// BEFORE (vulnerable):
// this.trustedHtml = this.sanitizer.bypassSecurityTrustHtml(userInput);

// AFTER (safe -- Angular DomSanitizer with validation):
import { Component, Pipe, PipeTransform } from '@angular/core';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

// Custom sanitization pipe:
@Pipe({ name: 'safeHtml' })
export class SafeHtmlPipe implements PipeTransform {
    constructor(private sanitizer: DomSanitizer) {}

    transform(value: string): SafeHtml {
        // Strip dangerous patterns BEFORE trusting:
        const cleaned = value
            .replace(/<script[^>]*>.*?<\\/script>/gi, '')
            .replace(/on\\w+\\s*=\\s*["'][^"']*["']/gi, '')
            .replace(/javascript:/gi, '')
            .replace(/<iframe[^>]*>.*?<\\/iframe>/gi, '');
        return this.sanitizer.bypassSecurityTrustHtml(cleaned);
    }
}

// In component -- prefer interpolation (auto-escaped):
@Component({
    template: `
        <!-- SAFE: Angular auto-escapes interpolation -->
        <p>{{ userInput }}</p>

        <!-- If HTML needed, use sanitization pipe: -->
        <div [innerHTML]="trustedContent | safeHtml"></div>
    `
})
export class SafeComponent {
    userInput: string = '';
    trustedContent: string = '';
}
''',
    config_template="",
)

_register(
    template_id="TPL-XSS-VUE-SANITIZE",
    vuln_type="XSS",
    language="javascript",
    framework="vue",
    description="Replace v-html with text interpolation or sanitized content in Vue.",
    effort="LOW",
    tags=["xss", "vue", "sanitization"],
    code_template='''\
<!-- BEFORE (vulnerable): -->
<!-- <div v-html="userInput"></div> -->

<!-- AFTER (safe): -->
<template>
  <!-- Option 1: Use text interpolation (auto-escaped by Vue): -->
  <p>{{ userInput }}</p>

  <!-- Option 2: If HTML is needed, sanitize first: -->
  <div v-html="sanitizedHtml"></div>
</template>

<script>
// Simple sanitizer (for production, use a proper library):
function sanitizeHtml(dirty) {
    const div = document.createElement('div');
    div.textContent = dirty;
    return div.innerHTML;
}

// Allowlist-based sanitizer:
function sanitizeAllowlist(html) {
    const allowedTags = ['b', 'i', 'em', 'strong', 'a', 'p', 'br'];
    const tagPattern = /<\\/?([a-z][a-z0-9]*)\\b[^>]*>/gi;
    return html.replace(tagPattern, (match, tag) => {
        return allowedTags.includes(tag.toLowerCase()) ? match : '';
    }).replace(/on\\w+\\s*=\\s*["'][^"']*["']/gi, '')
      .replace(/javascript:/gi, '');
}

export default {
    data() {
        return { userInput: '' };
    },
    computed: {
        sanitizedHtml() {
            return sanitizeAllowlist(this.userInput);
        }
    }
};
</script>
''',
    config_template="",
)

_register(
    template_id="TPL-XSS-DJANGO-ESCAPE",
    vuln_type="XSS",
    language="python",
    framework="django",
    description="Ensure Django auto-escaping is on; use mark_safe only after sanitization.",
    effort="TRIVIAL",
    tags=["xss", "python", "django", "template-escaping"],
    code_template='''\
# BEFORE (vulnerable):
# from django.utils.safestring import mark_safe
# return mark_safe(f"<div>{user_input}</div>")

# AFTER (safe):
# Django templates auto-escape by default. Ensure it is NOT disabled.

# In views.py -- NEVER mark_safe untrusted input:
from django.utils.html import escape, strip_tags
import re

def safe_render(request):
    user_input = request.GET.get("q", "")
    # Option 1: Use auto-escaping (just pass to template):
    return render(request, "results.html", {"query": user_input})

    # Option 2: If you need HTML subset, sanitize first:
    clean = strip_tags(user_input)
    return render(request, "results.html", {"query": clean})

# In template (results.html):
# {{ query }}          <-- auto-escaped, SAFE
# {{ query|escape }}   <-- explicit escape, SAFE
# {% autoescape on %}  <-- ensure block is escaped
#   {{ query }}
# {% endautoescape %}

# AVOID these unless content is trusted AND sanitized:
# {{ query|safe }}          <-- DANGEROUS
# {% autoescape off %}      <-- DANGEROUS

# For rich text, use bleach-like sanitization:
ALLOWED_TAGS = {"b", "i", "em", "strong", "a", "p", "br", "ul", "li"}

def sanitize_html(html_str: str) -> str:
    """Strip all tags except allowed ones."""
    tag_re = re.compile(r"</?([a-zA-Z][a-zA-Z0-9]*)\\b[^>]*>", re.DOTALL)
    def _replace(m):
        tag = m.group(1).lower()
        return m.group(0) if tag in ALLOWED_TAGS else ""
    result = tag_re.sub(_replace, html_str)
    result = re.sub(r"on\\w+\\s*=", "", result, flags=re.IGNORECASE)
    result = result.replace("javascript:", "")
    return result
''',
    config_template="",
)

_register(
    template_id="TPL-XSS-PHP-HTMLSPECIALCHARS",
    vuln_type="XSS",
    language="php",
    framework="php",
    description="Use htmlspecialchars() with ENT_QUOTES and UTF-8 on all output.",
    effort="TRIVIAL",
    tags=["xss", "php", "htmlspecialchars", "output-encoding"],
    code_template='''\
<?php
// BEFORE (vulnerable):
// echo "<div>" . $_GET['name'] . "</div>";

// AFTER (safe -- htmlspecialchars on all output):

// Helper function for consistent encoding:
function h(string $str): string {
    return htmlspecialchars($str, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

// Usage in HTML context:
echo "<div>" . h($_GET['name']) . "</div>";
echo '<input type="text" value="' . h($userInput) . '">';

// In attribute context:
echo '<a href="' . h($url) . '" title="' . h($title) . '">Link</a>';

// In JavaScript context (use json_encode):
echo '<script>var name = ' . json_encode($userName, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT) . ';</script>';

// Content Security Policy header (defense in depth):
header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'");

// For Twig templates (auto-escapes by default):
// {{ user_input }}          {# auto-escaped #}
// {{ user_input|raw }}      {# DANGEROUS -- avoid #}
?>
''',
    config_template="",
)

_register(
    template_id="TPL-XSS-EXPRESS-HELMET",
    vuln_type="XSS",
    language="javascript",
    framework="express",
    description="Add Helmet middleware for XSS protection headers in Express.",
    effort="TRIVIAL",
    tags=["xss", "express", "helmet", "csp", "headers"],
    code_template='''\
// BEFORE: No security headers
// const app = express();

// AFTER (safe -- Helmet middleware + CSP):
const express = require('express');
const helmet = require('helmet');
const app = express();

// Apply all Helmet protections:
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            frameSrc: ["'none'"],
            upgradeInsecureRequests: [],
        },
    },
    crossOriginEmbedderPolicy: true,
    crossOriginOpenerPolicy: true,
    crossOriginResourcePolicy: { policy: "same-origin" },
    xXssProtection: false,  // Deprecated; CSP is better
}));

// Template output encoding (EJS example):
// <%- userInput %>   <-- DANGEROUS (unescaped)
// <%= userInput %>   <-- SAFE (escaped)

// For API responses, set explicit content-type:
app.get('/api/data', (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.json({ data: userInput });  // JSON.stringify auto-escapes
});
''',
    config_template="",
)

# ===== Auth Templates (5) =====

_register(
    template_id="TPL-AUTH-JWT-RS256",
    vuln_type="AUTH",
    language="python",
    framework="jwt",
    description="Enforce RS256 algorithm to prevent JWT algorithm confusion attacks.",
    effort="MEDIUM",
    tags=["auth", "jwt", "rs256", "algorithm-confusion"],
    code_template='''\
# BEFORE (vulnerable -- accepts any algorithm):
# payload = jwt.decode(token, secret, algorithms=["HS256", "RS256", "none"])

# AFTER (safe -- enforce RS256 only):
import json
import hmac
import hashlib
import base64
import time
import os

# --- JWT RS256 Enforcement ---

class JWTValidator:
    """Strict JWT validator that ONLY accepts RS256."""

    ALLOWED_ALGORITHMS = ("RS256",)

    def __init__(self, public_key_pem: str):
        self._public_key = public_key_pem
        self._issuer = None
        self._audience = None

    def set_issuer(self, issuer: str) -> None:
        self._issuer = issuer

    def set_audience(self, audience: str) -> None:
        self._audience = audience

    def decode_header(self, token: str) -> dict:
        """Decode and validate JWT header."""
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid JWT format: expected 3 parts")
        header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_b64))

        # CRITICAL: Reject any algorithm not in allowlist
        alg = header.get("alg", "")
        if alg not in self.ALLOWED_ALGORITHMS:
            raise ValueError(f"Rejected algorithm: {alg}. Only {self.ALLOWED_ALGORITHMS} allowed.")

        # Reject 'none' algorithm explicitly
        if alg.lower() == "none":
            raise ValueError("Algorithm 'none' is forbidden")

        return header

    def validate_claims(self, payload: dict) -> None:
        """Validate standard JWT claims."""
        now = time.time()
        if "exp" in payload and payload["exp"] < now:
            raise ValueError("Token expired")
        if "nbf" in payload and payload["nbf"] > now + 30:
            raise ValueError("Token not yet valid")
        if self._issuer and payload.get("iss") != self._issuer:
            raise ValueError(f"Invalid issuer: {payload.get('iss')}")
        if self._audience and payload.get("aud") != self._audience:
            raise ValueError(f"Invalid audience: {payload.get('aud')}")
''',
    config_template="",
)

_register(
    template_id="TPL-AUTH-BCRYPT-HASH",
    vuln_type="AUTH",
    language="python",
    framework="bcrypt",
    description="Replace MD5/SHA password storage with bcrypt (cost 12+).",
    effort="MEDIUM",
    tags=["auth", "bcrypt", "password-hashing"],
    code_template='''\
# BEFORE (vulnerable):
# password_hash = hashlib.md5(password.encode()).hexdigest()

# AFTER (safe -- bcrypt with proper cost factor):
import hashlib
import hmac
import os
import base64

class PasswordHasher:
    """Secure password hasher using PBKDF2-SHA256 (stdlib, no external deps).

    For production with external deps, prefer bcrypt or argon2.
    This implementation uses PBKDF2 with 600,000 iterations (OWASP 2024 minimum).
    """

    ITERATIONS = 600_000       # OWASP minimum for PBKDF2-SHA256
    SALT_LENGTH = 32           # 256-bit salt
    KEY_LENGTH = 32            # 256-bit derived key
    ALGORITHM = "pbkdf2_sha256"

    @classmethod
    def hash_password(cls, password: str) -> str:
        """Hash a password with random salt. Returns storable string."""
        salt = os.urandom(cls.SALT_LENGTH)
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, cls.ITERATIONS, dklen=cls.KEY_LENGTH
        )
        salt_b64 = base64.b64encode(salt).decode("ascii")
        dk_b64 = base64.b64encode(dk).decode("ascii")
        return f"{cls.ALGORITHM}${cls.ITERATIONS}${salt_b64}${dk_b64}"

    @classmethod
    def verify_password(cls, password: str, stored_hash: str) -> bool:
        """Verify password against stored hash. Constant-time comparison."""
        parts = stored_hash.split("$")
        if len(parts) != 4 or parts[0] != cls.ALGORITHM:
            return False
        iterations = int(parts[1])
        salt = base64.b64decode(parts[2])
        expected_dk = base64.b64decode(parts[3])
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, iterations, dklen=len(expected_dk)
        )
        return hmac.compare_digest(dk, expected_dk)

# Usage:
# stored = PasswordHasher.hash_password("my-secure-password")
# valid  = PasswordHasher.verify_password("my-secure-password", stored)  # True
''',
    config_template="",
)

_register(
    template_id="TPL-AUTH-SECURE-COOKIES",
    vuln_type="AUTH",
    language="python",
    framework="flask",
    description="Configure session cookies with Secure, HttpOnly, SameSite flags.",
    effort="TRIVIAL",
    tags=["auth", "cookies", "session", "flask"],
    code_template='''\
# BEFORE (vulnerable -- default cookie settings):
# app.secret_key = "changeme"

# AFTER (safe -- hardened session configuration):
import os
import secrets

from flask import Flask

app = Flask(__name__)

# Generate cryptographically secure secret key:
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))

# Harden session cookie settings:
app.config.update(
    SESSION_COOKIE_SECURE=True,         # Only send over HTTPS
    SESSION_COOKIE_HTTPONLY=True,        # No JavaScript access
    SESSION_COOKIE_SAMESITE="Lax",      # CSRF protection
    SESSION_COOKIE_NAME="__Host-session",  # Cookie prefix for extra security
    SESSION_COOKIE_PATH="/",
    PERMANENT_SESSION_LIFETIME=1800,     # 30 min timeout
    SESSION_REFRESH_EACH_REQUEST=True,   # Sliding window
)

# For Django (settings.py):
# SESSION_COOKIE_SECURE = True
# SESSION_COOKIE_HTTPONLY = True
# SESSION_COOKIE_SAMESITE = "Lax"
# SESSION_COOKIE_AGE = 1800
# SESSION_EXPIRE_AT_BROWSER_CLOSE = True
# CSRF_COOKIE_SECURE = True
# CSRF_COOKIE_HTTPONLY = True
# CSRF_COOKIE_SAMESITE = "Lax"

# For Express.js:
# app.use(session({
#     secret: process.env.SESSION_SECRET,
#     name: '__Host-session',
#     cookie: {
#         secure: true,
#         httpOnly: true,
#         sameSite: 'lax',
#         maxAge: 30 * 60 * 1000,
#         path: '/',
#     },
#     resave: false,
#     saveUninitialized: false,
# }));
''',
    config_template="",
)

_register(
    template_id="TPL-AUTH-TOTP-2FA",
    vuln_type="AUTH",
    language="python",
    framework="totp",
    description="Implement TOTP-based two-factor authentication (RFC 6238).",
    effort="HIGH",
    tags=["auth", "totp", "2fa", "mfa"],
    code_template='''\
# TOTP (Time-based One-Time Password) implementation -- RFC 6238
# Pure stdlib -- no external dependencies

import hashlib
import hmac
import os
import struct
import time
import base64

class TOTPGenerator:
    """RFC 6238 TOTP generator/validator using HMAC-SHA1."""

    DIGITS = 6
    PERIOD = 30       # seconds
    SKEW = 1          # allow +/- 1 period for clock drift
    SECRET_LENGTH = 20  # 160-bit secret

    @classmethod
    def generate_secret(cls) -> str:
        """Generate a base32-encoded secret for the user."""
        raw = os.urandom(cls.SECRET_LENGTH)
        return base64.b32encode(raw).decode("ascii").rstrip("=")

    @classmethod
    def _dynamic_truncate(cls, hmac_digest: bytes) -> int:
        """Extract a 31-bit integer from HMAC digest."""
        offset = hmac_digest[-1] & 0x0F
        code_bytes = hmac_digest[offset:offset + 4]
        code_int = struct.unpack(">I", code_bytes)[0] & 0x7FFFFFFF
        return code_int % (10 ** cls.DIGITS)

    @classmethod
    def generate_code(cls, secret_b32: str, timestamp: float = None) -> str:
        """Generate current TOTP code."""
        if timestamp is None:
            timestamp = time.time()
        counter = int(timestamp) // cls.PERIOD
        secret = base64.b32decode(secret_b32 + "=" * (8 - len(secret_b32) % 8), casefold=True)
        msg = struct.pack(">Q", counter)
        h = hmac.new(secret, msg, hashlib.sha1).digest()
        code = cls._dynamic_truncate(h)
        return str(code).zfill(cls.DIGITS)

    @classmethod
    def verify_code(cls, secret_b32: str, code: str, timestamp: float = None) -> bool:
        """Verify TOTP code with clock skew tolerance."""
        if timestamp is None:
            timestamp = time.time()
        for offset in range(-cls.SKEW, cls.SKEW + 1):
            ts = timestamp + (offset * cls.PERIOD)
            if hmac.compare_digest(cls.generate_code(secret_b32, ts), code):
                return True
        return False

    @classmethod
    def get_provisioning_uri(cls, secret_b32: str, account: str, issuer: str) -> str:
        """Generate otpauth:// URI for QR code scanning."""
        return (
            f"otpauth://totp/{issuer}:{account}"
            f"?secret={secret_b32}&issuer={issuer}"
            f"&algorithm=SHA1&digits={cls.DIGITS}&period={cls.PERIOD}"
        )
''',
    config_template="",
)

_register(
    template_id="TPL-AUTH-SESSION-CONFIG",
    vuln_type="AUTH",
    language="python",
    framework="generic",
    description="Comprehensive session security: regeneration, timeout, binding.",
    effort="MEDIUM",
    tags=["auth", "session", "security", "timeout"],
    code_template='''\
# Comprehensive session security configuration

import hashlib
import os
import secrets
import time
from typing import Any, Dict, Optional

class SecureSessionManager:
    """Session manager with security best practices."""

    MAX_AGE = 1800           # 30 min absolute timeout
    IDLE_TIMEOUT = 900       # 15 min idle timeout
    MAX_SESSIONS = 3         # Max concurrent sessions per user
    REGENERATE_INTERVAL = 300  # Regenerate session ID every 5 min

    def __init__(self) -> None:
        self._sessions: Dict[str, Dict[str, Any]] = {}

    def create_session(self, user_id: str, ip: str, user_agent: str) -> str:
        """Create a new session with security metadata."""
        session_id = secrets.token_urlsafe(32)
        fingerprint = self._compute_fingerprint(ip, user_agent)
        now = time.time()
        self._sessions[session_id] = {
            "user_id": user_id,
            "created_at": now,
            "last_active": now,
            "last_regenerated": now,
            "fingerprint": fingerprint,
            "ip": ip,
        }
        self._enforce_max_sessions(user_id)
        return session_id

    def validate_session(self, session_id: str, ip: str, user_agent: str) -> Optional[str]:
        """Validate session. Returns user_id or None."""
        session = self._sessions.get(session_id)
        if not session:
            return None
        now = time.time()
        # Absolute timeout
        if now - session["created_at"] > self.MAX_AGE:
            self.destroy_session(session_id)
            return None
        # Idle timeout
        if now - session["last_active"] > self.IDLE_TIMEOUT:
            self.destroy_session(session_id)
            return None
        # Fingerprint binding (detect session hijacking)
        fp = self._compute_fingerprint(ip, user_agent)
        if fp != session["fingerprint"]:
            self.destroy_session(session_id)
            return None
        session["last_active"] = now
        return session["user_id"]

    def regenerate_session(self, old_id: str) -> Optional[str]:
        """Regenerate session ID to prevent fixation."""
        session = self._sessions.pop(old_id, None)
        if not session:
            return None
        new_id = secrets.token_urlsafe(32)
        session["last_regenerated"] = time.time()
        self._sessions[new_id] = session
        return new_id

    def destroy_session(self, session_id: str) -> None:
        """Destroy a session completely."""
        self._sessions.pop(session_id, None)

    def _compute_fingerprint(self, ip: str, user_agent: str) -> str:
        raw = f"{ip}|{user_agent}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def _enforce_max_sessions(self, user_id: str) -> None:
        user_sessions = [
            (sid, s) for sid, s in self._sessions.items()
            if s["user_id"] == user_id
        ]
        if len(user_sessions) > self.MAX_SESSIONS:
            user_sessions.sort(key=lambda x: x[1]["last_active"])
            for sid, _ in user_sessions[:len(user_sessions) - self.MAX_SESSIONS]:
                self.destroy_session(sid)
''',
    config_template="",
)

# ===== IDOR Templates (3) =====

_register(
    template_id="TPL-IDOR-MIDDLEWARE-AUTH",
    vuln_type="IDOR",
    language="python",
    framework="flask",
    description="Middleware-based authorization check preventing direct object reference.",
    effort="MEDIUM",
    tags=["idor", "authorization", "middleware", "flask"],
    code_template='''\
# BEFORE (vulnerable -- no ownership check):
# @app.route("/api/documents/<int:doc_id>")
# def get_document(doc_id):
#     return Document.query.get(doc_id).to_json()

# AFTER (safe -- ownership verification middleware):
from functools import wraps
from flask import Flask, request, jsonify, abort, g

def require_ownership(resource_type: str):
    """Decorator that verifies the current user owns the requested resource."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            user_id = g.current_user.id
            resource_id = kwargs.get(f"{resource_type}_id") or kwargs.get("id")
            if not resource_id:
                abort(400, description="Resource ID missing")

            # Check ownership in database
            ownership_map = {
                "document": lambda rid: Document.query.filter_by(
                    id=rid, owner_id=user_id
                ).first(),
                "order": lambda rid: Order.query.filter_by(
                    id=rid, customer_id=user_id
                ).first(),
                "profile": lambda rid: Profile.query.filter_by(
                    id=rid, user_id=user_id
                ).first(),
            }

            checker = ownership_map.get(resource_type)
            if not checker:
                abort(500, description=f"Unknown resource type: {resource_type}")

            resource = checker(resource_id)
            if not resource:
                # Return 404 (not 403) to avoid information disclosure
                abort(404, description="Resource not found")

            g.resource = resource
            return f(*args, **kwargs)
        return wrapper
    return decorator

# Usage:
@app.route("/api/documents/<int:document_id>")
@require_ownership("document")
def get_document(document_id):
    return jsonify(g.resource.to_dict())
''',
    config_template="",
)

_register(
    template_id="TPL-IDOR-UUID-MIGRATION",
    vuln_type="IDOR",
    language="python",
    framework="sqlalchemy",
    description="Migrate from sequential integer IDs to UUIDs for external references.",
    effort="HIGH",
    tags=["idor", "uuid", "sqlalchemy", "migration"],
    code_template='''\
# BEFORE (vulnerable -- sequential IDs are guessable):
# class Document(db.Model):
#     id = db.Column(db.Integer, primary_key=True, autoincrement=True)

# AFTER (safe -- UUIDv4 as external identifier):
import uuid as _uuid

# SQLAlchemy model with UUID external ID:
# (Keep integer PK for internal joins; expose UUID externally)

class Document:
    """Model with UUID external reference.

    Internal: integer `id` for foreign keys and joins (performance).
    External: UUID `external_id` for API exposure (security).
    """
    # id = db.Column(db.Integer, primary_key=True)           # internal only
    # external_id = db.Column(db.String(36), unique=True,
    #     nullable=False, default=lambda: str(_uuid.uuid4()), index=True)
    # owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    pass

# Migration script (Alembic):
MIGRATION_SQL = """
-- Step 1: Add UUID column
ALTER TABLE documents ADD COLUMN external_id VARCHAR(36);

-- Step 2: Populate existing rows
UPDATE documents SET external_id = gen_random_uuid()::text WHERE external_id IS NULL;

-- Step 3: Add constraints
ALTER TABLE documents ALTER COLUMN external_id SET NOT NULL;
ALTER TABLE documents ADD CONSTRAINT uq_documents_external_id UNIQUE (external_id);
CREATE INDEX idx_documents_external_id ON documents (external_id);

-- Step 4: Update API routes to use external_id
-- GET /api/documents/{external_id} instead of /api/documents/{id}
"""

# API layer:
def get_document_api(external_id: str):
    """Lookup by UUID -- no sequential enumeration possible."""
    try:
        _uuid.UUID(external_id, version=4)  # Validate UUID format
    except ValueError:
        return None  # 404 -- invalid format
    # doc = Document.query.filter_by(external_id=external_id, owner_id=user.id).first()
    return None
''',
    config_template="",
)

_register(
    template_id="TPL-IDOR-ABAC-PATTERN",
    vuln_type="IDOR",
    language="python",
    framework="generic",
    description="Attribute-Based Access Control (ABAC) pattern for fine-grained authorization.",
    effort="HIGH",
    tags=["idor", "abac", "authorization", "policy"],
    code_template='''\
# Attribute-Based Access Control (ABAC) engine
# Evaluates policies based on subject, resource, action, and environment attributes

from typing import Any, Dict, List, Callable

class ABACPolicy:
    """A single ABAC policy rule."""
    def __init__(self, name: str, description: str,
                 condition: Callable[[Dict, Dict, str, Dict], bool],
                 effect: str = "ALLOW"):
        self.name = name
        self.description = description
        self.condition = condition
        self.effect = effect  # "ALLOW" or "DENY"

class ABACEngine:
    """Attribute-Based Access Control engine."""

    def __init__(self) -> None:
        self._policies: List[ABACPolicy] = []
        self._default_effect = "DENY"  # Deny by default

    def add_policy(self, policy: ABACPolicy) -> None:
        self._policies.append(policy)

    def evaluate(self, subject: Dict[str, Any], resource: Dict[str, Any],
                 action: str, environment: Dict[str, Any] = None) -> bool:
        """Evaluate all policies. DENY takes precedence over ALLOW."""
        env = environment or {}
        allowed = False
        for policy in self._policies:
            try:
                if policy.condition(subject, resource, action, env):
                    if policy.effect == "DENY":
                        return False  # Explicit deny -- immediate rejection
                    allowed = True
            except Exception:
                continue  # Policy error = skip (fail closed)
        return allowed

# Pre-built policies:
def owner_policy():
    """Allow resource owners full access."""
    return ABACPolicy(
        name="owner-full-access",
        description="Resource owners can perform any action",
        condition=lambda sub, res, act, env: sub.get("user_id") == res.get("owner_id"),
        effect="ALLOW",
    )

def role_policy(required_role: str, allowed_actions: List[str]):
    """Allow specific role to perform specific actions."""
    return ABACPolicy(
        name=f"role-{required_role}",
        description=f"Role {required_role} can {allowed_actions}",
        condition=lambda sub, res, act, env: (
            required_role in sub.get("roles", []) and act in allowed_actions
        ),
        effect="ALLOW",
    )

def ip_deny_policy(blocked_ranges: List[str]):
    """Deny access from specific IP ranges."""
    return ABACPolicy(
        name="ip-blocklist",
        description="Block requests from untrusted IPs",
        condition=lambda sub, res, act, env: env.get("ip", "") in blocked_ranges,
        effect="DENY",
    )

# Usage:
# engine = ABACEngine()
# engine.add_policy(owner_policy())
# engine.add_policy(role_policy("admin", ["read", "write", "delete"]))
# engine.add_policy(role_policy("viewer", ["read"]))
# allowed = engine.evaluate(
#     subject={"user_id": 42, "roles": ["viewer"]},
#     resource={"id": 100, "owner_id": 99},
#     action="read"
# )
''',
    config_template="",
)

# ===== Rate Limit Templates (4) =====

_register(
    template_id="TPL-RATELIMIT-NGINX",
    vuln_type="RATE_LIMIT",
    language="nginx",
    framework="nginx",
    description="Nginx rate limiting with zone-based request throttling.",
    effort="TRIVIAL",
    tags=["rate-limit", "nginx", "throttling"],
    code_template="",
    config_template='''\
# /etc/nginx/conf.d/rate_limit.conf

# Define rate limit zones (shared memory):
limit_req_zone $binary_remote_addr zone=general:10m rate=10r/s;
limit_req_zone $binary_remote_addr zone=login:10m rate=3r/m;
limit_req_zone $binary_remote_addr zone=api:10m rate=30r/s;
limit_req_zone $binary_remote_addr zone=search:10m rate=5r/s;

# Custom error page for rate limiting:
limit_req_status 429;

server {
    listen 443 ssl;
    server_name example.com;

    # General rate limit (10 req/s with burst of 20):
    location / {
        limit_req zone=general burst=20 nodelay;
        proxy_pass http://backend;
    }

    # Strict rate limit for login (3 req/min):
    location /api/auth/login {
        limit_req zone=login burst=5 nodelay;
        proxy_pass http://backend;
    }

    # API rate limit (30 req/s with burst of 50):
    location /api/ {
        limit_req zone=api burst=50 nodelay;
        proxy_pass http://backend;
    }

    # Search rate limit (5 req/s):
    location /api/search {
        limit_req zone=search burst=10 nodelay;
        proxy_pass http://backend;
    }

    # Return proper 429 response:
    error_page 429 = @rate_limited;
    location @rate_limited {
        default_type application/json;
        return 429 '{"error": "rate_limit_exceeded", "retry_after": 60}';
    }
}
''',
)

_register(
    template_id="TPL-RATELIMIT-EXPRESS",
    vuln_type="RATE_LIMIT",
    language="javascript",
    framework="express",
    description="Express rate limiting with express-rate-limit middleware.",
    effort="TRIVIAL",
    tags=["rate-limit", "express", "middleware"],
    code_template='''\
// Rate limiting for Express.js applications
const rateLimit = require('express-rate-limit');

// General API rate limiter:
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,  // 15 minutes
    max: 100,                   // 100 requests per window
    standardHeaders: true,      // Return rate limit info in headers
    legacyHeaders: false,
    message: {
        error: 'rate_limit_exceeded',
        message: 'Too many requests, please try again later',
        retry_after: 900,
    },
    keyGenerator: (req) => {
        // Use X-Forwarded-For behind reverse proxy
        return req.headers['x-forwarded-for'] || req.ip;
    },
});

// Strict limiter for auth endpoints:
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,                     // 5 login attempts per 15 min
    skipSuccessfulRequests: true,
    message: {
        error: 'auth_rate_limit',
        message: 'Too many login attempts. Account temporarily locked.',
        retry_after: 900,
    },
});

// Apply limiters:
app.use('/api/', apiLimiter);
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);

// Per-user rate limit (after authentication):
const userLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 30,
    keyGenerator: (req) => req.user?.id || req.ip,
});
app.use('/api/user/', userLimiter);
''',
    config_template="",
)

_register(
    template_id="TPL-RATELIMIT-DJANGO",
    vuln_type="RATE_LIMIT",
    language="python",
    framework="django",
    description="Django rate limiting with decorator-based throttling.",
    effort="LOW",
    tags=["rate-limit", "django", "throttling", "decorator"],
    code_template='''\
# Django rate limiter -- pure stdlib implementation (no django-ratelimit needed)

import time
import hashlib
import threading
from functools import wraps
from typing import Callable, Dict, Tuple

class RateLimiter:
    """In-memory rate limiter using sliding window counter."""

    def __init__(self) -> None:
        self._windows: Dict[str, list] = {}
        self._lock = threading.RLock()

    def is_allowed(self, key: str, max_requests: int, window_seconds: int) -> Tuple[bool, int]:
        """Check if request is allowed. Returns (allowed, remaining)."""
        now = time.time()
        cutoff = now - window_seconds

        with self._lock:
            if key not in self._windows:
                self._windows[key] = []

            # Remove expired entries
            self._windows[key] = [t for t in self._windows[key] if t > cutoff]

            if len(self._windows[key]) >= max_requests:
                return False, 0

            self._windows[key].append(now)
            remaining = max_requests - len(self._windows[key])
            return True, remaining

_limiter = RateLimiter()

def rate_limit(max_requests: int = 10, window: int = 60, key_func: Callable = None):
    """Decorator for Django views with rate limiting."""
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            from django.http import JsonResponse

            # Generate rate limit key
            if key_func:
                rl_key = key_func(request)
            else:
                ip = request.META.get("HTTP_X_FORWARDED_FOR", "").split(",")[0].strip()
                ip = ip or request.META.get("REMOTE_ADDR", "unknown")
                path = request.path
                rl_key = hashlib.sha256(f"{ip}:{path}".encode()).hexdigest()

            allowed, remaining = _limiter.is_allowed(rl_key, max_requests, window)

            if not allowed:
                response = JsonResponse({
                    "error": "rate_limit_exceeded",
                    "retry_after": window,
                }, status=429)
                response["Retry-After"] = str(window)
                return response

            response = view_func(request, *args, **kwargs)
            response["X-RateLimit-Remaining"] = str(remaining)
            response["X-RateLimit-Limit"] = str(max_requests)
            return response
        return wrapper
    return decorator

# Usage:
# @rate_limit(max_requests=5, window=900)  # 5 per 15 min
# def login_view(request):
#     ...
''',
    config_template="",
)

_register(
    template_id="TPL-RATELIMIT-REDIS-TOKENBUCKET",
    vuln_type="RATE_LIMIT",
    language="python",
    framework="redis",
    description="Token bucket rate limiter pattern (pure Python, Redis-compatible logic).",
    effort="MEDIUM",
    tags=["rate-limit", "token-bucket", "redis", "algorithm"],
    code_template='''\
# Token Bucket Rate Limiter -- pure Python implementation
# (Production: back with Redis for distributed systems)

import time
import threading
from typing import Dict, Tuple

class TokenBucket:
    """Token bucket rate limiter.

    Allows bursts up to bucket capacity, then refills at steady rate.
    More flexible than fixed-window counters.
    """

    def __init__(self, capacity: int = 10, refill_rate: float = 1.0) -> None:
        """
        Args:
            capacity: Maximum tokens (burst size).
            refill_rate: Tokens added per second.
        """
        self.capacity = capacity
        self.refill_rate = refill_rate
        self._buckets: Dict[str, Tuple[float, float]] = {}  # key -> (tokens, last_refill)
        self._lock = threading.RLock()

    def consume(self, key: str, tokens: int = 1) -> Tuple[bool, float, int]:
        """Try to consume tokens. Returns (allowed, wait_time, remaining)."""
        now = time.time()

        with self._lock:
            if key not in self._buckets:
                self._buckets[key] = (float(self.capacity), now)

            current_tokens, last_refill = self._buckets[key]

            # Refill tokens based on elapsed time
            elapsed = now - last_refill
            refilled = current_tokens + (elapsed * self.refill_rate)
            current_tokens = min(refilled, float(self.capacity))

            if current_tokens >= tokens:
                # Consume tokens
                current_tokens -= tokens
                self._buckets[key] = (current_tokens, now)
                return True, 0.0, int(current_tokens)
            else:
                # Not enough tokens -- calculate wait time
                deficit = tokens - current_tokens
                wait_time = deficit / self.refill_rate
                self._buckets[key] = (current_tokens, now)
                return False, wait_time, 0

    def cleanup(self, max_age: float = 3600.0) -> int:
        """Remove stale bucket entries. Returns count removed."""
        now = time.time()
        removed = 0
        with self._lock:
            stale = [k for k, (_, t) in self._buckets.items() if now - t > max_age]
            for k in stale:
                del self._buckets[k]
                removed += 1
        return removed

# Pre-configured limiters for common scenarios:
class RateLimitPresets:
    """Ready-to-use rate limiter configurations."""

    @staticmethod
    def api_general() -> TokenBucket:
        """30 req/s with burst of 60."""
        return TokenBucket(capacity=60, refill_rate=30.0)

    @staticmethod
    def login() -> TokenBucket:
        """5 attempts per 15 min."""
        return TokenBucket(capacity=5, refill_rate=5.0 / 900.0)

    @staticmethod
    def password_reset() -> TokenBucket:
        """3 requests per hour."""
        return TokenBucket(capacity=3, refill_rate=3.0 / 3600.0)

    @staticmethod
    def search() -> TokenBucket:
        """10 req/s with burst of 20."""
        return TokenBucket(capacity=20, refill_rate=10.0)
''',
    config_template="",
)

# ===== CORS Templates (4) =====

_register(
    template_id="TPL-CORS-NGINX",
    vuln_type="CORS",
    language="nginx",
    framework="nginx",
    description="Strict CORS configuration for Nginx with origin allowlist.",
    effort="TRIVIAL",
    tags=["cors", "nginx", "headers"],
    code_template="",
    config_template='''\
# /etc/nginx/snippets/cors.conf
# Strict CORS with origin allowlist

# Map allowed origins:
map $http_origin $cors_origin {
    default "";
    "https://app.example.com"     "https://app.example.com";
    "https://admin.example.com"   "https://admin.example.com";
    "https://staging.example.com" "https://staging.example.com";
}

server {
    listen 443 ssl;

    location /api/ {
        # Only set CORS headers if origin is in allowlist:
        if ($cors_origin != "") {
            add_header 'Access-Control-Allow-Origin' $cors_origin always;
            add_header 'Access-Control-Allow-Methods' 'GET, POST, PUT, DELETE, OPTIONS' always;
            add_header 'Access-Control-Allow-Headers' 'Authorization, Content-Type, X-Requested-With' always;
            add_header 'Access-Control-Allow-Credentials' 'true' always;
            add_header 'Access-Control-Max-Age' '86400' always;
            add_header 'Vary' 'Origin' always;
        }

        # Handle preflight:
        if ($request_method = 'OPTIONS') {
            add_header 'Access-Control-Allow-Origin' $cors_origin always;
            add_header 'Access-Control-Allow-Methods' 'GET, POST, PUT, DELETE, OPTIONS' always;
            add_header 'Access-Control-Allow-Headers' 'Authorization, Content-Type, X-Requested-With' always;
            add_header 'Access-Control-Max-Age' '86400' always;
            add_header 'Content-Length' '0' always;
            add_header 'Content-Type' 'text/plain' always;
            return 204;
        }

        proxy_pass http://backend;
    }
}
''',
)

_register(
    template_id="TPL-CORS-EXPRESS",
    vuln_type="CORS",
    language="javascript",
    framework="express",
    description="Express CORS middleware with origin allowlist validation.",
    effort="TRIVIAL",
    tags=["cors", "express", "middleware"],
    code_template='''\
// BEFORE (vulnerable -- allow all origins):
// app.use(cors());

// AFTER (safe -- strict origin allowlist):
const cors = require('cors');

const ALLOWED_ORIGINS = new Set([
    'https://app.example.com',
    'https://admin.example.com',
]);

const corsOptions = {
    origin: function (origin, callback) {
        // Allow requests with no origin (mobile apps, curl, etc.)
        // Remove this check if you want to block non-browser requests
        if (!origin) return callback(null, true);

        if (ALLOWED_ORIGINS.has(origin)) {
            callback(null, true);
        } else {
            callback(new Error(`Origin ${origin} not allowed by CORS`));
        }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    allowedHeaders: ['Authorization', 'Content-Type', 'X-Requested-With'],
    credentials: true,
    maxAge: 86400,  // 24 hours preflight cache
    optionsSuccessStatus: 204,
};

app.use(cors(corsOptions));

// Per-route CORS (if needed):
app.get('/api/public', cors({ origin: '*', credentials: false }), (req, res) => {
    res.json({ data: 'public' });
});
''',
    config_template="",
)

_register(
    template_id="TPL-CORS-DJANGO",
    vuln_type="CORS",
    language="python",
    framework="django",
    description="Django CORS middleware with strict origin validation.",
    effort="TRIVIAL",
    tags=["cors", "django", "middleware"],
    code_template='''\
# Django CORS middleware -- pure implementation (no django-cors-headers needed)

import re
from typing import List, Set

class StrictCORSMiddleware:
    """CORS middleware with origin allowlist."""

    ALLOWED_ORIGINS: Set[str] = {
        "https://app.example.com",
        "https://admin.example.com",
    }
    ALLOWED_METHODS: str = "GET, POST, PUT, DELETE, PATCH, OPTIONS"
    ALLOWED_HEADERS: str = "Authorization, Content-Type, X-Requested-With"
    MAX_AGE: int = 86400

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Handle preflight
        if request.method == "OPTIONS":
            response = self._preflight_response(request)
            return response

        response = self.get_response(request)
        origin = request.META.get("HTTP_ORIGIN", "")
        if origin in self.ALLOWED_ORIGINS:
            response["Access-Control-Allow-Origin"] = origin
            response["Access-Control-Allow-Credentials"] = "true"
            response["Vary"] = "Origin"
        return response

    def _preflight_response(self, request):
        from django.http import HttpResponse
        origin = request.META.get("HTTP_ORIGIN", "")
        response = HttpResponse(status=204)
        if origin in self.ALLOWED_ORIGINS:
            response["Access-Control-Allow-Origin"] = origin
            response["Access-Control-Allow-Methods"] = self.ALLOWED_METHODS
            response["Access-Control-Allow-Headers"] = self.ALLOWED_HEADERS
            response["Access-Control-Allow-Credentials"] = "true"
            response["Access-Control-Max-Age"] = str(self.MAX_AGE)
            response["Vary"] = "Origin"
        return response

# In settings.py:
# MIDDLEWARE = [
#     "myapp.middleware.StrictCORSMiddleware",
#     ...
# ]
''',
    config_template="",
)

_register(
    template_id="TPL-CORS-SPRING",
    vuln_type="CORS",
    language="java",
    framework="spring-boot",
    description="Spring Boot CORS configuration with origin allowlist.",
    effort="TRIVIAL",
    tags=["cors", "spring", "java", "configuration"],
    code_template='''\
// BEFORE (vulnerable):
// @CrossOrigin(origins = "*")

// AFTER (safe -- strict CORS configuration):
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class CorsConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")
            .allowedOrigins(
                "https://app.example.com",
                "https://admin.example.com"
            )
            .allowedMethods("GET", "POST", "PUT", "DELETE", "PATCH")
            .allowedHeaders("Authorization", "Content-Type", "X-Requested-With")
            .allowCredentials(true)
            .maxAge(86400);

        // Public endpoints (no credentials):
        registry.addMapping("/api/public/**")
            .allowedOrigins("*")
            .allowedMethods("GET")
            .allowCredentials(false)
            .maxAge(86400);
    }
}

// For Spring Security integration:
// @Bean
// public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//     http.cors(cors -> cors.configurationSource(request -> {
//         CorsConfiguration config = new CorsConfiguration();
//         config.setAllowedOrigins(List.of("https://app.example.com"));
//         config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
//         config.setAllowedHeaders(List.of("Authorization", "Content-Type"));
//         config.setAllowCredentials(true);
//         return config;
//     }));
//     return http.build();
// }
''',
    config_template="",
)

# ===== Headers Templates (4) -- first 2 here, remaining 2 in part 2 =====

_register(
    template_id="TPL-HEADERS-NGINX",
    vuln_type="HEADERS",
    language="nginx",
    framework="nginx",
    description="Complete security header suite for Nginx.",
    effort="TRIVIAL",
    tags=["headers", "nginx", "csp", "hsts"],
    code_template="",
    config_template='''\
# /etc/nginx/snippets/security_headers.conf
# Complete security header suite -- include in server blocks

# HSTS -- force HTTPS for 1 year, include subdomains:
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

# Content Security Policy:
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'" always;

# Prevent MIME type sniffing:
add_header X-Content-Type-Options "nosniff" always;

# Clickjacking protection:
add_header X-Frame-Options "DENY" always;

# Referrer policy:
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# Permissions policy (disable dangerous features):
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()" always;

# Cross-Origin policies:
add_header Cross-Origin-Opener-Policy "same-origin" always;
add_header Cross-Origin-Embedder-Policy "require-corp" always;
add_header Cross-Origin-Resource-Policy "same-origin" always;

# Remove server version:
server_tokens off;

# Usage in server block:
# server {
#     include /etc/nginx/snippets/security_headers.conf;
#     ...
# }
''',
)

_register(
    template_id="TPL-HEADERS-EXPRESS",
    vuln_type="HEADERS",
    language="javascript",
    framework="express",
    description="Complete security header suite for Express.js via Helmet.",
    effort="TRIVIAL",
    tags=["headers", "express", "helmet", "csp"],
    code_template='''\
// Complete security headers for Express.js
const helmet = require('helmet');

app.use(helmet({
    // Strict-Transport-Security:
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true,
    },
    // Content-Security-Policy:
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
            fontSrc: ["'self'"],
            connectSrc: ["'self'"],
            frameAncestors: ["'none'"],
            baseUri: ["'self'"],
            formAction: ["'self'"],
            objectSrc: ["'none'"],
        },
    },
    // X-Content-Type-Options: nosniff
    noSniff: true,
    // X-Frame-Options: DENY
    frameguard: { action: 'deny' },
    // Referrer-Policy:
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    // Cross-Origin policies:
    crossOriginEmbedderPolicy: true,
    crossOriginOpenerPolicy: { policy: 'same-origin' },
    crossOriginResourcePolicy: { policy: 'same-origin' },
    // Disable X-Powered-By:
    hidePoweredBy: true,
    // Permissions-Policy:
    permittedCrossDomainPolicies: { permittedPolicies: 'none' },
}));

// Custom Permissions-Policy (not fully covered by Helmet):
app.use((req, res, next) => {
    res.setHeader('Permissions-Policy',
        'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
    next();
});
''',
    config_template="",
)

_register(
    template_id="TPL-HEADERS-DJANGO",
    vuln_type="HEADERS",
    language="python",
    framework="django",
    description="Complete security header suite for Django via settings and middleware.",
    effort="TRIVIAL",
    tags=["headers", "django", "csp", "hsts"],
    code_template='''\
# Django settings.py -- security headers configuration

# HSTS:
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# HTTPS enforcement:
SECURE_SSL_REDIRECT = True
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# Cookie security:
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True

# Content sniffing:
SECURE_CONTENT_TYPE_NOSNIFF = True

# Clickjacking:
X_FRAME_OPTIONS = "DENY"

# Referrer policy:
SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"

# Cross-origin opener policy:
SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"

# Custom CSP middleware:
class CSPMiddleware:
    """Add Content-Security-Policy header."""

    CSP_DIRECTIVES = {
        "default-src": "'self'",
        "script-src": "'self'",
        "style-src": "'self' 'unsafe-inline'",
        "img-src": "'self' data: https:",
        "font-src": "'self'",
        "connect-src": "'self'",
        "frame-ancestors": "'none'",
        "base-uri": "'self'",
        "form-action": "'self'",
        "object-src": "'none'",
    }

    def __init__(self, get_response):
        self.get_response = get_response
        self._csp_value = "; ".join(
            f"{k} {v}" for k, v in self.CSP_DIRECTIVES.items()
        )

    def __call__(self, request):
        response = self.get_response(request)
        response["Content-Security-Policy"] = self._csp_value
        response["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        )
        response["Cross-Origin-Embedder-Policy"] = "require-corp"
        response["Cross-Origin-Resource-Policy"] = "same-origin"
        return response
''',
    config_template="",
)

_register(
    template_id="TPL-HEADERS-SPRING",
    vuln_type="HEADERS",
    language="java",
    framework="spring-boot",
    description="Complete security header suite for Spring Boot via Spring Security.",
    effort="LOW",
    tags=["headers", "spring", "java", "spring-security"],
    code_template='''\
// Spring Security -- complete security headers configuration
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.*;

@Configuration
public class SecurityHeadersConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.headers(headers -> headers
            // HSTS:
            .httpStrictTransportSecurity(hsts -> hsts
                .maxAgeInSeconds(31536000)
                .includeSubDomains(true)
                .preload(true)
            )
            // Content-Security-Policy:
            .contentSecurityPolicy(csp -> csp
                .policyDirectives(
                    "default-src 'self'; " +
                    "script-src 'self'; " +
                    "style-src 'self' 'unsafe-inline'; " +
                    "img-src 'self' data: https:; " +
                    "frame-ancestors 'none'; " +
                    "base-uri 'self'; " +
                    "form-action 'self'"
                )
            )
            // X-Content-Type-Options:
            .contentTypeOptions(ct -> {})
            // X-Frame-Options:
            .frameOptions(fo -> fo.deny())
            // Referrer-Policy:
            .referrerPolicy(rp -> rp
                .policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN)
            )
            // Permissions-Policy:
            .permissionsPolicy(pp -> pp
                .policy("camera=(), microphone=(), geolocation=(), payment=()")
            )
            // Cross-Origin policies:
            .crossOriginOpenerPolicy(coop -> coop.policy(
                CrossOriginOpenerPolicyHeaderWriter.CrossOriginOpenerPolicy.SAME_ORIGIN
            ))
            .crossOriginEmbedderPolicy(coep -> coep.policy(
                CrossOriginEmbedderPolicyHeaderWriter.CrossOriginEmbedderPolicy.REQUIRE_CORP
            ))
            .crossOriginResourcePolicy(corp -> corp.policy(
                CrossOriginResourcePolicyHeaderWriter.CrossOriginResourcePolicy.SAME_ORIGIN
            ))
        );
        return http.build();
    }
}
''',
    config_template="",
)

# ===== WAF Templates (4) =====

_register(
    template_id="TPL-WAF-MODSEC-SQLI",
    vuln_type="WAF",
    language="modsecurity",
    framework="modsecurity",
    description="ModSecurity rule for SQL injection detection and blocking.",
    effort="LOW",
    tags=["waf", "modsecurity", "sqli", "rule"],
    code_template="",
    config_template='''\
# ModSecurity -- SQL Injection Detection Rules
# Place in /etc/modsecurity/rules/sqli.conf

# Rule 1: Detect common SQL injection keywords in parameters
SecRule ARGS "@rx (?i)(union\\s+(all\\s+)?select|select\\s+.*\\s+from|insert\\s+into|update\\s+.*\\s+set|delete\\s+from|drop\\s+(table|database)|alter\\s+table|exec(ute)?\\s|xp_cmdshell|information_schema)" \\
    "id:100001,\\
    phase:2,\\
    deny,\\
    status:403,\\
    log,\\
    msg:'SQL Injection detected in parameter',\\
    tag:'attack-sqli',\\
    severity:'CRITICAL',\\
    logdata:'Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}'"

# Rule 2: Detect SQL comment injection
SecRule ARGS "@rx (?i)(--|#|/\\*|\\*/|;\\s*$)" \\
    "id:100002,\\
    phase:2,\\
    deny,\\
    status:403,\\
    log,\\
    msg:'SQL comment injection detected',\\
    tag:'attack-sqli',\\
    severity:'HIGH',\\
    chain"
SecRule ARGS "@rx (?i)(select|union|insert|update|delete|drop|alter|exec)" \\
    "t:none,t:urlDecodeUni,t:lowercase"

# Rule 3: Detect SQL injection via User-Agent / Referer
SecRule REQUEST_HEADERS:User-Agent|REQUEST_HEADERS:Referer "@rx (?i)(union|select|from|where|order\\s+by|group\\s+by|having|benchmark|sleep\\(|waitfor)" \\
    "id:100003,\\
    phase:1,\\
    deny,\\
    status:403,\\
    log,\\
    msg:'SQL Injection in HTTP header',\\
    tag:'attack-sqli',\\
    severity:'CRITICAL'"

# Rule 4: Block numeric SQL injection (1 OR 1=1)
SecRule ARGS "@rx (?i)(\\b\\d+\\s*(=|<|>|!=|<>|<=|>=)\\s*\\d+\\b|\\bOR\\s+\\d+\\s*=\\s*\\d+)" \\
    "id:100004,\\
    phase:2,\\
    deny,\\
    status:403,\\
    log,\\
    msg:'Numeric SQL injection pattern detected',\\
    tag:'attack-sqli',\\
    severity:'HIGH'"
''',
)

_register(
    template_id="TPL-WAF-MODSEC-XSS",
    vuln_type="WAF",
    language="modsecurity",
    framework="modsecurity",
    description="ModSecurity rule for XSS detection and blocking.",
    effort="LOW",
    tags=["waf", "modsecurity", "xss", "rule"],
    code_template="",
    config_template='''\
# ModSecurity -- XSS Detection Rules
# Place in /etc/modsecurity/rules/xss.conf

# Rule 1: Detect script tags
SecRule ARGS "@rx (?i)<script[^>]*>.*?</script>" \\
    "id:100010,\\
    phase:2,\\
    deny,\\
    status:403,\\
    log,\\
    msg:'XSS: Script tag detected',\\
    tag:'attack-xss',\\
    severity:'CRITICAL'"

# Rule 2: Detect event handlers (onclick, onerror, etc.)
SecRule ARGS "@rx (?i)\\bon(error|load|click|mouseover|mouseout|focus|blur|submit|change|keyup|keydown|keypress)\\s*=" \\
    "id:100011,\\
    phase:2,\\
    deny,\\
    status:403,\\
    log,\\
    msg:'XSS: Event handler detected',\\
    tag:'attack-xss',\\
    severity:'HIGH'"

# Rule 3: Detect javascript: protocol
SecRule ARGS "@rx (?i)javascript\\s*:" \\
    "id:100012,\\
    phase:2,\\
    deny,\\
    status:403,\\
    log,\\
    msg:'XSS: javascript: protocol detected',\\
    tag:'attack-xss',\\
    severity:'HIGH'"

# Rule 4: Detect data: protocol abuse
SecRule ARGS "@rx (?i)data\\s*:\\s*text/(html|javascript)" \\
    "id:100013,\\
    phase:2,\\
    deny,\\
    status:403,\\
    log,\\
    msg:'XSS: data: protocol abuse detected',\\
    tag:'attack-xss',\\
    severity:'HIGH'"

# Rule 5: Detect SVG-based XSS
SecRule ARGS "@rx (?i)<svg[^>]*\\son\\w+\\s*=" \\
    "id:100014,\\
    phase:2,\\
    deny,\\
    status:403,\\
    log,\\
    msg:'XSS: SVG event handler detected',\\
    tag:'attack-xss',\\
    severity:'HIGH'"
''',
)

_register(
    template_id="TPL-WAF-CLOUDFLARE",
    vuln_type="WAF",
    language="cloudflare",
    framework="cloudflare",
    description="Cloudflare WAF custom expression rules for common attacks.",
    effort="LOW",
    tags=["waf", "cloudflare", "firewall-rules"],
    code_template="",
    config_template='''\
# Cloudflare WAF Custom Rules (Firewall Rules expressions)

# Rule 1: Block SQL Injection attempts
# Expression:
(http.request.uri.query contains "UNION" and http.request.uri.query contains "SELECT") or
(http.request.uri.query contains "' OR " and http.request.uri.query contains "=") or
(http.request.body contains "UNION SELECT") or
(http.request.body contains "1=1") or
(http.request.body contains "' OR '1'='1")
# Action: Block

# Rule 2: Block XSS attempts
# Expression:
(http.request.uri.query contains "<script") or
(http.request.uri.query contains "javascript:") or
(http.request.body contains "<script") or
(http.request.body contains "onerror=") or
(http.request.body contains "onload=")
# Action: Block

# Rule 3: Block suspicious User-Agents (scanners)
# Expression:
(http.user_agent contains "sqlmap") or
(http.user_agent contains "nikto") or
(http.user_agent contains "nessus") or
(http.user_agent contains "masscan") or
(http.user_agent contains "dirbuster") or
(http.user_agent eq "")
# Action: Challenge

# Rule 4: Rate limit login endpoint
# Expression:
(http.request.uri.path eq "/api/auth/login" and http.request.method eq "POST")
# Action: Rate Limit (5 requests per 10 minutes)

# Rule 5: Geo-blocking (adjust as needed)
# Expression:
(not ip.geoip.country in {"US" "BR" "GB" "DE" "FR" "JP"})
# Action: Challenge
''',
)

_register(
    template_id="TPL-WAF-AWS",
    vuln_type="WAF",
    language="json",
    framework="aws-waf",
    description="AWS WAF v2 JSON rule group for SQL injection and XSS protection.",
    effort="MEDIUM",
    tags=["waf", "aws", "wafv2", "rule-group"],
    code_template="",
    config_template='''\
{
    "Name": "SirenProtectionRuleGroup",
    "Scope": "REGIONAL",
    "Capacity": 500,
    "Rules": [
        {
            "Name": "BlockSQLInjection",
            "Priority": 1,
            "Action": {"Block": {}},
            "Statement": {
                "SqliMatchStatement": {
                    "FieldToMatch": {"Body": {}},
                    "TextTransformations": [
                        {"Priority": 0, "Type": "URL_DECODE"},
                        {"Priority": 1, "Type": "HTML_ENTITY_DECODE"},
                        {"Priority": 2, "Type": "LOWERCASE"}
                    ]
                }
            },
            "VisibilityConfig": {
                "SampledRequestsEnabled": true,
                "CloudWatchMetricsEnabled": true,
                "MetricName": "BlockSQLInjection"
            }
        },
        {
            "Name": "BlockXSS",
            "Priority": 2,
            "Action": {"Block": {}},
            "Statement": {
                "XssMatchStatement": {
                    "FieldToMatch": {"Body": {}},
                    "TextTransformations": [
                        {"Priority": 0, "Type": "URL_DECODE"},
                        {"Priority": 1, "Type": "HTML_ENTITY_DECODE"}
                    ]
                }
            },
            "VisibilityConfig": {
                "SampledRequestsEnabled": true,
                "CloudWatchMetricsEnabled": true,
                "MetricName": "BlockXSS"
            }
        },
        {
            "Name": "RateLimitGlobal",
            "Priority": 3,
            "Action": {"Block": {}},
            "Statement": {
                "RateBasedStatement": {
                    "Limit": 2000,
                    "AggregateKeyType": "IP"
                }
            },
            "VisibilityConfig": {
                "SampledRequestsEnabled": true,
                "CloudWatchMetricsEnabled": true,
                "MetricName": "RateLimitGlobal"
            }
        },
        {
            "Name": "BlockBadBots",
            "Priority": 4,
            "Action": {"Block": {}},
            "Statement": {
                "ByteMatchStatement": {
                    "FieldToMatch": {
                        "SingleHeader": {"Name": "user-agent"}
                    },
                    "PositionalConstraint": "CONTAINS",
                    "SearchString": "sqlmap",
                    "TextTransformations": [
                        {"Priority": 0, "Type": "LOWERCASE"}
                    ]
                }
            },
            "VisibilityConfig": {
                "SampledRequestsEnabled": true,
                "CloudWatchMetricsEnabled": true,
                "MetricName": "BlockBadBots"
            }
        }
    ],
    "VisibilityConfig": {
        "SampledRequestsEnabled": true,
        "CloudWatchMetricsEnabled": true,
        "MetricName": "SirenProtectionRuleGroup"
    }
}
''',
)

# ===== TLS Templates (2) =====

_register(
    template_id="TPL-TLS-NGINX",
    vuln_type="TLS",
    language="nginx",
    framework="nginx",
    description="Nginx TLS 1.2+ configuration with modern cipher suites.",
    effort="LOW",
    tags=["tls", "nginx", "ssl", "cipher-suites"],
    code_template="",
    config_template='''\
# /etc/nginx/snippets/ssl-params.conf
# Modern TLS configuration -- TLS 1.2+ only

# Protocols -- disable SSLv3, TLS 1.0, TLS 1.1:
ssl_protocols TLSv1.2 TLSv1.3;

# Cipher suites -- prefer server ciphers, modern only:
ssl_prefer_server_ciphers on;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;

# DH parameters (generate: openssl dhparam -out /etc/nginx/dhparam.pem 4096):
ssl_dhparam /etc/nginx/dhparam.pem;

# ECDH curve:
ssl_ecdh_curve secp384r1;

# Session configuration:
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:50m;
ssl_session_tickets off;

# OCSP stapling:
ssl_stapling on;
ssl_stapling_verify on;
resolver 1.1.1.1 8.8.8.8 valid=300s;
resolver_timeout 5s;

# HSTS:
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

# Usage:
# server {
#     listen 443 ssl http2;
#     ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
#     ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
#     include /etc/nginx/snippets/ssl-params.conf;
# }
''',
)

_register(
    template_id="TPL-TLS-APACHE",
    vuln_type="TLS",
    language="apache",
    framework="apache",
    description="Apache TLS 1.2+ configuration with modern cipher suites.",
    effort="LOW",
    tags=["tls", "apache", "ssl", "cipher-suites"],
    code_template="",
    config_template='''\
# /etc/apache2/conf-available/ssl-params.conf
# Modern TLS configuration for Apache 2.4+

# Enable SSL module:
# a2enmod ssl headers

# Protocols -- TLS 1.2+ only:
SSLProtocol -all +TLSv1.2 +TLSv1.3

# Cipher suites:
SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
SSLHonorCipherOrder on
SSLCompression off

# OCSP Stapling:
SSLUseStapling on
SSLStaplingCache "shmcb:/var/run/apache2/stapling_cache(128000)"
SSLStaplingResponseMaxAge 900

# Session:
SSLSessionTickets off

# HSTS:
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"

# Redirect HTTP to HTTPS:
# <VirtualHost *:80>
#     ServerName example.com
#     Redirect permanent / https://example.com/
# </VirtualHost>
#
# <VirtualHost *:443>
#     SSLEngine on
#     SSLCertificateFile /etc/letsencrypt/live/example.com/fullchain.pem
#     SSLCertificateKeyFile /etc/letsencrypt/live/example.com/privkey.pem
#     Include /etc/apache2/conf-available/ssl-params.conf
# </VirtualHost>
''',
)

# ===== SSRF Templates (2) =====

_register(
    template_id="TPL-SSRF-ALLOWLIST",
    vuln_type="SSRF",
    language="python",
    framework="generic",
    description="URL allowlist pattern to prevent server-side request forgery.",
    effort="MEDIUM",
    tags=["ssrf", "allowlist", "url-validation"],
    code_template='''\
# BEFORE (vulnerable -- fetches any user-supplied URL):
# response = urllib.request.urlopen(user_url)

# AFTER (safe -- strict URL allowlist):
import ipaddress
import re
import socket
from typing import List, Optional, Set
from urllib.parse import urlparse

class SSRFProtector:
    """Validates URLs against allowlist before making requests."""

    # Blocked IP ranges (RFC 1918, loopback, link-local, etc.):
    BLOCKED_NETWORKS = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),
        ipaddress.ip_network("0.0.0.0/8"),
        ipaddress.ip_network("100.64.0.0/10"),
        ipaddress.ip_network("::1/128"),
        ipaddress.ip_network("fc00::/7"),
        ipaddress.ip_network("fe80::/10"),
    ]

    ALLOWED_SCHEMES = {"https"}
    ALLOWED_PORTS = {443}

    def __init__(self, allowed_domains: Set[str] = None) -> None:
        self._allowed_domains = allowed_domains or set()

    def add_allowed_domain(self, domain: str) -> None:
        self._allowed_domains.add(domain.lower())

    def validate_url(self, url: str) -> bool:
        """Validate URL is safe to request. Returns True if allowed."""
        try:
            parsed = urlparse(url)
        except Exception:
            return False

        # Check scheme
        if parsed.scheme not in self.ALLOWED_SCHEMES:
            return False

        # Check port
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if port not in self.ALLOWED_PORTS:
            return False

        hostname = parsed.hostname
        if not hostname:
            return False

        # Check domain allowlist
        if self._allowed_domains:
            if not any(
                hostname == d or hostname.endswith(f".{d}")
                for d in self._allowed_domains
            ):
                return False

        # Resolve DNS and check IP
        try:
            addr_infos = socket.getaddrinfo(hostname, port)
            for family, _type, _proto, _canon, sockaddr in addr_infos:
                ip = ipaddress.ip_address(sockaddr[0])
                for network in self.BLOCKED_NETWORKS:
                    if ip in network:
                        return False
        except socket.gaierror:
            return False

        return True

# Usage:
# protector = SSRFProtector(allowed_domains={"api.example.com", "cdn.example.com"})
# if protector.validate_url(user_url):
#     response = urllib.request.urlopen(user_url)
''',
    config_template="",
)

_register(
    template_id="TPL-SSRF-URL-VALIDATION",
    vuln_type="SSRF",
    language="javascript",
    framework="node",
    description="URL validation and DNS rebinding protection for Node.js.",
    effort="MEDIUM",
    tags=["ssrf", "url-validation", "dns-rebinding", "node"],
    code_template='''\
// BEFORE (vulnerable):
// const response = await fetch(userProvidedUrl);

// AFTER (safe -- URL validation with DNS rebinding protection):
const { URL } = require('url');
const dns = require('dns');
const net = require('net');

const BLOCKED_RANGES = [
    /^127\\./,
    /^10\\./,
    /^172\\.(1[6-9]|2[0-9]|3[01])\\./,
    /^192\\.168\\./,
    /^169\\.254\\./,
    /^0\\./,
    /^::1$/,
    /^f[cd]/i,
    /^fe80/i,
];

const ALLOWED_PROTOCOLS = new Set(['https:']);
const ALLOWED_PORTS = new Set([443]);

async function validateUrl(userUrl) {
    let parsed;
    try {
        parsed = new URL(userUrl);
    } catch {
        throw new Error('Invalid URL format');
    }

    // Protocol check
    if (!ALLOWED_PROTOCOLS.has(parsed.protocol)) {
        throw new Error(`Blocked protocol: ${parsed.protocol}`);
    }

    // Port check
    const port = parsed.port ? parseInt(parsed.port) : 443;
    if (!ALLOWED_PORTS.has(port)) {
        throw new Error(`Blocked port: ${port}`);
    }

    // Resolve DNS to prevent rebinding attacks
    const addresses = await dns.promises.resolve4(parsed.hostname);

    for (const addr of addresses) {
        if (BLOCKED_RANGES.some(pattern => pattern.test(addr))) {
            throw new Error(`Blocked IP range: ${addr}`);
        }
    }

    // Double-check: resolve again right before request (anti-rebinding)
    const addresses2 = await dns.promises.resolve4(parsed.hostname);
    for (const addr of addresses2) {
        if (BLOCKED_RANGES.some(pattern => pattern.test(addr))) {
            throw new Error(`DNS rebinding detected: ${addr}`);
        }
    }

    return parsed.toString();
}

// Usage:
// try {
//     const safeUrl = await validateUrl(userInput);
//     const response = await fetch(safeUrl);
// } catch (err) {
//     console.error('SSRF blocked:', err.message);
// }
''',
    config_template="",
)

# ===== CMDi Templates (2) =====

_register(
    template_id="TPL-CMDI-SUBPROCESS",
    vuln_type="CMDI",
    language="python",
    framework="subprocess",
    description="Replace os.system/shell=True with subprocess argv list.",
    effort="LOW",
    tags=["cmdi", "python", "subprocess", "command-injection"],
    code_template='''\
# BEFORE (vulnerable):
# os.system(f"ping {user_input}")
# subprocess.call(f"nslookup {domain}", shell=True)

# AFTER (safe -- subprocess with argv list, NO shell=True):
import subprocess
import re

def safe_ping(host: str, count: int = 4) -> str:
    """Safe ping execution with input validation."""
    # Validate hostname format (alphanumeric, dots, hyphens only):
    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9.\\-]{0,253}[a-zA-Z0-9]$", host):
        raise ValueError(f"Invalid hostname: {host}")

    # Use argv list -- each argument is a separate element:
    result = subprocess.run(
        ["ping", "-c", str(count), host],  # NO shell=True
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.stdout

def safe_nslookup(domain: str) -> str:
    """Safe DNS lookup with strict validation."""
    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9.\\-]{0,253}$", domain):
        raise ValueError(f"Invalid domain: {domain}")

    result = subprocess.run(
        ["nslookup", domain],  # Argv list, no shell
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.stdout

def safe_git_clone(repo_url: str, dest: str) -> str:
    """Safe git clone with URL validation."""
    # Only allow HTTPS git URLs:
    if not re.match(r"^https://[a-zA-Z0-9.\\-]+/[a-zA-Z0-9_.\\-/]+\\.git$", repo_url):
        raise ValueError(f"Invalid repo URL: {repo_url}")

    result = subprocess.run(
        ["git", "clone", "--depth", "1", repo_url, dest],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git clone failed: {result.stderr}")
    return result.stdout
''',
    config_template="",
)

_register(
    template_id="TPL-CMDI-SHLEX",
    vuln_type="CMDI",
    language="python",
    framework="shlex",
    description="Use shlex.quote for safe shell argument escaping when shell=True is unavoidable.",
    effort="TRIVIAL",
    tags=["cmdi", "python", "shlex", "escaping"],
    code_template='''\
# When shell=True is UNAVOIDABLE (legacy code, complex pipelines):
import shlex
import subprocess

def safe_shell_command(filename: str) -> str:
    """Use shlex.quote to escape shell arguments."""
    # shlex.quote wraps the string in single quotes and escapes:
    safe_filename = shlex.quote(filename)
    cmd = f"wc -l {safe_filename}"

    result = subprocess.run(
        cmd,
        shell=True,   # Only when absolutely necessary
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.stdout

# Better approach: build command with shlex.join (Python 3.8+):
def safe_shell_join(args: list) -> str:
    """Use shlex.join for building safe shell command strings."""
    cmd = shlex.join(["grep", "-r", args[0], args[1]])
    result = subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.stdout

# Best approach: AVOID shell=True entirely:
def best_approach(pattern: str, directory: str) -> str:
    """Direct argv list -- no shell, no escaping needed."""
    result = subprocess.run(
        ["grep", "-r", pattern, directory],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.stdout
''',
    config_template="",
)

# ===== File Upload Templates (2) =====

_register(
    template_id="TPL-UPLOAD-EXTENSION",
    vuln_type="FILE_UPLOAD",
    language="python",
    framework="generic",
    description="File upload extension whitelist with double-extension check.",
    effort="LOW",
    tags=["file-upload", "extension", "whitelist", "validation"],
    code_template='''\
# BEFORE (vulnerable -- no file type validation):
# uploaded_file.save(f"/uploads/{uploaded_file.filename}")

# AFTER (safe -- strict extension whitelist + sanitization):
import os
import re
import uuid
import hashlib

ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".pdf", ".txt", ".csv"}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
UPLOAD_DIR = "/var/www/uploads"

def validate_and_save(filename: str, file_content: bytes) -> str:
    """Validate file and save with safe random name."""
    # 1. Check file size
    if len(file_content) > MAX_FILE_SIZE:
        raise ValueError(f"File too large: {len(file_content)} bytes (max {MAX_FILE_SIZE})")

    # 2. Sanitize filename -- strip path traversal
    basename = os.path.basename(filename)
    basename = re.sub(r"[^a-zA-Z0-9._-]", "_", basename)

    # 3. Check for double extensions (.php.jpg, .jsp.png, etc.)
    parts = basename.split(".")
    dangerous_extensions = {
        "php", "php3", "php4", "php5", "phtml", "phar",
        "jsp", "jspx", "asp", "aspx", "exe", "sh", "bat",
        "cmd", "com", "cgi", "py", "rb", "pl", "jar", "war",
        "svg", "html", "htm", "shtml", "xhtml",
    }
    for part in parts:
        if part.lower() in dangerous_extensions:
            raise ValueError(f"Dangerous extension detected: {part}")

    # 4. Validate against whitelist
    _, ext = os.path.splitext(basename)
    ext = ext.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError(f"Extension not allowed: {ext}")

    # 5. Generate random filename (prevent overwrite and enumeration)
    safe_name = f"{uuid.uuid4().hex}{ext}"
    safe_path = os.path.join(UPLOAD_DIR, safe_name)

    # 6. Ensure path is within upload directory
    real_path = os.path.realpath(safe_path)
    if not real_path.startswith(os.path.realpath(UPLOAD_DIR)):
        raise ValueError("Path traversal detected")

    # 7. Save file
    with open(safe_path, "wb") as f:
        f.write(file_content)

    return safe_name
''',
    config_template="",
)

_register(
    template_id="TPL-UPLOAD-MAGIC-BYTES",
    vuln_type="FILE_UPLOAD",
    language="python",
    framework="generic",
    description="Magic bytes (file signature) validation for upload content verification.",
    effort="LOW",
    tags=["file-upload", "magic-bytes", "content-type", "validation"],
    code_template='''\
# Validate file content by checking magic bytes (file signatures)
# Prevents renaming malicious files with safe extensions

import struct
from typing import Optional

# Magic byte signatures for common file types:
MAGIC_SIGNATURES = {
    "image/jpeg": [
        (b"\\xff\\xd8\\xff\\xe0", 0),  # JFIF
        (b"\\xff\\xd8\\xff\\xe1", 0),  # EXIF
        (b"\\xff\\xd8\\xff\\xdb", 0),  # JPEG raw
    ],
    "image/png": [
        (b"\\x89PNG\\r\\n\\x1a\\n", 0),
    ],
    "image/gif": [
        (b"GIF87a", 0),
        (b"GIF89a", 0),
    ],
    "application/pdf": [
        (b"%PDF-", 0),
    ],
    "application/zip": [
        (b"PK\\x03\\x04", 0),
    ],
    "text/plain": [],  # No magic bytes -- validated differently
    "text/csv": [],
}

# Dangerous content patterns (should NEVER appear in uploads):
DANGEROUS_PATTERNS = [
    b"<?php",
    b"<%@",           # JSP
    b"<script",
    b"#!/",           # Shebang
    b"import os",     # Python
    b"eval(",
    b"exec(",
    b"Runtime.getRuntime()",
    b"ProcessBuilder",
]

def validate_magic_bytes(content: bytes, declared_type: str) -> bool:
    """Validate file content matches declared MIME type via magic bytes."""
    if declared_type not in MAGIC_SIGNATURES:
        return False

    signatures = MAGIC_SIGNATURES[declared_type]

    # Text files have no magic bytes -- check for dangerous content instead
    if not signatures:
        return not _contains_dangerous_content(content)

    # Check if any signature matches
    for signature, offset in signatures:
        if content[offset:offset + len(signature)] == signature:
            # Additional check: ensure no embedded dangerous content
            if _contains_dangerous_content(content):
                return False
            return True

    return False

def _contains_dangerous_content(content: bytes) -> bool:
    """Check for embedded malicious patterns."""
    content_lower = content.lower()
    for pattern in DANGEROUS_PATTERNS:
        if pattern.lower() in content_lower:
            return True
    return False

def get_content_type(content: bytes) -> Optional[str]:
    """Detect content type from magic bytes."""
    for mime_type, signatures in MAGIC_SIGNATURES.items():
        for signature, offset in signatures:
            if content[offset:offset + len(signature)] == signature:
                return mime_type
    return None

# Usage:
# content = uploaded_file.read()
# declared = "image/jpeg"
# if not validate_magic_bytes(content, declared):
#     raise ValueError("File content does not match declared type")
# actual = get_content_type(content)
# if actual != declared:
#     raise ValueError(f"Type mismatch: declared={declared}, actual={actual}")
''',
    config_template="",
)

# ===== Deserialization Templates (2) =====

_register(
    template_id="TPL-DESER-PYTHON-SAFE",
    vuln_type="DESERIALIZATION",
    language="python",
    framework="generic",
    description="Replace pickle with JSON or restricted unpickler for safe deserialization.",
    effort="MEDIUM",
    tags=["deserialization", "python", "pickle", "json"],
    code_template='''\
# BEFORE (vulnerable -- pickle deserializes arbitrary objects):
# import pickle
# data = pickle.loads(user_data)

# AFTER (safe -- use JSON or restricted unpickler):
import json
import io
import pickle
from typing import Any, Set

# Option 1: USE JSON (preferred for most cases):
def safe_load(data: str) -> Any:
    """Load data from JSON string -- inherently safe."""
    return json.loads(data)

def safe_dump(obj: Any) -> str:
    """Serialize to JSON string."""
    return json.dumps(obj, default=str)

# Option 2: Restricted unpickler (when pickle format is unavoidable):
class RestrictedUnpickler(pickle.Unpickler):
    """Unpickler that only allows safe built-in types."""

    ALLOWED_CLASSES: Set[str] = {
        "builtins.dict",
        "builtins.list",
        "builtins.set",
        "builtins.tuple",
        "builtins.str",
        "builtins.int",
        "builtins.float",
        "builtins.bool",
        "builtins.bytes",
        "builtins.type",
        "builtins.NoneType",
        "builtins.complex",
        "builtins.frozenset",
        "collections.OrderedDict",
        "collections.defaultdict",
        "datetime.datetime",
        "datetime.date",
        "datetime.time",
        "datetime.timedelta",
    }

    def find_class(self, module: str, name: str) -> Any:
        full_name = f"{module}.{name}"
        if full_name not in self.ALLOWED_CLASSES:
            raise pickle.UnpicklingError(
                f"Blocked deserialization of {full_name}. "
                f"Only allowed: {self.ALLOWED_CLASSES}"
            )
        return super().find_class(module, name)

def restricted_loads(data: bytes) -> Any:
    """Deserialize pickle with restricted class allowlist."""
    return RestrictedUnpickler(io.BytesIO(data)).load()

# Option 3: HMAC-signed pickle (if pickle is required):
import hmac
import hashlib
import os

_SIGNING_KEY = os.environ.get("PICKLE_SIGNING_KEY", "change-me").encode()

def signed_dumps(obj: Any) -> bytes:
    """Serialize and sign with HMAC."""
    data = pickle.dumps(obj, protocol=pickle.HIGHEST_PROTOCOL)
    sig = hmac.new(_SIGNING_KEY, data, hashlib.sha256).digest()
    return sig + data

def signed_loads(signed_data: bytes) -> Any:
    """Verify HMAC signature before deserializing."""
    sig = signed_data[:32]
    data = signed_data[32:]
    expected = hmac.new(_SIGNING_KEY, data, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, expected):
        raise ValueError("Invalid signature -- data may be tampered")
    return restricted_loads(data)
''',
    config_template="",
)

_register(
    template_id="TPL-DESER-JAVA-SAFE",
    vuln_type="DESERIALIZATION",
    language="java",
    framework="generic",
    description="Replace ObjectInputStream with JSON or allowlist-based deserialization.",
    effort="HIGH",
    tags=["deserialization", "java", "objectinputstream", "json"],
    code_template='''\
// BEFORE (vulnerable):
// ObjectInputStream ois = new ObjectInputStream(inputStream);
// Object obj = ois.readObject();

// AFTER (safe -- multiple options):

// Option 1: USE JSON (Jackson -- preferred):
// import com.fasterxml.jackson.databind.ObjectMapper;
// ObjectMapper mapper = new ObjectMapper();
// mapper.enableDefaultTyping();  // DO NOT USE
// MyClass obj = mapper.readValue(jsonString, MyClass.class);  // Type-safe

// Option 2: Allowlist-based ObjectInputStream:
import java.io.*;
import java.util.Set;

public class SafeObjectInputStream extends ObjectInputStream {

    private static final Set<String> ALLOWED_CLASSES = Set.of(
        "java.lang.String",
        "java.lang.Integer",
        "java.lang.Long",
        "java.lang.Double",
        "java.lang.Boolean",
        "java.util.ArrayList",
        "java.util.HashMap",
        "java.util.LinkedHashMap",
        "java.util.HashSet",
        "java.util.Date",
        "[B"  // byte array
    );

    public SafeObjectInputStream(InputStream in) throws IOException {
        super(in);
    }

    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc)
            throws IOException, ClassNotFoundException {
        String className = desc.getName();
        if (!ALLOWED_CLASSES.contains(className)) {
            throw new InvalidClassException(
                "Blocked deserialization of: " + className +
                ". Not in allowlist."
            );
        }
        return super.resolveClass(desc);
    }
}

// Option 3: JEP 290 Serialization Filter (Java 9+):
// ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
//     "java.lang.*;java.util.*;!*"  // Allow java.lang/util, block everything else
// );
// ois.setObjectInputFilter(filter);

// Usage:
// SafeObjectInputStream sois = new SafeObjectInputStream(inputStream);
// Object obj = sois.readObject();  // Only allows whitelisted types
''',
    config_template="",
)

# ===== CSRF Templates (2) =====

_register(
    template_id="TPL-CSRF-TOKEN",
    vuln_type="CSRF",
    language="python",
    framework="flask",
    description="CSRF token implementation with double-submit cookie pattern.",
    effort="MEDIUM",
    tags=["csrf", "token", "flask", "double-submit"],
    code_template='''\
# CSRF protection with double-submit cookie pattern
import hashlib
import hmac
import os
import secrets
import time
from functools import wraps

class CSRFProtector:
    """Double-submit cookie CSRF protection."""

    TOKEN_LENGTH = 32
    TOKEN_LIFETIME = 3600  # 1 hour
    COOKIE_NAME = "_csrf_token"
    HEADER_NAME = "X-CSRF-Token"

    def __init__(self, secret_key: str = None) -> None:
        self._secret = (secret_key or os.environ.get(
            "CSRF_SECRET", secrets.token_hex(32)
        )).encode()

    def generate_token(self) -> str:
        """Generate a signed CSRF token."""
        raw = secrets.token_hex(self.TOKEN_LENGTH)
        timestamp = str(int(time.time()))
        payload = f"{raw}:{timestamp}"
        sig = hmac.new(self._secret, payload.encode(), hashlib.sha256).hexdigest()[:16]
        return f"{payload}:{sig}"

    def validate_token(self, token: str) -> bool:
        """Validate CSRF token signature and expiry."""
        try:
            parts = token.split(":")
            if len(parts) != 3:
                return False
            raw, timestamp_str, sig = parts

            # Check signature
            payload = f"{raw}:{timestamp_str}"
            expected_sig = hmac.new(
                self._secret, payload.encode(), hashlib.sha256
            ).hexdigest()[:16]
            if not hmac.compare_digest(sig, expected_sig):
                return False

            # Check expiry
            timestamp = int(timestamp_str)
            if time.time() - timestamp > self.TOKEN_LIFETIME:
                return False

            return True
        except (ValueError, IndexError):
            return False

# Flask integration:
# csrf = CSRFProtector()
#
# @app.before_request
# def check_csrf():
#     if request.method in ("POST", "PUT", "DELETE", "PATCH"):
#         cookie_token = request.cookies.get(CSRFProtector.COOKIE_NAME, "")
#         header_token = request.headers.get(CSRFProtector.HEADER_NAME, "")
#         if not cookie_token or cookie_token != header_token:
#             abort(403, "CSRF validation failed")
#         if not csrf.validate_token(header_token):
#             abort(403, "CSRF token expired or invalid")
#
# @app.after_request
# def set_csrf_cookie(response):
#     if CSRFProtector.COOKIE_NAME not in request.cookies:
#         token = csrf.generate_token()
#         response.set_cookie(
#             CSRFProtector.COOKIE_NAME, token,
#             secure=True, httponly=False, samesite="Lax",
#         )
#     return response
''',
    config_template="",
)

_register(
    template_id="TPL-CSRF-SAMESITE",
    vuln_type="CSRF",
    language="python",
    framework="generic",
    description="SameSite cookie attribute as CSRF defense layer.",
    effort="TRIVIAL",
    tags=["csrf", "samesite", "cookies", "defense-in-depth"],
    code_template='''\
# SameSite cookie attribute -- modern CSRF defense
# Works as defense-in-depth alongside CSRF tokens

# Python (stdlib http.cookies):
from http.cookies import SimpleCookie

def set_secure_cookie(name: str, value: str) -> str:
    """Generate a Set-Cookie header with SameSite protection."""
    cookie = SimpleCookie()
    cookie[name] = value
    cookie[name]["secure"] = True       # HTTPS only
    cookie[name]["httponly"] = True      # No JavaScript access
    cookie[name]["samesite"] = "Lax"    # CSRF protection
    cookie[name]["path"] = "/"
    cookie[name]["max-age"] = str(1800)  # 30 minutes
    return cookie[name].OutputString()

# SameSite values explained:
# - "Strict": Cookie NEVER sent on cross-site requests
#   Best for: session cookies on banking/admin apps
#   Downside: breaks inbound links (user must re-auth)
#
# - "Lax" (recommended): Cookie sent on top-level GET navigations only
#   Best for: most applications -- balances security and usability
#   Protects against: POST-based CSRF, iframe attacks
#
# - "None": Cookie sent on ALL requests (including cross-site)
#   REQUIRES Secure flag. Only for legitimate cross-site use cases.

# Flask settings.py:
# SESSION_COOKIE_SAMESITE = "Lax"
# SESSION_COOKIE_SECURE = True

# Django settings.py:
# SESSION_COOKIE_SAMESITE = "Lax"
# CSRF_COOKIE_SAMESITE = "Lax"

# Express.js:
# res.cookie('session', token, {
#     sameSite: 'lax',
#     secure: true,
#     httpOnly: true,
# });

# Spring Boot (application.properties):
# server.servlet.session.cookie.same-site=Lax
# server.servlet.session.cookie.secure=true
# server.servlet.session.cookie.http-only=true
''',
    config_template="",
)


# ---------------------------------------------------------------------------
# PriorityQueue -- dependency-aware remediation ordering
# ---------------------------------------------------------------------------


class PriorityQueue:
    """Dependency-aware priority queue for remediation steps.

    Priority formula: severity * (1/effort) * impact
    Higher score = higher priority (fix first).

    Respects dependencies: a step will not be dequeued before all its
    dependencies have been completed.

    Usage::

        pq = PriorityQueue()
        pq.push(step1)
        pq.push(step2)
        while pq:
            next_step = pq.pop()
    """

    def __init__(self) -> None:
        self._heap: List[Tuple[float, int, RemediationStep]] = []
        self._counter: int = 0
        self._lock = threading.RLock()
        self._completed: Set[str] = set()
        self._deferred: List[RemediationStep] = []

    def __len__(self) -> int:
        with self._lock:
            return len(self._heap) + len(self._deferred)

    def __bool__(self) -> bool:
        with self._lock:
            return bool(self._heap) or bool(self._deferred)

    def push(self, step: RemediationStep) -> None:
        """Add a remediation step to the queue."""
        with self._lock:
            priority = step.priority_score()
            # Use negative priority for max-heap behavior with heapq (min-heap)
            heapq.heappush(self._heap, (-priority, self._counter, step))
            self._counter += 1

    def pop(self) -> Optional[RemediationStep]:
        """Remove and return the highest-priority step whose deps are met."""
        with self._lock:
            # First, try to promote deferred steps whose deps are now met
            still_deferred: List[RemediationStep] = []
            for step in self._deferred:
                if self._deps_met(step):
                    priority = step.priority_score()
                    heapq.heappush(self._heap, (-priority, self._counter, step))
                    self._counter += 1
                else:
                    still_deferred.append(step)
            self._deferred = still_deferred

            # Pop from heap, deferring steps with unmet dependencies
            while self._heap:
                neg_priority, _count, step = heapq.heappop(self._heap)
                if self._deps_met(step):
                    self._completed.add(step.step_id)
                    return step
                else:
                    self._deferred.append(step)

            return None

    def peek(self) -> Optional[RemediationStep]:
        """Return the highest-priority step without removing it."""
        with self._lock:
            if self._heap:
                return self._heap[0][2]
            return None

    def mark_completed(self, step_id: str) -> None:
        """Mark a step as completed (for dependency resolution)."""
        with self._lock:
            self._completed.add(step_id)

    def get_all_sorted(self) -> List[RemediationStep]:
        """Return all steps sorted by priority (highest first)."""
        with self._lock:
            all_steps = [step for _, _, step in self._heap] + self._deferred
            all_steps.sort(key=lambda s: s.priority_score(), reverse=True)
            return all_steps

    def _deps_met(self, step: RemediationStep) -> bool:
        """Check if all dependencies of a step are completed."""
        if not step.dependencies:
            return True
        return all(dep in self._completed for dep in step.dependencies)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "queue_size": len(self),
            "completed": list(self._completed),
            "deferred_count": len(self._deferred),
            "steps": [s.to_dict() for s in self.get_all_sorted()],
        }


# ---------------------------------------------------------------------------
# SirenRemediationGenerator -- main orchestrator
# ---------------------------------------------------------------------------


class SirenRemediationGenerator:
    """Automated remediation plan generator with real code fixes.

    Generates SPECIFIC, WORKING code snippets for each vulnerability type
    and language/framework combination. Supports 50 fix templates across
    14 vulnerability categories.

    Usage::

        gen = SirenRemediationGenerator()
        fix = gen.generate_fix({"vuln_type": "SQLI", "language": "python",
                                "framework": "sqlalchemy", "severity": "CRITICAL"})
        plan = gen.generate_plan(findings, hourly_rate=200)
        print(plan.to_markdown())
        quick = gen.get_quick_wins(max_effort=4)
        waf_rules = gen.generate_waf_rules()
        headers = gen.generate_security_headers_config("nginx")
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._templates: Dict[str, List[FixTemplate]] = defaultdict(list)
        self._template_index: Dict[Tuple[str, str, str], FixTemplate] = {}
        self._all_templates: List[FixTemplate] = []
        self._plans: List[RemediationPlan] = []
        self._current_plan: Optional[RemediationPlan] = None
        self._priority_queue = PriorityQueue()
        self.load_templates()
        logger.info("SirenRemediationGenerator initialized -- %d templates loaded",
                     len(self._all_templates))

    # -------------------------------------------------------------------
    # Template loading
    # -------------------------------------------------------------------

    def load_templates(self) -> int:
        """Load all built-in fix templates into the registry.

        Returns:
            Number of templates loaded.
        """
        with self._lock:
            self._templates.clear()
            self._template_index.clear()
            self._all_templates.clear()

            for tpl in _BUILTIN_TEMPLATES:
                self._all_templates.append(tpl)
                self._templates[tpl.vuln_type].append(tpl)
                key = (tpl.vuln_type.upper(), tpl.language.lower(), tpl.framework.lower())
                self._template_index[key] = tpl

            logger.info("Loaded %d fix templates across %d vuln types",
                        len(self._all_templates), len(self._templates))
            return len(self._all_templates)

    def add_template(self, template: FixTemplate) -> None:
        """Add a custom fix template to the registry."""
        with self._lock:
            if not template.template_id:
                template.template_id = _make_template_id(
                    template.vuln_type, template.language, template.framework
                )
            self._all_templates.append(template)
            self._templates[template.vuln_type].append(template)
            key = (template.vuln_type.upper(), template.language.lower(),
                   template.framework.lower())
            self._template_index[key] = template
            logger.debug("Added custom template: %s", template.template_id)

    def get_template(self, vuln_type: str, language: str = "",
                     framework: str = "") -> Optional[FixTemplate]:
        """Look up the best matching template for a given vuln/lang/framework.

        Tries exact match first, then falls back to vuln_type + language,
        then vuln_type only.
        """
        with self._lock:
            vt = vuln_type.upper()
            lang = language.lower()
            fw = framework.lower()

            # Exact match
            key = (vt, lang, fw)
            if key in self._template_index:
                return self._template_index[key]

            # Match by vuln_type + language (any framework)
            for tpl in self._templates.get(vt, []):
                if tpl.language.lower() == lang:
                    return tpl

            # Match by vuln_type only (first available)
            templates = self._templates.get(vt, [])
            if templates:
                return templates[0]

            return None

    def list_templates(self, vuln_type: str = "") -> List[FixTemplate]:
        """List available templates, optionally filtered by vuln type."""
        with self._lock:
            if vuln_type:
                return list(self._templates.get(vuln_type.upper(), []))
            return list(self._all_templates)

    # -------------------------------------------------------------------
    # Fix generation
    # -------------------------------------------------------------------

    def generate_fix(self, finding: Dict[str, Any]) -> Optional[RemediationStep]:
        """Generate a remediation step for a single finding.

        Args:
            finding: Dict with keys: vuln_type, severity, language (opt),
                     framework (opt), title (opt), description (opt),
                     url (opt), parameter (opt).

        Returns:
            A RemediationStep with real code snippets, or None if no
            matching template found.
        """
        with self._lock:
            vuln_type = finding.get("vuln_type", "").upper()
            severity = finding.get("severity", "MEDIUM").upper()
            language = finding.get("language", "")
            framework = finding.get("framework", "")
            title = finding.get("title", f"Fix {vuln_type} vulnerability")
            description = finding.get("description", "")
            url = finding.get("url", "")
            parameter = finding.get("parameter", "")

            template = self.get_template(vuln_type, language, framework)
            if not template:
                logger.warning("No template found for %s/%s/%s", vuln_type, language, framework)
                return self._generate_generic_step(finding)

            # Determine effort and phase
            effort_level = template.effort
            effort_hours = EFFORT_HOURS.get(effort_level, 8.0)
            phase = self._determine_phase(severity, effort_level)
            impact_score = SEVERITY_SCORES.get(severity, 5.0)

            # Build code snippets dict
            code_snippets: Dict[str, str] = {}
            if template.code_template:
                ext = self._lang_extension(template.language)
                filename = f"fix_{vuln_type.lower()}{ext}"
                code_snippets[filename] = template.code_template
            if template.config_template:
                config_ext = self._config_extension(template.framework)
                config_name = f"config_{template.framework.lower()}{config_ext}"
                code_snippets[config_name] = template.config_template

            # Build description
            full_desc = template.description
            if url:
                full_desc += f"\n\nAffected URL: {url}"
            if parameter:
                full_desc += f"\nVulnerable parameter: {parameter}"
            if description:
                full_desc += f"\n\nFinding details: {description}"

            step = RemediationStep(
                title=title,
                description=full_desc,
                vuln_type=vuln_type,
                effort_level=effort_level,
                effort_hours=effort_hours,
                fix_type=self._determine_fix_type(template),
                code_snippets=code_snippets,
                config_changes=self._generate_config_steps(template),
                commands=self._generate_commands(template),
                verification_steps=self._generate_verification(vuln_type, url),
                rollback_steps=self._generate_rollback(template),
                references=self._generate_references(vuln_type),
                dependencies=[],
                severity=severity,
                phase=phase,
                impact_score=impact_score,
            )

            self._priority_queue.push(step)
            logger.debug("Generated fix %s for %s (%s)", step.step_id, vuln_type, severity)
            return step

    def _generate_generic_step(self, finding: Dict[str, Any]) -> RemediationStep:
        """Generate a generic remediation step when no template matches."""
        vuln_type = finding.get("vuln_type", "UNKNOWN")
        severity = finding.get("severity", "MEDIUM")
        return RemediationStep(
            title=f"Remediate {vuln_type} vulnerability",
            description=(
                f"A {severity} severity {vuln_type} vulnerability was identified. "
                "No specific code template is available for this combination. "
                "Manual review and remediation is recommended."
            ),
            vuln_type=vuln_type,
            effort_level="MEDIUM",
            effort_hours=8.0,
            fix_type="CODE_CHANGE",
            severity=severity,
            phase=self._determine_phase(severity, "MEDIUM"),
            impact_score=SEVERITY_SCORES.get(severity, 5.0),
            verification_steps=[
                "Rerun vulnerability scan after fix",
                "Perform manual code review of the affected component",
                "Test with known attack payloads",
            ],
            references=self._generate_references(vuln_type),
        )

    def _determine_phase(self, severity: str, effort: str) -> str:
        """Determine remediation phase based on severity and effort."""
        if severity in ("CRITICAL",) and effort in ("TRIVIAL", "LOW"):
            return "IMMEDIATE"
        if severity in ("CRITICAL", "HIGH"):
            return "SHORT_TERM"
        if severity == "MEDIUM":
            return "MEDIUM_TERM"
        return "LONG_TERM"

    def _determine_fix_type(self, template: FixTemplate) -> str:
        """Determine fix type from template content."""
        if template.config_template and not template.code_template:
            return "CONFIG_CHANGE"
        if template.vuln_type == "WAF":
            return "WAF_RULE"
        if template.vuln_type in ("TLS", "HEADERS", "CORS"):
            return "CONFIG_CHANGE"
        return "CODE_CHANGE"

    def _lang_extension(self, language: str) -> str:
        """Get file extension for a language."""
        ext_map = {
            "python": ".py", "javascript": ".js", "typescript": ".ts",
            "java": ".java", "csharp": ".cs", "php": ".php", "go": ".go",
            "ruby": ".rb", "nginx": ".conf", "apache": ".conf",
            "modsecurity": ".conf", "cloudflare": ".txt", "json": ".json",
        }
        return ext_map.get(language.lower(), ".txt")

    def _config_extension(self, framework: str) -> str:
        """Get config file extension for a framework."""
        ext_map = {
            "nginx": ".conf", "apache": ".conf", "modsecurity": ".conf",
            "aws-waf": ".json", "cloudflare": ".txt",
        }
        return ext_map.get(framework.lower(), ".conf")

    def _generate_config_steps(self, template: FixTemplate) -> List[str]:
        """Generate configuration change steps for a template."""
        steps: List[str] = []
        if template.config_template:
            steps.append(f"Apply configuration changes for {template.framework}")
            steps.append("Review and adjust values for your environment")
            steps.append("Test in staging before production deployment")
        return steps

    def _generate_commands(self, template: FixTemplate) -> List[str]:
        """Generate CLI commands for applying the fix."""
        commands: List[str] = []
        vt = template.vuln_type
        fw = template.framework.lower()

        if fw == "nginx":
            commands.extend([
                "# Test Nginx configuration:",
                "sudo nginx -t",
                "# Reload Nginx:",
                "sudo systemctl reload nginx",
            ])
        elif fw == "apache":
            commands.extend([
                "# Test Apache configuration:",
                "sudo apachectl configtest",
                "# Reload Apache:",
                "sudo systemctl reload apache2",
            ])
        elif fw == "modsecurity":
            commands.extend([
                "# Test ModSecurity rules:",
                "sudo nginx -t  # or apachectl configtest",
                "# Reload web server:",
                "sudo systemctl reload nginx",
            ])
        elif template.language == "python":
            commands.extend([
                "# Run tests after applying fix:",
                "python -m pytest tests/ -v",
                "# Check for regressions:",
                "python -m pytest tests/ --tb=short",
            ])
        elif template.language in ("javascript", "typescript"):
            commands.extend([
                "# Install dependencies if needed:",
                "npm install",
                "# Run tests:",
                "npm test",
            ])
        elif template.language == "java":
            commands.extend([
                "# Build and test:",
                "mvn clean test",
                "# Or with Gradle:",
                "gradle clean test",
            ])

        return commands

    def _generate_verification(self, vuln_type: str, url: str = "") -> List[str]:
        """Generate verification steps for a remediation."""
        steps = [
            f"Rerun vulnerability scan targeting {vuln_type} findings",
            "Review code changes with a security-focused peer review",
        ]

        vt = vuln_type.upper()
        if vt == "SQLI":
            steps.extend([
                "Test with SQL injection payloads: ' OR 1=1 --, UNION SELECT, etc.",
                "Verify all queries use parameterized statements",
                "Check for any remaining string concatenation in SQL",
            ])
        elif vt == "XSS":
            steps.extend([
                "Test with XSS payloads: <script>alert(1)</script>, etc.",
                "Verify Content-Security-Policy header is present",
                "Check all user input is properly encoded on output",
            ])
        elif vt == "AUTH":
            steps.extend([
                "Test authentication with invalid/expired tokens",
                "Verify password hashing uses strong algorithm (bcrypt/PBKDF2)",
                "Check session timeout and regeneration behavior",
            ])
        elif vt == "IDOR":
            steps.extend([
                "Test accessing resources with different user credentials",
                "Verify authorization checks on all object references",
                "Test with sequential and random IDs",
            ])
        elif vt == "SSRF":
            steps.extend([
                "Test with internal IP addresses (127.0.0.1, 10.x, 192.168.x)",
                "Verify URL allowlist is enforced",
                "Test DNS rebinding scenarios",
            ])
        elif vt == "CMDI":
            steps.extend([
                "Test with command injection payloads: ; ls, | cat /etc/passwd, etc.",
                "Verify no shell=True usage remains",
                "Check all external command execution uses argv lists",
            ])
        elif vt == "CSRF":
            steps.extend([
                "Test state-changing requests without CSRF token",
                "Verify SameSite cookie attribute is set",
                "Test cross-origin form submission",
            ])

        if url:
            steps.append(f"Specifically re-test: {url}")

        return steps

    def _generate_rollback(self, template: FixTemplate) -> List[str]:
        """Generate rollback steps for a remediation."""
        steps = [
            "Revert code changes via version control (git revert)",
            "Restore previous configuration from backup",
        ]
        if template.framework.lower() in ("nginx", "apache"):
            steps.append("Reload web server with previous configuration")
        if template.vuln_type == "WAF":
            steps.append("Disable WAF rules that cause false positives")
        return steps

    def _generate_references(self, vuln_type: str) -> List[str]:
        """Generate reference links for a vulnerability type."""
        refs: Dict[str, List[str]] = {
            "SQLI": [
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                "CWE-89: Improper Neutralization of Special Elements used in an SQL Command",
            ],
            "XSS": [
                "https://owasp.org/www-community/attacks/xss/",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                "CWE-79: Improper Neutralization of Input During Web Page Generation",
            ],
            "AUTH": [
                "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
                "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
                "CWE-287: Improper Authentication",
            ],
            "IDOR": [
                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
                "CWE-639: Authorization Bypass Through User-Controlled Key",
            ],
            "RATE_LIMIT": [
                "https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html",
                "CWE-770: Allocation of Resources Without Limits or Throttling",
            ],
            "CORS": [
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Origin_Resource_Sharing_Cheat_Sheet.html",
                "CWE-942: Permissive Cross-domain Policy with Untrusted Domains",
            ],
            "HEADERS": [
                "https://owasp.org/www-project-secure-headers/",
                "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
            ],
            "WAF": [
                "https://owasp.org/www-project-modsecurity-core-rule-set/",
                "https://coreruleset.org/",
            ],
            "TLS": [
                "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
                "https://wiki.mozilla.org/Security/Server_Side_TLS",
                "CWE-326: Inadequate Encryption Strength",
            ],
            "SSRF": [
                "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
                "CWE-918: Server-Side Request Forgery (SSRF)",
            ],
            "CMDI": [
                "https://owasp.org/www-community/attacks/Command_Injection",
                "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
                "CWE-78: Improper Neutralization of Special Elements used in an OS Command",
            ],
            "FILE_UPLOAD": [
                "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html",
                "CWE-434: Unrestricted Upload of File with Dangerous Type",
            ],
            "DESERIALIZATION": [
                "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
                "CWE-502: Deserialization of Untrusted Data",
            ],
            "CSRF": [
                "https://owasp.org/www-community/attacks/csrf",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
                "CWE-352: Cross-Site Request Forgery (CSRF)",
            ],
        }
        return refs.get(vuln_type.upper(), [
            "https://owasp.org/www-project-top-ten/",
        ])

    # -------------------------------------------------------------------
    # Plan generation
    # -------------------------------------------------------------------

    def generate_plan(self, findings: List[Dict[str, Any]],
                      hourly_rate: float = 150.0,
                      target: str = "") -> RemediationPlan:
        """Generate a complete remediation plan from a list of findings.

        Args:
            findings: List of finding dicts (vuln_type, severity, etc.).
            hourly_rate: Cost per hour for effort estimation.
            target: Target identifier (URL, app name, etc.).

        Returns:
            A fully populated RemediationPlan.
        """
        with self._lock:
            plan = RemediationPlan(
                target=target or "Unknown Target",
                hourly_rate=hourly_rate,
            )
            self._priority_queue = PriorityQueue()

            steps: List[RemediationStep] = []
            for finding in findings:
                step = self.generate_fix(finding)
                if step:
                    steps.append(step)

            # Sort by priority and assign to phases
            steps.sort(key=lambda s: s.priority_score(), reverse=True)

            for step in steps:
                plan.add_step(step, step.phase)

            # Identify quick wins
            plan.quick_wins = [
                s for s in steps
                if s.effort_level in ("TRIVIAL", "LOW") and
                s.severity in ("CRITICAL", "HIGH")
            ]

            # Build critical path (dependency chain)
            plan.critical_path = self._build_critical_path(steps)

            self._current_plan = plan
            self._plans.append(plan)

            logger.info("Generated plan %s: %d steps, %.1f hours, $%.2f",
                        plan.plan_id, sum(plan.steps_per_phase().values()),
                        plan.total_effort_hours, plan.total_cost)
            return plan

    def _build_critical_path(self, steps: List[RemediationStep]) -> List[RemediationStep]:
        """Build dependency-ordered critical path."""
        step_map = {s.step_id: s for s in steps}
        visited: Set[str] = set()
        path: List[RemediationStep] = []

        def _visit(step_id: str) -> None:
            if step_id in visited:
                return
            visited.add(step_id)
            step = step_map.get(step_id)
            if not step:
                return
            for dep in step.dependencies:
                _visit(dep)
            path.append(step)

        # Start with highest-priority steps
        for step in steps:
            _visit(step.step_id)

        return path

    # -------------------------------------------------------------------
    # Query methods
    # -------------------------------------------------------------------

    def get_quick_wins(self, max_effort: float = 4.0) -> List[RemediationStep]:
        """Get high-impact, low-effort fixes (quick wins).

        Args:
            max_effort: Maximum effort hours to qualify as quick win.

        Returns:
            List of steps sorted by priority (highest first).
        """
        with self._lock:
            if not self._current_plan:
                return []
            all_steps = self._current_plan.all_steps()
            wins = [
                s for s in all_steps
                if s.effort_hours <= max_effort
            ]
            wins.sort(key=lambda s: s.priority_score(), reverse=True)
            return wins

    def get_critical_path(self) -> List[RemediationStep]:
        """Get the critical path (dependency-ordered steps)."""
        with self._lock:
            if self._current_plan:
                return list(self._current_plan.critical_path)
            return []

    def estimate_total_effort(self) -> Dict[str, Any]:
        """Estimate total remediation effort and cost breakdown."""
        with self._lock:
            if not self._current_plan:
                return {"total_hours": 0, "total_cost": 0, "phases": {}}

            plan = self._current_plan
            result: Dict[str, Any] = {
                "total_hours": plan.total_effort_hours,
                "total_cost": plan.total_cost,
                "hourly_rate": plan.hourly_rate,
                "phases": {},
            }
            for phase in ("IMMEDIATE", "SHORT_TERM", "MEDIUM_TERM", "LONG_TERM"):
                steps = plan.phases.get(phase, [])
                phase_hours = sum(s.effort_hours for s in steps)
                result["phases"][phase] = {
                    "steps": len(steps),
                    "hours": phase_hours,
                    "cost": phase_hours * plan.hourly_rate,
                    "risk_reduction": plan.risk_reduction_per_phase.get(phase, 0.0),
                }
            return result

    # -------------------------------------------------------------------
    # WAF & header generation
    # -------------------------------------------------------------------

    def generate_waf_rules(self) -> Dict[str, str]:
        """Generate WAF rules for all supported platforms.

        Returns:
            Dict mapping platform name to rule configuration string.
        """
        with self._lock:
            rules: Dict[str, str] = {}
            for tpl in self._templates.get("WAF", []):
                platform = tpl.framework
                content = tpl.config_template or tpl.code_template
                if content:
                    rules[platform] = content
            return rules

    def generate_security_headers_config(self, framework: str) -> str:
        """Generate security headers configuration for a specific framework.

        Args:
            framework: One of 'nginx', 'apache', 'express', 'django', 'spring-boot'.

        Returns:
            Configuration string for the specified framework.
        """
        with self._lock:
            template = self.get_template("HEADERS", framework=framework)
            if template:
                return template.config_template or template.code_template
            # Fallback: check CORS and TLS templates for the framework
            for vt in ("CORS", "TLS"):
                tpl = self.get_template(vt, framework=framework)
                if tpl:
                    return tpl.config_template or tpl.code_template
            return f"# No security header template available for framework: {framework}"

    # -------------------------------------------------------------------
    # Export methods
    # -------------------------------------------------------------------

    def export_plan_markdown(self) -> str:
        """Export current remediation plan as Markdown."""
        with self._lock:
            if not self._current_plan:
                return "# No remediation plan generated yet\n\nRun generate_plan() first."
            return self._current_plan.to_markdown()

    def export_plan_json(self) -> str:
        """Export current remediation plan as JSON string."""
        with self._lock:
            if not self._current_plan:
                return json.dumps({"error": "No plan generated"}, indent=2)
            return json.dumps(self._current_plan.to_dict(), indent=2, default=str)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize generator state to dict."""
        with self._lock:
            return {
                "template_count": len(self._all_templates),
                "vuln_types": list(self._templates.keys()),
                "templates_per_type": {
                    vt: len(tpls) for vt, tpls in self._templates.items()
                },
                "plans_generated": len(self._plans),
                "current_plan": self._current_plan.to_dict() if self._current_plan else None,
                "priority_queue": self._priority_queue.to_dict(),
            }
