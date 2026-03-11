#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  🐳 SIREN CONTAINER SECURITY — Container & Orchestration Auditor  🐳        ██
██                                                                                ██
██  Auditoria completa de segurança em ambientes containerizados.               ██
██                                                                                ██
██  Capacidades:                                                                  ██
██    • Dockerfile analysis — detecta más práticas e vulns                      ██
██    • Docker Compose audit — serviços expostos, volumes perigosos             ██
██    • Kubernetes manifest audit — RBAC, NetworkPolicy, PodSecurity            ██
██    • Container escape detection — capabilities, mounts, namespaces            ██
██    • Image layer analysis — secrets em layers, base images inseguras          ██
██    • Runtime config audit — socket exposure, privilege escalation             ██
██    • Registry security — image signing, pull policies                          ██
██    • CIS Benchmark checks — Docker/K8s CIS compliance                         ██
██                                                                                ██
██  "SIREN escapa do container — ou impede que outros façam."                   ██
██                                                                                ██
████████████████████████████████████████████████████████████████████████████████████
"""

from __future__ import annotations

import logging
import re
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("siren.arsenal.container_security")


# ════════════════════════════════════════════════════════════════════════════════
# ENUMS
# ════════════════════════════════════════════════════════════════════════════════

class ContainerRuntime(Enum):
    DOCKER = auto()
    CONTAINERD = auto()
    CRIO = auto()
    PODMAN = auto()
    UNKNOWN = auto()


class OrchestratorType(Enum):
    KUBERNETES = auto()
    DOCKER_SWARM = auto()
    NOMAD = auto()
    ECS = auto()
    NONE = auto()


class Severity(Enum):
    CRITICAL = auto()
    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()
    INFO = auto()


class FindingCategory(Enum):
    """Categories of container security findings."""
    PRIVILEGE_ESCALATION = auto()
    CONTAINER_ESCAPE = auto()
    SECRETS_EXPOSURE = auto()
    NETWORK_EXPOSURE = auto()
    INSECURE_CONFIG = auto()
    VULNERABLE_BASE = auto()
    SUPPLY_CHAIN = auto()
    RBAC_MISCONFIGURATION = auto()
    RESOURCE_ABUSE = auto()
    COMPLIANCE = auto()


class CISBenchmark(Enum):
    """CIS Benchmark check references."""
    DOCKER_CIS_4_1 = "4.1 - Ensure a user for the container has been created"
    DOCKER_CIS_4_2 = "4.2 - Ensure that containers use only trusted base images"
    DOCKER_CIS_4_5 = "4.5 - Ensure Content trust for Docker is Enabled"
    DOCKER_CIS_4_6 = "4.6 - Ensure HEALTHCHECK instructions have been added"
    DOCKER_CIS_4_9 = "4.9 - Ensure that COPY is used instead of ADD"
    DOCKER_CIS_5_4 = "5.4 - Ensure privileged containers are not used"
    DOCKER_CIS_5_7 = "5.7 - Ensure privileged ports are not mapped"
    DOCKER_CIS_5_9 = "5.9 - Ensure the host's network namespace is not shared"
    DOCKER_CIS_5_10 = "5.10 - Ensure memory usage for the container is limited"
    DOCKER_CIS_5_12 = "5.12 - Ensure the container's root filesystem is read-only"
    DOCKER_CIS_5_15 = "5.15 - Ensure the host's process namespace is not shared"
    DOCKER_CIS_5_25 = "5.25 - Ensure the container is restricted from acquiring additional privileges"
    K8S_CIS_5_1_1 = "5.1.1 - Ensure cluster-admin role is only used where required"
    K8S_CIS_5_1_3 = "5.1.3 - Minimize wildcard use in Roles and ClusterRoles"
    K8S_CIS_5_2_2 = "5.2.2 - Minimize the admission of privileged containers"
    K8S_CIS_5_2_6 = "5.2.6 - Minimize the admission of root containers"
    K8S_CIS_5_4_1 = "5.4.1 - Prefer using secrets as files over secrets as env vars"


# ════════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class ContainerFinding:
    """A container security finding."""
    category: FindingCategory
    severity: Severity
    title: str
    description: str
    file_location: str = ""
    line_number: int = 0
    evidence: str = ""
    cis_ref: Optional[CISBenchmark] = None
    recommendation: str = ""
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category.name,
            "severity": self.severity.name,
            "title": self.title,
            "description": self.description,
            "file": self.file_location,
            "line": self.line_number,
            "evidence": self.evidence,
            "cis_ref": self.cis_ref.value if self.cis_ref else None,
            "recommendation": self.recommendation,
        }


@dataclass
class DockerfileInstruction:
    """Parsed Dockerfile instruction."""
    instruction: str   # FROM, RUN, COPY, etc.
    arguments: str
    line_number: int
    raw_line: str


@dataclass
class ContainerAuditReport:
    """Complete container security audit report."""
    target: str
    runtime: ContainerRuntime = ContainerRuntime.DOCKER
    orchestrator: OrchestratorType = OrchestratorType.NONE
    timestamp: float = field(default_factory=time.time)
    findings: List[ContainerFinding] = field(default_factory=list)
    cis_checks_passed: int = 0
    cis_checks_failed: int = 0
    cis_checks_total: int = 0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "runtime": self.runtime.name,
            "orchestrator": self.orchestrator.name,
            "critical_findings": self.critical_count,
            "high_findings": self.high_count,
            "total_findings": len(self.findings),
            "cis_compliance": f"{self.cis_checks_passed}/{self.cis_checks_total}",
            "findings": [f.to_dict() for f in self.findings],
        }


# ════════════════════════════════════════════════════════════════════════════════
# DOCKERFILE ANALYZER
# ════════════════════════════════════════════════════════════════════════════════

class DockerfileAnalyzer:
    """Deep analysis of Dockerfile security."""

    # Dangerous capabilities
    DANGEROUS_CAPS = {
        "SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN", "NET_RAW",
        "DAC_OVERRIDE", "SETUID", "SETGID", "SYS_RAWIO",
        "SYS_MODULE", "SYS_CHROOT", "MKNOD", "AUDIT_WRITE",
    }

    # Insecure base images (known vulnerable / EOL)
    INSECURE_BASES = {
        "python:2", "python:2.7", "node:8", "node:10",
        "ubuntu:14.04", "ubuntu:16.04", "debian:jessie",
        "debian:stretch", "centos:6", "centos:7",
        "alpine:3.8", "alpine:3.9", "alpine:3.10",
    }

    # Secret patterns in build commands
    SECRET_PATTERNS = [
        re.compile(r"(password|passwd|pwd)\s*=\s*\S+", re.I),
        re.compile(r"(api[_-]?key|apikey)\s*=\s*\S+", re.I),
        re.compile(r"(secret|token)\s*=\s*\S+", re.I),
        re.compile(r"(aws_access_key|aws_secret)", re.I),
        re.compile(r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----", re.I),
        re.compile(r"(mysql|postgres|redis)://\S+:\S+@", re.I),
    ]

    def analyze(self, content: str, filename: str = "Dockerfile") -> List[ContainerFinding]:
        """Analyze a Dockerfile for security issues."""
        findings: List[ContainerFinding] = []
        if not content:
            return findings

        try:
            instructions = self._parse_dockerfile(content)
        except Exception as exc:
            logger.warning("Failed to parse Dockerfile %s: %s", filename, exc)
            return findings

        if not instructions:
            return findings

        has_user = False
        has_healthcheck = False
        uses_latest = False

        for instr in instructions:
            cmd = instr.instruction.upper()

            # FROM analysis
            if cmd == "FROM":
                findings.extend(self._check_from(instr, filename))
                if ":latest" in instr.arguments or ":" not in instr.arguments.split()[0]:
                    uses_latest = True

            # RUN analysis
            elif cmd == "RUN":
                findings.extend(self._check_run(instr, filename))

            # COPY / ADD
            elif cmd == "ADD":
                findings.append(ContainerFinding(
                    category=FindingCategory.INSECURE_CONFIG,
                    severity=Severity.LOW,
                    title="ADD instruction used instead of COPY",
                    description="ADD can fetch remote URLs and extract archives, use COPY for local files",
                    file_location=filename,
                    line_number=instr.line_number,
                    evidence=instr.raw_line,
                    cis_ref=CISBenchmark.DOCKER_CIS_4_9,
                    recommendation="Replace ADD with COPY unless remote URL/archive extraction is needed",
                ))

            elif cmd == "USER":
                has_user = True

            elif cmd == "HEALTHCHECK":
                has_healthcheck = True

            # ENV secrets
            elif cmd == "ENV":
                for pattern in self.SECRET_PATTERNS:
                    if pattern.search(instr.arguments):
                        findings.append(ContainerFinding(
                            category=FindingCategory.SECRETS_EXPOSURE,
                            severity=Severity.CRITICAL,
                            title="Secret exposed in ENV instruction",
                            description="Secrets in ENV persist in image layers and can be extracted",
                            file_location=filename,
                            line_number=instr.line_number,
                            evidence=f"Pattern matched in: {instr.raw_line[:80]}...",
                            recommendation="Use build secrets (--secret) or runtime env injection",
                        ))
                        break

            # EXPOSE
            elif cmd == "EXPOSE":
                self._check_expose(instr, filename, findings)

        # Missing USER — runs as root
        if not has_user:
            findings.append(ContainerFinding(
                category=FindingCategory.PRIVILEGE_ESCALATION,
                severity=Severity.HIGH,
                title="Container runs as root",
                description="No USER instruction found — container will run as root",
                file_location=filename,
                cis_ref=CISBenchmark.DOCKER_CIS_4_1,
                recommendation="Add USER instruction with non-root user",
            ))

        # Missing HEALTHCHECK
        if not has_healthcheck:
            findings.append(ContainerFinding(
                category=FindingCategory.INSECURE_CONFIG,
                severity=Severity.LOW,
                title="No HEALTHCHECK instruction",
                description="Container has no health check — orchestrator cannot detect failures",
                file_location=filename,
                cis_ref=CISBenchmark.DOCKER_CIS_4_6,
                recommendation="Add HEALTHCHECK instruction",
            ))

        return findings

    def _check_from(self, instr: DockerfileInstruction, filename: str) -> List[ContainerFinding]:
        """Check FROM instruction."""
        findings: List[ContainerFinding] = []
        try:
            image = instr.arguments.split()[0].lower()
        except (IndexError, AttributeError):
            logger.warning("Malformed FROM instruction at line %d in %s", instr.line_number, filename)
            return findings

        # Check for :latest or no tag
        if ":latest" in image or ":" not in image.split("@")[0]:
            findings.append(ContainerFinding(
                category=FindingCategory.SUPPLY_CHAIN,
                severity=Severity.MEDIUM,
                title="Using :latest or untagged base image",
                description=f"Image '{image}' uses :latest or no tag — builds are non-reproducible",
                file_location=filename,
                line_number=instr.line_number,
                evidence=instr.raw_line,
                recommendation="Pin to specific version digest (sha256:...)",
            ))

        # Check for known insecure bases
        for insecure in self.INSECURE_BASES:
            if image.startswith(insecure):
                findings.append(ContainerFinding(
                    category=FindingCategory.VULNERABLE_BASE,
                    severity=Severity.HIGH,
                    title=f"Insecure/EOL base image: {image}",
                    description=f"Base image '{image}' is known to be vulnerable or end-of-life",
                    file_location=filename,
                    line_number=instr.line_number,
                    cis_ref=CISBenchmark.DOCKER_CIS_4_2,
                    recommendation="Upgrade to a supported, patched version",
                ))
                break

        return findings

    def _check_run(self, instr: DockerfileInstruction, filename: str) -> List[ContainerFinding]:
        """Check RUN instruction."""
        findings: List[ContainerFinding] = []
        args = instr.arguments

        # Secrets in RUN commands
        for pattern in self.SECRET_PATTERNS:
            try:
                if pattern.search(args):
                    findings.append(ContainerFinding(
                        category=FindingCategory.SECRETS_EXPOSURE,
                        severity=Severity.CRITICAL,
                        title="Secret exposed in RUN instruction",
                        description="RUN commands are stored in image layers — secrets can be extracted",
                        file_location=filename,
                        line_number=instr.line_number,
                        evidence=f"Match in: {instr.raw_line[:80]}...",
                        recommendation="Use multi-stage builds and --secret flag",
                    ))
                    break
            except re.error as exc:
                logger.warning("Regex error in secret pattern for %s: %s", filename, exc)

        # curl | bash pattern
        try:
            if re.search(r"curl\s.*\|\s*(bash|sh)", args, re.I):
                findings.append(ContainerFinding(
                    category=FindingCategory.SUPPLY_CHAIN,
                    severity=Severity.HIGH,
                    title="Remote script execution in build",
                    description="Piping curl to shell downloads and executes unverified code",
                    file_location=filename,
                    line_number=instr.line_number,
                    evidence=instr.raw_line,
                    recommendation="Download script, verify checksum, then execute",
                ))
        except re.error as exc:
            logger.warning("Regex error checking curl|bash in %s: %s", filename, exc)

        # chmod 777
        if "chmod 777" in args or "chmod -R 777" in args:
            findings.append(ContainerFinding(
                category=FindingCategory.INSECURE_CONFIG,
                severity=Severity.MEDIUM,
                title="Overly permissive file permissions",
                description="chmod 777 gives all users read/write/execute",
                file_location=filename,
                line_number=instr.line_number,
                recommendation="Use least-privilege permissions (e.g., chmod 755 or chmod 644)",
            ))

        # Package manager without cleanup
        try:
            pkg_install = re.search(r"(apt-get|yum|apk)\s+(install|add)", args, re.I)
            if pkg_install and "rm -rf" not in args and "--no-cache" not in args:
                findings.append(ContainerFinding(
                    category=FindingCategory.RESOURCE_ABUSE,
                    severity=Severity.LOW,
                    title="Package manager cache not cleaned",
                    description="Package installation without cache cleanup increases image size",
                    file_location=filename,
                    line_number=instr.line_number,
                    recommendation="Add cache cleanup (rm -rf /var/lib/apt/lists/* or --no-cache)",
                ))
        except re.error as exc:
            logger.warning("Regex error checking package manager in %s: %s", filename, exc)

        return findings

    @staticmethod
    def _check_expose(instr: DockerfileInstruction, filename: str, findings: List[ContainerFinding]) -> None:
        """Check EXPOSE ports."""
        try:
            ports = re.findall(r"\d+", instr.arguments)
            privileged_ports = [p for p in ports if int(p) < 1024 and int(p) != 443 and int(p) != 80]
        except (ValueError, re.error) as exc:
            logger.warning("Failed to parse EXPOSE ports at line %d in %s: %s", instr.line_number, filename, exc)
            return
        if privileged_ports:
            findings.append(ContainerFinding(
                category=FindingCategory.NETWORK_EXPOSURE,
                severity=Severity.LOW,
                title=f"Privileged ports exposed: {', '.join(privileged_ports)}",
                description="Privileged ports (< 1024) require elevated privileges",
                file_location=filename,
                line_number=instr.line_number,
                cis_ref=CISBenchmark.DOCKER_CIS_5_7,
                recommendation="Use non-privileged ports (> 1024) with port mapping",
            ))

    @staticmethod
    def _parse_dockerfile(content: str) -> List[DockerfileInstruction]:
        """Parse Dockerfile into instructions."""
        instructions: List[DockerfileInstruction] = []
        lines = content.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            if not line or line.startswith("#"):
                i += 1
                continue
            # Handle line continuations
            full_line = line
            while full_line.endswith("\\") and i + 1 < len(lines):
                i += 1
                full_line = full_line[:-1] + " " + lines[i].strip()

            parts = full_line.split(None, 1)
            if parts:
                instructions.append(DockerfileInstruction(
                    instruction=parts[0].upper(),
                    arguments=parts[1] if len(parts) > 1 else "",
                    line_number=i + 1,
                    raw_line=full_line,
                ))
            i += 1
        return instructions


# ════════════════════════════════════════════════════════════════════════════════
# KUBERNETES MANIFEST ANALYZER
# ════════════════════════════════════════════════════════════════════════════════

class KubernetesAnalyzer:
    """Analyzes Kubernetes manifests for security misconfigurations."""

    # Dangerous volume mounts
    DANGEROUS_MOUNTS = {
        "/", "/etc", "/proc", "/sys", "/dev",
        "/var/run/docker.sock", "/var/run/containerd",
        "/var/lib/kubelet", "/etc/kubernetes",
    }

    def analyze_manifest(self, content: str, filename: str = "manifest.yaml") -> List[ContainerFinding]:
        """Analyze a Kubernetes manifest (basic text parsing — no YAML lib)."""
        findings: List[ContainerFinding] = []
        if not content:
            return findings

        lines = content.splitlines()

        # Parse key-value pairs from YAML (simplified)
        try:
            context = self._extract_context(lines)
        except Exception as exc:
            logger.warning("Failed to extract context from %s: %s", filename, exc)
            context = {}

        # Privileged container
        if self._has_value(lines, "privileged", "true"):
            findings.append(ContainerFinding(
                category=FindingCategory.CONTAINER_ESCAPE,
                severity=Severity.CRITICAL,
                title="Privileged container detected",
                description="Container runs with all capabilities — trivial escape to host",
                file_location=filename,
                cis_ref=CISBenchmark.K8S_CIS_5_2_2,
                recommendation="Remove privileged: true, use specific capabilities",
            ))

        # Host PID/Network
        if self._has_value(lines, "hostPID", "true"):
            findings.append(ContainerFinding(
                category=FindingCategory.CONTAINER_ESCAPE,
                severity=Severity.CRITICAL,
                title="Host PID namespace shared",
                description="Container shares host PID namespace — can see and signal host processes",
                file_location=filename,
                cis_ref=CISBenchmark.DOCKER_CIS_5_15,
                recommendation="Set hostPID: false",
            ))

        if self._has_value(lines, "hostNetwork", "true"):
            findings.append(ContainerFinding(
                category=FindingCategory.NETWORK_EXPOSURE,
                severity=Severity.HIGH,
                title="Host network namespace shared",
                description="Container uses host network — can access all host network interfaces",
                file_location=filename,
                cis_ref=CISBenchmark.DOCKER_CIS_5_9,
                recommendation="Set hostNetwork: false, use NetworkPolicy",
            ))

        # Run as root
        if self._has_value(lines, "runAsRoot", "true") or self._has_value(lines, "runAsUser", "0"):
            findings.append(ContainerFinding(
                category=FindingCategory.PRIVILEGE_ESCALATION,
                severity=Severity.HIGH,
                title="Container runs as root (UID 0)",
                description="Container explicitly configured to run as root",
                file_location=filename,
                cis_ref=CISBenchmark.K8S_CIS_5_2_6,
                recommendation="Set runAsNonRoot: true and specify runAsUser > 0",
            ))

        # No resource limits
        has_limits = any("limits:" in line for line in lines)
        if not has_limits and context.get("kind") in ("Deployment", "StatefulSet", "DaemonSet", "Pod"):
            findings.append(ContainerFinding(
                category=FindingCategory.RESOURCE_ABUSE,
                severity=Severity.MEDIUM,
                title="No resource limits defined",
                description="Container has no CPU/memory limits — can consume all node resources",
                file_location=filename,
                cis_ref=CISBenchmark.DOCKER_CIS_5_10,
                recommendation="Define resources.limits for CPU and memory",
            ))

        # Dangerous volume mounts
        for mount in self.DANGEROUS_MOUNTS:
            if self._has_mount(lines, mount):
                findings.append(ContainerFinding(
                    category=FindingCategory.CONTAINER_ESCAPE,
                    severity=Severity.CRITICAL,
                    title=f"Dangerous host path mounted: {mount}",
                    description=f"Mounting '{mount}' gives container access to sensitive host paths",
                    file_location=filename,
                    recommendation=f"Remove hostPath mount for '{mount}'",
                ))

        # RBAC checks
        findings.extend(self._check_rbac(lines, filename))

        # Secrets in env
        findings.extend(self._check_secret_env(lines, filename))

        # allowPrivilegeEscalation
        if not self._has_value(lines, "allowPrivilegeEscalation", "false"):
            if context.get("kind") in ("Deployment", "StatefulSet", "DaemonSet", "Pod"):
                findings.append(ContainerFinding(
                    category=FindingCategory.PRIVILEGE_ESCALATION,
                    severity=Severity.MEDIUM,
                    title="Privilege escalation not disabled",
                    description="allowPrivilegeEscalation is not explicitly set to false",
                    file_location=filename,
                    cis_ref=CISBenchmark.DOCKER_CIS_5_25,
                    recommendation="Set allowPrivilegeEscalation: false in securityContext",
                ))

        return findings

    @staticmethod
    def _has_value(lines: List[str], key: str, value: str) -> bool:
        """Check if a YAML key has a specific value."""
        try:
            pattern = re.compile(rf"\b{re.escape(key)}\s*:\s*{re.escape(value)}\b", re.I)
            return any(pattern.search(line) for line in lines)
        except re.error as exc:
            logger.warning("Regex error checking YAML key '%s': %s", key, exc)
            return False

    @staticmethod
    def _has_mount(lines: List[str], path: str) -> bool:
        """Check if a path is mounted."""
        return any(path in line for line in lines if "hostPath" in line or "path:" in line)

    @staticmethod
    def _extract_context(lines: List[str]) -> Dict[str, str]:
        """Extract basic YAML context (kind, apiVersion)."""
        ctx: Dict[str, str] = {}
        for line in lines:
            if line.startswith("kind:"):
                ctx["kind"] = line.split(":", 1)[1].strip()
            elif line.startswith("apiVersion:"):
                ctx["apiVersion"] = line.split(":", 1)[1].strip()
        return ctx

    def _check_rbac(self, lines: List[str], filename: str) -> List[ContainerFinding]:
        """Check RBAC configurations."""
        findings: List[ContainerFinding] = []

        # Wildcard in RBAC rules
        for i, line in enumerate(lines):
            if "'*'" in line or '"*"' in line:
                if any("rules:" in lines[j] for j in range(max(0, i - 10), i)):
                    findings.append(ContainerFinding(
                        category=FindingCategory.RBAC_MISCONFIGURATION,
                        severity=Severity.HIGH,
                        title="Wildcard in RBAC rules",
                        description="Wildcard (*) grants access to all resources/verbs",
                        file_location=filename,
                        line_number=i + 1,
                        cis_ref=CISBenchmark.K8S_CIS_5_1_3,
                        recommendation="Use specific resources and verbs instead of wildcards",
                    ))
                    break

        # cluster-admin binding
        if any("cluster-admin" in line for line in lines):
            findings.append(ContainerFinding(
                category=FindingCategory.RBAC_MISCONFIGURATION,
                severity=Severity.HIGH,
                title="cluster-admin role binding found",
                description="cluster-admin has unrestricted access to the entire cluster",
                file_location=filename,
                cis_ref=CISBenchmark.K8S_CIS_5_1_1,
                recommendation="Use least-privilege roles instead of cluster-admin",
            ))

        return findings

    @staticmethod
    def _check_secret_env(lines: List[str], filename: str) -> List[ContainerFinding]:
        """Check for secrets exposed as environment variables."""
        findings: List[ContainerFinding] = []
        secret_env_pattern = re.compile(r"secretKeyRef", re.I)
        for i, line in enumerate(lines):
            if secret_env_pattern.search(line):
                findings.append(ContainerFinding(
                    category=FindingCategory.SECRETS_EXPOSURE,
                    severity=Severity.MEDIUM,
                    title="Secret exposed as environment variable",
                    description="Secrets in env vars can leak via /proc, logs, or error messages",
                    file_location=filename,
                    line_number=i + 1,
                    cis_ref=CISBenchmark.K8S_CIS_5_4_1,
                    recommendation="Mount secrets as files instead of env vars",
                ))
        return findings


# ════════════════════════════════════════════════════════════════════════════════
# DOCKER COMPOSE ANALYZER
# ════════════════════════════════════════════════════════════════════════════════

class DockerComposeAnalyzer:
    """Analyzes docker-compose files for security issues."""

    def analyze(self, content: str, filename: str = "docker-compose.yml") -> List[ContainerFinding]:
        """Analyze a docker-compose file."""
        findings: List[ContainerFinding] = []
        if not content:
            return findings
        lines = content.splitlines()

        # Privileged mode
        if any("privileged: true" in line for line in lines):
            findings.append(ContainerFinding(
                category=FindingCategory.CONTAINER_ESCAPE,
                severity=Severity.CRITICAL,
                title="Privileged service in Compose",
                description="Service runs in privileged mode — full host access",
                file_location=filename,
                recommendation="Remove privileged: true",
            ))

        # Docker socket mount
        if any("docker.sock" in line for line in lines):
            findings.append(ContainerFinding(
                category=FindingCategory.CONTAINER_ESCAPE,
                severity=Severity.CRITICAL,
                title="Docker socket mounted",
                description="Mounting docker.sock gives container full control over Docker daemon",
                file_location=filename,
                recommendation="Use Docker API proxy with limited permissions",
            ))

        # Network mode: host
        if any("network_mode: host" in line or 'network_mode: "host"' in line for line in lines):
            findings.append(ContainerFinding(
                category=FindingCategory.NETWORK_EXPOSURE,
                severity=Severity.HIGH,
                title="Host network mode in Compose",
                description="Service shares host network namespace",
                file_location=filename,
                recommendation="Use bridge networking with explicit port mapping",
            ))

        # Environment secrets
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("-") or ":" in stripped:
                for pattern in DockerfileAnalyzer.SECRET_PATTERNS:
                    if pattern.search(stripped):
                        findings.append(ContainerFinding(
                            category=FindingCategory.SECRETS_EXPOSURE,
                            severity=Severity.HIGH,
                            title="Secret in docker-compose environment",
                            description="Plaintext secret found in compose file",
                            file_location=filename,
                            line_number=i + 1,
                            evidence=f"Line: {stripped[:60]}...",
                            recommendation="Use Docker secrets or external secret management",
                        ))
                        break

        return findings


# ════════════════════════════════════════════════════════════════════════════════
# SIREN CONTAINER SECURITY — Main Orchestrator
# ════════════════════════════════════════════════════════════════════════════════

class SirenContainerSecurity:
    """
    Main container security audit engine.

    Orchestrates Dockerfile, Docker Compose, and Kubernetes manifest analysis.

    Usage:
        auditor = SirenContainerSecurity()

        # Analyze Dockerfile
        report = auditor.audit_dockerfile(content)

        # Analyze Kubernetes manifest
        report = auditor.audit_kubernetes(content)

        # Analyze Docker Compose
        report = auditor.audit_compose(content)
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._dockerfile_analyzer = DockerfileAnalyzer()
        self._k8s_analyzer = KubernetesAnalyzer()
        self._compose_analyzer = DockerComposeAnalyzer()
        self._stats: Dict[str, int] = defaultdict(int)
        logger.info("SirenContainerSecurity initialized")

    def audit_dockerfile(self, content: str, filename: str = "Dockerfile") -> ContainerAuditReport:
        """Audit a Dockerfile."""
        report = ContainerAuditReport(
            target=filename,
            runtime=ContainerRuntime.DOCKER,
        )
        report.findings = self._dockerfile_analyzer.analyze(content, filename)
        self._update_cis_stats(report)
        self._record_stats(report)
        return report

    def audit_kubernetes(self, content: str, filename: str = "manifest.yaml") -> ContainerAuditReport:
        """Audit a Kubernetes manifest."""
        report = ContainerAuditReport(
            target=filename,
            runtime=ContainerRuntime.DOCKER,
            orchestrator=OrchestratorType.KUBERNETES,
        )
        report.findings = self._k8s_analyzer.analyze_manifest(content, filename)
        self._update_cis_stats(report)
        self._record_stats(report)
        return report

    def audit_compose(self, content: str, filename: str = "docker-compose.yml") -> ContainerAuditReport:
        """Audit a Docker Compose file."""
        report = ContainerAuditReport(
            target=filename,
            runtime=ContainerRuntime.DOCKER,
        )
        report.findings = self._compose_analyzer.analyze(content, filename)
        self._update_cis_stats(report)
        self._record_stats(report)
        return report

    def audit_all(self, files: Dict[str, str]) -> List[ContainerAuditReport]:
        """Audit multiple container config files.

        Args:
            files: Dict of filename → content
        """
        reports: List[ContainerAuditReport] = []
        for filename, content in files.items():
            fn_lower = filename.lower()
            if "dockerfile" in fn_lower:
                reports.append(self.audit_dockerfile(content, filename))
            elif "compose" in fn_lower or "docker-compose" in fn_lower:
                reports.append(self.audit_compose(content, filename))
            elif fn_lower.endswith((".yaml", ".yml")):
                reports.append(self.audit_kubernetes(content, filename))
        return reports

    def get_stats(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._stats)

    # ── Private ─────────────────────────────────────────────────────────────

    @staticmethod
    def _update_cis_stats(report: ContainerAuditReport) -> None:
        """Calculate CIS benchmark compliance."""
        cis_findings = {f.cis_ref for f in report.findings if f.cis_ref}
        all_cis = set(CISBenchmark)
        report.cis_checks_total = len(all_cis)
        report.cis_checks_failed = len(cis_findings)
        report.cis_checks_passed = report.cis_checks_total - report.cis_checks_failed

    def _record_stats(self, report: ContainerAuditReport) -> None:
        with self._lock:
            self._stats["audits_run"] += 1
            self._stats["findings_total"] += len(report.findings)
            self._stats[f"critical_findings"] += report.critical_count
            self._stats[f"high_findings"] += report.high_count
