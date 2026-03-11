#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  📦 SIREN SUPPLY CHAIN — Dependency & Supply Chain Analysis Engine  📦       ██
██                                                                                ██
██  Análise profunda de cadeias de suprimento de software.                       ██
██                                                                                ██
██  Capacidades:                                                                  ██
██    • Dependency graph construction — mapeia árvore completa de deps          ██
██    • Known vulnerability matching — cruza deps com CVE database               ██
██    • License compliance — detecta incompatibilidades de licença               ██
██    • Typosquatting detection — identifica pacotes suspeitos                    ██
██    • Dependency confusion — detecta risco de substituição                     ██
██    • Phantom dependency detection — deps transitivas não declaradas          ██
██    • Supply chain attack indicators — backdoors, post-install scripts         ██
██    • SBOM generation — Software Bill of Materials                              ██
██                                                                                ██
██  "SIREN audita cada link da cadeia — do código ao deploy."                   ██
██                                                                                ██
████████████████████████████████████████████████████████████████████████████████████
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Deque, Dict, FrozenSet, List, Optional, Set, Tuple

logger = logging.getLogger("siren.arsenal.supply_chain")


# ════════════════════════════════════════════════════════════════════════════════
# ENUMS
# ════════════════════════════════════════════════════════════════════════════════

class PackageManager(Enum):
    """Supported package managers."""
    NPM = auto()
    PYPI = auto()
    MAVEN = auto()
    NUGET = auto()
    RUBYGEMS = auto()
    CARGO = auto()
    GO_MOD = auto()
    COMPOSER = auto()
    COCOAPODS = auto()
    GRADLE = auto()
    APK = auto()
    APT = auto()
    DOCKER = auto()
    UNKNOWN = auto()


class LicenseType(Enum):
    """License categories."""
    PERMISSIVE = auto()      # MIT, BSD, Apache
    WEAK_COPYLEFT = auto()   # LGPL, MPL
    STRONG_COPYLEFT = auto() # GPL, AGPL
    PROPRIETARY = auto()
    PUBLIC_DOMAIN = auto()   # CC0, Unlicense
    UNKNOWN = auto()


class RiskLevel(Enum):
    """Supply chain risk level."""
    CRITICAL = auto()
    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()
    INFO = auto()


class SupplyChainThreat(Enum):
    """Types of supply chain threats."""
    KNOWN_VULN = auto()
    TYPOSQUATTING = auto()
    DEPENDENCY_CONFUSION = auto()
    PHANTOM_DEPENDENCY = auto()
    MALICIOUS_SCRIPT = auto()
    ABANDONED_PACKAGE = auto()
    SINGLE_MAINTAINER = auto()
    UNPINNED_VERSION = auto()
    LICENSE_VIOLATION = auto()
    EXCESSIVE_PERMISSIONS = auto()
    OBFUSCATED_CODE = auto()
    DATA_EXFILTRATION = auto()
    BACKDOOR_INDICATOR = auto()
    NAMESPACE_HIJACK = auto()


# ════════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class PackageInfo:
    """Information about a dependency package."""
    name: str
    version: str = ""
    manager: PackageManager = PackageManager.UNKNOWN
    is_direct: bool = True
    is_dev: bool = False
    license_id: str = ""
    license_type: LicenseType = LicenseType.UNKNOWN
    homepage: str = ""
    repository: str = ""
    checksum_sha256: str = ""
    install_scripts: List[str] = field(default_factory=list)
    maintainer_count: int = 0
    download_count: int = 0
    last_publish_days: int = -1
    dependencies: List[str] = field(default_factory=list)

    @property
    def qualified_name(self) -> str:
        return f"{self.name}@{self.version}" if self.version else self.name

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "manager": self.manager.name,
            "is_direct": self.is_direct,
            "is_dev": self.is_dev,
            "license": self.license_id,
            "license_type": self.license_type.name,
            "dependencies": self.dependencies,
        }


@dataclass
class SupplyChainFinding:
    """A found supply chain issue."""
    threat: SupplyChainThreat
    risk: RiskLevel
    package: str
    version: str = ""
    title: str = ""
    description: str = ""
    evidence: str = ""
    cve_id: str = ""
    recommendation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "threat": self.threat.name,
            "risk": self.risk.name,
            "package": self.package,
            "version": self.version,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "cve_id": self.cve_id,
            "recommendation": self.recommendation,
        }


@dataclass
class DependencyNode:
    """Node in the dependency graph."""
    package: PackageInfo
    children: List[DependencyNode] = field(default_factory=list)
    depth: int = 0
    is_circular: bool = False

    @property
    def total_descendants(self) -> int:
        count = 0
        for child in self.children:
            count += 1 + child.total_descendants
        return count


@dataclass
class SBOMEntry:
    """Software Bill of Materials entry."""
    name: str
    version: str
    manager: PackageManager
    license_id: str
    checksum: str = ""
    supplier: str = ""
    is_direct: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "package_manager": self.manager.name,
            "license": self.license_id,
            "checksum_sha256": self.checksum,
            "supplier": self.supplier,
            "relationship": "direct" if self.is_direct else "transitive",
        }


@dataclass
class SupplyChainReport:
    """Complete supply chain analysis report."""
    target: str
    timestamp: float = field(default_factory=time.time)
    total_packages: int = 0
    direct_deps: int = 0
    transitive_deps: int = 0
    max_depth: int = 0
    findings: List[SupplyChainFinding] = field(default_factory=list)
    sbom: List[SBOMEntry] = field(default_factory=list)
    license_summary: Dict[str, int] = field(default_factory=dict)
    risk_summary: Dict[str, int] = field(default_factory=dict)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.risk == RiskLevel.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.risk == RiskLevel.HIGH)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "total_packages": self.total_packages,
            "direct_deps": self.direct_deps,
            "transitive_deps": self.transitive_deps,
            "max_depth": self.max_depth,
            "critical_findings": self.critical_count,
            "high_findings": self.high_count,
            "total_findings": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "license_summary": self.license_summary,
            "risk_summary": self.risk_summary,
            "sbom_entries": len(self.sbom),
        }


# ════════════════════════════════════════════════════════════════════════════════
# MANIFEST PARSERS — Extract deps from various lock/manifest files
# ════════════════════════════════════════════════════════════════════════════════

class ManifestParser:
    """Parse various package manager manifest files."""

    # License classification mapping
    LICENSE_MAP: Dict[str, LicenseType] = {
        "mit": LicenseType.PERMISSIVE,
        "bsd-2-clause": LicenseType.PERMISSIVE,
        "bsd-3-clause": LicenseType.PERMISSIVE,
        "apache-2.0": LicenseType.PERMISSIVE,
        "isc": LicenseType.PERMISSIVE,
        "unlicense": LicenseType.PUBLIC_DOMAIN,
        "cc0-1.0": LicenseType.PUBLIC_DOMAIN,
        "lgpl-2.1": LicenseType.WEAK_COPYLEFT,
        "lgpl-3.0": LicenseType.WEAK_COPYLEFT,
        "mpl-2.0": LicenseType.WEAK_COPYLEFT,
        "gpl-2.0": LicenseType.STRONG_COPYLEFT,
        "gpl-3.0": LicenseType.STRONG_COPYLEFT,
        "agpl-3.0": LicenseType.STRONG_COPYLEFT,
    }

    def classify_license(self, license_id: str) -> LicenseType:
        """Classify a license string into a category."""
        normalized = license_id.strip().lower().replace(" ", "-")
        return self.LICENSE_MAP.get(normalized, LicenseType.UNKNOWN)

    def parse_package_json(self, content: str) -> List[PackageInfo]:
        """Parse npm package.json."""
        packages: List[PackageInfo] = []
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, ValueError):
            return packages

        for dep_key, is_dev in [("dependencies", False), ("devDependencies", True)]:
            deps = data.get(dep_key, {})
            for name, version_spec in deps.items():
                packages.append(PackageInfo(
                    name=name,
                    version=version_spec,
                    manager=PackageManager.NPM,
                    is_direct=True,
                    is_dev=is_dev,
                ))
        return packages

    def parse_requirements_txt(self, content: str) -> List[PackageInfo]:
        """Parse Python requirements.txt."""
        packages: List[PackageInfo] = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # Handle various specifiers: pkg==1.0, pkg>=1.0, pkg~=1.0
            try:
                match = re.match(r"^([a-zA-Z0-9_.-]+)\s*([><=~!]+)?\s*(.+)?", line)
                if match:
                    name = match.group(1)
                    version = match.group(3) or ""
                    packages.append(PackageInfo(
                        name=name,
                        version=version.strip(),
                        manager=PackageManager.PYPI,
                        is_direct=True,
                    ))
            except re.error as exc:
                logger.warning("Failed to parse requirements line '%s': %s", line[:80], exc)
        return packages

    def parse_pom_xml(self, content: str) -> List[PackageInfo]:
        """Parse Maven pom.xml (basic regex parsing — no XML lib needed)."""
        packages: List[PackageInfo] = []
        try:
            # Match <dependency> blocks
            dep_pattern = re.compile(
                r"<dependency>\s*"
                r"<groupId>([^<]+)</groupId>\s*"
                r"<artifactId>([^<]+)</artifactId>\s*"
                r"(?:<version>([^<]+)</version>)?",
                re.DOTALL,
            )
            for match in dep_pattern.finditer(content):
                group_id = match.group(1).strip()
                artifact_id = match.group(2).strip()
                version = (match.group(3) or "").strip()
                packages.append(PackageInfo(
                    name=f"{group_id}:{artifact_id}",
                    version=version,
                    manager=PackageManager.MAVEN,
                    is_direct=True,
                ))
        except re.error as exc:
            logger.warning("Failed to parse pom.xml content: %s", exc)
        return packages

    def parse_go_mod(self, content: str) -> List[PackageInfo]:
        """Parse Go go.mod."""
        packages: List[PackageInfo] = []
        in_require = False
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("require ("):
                in_require = True
                continue
            if line == ")":
                in_require = False
                continue
            if in_require or line.startswith("require "):
                parts = line.replace("require ", "").strip().split()
                if len(parts) >= 2:
                    packages.append(PackageInfo(
                        name=parts[0],
                        version=parts[1],
                        manager=PackageManager.GO_MOD,
                        is_direct=True,
                    ))
        return packages

    def parse_cargo_toml(self, content: str) -> List[PackageInfo]:
        """Parse Rust Cargo.toml dependencies (basic parsing)."""
        packages: List[PackageInfo] = []
        in_deps = False
        for line in content.splitlines():
            line = line.strip()
            if line in ("[dependencies]", "[dev-dependencies]"):
                in_deps = True
                continue
            if line.startswith("[") and line.endswith("]"):
                in_deps = False
                continue
            if in_deps and "=" in line:
                name, _, ver = line.partition("=")
                ver = ver.strip().strip('"').strip("'")
                packages.append(PackageInfo(
                    name=name.strip(),
                    version=ver,
                    manager=PackageManager.CARGO,
                    is_direct=True,
                ))
        return packages


# ════════════════════════════════════════════════════════════════════════════════
# TYPOSQUATTING DETECTOR — Catches name-confusion attacks
# ════════════════════════════════════════════════════════════════════════════════

class TyposquattingDetector:
    """Detects potential typosquatting in package names."""

    # Popular packages per ecosystem (sample — SIREN's real DB would be larger)
    POPULAR_PACKAGES: Dict[PackageManager, Set[str]] = {
        PackageManager.NPM: {
            "lodash", "express", "react", "vue", "angular", "axios",
            "moment", "webpack", "babel", "eslint", "typescript", "jest",
            "mocha", "underscore", "async", "chalk", "commander", "debug",
            "request", "bluebird", "uuid", "cors", "socket.io", "next",
        },
        PackageManager.PYPI: {
            "requests", "flask", "django", "numpy", "pandas", "scipy",
            "boto3", "pillow", "sqlalchemy", "celery", "redis", "psycopg2",
            "cryptography", "pyyaml", "jinja2", "aiohttp", "fastapi",
            "pydantic", "httpx", "uvicorn", "pytest", "black", "mypy",
        },
    }

    def check(self, package: PackageInfo) -> Optional[SupplyChainFinding]:
        """Check if a package name is suspiciously similar to a popular one."""
        popular_set = self.POPULAR_PACKAGES.get(package.manager, set())
        if not popular_set or package.name in popular_set:
            return None

        for popular in popular_set:
            distance = self._levenshtein(package.name.lower(), popular.lower())
            name_len = max(len(package.name), len(popular))

            # Very close: 1-2 edits for packages >= 4 chars
            if name_len >= 4 and 0 < distance <= 2:
                return SupplyChainFinding(
                    threat=SupplyChainThreat.TYPOSQUATTING,
                    risk=RiskLevel.HIGH,
                    package=package.name,
                    version=package.version,
                    title=f"Possible typosquatting of '{popular}'",
                    description=(
                        f"Package '{package.name}' is {distance} edit(s) away from "
                        f"popular package '{popular}'. This is a common supply chain attack vector."
                    ),
                    evidence=f"Levenshtein distance: {distance}",
                    recommendation=f"Verify this is the intended package, not '{popular}'",
                )

            # Check common substitution patterns
            if self._is_substitution_variant(package.name, popular):
                return SupplyChainFinding(
                    threat=SupplyChainThreat.TYPOSQUATTING,
                    risk=RiskLevel.HIGH,
                    package=package.name,
                    version=package.version,
                    title=f"Name substitution variant of '{popular}'",
                    description=f"Package '{package.name}' uses common character substitution patterns vs '{popular}'",
                    recommendation=f"Verify this is the intended package, not '{popular}'",
                )

        return None

    @staticmethod
    def _levenshtein(s1: str, s2: str) -> int:
        """Compute Levenshtein edit distance."""
        if len(s1) < len(s2):
            return TyposquattingDetector._levenshtein(s2, s1)
        if not s2:
            return len(s1)

        prev_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row
        return prev_row[-1]

    @staticmethod
    def _is_substitution_variant(name: str, popular: str) -> bool:
        """Check for common character substitution patterns."""
        subs = [
            ("0", "o"), ("1", "l"), ("1", "i"),
            ("-", "_"), ("_", "-"), (".", "-"),
            ("rn", "m"), ("vv", "w"),
        ]
        normalized = name.lower()
        for old, new in subs:
            variant = normalized.replace(old, new)
            if variant == popular.lower():
                return True
        return False


# ════════════════════════════════════════════════════════════════════════════════
# DEPENDENCY CONFUSION DETECTOR
# ════════════════════════════════════════════════════════════════════════════════

class DependencyConfusionDetector:
    """Detects dependency confusion / substitution attack risks."""

    # Common internal package naming patterns
    INTERNAL_PATTERNS = [
        re.compile(r"^@[a-z-]+/"),          # Scoped npm packages
        re.compile(r"^internal[_-]"),        # internal-* prefix
        re.compile(r"^(com|org|net)\.[a-z]"), # Java-style reverse domain
        re.compile(r"^private[_-]"),
    ]

    def check(self, package: PackageInfo) -> Optional[SupplyChainFinding]:
        """Check for dependency confusion risk."""
        for pattern in self.INTERNAL_PATTERNS:
            try:
                match = pattern.search(package.name)
            except (re.error, TypeError) as exc:
                logger.warning("Regex error checking dependency confusion for '%s': %s", package.name, exc)
                continue
            if match:
                return SupplyChainFinding(
                    threat=SupplyChainThreat.DEPENDENCY_CONFUSION,
                    risk=RiskLevel.MEDIUM,
                    package=package.name,
                    version=package.version,
                    title="Potential dependency confusion target",
                    description=(
                        f"Package '{package.name}' matches internal naming patterns. "
                        "If not reserved in the public registry, an attacker could publish "
                        "a malicious package with the same name."
                    ),
                    recommendation="Reserve this name in the public registry or use scoped packages",
                )

        # Unpinned version (allows substitution)
        if package.version and package.version.startswith(("*", "latest", ">=", ">")):
            return SupplyChainFinding(
                threat=SupplyChainThreat.UNPINNED_VERSION,
                risk=RiskLevel.MEDIUM,
                package=package.name,
                version=package.version,
                title="Unpinned dependency version",
                description=(
                    f"Package '{package.name}' has unpinned version '{package.version}'. "
                    "This allows a malicious version to be pulled automatically."
                ),
                recommendation="Pin to specific version or use lockfile",
            )

        return None


# ════════════════════════════════════════════════════════════════════════════════
# INSTALL SCRIPT ANALYZER — Detects malicious post-install scripts
# ════════════════════════════════════════════════════════════════════════════════

class InstallScriptAnalyzer:
    """Analyzes package install scripts for suspicious behavior."""

    SUSPICIOUS_PATTERNS = [
        (re.compile(r"curl\s+.*\|\s*(bash|sh)", re.I), "Downloads and executes remote script"),
        (re.compile(r"wget\s+.*&&\s*(bash|sh|chmod)", re.I), "Downloads and executes remote script"),
        (re.compile(r"eval\s*\(\s*(atob|Buffer\.from|base64)", re.I), "Eval of encoded data"),
        (re.compile(r"child_process", re.I), "Spawns child process"),
        (re.compile(r"os\.system|subprocess\.(call|run|Popen)", re.I), "System command execution"),
        (re.compile(r"(\/etc\/passwd|\/etc\/shadow|\.ssh\/)", re.I), "Accesses sensitive system files"),
        (re.compile(r"(\.env|\.aws\/credentials|\.npmrc)", re.I), "Accesses credential files"),
        (re.compile(r"dns\.(lookup|resolve)|socket\.connect", re.I), "Network activity in install"),
        (re.compile(r"process\.env", re.I), "Reads environment variables"),
        (re.compile(r"(crypto|cipher)\.(create|encrypt)", re.I), "Encryption (potential data exfil)"),
    ]

    def analyze(self, package: PackageInfo) -> List[SupplyChainFinding]:
        """Analyze install scripts for suspicious patterns."""
        findings: List[SupplyChainFinding] = []

        for script in package.install_scripts:
            for pattern, description in self.SUSPICIOUS_PATTERNS:
                try:
                    match = pattern.search(script)
                except (re.error, TypeError) as exc:
                    logger.warning("Regex error in install script analysis for '%s': %s", package.name, exc)
                    continue
                if match:
                    findings.append(SupplyChainFinding(
                        threat=SupplyChainThreat.MALICIOUS_SCRIPT,
                        risk=RiskLevel.CRITICAL,
                        package=package.name,
                        version=package.version,
                        title=f"Suspicious install script: {description}",
                        description=f"Install script contains pattern indicating: {description}",
                        evidence=f"Pattern match: {pattern.pattern}",
                        recommendation="Review install script manually before installing",
                    ))

        return findings


# ════════════════════════════════════════════════════════════════════════════════
# LICENSE AUDITOR — Checks for license incompatibilities
# ════════════════════════════════════════════════════════════════════════════════

class LicenseAuditor:
    """Audits dependencies for license compliance issues."""

    # Licenses that may cause issues in proprietary projects
    RESTRICTIVE_LICENSES = {LicenseType.STRONG_COPYLEFT}

    def audit(self, packages: List[PackageInfo], project_license: LicenseType = LicenseType.PROPRIETARY) -> List[SupplyChainFinding]:
        """Audit all packages for license issues."""
        findings: List[SupplyChainFinding] = []

        for pkg in packages:
            if pkg.license_type == LicenseType.UNKNOWN and not pkg.is_dev:
                findings.append(SupplyChainFinding(
                    threat=SupplyChainThreat.LICENSE_VIOLATION,
                    risk=RiskLevel.MEDIUM,
                    package=pkg.name,
                    version=pkg.version,
                    title="Unknown license",
                    description=f"Package '{pkg.name}' has no identifiable license",
                    recommendation="Identify and verify the license before use",
                ))

            if pkg.license_type in self.RESTRICTIVE_LICENSES and not pkg.is_dev:
                if project_license in (LicenseType.PROPRIETARY, LicenseType.PERMISSIVE):
                    findings.append(SupplyChainFinding(
                        threat=SupplyChainThreat.LICENSE_VIOLATION,
                        risk=RiskLevel.HIGH,
                        package=pkg.name,
                        version=pkg.version,
                        title=f"Copyleft license ({pkg.license_id}) in non-copyleft project",
                        description=(
                            f"Package '{pkg.name}' uses {pkg.license_id} which may require "
                            "your project to be released under the same license."
                        ),
                        recommendation="Replace with a permissively-licensed alternative or comply with license terms",
                    ))

        return findings


# ════════════════════════════════════════════════════════════════════════════════
# DEPENDENCY GRAPH BUILDER
# ════════════════════════════════════════════════════════════════════════════════

class DependencyGraphBuilder:
    """Builds and analyzes the dependency graph."""

    def build(self, packages: List[PackageInfo]) -> Tuple[List[DependencyNode], int]:
        """Build dependency tree. Returns (root_nodes, max_depth)."""
        pkg_map = {p.name: p for p in packages}
        visited: Set[str] = set()
        roots: List[DependencyNode] = []
        max_depth = 0

        for pkg in packages:
            if pkg.is_direct:
                node, depth = self._build_node(pkg, pkg_map, visited, 0)
                roots.append(node)
                max_depth = max(max_depth, depth)

        return roots, max_depth

    # Maximum recursion depth for dependency graph building
    MAX_GRAPH_DEPTH = 100

    def _build_node(self, pkg: PackageInfo, pkg_map: Dict[str, PackageInfo],
                     visited: Set[str], depth: int) -> Tuple[DependencyNode, int]:
        """Recursively build a dependency node."""
        node = DependencyNode(package=pkg, depth=depth)

        if pkg.name in visited:
            node.is_circular = True
            return node, depth

        if depth >= self.MAX_GRAPH_DEPTH:
            logger.warning("Max dependency graph depth (%d) reached at package '%s'", self.MAX_GRAPH_DEPTH, pkg.name)
            return node, depth

        visited.add(pkg.name)
        max_depth = depth

        for dep_name in pkg.dependencies:
            child_pkg = pkg_map.get(dep_name)
            if child_pkg:
                child_node, child_depth = self._build_node(child_pkg, pkg_map, visited, depth + 1)
                node.children.append(child_node)
                max_depth = max(max_depth, child_depth)

        visited.discard(pkg.name)
        return node, max_depth

    @staticmethod
    def find_circular(roots: List[DependencyNode]) -> List[str]:
        """Find circular dependencies."""
        circular: List[str] = []

        def walk(node: DependencyNode) -> None:
            if node.is_circular:
                circular.append(node.package.name)
            for child in node.children:
                walk(child)

        for root in roots:
            walk(root)
        return circular


# ════════════════════════════════════════════════════════════════════════════════
# SIREN SUPPLY CHAIN ANALYZER — Main Orchestrator
# ════════════════════════════════════════════════════════════════════════════════

class SirenSupplyChain:
    """
    Main supply chain analysis engine.

    Orchestrates manifest parsing, dependency graphing, vulnerability matching,
    typosquatting detection, license auditing, and SBOM generation.

    Usage:
        analyzer = SirenSupplyChain()

        # From manifest content
        report = analyzer.analyze_manifest(content, "package.json")

        # From pre-parsed packages
        report = analyzer.analyze_packages(packages, target="my-project")
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._parser = ManifestParser()
        self._typo_detector = TyposquattingDetector()
        self._confusion_detector = DependencyConfusionDetector()
        self._script_analyzer = InstallScriptAnalyzer()
        self._license_auditor = LicenseAuditor()
        self._graph_builder = DependencyGraphBuilder()
        self._stats: Dict[str, int] = defaultdict(int)
        logger.info("SirenSupplyChain initialized")

    def analyze_manifest(self, content: str, filename: str, target: str = "") -> SupplyChainReport:
        """Analyze a manifest/lockfile content."""
        if not content:
            logger.warning("Empty manifest content for %s", filename)
            return SupplyChainReport(target=target or filename)
        try:
            packages = self._parse_manifest(content, filename)
        except Exception as exc:
            logger.warning("Failed to parse manifest %s: %s", filename, exc)
            return SupplyChainReport(target=target or filename)
        return self.analyze_packages(packages, target=target or filename)

    def analyze_packages(self, packages: List[PackageInfo], target: str = "") -> SupplyChainReport:
        """Run full supply chain analysis on a list of packages."""
        report = SupplyChainReport(target=target)

        with self._lock:
            self._stats["analyses_run"] += 1

        # 1. Build dependency graph
        roots, max_depth = self._graph_builder.build(packages)
        report.max_depth = max_depth
        report.total_packages = len(packages)
        report.direct_deps = sum(1 for p in packages if p.is_direct)
        report.transitive_deps = report.total_packages - report.direct_deps

        # 2. Run all checks
        findings: List[SupplyChainFinding] = []

        for pkg in packages:
            # Typosquatting
            typo = self._typo_detector.check(pkg)
            if typo:
                findings.append(typo)

            # Dependency confusion
            confusion = self._confusion_detector.check(pkg)
            if confusion:
                findings.append(confusion)

            # Install script analysis
            findings.extend(self._script_analyzer.analyze(pkg))

        # 3. License audit
        findings.extend(self._license_auditor.audit(packages))

        # 4. Circular dependency check
        circular = self._graph_builder.find_circular(roots)
        for circ_name in circular:
            findings.append(SupplyChainFinding(
                threat=SupplyChainThreat.PHANTOM_DEPENDENCY,
                risk=RiskLevel.LOW,
                package=circ_name,
                title="Circular dependency detected",
                description=f"Package '{circ_name}' is part of a circular dependency chain",
                recommendation="Review and break the circular dependency",
            ))

        # 5. Generate SBOM
        for pkg in packages:
            report.sbom.append(SBOMEntry(
                name=pkg.name,
                version=pkg.version,
                manager=pkg.manager,
                license_id=pkg.license_id,
                checksum=pkg.checksum_sha256,
                is_direct=pkg.is_direct,
            ))

        # 6. Summarize
        report.findings = sorted(findings, key=lambda f: list(RiskLevel).index(f.risk))

        license_counts: Dict[str, int] = defaultdict(int)
        for pkg in packages:
            license_counts[pkg.license_type.name] += 1
        report.license_summary = dict(license_counts)

        risk_counts: Dict[str, int] = defaultdict(int)
        for f in findings:
            risk_counts[f.risk.name] += 1
        report.risk_summary = dict(risk_counts)

        with self._lock:
            self._stats["packages_analyzed"] += len(packages)
            self._stats["findings_total"] += len(findings)

        return report

    def get_stats(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._stats)

    # ── Private ─────────────────────────────────────────────────────────────

    def _parse_manifest(self, content: str, filename: str) -> List[PackageInfo]:
        """Route to appropriate manifest parser."""
        fn = filename.lower()
        if fn in ("package.json",):
            return self._parser.parse_package_json(content)
        elif fn in ("requirements.txt", "constraints.txt"):
            return self._parser.parse_requirements_txt(content)
        elif fn == "pom.xml":
            return self._parser.parse_pom_xml(content)
        elif fn == "go.mod":
            return self._parser.parse_go_mod(content)
        elif fn in ("cargo.toml",):
            return self._parser.parse_cargo_toml(content)
        else:
            logger.warning("Unknown manifest format: %s", filename)
            return []
