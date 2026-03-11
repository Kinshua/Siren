#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  🛡️  SIREN DEFENSIVE MIRROR — Auto-Generation de Defesas  🛡️                 ██
██                                                                                ██
██  SIREN não apenas ATACA — ela gera as DEFESAS automaticamente.                ██
██                                                                                ██
██  Para cada vulnerabilidade encontrada, o mirror gera:                          ██
██    • WAF Rules — ModSecurity/Cloudflare/AWS WAF                               ██
██    • Firewall Rules — iptables/nftables                                       ██
██    • IDS Signatures — Snort/Suricata                                          ██
██    • SIGMA Rules — SIEM detection rules                                       ██
██    • Code Patches — Fix suggestions in context                                ██
██    • Config Fixes — Hardening recommendations                                 ██
██                                                                                ██
██  "Para cada espada que SIREN forja, ela também cria o escudo."                ██
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
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

logger = logging.getLogger("siren.intelligence.defensive_mirror")


# ════════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════════════════════════════

THREAD_POOL_SIZE = 4


# ════════════════════════════════════════════════════════════════════════════════
# ENUMS
# ════════════════════════════════════════════════════════════════════════════════


class RuleFormat(Enum):
    """Supported output formats for defensive rules."""
    MODSECURITY = "modsecurity"
    CLOUDFLARE = "cloudflare"
    AWS_WAF = "aws_waf"
    IPTABLES = "iptables"
    NFTABLES = "nftables"
    SNORT = "snort"
    SURICATA = "suricata"
    SIGMA = "sigma"
    CODE_PATCH = "code_patch"
    CONFIG_FIX = "config_fix"


class Severity(Enum):
    """Rule severity classification."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FixCategory(Enum):
    """Category of remediation."""
    INPUT_VALIDATION = "input_validation"
    OUTPUT_ENCODING = "output_encoding"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    ENCRYPTION = "encryption"
    CONFIGURATION = "configuration"
    RATE_LIMITING = "rate_limiting"
    NETWORK_SEGMENTATION = "network_segmentation"
    LOGGING = "logging"
    PATCHING = "patching"


# ════════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ════════════════════════════════════════════════════════════════════════════════


@dataclass
class DefensiveRule:
    """A generated defensive rule."""
    rule_id: str
    rule_format: RuleFormat
    severity: Severity
    title: str
    description: str
    rule_content: str               # The actual rule/signature/config text
    cwe_id: str = ""
    vuln_id: str = ""
    fix_category: FixCategory = FixCategory.INPUT_VALIDATION
    false_positive_risk: float = 0.1
    performance_impact: str = "low"  # low, medium, high
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "format": self.rule_format.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "rule_content": self.rule_content,
            "cwe_id": self.cwe_id,
            "fix_category": self.fix_category.value,
            "false_positive_risk": self.false_positive_risk,
            "performance_impact": self.performance_impact,
        }


# ════════════════════════════════════════════════════════════════════════════════
# CWE → DEFENSE KNOWLEDGE BASE
# ════════════════════════════════════════════════════════════════════════════════

_CWE_DEFENSE_KB: Dict[str, Dict[str, Any]] = {
    "CWE-89": {
        "name": "SQL Injection",
        "severity": Severity.CRITICAL,
        "categories": [FixCategory.INPUT_VALIDATION, FixCategory.OUTPUT_ENCODING],
        "waf_patterns": [
            r"(?i)(\b(union|select|insert|update|delete|drop|alter|create|exec)\b.*\b(from|into|table|where|set)\b)",
            r"(?i)(\b(or|and)\b\s+\d+\s*=\s*\d+)",
            r"(?i)(;\s*--)",
            r"(?i)('|\"|;|\b(benchmark|sleep|waitfor)\b)",
            r"(?i)(\b(information_schema|sysobjects|syscolumns)\b)",
        ],
        "snort_content": [
            'content:"UNION"; nocase;',
            'content:"SELECT"; nocase;',
            'content:"FROM"; nocase;',
            'pcre:"/union\\s+(all\\s+)?select/i";',
        ],
        "sigma_keywords": ["union select", "' or 1=1", "information_schema", "sleep(", "benchmark("],
        "code_fix": "Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
        "config_fix": "Enable SQL query logging. Use least-privilege database accounts. Deploy WAF.",
    },
    "CWE-79": {
        "name": "Cross-Site Scripting (XSS)",
        "severity": Severity.HIGH,
        "categories": [FixCategory.OUTPUT_ENCODING, FixCategory.INPUT_VALIDATION],
        "waf_patterns": [
            r"(?i)(<script[^>]*>)",
            r"(?i)(javascript\s*:)",
            r"(?i)(on(load|error|click|mouseover|focus|blur|submit)\s*=)",
            r"(?i)(<\s*img[^>]+onerror)",
            r"(?i)(<\s*svg[^>]+onload)",
            r"(?i)(<\s*iframe)",
        ],
        "snort_content": [
            'content:"<script"; nocase;',
            'content:"javascript:"; nocase;',
            'pcre:"/<script[^>]*>/i";',
        ],
        "sigma_keywords": ["<script>", "javascript:", "onerror=", "onload=", "alert("],
        "code_fix": "HTML-encode all user output. Use Content-Security-Policy headers. Use auto-escaping templates.",
        "config_fix": "Set Content-Security-Policy header. Enable X-XSS-Protection. Set HttpOnly on cookies.",
    },
    "CWE-78": {
        "name": "OS Command Injection",
        "severity": Severity.CRITICAL,
        "categories": [FixCategory.INPUT_VALIDATION],
        "waf_patterns": [
            r"(?i)(;\s*(ls|cat|wget|curl|nc|bash|sh|python|perl|ruby|php)\b)",
            r"(\|\s*\w+)",
            r"(`[^`]+`)",
            r"(\$\([^)]+\))",
            r"(?i)(\b(eval|exec|system|passthru|popen|shell_exec)\b\s*\()",
        ],
        "snort_content": [
            'pcre:"/;\\s*(ls|cat|id|whoami|uname)/i";',
            'content:"|"; content:"cat";',
        ],
        "sigma_keywords": ["; cat ", "; ls ", "| nc", "`id`", "$(whoami)"],
        "code_fix": "Never pass user input to shell commands. Use language-native APIs instead of system().",
        "config_fix": "Disable dangerous PHP functions (exec, system). Use AppArmor/SELinux. Restrict PATH.",
    },
    "CWE-22": {
        "name": "Path Traversal",
        "severity": Severity.HIGH,
        "categories": [FixCategory.INPUT_VALIDATION],
        "waf_patterns": [
            r"(\.\.[\\/])",
            r"(?i)(/etc/(passwd|shadow|hosts))",
            r"(?i)(/(windows|winnt)/system32)",
            r"(%2e%2e[\\/]|%252e%252e)",
            r"(\.\./\.\./)",
        ],
        "snort_content": [
            'content:"../"; content:"etc/passwd";',
            'pcre:"/\\.\\.\\/.*\\.\\.\\/.*passwd/";',
        ],
        "sigma_keywords": ["../", "..\\", "/etc/passwd", "boot.ini"],
        "code_fix": "Validate file paths against a whitelist. Use os.path.realpath() and verify prefix.",
        "config_fix": "Chroot the web application. Disable directory listing. Restrict file permissions.",
    },
    "CWE-918": {
        "name": "Server-Side Request Forgery (SSRF)",
        "severity": Severity.HIGH,
        "categories": [FixCategory.INPUT_VALIDATION, FixCategory.NETWORK_SEGMENTATION],
        "waf_patterns": [
            r"(?i)(169\.254\.169\.254)",
            r"(?i)(127\.0\.0\.\d+|localhost|0\.0\.0\.0)",
            r"(?i)(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)",
            r"(?i)(file://|gopher://|dict://|ftp://)",
        ],
        "snort_content": [
            'content:"169.254.169.254";',
            'content:"127.0.0.1";',
            'pcre:"/\\b(file|gopher|dict):\\/\\//i";',
        ],
        "sigma_keywords": ["169.254.169.254", "metadata/iam", "file://", "gopher://"],
        "code_fix": "Use allowlist for URLs/IPs. Block private IP ranges. Don't follow redirects blindly.",
        "config_fix": "Block metadata endpoints at network level. Use IMDSv2 (AWS). Segment internal services.",
    },
    "CWE-502": {
        "name": "Insecure Deserialization",
        "severity": Severity.CRITICAL,
        "categories": [FixCategory.INPUT_VALIDATION],
        "waf_patterns": [
            r"(?i)(rO0AB|aced0005)",
            r"(?i)(O:\d+:\")",
            r"(?i)(__wakeup|__destruct|__toString)",
            r"(?i)(java\.(lang|util|io|net)\.)",
        ],
        "snort_content": [
            'content:"rO0AB"; content:"aced0005";',
            'pcre:"/O:\\d+:\"/";',
        ],
        "sigma_keywords": ["ObjectInputStream", "unserialize(", "pickle.loads", "yaml.load"],
        "code_fix": "Don't deserialize untrusted data. Use JSON instead. Implement type whitelists.",
        "config_fix": "Disable Java RMI if unused. Update serialization libraries. Enable RASP.",
    },
    "CWE-611": {
        "name": "XML External Entity (XXE)",
        "severity": Severity.HIGH,
        "categories": [FixCategory.INPUT_VALIDATION, FixCategory.CONFIGURATION],
        "waf_patterns": [
            r"(?i)(<!ENTITY)",
            r"(?i)(<!DOCTYPE[^>]*\[)",
            r"(?i)(SYSTEM\s+\"(https?|file|ftp|gopher)://)",
            r"(?i)(<!ENTITY\s+%\s+\w+\s+SYSTEM)",
        ],
        "snort_content": [
            'content:"<!ENTITY"; nocase;',
            'content:"SYSTEM"; nocase;',
            'pcre:"/<!ENTITY[^>]*SYSTEM/i";',
        ],
        "sigma_keywords": ["<!ENTITY", "SYSTEM", "file:///", "expect://"],
        "code_fix": "Disable DTD processing. Disable external entities. Use defusedxml (Python).",
        "config_fix": "Disable DTDs in XML parser configuration. Upgrade XML libraries.",
    },
    "CWE-287": {
        "name": "Improper Authentication",
        "severity": Severity.CRITICAL,
        "categories": [FixCategory.AUTHENTICATION],
        "waf_patterns": [],
        "snort_content": [],
        "sigma_keywords": ["authentication bypass", "default password", "missing auth"],
        "code_fix": "Implement proper authentication. Use established frameworks. Enforce MFA.",
        "config_fix": "Change all default credentials. Enable account lockout. Implement MFA.",
    },
    "CWE-798": {
        "name": "Hardcoded Credentials",
        "severity": Severity.CRITICAL,
        "categories": [FixCategory.AUTHENTICATION, FixCategory.CONFIGURATION],
        "waf_patterns": [],
        "snort_content": [],
        "sigma_keywords": ["hardcoded password", "default credentials", "api_key ="],
        "code_fix": "Use environment variables or secrets manager. Never hardcode credentials.",
        "config_fix": "Rotate all hardcoded credentials. Implement secrets management (Vault, AWS SM).",
    },
    "CWE-434": {
        "name": "Unrestricted File Upload",
        "severity": Severity.CRITICAL,
        "categories": [FixCategory.INPUT_VALIDATION, FixCategory.CONFIGURATION],
        "waf_patterns": [
            r"(?i)(\.php\d?|\.phtml|\.pht)$",
            r"(?i)(\.asp|\.aspx|\.jsp|\.jspx)$",
            r"(?i)(\.sh|\.py|\.pl|\.rb|\.cgi)$",
        ],
        "snort_content": [
            'content:"Content-Disposition"; content:"filename="; pcre:"/\\.(php|asp|jsp|sh|py)/i";',
        ],
        "sigma_keywords": ["file upload", "webshell", ".php upload", ".asp upload"],
        "code_fix": "Validate file type (magic bytes, not extension). Store outside webroot. Rename uploaded files.",
        "config_fix": "Disable script execution in upload directory. Set file size limits. Scan uploads with AV.",
    },
    "CWE-94": {
        "name": "Code Injection",
        "severity": Severity.CRITICAL,
        "categories": [FixCategory.INPUT_VALIDATION],
        "waf_patterns": [
            r"(?i)(\beval\s*\()",
            r"(?i)(Function\s*\()",
            r"(?i)(\b(exec|compile|__import__)\s*\()",
        ],
        "snort_content": [
            'pcre:"/\\beval\\s*\\(/i";',
        ],
        "sigma_keywords": ["eval(", "exec(", "Function(", "import os"],
        "code_fix": "Never eval() user input. Use safe alternatives. Implement sandboxing.",
        "config_fix": "Disable eval in runtime config where possible. Use CSP to block inline scripts.",
    },
    "CWE-16": {
        "name": "Security Misconfiguration",
        "severity": Severity.MEDIUM,
        "categories": [FixCategory.CONFIGURATION],
        "waf_patterns": [],
        "snort_content": [],
        "sigma_keywords": ["debug mode", "default config", "directory listing"],
        "code_fix": "Follow framework hardening guides. Disable debug mode in production.",
        "config_fix": "Disable directory listing. Remove default pages. Disable unnecessary HTTP methods.",
    },
}


# ════════════════════════════════════════════════════════════════════════════════
# RULE GENERATORS
# ════════════════════════════════════════════════════════════════════════════════


class WAFRuleGenerator:
    """Generates WAF rules (ModSecurity, Cloudflare, AWS WAF)."""

    def __init__(self) -> None:
        self._rule_counter = 9500000  # Start rule IDs in custom range

    def generate(
        self, cwe_id: str, vuln_id: str = "", context: Optional[Dict[str, Any]] = None
    ) -> List[DefensiveRule]:
        """Generate WAF rules for a CWE."""
        kb = _CWE_DEFENSE_KB.get(cwe_id)
        if not kb or not kb.get("waf_patterns"):
            return []

        rules: List[DefensiveRule] = []
        for i, pattern in enumerate(kb["waf_patterns"]):
            self._rule_counter += 1
            rule_id = f"SIREN-WAF-{self._rule_counter}"

            modsec_rule = self._to_modsecurity(rule_id, pattern, kb, vuln_id)
            rules.append(DefensiveRule(
                rule_id=rule_id,
                rule_format=RuleFormat.MODSECURITY,
                severity=kb["severity"],
                title=f"Block {kb['name']} Pattern {i+1}",
                description=f"Auto-generated ModSecurity rule for {cwe_id} ({kb['name']})",
                rule_content=modsec_rule,
                cwe_id=cwe_id,
                vuln_id=vuln_id,
                fix_category=kb["categories"][0],
                false_positive_risk=0.15 if i == 0 else 0.1,
                performance_impact="low",
            ))

        return rules

    def _to_modsecurity(self, rule_id: str, pattern: str, kb: Dict, vuln_id: str) -> str:
        action = "deny" if kb["severity"] in (Severity.CRITICAL, Severity.HIGH) else "log"
        return (
            f'SecRule REQUEST_URI|ARGS|ARGS_NAMES|REQUEST_BODY "@rx {pattern}" '
            f'"id:{self._rule_counter},'
            f'phase:2,'
            f'{action},'
            f'status:403,'
            f'log,'
            f'msg:\'{kb["name"]} attempt detected (SIREN {rule_id})\','
            f'tag:\'SIREN/auto-generated\','
            f'tag:\'{vuln_id}\','
            f'severity:\'CRITICAL\'"'
        )


class FirewallRuleGenerator:
    """Generates network firewall rules (iptables/nftables)."""

    def generate(
        self, cwe_id: str, vuln_id: str = "", context: Optional[Dict[str, Any]] = None
    ) -> List[DefensiveRule]:
        """Generate firewall rules. Focuses on network-level CWEs."""
        ctx = context or {}
        rules: List[DefensiveRule] = []

        if cwe_id == "CWE-918":  # SSRF — block internal ranges
            rules.append(DefensiveRule(
                rule_id=f"SIREN-FW-{vuln_id}-SSRF-1",
                rule_format=RuleFormat.IPTABLES,
                severity=Severity.HIGH,
                title="Block SSRF to cloud metadata",
                description="Block outbound requests to AWS/GCP/Azure metadata endpoints",
                rule_content=(
                    "# Block cloud metadata endpoints\n"
                    "iptables -A OUTPUT -d 169.254.169.254 -j DROP\n"
                    "iptables -A OUTPUT -d 169.254.170.2 -j DROP\n"
                    "# Block internal network from web server\n"
                    "iptables -A OUTPUT -d 10.0.0.0/8 -j DROP\n"
                    "iptables -A OUTPUT -d 172.16.0.0/12 -j DROP\n"
                    "iptables -A OUTPUT -d 192.168.0.0/16 -j DROP"
                ),
                cwe_id=cwe_id,
                vuln_id=vuln_id,
                fix_category=FixCategory.NETWORK_SEGMENTATION,
            ))

        # Generic rate limiting for any exploitable service
        port = ctx.get("port", "80")
        rules.append(DefensiveRule(
            rule_id=f"SIREN-FW-{vuln_id}-RATE-1",
            rule_format=RuleFormat.IPTABLES,
            severity=Severity.MEDIUM,
            title=f"Rate limit on port {port}",
            description="Rate limit incoming connections to mitigate exploitation",
            rule_content=(
                f"# Rate limit — max 30 connections per minute per IP\n"
                f"iptables -A INPUT -p tcp --dport {port} "
                f"-m connlimit --connlimit-above 30 --connlimit-period 60 -j REJECT"
            ),
            cwe_id=cwe_id,
            vuln_id=vuln_id,
            fix_category=FixCategory.RATE_LIMITING,
        ))

        return rules


class IDSSignatureGenerator:
    """Generates Snort/Suricata IDS signatures."""

    def __init__(self) -> None:
        self._sid_counter = 3000000

    def generate(
        self, cwe_id: str, vuln_id: str = "", context: Optional[Dict[str, Any]] = None
    ) -> List[DefensiveRule]:
        """Generate IDS signatures for a CWE."""
        kb = _CWE_DEFENSE_KB.get(cwe_id)
        if not kb or not kb.get("snort_content"):
            return []

        rules: List[DefensiveRule] = []
        for i, content in enumerate(kb["snort_content"]):
            self._sid_counter += 1
            rule = self._build_snort_rule(content, kb, self._sid_counter, vuln_id)
            rules.append(DefensiveRule(
                rule_id=f"SIREN-IDS-{self._sid_counter}",
                rule_format=RuleFormat.SNORT,
                severity=kb["severity"],
                title=f"Detect {kb['name']} Pattern {i+1}",
                description=f"Snort signature for {cwe_id} exploitation attempts",
                rule_content=rule,
                cwe_id=cwe_id,
                vuln_id=vuln_id,
                fix_category=FixCategory.LOGGING,
                false_positive_risk=0.2,
            ))

        return rules

    def _build_snort_rule(
        self, content: str, kb: Dict[str, Any], sid: int, vuln_id: str
    ) -> str:
        action = "alert"
        return (
            f'{action} tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS '
            f'(msg:"SIREN: {kb["name"]} attempt [{vuln_id}]"; '
            f'{content} '
            f'classtype:web-application-attack; '
            f'sid:{sid}; rev:1; '
            f'metadata:tag SIREN, cwe {kb["name"]};)'
        )


class SIGMARuleGenerator:
    """Generates SIGMA rules for SIEM integration."""

    def generate(
        self, cwe_id: str, vuln_id: str = "", context: Optional[Dict[str, Any]] = None
    ) -> List[DefensiveRule]:
        """Generate SIGMA detection rules."""
        kb = _CWE_DEFENSE_KB.get(cwe_id)
        if not kb:
            return []

        keywords = kb.get("sigma_keywords", [])
        if not keywords:
            return []

        rule_id = hashlib.sha256(f"SIGMA_{cwe_id}_{vuln_id}".encode()).hexdigest()[:12]
        keywords_yaml = "\n".join(f"            - '*{kw}*'" for kw in keywords)

        sigma_rule = (
            f"title: SIREN Detection - {kb['name']}\n"
            f"id: {rule_id}\n"
            f"status: experimental\n"
            f"description: Auto-generated SIGMA rule for {cwe_id} ({kb['name']})\n"
            f"author: SIREN Defensive Mirror\n"
            f"date: {time.strftime('%Y/%m/%d')}\n"
            f"tags:\n"
            f"    - attack.initial_access\n"
            f"    - cwe.{cwe_id.lower().replace('-', '_')}\n"
            f"logsource:\n"
            f"    category: webserver\n"
            f"    product: generic\n"
            f"detection:\n"
            f"    selection:\n"
            f"        cs-uri-query|contains:\n"
            f"{keywords_yaml}\n"
            f"    condition: selection\n"
            f"level: {kb['severity'].value}\n"
            f"falsepositives:\n"
            f"    - Legitimate application behavior\n"
            f"references:\n"
            f"    - https://cwe.mitre.org/data/definitions/{cwe_id.split('-')[1]}.html"
        )

        return [DefensiveRule(
            rule_id=f"SIREN-SIGMA-{rule_id}",
            rule_format=RuleFormat.SIGMA,
            severity=kb["severity"],
            title=f"SIGMA: Detect {kb['name']}",
            description=f"SIGMA rule for {cwe_id} exploitation detection",
            rule_content=sigma_rule,
            cwe_id=cwe_id,
            vuln_id=vuln_id,
            fix_category=FixCategory.LOGGING,
            false_positive_risk=0.25,
        )]


class CodePatchGenerator:
    """Generates code-level fix recommendations."""

    def generate(
        self, cwe_id: str, vuln_id: str = "", context: Optional[Dict[str, Any]] = None
    ) -> List[DefensiveRule]:
        """Generate code patch recommendations."""
        kb = _CWE_DEFENSE_KB.get(cwe_id)
        if not kb or not kb.get("code_fix"):
            return []

        ctx = context or {}
        language = ctx.get("language", "generic")

        fix_content = f"# Fix for {cwe_id}: {kb['name']}\n"
        fix_content += f"# Language: {language}\n\n"
        fix_content += f"## Recommendation\n{kb['code_fix']}\n"

        # Add language-specific examples
        specific = self._get_language_specific(cwe_id, language)
        if specific:
            fix_content += f"\n## Example ({language})\n```{language}\n{specific}\n```\n"

        return [DefensiveRule(
            rule_id=f"SIREN-PATCH-{cwe_id}-{vuln_id}",
            rule_format=RuleFormat.CODE_PATCH,
            severity=kb["severity"],
            title=f"Code Fix: {kb['name']}",
            description=kb["code_fix"],
            rule_content=fix_content,
            cwe_id=cwe_id,
            vuln_id=vuln_id,
            fix_category=kb["categories"][0],
        )]

    def _get_language_specific(self, cwe_id: str, language: str) -> str:
        """Get language-specific fix examples."""
        examples: Dict[str, Dict[str, str]] = {
            "CWE-89": {
                "python": "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
                "java": 'PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");\nps.setInt(1, userId);',
                "php": "$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');\n$stmt->execute(['id' => $userId]);",
                "node": "db.query('SELECT * FROM users WHERE id = $1', [userId])",
            },
            "CWE-79": {
                "python": "from markupsafe import escape\nreturn escape(user_input)",
                "java": "import org.owasp.encoder.Encode;\nString safe = Encode.forHtml(userInput);",
                "php": "echo htmlspecialchars($userInput, ENT_QUOTES, 'UTF-8');",
                "node": "const escaped = require('he').encode(userInput);",
            },
            "CWE-78": {
                "python": "import subprocess\nsubprocess.run(['ls', '-la', safe_path], check=True)  # No shell=True",
                "java": "ProcessBuilder pb = new ProcessBuilder(\"ls\", \"-la\", safePath);\npb.start();",
                "php": "// Use escapeshellarg() at minimum\n$output = shell_exec('ls -la ' . escapeshellarg($safePath));",
                "node": "const { execFile } = require('child_process');\nexecFile('ls', ['-la', safePath]);",
            },
            "CWE-22": {
                "python": "import os\nreal = os.path.realpath(user_path)\nassert real.startswith(ALLOWED_DIR)",
                "java": "Path real = Paths.get(userPath).toRealPath();\nif (!real.startsWith(allowedDir)) throw new SecurityException();",
                "php": "$real = realpath($userPath);\nif (strpos($real, $allowedDir) !== 0) die('Access denied');",
                "node": "const real = fs.realpathSync(userPath);\nif (!real.startsWith(allowedDir)) throw new Error('Access denied');",
            },
        }
        return examples.get(cwe_id, {}).get(language, "")


class ConfigFixGenerator:
    """Generates configuration hardening recommendations."""

    def generate(
        self, cwe_id: str, vuln_id: str = "", context: Optional[Dict[str, Any]] = None
    ) -> List[DefensiveRule]:
        """Generate config fix recommendations."""
        kb = _CWE_DEFENSE_KB.get(cwe_id)
        if not kb or not kb.get("config_fix"):
            return []

        return [DefensiveRule(
            rule_id=f"SIREN-CONFIG-{cwe_id}-{vuln_id}",
            rule_format=RuleFormat.CONFIG_FIX,
            severity=kb["severity"],
            title=f"Config Hardening: {kb['name']}",
            description=kb["config_fix"],
            rule_content=f"# Configuration Fix for {cwe_id}: {kb['name']}\n\n{kb['config_fix']}",
            cwe_id=cwe_id,
            vuln_id=vuln_id,
            fix_category=FixCategory.CONFIGURATION,
        )]


# ════════════════════════════════════════════════════════════════════════════════
# MAIN INTERFACE: SirenDefensiveMirror
# ════════════════════════════════════════════════════════════════════════════════


class SirenDefensiveMirror:
    """Generates complete defensive packages for every vulnerability found.

    Usage:
        mirror = SirenDefensiveMirror()
        defenses = mirror.generate_all("CWE-89", vuln_id="sqli_login")
        for rule in defenses:
            print(rule.rule_id, rule.rule_format.value, rule.title)
    """

    def __init__(self) -> None:
        self._waf = WAFRuleGenerator()
        self._firewall = FirewallRuleGenerator()
        self._ids = IDSSignatureGenerator()
        self._sigma = SIGMARuleGenerator()
        self._code = CodePatchGenerator()
        self._config = ConfigFixGenerator()
        self._lock = threading.RLock()
        self._pool = ThreadPoolExecutor(max_workers=THREAD_POOL_SIZE, thread_name_prefix="siren-mirror")
        self._generated_rules: List[DefensiveRule] = []

        logger.info("SirenDefensiveMirror initialized")

    def generate_all(
        self, cwe_id: str, vuln_id: str = "", context: Optional[Dict[str, Any]] = None
    ) -> List[DefensiveRule]:
        """Generate ALL defensive rules for a CWE."""
        generators = [
            self._waf, self._firewall, self._ids,
            self._sigma, self._code, self._config,
        ]

        all_rules: List[DefensiveRule] = []
        for gen in generators:
            rules = gen.generate(cwe_id, vuln_id, context)
            all_rules.extend(rules)

        with self._lock:
            self._generated_rules.extend(all_rules)

        return all_rules

    def generate_for_scan(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Generate defensive rules for all vulnerabilities from a scan.

        Args:
            vulnerabilities: List of {"vuln_id": ..., "cwe_id": ..., "context": ...}
        Returns:
            Dict mapping vuln_id to list of rule dicts
        """
        result: Dict[str, List[Dict[str, Any]]] = {}

        for vuln in vulnerabilities:
            vuln_id = vuln.get("vuln_id", "")
            cwe_id = vuln.get("cwe_id", "")
            context = vuln.get("context", {})

            if cwe_id:
                rules = self.generate_all(cwe_id, vuln_id, context)
                if rules:
                    result[vuln_id] = [r.to_dict() for r in rules]

        return result

    def get_rules_by_format(self, fmt: RuleFormat) -> List[DefensiveRule]:
        """Get all generated rules of a specific format."""
        with self._lock:
            return [r for r in self._generated_rules if r.rule_format == fmt]

    def export_modsecurity(self) -> str:
        """Export all WAF rules as a single ModSecurity config file."""
        rules = self.get_rules_by_format(RuleFormat.MODSECURITY)
        lines = [
            "# ═══════════════════════════════════════════════",
            "# SIREN AUTO-GENERATED WAF RULES",
            f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"# Total rules: {len(rules)}",
            "# ═══════════════════════════════════════════════",
            "",
        ]
        for rule in rules:
            lines.append(f"# {rule.title}")
            lines.append(rule.rule_content)
            lines.append("")
        return "\n".join(lines)

    def export_snort(self) -> str:
        """Export all IDS rules as Snort-compatible config."""
        rules = self.get_rules_by_format(RuleFormat.SNORT)
        lines = [
            "# SIREN AUTO-GENERATED SNORT SIGNATURES",
            f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"# Total signatures: {len(rules)}",
            "",
        ]
        for rule in rules:
            lines.append(f"# {rule.title}")
            lines.append(rule.rule_content)
            lines.append("")
        return "\n".join(lines)

    def export_sigma_package(self) -> str:
        """Export all SIGMA rules."""
        rules = self.get_rules_by_format(RuleFormat.SIGMA)
        return "\n---\n".join(r.rule_content for r in rules)

    def get_remediation_report(self) -> Dict[str, Any]:
        """Generate a complete remediation report."""
        with self._lock:
            rules = list(self._generated_rules)

        by_severity: Dict[str, int] = defaultdict(int)
        by_format: Dict[str, int] = defaultdict(int)
        by_cwe: Dict[str, int] = defaultdict(int)

        for rule in rules:
            by_severity[rule.severity.value] += 1
            by_format[rule.rule_format.value] += 1
            if rule.cwe_id:
                by_cwe[rule.cwe_id] += 1

        return {
            "total_rules_generated": len(rules),
            "by_severity": dict(by_severity),
            "by_format": dict(by_format),
            "by_cwe": dict(by_cwe),
            "rules": [r.to_dict() for r in rules],
        }

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "total_rules": len(self._generated_rules),
                "formats": list(set(r.rule_format.value for r in self._generated_rules)),
                "cwes_covered": list(set(r.cwe_id for r in self._generated_rules if r.cwe_id)),
            }

    def save_state(self, path: Union[str, Path]) -> None:
        """Save generated rules to file."""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        report = self.get_remediation_report()
        p.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False)
        logger.info("SirenDefensiveMirror shutdown")
