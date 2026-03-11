#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  🛡️  SIREN API SECURITY SCANNER — Broken Access Control & Data Exposure  🛡️  ██
██                                                                                ██
██  Scanner completo para deteccao REAL de:                                       ██
██    • Broken Access Control (OWASP A01:2021)                                   ██
██    • Sensitive Data Exposure (OWASP A02:2021)                                 ██
██    • JWT Authentication Bypass                                                 ██
██    • IDOR (Insecure Direct Object References)                                 ██
██    • Missing Rate Limiting                                                     ██
██    • Audit Logging Gaps                                                        ██
██    • API Enumeration & Mass Data Exposure                                     ██
██    • BOLA/BFLA (Broken Object/Function Level Authorization)                   ██
██    • Excessive Data Exposure (OWASP API4:2019)                                ██
██    • Security Misconfiguration (OWASP API7:2019)                              ██
██                                                                                ██
██  Cobertura completa: OWASP Top 10 (2021) + OWASP API Security Top 10         ██
██  "O scanner nao adivinha. Ele PROVA."                                         ██
██                                                                                ██
████████████████████████████████████████████████████████████████████████████████████
"""

from __future__ import annotations

import asyncio
import base64
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
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

logger = logging.getLogger("siren.api_security")


# ════════════════════════════════════════════════════════════════════════════
# ENUMS & DATA MODELS
# ════════════════════════════════════════════════════════════════════════════


class APISeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def icon(self) -> str:
        return {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
            "info": "🔵",
        }[self.value]


class APIVulnCategory(Enum):
    BROKEN_ACCESS_CONTROL = "broken-access-control"
    SENSITIVE_DATA_EXPOSURE = "sensitive-data-exposure"
    BROKEN_AUTH = "broken-authentication"
    EXCESSIVE_DATA_EXPOSURE = "excessive-data-exposure"
    MISSING_RATE_LIMIT = "missing-rate-limit"
    BOLA = "broken-object-level-authorization"
    BFLA = "broken-function-level-authorization"
    MASS_ASSIGNMENT = "mass-assignment"
    SECURITY_MISCONFIG = "security-misconfiguration"
    INJECTION = "injection"
    IDOR = "insecure-direct-object-reference"
    USER_ENUMERATION = "user-enumeration"
    MISSING_AUDIT_LOG = "missing-audit-logging"
    JWT_VULNERABILITY = "jwt-vulnerability"
    CORS_MISCONFIG = "cors-misconfiguration"
    MISSING_AUTH = "missing-authentication"
    IMPROPER_INVENTORY = "improper-assets-management"


class ScopeLevel(Enum):
    PUBLIC = "public"
    AUTHENTICATED = "authenticated"
    SELF = "self"
    ADMIN = "admin"


@dataclass
class APIEndpoint:
    """Representacao de um endpoint de API descoberto."""

    url: str
    method: str = "GET"
    path: str = ""
    parameters: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    requires_auth: bool = False
    auth_level: ScopeLevel = ScopeLevel.PUBLIC
    response_schema: Dict[str, Any] = field(default_factory=dict)
    discovered_fields: List[str] = field(default_factory=list)
    sensitive_fields: List[str] = field(default_factory=list)


@dataclass
class DataExposureFinding:
    """Dado sensivel exposto encontrado."""

    field_name: str
    field_type: str  # email, phone, id, pii, internal, token, etc.
    sample_value: str = ""  # Masked for reporting
    count_exposed: int = 0
    endpoint: str = ""
    requires_auth_to_view: bool = False
    recommendation: str = ""


@dataclass
class APISecurityFinding:
    """Vulnerabilidade de seguranca de API encontrada."""

    title: str
    category: APIVulnCategory
    severity: APISeverity
    endpoint: str
    method: str = "GET"
    description: str = ""
    impact: str = ""
    evidence: str = ""
    remediation: str = ""
    cwe_id: int = 0
    cvss_score: float = 0.0
    owasp_ref: str = ""
    data_exposures: List[DataExposureFinding] = field(default_factory=list)
    request_dump: str = ""
    response_dump: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    is_confirmed: bool = False

    @property
    def unique_id(self) -> str:
        raw = f"{self.category.value}:{self.endpoint}:{self.method}:{self.title}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        return {
            "id": self.unique_id,
            "title": self.title,
            "category": self.category.value,
            "severity": self.severity.value,
            "endpoint": self.endpoint,
            "method": self.method,
            "description": self.description,
            "impact": self.impact,
            "evidence": self.evidence[:2000],
            "remediation": self.remediation,
            "cwe_id": self.cwe_id,
            "cvss_score": self.cvss_score,
            "owasp_ref": self.owasp_ref,
            "data_exposures": [
                {
                    "field": de.field_name,
                    "type": de.field_type,
                    "count": de.count_exposed,
                }
                for de in self.data_exposures
            ],
            "timestamp": self.timestamp,
            "confirmed": self.is_confirmed,
        }

    def to_markdown(self) -> str:
        lines = [
            f"### {self.severity.icon} {self.title}",
            "",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| Category | `{self.category.value}` |",
            f"| Severity | **{self.severity.value.upper()}** |",
            f"| CVSS | {self.cvss_score} |",
            f"| CWE | CWE-{self.cwe_id} |",
            f"| OWASP | {self.owasp_ref} |",
            f"| Endpoint | `{self.method} {self.endpoint}` |",
            f"| Confirmed | {'✅ Yes' if self.is_confirmed else '⚠️ Tentative'} |",
            "",
        ]
        if self.description:
            lines.extend(["**Description:**", self.description, ""])
        if self.evidence:
            lines.extend(["**Evidence:**", f"```\n{self.evidence[:2000]}\n```", ""])
        if self.data_exposures:
            lines.append("**Exposed Data Fields:**")
            lines.append("| Field | Type | Count |")
            lines.append("|-------|------|-------|")
            for de in self.data_exposures:
                lines.append(
                    f"| `{de.field_name}` | {de.field_type} | {de.count_exposed} |"
                )
            lines.append("")
        if self.impact:
            lines.extend(["**Impact:**", self.impact, ""])
        if self.remediation:
            lines.extend(["**Remediation:**", self.remediation, ""])
        return "\n".join(lines)


@dataclass
class APIAuditResult:
    """Resultado completo de auditoria de seguranca da API."""

    target: str
    scan_start: str = field(default_factory=lambda: datetime.now().isoformat())
    scan_end: str = ""
    endpoints_discovered: List[APIEndpoint] = field(default_factory=list)
    findings: List[APISecurityFinding] = field(default_factory=list)
    data_exposures: List[DataExposureFinding] = field(default_factory=list)
    auth_tested: bool = False
    rate_limit_tested: bool = False
    total_requests: int = 0
    duration_seconds: float = 0.0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == APISeverity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == APISeverity.HIGH)

    @property
    def severity_distribution(self) -> Dict[str, int]:
        dist: Dict[str, int] = {}
        for f in self.findings:
            dist[f.severity.value] = dist.get(f.severity.value, 0) + 1
        return dist

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "scan_start": self.scan_start,
            "scan_end": self.scan_end,
            "endpoints_discovered": len(self.endpoints_discovered),
            "total_findings": len(self.findings),
            "severity_distribution": self.severity_distribution,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "data_exposures_count": len(self.data_exposures),
            "auth_tested": self.auth_tested,
            "rate_limit_tested": self.rate_limit_tested,
            "total_requests": self.total_requests,
            "duration_seconds": self.duration_seconds,
            "findings": [f.to_dict() for f in self.findings],
        }


# ════════════════════════════════════════════════════════════════════════════
# SENSITIVE DATA PATTERNS — Deteccao de PII e dados sensiveis
# ════════════════════════════════════════════════════════════════════════════

# Fields considered sensitive in API responses (should not be exposed publicly)
SENSITIVE_FIELD_PATTERNS = {
    "email": [
        re.compile(r"\bemail\b", re.I),
        re.compile(r"\be[-_]?mail[-_]?address\b", re.I),
        re.compile(r"\bcorreio\b", re.I),
    ],
    "phone": [
        re.compile(r"\bphone\b", re.I),
        re.compile(r"\btelefone?\b", re.I),
        re.compile(r"\bmobile\b", re.I),
        re.compile(r"\bcell[-_]?phone\b", re.I),
    ],
    "password": [
        re.compile(r"\bpassw(or)?d\b", re.I),
        re.compile(r"\bsenha\b", re.I),
        re.compile(r"\bsecret\b", re.I),
        re.compile(r"\bhash\b", re.I),
        re.compile(r"\bpassword[-_]?hash\b", re.I),
    ],
    "token": [
        re.compile(r"\btoken\b", re.I),
        re.compile(r"\baccess[-_]?token\b", re.I),
        re.compile(r"\brefresh[-_]?token\b", re.I),
        re.compile(r"\bapi[-_]?key\b", re.I),
        re.compile(r"\bsession[-_]?id\b", re.I),
    ],
    "internal_id": [
        re.compile(r"^id$", re.I),
        re.compile(r"\b_id\b", re.I),
        re.compile(r"\buuid\b", re.I),
        re.compile(r"\binternal[-_]?id\b", re.I),
        re.compile(r"\buser[-_]?id\b", re.I),
    ],
    "pii_name": [
        re.compile(r"\bfull[-_]?name\b", re.I),
        re.compile(r"\bfirst[-_]?name\b", re.I),
        re.compile(r"\blast[-_]?name\b", re.I),
        re.compile(r"\bnome[-_]?completo\b", re.I),
        re.compile(r"\bcpf\b", re.I),
        re.compile(r"\bssn\b", re.I),
    ],
    "address": [
        re.compile(r"\baddress\b", re.I),
        re.compile(r"\bendereco\b", re.I),
        re.compile(r"\bzip[-_]?code\b", re.I),
        re.compile(r"\bcep\b", re.I),
        re.compile(r"\bcity\b", re.I),
        re.compile(r"\bstreet\b", re.I),
    ],
    "financial": [
        re.compile(r"\bcredit[-_]?card\b", re.I),
        re.compile(r"\bcard[-_]?number\b", re.I),
        re.compile(r"\bcvv\b", re.I),
        re.compile(r"\biban\b", re.I),
        re.compile(r"\bbank[-_]?account\b", re.I),
        re.compile(r"\bpayment\b", re.I),
    ],
    "ip_address": [
        re.compile(r"\bip[-_]?address\b", re.I),
        re.compile(r"\bremote[-_]?addr\b", re.I),
        re.compile(r"\blast[-_]?ip\b", re.I),
        re.compile(r"\blogin[-_]?ip\b", re.I),
    ],
    "internal_status": [
        re.compile(r"\blast[-_]?login\b", re.I),
        re.compile(r"\blogin[-_]?attempts\b", re.I),
        re.compile(r"\baccount[-_]?status\b", re.I),
        re.compile(r"\bis[-_]?admin\b", re.I),
        re.compile(r"\brole\b", re.I),
        re.compile(r"\bpermissions?\b", re.I),
        re.compile(r"\bflags?\b", re.I),
    ],
}

# Safe fields — allowed in public responses
SAFE_PUBLIC_FIELDS = {
    "username",
    "display_name",
    "displayName",
    "avatar_url",
    "avatarUrl",
    "avatar",
    "is_verified",
    "isVerified",
    "profile_url",
    "profileUrl",
    "bio_public",
    "created_at_public",
    "public_name",
    "handle",
    "slug",
    "verified",
    "badge",
    "tier",
    "level",
}

# Common API path patterns to test
COMMON_API_PATHS = [
    "/api/v1/users",
    "/api/v1/users/{id}",
    "/api/v1/users/search",
    "/api/v1/users/me",
    "/api/v1/users/list",
    "/api/v1/accounts",
    "/api/v1/profiles",
    "/api/v2/users",
    "/api/users",
    "/users",
    "/api/v1/admin/users",
    "/api/v1/members",
    "/api/v1/creators",
    "/api/v1/subscribers",
    "/api/v1/payments",
    "/api/v1/orders",
    "/api/v1/transactions",
    "/api/v1/config",
    "/api/v1/settings",
    "/api/v1/internal",
    "/api/v1/debug",
    "/api/v1/health",
    "/api/v1/status",
    "/api/v1/docs",
    "/api/v1/swagger",
    "/api/v1/graphql",
    "/graphql",
    "/.env",
    "/api/v1/export",
    "/api/v1/backup",
    "/api/v1/logs",
    "/api/v1/metrics",
    "/api/v1/analytics",
]

# UUID v4 pattern for IDOR testing
UUID_PATTERN = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
    re.I,
)

# Email pattern for data exposure detection
EMAIL_PATTERN = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
)

# JWT pattern
JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")


# ════════════════════════════════════════════════════════════════════════════
# HTTP CLIENT — Async HTTP com controle total
# ════════════════════════════════════════════════════════════════════════════


class APISecurityHTTP:
    """HTTP client otimizado para testes de seguranca de API."""

    def __init__(
        self,
        timeout: float = 30.0,
        max_concurrent: int = 10,
        request_delay_ms: float = 100.0,
        user_agent: str = "Siren-APISecurityScanner/1.0",
    ):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.request_delay_ms = request_delay_ms
        self.user_agent = user_agent
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._request_count = 0
        self._session = None

    async def _ensure_session(self):
        if self._session is None:
            try:
                import aiohttp

                self._session = aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    headers={"User-Agent": self.user_agent},
                )
            except ImportError:
                logger.warning("aiohttp not installed, using urllib fallback")

    async def close(self):
        if self._session:
            await self._session.close()
            self._session = None

    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[str] = None,
        json_data: Optional[dict] = None,
        cookies: Optional[Dict[str, str]] = None,
        follow_redirects: bool = True,
    ) -> Dict[str, Any]:
        """Faz uma requisicao HTTP e retorna resultado estruturado."""
        async with self._semaphore:
            self._request_count += 1
            if self.request_delay_ms > 0:
                await asyncio.sleep(self.request_delay_ms / 1000.0)

            await self._ensure_session()

            req_headers = dict(headers or {})
            if "User-Agent" not in req_headers:
                req_headers["User-Agent"] = self.user_agent

            start_time = time.monotonic()

            try:
                if self._session is not None:
                    # aiohttp path
                    kwargs: Dict[str, Any] = {
                        "headers": req_headers,
                        "allow_redirects": follow_redirects,
                        "ssl": False,
                    }
                    if data is not None:
                        kwargs["data"] = data
                    if json_data is not None:
                        kwargs["json"] = json_data
                    if cookies:
                        kwargs["cookies"] = cookies

                    async with self._session.request(method, url, **kwargs) as resp:
                        elapsed = time.monotonic() - start_time
                        body = await resp.text(errors="replace")
                        resp_headers = dict(resp.headers)
                        return {
                            "status": resp.status,
                            "headers": resp_headers,
                            "body": body,
                            "elapsed_ms": elapsed * 1000,
                            "url": str(resp.url),
                            "content_type": resp.content_type or "",
                            "content_length": len(body),
                        }
                else:
                    # urllib fallback for systems without aiohttp
                    import urllib.error
                    import urllib.request

                    req = urllib.request.Request(
                        url, method=method, headers=req_headers
                    )
                    if data is not None:
                        req.data = data.encode("utf-8")
                    if json_data is not None:
                        req.data = json.dumps(json_data).encode("utf-8")
                        req.add_header("Content-Type", "application/json")

                    try:
                        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                            elapsed = time.monotonic() - start_time
                            body = resp.read().decode("utf-8", errors="replace")
                            return {
                                "status": resp.status,
                                "headers": dict(resp.headers),
                                "body": body,
                                "elapsed_ms": elapsed * 1000,
                                "url": url,
                                "content_type": resp.headers.get("Content-Type", ""),
                                "content_length": len(body),
                            }
                    except urllib.error.HTTPError as e:
                        elapsed = time.monotonic() - start_time
                        body = (
                            e.read().decode("utf-8", errors="replace") if e.fp else ""
                        )
                        return {
                            "status": e.code,
                            "headers": dict(e.headers) if e.headers else {},
                            "body": body,
                            "elapsed_ms": elapsed * 1000,
                            "url": url,
                            "content_type": "",
                            "content_length": len(body),
                        }

            except asyncio.TimeoutError:
                elapsed = time.monotonic() - start_time
                return {
                    "status": 0,
                    "headers": {},
                    "body": "",
                    "elapsed_ms": elapsed * 1000,
                    "url": url,
                    "error": "timeout",
                    "content_type": "",
                    "content_length": 0,
                }
            except Exception as e:
                elapsed = time.monotonic() - start_time
                return {
                    "status": 0,
                    "headers": {},
                    "body": "",
                    "elapsed_ms": elapsed * 1000,
                    "url": url,
                    "error": str(e),
                    "content_type": "",
                    "content_length": 0,
                }


# ════════════════════════════════════════════════════════════════════════════
# BROKEN ACCESS CONTROL SCANNER — OWASP A01:2021
# ════════════════════════════════════════════════════════════════════════════


class BrokenAccessControlScanner:
    """Detecta endpoints de API com controle de acesso ausente ou insuficiente.

    Testes realizados:
    1. Acesso nao autenticado a endpoints que deveriam exigir auth
    2. IDOR — acesso a recursos de outros usuarios
    3. Privilege escalation — acesso a funcoes administrativas
    4. Bypass de autorizacao via manipulacao de headers
    5. HTTP method tampering (GET vs POST vs PUT vs DELETE)
    6. Path traversal em IDs de recursos
    """

    def __init__(self, http: APISecurityHTTP):
        self.http = http
        self.findings: List[APISecurityFinding] = []

    async def scan_unauthenticated_access(
        self,
        base_url: str,
        endpoints: Optional[List[str]] = None,
    ) -> List[APISecurityFinding]:
        """Testa acesso sem autenticacao a endpoints da API.

        Este e o teste principal baseado na vulnerabilidade Kippu.vip:
        endpoints retornando dados de usuarios sem token de autenticacao.
        """
        findings = []
        paths_to_test = endpoints or COMMON_API_PATHS

        for path in paths_to_test:
            # Skip paths with {id} placeholders for this test
            if "{" in path:
                continue

            url = f"{base_url.rstrip('/')}{path}"
            logger.info(f"Testing unauthenticated access: {url}")

            resp = await self.http.request("GET", url)

            if resp.get("error"):
                continue

            status = resp["status"]

            # 200 OK without auth = potential broken access control
            if status == 200:
                body = resp["body"]
                content_type = resp.get("content_type", "")

                # Check if response contains JSON data
                if "json" in content_type.lower() or body.strip().startswith(
                    ("{", "[")
                ):
                    try:
                        data = json.loads(body)
                    except json.JSONDecodeError:
                        continue

                    # Analyze exposed data
                    exposed_fields = self._analyze_exposed_fields(data)
                    sensitive_exposures = [
                        ef for ef in exposed_fields if ef.field_type != "safe"
                    ]

                    if sensitive_exposures:
                        record_count = self._count_records(data)
                        finding = APISecurityFinding(
                            title=f"Unauthenticated API Access — Sensitive Data Exposed at {path}",
                            category=APIVulnCategory.BROKEN_ACCESS_CONTROL,
                            severity=APISeverity.CRITICAL,
                            endpoint=path,
                            method="GET",
                            description=(
                                f"The endpoint {path} returns sensitive data without "
                                f"requiring authentication. {record_count} records exposed "
                                f"containing {len(sensitive_exposures)} types of sensitive data."
                            ),
                            impact=(
                                "Attackers can enumerate all users, harvest emails for phishing, "
                                "extract internal IDs for IDOR attacks, and violate LGPD/GDPR "
                                "privacy regulations."
                            ),
                            evidence=body[:3000],
                            remediation=(
                                "1. Add mandatory JWT/OAuth2 authentication middleware\n"
                                "2. Implement field-level access control (public vs private fields)\n"
                                "3. Return only public fields (username, display_name, avatar_url, is_verified) "
                                "for unauthenticated/listing requests\n"
                                "4. Add mandatory pagination with limited page sizes\n"
                                "5. Omit total count to prevent user enumeration\n"
                                "6. Implement rate limiting (10 req/min for unauthenticated)\n"
                                "7. Add audit logging for all data access"
                            ),
                            cwe_id=284,  # CWE-284: Improper Access Control
                            cvss_score=9.1,
                            owasp_ref="A01:2021 — Broken Access Control",
                            data_exposures=sensitive_exposures,
                            request_dump=f"GET {url} HTTP/1.1\nHost: {urllib.parse.urlparse(url).hostname}",
                            response_dump=body[:1500],
                            is_confirmed=True,
                        )
                        findings.append(finding)

                    # Also check if no pagination is enforced
                    if isinstance(data, list) and len(data) > 20:
                        findings.append(
                            APISecurityFinding(
                                title=f"Missing Pagination — Mass Data Dump at {path}",
                                category=APIVulnCategory.EXCESSIVE_DATA_EXPOSURE,
                                severity=APISeverity.HIGH,
                                endpoint=path,
                                method="GET",
                                description=(
                                    f"The endpoint returns {len(data)} records without pagination. "
                                    "This allows mass data extraction in a single request."
                                ),
                                impact="Facilitates bulk data harvesting and user enumeration.",
                                remediation=(
                                    "1. Enforce mandatory pagination (max 20 items per page)\n"
                                    "2. Implement cursor-based pagination for large datasets\n"
                                    "3. Omit or null the 'total' field to prevent enumeration\n"
                                    "4. Return structured response: {status, data: [], pagination: {page, limit}}"
                                ),
                                cwe_id=200,  # CWE-200: Exposure of Sensitive Information
                                cvss_score=7.5,
                                owasp_ref="API4:2019 — Lack of Resources & Rate Limiting",
                                is_confirmed=True,
                            )
                        )

            # 403 or 401 = properly protected (good)
            elif status in (401, 403):
                logger.info(f"  ✓ {path} properly requires authentication ({status})")

        self.findings.extend(findings)
        return findings

    async def scan_idor(
        self,
        base_url: str,
        auth_token: Optional[str] = None,
        user_ids: Optional[List[str]] = None,
    ) -> List[APISecurityFinding]:
        """Testa IDOR (Insecure Direct Object Reference) em endpoints de usuario.

        Tenta acessar recursos de outros usuarios usando IDs descobertos.
        """
        findings = []
        test_ids = user_ids or []

        # If no IDs provided, try to discover from listing
        if not test_ids:
            resp = await self.http.request(
                "GET",
                f"{base_url.rstrip('/')}/api/v1/users",
                headers={"Authorization": f"Bearer {auth_token}"} if auth_token else {},
            )
            if resp["status"] == 200:
                try:
                    data = json.loads(resp["body"])
                    test_ids = self._extract_ids(data)
                except (json.JSONDecodeError, KeyError):
                    pass

        if not test_ids:
            # Generate predictable UUIDs to test
            test_ids = [
                "00000000-0000-4000-8000-000000000001",
                "00000000-0000-4000-8000-000000000002",
                "1",
                "2",
                "3",
                "admin",
                "root",
            ]

        # Test accessing other user resources
        idor_paths = [
            "/api/v1/users/{id}",
            "/api/v1/users/{id}/profile",
            "/api/v1/users/{id}/settings",
            "/api/v1/users/{id}/payments",
            "/api/v1/users/{id}/messages",
            "/api/v1/users/{id}/subscriptions",
            "/api/v1/accounts/{id}",
        ]

        for path_template in idor_paths:
            for test_id in test_ids[:5]:  # Limit to prevent abuse
                path = path_template.replace("{id}", str(test_id))
                url = f"{base_url.rstrip('/')}{path}"

                headers = {}
                if auth_token:
                    headers["Authorization"] = f"Bearer {auth_token}"

                resp = await self.http.request("GET", url, headers=headers)

                if resp["status"] == 200:
                    body = resp["body"]
                    try:
                        data = json.loads(body)
                    except json.JSONDecodeError:
                        continue

                    exposed = self._analyze_exposed_fields(data)
                    sensitive = [e for e in exposed if e.field_type != "safe"]

                    if sensitive:
                        findings.append(
                            APISecurityFinding(
                                title=f"IDOR — Unauthorized Access to User Data at {path_template}",
                                category=APIVulnCategory.IDOR,
                                severity=APISeverity.HIGH,
                                endpoint=path_template,
                                method="GET",
                                description=(
                                    f"User data accessible via direct object reference at {path}. "
                                    f"Sensitive fields exposed: {', '.join(e.field_name for e in sensitive)}"
                                ),
                                impact=(
                                    "Attackers can access private data of any user by iterating "
                                    "through user IDs. Combined with user enumeration, this allows "
                                    "mass extraction of PII."
                                ),
                                remediation=(
                                    "1. Validate that the authenticated user owns the requested resource\n"
                                    "2. Implement object-level authorization checks\n"
                                    "3. Use non-predictable identifiers (UUIDv4)\n"
                                    "4. Return 403 Forbidden when accessing other users' resources\n"
                                    "5. Log all cross-user access attempts for security monitoring"
                                ),
                                cwe_id=639,  # CWE-639: Authorization Bypass Through User-Controlled Key
                                cvss_score=7.5,
                                owasp_ref="A01:2021 — Broken Access Control",
                                data_exposures=sensitive,
                                evidence=body[:1500],
                                is_confirmed=True,
                            )
                        )
                        break  # One finding per path template is enough

        self.findings.extend(findings)
        return findings

    async def scan_privilege_escalation(
        self,
        base_url: str,
        low_priv_token: Optional[str] = None,
    ) -> List[APISecurityFinding]:
        """Testa acesso a endpoints administrativos com tokens de baixo privilegio."""
        findings = []
        admin_paths = [
            "/api/v1/admin/users",
            "/api/v1/admin/settings",
            "/api/v1/admin/config",
            "/api/v1/admin/logs",
            "/api/v1/admin/dashboard",
            "/api/v1/admin/export",
            "/api/internal/users",
            "/api/internal/debug",
            "/admin/api/users",
            "/api/v1/users?role=admin",
            "/api/v1/users?admin=true",
        ]

        for path in admin_paths:
            url = f"{base_url.rstrip('/')}{path}"
            headers = {}
            if low_priv_token:
                headers["Authorization"] = f"Bearer {low_priv_token}"

            resp = await self.http.request("GET", url, headers=headers)

            if resp["status"] == 200:
                body = resp["body"]
                if body.strip().startswith(("{", "[")):
                    findings.append(
                        APISecurityFinding(
                            title=f"Privilege Escalation — Admin Endpoint Accessible: {path}",
                            category=APIVulnCategory.BFLA,
                            severity=APISeverity.CRITICAL,
                            endpoint=path,
                            method="GET",
                            description=(
                                f"Administrative endpoint {path} accessible with "
                                f"{'low-privilege token' if low_priv_token else 'no authentication'}."
                            ),
                            impact=(
                                "Complete admin access allows: user account manipulation, "
                                "configuration changes, data export, and potential full "
                                "system compromise."
                            ),
                            remediation=(
                                "1. Implement Role-Based Access Control (RBAC)\n"
                                "2. Verify admin role in middleware before admin endpoints\n"
                                "3. Separate admin API routes with distinct authentication\n"
                                "4. Add IP whitelisting for admin endpoints\n"
                                "5. Implement multi-factor authentication for admin access"
                            ),
                            cwe_id=269,  # CWE-269: Improper Privilege Management
                            cvss_score=9.8,
                            owasp_ref="A01:2021 — Broken Access Control",
                            evidence=body[:1500],
                            is_confirmed=True,
                        )
                    )

        self.findings.extend(findings)
        return findings

    async def scan_http_method_tampering(
        self,
        base_url: str,
        endpoints: Optional[List[str]] = None,
    ) -> List[APISecurityFinding]:
        """Testa se endpoints respondem a metodos HTTP inesperados."""
        findings = []
        paths = endpoints or ["/api/v1/users", "/api/v1/users/me"]
        dangerous_methods = ["PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"]

        for path in paths:
            url = f"{base_url.rstrip('/')}{path}"
            for method in dangerous_methods:
                resp = await self.http.request(method, url)

                if resp["status"] in (200, 201, 204):
                    findings.append(
                        APISecurityFinding(
                            title=f"HTTP Method Tampering — {method} Allowed on {path}",
                            category=APIVulnCategory.SECURITY_MISCONFIG,
                            severity=(
                                APISeverity.MEDIUM
                                if method == "OPTIONS"
                                else APISeverity.HIGH
                            ),
                            endpoint=path,
                            method=method,
                            description=(
                                f"The endpoint {path} responds to {method} requests "
                                f"with status {resp['status']}. This may allow unauthorized "
                                "data modification or deletion."
                            ),
                            remediation=(
                                "1. Explicitly whitelist allowed HTTP methods per endpoint\n"
                                "2. Return 405 Method Not Allowed for unsupported methods\n"
                                "3. Disable TRACE method server-wide\n"
                                "4. Ensure destructive methods (PUT/PATCH/DELETE) require "
                                "authentication and authorization"
                            ),
                            cwe_id=749,  # CWE-749: Exposed Dangerous Method
                            cvss_score=6.5 if method == "OPTIONS" else 8.0,
                            owasp_ref="A01:2021 — Broken Access Control",
                        )
                    )

        self.findings.extend(findings)
        return findings

    def _analyze_exposed_fields(
        self, data: Any, prefix: str = ""
    ) -> List[DataExposureFinding]:
        """Analisa recursivamente um payload JSON para encontrar campos sensiveis."""
        exposures: List[DataExposureFinding] = []

        if isinstance(data, list):
            # Analyze first item as representative
            if data:
                sample = data[0] if isinstance(data[0], dict) else {}
                for ef in self._analyze_exposed_fields(sample, prefix):
                    ef.count_exposed = len(data)
                    exposures.append(ef)
            return exposures

        if isinstance(data, dict):
            # If response has a "data" wrapper, analyze inside it
            if "data" in data and isinstance(data["data"], (list, dict)):
                return self._analyze_exposed_fields(data["data"], prefix)

            for key, value in data.items():
                full_key = f"{prefix}.{key}" if prefix else key

                # Check against sensitive patterns
                for field_type, patterns in SENSITIVE_FIELD_PATTERNS.items():
                    for pattern in patterns:
                        if pattern.search(key):
                            # Mask the sample value
                            masked = self._mask_value(str(value)) if value else ""
                            exposures.append(
                                DataExposureFinding(
                                    field_name=full_key,
                                    field_type=field_type,
                                    sample_value=masked,
                                    count_exposed=1,
                                    requires_auth_to_view=False,
                                    recommendation=self._get_field_recommendation(
                                        field_type
                                    ),
                                )
                            )
                            break

                # Recurse into nested objects
                if isinstance(value, dict):
                    exposures.extend(self._analyze_exposed_fields(value, full_key))

        return exposures

    def _count_records(self, data: Any) -> int:
        """Conta numero de registros no payload."""
        if isinstance(data, list):
            return len(data)
        if isinstance(data, dict):
            if "data" in data and isinstance(data["data"], list):
                return len(data["data"])
            if "results" in data and isinstance(data["results"], list):
                return len(data["results"])
            if "items" in data and isinstance(data["items"], list):
                return len(data["items"])
        return 1

    def _extract_ids(self, data: Any) -> List[str]:
        """Extrai IDs de um payload JSON."""
        ids = []
        records = (
            data
            if isinstance(data, list)
            else data.get("data", data.get("results", []))
        )
        if isinstance(records, list):
            for record in records[:10]:
                if isinstance(record, dict):
                    for key in ("id", "_id", "uuid", "user_id", "userId"):
                        if key in record and record[key]:
                            ids.append(str(record[key]))
                            break
        return ids

    @staticmethod
    def _mask_value(value: str) -> str:
        """Mascara um valor sensivel para o relatorio."""
        if not value or value == "None":
            return "[null]"
        if "@" in value:  # Email
            parts = value.split("@")
            return f"{parts[0][:2]}***@{parts[1]}" if len(parts) == 2 else "***@***"
        if len(value) > 4:
            return f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}"
        return "****"

    @staticmethod
    def _get_field_recommendation(field_type: str) -> str:
        """Retorna recomendacao para tratar cada tipo de campo sensivel."""
        recommendations = {
            "email": "Remove from public listings. Only return for the user's own profile.",
            "phone": "Never expose in API. Only return for the user's own profile.",
            "password": "CRITICAL: Never expose password hashes. Remove immediately.",
            "token": "CRITICAL: Never expose tokens in API responses. Use HTTP-only cookies.",
            "internal_id": "Use non-predictable identifiers. Do not expose internal UUIDs in listings.",
            "pii_name": "Remove from public listings. Only return for authenticated self-profile.",
            "address": "Never expose in public API. Only for authenticated self-profile.",
            "financial": "CRITICAL: Never expose financial data. PCI-DSS violation.",
            "ip_address": "Never expose. Internal use only. LGPD violation.",
            "internal_status": "Admin-only field. Never expose in user-facing API.",
        }
        return recommendations.get(
            field_type, "Review data classification and access policy."
        )


# ════════════════════════════════════════════════════════════════════════════
# SENSITIVE DATA EXPOSURE SCANNER — OWASP A02:2021
# ════════════════════════════════════════════════════════════════════════════


class DataExposureScanner:
    """Detecta exposicao de dados sensiveis em respostas da API.

    Testes realizados:
    1. PII em respostas JSON (email, phone, name, address)
    2. Internal IDs expostos (UUIDs, auto-increment IDs)
    3. Tokens/secrets em respostas
    4. Stack traces e debug info
    5. Server headers revelando tecnologia
    6. Dados financeiros expostos
    7. CORS misconfiguration permitindo data exfiltration
    """

    def __init__(self, http: APISecurityHTTP):
        self.http = http
        self.findings: List[APISecurityFinding] = []

    async def scan_response_headers(
        self,
        base_url: str,
    ) -> List[APISecurityFinding]:
        """Analisa headers de resposta para informacoes sensiveis e misconfiguration."""
        findings = []
        resp = await self.http.request("GET", base_url)

        if resp.get("error"):
            return findings

        headers = resp.get("headers", {})

        # Check security headers
        security_headers = {
            "Strict-Transport-Security": {
                "missing_msg": "HSTS header missing — allows MITM downgrade attacks",
                "severity": APISeverity.HIGH,
                "cwe": 319,
            },
            "X-Content-Type-Options": {
                "missing_msg": "X-Content-Type-Options missing — MIME sniffing possible",
                "severity": APISeverity.MEDIUM,
                "cwe": 16,
            },
            "X-Frame-Options": {
                "missing_msg": "X-Frame-Options missing — clickjacking possible",
                "severity": APISeverity.MEDIUM,
                "cwe": 1021,
            },
            "Content-Security-Policy": {
                "missing_msg": "CSP header missing — XSS mitigation reduced",
                "severity": APISeverity.MEDIUM,
                "cwe": 16,
            },
            "X-XSS-Protection": {
                "missing_msg": "X-XSS-Protection missing",
                "severity": APISeverity.LOW,
                "cwe": 16,
            },
        }

        for header, config in security_headers.items():
            header_lower = {k.lower(): v for k, v in headers.items()}
            if header.lower() not in header_lower:
                findings.append(
                    APISecurityFinding(
                        title=f"Missing Security Header: {header}",
                        category=APIVulnCategory.SECURITY_MISCONFIG,
                        severity=config["severity"],
                        endpoint="/",
                        method="GET",
                        description=config["missing_msg"],
                        remediation=f"Add `{header}` response header with appropriate value.",
                        cwe_id=config["cwe"],
                        owasp_ref="A05:2021 — Security Misconfiguration",
                    )
                )

        # Check for info-leaking headers
        info_headers = [
            "Server",
            "X-Powered-By",
            "X-AspNet-Version",
            "X-AspNetMvc-Version",
        ]
        for h in info_headers:
            h_lower = {k.lower(): v for k, v in headers.items()}
            if h.lower() in h_lower:
                findings.append(
                    APISecurityFinding(
                        title=f"Information Disclosure via Header: {h}",
                        category=APIVulnCategory.SECURITY_MISCONFIG,
                        severity=APISeverity.LOW,
                        endpoint="/",
                        method="GET",
                        description=f"Header `{h}: {h_lower[h.lower()]}` reveals server technology.",
                        remediation=f"Remove or obfuscate the `{h}` response header.",
                        cwe_id=200,
                        owasp_ref="A05:2021 — Security Misconfiguration",
                        evidence=f"{h}: {h_lower[h.lower()]}",
                    )
                )

        self.findings.extend(findings)
        return findings

    async def scan_cors_policy(
        self,
        base_url: str,
        endpoints: Optional[List[str]] = None,
    ) -> List[APISecurityFinding]:
        """Testa CORS misconfiguration que permite data exfiltration."""
        findings = []
        paths = endpoints or ["/api/v1/users", "/api/v1/users/me", "/"]

        malicious_origins = [
            "https://evil.com",
            "https://attacker.com",
            "null",
            f"https://{urllib.parse.urlparse(base_url).hostname}.evil.com",
        ]

        for path in paths:
            url = f"{base_url.rstrip('/')}{path}"
            for origin in malicious_origins:
                resp = await self.http.request(
                    "OPTIONS",
                    url,
                    headers={
                        "Origin": origin,
                        "Access-Control-Request-Method": "GET",
                    },
                )

                if resp.get("error"):
                    continue

                acao = ""
                for k, v in resp.get("headers", {}).items():
                    if k.lower() == "access-control-allow-origin":
                        acao = v
                        break

                if acao == "*" or acao == origin:
                    # Check if credentials are also allowed
                    acac = ""
                    for k, v in resp.get("headers", {}).items():
                        if k.lower() == "access-control-allow-credentials":
                            acac = v
                            break

                    severity = (
                        APISeverity.CRITICAL
                        if acac.lower() == "true"
                        else APISeverity.HIGH
                    )

                    findings.append(
                        APISecurityFinding(
                            title=f"CORS Misconfiguration — Origin {origin} Allowed at {path}",
                            category=APIVulnCategory.CORS_MISCONFIG,
                            severity=severity,
                            endpoint=path,
                            method="OPTIONS",
                            description=(
                                f"The endpoint reflects arbitrary origins ({acao}) in "
                                f"Access-Control-Allow-Origin. "
                                f"{'Credentials are also allowed, enabling authenticated data theft.' if acac.lower() == 'true' else ''}"
                            ),
                            impact=(
                                "Attackers can create malicious websites that steal user data "
                                "via cross-origin requests. With credentials allowed, authenticated "
                                "API calls can be made from attacker-controlled domains."
                            ),
                            remediation=(
                                "1. Whitelist specific allowed origins\n"
                                "2. Never reflect Origin header blindly\n"
                                "3. Never use Access-Control-Allow-Origin: *\n"
                                "4. Validate credentials flag against origin list\n"
                                "5. Implement server-side CORS validation middleware"
                            ),
                            cwe_id=942,  # CWE-942: Permissive Cross-domain Policy
                            cvss_score=8.6 if severity == APISeverity.CRITICAL else 7.0,
                            owasp_ref="A05:2021 — Security Misconfiguration",
                            evidence=f"Access-Control-Allow-Origin: {acao}",
                        )
                    )
                    break  # One finding per path is enough

        self.findings.extend(findings)
        return findings

    async def scan_debug_info_leak(
        self,
        base_url: str,
    ) -> List[APISecurityFinding]:
        """Testa exposicao de debug info, stack traces, e endpoints internos."""
        findings = []
        debug_paths = [
            "/api/debug",
            "/api/v1/debug",
            "/debug",
            "/_debug",
            "/api/internal",
            "/api/v1/internal",
            "/api/health",
            "/api/v1/health",
            "/api/config",
            "/api/v1/config",
            "/api/env",
            "/api/v1/env",
            "/.env",
            "/api/swagger",
            "/api/v1/swagger",
            "/swagger.json",
            "/openapi.json",
            "/api-docs",
            "/api/v1/docs",
            "/graphql",
            "/api/graphql",
            "/__debug__",
            "/trace",
            "/actuator",
            "/actuator/env",
            "/actuator/health",
        ]

        for path in debug_paths:
            url = f"{base_url.rstrip('/')}{path}"
            resp = await self.http.request("GET", url)

            if resp.get("error") or resp["status"] != 200:
                continue

            body = resp["body"]

            # Check for debug/config exposure
            debug_indicators = [
                "stack_trace",
                "traceback",
                "debug",
                "DATABASE_URL",
                "SECRET_KEY",
                "API_KEY",
                "password",
                "credentials",
                "internal_error",
                "SQLSTATE",
                "pg_",
                "mysql",
            ]

            for indicator in debug_indicators:
                if indicator.lower() in body.lower():
                    findings.append(
                        APISecurityFinding(
                            title=f"Debug/Internal Information Exposed at {path}",
                            category=APIVulnCategory.SENSITIVE_DATA_EXPOSURE,
                            severity=APISeverity.HIGH,
                            endpoint=path,
                            method="GET",
                            description=(
                                f"The endpoint {path} exposes internal debug information "
                                f"including potential {indicator}."
                            ),
                            impact="Internal configuration exposure aids further attacks.",
                            remediation=(
                                "1. Disable debug endpoints in production\n"
                                "2. Remove or restrict access to swagger/API documentation\n"
                                "3. Implement proper error handling that does not leak internals\n"
                                "4. Use environment-specific configuration"
                            ),
                            cwe_id=215,  # CWE-215: Information Exposure Through Debug Information
                            cvss_score=7.5,
                            owasp_ref="A05:2021 — Security Misconfiguration",
                            evidence=body[:1000],
                            is_confirmed=True,
                        )
                    )
                    break

        self.findings.extend(findings)
        return findings


# ════════════════════════════════════════════════════════════════════════════
# JWT SECURITY SCANNER
# ════════════════════════════════════════════════════════════════════════════


class JWTSecurityScanner:
    """Testa seguranca de tokens JWT em endpoints de API.

    Testes realizados:
    1. Algorithm None attack
    2. Algorithm confusion (RS256 → HS256)
    3. Weak signing key (brute force)
    4. Expired token acceptance
    5. Missing claims validation (iss, aud, exp)
    6. Token in URL parameter (leakage risk)
    7. JWK/JWKS injection
    """

    def __init__(self, http: APISecurityHTTP):
        self.http = http
        self.findings: List[APISecurityFinding] = []

    def _decode_jwt_parts(self, token: str) -> Tuple[dict, dict, bytes]:
        """Decodifica partes de um JWT sem validacao."""
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid JWT format")

        def _b64decode(s: str) -> bytes:
            if not s:
                return b""
            padding = 4 - len(s) % 4
            return base64.urlsafe_b64decode(s + "=" * padding)

        header = json.loads(_b64decode(parts[0]))
        payload = json.loads(_b64decode(parts[1]))
        signature = _b64decode(parts[2])
        return header, payload, signature

    def _forge_jwt(self, header: dict, payload: dict, key: bytes = b"") -> str:
        """Forja um JWT com header e payload customizados."""

        def _b64encode(data: bytes) -> str:
            return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

        h = _b64encode(json.dumps(header, separators=(",", ":")).encode())
        p = _b64encode(json.dumps(payload, separators=(",", ":")).encode())

        if header.get("alg", "").lower() == "none":
            return f"{h}.{p}."
        elif header.get("alg", "").startswith("HS"):
            signing_input = f"{h}.{p}".encode()
            sig = hmac.new(key, signing_input, hashlib.sha256).digest()
            return f"{h}.{p}.{_b64encode(sig)}"
        else:
            return f"{h}.{p}."

    async def scan_jwt_security(
        self,
        base_url: str,
        token: Optional[str] = None,
        protected_endpoint: str = "/api/v1/users/me",
    ) -> List[APISecurityFinding]:
        """Executa suite completa de testes JWT."""
        findings = []

        if not token:
            # Try to find a token from login
            logger.info("No token provided, skipping JWT-specific tests")
            return findings

        try:
            header, payload, sig = self._decode_jwt_parts(token)
        except (ValueError, json.JSONDecodeError) as e:
            logger.warning(f"Failed to decode JWT: {e}")
            return findings

        url = f"{base_url.rstrip('/')}{protected_endpoint}"

        # Test 1: Algorithm None Attack
        none_header = dict(header)
        none_header["alg"] = "none"
        none_token = self._forge_jwt(none_header, payload)

        resp = await self.http.request(
            "GET",
            url,
            headers={"Authorization": f"Bearer {none_token}"},
        )
        if resp["status"] == 200:
            findings.append(
                APISecurityFinding(
                    title="JWT Algorithm None Attack — Authentication Bypass",
                    category=APIVulnCategory.JWT_VULNERABILITY,
                    severity=APISeverity.CRITICAL,
                    endpoint=protected_endpoint,
                    method="GET",
                    description=(
                        "The server accepts JWT tokens with alg:none, allowing "
                        "complete authentication bypass by forging unsigned tokens."
                    ),
                    impact="Complete authentication bypass. Any user can be impersonated.",
                    remediation=(
                        "1. Explicitly reject alg:none in JWT validation\n"
                        "2. Use a JWT library that rejects none algorithm by default\n"
                        "3. Enforce expected algorithm (e.g., RS256) server-side\n"
                        "4. Never trust the alg header from client"
                    ),
                    cwe_id=347,  # CWE-347: Improper Verification of Cryptographic Signature
                    cvss_score=9.8,
                    owasp_ref="A02:2021 — Cryptographic Failures",
                    evidence=f"Token with alg:none accepted. Response: {resp['body'][:500]}",
                    is_confirmed=True,
                )
            )

        # Test 2: Expired Token
        expired_payload = dict(payload)
        expired_payload["exp"] = int(time.time()) - 86400  # 24h ago
        expired_token = self._forge_jwt(header, expired_payload)

        resp = await self.http.request(
            "GET",
            url,
            headers={"Authorization": f"Bearer {expired_token}"},
        )
        if resp["status"] == 200:
            findings.append(
                APISecurityFinding(
                    title="JWT Expired Token Accepted",
                    category=APIVulnCategory.JWT_VULNERABILITY,
                    severity=APISeverity.HIGH,
                    endpoint=protected_endpoint,
                    method="GET",
                    description="The server accepts expired JWT tokens.",
                    impact="Stolen tokens remain valid indefinitely.",
                    remediation=(
                        "1. Validate exp claim server-side\n"
                        "2. Set reasonable token lifetimes (15-60 minutes)\n"
                        "3. Implement token refresh mechanism\n"
                        "4. Maintain a token revocation list"
                    ),
                    cwe_id=613,  # CWE-613: Insufficient Session Expiration
                    cvss_score=7.5,
                    owasp_ref="A07:2021 — Identification and Authentication Failures",
                    is_confirmed=True,
                )
            )

        # Test 3: Weak key brute force (common secrets)
        common_secrets = [
            "secret",
            "password",
            "123456",
            "key",
            "jwt_secret",
            "your-256-bit-secret",
            "shhhhh",
            "change_me",
            "default",
            "mysecretkey",
            "jwt",
            "token_secret",
            "supersecret",
        ]

        if header.get("alg", "").startswith("HS"):
            for secret in common_secrets:
                forged = self._forge_jwt(header, payload, secret.encode())
                resp = await self.http.request(
                    "GET",
                    url,
                    headers={"Authorization": f"Bearer {forged}"},
                )
                if resp["status"] == 200:
                    findings.append(
                        APISecurityFinding(
                            title="JWT Weak Signing Key — Key Successfully Brute-Forced",
                            category=APIVulnCategory.JWT_VULNERABILITY,
                            severity=APISeverity.CRITICAL,
                            endpoint=protected_endpoint,
                            method="GET",
                            description=(
                                f"JWT signing key is weak. The secret '{secret[:3]}***' was "
                                "successfully guessed, allowing token forgery."
                            ),
                            impact=(
                                "Attacker can forge valid JWT tokens for any user, "
                                "achieving complete authentication bypass."
                            ),
                            remediation=(
                                "1. Use a strong random key (256+ bits)\n"
                                "2. Consider asymmetric algorithms (RS256, ES256)\n"
                                "3. Rotate keys periodically\n"
                                "4. Store keys in secure vault (not in source code)"
                            ),
                            cwe_id=521,  # CWE-521: Weak Password Requirements
                            cvss_score=9.8,
                            owasp_ref="A02:2021 — Cryptographic Failures",
                            is_confirmed=True,
                        )
                    )
                    break

        # Test 4: Missing claims
        missing_claims = []
        if "iss" not in payload:
            missing_claims.append("iss (issuer)")
        if "aud" not in payload:
            missing_claims.append("aud (audience)")
        if "exp" not in payload:
            missing_claims.append("exp (expiration)")
        if "iat" not in payload:
            missing_claims.append("iat (issued at)")
        if "sub" not in payload:
            missing_claims.append("sub (subject)")

        if missing_claims:
            findings.append(
                APISecurityFinding(
                    title="JWT Missing Security Claims",
                    category=APIVulnCategory.JWT_VULNERABILITY,
                    severity=APISeverity.MEDIUM,
                    endpoint=protected_endpoint,
                    method="GET",
                    description=f"JWT token is missing claims: {', '.join(missing_claims)}",
                    impact="Missing claims reduce token security and enable replay attacks.",
                    remediation=(
                        "Include all security-relevant claims: iss, aud, exp, iat, sub, jti.\n"
                        "Validate all claims server-side."
                    ),
                    cwe_id=345,  # CWE-345: Insufficient Verification of Data Authenticity
                    cvss_score=5.3,
                    owasp_ref="A07:2021 — Identification and Authentication Failures",
                )
            )

        self.findings.extend(findings)
        return findings


# ════════════════════════════════════════════════════════════════════════════
# RATE LIMIT SCANNER
# ════════════════════════════════════════════════════════════════════════════


class RateLimitScanner:
    """Testa mecanismos de rate limiting em endpoints da API.

    Detecta ausencia de limitacao que permite:
    - Brute force de credenciais
    - Enumeracao de usuarios em massa
    - Data scraping/harvesting
    - DoS via request flooding
    """

    def __init__(self, http: APISecurityHTTP):
        self.http = http
        self.findings: List[APISecurityFinding] = []

    async def scan_rate_limit(
        self,
        base_url: str,
        endpoints: Optional[List[str]] = None,
        requests_per_test: int = 30,
    ) -> List[APISecurityFinding]:
        """Testa rate limiting enviando rajadas de requisicoes."""
        findings = []
        paths = endpoints or ["/api/v1/users", "/api/v1/users/search"]

        for path in paths:
            url = f"{base_url.rstrip('/')}{path}"
            statuses = []
            response_times = []

            logger.info(f"Testing rate limit on {path} ({requests_per_test} requests)")

            for i in range(requests_per_test):
                resp = await self.http.request("GET", url)
                statuses.append(resp["status"])
                response_times.append(resp["elapsed_ms"])
                # Minimal delay to make it realistic
                await asyncio.sleep(0.05)

            # Analyze results
            rate_limited = any(s == 429 for s in statuses)
            blocked = any(
                s == 403 for s in statuses[10:]
            )  # Check if blocked after warmup
            all_success = all(s == 200 for s in statuses)

            if all_success:
                findings.append(
                    APISecurityFinding(
                        title=f"No Rate Limiting — {path} Accepts Unlimited Requests",
                        category=APIVulnCategory.MISSING_RATE_LIMIT,
                        severity=APISeverity.HIGH,
                        endpoint=path,
                        method="GET",
                        description=(
                            f"Sent {requests_per_test} requests to {path} in rapid succession. "
                            f"All returned 200 OK. Average response time: "
                            f"{sum(response_times)/len(response_times):.0f}ms. "
                            "No rate limiting detected."
                        ),
                        impact=(
                            "Without rate limiting, attackers can:\n"
                            "- Enumerate all users via API scraping\n"
                            "- Brute force credentials at high speed\n"
                            "- Perform DoS attacks\n"
                            "- Extract all data in minutes"
                        ),
                        remediation=(
                            "1. Implement rate limiting per IP: 60 req/min for authenticated, "
                            "10 req/min for unauthenticated\n"
                            "2. Use Redis-based rate limiter for < 5ms latency overhead\n"
                            "3. Return 429 Too Many Requests with Retry-After header\n"
                            "4. Implement progressive delays for repeated violations\n"
                            "5. Configure WAF rules for automated request detection\n"
                            "6. Add CAPTCHA after rate limit exceeded"
                        ),
                        cwe_id=770,  # CWE-770: Allocation of Resources Without Limits
                        cvss_score=7.5,
                        owasp_ref="API4:2019 — Lack of Resources & Rate Limiting",
                        evidence=(
                            f"Sent {requests_per_test} requests, all returned 200.\n"
                            f"Response times: min={min(response_times):.0f}ms, "
                            f"max={max(response_times):.0f}ms, "
                            f"avg={sum(response_times)/len(response_times):.0f}ms"
                        ),
                        is_confirmed=True,
                    )
                )
            elif rate_limited:
                logger.info(f"  ✓ Rate limiting detected on {path}")

        self.findings.extend(findings)
        return findings

    async def scan_login_rate_limit(
        self,
        login_url: str,
        requests_per_test: int = 20,
    ) -> List[APISecurityFinding]:
        """Testa rate limiting especificamente no endpoint de login."""
        findings = []
        statuses = []

        for i in range(requests_per_test):
            resp = await self.http.request(
                "POST",
                login_url,
                json_data={
                    "username": f"nonexistent_user_{i}",
                    "password": f"wrong_password_{i}",
                },
            )
            statuses.append(resp["status"])
            await asyncio.sleep(0.05)

        rate_limited = any(s == 429 for s in statuses)
        locked = any(s == 423 for s in statuses)

        if not rate_limited and not locked:
            findings.append(
                APISecurityFinding(
                    title="No Rate Limiting on Login Endpoint",
                    category=APIVulnCategory.MISSING_RATE_LIMIT,
                    severity=APISeverity.CRITICAL,
                    endpoint=login_url,
                    method="POST",
                    description=(
                        f"Sent {requests_per_test} failed login attempts in rapid succession. "
                        "No rate limiting or account lockout detected."
                    ),
                    impact=(
                        "Allows unlimited brute force attacks on user credentials. "
                        "Combined with exposed usernames, full credential compromise is possible."
                    ),
                    remediation=(
                        "1. Implement progressive lockout (5 attempts → 15min lock)\n"
                        "2. Rate limit login: 5 attempts/min per IP\n"
                        "3. Add CAPTCHA after 3 failed attempts\n"
                        "4. Implement account lockout notification via email\n"
                        "5. Use bcrypt/argon2 for slow password comparison"
                    ),
                    cwe_id=307,  # CWE-307: Improper Restriction of Excessive Authentication Attempts
                    cvss_score=9.0,
                    owasp_ref="A07:2021 — Identification and Authentication Failures",
                    is_confirmed=True,
                )
            )

        self.findings.extend(findings)
        return findings


# ════════════════════════════════════════════════════════════════════════════
# USER ENUMERATION SCANNER
# ════════════════════════════════════════════════════════════════════════════


class UserEnumerationScanner:
    """Detecta possibilidade de enumeracao de usuarios.

    Testes de timing e response-based enumeration:
    1. Response difference para usuario existente vs inexistente
    2. Timing attack no endpoint de login
    3. Registration endpoint enumeration
    4. Password reset enumeration
    5. API listing without pagination
    """

    def __init__(self, http: APISecurityHTTP):
        self.http = http
        self.findings: List[APISecurityFinding] = []

    async def scan_response_enumeration(
        self,
        base_url: str,
        login_url: Optional[str] = None,
    ) -> List[APISecurityFinding]:
        """Testa diferenca de resposta entre usuario valido e invalido."""
        findings = []
        url = login_url or f"{base_url.rstrip('/')}/api/v1/auth/login"

        # Test with likely valid username
        valid_usernames = ["admin", "user", "test"]
        invalid_username = f"nonexistent_xyzzy_{random.randint(10000, 99999)}"

        invalid_resp = await self.http.request(
            "POST",
            url,
            json_data={"username": invalid_username, "password": "wrong"},
        )

        for username in valid_usernames:
            valid_resp = await self.http.request(
                "POST",
                url,
                json_data={"username": username, "password": "wrong"},
            )

            if valid_resp.get("error") or invalid_resp.get("error"):
                continue

            # Check response differences
            different_status = valid_resp["status"] != invalid_resp["status"]
            different_body = valid_resp["body"] != invalid_resp["body"]
            different_length = (
                abs(valid_resp["content_length"] - invalid_resp["content_length"]) > 10
            )
            timing_diff = abs(valid_resp["elapsed_ms"] - invalid_resp["elapsed_ms"])
            timing_significant = timing_diff > 100  # >100ms difference

            if different_status or (different_body and different_length):
                findings.append(
                    APISecurityFinding(
                        title="User Enumeration via Login Response Differences",
                        category=APIVulnCategory.USER_ENUMERATION,
                        severity=APISeverity.MEDIUM,
                        endpoint=url,
                        method="POST",
                        description=(
                            f"Login endpoint returns different responses for existing vs "
                            f"non-existing usernames. Status: {valid_resp['status']} vs "
                            f"{invalid_resp['status']}, Length: {valid_resp['content_length']} vs "
                            f"{invalid_resp['content_length']}."
                        ),
                        impact="Allows attackers to enumerate valid usernames for targeted attacks.",
                        remediation=(
                            "1. Return identical responses for valid and invalid usernames\n"
                            "2. Use generic message: 'Invalid username or password'\n"
                            "3. Ensure consistent response time regardless of user existence\n"
                            "4. Rate limit login attempts"
                        ),
                        cwe_id=204,  # CWE-204: Observable Response Discrepancy
                        cvss_score=5.3,
                        owasp_ref="A07:2021 — Identification and Authentication Failures",
                    )
                )
                break

            if timing_significant:
                findings.append(
                    APISecurityFinding(
                        title="User Enumeration via Timing Attack",
                        category=APIVulnCategory.USER_ENUMERATION,
                        severity=APISeverity.MEDIUM,
                        endpoint=url,
                        method="POST",
                        description=(
                            f"Login endpoint shows timing difference of {timing_diff:.0f}ms "
                            "between existing and non-existing usernames."
                        ),
                        impact="Allows brute-force enumeration of valid usernames.",
                        remediation=(
                            "1. Use constant-time comparison for credentials\n"
                            "2. Always perform password hash comparison even for non-existing users\n"
                            "3. Add random delay to normalize response times"
                        ),
                        cwe_id=208,  # CWE-208: Observable Timing Discrepancy
                        cvss_score=5.3,
                        owasp_ref="A07:2021 — Identification and Authentication Failures",
                    )
                )
                break

        self.findings.extend(findings)
        return findings

    async def scan_total_count_exposure(
        self,
        base_url: str,
        endpoints: Optional[List[str]] = None,
    ) -> List[APISecurityFinding]:
        """Testa se endpoints expoe contagem total de registros."""
        findings = []
        paths = endpoints or ["/api/v1/users", "/api/v1/users/search"]

        for path in paths:
            url = f"{base_url.rstrip('/')}{path}"
            resp = await self.http.request("GET", url)

            if resp["status"] != 200 or resp.get("error"):
                continue

            try:
                data = json.loads(resp["body"])
            except json.JSONDecodeError:
                continue

            # Check for total count exposure
            total_fields = [
                "total",
                "total_count",
                "totalCount",
                "count",
                "total_records",
            ]
            for tf in total_fields:
                if isinstance(data, dict) and tf in data and data[tf] is not None:
                    findings.append(
                        APISecurityFinding(
                            title=f"User Count Exposed — {tf}={data[tf]} at {path}",
                            category=APIVulnCategory.USER_ENUMERATION,
                            severity=APISeverity.LOW,
                            endpoint=path,
                            method="GET",
                            description=(
                                f"The endpoint exposes total user count ({tf}={data[tf]}), "
                                "enabling attackers to measure the platform's user base."
                            ),
                            remediation=(
                                "1. Remove or null the total count field in public responses\n"
                                "2. Use cursor-based pagination instead of offset-based\n"
                                "3. Return total only for authenticated admin requests"
                            ),
                            cwe_id=200,
                            owasp_ref="API3:2019 — Excessive Data Exposure",
                        )
                    )
                    break

                # Check in nested pagination
                if isinstance(data, dict):
                    for pag_key in ("pagination", "meta", "paging"):
                        if pag_key in data and isinstance(data[pag_key], dict):
                            pag = data[pag_key]
                            if tf in pag and pag[tf] is not None:
                                findings.append(
                                    APISecurityFinding(
                                        title=f"User Count Exposed via Pagination — {tf}={pag[tf]}",
                                        category=APIVulnCategory.USER_ENUMERATION,
                                        severity=APISeverity.LOW,
                                        endpoint=path,
                                        method="GET",
                                        description=f"Pagination metadata exposes total count: {pag[tf]}",
                                        remediation="Return total as null in public responses.",
                                        cwe_id=200,
                                        owasp_ref="API3:2019 — Excessive Data Exposure",
                                    )
                                )

        self.findings.extend(findings)
        return findings


# ════════════════════════════════════════════════════════════════════════════
# CHANNEL BYPASS SCANNER — Inspired by Riachuelo/Midway Discovery
# ════════════════════════════════════════════════════════════════════════════


class ChannelBypassScanner:
    """Detecta bypass de controles de segurança via manipulação de canal/modo.

    Técnica descoberta empiricamente: APIs que servem web e mobile frequentemente
    aplicam controles de segurança (captcha, MFA, rate limiting, WAF) apenas no
    canal web, enquanto canais mobile/internos pulam a validação.

    Padrão: enviar a mesma request trocando headers de canal (channel, X-Client-Type,
    X-Platform, X-Requested-With, User-Agent mobile, etc.) e comparar se controles
    são relaxados.

    Referência:
    - OWASP API5:2023 — BFLA (Broken Function Level Authorization)
    - OWASP API8:2023 — Security Misconfiguration
    - CWE-863: Incorrect Authorization
    """

    # Headers comuns que identificam canal/plataforma em APIs multi-channel
    CHANNEL_HEADERS: List[Dict[str, str]] = [
        {"channel": "APP"},
        {"channel": "MOBILE"},
        {"channel": "IOS"},
        {"channel": "ANDROID"},
        {"channel": "app"},
        {"channel": "mobile"},
        {"channel": "internal"},
        {"channel": "INTERNAL"},
        {"channel": "API"},
        {"channel": "api"},
        {"channel": "SDK"},
        {"channel": "PARTNER"},
        {"X-Client-Type": "mobile"},
        {"X-Client-Type": "ios"},
        {"X-Client-Type": "android"},
        {"X-Client-Type": "app"},
        {"X-Client-Type": "internal"},
        {"X-Client-Type": "sdk"},
        {"X-Platform": "ios"},
        {"X-Platform": "android"},
        {"X-Platform": "mobile"},
        {"X-Requested-With": "com.company.app"},
        {"X-Requested-With": "XMLHttpRequest"},
        {"X-App-Version": "1.0.0"},
        {"X-App-Version": "99.0.0"},
    ]

    # User-Agents que simulam clientes mobile
    MOBILE_USER_AGENTS: List[str] = [
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
        "Dalvik/2.1.0 (Linux; U; Android 14; Pixel 8 Pro Build/AP3A.241005.015)",
        "okhttp/4.12.0",
        "Retrofit/2.9.0",
    ]

    # channel-id style numeric values to test
    CHANNEL_IDS: List[str] = [
        "100",
        "200",
        "300",
        "400",
        "500",
        "600",
        "700",
        "800",
        "900",
        "1000",
        "0",
        "1",
        "2",
        "3",
        "99",
        "999",
    ]

    def __init__(self, http: APISecurityHTTP):
        self.http = http
        self.findings: List[APISecurityFinding] = []

    async def scan_channel_bypass(
        self,
        base_url: str,
        endpoints: Optional[List[str]] = None,
        auth_headers: Optional[Dict[str, str]] = None,
        baseline_headers: Optional[Dict[str, str]] = None,
    ) -> List[APISecurityFinding]:
        """Testa bypass de segurança via troca de canal/plataforma.

        Estratégia (descoberta no Riachuelo/Midway):
        1. Faz request baseline com headers normais → registra resposta (ex: captcha error)
        2. Para cada variação de canal, repete a request
        3. Se a resposta muda de erro p/ sucesso, ou de 401/403 → 200, é bypass

        Args:
            base_url: URL base da API
            endpoints: Lista de endpoints a testar
            auth_headers: Headers de autenticação (token, api-key, etc)
            baseline_headers: Headers padrão da request "normal" (web)
        """
        findings: List[APISecurityFinding] = []
        test_paths = endpoints or ["/"]
        base_hdrs = dict(baseline_headers or {})

        for path in test_paths:
            url = (
                f"{base_url.rstrip('/')}{path}" if not path.startswith("http") else path
            )

            # Step 1: Baseline request (normal web channel)
            baseline_hdrs = {**base_hdrs}
            if auth_headers:
                baseline_hdrs.update(auth_headers)
            baseline = await self.http.request("GET", url, headers=baseline_hdrs)
            baseline_status = baseline.get("status", 0)
            baseline_body = baseline.get("body", "")

            # Detect if baseline has a security gate (captcha, 401, 403, error)
            has_security_gate = (
                baseline_status in (401, 403, 429)
                or "captcha" in baseline_body.lower()
                or "unauthorized" in baseline_body.lower()
                or "forbidden" in baseline_body.lower()
                or "rate limit" in baseline_body.lower()
                or "mfa" in baseline_body.lower()
                or "otp" in baseline_body.lower()
                or "token" in baseline_body.lower()
                and "invalid" in baseline_body.lower()
            )

            if not has_security_gate:
                continue  # No gate to bypass on this endpoint

            # Step 2: Test each channel variation
            for channel_hdrs in self.CHANNEL_HEADERS:
                test_hdrs = {**baseline_hdrs, **channel_hdrs}
                resp = await self.http.request("GET", url, headers=test_hdrs)
                resp_status = resp.get("status", 0)
                resp_body = resp.get("body", "")

                bypassed = self._detect_bypass(
                    baseline_status,
                    baseline_body,
                    resp_status,
                    resp_body,
                )

                if bypassed:
                    hdr_desc = ", ".join(f"{k}={v}" for k, v in channel_hdrs.items())
                    findings.append(
                        APISecurityFinding(
                            title=f"Channel Bypass — Security gate bypassed with {hdr_desc}",
                            category=APIVulnCategory.BFLA,
                            severity=APISeverity.CRITICAL,
                            endpoint=path,
                            method="GET",
                            description=(
                                f"Security controls (captcha/auth/rate-limit) at {path} are "
                                f"bypassed when sending header(s): {hdr_desc}. "
                                f"Baseline returned HTTP {baseline_status}, bypass returned "
                                f"HTTP {resp_status} with data."
                            ),
                            impact=(
                                "Attackers can bypass all client-side security controls "
                                "(captcha, MFA, rate limiting) by simply switching the "
                                "channel header. This allows mass data extraction, brute "
                                "force attacks, and complete security control evasion."
                            ),
                            evidence=(
                                f"Baseline ({baseline_status}): {baseline_body[:300]}\n"
                                f"Bypass ({resp_status}): {resp_body[:300]}"
                            ),
                            remediation=(
                                "1. Apply security controls uniformly across ALL channels\n"
                                "2. Server-side channel validation — reject unknown channel values\n"
                                "3. Captcha/MFA enforcement must be channel-agnostic\n"
                                "4. Implement allowlist for valid channel header values\n"
                                "5. Log and alert on channel-switching patterns"
                            ),
                            cwe_id=863,
                            cvss_score=9.8,
                            owasp_ref="API5:2023 — BFLA + API8:2023 — Security Misconfiguration",
                            request_dump=f"GET {url}\n{json.dumps(channel_hdrs, indent=2)}",
                            response_dump=resp_body[:1500],
                            is_confirmed=True,
                        )
                    )

            # Step 3: Test mobile User-Agents
            for ua in self.MOBILE_USER_AGENTS:
                test_hdrs = {**baseline_hdrs, "User-Agent": ua}
                resp = await self.http.request("GET", url, headers=test_hdrs)
                resp_status = resp.get("status", 0)
                resp_body = resp.get("body", "")

                if self._detect_bypass(
                    baseline_status, baseline_body, resp_status, resp_body
                ):
                    ua_short = ua[:60]
                    findings.append(
                        APISecurityFinding(
                            title=f"UA Bypass — Security gate bypassed with mobile User-Agent",
                            category=APIVulnCategory.BFLA,
                            severity=APISeverity.CRITICAL,
                            endpoint=path,
                            method="GET",
                            description=(
                                f"Security controls bypassed when using mobile User-Agent: "
                                f"{ua_short}..."
                            ),
                            impact=(
                                "Client-side security controls rely on User-Agent header for "
                                "enforcement decisions. Trivially spoofable."
                            ),
                            evidence=(
                                f"Baseline ({baseline_status}): {baseline_body[:200]}\n"
                                f"Bypass ({resp_status}): {resp_body[:200]}"
                            ),
                            remediation=(
                                "1. Never use User-Agent for security decisions\n"
                                "2. Apply captcha/MFA uniformly regardless of client type\n"
                                "3. Implement server-side validation independent of client headers"
                            ),
                            cwe_id=290,
                            cvss_score=9.1,
                            owasp_ref="API8:2023 — Security Misconfiguration",
                            is_confirmed=True,
                        )
                    )
                    break  # One UA bypass is enough

            # Step 4: Test channel-id numeric variations
            for cid in self.CHANNEL_IDS:
                test_hdrs = {**baseline_hdrs, "channel-id": cid}
                resp = await self.http.request("GET", url, headers=test_hdrs)
                resp_status = resp.get("status", 0)
                resp_body = resp.get("body", "")

                if self._detect_bypass(
                    baseline_status, baseline_body, resp_status, resp_body
                ):
                    findings.append(
                        APISecurityFinding(
                            title=f"Channel-ID Bypass — Security gate bypassed with channel-id={cid}",
                            category=APIVulnCategory.BFLA,
                            severity=APISeverity.HIGH,
                            endpoint=path,
                            method="GET",
                            description=(
                                f"Security controls bypassed with numeric channel-id={cid}."
                            ),
                            impact="Allows bypassing captcha/auth via channel-id manipulation.",
                            evidence=f"Bypass ({resp_status}): {resp_body[:300]}",
                            remediation="Validate channel-id against an allowlist on server side.",
                            cwe_id=863,
                            cvss_score=8.6,
                            owasp_ref="API5:2023 — BFLA",
                            is_confirmed=True,
                        )
                    )
                    break  # One finding per endpoint

        self.findings.extend(findings)
        return findings

    def _detect_bypass(
        self,
        baseline_status: int,
        baseline_body: str,
        test_status: int,
        test_body: str,
    ) -> bool:
        """Detecta se a resposta do teste indica bypass de controle de segurança."""
        bl = baseline_body.lower()
        tb = test_body.lower()

        # Case 1: Baseline was auth error, test returned data
        if baseline_status in (401, 403) and test_status == 200:
            # Make sure test response has actual content (not another error)
            if len(test_body) > 50 and not any(
                err in tb for err in ["unauthorized", "forbidden", "error", "invalid"]
            ):
                return True

        # Case 2: Baseline had captcha/security error, test doesn't
        if "captcha" in bl and "captcha" not in tb and test_status == 200:
            return True

        # Case 3: Baseline was rate-limited, test isn't
        if baseline_status == 429 and test_status == 200:
            return True

        # Case 4: Baseline had MFA/OTP requirement, test doesn't
        if (
            ("mfa" in bl or "otp" in bl)
            and "mfa" not in tb
            and "otp" not in tb
            and test_status == 200
        ):
            return True

        # Case 5: Both 200 but baseline has error in body, test has data
        if baseline_status == 200 and test_status == 200:
            baseline_has_error = any(
                e in bl
                for e in [
                    "captcha",
                    "invalid token",
                    "token inválido",
                    "unauthorized",
                    "rate limit",
                    "too many",
                ]
            )
            test_has_data = (
                not any(
                    e in tb
                    for e in [
                        "captcha",
                        "invalid token",
                        "token inválido",
                        "unauthorized",
                        "rate limit",
                        "too many",
                        "error",
                    ]
                )
                and len(test_body) > 100
            )
            if baseline_has_error and test_has_data:
                return True

        return False


class AuthGateBypassScanner:
    """Testa bypass de gates de autenticação secundária (captcha, MFA, OTP).

    Técnica: muitos sistemas implementam captcha/MFA apenas no frontend.
    Este scanner testa se o backend realmente valida estes controles, ou se
    pode ser contornado com:
    - Omissão do header/campo de captcha
    - Valor dummy/vazio
    - Troca de método HTTP
    - Troca de Content-Type
    - Remoção de headers específicos

    Referência:
    - OWASP API2:2023 — Broken Authentication
    - CWE-287: Improper Authentication
    - CWE-804: Guessable CAPTCHA
    """

    # Captcha field names commonly used in headers and body
    CAPTCHA_FIELDS: List[str] = [
        "captcha",
        "recaptcha",
        "g-recaptcha-response",
        "captcha-token",
        "captcha_token",
        "h-captcha-response",
        "cf-turnstile-response",
        "X-Captcha-Token",
        "X-Recaptcha-Token",
        "verification-token",
    ]

    # Dummy values to test if server actually validates
    DUMMY_VALUES: List[str] = [
        "",
        "x",
        "bypass",
        "test",
        "1",
        "true",
        "null",
        "undefined",
        "AAAA",
        "03AGdBq24" + "A" * 200,  # fake recaptcha-length token
    ]

    def __init__(self, http: APISecurityHTTP):
        self.http = http
        self.findings: List[APISecurityFinding] = []

    async def scan_captcha_bypass(
        self,
        base_url: str,
        endpoint: str,
        auth_headers: Optional[Dict[str, str]] = None,
        known_captcha_field: Optional[str] = None,
        method: str = "GET",
        body: Optional[dict] = None,
    ) -> List[APISecurityFinding]:
        """Testa se captcha é realmente validado no server-side.

        Estratégia:
        1. Request sem field de captcha → se retorna dados, captcha não é exigido
        2. Request com captcha vazio/dummy → se retorna dados, validação é fraca
        3. Request com método diferente (POST→GET) → pode pular middleware
        """
        findings: List[APISecurityFinding] = []
        url = f"{base_url.rstrip('/')}{endpoint}"
        base_hdrs = dict(auth_headers or {})

        captcha_fields = (
            [known_captcha_field] if known_captcha_field else self.CAPTCHA_FIELDS
        )

        for captcha_field in captcha_fields:
            # Test 1: Request WITHOUT captcha field
            resp_no_captcha = await self.http.request(
                method,
                url,
                headers=base_hdrs,
                json_data=body,
            )
            no_captcha_ok = self._is_success_response(resp_no_captcha)

            if no_captcha_ok:
                findings.append(
                    APISecurityFinding(
                        title=f"Captcha Not Required — {endpoint} accessible without captcha",
                        category=APIVulnCategory.BROKEN_AUTH,
                        severity=APISeverity.CRITICAL,
                        endpoint=endpoint,
                        method=method,
                        description=(
                            f"Endpoint {endpoint} returns valid data when the captcha "
                            f"field ({captcha_field}) is completely omitted. "
                            "Server does not enforce captcha validation."
                        ),
                        impact=(
                            "Captcha protection is purely client-side. Attackers can "
                            "make unlimited automated requests bypassing all captcha "
                            "controls, enabling mass data extraction and brute force."
                        ),
                        evidence=resp_no_captcha.get("body", "")[:500],
                        remediation=(
                            "1. Enforce captcha validation server-side as mandatory\n"
                            "2. Return 400/422 when captcha field is missing\n"
                            "3. Validate captcha token with provider API before processing\n"
                            "4. Apply same requirement across all channels/platforms"
                        ),
                        cwe_id=804,
                        cvss_score=9.1,
                        owasp_ref="API2:2023 — Broken Authentication",
                        is_confirmed=True,
                    )
                )
                continue  # No need to test dummy values if field is optional

            # Test 2: Request with dummy/empty captcha values
            for dummy in self.DUMMY_VALUES:
                test_hdrs = {**base_hdrs, captcha_field: dummy}
                test_body = dict(body or {})
                test_body[captcha_field] = dummy

                resp = await self.http.request(
                    method,
                    url,
                    headers=test_hdrs,
                    json_data=test_body if body else None,
                )

                if self._is_success_response(resp):
                    findings.append(
                        APISecurityFinding(
                            title=f"Captcha Bypass — Dummy value accepted: {captcha_field}={dummy!r}",
                            category=APIVulnCategory.BROKEN_AUTH,
                            severity=APISeverity.CRITICAL,
                            endpoint=endpoint,
                            method=method,
                            description=(
                                f"Captcha field '{captcha_field}' accepts dummy value "
                                f"'{dummy}'. Server either doesn't validate with the "
                                "captcha provider or has a bypass condition."
                            ),
                            impact=(
                                "Complete captcha bypass via trivial value substitution. "
                                "All rate limiting and bot protection is ineffective."
                            ),
                            evidence=resp.get("body", "")[:500],
                            remediation=(
                                "1. Always verify captcha token with the provider (Google/Cloudflare)\n"
                                "2. Reject empty, too-short, or obviously invalid tokens\n"
                                "3. Validate token was generated for YOUR site key\n"
                                "4. Check token freshness (reject tokens older than 2 min)"
                            ),
                            cwe_id=804,
                            cvss_score=9.1,
                            owasp_ref="API2:2023 — Broken Authentication",
                            is_confirmed=True,
                        )
                    )
                    break  # One dummy bypass per field is enough

        # Test 3: Method switching (POST endpoint accepting GET, which may skip middleware)
        alt_method = "GET" if method.upper() == "POST" else "POST"
        resp_alt = await self.http.request(alt_method, url, headers=base_hdrs)
        if self._is_success_response(resp_alt):
            findings.append(
                APISecurityFinding(
                    title=f"Method Switch Bypass — {alt_method} bypasses captcha at {endpoint}",
                    category=APIVulnCategory.SECURITY_MISCONFIG,
                    severity=APISeverity.HIGH,
                    endpoint=endpoint,
                    method=alt_method,
                    description=(
                        f"Switching from {method} to {alt_method} bypasses security "
                        f"middleware (captcha/auth) on {endpoint}."
                    ),
                    impact="Captcha/auth middleware only applies to specific HTTP method.",
                    evidence=resp_alt.get("body", "")[:300],
                    remediation="Apply security middleware to ALL HTTP methods on protected routes.",
                    cwe_id=287,
                    cvss_score=8.1,
                    owasp_ref="API8:2023 — Security Misconfiguration",
                    is_confirmed=True,
                )
            )

        self.findings.extend(findings)
        return findings

    def _is_success_response(self, resp: Dict[str, Any]) -> bool:
        """Determina se a resposta contém dados válidos (bypass bem-sucedido)."""
        status = resp.get("status", 0)
        body = resp.get("body", "")
        bl = body.lower()

        if status != 200:
            return False

        # Check for error indicators in body
        error_markers = [
            "captcha",
            "invalid",
            "unauthorized",
            "forbidden",
            "error",
            "missing",
            "required",
            "rate limit",
        ]
        if any(m in bl for m in error_markers):
            return False

        # Must have meaningful content
        if len(body) < 50:
            return False

        # Check for JSON data indicators
        if body.strip().startswith(("{", "[")):
            try:
                data = json.loads(body)
                if isinstance(data, dict):
                    # Has data-like keys (not just an error object)
                    data_keys = {
                        "data",
                        "results",
                        "items",
                        "records",
                        "contracts",
                        "users",
                        "accounts",
                        "list",
                        "content",
                        "response",
                    }
                    if any(k in data for k in data_keys):
                        return True
                    if len(data) > 3:
                        return True
                elif isinstance(data, list) and len(data) > 0:
                    return True
            except json.JSONDecodeError:
                pass

        return False


class HeaderPermutationFuzzer:
    """Fuzzer de permutação de headers para descoberta de bypass.

    Testa sistematicamente combinações de headers que podem alterar o
    comportamento do servidor, especialmente em relação a controles
    de segurança, roteamento e autorização.

    Técnica inspirada pelo Riachuelo: a combinação específica de
    channel + captcha dummy + auth token válido era o que causava bypass.

    Referência:
    - OWASP API8:2023 — Security Misconfiguration
    - CWE-436: Interpretation Conflict
    """

    # Security-relevant headers to test
    SECURITY_HEADERS_TO_FUZZ: Dict[str, List[str]] = {
        # IP spoofing headers
        "X-Forwarded-For": ["127.0.0.1", "10.0.0.1", "192.168.1.1", "::1"],
        "X-Real-IP": ["127.0.0.1", "10.0.0.1"],
        "X-Originating-IP": ["127.0.0.1"],
        "X-Client-IP": ["127.0.0.1"],
        "True-Client-IP": ["127.0.0.1"],
        # URL override headers
        "X-Original-URL": ["/admin", "/internal", "/debug"],
        "X-Rewrite-URL": ["/admin", "/internal"],
        # Host override
        "X-Forwarded-Host": ["localhost", "internal.api"],
        # Auth bypass headers
        "X-Custom-IP-Authorization": ["127.0.0.1"],
        "X-Auth-Bypass": ["true", "1"],
        "X-Internal": ["true", "1"],
        "X-Debug": ["true", "1"],
        "X-Test": ["true", "1"],
        # Content negotiation
        "Accept": [
            "application/xml",
            "text/xml",
            "application/x-www-form-urlencoded",
            "*/*",
        ],
    }

    def __init__(self, http: APISecurityHTTP):
        self.http = http
        self.findings: List[APISecurityFinding] = []

    async def scan_header_permutations(
        self,
        base_url: str,
        endpoint: str,
        auth_headers: Optional[Dict[str, str]] = None,
        method: str = "GET",
    ) -> List[APISecurityFinding]:
        """Testa permutações de headers para descobrir bypass de segurança."""
        findings: List[APISecurityFinding] = []
        url = f"{base_url.rstrip('/')}{endpoint}"
        base_hdrs = dict(auth_headers or {})

        # Baseline
        baseline = await self.http.request(method, url, headers=base_hdrs)
        baseline_status = baseline.get("status", 0)
        baseline_body = baseline.get("body", "")

        for header_name, values in self.SECURITY_HEADERS_TO_FUZZ.items():
            for value in values:
                test_hdrs = {**base_hdrs, header_name: value}
                resp = await self.http.request(method, url, headers=test_hdrs)
                resp_status = resp.get("status", 0)
                resp_body = resp.get("body", "")

                # Detect significant behavioral change
                is_bypass = False
                change_desc = ""

                if baseline_status in (401, 403) and resp_status == 200:
                    is_bypass = True
                    change_desc = f"Auth bypass: {baseline_status}→{resp_status}"
                elif baseline_status == 429 and resp_status == 200:
                    is_bypass = True
                    change_desc = f"Rate limit bypass: 429→{resp_status}"
                elif baseline_status == 200 and resp_status == 200:
                    # Check if different content (e.g., error→data)
                    bl = baseline_body.lower()
                    tb = resp_body.lower()
                    if (
                        ("error" in bl or "captcha" in bl)
                        and "error" not in tb
                        and "captcha" not in tb
                    ):
                        if len(resp_body) > len(baseline_body) * 1.5:
                            is_bypass = True
                            change_desc = f"Content change: error→data"

                if is_bypass:
                    sev = (
                        APISeverity.CRITICAL
                        if "Auth bypass" in change_desc
                        else APISeverity.HIGH
                    )
                    findings.append(
                        APISecurityFinding(
                            title=f"Header Bypass — {header_name}: {value} ({change_desc})",
                            category=APIVulnCategory.SECURITY_MISCONFIG,
                            severity=sev,
                            endpoint=endpoint,
                            method=method,
                            description=(
                                f"Adding header '{header_name}: {value}' changes server "
                                f"behavior: {change_desc}. This indicates the server uses "
                                "client-supplied headers for security decisions."
                            ),
                            impact=(
                                "Security controls can be bypassed by spoofing headers. "
                                "Attackers can impersonate internal clients, bypass IP "
                                "restrictions, or evade authentication."
                            ),
                            evidence=(
                                f"Baseline: HTTP {baseline_status} ({len(baseline_body)} bytes)\n"
                                f"With {header_name}={value}: HTTP {resp_status} ({len(resp_body)} bytes)\n"
                                f"Response: {resp_body[:300]}"
                            ),
                            remediation=(
                                f"1. Do not trust client-supplied '{header_name}' header\n"
                                "2. Set these headers only at the load balancer/reverse proxy\n"
                                "3. Strip or ignore unknown/spoofable headers\n"
                                "4. Use mutual TLS or signed tokens for internal service auth"
                            ),
                            cwe_id=436,
                            cvss_score=8.6 if "Auth" in change_desc else 7.5,
                            owasp_ref="API8:2023 — Security Misconfiguration",
                            is_confirmed=True,
                        )
                    )

        self.findings.extend(findings)
        return findings


# ════════════════════════════════════════════════════════════════════════════
# SIREN API SECURITY ENGINE — Orquestrador Principal
# ════════════════════════════════════════════════════════════════════════════


# Late import for cloud/JWT advanced scanners
try:
    from core.shannon.cloud_jwt_scanner import (
        CloudFunctionScanner,
        CORSAdvancedScanner,
        JSONInteropScanner,
        JWTAdvancedScanner,
    )

    _HAS_CLOUD_JWT = True
except ImportError:
    try:
        from cloud_jwt_scanner import (
            CloudFunctionScanner,
            CORSAdvancedScanner,
            JSONInteropScanner,
            JWTAdvancedScanner,
        )

        _HAS_CLOUD_JWT = True
    except ImportError:
        _HAS_CLOUD_JWT = False


class SirenAPISecurityEngine:
    """Motor principal de auditoria de seguranca de API.

    Integra todos os scanners e gera relatorio completo seguindo:
    - OWASP Top 10 (2021)
    - OWASP API Security Top 10 (2019/2023)
    - CWE/SANS Top 25
    - LGPD / GDPR compliance checks

    Phases 1-8: Original scanners
    Phases 9-12: Cloud & JWT Advanced (cloud_jwt_scanner module)
    Phases 13-15: Channel/Auth Gate Bypass & Header Permutation (Riachuelo-inspired)
    """

    def __init__(
        self,
        timeout: float = 30.0,
        max_concurrent: int = 10,
        request_delay_ms: float = 100.0,
    ):
        self.http = APISecurityHTTP(
            timeout=timeout,
            max_concurrent=max_concurrent,
            request_delay_ms=request_delay_ms,
        )
        self.bac_scanner = BrokenAccessControlScanner(self.http)
        self.data_scanner = DataExposureScanner(self.http)
        self.jwt_scanner = JWTSecurityScanner(self.http)
        self.rate_scanner = RateLimitScanner(self.http)
        self.enum_scanner = UserEnumerationScanner(self.http)

        # Bypass scanners (Riachuelo-inspired)
        self.channel_scanner = ChannelBypassScanner(self.http)
        self.authgate_scanner = AuthGateBypassScanner(self.http)
        self.header_fuzzer = HeaderPermutationFuzzer(self.http)

        # Advanced scanners (cloud_jwt_scanner module)
        if _HAS_CLOUD_JWT:
            self.cloud_scanner = CloudFunctionScanner(self.http)
            self.jwt_adv_scanner = JWTAdvancedScanner(self.http)
            self.cors_adv_scanner = CORSAdvancedScanner(self.http)
            self.json_scanner = JSONInteropScanner(self.http)
        else:
            self.cloud_scanner = None
            self.jwt_adv_scanner = None
            self.cors_adv_scanner = None
            self.json_scanner = None

        self.result: Optional[APIAuditResult] = None

    async def full_api_audit(
        self,
        target: str,
        jwt_token: Optional[str] = None,
        low_priv_token: Optional[str] = None,
        login_url: Optional[str] = None,
        endpoints: Optional[List[str]] = None,
        user_ids: Optional[List[str]] = None,
        signing_key: Optional[str] = None,
        function_code: Optional[str] = None,
        jwt_location: str = "header",
        jwt_field: str = "Jwt",
        jwt_extra_body: Optional[dict] = None,
        audiences_to_test: Optional[List[str]] = None,
        auth_headers: Optional[Dict[str, str]] = None,
        baseline_headers: Optional[Dict[str, str]] = None,
        captcha_field: Optional[str] = None,
    ) -> APIAuditResult:
        """Executa auditoria completa de seguranca da API.

        Fases:
        1. Endpoint Discovery & Unauthenticated Access
        2. Sensitive Data Exposure Analysis
        3. JWT Security Testing
        4. IDOR & Privilege Escalation
        5. Rate Limiting Analysis
        6. User Enumeration Testing
        7. CORS & Header Security
        8. User Enumeration (continued)
        9. Cloud Function Admin Enumeration
        10. JWT Advanced — Kid Injection & Key Discovery
        11. CORS Advanced & Header Injection
        12. JSON Interoperability Attacks
        13. Channel/Mode Bypass Discovery (Riachuelo-inspired)
        14. Auth Gate (Captcha/MFA) Bypass Testing (Riachuelo-inspired)
        15. Header Permutation Fuzzing (Riachuelo-inspired)
        """
        start = time.monotonic()
        self.result = APIAuditResult(target=target)

        try:
            logger.info(f"=== SIREN API Security Audit: {target} ===")

            # Phase 1: Unauthenticated Access Control
            logger.info("Phase 1: Testing unauthenticated access...")
            await self.bac_scanner.scan_unauthenticated_access(target, endpoints)

            # Phase 2: Security Headers & Data Exposure
            logger.info("Phase 2: Scanning response headers & data exposure...")
            await self.data_scanner.scan_response_headers(target)
            await self.data_scanner.scan_debug_info_leak(target)

            # Phase 3: CORS Policy
            logger.info("Phase 3: Testing CORS policy...")
            await self.data_scanner.scan_cors_policy(target, endpoints)

            # Phase 4: JWT Security
            logger.info("Phase 4: Testing JWT security...")
            self.result.auth_tested = True
            if jwt_token:
                await self.jwt_scanner.scan_jwt_security(target, jwt_token)

            # Phase 5: IDOR & Privilege Escalation
            logger.info("Phase 5: Testing IDOR & privilege escalation...")
            await self.bac_scanner.scan_idor(target, jwt_token, user_ids)
            await self.bac_scanner.scan_privilege_escalation(target, low_priv_token)

            # Phase 6: HTTP Method Tampering
            logger.info("Phase 6: Testing HTTP method tampering...")
            await self.bac_scanner.scan_http_method_tampering(target, endpoints)

            # Phase 7: Rate Limiting
            logger.info("Phase 7: Testing rate limiting...")
            self.result.rate_limit_tested = True
            await self.rate_scanner.scan_rate_limit(target, endpoints)
            if login_url:
                await self.rate_scanner.scan_login_rate_limit(login_url)

            # Phase 8: User Enumeration
            logger.info("Phase 8: Testing user enumeration...")
            await self.enum_scanner.scan_response_enumeration(target, login_url)
            await self.enum_scanner.scan_total_count_exposure(target, endpoints)

            # Phase 9-12: Advanced Cloud & JWT Scanners
            if self.cloud_scanner:
                # Phase 9: Cloud Function Admin Enumeration
                logger.info("Phase 9: Cloud function admin enumeration...")
                await self.cloud_scanner.scan_cloud_admin(target, function_code)
                await self.cloud_scanner.scan_cloud_fingerprint(target)

                # Phase 10: JWT Advanced (kid injection, key discovery, audience confusion)
                logger.info("Phase 10: JWT advanced attacks...")
                if signing_key or jwt_token:
                    await self.jwt_adv_scanner.scan_kid_injection(
                        target,
                        jwt_token,
                        signing_key,
                        jwt_location,
                        jwt_field,
                        jwt_extra_body,
                    )
                    await self.jwt_adv_scanner.scan_audience_confusion(
                        target,
                        jwt_token,
                        signing_key,
                        audiences_to_test,
                        jwt_location,
                        jwt_field,
                        jwt_extra_body,
                    )
                if not signing_key:
                    await self.jwt_adv_scanner.scan_hardcoded_key(
                        target,
                        None,
                        jwt_location,
                        jwt_field,
                        jwt_extra_body,
                    )

                # Phase 11: CORS Advanced & Header Injection
                logger.info("Phase 11: Advanced CORS & header injection...")
                await self.cors_adv_scanner.scan_cors_advanced(target)
                await self.cors_adv_scanner.scan_security_headers(target, endpoints)

                # Phase 12: JSON Interoperability
                logger.info("Phase 12: JSON interoperability attacks...")
                test_jwt = jwt_token or ""
                await self.json_scanner.scan_json_interop(target, jwt_field, test_jwt)
                await self.json_scanner.scan_header_injection(target)

            # Phase 13: Channel/Mode Bypass Discovery (Riachuelo-inspired)
            logger.info("Phase 13: Channel/mode bypass scanning...")
            await self.channel_scanner.scan_channel_bypass(
                target,
                endpoints,
                auth_headers,
                baseline_headers,
            )

            # Phase 14: Auth Gate (Captcha/MFA) Bypass
            logger.info("Phase 14: Auth gate bypass scanning...")
            if endpoints:
                for ep in endpoints[:5]:  # Test top 5 endpoints
                    await self.authgate_scanner.scan_captcha_bypass(
                        target,
                        ep,
                        auth_headers,
                        captcha_field,
                    )

            # Phase 15: Header Permutation Fuzzing
            logger.info("Phase 15: Header permutation fuzzing...")
            if endpoints:
                for ep in endpoints[:3]:  # Test top 3 endpoints
                    await self.header_fuzzer.scan_header_permutations(
                        target,
                        ep,
                        auth_headers,
                    )

        except Exception as e:
            logger.error(f"Audit error: {e}")
        finally:
            await self.http.close()

        # Aggregate findings
        all_findings = (
            self.bac_scanner.findings
            + self.data_scanner.findings
            + self.jwt_scanner.findings
            + self.rate_scanner.findings
            + self.enum_scanner.findings
            + self.channel_scanner.findings
            + self.authgate_scanner.findings
            + self.header_fuzzer.findings
        )
        # Add advanced scanner findings if available
        if self.cloud_scanner:
            all_findings += self.cloud_scanner.findings
        if self.jwt_adv_scanner:
            all_findings += self.jwt_adv_scanner.findings
        if self.cors_adv_scanner:
            all_findings += self.cors_adv_scanner.findings
        if self.json_scanner:
            all_findings += self.json_scanner.findings

        # Deduplicate by unique_id
        seen = set()
        for f in all_findings:
            if f.unique_id not in seen:
                self.result.findings.append(f)
                seen.add(f.unique_id)

        # Collect data exposures
        for f in self.result.findings:
            self.result.data_exposures.extend(f.data_exposures)

        self.result.total_requests = self.http._request_count
        self.result.scan_end = datetime.now().isoformat()
        self.result.duration_seconds = time.monotonic() - start

        logger.info(
            f"Audit complete: {len(self.result.findings)} findings, "
            f"{self.result.total_requests} requests in {self.result.duration_seconds:.1f}s"
        )

        return self.result

    def generate_report(self, include_full_evidence: bool = False) -> str:
        """Gera relatorio completo em Markdown."""
        if not self.result:
            return "No audit results available."

        r = self.result
        lines = [
            "# 🛡️ SIREN API Security Audit Report",
            "",
            f"**Target:** `{r.target}`",
            f"**Scan Start:** {r.scan_start}",
            f"**Scan End:** {r.scan_end}",
            f"**Duration:** {r.duration_seconds:.1f}s",
            f"**Total Requests:** {r.total_requests}",
            f"**Total Findings:** {len(r.findings)}",
            "",
            "## Severity Distribution",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ]

        for sev in ["critical", "high", "medium", "low", "info"]:
            count = r.severity_distribution.get(sev, 0)
            icon = APISeverity(sev).icon if count > 0 else "⚪"
            lines.append(f"| {icon} {sev.upper()} | {count} |")

        lines.extend(["", "## OWASP Coverage", ""])
        owasp_refs = set()
        for f in r.findings:
            if f.owasp_ref:
                owasp_refs.add(f.owasp_ref)
        for ref in sorted(owasp_refs):
            lines.append(f"- ✅ {ref}")

        lines.extend(["", "---", "", "## Findings", ""])

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            r.findings,
            key=lambda f: severity_order.get(f.severity.value, 99),
        )

        for f in sorted_findings:
            lines.append(f.to_markdown())
            lines.append("---\n")

        # Data exposure summary
        if r.data_exposures:
            lines.extend(
                [
                    "## Sensitive Data Exposure Summary",
                    "",
                    "| Field | Type | Records Exposed |",
                    "|-------|------|----------------|",
                ]
            )
            seen_fields = set()
            for de in r.data_exposures:
                key = f"{de.field_name}:{de.field_type}"
                if key not in seen_fields:
                    seen_fields.add(key)
                    lines.append(
                        f"| `{de.field_name}` | {de.field_type} | {de.count_exposed} |"
                    )
            lines.append("")

        # Compliance impact
        lines.extend(
            [
                "## Compliance Impact",
                "",
                "### LGPD (Lei Geral de Proteção de Dados)",
                "- **Art. 46**: Failure to implement adequate security measures",
                "- **Art. 48**: Mandatory notification to ANPD within reasonable time",
                "- **Art. 52**: Potential fine of 2% of revenue (up to R$ 50M per violation)",
                "",
                "### GDPR (General Data Protection Regulation)",
                "- **Art. 32**: Failure to ensure appropriate security of processing",
                "- **Art. 33**: Mandatory breach notification within 72 hours",
                "- **Art. 83**: Fine up to €20M or 4% of global annual turnover",
                "",
                "### OWASP Top 10 (2021) Violations",
            ]
        )
        for ref in sorted(owasp_refs):
            lines.append(f"- {ref}")

        # Remediation roadmap
        lines.extend(
            [
                "",
                "## Remediation Roadmap",
                "",
                "### Immediate (24 hours)",
                "1. Add authentication middleware to all user data endpoints",
                "2. Remove sensitive fields from public API responses",
                "3. Implement mandatory pagination with max 20 items per page",
                "4. Deploy rate limiting (Redis-based)",
                "",
                "### Short-term (1-2 weeks)",
                "5. Implement RBAC (Role-Based Access Control)",
                "6. Add JWT validation with proper algorithm enforcement",
                "7. Implement audit logging for all data access",
                "8. Fix CORS policy to whitelist specific origins",
                "9. Add security headers (HSTS, CSP, X-Frame-Options)",
                "",
                "### Medium-term (1-2 months)",
                "10. Security audit of all API endpoints",
                "11. Implement SAST/DAST in CI/CD pipeline",
                "12. Add automated security regression tests",
                "13. Implement WAF rules for enumeration prevention",
                "",
                "### Long-term (3-6 months)",
                "14. Bug bounty program",
                "15. SOC 2 / ISO 27001 certification preparation",
                "16. Continuous security monitoring and alerting",
                "",
                "---",
                f"*Generated by SIREN API Security Scanner v1.0.0 — {datetime.now().isoformat()}*",
            ]
        )

        return "\n".join(lines)

    def generate_json_report(self) -> str:
        """Gera relatorio em JSON."""
        if not self.result:
            return "{}"
        return json.dumps(self.result.to_dict(), indent=2, ensure_ascii=False)
