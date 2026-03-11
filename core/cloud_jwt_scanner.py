#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  🔱 SIREN CLOUD FUNCTIONS & JWT ADVANCED SCANNER                         🔱   ██
██                                                                                ██
██  Modulo avancado para deteccao de:                                            ██
██    • Cloud Function Admin Exposure (Azure/AWS/GCP)                            ██
██    • JWT Kid Header Injection & Key Confusion                                 ██
██    • CORS HTTP Downgrade & Origin Reflection                                  ██
██    • Security Header Compliance                                               ██
██    • JSON Interoperability Attacks                                             ██
██    • HTTP Smuggling & Path Manipulation                                       ██
██    • Dual Provider Token Confusion                                            ██
██                                                                                ██
██  Integra-se ao SirenAPISecurityEngine.full_api_audit()                        ██
██  "Cada header é uma confissão. Cada erro é um mapa."                          ██
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
import re
import time
from typing import Any, Dict, List, Optional, Tuple

# Import from the main api_security module
try:
    from core.shannon.api_security import (
        APISecurityFinding,
        APISecurityHTTP,
        APISeverity,
        APIVulnCategory,
    )
except ImportError:
    from api_security import (
        APISecurityFinding,
        APISecurityHTTP,
        APISeverity,
        APIVulnCategory,
    )

logger = logging.getLogger("siren.cloud_jwt_scanner")


# ════════════════════════════════════════════════════════════════════════════
# CLOUD FUNCTION SCANNER — Azure/AWS/GCP Admin Endpoint Detection
# ════════════════════════════════════════════════════════════════════════════


class CloudFunctionScanner:
    """Detecta endpoints administrativos de Cloud Functions expostos.

    Testes realizados:
    1. Azure Functions admin endpoints (/admin/host/*)
    2. Azure Durable Functions runtime (/runtime/webhooks/*)
    3. AWS Lambda & API Gateway system paths
    4. GCP Cloud Functions metadata
    5. Cloud provider fingerprinting via headers/errors
    6. Function code/key enumeration
    """

    # Azure Functions admin paths
    AZURE_ADMIN_PATHS = [
        "/admin/host/ping",
        "/admin/host/status",
        "/admin/host/keys",
        "/admin/host/systemkeys",
        "/admin/functions",
        "/admin/extensions",
        "/runtime/webhooks/durabletask/instances",
        "/runtime/webhooks/durabletask/orchestrations",
    ]

    # AWS Lambda / API Gateway paths
    AWS_PATHS = [
        "/.well-known/openid-configuration",
        "/api/health",
        "/api/status",
        "/restapis",
        "/stages",
        "/@connections",
    ]

    # GCP Cloud Functions paths
    GCP_PATHS = [
        "/robots.txt",
        "/_ah/health",
        "/_ah/warmup",
        "/_ah/start",
    ]

    # Common config/debug paths
    CONFIG_PATHS = [
        "/swagger/v1/swagger.json",
        "/swagger",
        "/api/swagger.json",
        "/api/openapi.json",
        "/api/debug",
        "/api/config",
        "/api/test",
        "/api/diagnostics",
        "/api/health",
        "/api/status",
        "/api/version",
        "/api/ping",
        "/.env",
        "/web.config",
        "/host.json",
        "/local.settings.json",
        "/appsettings.json",
        "/.git/HEAD",
        "/.git/config",
        "/favicon.ico",
    ]

    def __init__(self, http: APISecurityHTTP):
        self.http = http
        self.findings: List[APISecurityFinding] = []

    async def scan_cloud_admin(
        self,
        base_url: str,
        function_code: Optional[str] = None,
    ) -> List[APISecurityFinding]:
        """Enumera endpoints administrativos de Cloud Functions."""
        findings = []
        base = base_url.rstrip("/").rsplit("/api", 1)[0]  # Strip /api suffix

        logger.info("Scanning cloud function admin endpoints...")

        # Phase 1: Probe all admin paths
        for path in self.AZURE_ADMIN_PATHS + self.AWS_PATHS + self.GCP_PATHS:
            url = f"{base}{path}"
            resp = await self.http.request("GET", url)
            status = resp.get("status", 0)
            body = resp.get("body", "")

            if status == 0:
                continue

            if status == 200:
                findings.append(
                    APISecurityFinding(
                        title=f"Cloud Admin Endpoint Exposed — {path}",
                        category=APIVulnCategory.SECURITY_MISCONFIG,
                        severity=APISeverity.CRITICAL,
                        endpoint=path,
                        method="GET",
                        description=(
                            f"Administrative endpoint {path} is accessible without "
                            "authentication (HTTP 200). This exposes internal cloud "
                            "function management capabilities."
                        ),
                        impact=(
                            "Attacker can probe internal infrastructure, enumerate "
                            "functions, and potentially extract management keys."
                        ),
                        evidence=f"GET {url} → {status}\n{body[:500]}",
                        remediation=(
                            "1. Block admin paths at WAF/CDN level\n"
                            "2. Move admin endpoints to private VNET\n"
                            "3. Implement IP whitelist for admin access\n"
                            "4. Disable unnecessary admin endpoints"
                        ),
                        cwe_id=200,
                        cvss_score=8.6,
                        owasp_ref="A05:2021 — Security Misconfiguration",
                        is_confirmed=True,
                        request_dump=f"GET {url}",
                        response_dump=f"HTTP {status}\n{body[:1000]}",
                    )
                )
            elif status in (401, 403):
                # Endpoint exists but requires auth — still info leak
                severity = APISeverity.MEDIUM if "/admin/" in path else APISeverity.LOW
                findings.append(
                    APISecurityFinding(
                        title=f"Cloud Admin Endpoint Detected — {path}",
                        category=APIVulnCategory.SECURITY_MISCONFIG,
                        severity=severity,
                        endpoint=path,
                        method="GET",
                        description=(
                            f"Administrative endpoint {path} exists (HTTP {status}). "
                            "While authentication is required, the endpoint's existence "
                            "confirms cloud provider and enables targeted attacks."
                        ),
                        impact="Infrastructure fingerprinting and attack surface enumeration.",
                        evidence=f"GET {url} → {status}\n{body[:200]}",
                        remediation=(
                            "1. Return 404 for admin paths from public internet\n"
                            "2. Use network-level access control"
                        ),
                        cwe_id=200,
                        cvss_score=5.3 if "/admin/" in path else 3.0,
                        owasp_ref="A05:2021 — Security Misconfiguration",
                        is_confirmed=True,
                    )
                )

        # Phase 2: Test function code escalation
        if function_code:
            logger.info("Testing function code privilege escalation...")
            admin_with_code = [
                "/admin/host/status",
                "/admin/host/keys",
                "/admin/functions",
                "/runtime/webhooks/durabletask/instances",
            ]
            for path in admin_with_code:
                url = f"{base}{path}?code={function_code}"
                resp = await self.http.request("GET", url)
                status = resp.get("status", 0)

                if status == 200:
                    findings.append(
                        APISecurityFinding(
                            title=f"Function Code Escalates to Admin — {path}",
                            category=APIVulnCategory.BFLA,
                            severity=APISeverity.CRITICAL,
                            endpoint=path,
                            method="GET",
                            description=(
                                f"Function-level code grants access to admin endpoint {path}. "
                                "This is a privilege escalation from function-level to host-level."
                            ),
                            impact="Full admin access to cloud function management.",
                            evidence=f"GET {url} → {status}",
                            remediation="Require separate admin/master key for admin endpoints.",
                            cwe_id=269,
                            cvss_score=9.1,
                            owasp_ref="A01:2021 — Broken Access Control",
                            is_confirmed=True,
                        )
                    )
                elif status == 403:
                    # Function code recognized but insufficient — partial info
                    pass  # Logged in admin scan but not a separate finding

        # Phase 3: Config file exposure
        logger.info("Scanning configuration files...")
        for path in self.CONFIG_PATHS:
            url = f"{base}{path}"
            resp = await self.http.request("GET", url)
            status = resp.get("status", 0)
            body = resp.get("body", "")

            if status == 200 and len(body) > 10:
                content_type = resp.get("content_type", "")
                # Skip generic HTML error pages
                if "<html" in body.lower() and "404" in body.lower():
                    continue

                sev = APISeverity.HIGH
                if path in ("/robots.txt", "/favicon.ico"):
                    sev = APISeverity.INFO

                findings.append(
                    APISecurityFinding(
                        title=f"Configuration File Exposed — {path}",
                        category=APIVulnCategory.SENSITIVE_DATA_EXPOSURE,
                        severity=sev,
                        endpoint=path,
                        method="GET",
                        description=f"File {path} is publicly accessible.",
                        impact="May expose internal configuration, credentials, or API structure.",
                        evidence=f"GET {url} → {status}\nContent: {body[:300]}",
                        cwe_id=538,
                        cvss_score=7.5 if sev == APISeverity.HIGH else 2.0,
                        owasp_ref="A05:2021 — Security Misconfiguration",
                        is_confirmed=True,
                    )
                )

        self.findings.extend(findings)
        return findings

    async def scan_cloud_fingerprint(
        self,
        base_url: str,
    ) -> List[APISecurityFinding]:
        """Fingerprint cloud provider via response headers and errors."""
        findings = []
        base = base_url.rstrip("/").rsplit("/api", 1)[0]

        resp = await self.http.request("GET", f"{base}/nonexistent-{int(time.time())}")
        headers = resp.get("headers", {})
        body = resp.get("body", "")

        provider_hints = []

        # Check headers
        server = ""
        for k, v in headers.items():
            kl = k.lower()
            if kl == "server":
                server = v
            if "x-azure" in kl or "x-ms-" in kl:
                provider_hints.append(f"Azure: header {k}={v}")
            if "x-amz" in kl or "x-amzn" in kl:
                provider_hints.append(f"AWS: header {k}={v}")
            if "x-cloud-trace" in kl or "x-goog" in kl:
                provider_hints.append(f"GCP: header {k}={v}")
            if kl == "cf-ray":
                provider_hints.append(f"Cloudflare CDN: {k}={v}")

        # Check body for .NET/Azure patterns
        if "Microsoft.AspNetCore" in body or ".NET" in body:
            provider_hints.append("Runtime: .NET/ASP.NET Core")
        if "Azure" in body:
            provider_hints.append("Provider: Azure")

        if provider_hints:
            findings.append(
                APISecurityFinding(
                    title="Cloud Provider Fingerprinted",
                    category=APIVulnCategory.SENSITIVE_DATA_EXPOSURE,
                    severity=APISeverity.INFO,
                    endpoint="/",
                    method="GET",
                    description=f"Cloud infrastructure identified: {'; '.join(provider_hints)}",
                    impact="Enables targeted attacks against specific cloud platform.",
                    evidence="\n".join(provider_hints),
                    cwe_id=200,
                    cvss_score=2.0,
                    owasp_ref="A05:2021 — Security Misconfiguration",
                    is_confirmed=True,
                )
            )

        self.findings.extend(findings)
        return findings


# ════════════════════════════════════════════════════════════════════════════
# JWT ADVANCED SCANNER — Kid Injection, Key Confusion, Claim Manipulation
# ════════════════════════════════════════════════════════════════════════════


class JWTAdvancedScanner:
    """Testes avançados de JWT além do basico (alg:none, expired, weak key).

    Ataques cobertos:
    1. JWT Kid header injection (path traversal, SQL injection, arbitrary value)
    2. HMAC key confusion (symmetric key in client)
    3. JWK/JKU/X5U header injection (remote key fetch)
    4. Audience confusion (dual provider, multi-audience)
    5. Claim type confusion (array roles, object payloads)
    6. Algorithm downgrade with signed tokens
    """

    COMMON_SECRETS = [
        "secret",
        "password",
        "123456",
        "changeme",
        "jwt-secret",
        "your-256-bit-secret",
        "supersecret",
        "key",
        "test",
        "letmein",
        "admin",
        "default",
        "api-secret-key",
    ]

    KID_PAYLOADS = [
        "1",
        "0",
        "default",
        "primary",
        "master",
        "signing-key",
        "jwt-key",
        "null",
        "undefined",
        "",
        "/dev/null",
        "../../../dev/null",
        "key1",
        "hmac-key",
        "HS256",
        "' OR '1'='1",
        "' UNION SELECT 'secret' --",
        "../../../../../../etc/passwd",
    ]

    def __init__(self, http: APISecurityHTTP):
        self.http = http
        self.findings: List[APISecurityFinding] = []

    @staticmethod
    def _b64u_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    @staticmethod
    def _b64u_decode(s: str) -> bytes:
        padding = 4 - len(s) % 4
        return base64.urlsafe_b64decode(s + "=" * padding)

    def _forge_jwt(
        self,
        header: dict,
        payload: dict,
        secret: str = "",
        alg: Optional[str] = None,
    ) -> str:
        """Forge a JWT token with given header, payload, and secret."""
        if alg:
            header = dict(header)
            header["alg"] = alg

        h = self._b64u_encode(json.dumps(header, separators=(",", ":")).encode())
        p = self._b64u_encode(json.dumps(payload, separators=(",", ":")).encode())
        msg = f"{h}.{p}".encode()

        actual_alg = header.get("alg", "none").upper()

        if actual_alg == "NONE":
            return f"{h}.{p}."
        elif actual_alg.startswith("HS"):
            hash_func = {
                "HS256": hashlib.sha256,
                "HS384": hashlib.sha384,
                "HS512": hashlib.sha512,
            }.get(actual_alg, hashlib.sha256)
            sig = hmac.new(secret.encode(), msg, hash_func).digest()
            return f"{h}.{p}.{self._b64u_encode(sig)}"
        else:
            return f"{h}.{p}."

    def _decode_jwt(self, token: str) -> Tuple[dict, dict]:
        """Decode JWT header and payload without validation."""
        parts = token.split(".")
        if len(parts) < 2:
            raise ValueError("Invalid JWT")
        header = json.loads(self._b64u_decode(parts[0]))
        payload = json.loads(self._b64u_decode(parts[1]))
        return header, payload

    async def _send_jwt(
        self,
        base_url: str,
        token: str,
        endpoint: str = "",
        jwt_location: str = "header",
        jwt_field: str = "Jwt",
        extra_body: Optional[dict] = None,
    ) -> Dict[str, Any]:
        """Send a request with a JWT token.

        Supports:
        - header: Authorization: Bearer <token>
        - body: JSON body with jwt_field
        - query: ?token=<token>
        """
        url = base_url.rstrip("/")
        if endpoint:
            url = f"{url}/{endpoint.lstrip('/')}"

        if jwt_location == "header":
            resp = await self.http.request(
                "GET", url, headers={"Authorization": f"Bearer {token}"}
            )
        elif jwt_location == "body":
            body = extra_body or {}
            body[jwt_field] = token
            resp = await self.http.request("POST", url, json_data=body)
        elif jwt_location == "query":
            sep = "&" if "?" in url else "?"
            resp = await self.http.request("GET", f"{url}{sep}token={token}")
        else:
            resp = await self.http.request(
                "GET", url, headers={"Authorization": f"Bearer {token}"}
            )

        return resp

    def _classify_response(self, resp: Dict[str, Any]) -> str:
        """Classify JWT validation response into error categories."""
        body = resp.get("body", "")
        status = resp.get("status", 0)

        if status == 200:
            return "ACCEPTED"
        if "IDX10214" in body:
            return "AUD_FAIL"  # Signature passed, audience failed
        if "IDX10503" in body:
            return "SIG_FAIL"  # Signature validation failed
        if "IDX10504" in body:
            return "NO_SIG"  # No signature (alg:none etc)
        if "IDX10205" in body:
            return "ISS_FAIL"  # Issuer validation failed
        if "IDX10206" in body:
            return "NO_AUD"  # No audience claim
        if "IDX12741" in body:
            return "MALFORMED"  # Malformed JWT
        if "ValidationException" in body:
            return "BIZ_LOGIC"  # Passed JWT, hit business validation
        if status == 401:
            return "UNAUTH"
        if status == 403:
            return "FORBIDDEN"
        return f"OTHER_{status}"

    async def scan_kid_injection(
        self,
        base_url: str,
        token: Optional[str] = None,
        signing_key: Optional[str] = None,
        jwt_location: str = "header",
        jwt_field: str = "Jwt",
        extra_body: Optional[dict] = None,
        test_endpoint: str = "",
    ) -> List[APISecurityFinding]:
        """Test JWT kid header injection attack.

        The kid (Key ID) header hints which key the server should use.
        Some servers accept arbitrary kid values, enabling:
        - Key confusion attacks
        - Path traversal to read files as keys
        - SQL injection in kid lookup
        - Signature bypass
        """
        findings = []

        if not token and not signing_key:
            logger.info("No token or key provided, skipping kid injection test")
            return findings

        # Get baseline claims from existing token or use defaults
        if token:
            header, payload = self._decode_jwt(token)
        else:
            header = {"alg": "HS256", "typ": "JWT"}
            payload = {
                "sub": "test",
                "iss": "test-issuer",
                "aud": "test-audience",
                "exp": int(time.time()) + 3600,
                "iat": int(time.time()),
            }

        secret = signing_key or "secret"
        baseline_alg = header.get("alg", "HS256")

        # Test 1: Baseline without kid
        no_kid_header = {k: v for k, v in header.items() if k != "kid"}
        no_kid_token = self._forge_jwt(no_kid_header, payload, secret)
        no_kid_resp = await self._send_jwt(
            base_url, no_kid_token, test_endpoint, jwt_location, jwt_field, extra_body
        )
        no_kid_class = self._classify_response(no_kid_resp)

        # Test 2: Each kid payload
        kid_successes = []
        kid_anomalies = []

        for kid_val in self.KID_PAYLOADS:
            kid_header = dict(header)
            kid_header["kid"] = kid_val
            kid_token = self._forge_jwt(kid_header, payload, secret)
            kid_resp = await self._send_jwt(
                base_url, kid_token, test_endpoint, jwt_location, jwt_field, extra_body
            )
            kid_class = self._classify_response(kid_resp)

            if kid_class == "ACCEPTED":
                kid_successes.append(kid_val)
            elif kid_class != no_kid_class:
                kid_anomalies.append((kid_val, kid_class, no_kid_class))

        # Analyze results
        if kid_successes:
            findings.append(
                APISecurityFinding(
                    title="JWT Kid Header Injection — Authentication Bypass",
                    category=APIVulnCategory.JWT_VULNERABILITY,
                    severity=APISeverity.CRITICAL,
                    endpoint=test_endpoint or base_url,
                    method="POST" if jwt_location == "body" else "GET",
                    description=(
                        f"Adding kid header values to JWT causes the server to accept "
                        f"the token. Successful kid values: {kid_successes[:5]}"
                    ),
                    impact=(
                        "Complete authentication bypass. Attacker can forge JWT tokens "
                        "for any user by adding a kid header."
                    ),
                    evidence=(
                        f"Without kid: {no_kid_class}\n"
                        f"With kid={kid_successes[0]!r}: ACCEPTED\n"
                        f"Total kid values that bypass: {len(kid_successes)}"
                    ),
                    remediation=(
                        "1. Validate kid against a strict allowlist\n"
                        "2. Reject tokens with unexpected kid values\n"
                        "3. Use asymmetric keys (RS256/ES256)\n"
                        "4. Never use kid for file path or SQL queries"
                    ),
                    cwe_id=347,
                    cvss_score=9.8,
                    owasp_ref="A02:2021 — Cryptographic Failures",
                    is_confirmed=True,
                )
            )

        if kid_anomalies:
            # Kid changes validation behavior — indicates key confusion
            sig_bypass = [
                a for a in kid_anomalies if a[1] == "AUD_FAIL" and a[2] == "SIG_FAIL"
            ]
            if sig_bypass:
                findings.append(
                    APISecurityFinding(
                        title="JWT Kid Header — Signature Validation Bypass",
                        category=APIVulnCategory.JWT_VULNERABILITY,
                        severity=APISeverity.CRITICAL,
                        endpoint=test_endpoint or base_url,
                        method="POST" if jwt_location == "body" else "GET",
                        description=(
                            f"Adding kid header changes error from signature failure "
                            f"to audience failure, proving signature validation PASSES "
                            f"with the provided key when kid is present. "
                            f"Kid values that bypass signature: "
                            f"{[a[0] for a in sig_bypass][:10]}"
                        ),
                        impact=(
                            "The signing key is confirmed correct. With the right "
                            "audience claim, full JWT forgery is possible — enabling "
                            "impersonation of any user including administrators."
                        ),
                        evidence=(
                            f"Without kid: {sig_bypass[0][2]} (signature fails)\n"
                            f"With kid={sig_bypass[0][0]!r}: {sig_bypass[0][1]} "
                            f"(signature passes, audience fails)\n"
                            f"Key used: {secret[:8]}{'*' * max(0, len(secret)-8)}\n"
                            f"Total kid values that pass signature: {len(sig_bypass)}"
                        ),
                        remediation=(
                            "1. Rotate signing key immediately\n"
                            "2. Remove signing key from client applications\n"
                            "3. Migrate to asymmetric signing (RS256)\n"
                            "4. Implement strict kid validation"
                        ),
                        cwe_id=347,
                        cvss_score=9.8,
                        owasp_ref="A02:2021 — Cryptographic Failures",
                        is_confirmed=True,
                    )
                )

            # Check for other anomalies
            other_anomalies = [a for a in kid_anomalies if a[1] not in ("AUD_FAIL",)]
            if other_anomalies:
                findings.append(
                    APISecurityFinding(
                        title="JWT Kid Header — Behavioral Anomaly Detected",
                        category=APIVulnCategory.JWT_VULNERABILITY,
                        severity=APISeverity.MEDIUM,
                        endpoint=test_endpoint or base_url,
                        method="POST" if jwt_location == "body" else "GET",
                        description=(
                            f"Kid header values cause unexpected validation behavior "
                            f"changes: {[(a[0], a[1]) for a in other_anomalies][:5]}"
                        ),
                        impact="May indicate key confusion or injection vulnerability.",
                        evidence=str(other_anomalies[:5]),
                        cwe_id=287,
                        cvss_score=6.5,
                        owasp_ref="A07:2021 — Identification and Authentication Failures",
                        is_confirmed=True,
                    )
                )

        self.findings.extend(findings)
        return findings

    async def scan_audience_confusion(
        self,
        base_url: str,
        token: Optional[str] = None,
        signing_key: Optional[str] = None,
        audiences_to_test: Optional[List[str]] = None,
        jwt_location: str = "header",
        jwt_field: str = "Jwt",
        extra_body: Optional[dict] = None,
        test_endpoint: str = "",
    ) -> List[APISecurityFinding]:
        """Test for dual/multi provider audience confusion.

        Some servers have multiple JWT validation configurations triggered
        by different audience values. This can lead to:
        - Token confusion between providers
        - Signature bypass via wrong provider
        - Privilege escalation via audience switching
        """
        findings = []

        if not signing_key:
            return findings

        if token:
            header, payload = self._decode_jwt(token)
        else:
            header = {"alg": "HS256", "typ": "JWT", "kid": "1"}
            payload = {
                "sub": "test",
                "iss": "test-issuer",
                "exp": int(time.time()) + 3600,
                "iat": int(time.time()),
            }

        # Default test audiences
        if not audiences_to_test:
            audiences_to_test = [
                "test-audience",
                "https://localhost",
                "api://default",
                "self",
                "*",
            ]

        baseline_aud = payload.get("aud", "test-audience")
        results = {}

        for aud in audiences_to_test:
            test_payload = dict(payload)
            test_payload["aud"] = aud
            kid_header = dict(header)
            if "kid" not in kid_header:
                kid_header["kid"] = "1"

            test_token = self._forge_jwt(kid_header, test_payload, signing_key)
            resp = await self._send_jwt(
                base_url, test_token, test_endpoint, jwt_location, jwt_field, extra_body
            )
            classification = self._classify_response(resp)
            results[aud] = classification

        # Analyze for confusion — different audiences hitting different validators
        classifications = set(results.values())
        if len(classifications) > 1:
            # Different audiences cause different code paths
            aud_groups: Dict[str, List[str]] = {}
            for aud, cls in results.items():
                aud_groups.setdefault(cls, []).append(aud)

            if "SIG_FAIL" in aud_groups and "AUD_FAIL" in aud_groups:
                findings.append(
                    APISecurityFinding(
                        title="JWT Dual Provider — Audience-Based Token Confusion",
                        category=APIVulnCategory.JWT_VULNERABILITY,
                        severity=APISeverity.HIGH,
                        endpoint=test_endpoint or base_url,
                        method="POST" if jwt_location == "body" else "GET",
                        description=(
                            "Different audience values trigger different JWT validation "
                            "configurations with different signing keys. Audiences causing "
                            f"signature failure (different key): {aud_groups['SIG_FAIL'][:5]}. "
                            f"Audiences causing audience failure (same key): {aud_groups['AUD_FAIL'][:5]}."
                        ),
                        impact=(
                            "Multiple JWT validation configurations indicate multiple "
                            "auth providers. An attacker may exploit confusion between "
                            "providers to bypass authentication."
                        ),
                        evidence=json.dumps(results, indent=2)[:2000],
                        remediation=(
                            "1. Use distinct endpoints for each auth provider\n"
                            "2. Don't use audience claim to select validation config\n"
                            "3. Validate provider identity explicitly\n"
                            "4. Use unique issuer+audience pairs per provider"
                        ),
                        cwe_id=287,
                        cvss_score=7.2,
                        owasp_ref="A07:2021 — Identification and Authentication Failures",
                        is_confirmed=True,
                    )
                )

            if "ACCEPTED" in aud_groups:
                findings.append(
                    APISecurityFinding(
                        title="JWT Audience Bypass — Valid Audience Discovered",
                        category=APIVulnCategory.JWT_VULNERABILITY,
                        severity=APISeverity.CRITICAL,
                        endpoint=test_endpoint or base_url,
                        method="POST" if jwt_location == "body" else "GET",
                        description=(
                            f"Valid audience value(s) found: {aud_groups['ACCEPTED']}. "
                            "Token is fully accepted by the server."
                        ),
                        impact="Complete JWT forgery possible — any account can be impersonated.",
                        evidence=f"Accepted audiences: {aud_groups['ACCEPTED']}",
                        cwe_id=287,
                        cvss_score=9.8,
                        owasp_ref="A02:2021 — Cryptographic Failures",
                        is_confirmed=True,
                    )
                )

        self.findings.extend(findings)
        return findings

    async def scan_hardcoded_key(
        self,
        base_url: str,
        candidate_keys: Optional[List[str]] = None,
        jwt_location: str = "header",
        jwt_field: str = "Jwt",
        extra_body: Optional[dict] = None,
        test_endpoint: str = "",
    ) -> List[APISecurityFinding]:
        """Test if any common/extracted keys are the signing key.

        Uses behavioral difference detection: if a key is correct,
        the error typically advances to the next validation stage
        (e.g., from signature fail to audience fail).
        """
        findings = []
        keys = candidate_keys or self.COMMON_SECRETS

        header = {"alg": "HS256", "typ": "JWT", "kid": "1"}
        payload = {
            "sub": "test",
            "iss": "test-issuer",
            "aud": "test-audience",
            "exp": int(time.time()) + 3600,
            "iat": int(time.time()),
        }

        # Establish baseline with obviously wrong key
        wrong_token = self._forge_jwt(header, payload, "definitely-wrong-key-12345")
        wrong_resp = await self._send_jwt(
            base_url, wrong_token, test_endpoint, jwt_location, jwt_field, extra_body
        )
        wrong_class = self._classify_response(wrong_resp)

        confirmed_keys = []
        for key in keys:
            test_token = self._forge_jwt(header, payload, key)
            resp = await self._send_jwt(
                base_url, test_token, test_endpoint, jwt_location, jwt_field, extra_body
            )
            cls = self._classify_response(resp)

            if cls == "ACCEPTED":
                confirmed_keys.append(key)
            elif cls != wrong_class and cls in ("AUD_FAIL", "ISS_FAIL", "BIZ_LOGIC"):
                # Error advanced past signature — key is correct!
                confirmed_keys.append(key)

        if confirmed_keys:
            findings.append(
                APISecurityFinding(
                    title="JWT Signing Key Discovered — Token Forgery Possible",
                    category=APIVulnCategory.JWT_VULNERABILITY,
                    severity=APISeverity.CRITICAL,
                    endpoint=test_endpoint or base_url,
                    method="POST" if jwt_location == "body" else "GET",
                    description=(
                        f"JWT signing key(s) confirmed: "
                        f"{[k[:8] + '***' for k in confirmed_keys]}. "
                        "The key was found via behavioral difference in error responses."
                    ),
                    impact=(
                        "Attacker can forge valid JWT tokens, impersonate any user, "
                        "and escalate privileges to admin."
                    ),
                    evidence=(
                        f"Baseline (wrong key): {wrong_class}\n"
                        f"Correct key(s): {[k[:8] + '***' for k in confirmed_keys]} "
                        f"→ error advances past signature validation"
                    ),
                    remediation=(
                        "1. Rotate signing key immediately\n"
                        "2. Use asymmetric signing (RS256)\n"
                        "3. Store key in secure vault\n"
                        "4. Remove key from client applications"
                    ),
                    cwe_id=798,
                    cvss_score=9.8,
                    owasp_ref="A02:2021 — Cryptographic Failures",
                    is_confirmed=True,
                )
            )

        self.findings.extend(findings)
        return findings


# ════════════════════════════════════════════════════════════════════════════
# CORS & HEADER ADVANCED SCANNER
# ════════════════════════════════════════════════════════════════════════════


class CORSAdvancedScanner:
    """Advanced CORS and security header analysis.

    Beyond basic CORS checks:
    1. HTTP downgrade reflection (http:// origin on https:// API)
    2. Subdomain wildcard matching
    3. Null origin reflection
    4. Preflight bypass
    5. Security header compliance audit
    """

    REQUIRED_HEADERS = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Strict-Transport-Security": None,  # Any value
        "Content-Security-Policy": None,
        "Referrer-Policy": None,
        "X-XSS-Protection": None,
    }

    def __init__(self, http: APISecurityHTTP):
        self.http = http
        self.findings: List[APISecurityFinding] = []

    async def scan_cors_advanced(
        self,
        base_url: str,
        domain: Optional[str] = None,
        endpoints: Optional[List[str]] = None,
    ) -> List[APISecurityFinding]:
        """Deep CORS policy analysis."""
        findings = []
        test_url = base_url.rstrip("/")

        # Extract domain from URL if not provided
        if not domain:
            from urllib.parse import urlparse

            parsed = urlparse(base_url)
            domain = parsed.hostname or "example.com"

        test_origins = [
            (f"https://{domain}", "legitimate HTTPS", False),
            (f"http://{domain}", "HTTP downgrade", True),
            (f"https://www.{domain}", "www subdomain", False),
            (f"https://evil.{domain}", "subdomain takeover", True),
            (f"https://{domain}.evil.com", "suffix match bypass", True),
            ("https://evil.com", "arbitrary origin", True),
            ("null", "null origin", True),
            ("https://localhost", "localhost", True),
            ("http://localhost:3000", "dev localhost", True),
            ("", "empty origin", False),
        ]

        reflected_dangerous = []

        for origin, label, is_dangerous in test_origins:
            headers = {"Origin": origin} if origin else {}
            resp = await self.http.request("POST", test_url, headers=headers)
            resp_headers = resp.get("headers", {})

            acao = ""
            acac = ""
            for k, v in resp_headers.items():
                if k.lower() == "access-control-allow-origin":
                    acao = v
                if k.lower() == "access-control-allow-credentials":
                    acac = v

            if acao and acao == origin and is_dangerous:
                reflected_dangerous.append((origin, label, acac))

        if reflected_dangerous:
            for origin, label, acac in reflected_dangerous:
                severity = APISeverity.HIGH
                cvss = 7.5

                if origin.startswith("http://") and not origin.startswith(
                    "http://localhost"
                ):
                    # HTTP downgrade is particularly dangerous
                    severity = APISeverity.HIGH
                    cvss = 7.5
                    desc = (
                        f"CORS reflects HTTP origin ({origin}), enabling MitM "
                        "to intercept and replay API requests via JavaScript injection."
                    )
                elif origin == "null":
                    severity = APISeverity.HIGH
                    cvss = 7.0
                    desc = (
                        "CORS reflects null origin, exploitable via sandboxed iframes."
                    )
                elif "evil" in origin:
                    severity = APISeverity.CRITICAL
                    cvss = 9.1
                    desc = f"CORS reflects arbitrary/malicious origin: {origin}"
                else:
                    severity = APISeverity.MEDIUM
                    cvss = 5.0
                    desc = f"CORS reflects potentially untrusted origin: {origin} ({label})"

                findings.append(
                    APISecurityFinding(
                        title=f"CORS Misconfiguration — {label}",
                        category=APIVulnCategory.CORS_MISCONFIG,
                        severity=severity,
                        endpoint=test_url,
                        method="POST",
                        description=desc,
                        impact=(
                            "Cross-origin requests from untrusted origins are allowed, "
                            "enabling data exfiltration and CSRF attacks."
                        ),
                        evidence=(
                            f"Origin: {origin}\n"
                            f"ACAO: {origin}\n"
                            f"ACAC: {acac or 'not set'}"
                        ),
                        remediation=(
                            "1. Whitelist only specific trusted HTTPS origins\n"
                            "2. Never reflect HTTP origins on HTTPS APIs\n"
                            "3. Do not reflect 'null' origin\n"
                            "4. Validate origin against exact match, not prefix/suffix"
                        ),
                        cwe_id=346,
                        cvss_score=cvss,
                        owasp_ref="A05:2021 — Security Misconfiguration",
                        is_confirmed=True,
                    )
                )

        self.findings.extend(findings)
        return findings

    async def scan_security_headers(
        self,
        base_url: str,
        endpoints: Optional[List[str]] = None,
    ) -> List[APISecurityFinding]:
        """Audit security header compliance across endpoints."""
        findings = []
        urls = [base_url.rstrip("/")]
        if endpoints:
            base = base_url.rstrip("/")
            urls.extend(f"{base}/{ep.lstrip('/')}" for ep in endpoints[:5])

        all_missing: Dict[str, List[str]] = {}

        for url in urls:
            resp = await self.http.request("POST", url)
            resp_headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}

            missing = []
            for header, expected in self.REQUIRED_HEADERS.items():
                hl = header.lower()
                if hl not in resp_headers:
                    missing.append(header)
                elif expected and resp_headers[hl] != expected:
                    missing.append(f"{header} (wrong value: {resp_headers[hl]})")

            if missing:
                all_missing[url] = missing

            # Check for info leak headers
            server = resp_headers.get("server", "")
            if server:
                findings.append(
                    APISecurityFinding(
                        title=f"Server Header Information Disclosure — {server}",
                        category=APIVulnCategory.SENSITIVE_DATA_EXPOSURE,
                        severity=APISeverity.LOW,
                        endpoint=url,
                        method="POST",
                        description=f"Server header reveals technology: {server}",
                        impact="Enables targeted attacks against specific server technology.",
                        evidence=f"Server: {server}",
                        cwe_id=200,
                        cvss_score=2.0,
                        owasp_ref="A05:2021 — Security Misconfiguration",
                        is_confirmed=True,
                    )
                )
                break  # Only report once

        if all_missing:
            # Consolidate missing headers across endpoints
            common_missing = set()
            for missing_list in all_missing.values():
                common_missing.update(missing_list)

            if common_missing:
                findings.append(
                    APISecurityFinding(
                        title="Security Headers Missing Across API",
                        category=APIVulnCategory.SECURITY_MISCONFIG,
                        severity=APISeverity.LOW,
                        endpoint="ALL",
                        method="*",
                        description=(
                            f"Missing security headers: {', '.join(sorted(common_missing))}"
                        ),
                        impact=(
                            "Missing headers leave users vulnerable to clickjacking, "
                            "MIME sniffing, XSS, and protocol downgrade attacks."
                        ),
                        evidence=json.dumps(
                            {
                                url: missing
                                for url, missing in list(all_missing.items())[:3]
                            },
                            indent=2,
                        ),
                        remediation=(
                            "Add the following headers to all API responses:\n"
                            "- X-Content-Type-Options: nosniff\n"
                            "- X-Frame-Options: DENY\n"
                            "- Strict-Transport-Security: max-age=31536000\n"
                            "- Content-Security-Policy: default-src 'self'\n"
                            "- Referrer-Policy: strict-origin-when-cross-origin"
                        ),
                        cwe_id=693,
                        cvss_score=3.7,
                        owasp_ref="A05:2021 — Security Misconfiguration",
                        is_confirmed=True,
                    )
                )

        self.findings.extend(findings)
        return findings


# ════════════════════════════════════════════════════════════════════════════
# JSON INTEROPERABILITY & HEADER INJECTION SCANNER
# ════════════════════════════════════════════════════════════════════════════


class JSONInteropScanner:
    """Tests JSON parsing quirks and header injection attacks.

    Attacks:
    1. Duplicate key handling (first vs last wins)
    2. Prototype pollution (__proto__, constructor)
    3. Type confusion (array body, null values)
    4. Unicode key obfuscation
    5. Header injection (Host, X-Forwarded-*, CF-Connecting-IP)
    6. Path manipulation (backslash, null byte, encoding)
    """

    def __init__(self, http: APISecurityHTTP):
        self.http = http
        self.findings: List[APISecurityFinding] = []

    async def scan_json_interop(
        self,
        base_url: str,
        jwt_field: str = "Jwt",
        test_jwt: str = "",
    ) -> List[APISecurityFinding]:
        """Test JSON parsing behavior."""
        findings = []
        url = base_url.rstrip("/")

        test_payloads = [
            (
                "Duplicate keys",
                f'{{{json.dumps(jwt_field)}: "a", {json.dumps(jwt_field)}: "b"}}',
            ),
            (
                "__proto__ pollution",
                f'{{"__proto__": {{"isAdmin": true}}, {json.dumps(jwt_field)}: "{test_jwt}"}}',
            ),
            (
                "constructor pollution",
                f'{{"constructor": {{"prototype": {{"isAdmin": true}}}}, {json.dumps(jwt_field)}: "{test_jwt}"}}',
            ),
            ("Array body", f"[{json.dumps({jwt_field: test_jwt})}]"),
            ("Bool JWT", json.dumps({jwt_field: True})),
            ("Null JWT", json.dumps({jwt_field: None})),
            ("Empty JWT", json.dumps({jwt_field: ""})),
            ("Integer JWT", json.dumps({jwt_field: 12345})),
        ]

        baseline_resp = await self.http.request(
            "POST",
            url,
            headers={"Content-Type": "application/json"},
            data=json.dumps({jwt_field: test_jwt or "invalid"}),
        )
        baseline_body = baseline_resp.get("body", "")

        for label, payload_str in test_payloads:
            resp = await self.http.request(
                "POST",
                url,
                headers={"Content-Type": "application/json"},
                data=payload_str,
            )
            body = resp.get("body", "")
            status = resp.get("status", 0)

            # Check for unexpected behavior
            if status == 500 or "unexpected error" in body.lower():
                findings.append(
                    APISecurityFinding(
                        title=f"JSON Interop — {label} Causes Server Error",
                        category=APIVulnCategory.INJECTION,
                        severity=APISeverity.MEDIUM,
                        endpoint=url,
                        method="POST",
                        description=(
                            f"Sending {label} causes an unexpected server error, "
                            "indicating improper input validation."
                        ),
                        impact="May enable injection or denial of service.",
                        evidence=f"Payload: {payload_str[:200]}\nResponse: [{status}] {body[:300]}",
                        remediation="Validate JSON structure before processing.",
                        cwe_id=20,
                        cvss_score=5.3,
                        owasp_ref="A03:2021 — Injection",
                        is_confirmed=True,
                    )
                )
            elif status == 200:
                findings.append(
                    APISecurityFinding(
                        title=f"JSON Interop — {label} Accepted",
                        category=APIVulnCategory.INJECTION,
                        severity=APISeverity.HIGH,
                        endpoint=url,
                        method="POST",
                        description=f"{label} payload was accepted (HTTP 200).",
                        impact="Unexpected JSON processing may lead to injection.",
                        evidence=f"Payload: {payload_str[:200]}\nResponse: [{status}] {body[:300]}",
                        cwe_id=20,
                        cvss_score=7.5,
                        owasp_ref="A03:2021 — Injection",
                        is_confirmed=True,
                    )
                )

        self.findings.extend(findings)
        return findings

    async def scan_header_injection(
        self,
        base_url: str,
    ) -> List[APISecurityFinding]:
        """Test header injection and IP spoofing attacks."""
        findings = []

        injection_headers = [
            ("X-Forwarded-Host", "evil.com", "Host header injection"),
            ("X-Forwarded-Host", "169.254.169.254", "SSRF via host header"),
            ("X-Original-URL", "/admin/host/status", "URL override"),
            ("X-Rewrite-URL", "/admin/host/keys", "URL rewrite"),
            ("X-Forwarded-For", "127.0.0.1", "IP spoofing (XFF)"),
            ("X-Real-IP", "127.0.0.1", "IP spoofing (X-Real-IP)"),
            ("X-Client-IP", "127.0.0.1", "IP spoofing (X-Client-IP)"),
            ("CF-Connecting-IP", "127.0.0.1", "Cloudflare IP spoofing"),
            ("True-Client-IP", "127.0.0.1", "Cloudflare True-Client-IP"),
            ("Forwarded", "for=127.0.0.1;host=evil.com", "RFC 7239 Forwarded"),
            ("X-Forwarded-Proto", "http", "Protocol downgrade"),
        ]

        for header_name, header_value, label in injection_headers:
            resp = await self.http.request(
                "POST",
                base_url,
                headers={header_name: header_value, "Content-Type": "application/json"},
                data="{}",
            )
            status = resp.get("status", 0)
            body = resp.get("body", "")

            # Check for error code differences (e.g., CF dns_loop)
            if "dns_loop" in body or "error_code" in body:
                findings.append(
                    APISecurityFinding(
                        title=f"Header Injection — {label}",
                        category=APIVulnCategory.SECURITY_MISCONFIG,
                        severity=APISeverity.MEDIUM,
                        endpoint=base_url,
                        method="POST",
                        description=(
                            f"Header {header_name}: {header_value} triggers "
                            f"abnormal response: {body[:200]}"
                        ),
                        impact="Header processing vulnerability — may enable IP spoofing or SSRF.",
                        evidence=f"{header_name}: {header_value} → [{status}] {body[:300]}",
                        remediation=(
                            "1. Strip untrusted proxy headers at CDN/LB level\n"
                            "2. Use trusted proxy configuration\n"
                            "3. Validate CF-Connecting-IP only from Cloudflare IPs"
                        ),
                        cwe_id=113,
                        cvss_score=5.3,
                        owasp_ref="A05:2021 — Security Misconfiguration",
                        is_confirmed=True,
                    )
                )
            elif status == 200:
                findings.append(
                    APISecurityFinding(
                        title=f"Header Injection — {label} Causes 200 OK",
                        category=APIVulnCategory.SECURITY_MISCONFIG,
                        severity=APISeverity.HIGH,
                        endpoint=base_url,
                        method="POST",
                        description=f"Header {header_name}: {header_value} produces 200 response.",
                        impact="Possible access control bypass via header manipulation.",
                        evidence=f"{header_name}: {header_value} → [{status}] {body[:300]}",
                        cwe_id=113,
                        cvss_score=7.5,
                        owasp_ref="A01:2021 — Broken Access Control",
                        is_confirmed=True,
                    )
                )

        self.findings.extend(findings)
        return findings
