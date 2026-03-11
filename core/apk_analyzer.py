#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  📱  SIREN APK ANALYZER — Deep Static Analysis for Android & iOS  📱          ██
██                                                                                ██
██  Analise estatica profunda e completa de APKs e IPAs:                          ██
██    • AndroidManifest.xml audit (permissions, components, intents)              ██
██    • DEX bytecode analysis (strings, crypto, reflection, native)              ██
██    • Certificate & signing validation (v1/v2/v3/v4 schemes)                    ██
██    • WebView security audit (JS interface, file access, mixed content)         ██
██    • Storage analysis (SharedPrefs, SQLite, file I/O, crypto usage)           ██
██    • Network security config (cleartext, cert pinning, trust anchors)         ██
██    • Native library analysis (.so files, JNI, stripped symbols)               ██
██    • Hardcoded secrets detection (keys, tokens, passwords, URLs)              ██
██    • Third-party SDK fingerprinting (trackers, ads, analytics)                ██
██    • ProGuard/R8 obfuscation assessment                                       ██
██    • IPA plist analysis, entitlements, ATS configuration                      ██
██    • OWASP MASVS v2 / MASTG compliance mapping                               ██
██    • CWE classification for every finding                                      ██
██    • Play Store & App Store policy violation detection                         ██
██                                                                                ██
██  "O codigo fala. Nos apenas escutamos cada sussurro."                          ██
██                                                                                ██
████████████████████████████████████████████████████████████████████████████████████
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import enum
import hashlib
import io
import json
import logging
import os
import re
import struct
import tempfile
import time
import xml.etree.ElementTree as ET
import zipfile
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

from .mobile_engine import (
    DANGEROUS_PERMISSIONS,
    OWASP_MOBILE_TOP10,
    APKInfo,
    IPAInfo,
    MobileFinding,
    SecurityLevel,
)

logger = logging.getLogger("siren.apk_analyzer")


# ════════════════════════════════════════════════════════════════════════════
# ENUMS & CONSTANTS
# ════════════════════════════════════════════════════════════════════════════


class AnalysisDepth(enum.Enum):
    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"
    EXHAUSTIVE = "exhaustive"


class ComponentType(enum.Enum):
    ACTIVITY = "activity"
    SERVICE = "service"
    RECEIVER = "receiver"
    PROVIDER = "provider"


# ── Hardcoded secrets patterns ──────────────────────────────────────────
SECRET_PATTERNS: Dict[str, re.Pattern] = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}", re.I),
    "aws_secret_key": re.compile(
        r"(?:aws|amazon).*?(?:secret|key).*?['\"][0-9a-zA-Z/+=]{40}['\"]", re.I
    ),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z_-]{35}", re.I),
    "google_oauth_id": re.compile(
        r"[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com", re.I
    ),
    "firebase_key": re.compile(r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}", re.I),
    "generic_api_key": re.compile(
        r"(?:api[_-]?key|apikey|api_secret)\s*[=:]\s*['\"]([a-zA-Z0-9_\-]{20,})['\"]",
        re.I,
    ),
    "generic_secret": re.compile(
        r"(?:secret|private[_-]?key|client[_-]?secret)\s*[=:]\s*['\"]([a-zA-Z0-9_\-]{20,})['\"]",
        re.I,
    ),
    "generic_password": re.compile(
        r"(?:password|passwd|pwd)\s*[=:]\s*['\"]([^\s'\"]{6,})['\"]", re.I
    ),
    "private_key_pem": re.compile(
        r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", re.I
    ),
    "jwt_token": re.compile(
        r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+"
    ),
    "basic_auth": re.compile(r"Basic\s+[A-Za-z0-9+/=]{20,}"),
    "bearer_token": re.compile(r"Bearer\s+[A-Za-z0-9_\-.~+/]+=*", re.I),
    "slack_token": re.compile(r"xox[bpors]-[0-9]{10,}-[a-zA-Z0-9-]+"),
    "github_token": re.compile(r"gh[ps]_[A-Za-z0-9_]{36,}"),
    "stripe_key": re.compile(r"(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{20,}"),
    "twilio_key": re.compile(r"SK[a-f0-9]{32}"),
    "sendgrid_key": re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"),
    "square_token": re.compile(r"sq0[a-z]{3}-[A-Za-z0-9_-]{22,}"),
    "telegram_bot": re.compile(r"\d{8,10}:[A-Za-z0-9_-]{35}"),
    "heroku_api": re.compile(
        r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"
    ),
    "ip_address_private": re.compile(
        r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
        r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
        r"192\.168\.\d{1,3}\.\d{1,3})\b"
    ),
    "hardcoded_url_with_creds": re.compile(
        r"https?://[^:]+:[^@]+@[a-zA-Z0-9._-]+", re.I
    ),
}

# ── Insecure crypto patterns ───────────────────────────────────────────
INSECURE_CRYPTO_PATTERNS: Dict[str, Tuple[str, str]] = {
    "DES": ("CWE-327", "DES is broken. Use AES-256-GCM."),
    "DESede": ("CWE-327", "3DES is deprecated. Use AES-256-GCM."),
    "RC4": ("CWE-327", "RC4 is broken. Use AES-256-GCM or ChaCha20."),
    "RC2": ("CWE-327", "RC2 is weak. Use AES-256-GCM."),
    "Blowfish": ("CWE-327", "Blowfish has small block size. Use AES-256-GCM."),
    "ECB": ("CWE-327", "ECB mode leaks patterns. Use CBC or GCM."),
    "MD5": ("CWE-328", "MD5 is broken for security. Use SHA-256+."),
    "SHA1": ("CWE-328", "SHA-1 is deprecated. Use SHA-256+."),
    "AES/ECB": ("CWE-327", "AES-ECB leaks patterns. Use AES-GCM."),
    "NoPadding": ("CWE-327", "NoPadding may leak plaintext length."),
    "PKCS1Padding": ("CWE-327", "PKCS1v1.5 is vulnerable to Bleichenbacher. Use OAEP."),
    "Math.random": ("CWE-330", "Math.random() is not cryptographically secure."),
    "java.util.Random": (
        "CWE-330",
        "java.util.Random is predictable. Use SecureRandom.",
    ),
    "SecretKeySpec": ("CWE-321", "Hardcoded key material detected. Use KeyStore."),
}

# ── Tracker SDK signatures ─────────────────────────────────────────────
TRACKER_SIGNATURES: Dict[str, Dict[str, str]] = {
    "com.facebook.": {"name": "Facebook SDK", "category": "analytics"},
    "com.google.firebase.analytics": {
        "name": "Firebase Analytics",
        "category": "analytics",
    },
    "com.google.android.gms.analytics": {
        "name": "Google Analytics",
        "category": "analytics",
    },
    "com.google.android.gms.ads": {"name": "Google AdMob", "category": "ads"},
    "com.appsflyer.": {"name": "AppsFlyer", "category": "attribution"},
    "com.adjust.sdk": {"name": "Adjust", "category": "attribution"},
    "io.branch.": {"name": "Branch", "category": "attribution"},
    "com.crashlytics.": {"name": "Crashlytics", "category": "crash-reporting"},
    "io.sentry.": {"name": "Sentry", "category": "error-tracking"},
    "com.newrelic.": {"name": "New Relic", "category": "monitoring"},
    "com.mixpanel.": {"name": "Mixpanel", "category": "analytics"},
    "com.amplitude.": {"name": "Amplitude", "category": "analytics"},
    "com.segment.": {"name": "Segment", "category": "analytics"},
    "com.appdynamics.": {"name": "AppDynamics", "category": "monitoring"},
    "com.unity3d.ads": {"name": "Unity Ads", "category": "ads"},
    "com.chartboost.": {"name": "Chartboost", "category": "ads"},
    "com.mopub.": {"name": "MoPub", "category": "ads"},
    "com.ironsource.": {"name": "IronSource", "category": "ads"},
    "com.vungle.": {"name": "Vungle", "category": "ads"},
    "com.inmobi.": {"name": "InMobi", "category": "ads"},
    "com.applovin.": {"name": "AppLovin", "category": "ads"},
    "com.braze.": {"name": "Braze", "category": "engagement"},
    "com.onelink.": {"name": "OneLink", "category": "attribution"},
    "com.flurry.": {"name": "Flurry", "category": "analytics"},
    "com.kochava.": {"name": "Kochava", "category": "attribution"},
}

# ── WebView vulnerability patterns ──────────────────────────────────────
WEBVIEW_VULN_PATTERNS: Dict[str, Tuple[str, SecurityLevel, str]] = {
    "setJavaScriptEnabled(true)": (
        "CWE-79",
        SecurityLevel.MEDIUM,
        "JavaScript enabled in WebView — XSS risk via injected content.",
    ),
    "addJavascriptInterface": (
        "CWE-749",
        SecurityLevel.HIGH,
        "JavaScript interface exposed to WebView — RCE risk on API < 17.",
    ),
    "setAllowFileAccess(true)": (
        "CWE-200",
        SecurityLevel.HIGH,
        "WebView file:// access enabled — local file exfiltration risk.",
    ),
    "setAllowFileAccessFromFileURLs(true)": (
        "CWE-200",
        SecurityLevel.CRITICAL,
        "WebView cross-file access — arbitrary file read via file:// XSS.",
    ),
    "setAllowUniversalAccessFromFileURLs(true)": (
        "CWE-200",
        SecurityLevel.CRITICAL,
        "WebView universal file access — full filesystem + network access from file://.",
    ),
    "setAllowContentAccess(true)": (
        "CWE-200",
        SecurityLevel.MEDIUM,
        "WebView content:// access — content provider data leakage.",
    ),
    "setMixedContentMode(0)": (
        "CWE-319",
        SecurityLevel.MEDIUM,
        "WebView allows mixed HTTP/HTTPS content — MITM risk.",
    ),
    "setSavePassword(true)": (
        "CWE-312",
        SecurityLevel.MEDIUM,
        "WebView stores passwords in plaintext autocomplete database.",
    ),
    "setWebContentsDebuggingEnabled(true)": (
        "CWE-489",
        SecurityLevel.HIGH,
        "WebView remote debugging enabled — full inspection/RCE in production.",
    ),
    "onReceivedSslError": (
        "CWE-295",
        SecurityLevel.CRITICAL,
        "Custom SSL error handler detected — may bypass certificate validation.",
    ),
    "shouldOverrideUrlLoading": (
        "CWE-939",
        SecurityLevel.LOW,
        "URL loading override — verify deep link validation.",
    ),
}


# ════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ════════════════════════════════════════════════════════════════════════════


@dataclass
class ManifestAnalysis:
    """Result of AndroidManifest.xml deep analysis."""

    package: str = ""
    version_name: str = ""
    version_code: int = 0
    min_sdk: int = 0
    target_sdk: int = 0
    compile_sdk: int = 0
    permissions_requested: List[str] = field(default_factory=list)
    permissions_defined: List[str] = field(default_factory=list)
    dangerous_permissions: List[str] = field(default_factory=list)
    activities: List[Dict[str, Any]] = field(default_factory=list)
    services: List[Dict[str, Any]] = field(default_factory=list)
    receivers: List[Dict[str, Any]] = field(default_factory=list)
    providers: List[Dict[str, Any]] = field(default_factory=list)
    exported_components: List[Dict[str, Any]] = field(default_factory=list)
    intent_filters: List[Dict[str, Any]] = field(default_factory=list)
    deeplinks: List[str] = field(default_factory=list)
    custom_schemes: List[str] = field(default_factory=list)
    meta_data: Dict[str, str] = field(default_factory=dict)
    features: List[str] = field(default_factory=list)
    libraries: List[str] = field(default_factory=list)
    debuggable: bool = False
    allow_backup: bool = True
    uses_cleartext: bool = False
    test_only: bool = False
    has_network_security_config: bool = False
    backup_agent: str = ""
    large_heap: bool = False
    task_affinity: str = ""
    findings: List[MobileFinding] = field(default_factory=list)


@dataclass
class DexAnalysis:
    """Result of DEX bytecode string analysis."""

    total_classes: int = 0
    total_methods: int = 0
    total_strings: int = 0
    secrets_found: List[Dict[str, Any]] = field(default_factory=list)
    insecure_crypto: List[Dict[str, Any]] = field(default_factory=list)
    webview_issues: List[Dict[str, Any]] = field(default_factory=list)
    native_methods: List[str] = field(default_factory=list)
    reflection_calls: List[str] = field(default_factory=list)
    dynamic_loading: List[str] = field(default_factory=list)
    url_strings: List[str] = field(default_factory=list)
    ip_addresses: List[str] = field(default_factory=list)
    sql_queries: List[str] = field(default_factory=list)
    logging_calls: int = 0
    obfuscation_ratio: float = 0.0
    trackers_found: List[Dict[str, str]] = field(default_factory=list)
    findings: List[MobileFinding] = field(default_factory=list)


@dataclass
class CertificateAnalysis:
    """Result of signing certificate analysis."""

    scheme_versions: List[int] = field(default_factory=list)
    cert_subject: str = ""
    cert_issuer: str = ""
    cert_serial: str = ""
    cert_fingerprint_sha1: str = ""
    cert_fingerprint_sha256: str = ""
    valid_from: str = ""
    valid_to: str = ""
    is_debug_cert: bool = False
    is_self_signed: bool = False
    key_algorithm: str = ""
    key_size: int = 0
    signature_algorithm: str = ""
    findings: List[MobileFinding] = field(default_factory=list)


@dataclass
class NetworkSecurityAnalysis:
    """Result of network security config analysis."""

    has_config: bool = False
    cleartextTrafficPermitted: bool = False
    trust_anchors: List[Dict[str, Any]] = field(default_factory=list)
    domain_configs: List[Dict[str, Any]] = field(default_factory=list)
    cert_pins: List[Dict[str, str]] = field(default_factory=list)
    pin_expiration: str = ""
    debug_overrides: bool = False
    findings: List[MobileFinding] = field(default_factory=list)


@dataclass
class NativeLibAnalysis:
    """Result of native library analysis."""

    libraries: List[Dict[str, Any]] = field(default_factory=list)
    architectures: List[str] = field(default_factory=list)
    has_stripped_symbols: bool = False
    dangerous_imports: List[Dict[str, str]] = field(default_factory=list)
    stack_canary: bool = False
    nx_bit: bool = False
    pie: bool = False
    relro: str = ""
    fortify: bool = False
    findings: List[MobileFinding] = field(default_factory=list)


@dataclass
class StorageAnalysis:
    """Result of data storage pattern analysis."""

    uses_shared_preferences: bool = False
    uses_encrypted_shared_prefs: bool = False
    uses_sqlite: bool = False
    uses_sqlcipher: bool = False
    uses_room: bool = False
    uses_realm: bool = False
    uses_internal_storage: bool = False
    uses_external_storage: bool = False
    uses_keystore: bool = False
    uses_file_provider: bool = False
    clipboard_usage: bool = False
    logging_detected: bool = False
    findings: List[MobileFinding] = field(default_factory=list)


@dataclass
class FullAnalysisResult:
    """Complete static analysis result."""

    apk_info: Optional[APKInfo] = None
    ipa_info: Optional[IPAInfo] = None
    manifest: Optional[ManifestAnalysis] = None
    dex: Optional[DexAnalysis] = None
    certificate: Optional[CertificateAnalysis] = None
    network_security: Optional[NetworkSecurityAnalysis] = None
    native_libs: Optional[NativeLibAnalysis] = None
    storage: Optional[StorageAnalysis] = None
    all_findings: List[MobileFinding] = field(default_factory=list)
    analysis_duration: float = 0.0
    analysis_depth: AnalysisDepth = AnalysisDepth.STANDARD
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    @property
    def severity_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in self.all_findings:
            key = f.severity.value
            counts[key] = counts.get(key, 0) + 1
        return counts

    @property
    def owasp_coverage(self) -> Dict[str, int]:
        cov: Dict[str, int] = {}
        for f in self.all_findings:
            if f.owasp_category:
                cov[f.owasp_category] = cov.get(f.owasp_category, 0) + 1
        return cov


# ════════════════════════════════════════════════════════════════════════════
# BINARY XML PARSER (Android)
# ════════════════════════════════════════════════════════════════════════════


class BinaryXMLParser:
    """Parse Android binary XML (AXML) from APK without external deps.

    Android compiles XML resources into a binary format. This parser
    handles the common cases needed for security analysis.
    """

    # Chunk types
    RES_NULL_TYPE = 0x0000
    RES_STRING_POOL_TYPE = 0x0001
    RES_TABLE_TYPE = 0x0002
    RES_XML_TYPE = 0x0003
    RES_XML_START_NAMESPACE_TYPE = 0x0100
    RES_XML_END_NAMESPACE_TYPE = 0x0101
    RES_XML_START_ELEMENT_TYPE = 0x0102
    RES_XML_END_ELEMENT_TYPE = 0x0103
    RES_XML_CDATA_TYPE = 0x0104

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._strings: List[str] = []
        self._namespaces: Dict[str, str] = {}
        self._events: List[Dict[str, Any]] = []

    def parse(self) -> Optional[ET.Element]:
        """Parse binary XML and return ElementTree root."""
        if len(self._data) < 8:
            return None

        try:
            magic, file_size = struct.unpack_from("<HH I", self._data, 0)
        except struct.error:
            return None

        if magic != self.RES_XML_TYPE:
            # Not binary XML — try as plain text
            try:
                text = self._data.decode("utf-8")
                return ET.fromstring(text)
            except Exception:
                return None

        offset = 8
        while offset < len(self._data) - 4:
            try:
                chunk_type, header_size, chunk_size = struct.unpack_from(
                    "<HH I", self._data, offset
                )
            except struct.error:
                break

            if chunk_size < 8:
                break

            if chunk_type == self.RES_STRING_POOL_TYPE:
                self._parse_string_pool(offset, chunk_size)
            elif chunk_type == self.RES_XML_START_NAMESPACE_TYPE:
                self._parse_namespace(offset)
            elif chunk_type == self.RES_XML_START_ELEMENT_TYPE:
                self._parse_start_element(offset)
            elif chunk_type == self.RES_XML_END_ELEMENT_TYPE:
                self._parse_end_element(offset)

            offset += chunk_size

        return self._build_tree()

    def _parse_string_pool(self, offset: int, chunk_size: int) -> None:
        """Parse string pool chunk."""
        try:
            pool_offset = offset + 8
            (
                string_count,
                style_count,
                flags,
                strings_start,
                styles_start,
            ) = struct.unpack_from("<5I", self._data, pool_offset)

            is_utf8 = (flags & (1 << 8)) != 0
            offsets_start = pool_offset + 20
            abs_strings_start = pool_offset + strings_start + 8 - 8

            for i in range(min(string_count, 10000)):
                str_offset = struct.unpack_from(
                    "<I", self._data, offsets_start + i * 4
                )[0]
                pos = abs_strings_start + str_offset

                if is_utf8:
                    # UTF-8: skip char count, read byte count
                    if pos + 2 > len(self._data):
                        self._strings.append("")
                        continue
                    n = self._data[pos + 1]
                    if n & 0x80:
                        n = ((n & 0x7F) << 8) | self._data[pos + 2]
                        pos += 3
                    else:
                        pos += 2
                    end = pos + n
                    if end > len(self._data):
                        end = len(self._data)
                    self._strings.append(
                        self._data[pos:end].decode("utf-8", errors="replace")
                    )
                else:
                    # UTF-16
                    if pos + 2 > len(self._data):
                        self._strings.append("")
                        continue
                    n = struct.unpack_from("<H", self._data, pos)[0]
                    if n & 0x8000:
                        n = ((n & 0x7FFF) << 16) | struct.unpack_from(
                            "<H", self._data, pos + 2
                        )[0]
                        pos += 4
                    else:
                        pos += 2
                    end = pos + n * 2
                    if end > len(self._data):
                        end = len(self._data)
                    self._strings.append(
                        self._data[pos:end].decode("utf-16-le", errors="replace")
                    )
        except Exception as e:
            logger.debug("String pool parse error: %s", e)

    def _parse_namespace(self, offset: int) -> None:
        """Parse namespace start."""
        try:
            prefix_idx, uri_idx = struct.unpack_from("<II", self._data, offset + 16)
            prefix = self._get_string(prefix_idx)
            uri = self._get_string(uri_idx)
            if prefix and uri:
                self._namespaces[uri] = prefix
        except Exception:
            pass

    def _parse_start_element(self, offset: int) -> None:
        """Parse start element."""
        try:
            (
                ns_idx,
                name_idx,
                attr_start,
                attr_size,
                attr_count,
                id_idx,
                class_idx,
                style_idx,
            ) = struct.unpack_from("<IIHHhHHH", self._data, offset + 16)
            name = self._get_string(name_idx)
            ns = self._get_string(ns_idx)

            attrs: Dict[str, str] = {}
            attr_offset = offset + 16 + attr_start
            for i in range(attr_count):
                a_off = attr_offset + i * (attr_size if attr_size > 0 else 20)
                a_ns, a_name, a_raw, a_type_size, a_type, a_data = struct.unpack_from(
                    "<IIIHbI", self._data, a_off
                )
                attr_name = self._get_string(a_name)
                attr_val = self._get_string(a_raw) if a_raw != 0xFFFFFFFF else ""

                if not attr_val:
                    # Decode typed value
                    val_type = (a_type >> 0) & 0xFF
                    if val_type == 0x03:  # string
                        attr_val = self._get_string(a_data)
                    elif val_type == 0x10:  # int dec
                        attr_val = str(a_data)
                    elif val_type == 0x11:  # int hex
                        attr_val = hex(a_data)
                    elif val_type == 0x12:  # boolean
                        attr_val = "true" if a_data != 0 else "false"
                    elif val_type == 0x01:  # reference
                        attr_val = f"@{hex(a_data)}"
                    else:
                        attr_val = str(a_data)

                if attr_name:
                    attrs[attr_name] = attr_val

            self._events.append(
                {
                    "type": "start",
                    "name": name,
                    "ns": ns,
                    "attrs": attrs,
                }
            )
        except Exception as e:
            logger.debug("Start element parse error: %s", e)

    def _parse_end_element(self, offset: int) -> None:
        """Parse end element."""
        try:
            ns_idx, name_idx = struct.unpack_from("<II", self._data, offset + 16)
            name = self._get_string(name_idx)
            self._events.append({"type": "end", "name": name})
        except Exception:
            pass

    def _get_string(self, idx: int) -> str:
        """Get string by index."""
        if idx == 0xFFFFFFFF or idx < 0 or idx >= len(self._strings):
            return ""
        return self._strings[idx]

    def _build_tree(self) -> Optional[ET.Element]:
        """Build ElementTree from parsed events."""
        stack: List[ET.Element] = []
        root: Optional[ET.Element] = None

        for event in self._events:
            if event["type"] == "start":
                elem = ET.Element(event["name"], event["attrs"])
                if stack:
                    stack[-1].append(elem)
                else:
                    root = elem
                stack.append(elem)
            elif event["type"] == "end":
                if stack:
                    stack.pop()

        return root


# ════════════════════════════════════════════════════════════════════════════
# DEX STRING EXTRACTOR
# ════════════════════════════════════════════════════════════════════════════


class DexStringExtractor:
    """Extract strings from DEX files without external deps.

    Reads the DEX string pool directly from binary format,
    extracting all string constants for security analysis.
    """

    DEX_MAGIC = b"dex\n"

    def __init__(self, data: bytes) -> None:
        self._data = data

    def extract(self) -> List[str]:
        """Extract all strings from DEX file."""
        if len(self._data) < 112 or not self._data.startswith(self.DEX_MAGIC):
            return []

        try:
            string_ids_size = struct.unpack_from("<I", self._data, 56)[0]
            string_ids_off = struct.unpack_from("<I", self._data, 60)[0]

            strings = []
            for i in range(min(string_ids_size, 500000)):
                str_data_off = struct.unpack_from(
                    "<I", self._data, string_ids_off + i * 4
                )[0]
                s = self._read_string(str_data_off)
                if s:
                    strings.append(s)

            return strings
        except Exception as e:
            logger.debug("DEX string extraction error: %s", e)
            return []

    def _read_string(self, offset: int) -> str:
        """Read a MUTF-8 string from DEX data."""
        try:
            # Read ULEB128 length
            _, new_offset = self._read_uleb128(offset)
            # Read null-terminated MUTF-8
            end = self._data.index(b"\x00", new_offset)
            raw = self._data[new_offset:end]
            return raw.decode("utf-8", errors="replace")
        except (ValueError, IndexError):
            return ""

    def _read_uleb128(self, offset: int) -> Tuple[int, int]:
        """Read ULEB128 value."""
        result = 0
        shift = 0
        while offset < len(self._data):
            b = self._data[offset]
            offset += 1
            result |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                break
            shift += 7
        return result, offset

    def get_class_count(self) -> int:
        """Get number of classes in DEX."""
        if len(self._data) < 112:
            return 0
        try:
            return struct.unpack_from("<I", self._data, 96)[0]
        except struct.error:
            return 0

    def get_method_count(self) -> int:
        """Get number of methods in DEX."""
        if len(self._data) < 112:
            return 0
        try:
            return struct.unpack_from("<I", self._data, 88)[0]
        except struct.error:
            return 0


# ════════════════════════════════════════════════════════════════════════════
# ELF ANALYZER (native .so libs)
# ════════════════════════════════════════════════════════════════════════════


class ELFAnalyzer:
    """Analyze ELF binaries (.so native libraries) for security properties."""

    ELF_MAGIC = b"\x7fELF"

    # ELF constants
    PT_GNU_STACK = 0x6474E551
    PT_GNU_RELRO = 0x6474E552

    def __init__(self, data: bytes) -> None:
        self._data = data
        self.is_64bit = False
        self.arch = ""
        self.imports: List[str] = []
        self.exports: List[str] = []
        self.has_nx = False
        self.has_pie = False
        self.has_canary = False
        self.relro = "none"
        self.has_fortify = False
        self.is_stripped = True

    def analyze(self) -> Dict[str, Any]:
        """Analyze ELF security properties."""
        if len(self._data) < 64 or not self._data.startswith(self.ELF_MAGIC):
            return {}

        self.is_64bit = self._data[4] == 2

        # Architecture
        e_machine = struct.unpack_from("<H", self._data, 18)[0]
        arch_map = {3: "x86", 40: "ARM", 62: "x86_64", 183: "ARM64"}
        self.arch = arch_map.get(e_machine, f"unknown({e_machine})")

        # ELF Type (2 = EXEC, 3 = DYN/shared)
        e_type = struct.unpack_from("<H", self._data, 16)[0]
        self.has_pie = e_type == 3  # DYN = position independent

        # Parse program headers for NX and RELRO
        self._parse_program_headers()

        # Parse dynamic section for imports
        self._parse_dynamic_strings()

        return {
            "arch": self.arch,
            "is_64bit": self.is_64bit,
            "pie": self.has_pie,
            "nx": self.has_nx,
            "canary": self.has_canary,
            "relro": self.relro,
            "fortify": self.has_fortify,
            "stripped": self.is_stripped,
            "imports": self.imports[:100],
        }

    def _parse_program_headers(self) -> None:
        """Parse program headers for NX and RELRO."""
        try:
            if self.is_64bit:
                e_phoff = struct.unpack_from("<Q", self._data, 32)[0]
                e_phentsize = struct.unpack_from("<H", self._data, 54)[0]
                e_phnum = struct.unpack_from("<H", self._data, 56)[0]
            else:
                e_phoff = struct.unpack_from("<I", self._data, 28)[0]
                e_phentsize = struct.unpack_from("<H", self._data, 42)[0]
                e_phnum = struct.unpack_from("<H", self._data, 44)[0]

            for i in range(min(e_phnum, 100)):
                ph_off = e_phoff + i * e_phentsize
                p_type = struct.unpack_from("<I", self._data, ph_off)[0]

                if p_type == self.PT_GNU_STACK:
                    if self.is_64bit:
                        p_flags = struct.unpack_from("<I", self._data, ph_off + 4)[0]
                    else:
                        p_flags = struct.unpack_from("<I", self._data, ph_off + 24)[0]
                    # NX = stack is NOT executable (no PF_X flag)
                    self.has_nx = (p_flags & 1) == 0

                elif p_type == self.PT_GNU_RELRO:
                    self.relro = "partial"  # Full RELRO requires BIND_NOW

        except Exception as e:
            logger.debug("ELF program header parse error: %s", e)

    def _parse_dynamic_strings(self) -> None:
        """Extract imported symbol names for security checks."""
        try:
            # Search for known function names in the binary
            text = self._data.decode("ascii", errors="ignore")

            dangerous_funcs = [
                "strcpy",
                "strcat",
                "sprintf",
                "gets",
                "scanf",
                "system",
                "popen",
                "exec",
                "dlopen",
                "dlsym",
                "__stack_chk_fail",
                "__stack_chk_guard",
            ]
            fortify_funcs = [
                "__strcpy_chk",
                "__strcat_chk",
                "__sprintf_chk",
                "__memcpy_chk",
                "__memmove_chk",
            ]

            for func in dangerous_funcs:
                if func in text:
                    self.imports.append(func)

            for func in fortify_funcs:
                if func in text:
                    self.has_fortify = True
                    break

            if "__stack_chk_fail" in text or "__stack_chk_guard" in text:
                self.has_canary = True

            # Check if symbol table is stripped
            if b".symtab" in self._data:
                self.is_stripped = False

        except Exception as e:
            logger.debug("ELF dynamic string parse error: %s", e)


# ════════════════════════════════════════════════════════════════════════════
# MANIFEST ANALYZER
# ════════════════════════════════════════════════════════════════════════════


class ManifestAnalyzer:
    """Deep analysis of AndroidManifest.xml."""

    _ANDROID_NS = "http://schemas.android.com/apk/res/android"

    def __init__(self, xml_root: ET.Element) -> None:
        self._root = xml_root

    def analyze(self) -> ManifestAnalysis:
        """Perform comprehensive manifest analysis."""
        result = ManifestAnalysis()

        # Package info
        result.package = self._root.get("package", "")
        result.version_name = self._attr("versionName", self._root)
        vc = self._attr("versionCode", self._root)
        result.version_code = int(vc) if vc.isdigit() else 0

        # SDK versions
        uses_sdk = self._root.find("uses-sdk")
        if uses_sdk is not None:
            ms = self._attr("minSdkVersion", uses_sdk)
            result.min_sdk = int(ms) if ms.isdigit() else 0
            ts = self._attr("targetSdkVersion", uses_sdk)
            result.target_sdk = int(ts) if ts.isdigit() else 0
            cs = self._attr("compileSdkVersion", uses_sdk)
            result.compile_sdk = int(cs) if cs.isdigit() else 0

        # Permissions
        for perm in self._root.findall("uses-permission"):
            name = self._attr("name", perm)
            if name:
                result.permissions_requested.append(name)
                if name in DANGEROUS_PERMISSIONS:
                    result.dangerous_permissions.append(name)

        for perm in self._root.findall("permission"):
            name = self._attr("name", perm)
            if name:
                result.permissions_defined.append(name)

        # Application attributes
        app = self._root.find("application")
        if app is not None:
            result.debuggable = self._attr("debuggable", app).lower() == "true"
            result.allow_backup = self._attr("allowBackup", app).lower() != "false"
            result.uses_cleartext = (
                self._attr("usesCleartextTraffic", app).lower() == "true"
            )
            result.test_only = self._attr("testOnly", app).lower() == "true"
            result.large_heap = self._attr("largeHeap", app).lower() == "true"
            result.backup_agent = self._attr("backupAgent", app)
            result.task_affinity = self._attr("taskAffinity", app)

            nsc = self._attr("networkSecurityConfig", app)
            result.has_network_security_config = bool(nsc)

            # Components
            self._analyze_components(app, result)

        # Features
        for feat in self._root.findall("uses-feature"):
            name = self._attr("name", feat)
            if name:
                result.features.append(name)

        # Libraries
        for lib in self._root.findall(".//uses-library"):
            name = self._attr("name", lib)
            if name:
                result.libraries.append(name)

        # Meta-data
        for md in self._root.findall(".//meta-data"):
            name = self._attr("name", md)
            value = self._attr("value", md) or self._attr("resource", md)
            if name:
                result.meta_data[name] = value

        # Generate findings
        self._generate_findings(result)

        return result

    def _attr(self, name: str, elem: ET.Element) -> str:
        """Get attribute with android namespace fallback."""
        val = elem.get(f"{{{self._ANDROID_NS}}}{name}", "")
        if not val:
            val = elem.get(name, "")
        return val

    def _analyze_components(self, app: ET.Element, result: ManifestAnalysis) -> None:
        """Analyze all app components."""
        component_types = {
            "activity": result.activities,
            "activity-alias": result.activities,
            "service": result.services,
            "receiver": result.receivers,
            "provider": result.providers,
        }

        for comp_type, comp_list in component_types.items():
            for comp in app.findall(comp_type):
                name = self._attr("name", comp)
                exported_raw = self._attr("exported", comp)
                permission = self._attr("permission", comp)

                # Parse intent filters
                filters = []
                for f in comp.findall("intent-filter"):
                    actions = [
                        self._attr("name", a)
                        for a in f.findall("action")
                        if self._attr("name", a)
                    ]
                    categories = [
                        self._attr("name", c)
                        for c in f.findall("category")
                        if self._attr("name", c)
                    ]
                    data_elems = f.findall("data")
                    data = []
                    for d in data_elems:
                        scheme = self._attr("scheme", d)
                        host = self._attr("host", d)
                        path = (
                            self._attr("path", d)
                            or self._attr("pathPrefix", d)
                            or self._attr("pathPattern", d)
                        )
                        if scheme:
                            if scheme in ("http", "https"):
                                dlink = f"{scheme}://{host or '*'}{path or '/*'}"
                                result.deeplinks.append(dlink)
                            else:
                                result.custom_schemes.append(scheme)
                            data.append({"scheme": scheme, "host": host, "path": path})

                    filters.append(
                        {
                            "actions": actions,
                            "categories": categories,
                            "data": data,
                        }
                    )

                has_filter = bool(filters)
                # Android default: exported=true if intent-filter present
                if exported_raw == "":
                    exported = has_filter
                else:
                    exported = exported_raw.lower() == "true"

                comp_info = {
                    "name": name,
                    "type": comp_type,
                    "exported": exported,
                    "permission": permission,
                    "intent_filters": filters,
                }
                comp_list.append(comp_info)

                if exported:
                    result.exported_components.append(comp_info)

                if filters:
                    result.intent_filters.extend(filters)

    def _generate_findings(self, result: ManifestAnalysis) -> None:
        """Generate security findings from manifest analysis."""
        # Debuggable
        if result.debuggable:
            result.findings.append(
                MobileFinding(
                    title="Application is debuggable",
                    severity=SecurityLevel.CRITICAL,
                    owasp_category="M7",
                    description=(
                        "android:debuggable=true allows attacker to attach debugger, "
                        "inspect memory, modify runtime behavior, and extract data."
                    ),
                    evidence='AndroidManifest.xml: android:debuggable="true"',
                    remediation='Remove android:debuggable or set to "false" for release builds.',
                    cwe="CWE-489",
                    cvss=7.5,
                    tags=["manifest", "debuggable", "critical"],
                )
            )

        # Test-only
        if result.test_only:
            result.findings.append(
                MobileFinding(
                    title="Test-only application flag set",
                    severity=SecurityLevel.HIGH,
                    owasp_category="M8",
                    description="android:testOnly=true — app has testing flags set in production.",
                    evidence='AndroidManifest.xml: android:testOnly="true"',
                    remediation="Remove testOnly flag for production builds",
                    cwe="CWE-489",
                    tags=["manifest", "test-only"],
                )
            )

        # Backup
        if result.allow_backup:
            result.findings.append(
                MobileFinding(
                    title="Application data backup enabled",
                    severity=SecurityLevel.MEDIUM,
                    owasp_category="M9",
                    description=(
                        "android:allowBackup=true. App data can be extracted via "
                        "'adb backup', potentially exposing credentials, tokens, and user data."
                    ),
                    evidence='AndroidManifest.xml: android:allowBackup="true" (or default)',
                    remediation=(
                        'Set android:allowBackup="false" or use android:fullBackupContent '
                        "to specify backup rules excluding sensitive data."
                    ),
                    cwe="CWE-530",
                    cvss=5.0,
                    tags=["manifest", "backup"],
                )
            )

        # Cleartext traffic
        if result.uses_cleartext:
            result.findings.append(
                MobileFinding(
                    title="Cleartext HTTP traffic permitted",
                    severity=SecurityLevel.HIGH,
                    owasp_category="M5",
                    description=(
                        "android:usesCleartextTraffic=true. All HTTP traffic is unencrypted "
                        "and vulnerable to interception, MITM, and data theft."
                    ),
                    evidence='AndroidManifest.xml: android:usesCleartextTraffic="true"',
                    remediation=(
                        'Set usesCleartextTraffic="false" and configure '
                        "network_security_config.xml for per-domain exceptions."
                    ),
                    cwe="CWE-319",
                    cvss=6.5,
                    tags=["manifest", "cleartext", "network"],
                )
            )

        # No network security config with cleartext
        if not result.has_network_security_config and result.target_sdk >= 28:
            result.findings.append(
                MobileFinding(
                    title="Missing Network Security Configuration",
                    severity=SecurityLevel.LOW,
                    owasp_category="M5",
                    description=(
                        "No network_security_config.xml defined. App relies on system defaults "
                        "without explicit cert pinning or domain-specific policies."
                    ),
                    evidence="AndroidManifest.xml: no networkSecurityConfig attribute",
                    remediation=(
                        "Add network_security_config.xml with certificate pinning, "
                        "per-domain cleartext policies, and custom trust anchors."
                    ),
                    cwe="CWE-295",
                    tags=["manifest", "network-security"],
                )
            )

        # Low target SDK
        if 0 < result.target_sdk < 31:
            result.findings.append(
                MobileFinding(
                    title=f"Outdated target SDK: {result.target_sdk}",
                    severity=SecurityLevel.MEDIUM,
                    owasp_category="M8",
                    description=(
                        f"targetSdkVersion={result.target_sdk}. App misses security "
                        f"hardening from Android 12+ (scoped storage enforcement, "
                        f"approximate location, PendingIntent mutability, exported components)."
                    ),
                    evidence=f'uses-sdk android:targetSdkVersion="{result.target_sdk}"',
                    remediation="Update targetSdkVersion to 34+ (Android 14)",
                    cwe="CWE-693",
                    tags=["manifest", "sdk-version"],
                )
            )

        if 0 < result.min_sdk < 23:
            result.findings.append(
                MobileFinding(
                    title=f"Very low minimum SDK: {result.min_sdk}",
                    severity=SecurityLevel.MEDIUM,
                    owasp_category="M8",
                    description=(
                        f"minSdkVersion={result.min_sdk}. Supports Android versions "
                        f"lacking runtime permissions, file-based encryption, and modern TLS."
                    ),
                    evidence=f'uses-sdk android:minSdkVersion="{result.min_sdk}"',
                    remediation="Set minSdkVersion to at least 23 (Android 6.0)",
                    cwe="CWE-693",
                    tags=["manifest", "sdk-version", "min-sdk"],
                )
            )

        # Dangerous permissions analysis
        privacy_critical = {
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.READ_CALL_LOG",
            "android.permission.READ_CONTACTS",
        }
        for perm in result.dangerous_permissions:
            sev = (
                SecurityLevel.HIGH if perm in privacy_critical else SecurityLevel.MEDIUM
            )
            short = perm.split(".")[-1]
            result.findings.append(
                MobileFinding(
                    title=f"Dangerous permission: {short}",
                    severity=sev,
                    owasp_category="M6",
                    description=f"App requests dangerous runtime permission: {perm}",
                    evidence=f'<uses-permission android:name="{perm}" />',
                    remediation=(
                        "Verify this permission is essential. Request at runtime. "
                        "Provide clear rationale to users. Use least-privilege principle."
                    ),
                    cwe="CWE-250",
                    tags=["manifest", "permissions", short.lower()],
                )
            )

        # Exported components without protection
        for comp in result.exported_components:
            if not comp.get("permission"):
                comp_name = comp.get("name", "unknown")
                comp_type = comp.get("type", "component")
                short_name = comp_name.split(".")[-1] if comp_name else "unknown"
                sev = (
                    SecurityLevel.HIGH
                    if comp_type == "provider"
                    else SecurityLevel.MEDIUM
                )
                result.findings.append(
                    MobileFinding(
                        title=f"Unprotected exported {comp_type}: {short_name}",
                        severity=sev,
                        owasp_category="M3",
                        description=(
                            f"Component {comp_name} is exported without permission protection. "
                            f"Any app on the device can interact with it."
                        ),
                        evidence=f'<{comp_type} android:name="{comp_name}" android:exported="true" />',
                        remediation=(
                            f"Add android:permission to protect this {comp_type}, "
                            f'or set android:exported="false" if external access is not needed.'
                        ),
                        cwe="CWE-926",
                        tags=["manifest", "exported", comp_type],
                    )
                )

        # Task affinity hijacking
        if result.task_affinity and result.task_affinity != result.package:
            result.findings.append(
                MobileFinding(
                    title="Custom task affinity set",
                    severity=SecurityLevel.LOW,
                    owasp_category="M3",
                    description=(
                        f'Application has custom taskAffinity="{result.task_affinity}". '
                        f"May be vulnerable to task hijacking (StrandHogg attack)."
                    ),
                    evidence=f'android:taskAffinity="{result.task_affinity}"',
                    remediation='Set android:taskAffinity="" for activities handling sensitive data',
                    cwe="CWE-1021",
                    tags=["manifest", "task-affinity"],
                )
            )

        # Custom permissions with normal protection level
        for perm_name in result.permissions_defined:
            result.findings.append(
                MobileFinding(
                    title=f"Custom permission defined: {perm_name.split('.')[-1]}",
                    severity=SecurityLevel.INFO,
                    owasp_category="M8",
                    description=f"App defines custom permission: {perm_name}",
                    evidence=f'<permission android:name="{perm_name}" />',
                    remediation="Ensure protectionLevel is 'signature' or 'signatureOrSystem'",
                    tags=["manifest", "custom-permission"],
                )
            )


# ════════════════════════════════════════════════════════════════════════════
# DEX DEEP ANALYZER
# ════════════════════════════════════════════════════════════════════════════


class DexDeepAnalyzer:
    """Deep analysis of DEX bytecode strings for security issues."""

    def __init__(
        self, strings: List[str], class_count: int = 0, method_count: int = 0
    ) -> None:
        self._strings = strings
        self._class_count = class_count
        self._method_count = method_count

    def analyze(self) -> DexAnalysis:
        """Perform comprehensive DEX string analysis."""
        result = DexAnalysis(
            total_classes=self._class_count,
            total_methods=self._method_count,
            total_strings=len(self._strings),
        )

        self._find_secrets(result)
        self._find_insecure_crypto(result)
        self._find_webview_issues(result)
        self._find_native_methods(result)
        self._find_reflection(result)
        self._find_dynamic_loading(result)
        self._find_urls(result)
        self._find_sql(result)
        self._find_logging(result)
        self._assess_obfuscation(result)
        self._find_trackers(result)
        self._generate_findings(result)

        return result

    def _find_secrets(self, result: DexAnalysis) -> None:
        """Find hardcoded secrets in strings."""
        checked: Set[str] = set()
        for s in self._strings:
            if len(s) < 8 or len(s) > 2000 or s in checked:
                continue
            checked.add(s)

            for pattern_name, pattern in SECRET_PATTERNS.items():
                m = pattern.search(s)
                if m:
                    # Filter false positives
                    match_text = m.group(0)
                    if self._is_false_positive(pattern_name, match_text):
                        continue
                    result.secrets_found.append(
                        {
                            "type": pattern_name,
                            "value": match_text[:80]
                            + ("..." if len(match_text) > 80 else ""),
                            "context": s[:120],
                        }
                    )

    def _is_false_positive(self, pattern_name: str, match: str) -> bool:
        """Filter common false positives."""
        if pattern_name == "ip_address_private":
            # Filter common non-sensitive IPs
            if match in ("10.0.0.1", "192.168.0.1", "192.168.1.1", "127.0.0.1"):
                return True
        if pattern_name == "generic_password":
            # Skip obvious examples/placeholders
            lower = match.lower()
            if any(
                x in lower
                for x in ("example", "placeholder", "your_", "change_me", "xxx")
            ):
                return True
        if pattern_name == "heroku_api":
            # UUIDs are common, not all are Heroku
            return True
        return False

    def _find_insecure_crypto(self, result: DexAnalysis) -> None:
        """Find insecure cryptographic usage."""
        for s in self._strings:
            for pattern, (cwe, desc) in INSECURE_CRYPTO_PATTERNS.items():
                if pattern in s:
                    result.insecure_crypto.append(
                        {
                            "pattern": pattern,
                            "cwe": cwe,
                            "description": desc,
                            "context": s[:150],
                        }
                    )

    def _find_webview_issues(self, result: DexAnalysis) -> None:
        """Find WebView security issues."""
        all_text = "\n".join(self._strings)
        for pattern, (cwe, severity, desc) in WEBVIEW_VULN_PATTERNS.items():
            if pattern in all_text:
                result.webview_issues.append(
                    {
                        "pattern": pattern,
                        "cwe": cwe,
                        "severity": severity.value,
                        "description": desc,
                    }
                )

    def _find_native_methods(self, result: DexAnalysis) -> None:
        """Find JNI native method declarations."""
        for s in self._strings:
            if "native " in s and "(" in s:
                result.native_methods.append(s[:200])

    def _find_reflection(self, result: DexAnalysis) -> None:
        """Find reflection API usage."""
        reflection_markers = [
            "java.lang.reflect.",
            "getDeclaredMethod",
            "getDeclaredField",
            "setAccessible",
            "java.lang.Class.forName",
            "getMethod(",
            "invoke(",
        ]
        for s in self._strings:
            for marker in reflection_markers:
                if marker in s:
                    result.reflection_calls.append(s[:200])
                    break

    def _find_dynamic_loading(self, result: DexAnalysis) -> None:
        """Find dynamic code loading."""
        dynamic_markers = [
            "DexClassLoader",
            "PathClassLoader",
            "InMemoryDexClassLoader",
            "dalvik.system.DexFile",
            "loadClass(",
            "System.loadLibrary",
            "System.load(",
            "Runtime.getRuntime().exec",
        ]
        for s in self._strings:
            for marker in dynamic_markers:
                if marker in s:
                    result.dynamic_loading.append(s[:200])
                    break

    def _find_urls(self, result: DexAnalysis) -> None:
        """Find URLs and IP addresses."""
        url_pattern = re.compile(r"https?://[^\s\"']+")
        ip_pattern = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")

        seen_urls: Set[str] = set()
        seen_ips: Set[str] = set()

        for s in self._strings:
            for m in url_pattern.finditer(s):
                url = m.group(0).rstrip(">/),;")
                if url not in seen_urls and len(url) < 500:
                    seen_urls.add(url)
                    result.url_strings.append(url)

            for m in ip_pattern.finditer(s):
                ip = m.group(0)
                if ip not in seen_ips:
                    seen_ips.add(ip)
                    result.ip_addresses.append(ip)

    def _find_sql(self, result: DexAnalysis) -> None:
        """Find SQL query patterns."""
        sql_pattern = re.compile(
            r"\b(?:SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER)\b.*?"
            r"\b(?:FROM|INTO|SET|TABLE|WHERE)\b",
            re.I,
        )
        for s in self._strings:
            if sql_pattern.search(s):
                result.sql_queries.append(s[:300])

    def _find_logging(self, result: DexAnalysis) -> None:
        """Count logging calls."""
        log_patterns = ["Log.d(", "Log.v(", "Log.i(", "Log.w(", "Log.e(", "println("]
        for s in self._strings:
            for p in log_patterns:
                if p in s:
                    result.logging_calls += 1
                    break

    def _assess_obfuscation(self, result: DexAnalysis) -> None:
        """Assess code obfuscation level."""
        if not self._strings:
            return

        short_class_pattern = re.compile(r"^L[a-z]{1,2}/[a-z]{1,2}/[a-z]{1,2};$")
        obfuscated = sum(1 for s in self._strings if short_class_pattern.match(s))
        total_classes = max(self._class_count, 1)
        result.obfuscation_ratio = (
            min(obfuscated / total_classes, 1.0) if total_classes > 0 else 0.0
        )

    def _find_trackers(self, result: DexAnalysis) -> None:
        """Find third-party tracker SDKs."""
        all_text = "\n".join(s for s in self._strings if "." in s and len(s) > 10)
        found: Set[str] = set()
        for prefix, info in TRACKER_SIGNATURES.items():
            if prefix in all_text and prefix not in found:
                found.add(prefix)
                result.trackers_found.append(
                    {
                        "name": info["name"],
                        "category": info["category"],
                        "package": prefix,
                    }
                )

    def _generate_findings(self, result: DexAnalysis) -> None:
        """Generate MobileFinding instances from DEX analysis."""
        # Secrets
        for secret in result.secrets_found:
            sev = (
                SecurityLevel.CRITICAL
                if secret["type"]
                in ("private_key_pem", "aws_secret_key", "generic_secret")
                else SecurityLevel.HIGH
            )
            result.findings.append(
                MobileFinding(
                    title=f"Hardcoded secret: {secret['type']}",
                    severity=sev,
                    owasp_category="M1",
                    description=f"Hardcoded {secret['type']} found in DEX bytecode.",
                    evidence=secret["value"],
                    remediation=(
                        "Remove hardcoded secrets. Use Android Keystore, "
                        "encrypted config, or server-side secret management."
                    ),
                    cwe="CWE-798",
                    cvss=8.0 if sev == SecurityLevel.CRITICAL else 6.5,
                    tags=["dex", "secrets", secret["type"]],
                )
            )

        # Insecure crypto
        seen: Set[str] = set()
        for crypto in result.insecure_crypto:
            key = crypto["pattern"]
            if key in seen:
                continue
            seen.add(key)
            result.findings.append(
                MobileFinding(
                    title=f"Insecure cryptography: {crypto['pattern']}",
                    severity=SecurityLevel.HIGH,
                    owasp_category="M10",
                    description=crypto["description"],
                    evidence=crypto["context"][:100],
                    remediation=crypto["description"],
                    cwe=crypto["cwe"],
                    tags=["dex", "crypto", crypto["pattern"].lower()],
                )
            )

        # WebView issues
        for wv in result.webview_issues:
            result.findings.append(
                MobileFinding(
                    title=f"WebView: {wv['pattern']}",
                    severity=SecurityLevel(wv["severity"]),
                    owasp_category="M4",
                    description=wv["description"],
                    evidence=wv["pattern"],
                    remediation=(
                        "Disable unnecessary WebView features. Validate all "
                        "content loaded. Use SafeBrowsing API."
                    ),
                    cwe=wv["cwe"],
                    tags=["dex", "webview"],
                )
            )

        # Dynamic loading
        if result.dynamic_loading:
            result.findings.append(
                MobileFinding(
                    title=f"Dynamic code loading detected ({len(result.dynamic_loading)} instances)",
                    severity=SecurityLevel.HIGH,
                    owasp_category="M7",
                    description=(
                        "App loads code dynamically at runtime. This can be exploited "
                        "for code injection if the loaded code source is not verified."
                    ),
                    evidence="; ".join(result.dynamic_loading[:3]),
                    remediation=(
                        "Verify integrity of dynamically loaded code. "
                        "Use signature verification. Avoid loading from external storage."
                    ),
                    cwe="CWE-94",
                    tags=["dex", "dynamic-loading"],
                )
            )

        # Reflection abuse
        if len(result.reflection_calls) > 10:
            result.findings.append(
                MobileFinding(
                    title=f"Heavy reflection usage ({len(result.reflection_calls)} instances)",
                    severity=SecurityLevel.LOW,
                    owasp_category="M7",
                    description="App uses extensive Java reflection, possibly to bypass access controls.",
                    evidence=f"{len(result.reflection_calls)} reflection API calls found",
                    remediation="Review reflection usage for security bypasses.",
                    tags=["dex", "reflection"],
                )
            )

        # Logging in release
        if result.logging_calls > 50:
            result.findings.append(
                MobileFinding(
                    title=f"Excessive logging: {result.logging_calls} calls",
                    severity=SecurityLevel.MEDIUM,
                    owasp_category="M9",
                    description=(
                        f"App contains {result.logging_calls} logging calls that "
                        f"may leak sensitive data to logcat."
                    ),
                    evidence=f"Log.d/v/i/w/e calls: {result.logging_calls}",
                    remediation=(
                        "Remove debug logging in release builds. Use ProGuard rules: "
                        "-assumenosideeffects class android.util.Log { *; }"
                    ),
                    cwe="CWE-532",
                    tags=["dex", "logging"],
                )
            )

        # Low obfuscation
        if result.obfuscation_ratio < 0.2 and result.total_classes > 100:
            result.findings.append(
                MobileFinding(
                    title=f"Low code obfuscation: {result.obfuscation_ratio:.0%}",
                    severity=SecurityLevel.MEDIUM,
                    owasp_category="M7",
                    description=(
                        f"Only {result.obfuscation_ratio:.0%} of classes appear obfuscated. "
                        f"App code can be easily reverse-engineered."
                    ),
                    evidence=f"Obfuscation ratio: {result.obfuscation_ratio:.1%} of {result.total_classes} classes",
                    remediation="Enable R8/ProGuard with strong obfuscation rules. Consider DexGuard or similar.",
                    cwe="CWE-693",
                    tags=["dex", "obfuscation"],
                )
            )

        # Trackers
        if result.trackers_found:
            tracker_names = ", ".join(t["name"] for t in result.trackers_found)
            ads = [t for t in result.trackers_found if t["category"] == "ads"]
            result.findings.append(
                MobileFinding(
                    title=f"Third-party SDKs: {len(result.trackers_found)} detected",
                    severity=SecurityLevel.INFO,
                    owasp_category="M6",
                    description=f"Detected SDKs: {tracker_names}",
                    evidence=json.dumps(result.trackers_found, indent=2),
                    remediation="Review SDK privacy policies and data collection practices.",
                    tags=["dex", "trackers", "privacy"],
                )
            )
            if len(ads) > 3:
                result.findings.append(
                    MobileFinding(
                        title=f"Excessive ad SDKs: {len(ads)} detected",
                        severity=SecurityLevel.LOW,
                        owasp_category="M2",
                        description=f"App embeds {len(ads)} ad SDKs, increasing attack surface.",
                        evidence=", ".join(a["name"] for a in ads),
                        remediation="Reduce ad SDK count. Each SDK is a potential supply chain risk.",
                        cwe="CWE-1104",
                        tags=["dex", "ads", "supply-chain"],
                    )
                )

        # HTTP URLs (non-HTTPS)
        http_urls = [u for u in result.url_strings if u.startswith("http://")]
        if http_urls:
            result.findings.append(
                MobileFinding(
                    title=f"Hardcoded HTTP URLs: {len(http_urls)}",
                    severity=SecurityLevel.MEDIUM,
                    owasp_category="M5",
                    description=f"Found {len(http_urls)} hardcoded HTTP (non-HTTPS) URLs.",
                    evidence="; ".join(http_urls[:5]),
                    remediation="Use HTTPS for all network communication.",
                    cwe="CWE-319",
                    tags=["dex", "http", "cleartext"],
                )
            )

        # SQL queries (potential injection surface)
        if result.sql_queries:
            raw_sql = [
                q
                for q in result.sql_queries
                if "?" not in q and "bind" not in q.lower()
            ]
            if raw_sql:
                result.findings.append(
                    MobileFinding(
                        title=f"Raw SQL queries: {len(raw_sql)} without parameterization",
                        severity=SecurityLevel.HIGH,
                        owasp_category="M4",
                        description="SQL queries without parameterized placeholders — SQL injection risk.",
                        evidence="; ".join(raw_sql[:3])[:200],
                        remediation="Use parameterized queries (?) or Room DAO with @Query annotations.",
                        cwe="CWE-89",
                        tags=["dex", "sql", "injection"],
                    )
                )


# ════════════════════════════════════════════════════════════════════════════
# NETWORK SECURITY CONFIG ANALYZER
# ════════════════════════════════════════════════════════════════════════════


class NetworkSecurityConfigAnalyzer:
    """Analyze Android network_security_config.xml."""

    def __init__(self, xml_data: bytes) -> None:
        self._data = xml_data

    def analyze(self) -> NetworkSecurityAnalysis:
        """Parse and analyze network security configuration."""
        result = NetworkSecurityAnalysis(has_config=True)

        try:
            root = ET.fromstring(self._data.decode("utf-8", errors="replace"))
        except ET.ParseError:
            # Try binary XML
            parser = BinaryXMLParser(self._data)
            root = parser.parse()
            if root is None:
                return result

        # Base config
        base = root.find("base-config")
        if base is not None:
            ct = base.get("cleartextTrafficPermitted", "false")
            result.cleartextTrafficPermitted = ct.lower() == "true"
            self._parse_trust_anchors(base, result, "base-config")

        # Domain configs
        for dc in root.findall("domain-config"):
            ct = dc.get("cleartextTrafficPermitted", "false")
            domains = [d.text for d in dc.findall("domain") if d.text]
            config = {
                "domains": domains,
                "cleartext": ct.lower() == "true",
            }

            # Cert pins
            pin_set = dc.find("pin-set")
            if pin_set is not None:
                expiry = pin_set.get("expiration", "")
                result.pin_expiration = expiry
                for pin in pin_set.findall("pin"):
                    digest = pin.get("digest", "SHA-256")
                    value = pin.text or ""
                    result.cert_pins.append(
                        {
                            "digest": digest,
                            "value": value,
                            "domains": domains,
                        }
                    )
                config["pinned"] = True

            self._parse_trust_anchors(dc, result, domains)
            result.domain_configs.append(config)

        # Debug overrides
        debug = root.find("debug-overrides")
        if debug is not None:
            result.debug_overrides = True

        self._generate_findings(result)
        return result

    def _parse_trust_anchors(
        self,
        element: ET.Element,
        result: NetworkSecurityAnalysis,
        context: Any,
    ) -> None:
        """Parse trust anchor configuration."""
        for ta in element.findall(".//trust-anchors/certificates"):
            src = ta.get("src", "")
            result.trust_anchors.append(
                {
                    "src": src,
                    "context": str(context),
                }
            )

    def _generate_findings(self, result: NetworkSecurityAnalysis) -> None:
        """Generate findings from network security config."""
        if result.cleartextTrafficPermitted:
            result.findings.append(
                MobileFinding(
                    title="Global cleartext traffic permitted in NSC",
                    severity=SecurityLevel.HIGH,
                    owasp_category="M5",
                    description="network_security_config.xml permits cleartext for all domains.",
                    evidence="base-config cleartextTrafficPermitted=true",
                    remediation="Set cleartextTrafficPermitted=false in base-config",
                    cwe="CWE-319",
                    tags=["nsc", "cleartext"],
                )
            )

        for dc in result.domain_configs:
            if dc.get("cleartext"):
                result.findings.append(
                    MobileFinding(
                        title=f"Cleartext permitted for: {', '.join(dc['domains'][:3])}",
                        severity=SecurityLevel.MEDIUM,
                        owasp_category="M5",
                        description=f"Cleartext traffic allowed for specific domains.",
                        evidence=f"Domains: {dc['domains']}",
                        remediation="Remove cleartext exceptions unless absolutely necessary.",
                        cwe="CWE-319",
                        tags=["nsc", "cleartext", "domain-config"],
                    )
                )

        for ta in result.trust_anchors:
            if ta["src"] == "user":
                result.findings.append(
                    MobileFinding(
                        title="User-installed CA certificates trusted",
                        severity=SecurityLevel.HIGH,
                        owasp_category="M5",
                        description="App trusts user-installed CA certificates, enabling MITM.",
                        evidence=f'<certificates src="user" /> in {ta["context"]}',
                        remediation='Remove src="user" trust anchors for production builds.',
                        cwe="CWE-295",
                        tags=["nsc", "trust-anchors", "user-ca"],
                    )
                )

        if result.debug_overrides:
            result.findings.append(
                MobileFinding(
                    title="Debug SSL overrides present",
                    severity=SecurityLevel.MEDIUM,
                    owasp_category="M5",
                    description="debug-overrides section exists in network security config.",
                    evidence="<debug-overrides> present in network_security_config.xml",
                    remediation="Ensure debug-overrides do not weaken security in release builds.",
                    cwe="CWE-295",
                    tags=["nsc", "debug"],
                )
            )

        if not result.cert_pins:
            result.findings.append(
                MobileFinding(
                    title="No certificate pinning configured",
                    severity=SecurityLevel.MEDIUM,
                    owasp_category="M5",
                    description="No pin-set defined in network_security_config.xml.",
                    evidence="No <pin-set> elements found",
                    remediation=(
                        "Add certificate pinning with backup pins and reasonable expiration. "
                        "Consider using OkHttp CertificatePinner as fallback."
                    ),
                    cwe="CWE-295",
                    tags=["nsc", "pinning"],
                )
            )


# ════════════════════════════════════════════════════════════════════════════
# IPA PLIST DEEP ANALYZER
# ════════════════════════════════════════════════════════════════════════════


class IPAPlistAnalyzer:
    """Deep analysis of iOS app plist and entitlements."""

    def __init__(
        self, plist_data: Dict[str, Any], entitlements: Optional[Dict[str, Any]] = None
    ) -> None:
        self._plist = plist_data
        self._entitlements = entitlements or {}

    def analyze(self) -> List[MobileFinding]:
        """Analyze plist for security issues."""
        findings: List[MobileFinding] = []

        self._check_ats(findings)
        self._check_url_schemes(findings)
        self._check_permissions(findings)
        self._check_entitlements(findings)
        self._check_background_modes(findings)
        self._check_misc(findings)

        return findings

    def _check_ats(self, findings: List[MobileFinding]) -> None:
        """Check App Transport Security settings."""
        ats = self._plist.get("NSAppTransportSecurity", {})
        if not isinstance(ats, dict):
            return

        if ats.get("NSAllowsArbitraryLoads"):
            findings.append(
                MobileFinding(
                    title="ATS globally disabled",
                    severity=SecurityLevel.HIGH,
                    owasp_category="M5",
                    description=(
                        "NSAllowsArbitraryLoads=true disables App Transport Security globally, "
                        "allowing all HTTP connections."
                    ),
                    evidence="NSAllowsArbitraryLoads = true",
                    remediation="Remove NSAllowsArbitraryLoads. Add per-domain exceptions if needed.",
                    cwe="CWE-319",
                    cvss=6.5,
                    tags=["ios", "plist", "ats"],
                )
            )

        if ats.get("NSAllowsArbitraryLoadsInWebContent"):
            findings.append(
                MobileFinding(
                    title="ATS disabled for web content",
                    severity=SecurityLevel.MEDIUM,
                    owasp_category="M5",
                    description="ATS disabled for WKWebView content, allowing HTTP in webviews.",
                    evidence="NSAllowsArbitraryLoadsInWebContent = true",
                    remediation="Enable ATS for web content or use per-domain exceptions.",
                    cwe="CWE-319",
                    tags=["ios", "plist", "ats", "webview"],
                )
            )

        if ats.get("NSAllowsLocalNetworking"):
            findings.append(
                MobileFinding(
                    title="Local networking ATS exception",
                    severity=SecurityLevel.LOW,
                    owasp_category="M5",
                    description="ATS allows unencrypted local network connections.",
                    evidence="NSAllowsLocalNetworking = true",
                    remediation="Verify this is necessary for app functionality.",
                    tags=["ios", "plist", "ats", "local"],
                )
            )

        # Per-domain exceptions
        exceptions = ats.get("NSExceptionDomains", {})
        if isinstance(exceptions, dict):
            for domain, config in exceptions.items():
                if isinstance(config, dict):
                    if config.get("NSExceptionAllowsInsecureHTTPLoads"):
                        findings.append(
                            MobileFinding(
                                title=f"ATS exception for: {domain}",
                                severity=SecurityLevel.MEDIUM,
                                owasp_category="M5",
                                description=f"HTTP allowed for {domain}",
                                evidence=f"{domain}: NSExceptionAllowsInsecureHTTPLoads = true",
                                remediation=f"Enable HTTPS for {domain}",
                                cwe="CWE-319",
                                tags=["ios", "plist", "ats", "exception"],
                            )
                        )
                    min_tls = config.get("NSExceptionMinimumTLSVersion", "")
                    if min_tls and min_tls < "TLSv1.2":
                        findings.append(
                            MobileFinding(
                                title=f"Weak TLS version for: {domain}",
                                severity=SecurityLevel.HIGH,
                                owasp_category="M5",
                                description=f"Minimum TLS {min_tls} allowed for {domain}",
                                evidence=f"{domain}: NSExceptionMinimumTLSVersion = {min_tls}",
                                remediation="Require TLSv1.2 minimum",
                                cwe="CWE-326",
                                tags=["ios", "plist", "ats", "tls"],
                            )
                        )

    def _check_url_schemes(self, findings: List[MobileFinding]) -> None:
        """Check URL scheme registrations."""
        url_types = self._plist.get("CFBundleURLTypes", [])
        if not isinstance(url_types, list):
            return

        for url_type in url_types:
            if not isinstance(url_type, dict):
                continue
            schemes = url_type.get("CFBundleURLSchemes", [])
            for scheme in schemes:
                findings.append(
                    MobileFinding(
                        title=f"URL scheme: {scheme}://",
                        severity=SecurityLevel.LOW,
                        owasp_category="M3",
                        description=f"App registers custom URL scheme '{scheme}://' — potential for URL scheme hijacking.",
                        evidence=f"CFBundleURLSchemes: {scheme}",
                        remediation="Validate all data from URL schemes. Use Universal Links for secure deep linking.",
                        cwe="CWE-939",
                        tags=["ios", "plist", "url-scheme"],
                    )
                )

    def _check_permissions(self, findings: List[MobileFinding]) -> None:
        """Check privacy permission descriptions."""
        privacy_keys = {
            "NSCameraUsageDescription": ("Camera", SecurityLevel.HIGH),
            "NSMicrophoneUsageDescription": ("Microphone", SecurityLevel.HIGH),
            "NSLocationWhenInUseUsageDescription": (
                "Location (in-use)",
                SecurityLevel.MEDIUM,
            ),
            "NSLocationAlwaysUsageDescription": (
                "Location (always)",
                SecurityLevel.HIGH,
            ),
            "NSLocationAlwaysAndWhenInUseUsageDescription": (
                "Location (always+in-use)",
                SecurityLevel.HIGH,
            ),
            "NSContactsUsageDescription": ("Contacts", SecurityLevel.HIGH),
            "NSCalendarsUsageDescription": ("Calendar", SecurityLevel.MEDIUM),
            "NSRemindersUsageDescription": ("Reminders", SecurityLevel.LOW),
            "NSPhotoLibraryUsageDescription": ("Photo Library", SecurityLevel.MEDIUM),
            "NSBluetoothAlwaysUsageDescription": ("Bluetooth", SecurityLevel.MEDIUM),
            "NSMotionUsageDescription": ("Motion", SecurityLevel.LOW),
            "NSHealthShareUsageDescription": ("Health Data", SecurityLevel.HIGH),
            "NSFaceIDUsageDescription": ("Face ID", SecurityLevel.INFO),
            "NSSpeechRecognitionUsageDescription": (
                "Speech Recognition",
                SecurityLevel.MEDIUM,
            ),
            "NSAppleMusicUsageDescription": ("Media Library", SecurityLevel.LOW),
        }

        for key, (name, severity) in privacy_keys.items():
            if key in self._plist:
                desc = self._plist[key]
                findings.append(
                    MobileFinding(
                        title=f"Privacy permission: {name}",
                        severity=severity,
                        owasp_category="M6",
                        description=f"App requests {name} access: '{desc}'",
                        evidence=f"{key}: {desc}",
                        remediation=f"Verify {name} access is essential.",
                        tags=[
                            "ios",
                            "plist",
                            "privacy",
                            name.lower().replace(" ", "-"),
                        ],
                    )
                )

    def _check_entitlements(self, findings: List[MobileFinding]) -> None:
        """Check entitlements for security issues."""
        if self._entitlements.get("get-task-allow"):
            findings.append(
                MobileFinding(
                    title="Debug entitlement: get-task-allow",
                    severity=SecurityLevel.CRITICAL,
                    owasp_category="M7",
                    description="get-task-allow=true enables debugger attachment in production.",
                    evidence="get-task-allow = true",
                    remediation="Remove get-task-allow for distribution builds.",
                    cwe="CWE-489",
                    cvss=7.5,
                    tags=["ios", "entitlements", "debug"],
                )
            )

        if self._entitlements.get("com.apple.developer.associated-domains"):
            domains = self._entitlements["com.apple.developer.associated-domains"]
            if isinstance(domains, list):
                for d in domains:
                    if d.startswith("applinks:"):
                        findings.append(
                            MobileFinding(
                                title=f"Universal Link: {d}",
                                severity=SecurityLevel.INFO,
                                owasp_category="M3",
                                description=f"App claims Universal Link domain: {d}",
                                evidence=f"associated-domains: {d}",
                                remediation="Ensure AASA file is properly configured.",
                                tags=["ios", "entitlements", "universal-links"],
                            )
                        )

        # Keychain sharing
        kcg = self._entitlements.get("keychain-access-groups", [])
        if isinstance(kcg, list) and len(kcg) > 1:
            findings.append(
                MobileFinding(
                    title=f"Keychain sharing: {len(kcg)} groups",
                    severity=SecurityLevel.LOW,
                    owasp_category="M9",
                    description=f"App shares keychain with {len(kcg)} access groups.",
                    evidence=f"keychain-access-groups: {kcg}",
                    remediation="Limit keychain sharing to necessary groups.",
                    tags=["ios", "entitlements", "keychain"],
                )
            )

    def _check_background_modes(self, findings: List[MobileFinding]) -> None:
        """Check background mode registrations."""
        modes = self._plist.get("UIBackgroundModes", [])
        if not isinstance(modes, list):
            return

        sensitive_modes = {"location", "audio", "voip", "bluetooth-central"}
        for mode in modes:
            if mode in sensitive_modes:
                findings.append(
                    MobileFinding(
                        title=f"Background mode: {mode}",
                        severity=SecurityLevel.LOW,
                        owasp_category="M6",
                        description=f"App runs in background with '{mode}' capability.",
                        evidence=f"UIBackgroundModes: {mode}",
                        remediation=f"Verify background {mode} is necessary.",
                        tags=["ios", "plist", "background", mode],
                    )
                )

    def _check_misc(self, findings: List[MobileFinding]) -> None:
        """Check miscellaneous security settings."""
        # Pasteboard sharing
        if self._plist.get("UIPasteboardName"):
            findings.append(
                MobileFinding(
                    title="Custom pasteboard defined",
                    severity=SecurityLevel.LOW,
                    owasp_category="M9",
                    description="App uses custom named pasteboard — data may persist.",
                    evidence=f"UIPasteboardName: {self._plist['UIPasteboardName']}",
                    remediation="Clear pasteboard on app background/termination.",
                    tags=["ios", "plist", "pasteboard"],
                )
            )

        # Disable screenshots
        if not self._plist.get("UIApplicationExitsOnSuspend", False):
            # This is normal, but worth noting for high-security apps
            pass


# ════════════════════════════════════════════════════════════════════════════
# CERTIFICATE ANALYZER
# ════════════════════════════════════════════════════════════════════════════


class CertificateAnalyzer:
    """Analyze APK signing certificates."""

    # Well-known debug certificate fingerprints
    DEBUG_CERT_SUBJECTS = frozenset(
        {
            "CN=Android Debug",
            "CN=Android Debug, O=Android, C=US",
        }
    )

    def __init__(self, cert_data: bytes) -> None:
        self._data = cert_data

    def analyze(self) -> CertificateAnalysis:
        """Analyze certificate for security issues."""
        result = CertificateAnalysis()

        # Try to parse basic certificate info
        self._parse_cert_info(result)
        self._generate_findings(result)

        return result

    def _parse_cert_info(self, result: CertificateAnalysis) -> None:
        """Parse certificate information from raw data."""
        try:
            # SHA-1 and SHA-256 fingerprints
            result.cert_fingerprint_sha1 = hashlib.sha1(self._data).hexdigest()
            result.cert_fingerprint_sha256 = hashlib.sha256(self._data).hexdigest()

            # Try to extract subject/issuer from DER-encoded cert
            # Look for common name sequences in the DER data
            text = self._data.decode("ascii", errors="ignore")

            # Simple extraction of CN fields
            cn_pattern = re.compile(r"CN=([^,/\x00]+)")
            matches = cn_pattern.findall(text)
            if len(matches) >= 2:
                result.cert_subject = matches[0].strip()
                result.cert_issuer = matches[1].strip()
            elif matches:
                result.cert_subject = matches[0].strip()
                result.cert_issuer = result.cert_subject

            result.is_self_signed = result.cert_subject == result.cert_issuer
            result.is_debug_cert = any(
                debug in f"CN={result.cert_subject}"
                for debug in self.DEBUG_CERT_SUBJECTS
            )

            # Try to detect key algorithm from OIDs in DER
            if b"\x2a\x86\x48\x86\xf7\x0d\x01\x01" in self._data:
                result.key_algorithm = "RSA"
            elif b"\x2a\x86\x48\xce\x3d\x02\x01" in self._data:
                result.key_algorithm = "EC"
            elif b"\x2a\x86\x48\xce\x38\x04\x01" in self._data:
                result.key_algorithm = "DSA"

            # Detect signature algorithm
            if b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b" in self._data:
                result.signature_algorithm = "SHA256withRSA"
            elif b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x05" in self._data:
                result.signature_algorithm = "SHA1withRSA"
            elif b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0c" in self._data:
                result.signature_algorithm = "SHA384withRSA"
            elif b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0d" in self._data:
                result.signature_algorithm = "SHA512withRSA"

        except Exception as e:
            logger.debug("Certificate parse error: %s", e)

    def _generate_findings(self, result: CertificateAnalysis) -> None:
        """Generate security findings from certificate analysis."""
        if result.is_debug_cert:
            result.findings.append(
                MobileFinding(
                    title="Debug signing certificate",
                    severity=SecurityLevel.CRITICAL,
                    owasp_category="M7",
                    description="APK is signed with Android debug certificate — not suitable for production.",
                    evidence=f"Certificate subject: {result.cert_subject}",
                    remediation="Sign with a proper release keystore. Rotate keys if debug build leaked.",
                    cwe="CWE-321",
                    cvss=8.0,
                    tags=["signing", "debug-cert"],
                )
            )

        if result.signature_algorithm == "SHA1withRSA":
            result.findings.append(
                MobileFinding(
                    title="Weak certificate signature: SHA-1",
                    severity=SecurityLevel.MEDIUM,
                    owasp_category="M10",
                    description="Certificate uses SHA-1 signature which is cryptographically deprecated.",
                    evidence=f"Algorithm: {result.signature_algorithm}",
                    remediation="Re-sign with SHA-256 or stronger. Use APK Signature Scheme v2+.",
                    cwe="CWE-328",
                    tags=["signing", "sha1"],
                )
            )

        if result.is_self_signed and not result.is_debug_cert:
            result.findings.append(
                MobileFinding(
                    title="Self-signed certificate",
                    severity=SecurityLevel.INFO,
                    owasp_category="M7",
                    description="APK uses self-signed certificate (normal for Android apps).",
                    evidence=f"Subject = Issuer: {result.cert_subject}",
                    tags=["signing", "self-signed"],
                )
            )


# ════════════════════════════════════════════════════════════════════════════
# STORAGE PATTERN ANALYZER
# ════════════════════════════════════════════════════════════════════════════


class StoragePatternAnalyzer:
    """Analyze data storage patterns from DEX strings."""

    def __init__(self, strings: List[str]) -> None:
        self._strings = strings

    def analyze(self) -> StorageAnalysis:
        """Detect data storage patterns."""
        result = StorageAnalysis()
        all_text = "\n".join(self._strings)

        result.uses_shared_preferences = (
            "SharedPreferences" in all_text or "getSharedPreferences" in all_text
        )
        result.uses_encrypted_shared_prefs = "EncryptedSharedPreferences" in all_text
        result.uses_sqlite = (
            "SQLiteDatabase" in all_text or "SQLiteOpenHelper" in all_text
        )
        result.uses_sqlcipher = "SQLCipher" in all_text or "net.sqlcipher" in all_text
        result.uses_room = "androidx.room" in all_text or "RoomDatabase" in all_text
        result.uses_realm = "io.realm" in all_text
        result.uses_internal_storage = (
            "openFileOutput" in all_text or "getFilesDir" in all_text
        )
        result.uses_external_storage = (
            "getExternalFilesDir" in all_text
            or "getExternalStorageDirectory" in all_text
            or "Environment.getExternalStorageDirectory" in all_text
        )
        result.uses_keystore = (
            "AndroidKeyStore" in all_text or "KeyStore.getInstance" in all_text
        )
        result.uses_file_provider = "FileProvider" in all_text
        result.clipboard_usage = (
            "ClipboardManager" in all_text or "setPrimaryClip" in all_text
        )
        result.logging_detected = (
            "Log.d(" in all_text or "Log.v(" in all_text or "Log.i(" in all_text
        )

        self._generate_findings(result)
        return result

    def _generate_findings(self, result: StorageAnalysis) -> None:
        """Generate findings from storage analysis."""
        if result.uses_shared_preferences and not result.uses_encrypted_shared_prefs:
            result.findings.append(
                MobileFinding(
                    title="SharedPreferences without encryption",
                    severity=SecurityLevel.MEDIUM,
                    owasp_category="M9",
                    description="App uses unencrypted SharedPreferences for data storage.",
                    evidence="SharedPreferences/getSharedPreferences detected without EncryptedSharedPreferences",
                    remediation="Migrate to EncryptedSharedPreferences from AndroidX Security.",
                    cwe="CWE-312",
                    tags=["storage", "shared-prefs", "unencrypted"],
                )
            )

        if result.uses_sqlite and not result.uses_sqlcipher:
            result.findings.append(
                MobileFinding(
                    title="SQLite database without encryption",
                    severity=SecurityLevel.MEDIUM,
                    owasp_category="M9",
                    description="App uses plain SQLite without encryption.",
                    evidence="SQLiteDatabase/SQLiteOpenHelper without SQLCipher",
                    remediation="Use SQLCipher for encrypted databases or Room with encryption.",
                    cwe="CWE-311",
                    tags=["storage", "sqlite", "unencrypted"],
                )
            )

        if result.uses_external_storage:
            result.findings.append(
                MobileFinding(
                    title="External storage usage detected",
                    severity=SecurityLevel.HIGH,
                    owasp_category="M9",
                    description=(
                        "App writes to external storage which is world-readable on "
                        "Android < 10 and accessible to other apps."
                    ),
                    evidence="getExternalFilesDir/getExternalStorageDirectory usage",
                    remediation="Use internal storage or scoped storage. Encrypt external files.",
                    cwe="CWE-276",
                    tags=["storage", "external-storage"],
                )
            )

        if result.clipboard_usage:
            result.findings.append(
                MobileFinding(
                    title="Clipboard access detected",
                    severity=SecurityLevel.MEDIUM,
                    owasp_category="M9",
                    description="App interacts with clipboard — sensitive data may be exposed.",
                    evidence="ClipboardManager/setPrimaryClip detected",
                    remediation="Avoid copying sensitive data to clipboard. Clear after use.",
                    cwe="CWE-200",
                    tags=["storage", "clipboard"],
                )
            )

        if not result.uses_keystore:
            result.findings.append(
                MobileFinding(
                    title="Android KeyStore not used",
                    severity=SecurityLevel.MEDIUM,
                    owasp_category="M10",
                    description="App does not appear to use Android KeyStore for cryptographic key storage.",
                    evidence="No AndroidKeyStore/KeyStore.getInstance references found",
                    remediation="Use Android KeyStore for all cryptographic key storage.",
                    cwe="CWE-321",
                    tags=["storage", "keystore"],
                )
            )


# ════════════════════════════════════════════════════════════════════════════
# PLAY STORE POLICY CHECKER
# ════════════════════════════════════════════════════════════════════════════


class PlayStorePolicyChecker:
    """Check for Google Play Store policy violations."""

    def check(
        self, manifest: ManifestAnalysis, dex: DexAnalysis
    ) -> List[MobileFinding]:
        """Check for Play Store policy violations."""
        findings: List[MobileFinding] = []

        # Target SDK requirement (Play Store requires recent SDK)
        if 0 < manifest.target_sdk < 33:
            findings.append(
                MobileFinding(
                    title=f"Play Store: targetSdk {manifest.target_sdk} below requirement",
                    severity=SecurityLevel.HIGH,
                    owasp_category="M8",
                    description=(
                        f"Google Play requires targetSdkVersion >= 33 for new apps "
                        f"and updates. Current: {manifest.target_sdk}."
                    ),
                    evidence=f"targetSdkVersion={manifest.target_sdk}",
                    remediation="Update targetSdkVersion to 34+",
                    tags=["policy", "play-store", "target-sdk"],
                )
            )

        # Background location
        if (
            "android.permission.ACCESS_BACKGROUND_LOCATION"
            in manifest.permissions_requested
        ):
            findings.append(
                MobileFinding(
                    title="Play Store: Background location — requires justification",
                    severity=SecurityLevel.MEDIUM,
                    owasp_category="M6",
                    description=(
                        "ACCESS_BACKGROUND_LOCATION requires Play Console declaration "
                        "and review. May cause app rejection if unjustified."
                    ),
                    evidence="uses-permission: ACCESS_BACKGROUND_LOCATION",
                    remediation="Document background location usage or remove permission.",
                    tags=["policy", "play-store", "location"],
                )
            )

        # SMS/Call permissions
        sms_call_perms = {
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_CALL_LOG",
            "android.permission.WRITE_CALL_LOG",
            "android.permission.PROCESS_OUTGOING_CALLS",
        }
        restricted = sms_call_perms & set(manifest.permissions_requested)
        if restricted:
            findings.append(
                MobileFinding(
                    title=f"Play Store: Restricted permissions ({len(restricted)})",
                    severity=SecurityLevel.HIGH,
                    owasp_category="M6",
                    description=(
                        f"App uses restricted SMS/Call permissions: {restricted}. "
                        f"Requires Play Console approval or will be rejected."
                    ),
                    evidence=str(restricted),
                    remediation="Submit permission declaration form in Play Console.",
                    tags=["policy", "play-store", "restricted-permissions"],
                )
            )

        # ALL_FILES_ACCESS
        if (
            "android.permission.MANAGE_EXTERNAL_STORAGE"
            in manifest.permissions_requested
        ):
            findings.append(
                MobileFinding(
                    title="Play Store: All files access — requires approval",
                    severity=SecurityLevel.MEDIUM,
                    owasp_category="M6",
                    description="MANAGE_EXTERNAL_STORAGE requires Play Console declaration.",
                    evidence="uses-permission: MANAGE_EXTERNAL_STORAGE",
                    remediation="Use Storage Access Framework or MediaStore API instead.",
                    tags=["policy", "play-store", "storage"],
                )
            )

        # Deceptive behavior indicators
        if dex.dynamic_loading:
            findings.append(
                MobileFinding(
                    title="Play Store: Dynamic code loading — policy risk",
                    severity=SecurityLevel.MEDIUM,
                    owasp_category="M2",
                    description=(
                        "Dynamic code loading may violate Play Store policy on "
                        "deceptive behavior if used to download and execute new code."
                    ),
                    evidence=f"Dynamic loading: {len(dex.dynamic_loading)} instances",
                    remediation="Ensure all executable code is included in the APK bundle.",
                    tags=["policy", "play-store", "dynamic-code"],
                )
            )

        return findings


# ════════════════════════════════════════════════════════════════════════════
# MAIN ANALYZER — FULL ORCHESTRATION
# ════════════════════════════════════════════════════════════════════════════


class SirenAPKAnalyzer:
    """Complete static analysis orchestrator for Android APKs and iOS IPAs.

    Performs exhaustive security analysis covering:
    - Manifest/plist audit
    - DEX bytecode string analysis
    - Certificate validation
    - Network security config
    - Native library security
    - Data storage patterns
    - Third-party SDK detection
    - Play Store policy compliance
    - OWASP MASVS mapping
    """

    VERSION = "1.0.0"

    def __init__(
        self,
        apk_path: str = "",
        ipa_path: str = "",
        depth: AnalysisDepth = AnalysisDepth.STANDARD,
    ) -> None:
        self.apk_path = apk_path
        self.ipa_path = ipa_path
        self.depth = depth

    async def analyze_apk(self) -> FullAnalysisResult:
        """Run full static analysis on an APK file."""
        start = time.time()
        result = FullAnalysisResult(analysis_depth=self.depth)

        if not self.apk_path or not os.path.isfile(self.apk_path):
            logger.error("APK file not found: %s", self.apk_path)
            return result

        logger.info(
            "[SIREN APK] Starting %s analysis of %s",
            self.depth.value,
            os.path.basename(self.apk_path),
        )

        try:
            with zipfile.ZipFile(self.apk_path, "r") as zf:
                # 1. Manifest analysis
                manifest_result = await self._analyze_manifest(zf)
                result.manifest = manifest_result
                result.all_findings.extend(manifest_result.findings)

                # 2. DEX analysis
                dex_result = await self._analyze_dex(zf)
                result.dex = dex_result
                result.all_findings.extend(dex_result.findings)

                # 3. Certificate analysis
                cert_result = await self._analyze_certificate(zf)
                result.certificate = cert_result
                result.all_findings.extend(cert_result.findings)

                # 4. Network security config
                nsc_result = await self._analyze_network_config(zf)
                result.network_security = nsc_result
                result.all_findings.extend(nsc_result.findings)

                # 5. Native libraries (if DEEP or EXHAUSTIVE)
                if self.depth.value in ("deep", "exhaustive"):
                    native_result = await self._analyze_native_libs(zf)
                    result.native_libs = native_result
                    result.all_findings.extend(native_result.findings)

                # 6. Storage patterns
                if dex_result:
                    storage_analyzer = StoragePatternAnalyzer(
                        [s.get("context", "") for s in dex_result.secrets_found]
                        if dex_result.secrets_found
                        else []
                    )
                    # Re-extract strings for storage analysis
                    all_dex_strings = []
                    for name in zf.namelist():
                        if name.endswith(".dex"):
                            try:
                                dex_data = zf.read(name)
                                extractor = DexStringExtractor(dex_data)
                                all_dex_strings.extend(extractor.extract())
                            except Exception:
                                pass
                    if all_dex_strings:
                        storage_analyzer = StoragePatternAnalyzer(all_dex_strings)
                        storage_result = storage_analyzer.analyze()
                        result.storage = storage_result
                        result.all_findings.extend(storage_result.findings)

                # 7. Play Store policy check (if STANDARD+)
                if manifest_result and dex_result:
                    policy_checker = PlayStorePolicyChecker()
                    policy_findings = policy_checker.check(manifest_result, dex_result)
                    result.all_findings.extend(policy_findings)

                # Build APKInfo summary
                result.apk_info = self._build_apk_info(zf, manifest_result)

        except zipfile.BadZipFile:
            logger.error("Invalid APK (not a valid ZIP): %s", self.apk_path)
        except Exception as e:
            logger.error("APK analysis error: %s", e)

        result.analysis_duration = time.time() - start
        logger.info(
            "[SIREN APK] Analysis complete: %d findings in %.1fs",
            len(result.all_findings),
            result.analysis_duration,
        )

        return result

    async def analyze_ipa(self) -> FullAnalysisResult:
        """Run static analysis on an IPA file."""
        start = time.time()
        result = FullAnalysisResult(analysis_depth=self.depth)

        if not self.ipa_path or not os.path.isfile(self.ipa_path):
            logger.error("IPA file not found: %s", self.ipa_path)
            return result

        logger.info(
            "[SIREN IPA] Starting %s analysis of %s",
            self.depth.value,
            os.path.basename(self.ipa_path),
        )

        try:
            with zipfile.ZipFile(self.ipa_path, "r") as zf:
                # Find the .app directory
                app_dir = ""
                for name in zf.namelist():
                    if name.startswith("Payload/") and name.endswith(".app/Info.plist"):
                        app_dir = name.rsplit("Info.plist", 1)[0]
                        break

                if not app_dir:
                    logger.error("No .app directory found in IPA")
                    return result

                # Parse Info.plist
                plist_data = self._parse_plist_xml(zf.read(f"{app_dir}Info.plist"))

                # Parse entitlements if available
                entitlements = {}
                ent_path = f"{app_dir}embedded.mobileprovision"
                if ent_path in zf.namelist():
                    try:
                        mp_data = zf.read(ent_path)
                        entitlements = self._extract_entitlements(mp_data)
                    except Exception as e:
                        logger.debug("Entitlements extraction error: %s", e)

                # Analyze
                analyzer = IPAPlistAnalyzer(plist_data, entitlements)
                findings = analyzer.analyze()
                result.all_findings.extend(findings)

                # Build IPAInfo
                result.ipa_info = self._build_ipa_info(
                    zf, plist_data, entitlements, app_dir
                )

        except zipfile.BadZipFile:
            logger.error("Invalid IPA (not a valid ZIP): %s", self.ipa_path)
        except Exception as e:
            logger.error("IPA analysis error: %s", e)

        result.analysis_duration = time.time() - start
        logger.info(
            "[SIREN IPA] Analysis complete: %d findings in %.1fs",
            len(result.all_findings),
            result.analysis_duration,
        )

        return result

    # ── Internal APK Analysis Methods ───────────────────────────────────

    async def _analyze_manifest(self, zf: zipfile.ZipFile) -> ManifestAnalysis:
        """Extract and analyze AndroidManifest.xml."""
        try:
            manifest_data = zf.read("AndroidManifest.xml")
            parser = BinaryXMLParser(manifest_data)
            root = parser.parse()
            if root is None:
                logger.warning("Failed to parse AndroidManifest.xml")
                return ManifestAnalysis()

            analyzer = ManifestAnalyzer(root)
            return analyzer.analyze()
        except KeyError:
            logger.warning("AndroidManifest.xml not found in APK")
            return ManifestAnalysis()
        except Exception as e:
            logger.debug("Manifest analysis error: %s", e)
            return ManifestAnalysis()

    async def _analyze_dex(self, zf: zipfile.ZipFile) -> DexAnalysis:
        """Extract and analyze all DEX files."""
        all_strings: List[str] = []
        total_classes = 0
        total_methods = 0

        for name in sorted(zf.namelist()):
            if name.endswith(".dex"):
                try:
                    dex_data = zf.read(name)
                    extractor = DexStringExtractor(dex_data)
                    strings = extractor.extract()
                    all_strings.extend(strings)
                    total_classes += extractor.get_class_count()
                    total_methods += extractor.get_method_count()
                except Exception as e:
                    logger.debug("DEX analysis error for %s: %s", name, e)

        if not all_strings:
            return DexAnalysis()

        # Limit string analysis for QUICK mode
        if self.depth == AnalysisDepth.QUICK:
            all_strings = all_strings[:50000]

        analyzer = DexDeepAnalyzer(all_strings, total_classes, total_methods)
        return analyzer.analyze()

    async def _analyze_certificate(self, zf: zipfile.ZipFile) -> CertificateAnalysis:
        """Analyze APK signing certificate."""
        # Look for cert in META-INF
        cert_files = [
            n
            for n in zf.namelist()
            if n.startswith("META-INF/")
            and (n.endswith(".RSA") or n.endswith(".DSA") or n.endswith(".EC"))
        ]

        if not cert_files:
            result = CertificateAnalysis()
            result.findings.append(
                MobileFinding(
                    title="No signing certificate found",
                    severity=SecurityLevel.HIGH,
                    owasp_category="M7",
                    description="APK does not contain a v1 signing certificate in META-INF/.",
                    evidence="No .RSA/.DSA/.EC file in META-INF/",
                    remediation="Verify APK is properly signed with APK Signature Scheme v2/v3.",
                    tags=["signing", "missing-cert"],
                )
            )
            return result

        try:
            cert_data = zf.read(cert_files[0])
            analyzer = CertificateAnalyzer(cert_data)
            result = analyzer.analyze()

            # Check for v2/v3 signatures
            # APK Sig Block is at the end of the ZIP before Central Directory
            # We check for the magic bytes
            apk_data = Path(self.apk_path).read_bytes()
            if b"APK Sig Block 42" in apk_data:
                result.scheme_versions.append(2)
            if 1 not in result.scheme_versions:
                result.scheme_versions.insert(0, 1)

            return result
        except Exception as e:
            logger.debug("Certificate analysis error: %s", e)
            return CertificateAnalysis()

    async def _analyze_network_config(
        self, zf: zipfile.ZipFile
    ) -> NetworkSecurityAnalysis:
        """Analyze network_security_config.xml if present."""
        # Check for network security config
        nsc_paths = [
            "res/xml/network_security_config.xml",
            "res/xml/network_security_configuration.xml",
        ]

        for nsc_path in nsc_paths:
            if nsc_path in zf.namelist():
                try:
                    nsc_data = zf.read(nsc_path)
                    analyzer = NetworkSecurityConfigAnalyzer(nsc_data)
                    return analyzer.analyze()
                except Exception as e:
                    logger.debug("NSC analysis error: %s", e)

        # No config found
        result = NetworkSecurityAnalysis(has_config=False)
        result.findings.append(
            MobileFinding(
                title="No network security configuration",
                severity=SecurityLevel.LOW,
                owasp_category="M5",
                description="App does not define network_security_config.xml.",
                evidence="res/xml/network_security_config.xml not found",
                remediation="Add network security config with cert pinning and cleartext policies.",
                cwe="CWE-295",
                tags=["nsc", "missing"],
            )
        )
        return result

    async def _analyze_native_libs(self, zf: zipfile.ZipFile) -> NativeLibAnalysis:
        """Analyze native .so libraries."""
        result = NativeLibAnalysis()

        so_files = [n for n in zf.namelist() if n.endswith(".so")]
        architectures: Set[str] = set()

        for so_path in so_files:
            # Extract architecture from path
            parts = so_path.split("/")
            for part in parts:
                if part in ("armeabi-v7a", "arm64-v8a", "x86", "x86_64", "armeabi"):
                    architectures.add(part)

            try:
                so_data = zf.read(so_path)
                elf = ELFAnalyzer(so_data)
                info = elf.analyze()

                lib_name = os.path.basename(so_path)
                lib_info = {
                    "name": lib_name,
                    "path": so_path,
                    "size": len(so_data),
                    **info,
                }
                result.libraries.append(lib_info)

                # Security checks
                if not info.get("nx"):
                    result.findings.append(
                        MobileFinding(
                            title=f"NX disabled: {lib_name}",
                            severity=SecurityLevel.HIGH,
                            owasp_category="M7",
                            description=f"Native library {lib_name} has executable stack (NX disabled).",
                            evidence=f"{so_path}: NX bit not set",
                            remediation="Compile with -z noexecstack",
                            cwe="CWE-119",
                            tags=["native", "nx", lib_name],
                        )
                    )

                if not info.get("pie"):
                    result.findings.append(
                        MobileFinding(
                            title=f"No PIE: {lib_name}",
                            severity=SecurityLevel.MEDIUM,
                            owasp_category="M7",
                            description=f"Native library {lib_name} is not position-independent.",
                            evidence=f"{so_path}: PIE not enabled",
                            remediation="Compile with -fPIE -pie",
                            cwe="CWE-119",
                            tags=["native", "pie", lib_name],
                        )
                    )

                if not info.get("canary"):
                    result.findings.append(
                        MobileFinding(
                            title=f"No stack canary: {lib_name}",
                            severity=SecurityLevel.MEDIUM,
                            owasp_category="M7",
                            description=f"Native library {lib_name} lacks stack canary protection.",
                            evidence=f"{so_path}: no __stack_chk_fail",
                            remediation="Compile with -fstack-protector-all",
                            cwe="CWE-121",
                            tags=["native", "stack-canary", lib_name],
                        )
                    )

                # Check dangerous imports
                dangerous = {"strcpy", "strcat", "sprintf", "gets", "system", "popen"}
                for imp in info.get("imports", []):
                    if imp in dangerous:
                        result.dangerous_imports.append(
                            {
                                "library": lib_name,
                                "function": imp,
                            }
                        )
                        result.findings.append(
                            MobileFinding(
                                title=f"Dangerous function: {imp} in {lib_name}",
                                severity=(
                                    SecurityLevel.HIGH
                                    if imp in ("system", "popen")
                                    else SecurityLevel.MEDIUM
                                ),
                                owasp_category="M7",
                                description=f"Native library uses dangerous function {imp}().",
                                evidence=f"{so_path}: {imp}()",
                                remediation=f"Replace {imp}() with safe alternative.",
                                cwe="CWE-676",
                                tags=["native", "dangerous-func", imp],
                            )
                        )

            except Exception as e:
                logger.debug("Native lib analysis error for %s: %s", so_path, e)

        result.architectures = sorted(architectures)

        if not result.architectures:
            pass  # No native code — this is fine
        elif "arm64-v8a" not in result.architectures:
            result.findings.append(
                MobileFinding(
                    title="Missing arm64-v8a native library",
                    severity=SecurityLevel.LOW,
                    owasp_category="M8",
                    description="No arm64-v8a native libraries — Play Store requires 64-bit support.",
                    evidence=f"Architectures: {result.architectures}",
                    remediation="Add arm64-v8a builds for 64-bit support.",
                    tags=["native", "architecture", "64bit"],
                )
            )

        return result

    def _build_apk_info(
        self, zf: zipfile.ZipFile, manifest: ManifestAnalysis
    ) -> APKInfo:
        """Build APKInfo from analysis results."""
        info = APKInfo()
        info.path = self.apk_path
        info.package_name = manifest.package
        info.version_name = manifest.version_name
        info.version_code = manifest.version_code
        info.min_sdk = manifest.min_sdk
        info.target_sdk = manifest.target_sdk
        info.compile_sdk = manifest.compile_sdk
        info.permissions = manifest.permissions_requested
        info.dangerous_permissions = manifest.dangerous_permissions
        info.debuggable = manifest.debuggable
        info.allow_backup = manifest.allow_backup
        info.uses_cleartext = manifest.uses_cleartext
        info.deeplinks = manifest.deeplinks
        info.custom_schemes = list(set(manifest.custom_schemes))
        info.meta_data = manifest.meta_data
        info.exported_components = [c["name"] for c in manifest.exported_components]
        info.activities = [a["name"] for a in manifest.activities]
        info.services = [s["name"] for s in manifest.services]
        info.receivers = [r["name"] for r in manifest.receivers]
        info.providers = [p["name"] for p in manifest.providers]

        # Count DEX files
        info.dex_count = sum(1 for n in zf.namelist() if n.endswith(".dex"))

        # Native libs
        info.native_libs = [
            os.path.basename(n) for n in zf.namelist() if n.endswith(".so")
        ]

        # File hash
        try:
            h = hashlib.sha256()
            with open(self.apk_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            info.sha256 = h.hexdigest()
        except Exception:
            pass

        # Total size
        try:
            info.total_size_bytes = os.path.getsize(self.apk_path)
        except Exception:
            pass

        return info

    # ── Internal IPA Analysis Methods ───────────────────────────────────

    def _parse_plist_xml(self, data: bytes) -> Dict[str, Any]:
        """Parse XML plist data into dict."""
        try:
            text = data.decode("utf-8", errors="replace")
            root = ET.fromstring(text)

            dict_elem = root.find("dict")
            if dict_elem is not None:
                return self._plist_dict_to_python(dict_elem)
        except ET.ParseError:
            # Try binary plist (simplified)
            return self._parse_binary_plist(data)
        except Exception as e:
            logger.debug("Plist parse error: %s", e)

        return {}

    def _plist_dict_to_python(self, dict_elem: ET.Element) -> Dict[str, Any]:
        """Convert plist dict element to Python dict."""
        result: Dict[str, Any] = {}
        children = list(dict_elem)

        i = 0
        while i < len(children) - 1:
            if children[i].tag == "key":
                key = children[i].text or ""
                value = self._plist_value(children[i + 1])
                result[key] = value
                i += 2
            else:
                i += 1

        return result

    def _plist_value(self, elem: ET.Element) -> Any:
        """Convert plist value element to Python value."""
        tag = elem.tag
        if tag == "string":
            return elem.text or ""
        elif tag == "integer":
            return int(elem.text or "0")
        elif tag == "real":
            return float(elem.text or "0")
        elif tag == "true":
            return True
        elif tag == "false":
            return False
        elif tag == "array":
            return [self._plist_value(child) for child in elem]
        elif tag == "dict":
            return self._plist_dict_to_python(elem)
        elif tag == "data":
            try:
                return base64.b64decode(elem.text or "")
            except Exception:
                return elem.text or ""
        return elem.text or ""

    def _parse_binary_plist(self, data: bytes) -> Dict[str, Any]:
        """Minimal binary plist parser — extracts key strings."""
        result: Dict[str, Any] = {}
        if not data.startswith(b"bplist"):
            return result

        # Extract readable strings as keys
        text = data.decode("ascii", errors="ignore")
        # Find NSAppTransportSecurity patterns
        if "NSAllowsArbitraryLoads" in text:
            result.setdefault("NSAppTransportSecurity", {})[
                "NSAllowsArbitraryLoads"
            ] = True

        return result

    def _extract_entitlements(self, mp_data: bytes) -> Dict[str, Any]:
        """Extract entitlements from mobileprovision file."""
        # Mobile provision is a CMS envelope containing a plist
        # Find the plist within
        start = mp_data.find(b"<?xml")
        end = mp_data.find(b"</plist>")

        if start == -1 or end == -1:
            return {}

        plist_data = mp_data[start : end + len(b"</plist>")]
        full_plist = self._parse_plist_xml(plist_data)

        return full_plist.get("Entitlements", {})

    def _build_ipa_info(
        self,
        zf: zipfile.ZipFile,
        plist: Dict[str, Any],
        entitlements: Dict[str, Any],
        app_dir: str,
    ) -> IPAInfo:
        """Build IPAInfo from analysis results."""
        info = IPAInfo()
        info.path = self.ipa_path
        info.bundle_id = plist.get("CFBundleIdentifier", "")
        info.bundle_name = plist.get("CFBundleName", "")
        info.version = plist.get("CFBundleShortVersionString", "")
        info.build = plist.get("CFBundleVersion", "")
        info.min_ios = plist.get("MinimumOSVersion", "")
        info.entitlements = entitlements

        # URL schemes
        for url_type in plist.get("CFBundleURLTypes", []):
            if isinstance(url_type, dict):
                info.url_schemes.extend(url_type.get("CFBundleURLSchemes", []))

        # Universal links
        assoc = entitlements.get("com.apple.developer.associated-domains", [])
        if isinstance(assoc, list):
            info.universal_links = [d for d in assoc if d.startswith("applinks:")]

        # ATS
        ats = plist.get("NSAppTransportSecurity", {})
        if isinstance(ats, dict):
            info.allows_arbitrary_loads = bool(ats.get("NSAllowsArbitraryLoads"))
            info.has_app_transport_security = True

        # Frameworks
        for name in zf.namelist():
            if name.startswith(f"{app_dir}Frameworks/") and name.endswith(
                ".framework/"
            ):
                fw_name = name.split("/")[-2].replace(".framework", "")
                if fw_name not in info.frameworks:
                    info.frameworks.append(fw_name)

        # Hash
        try:
            h = hashlib.sha256()
            with open(self.ipa_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            info.sha256 = h.hexdigest()
        except Exception:
            pass

        try:
            info.total_size_bytes = os.path.getsize(self.ipa_path)
        except Exception:
            pass

        return info
