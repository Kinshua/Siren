#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  🔬  SIREN DEEP FINGERPRINT — Multi-Layer Stack Detection Engine  🔬          ██
██                                                                                ██
██  Fingerprinting profundo multi-camada: vai além de banners e headers.          ██
██                                                                                ██
██  Camadas de Detecção:                                                         ██
██    L0 — Banner Grabbing (trivial, 80% dos scanners param aqui)               ██
██    L1 — Header Analysis (timing, ordering, casing, defaults)                 ██
██    L2 — Behavioral Probing (error patterns, 404 styles, redirects)           ██
██    L3 — Protocol Quirks (TCP window, TLS ciphers, HTTP/2 frames)            ██
██    L4 — Application DNA (response body patterns, JS frameworks, meta)        ██
██    L5 — Timing Analysis (processing latency, GC pauses, cold starts)         ██
██    L6 — Composite Inference (combina L0-L5 com bayesian scoring)             ██
██                                                                                ██
██  "Quando o WAF esconde o Server header, SIREN lê a assinatura no silêncio." ██
██                                                                                ██
████████████████████████████████████████████████████████████████████████████████████
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import re
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

logger = logging.getLogger("siren.intelligence.deep_fingerprint")


# ════════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════════════════════════════

MAX_FINGERPRINT_CACHE = 10_000
VERSION_INFERENCE_MIN_CONFIDENCE = 0.55
TIMING_SAMPLE_COUNT = 5
COMPOSITE_WEIGHT_SUM = 1.0


# ════════════════════════════════════════════════════════════════════════════════
# ENUMS
# ════════════════════════════════════════════════════════════════════════════════

class FingerprintLayer(Enum):
    """Detection layer that produced the fingerprint."""
    L0_BANNER = auto()
    L1_HEADER = auto()
    L2_BEHAVIOR = auto()
    L3_PROTOCOL = auto()
    L4_APP_DNA = auto()
    L5_TIMING = auto()
    L6_COMPOSITE = auto()


class TechCategory(Enum):
    """Technology category taxonomy."""
    WEB_SERVER = auto()
    APP_FRAMEWORK = auto()
    LANGUAGE_RUNTIME = auto()
    CMS = auto()
    DATABASE = auto()
    CACHE = auto()
    CDN = auto()
    WAF = auto()
    LOAD_BALANCER = auto()
    CONTAINER_RUNTIME = auto()
    OS = auto()
    JS_FRAMEWORK = auto()
    CSS_FRAMEWORK = auto()
    ANALYTICS = auto()
    PAYMENT = auto()
    AUTH_PROVIDER = auto()
    CI_CD = auto()
    CLOUD_PROVIDER = auto()
    MESSAGE_QUEUE = auto()
    SEARCH_ENGINE = auto()
    REVERSE_PROXY = auto()


class VersionConfidence(Enum):
    """Confidence in version detection."""
    EXACT = auto()       # "nginx/1.24.0" from banner
    MINOR = auto()       # "nginx/1.24.x"
    MAJOR = auto()       # "nginx/1.x"
    RANGE = auto()       # "nginx 1.20-1.24"
    FAMILY_ONLY = auto() # "nginx" (no version)


# ════════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class TechSignature:
    """
    A technology signature — a fingerprint pattern that identifies a technology.
    Each signature has detection rules for one or more layers.
    """
    tech_name: str
    category: TechCategory
    vendor: str = ""
    # Detection rules per layer (dict of layer → pattern list)
    banner_patterns: List[str] = field(default_factory=list)
    header_signatures: Dict[str, str] = field(default_factory=dict)  # header → regex
    behavior_patterns: List[str] = field(default_factory=list)
    body_patterns: List[str] = field(default_factory=list)
    meta_patterns: List[str] = field(default_factory=list)
    js_patterns: List[str] = field(default_factory=list)
    cookie_patterns: List[str] = field(default_factory=list)
    # Version extraction
    version_regex: str = ""  # Group 1 = version string
    # Known CVEs per version range
    cve_ranges: Dict[str, List[str]] = field(default_factory=dict)  # "< 1.25.0" → [CVE-...]
    # Detection weight
    weight: float = 1.0
    # Implies other technologies
    implies: List[str] = field(default_factory=list)
    # Excludes other technologies
    excludes: List[str] = field(default_factory=list)


@dataclass
class DetectedTech:
    """A single technology detection result."""
    tech_name: str
    category: TechCategory
    version: str = ""
    version_confidence: VersionConfidence = VersionConfidence.FAMILY_ONLY
    confidence: float = 0.0  # [0, 1]
    layers_detected: Set[FingerprintLayer] = field(default_factory=set)
    evidence: List[str] = field(default_factory=list)
    cves: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tech_name": self.tech_name,
            "category": self.category.name,
            "version": self.version,
            "version_confidence": self.version_confidence.name,
            "confidence": round(self.confidence, 4),
            "layers_detected": [l.name for l in self.layers_detected],
            "evidence": self.evidence,
            "cves": self.cves,
            "metadata": self.metadata,
        }


@dataclass
class FingerprintResult:
    """Complete fingerprint result for a target."""
    target: str
    timestamp: float = field(default_factory=time.time)
    technologies: List[DetectedTech] = field(default_factory=list)
    raw_signals: Dict[str, Any] = field(default_factory=dict)
    header_hash: str = ""
    behavior_hash: str = ""
    composite_score: float = 0.0
    scan_duration_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "timestamp": self.timestamp,
            "technologies": [t.to_dict() for t in self.technologies],
            "raw_signals": self.raw_signals,
            "header_hash": self.header_hash,
            "behavior_hash": self.behavior_hash,
            "composite_score": round(self.composite_score, 4),
            "scan_duration_ms": round(self.scan_duration_ms, 2),
            "tech_count": len(self.technologies),
        }

    def get_by_category(self, category: TechCategory) -> List[DetectedTech]:
        return [t for t in self.technologies if t.category == category]

    def get_high_confidence(self, threshold: float = 0.7) -> List[DetectedTech]:
        return [t for t in self.technologies if t.confidence >= threshold]

    def get_all_cves(self) -> List[str]:
        cves: List[str] = []
        for t in self.technologies:
            cves.extend(t.cves)
        return sorted(set(cves))


@dataclass
class HeaderProfile:
    """Structured profile from HTTP headers."""
    server: str = ""
    x_powered_by: str = ""
    header_order: List[str] = field(default_factory=list)
    header_casing: Dict[str, str] = field(default_factory=dict)  # normalized → original
    cookies: Dict[str, str] = field(default_factory=dict)
    security_headers: Dict[str, bool] = field(default_factory=dict)
    custom_headers: Dict[str, str] = field(default_factory=dict)
    content_type: str = ""
    etag_format: str = ""  # weak/strong, hex/base64
    cache_behavior: str = ""


@dataclass
class BehaviorProfile:
    """Target behavior profile from probing responses."""
    error_404_signature: str = ""      # hash of 404 page body pattern
    error_500_signature: str = ""      # hash of 500 page body pattern
    redirect_pattern: str = ""         # how redirects are issued
    path_traversal_response: str = ""  # response to ../../../etc
    method_not_allowed: List[str] = field(default_factory=list)  # blocked methods
    default_page_hash: str = ""
    robots_txt_hash: str = ""
    favicon_hash: str = ""


@dataclass
class TimingProfile:
    """Timing analysis profile."""
    avg_response_ms: float = 0.0
    std_response_ms: float = 0.0
    min_response_ms: float = 0.0
    max_response_ms: float = 0.0
    gc_pause_detected: bool = False
    cold_start_detected: bool = False
    timing_cluster: str = ""  # "fast" / "medium" / "slow" / "variable"


# ════════════════════════════════════════════════════════════════════════════════
# SIGNATURE DATABASE — Built-in technology signatures
# ════════════════════════════════════════════════════════════════════════════════

class SignatureDB:
    """
    Database of technology signatures for fingerprinting.
    Thread-safe, extensible with custom signatures.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._signatures: Dict[str, TechSignature] = {}
        self._load_builtin()

    def _load_builtin(self) -> None:
        """Load built-in signatures."""
        builtins = [
            # ── Web Servers ──────────────────────────────────────
            TechSignature(
                tech_name="nginx", category=TechCategory.WEB_SERVER, vendor="F5/NGINX",
                banner_patterns=[r"nginx/?[\d.]*"],
                header_signatures={"server": r"nginx"},
                version_regex=r"nginx/([\d.]+)",
                body_patterns=[r"<center>nginx</center>", r"<hr><center>nginx"],
                cve_ranges={
                    "< 1.25.4": ["CVE-2024-7347"],
                    "< 1.25.0": ["CVE-2023-44487"],
                    "< 1.21.0": ["CVE-2021-23017"],
                },
                implies=["Linux"],
            ),
            TechSignature(
                tech_name="Apache", category=TechCategory.WEB_SERVER, vendor="Apache Foundation",
                banner_patterns=[r"Apache/?[\d.]*"],
                header_signatures={"server": r"Apache"},
                version_regex=r"Apache/([\d.]+)",
                body_patterns=[r"Apache/[\d.]+ Server at", r"<address>Apache"],
                cve_ranges={
                    "< 2.4.58": ["CVE-2023-45802", "CVE-2023-43622"],
                    "< 2.4.55": ["CVE-2023-25690", "CVE-2023-27522"],
                    "< 2.4.52": ["CVE-2022-22720", "CVE-2021-44790"],
                },
            ),
            TechSignature(
                tech_name="IIS", category=TechCategory.WEB_SERVER, vendor="Microsoft",
                banner_patterns=[r"Microsoft-IIS/?[\d.]*"],
                header_signatures={"server": r"Microsoft-IIS", "x-powered-by": r"ASP\.NET"},
                version_regex=r"Microsoft-IIS/([\d.]+)",
                body_patterns=[r"IIS Windows Server"],
                implies=["ASP.NET", "Windows Server"],
                cve_ranges={
                    "< 10.0": ["CVE-2021-31166", "CVE-2022-21907"],
                },
            ),
            TechSignature(
                tech_name="LiteSpeed", category=TechCategory.WEB_SERVER, vendor="LiteSpeed Technologies",
                banner_patterns=[r"LiteSpeed"],
                header_signatures={"server": r"LiteSpeed"},
                version_regex=r"LiteSpeed/([\d.]+)",
            ),
            TechSignature(
                tech_name="Caddy", category=TechCategory.WEB_SERVER, vendor="Caddy",
                banner_patterns=[r"Caddy"],
                header_signatures={"server": r"Caddy"},
                version_regex=r"Caddy/([\d.]+)",
            ),
            # ── CDN / Reverse Proxy ──────────────────────────────
            TechSignature(
                tech_name="Cloudflare", category=TechCategory.CDN, vendor="Cloudflare",
                header_signatures={"server": r"cloudflare", "cf-ray": r".+", "cf-cache-status": r".+"},
                cookie_patterns=[r"__cf_bm", r"__cflb", r"cf_clearance"],
                body_patterns=[r"cloudflare"],
            ),
            TechSignature(
                tech_name="AWS CloudFront", category=TechCategory.CDN, vendor="Amazon",
                header_signatures={"x-amz-cf-id": r".+", "x-amz-cf-pop": r".+", "via": r"cloudfront"},
                implies=["AWS"],
            ),
            TechSignature(
                tech_name="Akamai", category=TechCategory.CDN, vendor="Akamai",
                header_signatures={"x-akamai-transformed": r".+"},
                cookie_patterns=[r"akamai"],
            ),
            TechSignature(
                tech_name="Fastly", category=TechCategory.CDN, vendor="Fastly",
                header_signatures={"x-served-by": r"cache-", "x-fastly-request-id": r".+"},
            ),
            TechSignature(
                tech_name="Varnish", category=TechCategory.REVERSE_PROXY, vendor="Varnish Software",
                header_signatures={"via": r"varnish", "x-varnish": r"\d+"},
            ),
            # ── WAF ──────────────────────────────────────────────
            TechSignature(
                tech_name="AWS WAF", category=TechCategory.WAF, vendor="Amazon",
                header_signatures={"x-amzn-requestid": r".+"},
                cookie_patterns=[r"aws-waf-token"],
                body_patterns=[r"Request blocked"],
            ),
            TechSignature(
                tech_name="ModSecurity", category=TechCategory.WAF, vendor="Trustwave",
                header_signatures={"server": r"mod_security"},
                body_patterns=[r"ModSecurity", r"mod_security", r"OWASP ModSecurity"],
            ),
            TechSignature(
                tech_name="Imperva/Incapsula", category=TechCategory.WAF, vendor="Imperva",
                header_signatures={"x-iinfo": r".+", "x-cdn": r"Imperva"},
                cookie_patterns=[r"incap_ses_", r"visid_incap_"],
            ),
            TechSignature(
                tech_name="Sucuri", category=TechCategory.WAF, vendor="Sucuri",
                header_signatures={"x-sucuri-id": r".+", "server": r"Sucuri"},
                body_patterns=[r"Access Denied - Sucuri"],
            ),
            # ── Language / Runtime ────────────────────────────────
            TechSignature(
                tech_name="PHP", category=TechCategory.LANGUAGE_RUNTIME, vendor="PHP Group",
                header_signatures={"x-powered-by": r"PHP"},
                version_regex=r"PHP/([\d.]+)",
                cookie_patterns=[r"PHPSESSID"],
                body_patterns=[r"Fatal error:.*in.*/.*\.php", r"Parse error:.*\.php"],
                cve_ranges={
                    "< 8.3.4": ["CVE-2024-2756"],
                    "< 8.2.0": ["CVE-2022-31631"],
                    "< 8.1.0": ["CVE-2021-21708"],
                    "< 7.4.0": ["CVE-2019-11043"],
                },
            ),
            TechSignature(
                tech_name="ASP.NET", category=TechCategory.LANGUAGE_RUNTIME, vendor="Microsoft",
                header_signatures={"x-powered-by": r"ASP\.NET", "x-aspnet-version": r".+"},
                version_regex=r"X-AspNet-Version: ([\d.]+)",
                cookie_patterns=[r"ASP\.NET_SessionId", r"\.AspNetCore\."],
                implies=["IIS", "Windows Server"],
            ),
            TechSignature(
                tech_name="Java/Servlet", category=TechCategory.LANGUAGE_RUNTIME, vendor="Oracle",
                header_signatures={"x-powered-by": r"Servlet"},
                cookie_patterns=[r"JSESSIONID"],
                body_patterns=[r"java\.lang\.", r"javax\.servlet", r"org\.apache\.catalina"],
                implies=["Tomcat"],
            ),
            TechSignature(
                tech_name="Python", category=TechCategory.LANGUAGE_RUNTIME,
                header_signatures={"server": r"gunicorn|uvicorn|waitress|CherryPy"},
                body_patterns=[r"Traceback \(most recent call last\)", r"File \".*\.py\""],
            ),
            TechSignature(
                tech_name="Node.js", category=TechCategory.LANGUAGE_RUNTIME, vendor="OpenJS Foundation",
                header_signatures={"x-powered-by": r"Express"},
                body_patterns=[r"Cannot GET /", r"ReferenceError:", r"SyntaxError:.*\.js"],
                cookie_patterns=[r"connect\.sid"],
            ),
            # ── Frameworks ────────────────────────────────────────
            TechSignature(
                tech_name="Django", category=TechCategory.APP_FRAMEWORK, vendor="Django Software Foundation",
                header_signatures={"x-frame-options": r"DENY"},
                cookie_patterns=[r"csrftoken", r"django_language", r"sessionid"],
                body_patterns=[r"csrfmiddlewaretoken", r"django\.contrib"],
                implies=["Python"],
            ),
            TechSignature(
                tech_name="Flask", category=TechCategory.APP_FRAMEWORK, vendor="Pallets",
                header_signatures={"server": r"Werkzeug"},
                body_patterns=[r"Werkzeug Debugger", r"werkzeug\.exceptions"],
                implies=["Python"],
            ),
            TechSignature(
                tech_name="Spring Boot", category=TechCategory.APP_FRAMEWORK, vendor="VMware",
                header_signatures={"x-application-context": r".+"},
                body_patterns=[r"Whitelabel Error Page", r'"timestamp":.*"status":.*"error"'],
                cookie_patterns=[r"JSESSIONID"],
                implies=["Java/Servlet"],
                cve_ranges={
                    "< 3.2.2": ["CVE-2023-34055"],
                    "< 2.7.0": ["CVE-2022-22965"],  # Spring4Shell
                },
            ),
            TechSignature(
                tech_name="Laravel", category=TechCategory.APP_FRAMEWORK, vendor="Laravel",
                cookie_patterns=[r"laravel_session", r"XSRF-TOKEN"],
                body_patterns=[r"laravel", r"Illuminate\\"],
                header_signatures={"set-cookie": r"laravel_session"},
                implies=["PHP"],
            ),
            TechSignature(
                tech_name="Ruby on Rails", category=TechCategory.APP_FRAMEWORK, vendor="Rails",
                header_signatures={"x-powered-by": r"Phusion Passenger", "x-runtime": r"[\d.]+"},
                cookie_patterns=[r"_session_id"],
                body_patterns=[r"ActionController", r"ActiveRecord"],
            ),
            TechSignature(
                tech_name="Express.js", category=TechCategory.APP_FRAMEWORK,
                header_signatures={"x-powered-by": r"Express"},
                implies=["Node.js"],
            ),
            TechSignature(
                tech_name="Next.js", category=TechCategory.APP_FRAMEWORK, vendor="Vercel",
                header_signatures={"x-powered-by": r"Next\.js", "x-nextjs-cache": r".+", "x-nextjs-matched-path": r".+"},
                body_patterns=[r"__NEXT_DATA__", r"/_next/static", r"__next"],
                cookie_patterns=[r"__next"],
                implies=["Node.js", "React"],
            ),
            TechSignature(
                tech_name="Nuxt.js", category=TechCategory.APP_FRAMEWORK, vendor="NuxtLabs",
                body_patterns=[r"__NUXT__", r"/_nuxt/"],
                implies=["Node.js", "Vue.js"],
            ),
            # ── CMS ───────────────────────────────────────────────
            TechSignature(
                tech_name="WordPress", category=TechCategory.CMS, vendor="Automattic",
                body_patterns=[r"/wp-content/", r"/wp-includes/", r"wp-json", r"WordPress"],
                meta_patterns=[r'<meta name="generator" content="WordPress'],
                header_signatures={"link": r"wp-json"},
                cookie_patterns=[r"wordpress_", r"wp-settings-"],
                implies=["PHP", "MySQL"],
                cve_ranges={
                    "< 6.4.3": ["CVE-2024-1071"],
                    "< 6.3.2": ["CVE-2023-39999"],
                },
            ),
            TechSignature(
                tech_name="Drupal", category=TechCategory.CMS, vendor="Drupal Association",
                body_patterns=[r"/sites/default/files", r"Drupal\.settings"],
                header_signatures={"x-generator": r"Drupal", "x-drupal-cache": r".+"},
                meta_patterns=[r'<meta name="generator" content="Drupal'],
                implies=["PHP"],
                cve_ranges={
                    "< 10.2.0": ["CVE-2023-44383"],
                    "< 9.5.0": ["CVE-2022-25277"],
                },
            ),
            TechSignature(
                tech_name="Joomla", category=TechCategory.CMS, vendor="Open Source Matters",
                body_patterns=[r"/media/jui/", r"/components/com_"],
                meta_patterns=[r'<meta name="generator" content="Joomla'],
                cookie_patterns=[r"joomla_"],
                implies=["PHP", "MySQL"],
            ),
            # ── Modern Frameworks & Runtimes ─────────────────────
            TechSignature(
                tech_name="Astro", category=TechCategory.APP_FRAMEWORK, vendor="Astro",
                body_patterns=[r"astro-island", r'data-astro-\w+', r"astro\.config"],
                implies=["Node.js"],
            ),
            TechSignature(
                tech_name="Qwik", category=TechCategory.APP_FRAMEWORK, vendor="Builder.io",
                body_patterns=[r"q:container", r"qwik", r"qwik-loader"],
                implies=["Node.js"],
            ),
            TechSignature(
                tech_name="Remix", category=TechCategory.APP_FRAMEWORK, vendor="Shopify",
                body_patterns=[r"__remix", r"entry\.client", r"remix-run"],
                implies=["Node.js", "React"],
            ),
            TechSignature(
                tech_name="SvelteKit", category=TechCategory.APP_FRAMEWORK, vendor="Svelte",
                body_patterns=[r"__sveltekit", r"_app/immutable"],
                implies=["Node.js", "Svelte"],
            ),
            TechSignature(
                tech_name="Bun", category=TechCategory.LANGUAGE_RUNTIME, vendor="Oven",
                header_signatures={"x-powered-by": r"[Bb]un", "server": r"[Bb]un"},
            ),
            TechSignature(
                tech_name="Deno", category=TechCategory.LANGUAGE_RUNTIME, vendor="Deno Land",
                header_signatures={"x-powered-by": r"[Dd]eno", "server": r"[Dd]eno"},
            ),
            # ── JS Frameworks ─────────────────────────────────────
            TechSignature(
                tech_name="React", category=TechCategory.JS_FRAMEWORK, vendor="Meta",
                body_patterns=[r"react\.production\.min\.js", r'data-reactroot', r"__REACT_DEVTOOLS"],
                js_patterns=[r"react-dom", r"createElement"],
            ),
            TechSignature(
                tech_name="Vue.js", category=TechCategory.JS_FRAMEWORK, vendor="Evan You",
                body_patterns=[r"vue\.min\.js", r"vue\.runtime", r'data-v-[a-f0-9]'],
                js_patterns=[r"__vue__", r"Vue\.component"],
            ),
            TechSignature(
                tech_name="Angular", category=TechCategory.JS_FRAMEWORK, vendor="Google",
                body_patterns=[r"ng-version", r"ng-app", r"angular\.min\.js"],
                js_patterns=[r"@angular/core"],
            ),
            TechSignature(
                tech_name="jQuery", category=TechCategory.JS_FRAMEWORK, vendor="OpenJS Foundation",
                body_patterns=[r"jquery[\.-][\d.]*\.min\.js", r"jquery\.min\.js"],
                js_patterns=[r"jQuery"],
                version_regex=r"jquery[.-]([\d.]+)",
            ),
            # ── Databases (from error leaks) ──────────────────────
            TechSignature(
                tech_name="MySQL", category=TechCategory.DATABASE, vendor="Oracle",
                body_patterns=[r"MySQL.*Error", r"mysql_fetch", r"You have an error in your SQL syntax"],
            ),
            TechSignature(
                tech_name="PostgreSQL", category=TechCategory.DATABASE, vendor="PostgreSQL Global",
                body_patterns=[r"PostgreSQL.*ERROR", r"pg_query", r"PSQLException"],
            ),
            TechSignature(
                tech_name="MongoDB", category=TechCategory.DATABASE, vendor="MongoDB Inc",
                body_patterns=[r"MongoError", r"MongoServerError", r"mongoose"],
            ),
            TechSignature(
                tech_name="Redis", category=TechCategory.CACHE, vendor="Redis Ltd",
                body_patterns=[r"WRONGTYPE Operation", r"redis\.exceptions"],
            ),
            # ── Analytics / Tracking ──────────────────────────────
            TechSignature(
                tech_name="Google Analytics", category=TechCategory.ANALYTICS, vendor="Google",
                body_patterns=[r"google-analytics\.com/analytics\.js", r"gtag/js", r"UA-\d+-\d+", r"G-[A-Z0-9]+"],
                js_patterns=[r"googletagmanager\.com"],
            ),
            TechSignature(
                tech_name="Google Tag Manager", category=TechCategory.ANALYTICS, vendor="Google",
                body_patterns=[r"googletagmanager\.com/gtm\.js", r"GTM-[A-Z0-9]+"],
            ),
            # ── Cloud Providers ───────────────────────────────────
            TechSignature(
                tech_name="AWS", category=TechCategory.CLOUD_PROVIDER, vendor="Amazon",
                header_signatures={"x-amz-request-id": r".+", "x-amz-id-2": r".+"},
            ),
            TechSignature(
                tech_name="Google Cloud", category=TechCategory.CLOUD_PROVIDER, vendor="Google",
                header_signatures={"x-cloud-trace-context": r".+", "via": r"google"},
            ),
            TechSignature(
                tech_name="Azure", category=TechCategory.CLOUD_PROVIDER, vendor="Microsoft",
                header_signatures={"x-ms-request-id": r".+", "x-azure-ref": r".+"},
            ),
            # ── Container / Orchestration ─────────────────────────
            TechSignature(
                tech_name="Kubernetes", category=TechCategory.CONTAINER_RUNTIME, vendor="CNCF",
                header_signatures={"x-envoy-upstream-service-time": r".+"},
                body_patterns=[r"kubernetes", r"kube-system"],
            ),
            TechSignature(
                tech_name="Envoy Proxy", category=TechCategory.REVERSE_PROXY, vendor="CNCF",
                header_signatures={"server": r"envoy", "x-envoy-upstream-service-time": r"\d+"},
                implies=["Kubernetes"],
            ),
            TechSignature(
                tech_name="Traefik", category=TechCategory.REVERSE_PROXY, vendor="Traefik Labs",
                header_signatures={"server": r"Traefik"},
            ),
        ]
        for sig in builtins:
            self._signatures[sig.tech_name] = sig

    def get(self, tech_name: str) -> Optional[TechSignature]:
        with self._lock:
            return self._signatures.get(tech_name)

    def add(self, signature: TechSignature) -> None:
        with self._lock:
            self._signatures[signature.tech_name] = signature

    def all_signatures(self) -> List[TechSignature]:
        with self._lock:
            return list(self._signatures.values())

    def count(self) -> int:
        with self._lock:
            return len(self._signatures)


# ════════════════════════════════════════════════════════════════════════════════
# LAYER ANALYZERS — Each layer extracts signals independently
# ════════════════════════════════════════════════════════════════════════════════

class L0BannerAnalyzer:
    """Layer 0: Banner grabbing — extracts tech from server banners."""

    def __init__(self, db: SignatureDB) -> None:
        self._db = db

    def analyze(self, banner: str) -> List[Tuple[str, float, str]]:
        """Returns [(tech_name, confidence, evidence), ...]"""
        if not banner:
            return []
        results: List[Tuple[str, float, str]] = []
        for sig in self._db.all_signatures():
            for pattern in sig.banner_patterns:
                m = re.search(pattern, banner, re.IGNORECASE)
                if m:
                    results.append((sig.tech_name, 0.90, f"Banner match: {m.group(0)}"))
                    break
        return results


class L1HeaderAnalyzer:
    """
    Layer 1: Header analysis — goes beyond simple matching.
    Analyzes header ordering, casing, default values, and anomalies.
    """

    # Known header orderings per server (first 5 headers)
    HEADER_ORDER_SIGNATURES: Dict[str, List[str]] = {
        "nginx": ["server", "date", "content-type", "content-length", "connection"],
        "Apache": ["date", "server", "content-type", "content-length"],
        "IIS": ["content-type", "server", "x-powered-by", "date"],
        "Cloudflare": ["date", "content-type", "transfer-encoding", "connection", "cf-ray"],
    }

    def __init__(self, db: SignatureDB) -> None:
        self._db = db

    def analyze(self, headers: Dict[str, str]) -> Tuple[List[Tuple[str, float, str]], HeaderProfile]:
        """Analyze headers deeply. Returns detections and profile."""
        detections: List[Tuple[str, float, str]] = []
        profile = HeaderProfile()

        headers_lower = {k.lower(): v for k, v in headers.items()}
        profile.header_order = list(headers.keys())
        profile.header_casing = {k.lower(): k for k in headers.keys()}
        profile.server = headers_lower.get("server", "")
        profile.x_powered_by = headers_lower.get("x-powered-by", "")
        profile.content_type = headers_lower.get("content-type", "")

        # Extract ETag format
        etag = headers_lower.get("etag", "")
        if etag:
            if etag.startswith("W/"):
                profile.etag_format = "weak"
            else:
                profile.etag_format = "strong"

        # Security headers check
        sec_headers = [
            "strict-transport-security", "content-security-policy",
            "x-frame-options", "x-content-type-options",
            "x-xss-protection", "referrer-policy", "permissions-policy",
        ]
        for h in sec_headers:
            profile.security_headers[h] = h in headers_lower

        # Match against signatures
        for sig in self._db.all_signatures():
            for header_name, pattern in sig.header_signatures.items():
                value = headers_lower.get(header_name, "")
                if value and re.search(pattern, value, re.IGNORECASE):
                    detections.append(
                        (sig.tech_name, 0.85, f"Header '{header_name}': '{value}' matches /{pattern}/")
                    )
                    break

        # Header order analysis
        order_lower = [h.lower() for h in profile.header_order[:5]]
        for server_name, expected_order in self.HEADER_ORDER_SIGNATURES.items():
            match_count = sum(
                1 for i, h in enumerate(order_lower)
                if i < len(expected_order) and h == expected_order[i]
            )
            if match_count >= 3:
                detections.append(
                    (server_name, 0.60, f"Header order matches {server_name} pattern ({match_count}/5)")
                )

        # Cookie-based detection
        set_cookie = headers_lower.get("set-cookie", "")
        for sig in self._db.all_signatures():
            for cp in sig.cookie_patterns:
                if re.search(cp, set_cookie, re.IGNORECASE):
                    detections.append(
                        (sig.tech_name, 0.80, f"Cookie pattern '{cp}' found")
                    )
                    break

        return detections, profile


class L2BehaviorAnalyzer:
    """
    Layer 2: Behavioral analysis — examines how the server responds
    to unusual requests (404, 500, method not allowed, path traversal).
    """

    # Known 404 page patterns
    ERROR_SIGNATURES: Dict[str, List[str]] = {
        "nginx": [r"<center>nginx</center>", r"<title>404 Not Found</title>.*nginx"],
        "Apache": [r"<address>Apache.*Server at", r"Not Found.*The requested URL"],
        "IIS": [r"Server Error in.*Application", r"HTTP Error 404.*IIS"],
        "Tomcat": [r"Apache Tomcat.*404", r"HTTP Status 404"],
        "Express.js": [r"Cannot GET", r"Cannot POST"],
        "Django": [r"Page not found.*404", r"Using the URLconf defined in"],
        "Laravel": [r"Sorry, the page you are looking for could not be found", r"NotFoundHttpException"],
        "Spring Boot": [r"Whitelabel Error Page", r'"status":404'],
    }

    def analyze(
        self,
        error_404_body: str = "",
        error_500_body: str = "",
        method_responses: Optional[Dict[str, int]] = None,
    ) -> Tuple[List[Tuple[str, float, str]], BehaviorProfile]:
        """Analyze target behavior. Returns detections and profile."""
        detections: List[Tuple[str, float, str]] = []
        profile = BehaviorProfile()

        if error_404_body:
            profile.error_404_signature = hashlib.md5(
                error_404_body.encode(errors="ignore")
            ).hexdigest()[:12]

            for server, patterns in self.ERROR_SIGNATURES.items():
                for pattern in patterns:
                    if re.search(pattern, error_404_body, re.IGNORECASE | re.DOTALL):
                        detections.append(
                            (server, 0.75, f"404 page matches {server} signature")
                        )
                        break

        if error_500_body:
            profile.error_500_signature = hashlib.md5(
                error_500_body.encode(errors="ignore")
            ).hexdigest()[:12]

            # Stack trace analysis
            if "Traceback (most recent call last)" in error_500_body:
                detections.append(("Python", 0.95, "Python traceback in error page"))
            if "java.lang." in error_500_body or "javax.servlet" in error_500_body:
                detections.append(("Java/Servlet", 0.95, "Java stack trace in error page"))
            if "at Microsoft.AspNetCore" in error_500_body:
                detections.append(("ASP.NET", 0.95, "ASP.NET stack trace in error page"))
            if "Fatal error:" in error_500_body and ".php" in error_500_body:
                detections.append(("PHP", 0.95, "PHP fatal error in error page"))

        if method_responses:
            blocked = [m for m, code in method_responses.items() if code in (405, 501)]
            profile.method_not_allowed = blocked

        return detections, profile


class L4AppDNAAnalyzer:
    """
    Layer 4: Application DNA — analyzes response body patterns.
    Detects JS frameworks, CSS frameworks, meta tags, embedded techs.
    """

    def __init__(self, db: SignatureDB) -> None:
        self._db = db

    def analyze(self, body: str) -> List[Tuple[str, float, str]]:
        """Analyze response body for technology fingerprints."""
        if not body:
            return []

        detections: List[Tuple[str, float, str]] = []

        for sig in self._db.all_signatures():
            # Body patterns
            for pattern in sig.body_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    detections.append(
                        (sig.tech_name, 0.80, f"Body pattern: {pattern[:60]}")
                    )
                    break

            # Meta tag patterns
            for pattern in sig.meta_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    detections.append(
                        (sig.tech_name, 0.90, f"Meta tag: {pattern[:60]}")
                    )
                    break

            # JS patterns (script src, inline JS)
            for pattern in sig.js_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    detections.append(
                        (sig.tech_name, 0.70, f"JS pattern: {pattern[:60]}")
                    )
                    break

        # Additional heuristic: check for common patterns not in signature DB
        if re.search(r'<link[^>]*rel="stylesheet"[^>]*bootstrap', body, re.IGNORECASE):
            detections.append(("Bootstrap", 0.85, "Bootstrap CSS detected"))
        if re.search(r'tailwindcss|tailwind\.min\.css', body, re.IGNORECASE):
            detections.append(("Tailwind CSS", 0.85, "Tailwind CSS detected"))
        if re.search(r'font-awesome|fontawesome', body, re.IGNORECASE):
            detections.append(("Font Awesome", 0.80, "Font Awesome detected"))

        return detections


class L5TimingAnalyzer:
    """
    Layer 5: Timing analysis — detects technology from response latencies.
    Different stacks have different timing fingerprints.
    """

    # Typical timing profiles (ms) for different stacks
    TIMING_PROFILES: Dict[str, Tuple[float, float]] = {
        # (avg_ms_range_low, avg_ms_range_high)
        "nginx_static": (1.0, 15.0),
        "cdn_cached": (5.0, 30.0),
        "node_express": (10.0, 80.0),
        "python_django": (20.0, 150.0),
        "java_spring": (30.0, 200.0),
        "php_wordpress": (50.0, 400.0),
        "ruby_rails": (40.0, 250.0),
        "serverless_cold": (200.0, 3000.0),
    }

    def analyze(self, response_times_ms: List[float]) -> Tuple[List[Tuple[str, float, str]], TimingProfile]:
        """Analyze response timing pattern."""
        detections: List[Tuple[str, float, str]] = []
        profile = TimingProfile()

        if not response_times_ms or len(response_times_ms) < 2:
            return detections, profile

        profile.avg_response_ms = sum(response_times_ms) / len(response_times_ms)
        profile.min_response_ms = min(response_times_ms)
        profile.max_response_ms = max(response_times_ms)

        # Standard deviation
        mean = profile.avg_response_ms
        variance = sum((t - mean) ** 2 for t in response_times_ms) / len(response_times_ms)
        profile.std_response_ms = math.sqrt(variance)

        # GC pause detection (sudden spike > 3x std dev)
        if profile.std_response_ms > 0:
            spikes = [t for t in response_times_ms if t > mean + 3 * profile.std_response_ms]
            if spikes:
                profile.gc_pause_detected = True
                detections.append(
                    ("Java/Servlet", 0.30, f"GC pause pattern: {len(spikes)} spikes detected")
                )

        # Cold start detection (first request >> subsequent)
        if len(response_times_ms) >= 3:
            first = response_times_ms[0]
            rest_avg = sum(response_times_ms[1:]) / (len(response_times_ms) - 1)
            if first > rest_avg * 3:
                profile.cold_start_detected = True
                detections.append(
                    ("AWS Lambda", 0.35, f"Cold start pattern: first={first:.0f}ms, rest_avg={rest_avg:.0f}ms")
                )

        # Timing cluster
        avg = profile.avg_response_ms
        if avg < 20:
            profile.timing_cluster = "fast"
        elif avg < 100:
            profile.timing_cluster = "medium"
        elif avg < 500:
            profile.timing_cluster = "slow"
        else:
            profile.timing_cluster = "variable"

        return detections, profile


# ════════════════════════════════════════════════════════════════════════════════
# VERSION RESOLVER — Extract and infer precise versions
# ════════════════════════════════════════════════════════════════════════════════

class VersionResolver:
    """
    Resolves technology versions from multiple signals.
    Combines banner version, header hints, CVE response, and behavior.
    """

    def __init__(self, db: SignatureDB) -> None:
        self._db = db

    def resolve(
        self, tech_name: str, raw_signals: Dict[str, str],
    ) -> Tuple[str, VersionConfidence]:
        """Attempt to resolve version for a technology."""
        sig = self._db.get(tech_name)
        if not sig or not sig.version_regex:
            return "", VersionConfidence.FAMILY_ONLY

        # Search all raw signal values for version regex
        for source, value in raw_signals.items():
            m = re.search(sig.version_regex, value, re.IGNORECASE)
            if m:
                version = m.group(1)
                parts = version.split(".")
                if len(parts) >= 3:
                    return version, VersionConfidence.EXACT
                elif len(parts) == 2:
                    return version, VersionConfidence.MINOR
                elif len(parts) == 1:
                    return version, VersionConfidence.MAJOR

        return "", VersionConfidence.FAMILY_ONLY

    def lookup_cves(self, tech_name: str, version: str) -> List[str]:
        """Look up known CVEs for a tech at a given version."""
        sig = self._db.get(tech_name)
        if not sig or not version:
            return []

        cves: List[str] = []
        for range_str, cve_list in sig.cve_ranges.items():
            if self._version_in_range(version, range_str):
                cves.extend(cve_list)
        return sorted(set(cves))

    @staticmethod
    def _version_in_range(version: str, range_str: str) -> bool:
        """Check if version matches range like '< 1.25.0' or '>= 2.0.0'."""
        range_str = range_str.strip()
        parts = range_str.split(None, 1)
        if len(parts) != 2:
            return False
        op, target = parts[0], parts[1]

        try:
            v_parts = [int(x) for x in version.split(".")]
            t_parts = [int(x) for x in target.split(".")]
        except (ValueError, AttributeError):
            return False

        # Pad to same length
        max_len = max(len(v_parts), len(t_parts))
        v_parts.extend([0] * (max_len - len(v_parts)))
        t_parts.extend([0] * (max_len - len(t_parts)))

        if op == "<":
            return v_parts < t_parts
        elif op == "<=":
            return v_parts <= t_parts
        elif op == ">":
            return v_parts > t_parts
        elif op == ">=":
            return v_parts >= t_parts
        elif op == "==":
            return v_parts == t_parts
        return False


# ════════════════════════════════════════════════════════════════════════════════
# COMPOSITE SCORER — Bayesian combination of multi-layer signals
# ════════════════════════════════════════════════════════════════════════════════

class CompositeScorer:
    """
    Combines detections from all layers using weighted Bayesian scoring.
    Multi-layer corroboration increases confidence significantly.
    """

    # Weight per layer (how much each layer contributes to final score)
    LAYER_WEIGHTS: Dict[FingerprintLayer, float] = {
        FingerprintLayer.L0_BANNER: 0.20,
        FingerprintLayer.L1_HEADER: 0.20,
        FingerprintLayer.L2_BEHAVIOR: 0.20,
        FingerprintLayer.L3_PROTOCOL: 0.10,
        FingerprintLayer.L4_APP_DNA: 0.20,
        FingerprintLayer.L5_TIMING: 0.10,
    }

    # Multi-layer corroboration bonus
    CORROBORATION_BONUS: Dict[int, float] = {
        1: 0.0,     # Single layer — no bonus
        2: 0.10,    # Two layers agree — +10%
        3: 0.20,    # Three layers — +20%
        4: 0.30,    # Four layers — +30%
        5: 0.35,    # Five layers — high corroboration
        6: 0.40,    # All layers detected — maximum bonus
    }

    def score(
        self,
        detections: Dict[str, List[Tuple[FingerprintLayer, float, str]]],
    ) -> List[DetectedTech]:
        """
        Score all detections and produce final tech list.

        Args:
            detections: {tech_name: [(layer, confidence, evidence), ...]}

        Returns:
            Sorted list of DetectedTech (highest confidence first)
        """
        results: List[DetectedTech] = []

        for tech_name, signals in detections.items():
            layers_seen: Set[FingerprintLayer] = set()
            evidence: List[str] = []
            weighted_sum = 0.0
            weight_total = 0.0

            for layer, conf, ev in signals:
                layers_seen.add(layer)
                evidence.append(f"[{layer.name}] {ev}")
                w = self.LAYER_WEIGHTS.get(layer, 0.1)
                weighted_sum += conf * w
                weight_total += w

            if weight_total == 0:
                continue

            base_score = weighted_sum / weight_total
            corroboration = self.CORROBORATION_BONUS.get(len(layers_seen), 0.40)
            final_score = min(1.0, base_score + corroboration)

            dt = DetectedTech(
                tech_name=tech_name,
                category=TechCategory.WEB_SERVER,  # placeholder, resolved later
                confidence=final_score,
                layers_detected=layers_seen,
                evidence=evidence,
            )
            results.append(dt)

        results.sort(key=lambda t: t.confidence, reverse=True)
        return results


# ════════════════════════════════════════════════════════════════════════════════
# SIREN DEEP FINGERPRINT ENGINE — Main Orchestrator
# ════════════════════════════════════════════════════════════════════════════════

class SirenDeepFingerprint:
    """
    Main deep fingerprinting engine.

    Orchestrates all layers (L0-L6), combining multi-layer signals into
    a comprehensive, confidence-scored technology profile.

    Usage:
        engine = SirenDeepFingerprint()
        result = engine.fingerprint(
            target="example.com",
            banner="nginx/1.24.0",
            headers={"Server": "nginx/1.24.0", ...},
            body="<html>...</html>",
            error_404_body="<html>404 Not Found</html>",
            response_times_ms=[12.5, 11.0, 13.2, 12.8, 11.5],
        )
        for tech in result.get_high_confidence():
            print(f"{tech.tech_name} {tech.version} ({tech.confidence:.0%})")
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._db = SignatureDB()
        self._l0 = L0BannerAnalyzer(self._db)
        self._l1 = L1HeaderAnalyzer(self._db)
        self._l2 = L2BehaviorAnalyzer()
        self._l4 = L4AppDNAAnalyzer(self._db)
        self._l5 = L5TimingAnalyzer()
        self._version_resolver = VersionResolver(self._db)
        self._scorer = CompositeScorer()
        self._cache: Dict[str, FingerprintResult] = {}
        logger.info("SirenDeepFingerprint initialized with %d signatures", self._db.count())

    def fingerprint(
        self,
        target: str,
        banner: str = "",
        headers: Optional[Dict[str, str]] = None,
        body: str = "",
        error_404_body: str = "",
        error_500_body: str = "",
        method_responses: Optional[Dict[str, int]] = None,
        response_times_ms: Optional[List[float]] = None,
    ) -> FingerprintResult:
        """
        Perform deep fingerprinting on a target.

        Runs all layers, combines signals, resolves versions, maps CVEs.
        """
        with self._lock:
            start = time.time()
            headers = headers or {}

            # Collect all detections: {tech_name: [(layer, confidence, evidence)]}
            all_detections: Dict[str, List[Tuple[FingerprintLayer, float, str]]] = defaultdict(list)
            raw_signals: Dict[str, str] = {}

            # ── L0: Banner ────────────────────────────────────────
            if banner:
                raw_signals["banner"] = banner
                for tech, conf, ev in self._l0.analyze(banner):
                    all_detections[tech].append((FingerprintLayer.L0_BANNER, conf, ev))

            # ── L1: Headers ───────────────────────────────────────
            if headers:
                raw_signals["server"] = headers.get("Server", headers.get("server", ""))
                raw_signals["x-powered-by"] = headers.get("X-Powered-By", headers.get("x-powered-by", ""))
                raw_signals["set-cookie"] = headers.get("Set-Cookie", headers.get("set-cookie", ""))
                l1_dets, header_profile = self._l1.analyze(headers)
                for tech, conf, ev in l1_dets:
                    all_detections[tech].append((FingerprintLayer.L1_HEADER, conf, ev))

            # ── L2: Behavior ──────────────────────────────────────
            if error_404_body or error_500_body or method_responses:
                l2_dets, behavior_profile = self._l2.analyze(
                    error_404_body, error_500_body, method_responses,
                )
                for tech, conf, ev in l2_dets:
                    all_detections[tech].append((FingerprintLayer.L2_BEHAVIOR, conf, ev))

            # ── L4: App DNA ───────────────────────────────────────
            if body:
                raw_signals["body_snippet"] = body[:500]
                l4_dets = self._l4.analyze(body)
                for tech, conf, ev in l4_dets:
                    all_detections[tech].append((FingerprintLayer.L4_APP_DNA, conf, ev))

            # ── L5: Timing ────────────────────────────────────────
            if response_times_ms:
                l5_dets, timing_profile = self._l5.analyze(response_times_ms)
                for tech, conf, ev in l5_dets:
                    all_detections[tech].append((FingerprintLayer.L5_TIMING, conf, ev))

            # ── L6: Composite Scoring ─────────────────────────────
            techs = self._scorer.score(all_detections)

            # ── Resolve categories, versions, CVEs ────────────────
            for tech in techs:
                sig = self._db.get(tech.tech_name)
                if sig:
                    tech.category = sig.category

                    # Version resolution
                    version, v_conf = self._version_resolver.resolve(
                        tech.tech_name, raw_signals,
                    )
                    if version:
                        tech.version = version
                        tech.version_confidence = v_conf
                        tech.cves = self._version_resolver.lookup_cves(tech.tech_name, version)

            # ── Implied technologies ──────────────────────────────
            techs = self._resolve_implications(techs)

            # ── Build result ──────────────────────────────────────
            elapsed = (time.time() - start) * 1000
            result = FingerprintResult(
                target=target,
                technologies=techs,
                raw_signals=raw_signals,
                scan_duration_ms=elapsed,
                composite_score=sum(t.confidence for t in techs) / max(len(techs), 1),
            )

            # Cache
            self._cache[target] = result
            logger.info(
                "Fingerprinted %s: %d technologies in %.1fms",
                target, len(techs), elapsed,
            )
            return result

    def get_cached(self, target: str) -> Optional[FingerprintResult]:
        with self._lock:
            return self._cache.get(target)

    def add_signature(self, signature: TechSignature) -> None:
        """Add a custom technology signature."""
        self._db.add(signature)

    def signature_count(self) -> int:
        return self._db.count()

    def _resolve_implications(self, techs: List[DetectedTech]) -> List[DetectedTech]:
        """Add implied technologies not already in the list."""
        detected_names = {t.tech_name for t in techs}
        additions: List[DetectedTech] = []

        for tech in techs:
            sig = self._db.get(tech.tech_name)
            if not sig:
                continue
            for implied_name in sig.implies:
                if implied_name not in detected_names:
                    implied_sig = self._db.get(implied_name)
                    cat = implied_sig.category if implied_sig else TechCategory.WEB_SERVER
                    additions.append(DetectedTech(
                        tech_name=implied_name,
                        category=cat,
                        confidence=tech.confidence * 0.60,  # Lower confidence for implied
                        layers_detected=set(),
                        evidence=[f"Implied by {tech.tech_name}"],
                    ))
                    detected_names.add(implied_name)

        techs.extend(additions)
        techs.sort(key=lambda t: t.confidence, reverse=True)
        return techs
