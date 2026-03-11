#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  🔍  SIREN RECON ENGINE — Reconhecimento Completo de Alvos  🔍               ██
██                                                                                ██
██  Modulo de reconhecimento com capacidades REAIS:                               ██
██    • Port Scanning (TCP Connect / SYN)                                         ██
██    • Service Fingerprinting                                                     ██
██    • Technology Detection (Wappalyzer-style)                                   ██
██    • Subdomain Enumeration                                                      ██
██    • Directory Bruteforce                                                        ██
██    • API Endpoint Discovery                                                     ██
██    • WAF Detection                                                              ██
██    • DNS Enumeration                                                             ██
██    • SSL/TLS Analysis                                                            ██
██    • CMS Detection                                                              ██
██    • JavaScript Analysis                                                         ██
██    • Email Harvesting                                                            ██
██    • Web Spider / Link Extraction                                               ██
██    • Robots.txt / Sitemap.xml Analysis                                          ██
██    • Virtual Host Discovery                                                     ██
██    • Cloud Provider Detection                                                   ██
██                                                                                ██
██  "Antes de atacar, conheca TUDO."                                             ██
██                                                                                ██
████████████████████████████████████████████████████████████████████████████████████
"""

from __future__ import annotations

import asyncio
import base64
import enum
import hashlib
import json
import logging
import os
import random
import re
import socket
import ssl
import struct
import time
import urllib.error
import urllib.parse
import urllib.request
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

logger = logging.getLogger("siren.recon")


# ════════════════════════════════════════════════════════════════════════════
# ENUMS & DATA CLASSES
# ════════════════════════════════════════════════════════════════════════════


class PortState(enum.Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


class ServiceConfidence(enum.Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class PortResult:
    """Resultado de scan de uma porta."""

    port: int
    state: PortState
    service: str = ""
    version: str = ""
    banner: str = ""
    protocol: str = "tcp"
    confidence: ServiceConfidence = ServiceConfidence.LOW
    response_time_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "port": self.port,
            "state": self.state.value,
            "service": self.service,
            "version": self.version,
            "banner": self.banner[:200],
            "protocol": self.protocol,
            "confidence": self.confidence.value,
            "response_time_ms": round(self.response_time_ms, 2),
        }


@dataclass
class TechFingerprint:
    """Tecnologia detectada no alvo."""

    name: str
    version: str = ""
    category: str = ""
    confidence: float = 0.0
    evidence: str = ""
    cpe: str = ""
    website: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "category": self.category,
            "confidence": round(self.confidence, 2),
            "evidence": self.evidence[:200],
            "cpe": self.cpe,
        }


@dataclass
class SubdomainResult:
    """Subdominio descoberto."""

    subdomain: str
    ip: str = ""
    status_code: int = 0
    title: str = ""
    server: str = ""
    resolved: bool = False
    is_wildcard: bool = False

    def to_dict(self) -> dict:
        return {
            "subdomain": self.subdomain,
            "ip": self.ip,
            "status_code": self.status_code,
            "title": self.title,
            "server": self.server,
            "resolved": self.resolved,
        }


@dataclass
class DirectoryResult:
    """Diretorio/arquivo descoberto por bruteforce."""

    path: str
    url: str
    status_code: int
    content_length: int = 0
    redirect_url: str = ""
    content_type: str = ""
    title: str = ""
    interesting: bool = False

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "url": self.url,
            "status_code": self.status_code,
            "content_length": self.content_length,
            "redirect_url": self.redirect_url,
            "content_type": self.content_type,
            "interesting": self.interesting,
        }


@dataclass
class WAFResult:
    """WAF detectado."""

    name: str
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    bypass_tips: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "bypass_tips": self.bypass_tips,
        }


@dataclass
class SSLInfo:
    """Informacoes SSL/TLS."""

    version: str = ""
    cipher: str = ""
    bits: int = 0
    issuer: str = ""
    subject: str = ""
    sans: List[str] = field(default_factory=list)
    not_before: str = ""
    not_after: str = ""
    expired: bool = False
    self_signed: bool = False
    weak_cipher: bool = False
    supports_tls13: bool = False
    supports_tls12: bool = False
    supports_tls11: bool = False
    supports_tls10: bool = False
    supports_sslv3: bool = False
    hsts: bool = False
    hsts_max_age: int = 0

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "cipher": self.cipher,
            "bits": self.bits,
            "issuer": self.issuer,
            "subject": self.subject,
            "sans": self.sans[:20],
            "not_before": self.not_before,
            "not_after": self.not_after,
            "expired": self.expired,
            "self_signed": self.self_signed,
            "weak_cipher": self.weak_cipher,
            "tls_versions": {
                "tls1.3": self.supports_tls13,
                "tls1.2": self.supports_tls12,
                "tls1.1": self.supports_tls11,
                "tls1.0": self.supports_tls10,
                "sslv3": self.supports_sslv3,
            },
            "hsts": self.hsts,
            "hsts_max_age": self.hsts_max_age,
        }


@dataclass
class ReconResult:
    """Resultado consolidado de reconhecimento."""

    target: str
    start_time: float = 0.0
    end_time: float = 0.0
    ip_address: str = ""
    ports: List[PortResult] = field(default_factory=list)
    technologies: List[TechFingerprint] = field(default_factory=list)
    subdomains: List[SubdomainResult] = field(default_factory=list)
    directories: List[DirectoryResult] = field(default_factory=list)
    waf: Optional[WAFResult] = None
    ssl_info: Optional[SSLInfo] = None
    emails: List[str] = field(default_factory=list)
    dns_records: Dict[str, List[str]] = field(default_factory=dict)
    robots_paths: List[str] = field(default_factory=list)
    sitemap_urls: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    js_files: List[str] = field(default_factory=list)
    comments: List[str] = field(default_factory=list)
    cloud_provider: str = ""
    cms: str = ""
    web_server: str = ""
    programming_language: str = ""
    frameworks: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        if self.end_time and self.start_time:
            return self.end_time - self.start_time
        return 0.0

    @property
    def open_ports(self) -> List[PortResult]:
        return [p for p in self.ports if p.state == PortState.OPEN]

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "ip_address": self.ip_address,
            "duration_seconds": round(self.duration_seconds, 2),
            "web_server": self.web_server,
            "programming_language": self.programming_language,
            "cms": self.cms,
            "cloud_provider": self.cloud_provider,
            "frameworks": self.frameworks,
            "waf": self.waf.to_dict() if self.waf else None,
            "ssl": self.ssl_info.to_dict() if self.ssl_info else None,
            "open_ports": [p.to_dict() for p in self.open_ports],
            "technologies": [t.to_dict() for t in self.technologies],
            "subdomains_found": len(self.subdomains),
            "subdomains": [s.to_dict() for s in self.subdomains[:50]],
            "directories_found": len(self.directories),
            "directories": [d.to_dict() for d in self.directories[:100]],
            "emails": self.emails[:30],
            "dns_records": self.dns_records,
            "robots_paths": self.robots_paths[:50],
            "sitemap_urls": len(self.sitemap_urls),
            "api_endpoints": self.api_endpoints[:100],
            "js_files": self.js_files[:50],
            "errors": self.errors[:20],
        }


# ════════════════════════════════════════════════════════════════════════════
# RECON CONFIGURATION
# ════════════════════════════════════════════════════════════════════════════


@dataclass
class ReconConfig:
    """Configuracao do modulo de reconhecimento."""

    target: str
    timeout_seconds: float = 10.0
    max_concurrent: int = 50

    # Port scanning
    enable_port_scan: bool = True
    port_scan_type: str = "common"  # "common", "top100", "top1000", "full"
    custom_ports: List[int] = field(default_factory=list)

    # Subdomain enumeration
    enable_subdomain_enum: bool = True
    subdomain_wordlist: str = ""  # path to custom wordlist
    subdomain_threads: int = 20

    # Directory bruteforce
    enable_dir_bruteforce: bool = True
    dir_wordlist: str = ""
    dir_extensions: List[str] = field(
        default_factory=lambda: [
            ".php",
            ".asp",
            ".aspx",
            ".jsp",
            ".html",
            ".js",
            ".json",
            ".xml",
            ".txt",
            ".bak",
            ".old",
            ".conf",
            ".config",
            ".env",
            ".sql",
            ".db",
            ".log",
            ".yml",
            ".yaml",
            ".toml",
        ]
    )
    dir_threads: int = 20

    # Technology detection
    enable_tech_detect: bool = True

    # WAF detection
    enable_waf_detect: bool = True

    # SSL analysis
    enable_ssl_analysis: bool = True

    # DNS enumeration
    enable_dns_enum: bool = True

    # Other
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    verify_ssl: bool = False


# ════════════════════════════════════════════════════════════════════════════
# PORT DATABASES
# ════════════════════════════════════════════════════════════════════════════

COMMON_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    111,
    135,
    139,
    143,
    443,
    445,
    993,
    995,
    1433,
    1521,
    1723,
    3306,
    3389,
    5432,
    5900,
    5985,
    6379,
    8000,
    8080,
    8443,
    8888,
    9090,
    9200,
    9300,
    27017,
]

TOP_100_PORTS = [
    7,
    9,
    13,
    21,
    22,
    23,
    25,
    26,
    37,
    53,
    79,
    80,
    81,
    88,
    106,
    110,
    111,
    113,
    119,
    135,
    139,
    143,
    144,
    179,
    199,
    389,
    427,
    443,
    444,
    445,
    465,
    513,
    514,
    515,
    543,
    544,
    548,
    554,
    587,
    631,
    646,
    873,
    990,
    993,
    995,
    1025,
    1026,
    1027,
    1028,
    1029,
    1110,
    1433,
    1720,
    1723,
    1755,
    1900,
    2000,
    2001,
    2049,
    2121,
    2717,
    3000,
    3128,
    3306,
    3389,
    3986,
    4899,
    5000,
    5009,
    5051,
    5060,
    5101,
    5190,
    5357,
    5432,
    5631,
    5666,
    5800,
    5900,
    6000,
    6001,
    6646,
    7070,
    8000,
    8008,
    8009,
    8080,
    8081,
    8443,
    8888,
    9100,
    9999,
    10000,
    32768,
    49152,
    49153,
    49154,
    49155,
    49156,
]

SERVICE_BANNERS = {
    21: (
        "ftp",
        [
            (re.compile(r"220.*FTP", re.I), "FTP"),
            (re.compile(r"220.*vsftpd", re.I), "vsftpd"),
            (re.compile(r"220.*ProFTPD", re.I), "ProFTPD"),
            (re.compile(r"220.*FileZilla", re.I), "FileZilla FTP"),
            (re.compile(r"220.*Pure-FTPd", re.I), "Pure-FTPd"),
        ],
    ),
    22: (
        "ssh",
        [
            (re.compile(r"SSH-2\.0-OpenSSH[_\s]+([\d.]+)", re.I), "OpenSSH"),
            (re.compile(r"SSH-2\.0-dropbear", re.I), "Dropbear"),
            (re.compile(r"SSH-2\.0-libssh", re.I), "libssh"),
        ],
    ),
    25: (
        "smtp",
        [
            (re.compile(r"220.*ESMTP", re.I), "SMTP"),
            (re.compile(r"220.*Postfix", re.I), "Postfix"),
            (re.compile(r"220.*Exim", re.I), "Exim"),
            (re.compile(r"220.*Microsoft ESMTP", re.I), "Exchange"),
        ],
    ),
    80: ("http", []),
    110: (
        "pop3",
        [
            (re.compile(r"\+OK.*Dovecot", re.I), "Dovecot"),
        ],
    ),
    143: (
        "imap",
        [
            (re.compile(r"\* OK.*Dovecot", re.I), "Dovecot"),
            (re.compile(r"\* OK.*Courier", re.I), "Courier"),
        ],
    ),
    443: ("https", []),
    445: ("smb", []),
    1433: ("mssql", []),
    3306: (
        "mysql",
        [
            (re.compile(r"[\x00-\xff]*mysql", re.I), "MySQL"),
            (re.compile(r"MariaDB", re.I), "MariaDB"),
        ],
    ),
    3389: ("rdp", []),
    5432: ("postgresql", []),
    5900: (
        "vnc",
        [
            (re.compile(r"RFB\s+([\d.]+)", re.I), "VNC"),
        ],
    ),
    6379: (
        "redis",
        [
            (re.compile(r"redis_version:([\d.]+)", re.I), "Redis"),
            (re.compile(r"-ERR", re.I), "Redis"),
        ],
    ),
    8080: ("http-proxy", []),
    9200: ("elasticsearch", []),
    27017: ("mongodb", []),
}


# ════════════════════════════════════════════════════════════════════════════
# TECHNOLOGY FINGERPRINT DATABASE — Regras Wappalyzer-style
# ════════════════════════════════════════════════════════════════════════════

TECH_FINGERPRINTS = [
    # Web Servers
    {
        "name": "Apache",
        "category": "web-server",
        "headers": {"server": r"Apache(?:/([\d.]+))?"},
        "cpe": "cpe:/a:apache:http_server",
    },
    {
        "name": "Nginx",
        "category": "web-server",
        "headers": {"server": r"nginx(?:/([\d.]+))?"},
        "cpe": "cpe:/a:nginx:nginx",
    },
    {
        "name": "IIS",
        "category": "web-server",
        "headers": {"server": r"Microsoft-IIS(?:/([\d.]+))?"},
        "cpe": "cpe:/a:microsoft:iis",
    },
    {
        "name": "LiteSpeed",
        "category": "web-server",
        "headers": {"server": r"LiteSpeed"},
        "cpe": "cpe:/a:litespeedtech:litespeed_web_server",
    },
    {"name": "Caddy", "category": "web-server", "headers": {"server": r"Caddy"}},
    {
        "name": "Cloudflare",
        "category": "cdn",
        "headers": {"server": r"cloudflare", "cf-ray": r"."},
        "cpe": "cpe:/a:cloudflare:cloudflare",
    },
    # Programming Languages
    {
        "name": "PHP",
        "category": "language",
        "headers": {"x-powered-by": r"PHP(?:/([\d.]+))?"},
        "cookies": {"PHPSESSID": r"."},
        "cpe": "cpe:/a:php:php",
    },
    {
        "name": "ASP.NET",
        "category": "language",
        "headers": {"x-powered-by": r"ASP\.NET", "x-aspnet-version": r"([\d.]+)"},
        "cookies": {"ASP.NET_SessionId": r"."},
        "cpe": "cpe:/a:microsoft:asp.net",
    },
    {
        "name": "Java",
        "category": "language",
        "headers": {"x-powered-by": r"(?:Servlet|JSP|Tomcat)"},
        "cookies": {"JSESSIONID": r"."},
    },
    {
        "name": "Python",
        "category": "language",
        "headers": {
            "x-powered-by": r"Python",
            "server": r"(?:gunicorn|uvicorn|waitress|CherryPy)",
        },
    },
    {
        "name": "Node.js",
        "category": "language",
        "headers": {"x-powered-by": r"Express"},
        "cookies": {"connect.sid": r"."},
    },
    {
        "name": "Ruby",
        "category": "language",
        "headers": {"x-powered-by": r"Phusion Passenger"},
        "cookies": {"_session_id": r"."},
    },
    # Frameworks
    {
        "name": "Laravel",
        "category": "framework",
        "cookies": {"laravel_session": r"."},
        "meta": {"csrf-token": r"."},
    },
    {
        "name": "Django",
        "category": "framework",
        "cookies": {"csrftoken": r".", "django_language": r"."},
        "html": [r"csrfmiddlewaretoken"],
    },
    {
        "name": "Rails",
        "category": "framework",
        "headers": {"x-powered-by": r"Phusion"},
        "cookies": {"_rails_session": r"."},
    },
    {
        "name": "Spring",
        "category": "framework",
        "headers": {"x-application-context": r"."},
        "cookies": {"JSESSIONID": r"."},
    },
    {
        "name": "Flask",
        "category": "framework",
        "headers": {"server": r"(?:Werkzeug|gunicorn)"},
        "cookies": {"session": r"eyJ"},
    },
    {
        "name": "Express.js",
        "category": "framework",
        "headers": {"x-powered-by": r"Express"},
    },
    {
        "name": "Next.js",
        "category": "framework",
        "headers": {"x-powered-by": r"Next\.js"},
        "html": [r"__NEXT_DATA__", r"/_next/"],
    },
    {"name": "Nuxt.js", "category": "framework", "html": [r"__NUXT__", r"/_nuxt/"]},
    {
        "name": "Vue.js",
        "category": "framework",
        "html": [r"v-[a-z]+=\"", r"vue\.(?:min\.)?js"],
    },
    {
        "name": "React",
        "category": "framework",
        "html": [r"react\.(?:min\.)?js", r"data-reactroot", r"__REACT_DEVTOOLS_"],
    },
    {
        "name": "Angular",
        "category": "framework",
        "html": [
            r"ng-(?:app|version|controller)",
            r"angular\.(?:min\.)?js",
            r"ng-version=\"",
        ],
    },
    # CMS
    {
        "name": "WordPress",
        "category": "cms",
        "html": [r"/wp-content/", r"/wp-includes/", r"wp-json", r"wordpress"],
        "meta": {"generator": r"WordPress\s*([\d.]+)?"},
    },
    {
        "name": "Joomla",
        "category": "cms",
        "html": [r"/media/jui/", r"/components/com_"],
        "meta": {"generator": r"Joomla"},
    },
    {
        "name": "Drupal",
        "category": "cms",
        "headers": {"x-drupal-cache": r".", "x-generator": r"Drupal"},
        "html": [r"Drupal\.settings", r"/sites/default/files/"],
    },
    {
        "name": "Magento",
        "category": "cms",
        "cookies": {"frontend": r"."},
        "html": [r"/skin/frontend/", r"Mage\.Cookies", r"/static/frontend/"],
    },
    {
        "name": "Shopify",
        "category": "cms",
        "headers": {"x-shopid": r"."},
        "html": [r"cdn\.shopify\.com", r"Shopify\.theme"],
    },
    {
        "name": "Ghost",
        "category": "cms",
        "headers": {"x-powered-by": r"Ghost"},
        "meta": {"generator": r"Ghost"},
    },
    {"name": "Wix", "category": "cms", "html": [r"wix\.com", r"X-Wix"]},
    {
        "name": "Squarespace",
        "category": "cms",
        "html": [r"squarespace", r"static\.squarespace"],
    },
    # Analytics / Marketing
    {
        "name": "Google Analytics",
        "category": "analytics",
        "html": [
            r"google-analytics\.com/analytics\.js",
            r"gtag\(",
            r"UA-\d+-\d+",
            r"G-[A-Z0-9]+",
        ],
    },
    {
        "name": "Google Tag Manager",
        "category": "analytics",
        "html": [r"googletagmanager\.com/gtm\.js", r"GTM-[A-Z0-9]+"],
    },
    {
        "name": "Facebook Pixel",
        "category": "analytics",
        "html": [r"connect\.facebook\.net", r"fbevents\.js", r"fbq\("],
    },
    {
        "name": "Hotjar",
        "category": "analytics",
        "html": [r"static\.hotjar\.com", r"hjSiteSettings"],
    },
    # Security
    {
        "name": "Cloudflare WAF",
        "category": "security",
        "headers": {"cf-ray": r".", "server": r"cloudflare"},
    },
    {"name": "AWS WAF", "category": "security", "headers": {"x-amzn-requestid": r"."}},
    {
        "name": "Akamai",
        "category": "security",
        "headers": {"x-akamai-transformed": r"."},
    },
    {
        "name": "Sucuri",
        "category": "security",
        "headers": {"x-sucuri-id": r".", "server": r"Sucuri"},
    },
    {"name": "Imperva", "category": "security", "headers": {"x-iinfo": r"."}},
    # JavaScript Libraries
    {
        "name": "jQuery",
        "category": "js-library",
        "html": [r"jquery(?:\.min)?\.js", r"jQuery\s*v?([\d.]+)"],
    },
    {
        "name": "Bootstrap",
        "category": "css-framework",
        "html": [r"bootstrap(?:\.min)?\.(?:js|css)", r"Bootstrap\s*v?([\d.]+)"],
    },
    {
        "name": "Tailwind CSS",
        "category": "css-framework",
        "html": [r"tailwindcss", r"tailwind\."],
    },
    {
        "name": "Font Awesome",
        "category": "font",
        "html": [r"font-awesome", r"fontawesome", r"fa-[a-z]+"],
    },
]

# ════════════════════════════════════════════════════════════════════════════
# WAF DETECTION SIGNATURES
# ════════════════════════════════════════════════════════════════════════════

WAF_SIGNATURES = [
    {
        "name": "Cloudflare",
        "headers": {"server": r"cloudflare", "cf-ray": r"."},
        "cookies": ["__cfduid", "cf_clearance", "__cf_bm"],
        "body": [r"Attention Required! \| Cloudflare", r"cloudflare-nginx"],
        "status_codes": [403, 503],
        "bypass_tips": [
            "Try finding origin IP via DNS history",
            "Use Cloudflare bypass techniques (direct IP)",
            "Try different User-Agents",
        ],
    },
    {
        "name": "AWS WAF",
        "headers": {"x-amzn-requestid": r".", "x-amz-cf-id": r"."},
        "body": [r"<html><head><title>403 Forbidden</title></head>"],
        "bypass_tips": [
            "Try case manipulation in payloads",
            "Use Unicode normalization bypass",
        ],
    },
    {
        "name": "ModSecurity",
        "headers": {"server": r"mod_security"},
        "body": [r"mod_security", r"NOYB", r"This error was generated by Mod_Security"],
        "bypass_tips": [
            "Try encoding payloads (double URL encode)",
            "Split payloads across parameters",
            "Use comment-based bypass in SQL",
        ],
    },
    {
        "name": "Akamai",
        "headers": {"x-akamai-transformed": r".", "server": r"AkamaiGHost"},
        "body": [r"Reference&#32;&#35;"],
        "bypass_tips": [
            "Try HTTP parameter pollution",
            "Use chunked transfer encoding",
        ],
    },
    {
        "name": "Imperva / Incapsula",
        "headers": {"x-iinfo": r".", "x-cdn": r"Imperva"},
        "cookies": ["incap_ses", "visid_incap"],
        "body": [r"<html><head><META NAME=\"robots\".*incapsula"],
        "bypass_tips": [
            "Try different HTTP methods",
            "Use HTTP/2 if available",
        ],
    },
    {
        "name": "Sucuri",
        "headers": {"x-sucuri-id": r".", "server": r"Sucuri"},
        "body": [r"Access Denied.*Sucuri", r"sucuri\.net/privacy"],
        "bypass_tips": [
            "Find origin IP via historical DNS",
            "Try different request methods",
        ],
    },
    {
        "name": "Wordfence",
        "body": [r"wordfence", r"Generated by Wordfence"],
        "bypass_tips": [
            "Try bypassing via REST API",
            "Use wp-json endpoints",
        ],
    },
    {
        "name": "F5 BIG-IP ASM",
        "headers": {"server": r"BIG-IP", "x-wa-info": r"."},
        "cookies": ["BIGipServer", "TS"],
        "body": [r"The requested URL was rejected"],
        "bypass_tips": [
            "Try HTTP desync attacks",
            "Use multipart content type",
        ],
    },
    {
        "name": "Barracuda",
        "headers": {"server": r"Barracuda"},
        "cookies": ["barra_counter_session"],
        "bypass_tips": [
            "Try parameter fragmentation",
        ],
    },
    {
        "name": "DenyAll",
        "headers": {"server": r"DenyAll"},
        "cookies": ["sessioncookie"],
    },
    {
        "name": "Fortinet FortiWeb",
        "headers": {"server": r"FortiWeb"},
        "cookies": ["FORTIWAFSID"],
    },
    {
        "name": "Radware AppWall",
        "headers": {"x-sl-compstate": r"."},
    },
]

# ════════════════════════════════════════════════════════════════════════════
# SUBDOMAIN WORDLIST (built-in common subdomains)
# ════════════════════════════════════════════════════════════════════════════

DEFAULT_SUBDOMAINS = [
    "www",
    "mail",
    "ftp",
    "localhost",
    "webmail",
    "smtp",
    "pop",
    "ns1",
    "ns2",
    "ns3",
    "ns4",
    "dns",
    "dns1",
    "dns2",
    "mx",
    "mx1",
    "mx2",
    "admin",
    "api",
    "dev",
    "staging",
    "stage",
    "test",
    "testing",
    "qa",
    "uat",
    "beta",
    "demo",
    "app",
    "apps",
    "web",
    "www2",
    "portal",
    "secure",
    "vpn",
    "remote",
    "gateway",
    "proxy",
    "cdn",
    "static",
    "assets",
    "media",
    "images",
    "img",
    "download",
    "downloads",
    "upload",
    "uploads",
    "files",
    "docs",
    "doc",
    "help",
    "support",
    "status",
    "monitor",
    "monitoring",
    "dashboard",
    "panel",
    "control",
    "cp",
    "cpanel",
    "whm",
    "plesk",
    "jenkins",
    "ci",
    "build",
    "git",
    "svn",
    "repo",
    "repos",
    "jira",
    "confluence",
    "wiki",
    "blog",
    "forum",
    "shop",
    "store",
    "pay",
    "payment",
    "billing",
    "invoice",
    "crm",
    "erp",
    "hr",
    "sso",
    "auth",
    "login",
    "signup",
    "register",
    "account",
    "accounts",
    "user",
    "users",
    "profile",
    "search",
    "news",
    "old",
    "new",
    "backup",
    "bak",
    "temp",
    "tmp",
    "intranet",
    "internal",
    "corp",
    "corporate",
    "office",
    "exchange",
    "owa",
    "autodiscover",
    "m",
    "mobile",
    "wap",
    "imap",
    "pop3",
    "calendar",
    "chat",
    "meet",
    "video",
    "stream",
    "live",
    "data",
    "db",
    "database",
    "sql",
    "mysql",
    "postgres",
    "mongo",
    "redis",
    "elastic",
    "elasticsearch",
    "kibana",
    "grafana",
    "prometheus",
    "nagios",
    "zabbix",
    "splunk",
    "log",
    "logs",
    "syslog",
    "v1",
    "v2",
    "v3",
    "api-v1",
    "api-v2",
    "rest",
    "graphql",
    "sandbox",
    "preview",
    "pre",
    "preprod",
    "production",
    "prod",
]

# ════════════════════════════════════════════════════════════════════════════
# DIRECTORY WORDLIST (built-in common paths)
# ════════════════════════════════════════════════════════════════════════════

DEFAULT_DIRECTORIES = [
    "admin",
    "administrator",
    "login",
    "wp-admin",
    "wp-login.php",
    "wp-content",
    "wp-includes",
    "wp-json",
    "api",
    "api/v1",
    "api/v2",
    "graphql",
    "rest",
    "swagger",
    "swagger-ui",
    "api-docs",
    "docs",
    "documentation",
    "doc",
    "help",
    "info",
    "status",
    "health",
    "healthcheck",
    ".well-known",
    "robots.txt",
    "sitemap.xml",
    "favicon.ico",
    "crossdomain.xml",
    "security.txt",
    ".well-known/security.txt",
    "humans.txt",
    "manifest.json",
    "browserconfig.xml",
    ".git",
    ".git/HEAD",
    ".git/config",
    ".gitignore",
    ".env",
    ".env.bak",
    ".env.local",
    ".env.production",
    ".htaccess",
    ".htpasswd",
    "web.config",
    "config.php",
    "config.yml",
    "config.json",
    "settings.php",
    "settings.py",
    "application.properties",
    "application.yml",
    "backup",
    "backups",
    "bak",
    "old",
    "temp",
    "tmp",
    "test",
    "testing",
    "debug",
    "trace",
    "actuator",
    "console",
    "shell",
    "terminal",
    "cmd",
    "command",
    "phpmyadmin",
    "pma",
    "adminer",
    "phpinfo.php",
    "info.php",
    "server-status",
    "server-info",
    "nginx-status",
    "cgi-bin",
    "cgi-bin/",
    "fcgi-bin",
    "upload",
    "uploads",
    "files",
    "media",
    "assets",
    "static",
    "images",
    "img",
    "css",
    "js",
    "scripts",
    "fonts",
    "include",
    "includes",
    "inc",
    "lib",
    "libs",
    "vendor",
    "node_modules",
    "package.json",
    "package-lock.json",
    "composer.json",
    "composer.lock",
    "Gemfile",
    "Gemfile.lock",
    "requirements.txt",
    "Pipfile",
    "Pipfile.lock",
    "Makefile",
    "Dockerfile",
    "docker-compose.yml",
    "database",
    "db",
    "sql",
    "dump.sql",
    "backup.sql",
    "log",
    "logs",
    "error.log",
    "access.log",
    "debug.log",
    "Thumbs.db",
    ".DS_Store",
    "desktop.ini",
    "user",
    "users",
    "account",
    "accounts",
    "profile",
    "profiles",
    "register",
    "signup",
    "signin",
    "auth",
    "authentication",
    "logout",
    "signout",
    "forgot",
    "reset",
    "password",
    "dashboard",
    "panel",
    "control",
    "cp",
    "manage",
    "search",
    "query",
    "find",
    "lookup",
    "download",
    "export",
    "import",
    "report",
    "reports",
    "install",
    "setup",
    "wizard",
    "init",
    "initialize",
    "xmlrpc.php",
    "wp-cron.php",
    "wp-config.php.bak",
    "elmah.axd",
    "trace.axd",
    "glimpse.axd",
    "metrics",
    "prometheus",
    "grafana",
    ".svn",
    ".svn/entries",
    ".hg",
    "ckeditor",
    "tinymce",
    "editor",
    "filemanager",
    "socket.io",
    "ws",
    "websocket",
    "proxy",
    "redirect",
    "oauth",
    "callback",
    "newsletter",
    "subscribe",
    "unsubscribe",
    "feed",
    "rss",
    "atom",
    "sitemap",
    "archive",
    "archives",
    "cache",
    "cached",
    "public",
    "private",
    "secret",
    "hidden",
    "data",
    "json",
    "xml",
    "csv",
    "v1",
    "v2",
    "v3",
    "version",
]

# ════════════════════════════════════════════════════════════════════════════
# CLOUD PROVIDER DETECTION
# ════════════════════════════════════════════════════════════════════════════

CLOUD_SIGNATURES = {
    "AWS": {
        "headers": [r"x-amz-", r"x-amzn-"],
        "cnames": [r"\.amazonaws\.com", r"\.cloudfront\.net", r"\.elb\.amazonaws\.com"],
        "body": [r"AmazonS3", r"aws-", r"Amazon Web Services"],
    },
    "Azure": {
        "headers": [r"x-ms-", r"x-azure-"],
        "cnames": [
            r"\.azurewebsites\.net",
            r"\.azure-api\.net",
            r"\.cloudapp\.azure\.com",
            r"\.blob\.core\.windows\.net",
        ],
    },
    "Google Cloud": {
        "headers": [r"x-goog-", r"x-cloud-trace-context"],
        "cnames": [
            r"\.appspot\.com",
            r"\.googleapis\.com",
            r"\.run\.app",
            r"\.cloudfunctions\.net",
        ],
    },
    "Cloudflare": {
        "headers": [r"cf-ray", r"cf-cache-status"],
        "cnames": [r"\.cdn\.cloudflare\.net"],
    },
    "DigitalOcean": {
        "cnames": [r"\.digitaloceanspaces\.com", r"\.ondigitalocean\.app"],
    },
    "Heroku": {
        "headers": [r"via:.*vegur"],
        "cnames": [r"\.herokuapp\.com", r"\.herokussl\.com"],
    },
    "Vercel": {
        "headers": [r"x-vercel-"],
        "cnames": [r"\.vercel\.app", r"\.now\.sh"],
    },
    "Netlify": {
        "headers": [r"x-nf-request-id"],
        "cnames": [r"\.netlify\.app", r"\.netlify\.com"],
    },
}

# ════════════════════════════════════════════════════════════════════════════
# SIREN RECON ENGINE — O Motor de Reconhecimento
# ════════════════════════════════════════════════════════════════════════════


class SirenRecon:
    """Motor de reconhecimento completo do SIREN.

    Executa reconhecimento abrangente em alvos incluindo:
    port scanning, tech detection, subdomain enumeration,
    directory bruteforce, WAF detection, SSL analysis, etc.

    Usage:
        recon = SirenRecon(ReconConfig(target="https://example.com"))
        result = await recon.run()
    """

    def __init__(self, config: ReconConfig):
        self.config = config
        self.result = ReconResult(target=config.target)
        self._semaphore: Optional[asyncio.Semaphore] = None

    async def run(self) -> ReconResult:
        """Executa reconhecimento completo."""
        self.result.start_time = time.time()
        self._semaphore = asyncio.Semaphore(self.config.max_concurrent)
        logger.info(f"[SIREN RECON] Starting recon: {self.config.target}")

        parsed = urllib.parse.urlparse(self.config.target)
        hostname = parsed.hostname or parsed.path

        # Phase 1: DNS Resolution
        try:
            self.result.ip_address = socket.gethostbyname(hostname)
            logger.info(
                f"[SIREN RECON] Resolved {hostname} -> {self.result.ip_address}"
            )
        except socket.gaierror:
            self.result.errors.append(f"DNS resolution failed for {hostname}")

        # Phase 2: Run modules in parallel
        tasks = []

        if self.config.enable_port_scan:
            tasks.append(self._port_scan(hostname))

        if self.config.enable_tech_detect:
            tasks.append(self._detect_technologies())

        if self.config.enable_waf_detect:
            tasks.append(self._detect_waf())

        if self.config.enable_ssl_analysis and (
            parsed.scheme == "https" or not parsed.scheme
        ):
            tasks.append(self._analyze_ssl(hostname))

        if self.config.enable_dns_enum:
            tasks.append(self._enumerate_dns(hostname))

        tasks.append(self._analyze_robots_sitemap())
        tasks.append(self._extract_emails_and_comments())
        tasks.append(self._detect_cloud_provider())

        await asyncio.gather(*tasks, return_exceptions=True)

        # Phase 3: Sequential deeper analysis
        if self.config.enable_subdomain_enum:
            await self._enumerate_subdomains(hostname)

        if self.config.enable_dir_bruteforce:
            await self._bruteforce_directories()

        # Phase 4: API endpoint discovery from JS files
        await self._discover_api_endpoints()

        self.result.end_time = time.time()
        logger.info(
            f"[SIREN RECON] Complete: {len(self.result.open_ports)} open ports, "
            f"{len(self.result.technologies)} technologies, "
            f"{len(self.result.subdomains)} subdomains, "
            f"{len(self.result.directories)} directories, "
            f"{self.result.duration_seconds:.1f}s"
        )
        return self.result

    # ── HTTP Helper ─────────────────────────────────────────────────────

    async def _http_get(
        self, url: str, headers: Optional[Dict[str, str]] = None, timeout: float = 0
    ) -> Tuple[int, Dict[str, str], str]:
        """GET request simples retornando (status, headers, body)."""
        tout = timeout or self.config.timeout_seconds
        req_headers = {"User-Agent": self.config.user_agent}
        if headers:
            req_headers.update(headers)

        try:
            req = urllib.request.Request(url, headers=req_headers)
            ctx = None
            if not self.config.verify_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

            loop = asyncio.get_event_loop()

            def do_req():
                try:
                    if ctx:
                        resp = urllib.request.urlopen(req, timeout=tout, context=ctx)
                    else:
                        resp = urllib.request.urlopen(req, timeout=tout)
                    status = resp.getcode()
                    rh = {k.lower(): v for k, v in resp.getheaders()}
                    body = resp.read().decode("utf-8", errors="replace")
                    return status, rh, body
                except urllib.error.HTTPError as e:
                    rh = (
                        {k.lower(): v for k, v in e.headers.items()}
                        if e.headers
                        else {}
                    )
                    try:
                        body = e.read().decode("utf-8", errors="replace")
                    except Exception:
                        body = ""
                    return e.code, rh, body
                except Exception as ex:
                    return 0, {}, str(ex)

            return await loop.run_in_executor(None, do_req)
        except Exception as e:
            return 0, {}, str(e)

    # ── Port Scanning ───────────────────────────────────────────────────

    async def _port_scan(self, hostname: str) -> None:
        """Scan de portas TCP via connect()."""
        if self.config.custom_ports:
            ports = self.config.custom_ports
        elif self.config.port_scan_type == "top100":
            ports = TOP_100_PORTS
        elif self.config.port_scan_type == "top1000":
            ports = list(range(1, 1001))
        elif self.config.port_scan_type == "full":
            ports = list(range(1, 65536))
        else:
            ports = COMMON_PORTS

        logger.info(f"[SIREN RECON] Port scanning {hostname}: {len(ports)} ports")

        async def scan_port(port: int) -> Optional[PortResult]:
            async with self._semaphore:
                start = time.time()
                try:
                    loop = asyncio.get_event_loop()
                    conn = asyncio.open_connection(hostname, port)
                    reader, writer = await asyncio.wait_for(conn, timeout=3.0)
                    elapsed = (time.time() - start) * 1000

                    # Try to grab banner
                    banner = ""
                    service = SERVICE_BANNERS.get(port, (f"unknown-{port}", []))[0]
                    version = ""

                    try:
                        writer.write(b"\r\n")
                        await writer.drain()
                        data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                        banner = data.decode("utf-8", errors="replace").strip()

                        # Service fingerprinting
                        svc_info = SERVICE_BANNERS.get(port)
                        if svc_info:
                            for pattern, svc_name in svc_info[1]:
                                m = pattern.search(banner)
                                if m:
                                    service = svc_name
                                    if m.groups():
                                        version = m.group(1)
                                    break
                    except Exception as e:
                        logger.debug("Banner grab error on port: %s", e)

                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception as e:
                        logger.debug("Writer close error: %s", e)

                    return PortResult(
                        port=port,
                        state=PortState.OPEN,
                        service=service,
                        version=version,
                        banner=banner[:200],
                        confidence=(
                            ServiceConfidence.HIGH
                            if banner
                            else ServiceConfidence.MEDIUM
                        ),
                        response_time_ms=elapsed,
                    )
                except asyncio.TimeoutError:
                    return PortResult(port=port, state=PortState.FILTERED)
                except ConnectionRefusedError:
                    return PortResult(port=port, state=PortState.CLOSED)
                except Exception:
                    return None

        tasks = [scan_port(p) for p in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, PortResult) and r.state == PortState.OPEN:
                self.result.ports.append(r)

    # ── Technology Detection ────────────────────────────────────────────

    async def _detect_technologies(self) -> None:
        """Detecta tecnologias usadas no alvo (Wappalyzer-style)."""
        try:
            status, headers, body = await self._http_get(self.config.target)
            if status == 0:
                return

            for fp in TECH_FINGERPRINTS:
                matched = False
                evidence = ""
                version = ""

                # Check headers
                if "headers" in fp:
                    for hdr_name, hdr_pattern in fp["headers"].items():
                        hdr_val = headers.get(hdr_name, "")
                        if hdr_val:
                            m = re.search(hdr_pattern, hdr_val, re.I)
                            if m:
                                matched = True
                                evidence = f"Header {hdr_name}: {hdr_val}"
                                if m.groups():
                                    version = m.group(1) or ""
                                break

                # Check cookies
                if not matched and "cookies" in fp:
                    set_cookie = headers.get("set-cookie", "")
                    for ck_name, ck_pattern in fp["cookies"].items():
                        if ck_name.lower() in set_cookie.lower():
                            matched = True
                            evidence = f"Cookie: {ck_name}"
                            break

                # Check HTML body
                if not matched and "html" in fp:
                    for html_pattern in fp["html"]:
                        m = re.search(html_pattern, body, re.I)
                        if m:
                            matched = True
                            evidence = f"HTML match: {m.group(0)[:80]}"
                            if m.groups():
                                version = m.group(1) or ""
                            break

                # Check meta tags
                if not matched and "meta" in fp:
                    for meta_name, meta_pattern in fp["meta"].items():
                        meta_re = re.compile(
                            rf'<meta[^>]*name=["\']?{re.escape(meta_name)}["\']?[^>]*content=["\']?([^"\']+)',
                            re.I,
                        )
                        m = meta_re.search(body)
                        if m:
                            content = m.group(1)
                            mm = re.search(meta_pattern, content, re.I)
                            if mm:
                                matched = True
                                evidence = f"Meta {meta_name}: {content}"
                                if mm.groups():
                                    version = mm.group(1) or ""
                                break

                if matched:
                    tech = TechFingerprint(
                        name=fp["name"],
                        version=version,
                        category=fp.get("category", ""),
                        confidence=0.9 if version else 0.7,
                        evidence=evidence,
                        cpe=fp.get("cpe", ""),
                    )
                    self.result.technologies.append(tech)

                    # Set shortcuts
                    if fp.get("category") == "web-server":
                        self.result.web_server = f"{fp['name']}" + (
                            f" {version}" if version else ""
                        )
                    elif fp.get("category") == "language":
                        self.result.programming_language = fp["name"]
                    elif fp.get("category") == "cms":
                        self.result.cms = fp["name"]
                    elif fp.get("category") == "framework":
                        self.result.frameworks.append(fp["name"])

            # Extract JS files
            js_pattern = re.compile(
                r'(?:src|href)=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', re.I
            )
            for m in js_pattern.finditer(body):
                js_url = urllib.parse.urljoin(self.config.target, m.group(1))
                if js_url not in self.result.js_files:
                    self.result.js_files.append(js_url)

        except Exception as e:
            self.result.errors.append(f"Tech detection error: {e}")

    # ── WAF Detection ───────────────────────────────────────────────────

    async def _detect_waf(self) -> None:
        """Detecta Web Application Firewalls."""
        try:
            # Normal request
            _, headers_normal, body_normal = await self._http_get(self.config.target)

            # Malicious request to trigger WAF
            evil_url = (
                self.config.target.rstrip("/")
                + "/?id=1' OR 1=1 --&<script>alert(1)</script>"
            )
            status_evil, headers_evil, body_evil = await self._http_get(evil_url)

            combined_headers = {**headers_normal, **headers_evil}
            combined_body = body_normal + body_evil
            combined_cookies = combined_headers.get("set-cookie", "")

            for sig in WAF_SIGNATURES:
                score = 0.0
                evidence_list = []

                # Check headers
                if "headers" in sig:
                    for hdr_name, hdr_pattern in sig["headers"].items():
                        val = combined_headers.get(hdr_name, "")
                        if val and re.search(hdr_pattern, val, re.I):
                            score += 0.3
                            evidence_list.append(f"Header {hdr_name}: {val[:80]}")

                # Check cookies
                if "cookies" in sig:
                    for ck_name in sig["cookies"]:
                        if ck_name.lower() in combined_cookies.lower():
                            score += 0.2
                            evidence_list.append(f"Cookie: {ck_name}")

                # Check body
                if "body" in sig:
                    for bp in sig["body"]:
                        if re.search(bp, combined_body, re.I):
                            score += 0.3
                            evidence_list.append(f"Body match: {bp[:60]}")

                # Check blocked status
                if "status_codes" in sig and status_evil in sig["status_codes"]:
                    score += 0.2
                    evidence_list.append(f"Blocked with HTTP {status_evil}")

                if score >= 0.3:
                    self.result.waf = WAFResult(
                        name=sig["name"],
                        confidence=min(score, 1.0),
                        evidence=evidence_list,
                        bypass_tips=sig.get("bypass_tips", []),
                    )
                    logger.info(
                        f"[SIREN RECON] WAF detected: {sig['name']} ({score:.0%})"
                    )
                    return

        except Exception as e:
            self.result.errors.append(f"WAF detection error: {e}")

    # ── SSL/TLS Analysis ────────────────────────────────────────────────

    async def _analyze_ssl(self, hostname: str) -> None:
        """Analisa configuracao SSL/TLS."""
        try:
            loop = asyncio.get_event_loop()

            def do_ssl_check():
                info = SSLInfo()
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE

                    with socket.create_connection((hostname, 443), timeout=10) as sock:
                        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                            cert = ssock.getpeercert(binary_form=True)
                            cipher_info = ssock.cipher()
                            version = ssock.version()

                            info.version = version or ""
                            if cipher_info:
                                info.cipher = cipher_info[0]
                                info.bits = (
                                    cipher_info[2] if len(cipher_info) > 2 else 0
                                )

                            # Parse certificate
                            cert_dict = ssock.getpeercert()
                            if cert_dict:
                                # Subject
                                subject = cert_dict.get("subject", ())
                                for rdn in subject:
                                    for attr_type, attr_value in rdn:
                                        if attr_type == "commonName":
                                            info.subject = attr_value

                                # Issuer
                                issuer = cert_dict.get("issuer", ())
                                issuer_parts = []
                                for rdn in issuer:
                                    for attr_type, attr_value in rdn:
                                        issuer_parts.append(f"{attr_type}={attr_value}")
                                info.issuer = ", ".join(issuer_parts)

                                # SANs
                                sans = cert_dict.get("subjectAltName", ())
                                info.sans = [v for t, v in sans if t == "DNS"]

                                # Dates
                                info.not_before = cert_dict.get("notBefore", "")
                                info.not_after = cert_dict.get("notAfter", "")

                                # Check expiry
                                if info.not_after:
                                    try:
                                        from email.utils import parsedate_to_datetime

                                        exp_date = parsedate_to_datetime(info.not_after)
                                        info.expired = (
                                            exp_date.timestamp() < time.time()
                                        )
                                    except Exception:
                                        pass

                                # Self-signed check
                                if info.subject and info.issuer:
                                    if info.subject in info.issuer:
                                        info.self_signed = True

                            # Weak cipher check
                            weak_ciphers = [
                                "RC4",
                                "DES",
                                "3DES",
                                "NULL",
                                "EXPORT",
                                "anon",
                            ]
                            if info.cipher:
                                info.weak_cipher = any(
                                    w in info.cipher.upper() for w in weak_ciphers
                                )

                except Exception as e:
                    info = SSLInfo()

                # Check TLS version support
                tls_versions = {
                    "tls1.3": (
                        ssl.TLSVersion.TLSv1_3
                        if hasattr(ssl.TLSVersion, "TLSv1_3")
                        else None
                    ),
                    "tls1.2": (
                        ssl.TLSVersion.TLSv1_2
                        if hasattr(ssl.TLSVersion, "TLSv1_2")
                        else None
                    ),
                }
                for name, ver in tls_versions.items():
                    if ver is None:
                        continue
                    try:
                        ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                        ctx2.check_hostname = False
                        ctx2.verify_mode = ssl.CERT_NONE
                        ctx2.minimum_version = ver
                        ctx2.maximum_version = ver
                        with socket.create_connection((hostname, 443), timeout=5) as s:
                            with ctx2.wrap_socket(s, server_hostname=hostname) as ss:
                                if name == "tls1.3":
                                    info.supports_tls13 = True
                                elif name == "tls1.2":
                                    info.supports_tls12 = True
                    except Exception:
                        pass

                return info

            self.result.ssl_info = await loop.run_in_executor(None, do_ssl_check)

            # Check HSTS via HTTP
            _, headers, _ = await self._http_get(self.config.target)
            hsts = headers.get("strict-transport-security", "")
            if hsts and self.result.ssl_info:
                self.result.ssl_info.hsts = True
                ma_match = re.search(r"max-age=(\d+)", hsts)
                if ma_match:
                    self.result.ssl_info.hsts_max_age = int(ma_match.group(1))

        except Exception as e:
            self.result.errors.append(f"SSL analysis error: {e}")

    # ── DNS Enumeration ─────────────────────────────────────────────────

    async def _enumerate_dns(self, hostname: str) -> None:
        """Enumera registros DNS."""
        loop = asyncio.get_event_loop()

        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

        async def query_dns(rtype: str) -> Tuple[str, List[str]]:
            try:
                if rtype == "A":
                    result = await loop.run_in_executor(
                        None, lambda: socket.getaddrinfo(hostname, None, socket.AF_INET)
                    )
                    ips = list({r[4][0] for r in result})
                    return "A", ips
                elif rtype == "AAAA":
                    try:
                        result = await loop.run_in_executor(
                            None,
                            lambda: socket.getaddrinfo(hostname, None, socket.AF_INET6),
                        )
                        ips = list({r[4][0] for r in result})
                        return "AAAA", ips
                    except socket.gaierror:
                        return "AAAA", []
                elif rtype == "MX":
                    # Use nslookup fallback on Windows
                    try:
                        proc = await asyncio.create_subprocess_exec(
                            "nslookup",
                            "-type=mx",
                            hostname,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE,
                        )
                        stdout, _ = await asyncio.wait_for(
                            proc.communicate(), timeout=10
                        )
                        output = stdout.decode("utf-8", errors="replace")
                        mx_records = re.findall(r"mail exchanger = (.+)", output)
                        return "MX", [r.strip() for r in mx_records]
                    except Exception:
                        return "MX", []
                elif rtype == "NS":
                    try:
                        proc = await asyncio.create_subprocess_exec(
                            "nslookup",
                            "-type=ns",
                            hostname,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE,
                        )
                        stdout, _ = await asyncio.wait_for(
                            proc.communicate(), timeout=10
                        )
                        output = stdout.decode("utf-8", errors="replace")
                        ns_records = re.findall(r"nameserver = (.+)", output)
                        return "NS", [r.strip() for r in ns_records]
                    except Exception:
                        return "NS", []
                elif rtype == "TXT":
                    try:
                        proc = await asyncio.create_subprocess_exec(
                            "nslookup",
                            "-type=txt",
                            hostname,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE,
                        )
                        stdout, _ = await asyncio.wait_for(
                            proc.communicate(), timeout=10
                        )
                        output = stdout.decode("utf-8", errors="replace")
                        txt_records = re.findall(r'"([^"]+)"', output)
                        return "TXT", txt_records
                    except Exception:
                        return "TXT", []
                else:
                    return rtype, []
            except Exception:
                return rtype, []

        tasks = [query_dns(rt) for rt in record_types]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, tuple) and r[1]:
                self.result.dns_records[r[0]] = r[1]

    # ── robots.txt & sitemap.xml ────────────────────────────────────────

    async def _analyze_robots_sitemap(self) -> None:
        """Analisa robots.txt e sitemap.xml."""
        base = self.config.target.rstrip("/")

        # robots.txt
        try:
            status, _, body = await self._http_get(f"{base}/robots.txt")
            if status == 200 and body:
                for line in body.splitlines():
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if (
                            path
                            and path != "/"
                            and path not in self.result.robots_paths
                        ):
                            self.result.robots_paths.append(path)
                    elif line.lower().startswith("sitemap:"):
                        sm_url = line.split(":", 1)[1].strip()
                        if sm_url.startswith("http"):
                            if sm_url not in self.result.sitemap_urls:
                                self.result.sitemap_urls.append(sm_url)
        except Exception as e:
            logger.debug("robots.txt parsing error: %s", e)

        # sitemap.xml
        try:
            status, _, body = await self._http_get(f"{base}/sitemap.xml")
            if status == 200 and body:
                urls = re.findall(r"<loc>(.*?)</loc>", body, re.I)
                for u in urls[:500]:
                    if u not in self.result.sitemap_urls:
                        self.result.sitemap_urls.append(u)
        except Exception as e:
            logger.debug("sitemap.xml parsing error: %s", e)

    # ── Email & Comment Extraction ──────────────────────────────────────

    async def _extract_emails_and_comments(self) -> None:
        """Extrai emails e comentarios HTML da pagina principal."""
        try:
            _, _, body = await self._http_get(self.config.target)
            if not body:
                return

            # Emails
            email_re = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
            emails = email_re.findall(body)
            for e in emails:
                if e not in self.result.emails and not e.endswith(
                    (".png", ".jpg", ".gif", ".css", ".js")
                ):
                    self.result.emails.append(e)

            # HTML comments
            comment_re = re.compile(r"<!--(.*?)-->", re.DOTALL)
            for m in comment_re.finditer(body):
                comment = m.group(1).strip()
                if comment and len(comment) > 5 and len(comment) < 500:
                    if comment not in self.result.comments:
                        self.result.comments.append(comment)

        except Exception as e:
            logger.debug("Email/comment extraction error: %s", e)

    # ── Cloud Provider Detection ────────────────────────────────────────

    async def _detect_cloud_provider(self) -> None:
        """Detecta provedor cloud."""
        try:
            _, headers, body = await self._http_get(self.config.target)
            headers_str = " ".join(f"{k}:{v}" for k, v in headers.items())

            for provider, sigs in CLOUD_SIGNATURES.items():
                # Check headers
                if "headers" in sigs:
                    for hp in sigs["headers"]:
                        if re.search(hp, headers_str, re.I):
                            self.result.cloud_provider = provider
                            return

                # Check CNAME records
                if "cnames" in sigs:
                    for cp in sigs["cnames"]:
                        parsed = urllib.parse.urlparse(self.config.target)
                        hostname = parsed.hostname or ""
                        try:
                            cname = socket.getfqdn(hostname)
                            if re.search(cp, cname, re.I):
                                self.result.cloud_provider = provider
                                return
                        except Exception as e:
                            logger.debug(
                                "CNAME resolution error for %s: %s", hostname, e
                            )

                # Check body
                if "body" in sigs:
                    for bp in sigs["body"]:
                        if re.search(bp, body, re.I):
                            self.result.cloud_provider = provider
                            return
        except Exception as e:
            logger.debug("Cloud provider detection error: %s", e)

    # ── Subdomain Enumeration ───────────────────────────────────────────

    async def _enumerate_subdomains(self, base_domain: str) -> None:
        """Enumera subdominios via wordlist + DNS resolution."""
        # Extract base domain (remove www. etc)
        parts = base_domain.split(".")
        if len(parts) > 2:
            domain = ".".join(parts[-2:])
        else:
            domain = base_domain

        # Check for wildcard
        wildcard_ip = None
        try:
            # Try a random subdomain to detect wildcard
            random_sub = f"siren-random-{random.randint(100000,999999)}.{domain}"
            wildcard_ip = socket.gethostbyname(random_sub)
        except socket.gaierror:
            pass  # No wildcard

        wordlist = DEFAULT_SUBDOMAINS
        if self.config.subdomain_wordlist and os.path.isfile(
            self.config.subdomain_wordlist
        ):
            try:
                with open(self.config.subdomain_wordlist) as f:
                    wordlist = [
                        l.strip() for l in f if l.strip() and not l.startswith("#")
                    ]
            except Exception as e:
                logger.debug("Subdomain wordlist load error: %s", e)

        logger.info(
            f"[SIREN RECON] Subdomain enumeration: {len(wordlist)} candidates for {domain}"
        )

        async def check_subdomain(sub: str) -> Optional[SubdomainResult]:
            async with self._semaphore:
                fqdn = f"{sub}.{domain}"
                try:
                    loop = asyncio.get_event_loop()
                    ip = await loop.run_in_executor(
                        None, lambda: socket.gethostbyname(fqdn)
                    )

                    if ip == wildcard_ip:
                        return None  # Wildcard hit

                    result = SubdomainResult(
                        subdomain=fqdn,
                        ip=ip,
                        resolved=True,
                    )

                    # Try HTTP
                    try:
                        status, headers, body = await self._http_get(
                            f"http://{fqdn}", timeout=5
                        )
                        result.status_code = status
                        result.server = headers.get("server", "")
                        title_m = re.search(r"<title>(.*?)</title>", body, re.I | re.S)
                        if title_m:
                            result.title = title_m.group(1).strip()[:100]
                    except Exception as e:
                        logger.debug("Subdomain HTTP probe error: %s", e)

                    return result
                except socket.gaierror:
                    return None
                except Exception:
                    return None

        tasks = [check_subdomain(sub) for sub in wordlist]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, SubdomainResult):
                self.result.subdomains.append(r)

    # ── Directory Bruteforce ────────────────────────────────────────────

    async def _bruteforce_directories(self) -> None:
        """Bruteforce de diretorios e arquivos."""
        base = self.config.target.rstrip("/")
        wordlist = DEFAULT_DIRECTORIES

        if self.config.dir_wordlist and os.path.isfile(self.config.dir_wordlist):
            try:
                with open(self.config.dir_wordlist) as f:
                    wordlist = [
                        l.strip() for l in f if l.strip() and not l.startswith("#")
                    ]
            except Exception as e:
                logger.debug("Directory wordlist load error: %s", e)

        # Get baseline 404 signature
        not_found_status = 0
        not_found_size = 0
        try:
            s, _, b = await self._http_get(
                f"{base}/siren-nonexistent-{random.randint(100000,999999)}"
            )
            not_found_status = s
            not_found_size = len(b)
        except Exception:
            not_found_status = 404

        logger.info(f"[SIREN RECON] Directory bruteforce: {len(wordlist)} paths")

        # Interesting status codes
        interesting_codes = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500}

        async def check_path(path: str) -> Optional[DirectoryResult]:
            async with self._semaphore:
                url = f"{base}/{path.lstrip('/')}"
                try:
                    status, headers, body = await self._http_get(url, timeout=5)

                    if (
                        status == not_found_status
                        and abs(len(body) - not_found_size) < 100
                    ):
                        return None

                    if status in interesting_codes:
                        title_m = re.search(r"<title>(.*?)</title>", body, re.I | re.S)
                        title = title_m.group(1).strip()[:100] if title_m else ""

                        is_interesting = status in (200, 401, 403, 500) or any(
                            x in path.lower()
                            for x in [
                                ".env",
                                ".git",
                                "admin",
                                "config",
                                "backup",
                                "debug",
                                "phpinfo",
                                "server-status",
                                ".sql",
                                "password",
                                "secret",
                                "key",
                            ]
                        )

                        return DirectoryResult(
                            path=path,
                            url=url,
                            status_code=status,
                            content_length=len(body),
                            redirect_url=headers.get("location", ""),
                            content_type=headers.get("content-type", ""),
                            title=title,
                            interesting=is_interesting,
                        )
                    return None
                except Exception:
                    return None

        tasks = [check_path(p) for p in wordlist]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, DirectoryResult):
                self.result.directories.append(r)

    # ── API Endpoint Discovery from JS ──────────────────────────────────

    async def _discover_api_endpoints(self) -> None:
        """Descobre endpoints de API analisando arquivos JavaScript."""
        api_pattern = re.compile(
            r"""(?:['"`])(\/(?:api|rest|graphql|v\d+|auth|user|admin|data|endpoint)[\/\w.-]*?)(?:['"`])""",
            re.I,
        )
        url_pattern = re.compile(
            r"""(?:['"`])((?:https?:)?\/\/[^'"`\s]{5,200})(?:['"`])""",
            re.I,
        )
        fetch_pattern = re.compile(
            r"""(?:fetch|axios|ajax|XMLHttpRequest)\s*\(\s*['"`]([^'"`]+)['"`]""",
            re.I,
        )

        for js_url in self.result.js_files[:20]:
            try:
                _, _, body = await self._http_get(js_url, timeout=10)
                if not body:
                    continue

                # Extract API paths
                for m in api_pattern.finditer(body):
                    ep = m.group(1)
                    if ep not in self.result.api_endpoints:
                        self.result.api_endpoints.append(ep)

                # Extract fetch/ajax calls
                for m in fetch_pattern.finditer(body):
                    ep = m.group(1)
                    if ep.startswith("/") and ep not in self.result.api_endpoints:
                        self.result.api_endpoints.append(ep)

            except Exception:
                continue


# ════════════════════════════════════════════════════════════════════════════
# CONVENIENCE FUNCTIONS
# ════════════════════════════════════════════════════════════════════════════


async def quick_recon(target: str, **kwargs) -> ReconResult:
    """Reconhecimento rapido com config default."""
    config = ReconConfig(target=target, **kwargs)
    recon = SirenRecon(config)
    return await recon.run()


async def deep_recon(target: str, **kwargs) -> ReconResult:
    """Reconhecimento profundo."""
    config = ReconConfig(
        target=target,
        port_scan_type="top100",
        max_concurrent=100,
        **kwargs,
    )
    recon = SirenRecon(config)
    return await recon.run()


def recon_sync(target: str, **kwargs) -> ReconResult:
    """Wrapper sincrono."""
    return asyncio.run(quick_recon(target, **kwargs))
