#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  🔌 SIREN WEBSOCKET ENGINE — WebSocket Protocol Testing Suite  🔌            ██
██                                                                                ██
██  Motor de teste e exploração para comunicações WebSocket.                     ██
██                                                                                ██
██  Capacidades:                                                                  ██
██    • Handshake analysis — validação de Upgrade, CORS, Origin                 ██
██    • Frame dissection — opcodes, masking, fragmentation                       ██
██    • Message fuzzing — mutation-based e generation-based                       ██
██    • CSWSH detection — Cross-Site WebSocket Hijacking                         ██
██    • Injection testing — JSON injection, command injection via WS             ██
██    • Rate limit testing — message flooding analysis                            ██
██    • Session hijacking — token replay, auth bypass                            ██
██    • Protocol violation — RFC 6455 compliance checking                         ██
██                                                                                ██
██  "SIREN ouve cada frame — e injeta onde dói."                                ██
██                                                                                ██
████████████████████████████████████████████████████████████████████████████████████
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import struct
import threading
import time
from base64 import b64decode, b64encode
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum, IntEnum, auto
from typing import Any, Deque, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("siren.arsenal.websocket_engine")


# ════════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════════════════════════════

WS_MAGIC_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
MAX_FRAME_SIZE = 16 * 1024 * 1024  # 16MB
MAX_MESSAGE_LOG = 10_000


# ════════════════════════════════════════════════════════════════════════════════
# ENUMS
# ════════════════════════════════════════════════════════════════════════════════

class WSOpcode(IntEnum):
    """WebSocket frame opcodes (RFC 6455)."""
    CONTINUATION = 0x0
    TEXT = 0x1
    BINARY = 0x2
    CLOSE = 0x8
    PING = 0x9
    PONG = 0xA


class WSCloseCode(IntEnum):
    """WebSocket close status codes."""
    NORMAL = 1000
    GOING_AWAY = 1001
    PROTOCOL_ERROR = 1002
    UNSUPPORTED = 1003
    NO_STATUS = 1005
    ABNORMAL = 1006
    INVALID_PAYLOAD = 1007
    POLICY_VIOLATION = 1008
    MESSAGE_TOO_BIG = 1009
    MISSING_EXTENSION = 1010
    INTERNAL_ERROR = 1011
    TLS_HANDSHAKE_FAIL = 1015


class WSVulnType(Enum):
    """WebSocket vulnerability types."""
    CSWSH = auto()                    # Cross-Site WebSocket Hijacking
    MISSING_ORIGIN_CHECK = auto()
    AUTH_BYPASS = auto()
    TOKEN_IN_URL = auto()
    INJECTION = auto()
    COMMAND_INJECTION = auto()
    MISSING_RATE_LIMIT = auto()
    NO_MESSAGE_VALIDATION = auto()
    INSECURE_TRANSPORT = auto()
    INFORMATION_DISCLOSURE = auto()
    SESSION_FIXATION = auto()
    PROTOCOL_VIOLATION = auto()
    FRAME_INJECTION = auto()
    DOS_VIA_FRAGMENTATION = auto()


class RiskLevel(Enum):
    CRITICAL = auto()
    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()
    INFO = auto()


class MessageDirection(Enum):
    CLIENT_TO_SERVER = auto()
    SERVER_TO_CLIENT = auto()


# ════════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class WSFrame:
    """Parsed WebSocket frame."""
    fin: bool = True
    rsv1: bool = False
    rsv2: bool = False
    rsv3: bool = False
    opcode: WSOpcode = WSOpcode.TEXT
    masked: bool = False
    mask_key: bytes = b""
    payload_length: int = 0
    payload: bytes = b""
    timestamp: float = field(default_factory=time.time)

    @property
    def is_control(self) -> bool:
        return self.opcode >= 0x8

    @property
    def is_text(self) -> bool:
        return self.opcode == WSOpcode.TEXT

    @property
    def text(self) -> str:
        try:
            return self.payload.decode("utf-8")
        except (UnicodeDecodeError, ValueError):
            return ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fin": self.fin,
            "opcode": self.opcode.name,
            "masked": self.masked,
            "payload_length": self.payload_length,
            "payload_preview": self.payload[:256].hex() if not self.is_text else self.text[:256],
        }


@dataclass
class WSHandshake:
    """WebSocket handshake information."""
    url: str = ""
    request_headers: Dict[str, str] = field(default_factory=dict)
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_code: int = 0
    ws_key: str = ""
    ws_accept: str = ""
    origin: str = ""
    protocol: str = ""
    extensions: List[str] = field(default_factory=list)
    is_secure: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "response_code": self.response_code,
            "origin": self.origin,
            "protocol": self.protocol,
            "extensions": self.extensions,
            "is_secure": self.is_secure,
        }


@dataclass
class WSMessage:
    """A complete WebSocket message (may span multiple frames)."""
    direction: MessageDirection
    opcode: WSOpcode
    payload: bytes
    timestamp: float = field(default_factory=time.time)
    frame_count: int = 1

    @property
    def text(self) -> str:
        if self.opcode == WSOpcode.TEXT:
            try:
                return self.payload.decode("utf-8")
            except (UnicodeDecodeError, ValueError):
                pass
        return ""

    @property
    def is_json(self) -> bool:
        t = self.text.strip()
        return t.startswith("{") or t.startswith("[")

    def parse_json(self) -> Optional[Any]:
        if self.is_json:
            try:
                return json.loads(self.text)
            except (json.JSONDecodeError, ValueError):
                pass
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "direction": self.direction.name,
            "opcode": self.opcode.name,
            "size": len(self.payload),
            "frames": self.frame_count,
            "is_json": self.is_json,
            "preview": self.text[:200] if self.opcode == WSOpcode.TEXT else self.payload[:100].hex(),
        }


@dataclass
class WSFinding:
    """A WebSocket security finding."""
    vuln_type: WSVulnType
    risk: RiskLevel
    title: str
    description: str
    evidence: str = ""
    payload: str = ""
    recommendation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.vuln_type.name,
            "risk": self.risk.name,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "payload": self.payload,
            "recommendation": self.recommendation,
        }


@dataclass
class FuzzPayload:
    """A WebSocket fuzzing payload."""
    name: str
    payload: bytes
    opcode: WSOpcode = WSOpcode.TEXT
    description: str = ""
    category: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "opcode": self.opcode.name,
            "size": len(self.payload),
            "category": self.category,
        }


@dataclass
class WSReport:
    """Complete WebSocket analysis report."""
    endpoint: str
    timestamp: float = field(default_factory=time.time)
    handshake: Optional[WSHandshake] = None
    messages_captured: int = 0
    findings: List[WSFinding] = field(default_factory=list)
    message_types: Dict[str, int] = field(default_factory=dict)
    fuzz_payloads_generated: int = 0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.risk == RiskLevel.CRITICAL)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "handshake": self.handshake.to_dict() if self.handshake else None,
            "messages_captured": self.messages_captured,
            "message_types": self.message_types,
            "findings_count": len(self.findings),
            "critical_findings": self.critical_count,
            "findings": [f.to_dict() for f in self.findings],
            "fuzz_payloads": self.fuzz_payloads_generated,
        }


# ════════════════════════════════════════════════════════════════════════════════
# FRAME CODEC — Encode/Decode WebSocket frames
# ════════════════════════════════════════════════════════════════════════════════

class WSFrameCodec:
    """WebSocket frame encoder/decoder per RFC 6455."""

    @staticmethod
    def decode_frame(data: bytes) -> Tuple[Optional[WSFrame], int]:
        """Decode a single WebSocket frame from bytes.
        Returns (frame, bytes_consumed) or (None, 0) if incomplete.
        """
        if len(data) < 2:
            return None, 0

        byte0 = data[0]
        byte1 = data[1]

        fin = bool(byte0 & 0x80)
        rsv1 = bool(byte0 & 0x40)
        rsv2 = bool(byte0 & 0x20)
        rsv3 = bool(byte0 & 0x10)
        opcode_val = byte0 & 0x0F

        try:
            opcode = WSOpcode(opcode_val)
        except ValueError:
            opcode = WSOpcode.TEXT

        masked = bool(byte1 & 0x80)
        payload_length = byte1 & 0x7F
        offset = 2

        if payload_length == 126:
            if len(data) < offset + 2:
                return None, 0
            payload_length = struct.unpack("!H", data[offset:offset + 2])[0]
            offset += 2
        elif payload_length == 127:
            if len(data) < offset + 8:
                return None, 0
            payload_length = struct.unpack("!Q", data[offset:offset + 8])[0]
            offset += 8

        mask_key = b""
        if masked:
            if len(data) < offset + 4:
                return None, 0
            mask_key = data[offset:offset + 4]
            offset += 4

        if len(data) < offset + payload_length:
            return None, 0

        payload = data[offset:offset + payload_length]
        if masked and mask_key:
            payload = WSFrameCodec._apply_mask(payload, mask_key)

        frame = WSFrame(
            fin=fin, rsv1=rsv1, rsv2=rsv2, rsv3=rsv3,
            opcode=opcode, masked=masked, mask_key=mask_key,
            payload_length=payload_length, payload=payload,
        )
        return frame, offset + payload_length

    @staticmethod
    def encode_frame(opcode: WSOpcode, payload: bytes, masked: bool = True, fin: bool = True) -> bytes:
        """Encode a WebSocket frame."""
        header = bytearray()

        byte0 = opcode.value
        if fin:
            byte0 |= 0x80
        header.append(byte0)

        length = len(payload)
        mask_bit = 0x80 if masked else 0

        if length < 126:
            header.append(mask_bit | length)
        elif length < 65536:
            header.append(mask_bit | 126)
            header.extend(struct.pack("!H", length))
        else:
            header.append(mask_bit | 127)
            header.extend(struct.pack("!Q", length))

        if masked:
            mask_key = os.urandom(4)
            header.extend(mask_key)
            payload = WSFrameCodec._apply_mask(payload, mask_key)

        return bytes(header) + payload

    @staticmethod
    def _apply_mask(data: bytes, mask: bytes) -> bytes:
        """Apply/remove XOR mask."""
        result = bytearray(len(data))
        for i in range(len(data)):
            result[i] = data[i] ^ mask[i % 4]
        return bytes(result)


# ════════════════════════════════════════════════════════════════════════════════
# HANDSHAKE ANALYZER — Validates WS handshake security
# ════════════════════════════════════════════════════════════════════════════════

class HandshakeAnalyzer:
    """Analyzes WebSocket handshake for security issues."""

    def analyze(self, handshake: WSHandshake) -> List[WSFinding]:
        """Analyze handshake for security findings."""
        findings: List[WSFinding] = []

        # 1. Insecure transport (ws:// instead of wss://)
        if not handshake.is_secure:
            findings.append(WSFinding(
                vuln_type=WSVulnType.INSECURE_TRANSPORT,
                risk=RiskLevel.HIGH,
                title="WebSocket over unencrypted connection (ws://)",
                description="Messages are transmitted in plaintext — vulnerable to MITM",
                evidence=f"URL: {handshake.url}",
                recommendation="Use wss:// (WebSocket Secure) for all connections",
            ))

        # 2. Token in URL
        url_lower = handshake.url.lower()
        if any(kw in url_lower for kw in ("token=", "key=", "auth=", "jwt=", "session=")):
            findings.append(WSFinding(
                vuln_type=WSVulnType.TOKEN_IN_URL,
                risk=RiskLevel.HIGH,
                title="Authentication token in WebSocket URL",
                description="Tokens in URLs are logged in server logs, proxies, and browser history",
                evidence=f"URL contains auth parameter",
                recommendation="Send authentication tokens in the first WebSocket message or via cookies",
            ))

        # 3. CSWSH (Cross-Site WebSocket Hijacking)
        origin = handshake.request_headers.get("Origin", "")
        sec_ws_origin = handshake.response_headers.get("Access-Control-Allow-Origin", "")

        if not origin:
            findings.append(WSFinding(
                vuln_type=WSVulnType.MISSING_ORIGIN_CHECK,
                risk=RiskLevel.HIGH,
                title="No Origin header in WebSocket handshake",
                description="Without Origin validation, CSWSH attacks are possible",
                recommendation="Validate Origin header on server side",
            ))
        elif sec_ws_origin == "*":
            findings.append(WSFinding(
                vuln_type=WSVulnType.CSWSH,
                risk=RiskLevel.CRITICAL,
                title="Wildcard CORS on WebSocket endpoint",
                description="Access-Control-Allow-Origin: * allows any site to connect",
                evidence="Access-Control-Allow-Origin: *",
                recommendation="Whitelist specific origins for WebSocket connections",
            ))

        # 4. Sec-WebSocket-Accept validation
        if handshake.ws_key and handshake.ws_accept:
            expected = self._compute_accept(handshake.ws_key)
            if handshake.ws_accept != expected:
                findings.append(WSFinding(
                    vuln_type=WSVulnType.PROTOCOL_VIOLATION,
                    risk=RiskLevel.MEDIUM,
                    title="Invalid Sec-WebSocket-Accept header",
                    description="Server's Sec-WebSocket-Accept doesn't match expected value",
                    evidence=f"Expected: {expected}, Got: {handshake.ws_accept}",
                    recommendation="Server must correctly compute Sec-WebSocket-Accept per RFC 6455",
                ))

        # 5. Missing security headers
        resp_headers = {k.lower(): v for k, v in handshake.response_headers.items()}
        if "strict-transport-security" not in resp_headers:
            findings.append(WSFinding(
                vuln_type=WSVulnType.INSECURE_TRANSPORT,
                risk=RiskLevel.LOW,
                title="Missing HSTS header on WebSocket endpoint",
                description="Strict-Transport-Security not set on the upgrade response",
                recommendation="Add HSTS header to WebSocket endpoints",
            ))

        return findings

    @staticmethod
    def _compute_accept(key: str) -> str:
        """Compute expected Sec-WebSocket-Accept value."""
        combined = key.strip() + WS_MAGIC_GUID
        digest = hashlib.sha1(combined.encode("ascii")).digest()
        return b64encode(digest).decode("ascii")


# ════════════════════════════════════════════════════════════════════════════════
# MESSAGE ANALYZER — Analyzes captured WS messages for patterns
# ════════════════════════════════════════════════════════════════════════════════

class MessageAnalyzer:
    """Analyzes WebSocket message patterns."""

    SENSITIVE_PATTERNS = [
        re.compile(r'"(password|passwd|pwd)"\s*:\s*"[^"]+"', re.I),
        re.compile(r'"(token|jwt|session|auth)"\s*:\s*"[^"]+"', re.I),
        re.compile(r'"(api[_-]?key|apikey|secret)"\s*:\s*"[^"]+"', re.I),
        re.compile(r'"(credit|card|cvv|ssn)"\s*:\s*"[^"]+"', re.I),
        re.compile(r'"(private[_-]?key)"\s*:\s*"[^"]+"', re.I),
    ]

    INJECTION_INDICATORS = [
        re.compile(r"(sql|syntax)\s+error", re.I),
        re.compile(r"(stack\s*trace|traceback|exception)", re.I),
        re.compile(r"at\s+\w+\.\w+\([\w:.]+\)", re.I),  # Java stack trace
    ]

    def analyze_messages(self, messages: List[WSMessage]) -> List[WSFinding]:
        """Analyze captured messages for security issues."""
        findings: List[WSFinding] = []

        for msg in messages:
            text = msg.text
            if not text:
                continue

            # Sensitive data exposure
            for pattern in self.SENSITIVE_PATTERNS:
                match = pattern.search(text)
                if match:
                    findings.append(WSFinding(
                        vuln_type=WSVulnType.INFORMATION_DISCLOSURE,
                        risk=RiskLevel.HIGH,
                        title="Sensitive data in WebSocket message",
                        description=f"Message contains potentially sensitive data: {match.group(1)}",
                        evidence=text[:200],
                        recommendation="Avoid sending sensitive data over WebSocket if possible",
                    ))
                    break

            # Error leakage (injection indicator)
            for pattern in self.INJECTION_INDICATORS:
                if pattern.search(text):
                    findings.append(WSFinding(
                        vuln_type=WSVulnType.INJECTION,
                        risk=RiskLevel.MEDIUM,
                        title="Error/stack trace in WebSocket response",
                        description="Server error details leaked in WebSocket message",
                        evidence=text[:300],
                        recommendation="Sanitize error messages — never expose stack traces",
                    ))
                    break

        # Message type statistics
        json_count = sum(1 for m in messages if m.is_json)
        if json_count > 0 and not self._has_type_field(messages):
            findings.append(WSFinding(
                vuln_type=WSVulnType.NO_MESSAGE_VALIDATION,
                risk=RiskLevel.LOW,
                title="JSON messages without type field",
                description="JSON WebSocket messages lack a consistent type/action field",
                recommendation="Use structured message format with type discrimination",
            ))

        return findings

    @staticmethod
    def _has_type_field(messages: List[WSMessage]) -> bool:
        """Check if JSON messages have a consistent type field."""
        type_fields = {"type", "action", "event", "op", "cmd", "method"}
        for msg in messages:
            data = msg.parse_json()
            if isinstance(data, dict):
                if any(tf in data for tf in type_fields):
                    return True
        return False


# ════════════════════════════════════════════════════════════════════════════════
# FUZZ GENERATOR — Generates WebSocket fuzzing payloads
# ════════════════════════════════════════════════════════════════════════════════

class WSFuzzGenerator:
    """Generates WebSocket-specific fuzzing payloads."""

    def generate_payloads(self, sample_messages: List[WSMessage] = None) -> List[FuzzPayload]:
        """Generate a set of fuzzing payloads."""
        payloads: List[FuzzPayload] = []

        # Protocol-level fuzzing
        payloads.extend(self._protocol_fuzzing())

        # Injection payloads
        payloads.extend(self._injection_payloads())

        # If we have sample messages, generate mutations
        if sample_messages:
            payloads.extend(self._mutation_payloads(sample_messages))

        return payloads

    @staticmethod
    def _protocol_fuzzing() -> List[FuzzPayload]:
        """Generate protocol-level fuzz payloads."""
        return [
            # Oversized frames
            FuzzPayload(
                name="oversized_text",
                payload=b"A" * 1_000_000,
                opcode=WSOpcode.TEXT,
                description="1MB text frame for buffer overflow testing",
                category="size",
            ),
            # Empty frames
            FuzzPayload(
                name="empty_text",
                payload=b"",
                opcode=WSOpcode.TEXT,
                description="Empty text frame",
                category="boundary",
            ),
            # Invalid UTF-8
            FuzzPayload(
                name="invalid_utf8",
                payload=b"\xff\xfe\x80\x81\xc0\xaf",
                opcode=WSOpcode.TEXT,
                description="Invalid UTF-8 in text frame (RFC violation)",
                category="encoding",
            ),
            # Binary in text frame
            FuzzPayload(
                name="binary_in_text",
                payload=bytes(range(256)),
                opcode=WSOpcode.TEXT,
                description="All byte values in text frame",
                category="encoding",
            ),
            # Null bytes
            FuzzPayload(
                name="null_bytes",
                payload=b"test\x00injected",
                opcode=WSOpcode.TEXT,
                description="Null byte injection",
                category="injection",
            ),
            # Close frame with no status
            FuzzPayload(
                name="close_no_status",
                payload=b"",
                opcode=WSOpcode.CLOSE,
                description="Close frame without status code",
                category="protocol",
            ),
            # Close frame with invalid status
            FuzzPayload(
                name="close_invalid_status",
                payload=struct.pack("!H", 9999),
                opcode=WSOpcode.CLOSE,
                description="Close frame with invalid status code",
                category="protocol",
            ),
            # Ping with large payload
            FuzzPayload(
                name="large_ping",
                payload=b"P" * 125,
                opcode=WSOpcode.PING,
                description="Maximum-size ping frame (125 bytes)",
                category="protocol",
            ),
            # Oversized ping (control frames must be <= 125 bytes)
            FuzzPayload(
                name="oversized_ping",
                payload=b"P" * 200,
                opcode=WSOpcode.PING,
                description="Oversized ping frame (RFC violation)",
                category="protocol",
            ),
        ]

    @staticmethod
    def _injection_payloads() -> List[FuzzPayload]:
        """Generate injection-focused payloads."""
        templates = [
            # SQL Injection
            ('sqli_1', '{"id": "1 OR 1=1--"}', "injection"),
            ('sqli_2', '{"query": "\' UNION SELECT * FROM users--"}', "injection"),
            # XSS
            ('xss_1', '{"message": "<script>alert(1)</script>"}', "xss"),
            ('xss_2', '{"name": "<img src=x onerror=alert(1)>"}', "xss"),
            # Command Injection
            ('cmdi_1', '{"cmd": "; cat /etc/passwd"}', "command_injection"),
            ('cmdi_2', '{"file": "$(whoami)"}', "command_injection"),
            # Path Traversal
            ('path_1', '{"file": "../../../etc/passwd"}', "path_traversal"),
            ('path_2', '{"path": "....//....//etc/passwd"}', "path_traversal"),
            # SSTI
            ('ssti_1', '{"template": "{{7*7}}"}', "ssti"),
            ('ssti_2', '{"input": "${7*7}"}', "ssti"),
            # JSON specific
            ('json_bomb', '{"a":' * 30 + '"x"' + '}' * 30, "dos"),
            ('json_deep', '[[[[[[[[[[[[[[[[' + ']]]]]]]]]]]]]]]]', "dos"),
            # Large numbers
            ('large_num', '{"id": 99999999999999999999999999}', "boundary"),
            # Negative
            ('negative', '{"id": -1}', "boundary"),
            # Type confusion
            ('type_confusion', '{"id": true, "name": 123, "admin": "yes"}', "logic"),
        ]

        payloads: List[FuzzPayload] = []
        for name, text, category in templates:
            payloads.append(FuzzPayload(
                name=name,
                payload=text.encode("utf-8"),
                opcode=WSOpcode.TEXT,
                description=f"Injection payload: {category}",
                category=category,
            ))
        return payloads

    def _mutation_payloads(self, messages: List[WSMessage]) -> List[FuzzPayload]:
        """Generate mutation-based payloads from captured messages."""
        payloads: List[FuzzPayload] = []

        for i, msg in enumerate(messages[:10]):
            data = msg.parse_json()
            if not isinstance(data, dict):
                continue

            # Mutate string values
            for key, value in data.items():
                if isinstance(value, str):
                    mutated = dict(data)
                    mutated[key] = "A" * 10000  # Buffer overflow test
                    payloads.append(FuzzPayload(
                        name=f"mutate_{i}_{key}_overflow",
                        payload=json.dumps(mutated).encode("utf-8"),
                        opcode=WSOpcode.TEXT,
                        category="mutation",
                    ))

                elif isinstance(value, (int, float)):
                    # Type confusion: send string instead of number
                    mutated = dict(data)
                    mutated[key] = "not_a_number"
                    payloads.append(FuzzPayload(
                        name=f"mutate_{i}_{key}_typeconf",
                        payload=json.dumps(mutated).encode("utf-8"),
                        opcode=WSOpcode.TEXT,
                        category="mutation",
                    ))

        return payloads


# ════════════════════════════════════════════════════════════════════════════════
# SIREN WEBSOCKET ENGINE — Main Orchestrator
# ════════════════════════════════════════════════════════════════════════════════

class SirenWebSocketEngine:
    """
    Main WebSocket testing engine.

    Orchestrates handshake analysis, frame dissection, message analysis,
    and fuzzing payload generation.

    Usage:
        engine = SirenWebSocketEngine()

        # Analyze handshake
        handshake = WSHandshake(url="ws://target.com/ws", ...)
        findings = engine.analyze_handshake(handshake)

        # Analyze captured messages
        findings = engine.analyze_messages(messages)

        # Generate fuzz payloads
        payloads = engine.generate_fuzz_payloads(messages)
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._codec = WSFrameCodec()
        self._handshake_analyzer = HandshakeAnalyzer()
        self._message_analyzer = MessageAnalyzer()
        self._fuzz_generator = WSFuzzGenerator()
        self._messages: Deque[WSMessage] = deque(maxlen=MAX_MESSAGE_LOG)
        self._stats: Dict[str, int] = defaultdict(int)
        logger.info("SirenWebSocketEngine initialized")

    def decode_frame(self, data: bytes) -> Tuple[Optional[WSFrame], int]:
        """Decode a WebSocket frame from raw bytes."""
        return self._codec.decode_frame(data)

    def encode_frame(self, opcode: WSOpcode, payload: bytes, masked: bool = True) -> bytes:
        """Encode a WebSocket frame."""
        return self._codec.encode_frame(opcode, payload, masked)

    def analyze_handshake(self, handshake: WSHandshake) -> List[WSFinding]:
        """Analyze WebSocket handshake for security issues."""
        findings = self._handshake_analyzer.analyze(handshake)
        with self._lock:
            self._stats["handshakes_analyzed"] += 1
            self._stats["findings_total"] += len(findings)
        return findings

    def record_message(self, msg: WSMessage) -> None:
        """Record a captured message for analysis."""
        with self._lock:
            self._messages.append(msg)
            self._stats["messages_captured"] += 1

    def analyze_messages(self, messages: Optional[List[WSMessage]] = None) -> List[WSFinding]:
        """Analyze captured messages."""
        if messages is None:
            with self._lock:
                messages = list(self._messages)
        findings = self._message_analyzer.analyze_messages(messages)
        with self._lock:
            self._stats["findings_total"] += len(findings)
        return findings

    def generate_fuzz_payloads(self, sample_messages: Optional[List[WSMessage]] = None) -> List[FuzzPayload]:
        """Generate fuzzing payloads."""
        if sample_messages is None:
            with self._lock:
                sample_messages = list(self._messages)
        payloads = self._fuzz_generator.generate_payloads(sample_messages)
        with self._lock:
            self._stats["fuzz_payloads_generated"] += len(payloads)
        return payloads

    def full_analysis(self, endpoint: str, handshake: Optional[WSHandshake] = None,
                       messages: Optional[List[WSMessage]] = None) -> WSReport:
        """Run full WebSocket security analysis."""
        report = WSReport(endpoint=endpoint)

        findings: List[WSFinding] = []

        # Handshake analysis
        if handshake:
            report.handshake = handshake
            findings.extend(self.analyze_handshake(handshake))

        # Message analysis
        msgs = messages or list(self._messages)
        report.messages_captured = len(msgs)
        findings.extend(self._message_analyzer.analyze_messages(msgs))

        # Message type breakdown
        types: Dict[str, int] = defaultdict(int)
        for m in msgs:
            types[m.opcode.name] += 1
        report.message_types = dict(types)

        # Fuzz payloads
        payloads = self.generate_fuzz_payloads(msgs)
        report.fuzz_payloads_generated = len(payloads)

        report.findings = sorted(findings, key=lambda f: list(RiskLevel).index(f.risk))
        return report

    def get_stats(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._stats)
