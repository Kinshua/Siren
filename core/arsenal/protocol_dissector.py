#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  🔬 SIREN PROTOCOL DISSECTOR — Binary Protocol Analysis Engine  🔬           ██
██                                                                                ██
██  Análise profunda de protocolos de rede com dissecação multi-camada.          ██
██                                                                                ██
██  Capacidades:                                                                  ██
██    • Layer-by-layer packet dissection — Ethernet→IP→TCP/UDP→App              ██
██    • Protocol fingerprinting — identifica protocolos desconhecidos             ██
██    • Binary pattern recognition — detecta estruturas em payloads              ██
██    • Field extraction & mutation — extrai e modifica campos                    ██
██    • Anomaly detection — detecta desvios do protocolo                         ██
██    • Session reconstruction — reconstrói sessões TCP completas                ██
██    • Smart fuzzing seed generation — gera seeds para fuzzing                  ██
██                                                                                ██
██  "SIREN disseca cada bit — nada se esconde no wire."                          ██
██                                                                                ██
████████████████████████████████████████████████████████████████████████████████████
"""

from __future__ import annotations

import hashlib
import logging
import struct
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum, IntEnum, auto
from typing import Any, Callable, Deque, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("siren.arsenal.protocol_dissector")


# ════════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════════════════════════════

MAX_PACKET_SIZE = 65535
MAX_SESSION_PACKETS = 50_000
ENTROPY_THRESHOLD_ENCRYPTED = 7.5  # bits per byte


# ════════════════════════════════════════════════════════════════════════════════
# ENUMS
# ════════════════════════════════════════════════════════════════════════════════

class ProtocolLayer(IntEnum):
    """OSI-inspired layer classification."""
    PHYSICAL = 1
    DATALINK = 2
    NETWORK = 3
    TRANSPORT = 4
    SESSION = 5
    PRESENTATION = 6
    APPLICATION = 7


class TransportProto(Enum):
    TCP = auto()
    UDP = auto()
    SCTP = auto()
    ICMP = auto()
    UNKNOWN = auto()


class AppProtocol(Enum):
    """Known application-layer protocols."""
    HTTP = auto()
    HTTPS = auto()
    HTTP2 = auto()
    HTTP3 = auto()
    DNS = auto()
    FTP = auto()
    SSH = auto()
    SMTP = auto()
    IMAP = auto()
    POP3 = auto()
    TELNET = auto()
    RDP = auto()
    SMB = auto()
    MYSQL = auto()
    POSTGRESQL = auto()
    REDIS = auto()
    MONGODB = auto()
    MQTT = auto()
    AMQP = auto()
    WEBSOCKET = auto()
    GRPC = auto()
    GRAPHQL = auto()
    SOCKS = auto()
    TLS = auto()
    QUIC = auto()
    CUSTOM_BINARY = auto()
    UNKNOWN = auto()


class FieldType(Enum):
    """Types of fields found in binary protocols."""
    UINT8 = auto()
    UINT16_BE = auto()
    UINT16_LE = auto()
    UINT32_BE = auto()
    UINT32_LE = auto()
    UINT64_BE = auto()
    UINT64_LE = auto()
    INT8 = auto()
    INT16_BE = auto()
    INT32_BE = auto()
    FLOAT_BE = auto()
    FLOAT_LE = auto()
    STRING_FIXED = auto()
    STRING_NULL_TERM = auto()
    STRING_LENGTH_PREFIXED = auto()
    BYTES_RAW = auto()
    PADDING = auto()
    FLAG_BITS = auto()
    CHECKSUM = auto()
    MAGIC_BYTES = auto()
    TIMESTAMP = auto()
    IPV4_ADDR = auto()
    IPV6_ADDR = auto()


class AnomalyType(Enum):
    """Types of protocol anomalies."""
    MALFORMED_HEADER = auto()
    INVALID_LENGTH = auto()
    UNEXPECTED_FLAGS = auto()
    PROTOCOL_VIOLATION = auto()
    SUSPICIOUS_PAYLOAD = auto()
    FRAGMENTATION_ABUSE = auto()
    DESYNC_DETECTED = auto()
    ENCODING_MISMATCH = auto()
    SEQUENCE_ANOMALY = auto()
    TIMING_ANOMALY = auto()


class DissectionDepth(Enum):
    """How deep to dissect."""
    HEADERS_ONLY = auto()
    SHALLOW = auto()       # Known fields only
    DEEP = auto()          # + pattern recognition on payload
    EXHAUSTIVE = auto()    # + entropy analysis + fuzzing seed gen


# ════════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class ProtocolField:
    """A single field extracted from a protocol message."""
    name: str
    field_type: FieldType
    offset: int
    length: int
    value: Any = None
    raw_bytes: bytes = b""
    is_mutable: bool = True
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "type": self.field_type.name,
            "offset": self.offset,
            "length": self.length,
            "value": repr(self.value),
            "is_mutable": self.is_mutable,
        }


@dataclass
class DissectedPacket:
    """Result of dissecting a single packet/message."""
    raw: bytes
    timestamp: float = field(default_factory=time.time)
    transport: TransportProto = TransportProto.TCP
    app_protocol: AppProtocol = AppProtocol.UNKNOWN
    src_addr: str = ""
    dst_addr: str = ""
    src_port: int = 0
    dst_port: int = 0
    fields: List[ProtocolField] = field(default_factory=list)
    anomalies: List[AnomalyType] = field(default_factory=list)
    entropy: float = 0.0
    is_encrypted: bool = False
    is_compressed: bool = False
    payload_offset: int = 0
    layer: ProtocolLayer = ProtocolLayer.APPLICATION

    @property
    def payload(self) -> bytes:
        return self.raw[self.payload_offset:] if self.payload_offset < len(self.raw) else b""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "protocol": self.app_protocol.name,
            "transport": self.transport.name,
            "src": f"{self.src_addr}:{self.src_port}",
            "dst": f"{self.dst_addr}:{self.dst_port}",
            "size": len(self.raw),
            "fields": [f.to_dict() for f in self.fields],
            "anomalies": [a.name for a in self.anomalies],
            "entropy": round(self.entropy, 3),
            "is_encrypted": self.is_encrypted,
        }


@dataclass
class ProtocolSignature:
    """Signature for identifying a protocol."""
    protocol: AppProtocol
    magic_bytes: Optional[bytes] = None
    magic_offset: int = 0
    port_hints: Set[int] = field(default_factory=set)
    header_patterns: List[bytes] = field(default_factory=list)
    min_length: int = 0
    confidence: float = 0.8


@dataclass
class SessionState:
    """Reconstructed session state."""
    session_id: str = ""
    src: str = ""
    dst: str = ""
    protocol: AppProtocol = AppProtocol.UNKNOWN
    packets: Deque[DissectedPacket] = field(default_factory=lambda: deque(maxlen=MAX_SESSION_PACKETS))
    start_time: float = 0.0
    last_seen: float = 0.0
    bytes_sent: int = 0
    bytes_received: int = 0
    state: str = "INIT"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "src": self.src,
            "dst": self.dst,
            "protocol": self.protocol.name,
            "packet_count": len(self.packets),
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "duration_s": round(self.last_seen - self.start_time, 3) if self.start_time else 0,
            "state": self.state,
        }


@dataclass
class FuzzingSeed:
    """Generated fuzzing seed from protocol analysis."""
    base_payload: bytes
    mutation_points: List[Tuple[int, int, str]] = field(default_factory=list)  # (offset, len, field_name)
    protocol: AppProtocol = AppProtocol.UNKNOWN
    priority: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "base_size": len(self.base_payload),
            "mutation_points": len(self.mutation_points),
            "protocol": self.protocol.name,
            "priority": self.priority,
        }


# ════════════════════════════════════════════════════════════════════════════════
# ENTROPY CALCULATOR
# ════════════════════════════════════════════════════════════════════════════════

class EntropyAnalyzer:
    """Shannon entropy analysis on binary data."""

    @staticmethod
    def calculate(data: bytes) -> float:
        """Calculate Shannon entropy in bits per byte."""
        if not data:
            return 0.0
        freq: Dict[int, int] = defaultdict(int)
        for byte_val in data:
            freq[byte_val] += 1
        length = len(data)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * (p and (p > 0) and __import__("math").log2(p))
        return entropy

    @staticmethod
    def is_encrypted(data: bytes) -> bool:
        """Heuristic: high entropy + no clear text patterns → likely encrypted."""
        if len(data) < 16:
            return False
        entropy = EntropyAnalyzer.calculate(data)
        if entropy >= ENTROPY_THRESHOLD_ENCRYPTED:
            return True
        # Check for common plaintext indicators
        try:
            _ = data[:64].decode("ascii")
            return False  # Has ASCII content → not encrypted
        except (UnicodeDecodeError, ValueError):
            return entropy > 6.5

    @staticmethod
    def is_compressed(data: bytes) -> bool:
        """Detect common compression signatures."""
        if len(data) < 4:
            return False
        signatures = [
            b"\x1f\x8b",           # gzip
            b"PK\x03\x04",         # zip
            b"\xfd7zXZ\x00",       # xz
            b"BZ",                  # bzip2
            b"\x28\xb5\x2f\xfd",   # zstd
            b"\x04\x22\x4d\x18",   # lz4
        ]
        for sig in signatures:
            if data[:len(sig)] == sig:
                return True
        return False


# ════════════════════════════════════════════════════════════════════════════════
# PROTOCOL IDENTIFIER — Fingerprints the protocol from raw bytes
# ════════════════════════════════════════════════════════════════════════════════

class ProtocolIdentifier:
    """Identifies application-layer protocols from raw data."""

    def __init__(self) -> None:
        self._signatures = self._build_signatures()

    def identify(self, data: bytes, dst_port: int = 0, src_port: int = 0) -> Tuple[AppProtocol, float]:
        """Identify the protocol. Returns (protocol, confidence)."""
        if not data:
            return AppProtocol.UNKNOWN, 0.0

        best_match = AppProtocol.UNKNOWN
        best_confidence = 0.0

        for sig in self._signatures:
            confidence = self._match_signature(data, sig, dst_port, src_port)
            if confidence > best_confidence:
                best_confidence = confidence
                best_match = sig.protocol

        return best_match, best_confidence

    def _match_signature(self, data: bytes, sig: ProtocolSignature, dst_port: int, src_port: int) -> float:
        """Match data against a protocol signature."""
        score = 0.0

        if len(data) < sig.min_length:
            return 0.0

        # Magic byte match — strong signal
        if sig.magic_bytes and len(data) > sig.magic_offset + len(sig.magic_bytes):
            chunk = data[sig.magic_offset:sig.magic_offset + len(sig.magic_bytes)]
            if chunk == sig.magic_bytes:
                score += 0.6

        # Port hint match — moderate signal
        if sig.port_hints:
            if dst_port in sig.port_hints or src_port in sig.port_hints:
                score += 0.25

        # Header pattern match
        for pattern in sig.header_patterns:
            if pattern in data[:256]:
                score += 0.15

        return min(score, 1.0)

    @staticmethod
    def _build_signatures() -> List[ProtocolSignature]:
        """Build protocol signature database."""
        return [
            ProtocolSignature(
                protocol=AppProtocol.HTTP,
                header_patterns=[b"HTTP/1.", b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS "],
                port_hints={80, 8080, 8000, 8888, 3000},
                min_length=4,
            ),
            ProtocolSignature(
                protocol=AppProtocol.TLS,
                magic_bytes=b"\x16\x03",
                port_hints={443, 8443, 993, 995, 465},
                min_length=5,
            ),
            ProtocolSignature(
                protocol=AppProtocol.SSH,
                magic_bytes=b"SSH-",
                port_hints={22, 2222},
                min_length=4,
            ),
            ProtocolSignature(
                protocol=AppProtocol.DNS,
                port_hints={53},
                min_length=12,
            ),
            ProtocolSignature(
                protocol=AppProtocol.MYSQL,
                port_hints={3306},
                min_length=4,
            ),
            ProtocolSignature(
                protocol=AppProtocol.POSTGRESQL,
                port_hints={5432},
                min_length=8,
            ),
            ProtocolSignature(
                protocol=AppProtocol.REDIS,
                header_patterns=[b"+OK", b"-ERR", b"$", b"*"],
                port_hints={6379},
                min_length=1,
            ),
            ProtocolSignature(
                protocol=AppProtocol.MONGODB,
                port_hints={27017},
                min_length=16,
            ),
            ProtocolSignature(
                protocol=AppProtocol.MQTT,
                magic_bytes=b"\x10",
                port_hints={1883, 8883},
                min_length=2,
            ),
            ProtocolSignature(
                protocol=AppProtocol.SMB,
                magic_bytes=b"\xffSMB",
                port_hints={445, 139},
                min_length=4,
            ),
            ProtocolSignature(
                protocol=AppProtocol.FTP,
                header_patterns=[b"220 ", b"USER ", b"PASS "],
                port_hints={21},
                min_length=3,
            ),
            ProtocolSignature(
                protocol=AppProtocol.SMTP,
                header_patterns=[b"220 ", b"EHLO ", b"HELO ", b"MAIL FROM:"],
                port_hints={25, 587},
                min_length=3,
            ),
            ProtocolSignature(
                protocol=AppProtocol.GRPC,
                header_patterns=[b"PRI * HTTP/2.0", b"grpc-"],
                port_hints={50051},
                min_length=9,
            ),
            ProtocolSignature(
                protocol=AppProtocol.SOCKS,
                magic_bytes=b"\x05",
                port_hints={1080},
                min_length=3,
            ),
            ProtocolSignature(
                protocol=AppProtocol.QUIC,
                port_hints={443},
                min_length=1,
            ),
            ProtocolSignature(
                protocol=AppProtocol.RDP,
                magic_bytes=b"\x03\x00",
                port_hints={3389},
                min_length=4,
            ),
            ProtocolSignature(
                protocol=AppProtocol.TELNET,
                magic_bytes=b"\xff\xfd",
                port_hints={23},
                min_length=3,
            ),
        ]


# ════════════════════════════════════════════════════════════════════════════════
# BINARY FIELD EXTRACTOR — Extracts typed fields from binary data
# ════════════════════════════════════════════════════════════════════════════════

class BinaryFieldExtractor:
    """Extracts and decodes structured binary fields."""

    _UNPACK_MAP: Dict[FieldType, str] = {
        FieldType.UINT8: "!B",
        FieldType.UINT16_BE: "!H",
        FieldType.UINT16_LE: "<H",
        FieldType.UINT32_BE: "!I",
        FieldType.UINT32_LE: "<I",
        FieldType.UINT64_BE: "!Q",
        FieldType.UINT64_LE: "<Q",
        FieldType.INT8: "!b",
        FieldType.INT16_BE: "!h",
        FieldType.INT32_BE: "!i",
        FieldType.FLOAT_BE: "!f",
        FieldType.FLOAT_LE: "<f",
    }

    def extract_field(self, data: bytes, offset: int, ftype: FieldType, length: int = 0) -> Optional[ProtocolField]:
        """Extract a single field from data at offset."""
        if offset >= len(data):
            return None

        fmt = self._UNPACK_MAP.get(ftype)
        if fmt:
            size = struct.calcsize(fmt)
            if offset + size > len(data):
                return None
            raw = data[offset:offset + size]
            value = struct.unpack(fmt, raw)[0]
            return ProtocolField(
                name="",
                field_type=ftype,
                offset=offset,
                length=size,
                value=value,
                raw_bytes=raw,
            )

        if ftype == FieldType.STRING_NULL_TERM:
            end = data.index(0, offset) if 0 in data[offset:] else len(data)
            raw = data[offset:end]
            return ProtocolField(
                name="", field_type=ftype, offset=offset,
                length=end - offset, value=raw.decode("utf-8", errors="replace"),
                raw_bytes=raw,
            )

        if ftype == FieldType.STRING_FIXED and length > 0:
            end = min(offset + length, len(data))
            raw = data[offset:end]
            return ProtocolField(
                name="", field_type=ftype, offset=offset,
                length=end - offset, value=raw.decode("utf-8", errors="replace"),
                raw_bytes=raw,
            )

        if ftype == FieldType.IPV4_ADDR and offset + 4 <= len(data):
            raw = data[offset:offset + 4]
            value = ".".join(str(b) for b in raw)
            return ProtocolField(
                name="", field_type=ftype, offset=offset,
                length=4, value=value, raw_bytes=raw, is_mutable=False,
            )

        if ftype == FieldType.BYTES_RAW and length > 0:
            end = min(offset + length, len(data))
            raw = data[offset:end]
            return ProtocolField(
                name="", field_type=ftype, offset=offset,
                length=end - offset, value=raw, raw_bytes=raw,
            )

        return None

    def detect_fields(self, data: bytes, max_fields: int = 50) -> List[ProtocolField]:
        """Auto-detect fields by heuristic analysis of binary data."""
        fields: List[ProtocolField] = []
        offset = 0

        while offset < len(data) and len(fields) < max_fields:
            # Try to detect field boundaries via heuristics
            f = self._heuristic_detect(data, offset)
            if f:
                fields.append(f)
                offset += f.length
            else:
                offset += 1

        return fields

    def _heuristic_detect(self, data: bytes, offset: int) -> Optional[ProtocolField]:
        """Heuristic field detection at a given offset."""
        remaining = len(data) - offset
        if remaining <= 0:
            return None

        # Check for null-terminated string
        if remaining >= 4:
            try:
                chunk = data[offset:offset + min(256, remaining)]
                text = chunk.split(b"\x00")[0]
                if len(text) >= 4 and all(32 <= b < 127 for b in text):
                    return ProtocolField(
                        name="text_field",
                        field_type=FieldType.STRING_NULL_TERM,
                        offset=offset,
                        length=len(text) + 1,
                        value=text.decode("ascii"),
                        raw_bytes=text + b"\x00",
                    )
            except (ValueError, UnicodeDecodeError):
                pass

        # Check for common 4-byte patterns (uint32 length prefix)
        if remaining >= 8:
            val_be = struct.unpack("!I", data[offset:offset + 4])[0]
            if 1 < val_be < remaining - 4:
                return ProtocolField(
                    name="length_prefix",
                    field_type=FieldType.UINT32_BE,
                    offset=offset,
                    length=4,
                    value=val_be,
                    raw_bytes=data[offset:offset + 4],
                )

        # Check for 2-byte patterns (uint16 length prefix)
        if remaining >= 4:
            val_be = struct.unpack("!H", data[offset:offset + 2])[0]
            if 1 < val_be < remaining - 2:
                return ProtocolField(
                    name="length_prefix_16",
                    field_type=FieldType.UINT16_BE,
                    offset=offset,
                    length=2,
                    value=val_be,
                    raw_bytes=data[offset:offset + 2],
                )

        return None


# ════════════════════════════════════════════════════════════════════════════════
# HTTP DISSECTOR — Deep HTTP/1.x analysis
# ════════════════════════════════════════════════════════════════════════════════

class HTTPDissector:
    """Dissects HTTP/1.x requests and responses."""

    def dissect(self, data: bytes) -> List[ProtocolField]:
        """Extract HTTP fields from raw data."""
        fields: List[ProtocolField] = []
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            return fields

        lines = text.split("\r\n")
        if not lines:
            return fields

        # Request or status line
        first_line = lines[0]
        fields.append(ProtocolField(
            name="request_line" if " HTTP/" in first_line else "status_line",
            field_type=FieldType.STRING_FIXED,
            offset=0, length=len(first_line),
            value=first_line,
            raw_bytes=first_line.encode("utf-8", errors="replace"),
            is_mutable=True,
        ))

        # Headers
        header_offset = len(first_line) + 2
        for line in lines[1:]:
            if not line:
                # End of headers
                fields.append(ProtocolField(
                    name="header_end",
                    field_type=FieldType.BYTES_RAW,
                    offset=header_offset, length=2,
                    value=b"\r\n",
                    raw_bytes=b"\r\n",
                    is_mutable=False,
                ))
                header_offset += 2
                break
            if ":" in line:
                key, _, val = line.partition(":")
                fields.append(ProtocolField(
                    name=f"header.{key.strip().lower()}",
                    field_type=FieldType.STRING_FIXED,
                    offset=header_offset, length=len(line),
                    value=val.strip(),
                    raw_bytes=line.encode("utf-8", errors="replace"),
                    is_mutable=True,
                    description=f"HTTP header: {key.strip()}",
                ))
            header_offset += len(line) + 2

        # Body
        body_start = text.find("\r\n\r\n")
        if body_start >= 0:
            body_start += 4
            body = data[body_start:]
            if body:
                fields.append(ProtocolField(
                    name="body",
                    field_type=FieldType.BYTES_RAW,
                    offset=body_start, length=len(body),
                    value=body[:512],  # Truncate for display
                    raw_bytes=body,
                    is_mutable=True,
                ))

        return fields


# ════════════════════════════════════════════════════════════════════════════════
# TLS DISSECTOR — TLS Record/Handshake analysis
# ════════════════════════════════════════════════════════════════════════════════

class TLSDissector:
    """Dissects TLS record layer."""

    TLS_CONTENT_TYPES = {
        20: "ChangeCipherSpec",
        21: "Alert",
        22: "Handshake",
        23: "ApplicationData",
    }

    TLS_HANDSHAKE_TYPES = {
        1: "ClientHello",
        2: "ServerHello",
        11: "Certificate",
        12: "ServerKeyExchange",
        13: "CertificateRequest",
        14: "ServerHelloDone",
        15: "CertificateVerify",
        16: "ClientKeyExchange",
        20: "Finished",
    }

    def dissect(self, data: bytes) -> List[ProtocolField]:
        """Extract TLS fields from raw data."""
        fields: List[ProtocolField] = []
        if len(data) < 5:
            return fields

        content_type = data[0]
        version_major = data[1]
        version_minor = data[2]
        record_length = struct.unpack("!H", data[3:5])[0]

        fields.append(ProtocolField(
            name="content_type", field_type=FieldType.UINT8,
            offset=0, length=1,
            value=self.TLS_CONTENT_TYPES.get(content_type, f"Unknown({content_type})"),
            raw_bytes=data[0:1], is_mutable=False,
        ))
        fields.append(ProtocolField(
            name="tls_version", field_type=FieldType.UINT16_BE,
            offset=1, length=2,
            value=f"{version_major}.{version_minor}",
            raw_bytes=data[1:3], is_mutable=False,
        ))
        fields.append(ProtocolField(
            name="record_length", field_type=FieldType.UINT16_BE,
            offset=3, length=2,
            value=record_length,
            raw_bytes=data[3:5], is_mutable=False,
        ))

        # Handshake dissection
        if content_type == 22 and len(data) > 9:
            hs_type = data[5]
            hs_length = struct.unpack("!I", b"\x00" + data[6:9])[0]
            fields.append(ProtocolField(
                name="handshake_type", field_type=FieldType.UINT8,
                offset=5, length=1,
                value=self.TLS_HANDSHAKE_TYPES.get(hs_type, f"Unknown({hs_type})"),
                raw_bytes=data[5:6], is_mutable=False,
            ))
            fields.append(ProtocolField(
                name="handshake_length", field_type=FieldType.UINT32_BE,
                offset=6, length=3,
                value=hs_length,
                raw_bytes=data[6:9], is_mutable=False,
            ))

            # ClientHello extensions (SNI extraction)
            if hs_type == 1 and len(data) > 43:
                self._extract_client_hello(data, 9, fields)

        return fields

    def _extract_client_hello(self, data: bytes, offset: int, fields: List[ProtocolField]) -> None:
        """Extract ClientHello fields including SNI."""
        if offset + 34 > len(data):
            return
        # Client version
        fields.append(ProtocolField(
            name="client_version", field_type=FieldType.UINT16_BE,
            offset=offset, length=2,
            value=f"{data[offset]}.{data[offset + 1]}",
            raw_bytes=data[offset:offset + 2], is_mutable=False,
        ))
        # Random
        fields.append(ProtocolField(
            name="client_random", field_type=FieldType.BYTES_RAW,
            offset=offset + 2, length=32,
            value=data[offset + 2:offset + 34].hex(),
            raw_bytes=data[offset + 2:offset + 34], is_mutable=False,
        ))

        # Session ID length + skip
        ptr = offset + 34
        if ptr >= len(data):
            return
        sid_len = data[ptr]
        ptr += 1 + sid_len

        # Cipher suites
        if ptr + 2 > len(data):
            return
        cs_len = struct.unpack("!H", data[ptr:ptr + 2])[0]
        num_suites = cs_len // 2
        fields.append(ProtocolField(
            name="cipher_suite_count", field_type=FieldType.UINT16_BE,
            offset=ptr, length=2,
            value=num_suites,
            raw_bytes=data[ptr:ptr + 2], is_mutable=False,
        ))
        ptr += 2 + cs_len

        # Compression methods — skip
        if ptr >= len(data):
            return
        comp_len = data[ptr]
        ptr += 1 + comp_len

        # Extensions
        if ptr + 2 > len(data):
            return
        ext_total = struct.unpack("!H", data[ptr:ptr + 2])[0]
        ptr += 2
        ext_end = min(ptr + ext_total, len(data))

        while ptr + 4 <= ext_end:
            ext_type = struct.unpack("!H", data[ptr:ptr + 2])[0]
            ext_len = struct.unpack("!H", data[ptr + 2:ptr + 4])[0]
            # SNI extension (type 0)
            if ext_type == 0 and ptr + 4 + ext_len <= len(data) and ext_len > 5:
                sni_start = ptr + 4 + 5  # Skip list_len(2) + type(1) + name_len(2)
                sni_bytes = data[sni_start:ptr + 4 + ext_len]
                try:
                    sni = sni_bytes.decode("ascii")
                    fields.append(ProtocolField(
                        name="sni_hostname", field_type=FieldType.STRING_FIXED,
                        offset=sni_start, length=len(sni_bytes),
                        value=sni,
                        raw_bytes=sni_bytes, is_mutable=True,
                        description="Server Name Indication",
                    ))
                except (UnicodeDecodeError, ValueError):
                    pass
            ptr += 4 + ext_len


# ════════════════════════════════════════════════════════════════════════════════
# DNS DISSECTOR — DNS query/response analysis
# ════════════════════════════════════════════════════════════════════════════════

class DNSDissector:
    """Dissects DNS messages."""

    DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 15: "MX",
                 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}

    def dissect(self, data: bytes) -> List[ProtocolField]:
        fields: List[ProtocolField] = []
        if len(data) < 12:
            return fields

        txid = struct.unpack("!H", data[0:2])[0]
        flags = struct.unpack("!H", data[2:4])[0]
        qd_count = struct.unpack("!H", data[4:6])[0]
        an_count = struct.unpack("!H", data[6:8])[0]

        is_response = bool(flags & 0x8000)

        fields.append(ProtocolField(
            name="transaction_id", field_type=FieldType.UINT16_BE,
            offset=0, length=2, value=txid, raw_bytes=data[0:2],
        ))
        fields.append(ProtocolField(
            name="flags", field_type=FieldType.FLAG_BITS,
            offset=2, length=2,
            value=f"{'Response' if is_response else 'Query'} flags=0x{flags:04x}",
            raw_bytes=data[2:4], is_mutable=True,
        ))
        fields.append(ProtocolField(
            name="questions", field_type=FieldType.UINT16_BE,
            offset=4, length=2, value=qd_count, raw_bytes=data[4:6],
        ))
        fields.append(ProtocolField(
            name="answers", field_type=FieldType.UINT16_BE,
            offset=6, length=2, value=an_count, raw_bytes=data[6:8],
        ))

        # Parse question section
        ptr = 12
        for _ in range(min(qd_count, 10)):
            name, ptr = self._read_name(data, ptr)
            if ptr + 4 <= len(data):
                qtype = struct.unpack("!H", data[ptr:ptr + 2])[0]
                fields.append(ProtocolField(
                    name="query_name", field_type=FieldType.STRING_NULL_TERM,
                    offset=12, length=ptr - 12 + 4,
                    value=f"{name} ({self.DNS_TYPES.get(qtype, str(qtype))})",
                    raw_bytes=name.encode(),
                    is_mutable=True,
                ))
                ptr += 4

        return fields

    @staticmethod
    def _read_name(data: bytes, offset: int, max_jumps: int = 10) -> Tuple[str, int]:
        labels: List[str] = []
        ptr = offset
        jumped = False
        jumps = 0
        end_ptr = offset

        while ptr < len(data) and jumps < max_jumps:
            length = data[ptr]
            if length == 0:
                if not jumped:
                    end_ptr = ptr + 1
                break
            if (length & 0xC0) == 0xC0:
                if ptr + 1 >= len(data):
                    break
                jump_target = struct.unpack("!H", data[ptr:ptr + 2])[0] & 0x3FFF
                if not jumped:
                    end_ptr = ptr + 2
                ptr = jump_target
                jumped = True
                jumps += 1
                continue
            ptr += 1
            if ptr + length > len(data):
                break
            labels.append(data[ptr:ptr + length].decode("ascii", errors="replace"))
            ptr += length

        return ".".join(labels), end_ptr


# ════════════════════════════════════════════════════════════════════════════════
# ANOMALY DETECTOR — Detects protocol-level anomalies
# ════════════════════════════════════════════════════════════════════════════════

class AnomalyDetector:
    """Detects protocol-level anomalies."""

    def analyze(self, packet: DissectedPacket) -> List[AnomalyType]:
        """Check a dissected packet for anomalies."""
        anomalies: List[AnomalyType] = []

        # Length validation
        for f in packet.fields:
            if f.name == "content-length" or f.name == "record_length":
                try:
                    declared_len = int(f.value)
                    actual = len(packet.payload)
                    if declared_len > 0 and abs(declared_len - actual) > actual * 0.5:
                        anomalies.append(AnomalyType.INVALID_LENGTH)
                except (ValueError, TypeError):
                    pass

        # Entropy anomaly (high entropy in unexpected places)
        if packet.app_protocol in (AppProtocol.HTTP, AppProtocol.FTP, AppProtocol.SMTP):
            if packet.entropy > 7.0 and not packet.is_compressed:
                anomalies.append(AnomalyType.SUSPICIOUS_PAYLOAD)

        # Protocol-specific checks
        if packet.app_protocol == AppProtocol.HTTP:
            anomalies.extend(self._check_http_anomalies(packet))

        if packet.app_protocol == AppProtocol.DNS:
            anomalies.extend(self._check_dns_anomalies(packet))

        return anomalies

    @staticmethod
    def _check_http_anomalies(packet: DissectedPacket) -> List[AnomalyType]:
        """HTTP-specific anomaly detection."""
        anomalies: List[AnomalyType] = []
        header_names = {f.name for f in packet.fields}

        # Duplicate host headers (HTTP request smuggling indicator)
        host_count = sum(1 for f in packet.fields if f.name == "header.host")
        if host_count > 1:
            anomalies.append(AnomalyType.DESYNC_DETECTED)

        # Both Content-Length and Transfer-Encoding (smuggling)
        has_cl = "header.content-length" in header_names
        has_te = "header.transfer-encoding" in header_names
        if has_cl and has_te:
            anomalies.append(AnomalyType.DESYNC_DETECTED)

        return anomalies

    @staticmethod
    def _check_dns_anomalies(packet: DissectedPacket) -> List[AnomalyType]:
        """DNS-specific anomaly checks."""
        anomalies: List[AnomalyType] = []
        if len(packet.raw) > 512 and packet.transport == TransportProto.UDP:
            pass  # EDNS allows larger
        if len(packet.raw) > 4096:
            anomalies.append(AnomalyType.SUSPICIOUS_PAYLOAD)
        return anomalies


# ════════════════════════════════════════════════════════════════════════════════
# FUZZING SEED GENERATOR — Creates intelligent fuzzing seeds
# ════════════════════════════════════════════════════════════════════════════════

class FuzzingSeedGenerator:
    """Generates fuzzing seeds from dissected protocol messages."""

    def generate(self, packet: DissectedPacket, max_seeds: int = 10) -> List[FuzzingSeed]:
        """Generate fuzzing seeds from a dissected packet."""
        seeds: List[FuzzingSeed] = []

        # Find mutable fields
        mutable_fields = [f for f in packet.fields if f.is_mutable and f.length > 0]
        if not mutable_fields:
            return seeds

        # Seed 1: Original packet with all mutation points
        mutation_points = [
            (f.offset, f.length, f.name)
            for f in mutable_fields
        ]
        seeds.append(FuzzingSeed(
            base_payload=packet.raw,
            mutation_points=mutation_points,
            protocol=packet.app_protocol,
            priority=10,
        ))

        # Seed 2: Minimal packet (remove optional fields)
        seeds.extend(self._generate_minimal_seeds(packet, mutable_fields, max_seeds - 1))

        return seeds[:max_seeds]

    @staticmethod
    def _generate_minimal_seeds(packet: DissectedPacket, fields: List[ProtocolField], max_count: int) -> List[FuzzingSeed]:
        """Generate minimized seeds targeting specific fields."""
        seeds: List[FuzzingSeed] = []

        for f in fields[:max_count]:
            seed = FuzzingSeed(
                base_payload=packet.raw,
                mutation_points=[(f.offset, f.length, f.name)],
                protocol=packet.app_protocol,
                priority=5,
            )
            seeds.append(seed)

        return seeds


# ════════════════════════════════════════════════════════════════════════════════
# SESSION RECONSTRUCTOR — Reassembles sessions from packets
# ════════════════════════════════════════════════════════════════════════════════

class SessionReconstructor:
    """Reconstructs application-layer sessions from packets."""

    def __init__(self) -> None:
        self._sessions: Dict[str, SessionState] = {}
        self._lock = threading.RLock()

    def add_packet(self, packet: DissectedPacket) -> str:
        """Add a packet to session tracking. Returns session ID."""
        sid = self._make_session_id(packet)
        with self._lock:
            if sid not in self._sessions:
                self._sessions[sid] = SessionState(
                    session_id=sid,
                    src=f"{packet.src_addr}:{packet.src_port}",
                    dst=f"{packet.dst_addr}:{packet.dst_port}",
                    protocol=packet.app_protocol,
                    start_time=packet.timestamp,
                    state="ACTIVE",
                )
            session = self._sessions[sid]
            session.packets.append(packet)
            session.last_seen = packet.timestamp
            if packet.src_addr == session.src.split(":")[0]:
                session.bytes_sent += len(packet.raw)
            else:
                session.bytes_received += len(packet.raw)
        return sid

    def get_session(self, session_id: str) -> Optional[SessionState]:
        with self._lock:
            return self._sessions.get(session_id)

    def get_all_sessions(self) -> Dict[str, Dict[str, Any]]:
        with self._lock:
            return {sid: s.to_dict() for sid, s in self._sessions.items()}

    @staticmethod
    def _make_session_id(packet: DissectedPacket) -> str:
        """Create a deterministic session ID from packet endpoints."""
        endpoints = sorted([
            f"{packet.src_addr}:{packet.src_port}",
            f"{packet.dst_addr}:{packet.dst_port}",
        ])
        raw_id = f"{endpoints[0]}<>{endpoints[1]}"
        return hashlib.sha256(raw_id.encode()).hexdigest()[:16]


# ════════════════════════════════════════════════════════════════════════════════
# SIREN PROTOCOL DISSECTOR — Main Orchestrator
# ════════════════════════════════════════════════════════════════════════════════

class SirenProtocolDissector:
    """
    Main protocol dissector engine.

    Orchestrates identification, dissection, anomaly detection,
    session reconstruction, and fuzzing seed generation.

    Usage:
        dissector = SirenProtocolDissector()

        # Dissect raw data
        result = dissector.dissect(raw_bytes, dst_port=443)

        # Get session info
        sessions = dissector.get_sessions()

        # Generate fuzzing seeds
        seeds = dissector.get_fuzzing_seeds(result)
    """

    def __init__(self, depth: DissectionDepth = DissectionDepth.DEEP) -> None:
        self._lock = threading.RLock()
        self._depth = depth
        self._identifier = ProtocolIdentifier()
        self._field_extractor = BinaryFieldExtractor()
        self._http_dissector = HTTPDissector()
        self._tls_dissector = TLSDissector()
        self._dns_dissector = DNSDissector()
        self._anomaly_detector = AnomalyDetector()
        self._session_reconstructor = SessionReconstructor()
        self._fuzzing_generator = FuzzingSeedGenerator()
        self._stats: Dict[str, int] = defaultdict(int)
        logger.info("SirenProtocolDissector initialized (depth=%s)", depth.name)

    def dissect(
        self,
        data: bytes,
        src_addr: str = "",
        dst_addr: str = "",
        src_port: int = 0,
        dst_port: int = 0,
        transport: TransportProto = TransportProto.TCP,
    ) -> DissectedPacket:
        """Dissect raw network data into structured fields."""
        if not data or len(data) > MAX_PACKET_SIZE:
            return DissectedPacket(raw=data[:MAX_PACKET_SIZE] if data else b"")

        with self._lock:
            self._stats["total_packets"] += 1

        # 1. Identify protocol
        protocol, confidence = self._identifier.identify(data, dst_port, src_port)

        # 2. Create packet
        packet = DissectedPacket(
            raw=data,
            transport=transport,
            app_protocol=protocol,
            src_addr=src_addr,
            dst_addr=dst_addr,
            src_port=src_port,
            dst_port=dst_port,
        )

        # 3. Entropy analysis
        if self._depth in (DissectionDepth.DEEP, DissectionDepth.EXHAUSTIVE):
            packet.entropy = EntropyAnalyzer.calculate(data)
            packet.is_encrypted = EntropyAnalyzer.is_encrypted(data)
            packet.is_compressed = EntropyAnalyzer.is_compressed(data)

        # 4. Protocol-specific dissection
        if self._depth != DissectionDepth.HEADERS_ONLY:
            packet.fields = self._dissect_protocol(packet, protocol)

        # 5. Anomaly detection
        if self._depth in (DissectionDepth.DEEP, DissectionDepth.EXHAUSTIVE):
            packet.anomalies = self._anomaly_detector.analyze(packet)

        # 6. Session tracking
        self._session_reconstructor.add_packet(packet)

        with self._lock:
            self._stats[f"protocol.{protocol.name}"] += 1
            if packet.anomalies:
                self._stats["anomalies_detected"] += len(packet.anomalies)

        return packet

    def get_fuzzing_seeds(self, packet: DissectedPacket, max_seeds: int = 10) -> List[FuzzingSeed]:
        """Generate fuzzing seeds from a dissected packet."""
        return self._fuzzing_generator.generate(packet, max_seeds)

    def get_sessions(self) -> Dict[str, Dict[str, Any]]:
        return self._session_reconstructor.get_all_sessions()

    def get_stats(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._stats)

    # ── Private ─────────────────────────────────────────────────────────────

    def _dissect_protocol(self, packet: DissectedPacket, protocol: AppProtocol) -> List[ProtocolField]:
        """Route to protocol-specific dissector."""
        if protocol == AppProtocol.HTTP:
            return self._http_dissector.dissect(packet.raw)
        elif protocol == AppProtocol.TLS:
            return self._tls_dissector.dissect(packet.raw)
        elif protocol == AppProtocol.DNS:
            return self._dns_dissector.dissect(packet.raw)
        elif protocol == AppProtocol.CUSTOM_BINARY or protocol == AppProtocol.UNKNOWN:
            return self._field_extractor.detect_fields(packet.raw)
        return []
