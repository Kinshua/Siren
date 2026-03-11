#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  🔬 SIREN FIRMWARE ANALYZER — Deep Firmware Reverse Engineering Engine  🔬  ██
██                                                                                ██
██  Analise profunda de firmware: entropia, filesystems, strings, crypto,        ██
██  credenciais hardcoded, padroes de vulnerabilidade e comparacao binaria.      ██
██                                                                                ██
██  Capacidades:                                                                  ██
██    • Entropy analysis — Shannon entropy com sliding window                    ██
██    • Filesystem extraction — squashfs/cramfs/jffs2/ubifs/ext4                ██
██    • Binary string extraction — URLs, IPs, emails, API keys, certs           ██
██    • Crypto key finder — DES/RC4/MD5 weakness, hardcoded keys/IVs           ██
██    • Hardcoded credential detection — passwords, base64 creds, env leaks     ██
██    • Vulnerability pattern matching — CVE patterns, buffer overflows          ██
██    • Firmware comparison — binary diff, patch analysis, delta functions       ██
██    • Report generation — consolidated findings with severity scoring          ██
██                                                                                ██
██  "SIREN disseca o firmware ate o ultimo byte. Nada escapa."                   ██
██                                                                                ██
████████████████████████████████████████████████████████████████████████████████████
"""

from __future__ import annotations

import binascii
import hashlib
import io
import json
import logging
import math
import os
import re
import string
import struct
import threading
import time
import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import PurePosixPath
from typing import Any, Callable, Dict, Generator, List, Optional, Set, Tuple

logger = logging.getLogger("siren.arsenal.firmware_analyzer")


# ════════════════════════════════════════════════════════════════════════════════
# ENUMS
# ════════════════════════════════════════════════════════════════════════════════

class Severity(Enum):
    """Severity levels for firmware findings."""
    CRITICAL = auto()
    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()
    INFO = auto()


class FindingCategory(Enum):
    """Categories of firmware security findings."""
    ENTROPY_ANOMALY = auto()
    FILESYSTEM_DETECTED = auto()
    SENSITIVE_STRING = auto()
    HARDCODED_CREDENTIAL = auto()
    WEAK_CRYPTO = auto()
    CRYPTO_KEY_EXPOSED = auto()
    VULNERABLE_FUNCTION = auto()
    BUFFER_OVERFLOW = auto()
    FORMAT_STRING = auto()
    CVE_PATTERN = auto()
    CERTIFICATE_ISSUE = auto()
    BACKDOOR_INDICATOR = auto()
    DEBUG_ARTIFACT = auto()
    INSECURE_PROTOCOL = auto()
    BINARY_DIFF = auto()
    REMOVED_SECURITY = auto()
    ADDED_VULNERABILITY = auto()


class FilesystemType(Enum):
    """Supported firmware filesystem types."""
    SQUASHFS = auto()
    CRAMFS = auto()
    JFFS2 = auto()
    UBIFS = auto()
    EXT4 = auto()
    ROMFS = auto()
    YAFFS2 = auto()
    CPIO = auto()
    TAR = auto()
    UNKNOWN = auto()


class CryptoAlgorithm(Enum):
    """Cryptographic algorithms detectable in firmware."""
    AES = auto()
    DES = auto()
    TRIPLE_DES = auto()
    RC4 = auto()
    BLOWFISH = auto()
    RSA = auto()
    DSA = auto()
    ECDSA = auto()
    MD5 = auto()
    SHA1 = auto()
    SHA256 = auto()
    SHA512 = auto()
    HMAC = auto()
    UNKNOWN = auto()


class CryptoWeakness(Enum):
    """Types of cryptographic weaknesses."""
    WEAK_ALGORITHM = auto()
    HARDCODED_KEY = auto()
    HARDCODED_IV = auto()
    NULL_IV = auto()
    ECB_MODE = auto()
    BROKEN_RNG = auto()
    SHORT_KEY = auto()
    EXPIRED_CERT = auto()
    SELF_SIGNED_CERT = auto()
    WEAK_HASH = auto()
    STATIC_SALT = auto()


class ComparisonResult(Enum):
    """Result types for firmware comparison."""
    IDENTICAL = auto()
    MODIFIED = auto()
    ADDED = auto()
    REMOVED = auto()
    PATCHED = auto()
    REGRESSION = auto()


class ArchType(Enum):
    """Firmware CPU architecture."""
    ARM = auto()
    ARM64 = auto()
    MIPS = auto()
    MIPS64 = auto()
    X86 = auto()
    X86_64 = auto()
    PPC = auto()
    SPARC = auto()
    RISCV = auto()
    UNKNOWN = auto()


class Endianness(Enum):
    """Byte ordering."""
    LITTLE = auto()
    BIG = auto()
    UNKNOWN = auto()


# ════════════════════════════════════════════════════════════════════════════════
# DATACLASSES
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class EntropyRegion:
    """A region of the firmware with computed entropy."""
    offset: int = 0
    size: int = 0
    entropy: float = 0.0
    classification: str = ""
    is_compressed: bool = False
    is_encrypted: bool = False
    is_code: bool = False
    is_padding: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "offset": self.offset,
            "size": self.size,
            "entropy": round(self.entropy, 6),
            "classification": self.classification,
            "is_compressed": self.is_compressed,
            "is_encrypted": self.is_encrypted,
            "is_code": self.is_code,
            "is_padding": self.is_padding,
        }


@dataclass
class EntropyProfile:
    """Full entropy profile for a firmware image."""
    firmware_hash: str = ""
    total_size: int = 0
    global_entropy: float = 0.0
    window_size: int = 256
    regions: List[EntropyRegion] = field(default_factory=list)
    histogram_data: List[float] = field(default_factory=list)
    compressed_pct: float = 0.0
    encrypted_pct: float = 0.0
    code_pct: float = 0.0
    padding_pct: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "firmware_hash": self.firmware_hash,
            "total_size": self.total_size,
            "global_entropy": round(self.global_entropy, 6),
            "window_size": self.window_size,
            "regions": [r.to_dict() for r in self.regions],
            "histogram_data": [round(h, 4) for h in self.histogram_data],
            "compressed_pct": round(self.compressed_pct, 2),
            "encrypted_pct": round(self.encrypted_pct, 2),
            "code_pct": round(self.code_pct, 2),
            "padding_pct": round(self.padding_pct, 2),
            "timestamp": self.timestamp,
        }


@dataclass
class FilesystemEntry:
    """A file entry found within a firmware filesystem."""
    path: str = ""
    size: int = 0
    offset: int = 0
    entry_type: str = "file"
    permissions: str = ""
    owner: str = ""
    is_executable: bool = False
    is_setuid: bool = False
    is_setgid: bool = False
    is_symlink: bool = False
    link_target: str = ""
    sha256: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "size": self.size,
            "offset": self.offset,
            "entry_type": self.entry_type,
            "permissions": self.permissions,
            "owner": self.owner,
            "is_executable": self.is_executable,
            "is_setuid": self.is_setuid,
            "is_setgid": self.is_setgid,
            "is_symlink": self.is_symlink,
            "link_target": self.link_target,
            "sha256": self.sha256,
        }


@dataclass
class FilesystemInfo:
    """Metadata about a detected filesystem within firmware."""
    fs_type: FilesystemType = FilesystemType.UNKNOWN
    offset: int = 0
    size: int = 0
    magic_bytes: bytes = b""
    block_size: int = 0
    compression: str = ""
    endianness: Endianness = Endianness.UNKNOWN
    version: str = ""
    entries: List[FilesystemEntry] = field(default_factory=list)
    total_files: int = 0
    total_dirs: int = 0
    interesting_files: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fs_type": self.fs_type.name,
            "offset": self.offset,
            "size": self.size,
            "magic_bytes": self.magic_bytes.hex(),
            "block_size": self.block_size,
            "compression": self.compression,
            "endianness": self.endianness.name,
            "version": self.version,
            "entries": [e.to_dict() for e in self.entries],
            "total_files": self.total_files,
            "total_dirs": self.total_dirs,
            "interesting_files": self.interesting_files,
        }


@dataclass
class ExtractedString:
    """A string extracted from binary firmware data."""
    value: str = ""
    offset: int = 0
    length: int = 0
    string_type: str = "ascii"
    context_before: bytes = b""
    context_after: bytes = b""
    category: str = ""
    confidence: float = 0.0
    is_url: bool = False
    is_ip: bool = False
    is_email: bool = False
    is_api_key: bool = False
    is_cert: bool = False
    is_password: bool = False
    is_path: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "value": self.value,
            "offset": self.offset,
            "length": self.length,
            "string_type": self.string_type,
            "context_before": self.context_before.hex() if self.context_before else "",
            "context_after": self.context_after.hex() if self.context_after else "",
            "category": self.category,
            "confidence": round(self.confidence, 4),
            "is_url": self.is_url,
            "is_ip": self.is_ip,
            "is_email": self.is_email,
            "is_api_key": self.is_api_key,
            "is_cert": self.is_cert,
            "is_password": self.is_password,
            "is_path": self.is_path,
        }


@dataclass
class CryptoFinding:
    """A cryptographic artifact found in firmware."""
    algorithm: CryptoAlgorithm = CryptoAlgorithm.UNKNOWN
    weakness: CryptoWeakness = CryptoWeakness.WEAK_ALGORITHM
    offset: int = 0
    size: int = 0
    key_data: bytes = b""
    iv_data: bytes = b""
    description: str = ""
    severity: Severity = Severity.MEDIUM
    confidence: float = 0.0
    context: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "algorithm": self.algorithm.name,
            "weakness": self.weakness.name,
            "offset": self.offset,
            "size": self.size,
            "key_data_hex": self.key_data.hex() if self.key_data else "",
            "iv_data_hex": self.iv_data.hex() if self.iv_data else "",
            "description": self.description,
            "severity": self.severity.name,
            "confidence": round(self.confidence, 4),
            "context": self.context,
        }


@dataclass
class CredentialFinding:
    """A hardcoded credential found in firmware."""
    cred_type: str = ""
    username: str = ""
    password: str = ""
    location: str = ""
    offset: int = 0
    raw_match: str = ""
    encoding: str = "plaintext"
    confidence: float = 0.0
    severity: Severity = Severity.HIGH
    context: str = ""
    is_default: bool = False
    is_base64: bool = False
    is_env_var: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cred_type": self.cred_type,
            "username": self.username,
            "password": self.password[:4] + "****" if len(self.password) > 4 else "****",
            "location": self.location,
            "offset": self.offset,
            "raw_match": self.raw_match[:80] + "..." if len(self.raw_match) > 80 else self.raw_match,
            "encoding": self.encoding,
            "confidence": round(self.confidence, 4),
            "severity": self.severity.name,
            "context": self.context,
            "is_default": self.is_default,
            "is_base64": self.is_base64,
            "is_env_var": self.is_env_var,
        }


@dataclass
class VulnMatch:
    """A vulnerability pattern match in firmware."""
    pattern_name: str = ""
    cve_id: str = ""
    function_name: str = ""
    offset: int = 0
    matched_bytes: bytes = b""
    description: str = ""
    severity: Severity = Severity.MEDIUM
    category: FindingCategory = FindingCategory.VULNERABLE_FUNCTION
    confidence: float = 0.0
    remediation: str = ""
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pattern_name": self.pattern_name,
            "cve_id": self.cve_id,
            "function_name": self.function_name,
            "offset": self.offset,
            "matched_bytes": self.matched_bytes.hex() if self.matched_bytes else "",
            "description": self.description,
            "severity": self.severity.name,
            "category": self.category.name,
            "confidence": round(self.confidence, 4),
            "remediation": self.remediation,
            "references": self.references,
        }


@dataclass
class BinaryDelta:
    """A difference between two firmware versions."""
    offset: int = 0
    size: int = 0
    old_data: bytes = b""
    new_data: bytes = b""
    result_type: ComparisonResult = ComparisonResult.MODIFIED
    description: str = ""
    security_impact: str = ""
    severity: Severity = Severity.INFO
    in_function: str = ""
    in_section: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "offset": self.offset,
            "size": self.size,
            "old_data_hex": self.old_data[:64].hex() if self.old_data else "",
            "new_data_hex": self.new_data[:64].hex() if self.new_data else "",
            "result_type": self.result_type.name,
            "description": self.description,
            "security_impact": self.security_impact,
            "severity": self.severity.name,
            "in_function": self.in_function,
            "in_section": self.in_section,
        }


@dataclass
class FirmwareFinding:
    """A consolidated finding from firmware analysis."""
    finding_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    category: FindingCategory = FindingCategory.SENSITIVE_STRING
    severity: Severity = Severity.INFO
    title: str = ""
    description: str = ""
    offset: int = 0
    size: int = 0
    evidence: str = ""
    confidence: float = 0.0
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "category": self.category.name,
            "severity": self.severity.name,
            "title": self.title,
            "description": self.description,
            "offset": self.offset,
            "size": self.size,
            "evidence": self.evidence[:200] if self.evidence else "",
            "confidence": round(self.confidence, 4),
            "remediation": self.remediation,
            "references": self.references,
            "metadata": self.metadata,
            "timestamp": self.timestamp,
        }


@dataclass
class FirmwareReport:
    """Complete firmware analysis report."""
    report_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    firmware_name: str = ""
    firmware_size: int = 0
    firmware_hash_sha256: str = ""
    firmware_hash_md5: str = ""
    architecture: ArchType = ArchType.UNKNOWN
    endianness: Endianness = Endianness.UNKNOWN
    entropy_profile: Optional[EntropyProfile] = None
    filesystems: List[FilesystemInfo] = field(default_factory=list)
    strings_extracted: int = 0
    findings: List[FirmwareFinding] = field(default_factory=list)
    crypto_findings: List[CryptoFinding] = field(default_factory=list)
    credential_findings: List[CredentialFinding] = field(default_factory=list)
    vuln_matches: List[VulnMatch] = field(default_factory=list)
    comparison_deltas: List[BinaryDelta] = field(default_factory=list)
    analysis_time_seconds: float = 0.0
    summary: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "firmware_name": self.firmware_name,
            "firmware_size": self.firmware_size,
            "firmware_hash_sha256": self.firmware_hash_sha256,
            "firmware_hash_md5": self.firmware_hash_md5,
            "architecture": self.architecture.name,
            "endianness": self.endianness.name,
            "entropy_profile": self.entropy_profile.to_dict() if self.entropy_profile else None,
            "filesystems": [f.to_dict() for f in self.filesystems],
            "strings_extracted": self.strings_extracted,
            "findings": [f.to_dict() for f in self.findings],
            "crypto_findings": [c.to_dict() for c in self.crypto_findings],
            "credential_findings": [c.to_dict() for c in self.credential_findings],
            "vuln_matches": [v.to_dict() for v in self.vuln_matches],
            "comparison_deltas": [d.to_dict() for d in self.comparison_deltas],
            "analysis_time_seconds": round(self.analysis_time_seconds, 3),
            "summary": self.summary,
            "timestamp": self.timestamp,
        }

    def severity_counts(self) -> Dict[str, int]:
        """Count findings by severity level."""
        counts: Dict[str, int] = {s.name: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.name] += 1
        return counts

    def category_counts(self) -> Dict[str, int]:
        """Count findings by category."""
        counts: Dict[str, int] = defaultdict(int)
        for f in self.findings:
            counts[f.category.name] += 1
        return dict(counts)


@dataclass
class FirmwareMetadata:
    """Basic metadata about a firmware image."""
    file_path: str = ""
    file_size: int = 0
    sha256: str = ""
    md5: str = ""
    architecture: ArchType = ArchType.UNKNOWN
    endianness: Endianness = Endianness.UNKNOWN
    header_magic: bytes = b""
    vendor_guess: str = ""
    device_guess: str = ""
    version_guess: str = ""
    build_date_guess: str = ""
    load_address: int = 0
    entry_point: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "file_size": self.file_size,
            "sha256": self.sha256,
            "md5": self.md5,
            "architecture": self.architecture.name,
            "endianness": self.endianness.name,
            "header_magic": self.header_magic.hex() if self.header_magic else "",
            "vendor_guess": self.vendor_guess,
            "device_guess": self.device_guess,
            "version_guess": self.version_guess,
            "build_date_guess": self.build_date_guess,
            "load_address": hex(self.load_address),
            "entry_point": hex(self.entry_point),
        }


# ════════════════════════════════════════════════════════════════════════════════
# MAGIC BYTES DATABASE
# ════════════════════════════════════════════════════════════════════════════════

_FILESYSTEM_MAGIC: Dict[FilesystemType, List[Tuple[bytes, int]]] = {
    # (magic_bytes, typical_offset_within_header)
    FilesystemType.SQUASHFS: [
        (b"hsqs", 0),          # SquashFS LE
        (b"sqsh", 0),          # SquashFS BE
        (b"shsq", 0),          # SquashFS alt LE
        (b"qshs", 0),          # SquashFS alt BE
        (b"tqsh", 0),          # SquashFS LZMA
        (b"hsqt", 0),          # SquashFS LZMA alt
    ],
    FilesystemType.CRAMFS: [
        (b"\x45\x3d\xcd\x28", 0),  # CramFS LE
        (b"\x28\xcd\x3d\x45", 0),  # CramFS BE
    ],
    FilesystemType.JFFS2: [
        (b"\x85\x19", 0),      # JFFS2 LE
        (b"\x19\x85", 0),      # JFFS2 BE
    ],
    FilesystemType.UBIFS: [
        (b"UBI#", 0),          # UBI superblock
        (b"\x31\x18\x10\x06", 0),  # UBIFS node magic
    ],
    FilesystemType.EXT4: [
        (b"\x53\xef", 0x38),   # EXT superblock magic at offset 0x438
    ],
    FilesystemType.ROMFS: [
        (b"-rom1fs-", 0),      # RomFS
    ],
    FilesystemType.CPIO: [
        (b"070701", 0),        # CPIO newc
        (b"070702", 0),        # CPIO newc CRC
        (b"\xc7\x71", 0),     # CPIO binary LE
        (b"\x71\xc7", 0),     # CPIO binary BE
    ],
}

_ARCH_SIGNATURES: Dict[ArchType, List[bytes]] = {
    ArchType.ARM: [
        b"\x7fELF\x01\x01\x01",      # ELF 32-bit LE (ARM)
    ],
    ArchType.ARM64: [
        b"\x7fELF\x02\x01\x01",      # ELF 64-bit LE (ARM64)
    ],
    ArchType.MIPS: [
        b"\x7fELF\x01\x02\x01",      # ELF 32-bit BE (MIPS)
    ],
    ArchType.X86: [
        b"\x7fELF\x01\x01\x01\x00",  # ELF 32-bit LE x86
    ],
    ArchType.X86_64: [
        b"\x7fELF\x02\x01\x01\x00",  # ELF 64-bit LE x86_64
    ],
}

_FIRMWARE_HEADER_MAGIC: List[Tuple[bytes, str]] = [
    (b"\x27\x05\x19\x56", "uImage"),
    (b"UBI#", "UBI"),
    (b"\xde\xad\xc0\xde", "Broadcom TRX"),
    (b"HDR0", "Broadcom TRX"),
    (b"NRG1", "TP-Link"),
    (b"\x01\x00\x00\x00ASUS", "ASUS"),
    (b"SHRS", "D-Link SHRS"),
    (b"\x5e\xa3\xa4\x17", "SEAMA"),
    (b"CSYS", "CSYS generic"),
    (b"\xd0\x0d\xfe\xed", "FDT/DTB"),
    (b"\xed\xfe\x0d\xd0", "FDT/DTB LE"),
    (b"androidboot", "Android boot"),
    (b"ANDROID!", "Android boot image"),
    (b"\x1f\x8b\x08", "gzip compressed"),
    (b"\xfd\x37\x7a\x58\x5a\x00", "xz compressed"),
    (b"\x42\x5a\x68", "bzip2 compressed"),
    (b"\x5d\x00\x00", "LZMA compressed"),
    (b"\x89\x4c\x5a\x4f", "LZO compressed"),
    (b"\x04\x22\x4d\x18", "LZ4 compressed"),
    (b"\x28\xb5\x2f\xfd", "Zstandard compressed"),
]


# ════════════════════════════════════════════════════════════════════════════════
# ENTROPY ANALYZER
# ════════════════════════════════════════════════════════════════════════════════

class EntropyAnalyzer:
    """
    Shannon entropy analysis engine for firmware images.

    Computes sliding-window entropy to identify compressed, encrypted, code,
    and padding regions within a binary firmware image.

    Usage:
        analyzer = EntropyAnalyzer(window_size=256, step_size=128)
        profile = analyzer.analyze(firmware_data)
        histogram = analyzer.ascii_histogram(profile)
        print(histogram)
    """

    # Entropy thresholds for classification
    ENTROPY_ENCRYPTED_MIN: float = 7.9      # Near-max: likely encrypted/random
    ENTROPY_COMPRESSED_MIN: float = 7.0      # High entropy: compressed data
    ENTROPY_CODE_MIN: float = 4.5            # Moderate: executable code
    ENTROPY_CODE_MAX: float = 7.0            # Upper bound for code
    ENTROPY_DATA_MIN: float = 2.0            # Structured data
    ENTROPY_DATA_MAX: float = 4.5            # Upper bound for data
    ENTROPY_PADDING_MAX: float = 0.5         # Near-zero: padding/empty

    def __init__(
        self,
        window_size: int = 256,
        step_size: int = 128,
        merge_threshold: int = 512,
    ) -> None:
        self._lock = threading.RLock()
        self._window_size = max(64, window_size)
        self._step_size = max(1, step_size)
        self._merge_threshold = merge_threshold
        self._byte_log2: List[float] = self._precompute_log2_table()
        logger.info(
            "EntropyAnalyzer initialized (window=%d, step=%d)",
            self._window_size, self._step_size,
        )

    @staticmethod
    def _precompute_log2_table() -> List[float]:
        """Precompute -p*log2(p) for p=i/256 for each byte count i in [0..256]."""
        table: List[float] = [0.0] * 257
        for i in range(1, 257):
            p = i / 256.0
            table[i] = -p * math.log2(p)
        return table

    def shannon_entropy(self, data: bytes) -> float:
        """Compute Shannon entropy of a byte sequence (0.0 to 8.0)."""
        if not data:
            return 0.0
        length = len(data)
        if length == 0:
            return 0.0
        counts = Counter(data)
        entropy = 0.0
        for count in counts.values():
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return entropy

    def _fast_window_entropy(self, data: bytes, offset: int, size: int) -> float:
        """Compute entropy for a specific window using optimized counting."""
        window = data[offset:offset + size]
        if len(window) < 16:
            return 0.0
        return self.shannon_entropy(window)

    def _classify_region(self, entropy: float) -> Tuple[str, bool, bool, bool, bool]:
        """
        Classify a region by its entropy value.

        Returns:
            (classification, is_compressed, is_encrypted, is_code, is_padding)
        """
        if entropy >= self.ENTROPY_ENCRYPTED_MIN:
            return ("encrypted_or_random", False, True, False, False)
        elif entropy >= self.ENTROPY_COMPRESSED_MIN:
            return ("compressed", True, False, False, False)
        elif entropy >= self.ENTROPY_CODE_MIN:
            return ("executable_code", False, False, True, False)
        elif entropy >= self.ENTROPY_DATA_MIN:
            return ("structured_data", False, False, False, False)
        elif entropy <= self.ENTROPY_PADDING_MAX:
            return ("padding_or_empty", False, False, False, True)
        else:
            return ("low_entropy_data", False, False, False, False)

    def analyze(self, data: bytes, firmware_hash: str = "") -> EntropyProfile:
        """
        Perform full entropy analysis on firmware data.

        Args:
            data: Raw firmware binary data.
            firmware_hash: Optional pre-computed hash for identification.

        Returns:
            EntropyProfile with per-region entropy data.
        """
        with self._lock:
            start_time = time.time()
            total_size = len(data)

            if not firmware_hash:
                firmware_hash = hashlib.sha256(data).hexdigest()

            global_entropy = self.shannon_entropy(data)
            histogram_data: List[float] = []
            raw_regions: List[Tuple[int, float]] = []

            # Sliding window entropy computation
            offset = 0
            while offset < total_size:
                window_end = min(offset + self._window_size, total_size)
                actual_size = window_end - offset
                if actual_size < 16:
                    break
                ent = self._fast_window_entropy(data, offset, actual_size)
                histogram_data.append(ent)
                raw_regions.append((offset, ent))
                offset += self._step_size

            # Merge adjacent regions with similar classification
            merged_regions = self._merge_regions(raw_regions, data)

            # Compute percentages
            compressed_bytes = 0
            encrypted_bytes = 0
            code_bytes = 0
            padding_bytes = 0
            for region in merged_regions:
                if region.is_compressed:
                    compressed_bytes += region.size
                if region.is_encrypted:
                    encrypted_bytes += region.size
                if region.is_code:
                    code_bytes += region.size
                if region.is_padding:
                    padding_bytes += region.size

            profile = EntropyProfile(
                firmware_hash=firmware_hash,
                total_size=total_size,
                global_entropy=global_entropy,
                window_size=self._window_size,
                regions=merged_regions,
                histogram_data=histogram_data,
                compressed_pct=(compressed_bytes / total_size * 100) if total_size > 0 else 0.0,
                encrypted_pct=(encrypted_bytes / total_size * 100) if total_size > 0 else 0.0,
                code_pct=(code_bytes / total_size * 100) if total_size > 0 else 0.0,
                padding_pct=(padding_bytes / total_size * 100) if total_size > 0 else 0.0,
                timestamp=time.time(),
            )

            elapsed = time.time() - start_time
            logger.info(
                "Entropy analysis complete: %d bytes, global=%.4f, %d regions, %.3fs",
                total_size, global_entropy, len(merged_regions), elapsed,
            )
            return profile

    def _merge_regions(
        self, raw_regions: List[Tuple[int, float]], data: bytes
    ) -> List[EntropyRegion]:
        """Merge adjacent windows with the same classification into larger regions."""
        if not raw_regions:
            return []

        merged: List[EntropyRegion] = []
        current_offset, current_ent = raw_regions[0]
        current_class, c_comp, c_enc, c_code, c_pad = self._classify_region(current_ent)
        accumulated_entropy: List[float] = [current_ent]
        region_start = current_offset

        for i in range(1, len(raw_regions)):
            offset, ent = raw_regions[i]
            classification, is_comp, is_enc, is_code, is_pad = self._classify_region(ent)

            if classification == current_class and (offset - region_start) < self._merge_threshold * 10:
                accumulated_entropy.append(ent)
            else:
                # Finalize current region
                region_size = offset - region_start
                avg_ent = sum(accumulated_entropy) / len(accumulated_entropy)
                merged.append(EntropyRegion(
                    offset=region_start,
                    size=region_size,
                    entropy=avg_ent,
                    classification=current_class,
                    is_compressed=c_comp,
                    is_encrypted=c_enc,
                    is_code=c_code,
                    is_padding=c_pad,
                ))
                # Start new region
                region_start = offset
                current_class = classification
                c_comp, c_enc, c_code, c_pad = is_comp, is_enc, is_code, is_pad
                accumulated_entropy = [ent]

        # Finalize last region
        if accumulated_entropy:
            region_size = len(data) - region_start
            avg_ent = sum(accumulated_entropy) / len(accumulated_entropy)
            merged.append(EntropyRegion(
                offset=region_start,
                size=region_size,
                entropy=avg_ent,
                classification=current_class,
                is_compressed=c_comp,
                is_encrypted=c_enc,
                is_code=c_code,
                is_padding=c_pad,
            ))

        return merged

    def detect_anomalies(self, profile: EntropyProfile) -> List[FirmwareFinding]:
        """Detect entropy-based anomalies (sudden jumps, suspicious regions)."""
        findings: List[FirmwareFinding] = []

        for region in profile.regions:
            if region.is_encrypted and region.size > 1024:
                findings.append(FirmwareFinding(
                    category=FindingCategory.ENTROPY_ANOMALY,
                    severity=Severity.MEDIUM,
                    title=f"High-entropy region detected (possible encryption)",
                    description=(
                        f"Region at offset 0x{region.offset:08x} "
                        f"(size={region.size} bytes) has entropy {region.entropy:.4f}, "
                        f"indicating encrypted or random data."
                    ),
                    offset=region.offset,
                    size=region.size,
                    evidence=f"entropy={region.entropy:.4f}",
                    confidence=min(0.95, (region.entropy - 7.5) * 2.0),
                    metadata={"entropy": region.entropy, "classification": region.classification},
                ))

            # Detect suspiciously uniform entropy (could be XOR-encrypted)
            if 6.0 <= region.entropy <= 7.5 and region.size > 4096:
                findings.append(FirmwareFinding(
                    category=FindingCategory.ENTROPY_ANOMALY,
                    severity=Severity.LOW,
                    title=f"Uniformly high entropy region (possible XOR/simple cipher)",
                    description=(
                        f"Region at offset 0x{region.offset:08x} "
                        f"(size={region.size} bytes) has uniform entropy {region.entropy:.4f}. "
                        f"Could indicate simple XOR or substitution cipher."
                    ),
                    offset=region.offset,
                    size=region.size,
                    evidence=f"entropy={region.entropy:.4f}",
                    confidence=0.4,
                    metadata={"entropy": region.entropy},
                ))

        # Check for entropy transitions (jumps > 3.0 bits between regions)
        for i in range(1, len(profile.regions)):
            prev = profile.regions[i - 1]
            curr = profile.regions[i]
            delta = abs(curr.entropy - prev.entropy)
            if delta > 3.0:
                findings.append(FirmwareFinding(
                    category=FindingCategory.ENTROPY_ANOMALY,
                    severity=Severity.INFO,
                    title=f"Sharp entropy transition detected",
                    description=(
                        f"Entropy jumps from {prev.entropy:.4f} to {curr.entropy:.4f} "
                        f"(delta={delta:.4f}) at offset 0x{curr.offset:08x}. "
                        f"May indicate boundary between firmware sections."
                    ),
                    offset=curr.offset,
                    size=0,
                    evidence=f"delta={delta:.4f}",
                    confidence=0.7,
                    metadata={"prev_entropy": prev.entropy, "curr_entropy": curr.entropy},
                ))

        return findings

    def ascii_histogram(
        self,
        profile: EntropyProfile,
        width: int = 60,
        height: int = 20,
        show_regions: bool = True,
    ) -> str:
        """
        Generate an ASCII art histogram of entropy distribution.

        Args:
            profile: EntropyProfile from analysis.
            width: Character width of the histogram.
            height: Character height of the histogram.
            show_regions: Whether to annotate region boundaries.

        Returns:
            Multi-line ASCII string with entropy visualization.
        """
        if not profile.histogram_data:
            return "[No entropy data available]"

        data = profile.histogram_data
        max_entropy = 8.0
        num_points = len(data)

        # Resample data to fit width
        if num_points > width:
            step = num_points / width
            resampled: List[float] = []
            for i in range(width):
                start_idx = int(i * step)
                end_idx = int((i + 1) * step)
                chunk = data[start_idx:end_idx]
                resampled.append(sum(chunk) / len(chunk) if chunk else 0.0)
        else:
            resampled = list(data)
            while len(resampled) < width:
                resampled.append(0.0)

        lines: List[str] = []
        lines.append(f"  Entropy Distribution ({profile.total_size:,} bytes, global={profile.global_entropy:.4f})")
        lines.append(f"  {'=' * (width + 6)}")

        # Build rows from top (8.0) to bottom (0.0)
        for row in range(height, 0, -1):
            threshold = (row / height) * max_entropy
            label = f"{threshold:4.1f} |"
            bar_chars: List[str] = []
            for val in resampled[:width]:
                if val >= threshold:
                    # Graduated fill characters
                    if val >= 7.9:
                        bar_chars.append("#")
                    elif val >= 7.0:
                        bar_chars.append("@")
                    elif val >= 5.0:
                        bar_chars.append("*")
                    elif val >= 3.0:
                        bar_chars.append("+")
                    elif val >= 1.0:
                        bar_chars.append(".")
                    else:
                        bar_chars.append(":")
                else:
                    bar_chars.append(" ")
            lines.append(f"  {label}{''.join(bar_chars)}|")

        # X-axis
        lines.append(f"  {'':>5}+{'-' * width}+")

        # Offset labels
        total = profile.total_size
        quarter = total // 4
        offset_line = f"  {'':>5} 0x{0:08x}"
        mid_pos = width // 2
        offset_line += " " * max(1, mid_pos - 14) + f"0x{total // 2:08x}"
        offset_line += " " * max(1, width - len(offset_line) + 2) + f"0x{total:08x}"
        lines.append(offset_line)

        # Legend
        lines.append("")
        lines.append("  Legend: # encrypted (>7.9) | @ compressed (>7.0) | * code (>5.0) | + data (>3.0) | . low (<3.0)")

        # Region summary
        if show_regions and profile.regions:
            lines.append("")
            lines.append("  Region Summary:")
            lines.append(f"  {'Offset':>12} {'Size':>10} {'Entropy':>8} {'Type':<24}")
            lines.append(f"  {'-' * 12} {'-' * 10} {'-' * 8} {'-' * 24}")
            for r in profile.regions[:30]:  # Cap at 30 regions for display
                lines.append(
                    f"  0x{r.offset:08x} {r.size:>10,} {r.entropy:>8.4f} {r.classification:<24}"
                )
            if len(profile.regions) > 30:
                lines.append(f"  ... and {len(profile.regions) - 30} more regions")

        # Statistics
        lines.append("")
        lines.append(f"  Statistics:")
        lines.append(f"    Compressed: {profile.compressed_pct:.1f}%  |  Encrypted: {profile.encrypted_pct:.1f}%  |  Code: {profile.code_pct:.1f}%  |  Padding: {profile.padding_pct:.1f}%")

        return "\n".join(lines)

    def byte_frequency_histogram(self, data: bytes) -> str:
        """Generate ASCII histogram of byte value frequency distribution."""
        if not data:
            return "[No data]"

        counts = Counter(data)
        max_count = max(counts.values()) if counts else 1
        width = 40
        lines: List[str] = []
        lines.append("  Byte Frequency Distribution:")
        lines.append(f"  {'Byte':>6} {'Count':>8} {'Bar':<{width + 2}}")

        # Show top 16 most frequent bytes and bottom 4
        sorted_bytes = sorted(counts.items(), key=lambda x: -x[1])
        display_bytes = sorted_bytes[:16]
        if len(sorted_bytes) > 20:
            display_bytes.append((-1, 0))  # separator
            display_bytes.extend(sorted_bytes[-4:])

        for byte_val, count in display_bytes:
            if byte_val == -1:
                lines.append(f"  {'...':>6} {'...':>8}")
                continue
            bar_len = int((count / max_count) * width)
            bar = "|" + "=" * bar_len
            printable = chr(byte_val) if 32 <= byte_val < 127 else "."
            lines.append(f"  0x{byte_val:02x} {printable} {count:>8} {bar}")

        unique = len(counts)
        lines.append(f"\n  Unique bytes: {unique}/256 ({unique / 256 * 100:.1f}%)")
        return "\n".join(lines)


# ════════════════════════════════════════════════════════════════════════════════
# FILESYSTEM EXTRACTOR
# ════════════════════════════════════════════════════════════════════════════════

class FilesystemExtractor:
    """
    Filesystem detection and extraction engine for firmware images.

    Scans binary data for known filesystem magic bytes (squashfs, cramfs,
    jffs2, ubifs, ext4, romfs, cpio) and parses headers to extract file
    listings.

    Usage:
        extractor = FilesystemExtractor()
        filesystems = extractor.scan(firmware_data)
        for fs in filesystems:
            print(f"Found {fs.fs_type.name} at 0x{fs.offset:08x}")
    """

    # Interesting files for security analysis
    INTERESTING_PATTERNS: List[str] = [
        "etc/passwd", "etc/shadow", "etc/hosts",
        "etc/ssl/", "etc/pki/", "etc/ssh/",
        "etc/config", "etc/default/", "etc/init.d/",
        ".pem", ".key", ".crt", ".cer", ".p12", ".pfx",
        ".conf", ".cfg", ".ini", ".json", ".xml", ".yaml", ".yml",
        "id_rsa", "id_dsa", "id_ecdsa", "authorized_keys",
        "htpasswd", "htaccess",
        "wp-config", "database.yml", "settings.py",
        "Dockerfile", "docker-compose",
        ".sh", ".bash", ".cgi", ".php", ".asp", ".py",
        "busybox", "dropbear", "telnetd", "httpd",
        "libcrypto", "libssl", "libc.so",
        "/dev/", "/proc/", "/tmp/",
    ]

    # Files that commonly contain credentials
    CREDENTIAL_FILES: List[str] = [
        "etc/passwd", "etc/shadow", "etc/group",
        "etc/config/", "etc/default/", "etc/ppp/",
        ".htpasswd", "htpasswd", "shadow",
        "nvram", "boardData", "art",
    ]

    def __init__(self, scan_step: int = 4, max_fs_size: int = 256 * 1024 * 1024) -> None:
        self._lock = threading.RLock()
        self._scan_step = max(1, scan_step)
        self._max_fs_size = max_fs_size
        logger.info("FilesystemExtractor initialized (step=%d)", self._scan_step)

    def scan(self, data: bytes) -> List[FilesystemInfo]:
        """
        Scan firmware data for all recognizable filesystem signatures.

        Args:
            data: Raw firmware binary data.

        Returns:
            List of FilesystemInfo objects for each found filesystem.
        """
        with self._lock:
            start_time = time.time()
            found: List[FilesystemInfo] = []
            data_len = len(data)

            for fs_type, magic_list in _FILESYSTEM_MAGIC.items():
                for magic_bytes, header_offset in magic_list:
                    # Scan through the firmware looking for magic bytes
                    search_offset = 0
                    while search_offset < data_len - len(magic_bytes):
                        pos = data.find(magic_bytes, search_offset)
                        if pos == -1:
                            break

                        # Check alignment (most FS headers are 4-byte aligned)
                        actual_fs_offset = pos - header_offset
                        if actual_fs_offset < 0:
                            search_offset = pos + self._scan_step
                            continue

                        # Parse this filesystem
                        fs_info = self._parse_filesystem(data, actual_fs_offset, fs_type, magic_bytes)
                        if fs_info is not None:
                            # Check for overlap with existing found filesystems
                            is_overlap = False
                            for existing in found:
                                if (actual_fs_offset >= existing.offset and
                                        actual_fs_offset < existing.offset + existing.size):
                                    is_overlap = True
                                    break
                            if not is_overlap:
                                found.append(fs_info)

                        search_offset = pos + self._scan_step

            elapsed = time.time() - start_time
            logger.info(
                "Filesystem scan complete: found %d filesystems in %.3fs",
                len(found), elapsed,
            )
            return found

    def _parse_filesystem(
        self, data: bytes, offset: int, fs_type: FilesystemType, magic: bytes
    ) -> Optional[FilesystemInfo]:
        """Parse filesystem header and extract metadata."""
        try:
            if fs_type == FilesystemType.SQUASHFS:
                return self._parse_squashfs(data, offset, magic)
            elif fs_type == FilesystemType.CRAMFS:
                return self._parse_cramfs(data, offset, magic)
            elif fs_type == FilesystemType.JFFS2:
                return self._parse_jffs2(data, offset, magic)
            elif fs_type == FilesystemType.UBIFS:
                return self._parse_ubifs(data, offset, magic)
            elif fs_type == FilesystemType.EXT4:
                return self._parse_ext4(data, offset, magic)
            elif fs_type == FilesystemType.ROMFS:
                return self._parse_romfs(data, offset, magic)
            elif fs_type == FilesystemType.CPIO:
                return self._parse_cpio(data, offset, magic)
            else:
                return FilesystemInfo(
                    fs_type=fs_type, offset=offset, magic_bytes=magic,
                )
        except Exception as exc:
            logger.debug("Failed to parse %s at offset 0x%08x: %s", fs_type.name, offset, exc)
            return None

    def _parse_squashfs(self, data: bytes, offset: int, magic: bytes) -> Optional[FilesystemInfo]:
        """Parse SquashFS superblock."""
        if offset + 96 > len(data):
            return None

        # Determine endianness from magic
        is_le = magic in (b"hsqs", b"shsq", b"hsqt")
        endian = "<" if is_le else ">"

        try:
            # SquashFS superblock structure (simplified)
            # offset 0: magic (4)
            # offset 4: inode_count (4)
            # offset 8: modification_time (4)
            # offset 12: block_size (4)
            # offset 16: fragment_count (4)
            # offset 20: compression_id (2)
            # offset 22: block_log (2)
            # offset 24: flags (2)
            # offset 26: id_count (2)
            # offset 28: version_major (2)
            # offset 30: version_minor (2)
            # offset 32-39: root_inode (8)
            # offset 40-47: bytes_used (8)

            inode_count = struct.unpack_from(f"{endian}I", data, offset + 4)[0]
            block_size = struct.unpack_from(f"{endian}I", data, offset + 12)[0]
            compression_id = struct.unpack_from(f"{endian}H", data, offset + 20)[0]
            version_major = struct.unpack_from(f"{endian}H", data, offset + 28)[0]
            version_minor = struct.unpack_from(f"{endian}H", data, offset + 30)[0]
            bytes_used = struct.unpack_from(f"{endian}Q", data, offset + 40)[0]

            # Sanity checks
            if inode_count == 0 or inode_count > 1000000:
                return None
            if block_size == 0 or block_size > 4 * 1024 * 1024:
                return None
            if bytes_used > self._max_fs_size or bytes_used == 0:
                return None

            compression_map = {
                1: "gzip", 2: "lzma", 3: "lzo", 4: "xz", 5: "lz4", 6: "zstd",
            }
            compression = compression_map.get(compression_id, f"unknown({compression_id})")

            entries = self._extract_squashfs_filenames(data, offset, bytes_used, endian)
            interesting = self._find_interesting_files(entries)

            return FilesystemInfo(
                fs_type=FilesystemType.SQUASHFS,
                offset=offset,
                size=int(bytes_used),
                magic_bytes=magic,
                block_size=block_size,
                compression=compression,
                endianness=Endianness.LITTLE if is_le else Endianness.BIG,
                version=f"{version_major}.{version_minor}",
                entries=entries,
                total_files=sum(1 for e in entries if e.entry_type == "file"),
                total_dirs=sum(1 for e in entries if e.entry_type == "directory"),
                interesting_files=interesting,
            )
        except struct.error:
            return None

    def _extract_squashfs_filenames(
        self, data: bytes, fs_offset: int, fs_size: int, endian: str
    ) -> List[FilesystemEntry]:
        """
        Extract visible filenames from SquashFS data by scanning for string patterns.
        This is a heuristic approach without full decompression.
        """
        entries: List[FilesystemEntry] = []
        fs_data = data[fs_offset:fs_offset + min(int(fs_size), len(data) - fs_offset)]

        # Scan for path-like strings in the filesystem region
        path_pattern = re.compile(
            rb'((?:/[a-zA-Z0-9_.\-]+)+(?:\.[a-zA-Z0-9]{1,8})?)',
        )
        seen_paths: Set[str] = set()

        for match in path_pattern.finditer(fs_data):
            path_str = match.group(1).decode("ascii", errors="ignore")
            if path_str in seen_paths:
                continue
            seen_paths.add(path_str)

            # Determine entry type heuristically
            has_ext = "." in path_str.split("/")[-1]
            entry_type = "file" if has_ext else "directory"

            # Check for executable indicators
            is_exec = any(path_str.endswith(ext) for ext in [
                ".sh", ".cgi", ".py", ".pl", ".rb", ".elf", "",
            ]) or "/bin/" in path_str or "/sbin/" in path_str

            # Check for setuid-typical paths
            is_setuid = any(s in path_str for s in [
                "/bin/su", "/bin/sudo", "/bin/passwd", "/usr/bin/sudo",
            ])

            entry = FilesystemEntry(
                path=path_str,
                offset=fs_offset + match.start(),
                entry_type=entry_type,
                is_executable=is_exec,
                is_setuid=is_setuid,
            )
            entries.append(entry)

            if len(entries) >= 5000:
                break

        return entries

    def _parse_cramfs(self, data: bytes, offset: int, magic: bytes) -> Optional[FilesystemInfo]:
        """Parse CramFS superblock."""
        if offset + 76 > len(data):
            return None

        is_le = magic == b"\x45\x3d\xcd\x28"
        endian = "<" if is_le else ">"

        try:
            # CramFS superblock
            fs_size = struct.unpack_from(f"{endian}I", data, offset + 4)[0]
            flags = struct.unpack_from(f"{endian}I", data, offset + 8)[0]
            # future field at offset 12
            # signature at offset 16: "Compressed ROMFS"
            sig = data[offset + 16:offset + 32]

            if b"Compressed" not in sig and fs_size > self._max_fs_size:
                return None

            if fs_size == 0 or fs_size > self._max_fs_size:
                fs_size = min(len(data) - offset, self._max_fs_size)

            file_count = (flags >> 8) & 0xFFFF  # Rough estimate from flags

            entries = self._scan_generic_paths(data, offset, min(fs_size, len(data) - offset))
            interesting = self._find_interesting_files(entries)

            return FilesystemInfo(
                fs_type=FilesystemType.CRAMFS,
                offset=offset,
                size=fs_size,
                magic_bytes=magic,
                compression="zlib",
                endianness=Endianness.LITTLE if is_le else Endianness.BIG,
                entries=entries,
                total_files=sum(1 for e in entries if e.entry_type == "file"),
                total_dirs=sum(1 for e in entries if e.entry_type == "directory"),
                interesting_files=interesting,
            )
        except struct.error:
            return None

    def _parse_jffs2(self, data: bytes, offset: int, magic: bytes) -> Optional[FilesystemInfo]:
        """Parse JFFS2 filesystem nodes."""
        is_le = magic == b"\x85\x19"
        endian = "<" if is_le else ">"

        # JFFS2 is node-based, scan for directory entry nodes
        entries: List[FilesystemEntry] = []
        scan_end = min(offset + self._max_fs_size, len(data))
        pos = offset
        fs_size = 0
        dirent_magic = struct.pack(f"{endian}H", 0xE001)  # JFFS2_NODETYPE_DIRENT

        node_count = 0
        while pos < scan_end - 12 and node_count < 50000:
            # Check for JFFS2 node magic
            node_magic = data[pos:pos + 2]
            if node_magic != magic:
                pos += 4
                continue

            try:
                node_type = struct.unpack_from(f"{endian}H", data, pos + 2)[0]
                total_len = struct.unpack_from(f"{endian}I", data, pos + 4)[0]

                if total_len == 0 or total_len > 1024 * 1024:
                    pos += 4
                    continue

                # Directory entry node
                if node_type == 0xE001:
                    if pos + 40 < scan_end:
                        name_len = struct.unpack_from(f"{endian}B", data, pos + 37)[0]
                        if 0 < name_len < 256 and pos + 40 + name_len <= scan_end:
                            name = data[pos + 40:pos + 40 + name_len]
                            try:
                                name_str = name.decode("utf-8", errors="ignore").strip("\x00")
                                if name_str and all(c in string.printable for c in name_str):
                                    entry_type_byte = struct.unpack_from("B", data, pos + 38)[0]
                                    e_type = "directory" if entry_type_byte == 4 else "file"
                                    entries.append(FilesystemEntry(
                                        path=name_str,
                                        offset=pos,
                                        entry_type=e_type,
                                    ))
                            except (UnicodeDecodeError, ValueError):
                                pass

                fs_size = (pos + total_len) - offset
                pos += max(4, (total_len + 3) & ~3)  # 4-byte aligned
                node_count += 1
            except struct.error:
                pos += 4

        if not entries:
            return None

        interesting = self._find_interesting_files(entries)

        return FilesystemInfo(
            fs_type=FilesystemType.JFFS2,
            offset=offset,
            size=max(fs_size, 1),
            magic_bytes=magic,
            compression="zlib",
            endianness=Endianness.LITTLE if is_le else Endianness.BIG,
            entries=entries,
            total_files=sum(1 for e in entries if e.entry_type == "file"),
            total_dirs=sum(1 for e in entries if e.entry_type == "directory"),
            interesting_files=interesting,
        )

    def _parse_ubifs(self, data: bytes, offset: int, magic: bytes) -> Optional[FilesystemInfo]:
        """Parse UBI/UBIFS header."""
        if offset + 64 > len(data):
            return None

        try:
            if magic == b"UBI#":
                # UBI superblock header
                version = struct.unpack_from(">B", data, offset + 4)[0]
                if version > 10:
                    return None

                entries = self._scan_generic_paths(data, offset, min(self._max_fs_size, len(data) - offset))
                interesting = self._find_interesting_files(entries)

                return FilesystemInfo(
                    fs_type=FilesystemType.UBIFS,
                    offset=offset,
                    size=min(self._max_fs_size, len(data) - offset),
                    magic_bytes=magic,
                    endianness=Endianness.BIG,
                    version=str(version),
                    entries=entries,
                    total_files=len([e for e in entries if e.entry_type == "file"]),
                    total_dirs=len([e for e in entries if e.entry_type == "directory"]),
                    interesting_files=interesting,
                )
            else:
                # UBIFS node
                entries = self._scan_generic_paths(data, offset, min(self._max_fs_size, len(data) - offset))
                interesting = self._find_interesting_files(entries)

                return FilesystemInfo(
                    fs_type=FilesystemType.UBIFS,
                    offset=offset,
                    size=min(self._max_fs_size, len(data) - offset),
                    magic_bytes=magic,
                    entries=entries,
                    total_files=len([e for e in entries if e.entry_type == "file"]),
                    total_dirs=len([e for e in entries if e.entry_type == "directory"]),
                    interesting_files=interesting,
                )
        except struct.error:
            return None

    def _parse_ext4(self, data: bytes, offset: int, magic: bytes) -> Optional[FilesystemInfo]:
        """Parse EXT4 superblock (magic at superblock_offset + 0x38)."""
        # EXT superblock starts 1024 bytes into the partition
        sb_offset = offset - 0x38  # Adjust for the magic position within superblock
        if sb_offset < 0:
            sb_offset = offset
        if sb_offset + 1024 > len(data):
            return None

        try:
            # Superblock is at byte 1024 of the filesystem, or at offset directly
            base = sb_offset
            inode_count = struct.unpack_from("<I", data, base + 0x00)[0]
            block_count = struct.unpack_from("<I", data, base + 0x04)[0]
            block_size_log = struct.unpack_from("<I", data, base + 0x18)[0]
            block_size = 1024 << block_size_log

            if inode_count == 0 or block_count == 0:
                return None
            if block_size > 65536 or block_size < 512:
                return None

            fs_size = block_count * block_size
            if fs_size > self._max_fs_size:
                fs_size = self._max_fs_size

            # Read volume label (at offset 0x78 in superblock, 16 bytes)
            label_raw = data[base + 0x78:base + 0x78 + 16]
            label = label_raw.split(b"\x00")[0].decode("ascii", errors="ignore")

            entries = self._scan_generic_paths(data, sb_offset, min(fs_size, len(data) - sb_offset))
            interesting = self._find_interesting_files(entries)

            return FilesystemInfo(
                fs_type=FilesystemType.EXT4,
                offset=sb_offset,
                size=fs_size,
                magic_bytes=magic,
                block_size=block_size,
                endianness=Endianness.LITTLE,
                version=label if label else "ext4",
                entries=entries,
                total_files=sum(1 for e in entries if e.entry_type == "file"),
                total_dirs=sum(1 for e in entries if e.entry_type == "directory"),
                interesting_files=interesting,
            )
        except struct.error:
            return None

    def _parse_romfs(self, data: bytes, offset: int, magic: bytes) -> Optional[FilesystemInfo]:
        """Parse RomFS header."""
        if offset + 32 > len(data):
            return None

        try:
            fs_size = struct.unpack_from(">I", data, offset + 8)[0]
            if fs_size == 0 or fs_size > self._max_fs_size:
                return None

            # Volume name follows at offset 16, null-terminated, 16-byte aligned
            vol_end = data.index(b"\x00", offset + 16)
            vol_name = data[offset + 16:vol_end].decode("ascii", errors="ignore")

            entries = self._scan_generic_paths(data, offset, min(fs_size, len(data) - offset))
            interesting = self._find_interesting_files(entries)

            return FilesystemInfo(
                fs_type=FilesystemType.ROMFS,
                offset=offset,
                size=fs_size,
                magic_bytes=magic,
                endianness=Endianness.BIG,
                version=vol_name,
                entries=entries,
                total_files=sum(1 for e in entries if e.entry_type == "file"),
                total_dirs=sum(1 for e in entries if e.entry_type == "directory"),
                interesting_files=interesting,
            )
        except (struct.error, ValueError):
            return None

    def _parse_cpio(self, data: bytes, offset: int, magic: bytes) -> Optional[FilesystemInfo]:
        """Parse CPIO archive (newc format)."""
        entries: List[FilesystemEntry] = []
        pos = offset
        end = min(offset + self._max_fs_size, len(data))

        is_ascii_format = magic in (b"070701", b"070702")

        if is_ascii_format:
            while pos < end - 110:
                header_magic = data[pos:pos + 6]
                if header_magic not in (b"070701", b"070702"):
                    break

                try:
                    namesize = int(data[pos + 94:pos + 102], 16)
                    filesize = int(data[pos + 54:pos + 62], 16)
                    mode = int(data[pos + 14:pos + 22], 16)

                    if namesize <= 0 or namesize > 4096:
                        break

                    name_start = pos + 110
                    name_end = name_start + namesize - 1  # -1 for null
                    name = data[name_start:name_end].decode("ascii", errors="ignore")

                    if name == "TRAILER!!!":
                        break

                    is_dir = (mode & 0o170000) == 0o040000
                    is_exec = bool(mode & 0o111)
                    is_setuid = bool(mode & 0o4000)
                    is_setgid = bool(mode & 0o2000)
                    is_symlink = (mode & 0o170000) == 0o120000

                    perm_str = oct(mode & 0o7777)

                    entries.append(FilesystemEntry(
                        path=name,
                        size=filesize,
                        offset=pos,
                        entry_type="directory" if is_dir else "symlink" if is_symlink else "file",
                        permissions=perm_str,
                        is_executable=is_exec,
                        is_setuid=is_setuid,
                        is_setgid=is_setgid,
                        is_symlink=is_symlink,
                    ))

                    # Advance to next entry (header + name padded to 4-byte, data padded to 4-byte)
                    header_plus_name = 110 + namesize
                    header_plus_name = (header_plus_name + 3) & ~3
                    data_padded = (filesize + 3) & ~3
                    pos += header_plus_name + data_padded
                except (ValueError, IndexError):
                    break

                if len(entries) >= 10000:
                    break
        else:
            # Binary CPIO — just do generic path scan
            entries = self._scan_generic_paths(data, offset, min(self._max_fs_size, len(data) - offset))

        if not entries:
            return None

        interesting = self._find_interesting_files(entries)
        fs_size = max(1, (pos - offset) if pos > offset else len(data) - offset)

        return FilesystemInfo(
            fs_type=FilesystemType.CPIO,
            offset=offset,
            size=fs_size,
            magic_bytes=magic,
            entries=entries,
            total_files=sum(1 for e in entries if e.entry_type == "file"),
            total_dirs=sum(1 for e in entries if e.entry_type == "directory"),
            interesting_files=interesting,
        )

    def _scan_generic_paths(
        self, data: bytes, offset: int, size: int
    ) -> List[FilesystemEntry]:
        """Generic path extraction by scanning for filesystem-like strings."""
        entries: List[FilesystemEntry] = []
        region = data[offset:offset + min(size, len(data) - offset)]

        # Look for Unix-style paths
        path_re = re.compile(
            rb'(/(?:bin|sbin|usr|etc|var|lib|opt|home|root|tmp|dev|proc|sys|mnt|boot)'
            rb'(?:/[a-zA-Z0-9_.\-]{1,64}){0,8})',
        )
        seen: Set[str] = set()

        for match in path_re.finditer(region):
            path_str = match.group(1).decode("ascii", errors="ignore")
            if path_str in seen:
                continue
            seen.add(path_str)

            has_ext = "." in path_str.rsplit("/", 1)[-1]
            is_exec = "/bin/" in path_str or "/sbin/" in path_str
            entries.append(FilesystemEntry(
                path=path_str,
                offset=offset + match.start(),
                entry_type="file" if has_ext else "directory",
                is_executable=is_exec,
            ))
            if len(entries) >= 5000:
                break

        return entries

    def _find_interesting_files(self, entries: List[FilesystemEntry]) -> List[str]:
        """Identify security-relevant files from the file listing."""
        interesting: List[str] = []

        for entry in entries:
            path_lower = entry.path.lower()
            for pattern in self.INTERESTING_PATTERNS:
                if pattern in path_lower:
                    interesting.append(entry.path)
                    break

            # Setuid/setgid are always interesting
            if entry.is_setuid or entry.is_setgid:
                if entry.path not in interesting:
                    interesting.append(entry.path)

        return interesting[:500]  # Cap

    def generate_findings(self, filesystems: List[FilesystemInfo]) -> List[FirmwareFinding]:
        """Generate security findings from detected filesystems."""
        findings: List[FirmwareFinding] = []

        for fs_info in filesystems:
            # Finding: filesystem detected
            findings.append(FirmwareFinding(
                category=FindingCategory.FILESYSTEM_DETECTED,
                severity=Severity.INFO,
                title=f"{fs_info.fs_type.name} filesystem detected",
                description=(
                    f"Found {fs_info.fs_type.name} filesystem at offset 0x{fs_info.offset:08x}, "
                    f"size={fs_info.size:,} bytes, compression={fs_info.compression or 'none'}, "
                    f"files={fs_info.total_files}, dirs={fs_info.total_dirs}"
                ),
                offset=fs_info.offset,
                size=fs_info.size,
                confidence=0.9,
                metadata={"fs_type": fs_info.fs_type.name, "compression": fs_info.compression},
            ))

            # Check for sensitive files
            for path in fs_info.interesting_files:
                path_lower = path.lower()
                severity = Severity.INFO
                category = FindingCategory.SENSITIVE_STRING

                if any(s in path_lower for s in ["shadow", "passwd", "htpasswd"]):
                    severity = Severity.HIGH
                    category = FindingCategory.HARDCODED_CREDENTIAL
                elif any(s in path_lower for s in [".key", "id_rsa", "id_dsa", "id_ecdsa", ".pem"]):
                    severity = Severity.HIGH
                    category = FindingCategory.CRYPTO_KEY_EXPOSED
                elif any(s in path_lower for s in [".conf", ".cfg", ".ini"]):
                    severity = Severity.MEDIUM
                elif "telnetd" in path_lower:
                    severity = Severity.HIGH
                    category = FindingCategory.INSECURE_PROTOCOL

                findings.append(FirmwareFinding(
                    category=category,
                    severity=severity,
                    title=f"Interesting file found: {path}",
                    description=f"Security-relevant file detected in {fs_info.fs_type.name} at 0x{fs_info.offset:08x}",
                    offset=fs_info.offset,
                    evidence=path,
                    confidence=0.85,
                    metadata={"filesystem": fs_info.fs_type.name, "file_path": path},
                ))

            # Check for setuid binaries
            for entry in fs_info.entries:
                if entry.is_setuid:
                    findings.append(FirmwareFinding(
                        category=FindingCategory.VULNERABLE_FUNCTION,
                        severity=Severity.MEDIUM,
                        title=f"Setuid binary found: {entry.path}",
                        description=(
                            f"Setuid binary at {entry.path} could be a privilege escalation vector."
                        ),
                        offset=entry.offset,
                        evidence=entry.path,
                        confidence=0.8,
                        remediation="Review setuid binary for vulnerabilities. Remove setuid bit if not required.",
                    ))

        return findings


# ════════════════════════════════════════════════════════════════════════════════
# SIREN FIRMWARE ANALYZER — ORCHESTRATOR
# ════════════════════════════════════════════════════════════════════════════════


class SirenFirmwareAnalyzer:
    """
    Orchestrates complete firmware reverse-engineering & security analysis.

    Coordinates EntropyAnalyzer and FilesystemExtractor to provide a unified
    interface for fully automated firmware assessments.

    Usage::

        analyzer = SirenFirmwareAnalyzer()

        # Full automated analysis
        report = analyzer.full_analysis(firmware_data, name="router_v2.bin")

        # Individual operations
        profile = analyzer.analyze_entropy(data)
        filesystems = analyzer.extract_filesystems(data)
        findings = analyzer.scan_for_credentials(data)

        # Report
        report = analyzer.generate_report()
    """

    def __init__(self, timeout: float = 60.0) -> None:
        self._lock = threading.RLock()
        self._timeout = timeout

        # Sub-engines
        self._entropy_analyzer = EntropyAnalyzer()
        self._fs_extractor = FilesystemExtractor()

        # State
        self._findings: List[FirmwareFinding] = []
        self._crypto_findings: List[CryptoFinding] = []
        self._credential_findings: List[CredentialFinding] = []
        self._vuln_matches: List[VulnMatch] = []
        self._filesystems: List[FilesystemInfo] = []
        self._entropy_profile: Optional[EntropyProfile] = None
        self._metadata: Optional[FirmwareMetadata] = None
        self._scan_start: float = 0.0
        self._scan_end: float = 0.0
        self._scan_phases: List[Dict[str, Any]] = []

        logger.info("SirenFirmwareAnalyzer initialized (timeout=%.1fs)", timeout)

    # ── Phase Methods ───────────────────────────────────────────────────────

    def analyze_entropy(self, data: bytes) -> EntropyProfile:
        """Phase 1: Run Shannon entropy analysis with sliding window."""
        with self._lock:
            phase_start = time.time()
            profile = self._entropy_analyzer.analyze(data)
            self._entropy_profile = profile

            # Generate findings from entropy anomalies
            for region in profile.regions:
                if region.entropy > 7.5:
                    self._findings.append(FirmwareFinding(
                        category=FindingCategory.ENTROPY_ANOMALY,
                        severity=Severity.MEDIUM,
                        title=f"High entropy region at 0x{region.offset:08x}",
                        description=(
                            f"Region of {region.size:,} bytes with entropy {region.entropy:.4f} "
                            f"(likely encrypted/compressed data)"
                        ),
                        offset=region.offset,
                        size=region.size,
                        confidence=min(1.0, region.entropy / 8.0),
                        metadata={"entropy": region.entropy, "classification": region.classification},
                    ))
                elif region.entropy < 0.5 and region.size > 1024:
                    self._findings.append(FirmwareFinding(
                        category=FindingCategory.ENTROPY_ANOMALY,
                        severity=Severity.LOW,
                        title=f"Low entropy region at 0x{region.offset:08x}",
                        description=(
                            f"Region of {region.size:,} bytes with entropy {region.entropy:.4f} "
                            f"(likely padding, empty space, or repeated data)"
                        ),
                        offset=region.offset,
                        size=region.size,
                        confidence=0.7,
                        metadata={"entropy": region.entropy, "classification": region.classification},
                    ))

            self._scan_phases.append({
                "phase": "entropy_analysis",
                "duration": time.time() - phase_start,
                "regions_found": len(profile.regions),
                "overall_entropy": profile.overall_entropy,
            })
            logger.info("Entropy analysis complete: %.4f overall, %d regions",
                        profile.overall_entropy, len(profile.regions))
            return profile

    def extract_filesystems(self, data: bytes) -> List[FilesystemInfo]:
        """Phase 2: Detect and extract embedded filesystems."""
        with self._lock:
            phase_start = time.time()
            filesystems = self._fs_extractor.detect_filesystems(data)
            self._filesystems = filesystems

            # Generate findings from filesystem detection
            fs_findings = self._fs_extractor.generate_findings(filesystems)
            self._findings.extend(fs_findings)

            self._scan_phases.append({
                "phase": "filesystem_extraction",
                "duration": time.time() - phase_start,
                "filesystems_found": len(filesystems),
                "total_files": sum(fs.total_files for fs in filesystems),
            })
            logger.info("Filesystem extraction: %d filesystems detected", len(filesystems))
            return filesystems

    def scan_strings(self, data: bytes) -> List[ExtractedString]:
        """Phase 3: Extract and classify security-relevant strings."""
        with self._lock:
            phase_start = time.time()
            strings = self._entropy_analyzer.extract_strings(data)

            # Classify strings into findings
            for s in strings:
                if s.category in ("api_key", "private_key", "jwt_token", "aws_key"):
                    self._findings.append(FirmwareFinding(
                        category=FindingCategory.CRYPTO_KEY_EXPOSED,
                        severity=Severity.CRITICAL,
                        title=f"Exposed {s.category} in firmware",
                        description=f"Found {s.category} at offset 0x{s.offset:08x}",
                        offset=s.offset,
                        evidence=s.value[:80] + ("..." if len(s.value) > 80 else ""),
                        confidence=s.confidence,
                        remediation="Remove hardcoded keys. Use secure key storage (TPM, HSM, KMS).",
                    ))
                elif s.category in ("password", "credential"):
                    self._credential_findings.append(CredentialFinding(
                        cred_type=s.category,
                        value=s.value[:60],
                        context=s.context[:100] if s.context else "",
                        offset=s.offset,
                        severity=Severity.HIGH,
                        confidence=s.confidence,
                    ))
                elif s.category in ("ip_address", "url", "email"):
                    self._findings.append(FirmwareFinding(
                        category=FindingCategory.SENSITIVE_STRING,
                        severity=Severity.LOW,
                        title=f"Network artifact: {s.category}",
                        description=f"Found {s.category} string at offset 0x{s.offset:08x}",
                        offset=s.offset,
                        evidence=s.value[:120],
                        confidence=s.confidence,
                    ))

            self._scan_phases.append({
                "phase": "string_extraction",
                "duration": time.time() - phase_start,
                "strings_found": len(strings),
                "credentials_found": len(self._credential_findings),
            })
            logger.info("String scan: %d strings, %d credentials",
                        len(strings), len(self._credential_findings))
            return strings

    def scan_crypto(self, data: bytes) -> List[CryptoFinding]:
        """Phase 4: Detect cryptographic material and weaknesses."""
        with self._lock:
            phase_start = time.time()
            crypto_findings = self._entropy_analyzer.find_crypto_material(data)
            self._crypto_findings.extend(crypto_findings)

            for cf in crypto_findings:
                sev = Severity.MEDIUM
                if cf.weakness in (CryptoWeakness.HARDCODED_KEY, CryptoWeakness.HARDCODED_IV):
                    sev = Severity.CRITICAL
                elif cf.weakness == CryptoWeakness.WEAK_ALGORITHM:
                    sev = Severity.HIGH
                elif cf.weakness == CryptoWeakness.INSUFFICIENT_KEY_LENGTH:
                    sev = Severity.HIGH

                self._findings.append(FirmwareFinding(
                    category=FindingCategory.WEAK_CRYPTO,
                    severity=sev,
                    title=f"{cf.algorithm.name} — {cf.weakness.name}",
                    description=cf.description,
                    offset=cf.offset,
                    evidence=cf.evidence[:100] if cf.evidence else "",
                    confidence=cf.confidence,
                    remediation="Use AES-256-GCM with proper key management. Avoid hardcoded keys/IVs.",
                ))

            self._scan_phases.append({
                "phase": "crypto_scan",
                "duration": time.time() - phase_start,
                "crypto_findings": len(crypto_findings),
            })
            logger.info("Crypto scan: %d findings", len(crypto_findings))
            return crypto_findings

    def scan_vulnerabilities(self, data: bytes) -> List[VulnMatch]:
        """Phase 5: Pattern-match known vulnerability signatures."""
        with self._lock:
            phase_start = time.time()
            vuln_matches = self._entropy_analyzer.scan_vuln_patterns(data)
            self._vuln_matches.extend(vuln_matches)

            for vm in vuln_matches:
                self._findings.append(FirmwareFinding(
                    category=FindingCategory.CVE_PATTERN if vm.cve_id else FindingCategory.VULNERABLE_FUNCTION,
                    severity=vm.severity,
                    title=vm.title,
                    description=vm.description,
                    offset=vm.offset,
                    evidence=vm.evidence[:120] if vm.evidence else "",
                    confidence=vm.confidence,
                    remediation=vm.remediation,
                    references=[vm.cve_id] if vm.cve_id else [],
                ))

            self._scan_phases.append({
                "phase": "vuln_scan",
                "duration": time.time() - phase_start,
                "vuln_matches": len(vuln_matches),
            })
            logger.info("Vulnerability scan: %d matches", len(vuln_matches))
            return vuln_matches

    def compare_firmware(self, old_data: bytes, new_data: bytes) -> List[BinaryDelta]:
        """Phase 6 (optional): Compare two firmware versions for security regressions."""
        with self._lock:
            phase_start = time.time()
            deltas = self._entropy_analyzer.compare_binaries(old_data, new_data)

            for delta in deltas:
                if delta.classification in (ComparisonResult.REMOVED_SECURITY, ComparisonResult.ADDED_VULN):
                    sev = Severity.HIGH if delta.classification == ComparisonResult.ADDED_VULN else Severity.MEDIUM
                    cat = (FindingCategory.ADDED_VULNERABILITY
                           if delta.classification == ComparisonResult.ADDED_VULN
                           else FindingCategory.REMOVED_SECURITY)
                    self._findings.append(FirmwareFinding(
                        category=cat,
                        severity=sev,
                        title=f"Binary diff: {delta.classification.name}",
                        description=delta.description,
                        offset=delta.offset,
                        size=delta.size,
                        confidence=delta.confidence,
                    ))

            self._scan_phases.append({
                "phase": "firmware_comparison",
                "duration": time.time() - phase_start,
                "deltas_found": len(deltas),
            })
            logger.info("Firmware comparison: %d deltas", len(deltas))
            return deltas

    # ── Report Generation ───────────────────────────────────────────────────

    def generate_report(self, firmware_name: str = "", firmware_size: int = 0) -> FirmwareReport:
        """Generate a consolidated firmware analysis report."""
        with self._lock:
            all_findings = list(self._findings)

            critical = sum(1 for f in all_findings if f.severity == Severity.CRITICAL)
            high = sum(1 for f in all_findings if f.severity == Severity.HIGH)
            medium = sum(1 for f in all_findings if f.severity == Severity.MEDIUM)
            low = sum(1 for f in all_findings if f.severity == Severity.LOW)
            info = sum(1 for f in all_findings if f.severity == Severity.INFO)

            risk_score = min(100.0, critical * 25.0 + high * 15.0 + medium * 8.0 + low * 3.0 + info * 0.5)

            category_counts: Dict[str, int] = defaultdict(int)
            for f in all_findings:
                category_counts[f.category.name] += 1

            summary_parts = [
                f"Firmware analysis completed in {self._scan_end - self._scan_start:.1f}s.",
                f"Found {len(all_findings)} findings across {len(self._scan_phases)} phases.",
            ]
            if critical > 0:
                summary_parts.append(f"CRITICAL: {critical} findings require immediate remediation.")
            if high > 0:
                summary_parts.append(f"HIGH: {high} findings need priority attention.")

            report = FirmwareReport(
                firmware_name=firmware_name,
                firmware_size=firmware_size,
                firmware_hash_sha256=self._metadata.sha256 if self._metadata else "",
                firmware_hash_md5=self._metadata.md5 if self._metadata else "",
                entropy_profile=self._entropy_profile,
                filesystems=self._filesystems,
                findings=all_findings,
                crypto_findings=list(self._crypto_findings),
                credential_findings=list(self._credential_findings),
                vuln_matches=list(self._vuln_matches),
                analysis_time_seconds=self._scan_end - self._scan_start,
                summary={
                    "total_findings": len(all_findings),
                    "severity_breakdown": {"CRITICAL": critical, "HIGH": high, "MEDIUM": medium, "LOW": low, "INFO": info},
                    "category_breakdown": dict(category_counts),
                    "risk_score": round(risk_score, 1),
                    "risk_rating": "CRITICAL" if risk_score >= 80 else "HIGH" if risk_score >= 50 else "MEDIUM" if risk_score >= 25 else "LOW",
                    "executive_summary": " ".join(summary_parts),
                    "phases": self._scan_phases,
                },
            )

            logger.info("Report generated: %d findings, risk=%.1f", len(all_findings), risk_score)
            return report

    # ── Full Automated Analysis ─────────────────────────────────────────────

    def full_analysis(
        self,
        data: bytes,
        name: str = "firmware.bin",
        compare_with: Optional[bytes] = None,
    ) -> FirmwareReport:
        """
        Execute a complete automated firmware security analysis.

        Runs all phases: entropy → filesystem → strings → crypto → vulns → (compare).
        """
        with self._lock:
            self._scan_start = time.time()
            logger.info("Starting full firmware analysis: %s (%d bytes)", name, len(data))

            # Build metadata
            self._metadata = FirmwareMetadata(
                file_path=name,
                file_size=len(data),
                sha256=hashlib.sha256(data).hexdigest(),
                md5=hashlib.md5(data).hexdigest(),
            )

        # Phase 1: Entropy
        self.analyze_entropy(data)

        # Phase 2: Filesystem extraction
        self.extract_filesystems(data)

        # Phase 3: String extraction
        self.scan_strings(data)

        # Phase 4: Crypto scan
        self.scan_crypto(data)

        # Phase 5: Vulnerability patterns
        self.scan_vulnerabilities(data)

        # Phase 6 (optional): Firmware comparison
        if compare_with is not None:
            self.compare_firmware(compare_with, data)

        with self._lock:
            self._scan_end = time.time()

        # Generate report
        report = self.generate_report(firmware_name=name, firmware_size=len(data))

        duration = self._scan_end - self._scan_start
        logger.info(
            "Full analysis complete in %.2fs: %d findings, risk=%s",
            duration, len(report.findings), report.summary.get("risk_rating", "?"),
        )
        return report

    # ── Accessors ───────────────────────────────────────────────────────────

    def get_findings(self) -> List[FirmwareFinding]:
        """Return all findings."""
        with self._lock:
            return list(self._findings)

    def get_crypto_findings(self) -> List[CryptoFinding]:
        """Return all cryptographic findings."""
        with self._lock:
            return list(self._crypto_findings)

    def get_credential_findings(self) -> List[CredentialFinding]:
        """Return all credential findings."""
        with self._lock:
            return list(self._credential_findings)

    def reset(self) -> None:
        """Reset all analysis state."""
        with self._lock:
            self._findings.clear()
            self._crypto_findings.clear()
            self._credential_findings.clear()
            self._vuln_matches.clear()
            self._filesystems.clear()
            self._entropy_profile = None
            self._metadata = None
            self._scan_phases.clear()
            self._scan_start = 0.0
            self._scan_end = 0.0
            logger.info("SirenFirmwareAnalyzer state reset")

    def to_dict(self) -> Dict[str, Any]:
        """Serialize analyzer state."""
        with self._lock:
            return {
                "total_findings": len(self._findings),
                "crypto_findings": len(self._crypto_findings),
                "credential_findings": len(self._credential_findings),
                "vuln_matches": len(self._vuln_matches),
                "filesystems_detected": len(self._filesystems),
                "entropy_profile": self._entropy_profile.to_dict() if self._entropy_profile else None,
                "metadata": self._metadata.to_dict() if self._metadata else None,
                "scan_phases": self._scan_phases,
                "scan_start": self._scan_start,
                "scan_end": self._scan_end,
            }
