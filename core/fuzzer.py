#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  🧬  SIREN FUZZER ENGINE — Motor de Fuzzing Inteligente com IA  🧬            ██
██                                                                                ██
██  Fuzzing de nivel militar com:                                                 ██
██    • Mutacao genetica adaptativa                                               ██
██    • Cobertura de codigo AST-guided                                            ██
██    • Grammar-based fuzzing para protocolos                                     ██
██    • Corpus management inteligente                                             ██
██    • Analise diferencial de resposta                                           ██
██    • Rate limiting auto-calibrado                                              ██
██    • Crash triage automatico                                                   ██
██                                                                                ██
██  "O fuzzer nao adivinha. Ele evolui ate encontrar a fratura perfeita."         ██
██                                                                                ██
████████████████████████████████████████████████████████████████████████████████████
"""

from __future__ import annotations

import asyncio
import base64
import copy
import hashlib
import html
import json
import logging
import math
import os
import random
import re
import string
import struct
import time
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import (
    Any,
    AsyncIterator,
    Callable,
    Dict,
    FrozenSet,
    List,
    Optional,
    Sequence,
    Set,
    Tuple,
    Union,
)

logger = logging.getLogger("siren.fuzzer")


# ════════════════════════════════════════════════════════════════════════════════
# CONSTANTS & MAGIC VALUES
# ════════════════════════════════════════════════════════════════════════════════

# Integer boundaries that historically cause overflows
BOUNDARY_INTS: List[int] = [
    0,
    1,
    -1,
    2,
    -2,
    0x7F,
    0x80,
    0xFF,
    0x100,
    0x7FFF,
    0x8000,
    0xFFFF,
    0x10000,
    0x7FFFFFFF,
    0x80000000,
    0xFFFFFFFF,
    0x100000000,
    0x7FFFFFFFFFFFFFFF,
    0x8000000000000000,
    0xFFFFFFFFFFFFFFFF,
    -0x80,
    -0x8000,
    -0x80000000,
    -0x8000000000000000,
    127,
    128,
    255,
    256,
    32767,
    32768,
    65535,
    65536,
    2147483647,
    2147483648,
    4294967295,
    4294967296,
]

# Format string specifiers
FORMAT_STRINGS: List[str] = [
    "%s",
    "%n",
    "%x",
    "%d",
    "%p",
    "%s" * 50,
    "%n" * 20,
    "%x" * 100,
    "%.1024d",
    "%.2048d",
    "%08x." * 20,
    "AAAA%08x.%08x.%08x.%08x.%08x",
    "%1$s",
    "%2$s",
    "%3$s",
    "%1$n",
    "%2$n",
    "%-1s",
    "%+1s",
    "% 1s",
    "%#1s",
    "%01s",
]

# Path traversal sequences
PATH_TRAVERSALS: List[str] = [
    "../",
    "..\\",
    "....//",
    "....\\\\",
    "../" * 10,
    "..\\" * 10,
    "..%2f",
    "..%5c",
    "%2e%2e%2f",
    "%2e%2e/",
    "..%252f",
    "..%c0%af",
    "..%c1%9c",
    "..%ef%bc%8f",
    "%uff0e%uff0e%u2215",
    "....//....//....//",
    "/etc/passwd",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    "\\\\?\\C:\\Windows\\System32\\drivers\\etc\\hosts",
]

# Unicode edge cases
UNICODE_HELL: List[str] = [
    "\x00",
    "\x01",
    "\x1f",
    "\x7f",
    "\xff",
    "\xfe",
    "\u0000",
    "\u200b",
    "\u200c",
    "\u200d",
    "\ufeff",
    "\ud800",
    "\udbff",
    "\udc00",
    "\udfff",
    "\ufffd",
    "\ufffe",
    "\uffff",
    "Ā" * 1000,
    "𐀀" * 500,
    "\u202e" + "dlrow olleh",  # RTL override
    "\u0300" * 100,  # combining marks
    "\r\n",
    "\r",
    "\n",
    "\r\n" * 100,
    "\x0b",
    "\x0c",
    "\x85",
    "\u2028",
    "\u2029",
]

# HTTP method tampering
HTTP_METHODS: List[str] = [
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "PATCH",
    "OPTIONS",
    "HEAD",
    "TRACE",
    "CONNECT",
    "PROPFIND",
    "PROPPATCH",
    "MKCOL",
    "COPY",
    "MOVE",
    "LOCK",
    "UNLOCK",
    "PURGE",
    "LINK",
    "UNLINK",
    "GETS",
    "POSTS",
    "JEFF",
    "HACK",
    "get",
    "post",
    "GeT",
    "pOsT",
]

# Content-Type variations
CONTENT_TYPES: List[str] = [
    "application/json",
    "application/xml",
    "text/xml",
    "application/x-www-form-urlencoded",
    "multipart/form-data",
    "text/plain",
    "text/html",
    "application/javascript",
    "application/octet-stream",
    "application/graphql",
    "application/x-yaml",
    "text/csv",
    "application/json; charset=utf-8",
    "application/json; charset=utf-16",
    "application/json\r\n",
    "application/json\x00",
]

# CRLF injection
CRLF_INJECTIONS: List[str] = [
    "\r\n",
    "\r",
    "\n",
    "%0d%0a",
    "%0d",
    "%0a",
    "%0D%0A",
    "%0D",
    "%0A",
    "\r\nX-Injected: true",
    "%0d%0aX-Injected:%20true",
    "\r\nSet-Cookie: hacked=1",
    "%0d%0aSet-Cookie:%20hacked=1",
    "\r\n\r\n<html>injected</html>",
    "%%0d0a",
    "%25%30%64%25%30%61",
    "\r\nTransfer-Encoding: chunked",
    "\r\nContent-Length: 0\r\n\r\n",
]


# ════════════════════════════════════════════════════════════════════════════════
# MUTATION STRATEGIES
# ════════════════════════════════════════════════════════════════════════════════


class MutationStrategy(Enum):
    """Estrategias de mutacao disponiveis."""

    BIT_FLIP = auto()
    BYTE_FLIP = auto()
    BYTE_INSERT = auto()
    BYTE_DELETE = auto()
    BYTE_REPEAT = auto()
    BOUNDARY_VALUE = auto()
    DICTIONARY_INSERT = auto()
    ARITHMETIC = auto()
    HAVOC = auto()
    SPLICE = auto()
    TRIM = auto()
    CLONE = auto()
    OVERWRITE = auto()
    INTEREST_8 = auto()
    INTEREST_16 = auto()
    INTEREST_32 = auto()
    FORMAT_STRING = auto()
    UNICODE_MUTATION = auto()
    ENCODING_MUTATION = auto()
    STRUCTURE_AWARE = auto()


@dataclass
class MutationResult:
    """Resultado de uma mutacao."""

    original: bytes
    mutated: bytes
    strategy: MutationStrategy
    position: int = 0
    description: str = ""

    @property
    def changed(self) -> bool:
        return self.original != self.mutated

    @property
    def diff_count(self) -> int:
        return sum(1 for a, b in zip(self.original, self.mutated) if a != b) + abs(
            len(self.original) - len(self.mutated)
        )


class Mutator:
    """Motor de mutacao genetica.

    Aplica mutacoes inteligentes a inputs para descobrir vulnerabilidades.
    Combina estrategias classicas (AFL-style) com mutacoes orientadas
    a protocolos web (JSON, XML, URL-encoded, etc).
    """

    # Interesting 8-bit values
    INTERESTING_8: List[int] = [0, 1, 0x7F, 0x80, 0xFF]
    # Interesting 16-bit values (little-endian)
    INTERESTING_16: List[int] = [0, 1, 0x7F, 0x80, 0xFF, 0x100, 0x7FFF, 0x8000, 0xFFFF]
    # Interesting 32-bit values
    INTERESTING_32: List[int] = [
        0,
        1,
        0x7F,
        0x80,
        0xFF,
        0x100,
        0x7FFF,
        0x8000,
        0xFFFF,
        0x10000,
        0x7FFFFFFF,
        0x80000000,
        0xFFFFFFFF,
    ]

    def __init__(
        self,
        dictionary: Optional[List[bytes]] = None,
        max_input_size: int = 1024 * 1024,  # 1MB
        seed: Optional[int] = None,
    ):
        self.dictionary = dictionary or []
        self.max_input_size = max_input_size
        self._rng = random.Random(seed)
        self._strategies_weights: Dict[MutationStrategy, float] = {
            s: 1.0 for s in MutationStrategy
        }
        self._strategy_hits: Dict[MutationStrategy, int] = {
            s: 0 for s in MutationStrategy
        }

    def mutate(self, data: bytes, count: int = 1) -> List[MutationResult]:
        """Aplica N mutacoes ao input."""
        results = []
        for _ in range(count):
            strategy = self._select_strategy()
            result = self._apply_mutation(data, strategy)
            results.append(result)
        return results

    def boost_strategy(self, strategy: MutationStrategy, factor: float = 2.0):
        """Aumenta peso de uma estrategia que encontrou algo."""
        self._strategies_weights[strategy] *= factor
        self._strategy_hits[strategy] += 1

    def _select_strategy(self) -> MutationStrategy:
        """Seleciona estrategia ponderada."""
        strategies = list(self._strategies_weights.keys())
        weights = list(self._strategies_weights.values())
        return self._rng.choices(strategies, weights=weights, k=1)[0]

    def _apply_mutation(
        self, data: bytes, strategy: MutationStrategy
    ) -> MutationResult:
        """Aplica uma mutacao especifica."""
        handlers = {
            MutationStrategy.BIT_FLIP: self._mutate_bit_flip,
            MutationStrategy.BYTE_FLIP: self._mutate_byte_flip,
            MutationStrategy.BYTE_INSERT: self._mutate_byte_insert,
            MutationStrategy.BYTE_DELETE: self._mutate_byte_delete,
            MutationStrategy.BYTE_REPEAT: self._mutate_byte_repeat,
            MutationStrategy.BOUNDARY_VALUE: self._mutate_boundary,
            MutationStrategy.DICTIONARY_INSERT: self._mutate_dictionary,
            MutationStrategy.ARITHMETIC: self._mutate_arithmetic,
            MutationStrategy.HAVOC: self._mutate_havoc,
            MutationStrategy.SPLICE: self._mutate_splice,
            MutationStrategy.TRIM: self._mutate_trim,
            MutationStrategy.CLONE: self._mutate_clone,
            MutationStrategy.OVERWRITE: self._mutate_overwrite,
            MutationStrategy.INTEREST_8: self._mutate_interest_8,
            MutationStrategy.INTEREST_16: self._mutate_interest_16,
            MutationStrategy.INTEREST_32: self._mutate_interest_32,
            MutationStrategy.FORMAT_STRING: self._mutate_format_string,
            MutationStrategy.UNICODE_MUTATION: self._mutate_unicode,
            MutationStrategy.ENCODING_MUTATION: self._mutate_encoding,
            MutationStrategy.STRUCTURE_AWARE: self._mutate_structure,
        }
        handler = handlers.get(strategy, self._mutate_bit_flip)
        try:
            return handler(data, strategy)
        except Exception:
            return MutationResult(data, data, strategy, description="mutation failed")

    def _mutate_bit_flip(
        self, data: bytes, strategy: MutationStrategy
    ) -> MutationResult:
        if not data:
            return MutationResult(data, b"\x00", strategy, description="empty input")
        buf = bytearray(data)
        pos = self._rng.randint(0, len(buf) - 1)
        bit = self._rng.randint(0, 7)
        buf[pos] ^= 1 << bit
        return MutationResult(
            data, bytes(buf), strategy, pos, f"bit flip @{pos} bit {bit}"
        )

    def _mutate_byte_flip(
        self, data: bytes, strategy: MutationStrategy
    ) -> MutationResult:
        if not data:
            return MutationResult(data, b"\xff", strategy)
        buf = bytearray(data)
        pos = self._rng.randint(0, len(buf) - 1)
        width = self._rng.choice([1, 2, 4])
        for i in range(min(width, len(buf) - pos)):
            buf[pos + i] ^= 0xFF
        return MutationResult(
            data, bytes(buf), strategy, pos, f"byte flip {width} @{pos}"
        )

    def _mutate_byte_insert(
        self, data: bytes, strategy: MutationStrategy
    ) -> MutationResult:
        buf = bytearray(data)
        pos = self._rng.randint(0, len(buf))
        count = self._rng.randint(1, 32)
        insert_byte = self._rng.randint(0, 255)
        insertion = bytes([insert_byte] * count)
        buf[pos:pos] = insertion
        if len(buf) > self.max_input_size:
            buf = buf[: self.max_input_size]
        return MutationResult(
            data,
            bytes(buf),
            strategy,
            pos,
            f"insert {count}x 0x{insert_byte:02x} @{pos}",
        )

    def _mutate_byte_delete(
        self, data: bytes, strategy: MutationStrategy
    ) -> MutationResult:
        if len(data) < 2:
            return MutationResult(
                data, data, strategy, description="too small to delete"
            )
        buf = bytearray(data)
        count = self._rng.randint(1, min(32, len(buf) - 1))
        pos = self._rng.randint(0, len(buf) - count)
        del buf[pos : pos + count]
        return MutationResult(
            data, bytes(buf), strategy, pos, f"delete {count} bytes @{pos}"
        )

    def _mutate_byte_repeat(
        self, data: bytes, strategy: MutationStrategy
    ) -> MutationResult:
        if not data:
            return MutationResult(data, b"A" * 100, strategy)
        buf = bytearray(data)
        pos = self._rng.randint(0, len(buf) - 1)
        repeat = self._rng.randint(2, 128)
        chunk = buf[pos : pos + self._rng.randint(1, 8)]
        insertion = bytes(chunk) * repeat
        buf[pos:pos] = insertion
        if len(buf) > self.max_input_size:
            buf = buf[: self.max_input_size]
        return MutationResult(
            data, bytes(buf), strategy, pos, f"repeat {repeat}x @{pos}"
        )

    def _mutate_boundary(
        self, data: bytes, strategy: MutationStrategy
    ) -> MutationResult:
        """Substitui valores numericos por boundary values."""
        text = data.decode("utf-8", errors="replace")
        numbers = list(re.finditer(r"-?\d+", text))
        if not numbers:
            val = self._rng.choice(BOUNDARY_INTS)
            return MutationResult(
                data, str(val).encode(), strategy, description=f"boundary value {val}"
            )
        match = self._rng.choice(numbers)
        boundary = self._rng.choice(BOUNDARY_INTS)
        new_text = text[: match.start()] + str(boundary) + text[match.end() :]
        return MutationResult(
            data,
            new_text.encode("utf-8"),
            strategy,
            match.start(),
            f"boundary {match.group()} -> {boundary}",
        )

    def _mutate_dictionary(
        self, data: bytes, strategy: MutationStrategy
    ) -> MutationResult:
        if not self.dictionary:
            # Use built-in payloads
            builtins = [
                b"'",
                b'"',
                b"\\",
                b"<",
                b">",
                b"&",
                b";",
                b"' OR '1'='1",
                b'" OR "1"="1',
                b"{{7*7}}",
                b"<script>alert(1)</script>",
                b"${7*7}",
                b"../../../etc/passwd",
                b"|id",
                b"`id`",
                b"$(id)",
                b"%0a",
                b"\r\n",
                b"\x00",
            ]
            word = self._rng.choice(builtins)
        else:
            word = self._rng.choice(self.dictionary)
        buf = bytearray(data)
        pos = self._rng.randint(0, max(0, len(buf)))
        buf[pos:pos] = word
        if len(buf) > self.max_input_size:
            buf = buf[: self.max_input_size]
        return MutationResult(
            data, bytes(buf), strategy, pos, f"dict insert '{word[:30]}' @{pos}"
        )

    def _mutate_arithmetic(
        self, data: bytes, strategy: MutationStrategy
    ) -> MutationResult:
        if len(data) < 4:
            return MutationResult(
                data, data, strategy, description="too small for arithmetic"
            )
        buf = bytearray(data)
        width = self._rng.choice([1, 2, 4])
        pos = self._rng.randint(0, len(buf) - width)
        delta = self._rng.randint(1, 35)
        if self._rng.random() < 0.5:
            delta = -delta
        if width == 1:
            buf[pos] = (buf[pos] + delta) & 0xFF
        elif width == 2:
            val = struct.unpack_from("<H", buf, pos)[0]
            val = (val + delta) & 0xFFFF
            struct.pack_into("<H", buf, pos, val)
        elif width == 4:
            val = struct.unpack_from("<I", buf, pos)[0]
            val = (val + delta) & 0xFFFFFFFF
            struct.pack_into("<I", buf, pos, val)
        return MutationResult(
            data,
            bytes(buf),
            strategy,
            pos,
            f"arith {width}B {'+' if delta > 0 else ''}{delta} @{pos}",
        )

    def _mutate_havoc(self, data: bytes, strategy: MutationStrategy) -> MutationResult:
        """Modo caos — aplica multiplas mutacoes randomicas."""
        buf = bytearray(data) if data else bytearray(b"A" * 16)
        rounds = self._rng.randint(2, 16)
        desc_parts = []
        for _ in range(rounds):
            op = self._rng.randint(0, 14)
            if op == 0 and buf:  # bit flip
                pos = self._rng.randint(0, len(buf) - 1)
                buf[pos] ^= 1 << self._rng.randint(0, 7)
            elif op == 1 and buf:  # set interesting 8
                pos = self._rng.randint(0, len(buf) - 1)
                buf[pos] = self._rng.choice(self.INTERESTING_8) & 0xFF
            elif op == 2 and len(buf) >= 2:  # set interesting 16
                pos = self._rng.randint(0, len(buf) - 2)
                val = self._rng.choice(self.INTERESTING_16) & 0xFFFF
                struct.pack_into("<H", buf, pos, val)
            elif op == 3 and len(buf) >= 4:  # set interesting 32
                pos = self._rng.randint(0, len(buf) - 4)
                val = self._rng.choice(self.INTERESTING_32) & 0xFFFFFFFF
                struct.pack_into("<I", buf, pos, val)
            elif op == 4 and buf:  # subtract from byte
                pos = self._rng.randint(0, len(buf) - 1)
                buf[pos] = (buf[pos] - self._rng.randint(1, 35)) & 0xFF
            elif op == 5 and buf:  # add to byte
                pos = self._rng.randint(0, len(buf) - 1)
                buf[pos] = (buf[pos] + self._rng.randint(1, 35)) & 0xFF
            elif op == 6 and buf:  # random byte
                pos = self._rng.randint(0, len(buf) - 1)
                buf[pos] = self._rng.randint(0, 255)
            elif op == 7:  # delete bytes
                if len(buf) > 2:
                    count = self._rng.randint(1, min(8, len(buf) - 1))
                    pos = self._rng.randint(0, len(buf) - count)
                    del buf[pos : pos + count]
            elif op == 8:  # clone/insert bytes
                if buf and len(buf) < self.max_input_size:
                    count = self._rng.randint(1, min(16, len(buf)))
                    src = self._rng.randint(0, len(buf) - count)
                    dst = self._rng.randint(0, len(buf))
                    buf[dst:dst] = buf[src : src + count]
            elif op == 9:  # overwrite with random
                if buf:
                    count = self._rng.randint(1, min(16, len(buf)))
                    pos = self._rng.randint(0, len(buf) - count)
                    for i in range(count):
                        buf[pos + i] = self._rng.randint(0, 255)
            elif op == 10 and buf:  # overwrite with interesting
                if len(buf) >= 4:
                    pos = self._rng.randint(0, len(buf) - 4)
                    val = self._rng.choice(BOUNDARY_INTS) & 0xFFFFFFFF
                    struct.pack_into("<I", buf, pos, val)
            elif op == 11:  # insert null bytes
                pos = self._rng.randint(0, len(buf))
                buf[pos:pos] = b"\x00" * self._rng.randint(1, 8)
            elif op == 12 and buf:  # swap bytes
                if len(buf) >= 2:
                    a = self._rng.randint(0, len(buf) - 1)
                    b_idx = self._rng.randint(0, len(buf) - 1)
                    buf[a], buf[b_idx] = buf[b_idx], buf[a]
            elif op == 13:  # duplicate chunk
                if buf and len(buf) < self.max_input_size:
                    size = self._rng.randint(1, min(64, len(buf)))
                    pos = self._rng.randint(0, len(buf) - size)
                    buf.extend(buf[pos : pos + size])
            elif op == 14 and buf:  # set all same byte
                if self._rng.random() < 0.1:
                    fill = self._rng.choice([0x00, 0x41, 0xFF, 0x0A, 0x20])
                    size = self._rng.randint(1, min(32, len(buf)))
                    pos = self._rng.randint(0, len(buf) - size)
                    for i in range(size):
                        buf[pos + i] = fill
            desc_parts.append(f"op{op}")
        if len(buf) > self.max_input_size:
            buf = buf[: self.max_input_size]
        return MutationResult(
            data,
            bytes(buf),
            strategy,
            0,
            f"havoc {rounds} ops: {','.join(desc_parts[:5])}",
        )

    def _mutate_splice(self, data: bytes, strategy: MutationStrategy) -> MutationResult:
        """Splice with random data."""
        if len(data) < 4:
            return MutationResult(data, data + os.urandom(16), strategy)
        split = self._rng.randint(1, len(data) - 1)
        random_tail = os.urandom(self._rng.randint(1, 64))
        result = data[:split] + random_tail
        if len(result) > self.max_input_size:
            result = result[: self.max_input_size]
        return MutationResult(data, result, strategy, split, f"splice @{split}")

    def _mutate_trim(self, data: bytes, strategy: MutationStrategy) -> MutationResult:
        if len(data) < 4:
            return MutationResult(data, data, strategy, description="too small to trim")
        trim_to = self._rng.randint(1, len(data) - 1)
        return MutationResult(
            data, data[:trim_to], strategy, trim_to, f"trim to {trim_to}"
        )

    def _mutate_clone(self, data: bytes, strategy: MutationStrategy) -> MutationResult:
        if not data:
            return MutationResult(data, data, strategy)
        repeat = self._rng.randint(2, 10)
        result = data * repeat
        if len(result) > self.max_input_size:
            result = result[: self.max_input_size]
        return MutationResult(data, result, strategy, 0, f"clone x{repeat}")

    def _mutate_overwrite(
        self, data: bytes, strategy: MutationStrategy
    ) -> MutationResult:
        if not data:
            return MutationResult(data, os.urandom(16), strategy)
        buf = bytearray(data)
        count = self._rng.randint(1, min(32, len(buf)))
        pos = self._rng.randint(0, len(buf) - count)
        replacement = os.urandom(count)
        buf[pos : pos + count] = replacement
        return MutationResult(
            data, bytes(buf), strategy, pos, f"overwrite {count}B @{pos}"
        )

    def _mutate_interest_8(
        self, data: bytes, strategy: MutationStrategy
    ) -> MutationResult:
        if not data:
            return MutationResult(
                data, bytes([self._rng.choice(self.INTERESTING_8) & 0xFF]), strategy
            )
        buf = bytearray(data)
        pos = self._rng.randint(0, len(buf) - 1)
        val = self._rng.choice(self.INTERESTING_8) & 0xFF
        buf[pos] = val
        return MutationResult(
            data, bytes(buf), strategy, pos, f"interest8 {val} @{pos}"
        )

    def _mutate_interest_16(
        self, data: bytes, strategy: MutationStrategy
    ) -> MutationResult:
        if len(data) < 2:
            return MutationResult(data, data, strategy)
        buf = bytearray(data)
        pos = self._rng.randint(0, len(buf) - 2)
        val = self._rng.choice(self.INTERESTING_16) & 0xFFFF
        endian = self._rng.choice(["<H", ">H"])
        struct.pack_into(endian, buf, pos, val)
        return MutationResult(
            data, bytes(buf), strategy, pos, f"interest16 {val} {endian} @{pos}"
        )

    def _mutate_interest_32(
        self, data: bytes, strategy: MutationStrategy
    ) -> MutationResult:
        if len(data) < 4:
            return MutationResult(data, data, strategy)
        buf = bytearray(data)
        pos = self._rng.randint(0, len(buf) - 4)
        val = self._rng.choice(self.INTERESTING_32) & 0xFFFFFFFF
        endian = self._rng.choice(["<I", ">I"])
        struct.pack_into(endian, buf, pos, val)
        return MutationResult(
            data, bytes(buf), strategy, pos, f"interest32 {val} {endian} @{pos}"
        )

    def _mutate_format_string(
        self, data: bytes, strategy: MutationStrategy
    ) -> MutationResult:
        fmt = self._rng.choice(FORMAT_STRINGS)
        text = data.decode("utf-8", errors="replace")
        if text:
            pos = self._rng.randint(0, len(text))
            new_text = text[:pos] + fmt + text[pos:]
        else:
            new_text = fmt
        return MutationResult(
            data,
            new_text.encode("utf-8"),
            strategy,
            description=f"format string '{fmt}'",
        )

    def _mutate_unicode(
        self, data: bytes, strategy: MutationStrategy
    ) -> MutationResult:
        text = data.decode("utf-8", errors="replace")
        uchar = self._rng.choice(UNICODE_HELL)
        pos = self._rng.randint(0, max(0, len(text)))
        new_text = text[:pos] + uchar + text[pos:]
        return MutationResult(
            data,
            new_text.encode("utf-8", errors="replace"),
            strategy,
            description=f"unicode @{pos}",
        )

    def _mutate_encoding(
        self, data: bytes, strategy: MutationStrategy
    ) -> MutationResult:
        """Muta encodings — double-encode, different charsets, etc."""
        text = data.decode("utf-8", errors="replace")
        op = self._rng.randint(0, 5)
        if op == 0:  # URL double-encode
            result = urllib.parse.quote(urllib.parse.quote(text))
        elif op == 1:  # HTML entity encode
            result = html.escape(text)
        elif op == 2:  # Base64
            result = base64.b64encode(data).decode()
        elif op == 3:  # Unicode escape
            result = text.encode("unicode_escape").decode("ascii")
        elif op == 4:  # Hex encode
            result = data.hex()
        else:  # Mixed encoding
            parts = []
            for ch in text:
                encoding = self._rng.choice(["raw", "url", "html", "unicode"])
                if encoding == "raw":
                    parts.append(ch)
                elif encoding == "url":
                    parts.append(urllib.parse.quote(ch))
                elif encoding == "html":
                    parts.append(f"&#{ord(ch)};")
                else:
                    parts.append(f"\\u{ord(ch):04x}")
            result = "".join(parts)
        return MutationResult(
            data,
            result.encode("utf-8", errors="replace"),
            strategy,
            description=f"encoding op{op}",
        )

    def _mutate_structure(
        self, data: bytes, strategy: MutationStrategy
    ) -> MutationResult:
        """Mutacao com awareness de estrutura (JSON, XML, URL)."""
        text = data.decode("utf-8", errors="replace")

        # Try JSON
        try:
            obj = json.loads(text)
            mutated = self._mutate_json_structure(obj)
            return MutationResult(
                data,
                json.dumps(mutated).encode("utf-8"),
                strategy,
                description="json structure",
            )
        except (json.JSONDecodeError, ValueError):
            pass

        # Try URL-encoded
        if "=" in text and "&" in text:
            params = urllib.parse.parse_qs(text, keep_blank_values=True)
            mutated = self._mutate_urlencoded_structure(params)
            return MutationResult(
                data,
                urllib.parse.urlencode(mutated, doseq=True).encode(),
                strategy,
                description="urlencoded structure",
            )

        # Fallback to dictionary insert
        return self._mutate_dictionary(data, strategy)

    def _mutate_json_structure(self, obj: Any, depth: int = 0) -> Any:
        """Muta um objeto JSON recursivamente."""
        if depth > 10:
            return obj

        if isinstance(obj, dict):
            result = {}
            for key, value in obj.items():
                op = self._rng.randint(0, 9)
                if op == 0:  # mutate key
                    new_key = key + self._rng.choice(
                        ["'", '"', "\\", "__proto__", "constructor"]
                    )
                    result[new_key] = value
                elif op == 1:  # delete key
                    continue
                elif op == 2:  # add injection key
                    result[key] = value
                    result["__proto__"] = {"admin": True}
                elif op == 3:  # type confusion
                    if isinstance(value, str):
                        result[key] = self._rng.randint(-999999, 999999)
                    elif isinstance(value, (int, float)):
                        result[key] = str(value) + "' OR '1'='1"
                    elif isinstance(value, bool):
                        result[key] = [value]
                    elif isinstance(value, list):
                        result[key] = {"0": value[0] if value else None}
                    else:
                        result[key] = value
                else:
                    result[key] = self._mutate_json_structure(value, depth + 1)
            # Sometimes add extra keys
            if self._rng.random() < 0.3:
                extra_keys = [
                    "__proto__",
                    "constructor",
                    "prototype",
                    "admin",
                    "role",
                    "isAdmin",
                    "debug",
                    "$where",
                    "$gt",
                    "$ne",
                ]
                result[self._rng.choice(extra_keys)] = self._rng.choice(
                    [True, 1, "admin", {"$gt": ""}, [None], "' OR '1'='1"]
                )
            return result

        elif isinstance(obj, list):
            if self._rng.random() < 0.2:
                return obj * self._rng.randint(2, 100)  # array repetition
            return [self._mutate_json_structure(item, depth + 1) for item in obj]

        elif isinstance(obj, str):
            payloads = [
                "' OR '1'='1",
                '" OR "1"="1',
                "{{7*7}}",
                "${7*7}",
                "<script>alert(1)</script>",
                "'; DROP TABLE users;--",
                "../../../etc/passwd",
                "|id",
                "`id`",
                "$(id)",
                "admin",
                "true",
                "null",
                str(0x7FFFFFFF),
                "A" * 10000,
                "%s" * 50,
                "{}" * 100,
            ]
            return self._rng.choice(payloads)

        elif isinstance(obj, (int, float)):
            return self._rng.choice(BOUNDARY_INTS[:20])

        elif isinstance(obj, bool):
            return not obj

        elif obj is None:
            return self._rng.choice([0, "", False, [], {}, "null", "undefined"])

        return obj

    def _mutate_urlencoded_structure(self, params: Dict) -> Dict:
        """Muta parametros URL-encoded."""
        result = {}
        injections = [
            "' OR '1'='1",
            '" OR "1"="1',
            "<script>alert(1)</script>",
            "../../../etc/passwd",
            "|id",
            "{{7*7}}",
            "${7*7}",
            "%0a%0d",
        ]
        for key, values in params.items():
            op = self._rng.randint(0, 5)
            if op == 0:  # inject into value
                result[key] = [self._rng.choice(injections)]
            elif op == 1:  # duplicate with injection
                result[key] = values
                result[key + "'"] = [self._rng.choice(injections)]
            elif op == 2:  # overflow value
                result[key] = ["A" * 10000]
            elif op == 3:  # type confusion
                result[key + "[]"] = values
            elif op == 4:  # null byte
                result[key] = [values[0] + "\x00" if values else "\x00"]
            else:
                result[key] = values
        return result


# ════════════════════════════════════════════════════════════════════════════════
# CORPUS MANAGEMENT
# ════════════════════════════════════════════════════════════════════════════════


@dataclass
class CorpusEntry:
    """Uma entrada no corpus de fuzzing."""

    data: bytes
    source: str = "seed"
    coverage_hash: str = ""
    found_at: float = field(default_factory=time.time)
    hit_count: int = 0
    interesting: bool = False
    crashes: int = 0
    hang_count: int = 0
    exec_time_ms: float = 0.0
    energy: float = 1.0  # scheduling energy
    favorite: bool = False

    @property
    def id(self) -> str:
        return hashlib.sha256(self.data).hexdigest()[:16]

    @property
    def size(self) -> int:
        return len(self.data)


class Corpus:
    """Gerenciador de corpus de fuzzing.

    Mantém inputs de seed, descobre novos inputs interessantes,
    e aplica power scheduling para priorizar inputs produtivos.
    """

    def __init__(self, corpus_dir: Optional[Path] = None, max_entries: int = 10000):
        self.entries: Dict[str, CorpusEntry] = {}
        self.corpus_dir = corpus_dir
        self.max_entries = max_entries
        self._coverage_set: Set[str] = set()
        self._total_executions: int = 0

    def add_seed(self, data: bytes, source: str = "seed") -> CorpusEntry:
        """Adiciona um seed ao corpus."""
        entry = CorpusEntry(data=data, source=source)
        self.entries[entry.id] = entry
        return entry

    def add_seeds_from_dir(self, directory: Path) -> int:
        """Carrega seeds de um diretório."""
        count = 0
        if not directory.exists():
            return 0
        for f in directory.iterdir():
            if f.is_file() and f.stat().st_size > 0:
                try:
                    data = f.read_bytes()
                    self.add_seed(data, f"file:{f.name}")
                    count += 1
                except Exception as e:
                    logger.debug("Seed file load error for %s: %s", f.name, e)
        return count

    def add_if_interesting(
        self,
        data: bytes,
        coverage_hash: str,
        exec_time_ms: float = 0.0,
        source: str = "mutation",
    ) -> Optional[CorpusEntry]:
        """Adiciona ao corpus se coverage hash e novo."""
        if coverage_hash in self._coverage_set:
            return None

        self._coverage_set.add(coverage_hash)
        entry = CorpusEntry(
            data=data,
            source=source,
            coverage_hash=coverage_hash,
            exec_time_ms=exec_time_ms,
            interesting=True,
        )
        self.entries[entry.id] = entry

        # Evict least interesting if over limit
        if len(self.entries) > self.max_entries:
            self._evict()

        return entry

    def select(self, count: int = 1) -> List[CorpusEntry]:
        """Seleciona entradas para mutacao (power scheduling)."""
        if not self.entries:
            return []

        entries = list(self.entries.values())
        weights = [e.energy for e in entries]
        total = sum(weights)
        if total == 0:
            weights = [1.0] * len(entries)

        selected = random.choices(entries, weights=weights, k=min(count, len(entries)))
        for entry in selected:
            entry.hit_count += 1
            # Decrease energy after selection (exploitation vs exploration)
            entry.energy *= 0.95
        return selected

    def mark_crash(self, entry_id: str):
        """Marca uma entrada como causadora de crash."""
        if entry_id in self.entries:
            self.entries[entry_id].crashes += 1
            self.entries[entry_id].energy *= 3.0  # Boost crashes
            self.entries[entry_id].favorite = True

    def save(self, output_dir: Path):
        """Salva corpus em disco."""
        output_dir.mkdir(parents=True, exist_ok=True)
        for entry in self.entries.values():
            entry_file = output_dir / f"id_{entry.id}"
            entry_file.write_bytes(entry.data)
        # Save metadata
        meta = {
            "total_entries": len(self.entries),
            "total_coverage": len(self._coverage_set),
            "total_crashes": sum(e.crashes for e in self.entries.values()),
        }
        (output_dir / "corpus_meta.json").write_text(
            json.dumps(meta, indent=2), encoding="utf-8"
        )

    def _evict(self):
        """Remove entradas menos interessantes."""
        entries = sorted(self.entries.values(), key=lambda e: e.energy)
        to_remove = len(self.entries) - self.max_entries
        for entry in entries[:to_remove]:
            if not entry.favorite:
                del self.entries[entry.id]

    def stats(self) -> Dict[str, Any]:
        return {
            "total_entries": len(self.entries),
            "total_coverage": len(self._coverage_set),
            "total_crashes": sum(e.crashes for e in self.entries.values()),
            "favorites": sum(1 for e in self.entries.values() if e.favorite),
            "avg_energy": sum(e.energy for e in self.entries.values())
            / max(1, len(self.entries)),
        }


# ════════════════════════════════════════════════════════════════════════════════
# COVERAGE TRACKING
# ════════════════════════════════════════════════════════════════════════════════


class CoverageType(Enum):
    """Tipos de cobertura rastreados."""

    STATUS_CODE = auto()
    RESPONSE_SIZE = auto()
    RESPONSE_TIME = auto()
    CONTENT_TYPE = auto()
    HEADER_SET = auto()
    ERROR_PATTERN = auto()
    BODY_STRUCTURE = auto()
    REDIRECT_CHAIN = auto()


@dataclass
class CoveragePoint:
    """Um ponto de cobertura observado."""

    cov_type: CoverageType
    value: str
    first_seen: float = field(default_factory=time.time)
    hit_count: int = 1

    @property
    def hash(self) -> str:
        return hashlib.md5(f"{self.cov_type.name}:{self.value}".encode()).hexdigest()[
            :12
        ]


class CoverageTracker:
    """Rastreia cobertura de resposta HTTP para guiar o fuzzer.

    Como nao temos cobertura de codigo (black-box), usamos
    cobertura de COMPORTAMENTO — status codes, tempos de resposta,
    tamanhos, estrutura de resposta, headers, etc.
    """

    def __init__(self):
        self._points: Dict[str, CoveragePoint] = {}
        self._status_codes: Set[int] = set()
        self._size_buckets: Set[int] = set()
        self._time_buckets: Set[int] = set()
        self._error_patterns: Set[str] = set()
        self._content_types: Set[str] = set()
        self._total_inputs: int = 0

    def track(
        self,
        status_code: int,
        response_body: str,
        response_headers: Dict[str, str],
        response_time_ms: float,
        content_type: str = "",
    ) -> Tuple[str, bool]:
        """Rastreia cobertura de uma resposta. Retorna (hash, is_new)."""
        self._total_inputs += 1
        coverage_parts = []
        is_new = False

        # Status code
        if status_code not in self._status_codes:
            self._status_codes.add(status_code)
            is_new = True
        coverage_parts.append(f"s:{status_code}")

        # Response size bucket (log2)
        size = len(response_body)
        size_bucket = int(math.log2(size + 1)) if size > 0 else 0
        if size_bucket not in self._size_buckets:
            self._size_buckets.add(size_bucket)
            is_new = True
        coverage_parts.append(f"z:{size_bucket}")

        # Response time bucket (log scale)
        time_bucket = (
            int(math.log2(response_time_ms + 1)) if response_time_ms > 0 else 0
        )
        if time_bucket not in self._time_buckets:
            self._time_buckets.add(time_bucket)
            is_new = True
        coverage_parts.append(f"t:{time_bucket}")

        # Content type
        ct = content_type or response_headers.get("content-type", "unknown")
        if ct not in self._content_types:
            self._content_types.add(ct)
            is_new = True
        coverage_parts.append(f"ct:{ct[:20]}")

        # Error patterns in body
        error_patterns = [
            r"(?i)error",
            r"(?i)exception",
            r"(?i)traceback",
            r"(?i)syntax error",
            r"(?i)sql",
            r"(?i)stack trace",
            r"(?i)undefined",
            r"(?i)null.*reference",
            r"(?i)segmentation",
            r"(?i)core dump",
            r"(?i)internal server",
            r"(?i)fatal",
        ]
        for pattern in error_patterns:
            if re.search(pattern, response_body[:5000]):
                pattern_key = pattern.replace(r"(?i)", "")[:15]
                if pattern_key not in self._error_patterns:
                    self._error_patterns.add(pattern_key)
                    is_new = True
                coverage_parts.append(f"e:{pattern_key}")
                break

        # Body structure hash (rough)
        structure = self._extract_structure(response_body[:2000])
        coverage_parts.append(f"st:{structure[:20]}")

        coverage_hash = hashlib.md5("|".join(coverage_parts).encode()).hexdigest()[:16]

        if is_new:
            point = CoveragePoint(
                cov_type=CoverageType.STATUS_CODE,
                value="|".join(coverage_parts),
            )
            self._points[coverage_hash] = point

        return coverage_hash, is_new

    def _extract_structure(self, body: str) -> str:
        """Extrai um hash da estrutura do body (tags HTML, keys JSON, etc)."""
        # JSON structure
        try:
            obj = json.loads(body)
            return self._json_structure_hash(obj)
        except (json.JSONDecodeError, ValueError):
            pass

        # HTML structure (tag sequence)
        tags = re.findall(r"<(/?\w+)", body[:2000])
        if tags:
            return hashlib.md5("|".join(tags[:20]).encode()).hexdigest()[:12]

        # Plain text — length bucket
        return f"text:{len(body) // 100}"

    def _json_structure_hash(self, obj: Any, depth: int = 0) -> str:
        if depth > 5:
            return "deep"
        if isinstance(obj, dict):
            keys = sorted(obj.keys())[:10]
            return "D:" + ",".join(keys)
        elif isinstance(obj, list):
            return f"L:{len(obj)}"
        elif isinstance(obj, str):
            return "S"
        elif isinstance(obj, (int, float)):
            return "N"
        elif isinstance(obj, bool):
            return "B"
        elif obj is None:
            return "null"
        return "?"

    def stats(self) -> Dict[str, Any]:
        return {
            "total_inputs": self._total_inputs,
            "unique_coverage_points": len(self._points),
            "status_codes": sorted(self._status_codes),
            "size_buckets": len(self._size_buckets),
            "time_buckets": len(self._time_buckets),
            "error_patterns": list(self._error_patterns),
            "content_types": list(self._content_types),
        }


# ════════════════════════════════════════════════════════════════════════════════
# CRASH TRIAGE
# ════════════════════════════════════════════════════════════════════════════════


class CrashSeverity(Enum):
    """Severidade de um crash."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class CrashReport:
    """Report de um crash encontrado pelo fuzzer."""

    crash_id: str
    severity: CrashSeverity
    input_data: bytes
    status_code: int
    response_body: str
    response_headers: Dict[str, str]
    response_time_ms: float
    mutation_strategy: MutationStrategy
    mutation_description: str
    timestamp: float = field(default_factory=time.time)
    url: str = ""
    method: str = "GET"
    deduplicated: bool = False
    crash_signature: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "crash_id": self.crash_id,
            "severity": self.severity.value,
            "input_hex": self.input_data[:200].hex(),
            "input_text": self.input_data[:200].decode("utf-8", errors="replace"),
            "status_code": self.status_code,
            "response_size": len(self.response_body),
            "response_time_ms": self.response_time_ms,
            "mutation": self.mutation_strategy.name,
            "mutation_desc": self.mutation_description,
            "url": self.url,
            "method": self.method,
            "crash_signature": self.crash_signature,
            "timestamp": self.timestamp,
        }


class CrashTriager:
    """Analisa e classifica crashes encontrados pelo fuzzer.

    Funcionalidades:
    - Deduplica crashes por signature (stack trace hash)
    - Classifica severidade (info→critical)
    - Gera PoC reproduzivel
    - Detecta security-relevant crashes
    """

    SECURITY_PATTERNS = {
        CrashSeverity.CRITICAL: [
            r"(?i)sql.*syntax",
            r"(?i)mysql.*error",
            r"(?i)postgres.*error",
            r"(?i)ora-\d{5}",
            r"(?i)sqlite.*error",
            r"(?i)remote code execution",
            r"(?i)command injection",
            r"(?i)eval\(\)",
            r"(?i)exec\(\)",
            r"(?i)deserialization",
        ],
        CrashSeverity.HIGH: [
            r"(?i)stack trace",
            r"(?i)traceback.*most recent",
            r"(?i)at\s+[\w.]+\([\w.]+:\d+\)",
            r"(?i)null.*pointer",
            r"(?i)buffer overflow",
            r"(?i)heap.*corrupt",
            r"(?i)segmentation fault",
            r"(?i)access violation",
            r"(?i)path.*traversal",
            r"(?i)directory.*listing",
        ],
        CrashSeverity.MEDIUM: [
            r"(?i)exception",
            r"(?i)error.*\d{3}",
            r"(?i)internal server error",
            r"(?i)bad gateway",
            r"(?i)service unavailable",
            r"(?i)timeout",
            r"(?i)connection refused",
            r"(?i)unhandled",
            r"(?i)uncaught",
        ],
        CrashSeverity.LOW: [
            r"(?i)warning",
            r"(?i)deprecated",
            r"(?i)notice",
            r"(?i)debug",
            r"(?i)verbose",
        ],
    }

    def __init__(self):
        self.crashes: List[CrashReport] = []
        self._signatures: Set[str] = set()
        self._dedup_count: int = 0

    def analyze(
        self,
        input_data: bytes,
        status_code: int,
        response_body: str,
        response_headers: Dict[str, str],
        response_time_ms: float,
        mutation_result: MutationResult,
        url: str = "",
        method: str = "GET",
    ) -> Optional[CrashReport]:
        """Analisa uma resposta e cria CrashReport se relevante."""
        # Check if this is a crash
        is_crash, severity = self._is_crash(
            status_code, response_body, response_time_ms
        )
        if not is_crash:
            return None

        # Generate crash signature for dedup
        signature = self._generate_signature(status_code, response_body)

        # Dedup
        if signature in self._signatures:
            self._dedup_count += 1
            return None

        self._signatures.add(signature)

        crash = CrashReport(
            crash_id=hashlib.sha256(
                f"{url}:{input_data.hex()[:100]}:{status_code}".encode()
            ).hexdigest()[:16],
            severity=severity,
            input_data=input_data,
            status_code=status_code,
            response_body=response_body[:5000],
            response_headers=response_headers,
            response_time_ms=response_time_ms,
            mutation_strategy=mutation_result.strategy,
            mutation_description=mutation_result.description,
            url=url,
            method=method,
            crash_signature=signature,
        )

        self.crashes.append(crash)
        return crash

    def _is_crash(
        self, status_code: int, body: str, time_ms: float
    ) -> Tuple[bool, CrashSeverity]:
        """Determina se uma resposta e um crash e sua severidade."""
        # Server errors are always interesting
        if status_code >= 500:
            # Check for specific patterns
            for severity, patterns in self.SECURITY_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, body[:5000]):
                        return True, severity
            return True, CrashSeverity.MEDIUM

        # Extremely slow responses (potential DoS)
        if time_ms > 10000:
            return True, CrashSeverity.HIGH

        # Very slow (> 5s) with error patterns
        if time_ms > 5000:
            for severity in [CrashSeverity.CRITICAL, CrashSeverity.HIGH]:
                for pattern in self.SECURITY_PATTERNS[severity]:
                    if re.search(pattern, body[:5000]):
                        return True, severity

        # Check for info leakage in any status code
        for pattern in self.SECURITY_PATTERNS[CrashSeverity.CRITICAL]:
            if re.search(pattern, body[:5000]):
                return True, CrashSeverity.CRITICAL

        for pattern in self.SECURITY_PATTERNS[CrashSeverity.HIGH]:
            if re.search(pattern, body[:5000]):
                return True, CrashSeverity.HIGH

        return False, CrashSeverity.INFO

    def _generate_signature(self, status_code: int, body: str) -> str:
        """Gera signature unica para deduplicacao de crashes."""
        parts = [str(status_code)]

        # Extract error lines
        for line in body.split("\n")[:20]:
            line = line.strip()
            # Stack trace lines
            if re.match(r"^\s*at\s+", line) or re.match(r"^\s*File\s+", line):
                # Remove line numbers for better dedup
                cleaned = re.sub(r":\d+", ":N", line)
                cleaned = re.sub(r"line\s+\d+", "line N", cleaned)
                parts.append(cleaned[:100])
            # Error type
            elif re.match(r"^[\w.]+Error:", line) or re.match(
                r"^[\w.]+Exception:", line
            ):
                parts.append(line[:100])

        sig_str = "|".join(parts[:10])
        return hashlib.md5(sig_str.encode()).hexdigest()[:16]

    def save_crashes(self, output_dir: Path):
        """Salva todos os crashes em disco."""
        output_dir.mkdir(parents=True, exist_ok=True)
        for crash in self.crashes:
            crash_dir = output_dir / f"crash_{crash.crash_id}"
            crash_dir.mkdir(exist_ok=True)

            # Input
            (crash_dir / "input.bin").write_bytes(crash.input_data)
            (crash_dir / "input.txt").write_text(
                crash.input_data.decode("utf-8", errors="replace"),
                encoding="utf-8",
            )

            # Metadata
            (crash_dir / "crash.json").write_text(
                json.dumps(crash.to_dict(), indent=2, ensure_ascii=False),
                encoding="utf-8",
            )

            # Response
            (crash_dir / "response.txt").write_text(
                f"HTTP {crash.status_code}\n"
                f"Time: {crash.response_time_ms:.0f}ms\n"
                f"Headers: {json.dumps(crash.response_headers, indent=2)}\n\n"
                f"{crash.response_body}",
                encoding="utf-8",
            )

            # PoC
            poc = self._generate_poc(crash)
            (crash_dir / "poc.sh").write_text(poc, encoding="utf-8")

        # Summary
        summary = {
            "total_crashes": len(self.crashes),
            "deduplicated": self._dedup_count,
            "by_severity": {},
        }
        for sev in CrashSeverity:
            count = sum(1 for c in self.crashes if c.severity == sev)
            if count:
                summary["by_severity"][sev.value] = count

        (output_dir / "crash_summary.json").write_text(
            json.dumps(summary, indent=2), encoding="utf-8"
        )

    def _generate_poc(self, crash: CrashReport) -> str:
        """Gera script de PoC reproduzivel."""
        input_text = crash.input_data.decode("utf-8", errors="replace")
        escaped_input = input_text.replace("'", "'\\''")

        poc = f"""#!/bin/bash
# SIREN Fuzzer — Crash PoC
# Crash ID: {crash.crash_id}
# Severity: {crash.severity.value.upper()}
# URL: {crash.url}
# Mutation: {crash.mutation_strategy.name} — {crash.mutation_description}

curl -v -X {crash.method} \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  -d '{escaped_input}' \\
  '{crash.url}'

# Expected: HTTP {crash.status_code}
# Response Time: {crash.response_time_ms:.0f}ms
"""
        return poc

    def stats(self) -> Dict[str, Any]:
        by_severity = {}
        by_strategy = {}
        for crash in self.crashes:
            sev = crash.severity.value
            by_severity[sev] = by_severity.get(sev, 0) + 1
            strat = crash.mutation_strategy.name
            by_strategy[strat] = by_strategy.get(strat, 0) + 1

        return {
            "total_crashes": len(self.crashes),
            "unique_signatures": len(self._signatures),
            "deduplicated": self._dedup_count,
            "by_severity": by_severity,
            "by_strategy": by_strategy,
        }


# ════════════════════════════════════════════════════════════════════════════════
# RATE LIMITER — Auto-calibrating
# ════════════════════════════════════════════════════════════════════════════════


class AdaptiveRateLimiter:
    """Rate limiter auto-calibrado.

    Automaticamente ajusta a taxa de requests baseado em:
    - Status codes 429 (too many requests)
    - Tempos de resposta crescentes
    - Erros de conexao
    - Headers de rate limit (X-RateLimit-*)
    """

    def __init__(
        self,
        initial_rps: float = 50.0,
        min_rps: float = 1.0,
        max_rps: float = 500.0,
        backoff_factor: float = 0.5,
        recovery_factor: float = 1.1,
    ):
        self.current_rps = initial_rps
        self.min_rps = min_rps
        self.max_rps = max_rps
        self.backoff_factor = backoff_factor
        self.recovery_factor = recovery_factor
        self._last_request_time: float = 0
        self._consecutive_ok: int = 0
        self._consecutive_throttle: int = 0
        self._total_throttles: int = 0
        self._window_start: float = time.time()
        self._window_count: int = 0

    async def acquire(self):
        """Espera ate que seja seguro enviar outro request."""
        now = time.time()
        min_interval = 1.0 / self.current_rps
        elapsed = now - self._last_request_time

        if elapsed < min_interval:
            await asyncio.sleep(min_interval - elapsed)

        self._last_request_time = time.time()
        self._window_count += 1

    def report_response(
        self,
        status_code: int,
        response_time_ms: float,
        headers: Optional[Dict[str, str]] = None,
    ):
        """Reporta resultado de um request para auto-calibracao."""
        headers = headers or {}

        # Check for rate limiting
        if status_code == 429:
            self._consecutive_throttle += 1
            self._consecutive_ok = 0
            self._total_throttles += 1

            # Check Retry-After header
            retry_after = headers.get("retry-after", "")
            if retry_after.isdigit():
                wait_seconds = int(retry_after)
                self.current_rps = min(self.current_rps, 1.0 / max(wait_seconds, 1))
            else:
                self.current_rps *= self.backoff_factor

            # Check X-RateLimit headers
            remaining = headers.get("x-ratelimit-remaining", "")
            if remaining.isdigit() and int(remaining) == 0:
                reset = headers.get("x-ratelimit-reset", "")
                if reset.isdigit():
                    reset_time = int(reset)
                    now = int(time.time())
                    if reset_time > now:
                        wait = reset_time - now
                        self.current_rps = min(self.current_rps, 1.0 / max(wait, 1))

        elif status_code >= 500 and response_time_ms > 5000:
            # Server struggling — back off
            self.current_rps *= 0.7
            self._consecutive_ok = 0

        else:
            self._consecutive_ok += 1
            self._consecutive_throttle = 0

            # Slowly recover
            if self._consecutive_ok > 10:
                self.current_rps *= self.recovery_factor
                self._consecutive_ok = 0

        # Clamp
        self.current_rps = max(self.min_rps, min(self.max_rps, self.current_rps))

    def stats(self) -> Dict[str, Any]:
        return {
            "current_rps": round(self.current_rps, 2),
            "total_throttles": self._total_throttles,
            "consecutive_ok": self._consecutive_ok,
            "window_count": self._window_count,
        }


# ════════════════════════════════════════════════════════════════════════════════
# PARAMETER FUZZER — Web-specific
# ════════════════════════════════════════════════════════════════════════════════


class FuzzTarget(Enum):
    """O que esta sendo fuzzado."""

    URL_PATH = auto()
    QUERY_PARAM = auto()
    POST_BODY = auto()
    HEADER_VALUE = auto()
    COOKIE_VALUE = auto()
    JSON_FIELD = auto()
    XML_ELEMENT = auto()
    MULTIPART_FIELD = auto()
    GRAPHQL_VARIABLE = auto()


@dataclass
class FuzzPoint:
    """Um ponto especifico para fuzzing em um request."""

    target: FuzzTarget
    name: str  # parameter name / header name / path segment
    original_value: str
    url: str
    method: str = "GET"
    content_type: str = ""
    position: int = 0  # position within the request

    def build_request(self, fuzzed_value: str) -> Dict[str, Any]:
        """Constroi um request com o valor fuzzado no ponto correto."""
        if self.target == FuzzTarget.QUERY_PARAM:
            parsed = urllib.parse.urlparse(self.url)
            params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            params[self.name] = [fuzzed_value]
            new_query = urllib.parse.urlencode(params, doseq=True)
            new_url = parsed._replace(query=new_query).geturl()
            return {"url": new_url, "method": self.method}

        elif self.target == FuzzTarget.URL_PATH:
            parsed = urllib.parse.urlparse(self.url)
            path_parts = parsed.path.split("/")
            if self.position < len(path_parts):
                path_parts[self.position] = fuzzed_value
            new_path = "/".join(path_parts)
            new_url = parsed._replace(path=new_path).geturl()
            return {"url": new_url, "method": self.method}

        elif self.target == FuzzTarget.POST_BODY:
            return {
                "url": self.url,
                "method": "POST",
                "body": fuzzed_value,
                "content_type": self.content_type
                or "application/x-www-form-urlencoded",
            }

        elif self.target == FuzzTarget.HEADER_VALUE:
            return {
                "url": self.url,
                "method": self.method,
                "extra_headers": {self.name: fuzzed_value},
            }

        elif self.target == FuzzTarget.COOKIE_VALUE:
            return {
                "url": self.url,
                "method": self.method,
                "extra_headers": {"Cookie": f"{self.name}={fuzzed_value}"},
            }

        elif self.target == FuzzTarget.JSON_FIELD:
            try:
                body = json.loads(self.original_value)
                body = self._set_json_field(body, self.name, fuzzed_value)
                return {
                    "url": self.url,
                    "method": self.method or "POST",
                    "body": json.dumps(body),
                    "content_type": "application/json",
                }
            except (json.JSONDecodeError, ValueError):
                return {
                    "url": self.url,
                    "method": "POST",
                    "body": fuzzed_value,
                    "content_type": "application/json",
                }

        return {"url": self.url, "method": self.method, "body": fuzzed_value}

    def _set_json_field(self, obj: Any, field_path: str, value: str) -> Any:
        """Define um campo em um objeto JSON por path (e.g. 'user.name')."""
        parts = field_path.split(".")
        current = obj
        for part in parts[:-1]:
            if isinstance(current, dict) and part in current:
                current = current[part]
            elif isinstance(current, list):
                try:
                    idx = int(part)
                    current = current[idx]
                except (ValueError, IndexError):
                    return obj
            else:
                return obj
        if isinstance(current, dict):
            current[parts[-1]] = value
        return obj


class ParameterDiscovery:
    """Descobre pontos de fuzzing automaticamente a partir de requests/responses."""

    # Common parameter names to test even if not seen
    COMMON_PARAMS: List[str] = [
        "id",
        "user",
        "username",
        "email",
        "password",
        "token",
        "page",
        "limit",
        "offset",
        "search",
        "q",
        "query",
        "sort",
        "order",
        "filter",
        "type",
        "action",
        "cmd",
        "file",
        "path",
        "url",
        "redirect",
        "callback",
        "next",
        "debug",
        "test",
        "admin",
        "role",
        "key",
        "api_key",
        "format",
        "output",
        "lang",
        "locale",
        "template",
        "include",
        "require",
        "load",
        "import",
        "module",
    ]

    COMMON_HEADERS: List[str] = [
        "X-Forwarded-For",
        "X-Forwarded-Host",
        "X-Original-URL",
        "X-Rewrite-URL",
        "X-Custom-IP-Authorization",
        "X-Forwarded-Port",
        "X-Forwarded-Proto",
        "Origin",
        "Referer",
        "Accept",
        "Accept-Language",
        "Content-Type",
        "Authorization",
        "Cookie",
        "X-Requested-With",
        "X-HTTP-Method-Override",
        "If-Modified-Since",
        "If-None-Match",
    ]

    def discover(
        self,
        url: str,
        method: str = "GET",
        body: str = "",
        headers: Dict[str, str] = None,
    ) -> List[FuzzPoint]:
        """Descobre todos os pontos fuzzaveis em um request."""
        points = []
        headers = headers or {}

        # URL path segments
        parsed = urllib.parse.urlparse(url)
        path_parts = parsed.path.split("/")
        for i, part in enumerate(path_parts):
            if part and not part.startswith("."):
                points.append(
                    FuzzPoint(
                        target=FuzzTarget.URL_PATH,
                        name=f"path_{i}",
                        original_value=part,
                        url=url,
                        method=method,
                        position=i,
                    )
                )

        # Query parameters
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        for name, values in params.items():
            points.append(
                FuzzPoint(
                    target=FuzzTarget.QUERY_PARAM,
                    name=name,
                    original_value=values[0] if values else "",
                    url=url,
                    method=method,
                )
            )

        # Add common params not already present
        for param in self.COMMON_PARAMS[:15]:
            if param not in params:
                base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                new_params = dict(params)
                new_params[param] = ["FUZZ"]
                new_query = urllib.parse.urlencode(new_params, doseq=True)
                test_url = f"{base_url}?{new_query}"
                points.append(
                    FuzzPoint(
                        target=FuzzTarget.QUERY_PARAM,
                        name=param,
                        original_value="FUZZ",
                        url=test_url,
                        method=method,
                    )
                )

        # Body parameters
        if body:
            # JSON body
            try:
                obj = json.loads(body)
                json_fields = self._extract_json_fields(obj)
                for field_path, value in json_fields:
                    points.append(
                        FuzzPoint(
                            target=FuzzTarget.JSON_FIELD,
                            name=field_path,
                            original_value=body,
                            url=url,
                            method=method,
                            content_type="application/json",
                        )
                    )
            except (json.JSONDecodeError, ValueError):
                pass

            # URL-encoded body
            if "=" in body:
                body_params = urllib.parse.parse_qs(body, keep_blank_values=True)
                for name, values in body_params.items():
                    points.append(
                        FuzzPoint(
                            target=FuzzTarget.POST_BODY,
                            name=name,
                            original_value=values[0] if values else "",
                            url=url,
                            method=method or "POST",
                            content_type="application/x-www-form-urlencoded",
                        )
                    )

        # Headers
        for header in self.COMMON_HEADERS[:10]:
            points.append(
                FuzzPoint(
                    target=FuzzTarget.HEADER_VALUE,
                    name=header,
                    original_value=headers.get(header, ""),
                    url=url,
                    method=method,
                )
            )

        # Cookies
        cookie_header = headers.get("Cookie", "")
        if cookie_header:
            for cookie in cookie_header.split(";"):
                cookie = cookie.strip()
                if "=" in cookie:
                    name, value = cookie.split("=", 1)
                    points.append(
                        FuzzPoint(
                            target=FuzzTarget.COOKIE_VALUE,
                            name=name.strip(),
                            original_value=value.strip(),
                            url=url,
                            method=method,
                        )
                    )

        return points

    def _extract_json_fields(self, obj: Any, prefix: str = "") -> List[Tuple[str, Any]]:
        """Extrai todos os campos leaf de um JSON."""
        fields = []
        if isinstance(obj, dict):
            for key, value in obj.items():
                path = f"{prefix}.{key}" if prefix else key
                if isinstance(value, (dict, list)):
                    fields.extend(self._extract_json_fields(value, path))
                else:
                    fields.append((path, value))
        elif isinstance(obj, list):
            for i, item in enumerate(obj[:5]):
                path = f"{prefix}.{i}" if prefix else str(i)
                if isinstance(item, (dict, list)):
                    fields.extend(self._extract_json_fields(item, path))
                else:
                    fields.append((path, item))
        return fields


# ════════════════════════════════════════════════════════════════════════════════
# SIREN FUZZER — O Motor Principal
# ════════════════════════════════════════════════════════════════════════════════


@dataclass
class FuzzerConfig:
    """Configuracao do fuzzer."""

    target_url: str
    max_iterations: int = 10000
    max_time_seconds: float = 3600.0
    max_crashes: int = 100
    initial_rps: float = 50.0
    max_input_size: int = 1024 * 64  # 64KB
    corpus_dir: Optional[str] = None
    output_dir: str = "./fuzzer-output"
    seed_inputs: List[str] = field(default_factory=list)
    dictionary: List[str] = field(default_factory=list)
    methods: List[str] = field(default_factory=lambda: ["GET", "POST"])
    headers: Dict[str, str] = field(default_factory=dict)
    fuzz_headers: bool = True
    fuzz_cookies: bool = True
    fuzz_path: bool = True
    fuzz_params: bool = True
    fuzz_body: bool = True
    parallel_workers: int = 10
    save_all_responses: bool = False


@dataclass
class FuzzerStats:
    """Estatisticas do fuzzer."""

    total_iterations: int = 0
    total_crashes: int = 0
    unique_crashes: int = 0
    coverage_points: int = 0
    corpus_size: int = 0
    current_rps: float = 0.0
    elapsed_seconds: float = 0.0
    mutations_per_strategy: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_iterations": self.total_iterations,
            "total_crashes": self.total_crashes,
            "unique_crashes": self.unique_crashes,
            "coverage_points": self.coverage_points,
            "corpus_size": self.corpus_size,
            "current_rps": round(self.current_rps, 2),
            "elapsed_seconds": round(self.elapsed_seconds, 2),
            "execs_per_second": round(
                self.total_iterations / max(0.1, self.elapsed_seconds), 2
            ),
        }


class SirenFuzzer:
    """Motor de fuzzing inteligente do SIREN.

    Combina:
    - Mutacao genetica adaptativa (AFL-inspired)
    - Coverage-guided feedback (black-box via response analysis)
    - Grammar-aware fuzzing para protocolos web
    - Crash triage automatico com dedup
    - Rate limiting auto-calibrado
    - Corpus management com power scheduling

    Pipeline:
    1. Discovery: encontra pontos fuzzaveis
    2. Corpus: carrega/gera seeds iniciais
    3. Loop:
       a. Seleciona input do corpus
       b. Aplica mutacoes
       c. Envia request
       d. Analisa cobertura
       e. Triage crashes
       f. Adiciona inputs interessantes ao corpus
    4. Report: gera relatorio de crashes
    """

    def __init__(self, config: FuzzerConfig):
        self.config = config
        self.mutator = Mutator(
            dictionary=[d.encode() for d in config.dictionary],
            max_input_size=config.max_input_size,
        )
        self.corpus = Corpus(
            corpus_dir=Path(config.corpus_dir) if config.corpus_dir else None,
        )
        self.coverage = CoverageTracker()
        self.triager = CrashTriager()
        self.rate_limiter = AdaptiveRateLimiter(initial_rps=config.initial_rps)
        self.discovery = ParameterDiscovery()
        self._running = False
        self._start_time: float = 0
        self._stats = FuzzerStats()
        self._fuzz_points: List[FuzzPoint] = []

    async def run(
        self,
        send_request: Callable,
        progress_callback: Optional[Callable] = None,
    ) -> FuzzerStats:
        """Executa o fuzzer.

        Args:
            send_request: async function(url, method, headers, body) -> (status, body, headers, time_ms)
            progress_callback: optional callback(stats) chamado periodicamente
        """
        self._running = True
        self._start_time = time.time()

        # 1. Discovery
        self._fuzz_points = self.discovery.discover(
            self.config.target_url,
            headers=self.config.headers,
        )
        logger.info(f"Discovered {len(self._fuzz_points)} fuzz points")

        # 2. Seed corpus
        self._seed_corpus()

        # 3. Fuzz loop
        iteration = 0
        while self._should_continue(iteration):
            try:
                await self._fuzz_iteration(send_request, iteration)
                iteration += 1
                self._stats.total_iterations = iteration

                # Progress callback
                if progress_callback and iteration % 100 == 0:
                    self._update_stats()
                    progress_callback(self._stats)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Fuzzer error at iteration {iteration}: {e}")
                continue

        # 4. Save results
        self._save_results()
        self._update_stats()

        self._running = False
        return self._stats

    def stop(self):
        """Para o fuzzer."""
        self._running = False

    def _should_continue(self, iteration: int) -> bool:
        """Verifica se o fuzzer deve continuar."""
        if not self._running:
            return False
        if iteration >= self.config.max_iterations:
            return False
        elapsed = time.time() - self._start_time
        if elapsed >= self.config.max_time_seconds:
            return False
        if len(self.triager.crashes) >= self.config.max_crashes:
            return False
        return True

    def _seed_corpus(self):
        """Inicializa o corpus com seeds."""
        # User-provided seeds
        for seed in self.config.seed_inputs:
            self.corpus.add_seed(seed.encode("utf-8"), "user_seed")

        # Corpus directory
        if self.config.corpus_dir:
            self.corpus.add_seeds_from_dir(Path(self.config.corpus_dir))

        # Default seeds based on fuzz points
        if not self.corpus.entries:
            defaults = [
                b"test",
                b"1",
                b"admin",
                b"true",
                b"null",
                b'{"id":1}',
                b'{"test":"value"}',
                b"param1=value1&param2=value2",
                b"<root><item>test</item></root>",
                b"A" * 100,
                b"1" * 50,
            ]
            for seed in defaults:
                self.corpus.add_seed(seed, "default")

            # Seeds from fuzz points
            for point in self._fuzz_points[:20]:
                if point.original_value:
                    self.corpus.add_seed(
                        point.original_value.encode("utf-8"),
                        f"discovered:{point.name}",
                    )

    async def _fuzz_iteration(self, send_request: Callable, iteration: int):
        """Uma iteracao do fuzzer."""
        # Select input from corpus
        entries = self.corpus.select(1)
        if not entries:
            return

        entry = entries[0]

        # Select fuzz point
        if self._fuzz_points:
            fuzz_point = random.choice(self._fuzz_points)
        else:
            fuzz_point = FuzzPoint(
                target=FuzzTarget.QUERY_PARAM,
                name="fuzz",
                original_value="",
                url=self.config.target_url,
            )

        # Mutate
        mutations = self.mutator.mutate(entry.data, count=1)
        if not mutations:
            return

        mutation = mutations[0]
        fuzzed_value = mutation.mutated.decode("utf-8", errors="replace")

        # Build request
        req = fuzz_point.build_request(fuzzed_value)
        url = req.get("url", self.config.target_url)
        method = req.get("method", "GET")
        body = req.get("body", "")
        headers = dict(self.config.headers)
        if "extra_headers" in req:
            headers.update(req["extra_headers"])
        if "content_type" in req:
            headers["Content-Type"] = req["content_type"]

        # Rate limit
        await self.rate_limiter.acquire()

        # Send request
        try:
            status, resp_body, resp_headers, time_ms = await send_request(
                url, method, headers, body
            )
        except Exception as e:
            logger.debug(f"Request failed: {e}")
            return

        # Report to rate limiter
        self.rate_limiter.report_response(status, time_ms, resp_headers)

        # Track coverage
        cov_hash, is_new = self.coverage.track(
            status,
            resp_body,
            resp_headers,
            time_ms,
        )

        # Add to corpus if new coverage
        if is_new:
            self.corpus.add_if_interesting(
                mutation.mutated,
                cov_hash,
                time_ms,
                f"mutation:{mutation.strategy.name}",
            )
            # Boost the strategy that found something
            self.mutator.boost_strategy(mutation.strategy)

        # Crash triage
        crash = self.triager.analyze(
            mutation.mutated,
            status,
            resp_body,
            resp_headers,
            time_ms,
            mutation,
            url,
            method,
        )
        if crash:
            self._stats.total_crashes += 1
            self._stats.unique_crashes = len(self.triager.crashes)
            self.corpus.mark_crash(entry.id)
            logger.warning(
                f"CRASH [{crash.severity.value.upper()}] "
                f"{crash.crash_id} — {crash.mutation_description}"
            )

    def _save_results(self):
        """Salva resultados do fuzzing."""
        output_dir = Path(self.config.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        # Crashes
        self.triager.save_crashes(output_dir / "crashes")

        # Corpus
        self.corpus.save(output_dir / "corpus")

        # Stats
        self._update_stats()
        stats_file = output_dir / "fuzzer_stats.json"
        stats_file.write_text(
            json.dumps(
                {
                    "config": {
                        "target": self.config.target_url,
                        "max_iterations": self.config.max_iterations,
                        "max_time": self.config.max_time_seconds,
                    },
                    "stats": self._stats.to_dict(),
                    "coverage": self.coverage.stats(),
                    "corpus": self.corpus.stats(),
                    "crashes": self.triager.stats(),
                    "rate_limiter": self.rate_limiter.stats(),
                },
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

        # Fuzz points
        points_file = output_dir / "fuzz_points.json"
        points_file.write_text(
            json.dumps(
                [
                    {
                        "target": p.target.name,
                        "name": p.name,
                        "original_value": p.original_value[:100],
                        "url": p.url,
                        "method": p.method,
                    }
                    for p in self._fuzz_points
                ],
                indent=2,
            ),
            encoding="utf-8",
        )

    def _update_stats(self):
        """Atualiza estatisticas."""
        self._stats.elapsed_seconds = time.time() - self._start_time
        self._stats.coverage_points = len(self.coverage._points)
        self._stats.corpus_size = len(self.corpus.entries)
        self._stats.current_rps = self.rate_limiter.current_rps


# ════════════════════════════════════════════════════════════════════════════════
# GRAMMAR FUZZER — Protocol-aware fuzzing
# ════════════════════════════════════════════════════════════════════════════════


class GrammarRule:
    """Uma regra de grammar para fuzzing baseado em gramatica."""

    def __init__(self, name: str, productions: List[Union[str, List[str]]]):
        self.name = name
        self.productions = productions

    def expand(self, depth: int = 0, max_depth: int = 10) -> str:
        """Expande esta regra recursivamente."""
        if depth >= max_depth:
            # Return shortest terminal production
            terminals = [
                p for p in self.productions if isinstance(p, str) and "<" not in p
            ]
            return random.choice(terminals) if terminals else ""
        prod = random.choice(self.productions)
        if isinstance(prod, str):
            return prod
        return "".join(prod)


class GrammarFuzzer:
    """Fuzzer baseado em gramatica para protocolos especificos.

    Gera inputs sintaticamente validos mas semanticamente maliciosos.
    """

    # Pre-built grammars
    HTTP_REQUEST_GRAMMAR: Dict[str, List[str]] = {
        "<request>": [
            "<method> <path> HTTP/<version>\r\n<headers>\r\n<body>",
        ],
        "<method>": HTTP_METHODS,
        "<path>": [
            "/",
            "/api/v1/users",
            "/admin",
            "/login",
            "/<path_segment>/<path_segment>",
            "/<path_segment>?<query>",
            "/<traversal>",
        ],
        "<path_segment>": [
            "api",
            "v1",
            "v2",
            "users",
            "admin",
            "login",
            "search",
            "test",
            "debug",
            "config",
            "internal",
            "<injection>",
        ],
        "<traversal>": PATH_TRAVERSALS,
        "<query>": [
            "<param>=<value>",
            "<param>=<value>&<param>=<value>",
            "<param>=<injection>",
        ],
        "<param>": [
            "id",
            "user",
            "q",
            "search",
            "page",
            "cmd",
            "file",
            "url",
            "path",
            "debug",
            "admin",
        ],
        "<value>": [
            "1",
            "test",
            "admin",
            "true",
            "<injection>",
        ],
        "<injection>": [
            "' OR '1'='1",
            '" OR "1"="1"',
            "<script>alert(1)</script>",
            "{{7*7}}",
            "${7*7}",
            "../../../etc/passwd",
            "|id",
            "`id`",
            "$(id)",
            "%0d%0aInjected: true",
        ],
        "<version>": ["1.0", "1.1", "2.0", "0.9", "3.0", "9.9"],
        "<headers>": [
            "Host: target.com\r\n",
            "Host: target.com\r\nContent-Type: <content_type>\r\n",
            "Host: target.com\r\n<injection_header>\r\n",
        ],
        "<content_type>": CONTENT_TYPES,
        "<injection_header>": [
            "X-Forwarded-For: 127.0.0.1",
            "X-Forwarded-For: <injection>",
            "X-Original-URL: /admin",
            "X-Rewrite-URL: /admin",
            "Transfer-Encoding: chunked",
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity",
            "Content-Length: 0\r\nTransfer-Encoding: chunked",
        ],
        "<body>": ["", "<query>", "<json_body>"],
        "<json_body>": [
            '{"id":1}',
            '{"user":"<injection>"}',
            '{"__proto__":{"admin":true}}',
            '{"constructor":{"prototype":{"admin":true}}}',
        ],
    }

    JSON_GRAMMAR: Dict[str, List[str]] = {
        "<json>": ["<object>", "<array>"],
        "<object>": [
            "{}",
            '{"<key>":<value>}',
            '{"<key>":<value>,"<key>":<value>}',
            '{"<key>":<value>,"<key>":<value>,"<key>":<value>}',
        ],
        "<array>": [
            "[]",
            "[<value>]",
            "[<value>,<value>]",
            "[<value>,<value>,<value>,<value>,<value>]",
        ],
        "<key>": [
            "id",
            "name",
            "email",
            "password",
            "role",
            "admin",
            "user",
            "data",
            "query",
            "cmd",
            "file",
            "url",
            "__proto__",
            "constructor",
            "prototype",
            "$where",
            "$gt",
            "$ne",
            "$regex",
        ],
        "<value>": [
            "<string>",
            "<number>",
            "true",
            "false",
            "null",
            "<object>",
            "<array>",
        ],
        "<string>": [
            '"test"',
            '"admin"',
            '"<injection>"',
            '""',
            '"A"',
            '"' + "A" * 10000 + '"',
        ],
        "<number>": [str(n) for n in BOUNDARY_INTS[:15]],
        "<injection>": [
            "' OR '1'='1",
            "{{7*7}}",
            "${7*7}",
            "<script>alert(1)</script>",
            "../../../etc/passwd",
            "|id",
        ],
    }

    def __init__(self, grammar: Optional[Dict[str, List[str]]] = None):
        self.grammar = grammar or self.HTTP_REQUEST_GRAMMAR
        self._cache: Dict[str, List[str]] = {}

    def generate(self, start: str = "<request>", max_depth: int = 15) -> str:
        """Gera um input a partir da gramatica."""
        return self._expand(start, 0, max_depth)

    def generate_batch(self, count: int, start: str = "<request>") -> List[str]:
        """Gera multiplos inputs."""
        return [self.generate(start) for _ in range(count)]

    def _expand(self, symbol: str, depth: int, max_depth: int) -> str:
        if depth >= max_depth:
            return self._shortest_terminal(symbol)

        # Check if it's a non-terminal
        if symbol.startswith("<") and symbol.endswith(">"):
            productions = self.grammar.get(symbol, [symbol[1:-1]])
            production = random.choice(productions)
            # Recursively expand non-terminals in the production
            result = []
            i = 0
            while i < len(production):
                if production[i] == "<":
                    end = production.find(">", i)
                    if end != -1:
                        nt = production[i : end + 1]
                        result.append(self._expand(nt, depth + 1, max_depth))
                        i = end + 1
                    else:
                        result.append(production[i])
                        i += 1
                else:
                    result.append(production[i])
                    i += 1
            return "".join(result)
        return symbol

    def _shortest_terminal(self, symbol: str) -> str:
        """Retorna a producao terminal mais curta."""
        if symbol not in self.grammar:
            return symbol.strip("<>")
        productions = self.grammar[symbol]
        terminals = [p for p in productions if "<" not in p]
        if terminals:
            return min(terminals, key=len)
        return ""


# ════════════════════════════════════════════════════════════════════════════════
# DIFFERENTIAL FUZZER
# ════════════════════════════════════════════════════════════════════════════════


@dataclass
class DiffResult:
    """Resultado de fuzzing diferencial."""

    input_data: bytes
    responses: Dict[str, Tuple[int, str, float]]  # endpoint -> (status, body, time)
    differences: List[str]
    severity: str = "info"

    @property
    def has_differences(self) -> bool:
        return len(self.differences) > 0


class DifferentialFuzzer:
    """Fuzzer diferencial — compara respostas entre endpoints/versoes.

    Util para:
    - Comparar API v1 vs v2
    - Detectar inconsistencias de autorizacao
    - Encontrar endpoints com comportamento diferente
    - WAF bypass detection (com/sem headers)
    """

    def __init__(self, endpoints: List[str]):
        self.endpoints = endpoints
        self.results: List[DiffResult] = []

    async def fuzz(
        self,
        inputs: List[bytes],
        send_request: Callable,
    ) -> List[DiffResult]:
        """Envia cada input para todos os endpoints e compara."""
        for input_data in inputs:
            fuzzed_value = input_data.decode("utf-8", errors="replace")
            responses: Dict[str, Tuple[int, str, float]] = {}

            for endpoint in self.endpoints:
                try:
                    url = endpoint
                    if "?" in url:
                        url += f"&fuzz={urllib.parse.quote(fuzzed_value)}"
                    else:
                        url += f"?fuzz={urllib.parse.quote(fuzzed_value)}"

                    status, body, headers, time_ms = await send_request(
                        url, "GET", {}, ""
                    )
                    responses[endpoint] = (status, body[:1000], time_ms)
                except Exception:
                    responses[endpoint] = (-1, "error", 0)

            # Compare
            differences = self._compare(responses)
            if differences:
                result = DiffResult(
                    input_data=input_data,
                    responses=responses,
                    differences=differences,
                    severity=self._classify_diff(differences),
                )
                self.results.append(result)

        return self.results

    def _compare(self, responses: Dict[str, Tuple[int, str, float]]) -> List[str]:
        """Compara respostas entre endpoints."""
        diffs = []
        endpoints = list(responses.keys())

        for i in range(len(endpoints)):
            for j in range(i + 1, len(endpoints)):
                e1, e2 = endpoints[i], endpoints[j]
                r1, r2 = responses[e1], responses[e2]

                # Status code difference
                if r1[0] != r2[0]:
                    diffs.append(f"Status diff: {e1}={r1[0]} vs {e2}={r2[0]}")

                # Response size difference (>50%)
                s1, s2 = len(r1[1]), len(r2[1])
                if s1 > 0 and s2 > 0:
                    ratio = max(s1, s2) / min(s1, s2)
                    if ratio > 1.5:
                        diffs.append(
                            f"Size diff: {e1}={s1}B vs {e2}={s2}B (ratio={ratio:.1f})"
                        )

                # Timing difference (>3x)
                t1, t2 = r1[2], r2[2]
                if t1 > 0 and t2 > 0:
                    t_ratio = max(t1, t2) / max(min(t1, t2), 0.1)
                    if t_ratio > 3.0:
                        diffs.append(f"Time diff: {e1}={t1:.0f}ms vs {e2}={t2:.0f}ms")

                # Auth difference (one 200, other 403/401)
                if (r1[0] == 200 and r2[0] in (401, 403)) or (
                    r2[0] == 200 and r1[0] in (401, 403)
                ):
                    diffs.append(f"AUTH BYPASS: {e1}={r1[0]} vs {e2}={r2[0]}")

        return diffs

    def _classify_diff(self, differences: List[str]) -> str:
        """Classifica severidade das diferencas."""
        for diff in differences:
            if "AUTH BYPASS" in diff:
                return "critical"
            if "Status diff" in diff and ("500" in diff or "200" in diff):
                return "high"
        if any("Time diff" in d for d in differences):
            return "medium"
        return "low"


# ════════════════════════════════════════════════════════════════════════════════
# WORDLIST GENERATOR
# ════════════════════════════════════════════════════════════════════════════════


class WordlistGenerator:
    """Gera wordlists personalizadas para fuzzing."""

    @staticmethod
    def from_url(url: str) -> List[str]:
        """Gera wordlist baseada na URL do target."""
        parsed = urllib.parse.urlparse(url)
        words = set()

        # Domain parts
        domain = parsed.hostname or ""
        for part in domain.split("."):
            if part and part not in ("www", "com", "org", "net", "io"):
                words.add(part)
                words.add(part.lower())
                words.add(part.upper())

        # Path parts
        for part in parsed.path.split("/"):
            if part:
                words.add(part)
                # Variations
                words.add(part + "s")
                words.add(part + "es")
                words.add(part.rstrip("s"))
                words.add(part + "_old")
                words.add(part + "_backup")
                words.add(part + "_test")
                words.add(part + "_admin")
                words.add(part + "_api")
                words.add(part + ".bak")
                words.add(part + ".old")
                words.add(part + "~")
                words.add("." + part)

        # Common extensions
        for word in list(words):
            words.add(word + ".json")
            words.add(word + ".xml")
            words.add(word + ".yaml")
            words.add(word + ".yml")

        # Standard discovery words
        standard = [
            "admin",
            "api",
            "v1",
            "v2",
            "v3",
            "internal",
            "debug",
            "test",
            "staging",
            "dev",
            "backup",
            "old",
            "login",
            "register",
            "config",
            "settings",
            "users",
            "user",
            "profile",
            "dashboard",
            "panel",
            "console",
            "graphql",
            "swagger",
            "docs",
            "health",
            "status",
            "metrics",
            "actuator",
            "env",
            "info",
            ".env",
            ".git",
            ".svn",
            ".htaccess",
            "robots.txt",
            "sitemap.xml",
            "crossdomain.xml",
            "security.txt",
            "wp-admin",
            "wp-login",
            "wp-config.php",
            "server-status",
            "server-info",
            "phpinfo.php",
            "info.php",
            "test.php",
        ]
        words.update(standard)

        return sorted(words)

    @staticmethod
    def numbers(start: int = 0, end: int = 10000, step: int = 1) -> List[str]:
        """Gera range de numeros."""
        return [str(i) for i in range(start, end, step)]

    @staticmethod
    def permutations(base: str, suffixes: Optional[List[str]] = None) -> List[str]:
        """Gera permutacoes de uma palavra base."""
        suffixes = suffixes or [
            "",
            "s",
            "es",
            "1",
            "2",
            "123",
            "_old",
            "_new",
            "_test",
            "_backup",
            "_dev",
            "_staging",
            "_admin",
            "_api",
            ".bak",
            ".old",
            ".tmp",
            "~",
            ".swp",
        ]
        words = []
        for suffix in suffixes:
            words.append(base + suffix)
            words.append(base.upper() + suffix)
            words.append(base.capitalize() + suffix)
        return words

    @staticmethod
    def cewl_like(text: str, min_length: int = 3, max_length: int = 30) -> List[str]:
        """Extrai palavras unicas de um texto (CeWL-style)."""
        words = set()
        # Extract words
        for match in re.finditer(r"[a-zA-Z][a-zA-Z0-9_-]*", text):
            word = match.group()
            if min_length <= len(word) <= max_length:
                words.add(word.lower())
        # Extract emails
        for match in re.finditer(r"[\w.+-]+@[\w-]+\.[\w.-]+", text):
            parts = match.group().split("@")
            words.add(parts[0])
            words.update(parts[1].split("."))
        return sorted(words)
