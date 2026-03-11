#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  🌐  SIREN NETWORK ENGINE — Async HTTP Warfare Infrastructure  🌐             ██
██                                                                                ██
██  Modulo de rede completo para o SIREN (Shannon Intelligence Recon &            ██
██  Exploitation Nexus). Todo scan, recon, exploit e fuzzing passa por aqui.      ██
██                                                                                ██
██  Features:                                                                     ██
██    • Async HTTP client (aiohttp) com session management                       ██
██    • Proxy chain & rotation (HTTP/SOCKS4/SOCKS5)                              ██
██    • Rate limiting adaptativo (respeita 429/503)                               ██
██    • Cookie jar persistente                                                    ██
██    • Request/Response interception & modification                              ██
██    • TLS fingerprint analysis                                                  ██
██    • WebSocket client                                                          ██
██    • DNS resolution & caching                                                  ██
██    • Retry com backoff exponencial                                             ██
██    • Request queue com prioridades                                             ██
██    • Response caching (deduplicacao inteligente)                                ██
██    • HAR (HTTP Archive) export                                                 ██
██    • Certificate chain extraction                                              ██
██                                                                                ██
██  "A rede e o sistema nervoso do predador. Cada pacote, um impulso."           ██
██                                                                                ██
████████████████████████████████████████████████████████████████████████████████████
"""

from __future__ import annotations

import asyncio
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
import urllib.parse
from collections import OrderedDict, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from io import BytesIO
from pathlib import Path
from typing import (
    Any,
    AsyncIterator,
    Awaitable,
    Callable,
    Deque,
    Dict,
    List,
    Optional,
    Set,
    Tuple,
    Union,
)

logger = logging.getLogger("siren.network")


# ════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════════════════════════

DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
]

COMMON_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Cache-Control": "max-age=0",
}

SEC_HEADERS_TO_CHECK = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Cross-Origin-Embedder-Policy",
]


# ════════════════════════════════════════════════════════════════════════════
# ENUMS
# ════════════════════════════════════════════════════════════════════════════


class ProxyType(enum.Enum):
    HTTP = "http"
    HTTPS = "https"
    SOCKS4 = "socks4"
    SOCKS5 = "socks5"


class RequestPriority(enum.Enum):
    CRITICAL = 0
    HIGH = 1
    NORMAL = 2
    LOW = 3
    BACKGROUND = 4


class AuthType(enum.Enum):
    NONE = "none"
    BASIC = "basic"
    BEARER = "bearer"
    DIGEST = "digest"
    NTLM = "ntlm"
    COOKIE = "cookie"
    CUSTOM = "custom"


# ════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ════════════════════════════════════════════════════════════════════════════


@dataclass
class ProxyConfig:
    """Configuracao de proxy individual."""

    host: str
    port: int
    proxy_type: ProxyType = ProxyType.HTTP
    username: Optional[str] = None
    password: Optional[str] = None
    alive: bool = True
    last_check: float = 0.0
    response_time_ms: float = 0.0
    fail_count: int = 0

    @property
    def url(self) -> str:
        auth = ""
        if self.username and self.password:
            auth = f"{self.username}:{self.password}@"
        return f"{self.proxy_type.value}://{auth}{self.host}:{self.port}"

    def mark_failed(self) -> None:
        self.fail_count += 1
        if self.fail_count >= 3:
            self.alive = False

    def mark_success(self, response_time_ms: float) -> None:
        self.fail_count = 0
        self.alive = True
        self.response_time_ms = response_time_ms
        self.last_check = time.time()


@dataclass
class RequestConfig:
    """Configuracao de uma request individual."""

    url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    params: Dict[str, str] = field(default_factory=dict)
    data: Optional[Union[str, bytes, dict]] = None
    json_data: Optional[dict] = None
    cookies: Dict[str, str] = field(default_factory=dict)
    timeout: float = 30.0
    allow_redirects: bool = True
    max_redirects: int = 10
    verify_ssl: bool = False
    proxy: Optional[ProxyConfig] = None
    priority: RequestPriority = RequestPriority.NORMAL
    retries: int = 3
    retry_delay: float = 1.0
    auth: Optional[Tuple[str, str]] = None
    auth_type: AuthType = AuthType.NONE
    bearer_token: Optional[str] = None
    raw_body: Optional[bytes] = None
    content_type: Optional[str] = None
    tag: str = ""  # For tracking/grouping requests


@dataclass
class ResponseData:
    """Dados de resposta HTTP estruturados."""

    url: str
    status_code: int
    headers: Dict[str, str]
    body: bytes
    text: str
    elapsed_ms: float
    redirect_history: List[str] = field(default_factory=list)
    cookies: Dict[str, str] = field(default_factory=dict)
    content_type: str = ""
    content_length: int = 0
    encoding: str = "utf-8"
    is_json: bool = False
    is_html: bool = False
    is_xml: bool = False
    cert_info: Optional[Dict[str, Any]] = None
    request_tag: str = ""
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 400

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300

    @property
    def is_redirect(self) -> bool:
        return 300 <= self.status_code < 400

    @property
    def is_client_error(self) -> bool:
        return 400 <= self.status_code < 500

    @property
    def is_server_error(self) -> bool:
        return self.status_code >= 500

    @property
    def json(self) -> Optional[dict]:
        if self.is_json:
            try:
                return json.loads(self.text)
            except (json.JSONDecodeError, ValueError):
                return None
        return None

    @property
    def title(self) -> Optional[str]:
        """Extrai <title> do HTML."""
        if not self.is_html:
            return None
        match = re.search(
            r"<title[^>]*>(.*?)</title>", self.text, re.IGNORECASE | re.DOTALL
        )
        return match.group(1).strip() if match else None

    def header(self, name: str, default: str = "") -> str:
        """Busca header case-insensitive."""
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return default

    @property
    def security_headers(self) -> Dict[str, Optional[str]]:
        """Analisa headers de seguranca."""
        result: Dict[str, Optional[str]] = {}
        for h in SEC_HEADERS_TO_CHECK:
            result[h] = self.header(h) or None
        return result

    @property
    def missing_security_headers(self) -> List[str]:
        """Retorna headers de seguranca ausentes."""
        return [h for h, v in self.security_headers.items() if v is None]

    @property
    def server(self) -> Optional[str]:
        return self.header("Server") or None

    @property
    def powered_by(self) -> Optional[str]:
        return self.header("X-Powered-By") or None

    @property
    def body_hash(self) -> str:
        return hashlib.sha256(self.body).hexdigest()

    @property
    def body_size(self) -> int:
        return len(self.body)

    def contains(self, pattern: str, case_sensitive: bool = False) -> bool:
        """Verifica se o body contem um padrao."""
        if case_sensitive:
            return pattern in self.text
        return pattern.lower() in self.text.lower()

    def regex_search(self, pattern: str, flags: int = re.IGNORECASE) -> List[str]:
        """Busca regex no body, retorna todos os matches."""
        return re.findall(pattern, self.text, flags)

    def extract_links(self) -> List[str]:
        """Extrai todos os links do HTML."""
        if not self.is_html:
            return []
        patterns = [
            r'href=["\']([^"\']+)["\']',
            r'src=["\']([^"\']+)["\']',
            r'action=["\']([^"\']+)["\']',
        ]
        links: List[str] = []
        for p in patterns:
            links.extend(re.findall(p, self.text, re.IGNORECASE))
        return list(set(links))

    def extract_forms(self) -> List[Dict[str, Any]]:
        """Extrai formularios HTML."""
        if not self.is_html:
            return []
        forms: List[Dict[str, Any]] = []
        form_pattern = re.compile(
            r"<form([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL
        )
        input_pattern = re.compile(r"<input([^>]*)>", re.IGNORECASE)
        select_pattern = re.compile(
            r"<select([^>]*)>.*?</select>", re.IGNORECASE | re.DOTALL
        )
        textarea_pattern = re.compile(r"<textarea([^>]*)>", re.IGNORECASE)

        for form_match in form_pattern.finditer(self.text):
            attrs_str = form_match.group(1)
            form_body = form_match.group(2)

            form: Dict[str, Any] = {
                "action": _extract_attr(attrs_str, "action") or "",
                "method": (_extract_attr(attrs_str, "method") or "GET").upper(),
                "enctype": _extract_attr(attrs_str, "enctype")
                or "application/x-www-form-urlencoded",
                "id": _extract_attr(attrs_str, "id") or "",
                "class": _extract_attr(attrs_str, "class") or "",
                "inputs": [],
            }

            for inp in input_pattern.finditer(form_body):
                inp_attrs = inp.group(1)
                form["inputs"].append(
                    {
                        "name": _extract_attr(inp_attrs, "name") or "",
                        "type": (_extract_attr(inp_attrs, "type") or "text").lower(),
                        "value": _extract_attr(inp_attrs, "value") or "",
                        "id": _extract_attr(inp_attrs, "id") or "",
                        "required": "required" in inp_attrs.lower(),
                        "placeholder": _extract_attr(inp_attrs, "placeholder") or "",
                    }
                )

            for sel in select_pattern.finditer(form_body):
                sel_attrs = sel.group(1)
                form["inputs"].append(
                    {
                        "name": _extract_attr(sel_attrs, "name") or "",
                        "type": "select",
                        "value": "",
                        "id": _extract_attr(sel_attrs, "id") or "",
                        "required": "required" in sel_attrs.lower(),
                        "placeholder": "",
                    }
                )

            for ta in textarea_pattern.finditer(form_body):
                ta_attrs = ta.group(1)
                form["inputs"].append(
                    {
                        "name": _extract_attr(ta_attrs, "name") or "",
                        "type": "textarea",
                        "value": "",
                        "id": _extract_attr(ta_attrs, "id") or "",
                        "required": "required" in ta_attrs.lower(),
                        "placeholder": _extract_attr(ta_attrs, "placeholder") or "",
                    }
                )

            forms.append(form)

        return forms

    def extract_comments(self) -> List[str]:
        """Extrai comentarios HTML."""
        if not self.is_html:
            return []
        return re.findall(r"<!--(.*?)-->", self.text, re.DOTALL)

    def extract_scripts(self) -> List[Dict[str, str]]:
        """Extrai scripts inline e externos."""
        if not self.is_html:
            return []
        scripts: List[Dict[str, str]] = []
        pattern = re.compile(
            r"<script([^>]*)>(.*?)</script>", re.IGNORECASE | re.DOTALL
        )
        for match in pattern.finditer(self.text):
            attrs = match.group(1)
            content = match.group(2).strip()
            scripts.append(
                {
                    "src": _extract_attr(attrs, "src") or "",
                    "type": _extract_attr(attrs, "type") or "text/javascript",
                    "content": content[:500] if content else "",
                    "inline": bool(content),
                    "integrity": _extract_attr(attrs, "integrity") or "",
                    "crossorigin": _extract_attr(attrs, "crossorigin") or "",
                }
            )
        return scripts

    def extract_meta_tags(self) -> List[Dict[str, str]]:
        """Extrai meta tags."""
        if not self.is_html:
            return []
        tags: List[Dict[str, str]] = []
        pattern = re.compile(r"<meta([^>]*)>", re.IGNORECASE)
        for match in pattern.finditer(self.text):
            attrs = match.group(1)
            tags.append(
                {
                    "name": _extract_attr(attrs, "name") or "",
                    "content": _extract_attr(attrs, "content") or "",
                    "property": _extract_attr(attrs, "property") or "",
                    "http-equiv": _extract_attr(attrs, "http-equiv") or "",
                    "charset": _extract_attr(attrs, "charset") or "",
                }
            )
        return tags

    def extract_emails(self) -> List[str]:
        """Extrai enderecos de email."""
        return list(
            set(
                re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", self.text)
            )
        )

    def extract_api_keys(self) -> List[Dict[str, str]]:
        """Tenta identificar chaves de API expostas (regex heuristics)."""
        patterns = {
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "AWS Secret Key": r"[0-9a-zA-Z/+]{40}",
            "Google API Key": r"AIza[0-9A-Za-z_-]{35}",
            "GitHub Token": r"gh[ps]_[0-9a-zA-Z]{36}",
            "Slack Token": r"xox[baprs]-[0-9a-zA-Z-]+",
            "Stripe Key": r"sk_live_[0-9a-zA-Z]{24,}",
            "JWT Token": r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
            "Private Key": r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
            "Generic API Key": r'(?:api[_-]?key|apikey|api_secret|access_token)\s*[=:]\s*["\']([a-zA-Z0-9_-]{20,})["\']',
            "Bearer Token": r"[Bb]earer\s+[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
        }
        findings: List[Dict[str, str]] = []
        for name, pattern in patterns.items():
            matches = re.findall(pattern, self.text)
            for m in matches:
                findings.append(
                    {"type": name, "value": m[:50] + "..." if len(m) > 50 else m}
                )
        return findings

    def to_har_entry(self) -> dict:
        """Converte para formato HAR entry."""
        return {
            "startedDateTime": datetime.now().isoformat(),
            "time": self.elapsed_ms,
            "request": {
                "method": "GET",
                "url": self.url,
                "httpVersion": "HTTP/1.1",
                "headers": [{"name": k, "value": v} for k, v in self.headers.items()],
                "queryString": [],
                "cookies": [{"name": k, "value": v} for k, v in self.cookies.items()],
                "headersSize": -1,
                "bodySize": 0,
            },
            "response": {
                "status": self.status_code,
                "statusText": "",
                "httpVersion": "HTTP/1.1",
                "headers": [{"name": k, "value": v} for k, v in self.headers.items()],
                "content": {
                    "size": self.body_size,
                    "mimeType": self.content_type,
                    "text": self.text[:10000] if len(self.text) > 10000 else self.text,
                },
                "cookies": [],
                "headersSize": -1,
                "bodySize": self.body_size,
                "redirectURL": "",
            },
            "cache": {},
            "timings": {
                "send": 0,
                "wait": self.elapsed_ms,
                "receive": 0,
            },
        }


# ════════════════════════════════════════════════════════════════════════════
# RATE LIMITER — Rate limiting adaptativo
# ════════════════════════════════════════════════════════════════════════════


class AdaptiveRateLimiter:
    """Rate limiter adaptativo que respeita respostas do servidor.

    Ajusta automaticamente o rate quando recebe 429 (Too Many Requests)
    ou 503 (Service Unavailable). Usa token bucket algorithm.
    """

    def __init__(
        self,
        requests_per_second: float = 10.0,
        burst_size: int = 20,
        min_rps: float = 0.5,
        max_rps: float = 100.0,
        backoff_factor: float = 0.5,
        recovery_factor: float = 1.1,
    ):
        self.rps = requests_per_second
        self.burst_size = burst_size
        self.min_rps = min_rps
        self.max_rps = max_rps
        self.backoff_factor = backoff_factor
        self.recovery_factor = recovery_factor
        self._tokens = float(burst_size)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()
        self._total_requests = 0
        self._throttled_count = 0
        self._domain_limiters: Dict[str, float] = {}

    async def acquire(self, domain: str = "") -> None:
        """Aguarda ate que um token esteja disponivel."""
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(
                self.burst_size,
                self._tokens + elapsed * self.rps,
            )
            self._last_refill = now

            if self._tokens < 1.0:
                wait_time = (1.0 - self._tokens) / self.rps
                self._throttled_count += 1
                await asyncio.sleep(wait_time)
                self._tokens = 0.0
            else:
                self._tokens -= 1.0

            # Domain-specific delay
            if domain and domain in self._domain_limiters:
                domain_delay = self._domain_limiters[domain]
                if domain_delay > 0:
                    await asyncio.sleep(domain_delay)

            self._total_requests += 1

    def on_response(
        self, status_code: int, domain: str = "", retry_after: Optional[float] = None
    ) -> None:
        """Ajusta rate baseado na resposta do servidor."""
        if status_code == 429 or status_code == 503:
            # Backoff
            self.rps = max(self.min_rps, self.rps * self.backoff_factor)
            if domain:
                current = self._domain_limiters.get(domain, 0.0)
                self._domain_limiters[domain] = min(30.0, current + 1.0)
            if retry_after:
                # Respect Retry-After header
                if domain:
                    self._domain_limiters[domain] = retry_after
            logger.warning(f"Rate limited on {domain}. Adjusted RPS to {self.rps:.1f}")
        elif 200 <= status_code < 400:
            # Gradual recovery
            self.rps = min(self.max_rps, self.rps * self.recovery_factor)
            if domain:
                current = self._domain_limiters.get(domain, 0.0)
                if current > 0:
                    self._domain_limiters[domain] = max(0.0, current - 0.1)

    @property
    def stats(self) -> Dict[str, Any]:
        return {
            "current_rps": round(self.rps, 2),
            "total_requests": self._total_requests,
            "throttled": self._throttled_count,
            "domain_delays": dict(self._domain_limiters),
        }


# ════════════════════════════════════════════════════════════════════════════
# RESPONSE CACHE — Cache de respostas para deduplicacao
# ════════════════════════════════════════════════════════════════════════════


class ResponseCache:
    """Cache LRU de respostas HTTP.

    Evita requests duplicados para o mesmo recurso,
    respeitando headers Cache-Control e TTL customizado.
    """

    def __init__(self, max_size: int = 1000, default_ttl: float = 300.0):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self._cache: OrderedDict[str, Tuple[ResponseData, float]] = OrderedDict()
        self._hits = 0
        self._misses = 0

    def _make_key(self, method: str, url: str, body_hash: str = "") -> str:
        """Gera chave de cache."""
        raw = f"{method.upper()}::{url}::{body_hash}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def get(self, method: str, url: str, body_hash: str = "") -> Optional[ResponseData]:
        """Busca resposta do cache."""
        key = self._make_key(method, url, body_hash)
        if key in self._cache:
            response, expires = self._cache[key]
            if time.time() < expires:
                self._cache.move_to_end(key)
                self._hits += 1
                return response
            else:
                del self._cache[key]
        self._misses += 1
        return None

    def put(
        self,
        method: str,
        url: str,
        response: ResponseData,
        ttl: Optional[float] = None,
        body_hash: str = "",
    ) -> None:
        """Adiciona resposta ao cache."""
        if not response.is_success:
            return  # Don't cache errors

        key = self._make_key(method, url, body_hash)
        expires = time.time() + (ttl or self.default_ttl)

        # Check Cache-Control
        cc = response.header("Cache-Control")
        if cc:
            if "no-store" in cc or "no-cache" in cc:
                return
            max_age_match = re.search(r"max-age=(\d+)", cc)
            if max_age_match:
                expires = time.time() + int(max_age_match.group(1))

        self._cache[key] = (response, expires)

        # Evict if over capacity
        while len(self._cache) > self.max_size:
            self._cache.popitem(last=False)

    def clear(self) -> None:
        self._cache.clear()

    @property
    def stats(self) -> Dict[str, Any]:
        hit_rate = self._hits / max(1, self._hits + self._misses) * 100
        return {
            "size": len(self._cache),
            "max_size": self.max_size,
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": f"{hit_rate:.1f}%",
        }


# ════════════════════════════════════════════════════════════════════════════
# PROXY ROTATOR — Rotacao inteligente de proxies
# ════════════════════════════════════════════════════════════════════════════


class ProxyRotator:
    """Roteador de proxies com health checking e rotacao automatica.

    Suporta HTTP, HTTPS, SOCKS4 e SOCKS5. Faz health check periodico,
    remove proxies mortos, e rotaciona entre os vivos usando weighted random.
    """

    def __init__(self, proxies: Optional[List[ProxyConfig]] = None):
        self._proxies: List[ProxyConfig] = proxies or []
        self._index = 0
        self._lock = asyncio.Lock()

    def add(self, proxy: ProxyConfig) -> None:
        self._proxies.append(proxy)

    def add_from_string(self, proxy_str: str) -> None:
        """Adiciona proxy de string. Formato: type://user:pass@host:port"""
        parsed = urllib.parse.urlparse(proxy_str)
        proxy_type = ProxyType.HTTP
        if parsed.scheme:
            try:
                proxy_type = ProxyType(parsed.scheme.lower())
            except ValueError:
                proxy_type = ProxyType.HTTP
        self.add(
            ProxyConfig(
                host=parsed.hostname or "127.0.0.1",
                port=parsed.port or 8080,
                proxy_type=proxy_type,
                username=parsed.username,
                password=parsed.password,
            )
        )

    def add_list(self, proxy_strings: List[str]) -> None:
        for ps in proxy_strings:
            self.add_from_string(ps)

    def load_from_file(self, filepath: str) -> int:
        """Carrega proxies de arquivo (um por linha)."""
        count = 0
        path = Path(filepath)
        if path.exists():
            for line in path.read_text().strip().split("\n"):
                line = line.strip()
                if line and not line.startswith("#"):
                    self.add_from_string(line)
                    count += 1
        return count

    async def get_next(self) -> Optional[ProxyConfig]:
        """Retorna o proximo proxy vivo usando round-robin."""
        async with self._lock:
            alive = [p for p in self._proxies if p.alive]
            if not alive:
                return None
            self._index = (self._index + 1) % len(alive)
            return alive[self._index]

    async def get_random(self) -> Optional[ProxyConfig]:
        """Retorna um proxy aleatorio vivo (weighted by response time)."""
        async with self._lock:
            alive = [p for p in self._proxies if p.alive]
            if not alive:
                return None
            # Weight by inverse response time (faster = more likely)
            if any(p.response_time_ms > 0 for p in alive):
                weights = [1.0 / max(p.response_time_ms, 1.0) for p in alive]
                total = sum(weights)
                weights = [w / total for w in weights]
                return random.choices(alive, weights=weights, k=1)[0]
            return random.choice(alive)

    async def get_fastest(self) -> Optional[ProxyConfig]:
        """Retorna o proxy mais rapido."""
        async with self._lock:
            alive = [p for p in self._proxies if p.alive and p.response_time_ms > 0]
            if not alive:
                alive = [p for p in self._proxies if p.alive]
            if not alive:
                return None
            return min(alive, key=lambda p: p.response_time_ms)

    async def health_check(
        self, test_url: str = "https://httpbin.org/ip", timeout: float = 10.0
    ) -> Dict[str, Any]:
        """Verifica saude de todos os proxies."""
        results = {"total": len(self._proxies), "alive": 0, "dead": 0, "checked": []}

        for proxy in self._proxies:
            start = time.time()
            try:
                # Simple TCP connection test
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(proxy.host, proxy.port),
                    timeout=timeout,
                )
                writer.close()
                await writer.wait_closed()
                elapsed = (time.time() - start) * 1000
                proxy.mark_success(elapsed)
                results["alive"] += 1
                results["checked"].append(
                    {"proxy": proxy.url, "status": "alive", "ms": round(elapsed, 1)}
                )
            except Exception as e:
                proxy.mark_failed()
                results["dead"] += 1
                results["checked"].append(
                    {"proxy": proxy.url, "status": "dead", "error": str(e)}
                )

        return results

    @property
    def alive_count(self) -> int:
        return sum(1 for p in self._proxies if p.alive)

    @property
    def total_count(self) -> int:
        return len(self._proxies)


# ════════════════════════════════════════════════════════════════════════════
# COOKIE JAR — Gerenciador de cookies persistente
# ════════════════════════════════════════════════════════════════════════════


@dataclass
class Cookie:
    """Cookie HTTP individual."""

    name: str
    value: str
    domain: str = ""
    path: str = "/"
    expires: Optional[float] = None
    secure: bool = False
    http_only: bool = False
    same_site: str = ""
    created: float = field(default_factory=time.time)

    @property
    def is_expired(self) -> bool:
        if self.expires is None:
            return False  # Session cookie
        return time.time() > self.expires

    @property
    def is_session(self) -> bool:
        return self.expires is None

    def matches_domain(self, domain: str) -> bool:
        if not self.domain:
            return True
        return domain.endswith(self.domain) or domain == self.domain.lstrip(".")


class CookieJar:
    """Gerenciador de cookies thread-safe e persistivel."""

    def __init__(self):
        self._cookies: Dict[str, Dict[str, Cookie]] = defaultdict(dict)
        # domain -> {name: Cookie}

    def set(self, cookie: Cookie) -> None:
        """Adiciona ou atualiza cookie."""
        self._cookies[cookie.domain][cookie.name] = cookie

    def set_from_header(self, set_cookie: str, domain: str = "") -> None:
        """Parseia Set-Cookie header e armazena."""
        parts = set_cookie.split(";")
        if not parts:
            return

        # Name=Value
        name_value = parts[0].strip()
        if "=" not in name_value:
            return
        name, value = name_value.split("=", 1)

        cookie = Cookie(name=name.strip(), value=value.strip(), domain=domain)

        for part in parts[1:]:
            part = part.strip().lower()
            if part.startswith("domain="):
                cookie.domain = part[7:].strip()
            elif part.startswith("path="):
                cookie.path = part[5:].strip()
            elif part.startswith("expires="):
                try:
                    from email.utils import parsedate_to_datetime

                    dt = parsedate_to_datetime(part[8:].strip())
                    cookie.expires = dt.timestamp()
                except Exception:
                    pass
            elif part.startswith("max-age="):
                try:
                    cookie.expires = time.time() + int(part[8:].strip())
                except ValueError:
                    pass
            elif part == "secure":
                cookie.secure = True
            elif part == "httponly":
                cookie.http_only = True
            elif part.startswith("samesite="):
                cookie.same_site = part[9:].strip()

        self.set(cookie)

    def get_for_url(self, url: str) -> Dict[str, str]:
        """Retorna cookies aplicaveis para URL."""
        parsed = urllib.parse.urlparse(url)
        domain = parsed.hostname or ""
        path = parsed.path or "/"
        is_secure = parsed.scheme == "https"

        result: Dict[str, str] = {}
        for cookie_domain, cookies in self._cookies.items():
            for name, cookie in cookies.items():
                if cookie.is_expired:
                    continue
                if not cookie.matches_domain(domain):
                    continue
                if cookie.secure and not is_secure:
                    continue
                if not path.startswith(cookie.path):
                    continue
                result[name] = cookie.value

        return result

    def get_all(self) -> List[Cookie]:
        """Retorna todos os cookies."""
        result: List[Cookie] = []
        for domain_cookies in self._cookies.values():
            result.extend(domain_cookies.values())
        return result

    def clear(self, domain: Optional[str] = None) -> None:
        if domain:
            self._cookies.pop(domain, None)
        else:
            self._cookies.clear()

    def clear_expired(self) -> int:
        """Remove cookies expirados, retorna quantos foram removidos."""
        removed = 0
        for domain in list(self._cookies.keys()):
            for name in list(self._cookies[domain].keys()):
                if self._cookies[domain][name].is_expired:
                    del self._cookies[domain][name]
                    removed += 1
            if not self._cookies[domain]:
                del self._cookies[domain]
        return removed

    def save(self, filepath: str) -> None:
        """Salva cookies em arquivo JSON."""
        data = []
        for cookie in self.get_all():
            if not cookie.is_expired:
                data.append(
                    {
                        "name": cookie.name,
                        "value": cookie.value,
                        "domain": cookie.domain,
                        "path": cookie.path,
                        "expires": cookie.expires,
                        "secure": cookie.secure,
                        "http_only": cookie.http_only,
                        "same_site": cookie.same_site,
                    }
                )
        Path(filepath).write_text(json.dumps(data, indent=2), encoding="utf-8")

    def load(self, filepath: str) -> int:
        """Carrega cookies de arquivo JSON, retorna quantos foram carregados."""
        path = Path(filepath)
        if not path.exists():
            return 0
        data = json.loads(path.read_text(encoding="utf-8"))
        count = 0
        for entry in data:
            cookie = Cookie(**entry)
            if not cookie.is_expired:
                self.set(cookie)
                count += 1
        return count

    @property
    def count(self) -> int:
        return sum(len(c) for c in self._cookies.values())

    def to_header_string(self, url: str) -> str:
        """Gera header Cookie: para URL."""
        cookies = self.get_for_url(url)
        return "; ".join(f"{k}={v}" for k, v in cookies.items())


# ════════════════════════════════════════════════════════════════════════════
# REQUEST INTERCEPTOR — Hook system para modificar requests/responses
# ════════════════════════════════════════════════════════════════════════════


class InterceptorChain:
    """Chain of responsibility para interceptar e modificar requests/responses.

    Permite adicionar hooks que modificam requests antes do envio
    e responses depois do recebimento. Util para:
    - Adicionar headers de autenticacao
    - Logging/tracing
    - Modificar payloads
    - Injetar tokens CSRF
    """

    def __init__(self):
        self._request_hooks: List[Callable[[RequestConfig], RequestConfig]] = []
        self._response_hooks: List[Callable[[ResponseData], ResponseData]] = []
        self._error_hooks: List[Callable[[Exception, RequestConfig], None]] = []

    def add_request_hook(self, hook: Callable[[RequestConfig], RequestConfig]) -> None:
        self._request_hooks.append(hook)

    def add_response_hook(self, hook: Callable[[ResponseData], ResponseData]) -> None:
        self._response_hooks.append(hook)

    def add_error_hook(self, hook: Callable[[Exception, RequestConfig], None]) -> None:
        self._error_hooks.append(hook)

    def process_request(self, config: RequestConfig) -> RequestConfig:
        """Aplica todos os hooks de request."""
        for hook in self._request_hooks:
            try:
                config = hook(config)
            except Exception as e:
                logger.warning(f"Request hook error: {e}")
        return config

    def process_response(self, response: ResponseData) -> ResponseData:
        """Aplica todos os hooks de response."""
        for hook in self._response_hooks:
            try:
                response = hook(response)
            except Exception as e:
                logger.warning(f"Response hook error: {e}")
        return response

    def handle_error(self, error: Exception, config: RequestConfig) -> None:
        """Notifica hooks de erro."""
        for hook in self._error_hooks:
            try:
                hook(error, config)
            except Exception as e:
                logger.warning(f"Error hook error: {e}")


# ════════════════════════════════════════════════════════════════════════════
# FINGERPRINTER — Analise de fingerprint TLS + HTTP
# ════════════════════════════════════════════════════════════════════════════


class ServerFingerprinter:
    """Analisa servidor para identificar tecnologias, WAF, framework, etc."""

    # Technology signatures
    TECH_SIGNATURES = {
        "headers": {
            "X-Powered-By": {
                "Express": "express",
                "PHP": "php",
                "ASP.NET": "asp.net",
                "Next.js": "nextjs",
                "Nuxt": "nuxt",
                "Django": "django",
                "Flask": "flask",
                "Spring": "spring",
                "Ruby": "ruby",
                "Kestrel": "dotnet",
            },
            "Server": {
                "nginx": "nginx",
                "Apache": "apache",
                "Microsoft-IIS": "iis",
                "cloudflare": "cloudflare",
                "AmazonS3": "s3",
                "gws": "google",
                "openresty": "openresty",
                "LiteSpeed": "litespeed",
                "Caddy": "caddy",
                "gunicorn": "gunicorn",
                "uvicorn": "uvicorn",
                "Kestrel": "kestrel",
                "Cowboy": "cowboy",
            },
        },
        "body": {
            "wp-content": "wordpress",
            "wp-includes": "wordpress",
            "Joomla": "joomla",
            "drupal": "drupal",
            "__VIEWSTATE": "asp.net-webforms",
            "_next/": "nextjs",
            "__nuxt": "nuxt",
            "react-root": "react",
            "ng-": "angular",
            "vue": "vue",
            "ember": "ember",
            "svelte": "svelte",
            "laravel": "laravel",
            "csrfmiddlewaretoken": "django",
            "rails": "rails",
            "phpmyadmin": "phpmyadmin",
        },
        "cookies": {
            "PHPSESSID": "php",
            "JSESSIONID": "java",
            "ASP.NET_SessionId": "asp.net",
            "csrftoken": "django",
            "_rails_session": "rails",
            "connect.sid": "express",
            "laravel_session": "laravel",
            "wp-settings": "wordpress",
        },
    }

    # WAF signatures
    WAF_SIGNATURES = {
        "headers": {
            "cf-ray": "Cloudflare",
            "x-sucuri": "Sucuri",
            "x-akamai": "Akamai",
            "x-aws-waf": "AWS WAF",
            "x-cdn": "CDN (generic)",
            "x-cache": "Varnish/CDN",
        },
        "body": {
            "cloudflare": "Cloudflare",
            "sucuri": "Sucuri",
            "incapsula": "Imperva/Incapsula",
            "akamai": "Akamai",
            "modsecurity": "ModSecurity",
            "wordfence": "Wordfence",
            "f5": "F5 BIG-IP",
        },
        "status_patterns": {
            403: "Possible WAF block",
            406: "Possible WAF block (Not Acceptable)",
            429: "Rate limiting active",
            503: "Possible WAF challenge page",
        },
    }

    @classmethod
    def fingerprint(cls, response: ResponseData) -> Dict[str, Any]:
        """Analisa response para identificar tecnologias e WAF."""
        result: Dict[str, Any] = {
            "technologies": [],
            "waf": [],
            "server": response.server,
            "powered_by": response.powered_by,
            "framework": None,
            "language": None,
            "cms": None,
            "cdn": None,
            "security_headers": response.security_headers,
            "missing_security_headers": response.missing_security_headers,
        }

        detected_techs: Set[str] = set()

        # Check headers
        for header_name, signatures in cls.TECH_SIGNATURES["headers"].items():
            header_value = response.header(header_name)
            if header_value:
                for sig, tech in signatures.items():
                    if sig.lower() in header_value.lower():
                        detected_techs.add(tech)

        # Check body
        for sig, tech in cls.TECH_SIGNATURES["body"].items():
            if sig.lower() in response.text.lower():
                detected_techs.add(tech)

        # Check cookies
        for cookie_name, tech in cls.TECH_SIGNATURES["cookies"].items():
            if cookie_name in response.cookies:
                detected_techs.add(tech)

        result["technologies"] = sorted(detected_techs)

        # Detect WAF
        detected_wafs: Set[str] = set()
        for header_name, waf_name in cls.WAF_SIGNATURES["headers"].items():
            if response.header(header_name):
                detected_wafs.add(waf_name)

        for sig, waf_name in cls.WAF_SIGNATURES["body"].items():
            if sig.lower() in response.text.lower():
                detected_wafs.add(waf_name)

        result["waf"] = sorted(detected_wafs)

        # Categorize
        cms_techs = {"wordpress", "joomla", "drupal", "phpmyadmin"}
        framework_techs = {
            "express",
            "django",
            "flask",
            "spring",
            "rails",
            "laravel",
            "nextjs",
            "nuxt",
            "react",
            "angular",
            "vue",
        }
        language_techs = {"php", "java", "ruby", "asp.net", "dotnet", "python"}
        cdn_techs = {"cloudflare", "akamai", "s3"}

        for tech in detected_techs:
            if tech in cms_techs and not result["cms"]:
                result["cms"] = tech
            elif tech in framework_techs and not result["framework"]:
                result["framework"] = tech
            elif tech in language_techs and not result["language"]:
                result["language"] = tech
            elif tech in cdn_techs and not result["cdn"]:
                result["cdn"] = tech

        return result


# ════════════════════════════════════════════════════════════════════════════
# DNS RESOLVER — Resolucao e cache DNS
# ════════════════════════════════════════════════════════════════════════════


class DNSResolver:
    """Resolver DNS com cache, fallback, e record type support."""

    def __init__(
        self,
        nameservers: Optional[List[str]] = None,
        cache_ttl: float = 300.0,
        timeout: float = 5.0,
    ):
        self._nameservers = nameservers or ["8.8.8.8", "8.8.4.4", "1.1.1.1"]
        self._cache: Dict[str, Tuple[List[str], float]] = {}
        self._cache_ttl = cache_ttl
        self._timeout = timeout

    async def resolve(self, hostname: str, record_type: str = "A") -> List[str]:
        """Resolve hostname, retorna lista de IPs/records."""
        cache_key = f"{hostname}:{record_type}"
        cached = self._cache.get(cache_key)
        if cached:
            records, expires = cached
            if time.time() < expires:
                return records

        try:
            loop = asyncio.get_event_loop()
            if record_type == "A":
                infos = await loop.getaddrinfo(
                    hostname,
                    None,
                    family=socket.AF_INET,
                    type=socket.SOCK_STREAM,
                )
                records = list(set(info[4][0] for info in infos))
            elif record_type == "AAAA":
                infos = await loop.getaddrinfo(
                    hostname,
                    None,
                    family=socket.AF_INET6,
                    type=socket.SOCK_STREAM,
                )
                records = list(set(info[4][0] for info in infos))
            else:
                # For other types, try basic resolution
                infos = await loop.getaddrinfo(hostname, None)
                records = list(set(info[4][0] for info in infos))

            self._cache[cache_key] = (records, time.time() + self._cache_ttl)
            return records

        except Exception as e:
            logger.debug(f"DNS resolution failed for {hostname}: {e}")
            return []

    async def reverse_lookup(self, ip: str) -> Optional[str]:
        """Reverse DNS lookup."""
        try:
            loop = asyncio.get_event_loop()
            result = await loop.getnameinfo((ip, 0), 0)
            return result[0]
        except Exception:
            return None

    async def get_all_records(self, hostname: str) -> Dict[str, List[str]]:
        """Busca todos os tipos de record para um hostname."""
        results: Dict[str, List[str]] = {}
        for rtype in ["A", "AAAA"]:
            records = await self.resolve(hostname, rtype)
            if records:
                results[rtype] = records
        return results

    def clear_cache(self) -> None:
        self._cache.clear()

    @property
    def cache_size(self) -> int:
        return len(self._cache)


# ════════════════════════════════════════════════════════════════════════════
# HAR RECORDER — Gravador de HTTP Archive
# ════════════════════════════════════════════════════════════════════════════


class HARRecorder:
    """Grava todas as requisicoes/respostas no formato HAR (HTTP Archive).

    Util para analise posterior, replay, e export para ferramentas
    como Burp Suite, OWASP ZAP, etc.
    """

    def __init__(self, name: str = "SIREN Network Engine"):
        self._name = name
        self._entries: List[dict] = []
        self._start_time = datetime.now()
        self._recording = True

    def record(
        self,
        request: RequestConfig,
        response: ResponseData,
    ) -> None:
        """Gravar um par request/response."""
        if not self._recording:
            return

        entry = {
            "startedDateTime": datetime.now().isoformat(),
            "time": response.elapsed_ms,
            "request": {
                "method": request.method,
                "url": request.url,
                "httpVersion": "HTTP/1.1",
                "headers": [
                    {"name": k, "value": v} for k, v in request.headers.items()
                ],
                "queryString": [
                    {"name": k, "value": v} for k, v in request.params.items()
                ],
                "cookies": [
                    {"name": k, "value": v} for k, v in request.cookies.items()
                ],
                "headersSize": -1,
                "bodySize": len(str(request.data or request.json_data or "").encode()),
                "postData": (
                    {
                        "mimeType": request.content_type
                        or "application/x-www-form-urlencoded",
                        "text": str(request.data or request.json_data or ""),
                    }
                    if request.method in ("POST", "PUT", "PATCH")
                    else None
                ),
            },
            "response": {
                "status": response.status_code,
                "statusText": "",
                "httpVersion": "HTTP/1.1",
                "headers": [
                    {"name": k, "value": v} for k, v in response.headers.items()
                ],
                "content": {
                    "size": response.body_size,
                    "mimeType": response.content_type,
                    "text": (
                        response.text[:50000]
                        if len(response.text) > 50000
                        else response.text
                    ),
                },
                "cookies": [
                    {"name": k, "value": v} for k, v in response.cookies.items()
                ],
                "headersSize": -1,
                "bodySize": response.body_size,
                "redirectURL": response.header("Location", ""),
            },
            "cache": {},
            "timings": {
                "send": 0,
                "wait": response.elapsed_ms,
                "receive": 0,
            },
            "comment": request.tag or "",
        }
        self._entries.append(entry)

    def to_dict(self) -> dict:
        """Exporta como dict HAR."""
        return {
            "log": {
                "version": "1.2",
                "creator": {
                    "name": self._name,
                    "version": "1.0",
                },
                "entries": self._entries,
                "pages": [],
            }
        }

    def save(self, filepath: str) -> None:
        """Salva HAR em arquivo."""
        Path(filepath).write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    @property
    def entry_count(self) -> int:
        return len(self._entries)

    def pause(self) -> None:
        self._recording = False

    def resume(self) -> None:
        self._recording = True

    def clear(self) -> None:
        self._entries.clear()


# ════════════════════════════════════════════════════════════════════════════
# TLS ANALYZER — Analise de certificados e configuracao TLS
# ════════════════════════════════════════════════════════════════════════════


class TLSAnalyzer:
    """Analisa configuracao TLS/SSL de um servidor."""

    # Weak ciphers
    WEAK_CIPHERS = {
        "RC4",
        "DES",
        "3DES",
        "MD5",
        "NULL",
        "EXPORT",
        "anon",
        "RC2",
        "IDEA",
        "SEED",
    }

    # Good protocols
    GOOD_PROTOCOLS = {"TLSv1.2", "TLSv1.3"}
    DEPRECATED_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}

    @classmethod
    async def analyze(
        cls, hostname: str, port: int = 443, timeout: float = 10.0
    ) -> Dict[str, Any]:
        """Analisa configuracao TLS de servidor."""
        result: Dict[str, Any] = {
            "hostname": hostname,
            "port": port,
            "ssl_enabled": False,
            "certificate": None,
            "protocol": None,
            "cipher": None,
            "cipher_bits": None,
            "sni_required": False,
            "issues": [],
            "grade": "F",
        }

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            loop = asyncio.get_event_loop()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(hostname, port, ssl=ctx),
                timeout=timeout,
            )

            ssl_obj = writer.get_extra_info("ssl_object")
            if ssl_obj:
                result["ssl_enabled"] = True
                result["protocol"] = ssl_obj.version()
                cipher_info = ssl_obj.cipher()
                if cipher_info:
                    result["cipher"] = cipher_info[0]
                    result["protocol"] = cipher_info[1]
                    result["cipher_bits"] = cipher_info[2]

                # Certificate
                cert = ssl_obj.getpeercert(binary_form=False)
                if cert:
                    result["certificate"] = cls._parse_cert(cert, hostname)

                # Check for issues
                if result["protocol"] in cls.DEPRECATED_PROTOCOLS:
                    result["issues"].append(
                        f"Deprecated protocol: {result['protocol']}"
                    )

                if result["cipher"]:
                    for weak in cls.WEAK_CIPHERS:
                        if weak in result["cipher"].upper():
                            result["issues"].append(f"Weak cipher component: {weak}")
                            break

                # Grade
                result["grade"] = cls._calculate_grade(result)

            writer.close()
            await writer.wait_closed()

        except ssl.SSLError as e:
            result["issues"].append(f"SSL Error: {str(e)}")
        except asyncio.TimeoutError:
            result["issues"].append("Connection timeout")
        except ConnectionRefusedError:
            result["issues"].append("Connection refused")
        except Exception as e:
            result["issues"].append(f"Error: {str(e)}")

        return result

    @classmethod
    def _parse_cert(cls, cert: dict, hostname: str) -> Dict[str, Any]:
        """Parseia certificado SSL."""
        result: Dict[str, Any] = {
            "subject": {},
            "issuer": {},
            "valid_from": None,
            "valid_to": None,
            "expired": False,
            "self_signed": False,
            "hostname_match": False,
            "serial_number": cert.get("serialNumber", ""),
            "version": cert.get("version", 0),
            "san": [],
            "issues": [],
        }

        # Subject
        subject = cert.get("subject", ())
        for field_tuple in subject:
            for field_name, field_value in field_tuple:
                result["subject"][field_name] = field_value

        # Issuer
        issuer = cert.get("issuer", ())
        for field_tuple in issuer:
            for field_name, field_value in field_tuple:
                result["issuer"][field_name] = field_value

        # Validity
        not_before = cert.get("notBefore")
        not_after = cert.get("notAfter")
        if not_before:
            result["valid_from"] = not_before
        if not_after:
            result["valid_to"] = not_after
            try:
                from email.utils import parsedate_to_datetime

                expiry = parsedate_to_datetime(not_after)
                if expiry.timestamp() < time.time():
                    result["expired"] = True
                    result["issues"].append("Certificate expired")
            except Exception as e:
                logger.debug("Certificate expiry parse error: %s", e)

        # Self-signed check
        if result["subject"] == result["issuer"]:
            result["self_signed"] = True
            result["issues"].append("Self-signed certificate")

        # SAN (Subject Alternative Name)
        san = cert.get("subjectAltName", ())
        for san_type, san_value in san:
            result["san"].append({"type": san_type, "value": san_value})

        # Hostname match
        cn = result["subject"].get("commonName", "")
        san_names = [s["value"] for s in result["san"] if s["type"] == "DNS"]
        all_names = [cn] + san_names
        for name in all_names:
            if name == hostname or (
                name.startswith("*.") and hostname.endswith(name[1:])
            ):
                result["hostname_match"] = True
                break
        if not result["hostname_match"]:
            result["issues"].append(f"Hostname mismatch: {hostname} not in {all_names}")

        return result

    @classmethod
    def _calculate_grade(cls, result: Dict[str, Any]) -> str:
        """Calcula nota SSL (A-F)."""
        score = 100

        # Protocol
        protocol = result.get("protocol", "")
        if protocol in cls.DEPRECATED_PROTOCOLS:
            score -= 30
        if "TLSv1.3" not in str(protocol):
            score -= 5

        # Cipher
        cipher = result.get("cipher", "")
        if cipher:
            for weak in cls.WEAK_CIPHERS:
                if weak in cipher.upper():
                    score -= 25
                    break
        cipher_bits = result.get("cipher_bits", 0)
        if cipher_bits and cipher_bits < 128:
            score -= 20

        # Certificate issues
        cert = result.get("certificate", {})
        if cert:
            if cert.get("expired"):
                score -= 40
            if cert.get("self_signed"):
                score -= 30
            if not cert.get("hostname_match"):
                score -= 20

        # Other issues
        score -= len(result.get("issues", [])) * 5

        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"


# ════════════════════════════════════════════════════════════════════════════
# SIREN HTTP CLIENT — O Cliente HTTP Principal
# ════════════════════════════════════════════════════════════════════════════


class SirenHTTPClient:
    """Cliente HTTP async completo para operacoes SIREN.

    Features:
    - Sessions com cookie persistence
    - Proxy rotation
    - Rate limiting adaptativo
    - Response caching
    - Request/Response interception
    - HAR recording
    - User-Agent rotation
    - Retry com backoff
    - TLS analysis
    - DNS resolution
    """

    def __init__(
        self,
        base_url: str = "",
        timeout: float = 30.0,
        verify_ssl: bool = False,
        max_retries: int = 3,
        rps: float = 10.0,
        user_agent_rotation: bool = True,
        proxy_rotator: Optional[ProxyRotator] = None,
        record_har: bool = True,
        cache_enabled: bool = True,
        cache_ttl: float = 300.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.max_retries = max_retries
        self.user_agent_rotation = user_agent_rotation

        # Components
        self.cookies = CookieJar()
        self.rate_limiter = AdaptiveRateLimiter(requests_per_second=rps)
        self.proxy_rotator = proxy_rotator or ProxyRotator()
        self.interceptor = InterceptorChain()
        self.har_recorder = HARRecorder() if record_har else None
        self.cache = ResponseCache(default_ttl=cache_ttl) if cache_enabled else None
        self.dns = DNSResolver()
        self.fingerprinter = ServerFingerprinter()

        # Auth state
        self._auth_type: AuthType = AuthType.NONE
        self._auth_credentials: Optional[Tuple[str, str]] = None
        self._bearer_token: Optional[str] = None
        self._csrf_token: Optional[str] = None
        self._csrf_header: str = "X-CSRF-Token"
        self._csrf_field: str = "csrf_token"

        # Session headers
        self._session_headers: Dict[str, str] = dict(COMMON_HEADERS)

        # Statistics
        self._stats = {
            "total_requests": 0,
            "successful": 0,
            "failed": 0,
            "retried": 0,
            "cached": 0,
            "bytes_sent": 0,
            "bytes_received": 0,
            "start_time": time.time(),
        }

        # Semaphore for concurrency control
        self._semaphore = asyncio.Semaphore(50)

        # Session (aiohttp)
        self._session = None

    async def _ensure_session(self):
        """Cria/reutiliza aiohttp session."""
        if self._session is None:
            try:
                import aiohttp

                connector = aiohttp.TCPConnector(
                    ssl=self.verify_ssl,
                    limit=100,
                    limit_per_host=20,
                    ttl_dns_cache=300,
                    force_close=False,
                    enable_cleanup_closed=True,
                )
                timeout_config = aiohttp.ClientTimeout(total=self.timeout)
                self._session = aiohttp.ClientSession(
                    connector=connector,
                    timeout=timeout_config,
                )
            except ImportError:
                # Fallback: use urllib
                self._session = None

    async def close(self) -> None:
        """Fecha a sessao HTTP."""
        if self._session is not None:
            try:
                await self._session.close()
            except Exception:
                pass
            self._session = None

    def _get_user_agent(self) -> str:
        """Retorna User-Agent (random se rotation ativa)."""
        if self.user_agent_rotation:
            return random.choice(DEFAULT_USER_AGENTS)
        return DEFAULT_USER_AGENTS[0]

    def _build_url(self, url: str) -> str:
        """Constroi URL completa (resolve relativa se base_url definido)."""
        if url.startswith(("http://", "https://")):
            return url
        if self.base_url:
            return f"{self.base_url}/{url.lstrip('/')}"
        return url

    def _get_domain(self, url: str) -> str:
        """Extrai dominio de URL."""
        parsed = urllib.parse.urlparse(url)
        return parsed.hostname or ""

    def set_auth(
        self,
        auth_type: AuthType,
        credentials: Optional[Tuple[str, str]] = None,
        token: Optional[str] = None,
    ) -> None:
        """Configura autenticacao persistente para a sessao."""
        self._auth_type = auth_type
        if credentials:
            self._auth_credentials = credentials
        if token:
            self._bearer_token = token

    def set_csrf_token(
        self, token: str, header: str = "X-CSRF-Token", field: str = "csrf_token"
    ) -> None:
        """Configura CSRF token para requests automaticos."""
        self._csrf_token = token
        self._csrf_header = header
        self._csrf_field = field

    def set_header(self, name: str, value: str) -> None:
        """Define header persistente de sessao."""
        self._session_headers[name] = value

    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
        data: Optional[Union[str, bytes, dict]] = None,
        json_data: Optional[dict] = None,
        cookies: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
        allow_redirects: bool = True,
        proxy: Optional[ProxyConfig] = None,
        priority: RequestPriority = RequestPriority.NORMAL,
        retries: Optional[int] = None,
        tag: str = "",
        force_no_cache: bool = False,
    ) -> ResponseData:
        """Executa uma requisicao HTTP.

        Este e o metodo principal — todos os outros (get, post, etc.)
        delegam para este.
        """
        full_url = self._build_url(url)
        domain = self._get_domain(full_url)
        max_retries = retries if retries is not None else self.max_retries

        # Build request config
        req_headers = dict(self._session_headers)
        req_headers["User-Agent"] = self._get_user_agent()
        if headers:
            req_headers.update(headers)

        # Auth
        if self._auth_type == AuthType.BEARER and self._bearer_token:
            req_headers["Authorization"] = f"Bearer {self._bearer_token}"
        elif self._auth_type == AuthType.BASIC and self._auth_credentials:
            import base64

            cred = base64.b64encode(
                f"{self._auth_credentials[0]}:{self._auth_credentials[1]}".encode()
            ).decode()
            req_headers["Authorization"] = f"Basic {cred}"

        # CSRF
        if self._csrf_token and method.upper() in ("POST", "PUT", "PATCH", "DELETE"):
            req_headers[self._csrf_header] = self._csrf_token

        # Merge cookies
        all_cookies = self.cookies.get_for_url(full_url)
        if cookies:
            all_cookies.update(cookies)

        config = RequestConfig(
            url=full_url,
            method=method.upper(),
            headers=req_headers,
            params=params or {},
            data=data,
            json_data=json_data,
            cookies=all_cookies,
            timeout=timeout or self.timeout,
            allow_redirects=allow_redirects,
            verify_ssl=self.verify_ssl,
            proxy=proxy,
            priority=priority,
            retries=max_retries,
            tag=tag,
        )

        # Interceptor pre-processing
        config = self.interceptor.process_request(config)

        # Check cache
        if self.cache and not force_no_cache and config.method == "GET":
            cached = self.cache.get(config.method, config.url)
            if cached:
                self._stats["cached"] += 1
                return cached

        # Rate limiting
        await self.rate_limiter.acquire(domain)

        # Execute with retry
        last_error: Optional[str] = None
        for attempt in range(max_retries + 1):
            try:
                async with self._semaphore:
                    response = await self._do_request(config)

                # Update rate limiter
                retry_after = None
                ra_header = response.header("Retry-After")
                if ra_header:
                    try:
                        retry_after = float(ra_header)
                    except ValueError:
                        pass
                self.rate_limiter.on_response(response.status_code, domain, retry_after)

                # Process cookies from response
                for h_name, h_value in response.headers.items():
                    if h_name.lower() == "set-cookie":
                        self.cookies.set_from_header(h_value, domain)

                # Auto-detect CSRF token
                if not self._csrf_token:
                    self._auto_detect_csrf(response)

                # Interceptor post-processing
                response = self.interceptor.process_response(response)

                # Record HAR
                if self.har_recorder:
                    self.har_recorder.record(config, response)

                # Cache
                if self.cache and config.method == "GET" and response.is_success:
                    self.cache.put(config.method, config.url, response)

                # Stats
                self._stats["total_requests"] += 1
                self._stats["bytes_received"] += response.body_size
                if response.ok:
                    self._stats["successful"] += 1
                else:
                    self._stats["failed"] += 1

                return response

            except Exception as e:
                last_error = str(e)
                if attempt < max_retries:
                    self._stats["retried"] += 1
                    delay = min(2**attempt + random.random(), 30)
                    await asyncio.sleep(delay)
                    # Rotate proxy on failure
                    if self.proxy_rotator.alive_count > 0:
                        next_proxy = await self.proxy_rotator.get_next()
                        if next_proxy and proxy:
                            proxy.mark_failed()
                        config.proxy = next_proxy
                else:
                    self.interceptor.handle_error(e, config)

        # All retries failed
        self._stats["failed"] += 1
        return ResponseData(
            url=full_url,
            status_code=0,
            headers={},
            body=b"",
            text="",
            elapsed_ms=0,
            error=last_error or "All retries exhausted",
            request_tag=tag,
        )

    async def _do_request(self, config: RequestConfig) -> ResponseData:
        """Executa a request real usando aiohttp ou urllib fallback."""
        start = time.time()

        try:
            import aiohttp

            await self._ensure_session()

            if self._session:
                # Build request kwargs
                kwargs: Dict[str, Any] = {
                    "method": config.method,
                    "url": config.url,
                    "headers": config.headers,
                    "params": config.params if config.params else None,
                    "allow_redirects": config.allow_redirects,
                    "max_redirects": config.max_redirects,
                    "timeout": aiohttp.ClientTimeout(total=config.timeout),
                    "ssl": config.verify_ssl,
                }

                if config.cookies:
                    kwargs["cookies"] = config.cookies
                if config.json_data is not None:
                    kwargs["json"] = config.json_data
                elif config.data is not None:
                    kwargs["data"] = config.data
                elif config.raw_body is not None:
                    kwargs["data"] = config.raw_body
                if config.proxy:
                    kwargs["proxy"] = config.proxy.url

                async with self._session.request(**kwargs) as resp:
                    body = await resp.read()
                    elapsed = (time.time() - start) * 1000

                    # Decode text
                    encoding = resp.charset or "utf-8"
                    try:
                        text = body.decode(encoding, errors="replace")
                    except Exception:
                        text = body.decode("utf-8", errors="replace")

                    content_type = resp.headers.get("Content-Type", "")

                    # Collect response cookies
                    resp_cookies = {}
                    for cookie_name, cookie_morsel in resp.cookies.items():
                        resp_cookies[cookie_name] = cookie_morsel.value

                    # Redirect history
                    history = [str(h.url) for h in resp.history]

                    return ResponseData(
                        url=str(resp.url),
                        status_code=resp.status,
                        headers=dict(resp.headers),
                        body=body,
                        text=text,
                        elapsed_ms=elapsed,
                        redirect_history=history,
                        cookies=resp_cookies,
                        content_type=content_type,
                        content_length=len(body),
                        encoding=encoding,
                        is_json="json" in content_type.lower(),
                        is_html="html" in content_type.lower(),
                        is_xml="xml" in content_type.lower(),
                        request_tag=config.tag,
                    )
        except ImportError:
            pass

        # Fallback: urllib (synchronous, but wrapped in asyncio)
        return await self._urllib_fallback(config, start)

    async def _urllib_fallback(
        self, config: RequestConfig, start: float
    ) -> ResponseData:
        """Fallback HTTP usando urllib (sem aiohttp)."""
        import urllib.error
        import urllib.request

        loop = asyncio.get_event_loop()

        def _sync_request() -> ResponseData:
            _start = time.time()
            try:
                req = urllib.request.Request(
                    url=config.url,
                    method=config.method,
                    headers=config.headers,
                )

                if config.json_data is not None:
                    body = json.dumps(config.json_data).encode("utf-8")
                    req.add_header("Content-Type", "application/json")
                    req.data = body
                elif config.data is not None:
                    if isinstance(config.data, dict):
                        body = urllib.parse.urlencode(config.data).encode("utf-8")
                        req.add_header(
                            "Content-Type", "application/x-www-form-urlencoded"
                        )
                    elif isinstance(config.data, str):
                        body = config.data.encode("utf-8")
                    else:
                        body = config.data
                    req.data = body

                ctx = ssl.create_default_context()
                if not config.verify_ssl:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE

                resp = urllib.request.urlopen(
                    req,
                    timeout=config.timeout,
                    context=ctx,
                )
                resp_body = resp.read()
                elapsed = (time.time() - _start) * 1000

                content_type = resp.headers.get("Content-Type", "")
                encoding = "utf-8"
                if "charset=" in content_type:
                    encoding = content_type.split("charset=")[-1].split(";")[0].strip()

                text = resp_body.decode(encoding, errors="replace")

                return ResponseData(
                    url=config.url,
                    status_code=resp.status,
                    headers=dict(resp.headers),
                    body=resp_body,
                    text=text,
                    elapsed_ms=elapsed,
                    content_type=content_type,
                    content_length=len(resp_body),
                    encoding=encoding,
                    is_json="json" in content_type.lower(),
                    is_html="html" in content_type.lower(),
                    is_xml="xml" in content_type.lower(),
                    request_tag=config.tag,
                )

            except urllib.error.HTTPError as e:
                elapsed = (time.time() - _start) * 1000
                resp_body = e.read() if hasattr(e, "read") else b""
                text = resp_body.decode("utf-8", errors="replace")
                return ResponseData(
                    url=config.url,
                    status_code=e.code,
                    headers=dict(e.headers) if e.headers else {},
                    body=resp_body,
                    text=text,
                    elapsed_ms=elapsed,
                    content_type=e.headers.get("Content-Type", "") if e.headers else "",
                    content_length=len(resp_body),
                    request_tag=config.tag,
                )
            except Exception as e:
                elapsed = (time.time() - _start) * 1000
                return ResponseData(
                    url=config.url,
                    status_code=0,
                    headers={},
                    body=b"",
                    text="",
                    elapsed_ms=elapsed,
                    error=str(e),
                    request_tag=config.tag,
                )

        return await loop.run_in_executor(None, _sync_request)

    def _auto_detect_csrf(self, response: ResponseData) -> None:
        """Tenta detectar CSRF token automaticamente."""
        if not response.is_html:
            return

        # Check meta tags
        patterns = [
            r'<meta\s+name=["\']csrf-token["\']\s+content=["\']([^"\']+)["\']',
            r'<meta\s+content=["\']([^"\']+)["\']\s+name=["\']csrf-token["\']',
            r'<input[^>]+name=["\']_?csrf_?token["\'][^>]+value=["\']([^"\']+)["\']',
            r'<input[^>]+value=["\']([^"\']+)["\'][^>]+name=["\']_?csrf_?token["\']',
            r'<input[^>]+name=["\']csrfmiddlewaretoken["\'][^>]+value=["\']([^"\']+)["\']',
            r"csrfToken[\"']?\s*[:=]\s*[\"']([^\"']+)[\"']",
        ]
        for pattern in patterns:
            match = re.search(pattern, response.text, re.IGNORECASE)
            if match:
                self._csrf_token = match.group(1)
                logger.debug(f"Auto-detected CSRF token: {self._csrf_token[:20]}...")
                break

    # ── Convenience Methods ─────────────────────────────────────────────

    async def get(self, url: str, **kwargs) -> ResponseData:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> ResponseData:
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs) -> ResponseData:
        return await self.request("PUT", url, **kwargs)

    async def patch(self, url: str, **kwargs) -> ResponseData:
        return await self.request("PATCH", url, **kwargs)

    async def delete(self, url: str, **kwargs) -> ResponseData:
        return await self.request("DELETE", url, **kwargs)

    async def head(self, url: str, **kwargs) -> ResponseData:
        kwargs["allow_redirects"] = kwargs.get("allow_redirects", False)
        return await self.request("HEAD", url, **kwargs)

    async def options(self, url: str, **kwargs) -> ResponseData:
        return await self.request("OPTIONS", url, **kwargs)

    # ── Auth Methods ────────────────────────────────────────────────────

    async def login_form(
        self,
        login_url: str,
        username: str,
        password: str,
        username_field: str = "username",
        password_field: str = "password",
        extra_fields: Optional[Dict[str, str]] = None,
    ) -> ResponseData:
        """Realiza login via formulario HTML.

        1. GET na pagina de login (pega CSRF + cookies)
        2. POST com credenciais
        3. Retorna response do POST
        """
        # Step 1: Get login page
        page = await self.get(login_url)

        # Extract CSRF if present
        forms = page.extract_forms()
        form_data = {username_field: username, password_field: password}

        # Look for hidden fields (CSRF, etc)
        for form in forms:
            for inp in form.get("inputs", []):
                if inp.get("type") == "hidden" and inp.get("name") and inp.get("value"):
                    form_data[inp["name"]] = inp["value"]

        if extra_fields:
            form_data.update(extra_fields)

        # Step 2: POST login
        action_url = forms[0]["action"] if forms else login_url
        if not action_url.startswith("http"):
            from urllib.parse import urljoin

            action_url = urljoin(login_url, action_url)

        response = await self.post(action_url, data=form_data)
        return response

    async def login_json(
        self,
        login_url: str,
        username: str,
        password: str,
        username_field: str = "username",
        password_field: str = "password",
        extra_fields: Optional[Dict[str, str]] = None,
    ) -> ResponseData:
        """Realiza login via JSON API."""
        payload = {username_field: username, password_field: password}
        if extra_fields:
            payload.update(extra_fields)

        response = await self.post(
            login_url,
            json_data=payload,
            headers={"Content-Type": "application/json"},
        )

        # Extract token from response
        if response.is_json and response.json:
            for key in (
                "token",
                "access_token",
                "jwt",
                "auth_token",
                "session_token",
                "accessToken",
            ):
                token = response.json.get(key)
                if token:
                    self.set_auth(AuthType.BEARER, token=token)
                    break

        return response

    # ── Scanning Methods ────────────────────────────────────────────────

    async def crawl(
        self,
        start_url: str,
        max_depth: int = 3,
        max_pages: int = 100,
        same_domain_only: bool = True,
        exclude_patterns: Optional[List[str]] = None,
        include_patterns: Optional[List[str]] = None,
    ) -> Dict[str, ResponseData]:
        """Crawl básico - navega links automaticamente.

        Returns dict url -> ResponseData para cada pagina visitada.
        """
        visited: Dict[str, ResponseData] = {}
        queue: Deque[Tuple[str, int]] = deque()
        queue.append((self._build_url(start_url), 0))
        start_domain = self._get_domain(start_url)
        exclude_re = [re.compile(p, re.IGNORECASE) for p in (exclude_patterns or [])]
        include_re = [re.compile(p, re.IGNORECASE) for p in (include_patterns or [])]

        while queue and len(visited) < max_pages:
            url, depth = queue.popleft()

            if url in visited:
                continue
            if depth > max_depth:
                continue

            # Filter
            should_skip = False
            for pat in exclude_re:
                if pat.search(url):
                    should_skip = True
                    break
            if should_skip:
                continue

            if include_re:
                should_include = False
                for pat in include_re:
                    if pat.search(url):
                        should_include = True
                        break
                if not should_include:
                    continue

            # Domain check
            if same_domain_only and self._get_domain(url) != start_domain:
                continue

            try:
                response = await self.get(url, tag=f"crawl-depth-{depth}")
                visited[url] = response

                # Extract and queue links
                if response.is_html and depth < max_depth:
                    links = response.extract_links()
                    for link in links:
                        abs_link = self._resolve_url(url, link)
                        if abs_link and abs_link not in visited:
                            queue.append((abs_link, depth + 1))

            except Exception as e:
                logger.debug(f"Crawl error on {url}: {e}")

        return visited

    async def spider_forms(
        self, start_url: str, max_pages: int = 50
    ) -> List[Dict[str, Any]]:
        """Spider que coleta todos os formularios encontrados."""
        pages = await self.crawl(start_url, max_pages=max_pages)
        all_forms: List[Dict[str, Any]] = []
        for url, response in pages.items():
            forms = response.extract_forms()
            for form in forms:
                form["page_url"] = url
                all_forms.append(form)
        return all_forms

    async def enumerate_endpoints(
        self,
        base_url: str,
        wordlist: Optional[List[str]] = None,
        extensions: Optional[List[str]] = None,
        concurrency: int = 20,
        status_codes: Optional[Set[int]] = None,
    ) -> List[Dict[str, Any]]:
        """Directory/endpoint brute force.

        Testa wordlist de paths contra o servidor.
        """
        if wordlist is None:
            wordlist = DEFAULT_WORDLIST

        if extensions is None:
            extensions = [
                "",
                ".php",
                ".html",
                ".js",
                ".json",
                ".xml",
                ".txt",
                ".asp",
                ".aspx",
                ".jsp",
            ]

        valid_codes = status_codes or {200, 201, 204, 301, 302, 307, 308, 403}
        found: List[Dict[str, Any]] = []
        semaphore = asyncio.Semaphore(concurrency)

        async def check_path(path: str, ext: str) -> Optional[Dict[str, Any]]:
            full_url = f"{base_url.rstrip('/')}/{path.lstrip('/')}{ext}"
            async with semaphore:
                try:
                    resp = await self.get(
                        full_url, tag="dir-enum", allow_redirects=False
                    )
                    if resp.status_code in valid_codes:
                        return {
                            "url": full_url,
                            "status": resp.status_code,
                            "size": resp.body_size,
                            "content_type": resp.content_type,
                            "title": resp.title,
                            "redirect": resp.header("Location", ""),
                        }
                except Exception as e:
                    logger.debug("Directory brute path check error for %s: %s", word, e)
            return None

        tasks = []
        for word in wordlist:
            for ext in extensions:
                tasks.append(check_path(word, ext))

        results = await asyncio.gather(*tasks)
        found = [r for r in results if r is not None]

        return found

    def _resolve_url(self, base: str, link: str) -> Optional[str]:
        """Resolve URL relativa para absoluta."""
        if not link:
            return None
        if link.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
            return None
        try:
            return urllib.parse.urljoin(base, link)
        except Exception:
            return None

    # ── Utility Methods ─────────────────────────────────────────────────

    async def fingerprint(self, url: Optional[str] = None) -> Dict[str, Any]:
        """Fingerprint completo de um servidor."""
        target = url or self.base_url
        if not target:
            return {"error": "No URL specified"}

        response = await self.get(target, tag="fingerprint")
        fp = ServerFingerprinter.fingerprint(response)

        # Add TLS analysis
        parsed = urllib.parse.urlparse(target)
        if parsed.scheme == "https":
            tls = await TLSAnalyzer.analyze(parsed.hostname or "", parsed.port or 443)
            fp["tls"] = tls

        # Add DNS
        dns_records = await self.dns.get_all_records(parsed.hostname or "")
        fp["dns"] = dns_records

        return fp

    async def check_cors(
        self, url: str, origins: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Testa configuracao CORS."""
        test_origins = origins or [
            "https://evil.com",
            "https://attacker.com",
            "null",
            f"https://{self._get_domain(url)}.evil.com",
            "https://localhost",
            "file://",
        ]

        results: Dict[str, Any] = {"url": url, "tests": [], "vulnerable": False}

        for origin in test_origins:
            response = await self.get(
                url,
                headers={"Origin": origin},
                tag=f"cors-{origin}",
            )
            acao = response.header("Access-Control-Allow-Origin")
            acac = response.header("Access-Control-Allow-Credentials")

            test_result = {
                "origin": origin,
                "reflected": acao == origin,
                "allow_origin": acao,
                "allow_credentials": acac,
                "vulnerable": False,
            }

            if acao == origin or acao == "*":
                test_result["vulnerable"] = True
                results["vulnerable"] = True
                if acac and acac.lower() == "true":
                    test_result["severity"] = "CRITICAL"
                else:
                    test_result["severity"] = "HIGH"

            results["tests"].append(test_result)

        return results

    async def check_methods(self, url: str) -> Dict[str, Any]:
        """Testa metodos HTTP permitidos."""
        methods = [
            "GET",
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
            "OPTIONS",
            "HEAD",
            "TRACE",
            "CONNECT",
        ]
        results: Dict[str, Any] = {"url": url, "allowed": [], "dangerous": []}

        for method in methods:
            try:
                resp = await self.request(
                    method,
                    url,
                    allow_redirects=False,
                    timeout=10.0,
                    tag=f"method-{method}",
                )
                if resp.status_code not in (405, 501):
                    results["allowed"].append(
                        {
                            "method": method,
                            "status": resp.status_code,
                        }
                    )
                    if method in ("TRACE", "CONNECT", "PUT", "DELETE"):
                        results["dangerous"].append(method)
            except Exception as e:
                logger.debug("HTTP method test error for %s: %s", method, e)

        return results

    async def batch_get(
        self, urls: List[str], concurrency: int = 10
    ) -> Dict[str, ResponseData]:
        """GET em multiplas URLs com controle de concorrencia."""
        result: Dict[str, ResponseData] = {}
        sem = asyncio.Semaphore(concurrency)

        async def _fetch(url: str):
            async with sem:
                resp = await self.get(url, tag="batch")
                result[url] = resp

        await asyncio.gather(*[_fetch(u) for u in urls])
        return result

    @property
    def stats(self) -> Dict[str, Any]:
        """Retorna estatisticas da sessao."""
        elapsed = time.time() - self._stats["start_time"]
        rps = self._stats["total_requests"] / max(elapsed, 0.001)
        return {
            **self._stats,
            "elapsed_seconds": round(elapsed, 2),
            "effective_rps": round(rps, 2),
            "cache": self.cache.stats if self.cache else None,
            "rate_limiter": self.rate_limiter.stats,
            "cookies": self.cookies.count,
            "proxies_alive": self.proxy_rotator.alive_count,
            "har_entries": self.har_recorder.entry_count if self.har_recorder else 0,
        }


# ════════════════════════════════════════════════════════════════════════════
# DEFAULT WORDLIST — Paths mais comuns para directory enumeration
# ════════════════════════════════════════════════════════════════════════════

DEFAULT_WORDLIST = [
    "admin",
    "administrator",
    "login",
    "wp-admin",
    "wp-login",
    "dashboard",
    "panel",
    "api",
    "api/v1",
    "api/v2",
    "api/v3",
    "graphql",
    "swagger",
    "docs",
    "openapi",
    "health",
    "status",
    "config",
    "configuration",
    "settings",
    "setup",
    "install",
    "backup",
    "backups",
    "dump",
    "database",
    "db",
    "sql",
    "test",
    "testing",
    "debug",
    "dev",
    "staging",
    "sandbox",
    "upload",
    "uploads",
    "files",
    "media",
    "static",
    "assets",
    "images",
    "img",
    "css",
    "js",
    "scripts",
    "fonts",
    "robots.txt",
    "sitemap.xml",
    "crossdomain.xml",
    ".well-known",
    ".git",
    ".svn",
    ".env",
    ".env.local",
    ".env.production",
    ".htaccess",
    ".htpasswd",
    "web.config",
    "server-status",
    "server-info",
    "phpinfo",
    "info",
    "xmlrpc",
    "wp-json",
    "actuator",
    "actuator/health",
    "actuator/env",
    "actuator/info",
    "console",
    "adminer",
    "phpmyadmin",
    "pma",
    "mysql",
    "redis",
    "memcached",
    "elasticsearch",
    "kibana",
    "grafana",
    "prometheus",
    "metrics",
    "monitoring",
    "trace",
    "traces",
    "swagger-ui",
    "api-docs",
    "redoc",
    "rapidoc",
    "wp-content",
    "wp-includes",
    "xmlrpc.php",
    "readme",
    ".git/config",
    ".git/HEAD",
    ".gitignore",
    ".dockerignore",
    "Dockerfile",
    "docker-compose.yml",
    "package.json",
    "composer.json",
    "Gemfile",
    "requirements.txt",
    "Pipfile",
    "node_modules",
    "vendor",
    "bower_components",
    "cgi-bin",
    "cgi",
    "fcgi",
    "cron",
    "cronjobs",
    "log",
    "logs",
    "error.log",
    "access.log",
    "debug.log",
    "tmp",
    "temp",
    "cache",
    "session",
    "sessions",
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
    "oauth",
    "sso",
    "token",
    "tokens",
    "refresh",
    "verify",
    "confirm",
    "password",
    "reset",
    "forgot",
    "recover",
    "recovery",
    "search",
    "query",
    "find",
    "lookup",
    "export",
    "download",
    "report",
    "reports",
    "invoice",
    "invoices",
    "payment",
    "payments",
    "checkout",
    "cart",
    "order",
    "orders",
    "product",
    "products",
    "category",
    "categories",
    "tag",
    "tags",
    "comment",
    "comments",
    "review",
    "reviews",
    "message",
    "messages",
    "notification",
    "notifications",
    "webhook",
    "webhooks",
    "callback",
    "callbacks",
    "socket",
    "ws",
    "websocket",
    "socket.io",
    "feed",
    "rss",
    "atom",
    "changelog",
    "version",
    "about",
    "contact",
    "help",
    "faq",
    "terms",
    "privacy",
    "policy",
    "legal",
    "tos",
    "error",
    "404",
    "403",
    "500",
    "internal",
    "private",
    "secure",
    "restricted",
    "management",
    "manage",
    "control",
    "portal",
    "monitoring",
    "healthcheck",
    "readiness",
    "liveness",
    "env",
    "environment",
    "variables",
    "secret",
    "secrets",
    "credential",
    "credentials",
    "key",
    "keys",
    "cert",
    "certs",
    "certificate",
]


# ════════════════════════════════════════════════════════════════════════════
# HELPERS
# ════════════════════════════════════════════════════════════════════════════


def _extract_attr(attrs_str: str, attr_name: str) -> Optional[str]:
    """Extrai valor de atributo HTML de string de atributos."""
    patterns = [
        rf'{attr_name}\s*=\s*"([^"]*)"',
        rf"{attr_name}\s*=\s*'([^']*)'",
        rf"{attr_name}\s*=\s*(\S+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, attrs_str, re.IGNORECASE)
        if match:
            return match.group(1)
    return None


def parse_url(url: str) -> Dict[str, Any]:
    """Parseia URL e retorna componentes."""
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    return {
        "scheme": parsed.scheme,
        "hostname": parsed.hostname,
        "port": parsed.port,
        "path": parsed.path,
        "query": parsed.query,
        "params": {k: v[0] if len(v) == 1 else v for k, v in params.items()},
        "fragment": parsed.fragment,
        "netloc": parsed.netloc,
        "full": url,
    }


def build_url(
    base: str, path: str = "", params: Optional[Dict[str, str]] = None
) -> str:
    """Constroi URL a partir de componentes."""
    url = f"{base.rstrip('/')}/{path.lstrip('/')}" if path else base
    if params:
        query = urllib.parse.urlencode(params)
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}{query}"
    return url


def normalize_url(url: str) -> str:
    """Normaliza URL (remove fragmento, trailing slash, normaliza case)."""
    parsed = urllib.parse.urlparse(url)
    normalized = urllib.parse.urlunparse(
        (
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path.rstrip("/") or "/",
            parsed.params,
            parsed.query,
            "",  # No fragment
        )
    )
    return normalized
