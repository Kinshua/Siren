#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  ⚙️  ABYSSAL ENGINE v2.0 — Real AI Execution × SIREN Arsenal  ⚙️         ██
██                                                                                ██
██  The convergence point. Where Shannon's brain meets SIREN's body.          ██
██  This module orchestrates EVERYTHING:                                          ██
██                                                                                ██
██    1. Loads config (target, repo, auth, rules, AI provider)                    ██
██    2. Initializes the 5-phase pipeline                                         ██
██    3. Builds context-rich prompts per agent                                    ██
██    4. Executes via REAL AI (Anthropic/OpenAI/Ollama) with streaming            ██
██    5. Falls back to SIREN-native tool execution when no AI                 ██
██    6. Validates deliverables, checksums, and compiles final report             ██
██                                                                                ██
██  Supported AI Providers:                                                       ██
██    - Anthropic (Claude) — native, preferred                                    ██
██    - OpenAI (GPT) — via compatible interface                                   ██
██    - Ollama (local) — for airgapped environments                               ██
██    - Any OpenAI-compatible API (LiteLLM, vLLM, etc.)                          ██
██                                                                                ██
██  Features:                                                                     ██
██    - Streaming responses with live token counting                              ██
██    - Automatic cost tracking per agent                                         ██
██    - Tool-use integration (function calling)                                   ██
██    - Context window management with smart truncation                           ██
██    - Rate limit handling with exponential backoff                              ██
██    - Multi-provider failover chain                                             ██
██    - Deliverable extraction from AI responses                                  ██
██    - Git checkpoint integration                                                ██
██    - Session state persistence                                                 ██
██                                                                                ██
██  "O motor do abismo nao ronca. Ele sussurra — e tudo desmorona."              ██
██                                                                                ██
████████████████████████████████████████████████████████████████████████████████████
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from .agents import AGENTS, AgentDefinition, AgentStatus, PhaseName
from .models import ModelTier, get_all_models, resolve_model, validate_credentials
from .pipeline import Pipeline, PipelineResult, PipelineState, Result

logger = logging.getLogger("siren.engine")


# ════════════════════════════════════════════════════════════════════════════
# ENGINE CONFIGURATION
# ════════════════════════════════════════════════════════════════════════════


@dataclass
class EngineConfig:
    """Full configuration for the Abyssal Engine.

    Combines Shannon parameters (target, repo, auth) with SIREN
    capabilities (evasion, tool domains, kraken engine) and AI provider
    settings for real execution.
    """

    # ── Target ────────────────────────────────────────────────────────
    target_url: str = ""
    repo_path: str = ""

    # ── Output ────────────────────────────────────────────────────────
    output_dir: str = "./audit-logs"
    workspace: Optional[str] = None

    # ── Authentication (Shannon-style) ────────────────────────────────
    auth_login_url: Optional[str] = None
    auth_username: Optional[str] = None
    auth_password: Optional[str] = None
    auth_totp_secret: Optional[str] = None
    auth_login_flow: Optional[List[str]] = None
    auth_success_condition: Optional[str] = None

    # ── Rules (Shannon-style) ─────────────────────────────────────────
    avoid_paths: List[str] = field(default_factory=list)
    avoid_rules: List[Dict[str, str]] = field(default_factory=list)
    focus_paths: List[str] = field(default_factory=list)
    focus_rules: List[Dict[str, str]] = field(default_factory=list)

    # ── Pipeline ──────────────────────────────────────────────────────
    retry_preset: str = "production"
    max_concurrent_pipelines: int = 5
    pipeline_testing: bool = False
    enable_exploitation_gating: bool = True
    enable_git_checkpoints: bool = True

    # ── SIREN-specific ────────────────────────────────────────────
    enable_kraken_evasion: bool = True
    enable_safe_mode: bool = True
    attack_domains: Optional[List[str]] = None
    evasion_level: str = "maximum"

    # ── AI Provider Configuration ─────────────────────────────────────
    api_key: Optional[str] = None
    api_base_url: Optional[str] = None
    provider: str = "auto"  # auto, anthropic, openai, ollama, litellm
    model_overrides: Dict[str, str] = field(default_factory=dict)
    max_tokens_per_request: int = 64000
    temperature: float = 0.0
    enable_streaming: bool = True
    enable_tool_use: bool = True
    request_timeout: int = 600
    max_cost_usd: float = 0.0  # 0 = unlimited
    failover_providers: List[str] = field(default_factory=list)

    # ── Context Window ────────────────────────────────────────────────
    max_context_tokens: int = 200_000
    context_reserve_output: int = 64_000
    truncation_strategy: str = "smart"  # smart, tail, none

    def validate(self) -> Dict[str, Any]:
        """Validate config and return full diagnostics report."""
        errors: List[str] = []
        warnings: List[str] = []
        info: List[str] = []

        if not self.target_url:
            errors.append("target_url is required")
        if not self.repo_path:
            errors.append("repo_path is required for white-box analysis")
        elif not Path(self.repo_path).exists():
            errors.append(f"repo_path not found: {self.repo_path}")
        else:
            repo = Path(self.repo_path)
            try:
                file_count = sum(1 for _ in repo.rglob("*") if _.is_file())
                info.append(f"Repository has {file_count} files")
            except Exception:
                logger.debug("Could not count repo files")

        creds = validate_credentials()
        if not creds["valid"]:
            if creds["missing"]:
                warnings.append(
                    f"AI credentials missing: {', '.join(creds['missing'])}. "
                    "Pipeline will run in local-only mode."
                )
        else:
            info.append(f"AI provider: {creds.get('provider', 'unknown')}")

        provider_info = self._detect_provider()
        info.append(f"Detected provider: {provider_info['name']}")
        if provider_info.get("warning"):
            warnings.append(provider_info["warning"])

        if self.auth_login_url and not self.auth_username:
            warnings.append("auth_login_url set but no auth_username provided")
        if self.max_cost_usd > 0:
            info.append(f"Cost cap: ${self.max_cost_usd:.2f}")
        if self.pipeline_testing:
            info.append("Testing mode: reduced retries & delays")

        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings,
            "info": info,
            "credentials": creds,
            "provider": provider_info,
        }

    def _detect_provider(self) -> Dict[str, Any]:
        """Auto-detect AI provider from environment/config."""
        if self.provider != "auto":
            return {"name": self.provider, "configured": True}
        if self.api_key or os.environ.get("ANTHROPIC_API_KEY"):
            return {"name": "anthropic", "configured": True}
        if os.environ.get("OPENAI_API_KEY"):
            return {"name": "openai", "configured": True}
        if os.environ.get("OLLAMA_HOST") or os.environ.get("OLLAMA_BASE_URL"):
            return {"name": "ollama", "configured": True}
        if os.environ.get("LITELLM_API_KEY") or os.environ.get("LITELLM_BASE_URL"):
            return {"name": "litellm", "configured": True}
        return {
            "name": "none",
            "configured": False,
            "warning": (
                "No AI provider detected. Set ANTHROPIC_API_KEY, "
                "OPENAI_API_KEY, or OLLAMA_HOST."
            ),
        }

    def get_api_key(self) -> Optional[str]:
        """Resolve API key from config or environment."""
        if self.api_key:
            return self.api_key
        provider = self._detect_provider()["name"]
        env_map = {
            "anthropic": "ANTHROPIC_API_KEY",
            "openai": "OPENAI_API_KEY",
            "ollama": None,
            "litellm": "LITELLM_API_KEY",
        }
        env_var = env_map.get(provider)
        return os.environ.get(env_var) if env_var else None

    def get_base_url(self) -> Optional[str]:
        """Resolve API base URL for the provider."""
        if self.api_base_url:
            return self.api_base_url
        provider = self._detect_provider()["name"]
        defaults = {
            "anthropic": "https://api.anthropic.com",
            "openai": "https://api.openai.com/v1",
            "ollama": os.environ.get("OLLAMA_HOST", "http://localhost:11434"),
            "litellm": os.environ.get("LITELLM_BASE_URL", "http://localhost:4000"),
        }
        return defaults.get(provider)


# ════════════════════════════════════════════════════════════════════════════
# AI PROVIDER — Real integration with Claude / GPT / Ollama
# ════════════════════════════════════════════════════════════════════════════

PRICING: Dict[str, Dict[str, float]] = {
    "claude-opus-4-20250514": {"input": 15.0, "output": 75.0},
    "claude-sonnet-4-20250514": {"input": 3.0, "output": 15.0},
    "claude-haiku-4-5-20251001": {"input": 0.80, "output": 4.0},
    "claude-sonnet-4-6": {"input": 3.0, "output": 15.0},
    "claude-opus-4-6": {"input": 15.0, "output": 75.0},
    "gpt-4o": {"input": 2.50, "output": 10.0},
    "gpt-4o-mini": {"input": 0.15, "output": 0.60},
    "gpt-4.1": {"input": 2.0, "output": 8.0},
    "gpt-4.1-mini": {"input": 0.40, "output": 1.60},
    "gpt-4.1-nano": {"input": 0.10, "output": 0.40},
    "o3": {"input": 2.0, "output": 8.0},
    "o3-mini": {"input": 1.10, "output": 4.40},
    "o4-mini": {"input": 1.10, "output": 4.40},
}


@dataclass
class AIResponse:
    """Structured response from an AI provider call."""

    content: str = ""
    model: str = ""
    provider: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    cost_usd: float = 0.0
    duration_s: float = 0.0
    stop_reason: str = ""
    tool_calls: List[Dict[str, Any]] = field(default_factory=list)
    raw_response: Optional[Any] = None
    error: Optional[str] = None
    retries: int = 0

    @property
    def success(self) -> bool:
        return self.error is None and len(self.content) > 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model": self.model,
            "provider": self.provider,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens": self.total_tokens,
            "cost_usd": round(self.cost_usd, 6),
            "duration_s": round(self.duration_s, 2),
            "stop_reason": self.stop_reason,
            "content_length": len(self.content),
            "tool_calls": len(self.tool_calls),
            "retries": self.retries,
            "error": self.error,
        }


class _RateLimitError(Exception):
    """429 rate limit from AI provider."""


class _OverloadedError(Exception):
    """529 / 503 overloaded from AI provider."""


class _AuthError(Exception):
    """401/403 authentication error."""


class _CostCapError(Exception):
    """Spending cap exceeded."""


class AIProvider:
    """Unified AI provider interface for Anthropic, OpenAI, Ollama, etc.

    Handles:
    - Provider auto-detection from environment
    - Request construction per provider format
    - Cost calculation from token counts
    - Rate limit & overload retries with exponential backoff
    - Provider failover chain
    """

    def __init__(self, config: EngineConfig) -> None:
        self.config = config
        self._provider = config._detect_provider()["name"]
        self._api_key = config.get_api_key()
        self._base_url = config.get_base_url()
        self._total_cost = 0.0
        self._total_input_tokens = 0
        self._total_output_tokens = 0
        self._request_count = 0

    async def invoke(
        self,
        prompt: str,
        model_id: str,
        system_prompt: Optional[str] = None,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        tools: Optional[List[Dict[str, Any]]] = None,
    ) -> AIResponse:
        """Invoke the AI model with full error handling and retry logic."""
        max_tok = max_tokens or self.config.max_tokens_per_request
        temp = temperature if temperature is not None else self.config.temperature
        start = time.time()
        retries = 0
        last_error = ""

        providers_to_try = [self._provider] + self.config.failover_providers

        for provider in providers_to_try:
            for attempt in range(50):
                try:
                    response = await self._call_provider(
                        provider,
                        prompt,
                        model_id,
                        system_prompt,
                        max_tok,
                        temp,
                        tools,
                    )
                    response.duration_s = time.time() - start
                    response.retries = retries
                    response.cost_usd = self._calculate_cost(
                        model_id,
                        response.input_tokens,
                        response.output_tokens,
                    )

                    self._total_cost += response.cost_usd
                    self._total_input_tokens += response.input_tokens
                    self._total_output_tokens += response.output_tokens
                    self._request_count += 1

                    if (
                        self.config.max_cost_usd > 0
                        and self._total_cost > self.config.max_cost_usd
                    ):
                        response.error = (
                            f"Cost cap exceeded: ${self._total_cost:.2f} > "
                            f"${self.config.max_cost_usd:.2f}"
                        )
                        return response

                    return response

                except _RateLimitError as e:
                    retries += 1
                    delay = min(5 * (2**attempt), 1800)
                    logger.warning(
                        "Rate limited (attempt %d): %s — waiting %.0fs",
                        attempt + 1,
                        e,
                        delay,
                    )
                    await asyncio.sleep(delay)
                except _OverloadedError as e:
                    retries += 1
                    delay = min(10 * (2**attempt), 600)
                    logger.warning(
                        "Overloaded (attempt %d): %s — waiting %.0fs",
                        attempt + 1,
                        e,
                        delay,
                    )
                    await asyncio.sleep(delay)
                except _AuthError as e:
                    last_error = f"Auth failed for {provider}: {e}"
                    logger.error(last_error)
                    break
                except _CostCapError as e:
                    return AIResponse(error=str(e), duration_s=time.time() - start)
                except Exception as e:
                    retries += 1
                    last_error = str(e)
                    logger.debug(
                        "Provider %s attempt %d error: %s", provider, attempt, e
                    )
                    if attempt < 3:
                        await asyncio.sleep(2**attempt)
                    else:
                        break

        return AIResponse(
            error=last_error or "All providers failed",
            duration_s=time.time() - start,
            retries=retries,
        )

    async def _call_provider(
        self,
        provider: str,
        prompt: str,
        model_id: str,
        system_prompt: Optional[str],
        max_tokens: int,
        temperature: float,
        tools: Optional[List[Dict[str, Any]]],
    ) -> AIResponse:
        """Dispatch to the correct provider implementation."""
        dispatch = {
            "anthropic": self._call_anthropic,
            "openai": self._call_openai,
            "ollama": self._call_ollama,
        }
        handler = dispatch.get(provider, self._call_openai_compatible)
        return await handler(
            prompt,
            model_id,
            system_prompt,
            max_tokens,
            temperature,
            tools,
        )

    async def _call_anthropic(
        self,
        prompt: str,
        model_id: str,
        system_prompt: Optional[str],
        max_tokens: int,
        temperature: float,
        tools: Optional[List[Dict[str, Any]]],
    ) -> AIResponse:
        """Call Anthropic Claude API via urllib (zero dependencies)."""
        api_key = self._api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            raise _AuthError("ANTHROPIC_API_KEY not set")

        headers = {
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        }
        body: Dict[str, Any] = {
            "model": model_id,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system_prompt:
            body["system"] = system_prompt
        if tools and self.config.enable_tool_use:
            body["tools"] = tools

        data = json.dumps(body).encode("utf-8")
        base = self._base_url or "https://api.anthropic.com"
        url = f"{base}/v1/messages"
        req = Request(url, data=data, headers=headers, method="POST")

        try:
            loop = asyncio.get_event_loop()
            raw = await loop.run_in_executor(
                None,
                lambda: urlopen(req, timeout=self.config.request_timeout).read(),
            )
            resp = json.loads(raw)
        except HTTPError as e:
            status = e.code
            body_text = ""
            try:
                body_text = e.read().decode("utf-8", errors="ignore")
            except Exception:
                logger.debug("Could not read error body")
            if status == 429:
                raise _RateLimitError(f"429: {body_text[:200]}")
            if status == 529:
                raise _OverloadedError(f"529: {body_text[:200]}")
            if status in (401, 403):
                raise _AuthError(f"{status}: {body_text[:200]}")
            raise RuntimeError(f"Anthropic {status}: {body_text[:500]}")

        content_parts = resp.get("content", [])
        text = ""
        tc = []
        for part in content_parts:
            if part.get("type") == "text":
                text += part.get("text", "")
            elif part.get("type") == "tool_use":
                tc.append(part)
        usage = resp.get("usage", {})
        return AIResponse(
            content=text,
            model=resp.get("model", model_id),
            provider="anthropic",
            input_tokens=usage.get("input_tokens", 0),
            output_tokens=usage.get("output_tokens", 0),
            total_tokens=usage.get("input_tokens", 0) + usage.get("output_tokens", 0),
            stop_reason=resp.get("stop_reason", ""),
            tool_calls=tc,
            raw_response=resp,
        )

    async def _call_openai(
        self,
        prompt: str,
        model_id: str,
        system_prompt: Optional[str],
        max_tokens: int,
        temperature: float,
        tools: Optional[List[Dict[str, Any]]],
    ) -> AIResponse:
        """Call OpenAI API."""
        return await self._call_openai_compatible(
            prompt,
            model_id,
            system_prompt,
            max_tokens,
            temperature,
            tools,
            base_url="https://api.openai.com/v1",
            api_key=os.environ.get("OPENAI_API_KEY", self._api_key or ""),
        )

    async def _call_openai_compatible(
        self,
        prompt: str,
        model_id: str,
        system_prompt: Optional[str],
        max_tokens: int,
        temperature: float,
        tools: Optional[List[Dict[str, Any]]],
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
    ) -> AIResponse:
        """Call any OpenAI-compatible API."""
        key = api_key or self._api_key or ""
        url = f"{base_url or self._base_url or 'https://api.openai.com/v1'}/chat/completions"

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        body: Dict[str, Any] = {
            "model": model_id,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if tools and self.config.enable_tool_use:
            oai_tools = []
            for tool in tools:
                oai_tools.append(
                    {
                        "type": "function",
                        "function": {
                            "name": tool.get("name", ""),
                            "description": tool.get("description", ""),
                            "parameters": tool.get("input_schema", {}),
                        },
                    }
                )
            body["tools"] = oai_tools

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {key}",
        }
        data = json.dumps(body).encode("utf-8")
        req = Request(url, data=data, headers=headers, method="POST")

        try:
            loop = asyncio.get_event_loop()
            raw = await loop.run_in_executor(
                None,
                lambda: urlopen(req, timeout=self.config.request_timeout).read(),
            )
            resp = json.loads(raw)
        except HTTPError as e:
            status = e.code
            body_text = ""
            try:
                body_text = e.read().decode("utf-8", errors="ignore")
            except Exception:
                logger.debug("Could not read error body")
            if status == 429:
                raise _RateLimitError(f"429: {body_text[:200]}")
            if status in (401, 403):
                raise _AuthError(f"{status}: {body_text[:200]}")
            raise RuntimeError(f"OpenAI API {status}: {body_text[:500]}")

        choices = resp.get("choices", [])
        content = ""
        tc = []
        if choices:
            msg = choices[0].get("message", {})
            content = msg.get("content", "") or ""
            for t in msg.get("tool_calls", []):
                tc.append(t)
        usage = resp.get("usage", {})
        return AIResponse(
            content=content,
            model=resp.get("model", model_id),
            provider="openai",
            input_tokens=usage.get("prompt_tokens", 0),
            output_tokens=usage.get("completion_tokens", 0),
            total_tokens=usage.get("total_tokens", 0),
            stop_reason=choices[0].get("finish_reason", "") if choices else "",
            tool_calls=tc,
            raw_response=resp,
        )

    async def _call_ollama(
        self,
        prompt: str,
        model_id: str,
        system_prompt: Optional[str],
        max_tokens: int,
        temperature: float,
        tools: Optional[List[Dict[str, Any]]],
    ) -> AIResponse:
        """Call Ollama local API."""
        host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        url = f"{host}/api/chat"

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        body = {
            "model": model_id,
            "messages": messages,
            "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens},
        }
        data = json.dumps(body).encode("utf-8")
        req = Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            loop = asyncio.get_event_loop()
            raw = await loop.run_in_executor(
                None,
                lambda: urlopen(req, timeout=self.config.request_timeout).read(),
            )
            resp = json.loads(raw)
        except HTTPError as e:
            body_text = ""
            try:
                body_text = e.read().decode("utf-8", errors="ignore")
            except Exception:
                logger.debug("Could not read Ollama error body")
            raise RuntimeError(f"Ollama {e.code}: {body_text[:500]}")

        msg = resp.get("message", {})
        eval_count = resp.get("eval_count", 0)
        prompt_eval = resp.get("prompt_eval_count", 0)
        return AIResponse(
            content=msg.get("content", ""),
            model=resp.get("model", model_id),
            provider="ollama",
            input_tokens=prompt_eval,
            output_tokens=eval_count,
            total_tokens=prompt_eval + eval_count,
            stop_reason="stop",
        )

    def _calculate_cost(
        self,
        model_id: str,
        input_tokens: int,
        output_tokens: int,
    ) -> float:
        """Calculate cost in USD from token counts."""
        pricing = None
        for model_key, rates in PRICING.items():
            if model_id.startswith(model_key) or model_key.startswith(model_id):
                pricing = rates
                break
        if not pricing:
            pricing = {"input": 3.0, "output": 15.0}
        return (
            input_tokens / 1_000_000 * pricing["input"]
            + output_tokens / 1_000_000 * pricing["output"]
        )

    @property
    def total_cost(self) -> float:
        return self._total_cost

    @property
    def total_tokens(self) -> int:
        return self._total_input_tokens + self._total_output_tokens

    @property
    def request_count(self) -> int:
        return self._request_count


# ════════════════════════════════════════════════════════════════════════════
# PROMPT TEMPLATES — Enhanced templates with full Shannon context
# ════════════════════════════════════════════════════════════════════════════

PROMPT_TEMPLATES: Dict[str, str] = {
    "pre-recon-code": """You are an expert security code auditor performing deep white-box analysis.

TARGET: {target_url}
REPOSITORY: {repo_path}

## Objective
Comprehensive static analysis to map attack surface.

## Required Analysis
1. **Technology Stack** — Frameworks, languages, databases, deployment
2. **Entry Points** — Every API route, controller, WebSocket handler
3. **Authentication** — All auth mechanisms, session mgmt, token handling
4. **Data Flows** — Trace user input → processing → dangerous sinks
5. **Dependencies** — Third-party packages, known CVEs, versions
6. **Configurations** — Secrets in config, debug flags, CORS settings
7. **Attack Surface Map** — Visual of exploitable areas

## Shannon Protocol
- Structured data flow analysis for EVERY user input
- Map source → transform → sink for injection paths
- Identify all deserialization, eval(), exec(), template rendering
- Document all file I/O, command execution, network calls
- Assess authentication bypass vectors from code patterns

{arsenal_context}
{rules_context}

Format: Markdown with code snippets and line references.
Write findings to: {deliverable_path}
""",
    "recon": """You are an expert penetration tester performing comprehensive reconnaissance.

TARGET: {target_url}
REPOSITORY: {repo_path}
CODE ANALYSIS: {pre_recon_deliverable}

## Required Tasks
1. **Port Scan** — Full TCP, top 1000 UDP, service version detection
2. **Technology Fingerprinting** — Server, framework, WAF, CDN
3. **Directory Discovery** — Brute-force paths, backup files, configs
4. **DNS Enumeration** — Subdomains, zone transfers, records
5. **SSL/TLS** — Certificate analysis, cipher suites, weaknesses
6. **HTTP Analysis** — Security headers, CORS, CSP, cookies
7. **Authentication Flow** — Map login/registration/reset
8. **API Discovery** — Swagger/OpenAPI, GraphQL, WADL
9. **Content Discovery** — Hidden params, debug endpoints, admin panels
10. **WAF Detection** — Identify and fingerprint WAF

{arsenal_context}
{auth_context}
{rules_context}

Write findings to: {deliverable_path}
""",
    "vuln-injection": """You are a vulnerability analyst specializing in ALL injection attacks.

TARGET: {target_url}
RECON: {recon_deliverable}
CODE: {pre_recon_deliverable}

## Injection Types (ALL)
- SQL Injection (Union, Boolean, Time, Error, Stacked, Second-order)
- NoSQL Injection (MongoDB, CouchDB, Redis)
- OS Command Injection (shell, exec, system, popen, backticks)
- Code Injection (eval, exec, Function constructor, vm.runInNewContext)
- SSTI (Jinja2, Twig, Freemarker, Velocity, Mako, EJS, Pug)
- LDAP / XPath / Header / Email / Expression Language Injection

## Shannon Protocol — Structured Data Flow
For EACH injection:
1. **Source** — Where user input enters
2. **Transform** — Sanitization/encoding/validation
3. **Sink** — Dangerous function reached
4. **Exploitability** — Can payload survive transforms?
5. **Impact** — Data exfil, RCE, privilege escalation

## Output
1. Analysis report (Markdown with evidence)
2. Exploitation queue (JSON): {{"vulnerabilities": [{{"type": "...", "endpoint": "...", "param": "...", "technique": "...", "severity": "...", "confidence": "...", "evidence": "..."}}]}}

{arsenal_context}
{rules_context}
Write to: {deliverable_path}
""",
    "vuln-xss": """You are a vulnerability analyst specializing in Cross-Site Scripting.

TARGET: {target_url}
RECON: {recon_deliverable}
CODE: {pre_recon_deliverable}

## XSS Types (ALL contexts)
- Reflected XSS (GET, POST, headers, fragments)
- Stored XSS (comments, profiles, messages, file uploads)
- DOM-based XSS (document.write, innerHTML, eval, location)
- Mutation XSS (mXSS via browser HTML parser quirks)
- Blind XSS (stored, triggers in admin/internal panels)
- Self-XSS chains (with CSRF or clickjacking)

## Context Analysis
For each reflection: identify output context (HTML body, attribute,
JavaScript string, template literal, URL, CSS, SVG/MathML).

## CSP Analysis
- Identify CSP headers and bypass vectors
- Check unsafe-inline, nonce reuse, JSONP, etc.

## Output: Analysis + exploitation queue JSON
{arsenal_context}
{rules_context}
Write to: {deliverable_path}
""",
    "vuln-auth": """You are a vulnerability analyst specializing in authentication flaws.

TARGET: {target_url}
RECON: {recon_deliverable}
CODE: {pre_recon_deliverable}

## Authentication Vulnerability Types
- Default/weak credentials
- Credential stuffing (no rate limit, no CAPTCHA)
- Account enumeration (timing, error messages)
- Session fixation/hijacking/prediction
- JWT vulns (alg:none, weak keys, algorithm confusion, jwk injection)
- CSRF in state-changing operations
- OAuth/OIDC misconfigs (open redirect, PKCE bypass, token leakage)
- SAML vulns (XML signature wrapping, assertion replay)
- MFA bypass (backup codes, race conditions, response manipulation)
- Password reset poisoning (Host header, email parameter injection)
- Remember-me token weakness / Account lockout bypass
- Registration abuse (email verification bypass, role assignment)

{arsenal_context}
{auth_context}
{rules_context}
Write to: {deliverable_path}
""",
    "vuln-ssrf": """You are a vulnerability analyst specializing in SSRF.

TARGET: {target_url}
RECON: {recon_deliverable}
CODE: {pre_recon_deliverable}

## SSRF Analysis (Exhaustive)
- Classic SSRF, Blind SSRF (OOB DNS/HTTP), SSRF via redirects
- SSRF in PDF generators / image processors
- SSRF via file:// / gopher:// protocols
- Cloud metadata: AWS 169.254.169.254, GCP metadata.google.internal,
  Azure 169.254.169.254, DigitalOcean 169.254.169.254
- Internal service discovery via SSRF
- DNS rebinding attacks

## URL Parser Differentials
- http://evil.com@internal/
- http://127.0.0.1#@evil.com
- http://127.1 / http://0x7f000001 / http://2130706433
- http://[::1]/

{arsenal_context}
{rules_context}
Write to: {deliverable_path}
""",
    "vuln-authz": """You are a vulnerability analyst specializing in authorization flaws.

TARGET: {target_url}
RECON: {recon_deliverable}
CODE: {pre_recon_deliverable}

## Authorization Vulnerability Types
- IDOR (sequential IDs, UUID prediction, hash reversal)
- Horizontal/Vertical privilege escalation
- Missing function-level access control
- Mass assignment, Path traversal for authz bypass
- GraphQL authorization abuse
- API versioning bypass, Tenant isolation failure
- Rate limiting bypass, Business logic flaws

## Methodology
1. Map ALL endpoints with required roles
2. Test each: unauthenticated, low-priv, different user, admin
3. Document every authz check failure with exact req/res

{arsenal_context}
{auth_context}
{rules_context}
Write to: {deliverable_path}
""",
}

# Generate exploitation templates for each vuln type
for _vtype in ("injection", "xss", "auth", "ssrf", "authz"):
    PROMPT_TEMPLATES[f"exploit-{_vtype}"] = (
        f"You are an expert exploit developer proving "
        f"{_vtype.upper()} vulnerabilities.\n\n"
        "TARGET: {target_url}\n"
        "VULNERABILITY ANALYSIS: {vuln_deliverable}\n\n"
        "## Exploitation Protocol\n"
        "For EACH vulnerability:\n"
        "1. **Reproduce** — Confirm on live target\n"
        "2. **Exploit** — Develop working exploit with max impact\n"
        "3. **Document** — Copy-paste PoC\n"
        "4. **Evidence** — Request/response, data extracted\n"
        "5. **Impact** — Real-world impact demo\n"
        "6. **Chain** — Combine with other vulns\n\n"
        "## STRICT RULES\n"
        "- **No Exploit = No Report** — Discard unproven hypotheses\n"
        "- Every finding MUST have a working PoC\n"
        "- Mark severity: Critical (9.0-10.0), High (7.0-8.9), "
        "Medium (4.0-6.9), Low (0.1-3.9)\n"
        "- If not exploitable, explain why and discard\n\n"
        "## Output\n"
        "Exploitation evidence in Markdown:\n"
        "- Vuln title + CVSS + CWE\n"
        "- Steps to reproduce\n"
        "- PoC (ready to copy-paste)\n"
        "- Impact demonstration\n"
        "- Remediation recommendation\n\n"
        "{arsenal_context}\n"
        "{auth_context}\n"
        "{rules_context}\n"
        "Write evidence to: {deliverable_path}\n"
    )

PROMPT_TEMPLATES[
    "report-executive"
] = """You are compiling a professional penetration test report.

TARGET: {target_url}
EXPLOITATION EVIDENCE: {all_evidence_files}

## Report Structure (REQUIRED)

### 1. Executive Summary
- Engagement overview, scope, methodology
- Key findings summary with risk distribution
- Overall security posture assessment

### 2. Scope & Methodology
- Target details and testing boundaries
- Tools used (SIREN arsenal)
- Shannon AI pipeline (5 phases, 13 agents)

### 3. Findings (Critical → Informational)
For EACH confirmed finding:
- **Title** with severity badge, **CVSS v3.1**, **CWE ID**
- **Description**, **Impact**, **PoC**, **Evidence**, **Remediation**, **References**

### 4. Risk Matrix & Recommendations
- Quick wins (<1 day), Short-term (1 week), Long-term (architecture)

### 5. Appendices — Raw requests/responses, tool output, pipeline metrics

## RULES
- ONLY confirmed exploited vulnerabilities
- ZERO hallucinated findings
- Every finding has a working PoC

Arsenal: {tools_used}
Metrics: {pipeline_metrics}
Write to: {deliverable_path}
"""


# ════════════════════════════════════════════════════════════════════════════
# SIREN TOOL DEFINITIONS — For AI function calling
# ════════════════════════════════════════════════════════════════════════════

SIREN_TOOLS: List[Dict[str, Any]] = [
    {
        "name": "scan_ports",
        "description": "Scan TCP/UDP ports on a target host.",
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Target hostname or IP"},
                "ports": {"type": "string", "description": "Port range e.g. '1-65535'"},
                "scan_type": {
                    "type": "string",
                    "enum": ["tcp", "udp", "syn"],
                },
            },
            "required": ["host"],
        },
    },
    {
        "name": "http_request",
        "description": "Send HTTP request with full control over method, headers, body, cookies.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "method": {
                    "type": "string",
                    "enum": [
                        "GET",
                        "POST",
                        "PUT",
                        "DELETE",
                        "PATCH",
                        "OPTIONS",
                        "HEAD",
                    ],
                },
                "headers": {"type": "object"},
                "body": {"type": "string"},
                "cookies": {"type": "object"},
                "follow_redirects": {"type": "boolean"},
                "proxy": {"type": "string"},
                "timeout": {"type": "integer"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "directory_bruteforce",
        "description": "Brute-force directories/files on a web server.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "wordlist": {"type": "string"},
                "extensions": {"type": "array", "items": {"type": "string"}},
                "threads": {"type": "integer"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "sql_injection_test",
        "description": "Test a parameter for SQL injection.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "param": {"type": "string"},
                "method": {"type": "string", "enum": ["GET", "POST"]},
                "technique": {
                    "type": "string",
                    "enum": ["union", "boolean", "time", "error", "stacked", "all"],
                },
                "dbms": {
                    "type": "string",
                    "enum": ["mysql", "postgres", "mssql", "oracle", "sqlite", "auto"],
                },
            },
            "required": ["url", "param"],
        },
    },
    {
        "name": "xss_test",
        "description": "Test for Cross-Site Scripting vulnerabilities.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "param": {"type": "string"},
                "context": {
                    "type": "string",
                    "enum": ["html", "attribute", "javascript", "url", "auto"],
                },
                "bypass_waf": {"type": "boolean"},
            },
            "required": ["url", "param"],
        },
    },
    {
        "name": "analyze_code",
        "description": "Static analysis on source code files.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "language": {"type": "string"},
                "rules": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["path"],
        },
    },
    {
        "name": "browser_navigate",
        "description": "Navigate headless browser and interact with page.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "actions": {"type": "array", "items": {"type": "object"}},
                "screenshot": {"type": "boolean"},
                "wait_for": {"type": "string"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "crack_hash",
        "description": "Attempt to crack a hash.",
        "input_schema": {
            "type": "object",
            "properties": {
                "hash": {"type": "string"},
                "hash_type": {
                    "type": "string",
                    "enum": ["md5", "sha1", "sha256", "bcrypt", "ntlm", "auto"],
                },
                "wordlist": {"type": "string"},
            },
            "required": ["hash"],
        },
    },
    {
        "name": "jwt_attack",
        "description": "Analyze and attack a JWT token.",
        "input_schema": {
            "type": "object",
            "properties": {
                "token": {"type": "string"},
                "attacks": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "none_alg, key_confusion, brute_secret, kid_injection",
                },
            },
            "required": ["token"],
        },
    },
    {
        "name": "ssrf_test",
        "description": "Test for Server-Side Request Forgery.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "param": {"type": "string"},
                "callback_url": {"type": "string"},
                "protocols": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["url", "param"],
        },
    },
    {
        "name": "fuzz_parameter",
        "description": "Fuzz a parameter with smart payload generation.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "param": {"type": "string"},
                "wordlist": {"type": "string"},
                "encoding": {"type": "string"},
                "max_payloads": {"type": "integer"},
            },
            "required": ["url", "param"],
        },
    },
    {
        "name": "subdomain_enum",
        "description": "Enumerate subdomains of a target domain.",
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
                "wordlist": {"type": "string"},
                "resolvers": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["domain"],
        },
    },
]


# ════════════════════════════════════════════════════════════════════════════
# DELIVERABLE EXTRACTOR
# ════════════════════════════════════════════════════════════════════════════


class DeliverableExtractor:
    """Extract structured deliverables from AI model output."""

    @staticmethod
    def extract(content: str, agent: AgentDefinition) -> Dict[str, Any]:
        """Extract all deliverables from AI output content."""
        result: Dict[str, Any] = {
            "report": content,
            "findings_count": 0,
            "severity_distribution": {},
            "exploitation_queue": None,
            "pocs": [],
            "hash": hashlib.sha256(content.encode()).hexdigest()[:16],
        }

        if agent.phase == "vulnerability-analysis":
            queue = DeliverableExtractor._extract_json_queue(content)
            if queue:
                result["exploitation_queue"] = queue
                result["findings_count"] = len(queue.get("vulnerabilities", []))

        severity_map = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        content_lower = content.lower()
        for sev in severity_map:
            severity_map[sev] = len(
                re.findall(rf"\b{sev}\b.*(?:severity|cvss|risk|finding)", content_lower)
            )
        result["severity_distribution"] = {
            k: v for k, v in severity_map.items() if v > 0
        }

        pocs = DeliverableExtractor._extract_pocs(content)
        result["pocs"] = pocs
        if not result["findings_count"]:
            result["findings_count"] = len(pocs)

        return result

    @staticmethod
    def _extract_json_queue(content: str) -> Optional[Dict[str, Any]]:
        """Extract JSON exploitation queue from content."""
        patterns = [
            r"```json\s*\n(.*?)\n\s*```",
            r"```\s*\n(\{.*?\"vulnerabilities\".*?\})\s*\n```",
            r"(\{\"vulnerabilities\"\s*:\s*\[.*?\]\})",
        ]
        for pattern in patterns:
            for match in re.findall(pattern, content, re.DOTALL):
                try:
                    parsed = json.loads(match)
                    if isinstance(parsed, dict) and "vulnerabilities" in parsed:
                        return parsed
                except json.JSONDecodeError:
                    continue
        return None

    @staticmethod
    def _extract_pocs(content: str) -> List[Dict[str, str]]:
        """Extract Proof-of-Concept code blocks from content."""
        pocs: List[Dict[str, str]] = []
        poc_patterns = [
            r"(?:###?\s*(?:PoC|Proof[- ]of[- ]Concept|Exploit|Payload).*?)\n```(\w*)\n(.*?)```",
            r"```(?:bash|sh|curl|python|http)\n(.*?)```",
        ]
        for pattern in poc_patterns:
            for match in re.finditer(pattern, content, re.DOTALL | re.IGNORECASE):
                groups = match.groups()
                if len(groups) == 2:
                    pocs.append({"language": groups[0], "code": groups[1].strip()})
                elif len(groups) == 1:
                    pocs.append({"language": "bash", "code": groups[0].strip()})
        return pocs


# ════════════════════════════════════════════════════════════════════════════
# CONTEXT MANAGER — Smart truncation for context window limits
# ════════════════════════════════════════════════════════════════════════════


class ContextManager:
    """Manage prompt context to fit within model token limits.

    Uses multi-strategy approach:
    1. Estimate token count from text
    2. Priority-based section inclusion
    3. Smart truncation (keep headers, remove middle)
    """

    CHARS_PER_TOKEN = {
        "english": 4.0,
        "code": 3.5,
        "json": 3.0,
        "markdown": 3.8,
        "mixed": 3.7,
    }

    @classmethod
    def estimate_tokens(cls, text: str, content_type: str = "mixed") -> int:
        """Estimate token count from text."""
        if not text:
            return 0
        chars_per = cls.CHARS_PER_TOKEN.get(content_type, 3.7)
        code_blocks = len(re.findall(r"```", text))
        json_ratio = text.count("{") / max(len(text), 1)
        if code_blocks > 4 or json_ratio > 0.02:
            chars_per = min(chars_per, 3.2)
        return max(1, int(len(text) / chars_per))

    @classmethod
    def fit_to_budget(
        cls,
        sections: Dict[str, str],
        priorities: Dict[str, int],
        budget_tokens: int,
    ) -> str:
        """Assemble sections within token budget (higher priority first)."""
        sorted_sections = sorted(
            sections.items(),
            key=lambda x: priorities.get(x[0], 0),
            reverse=True,
        )
        result_parts = []
        remaining = budget_tokens

        for name, content in sorted_sections:
            tokens = cls.estimate_tokens(content)
            if tokens <= remaining:
                result_parts.append(content)
                remaining -= tokens
            elif remaining > 500:
                result_parts.append(cls.smart_truncate(content, remaining))
                remaining = 0
                break

        return "\n\n".join(result_parts)

    @classmethod
    def smart_truncate(cls, text: str, target_tokens: int) -> str:
        """Intelligently truncate keeping headers and structure."""
        target_chars = int(target_tokens * 3.7)
        if len(text) <= target_chars:
            return text

        lines = text.split("\n")
        keep_start = max(int(len(lines) * 0.3), 20)
        keep_end = max(int(len(lines) * 0.1), 5)

        kept = set(range(keep_start))
        kept.update(range(len(lines) - keep_end, len(lines)))
        # Always keep markdown headers
        for i, line in enumerate(lines):
            if line.strip().startswith("#"):
                kept.add(i)

        result_lines: List[str] = []
        prev_kept = True
        for i, line in enumerate(lines):
            if i in kept:
                if not prev_kept:
                    result_lines.append(
                        "\n[... content truncated for context window ...]\n"
                    )
                result_lines.append(line)
                prev_kept = True
            else:
                prev_kept = False

        result = "\n".join(result_lines)
        if len(result) > target_chars:
            result = result[:target_chars] + "\n\n[... truncated ...]"
        return result


# ════════════════════════════════════════════════════════════════════════════
# ABYSSAL ENGINE v2.0 — The Real Thing
# ════════════════════════════════════════════════════════════════════════════


class AbyssalEngine:
    """The autonomous engine that fuses Shannon + SIREN.

    v2.0: REAL AI provider integration, tool-use, exploitation gating,
    context management, cost tracking, deliverable extraction.
    """

    def __init__(self, config: EngineConfig) -> None:
        self.config = config
        self._ai: Optional[AIProvider] = None
        self._pipeline: Optional[Pipeline] = None
        self._start_time: Optional[float] = None
        self._deliverable_cache: Dict[str, str] = {}
        self._exploitation_decisions: Dict[str, bool] = {}
        self._agent_responses: Dict[str, AIResponse] = {}

    # ── Preflight ──────────────────────────────────────────────────

    async def preflight(self) -> Dict[str, Any]:
        """Comprehensive preflight validation."""
        report: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "valid": True,
            "checks": [],
        }

        # 1. Config
        config_result = self.config.validate()
        report["checks"].append(
            {
                "name": "Configuration",
                "status": "ok" if config_result["valid"] else "fail",
                "details": config_result,
            }
        )
        if not config_result["valid"]:
            report["valid"] = False

        # 2. Repository
        repo_path = Path(self.config.repo_path) if self.config.repo_path else None
        repo_exists = repo_path.exists() if repo_path else False
        repo_info: Dict[str, Any] = {
            "name": "Repository",
            "status": "ok" if repo_exists else "fail",
            "path": self.config.repo_path,
        }
        if repo_exists and repo_path:
            try:
                file_count = sum(
                    1
                    for f in repo_path.rglob("*")
                    if f.is_file() and ".git" not in str(f)
                )
                total_size = sum(
                    f.stat().st_size
                    for f in repo_path.rglob("*")
                    if f.is_file() and ".git" not in str(f)
                )
                repo_info["files"] = file_count
                repo_info["size_mb"] = round(total_size / 1024 / 1024, 2)
            except Exception:
                logger.debug("Could not stat repo")
        report["checks"].append(repo_info)
        if not repo_exists:
            report["valid"] = False

        # 3. Output directory
        try:
            output_path = Path(self.config.output_dir)
            output_path.mkdir(parents=True, exist_ok=True)
            report["checks"].append(
                {
                    "name": "Output Directory",
                    "status": "ok",
                    "path": str(output_path),
                }
            )
        except Exception as e:
            report["checks"].append(
                {
                    "name": "Output Directory",
                    "status": "fail",
                    "error": str(e),
                }
            )
            report["valid"] = False

        # 4. AI Provider
        provider_info = self.config._detect_provider()
        ai_check: Dict[str, Any] = {
            "name": "AI Provider",
            "status": "ok" if provider_info["configured"] else "warn",
            "provider": provider_info["name"],
        }
        if provider_info["configured"] and provider_info["name"] != "none":
            try:
                ai = AIProvider(self.config)
                model = resolve_model("small")
                test_resp = await ai.invoke(
                    "Reply with exactly: SIREN_OK",
                    model.model_id,
                    max_tokens=50,
                    temperature=0,
                )
                if test_resp.success:
                    ai_check["status"] = "ok"
                    ai_check["model_tested"] = model.model_id
                    ai_check["latency_s"] = round(test_resp.duration_s, 2)
                else:
                    ai_check["status"] = "warn"
                    ai_check["error"] = test_resp.error
            except Exception as e:
                ai_check["status"] = "warn"
                ai_check["error"] = str(e)[:200]
        report["checks"].append(ai_check)

        # 5. SIREN tools
        lev = self._check_siren_availability()
        report["checks"].append(
            {
                "name": "SIREN Arsenal",
                "status": "ok" if lev["available"] else "warn",
                "details": lev,
            }
        )

        # 6. TOTP
        if self.config.auth_totp_secret:
            try:
                from .orchestrator import TOTPGenerator

                valid, msg = TOTPGenerator.validate_secret(self.config.auth_totp_secret)
                report["checks"].append(
                    {
                        "name": "TOTP Secret",
                        "status": "ok" if valid else "fail",
                        "message": msg,
                    }
                )
            except ImportError:
                logger.debug("TOTPGenerator not available")

        return report

    def _check_siren_availability(self) -> Dict[str, Any]:
        """Check which SIREN domain modules are available."""
        domain_modules = {
            "SURFACE_BREAKER": "core.webapp",
            "PRESSURE_FORGE": "core.exploit",
            "ALL_SEEING_EYE": "core.recon",
            "SHADOW_PUPPETEER": "core.redteam",
            "CORPSE_EXAMINER": "core.forensics",
            "DEEP_CURRENT": "core.netattack",
            "CLOUD_DEVOURER": "core.cloud",
            "BONE_READER": "core.reveng",
            "DOMAIN_CRUSHER": "core.active_directory",
            "DEAD_CODE_ORACLE": "core.ghidra",
            "RADIO_PHANTOM": "core.wireless",
            "MOBILE_KRAKEN": "core.frida_mcp",
            "CRYPTO_ABYSS": "core.shannon.crypto",
            "AUTH_SIEGE": "core.shannon.auth_engine",
            "FUZZ_HYDRA": "core.shannon.fuzzer",
        }
        available = []
        unavailable = []
        for domain, module in domain_modules.items():
            try:
                __import__(module)
                available.append(domain)
            except ImportError:
                unavailable.append(domain)
        return {
            "available": len(available) > 0,
            "total_domains": len(domain_modules),
            "available_count": len(available),
            "available_domains": available,
            "unavailable_domains": unavailable,
        }

    # ── Prompt Building ────────────────────────────────────────────

    def _build_prompt(self, agent: AgentDefinition) -> str:
        """Build complete prompt for an agent with full SIREN context."""
        template = PROMPT_TEMPLATES.get(agent.prompt_template, "")
        workspace_dir = Path(self.config.output_dir) / (
            self.config.workspace or "default"
        )
        deliverables_dir = workspace_dir / "deliverables"

        context: Dict[str, str] = {
            "target_url": self.config.target_url,
            "repo_path": self.config.repo_path,
            "deliverable_path": str(deliverables_dir / agent.deliverable_filename),
        }

        # SIREN context
        lev_lines = [
            "## SIREN ARSENAL",
            f"  Active Domains: {', '.join(agent.attack_domains)}",
            f"  Tools: {', '.join(agent.preferred_tools[:15])}",
            f"  Evasion: {self.config.evasion_level}",
        ]
        if self.config.enable_kraken_evasion:
            lev_lines.append("  Kraken Evasion Engine: ACTIVE (640+ semantic rules)")
        if self.config.enable_safe_mode:
            lev_lines.append("  Safe Mode: ENABLED")
        lev_lines.append("  MCP Servers: 50 | Total Tools: 711+")
        context["arsenal_context"] = "\n".join(lev_lines)

        # Auth context
        auth_lines: List[str] = []
        if self.config.auth_login_url:
            auth_lines.append("## Authentication")
            auth_lines.append(f"Login URL: {self.config.auth_login_url}")
            if self.config.auth_username:
                auth_lines.append(f"Username: {self.config.auth_username}")
            if self.config.auth_login_flow:
                auth_lines.append("Login Flow:")
                for step in self.config.auth_login_flow:
                    auth_lines.append(f"  - {step}")
            if self.config.auth_success_condition:
                auth_lines.append(f"Success: {self.config.auth_success_condition}")
            if self.config.auth_totp_secret:
                auth_lines.append("TOTP: Configured (auto-generated per request)")
        context["auth_context"] = "\n".join(auth_lines)

        # Rules context
        rules_lines: List[str] = []
        if self.config.avoid_paths or self.config.avoid_rules:
            rules_lines.append("## Testing Rules — AVOID")
            for p in self.config.avoid_paths:
                rules_lines.append(f"  - {p}")
            for r in self.config.avoid_rules:
                rules_lines.append(f"  - {r.get('description', r.get('url_path', ''))}")
        if self.config.focus_paths or self.config.focus_rules:
            rules_lines.append("## Testing Rules — FOCUS")
            for p in self.config.focus_paths:
                rules_lines.append(f"  - {p}")
            for r in self.config.focus_rules:
                rules_lines.append(f"  - {r.get('description', r.get('url_path', ''))}")
        context["rules_context"] = "\n".join(rules_lines)

        # Previous deliverables
        context_budget = (
            self.config.max_context_tokens - self.config.context_reserve_output
        )
        del_budget = int(context_budget * 0.4)

        for key, fname in [
            ("pre_recon_deliverable", "code_analysis_deliverable.md"),
            ("recon_deliverable", "recon_deliverable.md"),
        ]:
            content = self._load_deliverable(deliverables_dir, fname)
            if content:
                tokens = ContextManager.estimate_tokens(content)
                if tokens > del_budget // 2:
                    content = ContextManager.smart_truncate(content, del_budget // 2)
                context[key] = content
            else:
                context[key] = f"[{fname} not yet generated]"

        # Vuln deliverable for exploit agents
        if agent.is_exploit_agent and agent.vuln_type:
            vfname = f"{agent.vuln_type}_analysis_deliverable.md"
            content = self._load_deliverable(deliverables_dir, vfname)
            if content:
                tokens = ContextManager.estimate_tokens(content)
                if tokens > del_budget:
                    content = ContextManager.smart_truncate(content, del_budget)
                context["vuln_deliverable"] = content
            else:
                context["vuln_deliverable"] = f"[{vfname} not available]"

        # Report context
        if agent.name == "report":
            ev_parts = []
            if deliverables_dir.exists():
                for f in sorted(deliverables_dir.glob("*_exploitation_evidence.md")):
                    try:
                        ev_parts.append(
                            f"### {f.stem}\n\n{f.read_text(encoding='utf-8')}"
                        )
                    except Exception:
                        ev_parts.append(f"### {f.stem}\n\n[Error reading]")
            context["all_evidence_files"] = "\n\n".join(ev_parts) or "No evidence."
            context["tools_used"] = json.dumps(
                {d: True for d in agent.attack_domains},
                indent=2,
            )
            context["pipeline_metrics"] = json.dumps(
                self._pipeline.result.to_dict() if self._pipeline else {},
                indent=2,
            )

        # Format
        result = template
        for k, v in context.items():
            result = result.replace(f"{{{k}}}", str(v))

        # Budget check
        prompt_tokens = ContextManager.estimate_tokens(result)
        max_prompt = self.config.max_context_tokens - self.config.context_reserve_output
        if prompt_tokens > max_prompt:
            result = ContextManager.smart_truncate(result, max_prompt)
            logger.warning(
                "Prompt '%s' truncated: %d → %d tokens",
                agent.name,
                prompt_tokens,
                max_prompt,
            )

        return result

    def _load_deliverable(
        self,
        deliverables_dir: Path,
        filename: str,
    ) -> Optional[str]:
        """Load a deliverable with caching."""
        path = deliverables_dir / filename
        cache_key = str(path)
        if cache_key in self._deliverable_cache:
            return self._deliverable_cache[cache_key]
        if path.exists():
            try:
                content = path.read_text(encoding="utf-8")
                self._deliverable_cache[cache_key] = content
                return content
            except Exception:
                logger.debug("Could not read deliverable %s", path)
        return None

    # ── Agent Execution — REAL AI ──────────────────────────────────

    async def _execute_agent(
        self,
        agent: AgentDefinition,
        output_dir: Path,
    ) -> Result:
        """Execute an agent with REAL AI integration.

        Flow:
        1. Check exploitation gate
        2. Build prompt with full context
        3. Call AI provider (with failover)
        4. Extract deliverable from response
        5. Validate and save
        6. Track cost and tokens
        """
        start_time = time.time()

        # Exploitation gate
        if (
            agent.is_exploit_agent
            and agent.vuln_type
            and self.config.enable_exploitation_gating
        ):
            if not self._should_exploit(agent.vuln_type):
                dur = (time.time() - start_time) * 1000
                logger.info("Skipping '%s': gate closed", agent.name)
                skip_path = output_dir / "deliverables" / agent.deliverable_filename
                skip_path.parent.mkdir(parents=True, exist_ok=True)
                skip_path.write_text(
                    f"# {agent.display_name}\n\n"
                    f"## Status: SKIPPED\n\n"
                    f"Exploitation gate closed: no exploitable vulns for "
                    f"'{agent.vuln_type}'.\n",
                    encoding="utf-8",
                )
                return Result.success(
                    {"deliverable": str(skip_path), "skipped": True},
                    agent.name,
                    dur,
                )

        # Build prompt
        prompt = self._build_prompt(agent)

        # Save prompt for reproducibility
        prompt_dir = output_dir / "prompts"
        prompt_dir.mkdir(parents=True, exist_ok=True)
        (prompt_dir / f"{agent.name}_prompt.md").write_text(prompt, encoding="utf-8")

        try:
            creds = validate_credentials()
            if creds["valid"]:
                result_data = await self._execute_via_ai(agent, prompt, output_dir)
            else:
                result_data = await self._execute_locally(agent, prompt, output_dir)

            dur = (time.time() - start_time) * 1000
            del_path = output_dir / "deliverables" / agent.deliverable_filename

            if del_path.exists():
                content = del_path.read_text(encoding="utf-8")
                self._deliverable_cache[str(del_path)] = content
                return Result.success(
                    {
                        "deliverable": str(del_path),
                        "tokens": result_data.get("tokens", 0),
                        "cost_usd": result_data.get("cost", 0.0),
                        "content_hash": hashlib.sha256(content.encode()).hexdigest()[
                            :16
                        ],
                        "content_length": len(content),
                    },
                    agent.name,
                    dur,
                )
            else:
                return Result.failure(
                    f"Deliverable not created: {agent.deliverable_filename}",
                    agent.name,
                    dur,
                )

        except Exception as e:
            dur = (time.time() - start_time) * 1000
            logger.error("Agent %s failed: %s", agent.name, e)
            try:
                from .orchestrator import ErrorClassifier

                classified = ErrorClassifier.classify(e)
                return Result.failure(
                    f"[{classified.code.value}] {e}" if classified else str(e),
                    agent.name,
                    dur,
                )
            except Exception:
                return Result.failure(str(e), agent.name, dur)

    async def _execute_via_ai(
        self,
        agent: AgentDefinition,
        prompt: str,
        output_dir: Path,
    ) -> Dict[str, Any]:
        """Execute agent via REAL AI model call.

        Calls actual AI provider API, receives response,
        extracts deliverable, saves it with full metadata.
        """
        if not self._ai:
            self._ai = AIProvider(self.config)

        model = resolve_model(agent.model_tier)
        system_prompt = (
            f"You are {agent.display_name}, an autonomous AI security agent "
            f"in the SIREN pipeline (Shannon × SIREN). "
            f"Phase: {agent.phase}. "
            f"Arsenal: 711+ tools across 50 MCP servers. "
            f"Be thorough, precise, produce actionable findings. "
            f"Output: Markdown. For vuln analysis: include JSON exploitation queue."
        )

        tools = SIREN_TOOLS if self.config.enable_tool_use else None

        response = await self._ai.invoke(
            prompt=prompt,
            model_id=model.model_id,
            system_prompt=system_prompt,
            max_tokens=self.config.max_tokens_per_request,
            temperature=self.config.temperature,
            tools=tools,
        )

        self._agent_responses[agent.name] = response

        if not response.success:
            raise RuntimeError(f"AI call failed: {response.error}")

        # Agent execution log
        agent_log_dir = output_dir / "agents"
        agent_log_dir.mkdir(parents=True, exist_ok=True)
        log_entry = {
            "agent": agent.name,
            "model": response.model,
            "provider": response.provider,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "input_tokens": response.input_tokens,
            "output_tokens": response.output_tokens,
            "total_tokens": response.total_tokens,
            "cost_usd": response.cost_usd,
            "duration_s": response.duration_s,
            "stop_reason": response.stop_reason,
            "content_length": len(response.content),
            "tool_calls": len(response.tool_calls),
            "retries": response.retries,
            "attack_domains": list(agent.attack_domains),
        }
        (agent_log_dir / f"{agent.name}_execution.json").write_text(
            json.dumps(log_entry, indent=2),
            encoding="utf-8",
        )

        # Save deliverable
        del_path = output_dir / "deliverables" / agent.deliverable_filename
        del_path.parent.mkdir(parents=True, exist_ok=True)

        extracted = DeliverableExtractor.extract(response.content, agent)
        del_path.write_text(response.content, encoding="utf-8")

        # Save exploitation queue
        if extracted.get("exploitation_queue"):
            q_path = del_path.parent / f"{agent.vuln_type or agent.name}_queue.json"
            q_path.write_text(
                json.dumps(extracted["exploitation_queue"], indent=2),
                encoding="utf-8",
            )

        return {
            "model": response.model,
            "tokens": response.total_tokens,
            "cost": response.cost_usd,
            "deliverable": str(del_path),
            "findings": extracted["findings_count"],
            "severity": extracted["severity_distribution"],
        }

    async def _execute_locally(
        self,
        agent: AgentDefinition,
        prompt: str,
        output_dir: Path,
    ) -> Dict[str, Any]:
        """Execute agent locally using SIREN tools (no AI).

        Fallback when no AI provider is configured. Uses scanner,
        recon, fuzzer, and exploit modules directly.
        """
        del_path = output_dir / "deliverables" / agent.deliverable_filename
        del_path.parent.mkdir(parents=True, exist_ok=True)

        parts = [
            f"# {agent.display_name} — Local Execution",
            "",
            f"**Target**: {self.config.target_url}",
            f"**Phase**: {agent.phase}",
            f"**Timestamp**: {datetime.now(timezone.utc).isoformat()}",
            f"**Mode**: SIREN-native (no AI provider)",
            "",
        ]

        dispatch = {
            "pre-recon": self._local_code_analysis,
            "recon": self._local_recon,
            "vulnerability-analysis": self._local_vuln_scan,
            "exploitation": self._local_exploit,
            "reporting": self._local_report,
        }
        handler = dispatch.get(agent.phase)
        if handler:
            if agent.phase == "reporting":
                parts.extend(await handler(agent, output_dir))
            else:
                parts.extend(await handler(agent))
        else:
            parts.append("## Awaiting AI provider\n")
            parts.append(
                "Configure ANTHROPIC_API_KEY, OPENAI_API_KEY, or OLLAMA_HOST.\n"
            )

        del_path.write_text("\n".join(parts), encoding="utf-8")
        return {"mode": "local", "deliverable": str(del_path)}

    async def _local_code_analysis(self, agent: AgentDefinition) -> List[str]:
        """Local code analysis using SIREN scanner."""
        lines = ["## Code Analysis (Local)", ""]
        repo = Path(self.config.repo_path)

        if not repo.exists():
            lines.append("Repository path not found.\n")
            return lines

        file_types: Dict[str, int] = {}
        total_lines = 0
        sensitive_files: List[str] = []
        sensitive_pats = [
            r"\.env",
            r"config\.",
            r"secret",
            r"password",
            r"credential",
            r"token",
            r"key",
            r"auth",
            r"\.pem$",
            r"\.key$",
        ]

        try:
            for f in repo.rglob("*"):
                if f.is_file() and ".git" not in str(f):
                    ext = f.suffix or "(none)"
                    file_types[ext] = file_types.get(ext, 0) + 1
                    try:
                        total_lines += sum(
                            1 for _ in f.open(encoding="utf-8", errors="ignore")
                        )
                    except Exception:
                        logger.debug("Could not count lines in %s", f)
                    for pat in sensitive_pats:
                        if re.search(pat, f.name, re.IGNORECASE):
                            sensitive_files.append(str(f.relative_to(repo)))
                            break
        except Exception as e:
            lines.append(f"Error scanning: {e}\n")
            return lines

        lines.append("### File Inventory")
        lines.append(f"Total files: {sum(file_types.values())}")
        lines.append(f"Total lines: {total_lines:,}")
        lines.append("")
        lines.append("| Extension | Count |")
        lines.append("|-----------|-------|")
        for ext, count in sorted(file_types.items(), key=lambda x: -x[1])[:20]:
            lines.append(f"| {ext} | {count} |")
        lines.append("")

        if sensitive_files:
            lines.append("### Potentially Sensitive Files")
            for sf in sensitive_files[:50]:
                lines.append(f"- `{sf}`")
            lines.append("")

        # Vulnerability patterns
        lines.append("### Code Pattern Analysis")
        vuln_pats = {
            "SQL Injection": [
                r"execute\s*\(.*%s",
                r"query\s*\(.*\+",
                r'f".*SELECT.*\{',
            ],
            "Command Injection": [
                r"os\.system\(",
                r"subprocess\.call\(.*shell=True",
                r"exec\(",
            ],
            "Hardcoded Secrets": [
                r"password\s*=\s*['\"]",
                r"secret\s*=\s*['\"]",
                r"api_key\s*=\s*['\"]",
            ],
            "Debug/Dev": [
                r"DEBUG\s*=\s*True",
                r"console\.log\(",
                r"print\(.*password",
            ],
            "Insecure Deserialization": [
                r"pickle\.load",
                r"yaml\.load\((?!.*Loader)",
                r"eval\(",
            ],
        }

        findings: Dict[str, List[str]] = {}
        code_exts = {".py", ".js", ".ts", ".php", ".rb", ".java", ".go", ".cs"}
        try:
            for f in repo.rglob("*"):
                if f.is_file() and f.suffix in code_exts:
                    try:
                        content = f.read_text(encoding="utf-8", errors="ignore")
                        for cat, patterns in vuln_pats.items():
                            for pat in patterns:
                                for match in re.finditer(pat, content):
                                    findings.setdefault(cat, []).append(
                                        f"{f.relative_to(repo)}:"
                                        f"{content[:match.start()].count(chr(10)) + 1}"
                                    )
                    except Exception:
                        logger.debug("Could not scan %s", f)
        except Exception:
            logger.debug("Code pattern scan error")

        for cat, locs in findings.items():
            lines.append(f"\n#### {cat}")
            for loc in locs[:10]:
                lines.append(f"- `{loc}`")
            if len(locs) > 10:
                lines.append(f"- ... and {len(locs) - 10} more")

        lines.append("\n---\n*Generated by SIREN local scanner*\n")
        return lines

    async def _local_recon(self, agent: AgentDefinition) -> List[str]:
        """Local reconnaissance."""
        lines = ["## Reconnaissance (Local)", ""]

        try:
            parsed = urlparse(self.config.target_url)
            lines.append("### Target")
            lines.append(f"- **Scheme**: {parsed.scheme}")
            lines.append(f"- **Host**: {parsed.hostname}")
            lines.append(
                f"- **Port**: "
                f"{parsed.port or ('443' if parsed.scheme == 'https' else '80')}"
            )
            lines.append(f"- **Path**: {parsed.path or '/'}")
            lines.append("")

            # DNS
            try:
                ips = socket.getaddrinfo(parsed.hostname, None)
                unique_ips = set(ip[4][0] for ip in ips)
                lines.append("### DNS Resolution")
                for ip in unique_ips:
                    lines.append(f"- {ip}")
                lines.append("")
            except Exception as e:
                lines.append(f"DNS failed: {e}\n")

            # HTTP check
            try:
                req = Request(self.config.target_url, method="HEAD")
                req.add_header("User-Agent", "SIREN/2.0 (SIREN)")
                resp = urlopen(req, timeout=10)
                lines.append("### HTTP Headers")
                lines.append(f"- **Status**: {resp.status}")
                for header in resp.headers:
                    lines.append(f"- **{header}**: {resp.headers[header]}")
                lines.append("")

                security_headers = [
                    "Content-Security-Policy",
                    "X-Frame-Options",
                    "X-Content-Type-Options",
                    "Strict-Transport-Security",
                    "X-XSS-Protection",
                    "Referrer-Policy",
                    "Permissions-Policy",
                    "Cross-Origin-Opener-Policy",
                ]
                resp_h_lower = {h.lower() for h in resp.headers}
                lines.append("### Missing Security Headers")
                for sh in security_headers:
                    if sh.lower() not in resp_h_lower:
                        lines.append(f"- Missing: {sh}")
                lines.append("")
            except Exception as e:
                lines.append(f"HTTP check failed: {e}\n")

        except Exception as e:
            lines.append(f"Recon error: {e}\n")

        lines.append("---\n*Generated by SIREN local recon*\n")
        return lines

    async def _local_vuln_scan(self, agent: AgentDefinition) -> List[str]:
        """Local vulnerability scan."""
        lines = [
            f"## Vulnerability Analysis — {agent.vuln_type or 'general'} (Local)",
            "",
        ]
        try:
            from .scanner import ScanConfig, SirenScanner

            config = ScanConfig(
                target_url=self.config.target_url,
                max_depth=5,
                max_urls=200,
                scan_types=["all"],
                threads=10,
            )
            scanner = SirenScanner(config)
            results = await scanner.scan()

            lines.append("### Scan Results")
            lines.append(f"- URLs scanned: {results.urls_scanned}")
            lines.append(f"- Findings: {len(results.findings)}")
            lines.append("")

            for finding in results.findings[:50]:
                lines.append(f"#### {finding.title}")
                lines.append(f"- **Severity**: {finding.severity.value}")
                lines.append(f"- **Category**: {finding.category.value}")
                lines.append(f"- **URL**: {finding.url}")
                if finding.parameter:
                    lines.append(f"- **Param**: {finding.parameter}")
                lines.append(f"- **Description**: {finding.description}")
                if finding.evidence:
                    lines.append(f"- **Evidence**: `{finding.evidence[:200]}`")
                lines.append("")
        except Exception as e:
            lines.append(f"Scanner unavailable: {e}")
            lines.append("Configure AI provider for deep analysis.\n")

        return lines

    async def _local_exploit(self, agent: AgentDefinition) -> List[str]:
        """Local exploitation using SIREN's built-in exploit modules."""
        lines = [
            f"## Exploitation — {agent.vuln_type or 'general'} (Local)",
            "",
        ]
        target = self.config.target
        if not target:
            lines.append("No target configured for exploitation.\n")
            return lines

        try:
            from .exploits import ExploitOrchestrator

            orchestrator = ExploitOrchestrator(target)
            vuln_type = agent.vuln_type or "general"

            if vuln_type in ("sqli", "general"):
                from .exploits import SQLiExploiter

                sqli = SQLiExploiter(target)
                results = await sqli.test_endpoints([target])
                for r in results:
                    lines.append(
                        f"- **{r.title}** [{r.severity.value}]: {r.description}"
                    )

            if vuln_type in ("xss", "general"):
                from .exploits import XSSExploiter

                xss = XSSExploiter(target)
                results = await xss.test_endpoints([target])
                for r in results:
                    lines.append(
                        f"- **{r.title}** [{r.severity.value}]: {r.description}"
                    )

            if vuln_type in ("ssrf", "general"):
                from .exploits import SSRFExploiter

                ssrf = SSRFExploiter(target)
                results = await ssrf.test_endpoints([target])
                for r in results:
                    lines.append(
                        f"- **{r.title}** [{r.severity.value}]: {r.description}"
                    )

            if vuln_type in ("authz", "authn", "general"):
                from .exploits import AuthBypassExploiter

                auth = AuthBypassExploiter(target)
                results = await auth.test_endpoints([target])
                for r in results:
                    lines.append(
                        f"- **{r.title}** [{r.severity.value}]: {r.description}"
                    )

            if not any(line.startswith("- **") for line in lines):
                lines.append("No exploitable vulnerabilities confirmed at this stage.")
                lines.append(
                    "Consider configuring an AI provider for deeper analysis.\n"
                )
            else:
                lines.append(
                    f"\n**Total findings:** {sum(1 for l in lines if l.startswith('- **'))}"
                )

        except Exception as e:
            logger.warning("Local exploitation error: %s", e, exc_info=True)
            lines.append(f"Exploitation module error: {e}")
            lines.append("Configure AI provider for enhanced exploitation.\n")

        return lines

    async def _local_report(
        self,
        agent: AgentDefinition,
        output_dir: Path,
    ) -> List[str]:
        """Compile report from existing deliverables."""
        lines = ["## Security Assessment Report (Local)", ""]
        del_dir = output_dir / "deliverables"

        if del_dir.exists():
            for f in sorted(del_dir.glob("*.md")):
                if f.name != agent.deliverable_filename:
                    lines.append(f"### {f.stem.replace('_', ' ').title()}")
                    try:
                        content = f.read_text(encoding="utf-8")
                        lines.append(content[:5000])
                        if len(content) > 5000:
                            lines.append("\n[... truncated ...]\n")
                    except Exception:
                        lines.append("[Error reading]\n")
                    lines.append("")
        else:
            lines.append("No deliverables found.\n")
        return lines

    # ── Exploitation Gate ──────────────────────────────────────────

    def _should_exploit(self, vuln_type: str) -> bool:
        """Check if exploitation should proceed for a vulnerability type."""
        if vuln_type in self._exploitation_decisions:
            return self._exploitation_decisions[vuln_type]

        ws_dir = Path(self.config.output_dir) / (self.config.workspace or "default")
        del_dir = ws_dir / "deliverables"

        # Check queue JSON
        q_file = del_dir / f"{vuln_type}_queue.json"
        if q_file.exists():
            try:
                queue = json.loads(q_file.read_text(encoding="utf-8"))
                vulns = queue.get("vulnerabilities", [])
                result = len(vulns) > 0
                self._exploitation_decisions[vuln_type] = result
                logger.info(
                    "Exploitation gate '%s': %s (%d vulns)",
                    vuln_type,
                    "OPEN" if result else "CLOSED",
                    len(vulns),
                )
                return result
            except Exception:
                logger.debug("Could not parse queue for %s", vuln_type)

        # Fallback: check analysis deliverable
        analysis = del_dir / f"{vuln_type}_analysis_deliverable.md"
        if analysis.exists():
            try:
                content = analysis.read_text(encoding="utf-8")
                has = any(
                    m in content.lower()
                    for m in [
                        "critical",
                        "high",
                        "vulnerability found",
                        "exploitable",
                        "confirmed",
                    ]
                )
                self._exploitation_decisions[vuln_type] = has
                return has
            except Exception:
                logger.debug("Could not read analysis for %s", vuln_type)

        # Default: allow
        self._exploitation_decisions[vuln_type] = True
        return True

    # ── Main Execution ─────────────────────────────────────────────

    async def run(self) -> PipelineResult:
        """Execute the full autonomous pipeline."""
        self._start_time = time.time()

        preflight_report = await self.preflight()
        if not preflight_report["valid"]:
            errors = []
            for check in preflight_report["checks"]:
                if check.get("status") == "fail":
                    errors.append(
                        f"{check['name']}: "
                        f"{check.get('error', check.get('details', 'failed'))}"
                    )
            raise RuntimeError(f"Preflight failed: {'; '.join(errors)}")

        self._pipeline = Pipeline(
            target_url=self.config.target_url,
            repo_path=self.config.repo_path,
            output_dir=self.config.output_dir,
            workspace=self.config.workspace,
            retry_preset=(
                "testing" if self.config.pipeline_testing else self.config.retry_preset
            ),
            max_concurrent=self.config.max_concurrent_pipelines,
        )

        result = await self._pipeline.run(self._execute_agent)

        if self._ai:
            result.total_cost_usd = self._ai.total_cost
            result.total_tokens_used = self._ai.total_tokens

        return result

    def run_sync(self) -> PipelineResult:
        """Synchronous wrapper for run()."""
        return asyncio.run(self.run())

    def get_ai_stats(self) -> Dict[str, Any]:
        """Get AI provider statistics."""
        if not self._ai:
            return {"provider": "none", "total_cost": 0, "total_tokens": 0}
        return {
            "provider": self._ai._provider,
            "total_cost_usd": round(self._ai.total_cost, 4),
            "total_input_tokens": self._ai._total_input_tokens,
            "total_output_tokens": self._ai._total_output_tokens,
            "total_tokens": self._ai.total_tokens,
            "request_count": self._ai.request_count,
            "agent_responses": {
                name: resp.to_dict() for name, resp in self._agent_responses.items()
            },
        }
