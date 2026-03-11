#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  🧠  MULTI-TIER MODEL SYSTEM — Shannon × SIREN AI Core  🧠               ██
██                                                                                ██
██  Sistema de 3 camadas de modelos AI, adaptado do Shannon (KeygraphHQ).         ██
██  Cada agente usa o tier adequado para sua complexidade:                         ██
██                                                                                ██
██    SMALL  → Sumarizacao, report compilation (claude-haiku)                     ██
██    MEDIUM → Analise de seguranca, vuln hunting (claude-sonnet)                 ██
██    LARGE  → Raciocinio profundo, code analysis (claude-opus)                   ██
██                                                                                ██
██  Suporta: Anthropic Direct, AWS Bedrock, Google Vertex AI, Router Mode         ██
██                                                                                ██
██  "O monstro nao usa uma mente. Usa tres — cada uma mais perigosa."            ██
██                                                                                ██
████████████████████████████████████████████████████████████████████████████████████
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Literal, Optional

ModelTier = Literal["small", "medium", "large"]

# ════════════════════════════════════════════════════════════════════════════
# DEFAULT MODEL IDS
# ════════════════════════════════════════════════════════════════════════════

DEFAULT_MODELS = {
    "small": "claude-haiku-4-5-20251001",
    "medium": "claude-sonnet-4-6",
    "large": "claude-opus-4-6",
}

# Bedrock model ID patterns
BEDROCK_MODELS = {
    "small": "us.anthropic.claude-haiku-4-5-20251001-v1:0",
    "medium": "us.anthropic.claude-sonnet-4-6",
    "large": "us.anthropic.claude-opus-4-6",
}

# Vertex AI model ID patterns
VERTEX_MODELS = {
    "small": "claude-haiku-4-5@20251001",
    "medium": "claude-sonnet-4-6",
    "large": "claude-opus-4-6",
}


# ════════════════════════════════════════════════════════════════════════════
# MODEL CONFIGURATION
# ════════════════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class ModelConfig:
    """Configuracao completa de um modelo AI."""

    model_id: str
    tier: ModelTier
    max_output_tokens: int = 64000
    provider: str = "anthropic"  # anthropic, bedrock, vertex, router

    @property
    def display_name(self) -> str:
        tier_icons = {"small": "⚡", "medium": "🧠", "large": "🔮"}
        return f"{tier_icons.get(self.tier, '?')} {self.model_id} [{self.tier}]"


# ════════════════════════════════════════════════════════════════════════════
# MODEL RESOLUTION
# ════════════════════════════════════════════════════════════════════════════


def detect_provider() -> str:
    """Detecta automaticamente o provider baseado em env vars."""
    if os.environ.get("CLAUDE_CODE_USE_BEDROCK") == "1":
        return "bedrock"
    if os.environ.get("CLAUDE_CODE_USE_VERTEX") == "1":
        return "vertex"
    if os.environ.get("OPENAI_API_KEY") or os.environ.get("OPENROUTER_API_KEY"):
        return "router"
    return "anthropic"


def resolve_model(tier: ModelTier) -> ModelConfig:
    """Resolve o modelo correto para um tier, considerando env vars e provider.

    Prioridade de resolucao:
    1. Env var explicita (ANTHROPIC_SMALL_MODEL, etc.)
    2. Provider-specific defaults (Bedrock, Vertex)
    3. Default Anthropic models
    """
    provider = detect_provider()

    # 1. Check explicit env var override
    env_key = f"ANTHROPIC_{tier.upper()}_MODEL"
    explicit_model = os.environ.get(env_key)

    if explicit_model:
        return ModelConfig(
            model_id=explicit_model,
            tier=tier,
            max_output_tokens=int(
                os.environ.get("CLAUDE_CODE_MAX_OUTPUT_TOKENS", "64000")
            ),
            provider=provider,
        )

    # 2. Provider-specific defaults
    if provider == "bedrock":
        model_id = BEDROCK_MODELS.get(tier, DEFAULT_MODELS[tier])
    elif provider == "vertex":
        model_id = VERTEX_MODELS.get(tier, DEFAULT_MODELS[tier])
    else:
        model_id = DEFAULT_MODELS[tier]

    return ModelConfig(
        model_id=model_id,
        tier=tier,
        max_output_tokens=int(os.environ.get("CLAUDE_CODE_MAX_OUTPUT_TOKENS", "64000")),
        provider=provider,
    )


def get_all_models() -> dict[ModelTier, ModelConfig]:
    """Retorna configuracao de todos os 3 tiers."""
    return {
        "small": resolve_model("small"),
        "medium": resolve_model("medium"),
        "large": resolve_model("large"),
    }


def validate_credentials() -> dict:
    """Valida que as credenciais necessarias estao configuradas.

    Returns:
        Dict com status de validacao e detalhes.
    """
    provider = detect_provider()
    result = {
        "provider": provider,
        "valid": False,
        "missing": [],
        "models": {},
    }

    if provider == "anthropic":
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        oauth = os.environ.get("CLAUDE_CODE_OAUTH_TOKEN")
        if not api_key and not oauth:
            result["missing"].append("ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN")
        else:
            result["valid"] = True

    elif provider == "bedrock":
        required = ["AWS_REGION", "AWS_BEARER_TOKEN_BEDROCK"]
        for key in required:
            if not os.environ.get(key):
                result["missing"].append(key)
        result["valid"] = len(result["missing"]) == 0

    elif provider == "vertex":
        required = [
            "CLOUD_ML_REGION",
            "ANTHROPIC_VERTEX_PROJECT_ID",
            "GOOGLE_APPLICATION_CREDENTIALS",
        ]
        for key in required:
            if not os.environ.get(key):
                result["missing"].append(key)
        result["valid"] = len(result["missing"]) == 0

    elif provider == "router":
        if not os.environ.get("OPENAI_API_KEY") and not os.environ.get(
            "OPENROUTER_API_KEY"
        ):
            result["missing"].append("OPENAI_API_KEY or OPENROUTER_API_KEY")
        else:
            result["valid"] = True

    # Get model configs
    for tier in ("small", "medium", "large"):
        result["models"][tier] = resolve_model(tier).display_name

    return result
