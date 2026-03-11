#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  🌊  ABYSSAL PIPELINE — Shannon × SIREN Workflow Orchestrator  🌊         ██
██                                                                                ██
██  Motor de pipeline assincrono inspirado no Temporal (Shannon/KeygraphHQ).       ██
██  Sem dependencia de Docker/Temporal — puro Python asyncio.                      ██
██                                                                                ██
██  5 fases, 13 agentes, paralelismo automatico, retry com backoff,               ██
██  checkpointing via filesystem, validacao de deliverables.                       ██
██                                                                                ██
██  O pipeline e a corrente sanguinea do monstro — cada fase alimenta a proxima.  ██
██                                                                                ██
██  "A corrente marinha nao para. E ela carrega tudo para o fundo."              ██
██                                                                                ██
████████████████████████████████████████████████████████████████████████████████████
"""

from __future__ import annotations

import asyncio
import enum
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set

from .agents import (
    AGENTS,
    AGENTS_BY_PHASE,
    PHASE_ORDER,
    AgentDefinition,
    AgentStatus,
    PhaseName,
)

# ════════════════════════════════════════════════════════════════════════════
# RESULT TYPE — Inspirado pelo Result<T,E> do Shannon
# ════════════════════════════════════════════════════════════════════════════


@dataclass
class Result:
    """Resultado discriminado — sucesso ou falha com contexto."""

    ok: bool
    value: Any = None
    error: Optional[str] = None
    duration_ms: float = 0
    agent_name: str = ""

    @property
    def is_ok(self) -> bool:
        return self.ok

    @property
    def is_err(self) -> bool:
        return not self.ok

    @classmethod
    def success(
        cls, value: Any, agent_name: str = "", duration_ms: float = 0
    ) -> "Result":
        return cls(ok=True, value=value, agent_name=agent_name, duration_ms=duration_ms)

    @classmethod
    def failure(
        cls, error: str, agent_name: str = "", duration_ms: float = 0
    ) -> "Result":
        return cls(
            ok=False, error=error, agent_name=agent_name, duration_ms=duration_ms
        )


# ════════════════════════════════════════════════════════════════════════════
# AGENT METRICS — Telemetria de cada agente
# ════════════════════════════════════════════════════════════════════════════


@dataclass
class AgentMetrics:
    """Metricas de execucao de um agente."""

    agent_name: str
    phase: PhaseName
    status: AgentStatus = AgentStatus.DORMANT
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    retry_count: int = 0
    tokens_used: int = 0
    cost_usd: float = 0.0
    deliverable_size: int = 0
    error_message: Optional[str] = None

    @property
    def duration_seconds(self) -> float:
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return 0.0

    @property
    def duration_display(self) -> str:
        d = self.duration_seconds
        if d < 60:
            return f"{d:.1f}s"
        if d < 3600:
            return f"{d / 60:.1f}m"
        return f"{d / 3600:.1f}h"

    @property
    def duration_ms(self) -> float:
        """Duracao em milissegundos."""
        return self.duration_seconds * 1000

    @property
    def success(self) -> bool:
        """Whether this agent completed successfully."""
        return self.status == AgentStatus.COMPLETED

    @property
    def error(self) -> Optional[str]:
        """Alias for error_message."""
        return self.error_message


# ════════════════════════════════════════════════════════════════════════════
# PIPELINE STATE — Estado persistivel do pipeline
# ════════════════════════════════════════════════════════════════════════════


class PipelineState(enum.Enum):
    """Estado global do pipeline."""

    IDLE = "idle"
    PREFLIGHT = "preflight"
    PRE_RECON = "pre_recon"
    RECON = "recon"
    VULN_ANALYSIS = "vuln_analysis"
    EXPLOITATION = "exploitation"
    REPORTING = "reporting"
    COMPLETED = "completed"
    FAILED = "failed"
    ABORTED = "aborted"


# ════════════════════════════════════════════════════════════════════════════
# PIPELINE RESULT — Resultado final do pipeline completo
# ════════════════════════════════════════════════════════════════════════════


@dataclass
class PipelineResult:
    """Resultado consolidado de toda a execucao do pipeline."""

    state: PipelineState
    target_url: str
    repo_path: str
    workspace: str
    start_time: float
    end_time: Optional[float] = None
    agent_metrics: Dict[str, AgentMetrics] = field(default_factory=dict)
    deliverables: Dict[str, str] = field(default_factory=dict)
    total_vulns_found: int = 0
    total_exploits_proven: int = 0
    error_message: Optional[str] = None

    @property
    def duration_seconds(self) -> float:
        if self.end_time:
            return self.end_time - self.start_time
        return time.time() - self.start_time

    @property
    def duration_display(self) -> str:
        d = self.duration_seconds
        if d < 60:
            return f"{d:.1f}s"
        if d < 3600:
            return f"{d / 60:.1f}m"
        return f"{d / 3600:.1f}h"

    @property
    def success_rate(self) -> float:
        if not self.agent_metrics:
            return 0.0
        completed = sum(
            1 for m in self.agent_metrics.values() if m.status == AgentStatus.COMPLETED
        )
        total = sum(
            1 for m in self.agent_metrics.values() if m.status != AgentStatus.DORMANT
        )
        return (completed / total * 100) if total > 0 else 0.0

    @property
    def total_cost(self) -> float:
        return sum(m.cost_usd for m in self.agent_metrics.values())

    @property
    def total_tokens(self) -> int:
        return sum(m.tokens_used for m in self.agent_metrics.values())

    @property
    def phases_completed(self) -> int:
        """Numero de fases completadas."""
        completed_phases = set()
        for m in self.agent_metrics.values():
            if m.status == AgentStatus.COMPLETED:
                completed_phases.add(m.phase)
        return len(completed_phases)

    @property
    def agents_succeeded(self) -> int:
        """Numero de agentes que tiveram sucesso."""
        return sum(
            1 for m in self.agent_metrics.values() if m.status == AgentStatus.COMPLETED
        )

    @property
    def agents_failed(self) -> int:
        """Numero de agentes que falharam."""
        return sum(
            1 for m in self.agent_metrics.values() if m.status == AgentStatus.FAILED
        )

    @property
    def total_duration_ms(self) -> float:
        """Duracao total em milissegundos."""
        return self.duration_seconds * 1000

    def to_dict(self) -> dict:
        """Serializa para dict (para session.json / JSON output)."""
        return {
            "state": self.state.value,
            "target_url": self.target_url,
            "repo_path": self.repo_path,
            "workspace": self.workspace,
            "duration": self.duration_display,
            "duration_seconds": round(self.duration_seconds, 2),
            "success_rate": f"{self.success_rate:.1f}%",
            "total_vulns_found": self.total_vulns_found,
            "total_exploits_proven": self.total_exploits_proven,
            "total_cost_usd": round(self.total_cost, 2),
            "total_tokens": self.total_tokens,
            "agents": {
                name: {
                    "status": m.status.value,
                    "phase": m.phase,
                    "duration": m.duration_display,
                    "retries": m.retry_count,
                    "tokens": m.tokens_used,
                    "cost_usd": round(m.cost_usd, 2),
                    "error": m.error_message,
                }
                for name, m in self.agent_metrics.items()
            },
            "deliverables": list(self.deliverables.keys()),
            "error": self.error_message,
        }

    def save(self, output_dir: Path) -> Path:
        """Salva session.json no diretorio de output."""
        output_dir.mkdir(parents=True, exist_ok=True)
        session_file = output_dir / "session.json"
        session_file.write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return session_file


# ════════════════════════════════════════════════════════════════════════════
# RETRY STRATEGY — Estrategia de retry adaptada do Shannon
# ════════════════════════════════════════════════════════════════════════════


@dataclass(frozen=True)
class RetryStrategy:
    """Configuracao de retry com backoff exponencial."""

    initial_delay_ms: int = 5000  # 5 seconds
    max_delay_ms: int = 1_800_000  # 30 minutes
    max_attempts: int = 50
    backoff_multiplier: float = 2.0
    jitter: bool = True

    def get_delay(self, attempt: int) -> float:
        """Calcula delay em segundos para a tentativa N."""
        import random as _random

        delay_ms = min(
            self.initial_delay_ms * (self.backoff_multiplier**attempt),
            self.max_delay_ms,
        )
        if self.jitter:
            delay_ms *= 0.5 + _random.random() * 0.5
        return delay_ms / 1000.0


# Presets de retry (adaptados do Shannon)
RETRY_PRESETS = {
    "production": RetryStrategy(
        initial_delay_ms=5_000,
        max_delay_ms=1_800_000,
        max_attempts=50,
    ),
    "testing": RetryStrategy(
        initial_delay_ms=1_000,
        max_delay_ms=30_000,
        max_attempts=5,
    ),
    "subscription": RetryStrategy(
        initial_delay_ms=5_000,
        max_delay_ms=21_600_000,  # 6 hours
        max_attempts=100,
    ),
    "preflight": RetryStrategy(
        initial_delay_ms=1_000,
        max_delay_ms=60_000,
        max_attempts=3,
    ),
}


# ════════════════════════════════════════════════════════════════════════════
# PIPELINE — O Orquestrador Principal
# ════════════════════════════════════════════════════════════════════════════


# Type alias for agent executor function
AgentExecutor = Callable[[AgentDefinition, Path], Coroutine[Any, Any, Result]]


class Pipeline:
    """Orquestrador de pipeline multi-fase, multi-agente, com paralelismo.

    Implementa a arquitetura de 5 fases do Shannon adaptada para o ecossistema
    SIREN, com suporte nativo a:
    - Execucao paralela de agentes independentes
    - Retry com backoff exponencial
    - Checkpointing via filesystem
    - Validacao de deliverables
    - Metricas e telemetria por agente
    - Resume de pipelines interrompidos

    Uso:
        pipeline = Pipeline(
            target_url="https://example.com",
            repo_path="/path/to/repo",
            output_dir="/path/to/output",
        )
        result = await pipeline.run(agent_executor)
    """

    def __init__(
        self,
        target_url: str,
        repo_path: str,
        output_dir: str = "./audit-logs",
        workspace: Optional[str] = None,
        retry_preset: str = "production",
        max_concurrent: int = 5,
        on_agent_start: Optional[Callable] = None,
        on_agent_complete: Optional[Callable] = None,
        on_phase_complete: Optional[Callable] = None,
    ):
        self.target_url = target_url
        self.repo_path = repo_path
        self.workspace = workspace or self._generate_workspace_name()
        self.output_dir = Path(output_dir) / self.workspace
        self.retry_strategy = RETRY_PRESETS.get(
            retry_preset, RETRY_PRESETS["production"]
        )
        self.max_concurrent = max_concurrent

        # Callbacks
        self._on_agent_start = on_agent_start
        self._on_agent_complete = on_agent_complete
        self._on_phase_complete = on_phase_complete

        # State
        self._state = PipelineState.IDLE
        self._result = PipelineResult(
            state=PipelineState.IDLE,
            target_url=target_url,
            repo_path=repo_path,
            workspace=self.workspace,
            start_time=time.time(),
        )

        # Initialize metrics for all agents
        for name, agent in AGENTS.items():
            self._result.agent_metrics[name] = AgentMetrics(
                agent_name=name,
                phase=agent.phase,
            )

    def _generate_workspace_name(self) -> str:
        """Gera nome de workspace automatico baseado no target."""
        from urllib.parse import urlparse

        parsed = urlparse(self.target_url)
        hostname = parsed.hostname or "unknown"
        hostname = hostname.replace(".", "-")
        ts = int(time.time() * 1000)
        return f"{hostname}_siren-{ts}"

    @property
    def state(self) -> PipelineState:
        return self._state

    @property
    def result(self) -> PipelineResult:
        return self._result

    def _check_prerequisites(self, agent: AgentDefinition) -> bool:
        """Verifica se todos os prerequisites de um agente foram concluidos."""
        for prereq in agent.prerequisites:
            metric = self._result.agent_metrics.get(prereq)
            if not metric or metric.status not in (
                AgentStatus.COMPLETED,
                AgentStatus.SKIPPED,
            ):
                return False
        return True

    def _check_deliverable(self, agent: AgentDefinition) -> bool:
        """Verifica se o deliverable de um agente ja existe (resume)."""
        deliverable_path = self.output_dir / "deliverables" / agent.deliverable_filename
        return deliverable_path.exists()

    async def _execute_agent_with_retry(
        self,
        agent: AgentDefinition,
        executor: AgentExecutor,
    ) -> Result:
        """Executa um agente com retry e backoff exponencial."""
        metrics = self._result.agent_metrics[agent.name]

        for attempt in range(self.retry_strategy.max_attempts):
            metrics.retry_count = attempt
            metrics.status = AgentStatus.RUNNING
            metrics.start_time = time.time()

            if self._on_agent_start:
                await self._safe_callback(self._on_agent_start, agent, attempt)

            try:
                result = await executor(agent, self.output_dir)

                if result.is_ok:
                    metrics.status = AgentStatus.COMPLETED
                    metrics.end_time = time.time()
                    metrics.tokens_used = (
                        getattr(result.value, "tokens", 0) if result.value else 0
                    )
                    metrics.cost_usd = (
                        getattr(result.value, "cost", 0.0) if result.value else 0.0
                    )

                    # Record deliverable
                    deliverable_path = (
                        self.output_dir / "deliverables" / agent.deliverable_filename
                    )
                    if deliverable_path.exists():
                        metrics.deliverable_size = deliverable_path.stat().st_size
                        self._result.deliverables[agent.deliverable_filename] = str(
                            deliverable_path
                        )

                    if self._on_agent_complete:
                        await self._safe_callback(
                            self._on_agent_complete, agent, result
                        )

                    return result

                # Non-retryable failure
                if attempt >= self.retry_strategy.max_attempts - 1:
                    metrics.status = AgentStatus.FAILED
                    metrics.end_time = time.time()
                    metrics.error_message = result.error
                    return result

            except Exception as e:
                if attempt >= self.retry_strategy.max_attempts - 1:
                    metrics.status = AgentStatus.FAILED
                    metrics.end_time = time.time()
                    metrics.error_message = str(e)
                    return Result.failure(str(e), agent.name)

            # Wait before retry
            delay = self.retry_strategy.get_delay(attempt)
            await asyncio.sleep(delay)

        metrics.status = AgentStatus.FAILED
        metrics.end_time = time.time()
        return Result.failure("Max retries exceeded", agent.name)

    async def _safe_callback(self, callback: Callable, *args: Any) -> None:
        """Executa callback de forma segura (ignora excecoes)."""
        try:
            if asyncio.iscoroutinefunction(callback):
                await callback(*args)
            else:
                callback(*args)
        except Exception as e:
            logger.debug("Pipeline callback error: %s", e)

    async def _run_phase_sequential(
        self,
        phase: PhaseName,
        executor: AgentExecutor,
    ) -> List[Result]:
        """Executa agentes de uma fase sequencialmente."""
        results = []
        for agent_name in AGENTS_BY_PHASE.get(phase, []):
            agent = AGENTS[agent_name]

            # Check if already completed (resume)
            if self._check_deliverable(agent):
                self._result.agent_metrics[agent_name].status = AgentStatus.COMPLETED
                results.append(Result.success(None, agent_name))
                continue

            result = await self._execute_agent_with_retry(agent, executor)
            results.append(result)

        if self._on_phase_complete:
            await self._safe_callback(self._on_phase_complete, phase, results)

        return results

    async def _run_phase_parallel(
        self,
        phase: PhaseName,
        executor: AgentExecutor,
    ) -> List[Result]:
        """Executa agentes de uma fase em paralelo (com limite de concorrencia)."""
        semaphore = asyncio.Semaphore(self.max_concurrent)
        agents = [AGENTS[n] for n in AGENTS_BY_PHASE.get(phase, [])]

        async def run_with_semaphore(agent: AgentDefinition) -> Result:
            # Check if prerequisites are met
            if not self._check_prerequisites(agent):
                self._result.agent_metrics[agent.name].status = AgentStatus.SKIPPED
                return Result.failure(
                    f"Prerequisites not met: {agent.prerequisites}",
                    agent.name,
                )

            # Check if already completed (resume)
            if self._check_deliverable(agent):
                self._result.agent_metrics[agent.name].status = AgentStatus.COMPLETED
                return Result.success(None, agent.name)

            async with semaphore:
                return await self._execute_agent_with_retry(agent, executor)

        tasks = [run_with_semaphore(agent) for agent in agents]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Convert exceptions to Results
        processed_results = []
        for i, r in enumerate(results):
            if isinstance(r, Exception):
                processed_results.append(Result.failure(str(r), agents[i].name))
            else:
                processed_results.append(r)

        if self._on_phase_complete:
            await self._safe_callback(self._on_phase_complete, phase, processed_results)

        return processed_results

    async def run(self, executor: AgentExecutor) -> PipelineResult:
        """Executa o pipeline completo de 5 fases.

        Args:
            executor: Funcao async que executa um agente individual.
                      Signature: async (agent: AgentDefinition, output_dir: Path) -> Result

        Returns:
            PipelineResult com todas as metricas e deliverables.
        """
        self._result.start_time = time.time()

        # Setup output directories
        (self.output_dir / "deliverables").mkdir(parents=True, exist_ok=True)
        (self.output_dir / "agents").mkdir(parents=True, exist_ok=True)
        (self.output_dir / "prompts").mkdir(parents=True, exist_ok=True)

        try:
            # ── Phase 1: Pre-Reconnaissance (sequential) ────────────────
            self._state = PipelineState.PRE_RECON
            self._result.state = PipelineState.PRE_RECON
            results = await self._run_phase_sequential("pre-recon", executor)
            if any(r.is_err for r in results):
                self._state = PipelineState.FAILED
                self._result.state = PipelineState.FAILED
                self._result.error_message = "Pre-recon phase failed"
                self._result.end_time = time.time()
                self._result.save(self.output_dir)
                return self._result

            # ── Phase 2: Reconnaissance (sequential) ────────────────────
            self._state = PipelineState.RECON
            self._result.state = PipelineState.RECON
            results = await self._run_phase_sequential("recon", executor)
            if any(r.is_err for r in results):
                self._state = PipelineState.FAILED
                self._result.state = PipelineState.FAILED
                self._result.error_message = "Recon phase failed"
                self._result.end_time = time.time()
                self._result.save(self.output_dir)
                return self._result

            # ── Phase 3: Vulnerability Analysis (parallel) ──────────────
            self._state = PipelineState.VULN_ANALYSIS
            self._result.state = PipelineState.VULN_ANALYSIS
            vuln_results = await self._run_phase_parallel(
                "vulnerability-analysis", executor
            )
            self._result.total_vulns_found = sum(1 for r in vuln_results if r.is_ok)

            # ── Phase 4: Exploitation (parallel) ────────────────────────
            self._state = PipelineState.EXPLOITATION
            self._result.state = PipelineState.EXPLOITATION
            exploit_results = await self._run_phase_parallel("exploitation", executor)
            self._result.total_exploits_proven = sum(
                1 for r in exploit_results if r.is_ok
            )

            # ── Phase 5: Reporting (sequential) ─────────────────────────
            self._state = PipelineState.REPORTING
            self._result.state = PipelineState.REPORTING
            await self._run_phase_sequential("reporting", executor)

            # ── Finalize ────────────────────────────────────────────────
            self._state = PipelineState.COMPLETED
            self._result.state = PipelineState.COMPLETED
            self._result.end_time = time.time()
            self._result.save(self.output_dir)

            return self._result

        except Exception as e:
            self._state = PipelineState.FAILED
            self._result.state = PipelineState.FAILED
            self._result.error_message = str(e)
            self._result.end_time = time.time()
            self._result.save(self.output_dir)
            return self._result

    def get_status_summary(self) -> dict:
        """Retorna um sumario de status do pipeline para UI."""
        phase_status = {}
        for phase in PHASE_ORDER:
            agents_in_phase = AGENTS_BY_PHASE.get(phase, [])
            completed = sum(
                1
                for a in agents_in_phase
                if self._result.agent_metrics[a].status == AgentStatus.COMPLETED
            )
            failed = sum(
                1
                for a in agents_in_phase
                if self._result.agent_metrics[a].status == AgentStatus.FAILED
            )
            running = sum(
                1
                for a in agents_in_phase
                if self._result.agent_metrics[a].status == AgentStatus.RUNNING
            )
            phase_status[phase] = {
                "total": len(agents_in_phase),
                "completed": completed,
                "failed": failed,
                "running": running,
                "progress": f"{completed}/{len(agents_in_phase)}",
            }

        return {
            "state": self._state.value,
            "workspace": self.workspace,
            "target": self.target_url,
            "duration": self._result.duration_display,
            "phases": phase_status,
            "vulns_found": self._result.total_vulns_found,
            "exploits_proven": self._result.total_exploits_proven,
        }
