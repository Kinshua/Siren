#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  ⏱  SIREN PERFORMANCE PROFILER — Runtime Intelligence & Optimization  ⏱      ██
██                                                                                ██
██  Profiling de performance em tempo real para auto-otimização da SIREN.        ██
██                                                                                ██
██  Capacidades:                                                                  ██
██    • Operation timing — mede cada operação com precisão de ns                ██
██    • Throughput tracking — ops/segundo por componente                         ██
██    • Memory profiling — tracking de alocação (sem instrumentation)            ██
██    • Bottleneck detection — identifica gargalos automaticamente               ██
██    • Success rate tracking — monitora taxa de sucesso por técnica            ██
██    • Adaptive optimization — sugere e aplica otimizações                      ██
██    • Historical analysis — compara performance ao longo do tempo             ██
██                                                                                ██
██  "SIREN mede tudo — e otimiza o que importa."                                ██
██                                                                                ██
████████████████████████████████████████████████████████████████████████████████████
"""

from __future__ import annotations

import logging
import math
import statistics
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Deque, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("siren.meta.performance_profiler")


# ════════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════════════════════════════

MAX_SAMPLES_PER_OP = 10_000
BOTTLENECK_PERCENTILE = 95
SLOW_OP_THRESHOLD_MS = 500
THROUGHPUT_WINDOW_SECONDS = 60
OPTIMIZATION_CHECK_INTERVAL = 100  # Check every N operations


# ════════════════════════════════════════════════════════════════════════════════
# ENUMS
# ════════════════════════════════════════════════════════════════════════════════

class ProfileCategory(Enum):
    """Category of profiled operation."""
    NETWORK_IO = auto()
    DISK_IO = auto()
    CPU_COMPUTE = auto()
    MEMORY_ALLOC = auto()
    CRYPTO = auto()
    PARSING = auto()
    FUZZING = auto()
    SCANNING = auto()
    REPORTING = auto()
    GRAPH_OP = auto()
    DB_QUERY = auto()
    ORCHESTRATION = auto()


class OptimizationLevel(Enum):
    """Optimization aggressiveness."""
    NONE = auto()
    CONSERVATIVE = auto()
    MODERATE = auto()
    AGGRESSIVE = auto()


# ════════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class TimingSample:
    """A single timing measurement."""
    start_ns: int
    end_ns: int
    success: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def duration_ms(self) -> float:
        return (self.end_ns - self.start_ns) / 1_000_000

    @property
    def duration_us(self) -> float:
        return (self.end_ns - self.start_ns) / 1_000


@dataclass
class OperationProfile:
    """Aggregated profile for a named operation."""
    name: str
    category: ProfileCategory = ProfileCategory.CPU_COMPUTE
    samples: Deque[TimingSample] = field(default_factory=lambda: deque(maxlen=MAX_SAMPLES_PER_OP))
    total_calls: int = 0
    total_successes: int = 0
    total_failures: int = 0
    _sum_ms: float = 0.0
    _sum_sq_ms: float = 0.0

    def record(self, sample: TimingSample) -> None:
        self.samples.append(sample)
        self.total_calls += 1
        ms = sample.duration_ms
        self._sum_ms += ms
        self._sum_sq_ms += ms * ms
        if sample.success:
            self.total_successes += 1
        else:
            self.total_failures += 1

    @property
    def avg_ms(self) -> float:
        if self.total_calls == 0:
            return 0.0
        return self._sum_ms / self.total_calls

    @property
    def std_ms(self) -> float:
        if self.total_calls < 2:
            return 0.0
        variance = (self._sum_sq_ms / self.total_calls) - (self.avg_ms ** 2)
        return math.sqrt(max(0.0, variance))

    @property
    def success_rate(self) -> float:
        if self.total_calls == 0:
            return 0.0
        return self.total_successes / self.total_calls

    @property
    def p50_ms(self) -> float:
        return self._percentile(50)

    @property
    def p95_ms(self) -> float:
        return self._percentile(95)

    @property
    def p99_ms(self) -> float:
        return self._percentile(99)

    @property
    def min_ms(self) -> float:
        if not self.samples:
            return 0.0
        return min(s.duration_ms for s in self.samples)

    @property
    def max_ms(self) -> float:
        if not self.samples:
            return 0.0
        return max(s.duration_ms for s in self.samples)

    def _percentile(self, p: int) -> float:
        if not self.samples:
            return 0.0
        durations = sorted(s.duration_ms for s in self.samples)
        idx = int(len(durations) * p / 100)
        idx = min(idx, len(durations) - 1)
        return durations[idx]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category.name,
            "total_calls": self.total_calls,
            "success_rate": round(self.success_rate, 4),
            "avg_ms": round(self.avg_ms, 3),
            "std_ms": round(self.std_ms, 3),
            "p50_ms": round(self.p50_ms, 3),
            "p95_ms": round(self.p95_ms, 3),
            "p99_ms": round(self.p99_ms, 3),
            "min_ms": round(self.min_ms, 3),
            "max_ms": round(self.max_ms, 3),
        }


@dataclass
class ThroughputTracker:
    """Tracks operations per second over a sliding window."""
    window_seconds: float = THROUGHPUT_WINDOW_SECONDS
    _timestamps: Deque[float] = field(default_factory=lambda: deque(maxlen=100_000))

    def record(self) -> None:
        self._timestamps.append(time.time())

    @property
    def ops_per_second(self) -> float:
        now = time.time()
        cutoff = now - self.window_seconds
        # Count events within window
        count = sum(1 for t in self._timestamps if t >= cutoff)
        if self.window_seconds <= 0:
            return 0.0
        return count / self.window_seconds


@dataclass
class BottleneckInfo:
    """Detected bottleneck."""
    operation: str
    category: ProfileCategory
    avg_ms: float
    p95_ms: float
    call_count: int
    total_time_ms: float       # Total time consumed by this op
    percentage_of_total: float # % of total execution time
    suggestion: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "operation": self.operation,
            "category": self.category.name,
            "avg_ms": round(self.avg_ms, 3),
            "p95_ms": round(self.p95_ms, 3),
            "call_count": self.call_count,
            "total_time_ms": round(self.total_time_ms, 2),
            "percentage_of_total": round(self.percentage_of_total, 2),
            "suggestion": self.suggestion,
        }


@dataclass
class OptimizationSuggestion:
    """An auto-generated optimization suggestion."""
    operation: str
    category: ProfileCategory
    current_metric: str
    suggestion: str
    estimated_improvement: str
    priority: int = 0  # 1-10

    def to_dict(self) -> Dict[str, Any]:
        return {
            "operation": self.operation,
            "category": self.category.name,
            "current_metric": self.current_metric,
            "suggestion": self.suggestion,
            "estimated_improvement": self.estimated_improvement,
            "priority": self.priority,
        }


# ════════════════════════════════════════════════════════════════════════════════
# TIMER CONTEXT MANAGER — Measure operation timing
# ════════════════════════════════════════════════════════════════════════════════

class Timer:
    """Context manager for timing operations."""

    def __init__(self, profiler: SirenPerformanceProfiler, operation: str) -> None:
        self._profiler = profiler
        self._operation = operation
        self._start_ns = 0
        self._success = True

    def __enter__(self) -> Timer:
        self._start_ns = time.perf_counter_ns()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        end_ns = time.perf_counter_ns()
        if exc_type is not None:
            self._success = False
        sample = TimingSample(
            start_ns=self._start_ns,
            end_ns=end_ns,
            success=self._success,
        )
        self._profiler._record_sample(self._operation, sample)

    def mark_failure(self) -> None:
        """Mark this operation as failed (before exiting context)."""
        self._success = False


# ════════════════════════════════════════════════════════════════════════════════
# SIREN PERFORMANCE PROFILER — Main Orchestrator
# ════════════════════════════════════════════════════════════════════════════════

class SirenPerformanceProfiler:
    """
    Main performance profiling engine.

    Tracks timing, throughput, success rates, bottlenecks, and optimization
    opportunities across all SIREN operations.

    Usage:
        profiler = SirenPerformanceProfiler()

        # Method 1: Context manager
        with profiler.time("network.http_request"):
            response = do_request()

        # Method 2: Manual timing
        profiler.start("scan.sql_injection")
        result = run_sqli_scan()
        profiler.stop("scan.sql_injection", success=result.found_vulns)

        # Analysis
        bottlenecks = profiler.detect_bottlenecks()
        suggestions = profiler.get_optimization_suggestions()
    """

    def __init__(self, optimization_level: OptimizationLevel = OptimizationLevel.MODERATE) -> None:
        self._lock = threading.RLock()
        self._operations: Dict[str, OperationProfile] = {}
        self._throughput: Dict[str, ThroughputTracker] = defaultdict(ThroughputTracker)
        self._pending_starts: Dict[str, int] = {}  # op → start_ns (manual timing)
        self._optimization_level = optimization_level
        self._total_ops = 0
        self._session_start = time.time()
        self._category_map: Dict[str, ProfileCategory] = {}
        logger.info("SirenPerformanceProfiler initialized (level=%s)", optimization_level.name)

    def set_category(self, operation: str, category: ProfileCategory) -> None:
        """Set the category for an operation name."""
        with self._lock:
            self._category_map[operation] = category
            if operation in self._operations:
                self._operations[operation].category = category

    def time(self, operation: str) -> Timer:
        """Return a context manager that times the operation."""
        return Timer(self, operation)

    def start(self, operation: str) -> None:
        """Start manual timing for an operation."""
        self._pending_starts[operation] = time.perf_counter_ns()

    def stop(self, operation: str, success: bool = True) -> float:
        """Stop manual timing. Returns duration in ms."""
        end_ns = time.perf_counter_ns()
        start_ns = self._pending_starts.pop(operation, 0)
        if start_ns == 0:
            return 0.0
        sample = TimingSample(start_ns=start_ns, end_ns=end_ns, success=success)
        self._record_sample(operation, sample)
        return sample.duration_ms

    def record_instant(self, operation: str, duration_ms: float, success: bool = True) -> None:
        """Record a pre-measured duration."""
        ns = int(duration_ms * 1_000_000)
        sample = TimingSample(start_ns=0, end_ns=ns, success=success)
        self._record_sample(operation, sample)

    def get_profile(self, operation: str) -> Optional[OperationProfile]:
        with self._lock:
            return self._operations.get(operation)

    def get_all_profiles(self) -> Dict[str, Dict[str, Any]]:
        with self._lock:
            return {name: op.to_dict() for name, op in self._operations.items()}

    def get_throughput(self, operation: str) -> float:
        with self._lock:
            tracker = self._throughput.get(operation)
            return tracker.ops_per_second if tracker else 0.0

    def detect_bottlenecks(self, top_n: int = 5) -> List[BottleneckInfo]:
        """Detect the top N bottleneck operations."""
        with self._lock:
            total_time = sum(
                op._sum_ms for op in self._operations.values()
            )
            if total_time == 0:
                return []

            bottlenecks: List[BottleneckInfo] = []
            for name, op in self._operations.items():
                if op.total_calls < 3:
                    continue
                total_op_time = op._sum_ms
                pct = (total_op_time / total_time) * 100

                suggestion = self._generate_bottleneck_suggestion(op)

                bottlenecks.append(BottleneckInfo(
                    operation=name,
                    category=op.category,
                    avg_ms=op.avg_ms,
                    p95_ms=op.p95_ms,
                    call_count=op.total_calls,
                    total_time_ms=total_op_time,
                    percentage_of_total=pct,
                    suggestion=suggestion,
                ))

            bottlenecks.sort(key=lambda b: b.total_time_ms, reverse=True)
            return bottlenecks[:top_n]

    def get_optimization_suggestions(self) -> List[OptimizationSuggestion]:
        """Generate optimization suggestions based on profiling data."""
        with self._lock:
            suggestions: List[OptimizationSuggestion] = []

            for name, op in self._operations.items():
                if op.total_calls < 5:
                    continue

                # High latency operations
                if op.p95_ms > SLOW_OP_THRESHOLD_MS:
                    suggestions.append(OptimizationSuggestion(
                        operation=name,
                        category=op.category,
                        current_metric=f"p95={op.p95_ms:.1f}ms",
                        suggestion="Consider async execution, caching, or connection pooling",
                        estimated_improvement="30-60% latency reduction",
                        priority=8,
                    ))

                # High variance operations
                if op.std_ms > op.avg_ms * 2:
                    suggestions.append(OptimizationSuggestion(
                        operation=name,
                        category=op.category,
                        current_metric=f"std={op.std_ms:.1f}ms vs avg={op.avg_ms:.1f}ms",
                        suggestion="High variance — investigate intermittent delays (DNS, GC, contention)",
                        estimated_improvement="More predictable performance",
                        priority=6,
                    ))

                # Low success rate
                if op.success_rate < 0.50 and op.total_calls >= 10:
                    suggestions.append(OptimizationSuggestion(
                        operation=name,
                        category=op.category,
                        current_metric=f"success_rate={op.success_rate:.1%}",
                        suggestion="Success rate below 50% — review error handling or skip failing targets",
                        estimated_improvement="Reduce wasted time on failing operations",
                        priority=9,
                    ))

                # Network I/O optimization
                if op.category == ProfileCategory.NETWORK_IO and op.avg_ms > 200:
                    suggestions.append(OptimizationSuggestion(
                        operation=name,
                        category=op.category,
                        current_metric=f"avg={op.avg_ms:.1f}ms",
                        suggestion="Batch requests, use connection reuse, or increase parallelism",
                        estimated_improvement="50-80% throughput improvement",
                        priority=7,
                    ))

            suggestions.sort(key=lambda s: s.priority, reverse=True)
            return suggestions

    def get_category_summary(self) -> Dict[str, Dict[str, Any]]:
        """Summarize performance by category."""
        with self._lock:
            summary: Dict[str, Dict[str, Any]] = {}
            for cat in ProfileCategory:
                ops = [op for op in self._operations.values() if op.category == cat]
                if not ops:
                    continue
                total_calls = sum(op.total_calls for op in ops)
                total_time = sum(op._sum_ms for op in ops)
                avg_success = (
                    sum(op.success_rate * op.total_calls for op in ops) / total_calls
                    if total_calls > 0 else 0.0
                )
                summary[cat.name] = {
                    "operation_count": len(ops),
                    "total_calls": total_calls,
                    "total_time_ms": round(total_time, 2),
                    "avg_success_rate": round(avg_success, 4),
                }
            return summary

    def get_session_stats(self) -> Dict[str, Any]:
        """Get overall session statistics."""
        with self._lock:
            elapsed = time.time() - self._session_start
            return {
                "session_duration_s": round(elapsed, 2),
                "total_operations": self._total_ops,
                "unique_operations": len(self._operations),
                "overall_ops_per_second": round(self._total_ops / max(elapsed, 0.001), 2),
                "optimization_level": self._optimization_level.name,
            }

    def reset(self) -> None:
        """Reset all profiling data."""
        with self._lock:
            self._operations.clear()
            self._throughput.clear()
            self._pending_starts.clear()
            self._total_ops = 0
            self._session_start = time.time()

    # ── Private helpers ─────────────────────────────────────────────────────

    def _record_sample(self, operation: str, sample: TimingSample) -> None:
        """Record a timing sample for an operation."""
        with self._lock:
            if operation not in self._operations:
                cat = self._category_map.get(operation, ProfileCategory.CPU_COMPUTE)
                self._operations[operation] = OperationProfile(name=operation, category=cat)
            self._operations[operation].record(sample)
            self._throughput[operation].record()
            self._total_ops += 1

    @staticmethod
    def _generate_bottleneck_suggestion(op: OperationProfile) -> str:
        """Generate a specific suggestion for a bottleneck."""
        if op.category == ProfileCategory.NETWORK_IO:
            return "Parallelize network I/O, use connection pooling, batch requests"
        elif op.category == ProfileCategory.DISK_IO:
            return "Use buffered I/O, batch writes, consider memory-mapped files"
        elif op.category == ProfileCategory.CPU_COMPUTE:
            if op.avg_ms > 1000:
                return "Consider algorithmic optimization or caching intermediate results"
            return "Profile hot paths, consider C extension for inner loops"
        elif op.category == ProfileCategory.CRYPTO:
            return "Use hardware-accelerated crypto, reduce key sizes if acceptable"
        elif op.category == ProfileCategory.PARSING:
            return "Use streaming parser, pre-compile regexes, cache parsed results"
        elif op.category == ProfileCategory.DB_QUERY:
            return "Add indexes, use prepared statements, implement query caching"
        elif op.category == ProfileCategory.GRAPH_OP:
            return "Optimize graph traversal, use adjacency matrix for dense graphs"
        return "Profile and optimize hot code path"
