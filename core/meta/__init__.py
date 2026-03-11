"""
╔══════════════════════════════════════════════════════════════════════════════════╗
║                                                                                  ║
║  🔄  SIREN META — Self-Evolution & Learning Layer                               ║
║                                                                                  ║
║  TIER 5 modules — SIREN learns from every scan and evolves.                      ║
║                                                                                  ║
║  • self_evolution        — Pattern learning, strategy optimization               ║
║  • strategy_db           — Strategy persistence & recommendation                 ║
║  • performance_profiler  — Runtime profiling & optimization hints                ║
║                                                                                  ║
╚══════════════════════════════════════════════════════════════════════════════════╝
"""

from .performance_profiler import (
    BottleneckInfo,
    OperationProfile,
    OptimizationSuggestion,
    SirenPerformanceProfiler,
    ThroughputTracker,
    Timer,
)
from .self_evolution import (
    EvolutionDB,
    FalsePositiveLearner,
    PatternLearner,
    PayloadEvolver,
    SirenSelfEvolution,
    StrategyOptimizer,
    TargetProfiler,
    TechniqueRanker,
)
from .strategy_db import (
    SimilarityEngine,
    SirenStrategyDB,
    StrategyChain,
    StrategyPersistence,
    StrategyRecommendation,
    StrategyRecord,
)

__all__ = [
    # Self Evolution
    "PatternLearner", "StrategyOptimizer", "PayloadEvolver",
    "TechniqueRanker", "FalsePositiveLearner", "TargetProfiler",
    "EvolutionDB", "SirenSelfEvolution",
    # Strategy DB
    "StrategyRecord", "StrategyChain", "StrategyRecommendation",
    "SimilarityEngine", "StrategyPersistence", "SirenStrategyDB",
    # Performance Profiler
    "OperationProfile", "ThroughputTracker", "BottleneckInfo",
    "OptimizationSuggestion", "Timer", "SirenPerformanceProfiler",
]
