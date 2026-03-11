"""
╔══════════════════════════════════════════════════════════════════════════════════╗
║                                                                                  ║
║  🧠  SIREN CORTEX — The Cognitive Core                                          ║
║                                                                                  ║
║  TIER 0 modules — the brain that THINKS, not just executes.                      ║
║                                                                                  ║
║  • bayesian_engine  — Probabilistic inference without LLM dependency             ║
║  • vuln_dna         — Vulnerability genetic fingerprinting                       ║
║  • exploit_synthesis — Algorithmic exploit chain generation                      ║
║  • attack_persona   — Dynamic attacker behavior simulation                       ║
║  • knowledge_graph  — Persistent cross-scan knowledge store                      ║
║                                                                                  ║
╚══════════════════════════════════════════════════════════════════════════════════╝
"""

from .adversarial_ml import (
    EvasionGenerator,
    EvasionResult,
    FeatureAnalyzer,
    MLModelProber,
    PerturbationEngine,
    SirenAdversarialML,
)
from .attack_persona import (
    AttackPersona,
    BehaviorSimulator,
    PersonaLibrary,
    PersonaStrategySelector,
    SirenAttackPersonaEngine,
)
from .attack_planner import (
    ActionLibrary,
    AttackPlan,
    PlanOptimizer,
    PlanSearchEngine,
    SirenAttackPlanner,
)
from .bayesian_engine import (
    BayesianNetwork,
    BayesianNode,
    BeliefState,
    EvidenceCollector,
    HypothesisRanker,
    PosteriorCalculator,
    SirenBayesianEngine,
)
from .cognitive_reasoner import (
    DeductiveEngine,
    Evidence,
    Hypothesis,
    InferenceRule,
    ReasoningChain,
    ReasoningReport,
    ReasoningResult,
    SirenCognitiveReasoner,
)
from .exploit_synthesis import (
    ChainCandidate,
    ChainExecutor,
    ChainOptimizer,
    ChainScorer,
    ChainSynthesizer,
    ExploitPrimitive,
    PrimitiveMapper,
    SirenExploitSynthesis,
)
from .knowledge_graph import (
    GraphQueryEngine,
    KnowledgeEdge,
    KnowledgeGraph,
    KnowledgeNode,
    SirenKnowledgeGraph,
)
from .vuln_dna import (
    DNAExtractor,
    GeneticComparator,
    LineageTracker,
    MutationAnalyzer,
    PredictiveGenetics,
    SirenVulnDNA,
    VulnGenome,
)

__all__ = [
    # Bayesian
    "BayesianNetwork", "BeliefState", "BayesianNode",
    "EvidenceCollector", "PosteriorCalculator", "HypothesisRanker",
    "SirenBayesianEngine",
    # Vuln DNA
    "VulnGenome", "DNAExtractor", "GeneticComparator",
    "LineageTracker", "MutationAnalyzer", "PredictiveGenetics", "SirenVulnDNA",
    # Exploit Synthesis
    "ExploitPrimitive", "PrimitiveMapper", "ChainCandidate",
    "ChainSynthesizer", "ChainScorer", "ChainOptimizer",
    "ChainExecutor", "SirenExploitSynthesis",
    # Attack Persona
    "AttackPersona", "PersonaLibrary", "BehaviorSimulator",
    "PersonaStrategySelector", "SirenAttackPersonaEngine",
    # Knowledge Graph
    "KnowledgeNode", "KnowledgeEdge", "KnowledgeGraph",
    "GraphQueryEngine", "SirenKnowledgeGraph",
    # Adversarial ML
    "FeatureAnalyzer", "MLModelProber", "PerturbationEngine",
    "EvasionGenerator", "EvasionResult", "SirenAdversarialML",
    # Attack Planner
    "ActionLibrary", "AttackPlan", "PlanSearchEngine",
    "PlanOptimizer", "SirenAttackPlanner",
    # Cognitive Reasoner
    "DeductiveEngine", "Evidence", "Hypothesis",
    "InferenceRule", "ReasoningChain", "ReasoningResult",
    "ReasoningReport", "SirenCognitiveReasoner",
]
