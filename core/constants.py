"""
████████████████████████████████████████████████████████████████████████████████████
██                                                                                ██
██  🔧  SIREN Constants — Shared Configuration & Constants  🔧                   ██
██                                                                                ██
██  Centralized constants used across all SIREN tiers.                           ██
██  "Uma base sólida sustenta qualquer abismo."                                  ██
██                                                                                ██
████████████████████████████████████████████████████████████████████████████████████
"""
from __future__ import annotations

# === Numerical Constants ===
EPSILON = 1e-12
LOG_EPSILON = 1e-300  # Floor value before log computation

# === Cache Limits ===
DEFAULT_CACHE_SIZE = 2048
DEFAULT_LRU_MAX = 4096

# === Search Limits ===
MAX_SEARCH_DEPTH = 50
MAX_BEAM_WIDTH = 50
MAX_CANDIDATES = 500

# === Thread Pool ===
DEFAULT_THREAD_POOL_SIZE = 4
THREAD_POOL_SHUTDOWN_TIMEOUT = 10  # seconds

# === Genome ===
GENOME_DIMENSIONS = 128
GENE_BLOCKS = 8
GENES_PER_BLOCK = 16

# === Temporal ===
TEMPORAL_DECAY_RATE = 0.5
STRATEGY_DECAY_HALF_LIFE_DAYS = 90
