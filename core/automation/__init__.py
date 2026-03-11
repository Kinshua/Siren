"""
╔══════════════════════════════════════════════════════════════════════════════════╗
║                                                                                  ║
║  🤖  SIREN AUTOMATION — Campaign & Continuous Operations                        ║
║                                                                                  ║
║  TIER 3 modules — multi-target campaigns, monitoring, correlation.               ║
║                                                                                  ║
║  • campaign_manager    — Multi-target campaign orchestration                     ║
║  • continuous_monitor  — Continuous monitoring with diff detection                ║
║  • result_correlator   — Cross-scan finding correlation & dedup                  ║
║                                                                                  ║
╚══════════════════════════════════════════════════════════════════════════════════╝
"""

from .campaign_manager import (
    Campaign,
    CampaignPersistence,
    CampaignPhase,
    CampaignTask,
    CampaignTemplates,
    SirenCampaignManager,
)
from .continuous_monitor import (
    Alert,
    AlertSeverity,
    ContentDiffer,
    MonitorTarget,
    SirenContinuousMonitor,
)
from .result_correlator import (
    CorrelatedFinding,
    CorrelationRule,
    CrossScanPattern,
    DeduplicationEngine,
    SirenResultCorrelator,
)

__all__ = [
    # Campaign Manager
    "Campaign", "CampaignTask", "CampaignPhase",
    "CampaignTemplates", "CampaignPersistence", "SirenCampaignManager",
    # Continuous Monitor
    "MonitorTarget", "Alert", "ContentDiffer",
    "AlertSeverity", "SirenContinuousMonitor",
    # Result Correlator
    "CorrelatedFinding", "CorrelationRule", "CrossScanPattern",
    "DeduplicationEngine", "SirenResultCorrelator",
]
