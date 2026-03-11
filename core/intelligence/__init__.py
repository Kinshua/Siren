"""
╔══════════════════════════════════════════════════════════════════════════════════╗
║                                                                                  ║
║  🛡️  SIREN INTELLIGENCE — Defensive & Analytical Layer                          ║
║                                                                                  ║
║  TIER 2 modules — transforms offensive findings into defensive intelligence.     ║
║                                                                                  ║
║  • defensive_mirror   — Auto-generates WAF/IDS/firewall/patch rules              ║
║  • attack_narrative   — Converts technical findings into narrative stories       ║
║  • osint_correlator   — OSINT entity correlation & enrichment                    ║
║  • deep_fingerprint   — Multi-layer technology fingerprinting                    ║
║  • cve_predictor      — CVE prediction & exploitability scoring                  ║
║  • social_engineering  — Phishing/pretext/vishing campaign generation            ║
║  • threat_hunting     — IOC extraction, SIGMA/YARA rule generation               ║
║                                                                                  ║
╚══════════════════════════════════════════════════════════════════════════════════╝
"""

from .attack_narrative import (
    AttackTimeline,
    AudienceAdapter,
    NarrativeChapter,
    NarrativeEngine,
    SirenAttackNarrative,
)
from .cve_predictor import (
    CVEDatabase,
    PredictionReport,
    SirenCVEPredictor,
)
from .deep_fingerprint import (
    FingerprintResult,
    SignatureDB,
    SirenDeepFingerprint,
)
from .defensive_mirror import (
    CodePatchGenerator,
    ConfigFixGenerator,
    FirewallRuleGenerator,
    IDSSignatureGenerator,
    SIGMARuleGenerator,
    SirenDefensiveMirror,
    WAFRuleGenerator,
)
from .osint_correlator import (
    DorkEngine,
    IdentityResolver,
    OSINTGraph,
    SirenOSINTCorrelator,
)
from .social_engineering import (
    DomainLookalikeGen,
    PhishingTemplateGen,
    PretextBuilder,
    SirenSocialEngineer,
    SMiShingGen,
    SocialEngReport,
    VishingScriptGen,
)
from .threat_hunting import (
    IOCExtractor,
    PlaybookLibrary,
    SirenThreatHunter,
    STIXExporter,
    YARARuleGenerator,
)
from .threat_hunting import (
    SIGMARuleGenerator as ThreatSIGMARuleGenerator,
)

__all__ = [
    # Defensive Mirror
    "WAFRuleGenerator", "FirewallRuleGenerator", "IDSSignatureGenerator",
    "CodePatchGenerator", "SIGMARuleGenerator", "ConfigFixGenerator",
    "SirenDefensiveMirror",
    # Attack Narrative
    "NarrativeChapter", "AttackTimeline", "NarrativeEngine",
    "AudienceAdapter", "SirenAttackNarrative",
    # OSINT Correlator
    "DorkEngine", "IdentityResolver", "OSINTGraph",
    "SirenOSINTCorrelator",
    # Deep Fingerprint
    "FingerprintResult", "SignatureDB", "SirenDeepFingerprint",
    # CVE Predictor
    "CVEDatabase", "PredictionReport", "SirenCVEPredictor",
    # Social Engineering
    "PhishingTemplateGen", "PretextBuilder", "VishingScriptGen",
    "SMiShingGen", "DomainLookalikeGen", "SocialEngReport",
    "SirenSocialEngineer",
    # Threat Hunting
    "IOCExtractor", "STIXExporter", "ThreatSIGMARuleGenerator",
    "YARARuleGenerator", "PlaybookLibrary", "SirenThreatHunter",
]
