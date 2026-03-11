"""
╔══════════════════════════════════════════════════════════════════════════════════╗
║                                                                                  ║
║  ⚔️  SIREN EVASION — WAF Bypass & Payload Transformation Suite                ║
║                                                                                  ║
║  Advanced evasion techniques for security control circumvention.                ║
║                                                                                  ║
║  • waf_bypass          — WAF fingerprinting, payload transformation             ║
║  • ids_evasion         — IDS/IPS evasion via fragmentation & timing             ║
║  • payload_obfuscator  — Multi-language payload obfuscation                     ║
║                                                                                  ║
╚══════════════════════════════════════════════════════════════════════════════════╝
"""

from .ids_evasion import (
    IDSEvasionReport,
    IDSFinding,
    PacketFragmenter,
    ProtocolAbuser,
    SessionSplitter,
    SirenIDSEvasion,
    TimingEvader,
    TrafficMixer,
)
from .payload_obfuscator import (
    CMDObfuscator,
    HTMLObfuscator,
    JSObfuscator,
    ObfuscationReport,
    ObfuscationResult,
    PowerShellObfuscator,
    ShellObfuscator,
    SirenPayloadObfuscator,
    SQLObfuscator,
)
from .waf_bypass import (
    BypassResult,
    BypassTechnique,
    EncodingChainer,
    PayloadMutator,
    PayloadTransformer,
    SirenWAFBypass,
    WAFBypassReport,
    WAFFingerprinter,
    WAFProfile,
)

__all__ = [
    # WAF Bypass
    "WAFProfile", "WAFFingerprinter", "PayloadTransformer",
    "PayloadMutator", "EncodingChainer", "BypassTechnique",
    "BypassResult", "WAFBypassReport", "SirenWAFBypass",
    # IDS Evasion
    "PacketFragmenter", "TimingEvader", "ProtocolAbuser",
    "TrafficMixer", "SessionSplitter",
    "IDSFinding", "IDSEvasionReport", "SirenIDSEvasion",
    # Payload Obfuscator
    "JSObfuscator", "SQLObfuscator", "CMDObfuscator",
    "HTMLObfuscator", "ShellObfuscator", "PowerShellObfuscator",
    "ObfuscationResult", "ObfuscationReport",
    "SirenPayloadObfuscator",
]
