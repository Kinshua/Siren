"""
╔══════════════════════════════════════════════════════════════════════════════════╗
║                                                                                  ║
║  ⚔️  SIREN ARSENAL — Extended Weapons Systems                                  ║
║                                                                                  ║
║  TIER 1 expansion — specialized engines for modern attack surfaces.              ║
║                                                                                  ║
║  • protocol_dissector  — Binary protocol analysis & fuzzing                      ║
║  • supply_chain        — Dependency analysis & known vuln detection              ║
║  • container_security  — Docker/K8s misconfig & escape detection                 ║
║  • graphql_engine      — Deep GraphQL introspection & exploitation               ║
║  • websocket_engine    — WebSocket protocol testing & injection                  ║
║  • iot_engine          — IoT/ICS device security assessment                      ║
║  • cloud_attack        — Multi-cloud offensive operations                        ║
║  • dast_engine         — Dynamic Application Security Testing                    ║
║  • sast_engine         — Static Application Security Testing                     ║
║  • ad_attack           — Active Directory attack & enumeration                   ║
║  • firmware_analyzer   — Firmware binary analysis & extraction                   ║
║  • llm_attack          — LLM/AI security testing                                 ║
║  • network_exploiter   — Network exploitation & lateral movement                 ║
║                                                                                  ║
╚══════════════════════════════════════════════════════════════════════════════════╝
"""

from .ad_attack import (
    ADFinding,
    ADReport,
    BloodHoundAnalyzer,
    DomainInfo,
    LDAPEnumerator,
    SirenADAttacker,
)
from .cloud_attack import (
    AWSExploiter,
    AzureExploiter,
    CloudAsset,
    CloudCredential,
    CloudCredentialHarvester,
    CloudFinding,
    CloudPrivEscChain,
    CloudPrivEscPath,
    GCPExploiter,
    IAMAnalyzer,
    MetadataExploiter,
    S3BucketScanner,
    SirenCloudAttacker,
)
from .container_security import (
    ContainerAuditReport,
    ContainerFinding,
    DockerfileAnalyzer,
    KubernetesAnalyzer,
    SirenContainerSecurity,
)
from .dast_engine import (
    AuthenticatedScanner,
    CrawlerEngine,
    DASTFinding,
    DASTReport,
    ParameterFuzzer,
    SirenDASTEngine,
)
from .firmware_analyzer import (
    BinaryDelta,
    EntropyAnalyzer,
    FirmwareFinding,
    FirmwareMetadata,
    FirmwareReport,
    SirenFirmwareAnalyzer,
)
from .graphql_engine import (
    GraphQLField,
    GraphQLSchema,
    IntrospectionQueryBuilder,
    QueryGenerator,
    SirenGraphQLEngine,
)
from .iot_engine import (
    AMQPAnalyzer,
    BACnetScanner,
    CoAPExploiter,
    DefaultCredDB,
    IoTDevice,
    IoTFinding,
    IoTFingerprinter,
    IoTReport,
    ModbusExploiter,
    MQTTExploiter,
    SirenIoTEngine,
    UPnPScanner,
)
from .llm_attack import (
    DataExfiltrator,
    JailbreakEngine,
    LLMFinding,
    LLMSecurityReport,
    PromptInjector,
    SirenLLMAttacker,
    SystemPromptExtractor,
)
from .network_exploiter import (
    CredentialHarvester,
    NetworkFinding,
    NetworkMapper,
    NetworkReport,
    ProtocolAttacker,
    ServiceExploiter,
    SirenNetworkExploiter,
    TunnelManager,
)
from .protocol_dissector import (
    BinaryFieldExtractor,
    FuzzingSeedGenerator,
    ProtocolField,
    ProtocolSignature,
    SirenProtocolDissector,
)
from .sast_engine import (
    SASTFinding,
    SASTReport,
    SirenSASTEngine,
    SourceDetector,
    TaintFlow,
)
from .sast_engine import (
    ScanConfig as SASTScanConfig,
)
from .supply_chain import (
    DependencyGraphBuilder,
    LicenseAuditor,
    ManifestParser,
    SirenSupplyChain,
    SupplyChainFinding,
    SupplyChainReport,
)
from .websocket_engine import (
    SirenWebSocketEngine,
    WSFrame,
    WSFuzzGenerator,
    WSMessage,
    WSReport,
)

__all__ = [
    # Protocol Dissector
    "ProtocolField", "ProtocolSignature", "BinaryFieldExtractor",
    "FuzzingSeedGenerator", "SirenProtocolDissector",
    # Supply Chain
    "SupplyChainFinding", "SupplyChainReport", "ManifestParser",
    "LicenseAuditor", "DependencyGraphBuilder", "SirenSupplyChain",
    # Container Security
    "ContainerFinding", "ContainerAuditReport", "DockerfileAnalyzer",
    "KubernetesAnalyzer", "SirenContainerSecurity",
    # GraphQL Engine
    "GraphQLSchema", "GraphQLField", "IntrospectionQueryBuilder",
    "QueryGenerator", "SirenGraphQLEngine",
    # WebSocket Engine
    "WSFrame", "WSMessage", "WSReport",
    "WSFuzzGenerator", "SirenWebSocketEngine",
    # IoT Engine
    "IoTFinding", "IoTDevice", "IoTReport", "DefaultCredDB",
    "IoTFingerprinter", "MQTTExploiter", "CoAPExploiter",
    "UPnPScanner", "ModbusExploiter", "BACnetScanner",
    "AMQPAnalyzer", "SirenIoTEngine",
    # Cloud Attack
    "CloudCredential", "CloudAsset", "CloudFinding", "CloudPrivEscPath",
    "MetadataExploiter", "S3BucketScanner", "AWSExploiter",
    "GCPExploiter", "AzureExploiter", "CloudPrivEscChain",
    "IAMAnalyzer", "CloudCredentialHarvester", "SirenCloudAttacker",
    # DAST Engine
    "DASTFinding", "DASTReport", "CrawlerEngine",
    "ParameterFuzzer", "AuthenticatedScanner", "SirenDASTEngine",
    # SAST Engine
    "SASTFinding", "SASTReport", "SASTScanConfig",
    "SirenSASTEngine", "SourceDetector", "TaintFlow",
    # AD Attack
    "ADFinding", "ADReport", "LDAPEnumerator",
    "BloodHoundAnalyzer", "DomainInfo", "SirenADAttacker",
    # Firmware Analyzer
    "FirmwareFinding", "FirmwareReport", "FirmwareMetadata",
    "EntropyAnalyzer", "BinaryDelta", "SirenFirmwareAnalyzer",
    # LLM Attack
    "LLMFinding", "LLMSecurityReport", "PromptInjector",
    "JailbreakEngine", "SystemPromptExtractor",
    "DataExfiltrator", "SirenLLMAttacker",
    # Network Exploiter
    "NetworkFinding", "NetworkReport", "NetworkMapper",
    "ServiceExploiter", "ProtocolAttacker",
    "CredentialHarvester", "TunnelManager",
    "SirenNetworkExploiter",
]
