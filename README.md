<div align="center">

```
    ███████╗██╗██████╗ ███████╗███╗   ██╗
    ██╔════╝██║██╔══██╗██╔════╝████╗  ██║
    ███████╗██║██████╔╝█████╗  ██╔██╗ ██║
    ╚════██║██║██╔══██╗██╔══╝  ██║╚██╗██║
    ███████║██║██║  ██║███████╗██║ ╚████║
    ╚══════╝╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝
```

### Shannon Intelligence Recon & Exploitation Nexus

**A fully autonomous cognitive offensive security engine.**<br>
Bayesian inference · Vulnerability genetics · Exploit chain synthesis · Self-evolving strategies

![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![MITRE](https://img.shields.io/badge/MITRE_ATT%26CK-14%2F14_Tactics-red?style=for-the-badge)
![Zero Deps](https://img.shields.io/badge/External_Deps-Zero-blue?style=for-the-badge)
![LOC](https://img.shields.io/badge/Lines_of_Code-55K+-purple?style=for-the-badge)

</div>

---

> [!IMPORTANT]
> **SIREN is designed for authorized security testing, bug bounty programs, CTF competitions, and educational purposes only.** Always obtain proper authorization before testing any target. Use responsibly.

---

## 🎯 What is SIREN?

Most "AI pentesting" tools are thin wrappers around LLM APIs — they send your target to ChatGPT and hope for the best. **SIREN is fundamentally different.**

SIREN is a **cognitive security engine** that thinks for itself. It uses a proprietary Bayesian inference engine, vulnerability DNA genetics, and algorithmic exploit chain synthesis — no LLM required for its core reasoning. It calculates attack probabilities mathematically, identifies vulnerability genetic fingerprints, and synthesizes multi-step exploit chains via A* pathfinding.

**What makes SIREN unique:**

| Capability | SIREN | Typical AI Pentest Tools |
|---|---|---|
| **Reasoning** | Bayesian inference engine (own math) | LLM API calls |
| **Vulnerability Analysis** | 128-dimensional genetic fingerprints | String matching / signatures |
| **Exploit Chains** | Algorithmic synthesis via A* pathfinding | Manual or LLM-suggested |
| **Attacker Simulation** | 8+ persona types (script kiddie → APT) | Single generic approach |
| **Defense Generation** | Auto-generates WAF/IDS/SIGMA rules | N/A |
| **Learning** | Self-evolving strategies with ELO ranking | Static |
| **Dependencies** | Zero (Python stdlib only) | Heavy (many packages) |
| **Offline** | Fully functional without internet | Requires API access |

---

## ✨ Features

### 🧠 Cognitive Core (Tier 0 — CORTEX)
- **Bayesian Engine** — Probabilistic inference that calculates the likelihood of each vulnerability existing on a target, mathematically, without guessing
- **Vulnerability DNA** — 128-dimensional genome representation of vulnerabilities. Compares genetic fingerprints across targets to predict new attack surfaces
- **Exploit Synthesis** — Combines individual vulnerabilities into multi-step chains via A* pathfinding (3 Low findings → 1 Critical chain)
- **Attack Personas** — Simulates 8+ attacker archetypes (script kiddie, insider threat, APT nation-state), each with different behavior patterns
- **Knowledge Graph** — Persistent graph that grows smarter with every scan, correlating findings across targets
- **Cognitive Reasoner** — Multi-modal reasoning (deductive, abductive, analogical, temporal, adversarial)
- **Adversarial ML** — Detects and tests machine learning model vulnerabilities

### ⚔️ Arsenal (Tier 1)
- **Protocol Dissector** — Binary protocol reverse-engineering and field extraction
- **Supply Chain Analyzer** — Dependency auditing, typosquatting detection, license compliance
- **Container Security** — Docker/Kubernetes CIS Benchmark auditing
- **GraphQL Engine** — Schema introspection, query generation, and exploitation
- **WebSocket Engine** — RFC 6455 testing, frame fuzzing, and injection
- **Cloud Attacker** — AWS/Azure/GCP privilege escalation and credential harvesting
- **IoT Engine** — MQTT/CoAP/Modbus/BACnet/UPnP device exploitation
- **Network Exploiter** — Service exploitation, credential harvesting, tunnel management
- **DAST Engine** — Dynamic application security testing with authenticated scanning
- **SAST Engine** — Static code analysis with taint flow tracking
- **AD Attacker** — Active Directory enumeration and exploitation
- **Firmware Analyzer** — Binary analysis, entropy detection, delta comparison
- **LLM Attacker** — Prompt injection, jailbreak testing, system prompt extraction

### 🔍 Intelligence (Tier 2)
- **Attack Narrative** — Generates executive-friendly reports with timeline chapters (CEOs understand stories, not CVE tables)
- **Defensive Mirror** — For every vulnerability found, auto-generates 6 defense layers: WAF rules, firewall rules, IDS signatures, SIGMA rules, code patches, and config fixes
- **OSINT Correlator** — Cross-source intelligence fusion with Google dorking and identity resolution
- **Deep Fingerprint** — L0-L6 multi-layer Bayesian fingerprinting
- **CVE Predictor** — Predicts likely CVEs with temporal scoring
- **Social Engineering** — Phishing template generation, pretext building, vishing scripts
- **Threat Hunter** — IOC extraction, STIX export, YARA rule generation

### 🔄 Automation (Tier 3)
- **Campaign Manager** — Orchestrate multi-phase security campaigns with persistence
- **Continuous Monitor** — Set up ongoing target surveillance with alerting
- **Result Correlator** — Cross-scan deduplication and trend analysis

### 📋 Output (Tier 4)
- **Compliance Mapper** — Maps findings to PCI-DSS, HIPAA, SOC2, ISO 27001, OWASP, NIST, CIS
- **Risk Scorer** — CVSS recalculated with business context (asset value, exposure, ROI)
- **Remediation Generator** — Language/framework-specific fix steps, not generic advice

### 🧬 Meta (Tier 5 — Self-Evolution)
- **Pattern Learner** — Learns from every scan to improve future strategies
- **Strategy DB** — Strategy bank with similarity search and multi-armed bandit selection
- **Technique Ranker** — ELO ranking system for attack techniques
- **Payload Evolver** — Genetic mutation of payloads for evasion
- **Performance Profiler** — Bottleneck detection and optimization suggestions

### 🛡️ Evasion Layer
- **WAF Bypass** — 640+ semantic evasion rules with WAF fingerprinting
- **IDS Evasion** — Packet fragmentation, timing evasion, protocol abuse
- **Payload Obfuscator** — Multi-language obfuscation (JS, SQL, CMD, HTML, Shell, PowerShell)

---

## 📦 Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     SIREN — 6-Tier Architecture                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  TIER 5 — META (Self-Evolution)                                 │
│    self_evolution.py · strategy_db.py · performance_profiler.py │
│                                                                  │
│  TIER 4 — OUTPUT (Compliance & Remediation)                     │
│    compliance_mapper.py · risk_scorer.py · remediation_gen.py   │
│                                                                  │
│  TIER 3 — AUTOMATION (Campaigns & Monitoring)                   │
│    campaign_manager.py · continuous_monitor.py · correlator.py  │
│                                                                  │
│  TIER 2 — INTELLIGENCE (Analytical)                             │
│    attack_narrative.py · defensive_mirror.py · osint.py         │
│    deep_fingerprint.py · cve_predictor.py · threat_hunting.py   │
│                                                                  │
│  TIER 1 — ARSENAL (Weapons Systems)                             │
│    protocol_dissector.py · supply_chain.py · container.py       │
│    graphql.py · websocket.py · cloud.py · iot.py · dast.py      │
│    sast.py · ad_attack.py · firmware.py · llm_attack.py         │
│    network_exploiter.py                                          │
│                                                                  │
│  TIER 0 — CORTEX (Cognitive Brain)                              │
│    bayesian_engine.py · vuln_dna.py · exploit_synthesis.py      │
│    attack_persona.py · knowledge_graph.py · cognitive.py        │
│    adversarial_ml.py · attack_planner.py                        │
│                                                                  │
├─────────────────────────────────────────────────────────────────┤
│  BASE — Shannon Engine (~55K lines)                              │
│    engine.py · scanner.py · recon.py · fuzzer.py · payloads.py  │
│    exploits.py · crypto.py · auth_engine.py · network.py        │
│    api_security.py · mobile_engine.py · attack_graph.py         │
│    threat_intel.py · orchestrator.py · pipeline.py              │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Setup & Usage

### Prerequisites

- **Python 3.9+** (no external dependencies required)

### Installation

```bash
# Clone the repository
git clone https://github.com/kinshua/siren.git
cd siren

# Run directly (zero dependencies — stdlib only)
python siren.py <target>
```

### Quick Start

```bash
# Scan a target
python siren.py example.com

# Target with full URL
python siren.py https://api.example.com
```

### Interactive Menu

Once launched, SIREN presents a compact interactive menu:

```
  PIPELINE
  [A] ALL                    Run full pipeline (Recon > Scan > Attack > Intel)
  [1] Full Pentest           Complete pipeline (13 agents, 5 phases)

  RECON
  [2] Recon + OSINT          Passive/active recon + OSINT correlation

  SCAN
  [3] Vuln Scan + DAST       Web vuln scanner + dynamic analysis
  [4] API + Crypto Audit     OWASP API Top 10 + JWT/TLS/cipher audit

  ATTACK
  [5] Attack Suite           Auth attack + fuzzer + exploit chains

  INTEL
  [6] Intel + Defense        Cognitive reasoning + narrative + defense rules

  EVASION
  [7] Evasion Test           WAF bypass + IDS evasion + payload obfuscation

  [0] Exit
```

### Example: Full Autonomous Scan

```bash
$ python siren.py target.com

# Select [A] for full assault
# SIREN automatically runs:
#   1. Recon + OSINT correlation
#   2. Vulnerability scanning + DAST
#   3. API + Cryptographic audit
#   4. Auth attacks + Fuzzing + Exploit chain synthesis
#   5. Cognitive analysis + Narrative report + Defense rules
#   6. WAF/IDS evasion testing
#
# Results saved to ./siren-output/<target>_<timestamp>/
```

### Output

All results are saved as structured JSON in `./siren-output/`:

```
siren-output/
└── target.com_20260311_143022/
    ├── recon.json              # Subdomains, ports, technologies
    ├── osint.json              # OSINT intelligence
    ├── vuln_scan.json          # Vulnerability findings
    ├── dast.json               # Dynamic analysis results
    ├── api_audit.json          # API security findings
    ├── crypto_audit.json       # Cryptographic audit
    ├── auth_audit.json         # Authentication testing
    ├── fuzzer.json             # Fuzzing results
    ├── exploit_chains.json     # Synthesized exploit chains
    ├── cognitive_report.json   # Multi-modal reasoning report
    ├── narrative.json          # Executive narrative
    ├── defensive_rules.json    # WAF/IDS/SIGMA rules
    ├── ids_evasion.json        # IDS evasion results
    └── payload_obfuscation.json # Obfuscation results
```

---

## 🧠 How the Cognitive Core Works

### Bayesian Inference

SIREN doesn't guess — it calculates. The Bayesian engine maintains a probabilistic belief state about each potential vulnerability on a target. As evidence is gathered (headers, responses, fingerprints), the engine updates posterior probabilities using Bayes' theorem:

```
P(Vuln | Evidence) = P(Evidence | Vuln) × P(Vuln) / P(Evidence)
```

This means SIREN can predict vulnerabilities it hasn't directly tested yet, based on correlations with observed evidence.

### Vulnerability DNA

Each vulnerability gets a 128-dimensional "genome" — a mathematical fingerprint that captures its behavioral characteristics. SIREN compares these genomes across targets using genetic algorithms:

- **DNA Extraction** — Converts vulnerability characteristics into genome vectors
- **Genetic Comparison** — Measures similarity between vulnerability genomes
- **Lineage Tracking** — Traces vulnerability evolution across versions
- **Mutation Analysis** — Detects how vulnerabilities mutate between deployments
- **Predictive Genetics** — Predicts new vulnerabilities based on genetic patterns

### Exploit Chain Synthesis

Individual vulnerabilities are rarely critical alone. SIREN's A* pathfinding algorithm automatically synthesizes multi-step attack chains:

```
Low: Open redirect  ─┐
Low: SSRF (partial)  ├─→  Chain: Critical (RCE)
Low: File upload     ─┘
```

The synthesizer evaluates all possible combinations, scores them by feasibility and impact, and presents optimized attack paths.

---

## 📊 Coverage

| Domain | Modules | Status |
|---|---|---|
| Web Application Security | Scanner, DAST, API Security, Fuzzer | ✅ Complete |
| Network Security | Network Exploiter, Protocol Dissector | ✅ Complete |
| Mobile Security | APK Analyzer, Dynamic Mobile, Payloads | ✅ Complete |
| Cloud Security | AWS/Azure/GCP Attacker, JWT Scanner | ✅ Complete |
| Container Security | Docker/K8s CIS Benchmarks | ✅ Complete |
| IoT Security | MQTT/CoAP/Modbus/BACnet/UPnP | ✅ Complete |
| Active Directory | LDAP Enum, BloodHound Analysis | ✅ Complete |
| Supply Chain | Dependency Audit, Typosquatting | ✅ Complete |
| Firmware Analysis | Binary Analysis, Entropy Detection | ✅ Complete |
| LLM/AI Security | Prompt Injection, Jailbreak Testing | ✅ Complete |
| Cryptography | JWT, TLS, Hashes, Ciphers, Padding Oracle | ✅ Complete |
| Authentication | Brute Force, Spray, MFA Bypass, OAuth | ✅ Complete |
| Evasion | WAF Bypass (640+ rules), IDS, Obfuscation | ✅ Complete |
| OSINT | Dorking, Identity Resolution, Graph Intel | ✅ Complete |
| Compliance | PCI-DSS, HIPAA, SOC2, ISO 27001, NIST | ✅ Complete |

**MITRE ATT&CK Coverage:** 14/14 tactics

---

## 🔬 Design Philosophy

1. **Zero external dependencies** — SIREN runs on Python stdlib only (3.9+). No `pip install` required. It can run on a Raspberry Pi, air-gapped, offline.

2. **Think, don't guess** — Every decision is backed by mathematical inference, not LLM hallucinations. The Bayesian engine provides confidence scores for all findings.

3. **Self-evolution** — SIREN learns from every scan. Pattern recognition, technique ranking via ELO, multi-armed bandit strategy selection, and genetic payload mutation.

4. **Offense informs defense** — For every vulnerability found, SIREN generates defensive countermeasures: WAF rules, IDS signatures, SIGMA rules, code patches, and configuration fixes.

5. **Thread-safe by default** — All engines use `threading.RLock` for safe concurrent operation.

---

## 📁 Project Structure

```
siren/
├── siren.py                  # Interactive CLI entry point
├── pyproject.toml            # Project metadata
├── LICENSE                   # MIT
├── README.md                 # This file
└── core/                     # Shannon Engine
    ├── __init__.py            # Module exports (1,100+ symbols)
    ├── engine.py              # Abyssal Engine — main orchestrator
    ├── scanner.py             # Vulnerability scanner
    ├── recon.py               # Reconnaissance engine
    ├── fuzzer.py              # Smart fuzzer with genetic mutation
    ├── payloads.py            # Payload arsenal
    ├── exploits.py            # Exploit orchestrator
    ├── crypto.py              # Cryptographic attack engine
    ├── auth_engine.py         # Authentication attack engine
    ├── network.py             # HTTP client and network tools
    ├── api_security.py        # API security auditor
    ├── mobile_engine.py       # Mobile security engine
    ├── attack_graph.py        # Attack graph builder
    ├── threat_intel.py        # Threat intelligence correlator
    ├── orchestrator.py        # Pipeline orchestrator
    ├── pipeline.py            # Workflow engine
    ├── reporter.py            # Report generator
    ├── models.py              # AI model configuration
    ├── agents.py              # Agent definitions
    ├── workspace.py           # Workspace & session management
    ├── cortex/                # TIER 0 — Cognitive Brain
    │   ├── bayesian_engine.py
    │   ├── vuln_dna.py
    │   ├── exploit_synthesis.py
    │   ├── attack_persona.py
    │   ├── knowledge_graph.py
    │   ├── cognitive_reasoner.py
    │   ├── adversarial_ml.py
    │   └── attack_planner.py
    ├── arsenal/               # TIER 1 — Weapons Systems
    │   ├── protocol_dissector.py
    │   ├── supply_chain.py
    │   ├── container_security.py
    │   ├── graphql_engine.py
    │   ├── websocket_engine.py
    │   ├── cloud_attack.py
    │   ├── iot_engine.py
    │   ├── network_exploiter.py
    │   ├── dast_engine.py
    │   ├── sast_engine.py
    │   ├── ad_attack.py
    │   ├── firmware_analyzer.py
    │   └── llm_attack.py
    ├── intelligence/          # TIER 2 — Analytical Intelligence
    │   ├── attack_narrative.py
    │   ├── defensive_mirror.py
    │   ├── osint_correlator.py
    │   ├── deep_fingerprint.py
    │   ├── cve_predictor.py
    │   ├── social_engineering.py
    │   └── threat_hunting.py
    ├── automation/            # TIER 3 — Campaigns & Monitoring
    │   ├── campaign_manager.py
    │   ├── continuous_monitor.py
    │   └── result_correlator.py
    ├── output/                # TIER 4 — Compliance & Remediation
    │   ├── compliance_mapper.py
    │   ├── risk_scorer.py
    │   └── remediation_generator.py
    ├── meta/                  # TIER 5 — Self-Evolution
    │   ├── self_evolution.py
    │   ├── strategy_db.py
    │   └── performance_profiler.py
    └── evasion/               # Evasion Layer
        ├── waf_bypass.py
        ├── ids_evasion.py
        └── payload_obfuscator.py
```

---

## 🤝 Contributing

Contributions are welcome! SIREN follows strict conventions:

- **Zero external dependencies** — stdlib only (Python 3.9+)
- **Thread safety** — All engines use `threading.RLock`
- **Dataclasses** — All data structures use `@dataclass` with `.to_dict()`
- **Naming** — Main classes follow `Siren{Capability}` pattern
- **Logging** — `logging.getLogger("siren.{tier}.{module}")`

---

## ⚠️ Legal Disclaimer

SIREN is provided for **authorized security testing and educational purposes only**. Users are solely responsible for ensuring they have proper authorization before testing any systems. The developers assume no liability for misuse of this software.

**Always:**
- Obtain written authorization before testing
- Follow responsible disclosure practices
- Comply with all applicable laws and regulations
- Use only in scope during bug bounty programs

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

*SIREN — Where mathematics meets offensive security.*

</div>
