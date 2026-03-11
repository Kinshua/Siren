<div align="center">

```
    ███████╗██╗██████╗ ███████╗███╗   ██╗
    ██╔════╝██║██╔══██╗██╔════╝████╗  ██║
    ███████╗██║██████╔╝█████╗  ██╔██╗ ██║
    ╚════██║██║██╔══██╗██╔══╝  ██║╚██╗██║
    ███████║██║██║  ██║███████╗██║ ╚████║
    ╚══════╝╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝
```

**Shannon Intelligence Recon & Exploitation Nexus**

Autonomous cognitive engine for offensive security assessments.

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg?style=flat-square)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg?style=flat-square)](LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-14%2F14-red.svg?style=flat-square)](#coverage)
[![Dependencies](https://img.shields.io/badge/dependencies-zero-blue.svg?style=flat-square)](#design-principles)

</div>

---

> **Notice:** This software is intended exclusively for authorized penetration testing, bug bounty programs, CTF competitions, and security research. Obtain written permission before scanning any target you do not own.

---

## Table of Contents

- [Overview](#overview)
- [How It Works](#how-it-works)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [Coverage](#coverage)
- [Design Principles](#design-principles)
- [Project Layout](#project-layout)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

SIREN is an offensive security engine built around mathematical reasoning rather than large-language-model prompts. Where most tools in this space forward targets to an external API and parse whatever comes back, SIREN maintains its own probabilistic model of the target, updates beliefs as evidence arrives, and synthesizes exploit chains algorithmically.

The core is written in pure Python (stdlib only, no third-party packages) and is organized into six operational tiers — from a Bayesian inference cortex down through arsenal modules, intelligence analysis, campaign automation, compliance output, and a self-evolution layer that improves strategy selection over time.

At a glance:

| | SIREN | Typical "AI Pentest" tools |
|---|---|---|
| Reasoning | Bayesian inference, own math | LLM API calls |
| Vuln analysis | 128-dim genetic fingerprints | Signature matching |
| Exploit chains | A\* pathfinding synthesis | Manual / LLM-suggested |
| Attacker models | 8+ behavioral personas | Single generic approach |
| Defense output | WAF / IDS / SIGMA rule generation | Not available |
| Adaptation | ELO-ranked strategy evolution | Static |
| Dependencies | None (Python stdlib) | Heavy |
| Offline use | Full functionality | Requires internet |

---

## How It Works

### Bayesian Inference

SIREN keeps a belief state — a set of probability distributions over possible vulnerabilities on a given target. Each piece of gathered evidence (response headers, status codes, technology fingerprints) triggers a posterior update:

```
P(vuln | evidence) = P(evidence | vuln) * P(vuln) / P(evidence)
```

This allows the engine to estimate the likelihood of vulnerabilities it has not directly tested, based on correlations observed in the evidence so far.

### Vulnerability Genetics

Every identified vulnerability is encoded as a 128-dimensional genome vector that captures its behavioral profile. The engine compares genomes across targets through:

- **Extraction** — mapping vulnerability traits to vector components
- **Comparison** — cosine similarity between genome vectors
- **Lineage tracking** — tracing how a vulnerability evolves across software versions
- **Mutation analysis** — detecting behavioral drift between deployments
- **Prediction** — forecasting undiscovered vulnerabilities from genetic patterns

### Exploit Chain Synthesis

Individual low-severity findings are rarely interesting on their own. The synthesis module uses A\* search to combine them into multi-step attack paths:

```
Open redirect   (Low)  ─┐
SSRF, partial   (Low)   ├──▶  Chained path  (Critical — RCE)
Unrestricted upload (Low) ─┘
```

Candidates are scored by feasibility, stealth, and impact. The output is a ranked list of actionable chains.

### Information Theory Scanner

Named after Claude Shannon, SIREN applies his mathematics directly to vulnerability detection. This module implements six engines that no other security tool in the world provides:

**Mutual Information scanning** measures statistical dependency between inputs and outputs using only benign probes. If changing a parameter from `test1` to `test2` causes structured response changes (high mutual information), the parameter likely flows into a query, template, or command — revealing injection points without triggering any WAF or IDS, because no malicious payload is ever sent.

**KL Divergence detection** builds a probability distribution of normal responses, then measures how much a probe response diverges from baseline. This is more precise than string comparison and works on dynamic pages where content changes between requests.

**Shannon Entropy analysis** profiles the entropy of responses and payloads. Payloads with entropy profiles that differ significantly from normal traffic are easily detected by WAFs. SIREN optimizes payload entropy to match the target's baseline traffic profile.

**Fisher Information probing** applies optimal experimental design to choose the minimum number of requests needed to confirm a vulnerability, based on how much information each probe provides. Fewer requests means less detection.

**Channel Capacity estimation** uses Shannon's channel capacity theorem to calculate the maximum data exfiltration rate through each endpoint, measured in bits per request.

**Kolmogorov Complexity estimation** uses compression analysis to detect when different inputs trigger different server code paths, and to identify obfuscated or encrypted content in responses.

---

## Architecture

SIREN is organized into six tiers, each building on the layers below it.

```
┌──────────────────────────────────────────────────────────────┐
│  TIER 5 — META            Self-evolution & strategy learning │
├──────────────────────────────────────────────────────────────┤
│  TIER 4 — OUTPUT          Compliance mapping & remediation   │
├──────────────────────────────────────────────────────────────┤
│  TIER 3 — AUTOMATION      Campaign orchestration & monitoring│
├──────────────────────────────────────────────────────────────┤
│  TIER 2 — INTELLIGENCE    Narrative, defense, OSINT, hunting │
├──────────────────────────────────────────────────────────────┤
│  TIER 1 — ARSENAL         13 specialized attack engines      │
├──────────────────────────────────────────────────────────────┤
│  TIER 0 — CORTEX          Bayesian brain, vuln DNA, synthesis│
├──────────────────────────────────────────────────────────────┤
│  BASE — Shannon Engine    Scanner, recon, fuzzer, payloads,  │
│                           exploits, crypto, auth, network,   │
│                           API, mobile, threat intel, pipeline│
└──────────────────────────────────────────────────────────────┘
```

**Tier 0 — CORTEX** contains the probabilistic reasoning core: Bayesian engine, vulnerability DNA, exploit chain synthesis via A\*, attack persona simulation, a persistent knowledge graph, multi-modal cognitive reasoner, adversarial ML detector, and attack planner.

**Tier 1 — ARSENAL** provides 13 domain-specific engines: protocol dissector, supply chain auditor, container security (Docker/K8s CIS), GraphQL, WebSocket (RFC 6455), cloud (AWS/Azure/GCP), IoT (MQTT/CoAP/Modbus/BACnet/UPnP), network exploiter, DAST, SAST with taint tracking, Active Directory, firmware analyzer, and LLM security tester.

**Tier 2 — INTELLIGENCE** handles analysis and reporting: executive-oriented attack narratives, defensive mirror (auto-generates WAF rules, firewall rules, IDS signatures, SIGMA rules, code patches, config fixes for each finding), OSINT correlator, deep fingerprinting (L0–L6), CVE prediction, social engineering modules, and threat hunting with IOC/STIX/YARA output.

**Tier 3 — AUTOMATION** manages campaign orchestration, continuous monitoring with alerting, and cross-scan result correlation with deduplication.

**Tier 4 — OUTPUT** maps findings to compliance frameworks (PCI-DSS v4.0, HIPAA, SOC 2, ISO 27001, OWASP Top 10, NIST 800-53, CIS Controls v8), calculates business-context risk scores, and generates framework-specific remediation plans.

**Tier 5 — META** drives self-improvement: pattern learning across scans, a strategy bank with similarity search, ELO-based technique ranking, genetic payload mutation, and a performance profiler that identifies bottlenecks.

**Evasion layer** (cross-cutting): 640+ WAF bypass rules with fingerprinting, IDS evasion via packet fragmentation and timing manipulation, and multi-language payload obfuscation (JavaScript, SQL, shell, HTML, PowerShell).

---

## Installation

Requirements: Python 3.9 or later. No additional packages.

```bash
git clone https://github.com/Kinshua/Siren.git
cd Siren
python siren.py --help
```

---

## Usage

Launch SIREN against a target:

```bash
python siren.py example.com
python siren.py https://api.example.com
```

The interactive menu groups operations into seven compact options:

```
PIPELINE
  [A] ALL                  Full pipeline (Recon > Scan > Attack > Intel)
  [1] Full Pentest         Complete 5-phase pipeline, 13 agents

RECON
  [2] Recon + OSINT        Subdomain enum, port scan, tech fingerprint, OSINT

SCAN
  [3] Vuln Scan + DAST     Web vulnerability scanner and dynamic analysis
  [4] API + Crypto Audit   OWASP API Top 10, JWT/TLS/cipher review

ATTACK
  [5] Attack Suite         Auth testing, smart fuzzing, exploit chain synthesis

INTEL
  [6] Intel + Defense      Cognitive reasoning, narrative report, defense rules

EVASION
  [7] Evasion Test         WAF bypass, IDS evasion, payload obfuscation

SHANNON
  [8] Info Theory Scan     Shannon entropy, mutual information, KL divergence

  [0] Exit
```

Selecting `[A]` runs all modules sequentially. Results are written as structured JSON to `./siren-output/<target>_<timestamp>/`.

```
siren-output/
└── example.com_20260311_143022/
    ├── recon.json
    ├── osint.json
    ├── vuln_scan.json
    ├── dast.json
    ├── api_audit.json
    ├── crypto_audit.json
    ├── auth_audit.json
    ├── fuzzer.json
    ├── exploit_chains.json
    ├── cognitive_report.json
    ├── narrative.json
    ├── defensive_rules.json
    ├── ids_evasion.json
    └── payload_obfuscation.json
```

---

## Coverage

| Domain | Modules |
|---|---|
| Web application | Scanner, DAST, API Security, Fuzzer |
| Network | Network Exploiter, Protocol Dissector |
| Mobile | APK Analyzer, Dynamic Mobile, Payload Generator |
| Cloud | AWS / Azure / GCP Attacker, JWT Scanner |
| Containers | Docker and Kubernetes CIS Benchmark audits |
| IoT | MQTT, CoAP, Modbus, BACnet, UPnP |
| Active Directory | LDAP enumeration, BloodHound-style analysis |
| Supply chain | Dependency audit, typosquatting detection |
| Firmware | Binary analysis, entropy detection, delta comparison |
| LLM / AI | Prompt injection, jailbreak, system prompt extraction |
| Cryptography | JWT, TLS, hash strength, padding oracle, timing attacks |
| Authentication | Brute force, password spray, MFA bypass, OAuth |
| Evasion | WAF bypass (640+ rules), IDS evasion, obfuscation |
| OSINT | Google dorking, identity resolution, graph correlation |
| Information theory | Shannon entropy, mutual information, KL divergence, Fisher info, channel capacity, Kolmogorov complexity |
| Compliance | PCI-DSS, HIPAA, SOC 2, ISO 27001, NIST, CIS |

MITRE ATT&CK: 14 of 14 tactics covered.

---

## Design Principles

1. **No external dependencies.** The entire engine runs on the Python standard library. No `pip install`, no version conflicts, no supply-chain risk. It will run on a Raspberry Pi in an air-gapped lab.

2. **Mathematical reasoning over generative guessing.** Decisions are driven by Bayesian posteriors and algorithmic search, not stochastic text generation. Every finding includes a confidence score derived from the evidence chain.

3. **Continuous self-improvement.** The meta layer records outcomes, ranks techniques by ELO, selects strategies via multi-armed bandit algorithms, and mutates payloads genetically. Each engagement makes the next one sharper.

4. **Offense produces defense.** For every vulnerability discovered, the intelligence tier generates six layers of countermeasures — WAF rules, firewall rules, IDS signatures, SIGMA detection rules, code-level patches, and configuration fixes — so the same report serves both red and blue teams.

5. **Thread safety throughout.** All engine classes use `threading.RLock` internally, making them safe for concurrent use in campaign automation and parallel scanning.

---

## Project Layout

```
Siren/
├── siren.py                    CLI entry point
├── pyproject.toml
├── LICENSE
└── core/
    ├── __init__.py              1,100+ exported symbols
    ├── engine.py                Main orchestrator
    ├── scanner.py               Vulnerability scanner
    ├── recon.py                 Reconnaissance
    ├── fuzzer.py                Genetic-mutation fuzzer
    ├── payloads.py              Payload arsenal
    ├── exploits.py              Exploit orchestration
    ├── crypto.py                Cryptographic attacks
    ├── auth_engine.py           Authentication attacks
    ├── network.py               HTTP client and utilities
    ├── api_security.py          API auditor
    ├── mobile_engine.py         Mobile security
    ├── attack_graph.py          Attack graph construction
    ├── threat_intel.py          Threat intelligence
    ├── orchestrator.py          Pipeline orchestration
    ├── pipeline.py              Workflow management
    ├── reporter.py              Report generation
    ├── models.py                AI model configuration
    ├── agents.py                Agent definitions
    ├── workspace.py             Session and workspace
    ├── cortex/                  Tier 0
    ├── arsenal/                 Tier 1
    ├── intelligence/            Tier 2
    ├── automation/              Tier 3
    ├── output/                  Tier 4
    ├── meta/                    Tier 5
    └── evasion/                 Cross-cutting evasion layer
```

---

## Contributing

Contributions are welcome. The codebase follows a few strict rules:

- **Zero external imports.** Only the Python 3.9+ standard library.
- **Thread safety.** Every engine class must use `threading.RLock`.
- **Data structures.** Use `@dataclass` with a `.to_dict()` method.
- **Naming.** Public engine classes follow the `Siren{Name}` convention.
- **Logging.** Use `logging.getLogger("siren.<tier>.<module>")`.

---

## License

Released under the [MIT License](LICENSE).

---

<div align="center">
<sub>SIREN — where mathematics meets offensive security.</sub>
</div>
