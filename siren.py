#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SIREN — Shannon Intelligence Recon & Exploitation Nexus

Usage:
    python siren.py <target>
    python siren.py example.com
    python siren.py https://api.example.com

Autonomous offensive security intelligence engine.
"""

import os
import sys
import time
import json
import asyncio
from pathlib import Path
from datetime import datetime

# ── Force UTF-8 on Windows console ───────────────────────────────────────
if sys.platform == "win32":
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

# ── Resolve project paths ────────────────────────────────────────────────
SCRIPT_DIR = Path(__file__).parent.resolve()
sys.path.insert(0, str(SCRIPT_DIR))

# ── ANSI Colors ──────────────────────────────────────────────────────────

class C:
    """Minimal ANSI color palette."""
    RST = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    WHITE = "\033[97m"
    BLOOD = "\033[38;5;196m"
    OCEAN = "\033[38;5;33m"
    TEAL = "\033[38;5;30m"

    @staticmethod
    def init():
        if sys.platform == "win32":
            os.system("")  # enable ANSI on Windows


# ── Banner ───────────────────────────────────────────────────────────────

BANNER = f"""
{C.OCEAN}{C.BOLD}
    ███████╗██╗██████╗ ███████╗███╗   ██╗
    ██╔════╝██║██╔══██╗██╔════╝████╗  ██║
    ███████╗██║██████╔╝█████╗  ██╔██╗ ██║
    ╚════██║██║██╔══██╗██╔══╝  ██║╚██╗██║
    ███████║██║██║  ██║███████╗██║ ╚████║
    ╚══════╝╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝{C.RST}
{C.DIM}    Shannon Intelligence Recon & Exploitation Nexus{C.RST}
"""

# ── Menu Options (Compact) ───────────────────────────────────────────────

MODULES = [
    # (key, label, description, category)
    ("A", "ALL",                  "Run full pipeline (Recon > Scan > Attack > Intel)",   "PIPELINE"),
    ("1", "Full Pentest",         "Complete pipeline (13 agents, 5 phases)",             "PIPELINE"),
    ("2", "Recon + OSINT",        "Passive/active recon + OSINT correlation",            "RECON"),
    ("3", "Vuln Scan + DAST",     "Web vuln scanner + dynamic analysis",                "SCAN"),
    ("4", "API + Crypto Audit",   "OWASP API Top 10 + JWT/TLS/cipher audit",            "SCAN"),
    ("5", "Attack Suite",         "Auth attack + fuzzer + exploit chains",               "ATTACK"),
    ("6", "Intel + Defense",      "Cognitive reasoning + narrative + defense rules",     "INTEL"),
    ("7", "Evasion Test",         "WAF bypass + IDS evasion + payload obfuscation",      "EVASION"),
    ("0", "Exit",                 "",                                                    ""),
]

CATEGORY_COLORS = {
    "PIPELINE": C.BLOOD,
    "RECON":    C.CYAN,
    "SCAN":     C.YELLOW,
    "ATTACK":   C.RED,
    "INTEL":    C.MAGENTA,
    "EVASION":  C.TEAL,
}

# ── Helpers ──────────────────────────────────────────────────────────────

def clear():
    os.system("cls" if sys.platform == "win32" else "clear")


def line(char="─", width=60):
    print(f"  {C.DIM}{char * width}{C.RST}")


def header(target: str):
    print(BANNER)
    line("═")
    print(f"  {C.BOLD}{C.TEAL}TARGET:{C.RST} {C.WHITE}{target}{C.RST}")
    line("═")
    print()


def show_menu():
    current_cat = ""
    for key, label, desc, cat in MODULES:
        if key == "0":
            print()
            print(f"  {C.DIM}[0] Exit{C.RST}")
            continue
        if cat != current_cat:
            current_cat = cat
            color = CATEGORY_COLORS.get(cat, C.DIM)
            print(f"\n  {color}{C.BOLD}{cat}{C.RST}")
        pad = " " if len(key) == 1 else ""
        print(f"  {C.CYAN}[{key}]{C.RST}{pad} {label:<22} {C.DIM}{desc}{C.RST}")
    print()


def prompt() -> str:
    try:
        return input(f"  {C.OCEAN}siren>{C.RST} ").strip()
    except (EOFError, KeyboardInterrupt):
        return "0"


def status(msg: str, icon: str = "▸", color: str = C.CYAN):
    print(f"  {color}{icon}{C.RST} {msg}")


def success(msg: str):
    status(msg, "✓", C.GREEN)


def error(msg: str):
    status(msg, "✗", C.RED)


def warn(msg: str):
    status(msg, "⚠", C.YELLOW)


def wait_enter():
    try:
        input(f"\n  {C.DIM}[Enter to return to menu]{C.RST}")
    except (EOFError, KeyboardInterrupt):
        pass


def ensure_output_dir(target: str) -> Path:
    safe_name = target.replace("https://", "").replace("http://", "").replace("/", "_").rstrip("_")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = Path("./siren-output") / f"{safe_name}_{ts}"
    out.mkdir(parents=True, exist_ok=True)
    return out


def save_result(output_dir: Path, name: str, data) -> Path:
    path = output_dir / f"{name}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)
    return path


# ── Module Runners ───────────────────────────────────────────────────────

def run_full_pentest(target: str, output_dir: Path):
    """1 - Full Pentest Pipeline."""
    status("Starting full SIREN pipeline...")
    print()

    from core.engine import AbyssalEngine, EngineConfig

    workspace = datetime.now().strftime("siren_%Y%m%d_%H%M%S")
    config = EngineConfig(target_url=target, output_dir=str(output_dir), workspace=workspace)
    engine = AbyssalEngine(config)

    status("Preflight checks...")
    preflight = asyncio.run(engine.preflight())
    if not preflight["valid"]:
        error("Preflight failed:")
        for check in preflight["checks"]:
            if check.get("status") == "fail":
                error(f"  {check['name']}: {check.get('error', 'failed')}")
        return

    success("Preflight OK")
    status("Executing 5 phases (13 agents)...")

    try:
        result = engine.run_sync()
        from core.reporter import AbyssalReporter
        reporter = AbyssalReporter(
            pipeline_result=result, output_dir=str(output_dir),
            target_url=target, workspace=workspace,
        )
        paths = reporter.save_report()
        print()
        success(f"State: {result.state.value}")
        success(f"Phases: {result.phases_completed}")
        success(f"Agents OK: {result.agents_succeeded} | Failed: {result.agents_failed}")
        success(f"Duration: {result.total_duration_ms / 1000:.2f}s")
        print()
        status(f"Report: {paths['report']}")
        status(f"Findings: {paths['findings']}")
    except Exception as e:
        error(f"Pipeline failed: {e}")


def run_recon_osint(target: str, output_dir: Path):
    """2 - Recon + OSINT."""
    # Recon
    status(f"Reconnaissance on {target}...")
    from core.recon import SirenRecon, ReconConfig
    config = ReconConfig(target=target)
    recon = SirenRecon(config)
    result = asyncio.run(recon.run())
    path = save_result(output_dir, "recon", result.to_dict())
    success(f"Subdomains: {len(result.subdomains)}")
    success(f"Ports: {len(result.ports)}")
    success(f"Technologies: {len(result.technologies)}")
    status(f"Saved: {path}")

    # OSINT
    print()
    status(f"OSINT correlation on {target}...")
    import urllib.parse
    from core.intelligence import SirenOSINTCorrelator
    engine = SirenOSINTCorrelator()
    domain = urllib.parse.urlparse(target).hostname or target
    osint_result = engine.ingest_domain(domain=domain)
    path = save_result(output_dir, "osint", osint_result if isinstance(osint_result, dict) else {"result": str(osint_result)})
    success(f"OSINT complete")
    status(f"Saved: {path}")


def run_vuln_scan_dast(target: str, output_dir: Path):
    """3 - Vuln Scan + DAST."""
    # Vuln Scanner
    status(f"Scanning vulnerabilities on {target}...")
    from core.scanner import SirenScanner, ScanConfig
    config = ScanConfig(target_url=target)
    scanner = SirenScanner(config)
    result = asyncio.run(scanner.run())
    path = save_result(output_dir, "vuln_scan", result.to_dict())
    success(f"Findings: {len(result.findings)}")
    for f in result.findings[:10]:
        sev_color = C.RED if f.severity.name in ("CRITICAL", "HIGH") else C.YELLOW
        print(f"    {sev_color}{f.severity.name:<10}{C.RST} {f.title}")
    if len(result.findings) > 10:
        print(f"    {C.DIM}... +{len(result.findings) - 10} more{C.RST}")
    status(f"Saved: {path}")

    # DAST
    print()
    status(f"DAST scan on {target}...")
    from core.arsenal import SirenDASTEngine
    engine = SirenDASTEngine()
    dast_result = engine.scan_target(target_url=target)
    path = save_result(output_dir, "dast", dast_result.to_dict() if hasattr(dast_result, 'to_dict') else {"result": str(dast_result)})
    success(f"DAST complete")
    status(f"Saved: {path}")


def run_api_crypto(target: str, output_dir: Path):
    """4 - API Security + Crypto Audit."""
    # API Security
    status(f"API audit on {target}...")
    from core.api_security import SirenAPISecurityEngine
    engine = SirenAPISecurityEngine()
    result = asyncio.run(engine.full_api_audit(target=target))
    path = save_result(output_dir, "api_audit", result if isinstance(result, dict) else {"result": str(result)})
    if isinstance(result, dict):
        success(f"Checks: {len(result.get('findings', result.get('checks', [])))}")
    status(f"Saved: {path}")

    # Crypto
    print()
    status(f"Cryptographic audit on {target}...")
    from core.crypto import SirenCryptoEngine
    crypto_engine = SirenCryptoEngine()
    crypto_result = asyncio.run(crypto_engine.full_crypto_audit(target=target))
    path = save_result(output_dir, "crypto_audit", crypto_result if isinstance(crypto_result, dict) else {"result": str(crypto_result)})
    success(f"Crypto audit complete")
    status(f"Saved: {path}")


def run_attack_suite(target: str, output_dir: Path):
    """5 - Auth Attack + Fuzzer + Exploit Chains."""
    # Auth
    status("Full auth audit...")
    from core.auth_engine import SirenAuthEngine
    auth = SirenAuthEngine()
    auth_result = asyncio.run(auth.full_auth_audit(target=target))
    path = save_result(output_dir, "auth_audit", auth_result if isinstance(auth_result, dict) else {"result": str(auth_result)})
    success(f"Auth audit complete")
    status(f"Saved: {path}")

    # Fuzzer
    print()
    status(f"Fuzzing {target}...")
    from core.fuzzer import SirenFuzzer, FuzzerConfig
    import urllib.request
    fuzz_config = FuzzerConfig(target=target)
    fuzzer = SirenFuzzer(fuzz_config)

    async def send_request(payload: str):
        url = f"{target}?fuzz={payload}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "SIREN/2.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                return resp.status, body
        except urllib.error.HTTPError as e:
            return e.code, str(e)
        except Exception as e:
            return 0, str(e)

    fuzz_result = asyncio.run(fuzzer.run(send_request=send_request))
    path = save_result(output_dir, "fuzzer", fuzz_result.to_dict() if hasattr(fuzz_result, 'to_dict') else {"result": str(fuzz_result)})
    success(f"Fuzzing complete")
    status(f"Saved: {path}")

    # Exploit Chains
    print()
    status("Synthesizing exploit chains...")
    from core.cortex import SirenExploitSynthesis
    from core.cortex.exploit_synthesis import ChainGoal
    synth = SirenExploitSynthesis()
    goal = ChainGoal.RCE if hasattr(ChainGoal, 'RCE') else list(ChainGoal)[0]
    chains = synth.synthesize(goal=goal)
    path = save_result(output_dir, "exploit_chains", {
        "goal": str(goal), "chains": [c.to_dict() if hasattr(c, 'to_dict') else str(c) for c in chains],
        "count": len(chains),
    })
    success(f"Chains synthesized: {len(chains)}")
    status(f"Saved: {path}")


def run_intel_defense(target: str, output_dir: Path):
    """6 - Cognitive Reasoning + Narrative + Defense Rules."""
    # Cognitive
    status("Starting multi-modal cognitive reasoning...")
    from core.cortex import SirenCognitiveReasoner
    from core.cortex.cognitive_reasoner import Evidence, EvidenceType
    reasoner = SirenCognitiveReasoner()
    evidence = [
        Evidence(evidence_type=EvidenceType.SCAN_RESULT, value=f"target_{target}"),
        Evidence(evidence_type=EvidenceType.PORT_STATE, value="port_443_open"),
        Evidence(evidence_type=EvidenceType.HEADER_ANALYSIS, value="web_application"),
    ]
    reasoner.add_evidence(evidence)
    report = reasoner.full_reasoning(target=target, goals=["data_exfiltration", "remote_code_execution_confirmed"])
    path = save_result(output_dir, "cognitive_report", report.to_dict())
    success(f"Modes used: {', '.join(report.modes_used)}")
    success(f"Confidence: {report.overall_confidence:.2%}")
    status(f"Saved: {path}")

    # Narrative
    print()
    status("Generating attack narrative...")
    from core.intelligence import SirenAttackNarrative
    narr = SirenAttackNarrative()
    narr_report = narr.generate_report(target=target)
    path = save_result(output_dir, "narrative", {"report": narr_report})
    success(f"Narrative generated")
    status(f"Saved: {path}")

    # Defensive Mirror
    print()
    status("Generating defensive rules...")
    from core.intelligence import SirenDefensiveMirror
    mirror = SirenDefensiveMirror()
    cwes = ["CWE-79", "CWE-89", "CWE-22", "CWE-287", "CWE-352"]
    all_rules = []
    for cwe in cwes:
        rules = mirror.generate_all(cwe_id=cwe, vuln_id=f"siren-{cwe}")
        all_rules.extend([r.to_dict() if hasattr(r, 'to_dict') else str(r) for r in rules])
        success(f"{cwe}: {len(rules)} rules generated")
    path = save_result(output_dir, "defensive_rules", {"rules": all_rules, "cwe_count": len(cwes)})
    status(f"Saved: {path}")


def run_evasion(target: str, output_dir: Path):
    """7 - Evasion Testing."""
    from core.evasion import SirenWAFBypass, SirenIDSEvasion, SirenPayloadObfuscator
    status("WAF Bypass + IDS Evasion + Payload Obfuscation...")

    waf = SirenWAFBypass()
    test_payloads = ["<script>alert(1)</script>", "' OR 1=1--", "{{7*7}}"]
    for p in test_payloads:
        result = waf.auto_bypass(payload=p)
        if hasattr(result, 'success') and result.success:
            success(f"WAF bypass: {p[:30]}...")

    ids = SirenIDSEvasion()
    ids_result = ids.full_evasion_test(target=target)
    save_result(output_dir, "ids_evasion", ids_result.to_dict() if hasattr(ids_result, 'to_dict') else {"result": str(ids_result)})

    obfuscator = SirenPayloadObfuscator()
    obf_result = obfuscator.full_obfuscation(payloads=test_payloads)
    save_result(output_dir, "payload_obfuscation", obf_result.to_dict() if hasattr(obf_result, 'to_dict') else {"result": str(obf_result)})

    success("Evasion testing complete")


def run_all(target: str, output_dir: Path):
    """A - Run ALL modules sequentially."""
    ALL_SEQUENCE = [
        ("2", "Recon + OSINT",      run_recon_osint),
        ("3", "Vuln Scan + DAST",   run_vuln_scan_dast),
        ("4", "API + Crypto",       run_api_crypto),
        ("5", "Attack Suite",       run_attack_suite),
        ("6", "Intel + Defense",    run_intel_defense),
        ("7", "Evasion Test",       run_evasion),
    ]

    print(f"""
  {C.BLOOD}{C.BOLD}SIREN FULL ASSAULT{C.RST}
  {C.DIM}Executing {len(ALL_SEQUENCE)} modules sequentially...{C.RST}
""")

    results = {}
    for i, (key, name, runner) in enumerate(ALL_SEQUENCE, 1):
        print(f"  {C.OCEAN}[{i}/{len(ALL_SEQUENCE)}]{C.RST} {C.BOLD}{name}{C.RST}")
        line()
        try:
            runner(target, output_dir)
            results[name] = "OK"
            success(f"{name} complete")
        except ImportError as e:
            results[name] = f"SKIP ({e})"
            warn(f"{name} skipped: {e}")
        except Exception as e:
            results[name] = f"FAIL ({e})"
            error(f"{name} failed: {e}")
        print()

    print()
    line("═")
    print(f"  {C.BOLD}SIREN SUMMARY{C.RST}")
    line("═")
    for name, result in results.items():
        icon = C.GREEN + "OK" if result == "OK" else C.RED + "FAIL" if "FAIL" in result else C.YELLOW + "SKIP"
        print(f"  {icon}{C.RST}  {name}")
    print()
    status(f"Output: {output_dir}")


# ── Dispatch Table ───────────────────────────────────────────────────────

DISPATCH = {
    "a": run_all, "A": run_all,
    "1": run_full_pentest,
    "2": run_recon_osint,
    "3": run_vuln_scan_dast,
    "4": run_api_crypto,
    "5": run_attack_suite,
    "6": run_intel_defense,
    "7": run_evasion,
}


# ── Main Loop ────────────────────────────────────────────────────────────

def main():
    C.init()

    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(BANNER)
        print(f"  {C.BOLD}Usage:{C.RST}  python siren.py <target>")
        print(f"  {C.BOLD}Ex:{C.RST}     python siren.py example.com")
        print(f"          python siren.py https://api.example.com")
        print()
        return 0

    target = sys.argv[1]
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    output_dir = ensure_output_dir(target)

    clear()
    header(target)
    show_menu()

    while True:
        choice = prompt()

        if choice == "0" or choice.lower() in ("exit", "quit", "q"):
            print(f"\n  {C.DIM}SIREN offline.{C.RST}\n")
            break

        if choice.lower() == "menu":
            clear()
            header(target)
            show_menu()
            continue

        if choice.lower() == "clear":
            clear()
            header(target)
            continue

        runner = DISPATCH.get(choice)
        if not runner:
            error(f"Invalid option: {choice}")
            continue

        print()
        line()
        try:
            runner(target, output_dir)
        except ImportError as e:
            error(f"Module not found: {e}")
        except Exception as e:
            error(f"Error: {e}")
        line()
        wait_enter()
        clear()
        header(target)
        show_menu()

    return 0


if __name__ == "__main__":
    sys.exit(main())
