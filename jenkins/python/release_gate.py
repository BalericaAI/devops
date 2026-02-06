#!/usr/bin/env python3
import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Exit codes
PASS = 0
E_POLICY_FAIL = 10
E_CRITICAL_PRESENT = 11
E_HIGH_THRESHOLD = 12
E_MANIFEST_SIGN = 13
E_REQUIRED_OUTPUTS = 14
E_REPORT_SECTIONS = 15
E_SECRETS_IN_OUTPUTS = 16

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNSPECIFIED"]

def load_policy(policy_path: Path) -> Dict[str, Any]:
    txt = policy_path.read_text(encoding="utf-8")
    try:
        import yaml  # type: ignore
        return yaml.safe_load(txt)
    except Exception:
        return json.loads(txt)

def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))

def file_exists(out_dir: Path, rel: str) -> bool:
    return (out_dir / rel).exists()

def count_severities(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {s: 0 for s in SEV_ORDER}
    for f in findings:
        s = str(f.get("severity", "UNSPECIFIED")).upper().strip()
        if s not in counts:
            s = "UNSPECIFIED"
        counts[s] += 1
    return counts

def scan_patterns(patterns: List[Dict[str, str]], text: str) -> List[str]:
    hits = []
    for item in patterns:
        name = item.get("name", "unnamed")
        rgx = item.get("regex", "")
        try:
            if re.search(rgx, text):
                hits.append(name)
        except re.error:
            hits.append(f"{name}(invalid-regex)")
    return hits

def report_missing_sections(required: List[str], md_text: str) -> List[str]:
    low = md_text.lower()
    missing = []
    for sec in required:
        if sec.lower() not in low:
            missing.append(sec)
    return missing

def summarize(mode: str, counts: Dict[str, int], warnings: List[str], fails: List[str]) -> None:
    print(f"\n=== RELEASE GATE SUMMARY ({mode}) ===")
    print("Severity counts (as-reported):")
    for s in SEV_ORDER:
        print(f"  {s:11s} : {counts.get(s,0)}")
    if warnings:
        print("\nWarnings:")
        for w in warnings:
            print(f"  - {w}")
    if fails:
        print("\nFailures:")
        for f in fails:
            print(f"  - {f}")
    print("====================================\n")

def gate_one_mode(policy: Dict[str, Any], mode: str, outputs_base: Path) -> int:
    rg = policy.get("release_gate", {}) or {}
    if not rg.get("enabled", True):
        print(f"[{mode}] release_gate.disabled => PASS")
        return PASS

    out_dir = outputs_base / mode
    fails: List[str] = []
    warns: List[str] = []

    # 1) required files exist
    required_files = rg.get("required_files", []) or []
    missing_files = [f for f in required_files if not file_exists(out_dir, f)]
    if missing_files:
        fails.append(f"Missing required outputs: {missing_files}")
        summarize(mode, {s: 0 for s in SEV_ORDER}, warns, fails)
        return E_REQUIRED_OUTPUTS

    # 2) policy reports must be PASS (pre and post)
    pre = read_json(out_dir / "policy_report.json")
    post = read_json(out_dir / "policy_report_post.json")
    if pre.get("status") != "PASS":
        fails.append(f"policy_report.json status={pre.get('status')} hard_fail_hits={pre.get('hard_fail_hits')}")
        summarize(mode, {s: 0 for s in SEV_ORDER}, warns, fails)
        return E_POLICY_FAIL
    if post.get("status") != "PASS":
        fails.append(f"policy_report_post.json status={post.get('status')} hard_fail_hits={post.get('hard_fail_hits')}")
        summarize(mode, {s: 0 for s in SEV_ORDER}, warns, fails)
        return E_SECRETS_IN_OUTPUTS

    # 3) manifest signing required?
    signer = (out_dir / "manifest_signer.txt").read_text(encoding="utf-8").strip()
    if rg.get("require_signed_manifest", True):
        allowed = set([s.lower() for s in (rg.get("allowed_signers", ["minisign","openssl"]) or [])])
        if signer.lower() not in allowed:
            fails.append(f"Manifest signer not allowed or missing: signer='{signer}' allowed={sorted(list(allowed))}")
            summarize(mode, {s: 0 for s in SEV_ORDER}, warns, fails)
            return E_MANIFEST_SIGN

        if not (out_dir / "manifest.sig").exists():
            fails.append("manifest.sig missing")
            summarize(mode, {s: 0 for s in SEV_ORDER}, warns, fails)
            return E_MANIFEST_SIGN

    # 4) findings severity gates
    findings = read_json(out_dir / "extracted_findings.json")
    if not isinstance(findings, list):
        fails.append("extracted_findings.json is not a list")
        summarize(mode, {s: 0 for s in SEV_ORDER}, warns, fails)
        return E_REQUIRED_OUTPUTS

    counts = count_severities(findings)

    if rg.get("fail_on_critical", True) and counts.get("CRITICAL", 0) > 0:
        fails.append("CRITICAL findings present (as-reported). Release blocked.")
        summarize(mode, counts, warns, fails)
        return E_CRITICAL_PRESENT

    max_high = int(rg.get("max_high_findings", 999999))
    if counts.get("HIGH", 0) > max_high:
        fails.append(f"HIGH findings exceed threshold: {counts.get('HIGH',0)} > {max_high}")
        summarize(mode, counts, warns, fails)
        return E_HIGH_THRESHOLD

    max_med = int(rg.get("max_medium_findings", 999999))
    if counts.get("MEDIUM", 0) > max_med:
        warns.append(f"MEDIUM findings exceed recommended threshold: {counts.get('MEDIUM',0)} > {max_med} (warning only)")

    # 5) report must contain required sections
    md = (out_dir / "consolidated_security_report.md").read_text(encoding="utf-8", errors="ignore")
    required_sections = rg.get("required_report_sections", []) or []
    missing_sections = report_missing_sections(required_sections, md)
    if missing_sections:
        fails.append(f"Report missing sections: {missing_sections}")
        summarize(mode, counts, warns, fails)
        return E_REPORT_SECTIONS

    # PASS
    summarize(mode, counts, warns, fails)
    return PASS

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["tokyo","ny","both"], default="both")
    ap.add_argument("--policy", default="policy.yml")
    ap.add_argument("--outputs-dir", default="outputs")
    args = ap.parse_args()

    policy = load_policy(Path(args.policy))
    outputs_base = Path(args.outputs_dir)

    modes = ["tokyo","ny"] if args.mode == "both" else [args.mode]

    # Fail fast: first non-zero code stops Jenkins
    for m in modes:
        code = gate_one_mode(policy, m, outputs_base)
        if code != PASS:
            print(f"[{m}] RELEASE GATE => FAIL (exit {code})")
            raise SystemExit(code)

    print("RELEASE GATE => PASS")
    raise SystemExit(PASS)

if __name__ == "__main__":
    main()
