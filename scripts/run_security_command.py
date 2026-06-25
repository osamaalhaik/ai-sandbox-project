import argparse
import json
import shlex
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DETECTION_PATH = ROOT / "data/processed/detection_results.jsonl"
SYSCALL_PATH = ROOT / "data/raw/syscall_events.jsonl"

SENSITIVE_MARKERS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/root/",
    ".ssh",
]

def read_jsonl(path):
    if not path.exists():
        return []

    records = []

    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            records.append(json.loads(line))

    return records

def last_detection_record():
    records = read_jsonl(DETECTION_PATH)

    if not records:
        return None

    return records[-1]

def decision_for(record):
    rules = set(rule_ids(record))
    risk_level = record.get("risk_level")

    if "POLICY_BLOCK_CRITICAL" in rules:
        return "block_critical"

    if "POLICY_CONFIRMATION_REQUIRED" in rules:
        return "require_confirmation"

    if "CONTEXT_AWARE_ALLOW_WITH_MONITORING" in rules:
        return "allow_with_monitoring"

    if risk_level == "low":
        return "allow"

    if risk_level == "suspicious":
        return "review"

    return "block_or_investigate"

def rule_ids(record):
    rules = record.get("triggered_rules", [])
    result = []

    for rule in rules:
        if isinstance(rule, dict):
            result.append(rule.get("rule_id", "UNKNOWN_RULE"))
        else:
            result.append(str(rule))

    return result

def sensitive_evidence_for_run(run_id):
    evidence = []

    for record in read_jsonl(SYSCALL_PATH):
        if record.get("run_id") != run_id:
            continue

        raw_line = record.get("raw_line", "")
        path = str(record.get("path") or "")

        if any(marker in raw_line or marker in path for marker in SENSITIVE_MARKERS):
            evidence.append(raw_line)

    return evidence

def print_record(record, command_text):
    rules = rule_ids(record)
    evidence = sensitive_evidence_for_run(record.get("run_id"))

    print("SECURITY_COMMAND_RESULT")
    print("Command:", command_text)
    print("Run ID:", record.get("run_id"))
    print("Executable:", record.get("executable"))
    print("Status:", record.get("status"))
    print("Risk Score:", record.get("risk_score"))
    print("Risk Level:", record.get("risk_level"))
    print("Triggered Rules:", rules)
    print("Decision:", decision_for(record))
    print("Explanation:", record.get("security_explanation"))

    if evidence:
        print("Evidence:")
        for item in evidence[-5:]:
            print(item)

def print_summary():
    records = read_jsonl(DETECTION_PATH)

    if not records:
        print("NO_DETECTION_RESULTS_FOUND")
        return

    print("SECURITY_RESULTS_SUMMARY")
    print("-" * 70)

    for record in records:
        rules = ",".join(rule_ids(record)) or "none"
        print(
            record.get("executable"),
            "|",
            record.get("status"),
            "|",
            record.get("risk_score"),
            "|",
            record.get("risk_level"),
            "|",
            decision_for(record),
            "|",
            rules,
        )

def run_command(command):
    pipeline_command = [
        sys.executable,
        str(ROOT / "scripts/run_trace_aware_pipeline.py"),
        "--",
        *command,
    ]

    completed = subprocess.run(
        pipeline_command,
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    if completed.returncode != 0:
        print("PIPELINE_FAILED")
        print("Return Code:", completed.returncode)

        if completed.stdout:
            print("STDOUT:")
            print(completed.stdout)

        if completed.stderr:
            print("STDERR:")
            print(completed.stderr)

        sys.exit(completed.returncode)

    record = last_detection_record()

    if record is None:
        print("NO_DETECTION_RESULT_CREATED")
        sys.exit(1)

    print_record(record, shlex.join(command))

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--summary", action="store_true")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    return parser.parse_args()

def main():
    args = parse_args()

    if args.summary:
        print_summary()
        return

    command = args.command

    if command and command[0] == "--":
        command = command[1:]

    if not command:
        print("COMMAND_REQUIRED")
        print("usage: python scripts/run_security_command.py -- <command>")
        sys.exit(2)

    run_command(command)

if __name__ == "__main__":
    main()
