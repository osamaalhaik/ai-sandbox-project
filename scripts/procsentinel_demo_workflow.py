from pathlib import Path
import json
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]

GATEWAY_DECISIONS = ROOT / "data/processed/gateway_decisions.jsonl"
PENDING_APPROVALS = ROOT / "data/processed/pending_approvals.jsonl"
APPROVAL_DECISIONS = ROOT / "data/processed/approval_decisions.jsonl"

def run_step(title, command):
    print()
    print("=" * 80)
    print(title)
    print("=" * 80)
    completed = subprocess.run(command, cwd=str(ROOT), text=True)
    if completed.returncode != 0:
        raise SystemExit(completed.returncode)

def read_jsonl(path):
    if not path.exists():
        return []

    records = []

    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            records.append(json.loads(line))

    return records

def reset_audit_files():
    for path in [GATEWAY_DECISIONS, PENDING_APPROVALS, APPROVAL_DECISIONS]:
        if path.exists():
            path.unlink()

def latest_pending_id():
    records = read_jsonl(PENDING_APPROVALS)

    if not records:
        return None

    return records[-1].get("gateway_decision_id")

def final_lifecycle_status(record, approvals_by_gateway_id):
    decision_id = record.get("gateway_decision_id")

    if decision_id in approvals_by_gateway_id:
        return approvals_by_gateway_id[decision_id].get("approval_status")

    return record.get("decision_status")

def print_audit_summary():
    gateway_records = read_jsonl(GATEWAY_DECISIONS)
    approval_records = read_jsonl(APPROVAL_DECISIONS)
    approvals_by_gateway_id = {
        record.get("gateway_decision_id"): record
        for record in approval_records
    }

    print()
    print("=" * 80)
    print("FINAL_AUDIT_SUMMARY")
    print("=" * 80)
    print("Gateway Decisions:", len(gateway_records))
    print("Approval Decisions:", len(approval_records))
    print()

    for record in gateway_records:
        print(
            record.get("command_text"),
            "|",
            record.get("security_decision"),
            "|",
            record.get("risk_score"),
            "|",
            record.get("risk_level"),
            "|",
            final_lifecycle_status(record, approvals_by_gateway_id),
        )

    if approval_records:
        print()
        print("APPROVAL_AUDIT")
        for record in approval_records:
            print(
                record.get("gateway_decision_id"),
                "|",
                record.get("approval_status"),
                "|",
                record.get("admin"),
                "|",
                record.get("execution_started"),
            )

def main():
    reset_audit_files()

    run_step(
        "RESET_RUNTIME_DEMO_DATA",
        [sys.executable, "scripts/reset_demo_data.py"],
    )

    workspace_cache = ROOT / "data/workspaces/default/cache"
    workspace_cache.mkdir(parents=True, exist_ok=True)
    (workspace_cache / "test.txt").write_text("demo", encoding="utf-8")

    run_step(
        "CASE_1_WORKSPACE_DESTRUCTIVE_COMMAND_ALLOWED_WITH_MONITORING",
        [sys.executable, "scripts/procsentinel_gateway.py", "--", "rm", "-rf", "data/workspaces/default/cache"],
    )

    run_step(
        "CASE_2_OUTSIDE_WORKSPACE_DESTRUCTIVE_COMMAND_REQUIRES_CONFIRMATION",
        [sys.executable, "scripts/procsentinel_gateway.py", "--", "rm", "-rf", "./cache"],
    )

    decision_id = latest_pending_id()

    if decision_id is None:
        raise SystemExit("NO_PENDING_APPROVAL_CREATED")

    run_step(
        "CASE_3_ADMIN_REJECTS_PENDING_COMMAND",
        [
            sys.executable,
            "scripts/procsentinel_approvals.py",
            "reject",
            decision_id,
            "--admin",
            "demo_admin",
            "--reason",
            "Outside workspace destructive deletion is rejected in the demo workflow.",
        ],
    )

    run_step(
        "CASE_4_CRITICAL_SYSTEM_COMMAND_BLOCKED_BEFORE_EXECUTION",
        [sys.executable, "scripts/procsentinel_gateway.py", "--", "rm", "-rf", "/etc"],
    )

    run_step(
        "DETECTION_RESULTS_SUMMARY",
        [sys.executable, "scripts/run_security_command.py", "--summary"],
    )

    print_audit_summary()

if __name__ == "__main__":
    main()
