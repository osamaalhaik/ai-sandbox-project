from pathlib import Path
from datetime import datetime, timezone
import argparse
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
PENDING_PATH = ROOT / "data/processed/pending_approvals.jsonl"
DECISIONS_PATH = ROOT / "data/processed/approval_decisions.jsonl"

def utc_now():
    return datetime.now(timezone.utc).isoformat()

def read_jsonl(path):
    if not path.exists():
        return []

    records = []

    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            records.append(json.loads(line))

    return records

def append_jsonl(path, record):
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("a", encoding="utf-8") as file:
        file.write(json.dumps(record, ensure_ascii=False) + "\n")

def approval_status_by_id():
    statuses = {}

    for record in read_jsonl(DECISIONS_PATH):
        statuses[record.get("gateway_decision_id")] = record.get("approval_status")

    return statuses

def pending_records():
    statuses = approval_status_by_id()
    records = []

    for record in read_jsonl(PENDING_PATH):
        decision_id = record.get("gateway_decision_id")

        if statuses.get(decision_id) is None:
            records.append(record)

    return records

def find_pending(decision_id):
    for record in pending_records():
        if record.get("gateway_decision_id") == decision_id:
            return record

    return None

def print_record(record):
    print("PENDING_APPROVAL")
    print("ID:", record.get("gateway_decision_id"))
    print("Created At:", record.get("created_at"))
    print("Command:", record.get("command_text"))
    print("Executable:", record.get("executable"))
    print("Risk Score:", record.get("risk_score"))
    print("Risk Level:", record.get("risk_level"))
    print("Decision:", record.get("security_decision"))
    print("Execution Strategy:", record.get("execution_strategy"))
    print("Workspace:", record.get("workspace_root"))
    print("Targets:")

    for path in record.get("resolved_target_paths", []):
        print("-", path)

    print("Reasons:")

    for reason in record.get("reasons", []):
        print("-", reason)

def list_pending():
    records = pending_records()

    if not records:
        print("NO_PENDING_APPROVALS")
        return

    print("PENDING_APPROVALS_COUNT:", len(records))
    print("-" * 70)

    for record in records:
        print_record(record)
        print("-" * 70)

def write_approval_decision(decision_id, status, admin, reason):
    record = find_pending(decision_id)

    if record is None:
        print("PENDING_APPROVAL_NOT_FOUND")
        return 1

    approval_record = {
        "approval_decision_id": f"{decision_id}:{status}",
        "gateway_decision_id": decision_id,
        "created_at": utc_now(),
        "approval_status": status,
        "admin": admin,
        "reason": reason,
        "command": record.get("command"),
        "command_text": record.get("command_text"),
        "risk_score": record.get("risk_score"),
        "risk_level": record.get("risk_level"),
        "security_decision": record.get("security_decision"),
        "execution_strategy": record.get("execution_strategy"),
        "approved_for_execution": status == "approved",
        "execution_started": False,
    }

    append_jsonl(DECISIONS_PATH, approval_record)

    print("APPROVAL_DECISION_RECORDED")
    print("Gateway Decision ID:", decision_id)
    print("Approval Status:", status)
    print("Execution Started:", False)

    return 0

def parse_args():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="action")

    subparsers.add_parser("list")

    approve_parser = subparsers.add_parser("approve")
    approve_parser.add_argument("gateway_decision_id")
    approve_parser.add_argument("--admin", default="admin")
    approve_parser.add_argument("--reason", default="Approved after human review.")

    reject_parser = subparsers.add_parser("reject")
    reject_parser.add_argument("gateway_decision_id")
    reject_parser.add_argument("--admin", default="admin")
    reject_parser.add_argument("--reason", default="Rejected after human review.")

    return parser.parse_args()

def main():
    args = parse_args()

    if args.action == "list":
        list_pending()
        return 0

    if args.action == "approve":
        return write_approval_decision(
            args.gateway_decision_id,
            "approved",
            args.admin,
            args.reason,
        )

    if args.action == "reject":
        return write_approval_decision(
            args.gateway_decision_id,
            "rejected",
            args.admin,
            args.reason,
        )

    print("ACTION_REQUIRED")
    print("usage: python scripts/procsentinel_approvals.py list")
    print("usage: python scripts/procsentinel_approvals.py approve <gateway_decision_id>")
    print("usage: python scripts/procsentinel_approvals.py reject <gateway_decision_id>")
    return 2

if __name__ == "__main__":
    raise SystemExit(main())
