from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
import json
import shlex
import uuid

def utc_now():
    return datetime.now(timezone.utc).isoformat()

def append_jsonl(path: Path, record: dict):
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("a", encoding="utf-8") as file:
        file.write(json.dumps(record, ensure_ascii=False) + "\n")

def decision_status(decision):
    if not decision.can_execute:
        return "denied"

    if decision.requires_confirmation:
        return "pending_confirmation"

    return "approved_for_execution"

def build_gateway_record(command, context, decision):
    return {
        "gateway_decision_id": str(uuid.uuid4()),
        "created_at": utc_now(),
        "command": command,
        "command_text": shlex.join(command),
        "executable": context.executable,
        "user_role": context.user_role,
        "policy_name": context.policy_name,
        "working_directory": str(context.working_directory),
        "workspace_root": str(context.workspace_root),
        "resolved_target_paths": [str(path) for path in context.resolved_target_paths],
        "is_destructive": context.is_destructive,
        "is_recursive": context.is_recursive,
        "is_force": context.is_force,
        "uses_shell": context.uses_shell,
        "has_workspace_target": context.has_workspace_target,
        "has_outside_workspace_target": context.has_outside_workspace_target,
        "has_sensitive_target": context.has_sensitive_target,
        "has_system_target": context.has_system_target,
        "security_decision": decision.decision,
        "risk_score": decision.risk_score,
        "risk_level": decision.risk_level,
        "execution_strategy": decision.execution_strategy,
        "requires_confirmation": decision.requires_confirmation,
        "can_execute": decision.can_execute,
        "decision_status": decision_status(decision),
        "risk_factors": [
            {
                "name": factor.name,
                "score": factor.score,
                "reason": factor.reason,
            }
            for factor in decision.risk_factors
        ],
        "reasons": list(decision.reasons),
    }

def persist_gateway_record(record, root: Path):
    decisions_path = root / "data/processed/gateway_decisions.jsonl"
    approvals_path = root / "data/processed/pending_approvals.jsonl"

    append_jsonl(decisions_path, record)

    if record.get("decision_status") == "pending_confirmation":
        append_jsonl(approvals_path, record)
