import json
import shlex
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.web_platform.database import Base, SessionLocal, engine
from app.web_platform.models import ApprovalDecisionRecord, AuditEventRecord, GatewayDecisionRecord

def parse_datetime(value):
    if not value:
        return None

    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None

def read_jsonl(path):
    if not path.exists():
        return []

    records = []

    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            records.append(json.loads(line))

    return records

def to_json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True)

def command_text(value):
    if isinstance(value, list):
        return shlex.join([str(item) for item in value])

    return str(value or "")

def import_gateway_decisions(session):
    path = ROOT / "data/processed/gateway_decisions.jsonl"
    records = read_jsonl(path)
    imported = 0

    for record in records:
        decision_id = record.get("gateway_decision_id")

        if not decision_id:
            continue

        row = session.get(GatewayDecisionRecord, decision_id)

        if row is None:
            row = GatewayDecisionRecord(gateway_decision_id=decision_id)

        row.created_at = parse_datetime(record.get("created_at"))
        row.command_text = record.get("command_text") or command_text(record.get("command"))
        row.executable = record.get("executable")
        row.user_role = record.get("user_role")
        row.policy_name = record.get("policy_name")
        row.working_directory = record.get("working_directory")
        row.workspace_root = record.get("workspace_root")
        row.resolved_target_paths_json = to_json(record.get("resolved_target_paths") or [])
        row.is_destructive = record.get("is_destructive")
        row.is_recursive = record.get("is_recursive")
        row.is_force = record.get("is_force")
        row.uses_shell = record.get("uses_shell")
        row.has_workspace_target = record.get("has_workspace_target")
        row.has_outside_workspace_target = record.get("has_outside_workspace_target")
        row.has_sensitive_target = record.get("has_sensitive_target")
        row.has_system_target = record.get("has_system_target")
        row.security_decision = record.get("security_decision") or "unknown"
        row.risk_score = int(record.get("risk_score") or 0)
        row.risk_level = record.get("risk_level") or "low"
        row.execution_strategy = record.get("execution_strategy")
        row.requires_confirmation = record.get("requires_confirmation")
        row.can_execute = record.get("can_execute")
        row.decision_status = record.get("decision_status")
        row.final_lifecycle_status = record.get("final_lifecycle_status") or record.get("decision_status")
        row.risk_factors_json = to_json(record.get("risk_factors") or [])
        row.reasons_json = to_json(record.get("reasons") or [])
        row.approval_admin = record.get("approval_admin")
        row.approval_reason = record.get("approval_reason")

        session.add(row)
        imported += 1

    return imported

def approval_action(record):
    value = (
        record.get("action")
        or record.get("decision")
        or record.get("approval_action")
        or record.get("approval_status")
        or record.get("status")
        or record.get("final_lifecycle_status")
    )

    if value:
        return str(value)

    approved = record.get("approved")

    if approved is True:
        return "approved"

    if approved is False:
        return "rejected"

    approved_for_execution = record.get("approved_for_execution")

    if approved_for_execution is True:
        return "approved"

    if approved_for_execution is False:
        return "rejected"

    rejected = record.get("rejected")

    if rejected is True:
        return "rejected"

    return "unknown"

def import_approval_decisions(session):
    path = ROOT / "data/processed/approval_decisions.jsonl"
    records = read_jsonl(path)

    session.query(ApprovalDecisionRecord).delete()

    imported = 0

    for record in records:
        action = approval_action(record)

        row = ApprovalDecisionRecord(
            gateway_decision_id=record.get("gateway_decision_id") or record.get("decision_id"),
            created_at=parse_datetime(record.get("created_at")),
            admin=record.get("admin") or record.get("approval_admin"),
            action=action,
            reason=record.get("reason") or record.get("approval_reason"),
            command_text=record.get("command_text") or command_text(record.get("command")),
            payload_json=to_json(record),
        )

        session.add(row)
        imported += 1

    return imported

def create_audit_events(session):
    session.flush()

    session.query(AuditEventRecord).filter(
        AuditEventRecord.event_type.in_(["gateway_decision_imported", "approval_decision_imported"])
    ).delete()

    session.flush()

    gateway_rows = session.query(GatewayDecisionRecord).all()
    approval_rows = session.query(ApprovalDecisionRecord).all()

    created = 0

    for row in gateway_rows:
        session.add(
            AuditEventRecord(
                created_at=row.created_at or datetime.now(timezone.utc),
                event_type="gateway_decision_imported",
                entity_type="gateway_decision",
                entity_id=row.gateway_decision_id,
                message=f"Gateway decision imported with risk level {row.risk_level}.",
                payload_json=to_json(
                    {
                        "security_decision": row.security_decision,
                        "risk_score": row.risk_score,
                        "risk_level": row.risk_level,
                        "decision_status": row.decision_status,
                        "final_lifecycle_status": row.final_lifecycle_status,
                    }
                ),
            )
        )
        created += 1

    for row in approval_rows:
        session.add(
            AuditEventRecord(
                created_at=row.created_at or datetime.now(timezone.utc),
                event_type="approval_decision_imported",
                entity_type="approval_decision",
                entity_id=str(row.id),
                message=f"Approval decision imported with action {row.action}.",
                payload_json=row.payload_json,
            )
        )
        created += 1

    return created

def main():
    Base.metadata.create_all(bind=engine)

    with SessionLocal() as session:
        gateway_count = import_gateway_decisions(session)
        approval_count = import_approval_decisions(session)
        audit_count = create_audit_events(session)
        session.commit()

    print(f"gateway_decisions_imported={gateway_count}")
    print(f"approval_decisions_imported={approval_count}")
    print(f"audit_events_created={audit_count}")

if __name__ == "__main__":
    main()
