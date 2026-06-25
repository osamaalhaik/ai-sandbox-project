import json
import shlex
from datetime import datetime, timezone
from pathlib import Path
from sqlalchemy.orm import Session
from .models import AnalysisRun, SecurityAlert, SyscallEvent, TriggeredRule

ROOT = Path(__file__).resolve().parents[2]

def utc_now():
    return datetime.now(timezone.utc)

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

def rule_ids(detection):
    result = set()

    for rule in detection.get("triggered_rules", []):
        if isinstance(rule, dict):
            result.add(str(rule.get("rule_id") or ""))

    return result

def decision_for(risk_level, detection):
    rules = rule_ids(detection)

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

def command_text(command):
    if isinstance(command, list):
        return shlex.join([str(item) for item in command])

    return str(command or "")

def alert_records(run, detection):
    alerts = []

    if run.status == "blocked":
        alerts.append(
            SecurityAlert(
                run_id=run.run_id,
                level="high",
                title="Command blocked by policy",
                message="The command was blocked before execution by the sandbox command policy.",
            )
        )

    if run.risk_level in {"high", "critical"}:
        alerts.append(
            SecurityAlert(
                run_id=run.run_id,
                level=run.risk_level,
                title=f"{run.risk_level.title()} risk execution",
                message=f"The analysis result produced a {run.risk_level} risk level.",
            )
        )

    for rule in detection.get("triggered_rules", []):
        if isinstance(rule, dict) and rule.get("rule_id") == "SENSITIVE_PATH_ACCESS":
            alerts.append(
                SecurityAlert(
                    run_id=run.run_id,
                    level="medium",
                    title="Sensitive path access",
                    message="The traced process accessed a sensitive filesystem path.",
                )
            )

    return alerts

def import_jsonl_results(session: Session):
    sandbox_path = ROOT / "data/raw/sandbox_runs.jsonl"
    detection_path = ROOT / "data/processed/detection_results.jsonl"
    syscall_path = ROOT / "data/raw/syscall_events.jsonl"

    sandbox_records = read_jsonl(sandbox_path)
    detection_records = read_jsonl(detection_path)
    syscall_records = read_jsonl(syscall_path)

    sandbox_by_id = {record.get("run_id"): record for record in sandbox_records if record.get("run_id")}
    detection_by_id = {record.get("run_id"): record for record in detection_records if record.get("run_id")}

    run_ids = sorted(set(sandbox_by_id.keys()) | set(detection_by_id.keys()))

    imported_runs = 0
    imported_syscalls = 0
    imported_rules = 0
    imported_alerts = 0

    for run_id in run_ids:
        sandbox = sandbox_by_id.get(run_id, {})
        detection = detection_by_id.get(run_id, {})

        run = session.get(AnalysisRun, run_id)

        if run is None:
            run = AnalysisRun(run_id=run_id)

        risk_level = detection.get("risk_level") or "low"

        run.command_text = command_text(sandbox.get("command"))
        run.executable = detection.get("executable")
        run.status = detection.get("status") or sandbox.get("status")
        run.policy_allowed = sandbox.get("policy_allowed")
        run.policy_reason = sandbox.get("policy_reason")
        run.risk_score = int(detection.get("risk_score") or 0)
        run.risk_level = risk_level
        run.final_decision = decision_for(risk_level, detection)
        run.security_explanation = detection.get("security_explanation")
        run.stdout = sandbox.get("stdout")
        run.stderr = sandbox.get("stderr")
        run.started_at = parse_datetime(sandbox.get("started_at"))
        run.finished_at = parse_datetime(sandbox.get("finished_at"))
        run.detected_at = parse_datetime(detection.get("detected_at"))
        run.created_at = run.started_at or run.detected_at or utc_now()

        session.add(run)
        session.flush()

        session.query(TriggeredRule).filter(TriggeredRule.run_id == run_id).delete()
        session.query(SyscallEvent).filter(SyscallEvent.run_id == run_id).delete()
        session.query(SecurityAlert).filter(SecurityAlert.run_id == run_id).delete()

        for rule in detection.get("triggered_rules", []):
            if isinstance(rule, dict):
                session.add(
                    TriggeredRule(
                        run_id=run_id,
                        rule_id=str(rule.get("rule_id") or "UNKNOWN_RULE"),
                        title=rule.get("title"),
                        severity=rule.get("severity"),
                        score=int(rule.get("score") or 0),
                        description=rule.get("description"),
                    )
                )
                imported_rules += 1

        for event in syscall_records:
            if event.get("run_id") != run_id:
                continue

            session.add(
                SyscallEvent(
                    run_id=run_id,
                    line_number=event.get("line_number"),
                    pid=event.get("pid"),
                    syscall=event.get("syscall"),
                    category=event.get("category"),
                    path=event.get("path"),
                    result=event.get("result"),
                    success=event.get("success"),
                    raw_line=event.get("raw_line"),
                )
            )
            imported_syscalls += 1

        for alert in alert_records(run, detection):
            session.add(alert)
            imported_alerts += 1

        imported_runs += 1

    session.commit()

    return {
        "imported_runs": imported_runs,
        "imported_rules": imported_rules,
        "imported_syscalls": imported_syscalls,
        "imported_alerts": imported_alerts,
    }
