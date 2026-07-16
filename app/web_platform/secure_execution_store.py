from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import func
from sqlalchemy.orm import Session

from .models import SecureExecutionRecord


ROOT = Path(__file__).resolve().parents[2]

SECURE_EXECUTION_RESULTS_PATH = (
    ROOT
    / "data/processed/secure_execution_results.jsonl"
)


def utc_now() -> datetime:
    return datetime.now(
        timezone.utc
    )


def parse_datetime(
    value: object,
) -> datetime | None:
    if value is None:
        return None

    if isinstance(
        value,
        datetime,
    ):
        return value

    text = str(
        value
    ).strip()

    if not text:
        return None

    if text.endswith(
        "Z"
    ):
        text = (
            text[:-1]
            + "+00:00"
        )

    try:
        return datetime.fromisoformat(
            text
        )
    except ValueError:
        return None


def read_jsonl(
    path: Path,
) -> tuple[list[dict], int]:
    if not path.exists():
        return [], 0

    records = []
    malformed = 0

    for line in path.read_text(
        encoding="utf-8"
    ).splitlines():
        if not line.strip():
            continue

        try:
            value = json.loads(
                line
            )
        except json.JSONDecodeError:
            malformed += 1
            continue

        if isinstance(
            value,
            dict,
        ):
            records.append(
                value
            )
        else:
            malformed += 1

    return records, malformed


def json_value(
    value: object,
) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
    )


def sync_secure_execution_results(
    session: Session,
    path: Path | str = (
        SECURE_EXECUTION_RESULTS_PATH
    ),
) -> dict:
    source_path = Path(
        path
    )

    records, malformed = read_jsonl(
        source_path
    )

    imported = 0
    updated = 0
    skipped = 0

    for payload in records:
        secure_execution_id = str(
            payload.get(
                "secure_execution_id"
            )
            or ""
        ).strip()

        if not secure_execution_id:
            skipped += 1
            continue

        record = session.get(
            SecureExecutionRecord,
            secure_execution_id,
        )

        if record is None:
            record = SecureExecutionRecord(
                secure_execution_id=(
                    secure_execution_id
                )
            )

            imported += 1
        else:
            updated += 1

        record.gateway_decision_id = (
            payload.get(
                "gateway_decision_id"
            )
        )

        record.run_id = payload.get(
            "run_id"
        )

        record.command_text = str(
            payload.get(
                "command_text"
            )
            or ""
        )

        record.working_directory = (
            payload.get(
                "working_directory"
            )
        )

        record.execution_strategy = (
            payload.get(
                "execution_strategy"
            )
        )

        record.execution_profile = (
            payload.get(
                "execution_profile"
            )
        )

        record.approval_verified = (
            payload.get(
                "approval_verified"
            )
        )

        record.monitoring_enabled = (
            payload.get(
                "monitoring_enabled"
            )
        )

        record.status = payload.get(
            "status"
        )

        record.failure_reason = (
            payload.get(
                "failure_reason"
            )
        )

        record.resource_controls_enabled = (
            payload.get(
                "resource_controls_enabled"
            )
        )

        record.private_root_enabled = (
            payload.get(
                "private_root_enabled"
            )
        )

        record.private_root_cleaned = (
            payload.get(
                "private_root_cleaned"
            )
        )

        record.cgroup_attached = (
            payload.get(
                "cgroup_attached"
            )
        )

        record.cgroup_cleaned = (
            payload.get(
                "cgroup_cleaned"
            )
        )

        record.cpu_throttled = (
            payload.get(
                "cpu_throttled"
            )
        )

        record.oom_killed = (
            payload.get(
                "oom_killed"
            )
        )

        record.pids_limit_hit = (
            payload.get(
                "pids_limit_hit"
            )
        )

        record.samples_count = int(
            payload.get(
                "samples_count"
            )
            or 0
        )

        record.max_processes_observed = int(
            payload.get(
                "max_processes_observed"
            )
            or 0
        )

        record.profile_json = json_value(
            payload.get(
                "profile"
            )
            or {}
        )

        record.run_result_json = json_value(
            payload.get(
                "run_result"
            )
            or {}
        )

        record.created_at = parse_datetime(
            payload.get(
                "created_at"
            )
        )

        record.finished_at = parse_datetime(
            payload.get(
                "finished_at"
            )
        )

        record.ingested_at = utc_now()

        session.add(
            record
        )

    session.commit()

    return {
        "source_path": str(
            source_path
        ),
        "source_exists": (
            source_path.exists()
        ),
        "records_found": len(
            records
        ),
        "imported": imported,
        "updated": updated,
        "skipped": skipped,
        "malformed": malformed,
    }


def decode_json(
    value: str | None,
) -> object:
    if not value:
        return {}

    try:
        return json.loads(
            value
        )
    except json.JSONDecodeError:
        return {}


def serialize_secure_execution(
    record: SecureExecutionRecord,
    include_run_result: bool = False,
) -> dict:
    result = {
        "secure_execution_id": (
            record.secure_execution_id
        ),
        "gateway_decision_id": (
            record.gateway_decision_id
        ),
        "run_id": record.run_id,
        "command": (
            record.command_text
        ),
        "working_directory": (
            record.working_directory
        ),
        "execution_strategy": (
            record.execution_strategy
        ),
        "execution_profile": (
            record.execution_profile
        ),
        "approval_verified": (
            record.approval_verified
        ),
        "monitoring_enabled": (
            record.monitoring_enabled
        ),
        "status": record.status,
        "failure_reason": (
            record.failure_reason
        ),
        "resource_controls_enabled": (
            record.resource_controls_enabled
        ),
        "private_root_enabled": (
            record.private_root_enabled
        ),
        "private_root_cleaned": (
            record.private_root_cleaned
        ),
        "cgroup_attached": (
            record.cgroup_attached
        ),
        "cgroup_cleaned": (
            record.cgroup_cleaned
        ),
        "cpu_throttled": (
            record.cpu_throttled
        ),
        "oom_killed": (
            record.oom_killed
        ),
        "pids_limit_hit": (
            record.pids_limit_hit
        ),
        "samples_count": (
            record.samples_count
        ),
        "max_processes_observed": (
            record.max_processes_observed
        ),
        "profile": decode_json(
            record.profile_json
        ),
        "created_at": (
            record.created_at.isoformat()
            if record.created_at
            else None
        ),
        "finished_at": (
            record.finished_at.isoformat()
            if record.finished_at
            else None
        ),
        "ingested_at": (
            record.ingested_at.isoformat()
            if record.ingested_at
            else None
        ),
    }

    if include_run_result:
        result["run_result"] = (
            decode_json(
                record.run_result_json
            )
        )

    return result


def secure_execution_summary(
    session: Session,
) -> dict:
    total = (
        session.query(
            func.count(
                SecureExecutionRecord
                .secure_execution_id
            )
        )
        .scalar()
        or 0
    )

    completed = (
        session.query(
            func.count(
                SecureExecutionRecord
                .secure_execution_id
            )
        )
        .filter(
            SecureExecutionRecord.status
            == "completed"
        )
        .scalar()
        or 0
    )

    failed = (
        session.query(
            func.count(
                SecureExecutionRecord
                .secure_execution_id
            )
        )
        .filter(
            SecureExecutionRecord.status
            == "failed"
        )
        .scalar()
        or 0
    )

    timed_out = (
        session.query(
            func.count(
                SecureExecutionRecord
                .secure_execution_id
            )
        )
        .filter(
            SecureExecutionRecord.status
            == "timed_out"
        )
        .scalar()
        or 0
    )

    oom_killed = (
        session.query(
            func.count(
                SecureExecutionRecord
                .secure_execution_id
            )
        )
        .filter(
            SecureExecutionRecord.oom_killed
            .is_(True)
        )
        .scalar()
        or 0
    )

    cpu_throttled = (
        session.query(
            func.count(
                SecureExecutionRecord
                .secure_execution_id
            )
        )
        .filter(
            SecureExecutionRecord.cpu_throttled
            .is_(True)
        )
        .scalar()
        or 0
    )

    pids_limit_hit = (
        session.query(
            func.count(
                SecureExecutionRecord
                .secure_execution_id
            )
        )
        .filter(
            SecureExecutionRecord.pids_limit_hit
            .is_(True)
        )
        .scalar()
        or 0
    )

    cleanup_failures = (
        session.query(
            func.count(
                SecureExecutionRecord
                .secure_execution_id
            )
        )
        .filter(
            (
                SecureExecutionRecord
                .private_root_cleaned
                .is_(False)
            )
            | (
                SecureExecutionRecord
                .cgroup_cleaned
                .is_(False)
            )
        )
        .scalar()
        or 0
    )

    return {
        "total": total,
        "completed": completed,
        "failed": failed,
        "timed_out": timed_out,
        "cpu_throttled": (
            cpu_throttled
        ),
        "oom_killed": oom_killed,
        "pids_limit_hit": (
            pids_limit_hit
        ),
        "cleanup_failures": (
            cleanup_failures
        ),
    }
