from __future__ import annotations

import json
import shlex
import threading
import uuid
from dataclasses import (
    asdict,
    is_dataclass,
)
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.sandbox.cgroup_v2 import (
    CgroupV2Manager,
)
from app.sandbox.private_root_runner import (
    PrivateRootRunner,
)

from .execution_profiles import (
    profile_for_strategy,
    strategy_requires_approval,
)


class SecureExecutionDenied(
    RuntimeError
):
    pass


class SecureExecutionService:
    _write_lock = threading.Lock()

    def __init__(
        self,
        output_path: str = (
            "data/processed/"
            "secure_execution_results.jsonl"
        ),
        runner: Any | None = None,
    ):
        self.output_path = Path(
            output_path
        )

        self.output_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.runner = (
            runner
            if runner is not None
            else PrivateRootRunner(
                output_path=(
                    "data/raw/"
                    "private_root_runs.jsonl"
                ),
                samples_output_path=(
                    "data/raw/"
                    "private_root_process_samples.jsonl"
                ),
                cgroup_manager=(
                    CgroupV2Manager()
                ),
            )
        )

    def execute(
        self,
        command: list[str],
        working_directory: str,
        execution_strategy: str,
        gateway_decision_id: str | None = None,
        approval_verified: bool = False,
        monitoring_enabled: bool = True,
    ) -> dict:
        normalized_command = [
            str(item)
            for item in command
        ]

        if not normalized_command:
            raise ValueError(
                "Command is required"
            )

        if (
            strategy_requires_approval(
                execution_strategy
            )
            and not approval_verified
        ):
            raise SecureExecutionDenied(
                "Human approval is required"
            )

        try:
            profile = profile_for_strategy(
                execution_strategy
            )
        except ValueError as exc:
            raise SecureExecutionDenied(
                str(exc)
            ) from exc

        execution_id = str(
            uuid.uuid4()
        )

        created_at = self._utc_now()

        try:
            result = self.runner.run(
                command=normalized_command,
                working_directory=(
                    working_directory
                ),
                timeout_seconds=(
                    profile.timeout_seconds
                ),
                monitoring_enabled=(
                    monitoring_enabled
                ),
                monitor_interval_seconds=(
                    profile
                    .monitor_interval_seconds
                ),
                resource_limits=(
                    profile.resource_limits()
                ),
            )
        except Exception as exc:
            failed_record = {
                "secure_execution_id": (
                    execution_id
                ),
                "gateway_decision_id": (
                    gateway_decision_id
                ),
                "run_id": None,
                "command": (
                    normalized_command
                ),
                "command_text": shlex.join(
                    normalized_command
                ),
                "working_directory": (
                    working_directory
                ),
                "execution_strategy": (
                    execution_strategy
                ),
                "execution_profile": (
                    profile.name
                ),
                "profile": (
                    profile.to_dict()
                ),
                "approval_verified": (
                    approval_verified
                ),
                "monitoring_enabled": (
                    monitoring_enabled
                ),
                "status": "failed",
                "failure_reason": (
                    "secure_execution_error"
                ),
                "error": str(exc),
                "created_at": created_at,
                "finished_at": (
                    self._utc_now()
                ),
                "run_result": {},
            }

            self._append(
                failed_record
            )

            raise

        run_result = self._serialize(
            result
        )

        record = {
            "secure_execution_id": (
                execution_id
            ),
            "gateway_decision_id": (
                gateway_decision_id
            ),
            "run_id": run_result.get(
                "run_id"
            ),
            "command": (
                normalized_command
            ),
            "command_text": shlex.join(
                normalized_command
            ),
            "working_directory": (
                working_directory
            ),
            "execution_strategy": (
                execution_strategy
            ),
            "execution_profile": (
                profile.name
            ),
            "profile": (
                profile.to_dict()
            ),
            "approval_verified": (
                approval_verified
            ),
            "monitoring_enabled": (
                monitoring_enabled
            ),
            "status": run_result.get(
                "status"
            ),
            "failure_reason": (
                run_result.get(
                    "failure_reason"
                )
            ),
            "resource_controls_enabled": (
                bool(
                    run_result.get(
                        "resource_controls_enabled"
                    )
                )
            ),
            "private_root_enabled": (
                bool(
                    run_result.get(
                        "private_root_enabled"
                    )
                )
            ),
            "private_root_cleaned": (
                bool(
                    run_result.get(
                        "private_root_cleaned"
                    )
                )
            ),
            "cgroup_attached": (
                bool(
                    run_result.get(
                        "cgroup_attached"
                    )
                )
            ),
            "cgroup_cleaned": (
                bool(
                    run_result.get(
                        "cgroup_cleaned"
                    )
                )
            ),
            "cpu_throttled": (
                bool(
                    run_result.get(
                        "cpu_throttled"
                    )
                )
            ),
            "oom_killed": (
                bool(
                    run_result.get(
                        "oom_killed"
                    )
                )
            ),
            "pids_limit_hit": (
                bool(
                    run_result.get(
                        "pids_limit_hit"
                    )
                )
            ),
            "samples_count": int(
                run_result.get(
                    "samples_count"
                )
                or 0
            ),
            "max_processes_observed": int(
                run_result.get(
                    "max_processes_observed"
                )
                or 0
            ),
            "created_at": (
                created_at
            ),
            "finished_at": (
                self._utc_now()
            ),
            "run_result": (
                run_result
            ),
        }

        self._append(
            record
        )

        return record

    def latest(
        self,
        limit: int = 100,
    ) -> list[dict]:
        if limit <= 0:
            return []

        if not self.output_path.exists():
            return []

        records = []

        for line in self.output_path.read_text(
            encoding="utf-8"
        ).splitlines():
            if not line.strip():
                continue

            try:
                records.append(
                    json.loads(line)
                )
            except json.JSONDecodeError:
                continue

        return list(
            reversed(
                records[-limit:]
            )
        )

    def find(
        self,
        secure_execution_id: str,
    ) -> dict | None:
        for record in self.latest(
            100000
        ):
            if (
                record.get(
                    "secure_execution_id"
                )
                == secure_execution_id
            ):
                return record

        return None

    def _append(
        self,
        record: dict,
    ) -> None:
        serialized = json.dumps(
            record,
            ensure_ascii=False,
            sort_keys=True,
        )

        with self._write_lock:
            with self.output_path.open(
                "a",
                encoding="utf-8",
            ) as file:
                file.write(
                    serialized + "\n"
                )

    def _serialize(
        self,
        result: Any,
    ) -> dict:
        if is_dataclass(
            result
        ):
            return asdict(
                result
            )

        if isinstance(
            result,
            dict,
        ):
            return dict(
                result
            )

        values = getattr(
            result,
            "__dict__",
            None,
        )

        if isinstance(
            values,
            dict,
        ):
            return dict(
                values
            )

        raise TypeError(
            "Unsupported runner result"
        )

    def _utc_now(
        self,
    ) -> str:
        return datetime.now(
            timezone.utc
        ).isoformat()
