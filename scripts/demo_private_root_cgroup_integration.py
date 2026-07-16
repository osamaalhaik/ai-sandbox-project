import json
import tempfile
from pathlib import Path

from app.sandbox.cgroup_v2 import (
    CgroupV2Limits,
    CgroupV2Manager,
)
from app.sandbox.private_root_runner import (
    PrivateRootRunner,
)


root = Path.cwd()
manager = CgroupV2Manager()

with tempfile.TemporaryDirectory() as directory:
    directory_path = Path(
        directory
    )

    runner = PrivateRootRunner(
        output_path=str(
            directory_path
            / "private-root-runs.jsonl"
        ),
        samples_output_path=str(
            directory_path
            / "private-root-samples.jsonl"
        ),
        cgroup_manager=manager,
    )

    cpu_result = runner.run(
        command=[
            str(
                root
                / "venv/bin/python"
            ),
            "scripts/demo_private_root_resource_target.py",
            "cpu",
        ],
        working_directory=str(root),
        timeout_seconds=15,
        resource_limits=CgroupV2Limits(
            cpu_quota_us=20000,
            cpu_period_us=100000,
            memory_max_bytes=201326592,
            memory_swap_max_bytes=0,
            pids_max=64,
        ),
    )

    memory_result = runner.run(
        command=[
            str(
                root
                / "venv/bin/python"
            ),
            "scripts/demo_private_root_resource_target.py",
            "memory",
        ],
        working_directory=str(root),
        timeout_seconds=20,
        resource_limits=CgroupV2Limits(
            cpu_quota_us=100000,
            cpu_period_us=100000,
            memory_max_bytes=134217728,
            memory_high_bytes=None,
            memory_swap_max_bytes=0,
            pids_max=32,
        ),
    )

    pids_result = runner.run(
        command=[
            str(
                root
                / "venv/bin/python"
            ),
            "scripts/demo_private_root_resource_target.py",
            "pids",
        ],
        working_directory=str(root),
        timeout_seconds=15,
        resource_limits=CgroupV2Limits(
            cpu_quota_us=100000,
            cpu_period_us=100000,
            memory_max_bytes=201326592,
            memory_swap_max_bytes=0,
            pids_max=12,
        ),
    )

    pids_target = json.loads(
        pids_result.stdout.strip()
    )

    validation = {
        "cpu_completed": (
            cpu_result.status
            == "completed"
        ),
        "cpu_throttled": (
            cpu_result.cpu_throttled
        ),
        "cpu_attached": (
            cpu_result.cgroup_attached
        ),
        "memory_failed": (
            memory_result.status
            == "failed"
        ),
        "memory_oom_killed": (
            memory_result.oom_killed
        ),
        "memory_reason": (
            memory_result.failure_reason
            == "cgroup_memory_limit_exceeded"
        ),
        "pids_completed": (
            pids_result.status
            == "completed"
        ),
        "pids_limit_hit": (
            pids_result.pids_limit_hit
        ),
        "pids_failure_observed": (
            pids_target[
                "failure"
            ]
            is not None
        ),
        "cleanup": all(
            (
                cpu_result.cgroup_cleaned,
                memory_result.cgroup_cleaned,
                pids_result.cgroup_cleaned,
                cpu_result.private_root_cleaned,
                memory_result.private_root_cleaned,
                pids_result.private_root_cleaned,
            )
        ),
    }

    failed = [
        name
        for name, value
        in validation.items()
        if not value
    ]

    output = {
        "validation_ok": (
            not failed
        ),
        "failed": failed,
        "cpu": {
            "status": cpu_result.status,
            "cpu_throttled": (
                cpu_result.cpu_throttled
            ),
            "snapshot": (
                cpu_result.cgroup_snapshot
            ),
        },
        "memory": {
            "status": (
                memory_result.status
            ),
            "failure_reason": (
                memory_result.failure_reason
            ),
            "oom_killed": (
                memory_result.oom_killed
            ),
            "snapshot": (
                memory_result.cgroup_snapshot
            ),
        },
        "pids": {
            "status": pids_result.status,
            "pids_limit_hit": (
                pids_result.pids_limit_hit
            ),
            "target": pids_target,
            "snapshot": (
                pids_result.cgroup_snapshot
            ),
        },
    }

    print(
        json.dumps(
            output,
            ensure_ascii=False,
            sort_keys=True,
        ),
        flush=True,
    )

    if failed:
        raise SystemExit(
            "PRIVATE_ROOT_CGROUP_VALIDATION_FAILED="
            + ",".join(failed)
        )

    print(
        "PRIVATE_ROOT_CGROUP_VALIDATION_OK",
        flush=True,
    )
