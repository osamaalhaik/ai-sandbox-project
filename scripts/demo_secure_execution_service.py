import json
import tempfile
from pathlib import Path

from app.sandbox.cgroup_v2 import (
    CgroupV2Manager,
)
from app.sandbox.private_root_runner import (
    PrivateRootRunner,
)
from app.security.secure_execution import (
    SecureExecutionService,
)


root = Path.cwd()

with tempfile.TemporaryDirectory() as directory:
    directory_path = Path(
        directory
    )

    service = SecureExecutionService(
        output_path=str(
            directory_path
            / "secure-executions.jsonl"
        ),
        runner=PrivateRootRunner(
            output_path=str(
                directory_path
                / "private-root-runs.jsonl"
            ),
            samples_output_path=str(
                directory_path
                / "private-root-samples.jsonl"
            ),
            cgroup_manager=(
                CgroupV2Manager()
            ),
        ),
    )

    record = service.execute(
        command=[
            str(
                root
                / "venv/bin/python"
            ),
            "-c",
            (
                "import json,os;"
                "print(json.dumps({"
                "'pid':os.getpid(),"
                "'ppid':os.getppid()"
                "}),flush=True)"
            ),
        ],
        working_directory=str(root),
        execution_strategy=(
            "lightweight_sandbox"
        ),
        gateway_decision_id=(
            "runtime-validation"
        ),
    )

    run_result = record[
        "run_result"
    ]

    target = json.loads(
        run_result[
            "stdout"
        ].strip()
    )

    validations = {
        "completed": (
            record["status"]
            == "completed"
        ),
        "profile_low": (
            record[
                "execution_profile"
            ]
            == "low"
        ),
        "target_pid_one": (
            target["pid"] == 1
        ),
        "private_root": (
            record[
                "private_root_enabled"
            ]
        ),
        "private_root_cleaned": (
            record[
                "private_root_cleaned"
            ]
        ),
        "resource_controls": (
            record[
                "resource_controls_enabled"
            ]
        ),
        "cgroup_attached": (
            record[
                "cgroup_attached"
            ]
        ),
        "cgroup_cleaned": (
            record[
                "cgroup_cleaned"
            ]
        ),
        "samples": (
            record[
                "samples_count"
            ]
            > 0
        ),
        "persisted": (
            len(
                service.latest()
            )
            == 1
        ),
    }

    failed = [
        name
        for name, value
        in validations.items()
        if not value
    ]

    print(
        json.dumps(
            {
                "validation_ok": (
                    not failed
                ),
                "failed": failed,
                "secure_execution_id": (
                    record[
                        "secure_execution_id"
                    ]
                ),
                "run_id": (
                    record["run_id"]
                ),
                "status": (
                    record["status"]
                ),
                "execution_profile": (
                    record[
                        "execution_profile"
                    ]
                ),
                "namespace_target_pid": (
                    target["pid"]
                ),
                "host_target_pid": (
                    run_result.get(
                        "target_pid"
                    )
                ),
                "samples_count": (
                    record[
                        "samples_count"
                    ]
                ),
                "max_processes_observed": (
                    record[
                        "max_processes_observed"
                    ]
                ),
                "cgroup_attached": (
                    record[
                        "cgroup_attached"
                    ]
                ),
                "cgroup_cleaned": (
                    record[
                        "cgroup_cleaned"
                    ]
                ),
                "private_root_cleaned": (
                    record[
                        "private_root_cleaned"
                    ]
                ),
            },
            ensure_ascii=False,
            sort_keys=True,
        ),
        flush=True,
    )

    if failed:
        raise SystemExit(
            "SECURE_EXECUTION_SERVICE_"
            "VALIDATION_FAILED="
            + ",".join(failed)
        )

    print(
        "SECURE_EXECUTION_SERVICE_"
        "VALIDATION_OK",
        flush=True,
    )
