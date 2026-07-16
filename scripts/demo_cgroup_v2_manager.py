import json
import os
import signal
import subprocess
import sys
import time
import uuid

from app.sandbox.cgroup_v2 import (
    CgroupV2Limits,
    CgroupV2Manager,
)


def wait_stopped(
    process_id: int,
) -> None:
    deadline = (
        time.monotonic()
        + 3
    )

    status_path = (
        f"/proc/{process_id}/status"
    )

    while time.monotonic() < deadline:
        try:
            status = open(
                status_path,
                encoding="utf-8",
            ).read()
        except FileNotFoundError:
            break

        if any(
            line.startswith(
                "State:"
            )
            and "T" in line
            for line in status.splitlines()
        ):
            return

        time.sleep(
            0.01
        )

    raise RuntimeError(
        "worker did not enter stopped state"
    )


def spawn_stopped(
    body: str,
) -> subprocess.Popen:
    code = (
        "import os,signal;"
        "os.kill(os.getpid(),signal.SIGSTOP);"
        + body
    )

    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            code,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    wait_stopped(
        process.pid
    )

    return process


manager = CgroupV2Manager()
preflight = manager.prepare()

cpu_handle = manager.create_run(
    f"cpu-{uuid.uuid4().hex[:8]}",
    CgroupV2Limits(
        cpu_quota_us=20000,
        cpu_period_us=100000,
        memory_max_bytes=134217728,
        memory_swap_max_bytes=0,
        pids_max=32,
    ),
)

cpu_process = spawn_stopped(
    (
        "import time;"
        "deadline=time.monotonic()+2.0;"
        "value=1;"
        "\nwhile time.monotonic()<deadline:"
        "\n value=(value*1103515245+12345)&0x7fffffff"
        "\nprint(value,flush=True)"
    )
)

manager.attach_pid(
    cpu_handle,
    cpu_process.pid,
)

os.kill(
    cpu_process.pid,
    signal.SIGCONT,
)

cpu_stdout, cpu_stderr = (
    cpu_process.communicate(
        timeout=5
    )
)

cpu_snapshot = manager.snapshot(
    cpu_handle
)

cpu_cleaned = manager.cleanup(
    cpu_handle
)

memory_handle = manager.create_run(
    f"memory-{uuid.uuid4().hex[:8]}",
    CgroupV2Limits(
        cpu_quota_us=100000,
        cpu_period_us=100000,
        memory_max_bytes=33554432,
        memory_swap_max_bytes=0,
        pids_max=16,
    ),
)

memory_process = spawn_stopped(
    (
        "import time;"
        "blocks=[];"
        "\nfor _ in range(160):"
        "\n blocks.append(bytearray(1024*1024))"
        "\n time.sleep(0.005)"
        "\nprint('MEMORY_LIMIT_NOT_ENFORCED',flush=True)"
    )
)

manager.attach_pid(
    memory_handle,
    memory_process.pid,
)

os.kill(
    memory_process.pid,
    signal.SIGCONT,
)

memory_stdout, memory_stderr = (
    memory_process.communicate(
        timeout=8
    )
)

memory_snapshot = manager.snapshot(
    memory_handle
)

memory_cleaned = manager.cleanup(
    memory_handle
)

pids_handle = manager.create_run(
    f"pids-{uuid.uuid4().hex[:8]}",
    CgroupV2Limits(
        cpu_quota_us=100000,
        cpu_period_us=100000,
        memory_max_bytes=134217728,
        memory_swap_max_bytes=0,
        pids_max=12,
    ),
)

pids_body = (
    "import json,subprocess;"
    "processes=[];"
    "failure=None;"
    "\ntry:"
    "\n for index in range(40):"
    "\n  try:"
    "\n   processes.append(subprocess.Popen(['sleep','3']))"
    "\n  except OSError as exc:"
    "\n   failure={'index':index,'errno':exc.errno,'error':str(exc)}"
    "\n   break"
    "\n print(json.dumps({'children':len(processes),'failure':failure}),flush=True)"
    "\nfinally:"
    "\n for process in processes:"
    "\n  process.terminate()"
    "\n for process in processes:"
    "\n  try:"
    "\n   process.wait(timeout=2)"
    "\n  except subprocess.TimeoutExpired:"
    "\n   process.kill()"
    "\n   process.wait()"
)

pids_process = spawn_stopped(
    pids_body
)

manager.attach_pid(
    pids_handle,
    pids_process.pid,
)

os.kill(
    pids_process.pid,
    signal.SIGCONT,
)

pids_stdout, pids_stderr = (
    pids_process.communicate(
        timeout=8
    )
)

pids_snapshot = manager.snapshot(
    pids_handle
)

pids_cleaned = manager.cleanup(
    pids_handle
)

pids_result = json.loads(
    pids_stdout.strip()
)

validation = {
    "cpu_limit": (
        cpu_process.returncode == 0
        and cpu_snapshot[
            "cpu_throttled"
        ]
    ),
    "memory_limit": (
        memory_process.returncode
        != 0
        and memory_snapshot[
            "oom_killed"
        ]
        and "MEMORY_LIMIT_NOT_ENFORCED"
        not in memory_stdout
    ),
    "pids_limit": (
        pids_process.returncode == 0
        and pids_snapshot[
            "pids_limit_hit"
        ]
        and pids_result[
            "failure"
        ]
        is not None
        and pids_result[
            "children"
        ]
        < 12
    ),
    "cleanup": (
        cpu_cleaned
        and memory_cleaned
        and pids_cleaned
    ),
}

failed = [
    name
    for name, value
    in validation.items()
    if not value
]

result = {
    "validation_ok": (
        not failed
    ),
    "failed": failed,
    "preflight": preflight,
    "cpu": {
        "return_code": (
            cpu_process.returncode
        ),
        "stdout": cpu_stdout.strip(),
        "stderr": cpu_stderr.strip(),
        "snapshot": cpu_snapshot,
        "cleaned": cpu_cleaned,
    },
    "memory": {
        "return_code": (
            memory_process.returncode
        ),
        "stdout": (
            memory_stdout.strip()
        ),
        "stderr": (
            memory_stderr.strip()
        ),
        "snapshot": memory_snapshot,
        "cleaned": memory_cleaned,
    },
    "pids": {
        "return_code": (
            pids_process.returncode
        ),
        "result": pids_result,
        "stderr": pids_stderr.strip(),
        "snapshot": pids_snapshot,
        "cleaned": pids_cleaned,
    },
}

print(
    json.dumps(
        result,
        ensure_ascii=False,
        sort_keys=True,
    ),
    flush=True,
)

if failed:
    raise SystemExit(
        "CGROUP_V2_MANAGER_VALIDATION_FAILED="
        + ",".join(failed)
    )

print(
    "CGROUP_V2_MANAGER_VALIDATION_OK",
    flush=True,
)
