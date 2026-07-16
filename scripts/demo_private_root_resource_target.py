import json
import os
import subprocess
import sys
import time


mode = (
    sys.argv[1]
    if len(sys.argv) > 1
    else ""
)

if mode == "cpu":
    deadline = (
        time.monotonic()
        + 2.0
    )

    value = 1

    while time.monotonic() < deadline:
        value = (
            value * 1103515245
            + 12345
        ) & 0x7FFFFFFF

    print(
        json.dumps(
            {
                "mode": mode,
                "pid": os.getpid(),
                "value": value,
            },
            sort_keys=True,
        ),
        flush=True,
    )

elif mode == "memory":
    blocks = []
    chunk_size = (
        16
        * 1024
        * 1024
    )

    while True:
        block = bytearray(
            chunk_size
        )

        for offset in range(
            0,
            chunk_size,
            4096,
        ):
            block[offset] = 1

        blocks.append(
            block
        )

elif mode == "pids":
    processes = []
    failure = None

    try:
        for index in range(64):
            try:
                processes.append(
                    subprocess.Popen(
                        [
                            "sleep",
                            "3",
                        ]
                    )
                )
            except OSError as exc:
                failure = {
                    "index": index,
                    "errno": exc.errno,
                    "error": str(exc),
                }

                break

        print(
            json.dumps(
                {
                    "mode": mode,
                    "pid": os.getpid(),
                    "children_started": (
                        len(processes)
                    ),
                    "failure": failure,
                },
                sort_keys=True,
            ),
            flush=True,
        )

        if failure is None:
            raise SystemExit(
                "PIDS_LIMIT_NOT_ENFORCED"
            )

    finally:
        for process in processes:
            process.terminate()

        for process in processes:
            try:
                process.wait(
                    timeout=2
                )
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

else:
    raise SystemExit(
        "Unknown resource target mode"
    )
