import json
import os
import subprocess
import sys
import time


children = [
    subprocess.Popen(
        [
            sys.executable,
            "-c",
            (
                "import os,time;"
                "print(os.getpid(), flush=True);"
                "time.sleep(1.2)"
            ),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    for _ in range(2)
]

print(
    json.dumps(
        {
            "pid": os.getpid(),
            "ppid": os.getppid(),
            "children": [
                child.pid
                for child in children
            ],
        },
        sort_keys=True,
    ),
    flush=True,
)

time.sleep(1.0)

for child in children:
    child.communicate(
        timeout=3
    )
