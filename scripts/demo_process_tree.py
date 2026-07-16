import subprocess
import time


children = [
    subprocess.Popen(
        ["sleep", "1.2"]
    ),
    subprocess.Popen(
        ["sleep", "1.2"]
    ),
]

print(
    "process_tree_demo_started",
    flush=True,
)

time.sleep(
    0.9
)

for child in children:
    child.wait()

print(
    "process_tree_demo_finished",
    flush=True,
)
