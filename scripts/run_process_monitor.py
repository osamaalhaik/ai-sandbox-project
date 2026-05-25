import json
import subprocess
import sys
import uuid
from dataclasses import asdict
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]

if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app.monitoring.process_monitor import ProcessMonitor


def main():
    run_id = str(uuid.uuid4())

    process = subprocess.Popen(
        ["python", "scripts/demo_monitored_process.py"],
        cwd=str(ROOT_DIR),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    monitor = ProcessMonitor()
    samples = monitor.monitor_until_exit(
        run_id=run_id,
        pid=process.pid,
        interval_seconds=0.1,
        max_duration_seconds=10,
    )

    stdout, stderr = process.communicate()

    result = {
        "run_id": run_id,
        "pid": process.pid,
        "exit_code": process.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "samples_count": len(samples),
        "last_sample": asdict(samples[-1]) if samples else None,
    }

    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
