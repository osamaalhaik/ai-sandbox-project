import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]

if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app.sandbox.runner import SandboxRunner


def normalize_command(command):
    if command and command[0] == "--":
        return command[1:]
    return command


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--cpu", type=int, default=5)
    parser.add_argument("--memory", type=int, default=256)
    parser.add_argument("--open-files", type=int, default=64)
    parser.add_argument("--cwd", type=str, default=None)
    parser.add_argument("--monitor-interval", type=float, default=0.2)
    parser.add_argument("--disable-monitoring", action="store_true")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()

    command = normalize_command(args.command)

    if not command:
        raise SystemExit("Command is required")

    runner = SandboxRunner()
    result = runner.run(
        command=command,
        timeout_seconds=args.timeout,
        max_cpu_seconds=args.cpu,
        max_memory_mb=args.memory,
        max_open_files=args.open_files,
        working_directory=args.cwd,
        monitoring_enabled=not args.disable_monitoring,
        monitor_interval_seconds=args.monitor_interval,
    )

    print(json.dumps(asdict(result), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
