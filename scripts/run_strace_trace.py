import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]

if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app.tracing.strace_runner import StraceRunner


def normalize_command(command):
    if command and command[0] == "--":
        return command[1:]
    return command


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--cwd", type=str, default=None)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()

    command = normalize_command(args.command)

    if not command:
        raise SystemExit("Command is required")

    runner = StraceRunner()
    result = runner.run(
        command=command,
        timeout_seconds=args.timeout,
        working_directory=args.cwd or str(ROOT_DIR),
    )

    print(json.dumps(asdict(result), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
