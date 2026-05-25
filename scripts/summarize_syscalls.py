import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]

if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app.tracing.syscall_summary import SyscallSummarizer


def read_latest_run_id(path: Path) -> str:
    if not path.exists():
        raise SystemExit("No strace runs file found")

    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]

    if not lines:
        raise SystemExit("No strace runs found")

    return json.loads(lines[-1])["run_id"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", type=str, default=None)
    parser.add_argument("--latest", action="store_true")
    args = parser.parse_args()

    runs_path = ROOT_DIR / "data/raw/strace_runs.jsonl"

    if args.latest or args.run_id is None:
        run_id = read_latest_run_id(runs_path)
    else:
        run_id = args.run_id

    summarizer = SyscallSummarizer()
    summary = summarizer.summarize(run_id)

    print(json.dumps(asdict(summary), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
