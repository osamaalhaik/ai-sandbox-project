import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]

if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app.detection.rules import RuleBasedDetector


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", type=str, default=None)
    parser.add_argument("--latest", action="store_true")
    args = parser.parse_args()

    detector = RuleBasedDetector()

    if args.latest or args.run_id is None:
        result = detector.detect_latest()
    else:
        result = detector.detect_by_run_id(args.run_id)

    print(json.dumps(asdict(result), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
