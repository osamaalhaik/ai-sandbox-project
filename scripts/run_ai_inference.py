import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]

if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app.ai.anomaly_detector import AIAnomalyDetector


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", type=str, default=None)
    args = parser.parse_args()

    detector = AIAnomalyDetector()

    if args.run_id:
        result = detector.infer_by_run_id(args.run_id)
    else:
        result = detector.infer_latest()

    print(json.dumps(asdict(result), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
