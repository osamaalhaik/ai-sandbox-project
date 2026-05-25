import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]

if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app.features.extractor import BehavioralFeatureExtractor


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", type=str, default=None)
    parser.add_argument("--latest", action="store_true")
    args = parser.parse_args()

    extractor = BehavioralFeatureExtractor()

    if args.latest or args.run_id is None:
        features = extractor.extract_latest()
    else:
        features = extractor.extract_by_run_id(args.run_id)

    print(json.dumps(asdict(features), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
