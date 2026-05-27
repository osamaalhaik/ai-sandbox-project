import argparse
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", choices=["safe", "sensitive", "blocked"], required=True)
    args = parser.parse_args()

    incoming_dir = ROOT_DIR / "data/live/incoming"
    incoming_dir.mkdir(parents=True, exist_ok=True)

    request_id = str(uuid.uuid4())
    request = {
        "request_id": request_id,
        "scenario": args.scenario,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    request_path = incoming_dir / f"{request_id}.json"
    request_path.write_text(json.dumps(request, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"request_created={request_path}")
    print(f"scenario={args.scenario}")


if __name__ == "__main__":
    main()
