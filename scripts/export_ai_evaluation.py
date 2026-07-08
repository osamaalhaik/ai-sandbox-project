import argparse
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.ai.evaluation import build_ai_evaluation_report


def write_json(report: dict, output_path: Path):
    output_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def write_csv(report: dict, output_path: Path):
    scenarios = report["scenarios"]

    with output_path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "name",
                "command",
                "context_classification",
                "rule_based_risk",
                "ai_prediction",
                "ai_risk_level",
                "final_decision",
                "explanation",
            ],
        )
        writer.writeheader()
        writer.writerows(scenarios)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--json-output", default="docs/evidence/ai_evaluation_report.json")
    parser.add_argument("--csv-output", default="docs/evidence/ai_evaluation_report.csv")
    args = parser.parse_args()

    report = build_ai_evaluation_report()

    json_path = Path(args.json_output)
    csv_path = Path(args.csv_output)

    json_path.parent.mkdir(parents=True, exist_ok=True)
    csv_path.parent.mkdir(parents=True, exist_ok=True)

    write_json(report, json_path)
    write_csv(report, csv_path)

    print(str(json_path))
    print(str(csv_path))


if __name__ == "__main__":
    main()
