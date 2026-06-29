import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.web_platform.report_exports import security_report_to_csv
from scripts.export_security_report import build_report

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="docs/evidence/security_summary_report.csv")
    args = parser.parse_args()

    report = build_report()
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(security_report_to_csv(report), encoding="utf-8")
    print(str(output_path))

if __name__ == "__main__":
    main()
