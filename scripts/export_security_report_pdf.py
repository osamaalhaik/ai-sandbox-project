import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.web_platform.report_pdf_exports import security_report_to_pdf_bytes
from scripts.export_security_report import build_report

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="docs/evidence/security_summary_report.pdf")
    args = parser.parse_args()

    report = build_report()
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(security_report_to_pdf_bytes(report))
    print(str(output_path))

if __name__ == "__main__":
    main()
