import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.web_platform.api import APPROVAL_DECISIONS_PATH, gateway_events, latest_records, refresh, stats, utc_now_string
from app.web_platform.database import SessionLocal
from app.web_platform.models import AnalysisRun, SecurityAlert
from app.web_platform.reports import build_security_report

def build_report():
    with SessionLocal() as session:
        refresh(session)

        latest_runs = session.query(AnalysisRun).order_by(AnalysisRun.created_at.desc()).limit(50).all()
        latest_alerts = session.query(SecurityAlert).order_by(SecurityAlert.created_at.desc()).limit(50).all()

        run_items = [
            {
                "run_id": item.run_id,
                "command": item.command_text,
                "executable": item.executable,
                "status": item.status,
                "risk_score": item.risk_score,
                "risk_level": item.risk_level,
                "decision": item.final_decision,
            }
            for item in latest_runs
        ]

        alert_items = [
            {
                "id": item.id,
                "run_id": item.run_id,
                "level": item.level,
                "title": item.title,
                "message": item.message,
                "created_at": item.created_at.isoformat() if item.created_at else None,
            }
            for item in latest_alerts
        ]

        return build_security_report(
            stats=stats(session),
            runs=run_items,
            gateway_decisions=gateway_events(50),
            approval_decisions=latest_records(APPROVAL_DECISIONS_PATH, 50),
            alerts=alert_items,
            generated_at=utc_now_string(),
        )

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="docs/evidence/security_summary_report.json")
    args = parser.parse_args()

    report = build_report()
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(str(output_path))

if __name__ == "__main__":
    main()
