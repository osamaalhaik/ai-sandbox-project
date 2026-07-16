import subprocess
from contextlib import asynccontextmanager
import json
import sys
from pathlib import Path
from datetime import datetime, timezone
from fastapi.responses import Response
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session
from .database import Base, engine, get_session
from .ingest import import_jsonl_results, read_jsonl
from .models import AnalysisRun, SecurityAlert, SyscallEvent, TriggeredRule
from .reports import build_security_report
from .report_exports import security_report_to_csv
from .report_pdf_exports import security_report_to_pdf_bytes
from app.security.taxonomy import (
    ALLOW_DECISIONS,
    BLOCK_DECISIONS,
    REVIEW_DECISIONS,
)

ROOT = Path(__file__).resolve().parents[2]
APP_DIR = Path(__file__).resolve().parent

@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="Linux Security Sandbox Platform",
    version="0.1.0",
    lifespan=lifespan,
)

templates = Jinja2Templates(directory=str(APP_DIR / "templates"))
app.mount("/static", StaticFiles(directory=str(APP_DIR / "static")), name="static")

class CommandRequest(BaseModel):
    command: list[str]

GATEWAY_DECISIONS_PATH = ROOT / "data/processed/gateway_decisions.jsonl"
PENDING_APPROVALS_PATH = ROOT / "data/processed/pending_approvals.jsonl"
APPROVAL_DECISIONS_PATH = ROOT / "data/processed/approval_decisions.jsonl"

def latest_records(path: Path, limit: int = 10):
    records = read_jsonl(path)
    return list(reversed(records[-limit:]))

def approval_statuses_by_gateway_id():
    statuses = {}

    for record in read_jsonl(APPROVAL_DECISIONS_PATH):
        decision_id = record.get("gateway_decision_id")

        if decision_id:
            statuses[decision_id] = record

    return statuses

def gateway_events(limit: int = 10):
    approvals = approval_statuses_by_gateway_id()
    records = latest_records(GATEWAY_DECISIONS_PATH, limit * 3)
    events = []

    for record in records:
        item = dict(record)
        approval = approvals.get(item.get("gateway_decision_id"))

        if approval:
            item["final_lifecycle_status"] = approval.get("approval_status")
            item["approval_admin"] = approval.get("admin")
            item["approval_reason"] = approval.get("reason")
        else:
            item["final_lifecycle_status"] = item.get("decision_status")
            item["approval_admin"] = None
            item["approval_reason"] = None

        events.append(item)

    return events[:limit]

def pending_approval_records(limit: int = 10):
    approvals = approval_statuses_by_gateway_id()
    records = []

    for record in reversed(read_jsonl(PENDING_APPROVALS_PATH)):
        decision_id = record.get("gateway_decision_id")

        if decision_id not in approvals:
            records.append(record)

        if len(records) >= limit:
            break

    return records

def gateway_dashboard_stats():
    gateway_records = read_jsonl(GATEWAY_DECISIONS_PATH)
    approval_records = read_jsonl(APPROVAL_DECISIONS_PATH)
    pending_records = pending_approval_records(100000)

    return {
        "total_gateway_decisions": len(gateway_records),
        "pending_approvals": len(pending_records),
        "rejected_commands": sum(1 for item in approval_records if item.get("approval_status") == "rejected"),
        "approved_commands": sum(1 for item in approval_records if item.get("approval_status") == "approved"),
        "critical_blocks": sum(1 for item in gateway_records if item.get("security_decision") == "block_critical"),
        "gateway_allowed": sum(1 for item in gateway_records if item.get("decision_status") == "approved_for_execution"),
    }

def utc_now_string():
    return datetime.now(timezone.utc).isoformat()

def append_jsonl(path: Path, record: dict):
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("a", encoding="utf-8") as file:
        file.write(json.dumps(record, ensure_ascii=False) + "\n")

def find_pending_approval(decision_id: str):
    for record in pending_approval_records(100000):
        if record.get("gateway_decision_id") == decision_id:
            return record

    return None

def write_web_approval_decision(decision_id: str, status: str, admin: str, reason: str):
    pending = find_pending_approval(decision_id)

    if pending is None:
        raise HTTPException(status_code=404, detail="Pending approval not found")

    record = {
        "approval_decision_id": f"{decision_id}:{status}",
        "gateway_decision_id": decision_id,
        "created_at": utc_now_string(),
        "approval_status": status,
        "admin": admin,
        "reason": reason,
        "command": pending.get("command"),
        "command_text": pending.get("command_text"),
        "risk_score": pending.get("risk_score"),
        "risk_level": pending.get("risk_level"),
        "security_decision": pending.get("security_decision"),
        "execution_strategy": pending.get("execution_strategy"),
        "approved_for_execution": status == "approved",
        "execution_started": False,
    }

    append_jsonl(APPROVAL_DECISIONS_PATH, record)
    return record

from .dashboard_service import build_dashboard_view_model, shell_context


def refresh(session: Session):
    return import_jsonl_results(session)

def stats(session: Session):
    total = session.query(func.count(AnalysisRun.run_id)).scalar() or 0
    allowed = (
        session.query(func.count(AnalysisRun.run_id))
        .filter(
            AnalysisRun.final_decision.in_(
                tuple(ALLOW_DECISIONS)
            )
        )
        .scalar()
        or 0
    )

    reviewed = (
        session.query(func.count(AnalysisRun.run_id))
        .filter(
            AnalysisRun.final_decision.in_(
                tuple(REVIEW_DECISIONS)
            )
        )
        .scalar()
        or 0
    )

    blocked = (
        session.query(func.count(AnalysisRun.run_id))
        .filter(
            AnalysisRun.final_decision.in_(
                tuple(BLOCK_DECISIONS)
            )
        )
        .scalar()
        or 0
    )
    alerts = session.query(func.count(SecurityAlert.id)).scalar() or 0
    sensitive = session.query(func.count(TriggeredRule.id)).filter(TriggeredRule.rule_id == "SENSITIVE_PATH_ACCESS").scalar() or 0

    result = {
        "total_runs": total,
        "allowed": allowed,
        "reviewed": reviewed,
        "blocked_or_investigate": blocked,
        "alerts": alerts,
        "sensitive_path_events": sensitive,
    }

    result.update(gateway_dashboard_stats())
    return result

@app.get("/", response_class=HTMLResponse)
def dashboard(
    request: Request,
    session: Session = Depends(get_session),
):
    refresh(session)

    latest_runs = (
        session.query(AnalysisRun)
        .order_by(AnalysisRun.created_at.desc())
        .limit(10)
        .all()
    )

    latest_alerts = (
        session.query(SecurityAlert)
        .order_by(SecurityAlert.created_at.desc())
        .limit(10)
        .all()
    )

    current_stats = stats(session)

    view_model = build_dashboard_view_model(
        session,
        current_stats,
    )

    context = {
        "request": request,
        "stats": current_stats,
        **view_model,

        "latest_runs": latest_runs,
        "latest_alerts": latest_alerts,
        "latest_gateway_events": gateway_events(10),

        # قائمة العناصر مفصولة عن عداد pending_approvals.
        "pending_approval_items": pending_approval_records(10),

        "latest_approval_decisions": latest_records(
            APPROVAL_DECISIONS_PATH,
            10,
        ),
    }

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        context,
    )


@app.get("/runs", response_class=HTMLResponse)
def runs_page(request: Request, session: Session = Depends(get_session)):
    refresh(session)
    runs = session.query(AnalysisRun).order_by(AnalysisRun.created_at.desc()).limit(100).all()

    return templates.TemplateResponse(request, "runs.html", {
            "request": request,
            "runs": runs,
            **shell_context(stats(session)),
        },
    )

@app.get("/runs/{run_id}", response_class=HTMLResponse)
def run_details_page(run_id: str, request: Request, session: Session = Depends(get_session)):
    refresh(session)
    run = session.get(AnalysisRun, run_id)

    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")

    syscalls = (
        session.query(SyscallEvent)
        .filter(SyscallEvent.run_id == run_id)
        .order_by(SyscallEvent.line_number.asc())
        .limit(200)
        .all()
    )

    return templates.TemplateResponse(request, "run_details.html", {
            "request": request,
            "run": run,
            "syscalls": syscalls,
            **shell_context(stats(session)),
        },
    )

@app.get("/alerts", response_class=HTMLResponse)
def alerts_page(request: Request, session: Session = Depends(get_session)):
    refresh(session)
    alerts = session.query(SecurityAlert).order_by(SecurityAlert.created_at.desc()).limit(100).all()

    return templates.TemplateResponse(request, "alerts.html", {
            "request": request,
            "alerts": alerts,
            **shell_context(stats(session)),
        },
    )

@app.get("/approvals", response_class=HTMLResponse)
def approvals_page(request: Request, session: Session = Depends(get_session)):
    refresh(session)

    return templates.TemplateResponse(request, "approvals.html", {
            "request": request,
            "stats": stats(session),
            "pending_approvals": pending_approval_records(100),
            "latest_approval_decisions": latest_records(APPROVAL_DECISIONS_PATH, 100),
            **shell_context(stats(session)),
        },
    )

@app.post("/approvals/{decision_id}/approve")
def approve_from_dashboard(
    decision_id: str,
    admin: str = "dashboard_admin",
    reason: str = "Approved from dashboard.",
):
    write_web_approval_decision(decision_id, "approved", admin, reason)
    return RedirectResponse(url="/approvals", status_code=303)

@app.post("/approvals/{decision_id}/reject")
def reject_from_dashboard(
    decision_id: str,
    admin: str = "dashboard_admin",
    reason: str = "Rejected from dashboard.",
):
    write_web_approval_decision(decision_id, "rejected", admin, reason)
    return RedirectResponse(url="/approvals", status_code=303)

@app.post("/api/gateway/approvals/{decision_id}/approve")
def api_gateway_approve(
    decision_id: str,
    admin: str = "api_admin",
    reason: str = "Approved from API.",
):
    return write_web_approval_decision(decision_id, "approved", admin, reason)

@app.post("/api/gateway/approvals/{decision_id}/reject")
def api_gateway_reject(
    decision_id: str,
    admin: str = "api_admin",
    reason: str = "Rejected from API.",
):
    return write_web_approval_decision(decision_id, "rejected", admin, reason)

@app.get("/api/stats")
def api_stats(session: Session = Depends(get_session)):
    refresh(session)
    return stats(session)

@app.get("/api/runs")
def api_runs(session: Session = Depends(get_session)):
    refresh(session)
    runs = session.query(AnalysisRun).order_by(AnalysisRun.created_at.desc()).limit(100).all()

    return [
        {
            "run_id": run.run_id,
            "command": run.command_text,
            "executable": run.executable,
            "status": run.status,
            "risk_score": run.risk_score,
            "risk_level": run.risk_level,
            "decision": run.final_decision,
            "created_at": (
                run.created_at.isoformat()
                if run.created_at
                else None
            ),
        }
        for run in runs
    ]

@app.get("/api/runs/{run_id}")
def api_run_details(run_id: str, session: Session = Depends(get_session)):
    refresh(session)
    run = session.get(AnalysisRun, run_id)

    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")

    return {
        "run_id": run.run_id,
        "command": run.command_text,
        "executable": run.executable,
        "status": run.status,
        "policy_allowed": run.policy_allowed,
        "policy_reason": run.policy_reason,
        "risk_score": run.risk_score,
        "risk_level": run.risk_level,
        "decision": run.final_decision,
        "explanation": run.security_explanation,
        "rules": [
            {
                "rule_id": rule.rule_id,
                "title": rule.title,
                "severity": rule.severity,
                "score": rule.score,
            }
            for rule in run.rules
        ],
        "alerts": [
            {
                "level": alert.level,
                "title": alert.title,
                "message": alert.message,
            }
            for alert in run.alerts
        ],
    }

@app.get("/api/gateway/decisions")
def api_gateway_decisions():
    return gateway_events(100)

@app.get("/api/gateway/pending")
def api_gateway_pending():
    return pending_approval_records(100)

@app.get("/api/gateway/approvals")
def api_gateway_approvals():
    return latest_records(APPROVAL_DECISIONS_PATH, 100)

@app.post("/api/runs/import")
def api_import(session: Session = Depends(get_session)):
    return refresh(session)

@app.post("/api/runs/execute")
def api_execute(payload: CommandRequest, session: Session = Depends(get_session)):
    if not payload.command:
        raise HTTPException(status_code=400, detail="Command is required")

    before_count = len(read_jsonl(GATEWAY_DECISIONS_PATH))

    command = [
        sys.executable,
        str(ROOT / "scripts/procsentinel_gateway.py"),
        "--",
        *payload.command,
    ]

    completed = subprocess.run(
        command,
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
    )

    if completed.returncode != 0:
        raise HTTPException(
            status_code=500,
            detail={
                "stdout": completed.stdout,
                "stderr": completed.stderr,
                "returncode": completed.returncode,
            },
        )

    refresh(session)

    gateway_records_list = read_jsonl(GATEWAY_DECISIONS_PATH)
    gateway_record = gateway_records_list[-1] if len(gateway_records_list) > before_count else None

    if gateway_record and gateway_record.get("decision_status") != "approved_for_execution":
        return {
            "gateway_decision_id": gateway_record.get("gateway_decision_id"),
            "command": gateway_record.get("command_text"),
            "status": gateway_record.get("decision_status"),
            "decision": gateway_record.get("security_decision"),
            "risk_score": gateway_record.get("risk_score"),
            "risk_level": gateway_record.get("risk_level"),
            "execution_started": False,
            "stdout": completed.stdout,
        }

    detection_records = read_jsonl(ROOT / "data/processed/detection_results.jsonl")

    if detection_records:
        run_id = detection_records[-1]["run_id"]
        run = session.get(AnalysisRun, run_id)

        if run is not None:
            return {
                "gateway_decision_id": gateway_record.get("gateway_decision_id") if gateway_record else None,
                "run_id": run.run_id,
                "command": run.command_text,
                "status": run.status,
                "risk_score": run.risk_score,
                "risk_level": run.risk_level,
                "decision": run.final_decision,
                "execution_started": True,
                "explanation": run.security_explanation,
            }

    if gateway_record:
        return {
            "gateway_decision_id": gateway_record.get("gateway_decision_id"),
            "command": gateway_record.get("command_text"),
            "status": gateway_record.get("decision_status"),
            "decision": gateway_record.get("security_decision"),
            "risk_score": gateway_record.get("risk_score"),
            "risk_level": gateway_record.get("risk_level"),
            "execution_started": gateway_record.get("decision_status") == "approved_for_execution",
            "stdout": completed.stdout,
        }

    raise HTTPException(status_code=500, detail="No gateway decision was created")


@app.get("/reports/security-summary", response_class=HTMLResponse)
def security_report_page(request: Request, session: Session = Depends(get_session)):
    report = api_security_summary(session)

    return templates.TemplateResponse(request, "security_report.html", {
            "request": request,
            "report": report,
            "summary": report.get("executive_summary", {}),
            "analysis_summary": report.get("analysis_run_summary", {}),
            "gateway_summary": report.get("gateway_summary", {}),
            "approval_summary": report.get("approval_summary", {}),
            "alert_summary": report.get("alert_summary", {}),
            "highest_risk_items": report.get("highest_risk_items", []),
            "recommendations": report.get("recommendations", []),
            **shell_context(stats(session)),
        },
    )



@app.get("/api/reports/security-summary.pdf")
def api_security_summary_pdf(session: Session = Depends(get_session)):
    report = api_security_summary(session)
    pdf_data = security_report_to_pdf_bytes(report)

    return Response(
        content=pdf_data,
        media_type="application/pdf",
        headers={
            "Content-Disposition": "attachment; filename=procsentinel_security_summary.pdf"
        },
    )

@app.get("/api/reports/security-summary.csv")
def api_security_summary_csv(session: Session = Depends(get_session)):
    report = api_security_summary(session)
    csv_data = security_report_to_csv(report)

    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=procsentinel_security_summary.csv"
        },
    )

@app.get("/api/reports/security-summary")
def api_security_summary(session: Session = Depends(get_session)):
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

@app.get("/project-overview")
def project_overview_page(
    request: Request,
    session: Session = Depends(get_session),
):
    refresh(session)

    return templates.TemplateResponse(
        request,
        "project_overview.html",
        {
            "request": request,
            **shell_context(stats(session)),
        },
    )

# Install optional dashboard authentication after all routes are registered.
from .auth import install_dashboard_auth
install_dashboard_auth(app)


from .operations_api import router as operations_router
app.include_router(operations_router)
