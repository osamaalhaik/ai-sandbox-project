from __future__ import annotations

import csv
import io
import math
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import func, or_
from sqlalchemy.orm import Query as SQLQuery
from sqlalchemy.orm import Session

from .database import get_session
from .models import AnalysisRun, SecurityAlert


router = APIRouter(
    prefix="/api/operations",
    tags=["Operations"],
)


RUN_SORT_COLUMNS = {
    "command": AnalysisRun.command_text,
    "executable": AnalysisRun.executable,
    "status": AnalysisRun.status,
    "risk_score": AnalysisRun.risk_score,
    "risk_level": AnalysisRun.risk_level,
    "decision": AnalysisRun.final_decision,
    "created_at": AnalysisRun.created_at,
}


ALERT_SORT_COLUMNS = {
    "level": SecurityAlert.level,
    "title": SecurityAlert.title,
    "run_id": SecurityAlert.run_id,
    "created_at": SecurityAlert.created_at,
}


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _pages(total: int, page_size: int) -> int:
    return max(1, math.ceil(total / page_size))


def _apply_run_filters(
    query: SQLQuery,
    q: str | None,
    status: str | None,
    risk: str | None,
    decision: str | None,
    date_from: datetime | None,
    date_to: datetime | None,
) -> SQLQuery:
    if q:
        pattern = f"%{q.strip()}%"

        query = query.filter(
            or_(
                AnalysisRun.run_id.ilike(pattern),
                AnalysisRun.command_text.ilike(pattern),
                AnalysisRun.executable.ilike(pattern),
                AnalysisRun.status.ilike(pattern),
                AnalysisRun.risk_level.ilike(pattern),
                AnalysisRun.final_decision.ilike(pattern),
            )
        )

    if status:
        query = query.filter(
            func.lower(AnalysisRun.status)
            == status.strip().lower()
        )

    if risk:
        query = query.filter(
            func.lower(AnalysisRun.risk_level)
            == risk.strip().lower()
        )

    if decision:
        query = query.filter(
            func.lower(AnalysisRun.final_decision)
            == decision.strip().lower()
        )

    if date_from:
        query = query.filter(
            AnalysisRun.created_at >= date_from
        )

    if date_to:
        query = query.filter(
            AnalysisRun.created_at <= date_to
        )

    return query


def _apply_alert_filters(
    query: SQLQuery,
    q: str | None,
    level: str | None,
    date_from: datetime | None,
    date_to: datetime | None,
) -> SQLQuery:
    if q:
        pattern = f"%{q.strip()}%"

        query = query.filter(
            or_(
                SecurityAlert.run_id.ilike(pattern),
                SecurityAlert.level.ilike(pattern),
                SecurityAlert.title.ilike(pattern),
                SecurityAlert.message.ilike(pattern),
            )
        )

    if level:
        query = query.filter(
            func.lower(SecurityAlert.level)
            == level.strip().lower()
        )

    if date_from:
        query = query.filter(
            SecurityAlert.created_at >= date_from
        )

    if date_to:
        query = query.filter(
            SecurityAlert.created_at <= date_to
        )

    return query


def _serialize_run(run: AnalysisRun) -> dict:
    return {
        "run_id": run.run_id,
        "command": run.command_text,
        "executable": run.executable,
        "status": run.status,
        "risk_score": run.risk_score,
        "risk_level": run.risk_level,
        "decision": run.final_decision,
        "created_at": _iso(run.created_at),
    }


def _serialize_alert(alert: SecurityAlert) -> dict:
    return {
        "run_id": alert.run_id,
        "level": alert.level,
        "title": alert.title,
        "message": alert.message,
        "created_at": _iso(alert.created_at),
    }


@router.get("/runs")
def operational_runs(
    q: str | None = None,
    status: str | None = None,
    risk: str | None = None,
    decision: str | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
    sort_by: str = "created_at",
    sort_dir: Literal["asc", "desc"] = "desc",
    session: Session = Depends(get_session),
):
    query = session.query(AnalysisRun)

    query = _apply_run_filters(
        query,
        q,
        status,
        risk,
        decision,
        date_from,
        date_to,
    )

    total = query.count()

    sort_column = RUN_SORT_COLUMNS.get(
        sort_by,
        AnalysisRun.created_at,
    )

    ordering = (
        sort_column.asc()
        if sort_dir == "asc"
        else sort_column.desc()
    )

    items = (
        query.order_by(ordering)
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return {
        "items": [
            _serialize_run(item)
            for item in items
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": _pages(total, page_size),
        "sort_by": sort_by,
        "sort_dir": sort_dir,
    }


@router.get("/alerts")
def operational_alerts(
    q: str | None = None,
    level: str | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
    sort_by: str = "created_at",
    sort_dir: Literal["asc", "desc"] = "desc",
    session: Session = Depends(get_session),
):
    query = session.query(SecurityAlert)

    query = _apply_alert_filters(
        query,
        q,
        level,
        date_from,
        date_to,
    )

    total = query.count()

    sort_column = ALERT_SORT_COLUMNS.get(
        sort_by,
        SecurityAlert.created_at,
    )

    ordering = (
        sort_column.asc()
        if sort_dir == "asc"
        else sort_column.desc()
    )

    items = (
        query.order_by(ordering)
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return {
        "items": [
            _serialize_alert(item)
            for item in items
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": _pages(total, page_size),
        "sort_by": sort_by,
        "sort_dir": sort_dir,
    }


@router.get("/runs.csv")
def operational_runs_csv(
    q: str | None = None,
    status: str | None = None,
    risk: str | None = None,
    decision: str | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    sort_by: str = "created_at",
    sort_dir: Literal["asc", "desc"] = "desc",
    session: Session = Depends(get_session),
):
    query = _apply_run_filters(
        session.query(AnalysisRun),
        q,
        status,
        risk,
        decision,
        date_from,
        date_to,
    )

    sort_column = RUN_SORT_COLUMNS.get(
        sort_by,
        AnalysisRun.created_at,
    )

    ordering = (
        sort_column.asc()
        if sort_dir == "asc"
        else sort_column.desc()
    )

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(
        [
            "run_id",
            "command",
            "executable",
            "status",
            "risk_score",
            "risk_level",
            "decision",
            "created_at",
        ]
    )

    for run in query.order_by(ordering).all():
        writer.writerow(
            [
                run.run_id,
                run.command_text,
                run.executable,
                run.status,
                run.risk_score,
                run.risk_level,
                run.final_decision,
                _iso(run.created_at),
            ]
        )

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={
            "Content-Disposition":
                'attachment; filename="procsentinel-runs.csv"'
        },
    )


@router.get("/alerts.csv")
def operational_alerts_csv(
    q: str | None = None,
    level: str | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    sort_by: str = "created_at",
    sort_dir: Literal["asc", "desc"] = "desc",
    session: Session = Depends(get_session),
):
    query = _apply_alert_filters(
        session.query(SecurityAlert),
        q,
        level,
        date_from,
        date_to,
    )

    sort_column = ALERT_SORT_COLUMNS.get(
        sort_by,
        SecurityAlert.created_at,
    )

    ordering = (
        sort_column.asc()
        if sort_dir == "asc"
        else sort_column.desc()
    )

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(
        [
            "run_id",
            "level",
            "title",
            "message",
            "created_at",
        ]
    )

    for alert in query.order_by(ordering).all():
        writer.writerow(
            [
                alert.run_id,
                alert.level,
                alert.title,
                alert.message,
                _iso(alert.created_at),
            ]
        )

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={
            "Content-Disposition":
                'attachment; filename="procsentinel-alerts.csv"'
        },
    )


@router.get("/summary")
def operational_summary(
    session: Session = Depends(get_session),
):
    risk_counts = dict(
        session.query(
            AnalysisRun.risk_level,
            func.count(AnalysisRun.run_id),
        )
        .group_by(AnalysisRun.risk_level)
        .all()
    )

    decision_counts = dict(
        session.query(
            AnalysisRun.final_decision,
            func.count(AnalysisRun.run_id),
        )
        .group_by(AnalysisRun.final_decision)
        .all()
    )

    alert_counts = dict(
        session.query(
            SecurityAlert.level,
            func.count(SecurityAlert.run_id),
        )
        .group_by(SecurityAlert.level)
        .all()
    )

    return {
        "total_runs": session.query(AnalysisRun).count(),
        "total_alerts": session.query(SecurityAlert).count(),
        "risk_levels": risk_counts,
        "decisions": decision_counts,
        "alert_levels": alert_counts,
    }
