from __future__ import annotations

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
)
from sqlalchemy.orm import Session

from .database import get_session
from .models import SecureExecutionRecord
from .secure_execution_store import (
    secure_execution_summary,
    serialize_secure_execution,
    sync_secure_execution_results,
)


router = APIRouter(
    prefix="/api/secure-executions",
    tags=[
        "secure-executions",
    ],
)


@router.post("/import")
def import_secure_executions(
    session: Session = Depends(
        get_session
    ),
):
    return sync_secure_execution_results(
        session
    )


@router.get("/summary")
def secure_executions_summary(
    session: Session = Depends(
        get_session
    ),
):
    sync_secure_execution_results(
        session
    )

    return secure_execution_summary(
        session
    )


@router.get("")
def list_secure_executions(
    status: str | None = None,
    profile: str | None = None,
    gateway_decision_id: str | None = None,
    page: int = Query(
        1,
        ge=1,
    ),
    page_size: int = Query(
        20,
        ge=1,
        le=100,
    ),
    session: Session = Depends(
        get_session
    ),
):
    sync_secure_execution_results(
        session
    )

    query = session.query(
        SecureExecutionRecord
    )

    if status:
        query = query.filter(
            SecureExecutionRecord.status
            == status
        )

    if profile:
        query = query.filter(
            SecureExecutionRecord
            .execution_profile
            == profile
        )

    if gateway_decision_id:
        query = query.filter(
            SecureExecutionRecord
            .gateway_decision_id
            == gateway_decision_id
        )

    total = query.count()

    items = (
        query
        .order_by(
            SecureExecutionRecord
            .created_at
            .desc()
        )
        .offset(
            (page - 1)
            * page_size
        )
        .limit(
            page_size
        )
        .all()
    )

    pages = (
        (
            total
            + page_size
            - 1
        )
        // page_size
    )

    return {
        "items": [
            serialize_secure_execution(
                item
            )
            for item in items
        ],
        "total": total,
        "page": page,
        "page_size": (
            page_size
        ),
        "pages": pages,
    }


@router.get(
    "/{secure_execution_id}"
)
def secure_execution_details(
    secure_execution_id: str,
    session: Session = Depends(
        get_session
    ),
):
    sync_secure_execution_results(
        session
    )

    record = session.get(
        SecureExecutionRecord,
        secure_execution_id,
    )

    if record is None:
        raise HTTPException(
            status_code=404,
            detail=(
                "Secure execution "
                "record not found"
            ),
        )

    return serialize_secure_execution(
        record,
        include_run_result=True,
    )
