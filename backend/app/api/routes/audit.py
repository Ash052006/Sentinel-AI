from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.dependencies import get_db, require_role
from app.models.audit_log import AuditLog
from app.models.user import User
from app.schemas.audit import AuditLogListResponse

router = APIRouter()


@router.get("/logs", response_model=AuditLogListResponse)
def get_audit_logs(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin")),
) -> AuditLogListResponse:
    total = db.execute(select(func.count(AuditLog.id))).scalar_one()

    logs = (
        db.execute(
            select(AuditLog)
            .order_by(AuditLog.created_at.desc())
            .offset(skip)
            .limit(limit)
        )
        .scalars()
        .all()
    )

    return AuditLogListResponse(
        items=logs,
        total=total,
        skip=skip,
        limit=limit,
    )
