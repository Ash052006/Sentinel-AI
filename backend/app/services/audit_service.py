import logging
import uuid

from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog

logger = logging.getLogger(__name__)


def log_action(
    db: Session,
    action: str,
    user_id: uuid.UUID | None = None,
    resource: str | None = None,
    details: str | None = None,
    ip_address: str | None = None,
) -> AuditLog | None:
    """Create and persist an audit log record.

    Adds an AuditLog row to the session and commits immediately
    so the record is durable even if the caller's outer transaction
    later fails or rolls back.

    Returns the created AuditLog, or None if persistence failed
    (error is logged but never raised to the caller).
    """
    try:
        audit_log = AuditLog(
            user_id=user_id,
            action=action,
            resource=resource,
            details=details,
            ip_address=ip_address,
        )
        db.add(audit_log)
        db.commit()
        db.refresh(audit_log)
        return audit_log
    except Exception:
        logger.exception("Failed to write audit log: action=%s resource=%s", action, resource)
        db.rollback()
        return None
