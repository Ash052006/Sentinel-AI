"""HTTP endpoints for submitting events into the detection pipeline.

Exposes the ingestion service built in
:mod:`app.services.ingest_service` so operators can load a JSON Lines
file from the browser instead of the terminal.  Ingestion is a data-plane
write, so it is restricted to the roles that already own data entry and
is audit-logged like every other privileged mutation.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from sqlalchemy.orm import Session

from app.api.dependencies import get_db, require_role
from app.models.user import User
from app.services.audit_service import log_action
from app.services.ingest_service import (
    FORMAT_DOC,
    MAX_INGEST_BYTES,
    IngestFormat,
    IngestRuleSetUnavailableError,
    IngestSummary,
    ingest_jsonl,
)

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/format", response_model=IngestFormat)
def get_ingest_format(
    current_user: User = Depends(require_role("admin", "analyst")),
) -> IngestFormat:
    """Return the expected JSONL contract.

    The UI renders its help text and validation hints from this response so
    the field list and ``SourceType`` values are never duplicated client-side.
    """
    return FORMAT_DOC


@router.post("/events", response_model=IngestSummary)
def ingest_events(
    request: Request,
    file: UploadFile = File(
        ...,
        description="JSON Lines file (.jsonl), one event object per line.",
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "analyst")),
) -> IngestSummary:
    """Ingest an uploaded JSONL file through normalize -> detect -> persist."""
    raw = file.file.read(MAX_INGEST_BYTES + 1)
    if len(raw) > MAX_INGEST_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds the {MAX_INGEST_BYTES // (1024 * 1024)} MB limit.",
        )

    try:
        content = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="File is not valid UTF-8 text.",
        ) from exc

    if not content.strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="File is empty.",
        )

    try:
        summary = ingest_jsonl(db, content)
    except IngestRuleSetUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    log_action(
        db=db,
        action="ingest.events.received",
        user_id=current_user.id,
        resource=file.filename or "upload.jsonl",
        details=(
            f"records={summary.total_records} accepted={summary.accepted_events} "
            f"rejected={summary.rejected_records} detections={summary.detections}"
        ),
        ip_address=request.client.host if request.client else None,
    )

    if summary.rejected_records:
        logger.info(
            "Ingest partially rejected: accepted=%d rejected=%d",
            summary.accepted_events,
            summary.rejected_records,
        )

    return summary
