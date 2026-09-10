import logging

from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse
from kafka import KafkaAdminClient
from kafka.errors import KafkaError
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.api.dependencies import get_db
from app.core.config import settings

router = APIRouter()
logger = logging.getLogger(__name__)


@router.get("/database")
def database_health(db: Session = Depends(get_db)):
    try:
        result = db.execute(
            text("SELECT current_database(), current_user")
        ).fetchone()

        return {
            "database": result[0],
            "user": result[1],
            "status": "connected",
        }
    except SQLAlchemyError:
        logger.exception("Database health check failed")
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "unhealthy",
                "detail": "Database is unavailable",
            },
        )


@router.get("/kafka")
def kafka_health():
    """Check Kafka broker connectivity.

    This is an independent dependency check — its failure does not
    affect the overall application health endpoint.
    """
    try:
        admin = KafkaAdminClient(
            bootstrap_servers=settings.kafka_bootstrap_servers,
            request_timeout_ms=5000,
        )
        try:
            admin.list_topics()
            return {
                "kafka": "connected",
                "status": "healthy",
            }
        finally:
            admin.close()
    except KafkaError:
        logger.warning("Health check: Kafka unreachable")
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "kafka": "unreachable",
                "status": "unhealthy",
            },
        )