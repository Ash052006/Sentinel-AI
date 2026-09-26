import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.core.config import settings
from app.core.logging import configure_logging
from app.database.postgres.session import engine

from app.api.router import api_router

configure_logging()
logger = logging.getLogger(__name__)

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    docs_url="/docs" if settings.debug else None,
    redoc_url="/redoc" if settings.debug else None,
)


# ---------------------------------------------------------------------------
# Centralized exception handlers
# ---------------------------------------------------------------------------

@app.exception_handler(Exception)
async def general_exception_handler(
    request: Request, exc: Exception
) -> JSONResponse:
    """Catch-all for unhandled exceptions. Log the full traceback but return
    a safe, generic message to the client.

    Note: HTTPException and RequestValidationError are handled by FastAPI's
    built-in handlers which already return controlled JSON responses.
    """
    logger.exception(
        "Unhandled exception: %s %s",
        request.method,
        request.url.path,
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )


# ---------------------------------------------------------------------------
# Root & health
# ---------------------------------------------------------------------------

@app.get("/")
def root():
    return {
        "message": "SentinelAI API",
        "version": settings.app_version,
        "status": "running",
    }


@app.get("/health")
def health_check():
    database_status = "unhealthy"

    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
            database_status = "healthy"
    except Exception:
        logger.warning("Health check: database unreachable")

    return {
        "status": "healthy",
        "environment": settings.environment,
        "database": database_status,
    }


app.include_router(api_router, prefix="/api")