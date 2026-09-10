from fastapi import APIRouter

from app.api.routes import audit, auth, health, users

api_router = APIRouter()


api_router.include_router(
    health.router,
    prefix="/health",
    tags=["Health"],
)

api_router.include_router(
    auth.router,
    prefix="/auth",
    tags=["Authentication"],
)

api_router.include_router(
    users.router,
    prefix="/users",
    tags=["Users"],
)

api_router.include_router(
    audit.router,
    prefix="/audit",
    tags=["Audit"],
)