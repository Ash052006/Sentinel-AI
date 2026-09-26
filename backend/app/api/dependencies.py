import logging
from collections.abc import Callable, Generator

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, selectinload

from app.core.security import decode_access_token
from app.database.postgres.session import SessionLocal
from app.models.user import User

logger = logging.getLogger(__name__)

bearer_scheme = HTTPBearer()


def get_db() -> Generator[Session, None, None]:
    try:
        db = SessionLocal()
    except SQLAlchemyError:
        logger.exception("Failed to create database session")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database is unavailable",
        )
    try:
        yield db
    finally:
        db.close()


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:

    user_id = decode_access_token(credentials.credentials)

    user = db.execute(
        select(User)
        .options(selectinload(User.role))
        .where(User.id == user_id)
    ).scalar_one_or_none()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive",
        )

    return user


def require_role(*allowed_roles: str) -> Callable:
    """Dependency factory that restricts access to users with specific roles.

    Usage:
        @router.get("/admin-only")
        def admin_endpoint(user: User = Depends(require_role("admin"))):
            ...

        @router.get("/multi-role")
        def multi_endpoint(user: User = Depends(require_role("admin", "analyst", "ciso"))):
            ...
    """

    def role_checker(
        request: Request,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db),
    ) -> User:
        if current_user.role is None or current_user.role.name not in allowed_roles:
            from app.services.audit_service import log_action

            log_action(
                db=db,
                action="auth.authorization.denied",
                user_id=current_user.id,
                resource="role_check",
                details=f"Required roles: {', '.join(allowed_roles)}",
                ip_address=request.client.host if request.client else None,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return current_user

    role_checker.__name__ = f"require_role({', '.join(allowed_roles)})"
    return role_checker