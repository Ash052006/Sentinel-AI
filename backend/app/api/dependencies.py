import logging
import uuid
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


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication token",
    )


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    # A signature-valid token must still carry a usable subject.  A token
    # minted with a non-UUID ``sub`` would otherwise reach the ``users.id``
    # comparison and surface a driver-level DataError as HTTP 500.  Anything
    # that is not a well-formed UUID is an authentication failure, not a
    # server error.  Genuine database faults are deliberately *not* caught
    # here: an outage must not be reported as a client auth failure.
    subject = decode_access_token(credentials.credentials)
    if not isinstance(subject, str):
        raise _unauthorized()
    try:
        user_id = uuid.UUID(subject)
    except (ValueError, AttributeError, TypeError):
        raise _unauthorized() from None

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