from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.dependencies import get_db
from app.core.security import create_access_token, hash_password, verify_password
from app.models.user import User
from app.schemas.auth import UserRegister, TokenResponse
from app.models.role import Role
from app.services.audit_service import log_action

router = APIRouter()


@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(
    user_data: UserRegister,
    request: Request,
    db: Session = Depends(get_db),
):
    existing_user = db.execute(
        select(User).where(User.email == user_data.email)
    ).scalar_one_or_none()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User with this email already exists",
        )

    role = db.execute(
        select(Role).where(Role.name == "analyst")
    ).scalar_one()

    user = User(
        email=user_data.email,
        password_hash=hash_password(user_data.password),
        is_active=True,
        role_id=role.id,
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    log_action(
        db=db,
        action="auth.register.success",
        user_id=user.id,
        resource="auth",
        details=f"Registered with role: {role.name}",
        ip_address=request.client.host if request.client else None,
    )

    return {
        "message": "User registered successfully",
        "user_id": str(user.id),
    }


@router.post("/login", response_model=TokenResponse)
def login(
    email: str,
    password: str,
    request: Request,
    db: Session = Depends(get_db),
):
    user = db.execute(
        select(User).where(User.email == email)
    ).scalar_one_or_none()

    if user is None or not verify_password(
        password,
        user.password_hash,
    ):
        log_action(
            db=db,
            action="auth.login.failed",
            resource="auth",
            details="Invalid credentials",
            ip_address=request.client.host if request.client else None,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not user.is_active:
        log_action(
            db=db,
            action="auth.login.failed",
            user_id=user.id,
            resource="auth",
            details="User account is inactive",
            ip_address=request.client.host if request.client else None,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive",
        )

    access_token = create_access_token(str(user.id))

    log_action(
        db=db,
        action="auth.login.success",
        user_id=user.id,
        resource="auth",
        ip_address=request.client.host if request.client else None,
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
    }