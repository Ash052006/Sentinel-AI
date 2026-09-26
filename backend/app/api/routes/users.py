from fastapi import APIRouter, Depends

from app.api.dependencies import get_current_user, require_role
from app.models.user import User

router = APIRouter()


@router.get("/me")
def get_me(current_user: User = Depends(get_current_user)):
    return {
        "id": str(current_user.id),
        "email": current_user.email,
        "is_active": current_user.is_active,
        "role": current_user.role.name if current_user.role else None,
    }


@router.get("/admin-test")
def admin_test(current_user: User = Depends(require_role("admin"))):
    return {"message": "Admin access granted"}


@router.get("/security-test")
def security_test(
    current_user: User = Depends(require_role("admin", "analyst", "ciso")),
):
    return {"message": "Security team access granted"}