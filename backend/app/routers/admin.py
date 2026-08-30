from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, field_validator

from app.services import supabase_client
from app.services.auth import CurrentUser, log_audit, require_role

router = APIRouter(prefix="/api/admin", tags=["admin"])

VALID_ROLES = ("admin", "analyst", "viewer")


class RoleChange(BaseModel):
    role: str

    @field_validator("role")
    @classmethod
    def role_is_valid(cls, value: str) -> str:
        if value not in VALID_ROLES:
            raise ValueError(f"role must be one of {VALID_ROLES}")
        return value


@router.get("/users")
def list_users(current_user: CurrentUser = Depends(require_role("admin"))):
    return {"users": supabase_client.list_user_profiles()}


@router.patch("/users/{user_id}/role")
def change_user_role(
    user_id: str,
    body: RoleChange,
    request: Request,
    current_user: CurrentUser = Depends(require_role("admin")),
):
    target = supabase_client.get_user_profile(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found.")

    updated = supabase_client.update_user_role(user_id, body.role)
    log_audit(
        request,
        current_user,
        "role_change",
        detail={"target_user": target["email"], "old_role": target["role"], "new_role": body.role},
    )
    return updated


@router.get("/audit-log")
def get_audit_log(
    limit: int = 200,
    offset: int = 0,
    current_user: CurrentUser = Depends(require_role("admin")),
):
    return {"entries": supabase_client.list_audit_log(limit=limit, offset=offset)}
