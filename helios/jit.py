"""Just-in-time privileged access and access reviews.

A person asks for prod-admin. HR approves. The role appears in the directory
for two minutes. A worker then removes it. Nobody keeps a standing admin role
from this flow.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from helios.config import JIT_MINUTES
from helios.store import (
    add_certification,
    add_role,
    audit,
    create_jit,
    due_jit,
    get_jit,
    get_user,
    latest_certification,
    list_jit,
    list_users,
    now_iso,
    remove_role,
    update_jit,
)


def _parse(stamp: str) -> datetime | None:
    if not stamp:
        return None
    return datetime.fromisoformat(stamp.replace("Z", "+00:00"))


def request_access(username: str, email: str, reason: str) -> str:
    reason = (reason or "").strip()
    if len(reason) < 8:
        raise ValueError("Write a short reason. A company will not approve a blank request.")
    for item in list_jit():
        if item["username"] == username and item["status"] in {"pending", "approved"}:
            if item["status"] == "approved":
                raise ValueError("This account already has a live privileged grant. Wait for it to expire.")
            raise ValueError("This account already has a request waiting for HR.")
    create_jit(username, email, reason)
    audit("jit_requested", username, username, reason)
    return "Request sent to HR. It does nothing until someone approves it."


def approve(request_id: int, approver: str) -> str:
    item = get_jit(request_id)
    if item is None or item["status"] != "pending":
        raise ValueError("That request is not waiting for approval.")
    if item["username"] == approver:
        raise ValueError("You cannot approve your own privileged access.")
    expires = datetime.now(timezone.utc) + timedelta(minutes=JIT_MINUTES)
    expires_stamp = expires.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    add_role(item["username"], "prod-admin")
    update_jit(
        request_id,
        status="approved",
        approver=approver,
        approved_at=now_iso(),
        expires_at=expires_stamp,
    )
    audit(
        "jit_approved",
        approver,
        item["username"],
        f"prod-admin until {expires_stamp}. Reason: {item['reason']}",
    )
    return (
        f"Approved for {JIT_MINUTES} minutes. The directory has prod-admin now. "
        "The person's current token does not. They see the new role only after a fresh sign-in, "
        "and only until this grant expires."
    )


def deny(request_id: int, approver: str) -> str:
    item = get_jit(request_id)
    if item is None or item["status"] != "pending":
        raise ValueError("That request is not waiting for approval.")
    update_jit(request_id, status="denied", approver=approver, approved_at=now_iso())
    audit("jit_denied", approver, item["username"], item["reason"])
    return "Request denied. No role was added."


def expire_due() -> int:
    count = 0
    for item in due_jit(now_iso()):
        remove_role(item["username"], "prod-admin")
        update_jit(item["id"], status="expired")
        audit("jit_expired", "worker", item["username"], "prod-admin removed because the time limit ended")
        count += 1
    return count


def review_rows() -> list[dict]:
    rows = []
    for user in list_users():
        cert = latest_certification(user["username"], "prod-admin")
        rows.append(
            {
                "username": user["username"],
                "display_name": user["display_name"],
                "department": user["department"],
                "active": user["active"],
                "roles": user["roles"],
                "has_prod_admin": "prod-admin" in user["roles"],
                "last_review": cert,
            }
        )
    return rows


def certify(reviewer: str, username: str) -> str:
    user = get_user(username)
    if user is None:
        raise ValueError("That account does not exist.")
    add_certification(reviewer, username, "roles", "certify")
    audit("review_certified", reviewer, username, "Reviewer confirmed the current roles can stay.")
    return f"Certified {user['display_name']}. Their roles were not changed."


def revoke_prod_admin(reviewer: str, username: str) -> str:
    user = get_user(username)
    if user is None or "prod-admin" not in user["roles"]:
        raise ValueError("That account does not have prod-admin.")
    remove_role(username, "prod-admin")
    for item in list_jit():
        if item["username"] == username and item["status"] == "approved":
            update_jit(item["id"], status="revoked")
    add_certification(reviewer, username, "prod-admin", "revoke")
    audit("review_revoked", reviewer, username, "Access review removed prod-admin.")
    return f"Removed prod-admin from {user['display_name']}."


def decorate_jit(items: list[dict]) -> list[dict]:
    now = datetime.now(timezone.utc)
    decorated = []
    for item in items:
        row = dict(item)
        expires = _parse(item.get("expires_at") or "")
        if item["status"] == "approved" and expires is not None:
            row["seconds_left"] = max(0, int((expires - now).total_seconds()))
        else:
            row["seconds_left"] = None
        decorated.append(row)
    return decorated
