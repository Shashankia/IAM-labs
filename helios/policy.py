"""The leave rule, written the way the screen explains it.

policies/leave.rego is the same rule in policy-as-code form.
Read that file when you want to see the four lines a company would review in Git.
"""

from __future__ import annotations

from datetime import datetime
from zoneinfo import ZoneInfo

INDIA = ZoneInfo("Asia/Kolkata")


def is_business_hours(moment: datetime | None = None) -> bool:
    moment = moment or datetime.now(INDIA)
    return moment.weekday() < 5 and 9 <= moment.hour < 18


def clock_context(mode: str) -> dict:
    real = datetime.now(INDIA)
    real_ok = is_business_hours(real)
    real_label = real.strftime("%A %d %b %Y, %H:%M IST")
    if mode == "sunday":
        allowed = False
        label = "Sunday 21:00 IST (lab clock)"
    elif mode == "real":
        allowed = real_ok
        label = f"{real_label} (real clock)"
    else:
        allowed = True
        label = "Wednesday 11:00 IST (lab clock)"
    return {
        "business_hours": allowed,
        "clock": label,
        "real_label": real_label,
        "real_open": real_ok,
        "mode": mode if mode in {"sunday", "real", "weekday"} else "weekday",
    }


def decide(subject: dict, resource: dict, context: dict) -> dict:
    roles = subject.get("roles") or []
    is_manager = "manager" in roles
    same_team = subject.get("department") == resource.get("department")
    hours_ok = bool(context.get("business_hours"))
    reasons = []
    if not is_manager:
        reasons.append("Only a manager can approve leave. This account does not have the manager role.")
    elif not same_team:
        reasons.append(
            f"A manager can approve leave only for their own department. "
            f"You are in {subject.get('department')}. This leave is for {resource.get('department')}."
        )
    if not hours_ok:
        reasons.append("Approvals are allowed only on weekdays between 09:00 and 18:00 India time.")
    allow = is_manager and same_team and hours_ok
    if allow:
        reasons.append("Allowed. The approver is a manager of the same department, inside business hours.")
    return {
        "allow": allow,
        "reasons": reasons,
        "input": {
            "action": "approve_leave",
            "subject": {
                "username": subject.get("username"),
                "roles": roles,
                "department": subject.get("department"),
            },
            "resource": {
                "requester": resource.get("requester"),
                "department": resource.get("department"),
            },
            "context": {
                "business_hours": hours_ok,
                "clock": context.get("clock"),
            },
        },
    }
