"""Joiner, mover, and leaver.

This is the one code file worth opening, and only if an interviewer asks
"what are the steps?". The order is the lesson, not the Python.

Joiner
1. Read the person from HR.
2. Create the account in the identity provider if it is missing.
3. Put them in the department group and give them the employee role.
4. Push the account to Payroll with SCIM.
5. Write an audit event.

Mover
1. Change the department in HR.
2. Change the group in the identity provider. Leave their other roles alone.
3. Push the new department to Payroll.
4. Write an audit event.

Leaver
1. Mark the person inactive in HR.
2. Disable the account in the identity provider. Do not delete it.
3. Mark the Payroll account inactive.
4. Write an audit event.

At a job, steps 2 and 3 are HTTPS calls to Entra ID, Okta, or SailPoint,
and to the application. Here those calls write the lab database, and the
Payroll step is a real HTTP call to the SCIM endpoint.
"""

from __future__ import annotations

import json
from urllib.parse import quote

import requests

from helios.config import DEPARTMENTS, LAB_PASSWORD, PAYROLL_BASE, SCIM_TOKEN
from helios.store import (
    audit,
    create_directory_user,
    ensure_employee_role,
    find_scim_by_username,
    get_hr_by_email,
    get_user,
    list_hr,
    set_active,
    set_department_group,
    upsert_hr_person,
    upsert_scim,
)

EXT = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"


class LifecycleError(Exception):
    pass


def scim_body(person: dict, active: bool) -> dict:
    return {
        "schemas": [
            "urn:ietf:params:scim:schemas:core:2.0:User",
            EXT,
        ],
        "userName": person["username"],
        "name": {"givenName": person["first_name"], "familyName": person["last_name"]},
        "emails": [{"value": person["email"], "primary": True}],
        "active": active,
        "externalId": person["email"],
        EXT: {"department": person["department"], "title": person["title"]},
    }


def _push_scim(person: dict, active: bool, use_http: bool) -> str:
    body = scim_body(person, active)
    if not use_http:
        status, _row = upsert_scim(body)
        return status
    headers = {"Authorization": f"Bearer {SCIM_TOKEN}", "Content-Type": "application/scim+json"}
    filt = quote(f'userName eq "{person["username"]}"')
    try:
        found = requests.get(
            f"{PAYROLL_BASE}/scim/v2/Users?filter={filt}",
            headers=headers,
            timeout=5,
        )
        found.raise_for_status()
        resources = found.json().get("Resources") or []
        if resources:
            scim_id = resources[0]["id"]
            response = requests.put(
                f"{PAYROLL_BASE}/scim/v2/Users/{scim_id}",
                headers=headers,
                data=json.dumps(body),
                timeout=5,
            )
        else:
            response = requests.post(
                f"{PAYROLL_BASE}/scim/v2/Users",
                headers=headers,
                data=json.dumps(body),
                timeout=5,
            )
        if response.status_code >= 400:
            raise LifecycleError(f"Payroll rejected the SCIM call ({response.status_code}). {response.text}")
        return "pushed"
    except requests.RequestException as exc:
        raise LifecycleError(
            "Payroll's SCIM endpoint is not reachable. Start the lab and open Payroll, then run the worker again."
        ) from exc


def _sync_active(person: dict, use_http: bool) -> list[str]:
    changes = []
    user = get_user(person["username"])
    if user is None:
        create_directory_user(
            person["username"],
            person["email"],
            person["first_name"],
            person["last_name"],
            person["department"],
            person["title"],
        )
        changes.append("created the identity account")
        user = get_user(person["username"])
    else:
        if not user["active"]:
            set_active(person["username"], True)
            changes.append("re-enabled the identity account")
        if user["department"] != person["department"]:
            set_department_group(person["username"], person["department"])
            changes.append(f"moved the group to {person['department']}")
    if user and "employee" not in (user["roles"] or []) and "idp-admin" not in (user["roles"] or []):
        ensure_employee_role(person["username"])
        changes.append("added the employee role")
    elif user and "employee" not in user["roles"] and person["username"] != "iam.admin":
        ensure_employee_role(person["username"])
    payroll = find_scim_by_username(person["username"])
    _push_scim(person, True, use_http)
    if payroll is None:
        changes.append("created the Payroll account through SCIM")
    elif not payroll["active"] or payroll["department"] != person["department"]:
        changes.append("updated the Payroll account through SCIM")
    return changes


def _sync_inactive(person: dict, use_http: bool) -> list[str]:
    changes = []
    user = get_user(person["username"])
    if user and user["active"]:
        set_active(person["username"], False)
        changes.append("disabled the identity account")
    payroll = find_scim_by_username(person["username"])
    if payroll is None or payroll["active"]:
        _push_scim(person, False, use_http)
        changes.append("marked the Payroll account inactive through SCIM")
    elif not use_http:
        _push_scim(person, False, use_http)
    return changes


def sync_person(email: str, use_http: bool = True) -> list[str]:
    person = get_hr_by_email(email)
    if person is None:
        raise LifecycleError("HR has no record for that email.")
    if person["active"]:
        return _sync_active(person, use_http)
    return _sync_inactive(person, use_http)


def reconcile(actor: str = "worker", use_http: bool = True) -> list[str]:
    notes = []
    for person in list_hr():
        changes = sync_person(person["email"], use_http=use_http)
        if changes:
            notes.append(f"{person['username']}: {', '.join(changes)}")
    detail = "; ".join(notes) if notes else "HR, the directory, and Payroll already match."
    audit("reconcile", actor, "helios", detail)
    return notes


def hire(actor: str, first: str, last: str, email: str, department: str, title: str, use_http: bool = True) -> str:
    email = (email or "").strip().lower()
    first = (first or "").strip()
    last = (last or "").strip()
    title = (title or "").strip() or "Employee"
    if not first or not last or "@" not in email:
        raise LifecycleError("Enter a first name, a last name, and a real email address.")
    if department not in DEPARTMENTS:
        raise LifecycleError("Choose a department that already exists as a group.")
    username = email.split("@", 1)[0]
    existing = get_hr_by_email(email)
    if existing and existing["active"]:
        raise LifecycleError(f"{existing['first_name']} {existing['last_name']} is already active in HR.")
    taken = get_user(username)
    if taken and (existing is None or existing["username"] != username):
        raise LifecycleError("That email produces a login name that already exists. Choose a different email.")
    kind = upsert_hr_person(email, username, first, last, department, title, True)
    changes = sync_person(email, use_http=use_http)
    event = "rehire" if kind == "rehire" else "joiner"
    detail = ", ".join(changes) if changes else "account already matched HR"
    detail = f"{detail}. Lab password is {LAB_PASSWORD}."
    audit(event, actor, username, detail)
    if event == "rehire":
        return f"Rehire complete for {first} {last}. The old login is active again. {detail}"
    return f"Joiner complete for {first} {last}. They can sign in as {username}. {detail}"


def transfer(actor: str, email: str, department: str, use_http: bool = True) -> str:
    person = get_hr_by_email(email)
    if person is None or not person["active"]:
        raise LifecycleError("Choose an active HR record to transfer.")
    if department not in DEPARTMENTS:
        raise LifecycleError("Choose a department that already exists as a group.")
    if person["department"] == department:
        return f"{person['first_name']} is already in {department}. Nothing changed."
    previous = person["department"]
    upsert_hr_person(
        person["email"],
        person["username"],
        person["first_name"],
        person["last_name"],
        department,
        person["title"],
        True,
    )
    changes = sync_person(person["email"], use_http=use_http)
    audit("mover", actor, person["username"], f"{previous} -> {department}. " + ", ".join(changes))
    return (
        f"Mover complete. {person['first_name']} moved from {previous} to {department}. "
        "Their current sign-in token still shows the old department until they sign in again."
    )


def exit_person(actor: str, email: str, use_http: bool = True) -> str:
    person = get_hr_by_email(email)
    if person is None:
        raise LifecycleError("HR has no record for that person.")
    if not person["active"]:
        return f"{person['first_name']} is already a leaver. The account stays disabled."
    upsert_hr_person(
        person["email"],
        person["username"],
        person["first_name"],
        person["last_name"],
        person["department"],
        person["title"],
        False,
    )
    changes = sync_person(person["email"], use_http=use_http)
    audit("leaver", actor, person["username"], ", ".join(changes) or "already disabled")
    return (
        f"Leaver complete for {person['first_name']} {person['last_name']}. "
        "The account still exists, and it is disabled in the identity provider and inactive in Payroll. "
        "A token they already hold works until it expires."
    )
