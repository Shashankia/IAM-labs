"""SQLite tables for HR, the directory, Payroll's copy, leave, and audit.

You do not need to read this file to learn the lab. It is the filing cabinet.
The stories live in jml.py, the admin console, and the project notes in docs/.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone

import pyotp
from werkzeug.security import check_password_hash, generate_password_hash

from helios.config import GROUPS, LAB_PASSWORD, OIDC_CLIENTS, SAML_ACS, SAML_ENTITY_ID, db_path

SCHEMA = """
CREATE TABLE IF NOT EXISTS hr_people (
    email TEXT PRIMARY KEY,
    username TEXT UNIQUE,
    first_name TEXT,
    last_name TEXT,
    department TEXT,
    title TEXT,
    active INTEGER NOT NULL,
    updated_at TEXT
);
CREATE TABLE IF NOT EXISTS idp_users (
    username TEXT PRIMARY KEY,
    email TEXT UNIQUE,
    first_name TEXT,
    last_name TEXT,
    department TEXT,
    title TEXT,
    password_hash TEXT,
    active INTEGER NOT NULL,
    mfa_required INTEGER NOT NULL,
    totp_secret TEXT,
    updated_at TEXT
);
CREATE TABLE IF NOT EXISTS idp_roles (
    username TEXT NOT NULL,
    role TEXT NOT NULL,
    PRIMARY KEY (username, role)
);
CREATE TABLE IF NOT EXISTS groups (
    name TEXT PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS memberships (
    username TEXT NOT NULL,
    group_name TEXT NOT NULL,
    PRIMARY KEY (username, group_name)
);
CREATE TABLE IF NOT EXISTS clients (
    client_id TEXT PRIMARY KEY,
    name TEXT,
    protocol TEXT,
    redirect_uri TEXT,
    post_logout_uri TEXT,
    pkce_required INTEGER
);
CREATE TABLE IF NOT EXISTS auth_codes (
    code TEXT PRIMARY KEY,
    client_id TEXT,
    redirect_uri TEXT,
    username TEXT,
    nonce TEXT,
    code_challenge TEXT,
    scope TEXT,
    expires_at INTEGER
);
CREATE TABLE IF NOT EXISTS scim_users (
    id TEXT PRIMARY KEY,
    user_name TEXT UNIQUE,
    given_name TEXT,
    family_name TEXT,
    email TEXT,
    department TEXT,
    title TEXT,
    active INTEGER NOT NULL,
    external_id TEXT,
    raw_json TEXT
);
CREATE TABLE IF NOT EXISTS leaves (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    requester_email TEXT,
    requester_name TEXT,
    department TEXT,
    days INTEGER,
    reason TEXT,
    status TEXT,
    decision_notes TEXT,
    created_at TEXT
);
CREATE TABLE IF NOT EXISTS jit_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    email TEXT,
    reason TEXT,
    status TEXT,
    requested_at TEXT,
    approver TEXT,
    approved_at TEXT,
    expires_at TEXT
);
CREATE TABLE IF NOT EXISTS certifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    reviewer TEXT,
    username TEXT,
    role_name TEXT,
    decision TEXT,
    created_at TEXT
);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT,
    event TEXT,
    actor TEXT,
    target TEXT,
    detail TEXT
);
"""

PEOPLE = [
    ("aisha.khan", "aisha.khan@helios.lab", "Aisha", "Khan", "Engineering", "Software engineer", ["employee"]),
    ("rahul.mehta", "rahul.mehta@helios.lab", "Rahul", "Mehta", "Engineering", "Engineering manager", ["employee", "manager"]),
    ("vikram.rao", "vikram.rao@helios.lab", "Vikram", "Rao", "Finance", "Accountant", ["employee"]),
    ("sara.fernandes", "sara.fernandes@helios.lab", "Sara", "Fernandes", "Finance", "Finance manager", ["employee", "manager"]),
    ("neha.joshi", "neha.joshi@helios.lab", "Neha", "Joshi", "Human Resources", "HR operations", ["employee", "hr-admin"]),
    ("kabir.das", "kabir.das@helios.lab", "Kabir", "Das", "Platform", "Platform engineer", ["employee"]),
]


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(db_path(), timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    with connect() as conn:
        conn.executescript(SCHEMA)
    seed_if_empty()


def reset_db() -> None:
    base = db_path()
    for extra in ("", "-wal", "-shm"):
        path = base.parent / f"{base.name}{extra}"
        path.unlink(missing_ok=True)
    init_db()
    audit("lab_reset", "iam.admin", "helios", "Starting story restored")


def seed_if_empty() -> None:
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        count = conn.execute("SELECT COUNT(*) AS c FROM idp_users").fetchone()["c"]
        if count:
            conn.commit()
            return
        password_hash = generate_password_hash(LAB_PASSWORD)
        created = now_iso()
        for name in GROUPS:
            conn.execute("INSERT OR IGNORE INTO groups (name) VALUES (?)", (name,))
        for client_id, client in OIDC_CLIENTS.items():
            conn.execute(
                """INSERT INTO clients (client_id, name, protocol, redirect_uri, post_logout_uri, pkce_required)
                   VALUES (?, ?, 'openid', ?, ?, 1)""",
                (client_id, client["name"], client["redirect_uri"], client["post_logout_uri"]),
            )
        conn.execute(
            """INSERT INTO clients (client_id, name, protocol, redirect_uri, post_logout_uri, pkce_required)
               VALUES (?, 'Team Wiki', 'saml', ?, ?, 0)""",
            (SAML_ENTITY_ID, SAML_ACS, f"{OIDC_CLIENTS['leave-portal']['post_logout_uri']}"),
        )
        for username, email, first, last, department, title, roles in PEOPLE:
            conn.execute(
                """INSERT INTO hr_people (email, username, first_name, last_name, department, title, active, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, 1, ?)""",
                (email, username, first, last, department, title, created),
            )
            secret = pyotp.random_base32() if username == "neha.joshi" else None
            mfa = 1 if username == "neha.joshi" else 0
            _insert_user(conn, username, email, first, last, department, title, password_hash, 1, mfa, secret, created)
            for role in roles:
                conn.execute("INSERT INTO idp_roles (username, role) VALUES (?, ?)", (username, role))
            conn.execute(
                "INSERT INTO memberships (username, group_name) VALUES (?, ?)",
                (username, department),
            )
            _upsert_scim_row(
                conn,
                {
                    "userName": username,
                    "name": {"givenName": first, "familyName": last},
                    "emails": [{"value": email, "primary": True}],
                    "active": True,
                    "externalId": email,
                    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
                        "department": department,
                        "title": title,
                    },
                },
            )
        _insert_user(
            conn,
            "iam.admin",
            "iam.admin@helios.lab",
            "IAM",
            "Admin",
            "Identity",
            "IAM engineer",
            password_hash,
            1,
            0,
            None,
            created,
        )
        conn.execute("INSERT INTO idp_roles (username, role) VALUES ('iam.admin', 'idp-admin')")
        conn.execute("INSERT INTO memberships (username, group_name) VALUES ('iam.admin', 'Identity')")
        conn.execute(
            """INSERT INTO leaves (requester_email, requester_name, department, days, reason, status, decision_notes, created_at)
               VALUES (?, ?, ?, ?, ?, 'pending', '', ?)""",
            ("aisha.khan@helios.lab", "Aisha Khan", "Engineering", 2, "Family function in Jaipur", created),
        )
        conn.execute(
            """INSERT INTO leaves (requester_email, requester_name, department, days, reason, status, decision_notes, created_at)
               VALUES (?, ?, ?, ?, ?, 'pending', '', ?)""",
            ("vikram.rao@helios.lab", "Vikram Rao", "Finance", 1, "Bank work for a home loan", created),
        )
        conn.execute(
            """INSERT INTO audit (ts, event, actor, target, detail) VALUES (?, 'reconcile', 'seed', 'helios', ?)""",
            (created, "Starting story loaded. Six employees are in HR, the directory, and Payroll."),
        )
        conn.commit()


def _insert_user(conn, username, email, first, last, department, title, password_hash, active, mfa, secret, updated):
    conn.execute(
        """INSERT INTO idp_users
           (username, email, first_name, last_name, department, title, password_hash, active, mfa_required, totp_secret, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (username, email, first, last, department, title, password_hash, active, mfa, secret, updated),
    )


def _user_from_row(conn, row) -> dict | None:
    if row is None:
        return None
    user = dict(row)
    user.pop("password_hash", None)
    roles = conn.execute("SELECT role FROM idp_roles WHERE username = ? ORDER BY role", (user["username"],)).fetchall()
    groups = conn.execute(
        "SELECT group_name FROM memberships WHERE username = ? ORDER BY group_name", (user["username"],)
    ).fetchall()
    user["roles"] = [item["role"] for item in roles]
    user["groups"] = [item["group_name"] for item in groups]
    user["display_name"] = f"{user['first_name']} {user['last_name']}".strip()
    user["active"] = bool(user["active"])
    user["mfa_required"] = bool(user["mfa_required"])
    return user


def get_user(username: str) -> dict | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM idp_users WHERE username = ?", (username,)).fetchone()
        return _user_from_row(conn, row)


def list_users() -> list[dict]:
    with connect() as conn:
        rows = conn.execute("SELECT * FROM idp_users ORDER BY username").fetchall()
        return [_user_from_row(conn, row) for row in rows]


def authenticate(username: str, password: str) -> tuple[dict | None, str]:
    username = (username or "").strip().lower()
    with connect() as conn:
        row = conn.execute("SELECT * FROM idp_users WHERE username = ?", (username,)).fetchone()
        if row is None:
            return None, "unknown"
        if not check_password_hash(row["password_hash"], password or ""):
            return None, "bad_password"
        if not row["active"]:
            return _user_from_row(conn, row), "disabled"
        return _user_from_row(conn, row), "ok"


def set_active(username: str, active: bool) -> None:
    with connect() as conn:
        conn.execute(
            "UPDATE idp_users SET active = ?, updated_at = ? WHERE username = ?",
            (1 if active else 0, now_iso(), username),
        )


def set_mfa(username: str, required: bool) -> None:
    with connect() as conn:
        row = conn.execute("SELECT totp_secret FROM idp_users WHERE username = ?", (username,)).fetchone()
        if row is None:
            return
        secret = row["totp_secret"]
        if required and not secret:
            secret = pyotp.random_base32()
        conn.execute(
            "UPDATE idp_users SET mfa_required = ?, totp_secret = ?, updated_at = ? WHERE username = ?",
            (1 if required else 0, secret, now_iso(), username),
        )


def add_role(username: str, role: str) -> None:
    with connect() as conn:
        conn.execute("INSERT OR IGNORE INTO idp_roles (username, role) VALUES (?, ?)", (username, role))


def remove_role(username: str, role: str) -> None:
    with connect() as conn:
        conn.execute("DELETE FROM idp_roles WHERE username = ? AND role = ?", (username, role))


def set_department_group(username: str, department: str) -> None:
    with connect() as conn:
        conn.execute(
            "UPDATE idp_users SET department = ?, updated_at = ? WHERE username = ?",
            (department, now_iso(), username),
        )
        conn.execute("DELETE FROM memberships WHERE username = ?", (username,))
        conn.execute("INSERT INTO memberships (username, group_name) VALUES (?, ?)", (username, department))


def ensure_employee_role(username: str) -> None:
    add_role(username, "employee")


def create_directory_user(username, email, first, last, department, title) -> None:
    created = now_iso()
    with connect() as conn:
        _insert_user(
            conn,
            username,
            email,
            first,
            last,
            department,
            title,
            generate_password_hash(LAB_PASSWORD),
            1,
            0,
            None,
            created,
        )
        conn.execute("INSERT OR IGNORE INTO idp_roles (username, role) VALUES (?, 'employee')", (username,))
        conn.execute("INSERT OR IGNORE INTO memberships (username, group_name) VALUES (?, ?)", (username, department))


def list_groups() -> list[dict]:
    with connect() as conn:
        groups = []
        for row in conn.execute("SELECT name FROM groups ORDER BY name"):
            members = conn.execute(
                """SELECT u.username, u.first_name, u.last_name, u.active
                   FROM memberships m JOIN idp_users u ON u.username = m.username
                   WHERE m.group_name = ? ORDER BY u.username""",
                (row["name"],),
            ).fetchall()
            groups.append(
                {
                    "name": row["name"],
                    "members": [
                        {
                            "username": item["username"],
                            "display_name": f"{item['first_name']} {item['last_name']}",
                            "active": bool(item["active"]),
                        }
                        for item in members
                    ],
                }
            )
        return groups


def list_clients() -> list[dict]:
    with connect() as conn:
        rows = conn.execute("SELECT * FROM clients ORDER BY protocol, name").fetchall()
        return [dict(row) for row in rows]


def get_client(client_id: str) -> dict | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM clients WHERE client_id = ?", (client_id,)).fetchone()
        return dict(row) if row else None


def save_auth_code(code, client_id, redirect_uri, username, nonce, code_challenge, scope, expires_at) -> None:
    with connect() as conn:
        conn.execute("DELETE FROM auth_codes WHERE expires_at < ?", (int(datetime.now(timezone.utc).timestamp()),))
        conn.execute(
            """INSERT INTO auth_codes
               (code, client_id, redirect_uri, username, nonce, code_challenge, scope, expires_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (code, client_id, redirect_uri, username, nonce, code_challenge, scope, expires_at),
        )


def take_auth_code(code: str) -> dict | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM auth_codes WHERE code = ?", (code,)).fetchone()
        if row is None:
            return None
        conn.execute("DELETE FROM auth_codes WHERE code = ?", (code,))
        return dict(row)


def list_hr() -> list[dict]:
    with connect() as conn:
        rows = conn.execute("SELECT * FROM hr_people ORDER BY first_name").fetchall()
        people = []
        for row in rows:
            person = dict(row)
            person["active"] = bool(person["active"])
            directory = conn.execute(
                "SELECT active, department FROM idp_users WHERE username = ?", (person["username"],)
            ).fetchone()
            payroll = conn.execute(
                "SELECT active FROM scim_users WHERE user_name = ?", (person["username"],)
            ).fetchone()
            person["directory_exists"] = directory is not None
            person["directory_active"] = bool(directory["active"]) if directory else False
            person["directory_department"] = directory["department"] if directory else ""
            person["payroll_exists"] = payroll is not None
            person["payroll_active"] = bool(payroll["active"]) if payroll else False
            people.append(person)
        return people


def get_hr_by_email(email: str) -> dict | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM hr_people WHERE email = ?", (email.lower().strip(),)).fetchone()
        if row is None:
            return None
        person = dict(row)
        person["active"] = bool(person["active"])
        return person


def upsert_hr_person(email, username, first, last, department, title, active: bool) -> str:
    """Insert or update HR. Returns 'created', 'rehire', or 'updated'."""
    email = email.lower().strip()
    username = username.lower().strip()
    with connect() as conn:
        existing = conn.execute("SELECT active FROM hr_people WHERE email = ?", (email,)).fetchone()
        if existing is None:
            conn.execute(
                """INSERT INTO hr_people (email, username, first_name, last_name, department, title, active, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (email, username, first, last, department, title, 1 if active else 0, now_iso()),
            )
            return "created"
        was_active = bool(existing["active"])
        conn.execute(
            """UPDATE hr_people
               SET username = ?, first_name = ?, last_name = ?, department = ?, title = ?, active = ?, updated_at = ?
               WHERE email = ?""",
            (username, first, last, department, title, 1 if active else 0, now_iso(), email),
        )
        if active and not was_active:
            return "rehire"
        return "updated"


def list_scim_users() -> list[dict]:
    with connect() as conn:
        rows = conn.execute("SELECT * FROM scim_users ORDER BY user_name").fetchall()
        users = []
        for row in rows:
            item = dict(row)
            item["active"] = bool(item["active"])
            users.append(item)
        return users


def find_scim_by_username(username: str) -> dict | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM scim_users WHERE user_name = ?", (username,)).fetchone()
        if row is None:
            return None
        item = dict(row)
        item["active"] = bool(item["active"])
        return item


def find_scim_by_id(scim_id: str) -> dict | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM scim_users WHERE id = ?", (scim_id,)).fetchone()
        if row is None:
            return None
        item = dict(row)
        item["active"] = bool(item["active"])
        return item


def _upsert_scim_row(conn, body: dict) -> tuple[str, dict]:
    username = body["userName"]
    name = body.get("name") or {}
    emails = body.get("emails") or [{}]
    email = emails[0].get("value", "") if emails else ""
    ext_key = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
    ext = body.get(ext_key) or {}
    active = 1 if body.get("active", True) else 0
    raw = json.dumps(body)
    existing = conn.execute("SELECT id FROM scim_users WHERE user_name = ?", (username,)).fetchone()
    if existing is None:
        scim_id = str(uuid.uuid4())
        conn.execute(
            """INSERT INTO scim_users
               (id, user_name, given_name, family_name, email, department, title, active, external_id, raw_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scim_id,
                username,
                name.get("givenName", ""),
                name.get("familyName", ""),
                email,
                ext.get("department", ""),
                ext.get("title", ""),
                active,
                body.get("externalId", email),
                raw,
            ),
        )
        status = "created"
    else:
        scim_id = existing["id"]
        conn.execute(
            """UPDATE scim_users
               SET given_name = ?, family_name = ?, email = ?, department = ?, title = ?, active = ?, external_id = ?, raw_json = ?
               WHERE id = ?""",
            (
                name.get("givenName", ""),
                name.get("familyName", ""),
                email,
                ext.get("department", ""),
                ext.get("title", ""),
                active,
                body.get("externalId", email),
                raw,
                scim_id,
            ),
        )
        status = "updated"
    row = conn.execute("SELECT * FROM scim_users WHERE id = ?", (scim_id,)).fetchone()
    return status, dict(row)


def upsert_scim(body: dict) -> tuple[str, dict]:
    with connect() as conn:
        return _upsert_scim_row(conn, body)


def patch_scim_active(scim_id: str, active: bool) -> dict | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM scim_users WHERE id = ?", (scim_id,)).fetchone()
        if row is None:
            return None
        raw = json.loads(row["raw_json"] or "{}")
        raw["active"] = active
        conn.execute(
            "UPDATE scim_users SET active = ?, raw_json = ? WHERE id = ?",
            (1 if active else 0, json.dumps(raw), scim_id),
        )
        updated = conn.execute("SELECT * FROM scim_users WHERE id = ?", (scim_id,)).fetchone()
        return dict(updated)


def add_leave(email, name, department, days, reason) -> int:
    with connect() as conn:
        cur = conn.execute(
            """INSERT INTO leaves (requester_email, requester_name, department, days, reason, status, decision_notes, created_at)
               VALUES (?, ?, ?, ?, ?, 'pending', '', ?)""",
            (email, name, department, days, reason, now_iso()),
        )
        return int(cur.lastrowid)


def list_leaves() -> list[dict]:
    with connect() as conn:
        rows = conn.execute("SELECT * FROM leaves ORDER BY id DESC").fetchall()
        return [dict(row) for row in rows]


def get_leave(leave_id: int) -> dict | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM leaves WHERE id = ?", (leave_id,)).fetchone()
        return dict(row) if row else None


def decide_leave(leave_id: int, status: str, notes: str) -> None:
    with connect() as conn:
        conn.execute(
            "UPDATE leaves SET status = ?, decision_notes = ? WHERE id = ?",
            (status, notes, leave_id),
        )


def create_jit(username, email, reason) -> int:
    with connect() as conn:
        cur = conn.execute(
            """INSERT INTO jit_requests (username, email, reason, status, requested_at, approver, approved_at, expires_at)
               VALUES (?, ?, ?, 'pending', ?, '', '', '')""",
            (username, email, reason, now_iso()),
        )
        return int(cur.lastrowid)


def list_jit() -> list[dict]:
    with connect() as conn:
        rows = conn.execute("SELECT * FROM jit_requests ORDER BY id DESC").fetchall()
        return [dict(row) for row in rows]


def get_jit(request_id: int) -> dict | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM jit_requests WHERE id = ?", (request_id,)).fetchone()
        return dict(row) if row else None


def update_jit(request_id: int, **fields) -> None:
    if not fields:
        return
    columns = ", ".join(f"{key} = ?" for key in fields)
    with connect() as conn:
        conn.execute(
            f"UPDATE jit_requests SET {columns} WHERE id = ?",
            (*fields.values(), request_id),
        )


def due_jit(now_stamp: str) -> list[dict]:
    with connect() as conn:
        rows = conn.execute(
            """SELECT * FROM jit_requests
               WHERE status = 'approved' AND expires_at != '' AND expires_at <= ?""",
            (now_stamp,),
        ).fetchall()
        return [dict(row) for row in rows]


def add_certification(reviewer, username, role_name, decision) -> None:
    with connect() as conn:
        conn.execute(
            """INSERT INTO certifications (reviewer, username, role_name, decision, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (reviewer, username, role_name, decision, now_iso()),
        )


def latest_certification(username: str, role_name: str) -> dict | None:
    with connect() as conn:
        row = conn.execute(
            """SELECT * FROM certifications
               WHERE username = ? AND role_name = ?
               ORDER BY id DESC LIMIT 1""",
            (username, role_name),
        ).fetchone()
        return dict(row) if row else None


def audit(event: str, actor: str, target: str, detail: str) -> None:
    stamp = now_iso()
    with connect() as conn:
        conn.execute(
            "INSERT INTO audit (ts, event, actor, target, detail) VALUES (?, ?, ?, ?, ?)",
            (stamp, event, actor, target, detail),
        )
    print(f"[audit] {stamp} {event} actor={actor} target={target} {detail}")


def list_audit(limit: int = 200) -> list[dict]:
    with connect() as conn:
        rows = conn.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(row) for row in rows]
