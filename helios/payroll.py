"""Payroll. The second application, plus the SCIM endpoint the worker calls.

Signing in here after Leave Portal is the single sign-on lesson.
The accounts list is the downstream copy created by joiner-mover-leaver.
"""

from __future__ import annotations

import json
import secrets

from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for

from helios.bags import forget, recall, remember
from helios.config import PAYROLL_BASE, PORTAL_BASE, ROOT, SCIM_TOKEN
from helios.events import label_for
from helios.oidc_client import OIDCClient, SignInError
from helios.store import (
    find_scim_by_id,
    find_scim_by_username,
    init_db,
    list_audit,
    list_scim_users,
    patch_scim_active,
    upsert_scim,
)
from helios.tokens import pkce_challenge

app = Flask(__name__, template_folder=str(ROOT / "helios" / "templates"), static_folder=str(ROOT / "helios" / "static"))
app.secret_key = "helios-payroll-lab-key"
app.config.update(
    SESSION_COOKIE_NAME="helios_payroll",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    TEMPLATES_AUTO_RELOAD=True,
)

CLIENT = OIDCClient("payroll-viewer", f"{PAYROLL_BASE}/callback")
EXT = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"


def _profile():
    return recall(session.get("sid")).get("profile")


def _shell(active: str):
    profile = _profile()
    return {
        "theme": "payroll",
        "brand": "Payroll",
        "system_label": "Second application",
        "persona": profile["name"] if profile else "Not signed in",
        "active": active,
        "profile": profile,
        "nav": [
            {"key": "home", "href": "/", "label": "Home"},
            {"key": "accounts", "href": "/accounts", "label": "Provisioned accounts"},
        ],
    }


def _scim_guard():
    header = request.headers.get("Authorization", "")
    if header != f"Bearer {SCIM_TOKEN}":
        body = {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "status": "401",
            "detail": "The provisioning token is missing or wrong.",
        }
        return jsonify(body), 401
    return None


def _resource(row: dict) -> dict:
    raw = json.loads(row["raw_json"] or "{}")
    raw["id"] = row["id"]
    raw.setdefault("schemas", ["urn:ietf:params:scim:schemas:core:2.0:User", EXT])
    return raw


@app.before_request
def _ready():
    init_db()


@app.get("/")
def home():
    profile = _profile()
    if not profile:
        return render_template("payroll/landing.html", portal=PORTAL_BASE, **_shell("home"))
    return render_template("payroll/home.html", portal=PORTAL_BASE, **_shell("home"))


@app.get("/login")
def login():
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    verifier = secrets.token_urlsafe(64)
    session["oidc"] = {"state": state, "nonce": nonce, "verifier": verifier}
    return redirect(CLIENT.authorization_url(state, nonce, pkce_challenge(verifier)))


@app.get("/callback")
def callback():
    expected = session.get("oidc") or {}
    if not expected or request.args.get("state") != expected.get("state"):
        flash("The sign-in state did not match. Start again from Payroll.", "bad")
        return redirect(url_for("home"))
    try:
        _tokens, claims = CLIENT.exchange(request.args.get("code", ""), expected.get("verifier", ""))
    except SignInError as exc:
        flash(str(exc), "bad")
        return redirect(url_for("home"))
    identity = claims["id"]
    if identity.get("nonce") != expected.get("nonce"):
        flash("The token nonce did not match this sign-in.", "bad")
        return redirect(url_for("home"))
    session["sid"] = remember(
        session.get("sid"),
        profile={
            "username": identity["preferred_username"],
            "name": identity["name"],
            "email": identity["email"],
            "department": identity["department"],
            "roles": identity["roles"],
            "exp": identity["exp"],
        },
    )
    session.pop("oidc", None)
    return redirect(url_for("home"))


@app.get("/logout")
def logout():
    forget(session.get("sid"))
    session.clear()
    return redirect(CLIENT.logout_url(f"{PAYROLL_BASE}/"))


@app.get("/accounts")
def accounts():
    users = list_scim_users()
    for user in users:
        try:
            user["pretty"] = json.dumps(json.loads(user["raw_json"] or "{}"), indent=2)
        except json.JSONDecodeError:
            user["pretty"] = user["raw_json"]
    pushes = [row for row in list_audit(80) if row["event"] in {"joiner", "mover", "leaver", "rehire", "reconcile", "scim_push"}]
    return render_template(
        "payroll/accounts.html",
        users=users,
        pushes=pushes,
        event_label=label_for,
        token_hint=SCIM_TOKEN,
        **_shell("accounts"),
    )


@app.get("/scim/v2/Users")
def scim_list():
    blocked = _scim_guard()
    if blocked:
        return blocked
    filt = request.args.get("filter", "")
    rows = list_scim_users()
    if filt:
        username = _filter_username(filt)
        rows = [row for row in rows if username and row["user_name"] == username]
    resources = [_resource(row) for row in rows]
    return jsonify(
        {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
            "totalResults": len(resources),
            "Resources": resources,
        }
    )


@app.post("/scim/v2/Users")
def scim_create():
    blocked = _scim_guard()
    if blocked:
        return blocked
    body = request.get_json(force=True, silent=True) or {}
    username = body.get("userName")
    if not username:
        return jsonify({"detail": "userName is required"}), 400
    if find_scim_by_username(username):
        return jsonify({"detail": "userName already exists"}), 409
    _status, row = upsert_scim(body)
    return jsonify(_resource(row)), 201


@app.put("/scim/v2/Users/<scim_id>")
def scim_replace(scim_id):
    blocked = _scim_guard()
    if blocked:
        return blocked
    if find_scim_by_id(scim_id) is None:
        return jsonify({"detail": "User not found"}), 404
    body = request.get_json(force=True, silent=True) or {}
    body["userName"] = body.get("userName") or find_scim_by_id(scim_id)["user_name"]
    _status, row = upsert_scim(body)
    return jsonify(_resource(row))


@app.patch("/scim/v2/Users/<scim_id>")
def scim_patch(scim_id):
    blocked = _scim_guard()
    if blocked:
        return blocked
    body = request.get_json(force=True, silent=True) or {}
    active = None
    for op in body.get("Operations") or []:
        if op.get("op", "").lower() == "replace" and op.get("path") == "active":
            active = bool(op.get("value"))
    if active is None:
        return jsonify({"detail": "This lab accepts a replace of the active field."}), 400
    row = patch_scim_active(scim_id, active)
    if row is None:
        return jsonify({"detail": "User not found"}), 404
    return jsonify(_resource(row))


@app.get("/healthz")
def healthz():
    return jsonify(ok=True, service="payroll")


def _filter_username(filt: str) -> str | None:
    marker = 'userName eq "'
    if marker not in filt or not filt.endswith('"'):
        return None
    return filt.split(marker, 1)[1][:-1]
