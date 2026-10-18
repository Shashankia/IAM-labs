"""Helios Identity. The sign-in page and the admin console.

Employees land here from an application. The IAM engineer (iam.admin) uses
the console to look at users, groups, applications, and the sign-in log.
"""

from __future__ import annotations

from urllib.parse import urlencode

import pyotp
from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for

from helios.config import DEPARTMENTS, ISSUER, LAB_PASSWORD, PAYROLL_BASE, PORTAL_BASE, ROOT
from helios.events import label_for
from helios.jit import certify, expire_due, review_rows, revoke_prod_admin
from helios.saml_util import build_response, encode_response, inflate_request, parse_authn_request
from helios.store import (
    add_role,
    audit,
    authenticate,
    create_directory_user,
    get_client,
    get_user,
    init_db,
    list_audit,
    list_clients,
    list_groups,
    list_users,
    remove_role,
    reset_db,
    set_active,
    set_mfa,
)
from helios.tokens import exchange, issue_code, jwks

app = Flask(__name__, template_folder=str(ROOT / "helios" / "templates"), static_folder=str(ROOT / "helios" / "static"))
app.secret_key = "helios-idp-lab-key"
app.config.update(
    SESSION_COOKIE_NAME="helios_idp",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    TEMPLATES_AUTO_RELOAD=True,
)

ACCOUNTS = [
    ("iam.admin", "You, the IAM engineer", "Admin console, users, applications, sign-in log"),
    ("aisha.khan", "Engineering employee", "Sign in to Leave Portal and read the token"),
    ("rahul.mehta", "Engineering manager", "Approve Aisha's leave"),
    ("sara.fernandes", "Finance manager", "Approve Vikram, and be refused for Aisha"),
    ("vikram.rao", "Finance employee", "The leaver in the HR exercise"),
    ("kabir.das", "Platform engineer", "Asks for two minutes of prod-admin"),
    ("neha.joshi", "HR, with MFA", "Hire, transfer, exit, approve privileged access"),
]


def _shell(**extra):
    user = get_user(session["user"]) if session.get("user") else None
    base = {
        "theme": "idp",
        "brand": "Helios Identity",
        "system_label": "Identity provider",
        "persona": user["display_name"] if user else "Not signed in",
        "signed_in": user,
        "active": "",
        "nav": [
            {"key": "dash", "href": "/admin", "label": "Dashboard"},
            {"key": "users", "href": "/admin/users", "label": "Users"},
            {"key": "groups", "href": "/admin/groups", "label": "Groups"},
            {"key": "apps", "href": "/admin/apps", "label": "Applications"},
            {"key": "audit", "href": "/admin/audit", "label": "Sign-in log"},
            {"key": "reviews", "href": "/admin/reviews", "label": "Access reviews"},
        ],
    }
    base.update(extra)
    return base


def _pending_app_name() -> str:
    pending = session.get("pending") or {}
    return pending.get("client_name") or ""


def _complete_pending():
    pending = session.pop("pending", None)
    user = get_user(session.get("user", ""))
    if pending is None:
        return redirect(url_for("account"))
    if user is None or not user["active"]:
        session.clear()
        flash("The account was disabled before the token was issued.", "bad")
        return redirect(url_for("login"))
    if pending["kind"] == "oidc":
        code = issue_code(
            pending["client_id"],
            pending["redirect_uri"],
            user["username"],
            pending["nonce"],
            pending["code_challenge"],
            pending["scope"],
        )
        audit("token_issued", user["username"], pending["client_id"], "A short-lived token was issued. The token itself is not in this log.")
        query = urlencode({"code": code, "state": pending["state"]})
        return redirect(f"{pending['redirect_uri']}?{query}")
    xml = build_response(user, ISSUER, pending["client_id"], pending["acs"], pending["request_id"])
    audit("saml_issued", user["username"], "Team Wiki", "A SAML assertion was posted back to the application. It is not signed in this lab.")
    return render_template(
        "idp/autopost.html",
        acs=pending["acs"],
        saml_response=encode_response(xml),
        relay_state="team-wiki",
        **_shell(),
    )


def _after_password(reused: bool):
    if not session.get("pending"):
        dest = session.pop("after_login", None)
        if dest == "admin":
            return redirect(url_for("admin_home"))
        return redirect(url_for("account"))
    if reused:
        pending = session["pending"]
        return render_template(
            "idp/sso.html",
            app_name=pending.get("client_name") or "the application",
            **_shell(active=""),
        )
    return _complete_pending()


def _require_admin():
    if not session.get("user"):
        session["after_login"] = "admin"
        return redirect(url_for("login"))
    user = get_user(session["user"])
    if user is None or "idp-admin" not in user["roles"]:
        flash("The admin console is for the IAM engineer account, iam.admin.", "bad")
        return redirect(url_for("account"))
    return None


@app.before_request
def _ready():
    init_db()
    expire_due()


@app.context_processor
def _labels():
    return {"event_label": label_for, "lab_password": LAB_PASSWORD}


@app.get("/")
def root():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        user, status = authenticate(username, password)
        if status in {"unknown", "bad_password"}:
            audit("login_failed", username.strip().lower() or "unknown", "helios", "Password was not accepted")
            flash("The username or password is wrong.", "bad")
        elif status == "disabled":
            audit("login_denied_disabled", user["username"], "helios", "Disabled accounts cannot start a new session")
            flash("This account is disabled. An exit, or an administrator, turned it off. The record was not deleted.", "bad")
        else:
            session["pre_user"] = user["username"]
            if user["mfa_required"]:
                audit("login_success", user["username"], "helios", "Password accepted. MFA is still required.")
                return redirect(url_for("mfa"))
            session["user"] = user["username"]
            session.pop("pre_user", None)
            audit("login_success", user["username"], "helios", "Password accepted. No second factor is required for this account.")
            return _after_password(False)
    return render_template("idp/login.html", accounts=ACCOUNTS, sent_by=_pending_app_name(), **_shell())


@app.route("/mfa", methods=["GET", "POST"])
def mfa():
    username = session.get("pre_user")
    user = get_user(username) if username else None
    if user is None or not user["mfa_required"] or not user.get("totp_secret"):
        return redirect(url_for("login"))
    if request.method == "POST":
        code = (request.form.get("code") or "").strip().replace(" ", "")
        if pyotp.TOTP(user["totp_secret"]).verify(code, valid_window=1):
            session["user"] = user["username"]
            session.pop("pre_user", None)
            audit("mfa_success", user["username"], "helios", "Time-based one-time code accepted")
            return _after_password(False)
        audit("mfa_failed", user["username"], "helios", "Time-based one-time code rejected")
        flash("That code is wrong or already expired. Reload this page and use the new lab code.", "bad")
    current = pyotp.TOTP(user["totp_secret"]).now()
    return render_template("idp/mfa.html", current_code=current, username=user["username"], **_shell())


@app.get("/continue")
def continue_sign_in():
    if not session.get("user"):
        return redirect(url_for("login"))
    return _complete_pending()


@app.get("/account")
def account():
    if not session.get("user"):
        return redirect(url_for("login"))
    user = get_user(session["user"])
    return render_template("idp/account.html", user=user, **_shell(active=""))


@app.get("/realms/helios/.well-known/openid-configuration")
def discovery():
    return jsonify(
        {
            "issuer": ISSUER,
            "authorization_endpoint": f"{ISSUER}/protocol/openid-connect/auth",
            "token_endpoint": f"{ISSUER}/protocol/openid-connect/token",
            "jwks_uri": f"{ISSUER}/protocol/openid-connect/certs",
            "userinfo_endpoint": f"{ISSUER}/protocol/openid-connect/userinfo",
            "end_session_endpoint": f"{ISSUER}/protocol/openid-connect/logout",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "code_challenge_methods_supported": ["S256"],
        }
    )


@app.get("/realms/helios/protocol/openid-connect/certs")
def certs():
    return jsonify(jwks())


@app.get("/realms/helios/protocol/openid-connect/auth")
def authorize():
    client_id = request.args.get("client_id", "")
    redirect_uri = request.args.get("redirect_uri", "")
    state = request.args.get("state", "")
    nonce = request.args.get("nonce", "")
    challenge = request.args.get("code_challenge", "")
    method = request.args.get("code_challenge_method", "")
    scope = request.args.get("scope", "")
    client = get_client(client_id)
    if client is None or client["protocol"] != "openid":
        return _plain("This application is not registered. An IAM engineer would add it under Applications.", 400)
    if redirect_uri != client["redirect_uri"]:
        return _plain(
            "redirect_uri mismatch. The address this app asked to return to is not the address registered for it. This is the most common SSO ticket.",
            400,
        )
    if request.args.get("response_type") != "code":
        return _plain("This identity provider only signs people in with the authorization code flow.", 400)
    if "openid" not in scope.split():
        return _plain("The request must include the openid scope.", 400)
    if method != "S256" or not challenge:
        return _plain("PKCE is required. The application must send a code_challenge using S256.", 400)
    session["pending"] = {
        "kind": "oidc",
        "client_id": client_id,
        "client_name": client["name"],
        "redirect_uri": redirect_uri,
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "scope": scope,
    }
    if session.get("user"):
        audit("sso_session_reused", session["user"], client_id, f"{client['name']} reused the existing identity session")
        return _after_password(True)
    return redirect(url_for("login"))


@app.post("/realms/helios/protocol/openid-connect/token")
def token():
    try:
        issued = exchange(
            request.form.get("code", ""),
            request.form.get("code_verifier", ""),
            request.form.get("client_id", ""),
            request.form.get("redirect_uri", ""),
        )
    except ValueError as exc:
        return jsonify(error="invalid_grant", error_description=str(exc)), 400
    return jsonify(
        {
            "token_type": issued["token_type"],
            "expires_in": issued["expires_in"],
            "id_token": issued["id_token"],
            "access_token": issued["access_token"],
        }
    )


@app.get("/realms/helios/protocol/openid-connect/userinfo")
def userinfo():
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return jsonify(error="missing token"), 401
    from helios.tokens import verify_signature

    try:
        claims = verify_signature(header.removeprefix("Bearer ").strip())
    except Exception:
        return jsonify(error="invalid token"), 401
    return jsonify(
        {
            "sub": claims["sub"],
            "name": claims.get("name"),
            "email": claims.get("email"),
            "preferred_username": claims.get("preferred_username"),
            "department": claims.get("department"),
            "groups": claims.get("groups", []),
            "roles": claims.get("roles", []),
        }
    )


@app.get("/realms/helios/protocol/openid-connect/logout")
def logout():
    actor = session.get("user") or "unknown"
    session.clear()
    audit("logout", actor, "helios", "Identity provider session ended")
    target = request.args.get("post_logout_redirect_uri", "")
    allowed = {item["post_logout_uri"] for item in list_clients()}
    if target and target in allowed:
        return redirect(target)
    return render_template("idp/signed_out.html", **_shell())


@app.get("/realms/helios/protocol/saml")
def saml_start():
    encoded = request.args.get("SAMLRequest", "")
    try:
        parsed = parse_authn_request(inflate_request(encoded))
    except Exception:
        return _plain("The SAML request could not be read.", 400)
    client = get_client(parsed["issuer"])
    if client is None or client["redirect_uri"] != parsed["acs"]:
        return _plain("This SAML application is not registered, or the reply address does not match.", 400)
    session["pending"] = {
        "kind": "saml",
        "client_id": client["client_id"],
        "client_name": client["name"],
        "acs": parsed["acs"],
        "request_id": parsed["id"],
    }
    if session.get("user"):
        audit("sso_session_reused", session["user"], "Team Wiki", "SAML sign-in reused the existing identity session")
        return _after_password(True)
    return redirect(url_for("login"))


@app.get("/admin")
def admin_home():
    blocked = _require_admin()
    if blocked:
        return blocked
    users = list_users()
    disabled = [user for user in users if not user["active"]]
    return render_template(
        "idp/admin.html",
        page="dash",
        users=users,
        disabled_count=len(disabled),
        recent=list_audit(8),
        portal=PORTAL_BASE,
        payroll=PAYROLL_BASE,
        **_shell(active="dash"),
    )


@app.post("/admin/reset")
def admin_reset():
    blocked = _require_admin()
    if blocked:
        return blocked
    try:
        reset_db()
    except OSError:
        flash("The database file is busy. Stop the lab, delete the data folder, and start again.", "bad")
        return redirect(url_for("admin_home"))
    session["user"] = "iam.admin"
    flash("The lab is back to the starting story. Sign-in sessions in the apps are now stale.", "ok")
    return redirect(url_for("admin_home"))


@app.get("/admin/users")
def admin_users():
    blocked = _require_admin()
    if blocked:
        return blocked
    return render_template("idp/admin.html", page="users", users=list_users(), departments=DEPARTMENTS, **_shell(active="users"))


@app.post("/admin/users")
def admin_users_create():
    blocked = _require_admin()
    if blocked:
        return blocked
    username = request.form.get("username", "").strip().lower()
    email = request.form.get("email", "").strip().lower()
    first = request.form.get("first_name", "").strip()
    last = request.form.get("last_name", "").strip()
    department = request.form.get("department", "")
    title = request.form.get("title", "").strip() or "Manual account"
    if not username or "@" not in email or not first or department not in DEPARTMENTS:
        flash("Username, email, first name, and department are required.", "bad")
        return redirect(url_for("admin_users"))
    if get_user(username):
        flash("That username already exists.", "bad")
        return redirect(url_for("admin_users"))
    create_directory_user(username, email, first, last, department, title)
    audit("joiner", session["user"], username, "Created by hand in the console. HR does not know about this account yet.")
    flash("Account created in the directory only. HR was not updated. Use this when the HR feed is down, and reconcile afterward.", "ok")
    return redirect(url_for("admin_user", username=username))


@app.route("/admin/users/<username>", methods=["GET", "POST"])
def admin_user(username):
    blocked = _require_admin()
    if blocked:
        return blocked
    if request.method == "POST":
        action = request.form.get("action")
        role = request.form.get("role", "")
        allowed_roles = {"employee", "manager", "hr-admin", "prod-admin", "idp-admin"}
        if action == "disable":
            set_active(username, False)
            audit("manual_disable", session["user"], username, "Disabled from the admin console")
            flash("Account disabled. A new sign-in will fail. An existing token still works until it expires.", "ok")
        elif action == "enable":
            set_active(username, True)
            audit("manual_enable", session["user"], username, "Enabled from the admin console")
            flash("Account enabled in the directory. If HR still says this person has left, the next reconcile will disable them again.", "ok")
        elif action == "mfa_on":
            set_mfa(username, True)
            audit("mfa_required_on", session["user"], username, "MFA required at the next sign-in")
            flash("MFA is now required. The next sign-in will ask for a 6-digit code.", "ok")
        elif action == "mfa_off":
            if username == "neha.joshi":
                flash("Neha keeps MFA so the lab always has one person to practise the second factor.", "bad")
            else:
                set_mfa(username, False)
                audit("mfa_required_off", session["user"], username, "MFA no longer required")
                flash("MFA is off for this account.", "ok")
        elif action == "grant" and role in allowed_roles:
            add_role(username, role)
            audit("role_granted", session["user"], username, f"Granted {role} from the console")
            flash(f"Granted {role}. Current tokens do not update until the person signs in again.", "ok")
        elif action == "revoke" and role in allowed_roles:
            if username == "iam.admin" and role == "idp-admin":
                flash("iam.admin keeps idp-admin so you can still open this console.", "bad")
            else:
                remove_role(username, role)
                audit("role_removed", session["user"], username, f"Removed {role} from the console")
                flash(f"Removed {role}.", "ok")
        return redirect(url_for("admin_user", username=username))
    user = get_user(username)
    if user is None:
        flash("No account with that username.", "bad")
        return redirect(url_for("admin_users"))
    return render_template(
        "idp/admin.html",
        page="user",
        person=user,
        role_catalog=["employee", "manager", "hr-admin", "prod-admin", "idp-admin"],
        **_shell(active="users"),
    )


@app.get("/admin/groups")
def admin_groups():
    blocked = _require_admin()
    if blocked:
        return blocked
    return render_template("idp/admin.html", page="groups", groups=list_groups(), **_shell(active="groups"))


@app.get("/admin/apps")
def admin_apps():
    blocked = _require_admin()
    if blocked:
        return blocked
    return render_template("idp/admin.html", page="apps", clients=list_clients(), issuer=ISSUER, **_shell(active="apps"))


@app.get("/admin/audit")
def admin_audit():
    blocked = _require_admin()
    if blocked:
        return blocked
    return render_template("idp/admin.html", page="audit", events=list_audit(300), **_shell(active="audit"))


@app.route("/admin/reviews", methods=["GET", "POST"])
def admin_reviews():
    blocked = _require_admin()
    if blocked:
        return blocked
    if request.method == "POST":
        username = request.form.get("username", "")
        decision = request.form.get("decision")
        try:
            if decision == "certify":
                flash(certify(session["user"], username), "ok")
            elif decision == "revoke":
                flash(revoke_prod_admin(session["user"], username), "ok")
        except ValueError as exc:
            flash(str(exc), "bad")
        return redirect(url_for("admin_reviews"))
    return render_template("idp/admin.html", page="reviews", rows=review_rows(), **_shell(active="reviews"))


@app.get("/healthz")
def healthz():
    return jsonify(ok=True, service="idp")


def _plain(message: str, status: int):
    return render_template("idp/problem.html", message=message, **_shell()), status
