"""Leave Portal. The business application employees sign in to.

Project 1 lives on Home, Token, and Team Wiki.
Project 2 lives on the HR feed.
Project 3 lives on Leave and Approvals.
Project 4 lives on Privileged access and Access reviews.
"""

from __future__ import annotations

import base64
import json
import secrets
from datetime import datetime, timezone
from urllib.parse import quote

from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for

from helios.bags import forget, recall, remember
from helios.config import DEPARTMENTS, IDP_BASE, LAB_PASSWORD, PAYROLL_BASE, PORTAL_BASE, ROOT, SAML_ACS, SAML_ENTITY_ID
from helios.jit import approve, certify, decorate_jit, deny, list_jit, request_access, review_rows, revoke_prod_admin
from helios.jml import LifecycleError, exit_person, hire, reconcile, transfer
from helios.oidc_client import OIDCClient, SignInError
from helios.policy import clock_context, decide
from helios.saml_util import build_authn_request, deflate_and_encode, parse_response
from helios.store import add_leave, audit, decide_leave, get_leave, get_user, init_db, list_hr, list_leaves
from helios.tokens import pkce_challenge

app = Flask(__name__, template_folder=str(ROOT / "helios" / "templates"), static_folder=str(ROOT / "helios" / "static"))
app.secret_key = "helios-portal-lab-key"
app.config.update(
    SESSION_COOKIE_NAME="helios_portal",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    TEMPLATES_AUTO_RELOAD=True,
)

CLIENT = OIDCClient("leave-portal", f"{PORTAL_BASE}/callback")

CLAIM_HELP = {
    "iss": "Issuer. Trust tokens only from this exact address.",
    "aud": "Audience. This token was minted for Leave Portal, not for Payroll.",
    "azp": "The application that requested the token.",
    "exp": "Expiry. After this moment the token is dead.",
    "iat": "Issued at. This is when the snapshot was taken.",
    "sub": "The stable id of the person. In this lab it is the username.",
    "preferred_username": "The login name.",
    "name": "The display name copied from the directory at sign-in.",
    "email": "The email copied from the directory at sign-in.",
    "nonce": "Ties this token to the sign-in request you started. It blocks a stolen token from another request.",
    "department": "Department at sign-in. A later transfer does not change this token.",
    "groups": "Groups at sign-in. Companies map these into application roles.",
    "roles": "What the person could do at sign-in. A new role needs a new token.",
    "realm_access": "The same roles, in the shape Keycloak uses. Entra ID uses a different claim name for the same idea.",
    "scope": "What the application asked to receive. openid means this is an identity sign-in.",
}


def _profile():
    return recall(session.get("sid")).get("profile")


def _live(profile):
    if not profile:
        return None
    return get_user(profile["username"])


def _gap(profile, live) -> list[str]:
    if not profile or not live:
        return []
    notes = []
    if not live["active"]:
        notes.append("The directory has disabled this account. This token still opens the page until it expires. That is why token lifetime is kept short.")
    if profile.get("department") != live["department"]:
        notes.append(f"The token says {profile.get('department')}. The directory now says {live['department']}. Sign in again to refresh the snapshot.")
    token_roles = set(profile.get("roles") or [])
    live_roles = set(live["roles"])
    if token_roles != live_roles:
        added = sorted(live_roles - token_roles)
        removed = sorted(token_roles - live_roles)
        bits = []
        if added:
            bits.append("added " + ", ".join(added))
        if removed:
            bits.append("removed " + ", ".join(removed))
        notes.append("The directory has " + " and ".join(bits) + " since this token was issued. The application will not notice until the next sign-in.")
    return notes


def _shell(active: str, profile=None):
    profile = _profile() if profile is None else profile
    return {
        "theme": "portal",
        "brand": "Leave Portal",
        "system_label": "Business application",
        "persona": profile["name"] if profile else "Not signed in",
        "active": active,
        "profile": profile,
        "nav": [
            {"key": "home", "href": "/home", "label": "Home"},
            {"key": "token", "href": "/token", "label": "Your token"},
            {"key": "saml", "href": "/saml/login", "label": "Team Wiki (SAML)"},
            {"key": "leave", "href": "/leave", "label": "Request leave"},
            {"key": "approve", "href": "/approve", "label": "Approvals"},
            {"key": "priv", "href": "/privileged", "label": "Privileged access"},
            {"key": "hr", "href": "/hr", "label": "HR feed"},
            {"key": "reviews", "href": "/reviews", "label": "Access reviews"},
            {"key": "study", "href": "/study", "label": "How to study"},
        ],
    }


def _roles(profile) -> set[str]:
    return set((profile or {}).get("roles") or [])


def _can_operate(profile) -> bool:
    roles = _roles(profile)
    return "hr-admin" in roles or "idp-admin" in roles


@app.before_request
def _ready():
    init_db()


@app.get("/")
def landing():
    if _profile():
        return redirect(url_for("home"))
    return render_template("portal/landing.html", idp=IDP_BASE, **_shell("home"))


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
    if request.args.get("error"):
        flash(request.args.get("error_description") or "The identity provider stopped the sign-in.", "bad")
        return redirect(url_for("landing"))
    if not expected or request.args.get("state") != expected.get("state"):
        flash("The sign-in state did not match. Start again. This check blocks a forged callback.", "bad")
        return redirect(url_for("landing"))
    try:
        tokens, claims = CLIENT.exchange(request.args.get("code", ""), expected.get("verifier", ""))
    except SignInError as exc:
        flash(str(exc), "bad")
        return redirect(url_for("landing"))
    if claims["id"].get("nonce") != expected.get("nonce"):
        flash("The token nonce did not match this sign-in.", "bad")
        return redirect(url_for("landing"))
    identity = claims["id"]
    session["sid"] = remember(
        session.get("sid"),
        profile={
            "username": identity["preferred_username"],
            "name": identity["name"],
            "email": identity["email"],
            "department": identity["department"],
            "roles": identity["roles"],
            "groups": identity["groups"],
            "exp": identity["exp"],
            "id_token": tokens["id_token"],
            "access_token": tokens["access_token"],
            "id_claims": identity,
            "access_claims": claims["access"],
        },
    )
    session.pop("oidc", None)
    audit("login_success", identity["preferred_username"], "leave-portal", "Leave Portal accepted the token")
    return redirect(url_for("home"))


@app.get("/logout")
def logout():
    forget(session.get("sid"))
    session.clear()
    flash("Leave Portal forgot you. The identity provider session may still be there, so the next sign-in can skip the password.", "ok")
    return redirect(url_for("landing"))


@app.get("/logout/everywhere")
def logout_everywhere():
    forget(session.get("sid"))
    session.clear()
    return redirect(CLIENT.logout_url(f"{PORTAL_BASE}/"))


@app.get("/home")
def home():
    profile = _profile()
    if not profile:
        return redirect(url_for("landing"))
    live = _live(profile)
    remaining = max(0, int(profile["exp"] - datetime.now(timezone.utc).timestamp()))
    return render_template(
        "portal/home.html",
        live=live,
        gaps=_gap(profile, live),
        remaining=remaining,
        payroll=PAYROLL_BASE,
        idp=IDP_BASE,
        **_shell("home", profile),
    )


@app.get("/token")
def token_page():
    profile = _profile()
    if not profile:
        return redirect(url_for("landing"))
    claims = profile["id_claims"]
    rows = []
    for key, meaning in CLAIM_HELP.items():
        if key in claims:
            value = claims[key]
            if isinstance(value, (dict, list)):
                value = json.dumps(value)
            rows.append({"key": key, "value": value, "meaning": meaning})
    header, payload, signature = _jwt_parts(profile["id_token"])
    return render_template(
        "portal/token.html",
        rows=rows,
        header=json.dumps(header, indent=2),
        payload=json.dumps(payload, indent=2),
        signature=signature,
        remaining=max(0, int(profile["exp"] - datetime.now(timezone.utc).timestamp())),
        **_shell("token", profile),
    )


@app.route("/leave", methods=["GET", "POST"])
def leave():
    profile = _profile()
    if not profile:
        return redirect(url_for("landing"))
    live = _live(profile)
    if request.method == "POST":
        if live and not live["active"]:
            flash("This account is disabled. A disabled person should not be able to ask for leave.", "bad")
            return redirect(url_for("leave"))
        try:
            days = int(request.form.get("days", "1"))
        except ValueError:
            days = 0
        reason = (request.form.get("reason") or "").strip()
        if days < 1 or days > 20 or len(reason) < 8:
            flash("Ask for 1 to 20 days and write a short reason.", "bad")
        else:
            add_leave(profile["email"], profile["name"], profile["department"], days, reason)
            audit("leave_requested", profile["username"], profile["email"], f"{days} days. {reason}")
            flash("Request sent. A manager in your department can approve it during business hours.", "ok")
        return redirect(url_for("leave"))
    mine = [item for item in list_leaves() if item["requester_email"] == profile["email"]]
    return render_template("portal/leave.html", mine=mine, live=live, **_shell("leave", profile))


@app.route("/approve", methods=["GET", "POST"])
def approve_leave():
    profile = _profile()
    if not profile:
        return redirect(url_for("landing"))
    mode = request.values.get("clock", "weekday")
    context = clock_context(mode)
    subject = {
        "username": profile["username"],
        "roles": profile["roles"],
        "department": profile["department"],
    }
    if request.method == "POST":
        item = get_leave(int(request.form.get("leave_id", "0")))
        if item is None or item["status"] != "pending":
            flash("That request is not pending.", "bad")
            return redirect(url_for("approve_leave", clock=mode))
        resource = {"requester": item["requester_email"], "department": item["department"]}
        decision = decide(subject, resource, context)
        if decision["allow"]:
            decide_leave(item["id"], "approved", decision["reasons"][0])
            audit("leave_approved", profile["username"], item["requester_email"], decision["reasons"][0])
            flash("Approved. The policy allowed it.", "ok")
        else:
            decide_leave(item["id"], "denied", " ".join(decision["reasons"]))
            audit("leave_denied", profile["username"], item["requester_email"], " ".join(decision["reasons"]))
            flash("Denied. " + " ".join(decision["reasons"]), "bad")
        return redirect(url_for("approve_leave", clock=mode))
    cards = []
    for item in list_leaves():
        if item["status"] != "pending":
            continue
        resource = {"requester": item["requester_email"], "department": item["department"]}
        cards.append({"leave": item, "decision": decide(subject, resource, context)})
    return render_template(
        "portal/approve.html",
        cards=cards,
        context=context,
        history=[item for item in list_leaves() if item["status"] != "pending"],
        **_shell("approve", profile),
    )


@app.route("/privileged", methods=["GET", "POST"])
def privileged():
    profile = _profile()
    if not profile:
        return redirect(url_for("landing"))
    if request.method == "POST":
        action = request.form.get("action")
        try:
            if action == "request":
                flash(request_access(profile["username"], profile["email"], request.form.get("reason", "")), "ok")
            elif action == "approve" and _can_operate(profile):
                flash(approve(int(request.form["request_id"]), profile["username"]), "ok")
            elif action == "deny" and _can_operate(profile):
                flash(deny(int(request.form["request_id"]), profile["username"]), "ok")
            else:
                flash("HR approves privileged access. Sign in as neha.joshi for that step.", "bad")
        except ValueError as exc:
            flash(str(exc), "bad")
        return redirect(url_for("privileged"))
    live = _live(profile)
    return render_template(
        "portal/privileged.html",
        requests=decorate_jit(list_jit()),
        live=live,
        can_approve=_can_operate(profile),
        gaps=_gap(profile, live),
        **_shell("priv", profile),
    )


@app.route("/hr", methods=["GET", "POST"])
def hr():
    profile = _profile()
    if not profile:
        return redirect(url_for("landing"))
    if not _can_operate(profile):
        flash("The HR feed is for Neha (hr-admin) or the IAM engineer (idp-admin).", "bad")
        return redirect(url_for("home"))
    if request.method == "POST":
        action = request.form.get("action")
        try:
            if action == "hire":
                message = hire(
                    profile["username"],
                    request.form.get("first_name", ""),
                    request.form.get("last_name", ""),
                    request.form.get("email", ""),
                    request.form.get("department", ""),
                    request.form.get("title", ""),
                )
            elif action == "transfer":
                message = transfer(profile["username"], request.form.get("email", ""), request.form.get("department", ""))
            elif action == "exit":
                message = exit_person(profile["username"], request.form.get("email", ""))
            elif action == "reconcile":
                notes = reconcile(profile["username"])
                message = "Reconcile finished. " + ("; ".join(notes) if notes else "Everything already matched.")
            else:
                message = "Unknown action."
            flash(message, "ok")
        except LifecycleError as exc:
            flash(str(exc), "bad")
        return redirect(url_for("hr"))
    return render_template(
        "portal/hr.html",
        people=list_hr(),
        departments=DEPARTMENTS,
        password=LAB_PASSWORD,
        **_shell("hr", profile),
    )


@app.route("/reviews", methods=["GET", "POST"])
def reviews():
    profile = _profile()
    if not profile:
        return redirect(url_for("landing"))
    if not _can_operate(profile):
        flash("Access reviews are for HR or the IAM engineer.", "bad")
        return redirect(url_for("home"))
    if request.method == "POST":
        username = request.form.get("username", "")
        try:
            if request.form.get("decision") == "revoke":
                flash(revoke_prod_admin(profile["username"], username), "ok")
            else:
                flash(certify(profile["username"], username), "ok")
        except ValueError as exc:
            flash(str(exc), "bad")
        return redirect(url_for("reviews"))
    return render_template("portal/reviews.html", rows=review_rows(), **_shell("reviews", profile))


@app.get("/saml/login")
def saml_login():
    destination = f"{IDP_BASE}/realms/helios/protocol/saml"
    _request_id, xml = build_authn_request(SAML_ENTITY_ID, SAML_ACS, destination)
    encoded = deflate_and_encode(xml)
    return redirect(f"{destination}?SAMLRequest={quote(encoded)}&RelayState=team-wiki")


@app.get("/saml/metadata")
def saml_metadata():
    xml = (
        f"<EntityDescriptor entityID=\"{SAML_ENTITY_ID}\">"
        f"<SPSSODescriptor><AssertionConsumerService Location=\"{SAML_ACS}\" "
        f"Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"/>"
        f"</SPSSODescriptor></EntityDescriptor>"
    )
    return app.response_class(xml, mimetype="application/xml")


@app.post("/saml/acs")
def saml_acs():
    try:
        parsed = parse_response(request.form.get("SAMLResponse", ""))
    except Exception:
        flash("The SAML response could not be read.", "bad")
        return redirect(url_for("landing"))
    session["sid"] = remember(session.get("sid"), saml=parsed)
    return redirect(url_for("saml_result"))


@app.get("/saml/result")
def saml_result():
    parsed = recall(session.get("sid")).get("saml")
    if not parsed:
        return redirect(url_for("saml_login"))
    return render_template("portal/saml.html", result=parsed, **_shell("saml", _profile()))


@app.get("/study")
def study():
    return render_template("portal/study.html", idp=IDP_BASE, payroll=PAYROLL_BASE, **_shell("study", _profile()))


@app.get("/healthz")
def healthz():
    return jsonify(ok=True, service="portal")


def _jwt_parts(token: str):
    header, payload, signature = token.split(".")

    def decode(part: str):
        pad = "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(part + pad))

    return decode(header), decode(payload), signature
