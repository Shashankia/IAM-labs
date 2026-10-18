import os
import tempfile
import unittest

TEMP = tempfile.TemporaryDirectory()
os.environ["HELIOS_DATA"] = TEMP.name

from helios.config import LAB_PASSWORD, OIDC_CLIENTS, SCIM_TOKEN  # noqa: E402
from helios.jit import approve, expire_due, request_access  # noqa: E402
from helios.jml import exit_person, hire, reconcile, transfer  # noqa: E402
from helios.policy import clock_context, decide  # noqa: E402
from helios.saml_util import (  # noqa: E402
    build_authn_request,
    build_response,
    deflate_and_encode,
    inflate_request,
    parse_authn_request,
    parse_response,
)
from helios.store import (  # noqa: E402
    authenticate,
    get_user,
    init_db,
    set_active,
    update_jit,
)
from helios.tokens import exchange, issue_code, pkce_challenge, verify  # noqa: E402
import pyotp  # noqa: E402


class LabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()

    def test_seed_roles_and_mfa(self):
        rahul = get_user("rahul.mehta")
        neha = get_user("neha.joshi")
        admin = get_user("iam.admin")
        self.assertIn("manager", rahul["roles"])
        self.assertTrue(neha["mfa_required"])
        self.assertIn("idp-admin", admin["roles"])
        self.assertNotIn("prod-admin", get_user("kabir.das")["roles"])

    def test_disabled_login_is_distinct_from_a_wrong_password(self):
        set_active("vikram.rao", False)
        user, status = authenticate("vikram.rao", LAB_PASSWORD)
        self.assertEqual(status, "disabled")
        self.assertIsNotNone(user)
        _user, bad = authenticate("vikram.rao", "nope")
        self.assertEqual(bad, "bad_password")
        set_active("vikram.rao", True)

    def test_pkce_token_is_a_snapshot_for_one_app(self):
        verifier = "a" * 48
        client = OIDC_CLIENTS["leave-portal"]
        code = issue_code(client and "leave-portal", client["redirect_uri"], "aisha.khan", "nonce-1", pkce_challenge(verifier), "openid profile email")
        issued = exchange(code, verifier, "leave-portal", client["redirect_uri"])
        claims = verify(issued["id_token"], "leave-portal")
        self.assertEqual(claims["preferred_username"], "aisha.khan")
        self.assertEqual(claims["aud"], "leave-portal")
        self.assertEqual(claims["groups"], get_user("aisha.khan")["groups"])
        with self.assertRaises(Exception):
            verify(issued["id_token"], "payroll-viewer")

    def test_wrong_verifier_is_rejected(self):
        client = OIDC_CLIENTS["leave-portal"]
        code = issue_code("leave-portal", client["redirect_uri"], "aisha.khan", "n", pkce_challenge("right-verifier-value"), "openid")
        with self.assertRaises(ValueError):
            exchange(code, "wrong-verifier-value", "leave-portal", client["redirect_uri"])

    def test_hire_transfer_exit_and_reconcile(self):
        message = hire("neha.joshi", "Meera", "Iyer", "meera.iyer@helios.lab", "Engineering", "Intern", use_http=False)
        self.assertIn("Joiner", message)
        meera = get_user("meera.iyer")
        self.assertTrue(meera["active"])
        self.assertIn("Engineering", meera["groups"])
        transfer("neha.joshi", "aisha.khan@helios.lab", "Finance", use_http=False)
        aisha = get_user("aisha.khan")
        self.assertEqual(aisha["department"], "Finance")
        self.assertEqual(aisha["groups"], ["Finance"])
        self.assertIn("employee", aisha["roles"])
        exit_person("neha.joshi", "vikram.rao@helios.lab", use_http=False)
        self.assertFalse(get_user("vikram.rao")["active"])
        set_active("aisha.khan", False)
        notes = reconcile("neha.joshi", use_http=False)
        self.assertTrue(get_user("aisha.khan")["active"])
        self.assertFalse(get_user("vikram.rao")["active"])
        self.assertTrue(any("aisha.khan" in note for note in notes))

    def test_policy_allow_and_three_denies(self):
        hours = clock_context("weekday")
        closed = clock_context("sunday")
        manager = {"username": "rahul.mehta", "roles": ["employee", "manager"], "department": "Engineering"}
        employee = {"username": "aisha.khan", "roles": ["employee"], "department": "Engineering"}
        own = {"requester": "aisha.khan", "department": "Engineering"}
        other = {"requester": "vikram.rao", "department": "Finance"}
        self.assertTrue(decide(manager, own, hours)["allow"])
        self.assertFalse(decide(employee, own, hours)["allow"])
        self.assertFalse(decide(manager, other, hours)["allow"])
        self.assertFalse(decide(manager, own, closed)["allow"])

    def test_jit_expires(self):
        request_access("kabir.das", "kabir.das@helios.lab", "Investigate a failed payroll deploy")
        from helios.store import list_jit

        pending = next(item for item in list_jit() if item["username"] == "kabir.das" and item["status"] == "pending")
        approve(pending["id"], "neha.joshi")
        self.assertIn("prod-admin", get_user("kabir.das")["roles"])
        update_jit(pending["id"], expires_at="2020-01-01T00:00:00Z")
        self.assertGreaterEqual(expire_due(), 1)
        self.assertNotIn("prod-admin", get_user("kabir.das")["roles"])

    def test_totp_accepts_the_current_code(self):
        neha = get_user("neha.joshi")
        code = pyotp.TOTP(neha["totp_secret"]).now()
        self.assertTrue(pyotp.TOTP(neha["totp_secret"]).verify(code, valid_window=1))

    def test_saml_request_and_assertion_roundtrip(self):
        request_id, xml = build_authn_request("http://sp", "http://sp/acs", "http://idp/saml")
        parsed = parse_authn_request(inflate_request(deflate_and_encode(xml)))
        self.assertEqual(parsed["id"], request_id)
        self.assertEqual(parsed["acs"], "http://sp/acs")
        user = get_user("aisha.khan")
        assertion = build_response(user, "http://idp", "http://sp", "http://sp/acs", request_id)
        fields = parse_response(assertion)
        self.assertEqual(fields["name_id"], "aisha.khan")
        self.assertEqual(fields["audience"], "http://sp")
        self.assertFalse(fields["signed"])

    def test_scim_rejects_a_missing_token(self):
        from helios.payroll import app

        client = app.test_client()
        response = client.get("/scim/v2/Users")
        self.assertEqual(response.status_code, 401)
        created = client.post(
            "/scim/v2/Users",
            json={
                "userName": "contractor.one",
                "name": {"givenName": "Con", "familyName": "Tractor"},
                "emails": [{"value": "contractor.one@helios.lab"}],
                "active": True,
                "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {"department": "Platform", "title": "Contractor"},
            },
            headers={"Authorization": f"Bearer {SCIM_TOKEN}"},
        )
        self.assertEqual(created.status_code, 201)

    def test_browser_login_returns_a_code(self):
        from helios.idp import app

        client = app.test_client()
        verifier = "browser-verifier-browser-verifier-browser-verifier"
        challenge = pkce_challenge(verifier)
        redirect_uri = OIDC_CLIENTS["leave-portal"]["redirect_uri"]
        start = client.get(
            "/realms/helios/protocol/openid-connect/auth",
            query_string={
                "response_type": "code",
                "client_id": "leave-portal",
                "redirect_uri": redirect_uri,
                "scope": "openid profile email",
                "state": "state-1",
                "nonce": "nonce-1",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        self.assertEqual(start.status_code, 302)
        posted = client.post("/login", data={"username": "aisha.khan", "password": LAB_PASSWORD})
        self.assertIn("code=", posted.headers["Location"])
        self.assertIn("state=state-1", posted.headers["Location"])


if __name__ == "__main__":
    unittest.main()
