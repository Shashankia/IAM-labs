"""What an application does during sign-in.

1. Build a sign-in link with a random state and a PKCE challenge.
2. Send the browser to the identity provider.
3. Receive a one-time code on the callback URL.
4. Exchange that code for tokens, sending the PKCE verifier.
5. Check the token's signature, issuer, audience, and expiry.
"""

from __future__ import annotations

from urllib.parse import urlencode

import requests

from helios.config import ISSUER
from helios.tokens import verify


class SignInError(Exception):
    pass


class OIDCClient:
    def __init__(self, client_id: str, redirect_uri: str):
        self.client_id = client_id
        self.redirect_uri = redirect_uri

    def authorization_url(self, state: str, nonce: str, challenge: str) -> str:
        query = urlencode(
            {
                "response_type": "code",
                "client_id": self.client_id,
                "redirect_uri": self.redirect_uri,
                "scope": "openid profile email",
                "state": state,
                "nonce": nonce,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            }
        )
        return f"{ISSUER}/protocol/openid-connect/auth?{query}"

    def exchange(self, code: str, verifier: str) -> tuple[dict, dict]:
        response = requests.post(
            f"{ISSUER}/protocol/openid-connect/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.redirect_uri,
                "client_id": self.client_id,
                "code_verifier": verifier,
            },
            timeout=10,
        )
        try:
            body = response.json()
        except ValueError as exc:
            raise SignInError("The identity provider did not return a token.") from exc
        if response.status_code >= 400:
            raise SignInError(body.get("error_description") or "The identity provider refused the code.")
        identity = verify(body["id_token"], self.client_id)
        access = verify(body["access_token"], self.client_id)
        return body, {"id": identity, "access": access}

    def logout_url(self, return_to: str) -> str:
        query = urlencode({"client_id": self.client_id, "post_logout_redirect_uri": return_to})
        return f"{ISSUER}/protocol/openid-connect/logout?{query}"
