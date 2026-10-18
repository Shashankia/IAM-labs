"""Issues and checks signed tokens.

The browser never comes here directly. The identity provider calls this after
the person has proved who they are. The application calls verify() before it
trusts a token. Codes and tokens are not written to the audit log.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from helios.config import ISSUER, TOKEN_TTL_SECONDS, data_dir
from helios.store import get_user, save_auth_code, take_auth_code

KID = "helios-1"


def _b64url_uint(number: int) -> str:
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _key_paths() -> tuple[Path, Path]:
    folder = data_dir()
    return folder / "idp_private.pem", folder / "idp_public.pem"


def load_keys():
    private_path, public_path = _key_paths()
    if not private_path.exists():
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        public_path.write_bytes(
            key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    private_pem = private_path.read_bytes()
    public_key = serialization.load_pem_public_key(public_path.read_bytes())
    return private_pem, public_key.public_numbers()


def jwks() -> dict:
    _, numbers = load_keys()
    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": KID,
                "n": _b64url_uint(numbers.n),
                "e": _b64url_uint(numbers.e),
            }
        ]
    }


def pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def issue_code(client_id, redirect_uri, username, nonce, code_challenge, scope) -> str:
    code = secrets.token_urlsafe(32)
    save_auth_code(
        code,
        client_id,
        redirect_uri,
        username,
        nonce,
        code_challenge,
        scope,
        int(time.time()) + 60,
    )
    return code


def _claims(user: dict, client_id: str, nonce: str, ttl: int) -> tuple[dict, dict]:
    issued = int(time.time())
    shared = {
        "iss": ISSUER,
        "sub": user["username"],
        "aud": client_id,
        "azp": client_id,
        "iat": issued,
        "exp": issued + ttl,
        "preferred_username": user["username"],
        "name": user["display_name"],
        "email": user["email"],
        "department": user["department"],
        "groups": user["groups"],
        "roles": user["roles"],
        "realm_access": {"roles": user["roles"]},
    }
    identity = dict(shared)
    identity["nonce"] = nonce
    access = dict(shared)
    access["scope"] = "openid profile email"
    return identity, access


def sign(payload: dict) -> str:
    private_pem, _numbers = load_keys()
    return jwt.encode(payload, private_pem, algorithm="RS256", headers={"kid": KID})


def verify(token: str, audience: str) -> dict:
    public_pem = _key_paths()[1].read_bytes()
    return jwt.decode(token, public_pem, algorithms=["RS256"], audience=audience, issuer=ISSUER)


def verify_signature(token: str) -> dict:
    public_pem = _key_paths()[1].read_bytes()
    return jwt.decode(
        token,
        public_pem,
        algorithms=["RS256"],
        issuer=ISSUER,
        options={"verify_aud": False},
    )


def exchange(code: str, verifier: str, client_id: str, redirect_uri: str) -> dict:
    row = take_auth_code(code)
    if row is None:
        raise ValueError("This sign-in code is missing or was already used.")
    if row["expires_at"] < int(time.time()):
        raise ValueError("This sign-in code has expired. Start the sign-in again.")
    if row["client_id"] != client_id or row["redirect_uri"] != redirect_uri:
        raise ValueError("The application details do not match the original request.")
    if pkce_challenge(verifier or "") != row["code_challenge"]:
        raise ValueError("The PKCE check failed. The application could not prove it started this sign-in.")
    user = get_user(row["username"])
    if user is None or not user["active"]:
        raise ValueError("The account is disabled, so no token was issued.")
    identity, access = _claims(user, client_id, row["nonce"], TOKEN_TTL_SECONDS)
    return {
        "token_type": "Bearer",
        "expires_in": TOKEN_TTL_SECONDS,
        "id_token": sign(identity),
        "access_token": sign(access),
        "id_claims": identity,
        "access_claims": access,
    }
