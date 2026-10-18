"""Server-side session bag.

The browser cookie only holds a short id. Tokens and SAML assertions stay
in this process, so they are not stuffed into the cookie.
"""

from __future__ import annotations

import secrets

STORE: dict[str, dict] = {}


def remember(sid: str | None, **updates) -> str:
    if not sid or sid not in STORE:
        sid = secrets.token_urlsafe(24)
        STORE[sid] = {}
    STORE[sid].update(updates)
    return sid


def recall(sid: str | None) -> dict:
    if not sid:
        return {}
    return STORE.get(sid, {})


def forget(sid: str | None) -> None:
    if sid:
        STORE.pop(sid, None)
