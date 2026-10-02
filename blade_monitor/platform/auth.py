"""Autenticação (senhas, sessões, chaves de API) e autorização por papel."""
from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from .db import Database, now

ROLES = ("admin", "partner_admin", "partner_analyst", "org_admin", "org_viewer")
PARTNER_ROLES = ("partner_admin", "partner_analyst")
ORG_ROLES = ("org_admin", "org_viewer")
SESSION_HOURS = 12
MIN_PASSWORD = 10

_SCRYPT = {"n": 2**14, "r": 8, "p": 1, "dklen": 32}


class AuthError(Exception):
    pass


# ----------------------------------------------------------------- senhas

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, **_SCRYPT)
    return f"scrypt${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, salt, digest = stored.split("$")
    except ValueError:
        return False
    if algo != "scrypt":
        return False
    candidate = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), **_SCRYPT)
    return hmac.compare_digest(candidate.hex(), digest)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


# ---------------------------------------------------------------- usuários

def create_user(db: Database, email: str, password: str, role: str, *, name: str = "",
                partner_id: int | None = None, org_id: int | None = None) -> int:
    email = email.strip().lower()
    if role not in ROLES:
        raise AuthError(f"papel inválido: {role}")
    if "@" not in email or len(email) > 254:
        raise AuthError("e-mail inválido")
    if len(password) < MIN_PASSWORD:
        raise AuthError(f"a senha precisa ter ao menos {MIN_PASSWORD} caracteres")
    if role in PARTNER_ROLES and not partner_id:
        raise AuthError("usuário de parceiro precisa de partner_id")
    if role in ORG_ROLES and not org_id:
        raise AuthError("usuário de cliente precisa de org_id")
    if db.one("SELECT 1 FROM users WHERE email = ?", (email,)):
        raise AuthError("e-mail já cadastrado")
    return db.execute(
        "INSERT INTO users (email, name, password_hash, role, partner_id, org_id, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        (email, name.strip(), hash_password(password), role,
         partner_id if role in PARTNER_ROLES else None,
         org_id if role in ORG_ROLES else None, now()))


def authenticate(db: Database, email: str, password: str) -> dict:
    user = db.one("SELECT * FROM users WHERE email = ?", (email.strip().lower(),))
    # Sempre calcula o hash para não vazar, pelo tempo, se o e-mail existe.
    ok = verify_password(password, user["password_hash"] if user else hash_password("x" * 12))
    if not user or not ok or not user["active"]:
        raise AuthError("credenciais inválidas")
    db.execute("UPDATE users SET last_login = ? WHERE id = ?", (now(), user["id"]))
    return user


def get_user(db: Database, user_id: int) -> dict | None:
    return db.one("SELECT * FROM users WHERE id = ? AND active = 1", (user_id,))


# ----------------------------------------------------------------- sessões

def create_session(db: Database, user_id: int) -> tuple[str, str]:
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
    expires = (datetime.now(timezone.utc) + timedelta(hours=SESSION_HOURS)).isoformat()
    db.execute("DELETE FROM sessions WHERE expires_at < ?", (now(),))
    db.execute("INSERT INTO sessions (token_hash, user_id, csrf, expires_at) VALUES (?, ?, ?, ?)",
               (_sha256(token), user_id, csrf, expires))
    return token, csrf


def session_user(db: Database, token: str) -> tuple[dict, str] | None:
    row = db.one("SELECT user_id, csrf, expires_at FROM sessions WHERE token_hash = ?",
                 (_sha256(token),))
    if not row or row["expires_at"] < now():
        return None
    user = get_user(db, row["user_id"])
    return (user, row["csrf"]) if user else None


def end_session(db: Database, token: str) -> None:
    db.execute("DELETE FROM sessions WHERE token_hash = ?", (_sha256(token),))


# ------------------------------------------------------------ chaves de API

def create_api_key(db: Database, user_id: int, name: str) -> tuple[int, str]:
    prefix = secrets.token_hex(4)
    key = f"bm_{prefix}_{secrets.token_urlsafe(32)}"
    key_id = db.execute(
        "INSERT INTO api_keys (user_id, name, prefix, key_hash, created_at) VALUES (?, ?, ?, ?, ?)",
        (user_id, name.strip() or "api", prefix, _sha256(key), now()))
    return key_id, key


def api_key_user(db: Database, key: str) -> dict | None:
    row = db.one("SELECT id, user_id FROM api_keys WHERE key_hash = ?", (_sha256(key),))
    if not row:
        return None
    db.execute("UPDATE api_keys SET last_used = ? WHERE id = ?", (now(), row["id"]))
    return get_user(db, row["user_id"])


# ------------------------------------------------------------- autorização

def can_view_org(user: dict, org: dict) -> bool:
    role = user["role"]
    if role == "admin":
        return True
    if role in PARTNER_ROLES:
        return org["partner_id"] is not None and org["partner_id"] == user["partner_id"]
    return org["id"] == user["org_id"]


def can_edit_org(user: dict, org: dict) -> bool:
    return can_view_org(user, org) and user["role"] != "org_viewer"


def can_manage_partner(user: dict, partner_id: int) -> bool:
    return user["role"] == "admin" or (
        user["role"] == "partner_admin" and user["partner_id"] == partner_id)


def public_user(user: dict) -> dict:
    return {k: user[k] for k in ("id", "email", "name", "role", "partner_id", "org_id",
                                 "active", "created_at", "last_login")}
