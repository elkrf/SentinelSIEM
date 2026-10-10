"""Authentification de la console (PBKDF2 + sessions en mémoire)."""
import hashlib
import hmac
import os
import secrets
import time

from . import db
from .config import DATA_DIR

SESSIONS: dict[str, dict] = {}
SESSION_TTL = 12 * 3600
COOKIE = "siem_session"


def _hash(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310000).hex()


def set_password(username: str, password: str):
    salt = os.urandom(16)
    db.set_private("auth", {"user": username, "salt": salt.hex(), "hash": _hash(password, salt)})


def ensure_admin():
    """Crée le compte admin au premier lancement, mot de passe dans data/admin_password.txt"""
    if db.get_private("auth"):
        return None
    pw = os.environ.get("SIEM_ADMIN_PASSWORD") or secrets.token_urlsafe(12)
    set_password("admin", pw)
    f = DATA_DIR / "admin_password.txt"
    f.write_text(f"Utilisateur : admin\nMot de passe : {pw}\n")
    os.chmod(f, 0o600)
    return pw


def check(username: str, password: str) -> bool:
    a = db.get_private("auth")
    if not a or username != a["user"]:
        return False
    return hmac.compare_digest(_hash(password, bytes.fromhex(a["salt"])), a["hash"])


def login(username: str) -> str:
    tok = secrets.token_urlsafe(32)
    SESSIONS[tok] = {"user": username, "expires": time.time() + SESSION_TTL}
    return tok


def logout(tok):
    SESSIONS.pop(tok, None)


def user_for(tok):
    s = SESSIONS.get(tok or "")
    if not s:
        return None
    if s["expires"] < time.time():
        SESSIONS.pop(tok, None)
        return None
    return s["user"]
