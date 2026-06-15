from dotenv import load_dotenv
load_dotenv()

"""
SecureLogin - Application Authentication System
================================================
A production-grade Flask web application demonstrating secure
authentication, session management, and OWASP best practices.

Author: Mallangouda Biradar
Tech Stack: Python, Flask, SQLite, bcrypt (PBKDF2), JWT
"""

import os
import sqlite3
import secrets
import hashlib
import hmac
import time
import jwt
import json
from datetime import datetime, timezone
from functools import wraps
from flask import (
    Flask, request, jsonify, render_template,
    redirect, url_for, session, g
)

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
#  CONFIGURATION
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

class Config:
    SECRET_KEY          = os.environ.get("SECRET_KEY", secrets.token_hex(32))
    JWT_SECRET          = os.environ.get("JWT_SECRET", secrets.token_hex(32))
    JWT_EXPIRY_SECONDS  = 3600          # 1 hour
    DATABASE            = "securelogin.db"
    MAX_LOGIN_ATTEMPTS  = 5
    LOCKOUT_SECONDS     = 300           # 5 minutes
    RATE_LIMIT_WINDOW   = 60            # seconds
    RATE_LIMIT_MAX      = 10            # requests per window per IP
    PBKDF2_ITERATIONS   = 390000        # OWASP recommended minimum (2023)


app = Flask(__name__)
app.config.from_object(Config)

# In-memory rate limiting store  { ip: [timestamp, ...] }
rate_limit_store: dict = {}


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
#  DATABASE
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def get_db():
    """Return a thread-local SQLite connection."""
    if "db" not in g:
        g.db = sqlite3.connect(
            app.config["DATABASE"],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Create tables on first run."""
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            username        TEXT    NOT NULL UNIQUE,
            email           TEXT    NOT NULL UNIQUE,
            password_hash   TEXT    NOT NULL,
            salt            TEXT    NOT NULL,
            created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
            is_active       INTEGER NOT NULL DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS login_attempts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT    NOT NULL,
            ip_address  TEXT    NOT NULL,
            success     INTEGER NOT NULL,
            attempted_at TEXT   NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS sessions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            jti         TEXT    NOT NULL UNIQUE,
            issued_at   TEXT    NOT NULL,
            expires_at  TEXT    NOT NULL,
            revoked     INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS csrf_tokens (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            session_jti TEXT NOT NULL,
            token       TEXT NOT NULL UNIQUE,
            used        INTEGER NOT NULL DEFAULT 0
        );
    """)
    db.commit()


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
#  PASSWORD HASHING  (bcrypt-equivalent via PBKDF2-HMAC-SHA256)
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# NOTE: On your local machine, replace these two functions with:
#   import bcrypt
#   def hash_password(plain):  return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode(), ""
#   def verify_password(plain, hashed, _salt): return bcrypt.checkpw(plain.encode(), hashed.encode())

def hash_password(plain_text: str) -> tuple[str, str]:
    """
    Hash a password using PBKDF2-HMAC-SHA256.
    Returns (hash_hex, salt_hex).
    """
    salt = secrets.token_bytes(32)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        plain_text.encode("utf-8"),
        salt,
        app.config["PBKDF2_ITERATIONS"]
    )
    return dk.hex(), salt.hex()


def verify_password(plain_text: str, stored_hash: str, stored_salt: str) -> bool:
    """Constant-time password comparison (prevents timing attacks)."""
    salt = bytes.fromhex(stored_salt)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        plain_text.encode("utf-8"),
        salt,
        app.config["PBKDF2_ITERATIONS"]
    )
    return hmac.compare_digest(dk.hex(), stored_hash)


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
#  JWT UTILITIES
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def generate_token(user_id: int, username: str) -> dict:
    """Issue a signed JWT with a unique JTI for revocation support."""
    jti = secrets.token_hex(16)
    now = datetime.now(timezone.utc)
    expiry = int(now.timestamp()) + app.config["JWT_EXPIRY_SECONDS"]

    payload = {
        "sub":      str(user_id),
        "username": username,
        "jti":      jti,
        "iat":      int(now.timestamp()),
        "exp":      expiry,
    }
    token = jwt.encode(payload, app.config["JWT_SECRET"], algorithm="HS256")

    # Store JTI in DB for revocation
    db = get_db()
    db.execute(
        "INSERT INTO sessions (user_id, jti, issued_at, expires_at) VALUES (?, ?, ?, ?)",
        (user_id, jti, now.isoformat(), datetime.fromtimestamp(expiry, timezone.utc).isoformat())
    )
    db.commit()
    return {"token": token, "jti": jti, "expires_at": expiry}


def decode_token(token: str) -> dict | None:
    """Decode and validate a JWT; check DB for revocation."""
    try:
        payload = jwt.decode(token, app.config["JWT_SECRET"], algorithms=["HS256"])
        # Check revocation
        db = get_db()
        row = db.execute(
            "SELECT revoked FROM sessions WHERE jti = ?", (payload["jti"],)
        ).fetchone()
        if row is None or row["revoked"]:
            return None
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
#  CSRF PROTECTION
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def generate_csrf_token(jti: str) -> str:
    """Generate a single-use CSRF token bound to a session JTI."""
    token = secrets.token_urlsafe(32)
    db = get_db()
    db.execute("INSERT INTO csrf_tokens (session_jti, token) VALUES (?, ?)", (jti, token))
    db.commit()
    return token


def validate_csrf_token(jti: str, token: str) -> bool:
    """Validate and consume a CSRF token (single-use)."""
    db = get_db()
    row = db.execute(
        "SELECT id FROM csrf_tokens WHERE session_jti = ? AND token = ? AND used = 0",
        (jti, token)
    ).fetchone()
    if not row:
        return False
    db.execute("UPDATE csrf_tokens SET used = 1 WHERE id = ?", (row["id"],))
    db.commit()
    return True


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
#  RATE LIMITING
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def is_rate_limited(ip: str) -> bool:
    """Sliding-window rate limiter (in-memory)."""
    now = time.time()
    window = app.config["RATE_LIMIT_WINDOW"]
    max_requests = app.config["RATE_LIMIT_MAX"]

    timestamps = rate_limit_store.get(ip, [])
    # Keep only timestamps within current window
    timestamps = [t for t in timestamps if now - t < window]
    timestamps.append(now)
    rate_limit_store[ip] = timestamps

    return len(timestamps) > max_requests


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
#  ACCOUNT LOCKOUT
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def is_account_locked(username: str) -> bool:
    """
    Lock account after MAX_LOGIN_ATTEMPTS failures within LOCKOUT_SECONDS.
    """
    db = get_db()
    cutoff = datetime.now(timezone.utc).timestamp() - app.config["LOCKOUT_SECONDS"]
    cutoff_str = datetime.fromtimestamp(cutoff, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    row = db.execute(
        """SELECT COUNT(*) as cnt FROM login_attempts
           WHERE username = ? AND success = 0
           AND attempted_at > ?""",
        (username, cutoff_str)
    ).fetchone()
    return row["cnt"] >= app.config["MAX_LOGIN_ATTEMPTS"]


def record_attempt(username: str, ip: str, success: bool):
    """Log every login attempt for auditing and lockout checks."""
    db = get_db()
    db.execute(
        "INSERT INTO login_attempts (username, ip_address, success) VALUES (?, ?, ?)",
        (username, ip, 1 if success else 0)
    )
    db.commit()


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
#  AUTH DECORATOR
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def require_auth(f):
    """JWT authentication decorator for protected routes."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid Authorization header"}), 401

        token = auth_header.split(" ", 1)[1]
        payload = decode_token(token)
        if not payload:
            return jsonify({"error": "Token invalid or expired"}), 401

        g.current_user = payload
        return f(*args, **kwargs)
    return decorated


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
#  ROUTES â€” AUTH API
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@app.route("/api/register", methods=["POST"])
def register():
    """
    POST /api/register
    Body: { "username": "...", "email": "...", "password": "..." }
    """
    ip = request.remote_addr

    if is_rate_limited(ip):
        return jsonify({"error": "Too many requests. Please slow down."}), 429

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "JSON body required"}), 400

    username = (data.get("username") or "").strip()
    email    = (data.get("email")    or "").strip().lower()
    password = (data.get("password") or "")

    # â”€â”€ Input Validation â”€â”€
    errors = []
    if not username or len(username) < 3:
        errors.append("Username must be at least 3 characters.")
    if len(username) > 30:
        errors.append("Username must be 30 characters or fewer.")
    if not email or "@" not in email:
        errors.append("Valid email required.")
    if len(password) < 8:
        errors.append("Password must be at least 8 characters.")
    if not any(c.isupper() for c in password):
        errors.append("Password must contain at least one uppercase letter.")
    if not any(c.isdigit() for c in password):
        errors.append("Password must contain at least one digit.")
    if errors:
        return jsonify({"errors": errors}), 422

    db = get_db()

    # Check uniqueness
    existing = db.execute(
        "SELECT id FROM users WHERE username = ? OR email = ?", (username, email)
    ).fetchone()
    if existing:
        # Generic message â€” don't reveal which field already exists (user enumeration prevention)
        return jsonify({"error": "Username or email already registered."}), 409

    pw_hash, salt = hash_password(password)

    db.execute(
        "INSERT INTO users (username, email, password_hash, salt) VALUES (?, ?, ?, ?)",
        (username, email, pw_hash, salt)
    )
    db.commit()

    return jsonify({"message": f"Account created for '{username}'. Please log in."}), 201


@app.route("/api/login", methods=["POST"])
def login():
    """
    POST /api/login
    Body: { "username": "...", "password": "..." }
    Returns: { "token": "...", "expires_at": ... }
    """
    ip = request.remote_addr

    if is_rate_limited(ip):
        return jsonify({"error": "Too many requests. Please try again later."}), 429

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "JSON body required"}), 400

    username = (data.get("username") or "").strip()
    password = (data.get("password") or "")

    if not username or not password:
        return jsonify({"error": "Username and password required."}), 400

    # Lockout check BEFORE hitting DB with password
    if is_account_locked(username):
        return jsonify({
            "error": f"Account locked due to too many failed attempts. "
                     f"Try again in {app.config['LOCKOUT_SECONDS'] // 60} minutes."
        }), 423

    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE username = ? AND is_active = 1", (username,)
    ).fetchone()

    # Always run verify_password to prevent timing-based user enumeration
    dummy_hash, dummy_salt = hash_password("dummy_password_for_timing")
    stored_hash = user["password_hash"] if user else dummy_hash
    stored_salt = user["salt"]          if user else dummy_salt

    password_ok = verify_password(password, stored_hash, stored_salt)

    if not user or not password_ok:
        record_attempt(username, ip, success=False)
        # Generic error â€” don't reveal whether username exists
        return jsonify({"error": "Invalid username or password."}), 401

    record_attempt(username, ip, success=True)

    token_data = generate_token(user["id"], user["username"])
    csrf = generate_csrf_token(token_data["jti"])

    return jsonify({
        "message": f"Welcome back, {user['username']}!",
        "token":      token_data["token"],
        "expires_at": token_data["expires_at"],
        "csrf_token": csrf,
    }), 200


@app.route("/api/logout", methods=["POST"])
@require_auth
def logout():
    """
    POST /api/logout
    Header: Authorization: Bearer <token>
    Revokes the JWT in the database (single-device logout).
    """
    jti = g.current_user["jti"]
    db  = get_db()
    db.execute("UPDATE sessions SET revoked = 1 WHERE jti = ?", (jti,))
    db.commit()
    return jsonify({"message": "Logged out successfully."}), 200


@app.route("/api/me", methods=["GET"])
@require_auth
def me():
    """
    GET /api/me
    Protected route â€” returns current user's profile.
    """
    username = g.current_user["username"]
    db = get_db()
    user = db.execute(
        "SELECT id, username, email, created_at FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    if not user:
        return jsonify({"error": "User not found."}), 404

    return jsonify({
        "id":         user["id"],
        "username":   user["username"],
        "email":      user["email"],
        "created_at": user["created_at"],
    }), 200


@app.route("/api/change-password", methods=["POST"])
@require_auth
def change_password():
    """
    POST /api/change-password
    Header: Authorization: Bearer <token>
    Body: { "old_password": "...", "new_password": "...", "csrf_token": "..." }
    """
    data = request.get_json(silent=True) or {}
    jti  = g.current_user["jti"]

    # CSRF validation for state-changing operation
    csrf = data.get("csrf_token", "")
    if not validate_csrf_token(jti, csrf):
        return jsonify({"error": "Invalid or expired CSRF token."}), 403

    old_pw = data.get("old_password", "")
    new_pw = data.get("new_password", "")

    if len(new_pw) < 8:
        return jsonify({"error": "New password must be at least 8 characters."}), 422

    db       = get_db()
    username = g.current_user["username"]
    user     = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    if not verify_password(old_pw, user["password_hash"], user["salt"]):
        return jsonify({"error": "Current password is incorrect."}), 401

    new_hash, new_salt = hash_password(new_pw)
    db.execute(
        "UPDATE users SET password_hash = ?, salt = ? WHERE username = ?",
        (new_hash, new_salt, username)
    )
    # Revoke all active sessions (force re-login on all devices)
    db.execute(
        "UPDATE sessions SET revoked = 1 WHERE user_id = ?", (user["id"],)
    )
    db.commit()

    return jsonify({"message": "Password changed. Please log in again."}), 200


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
#  ROUTES â€” FRONTEND
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
#  SECURITY HEADERS MIDDLEWARE
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@app.after_request
def set_security_headers(response):
    """Apply OWASP-recommended HTTP security headers to every response."""
    response.headers["X-Content-Type-Options"]    = "nosniff"
    response.headers["X-Frame-Options"]           = "DENY"
    response.headers["X-XSS-Protection"]          = "1; mode=block"
    response.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"]   = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline';"
    )
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
#  ENTRY POINT
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

if __name__ == "__main__":
    with app.app_context():
        init_db()
    app.run(debug=False, host="0.0.0.0", port=5000)

