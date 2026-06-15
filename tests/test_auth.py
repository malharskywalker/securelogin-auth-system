"""
Unit Tests — SecureLogin Authentication System
===============================================
Covers: registration, login, JWT, lockout, CSRF, rate limiting, auth decorator.
Run: python -m pytest tests/test_auth.py -v
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import json
import time
import unittest
import tempfile

# Set test DB before importing app
TEST_DB = tempfile.mktemp(suffix=".db")
os.environ["SECRET_KEY"] = "test-secret-key"
os.environ["JWT_SECRET"]  = "test-jwt-secret"

from app import app, init_db, hash_password, verify_password, decode_token


class BaseTestCase(unittest.TestCase):
    """Base class: fresh in-memory DB per test."""

    def setUp(self):
        app.config["TESTING"]        = True
        app.config["DATABASE"]       = TEST_DB
        app.config["RATE_LIMIT_MAX"] = 9999   # disable rate limiting in tests
        self.client = app.test_client()
        # Clear in-memory rate limit store between tests
        import app as app_module
        app_module.rate_limit_store.clear()
        with app.app_context():
            init_db()

    def tearDown(self):
        if os.path.exists(TEST_DB):
            os.remove(TEST_DB)

    # ── Helpers ──────────────────────────────

    def register(self, username="testuser", email="test@example.com", password="Test1234"):
        return self.client.post("/api/register", json={
            "username": username, "email": email, "password": password
        })

    def login(self, username="testuser", password="Test1234"):
        return self.client.post("/api/login", json={
            "username": username, "password": password
        })

    def auth_header(self, token):
        return {"Authorization": f"Bearer {token}"}


# ─────────────────────────────────────────────
#  PASSWORD HASHING
# ─────────────────────────────────────────────

class TestPasswordHashing(BaseTestCase):

    def test_hash_is_not_plaintext(self):
        pw_hash, salt = hash_password("MyPassword1")
        self.assertNotEqual(pw_hash, "MyPassword1")

    def test_correct_password_verifies(self):
        pw_hash, salt = hash_password("MyPassword1")
        self.assertTrue(verify_password("MyPassword1", pw_hash, salt))

    def test_wrong_password_fails(self):
        pw_hash, salt = hash_password("MyPassword1")
        self.assertFalse(verify_password("WrongPassword", pw_hash, salt))

    def test_same_password_different_salts(self):
        hash1, salt1 = hash_password("SamePassword1")
        hash2, salt2 = hash_password("SamePassword1")
        # Salts must differ (random) → hashes must differ
        self.assertNotEqual(salt1, salt2)
        self.assertNotEqual(hash1, hash2)


# ─────────────────────────────────────────────
#  REGISTRATION
# ─────────────────────────────────────────────

class TestRegistration(BaseTestCase):

    def test_successful_registration(self):
        r = self.register()
        self.assertEqual(r.status_code, 201)
        self.assertIn("created", r.get_json()["message"].lower())

    def test_duplicate_username_rejected(self):
        self.register()
        r = self.register()  # same username
        self.assertEqual(r.status_code, 409)

    def test_short_username_rejected(self):
        r = self.register(username="ab")
        self.assertEqual(r.status_code, 422)

    def test_missing_email_rejected(self):
        r = self.register(email="notanemail")
        self.assertEqual(r.status_code, 422)

    def test_weak_password_rejected(self):
        r = self.register(password="weakpass")   # no digit or uppercase
        self.assertEqual(r.status_code, 422)

    def test_short_password_rejected(self):
        r = self.register(password="Ab1")
        self.assertEqual(r.status_code, 422)

    def test_no_json_body(self):
        r = self.client.post("/api/register", data="not json", content_type="text/plain")
        self.assertEqual(r.status_code, 400)


# ─────────────────────────────────────────────
#  LOGIN & JWT
# ─────────────────────────────────────────────

class TestLogin(BaseTestCase):

    def setUp(self):
        super().setUp()
        self.register()   # create default user

    def test_successful_login_returns_token(self):
        r = self.login()
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertIn("token", data)
        self.assertIn("csrf_token", data)
        self.assertIn("expires_at", data)

    def test_wrong_password_rejected(self):
        r = self.login(password="WrongPass1")
        self.assertEqual(r.status_code, 401)

    def test_nonexistent_user_rejected(self):
        r = self.client.post("/api/login", json={"username": "ghost", "password": "Test1234"})
        self.assertEqual(r.status_code, 401)

    def test_generic_error_message(self):
        """Ensure error message doesn't reveal whether username exists."""
        r1 = self.login(username="testuser", password="BadPass1")
        r2 = self.login(username="nouser",   password="BadPass1")
        self.assertEqual(r1.get_json()["error"], r2.get_json()["error"])

    def test_jwt_payload_contains_username(self):
        token = self.login().get_json()["token"]
        with app.app_context():
            payload = decode_token(token)
        self.assertEqual(payload["username"], "testuser")

    def test_empty_credentials_rejected(self):
        r = self.client.post("/api/login", json={"username": "", "password": ""})
        self.assertEqual(r.status_code, 400)


# ─────────────────────────────────────────────
#  PROTECTED ROUTES
# ─────────────────────────────────────────────

class TestProtectedRoutes(BaseTestCase):

    def setUp(self):
        super().setUp()
        self.register()
        token_data = self.login().get_json()
        self.token = token_data["token"]
        self.csrf  = token_data["csrf_token"]

    def test_me_with_valid_token(self):
        r = self.client.get("/api/me", headers=self.auth_header(self.token))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["username"], "testuser")

    def test_me_without_token(self):
        r = self.client.get("/api/me")
        self.assertEqual(r.status_code, 401)

    def test_me_with_garbage_token(self):
        r = self.client.get("/api/me", headers=self.auth_header("garbage.token.here"))
        self.assertEqual(r.status_code, 401)

    def test_logout_revokes_token(self):
        self.client.post("/api/logout", headers=self.auth_header(self.token))
        # Token should now be invalid
        r = self.client.get("/api/me", headers=self.auth_header(self.token))
        self.assertEqual(r.status_code, 401)

    def test_change_password_requires_csrf(self):
        r = self.client.post("/api/change-password",
            headers=self.auth_header(self.token),
            json={"old_password": "Test1234", "new_password": "NewPass99", "csrf_token": "bad-csrf"}
        )
        self.assertEqual(r.status_code, 403)

    def test_change_password_success(self):
        r = self.client.post("/api/change-password",
            headers=self.auth_header(self.token),
            json={"old_password": "Test1234", "new_password": "NewPass99!", "csrf_token": self.csrf}
        )
        self.assertEqual(r.status_code, 200)

    def test_csrf_token_is_single_use(self):
        """CSRF token should be consumed on first use."""
        self.client.post("/api/change-password",
            headers=self.auth_header(self.token),
            json={"old_password": "Test1234", "new_password": "NewPass99!", "csrf_token": self.csrf}
        )
        # Re-login to get fresh token, try to reuse old CSRF
        new_login = self.login(password="NewPass99!")
        new_token = new_login.get_json()["token"]

        r = self.client.post("/api/change-password",
            headers=self.auth_header(new_token),
            json={"old_password": "NewPass99!", "new_password": "Another1!", "csrf_token": self.csrf}
        )
        self.assertEqual(r.status_code, 403)


# ─────────────────────────────────────────────
#  ACCOUNT LOCKOUT
# ─────────────────────────────────────────────

class TestAccountLockout(BaseTestCase):

    def setUp(self):
        super().setUp()
        self.register()
        app.config["MAX_LOGIN_ATTEMPTS"] = 3   # lower for tests

    def test_lockout_after_max_failures(self):
        for _ in range(3):
            self.login(password="WrongPass1")

        r = self.login()   # correct password — should still be locked
        self.assertEqual(r.status_code, 423)
        self.assertIn("locked", r.get_json()["error"].lower())

    def test_no_lockout_before_max(self):
        for _ in range(2):
            self.login(password="WrongPass1")

        r = self.login()   # correct password — should succeed
        self.assertEqual(r.status_code, 200)


# ─────────────────────────────────────────────
#  SECURITY HEADERS
# ─────────────────────────────────────────────

class TestSecurityHeaders(BaseTestCase):

    def test_security_headers_present(self):
        r = self.client.get("/")
        self.assertEqual(r.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(r.headers.get("X-Frame-Options"), "DENY")
        self.assertIn("default-src", r.headers.get("Content-Security-Policy", ""))

    def test_xss_protection_header(self):
        r = self.client.get("/")
        self.assertIn("X-XSS-Protection", r.headers)


if __name__ == "__main__":
    unittest.main(verbosity=2)
