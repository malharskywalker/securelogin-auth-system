# 🔐 SecureLogin — Application Authentication System

![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0-black?logo=flask)
![JWT](https://img.shields.io/badge/Auth-JWT-orange)
![OWASP](https://img.shields.io/badge/Security-OWASP%20Top%2010-red)
![Tests](https://img.shields.io/badge/Tests-28%20passing-brightgreen)

A production-grade web authentication system built with Python and Flask,
implementing OWASP security best practices from the ground up.

---

## 🚀 Features

| Feature | Details |
|---|---|
| 🔑 Password Hashing | PBKDF2-SHA256 · 390,000 iterations · unique salt per user |
| 🎫 JWT Sessions | HS256 signed · JTI-based server-side revocation |
| 🛡 CSRF Protection | Single-use tokens bound to session JTI |
| 🚦 Rate Limiting | Sliding window · 10 req / 60s / IP |
| 🔒 Account Lockout | 5 failures → 5 min lockout |
| 📋 Security Headers | CSP · HSTS · X-Frame-Options · X-XSS-Protection |
| ⏱ Timing-Safe Compare | `hmac.compare_digest` prevents timing attacks |
| 🕵 Enum Prevention | Generic errors · dummy hash always runs |
| 📝 Audit Logging | All login attempts logged with IP + timestamp |

---

## 🛠 Tech Stack

- **Backend:** Python 3.12, Flask 3.0
- **Database:** SQLite (parameterised queries — no raw SQL)
- **Auth:** PyJWT (HS256), PBKDF2-HMAC-SHA256
- **Security:** OWASP Top 10 coverage (see THREAT_MODEL.md)

---

## ⚡ Quick Start

```bash
git clone https://github.com/YOUR_USERNAME/securelogin-auth-system.git
cd securelogin-auth-system
python -m pip install -r requirements.txt
python app.py
```
Open **http://localhost:5000**

---

## 🔬 Run Tests

```bash
python -m unittest tests/test_auth.py -v
```
**28 tests** covering: registration validation, login flows,
JWT decode/revocation, lockout, CSRF enforcement, security headers.

---

## 📡 API Reference

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/api/register` | None | Create account |
| POST | `/api/login` | None | Get JWT token |
| GET | `/api/me` | Bearer | Get profile |
| POST | `/api/logout` | Bearer | Revoke token |
| POST | `/api/change-password` | Bearer + CSRF | Change password |

---

## 📂 Project Structure
securelogin/

├── app.py              # Flask app — routes, auth logic, middleware

├── requirements.txt

├── THREAT_MODEL.md     # STRIDE analysis + OWASP Top 10 mapping

├── templates/

│   ├── index.html      # Login / Register UI

│   └── dashboard.html  # Protected dashboard

└── tests/

└── test_auth.py    # 28 unit tests

---

## 🔐 Security Design

See [THREAT_MODEL.md](./THREAT_MODEL.md) for full STRIDE threat analysis,
attack vectors, mitigations, and OWASP Top 10 coverage table.

---

## 👤 Author

**Mallangouda Biradar**  
biradarmallangouda27@gmail.com