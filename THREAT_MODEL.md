# SecureLogin — Threat Model & Security Design

**Author:** Mallangouda Biradar  
**Project:** Application Authentication System  
**Stack:** Python · Flask · SQLite · PBKDF2/bcrypt · JWT  

---

## 1. Application Overview

SecureLogin is a web-based authentication system providing:
- User registration with input validation
- Secure login with JWT issuance
- Protected API endpoints (Bearer token)
- Password change with CSRF protection
- Session revocation (logout)

---

## 2. Assets & Trust Boundaries

| Asset | Sensitivity | Location |
|---|---|---|
| User passwords (plaintext) | Critical | In-transit only; never stored |
| Password hashes + salts | High | SQLite DB |
| JWT secret key | Critical | Environment variable |
| JWT tokens | High | Client localStorage; HTTP header |
| CSRF tokens | Medium | DB (single-use) |
| User PII (email) | High | SQLite DB |

**Trust boundaries:**  
- Browser ↔ Flask (HTTPS in production)  
- Flask ↔ SQLite (local filesystem)  
- Environment ↔ Flask (secrets via env vars)

---

## 3. STRIDE Threat Analysis

### T — Spoofing Identity
| Threat | Attack | Mitigation |
|---|---|---|
| Password brute-force | Attacker guesses passwords | Account lockout after 5 failures / 5 min window |
| Credential stuffing | Reuse of leaked credentials | Rate limiting (10 req / 60s / IP) + strong password policy |
| JWT forgery | Attacker crafts own token | HS256 signing with 32-byte random secret |

### R — Repudiation
| Threat | Mitigation |
|---|---|
| Deny login attempts | `login_attempts` table logs all attempts with IP + timestamp |
| Deny password change | All state changes require valid JWT + CSRF |

### I — Information Disclosure
| Threat | Attack | Mitigation |
|---|---|---|
| User enumeration via error msg | "Username not found" vs "Wrong password" | Generic error: "Invalid username or password" |
| Timing-based user enumeration | Response time differs if user exists | `hmac.compare_digest` + always run hash even for missing users |
| Password leakage via DB breach | Read DB file | PBKDF2-SHA256 with 390,000 iterations + unique salts per user |
| Token leakage in logs | Token in URL | Tokens only in `Authorization` header, never URL params |

### D — Denial of Service
| Threat | Mitigation |
|---|---|
| Registration spam | Rate limiting per IP |
| Login flooding | Rate limiting + account lockout |

### E — Elevation of Privilege
| Threat | Attack | Mitigation |
|---|---|---|
| Token reuse after logout | Reuse old JWT | JTI stored in DB; revoked on logout |
| CSRF on state-changing ops | Forge cross-origin requests | Single-use CSRF token required for `/change-password` |
| Password change without auth | Skip current password | Must provide `old_password`; verified server-side |
| XSS → token theft | Inject script to steal localStorage | Content-Security-Policy header blocks inline scripts (in production, move tokens to httpOnly cookies) |

---

## 4. Security Controls Implemented

### 4.1 Password Storage
```
PBKDF2-HMAC-SHA256
  iterations : 390,000  (OWASP 2023 minimum)
  salt       : 32 random bytes (per-user, cryptographically secure)
  output     : 32-byte derived key, stored as hex
  comparison : hmac.compare_digest() — constant-time
```
**Upgrade path:** Replace with bcrypt (work factor 12+) or Argon2id for production.

### 4.2 JWT Design
```
Algorithm  : HS256
Expiry     : 3600 seconds (1 hour)
Claims     : sub, username, jti, iat, exp
JTI (JWT ID): Unique per token; stored in DB for revocation
Revocation : Single token (logout) or all tokens (password change)
```

### 4.3 CSRF Protection
- Every login response issues a single-use CSRF token
- CSRF token is bound to the session JTI
- Required on all state-changing endpoints (`/change-password`)
- Token consumed on use — cannot be replayed

### 4.4 Rate Limiting
```
Algorithm : Sliding window (in-memory)
Window    : 60 seconds
Max reqs  : 10 per IP per window
Scope     : All API endpoints
```

### 4.5 Account Lockout
```
Max failures : 5 within lockout window
Lockout time : 5 minutes
Unlock       : Automatic after window expires
Scope        : Per username
```

### 4.6 HTTP Security Headers
| Header | Value | Protection |
|---|---|---|
| X-Content-Type-Options | nosniff | MIME sniffing |
| X-Frame-Options | DENY | Clickjacking |
| X-XSS-Protection | 1; mode=block | Reflected XSS (legacy) |
| Content-Security-Policy | default-src 'self' | XSS, data injection |
| Referrer-Policy | strict-origin-when-cross-origin | Info leakage |
| Strict-Transport-Security | max-age=31536000 | SSL stripping |

---

## 5. Known Limitations & Recommendations for Production

| Issue | Recommendation |
|---|---|
| Tokens in localStorage | Move to httpOnly, Secure, SameSite=Strict cookies |
| In-memory rate limiter | Replace with Redis for multi-process/distributed deployments |
| SQLite | Upgrade to PostgreSQL for concurrent write safety |
| HTTPS | Enforce TLS (Flask dev server doesn't support it) |
| Log sensitive data | Use structured logging; redact passwords/tokens |
| Argon2id | Upgrade from PBKDF2 to Argon2id (memory-hard) |

---

## 6. OWASP Top 10 Coverage

| OWASP Risk | Status |
|---|---|
| A01 Broken Access Control | ✅ JWT on all protected routes; token revocation |
| A02 Cryptographic Failures | ✅ PBKDF2 hashing; never store plaintext; HTTPS header |
| A03 Injection | ✅ Parameterised SQLite queries throughout |
| A04 Insecure Design | ✅ Threat model documented; lockout & rate limiting by design |
| A05 Security Misconfiguration | ✅ Security headers; debug=False |
| A07 Identification & Auth Failures | ✅ Lockout, rate limiting, generic errors, timing-safe compare |
| A09 Security Logging & Monitoring | ✅ All login attempts logged with IP and timestamp |
