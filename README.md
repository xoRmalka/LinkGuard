# LinkGuard

LinkGuard helps you assess a URL **before you click**. Paste a link, run automated checks (heuristics, domain age, Google Safe Browsing), and get a **safety score (0–100%)**, a verdict, and plain-language guidance—in **English or Hebrew** (RTL).

**Higher score = safer.** LinkGuard never claims a link is 100% safe.

---

## Features

| Area | Description |
|------|-------------|
| **URL scan** | Normalize URL, run 15-signal pipeline, return safety % + verdict + breakdown |
| **Guest mode** | Scan without sign-in (3 requests per UTC day per IP) |
| **Signed-in** | Saved scan history, favorites, report URL |
| **Reports** | Flag a suspicious URL; admins review/resolve via the Reports dashboard (`/admin/reports`) |
| **Auth** | [Clerk](https://clerk.com/) — optional; same app for client + API JWT |
| **Admin** | User list, invites, roles via Clerk `public_metadata.role`; gated client-side by admin role |
| **i18n** | EN / HE UI; Clerk components localized (`heIL` / `enUS`) |

---

## Architecture

```
Browser (Vite + React, :5173)
    │  /api/v1/*  (dev: Vite proxy → :5001)
    ▼
Flask API (server/, :5001)
    ├── SQLite (local) or Postgres (DATABASE_URL / Neon)
    ├── Clerk JWT verify + Backend API (roles, admin)
    └── Google Safe Browsing (optional)
```

| Layer | Tech |
|-------|------|
| **Client** | React 19, TypeScript, React Router, Vite 8 |
| **Server** | Flask, SQLAlchemy |
| **Auth** | Clerk (`@clerk/react`, `@clerk/localizations`) |
| **DB** | `server/linkguard.db` or Neon via `DATABASE_URL` |

---

## Quick start

### 1. API (Flask)

```bash
cd server
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env        # fill Clerk / Safe Browsing as needed
python run.py
```

- API: **http://127.0.0.1:5001**
- Health: `GET http://127.0.0.1:5001/api/v1/health`

### 2. Web (Vite)

```bash
cd client
cp .env.example .env.local
npm install
npm run dev
```

- App: **http://127.0.0.1:5173**
- In dev, Vite **proxies** `/api` → Flask (no `VITE_API_URL` needed).

### 3. Try it

1. Open the app → paste a URL → **Analyze**.
2. Optional: set Clerk keys (below), sign in, run another scan to save history.

---

## Environment variables

Use the **same Clerk application** for client and server keys.

### Client — `client/.env.local`

| Key | Purpose |
|-----|---------|
| `VITE_CLERK_PUBLISHABLE_KEY` | Sign-in, dashboard, favorites, reports. Empty = guest-only scans. |
| `VITE_API_URL` | Production API base (e.g. `https://api.example.com`). **Leave empty in dev.** |

**Details, examples, and server companion keys:** [client/README.md → Environment variables](client/README.md#environment-variables)

### Server — `server/.env`

| Key | Purpose |
|-----|---------|
| `CLERK_ISSUER` | Clerk Frontend API URL (must match JWT `iss`) |
| `CLERK_JWT_KEY` | Recommended: JWKS public key (PEM) from Clerk Dashboard |
| `CLERK_SECRET_KEY` | Backend API (roles, admin, invites). **Never** put in Vite. |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Optional; without it, threat-intel signal is skipped |
| `DATABASE_URL` | Postgres/Neon; if unset → SQLite `server/linkguard.db` |
| `CORS_ORIGINS` | Allowed browser origins if API is on another host |

Template with comments: [server/.env.example](server/.env.example)

### Clerk checklist

1. `VITE_CLERK_PUBLISHABLE_KEY` (client) + `CLERK_ISSUER` + `CLERK_SECRET_KEY` (server) from **one** Clerk app.
2. After sign-in, client calls `GET /api/v1/me` → provisions SQL user + default role.
3. Admin: set `public_metadata.role` to `admin` in Clerk Dashboard. See [docs/clerk-auth-rollout-plan.md](docs/clerk-auth-rollout-plan.md).

---

## Safety scoring (summary)

- **Score:** `0–100` = **% safe** (penalties subtracted from 100, capped at **95%** — no automated check guarantees full safety).
- **Verdicts:** `likely_safe` · `low_risk` · `moderate_risk` · `high_risk` · `dangerous` · `insufficient_data`
- **Signals (current, 15):** parse, http scheme, URL length, suspicious port, userinfo, IP host, internal/private host, punycode, shorteners, typosquatting, suspicious TLD, suspicious subdomain (incl. brand impersonation), domain age (RDAP), entropy, Safe Browsing
- **Removed:** direct SSL/TLS probe (security + false positives)

Weights: `server/app/services/weights.json` (`2026-07-21-v6-conservative`). Full rules: [plan.md](plan.md).

---

## Guest limits

Guests (no `Authorization` header) get **3 scans per UTC calendar day per IP**. Authenticated scans are stored per user; guest results are not persisted.

---

## Repository layout

```
LinkGuard/
├── README.md           ← you are here
├── plan.md             ← product & engineering plan
├── client/             ← Vite + React app → client/README.md
├── server/             ← Flask API
└── docs/
    └── clerk-auth-rollout-plan.md
```

---

## API overview

Prefix: `/api/v1`

| Method | Path | Auth |
|--------|------|------|
| `POST` | `/scans` | Optional (guest rate-limited) |
| `GET` | `/scans/{id}` | User |
| `GET` | `/me` | User — bootstrap + DB user row |
| `GET` | `/me/scans` | User — history |
| `GET` | `/favorites` | User |
| `POST` | `/scans/{id}/favorite` | User |
| `POST` | `/reports` | User |
| `GET` | `/admin/reports` | Admin |
| `PATCH` | `/admin/reports/{id}` | Admin |
| `DELETE` | `/admin/reports/{id}` | Admin |
| `GET` | `/admin/users` | Admin |
| `PATCH` | `/admin/users/{id}` | Admin |
| `POST` | `/admin/invites` | Admin |
| `DELETE` | `/admin/users/{id}` | Admin |
| `GET` | `/health` | Public |

---

## Tests

```bash
cd server
source .venv/bin/activate
pytest
```

Includes domain-age (RDAP) tests and normalization/scoring coverage.

---

## Documentation

| Document | Contents |
|----------|----------|
| [plan.md](plan.md) | Vision, scoring model, signals, API, data model, rollout status |
| [client/README.md](client/README.md) | Front-end setup, routes, env keys, i18n, scripts |
| [docs/clerk-auth-rollout-plan.md](docs/clerk-auth-rollout-plan.md) | Clerk roles, JWT, lazy defaults |

---

## Reset local database

To wipe local dev data (e.g. after scoring model changes):

```bash
rm server/linkguard.db
# restart Flask — tables are recreated via db.create_all()
```

---

*LinkGuard provides automated signals, not a guarantee. Always verify unexpected links through a trusted channel.*
