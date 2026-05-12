# LinkGuard

LinkGuard scores URLs using layered heuristics and (optionally) Google Safe Browsing, then explains the result in plain language—without claiming any link is 100% safe.

## Stack

- **Client:** Vite + React + TypeScript, React Router, [`@clerk/react`](https://clerk.com/docs/react/getting-started/quickstart) (optional), EN/HE + RTL
- **Server:** Flask + SQLAlchemy (SQLite locally, Neon Postgres via `DATABASE_URL`)

## Quick start

### 1) API (Flask)

```bash
cd server
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python run.py
```

API listens on `http://127.0.0.1:5001`. Health: `GET http://127.0.0.1:5001/api/v1/health`

### 2) Web (Vite)

```bash
cd client
cp .env.example .env.local
# Set VITE_CLERK_PUBLISHABLE_KEY in .env.local (see Clerk Dashboard → API keys → React).
npm install
npm run dev
```

Vite proxies `/api` → Flask, so the client can call `/api/v1/...` without CORS friction in dev.

### 3) Clerk + Neon (optional)

- Add `VITE_CLERK_PUBLISHABLE_KEY` to `client/.env.local` (or `.env`) and `CLERK_ISSUER` to `server/.env` (must equal the Dashboard **Frontend API URL** / JWT `iss`). If verification still fails, paste the **JWKS Public Key (PEM)** from Clerk → API keys into `CLERK_JWT_KEY` in `server/.env` (see `server/.env.example`). The client uses [`@clerk/react`](https://clerk.com/docs/react/getting-started/quickstart); `ClerkProvider` uses `import.meta.env.VITE_CLERK_PUBLISHABLE_KEY` (with Clerk’s bypass when the key is empty so guest mode still runs).
- Set `DATABASE_URL` to your Neon connection string for Postgres. If omitted, SQLite `server/linkguard.db` is created automatically.

**Admin (MVP):** promote a user to `admin` by updating the `users.role` column in the database after first sign-in.

## Guest limits

Guests (no `Authorization` bearer) are limited to **3 scans per UTC day per IP**, enforced in the API.

## Tests

```bash
cd server
source .venv/bin/activate
pytest
```

## Project docs

See `plan.md` for the full product and architecture plan.
