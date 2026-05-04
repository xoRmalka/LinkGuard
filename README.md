# LinkGuard

LinkGuard scores URLs using layered heuristics and (optionally) Google Safe Browsing, then explains the result in plain language—without claiming any link is 100% safe.

## Stack

- **Client:** Vite + React + TypeScript, React Router, Clerk (optional), EN/HE + RTL
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
cp .env.example .env
npm install
npm run dev
```

Vite proxies `/api` → Flask, so the client can call `/api/v1/...` without CORS friction in dev.

### 3) Clerk + Neon (optional)

- Add `VITE_CLERK_PUBLISHABLE_KEY` to `client/.env` and `CLERK_ISSUER` to `server/.env` so the API can verify JWTs for signed-in routes.
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
