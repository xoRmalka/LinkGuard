# LinkGuard — Web Client

The LinkGuard front end is a **Vite + React** single-page app that lets users paste a URL, run an automated safety check, and read a clear verdict with explanations in **English or Hebrew** (full **RTL** for Hebrew).

**Safety score:** results show **0–100% safe** (higher = safer), not a “risk score” where higher meant worse.

---

## Features

| Area | What you get |
|------|----------------|
| **Scan** | Home page URL input → result view with verdict, safety %, signal breakdown |
| **Auth** | Optional [Clerk](https://clerk.com/) sign-in/up; guest mode without a key |
| **History** | Dashboard of saved scans (signed-in) |
| **Favorites** | Save scans from the result page; list at `/favorites` |
| **Report** | Flag a URL for later moderation (`POST /api/v1/reports`) |
| **Admin** | User list, invites, roles (Clerk `public_metadata.role`) |
| **i18n** | `en.json` / `he.json`; Clerk UI localized (`heIL` / `enUS`) |

---

## Tech stack

- **React 19** + **TypeScript**
- **React Router 7**
- **Vite 8** (dev server + `/api` proxy to Flask)
- **Clerk** — `@clerk/react`, `@clerk/localizations`
- No UI framework — custom CSS in `src/index.css`

---

## Prerequisites

- **Node.js** 20+ (LTS recommended)
- **Flask API** running on `http://127.0.0.1:5001` (see [root README](../README.md))
- Optional: Clerk application (publishable key) for sign-in and saved history

---

## Quick start

```bash
# From repo root
cd client
cp .env.example .env.local
npm install
npm run dev
```

Open **http://127.0.0.1:5173** (default Vite port).

1. Start the **server** first (`cd server && python run.py`).
2. Paste a URL on Home and click **Analyze**.
3. For history, favorites, and reports: set `VITE_CLERK_PUBLISHABLE_KEY` in `.env.local` and sign in.

---

## Environment variables

Vite loads env files from `client/` in this order (later overrides earlier): `.env` → `.env.local` → `.env.[mode]` → `.env.[mode].local`.

**Only variables prefixed with `VITE_` are exposed to the browser.** Never put secrets (Clerk secret key, DB URL, Safe Browsing key) in client env files.

Copy the template:

```bash
cp .env.example .env.local
```

### Client keys (`client/.env.local`)

| Key | Required | Where to get it | Behavior |
|-----|----------|-----------------|----------|
| **`VITE_CLERK_PUBLISHABLE_KEY`** | For sign-in, history, favorites, reports, admin | [Clerk Dashboard](https://dashboard.clerk.com) → **API keys** → **React** → Publishable key (`pk_test_…` or `pk_live_…`) | If **empty**: app runs in **guest mode** — scan works, no sign-in UI; `ClerkProvider` uses Clerk’s dev bypass. If **set**: header shows Sign in / Sign up, `UserButton`, dashboard & favorites routes. Must be from the **same Clerk application** as `CLERK_ISSUER` on the server. |
| **`VITE_API_URL`** | Production only | Your deployed API origin, e.g. `https://api.linkguard.example` | If **empty** (recommended in dev): `api.ts` calls relative `/api/v1/...`, and Vite **proxies** `/api` → `http://127.0.0.1:5001` (`vite.config.ts`). If **set**: all API requests use that base URL (no proxy needed; configure CORS on the server). **Do not** include a trailing slash. |

**Example — local dev with Clerk:**

```env
VITE_CLERK_PUBLISHABLE_KEY=pk_test_xxxxxxxxxxxxxxxxxxxxxxxx
# VITE_API_URL=   ← leave unset; proxy handles /api
```

**Example — production (API on another host):**

```env
VITE_CLERK_PUBLISHABLE_KEY=pk_live_xxxxxxxxxxxxxxxxxxxxxxxx
VITE_API_URL=https://api.yourdomain.com
```

**Used in code:**

- `src/lib/env.ts` — `hasClerkPublishableKey`
- `src/lib/api.ts` — `VITE_API_URL` for `fetch` base
- `src/main.tsx` / `src/auth/ClerkProviderWithLocale.tsx` — Clerk provider + publishable key

### Server keys (`server/.env`) — required for a working dev stack

The client does not read these, but the API must have them for auth and scans to work when you use Clerk or hosted API.

| Key | Required | Purpose for the client |
|-----|----------|------------------------|
| **`CLERK_ISSUER`** | With Clerk | Must match JWT `iss` (Clerk **Frontend API URL**, e.g. `https://….clerk.accounts.dev`). Wrong value → `401` on `/me`, scans with Bearer token, favorites, reports. |
| **`CLERK_JWT_KEY`** | Recommended | PEM public key from Clerk → API keys. Avoids JWKS fetch issues in local dev. |
| **`CLERK_SECRET_KEY`** | With Clerk | Backend API: lazy default role, admin user list, invites. Never expose to Vite. |
| **`GOOGLE_SAFE_BROWSING_API_KEY`** | Optional | Without it, Safe Browsing signal is **skipped**; results may show `insufficient_data` when score would otherwise look very safe. |
| **`CORS_ORIGINS`** | If `VITE_API_URL` is set | Comma-separated browser origins allowed to call the API, e.g. `http://127.0.0.1:5173,http://localhost:5173`. Default in `config.py` includes common Vite URLs. |
| **`DATABASE_URL`** | Production | Postgres/Neon connection string. If unset, server uses SQLite `server/linkguard.db`. |

Full comments and examples: [`server/.env.example`](../server/.env.example).

### Checklist: Clerk + client + server aligned

1. Same Clerk app: `VITE_CLERK_PUBLISHABLE_KEY` (client) + `CLERK_ISSUER` + `CLERK_SECRET_KEY` (server).
2. Server running on port **5001** (or update `vite.config.ts` proxy target).
3. Client dev on **5173** included in `CORS_ORIGINS` if not using the Vite proxy.
4. After sign-in, browser should successfully call `GET /api/v1/me` (Network tab).

---

## Routes

| Path | Page | Auth |
|------|------|------|
| `/` | Home — analyze URL | — |
| `/result` | Scan result (state from navigation) | — |
| `/sign-in/*` | Clerk `<SignIn />` | — |
| `/sign-up/*` | Clerk `<SignUp />` | — |
| `/dashboard` | Scan history | Signed in |
| `/favorites` | Saved scans | Signed in |
| `/admin` | User admin | Clerk `admin` role |

After sign-in, `RootLayout` calls **`GET /api/v1/me`** to provision the local DB user and resolve Clerk role.

---

## Result UI (verdicts & bands)

Aligned with the API safety model:

| Verdict | Typical meaning |
|---------|-----------------|
| `safe` | High safety % (≥ 85) |
| `low_risk` | Mostly fine (≥ 70) |
| `moderate_risk` | Some concerns (≥ 50) |
| `high_risk` | Low safety % (&lt; 50) |
| `dangerous` | Safe Browsing match or critical |
| `insufficient_data` | Key checks missing / inconclusive |

Bands: `safe`, `low_risk`, `moderate_risk`, `high_risk` (shown as “Confidence level” in the UI).

Legacy API values (`safe_low`, `suspicious`, old bands) are mapped in `src/lib/riskDisplay.ts` for display only.

---

## Project structure

```
client/
├── public/
├── src/
│   ├── app/              AppRoutes
│   ├── auth/             ClerkProviderWithLocale (EN/HE)
│   ├── components/       Header, ScoreCard, VerdictBanner
│   ├── i18n/
│   │   ├── I18nProvider.tsx
│   │   └── locales/      en.json, he.json
│   ├── layouts/          RootLayout (header, footer, /me bootstrap)
│   ├── lib/              api.ts, types.ts, riskDisplay.ts, env.ts
│   ├── pages/            Home, Result, Dashboard, Favorites, Admin, Auth
│   ├── index.css
│   └── main.tsx
├── .env.example
├── package.json
└── vite.config.ts        /api → Flask proxy
```

---

## Internationalization

- Toggle **EN / HE** in the header; preference stored in `localStorage` (`linkguard.locale`).
- Hebrew sets `document.documentElement.dir = "rtl"` and `lang = "he"`.
- Result copy uses **i18n keys** from the API (`explanation_keys`, `action_keys`), not hardcoded paragraphs.
- Clerk components follow the active locale via `ClerkProviderWithLocale`.

Add strings in **both** `src/i18n/locales/en.json` and `he.json`.

---

## Scripts

| Command | Description |
|---------|-------------|
| `npm run dev` | Dev server + HMR (port 5173) |
| `npm run build` | `tsc -b` + production bundle → `dist/` |
| `npm run preview` | Serve `dist/` locally |
| `npm run lint` | ESLint |

---

## API usage (client)

Central client: `src/lib/api.ts` — `postScan`, `getMe`, `listMyScans`, `getFavorites`, `postFavorite`, `postReport`, admin helpers.

Dev requests go to `/api/v1/...` (proxied). Production: set `VITE_API_URL` if the API is on another host.

---

## Further reading

- [Root README](../README.md) — full stack, server setup, Clerk, Neon/SQLite  
- [plan.md](../plan.md) — product rules, scoring model, signals (SSL removed, RDAP domain age)  
- [Clerk React quickstart](https://clerk.com/docs/react/getting-started/quickstart)
