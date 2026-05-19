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

Copy `.env.example` → `.env.local` (git-ignored). Only `VITE_*` vars are exposed to the browser.

| Variable | Required | Description |
|----------|----------|-------------|
| `VITE_CLERK_PUBLISHABLE_KEY` | For auth | Clerk Dashboard → API keys → React. Empty = guest-only UI (no sign-in buttons). |
| `VITE_API_URL` | Production | API base URL, e.g. `https://api.example.com`. **Leave empty in dev** — Vite proxies `/api` → `http://127.0.0.1:5001`. |

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
