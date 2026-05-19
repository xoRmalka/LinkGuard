# LinkGuard — Product & Engineering Plan

## Vision

LinkGuard is a web application that helps users assess whether a URL is likely risky before they click. The client collects a URL, normalizes and validates it, and the backend runs layered checks (technical signals, typosquatting heuristics, domain age via RDAP, and threat-intelligence APIs). Results are presented as a **safety score (0–100%)**, a confidence band, a verdict, plain-language explanations (i18n keys), and recommended next steps—never as absolute certainty.

**Scoring semantics (current):** `score` is **percent safe** — **higher = safer**, **lower = riskier**. Penalties are subtracted from 100 based on per-signal `max_points` in `weights.json`. This replaced the earlier “risk score” model where a higher number meant more danger.

## Tech Stack

| Layer | Choice |
|--------|--------|
| Client | React (Vite + React Router) |
| Server | Python Flask (REST API) |
| Auth | [Clerk](https://clerk.com/) (`@clerk/react`, `@clerk/localizations` for EN/HE) |
| Database | SQLite locally (`server/linkguard.db`) or Neon Postgres via `DATABASE_URL` |
| i18n | Dictionary-based JSON (`en.json`, `he.json`); explanations/actions via API keys |
| RTL | Full layout RTL when Hebrew is selected (`I18nProvider` sets `dir` + `lang`) |

## Confirmed product decisions

| Topic | Decision |
|--------|----------|
| Guest scanning | **Allowed** with **3 scans per UTC day per IP**; **scan history only for signed-in users** (guest responses are not persisted). |
| Contributor (MVP) | **Same capabilities as user**; `contributor` role reserved for future features. |
| External APIs (phase 1) | **Google Safe Browsing + inner heuristics**; URLhaus, VirusTotal, etc. in **later phases**. |
| URL storage | Store **full normalized URL + host** when `user_id` is set (authenticated scans). |
| Clerk roles | **`public_metadata.role`**: `user` \| `admin` in MVP; lazy default `user` on authenticated API hit; **not** stored on SQL `users`. See `docs/clerk-auth-rollout-plan.md`. |
| Local user row | SQL `users.id` = Clerk `sub`; provisioned on **`GET /api/v1/me`** after sign-in (not on `POST /scans`). |
| SSL/TLS signal | **Removed** from pipeline (direct connection risk to malicious hosts + false positives); HTTPS still required for meaningful checks elsewhere. |
| Scoring config | `server/app/services/weights.json` + `WEIGHTS_VERSION` in config (`2026-05-17-v4-safety`). |

## Core product rules (non-negotiable)

1. **Never claim 100% safety.** Use calibrated language (e.g. `explanation.safe.*` i18n keys), not “definitely safe.”
2. **Insufficient data** is a first-class outcome when Safe Browsing is skipped/errors and the score would otherwise look very safe (`insufficient_data` verdict).
3. **Always** show: explanation keys, recommended action keys, and signal breakdown (including skipped/unknown checks).
4. **Safe Browsing match** (`concern: true`) → verdict **`dangerous`** regardless of safety %.

## User roles

| Role | Capabilities (MVP) |
|------|---------------------|
| **User** | Submit URLs (within limits), view scan history, favorites, report URL |
| **Contributor** | Same as user (reserved label) |
| **Admin** | Clerk user list, invite, role patch, deactivate; **reports moderation UI not built** |

**Implementation:** Role from Clerk **`public_metadata.role`** only. On **`GET /me`**, server runs `ensure_lazy_default_and_resolve` (Clerk Backend API) and **`_ensure_user`** (SQL row). Client calls `/me` from `RootLayout` after sign-in.

## Client pages (implemented)

### 1. Home

- Header: branding, **EN / HE**, Clerk sign-in/up (`SignInButton` redirect) when configured
- Hero + URL input + analyze CTA
- Example URLs; “how it works” copy uses **safety score** wording (EN + HE)

### 2. Result (after submit)

- **Verdict banner** (tones: ok / warn / danger / muted) for:
  - `safe` · `low_risk` · `moderate_risk` · `high_risk` · `dangerous` · `insufficient_data`
- **Safety score:** 0–100 (higher = safer), label “Safety score” / “ציון בטיחות”
- **Confidence band:** `safe` · `low_risk` · `moderate_risk` · `high_risk` (aligned with score thresholds)
- **Why / actions:** resolved from `explanation_keys` / `action_keys` via i18n
- Collapsible **signals** table (icons, tooltips, per-signal descriptions)
- **Report URL** · **Save to favorites** (auth-gated; favorite requires `scan_id` from saved scan)
- Clerk **localization** (`heIL` / `enUS`) via `ClerkProviderWithLocale`

### 3. Login / Register

- Embedded Clerk `<SignIn />` / `<SignUp />` at `/sign-in/*`, `/sign-up/*` (path routing)

### 4. User dashboard (`/dashboard`)

- Paginated **scan history**: URL, safety %, translated verdict, date

### 5. Favorites (`/favorites`)

- Lists favorited scans (`GET /api/v1/favorites`); full i18n for loading/empty/sign-in/error

### 6. Admin dashboard (`/admin`)

- Clerk-backed users + roles, invite, deactivate
- **No** reports inbox yet

## Localization (EN / HE)

- JSON dictionaries; RTL for Hebrew
- Clerk components localized when locale is `he` (`@clerk/localizations`)
- Legacy verdict/band values (`safe_low`, `suspicious`, `low`/`medium`/`high`) mapped in `riskDisplay.ts` for old DB rows if any remain

## Backend signals (current pipeline)

| Signal | Status | Notes |
|--------|--------|--------|
| Parse + normalization | Active | Scheme, host, IDN/punycode |
| Domain age | Active | **RDAP** lookup; TLD allowlist (`com`, `net`, `org`, `io`, `dev`, `app`); &lt;30d = concern; unknown TLD → `unknown` (small penalty) |
| Typosquatting / homograph | Active | Brand Levenshtein + mixed-script |
| IP-as-host | Active | Raw IP in host |
| Entropy | Active | High path/query entropy heuristic |
| Link shorteners | Active | Known shortener list |
| Google Safe Browsing | Active | Skipped if no API key; match → `dangerous` |
| **SSL/TLS** | **Removed** | Commented out in `pipeline.py`; do not re-enable without sandboxed fetch |

## Weighted scoring (safety model)

**Config:** `server/app/services/weights.json` (version `2026-05-17-v4-safety`).

| Signal | max_points (penalty cap) |
|--------|--------------------------|
| safe_browsing | 40 |
| domain_age | 30 |
| typosquatting | 18 |
| ip_host | 5 |
| entropy | 3 |
| shortener | 2 |
| parse | 2 |

**Per-signal penalty:**

- `concern: true` → full `max_points`
- `status: error` or `skipped` → 15% of max (uncertainty)
- `status: unknown` → 20% of max
- else → 0

**Aggregate:** `score = round(max(0, 100 - sum(penalties)))` capped at 100.

**Bands (field `risk_band`):**

| Safety % | Band |
|----------|------|
| ≥ 85 | `safe` |
| ≥ 70 | `low_risk` |
| ≥ 50 | `moderate_risk` |
| &lt; 50 | `high_risk` |

**Verdicts (field `verdict`):**

| Condition | Verdict |
|-----------|---------|
| Safe Browsing `concern` | `dangerous` |
| Insufficient-data rules | `insufficient_data` |
| Else by score | `safe` / `low_risk` / `moderate_risk` / `high_risk` (same thresholds as bands) |

**API payload:** `score`, `risk_band`, `verdict`, `breakdown[]` (each signal includes `points` = penalty), `weights_version`, `explanation_keys[]`, `action_keys[]`, `insufficient_reasons[]` (English server strings today).

## API routes (implemented)

Prefix: `/api/v1`. Guest scans: **3 per IP per UTC day** (`429` when exceeded).

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/scans` | Optional | Run pipeline; **persist** only when JWT present |
| GET | `/scans/{id}` | User+ (owner or admin) | Full scan |
| GET | `/me` | User+ | **Provision SQL user** + lazy Clerk role; returns `{ user_id, role }` |
| GET | `/me/scans` | User+ | Paginated history |
| POST | `/scans/{id}/favorite` | User+ | Toggle favorite |
| GET | `/favorites` | User+ | List favorited scans |
| POST | `/reports` | User+ | Create report (`status: open`); **no list/triage API** |
| GET | `/admin/users` | Admin | Clerk user list + roles |
| POST | `/admin/invites` | Admin | Invite |
| PATCH | `/admin/users/{id}` | Admin | Patch Clerk `public_metadata.role` |
| DELETE | `/admin/users/{id}` | Admin | Deactivate (Clerk + soft local user) |
| GET | `/health` | Public | Liveness |

## Data model (SQLAlchemy)

**users**

- `id` TEXT PK (= Clerk `sub`), `email`, timestamps, `deleted_at`
- **No `role` column** — Clerk only

**scans**

- `user_id` FK → `users.id` (required for saved scans)
- `input_url`, `normalized_url`, `host`, `score`, `verdict`, `risk_band`, `breakdown` JSON, `weights_version`, `created_at`

**favorites**

- `user_id`, `scan_id`; UNIQUE(`user_id`, `scan_id`)

**reports**

- `user_id`, `url`, optional `scan_id`, optional `note`, `status` (default `open`), `created_at`

**guest_scan_days**

- IP + UTC day + count for guest rate limit

## Repository layout

```
LinkGuard/
  plan.md
  docs/clerk-auth-rollout-plan.md
  client/          # Vite + React
  server/          # Flask
```

## Environment variables

| Variable | Purpose |
|----------|---------|
| `VITE_CLERK_PUBLISHABLE_KEY` | Client Clerk |
| `VITE_API_URL` | API base (optional; defaults same origin) |
| `CLERK_ISSUER`, `CLERK_JWT_KEY`, `CLERK_SECRET_KEY` | Server JWT + Backend API |
| `DATABASE_URL` | Postgres (else SQLite `server/linkguard.db`) |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Threat intel (skip signal if missing) |
| `CORS_ORIGINS` | Dev client origins |

## Deliverables & status

| Item | Status |
|------|--------|
| Monorepo client + server + README | Done |
| Home, Result, Auth, Dashboard, Favorites, Admin | Done |
| EN/HE + RTL + Clerk HE localization | Done |
| Safety scoring v4 + domain age RDAP | Done |
| Guest limit + auth history | Done |
| Favorites list + toggle | Done |
| Reports create-only | Done (moderation later) |
| Admin users/roles | Done |
| Tests (`test_domain_age.py`, normalization, etc.) | Partial |
| Admin reports UI | **Not started** |
| Expand RDAP TLD coverage (e.g. `.il`) | **Future** |
| `insufficient_reasons` i18n on server | **Future** |

## Phased rollout (updated)

1. **A:** React shell, i18n + RTL, Flask health, schema, Clerk — **done**
2. **B:** Normalization, inner signals, Safe Browsing, Result page — **done**
3. **C:** Auth history, favorites, reports API, guest limits — **done** (reports UI pending)
4. **D:** Safety scoring v4, domain age RDAP, SSL removed, client verdict alignment — **done**
5. **E:** Admin reports moderation, more TLDs / threat APIs, observability, copy/legal review — **next**

## Open decisions

- Whether to add **admin reports inbox** (list, status transitions, assignee)
- **Persist anonymous scans** or keep ephemeral-only (current: ephemeral for guests)
- **Contributor** future capabilities
- Optional: retry/`getMe` hardening so scan never runs before user row exists (today relies on `/me` after sign-in)

---

*Plan version: 2.0 — safety score model, new verdicts/bands, SSL removed, RDAP domain age, `/me` user provisioning, favorites page, Clerk i18n.*
