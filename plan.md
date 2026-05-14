# LinkGuard — Product & Engineering Plan

## Vision

LinkGuard is a web application that helps users assess whether a URL is likely risky before they click. The client collects a URL, normalizes and validates it, and the backend runs layered checks (technical signals, typosquatting heuristics, and threat-intelligence APIs). Results are presented as a weighted score, a risk band, plain-language explanations, and recommended next steps—never as absolute certainty.

## Tech Stack

| Layer | Choice |
|--------|--------|
| Client | React.js (SPA; Vite + React Router recommended) |
| Server | Python Flask (REST API) |
| Auth | [Clerk](https://clerk.com/) |
| Database | [Neon](https://neon.com/) (serverless Postgres) |
| i18n | Dictionary-based JSON; English default + Hebrew |
| RTL | Full layout RTL when Hebrew is selected |

## Confirmed product decisions

| Topic | Decision |
|--------|----------|
| Guest scanning | **Allowed** with **3 scans per day per IP**; **scan history only for signed-in users**. |
| Contributor (MVP) | **Same capabilities as user**; `contributor` role reserved for future features (simplest RBAC). |
| External APIs (phase 1) | **Google Safe Browsing + inner heuristics** first; URLhaus, VirusTotal, IPQualityScore, CheckPhish in **later phases** (wire with graceful degradation when keys exist). |
| URL storage | Store **full normalized URL + host** in Neon for dashboards and history. |
| Clerk roles | **`public_metadata.role`**: **`user`** \| **`admin`** in MVP (**`contributor`** later); lazy default **`user`** on first API hit; hybrid JWT + optional Clerk user fetch; no Neon `users.role` for authz. Details: `docs/clerk-auth-rollout-plan.md`. |

## Core product rules (non-negotiable)

1. **Never claim 100% safety.** Do not say “this link is definitely safe.” Use calibrated language, e.g. “No strong risk indicators were found based on the checks we could run.”
2. **Insufficient data** is a first-class outcome when APIs fail, quotas are exceeded, or signals are missing—show **Insufficient Data** with explanation and recommended next steps.
3. **Always** show: explanation (“why this result”), recommended actions, and which signals/sources contributed (including unavailable or skipped checks).

## User roles

| Role | Capabilities (MVP) |
|------|---------------------|
| **User** | Submit URLs (within limits), view own scan history, favorites, report URL |
| **Contributor** | Same as user; role kept for future differentiation |
| **Admin** | User list with roles, invite user, remove/deactivate user; optional moderation later |

**Implementation:** **`public_metadata.role`** (`user` \| `admin` in MVP; **`contributor`** later) is the **only** source of truth for permissions—**not** stored on Neon `users`. Map Clerk `sub` to `users.id` for FKs and optional email cache. On **first authenticated API hit**, if **`role`** is missing, the **server** sets **`user`** via Clerk Backend API (**lazy provisioning**; no webhook required for local). Read **`role`** with **hybrid** JWT claims first, **GET user** fallback (short TTL cache optional). See `docs/clerk-auth-rollout-plan.md`.

## Client pages

### 1. Home

- Header: LinkGuard branding, **EN / HE** language switcher, Login/Register (Clerk)
- Hero: simple value proposition
- Large URL input with **client-side format validation** and **normalization preview**
- Primary CTA to analyze
- Example “suspicious-looking” URLs for education (non-malicious patterns)
- Short “how it works” (normalize → check → score → explain)

### 2. Result (after submit)

- **Verdict banner:** Safe (low-risk wording only) | Suspicious | Dangerous | Insufficient Data  
- **Risk score:** 0–100 (weighted)
- **Risk level:** 0–24 Low · 25–49 Medium · 50–74 High · 75–100 Critical
- **Why this result?** Per-signal breakdown (pass / concern / unknown + short text)
- **Recommended next actions**
- **Sources/signals used** (ran, skipped, error)
- **Normalized URL** details (scheme, host, punycode, IP-as-host if applicable)
- **Report URL** · **Save to favorites** (auth-gated or prompt to sign in)

### 3. Login / Register

- Clerk `<SignIn />` / `<SignUp />` or hosted pages—**open decision:** embedded vs hosted (pick one for MVP consistency)

### 4. User dashboard

- **Scan history** table: URL (truncated), score, verdict/band, short reason, date—sorted by date descending, paginated

### 5. Admin dashboard

- Users + roles
- Invite user (email + role)
- Remove / deactivate user (soft delete + session policy)

## Localization (EN / HE)

- Default: **English**
- **Hebrew (עברית):** full **RTL** (`dir="rtl"`), logical CSS (`margin-inline`, `start`/`end`), mirrored header, forms, tables, dialogs
- Language switcher in header; persist preference (`localStorage` + optional profile field)
- All user-facing strings in JSON dictionaries (`en.json`, `he.json`)
- Locale-aware dates and numbers

**Quality bar:** Clean component structure, responsive layout, accessible UI (labels, focus, contrast, live regions for async scan).

## Backend validations

### Inner (computed) signals

| Signal | Notes |
|--------|--------|
| Parse + normalization | Scheme, host, path, IDN/punycode, sensible defaults |
| Domain age | RDAP/WHOIS with caching and rate limits |
| SSL/TLS | Validity, hostname match, chain, expiry |
| Typosquatting / homograph | Brand distance heuristics; confusable / mixed-script detection |
| IP-as-host | Literal IP in host vs domain |
| Entropy | High-randomness path/query heuristic |
| Link shorteners | Detect known shorteners; optional expand-once with strict limits |

### External APIs (phased)

| Phase | APIs |
|--------|------|
| **1** | Google Safe Browsing + all inner signals above |
| **2+** | URLhaus, VirusTotal, IPQualityScore, CheckPhish—each adapter returns `{ ok \| error \| skipped }` so the pipeline never fails silently |

**Resilience:** Missing keys or HTTP errors contribute to partial results or **Insufficient Data**, never a blank screen.

## Weighted scoring

- **Versioned config** (JSON/YAML): per-signal weight, caps, and behavior for `unknown` (document whether unknown slightly increases uncertainty or stays neutral)
- Output: `score` (0–100), `band`, `verdict`, `breakdown[]`, `weights_version`
- No secrets or raw API keys in client responses; redact sensitive logs

## Suggested API routes (Flask)

Prefix: `/api/v1` (JSON). Mutations and history require **Clerk JWT** verified server-side. Guest (unauthenticated) scans: **3 per IP per calendar day** (enforce server-side; return `429` with clear message when exceeded).

| Method | Path | Auth | Description |
|--------|------|------|---------------|
| POST | `/scans` | Optional / rate-limited | Body `{ url }` — run or enqueue scan |
| GET | `/scans/{id}` | Owner or Admin | Full result |
| GET | `/me` | User+ | Session bootstrap; resolves Clerk `public_metadata.role` (lazy default) |
| GET | `/me/scans` | User+ | Paginated history |
| POST | `/scans/{id}/favorite` | User+ | Favorite toggle |
| POST | `/reports` | User+ | Report URL + optional note |
| GET | `/admin/users` | Admin | List users + roles |
| POST | `/admin/invites` | Admin | Invite |
| DELETE | `/admin/users/{id}` | Admin | Deactivate |
| GET | `/health` | Public | Liveness |

## Data model (Neon / Postgres)

**users**

- `id` TEXT PK (= Clerk `sub`)
- `email` TEXT (optional cache from Clerk webhooks)
- `created_at`, `updated_at`, `deleted_at`
- **No `role` column** — app role lives in Clerk **`public_metadata`** only; see `docs/clerk-auth-rollout-plan.md`.

**scans**

- `id` UUID PK
- `user_id` UUID NULLABLE (null = anonymous scan row if you store anonymous results temporarily—**or** omit persistence for anonymous and only return JSON; if persisting for abuse analytics, use hashed fingerprint instead of full URL for anon—**recommend:** persist full URL + host only when `user_id` is set; for anonymous return in-memory only unless compliance requires otherwise)
- `input_url` TEXT, `normalized_url` TEXT, `host` TEXT
- `score` INT, `verdict` ENUM, `risk_band` ENUM
- `breakdown` JSONB
- `weights_version` TEXT
- `created_at` TIMESTAMPTZ
- Index: `(user_id, created_at DESC)`

**favorites**

- `user_id`, `scan_id` (or normalized URL), `created_at`; UNIQUE(user_id, target)

**reports**

- `id`, `user_id`, `url`, `scan_id` NULL, `note`, `status`, `created_at`

**rate_limits** (MVP)

- **Guests:** count scans by **client IP**, cap **3 per calendar day** (document timezone, e.g. UTC midnight).
- **Authenticated users:** optional higher/default tier (define separately); still track if abuse protection is needed.

*Refine anonymous persistence in implementation to match privacy policy; table above allows “history only when logged in” by only linking durable history to `user_id`.*

## Repository layout (suggested)

```
LinkGuard/
  plan.md
  client/          # Vite + React
  server/          # Flask
```

## Flask structure (suggested)

```
server/
  app/
    __init__.py
    routes/          # scans, admin, health
    services/
      normalize.py
      signals/
      integrations/  # safebrowsing (phase 1); stubs for others
      scoring.py
    models/
    auth/            # Clerk JWT
  migrations/        # Alembic
  tests/
```

## Client structure (suggested)

```
client/src/
  app/               # routes
  components/
  features/scan/, dashboard/, admin/
  i18n/              # en.json, he.json, provider
  lib/               # api client, url helpers
```

## Environment variables

- Clerk: publishable key (client), secret + JWKS (server)
- Neon: `DATABASE_URL`
- `GOOGLE_SAFE_BROWSING_API_KEY` (phase 1)
- Later: URLhaus, VirusTotal, IPQualityScore, CheckPhish keys as enabled

## Deliverables

1. Runnable monorepo: `client` + `server` + README
2. All core pages: Home, Result, Auth (Clerk), User dashboard, Admin dashboard
3. Reusable UI components; polished demo-ready visual design
4. Full EN/HE + RTL verification
5. Weighted scoring with visible breakdown and config versioning
6. Tests: URL normalization, scoring aggregation, mocked external HTTP

## Phased rollout

1. **A:** React shell, i18n + RTL, Flask health + mock scan; Neon schema; Clerk webhook or sync for `users`
2. **B:** Normalization + inner signals + Safe Browsing; Result page end-to-end
3. **C:** Auth-gated history, favorites, reports; anonymous limit enforcement
4. **D:** Admin invites/removals; additional API integrations
5. **E:** Observability, abuse hardening, copy/legal review for “never 100% safe” messaging

## Open decisions (non-blocking)

- Clerk **embedded vs hosted** auth pages
- Whether to **persist anonymous scans** at all (vs. ephemeral response only)
- Contributor **future** capabilities (queue, reputation, etc.)

---

*Plan version: 1.2 — guest limit: 3 scans per IP per day.*
