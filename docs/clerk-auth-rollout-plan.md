# Clerk auth & roles — LinkGuard

This document replaces the prior **organizations-only** rollout. LinkGuard uses **Clerk user metadata** (and session JWT claims) for **app roles**, with **no authorization role stored in Postgres**. The app is expected to run **locally** for development without requiring a public webhook URL unless you opt in later.

---

## Locked decisions

| Topic | Choice |
|--------|--------|
| Metadata key | **`public_metadata.role`** (string). |
| MVP role values | **`user`** and **`admin`** only in code and validation. **`contributor`** reserved for a later phase (product plan still lists it as same capabilities as `user`). |
| How the server reads `role` | **Hybrid (recommended):** use **`role` from the verified session JWT** when your Clerk **session token template** exposes `public_metadata` (or a dedicated `role` claim). If the claim is **missing or ambiguous** (e.g. right after lazy PATCH, before refresh), **fall back once** to **`GET /v1/users/{id}`** and optionally cache for a **short TTL** (e.g. 30–120s) keyed by `sub`. |
| Admin HTTP surface | **Full MVP:** implement real behavior for the admin routes below (Clerk Backend API + metadata), not only route gating. |

---

## Goals

| Goal | Outcome |
|------|---------|
| Roles | **`public_metadata.role`**: **`user`** \| **`admin`** in MVP; **`contributor`** later. |
| Default for new users | **`user`** — assigned lazily on the **server** the first time the user is seen, if **`role`** is missing. |
| Admin | At least one account has **`public_metadata.role: "admin"`** in the **Clerk Dashboard** (break-glass). Never promote to **admin** from “missing role.” |
| Guests | Unchanged: guest scans stay **outside** Clerk; no metadata needed. |
| No DB role | Neon **`users`** row is for **`id`** (= Clerk `sub`), **email** cache, timestamps — **not** for authorization **`role`**. |

---

## Principles

1. **Clerk is the source of truth** for who is admin; the API **never** uses `users.role` in Neon for authz (dropping that column is a **later migration** once code no longer references it).
2. **Server-only writes:** only Flask (with **`CLERK_SECRET_KEY`**) may set or change **`public_metadata.role`** — not the browser.
3. **Default role is the lowest privilege:** if **`role`** is absent, the backend sets **`user`** (never **`admin`**).
4. **JWT freshness:** after a successful Clerk API update to metadata, the **current** session JWT may not include the new claim until **token refresh** or **re-sign-in**. The API should treat a successful default assignment as authoritative for **that** request, and the client should tolerate a short delay or refresh session when needed.

---

## Phase 0 — Clerk Dashboard (manual)

- [ ] **`public_metadata`:** shape **`{ "role": "user" }`** or **`{ "role": "admin" }`** on users.
- [ ] Set **`role: "admin"`** on your admin test user in the Dashboard.
- [ ] (Recommended) **Session token template:** expose **`public_metadata`** or a top-level **`role`** claim so Flask can authorize without a Clerk HTTP call on every happy path. See [Session tokens](https://clerk.com/docs/guides/sessions/session-tokens).
- [ ] **Organizations:** leave **disabled** or unused for this path — no `CLERK_ORG_ID`, no org membership required.

---

## Phase 1 — Server configuration

| Variable | Purpose |
|----------|---------|
| `CLERK_SECRET_KEY` | Clerk Backend API — **required** for lazy default metadata and admin actions. |
| `CLERK_ISSUER`, `CLERK_JWT_KEY` (optional PEM) | Existing session JWT verification. |

Document in **`server/.env.example`**; never expose the secret key to Vite.

**`server/app/config.py`:** load `CLERK_SECRET_KEY` when metadata / Clerk API features are enabled.

---

## Phase 2 — Lazy default role (“first seen”)

No webhook required for local dev.

1. After **`verify_clerk_jwt`**, read **`sub`** and resolve **`role`** from JWT claims (**hybrid:** if missing, **`GET /v1/users/{user_id}`** and optional short TTL cache).
2. If **`role` is missing or empty**, call Clerk **`PATCH /v1/users/{user_id}`** (merge **`public_metadata`**) to set **`role: "user"`** (idempotent).
3. Handle **concurrent first requests** gracefully (duplicate PATCH with same value is fine).
4. **Short-circuit** after write: for that request, treat role as **`user`** without waiting for JWT refresh.

Optional later: **`user.created` webhook** (public HTTPS — ngrok or hosted function) if you need metadata **before** the first API call.

---

## Phase 3 — Authorization (replace DB `users.role`)

Today: **`users.role == "admin"`** in Neon (`require_admin`).

Target:

- **`require_app_admin`** (or renamed decorator): session JWT verified; **`public_metadata.role == "admin"`** via **hybrid** read above — **do not** read **`User.role`** from the database.
- **Cross-user admin read** of a scan: allow if **`role == "admin"`** in Clerk metadata/claims.

---

## Phase 4 — Admin API (everything needed for MVP)

Implement against **Clerk Backend API** with **`CLERK_SECRET_KEY`** (server only). Align paths with `plan.md` / Flask router prefix (`/api/v1`).

| Route | Behavior |
|-------|----------|
| **`GET /api/v1/admin/users`** | List users (Clerk **Users** list or search with pagination). Return id, email, primary identifiers, and **`public_metadata.role`** (or effective role after defaults). |
| **`PATCH /api/v1/admin/users/<user_id>`** (or `.../role`) | **Admin only:** merge **`public_metadata.role`** to **`user`** or **`admin`** only (MVP validation). Reject **`contributor`** until that phase exists. |
| **`POST /api/v1/admin/invites`** | Create a **Clerk invitation** for the email; on accept, user signs in — combine with **lazy default `role: user`** on first API hit **or** set default metadata via webhook later if you add one. Document chosen behavior in code comments. |
| **`DELETE /api/v1/admin/users/<user_id>`** | Product choice: **ban** user in Clerk, **delete** user, or **soft-delete** in Neon only for app rows — align with Clerk docs and privacy needs. If Neon soft-delete only, document that the user can still sign in to Clerk until Clerk-side ban. |

Replace stubs in **`server/app/routes/admin.py`** and remove dependence on **`User.role`** for authorization.

---

## Phase 5 — Client

- **Admin nav:** show **Admin** only when **`publicMetadata.role === "admin"`** or matching **session claim**, consistent with Flask **403**.
- No **`<OrganizationSwitcher />`** requirement for this plan path.

---

## Phase 6 — Data & migrations (deferred)

- **Migration (later):** drop **`users.role`** once no code path reads or writes it.
- Until then, code may ignore the column or stop writing it.

---

## Phase 7 — Testing checklist

- [ ] New self-registered user → first API hit → **`public_metadata.role`** becomes **`user`** (verify in Dashboard or next JWT).
- [ ] Admin user → **`role: admin`** → admin APIs **200**; non-admin → **403**.
- [ ] Guest scan still works without Clerk session.
- [ ] No accidental **admin** on empty metadata.

---

## Optional later: `user.created` webhook

Use if you need metadata **before** any LinkGuard API call. Requires a **public HTTPS** endpoint. Verify with **`CLERK_WEBHOOK_SIGNING_SECRET`** (Svix). See [Clerk webhooks](https://clerk.com/docs/integrations/webhooks/overview).

---

## Optional future: Clerk Organizations

If you later need a single shared org or org-only invites, see [Organizations](https://clerk.com/docs/organizations/overview).

---

## References

- [Clerk public metadata](https://clerk.com/docs/users/user-metadata)  
- [Clerk Backend API — Users](https://clerk.com/docs/reference/backend-api/tag/Users)  
- [Session tokens](https://clerk.com/docs/guides/sessions/session-tokens)  
- [Webhooks](https://clerk.com/docs/integrations/webhooks/overview)

---

*Plan version: 2.1 — `public_metadata.role`; MVP `user` \| `admin`; hybrid JWT + API read; full admin route MVP.*
