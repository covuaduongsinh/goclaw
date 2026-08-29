# 25 — Email + Password Sign-In

Accounts that a person signs in to with an email address and a password, alongside the credentials described in [20 — API Keys & Authentication](20-api-keys-auth.md).

Before this existed, GoClaw had no concept of a user account. Callers authenticated with a static gateway token, an API key, or a browser pairing code, and the user identity itself was a self-declared string in the `X-GoClaw-User-Id` header that was never verified. That made it impossible to onboard a person, to revoke one person's access, or to tell two people apart in an audit log.

Accounts are provisioned by an administrator. There is no self-service sign-up, no email delivery, and therefore no email verification or password-reset link. A forgotten password is reset by an administrator.

---

## 1. What a session token is

`POST /v1/auth/login` returns an opaque token of the form `goclaws_<64 hex characters>`. Only its SHA-256 hash is stored; the raw value exists solely in the client.

The prefix is deliberately one character longer than the API key prefix `goclaw_`, and does not match a `HasPrefix` test for it (the seventh byte is `s`, not `_`). Server and client both rely on telling the two apart.

The token is used exactly like any other bearer credential, which is why no transport changes were needed:

```
Authorization: Bearer goclaws_<64 hex>
```

```json
{"method": "connect", "params": {"token": "goclaws_<64 hex>", "user_id": "alice"}}
```

Default lifetime is 30 days, configurable with `GOCLAW_SESSION_TTL_HOURS`.

## 2. Identity and roles

`users.user_id` is separate from `users.id`. `id` is the immutable row key; `user_id` is the string identity that already threads through `tenant_users.user_id`, `api_keys.owner_id` and agent/session ownership.

Keeping them apart is what lets an administrator attach a new account to data that predates the account — including the bootstrap `system` identity — by passing `user_id` explicitly at creation. Without it, the identity is derived from the local part of the email address and made unique.

Once a session authenticates, `user_id` comes from the database. The `X-GoClaw-User-Id` header is ignored for session callers, and a mismatch is logged as `security.session_user_override`.

The gateway role is derived from `tenant_users.role` for the resolved tenant, the same source the browser-pairing path uses. **An account with no tenant membership resolves to `viewer`**, which the web dashboard treats as unusable — so create accounts with a tenant and role, or grant membership straight afterwards.

## 3. Endpoints

### Self-service

| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/v1/auth/login` | none | `{email, password}` → `{token, expires_at, user, tenants[]}` |
| POST | `/v1/auth/logout` | session | Revokes the calling session |
| GET | `/v1/auth/me` | any | Account, role, tenant and memberships |
| POST | `/v1/auth/change-password` | session | `{current_password, new_password}`; revokes every other session |

`logout`, `me` and `change-password` require `viewer` explicitly rather than the method-derived default. `httpMinRole` maps POST to `operator`, which would leave a viewer account unable to sign out or change its own password.

### Administration

All require `admin` **and** master scope, because `users` is a global table with no `tenant_id`. See `CONTRIBUTING.md` → "Tenant-scope guards".

| Method | Path |
|---|---|
| GET / POST | `/v1/users` |
| GET / PATCH / DELETE | `/v1/users/{id}` |
| POST | `/v1/users/{id}/password` |
| POST | `/v1/users/{id}/sessions/revoke` |

`POST /v1/users` accepts `{email, password, user_id?, display_name?, tenant_id?, tenant_role?, must_change_password?}`. When `tenant_id` is present the `tenant_users` row is written in the same request.

`PATCH` cannot change `user_id`: the value is referenced by tenant membership and resource ownership, so changing it in place would silently strip the account of its access. Rebinding an identity is a data migration.

### WebSocket

`users.list`, `users.get`, `users.create`, `users.update`, `users.delete`, `users.password.set` — same admin + master-scope rules. Params are camelCase, matching the rest of the WS surface.

> `MethodRole` is fail-closed: a method missing from the admin allowlist in `internal/permissions/policy.go` is denied for **every** role including owner, and the resulting error reads like an auth failure. `TestMethodRole_UsersMethodsAreAdmin` pins this.

## 4. Password handling

bcrypt at cost 12, configurable with `GOCLAW_BCRYPT_COST` (clamped to 10–15).

bcrypt rather than a memory-hard KDF because `/v1/auth/login` is reachable pre-auth: scrypt at `N=16384, r=16` costs 32 MB per attempt, so a handful of concurrent sign-ins exhausts a small container. bcrypt costs roughly 250 ms of CPU and 4 KB of memory, and carries its own cost parameter so the work factor can be raised later with `NeedsRehash`.

Policy: at least 12 characters, at most **72 bytes**. The byte limit is bcrypt's, and it matters in practice — accented Vietnamese runs 2–3 bytes per character, so a 25-character password can cross it. It is validated before hashing so the caller gets a 400 explaining the limit rather than an opaque 500.

## 5. Where the session branch sits in auth

HTTP (`internal/http/auth.go`), in order: gateway token → API key → **session token** → browser pairing → no-auth fallback.

Both neighbours matter:

- **After API keys**: a `goclaws_` token can never match an API key hash, so nothing is shadowed and the existing hot path is untouched.
- **Before pairing**: the web client sends `Authorization` and `X-GoClaw-Sender-Id` on the same request. If pairing resolved first, a signed-in user on a paired browser would authenticate as whatever `X-GoClaw-User-Id` claimed.

A token carrying the session prefix that does not resolve is **denied immediately**. It must not fall through to the no-auth fallback, which grants `RoleAdmin` whenever no gateway token is configured.

WebSocket (`internal/gateway/router.go`) mirrors this as Path 1c, between the API-key path and the no-token fallback, and rejects rather than issuing a pairing code.

Sessions are cached for 60 seconds — not the API key cache's five minutes. An API key is revoked rarely and by an administrator; a session is revoked by the person using it, every time they sign out.

## 6. Rate limiting

Two buckets, both must allow the request: 20/min per IP (burst 5) and 5/min per email (burst 3).

`rateLimitKeyFromRequest` is deliberately not reused — it falls back to `X-GoClaw-User-Id`, which on a pre-auth endpoint the caller picks freely, so rotating it would reset the budget.

Behind a reverse proxy every request arrives from the proxy's address and the per-IP bucket degrades to a single shared bucket. `X-Forwarded-For` is **not** consulted to compensate: without a list of trusted proxies, honouring it would let any caller reset their own bucket by inventing a header. The per-email bucket is unaffected by proxying and carries the protection there.

Sign-in answers the same message and status for an unknown address, a wrong password and a disabled account, and runs a bcrypt comparison against a dummy hash on the miss branch so response time does not reveal which addresses are registered. Logs record a truncated SHA-256 of the address, never the address itself.

## 7. Creating the first account

No account exists on a fresh install, so the first one is created from the command line, against the database rather than the API:

```bash
goclaw user create --email admin@example.com --generate --tenant master --role owner
```

`--generate` prints a random password once. Without it the password is read from the terminal with echo off, or from `GOCLAW_USER_PASSWORD`. `--password` exists but is not the default path: flag values appear in the process list and shell history.

Other subcommands: `goclaw user list`, `passwd`, `disable`, `enable`, `sessions list`, `sessions revoke`.

> The command is `user`, not `auth`: `goclaw auth` already manages the ChatGPT OAuth credential used by the Codex provider.

## 8. Degraded operation

Every route is wired only when the account store is present, and answers `503` when it is not.

This is reachable in practice: `docker-entrypoint.sh` runs `goclaw upgrade || echo "Upgrade warning"`, so a container starts even when a migration fails. In that state sign-in is unavailable while the gateway-token, API-key and pairing paths keep working — which is why the web login page keeps its **Token** tab alongside the new **Email** tab.

## 9. Schema

```sql
CREATE TABLE users (
    id                   UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    user_id              VARCHAR(255) NOT NULL UNIQUE,
    email                VARCHAR(320) NOT NULL,
    password_hash        TEXT NOT NULL,
    display_name         VARCHAR(255) NOT NULL DEFAULT '',
    status               VARCHAR(20) NOT NULL DEFAULT 'active',   -- active | disabled
    must_change_password BOOLEAN NOT NULL DEFAULT false,
    last_login_at        TIMESTAMPTZ,
    created_by           VARCHAR(255) NOT NULL DEFAULT '',
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX idx_users_email_lower ON users (lower(email));

CREATE TABLE user_sessions (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    user_uuid    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    user_id      VARCHAR(255) NOT NULL,          -- denormalized: one indexed lookup, no join
    token_hash   VARCHAR(64) NOT NULL UNIQUE,    -- SHA-256 hex
    tenant_id    UUID REFERENCES tenants(id),
    user_agent   VARCHAR(255) NOT NULL DEFAULT '',
    ip           VARCHAR(64) NOT NULL DEFAULT '',
    expires_at   TIMESTAMPTZ NOT NULL,
    revoked_at   TIMESTAMPTZ,
    last_seen_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_user_sessions_user ON user_sessions(user_uuid);
CREATE INDEX idx_user_sessions_expires ON user_sessions(expires_at);
```

Email uniqueness is enforced on `lower(email)`, so one person cannot become two accounts through casing.

Expired sessions are handled in three layers: lookups filter them out, an hourly sweeper deletes rows more than 7 days past expiry, and sign-in trims an account to its 10 newest live sessions so a login loop cannot grow the table without bound.

PostgreSQL migration `000098_user_accounts`; SQLite schema version 61. SQLite evaluates session expiry in Go rather than SQL, because its timestamps are text in the driver's layout, which is not the layout `datetime('now')` produces.

## 10. Web UI

The sign-in page has three tabs — **Email** (default), **Token**, **Pairing** — at `ui/web/src/pages/login/`.

`ws-client.ts` treats "connected with a token but assigned viewer" as a bad token and signs the client out. That heuristic holds for gateway tokens and API keys, which always carry at least operator, but not for an account, where viewer is legitimate. It is therefore skipped for tokens carrying `SESSION_TOKEN_PREFIX`; without that, an account with viewer membership would be signed out immediately after every successful login.

Account management lives at `/admin/users` (owner only). The password-change dialog opens from the user menu, and opens forced and undismissable while `must_change_password` is set.

## 11. Not included

No SMTP, no email verification, no password-reset link, no self-service sign-up, no OAuth or SSO. Desktop (`ui/desktop`) authenticates via an OS keyring token binding and has no router or login surface, so email sign-in is web-only.

## 12. File reference

| Area | Path |
|---|---|
| Password hashing | `internal/crypto/password.go` |
| Session tokens | `internal/crypto/apikey.go` |
| Store interface | `internal/store/user_store.go` |
| Store implementations | `internal/store/pg/user_store.go`, `internal/store/sqlitestore/users.go` |
| HTTP sign-in | `internal/http/auth_login.go` |
| HTTP administration | `internal/http/users_admin.go` |
| Session cache + resolution | `internal/http/user_session_cache.go` |
| Rate limiting | `internal/http/login_rate_limiter.go` |
| HTTP auth branch | `internal/http/auth.go` |
| WebSocket auth branch | `internal/gateway/router.go` |
| WebSocket methods | `internal/gateway/methods/users.go` |
| CLI | `cmd/user.go` |
| Session sweeper | `cmd/gateway_session_sweeper.go` |
| Migration | `migrations/000098_user_accounts.up.sql` |
