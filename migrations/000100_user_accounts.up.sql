-- Email + password sign-in.
--
-- Until now GoClaw had no concept of a user account: callers authenticated with
-- a static gateway token, an API key, or a browser pairing code, and the user
-- identity itself was a self-declared string in the X-GoClaw-User-Id header
-- that was never verified. That made it impossible to onboard a person, to
-- revoke one person's access, or to tell two people apart in an audit log.
--
-- users.user_id is deliberately separate from users.id: id is the immutable
-- database key, user_id is the string that already appears throughout the
-- system (tenant_users.user_id, api_keys.owner_id, agent/session ownership).
-- Keeping them apart lets an operator attach a new email account to identity
-- data that predates this table, including the bootstrap "system" identity.
--
-- The table is global (no tenant_id): tenant_users already models membership
-- with UNIQUE(tenant_id, user_id), so one account is allowed to belong to
-- several tenants. Writes are therefore gated by master scope, matching how
-- api_keys treats system-level keys.

CREATE TABLE users (
    id                   UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    user_id              VARCHAR(255) NOT NULL UNIQUE,
    email                VARCHAR(320) NOT NULL,
    password_hash        TEXT NOT NULL,
    display_name         VARCHAR(255) NOT NULL DEFAULT '',
    status               VARCHAR(20) NOT NULL DEFAULT 'active',
    must_change_password BOOLEAN NOT NULL DEFAULT false,
    last_login_at        TIMESTAMPTZ,
    created_by           VARCHAR(255) NOT NULL DEFAULT '',
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Email comparison is case-insensitive everywhere (lookup and uniqueness), so
-- Admin@Example.com and admin@example.com cannot become two accounts.
CREATE UNIQUE INDEX idx_users_email_lower ON users (lower(email));

-- Opaque session tokens issued by POST /v1/auth/login.
--
-- user_id is denormalized from users so the authentication hot path resolves a
-- request with a single indexed lookup and no join, the same shape as the
-- api_keys.key_hash lookup it sits next to.
CREATE TABLE user_sessions (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v7(),
    user_uuid    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    user_id      VARCHAR(255) NOT NULL,
    token_hash   VARCHAR(64) NOT NULL UNIQUE,
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
