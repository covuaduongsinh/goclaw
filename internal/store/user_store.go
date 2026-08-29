package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// User account status values.
const (
	UserStatusActive   = "active"
	UserStatusDisabled = "disabled"
)

// UserData is an email + password account.
//
// ID and UserID are deliberately distinct. ID is the immutable database key.
// UserID is the string identity that already threads through the rest of the
// system — tenant_users.user_id, api_keys.owner_id, agent and session
// ownership — and an operator may set it explicitly so a new account inherits
// data that predates the users table.
type UserData struct {
	ID                 uuid.UUID  `json:"id" db:"id"`
	UserID             string     `json:"user_id" db:"user_id"`
	Email              string     `json:"email" db:"email"`
	PasswordHash       string     `json:"-" db:"password_hash"` // never serialized
	DisplayName        string     `json:"display_name" db:"display_name"`
	Status             string     `json:"status" db:"status"`
	MustChangePassword bool       `json:"must_change_password" db:"must_change_password"`
	LastLoginAt        *time.Time `json:"last_login_at" db:"last_login_at"`
	CreatedBy          string     `json:"created_by" db:"created_by"`
	CreatedAt          time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at" db:"updated_at"`
}

// IsActive reports whether the account may sign in.
func (u *UserData) IsActive() bool { return u.Status == UserStatusActive }

// UserSessionData is a login session backing an opaque bearer token.
//
// UserID is denormalized from UserData so the authentication hot path resolves
// a request with one indexed lookup and no join.
type UserSessionData struct {
	ID         uuid.UUID  `json:"id" db:"id"`
	UserUUID   uuid.UUID  `json:"user_uuid" db:"user_uuid"`
	UserID     string     `json:"user_id" db:"user_id"`
	TokenHash  string     `json:"-" db:"token_hash"` // never serialized
	TenantID   uuid.UUID  `json:"tenant_id" db:"tenant_id"`
	UserAgent  string     `json:"user_agent" db:"user_agent"`
	IP         string     `json:"ip" db:"ip"`
	ExpiresAt  time.Time  `json:"expires_at" db:"expires_at"`
	RevokedAt  *time.Time `json:"revoked_at" db:"revoked_at"`
	LastSeenAt *time.Time `json:"last_seen_at" db:"last_seen_at"`
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
}

// MaxActiveSessionsPerUser caps how many live sessions one account keeps.
// Creating one past the cap evicts the oldest, so a script that logs in on a
// loop cannot grow the table without bound.
const MaxActiveSessionsPerUser = 10

// UserStore manages email/password accounts and their login sessions.
//
// The two tables share one interface because they are never used apart: sign-in
// reads users and writes user_sessions, and deleting a user cascades its
// sessions. No tenant scoping is applied at store level — users is a global
// table and callers enforce master scope.
type UserStore interface {
	// CreateUser inserts a new account. Returns a driver uniqueness error when
	// the email or user_id is already taken.
	CreateUser(ctx context.Context, u *UserData) error

	// GetUserByID looks up an account by its database key.
	// Returns sql.ErrNoRows when absent.
	GetUserByID(ctx context.Context, id uuid.UUID) (*UserData, error)

	// GetUserByUserID looks up an account by its string identity.
	GetUserByUserID(ctx context.Context, userID string) (*UserData, error)

	// GetUserByEmail looks up an account case-insensitively. Sign-in uses this,
	// so it must not filter on status: a disabled account has to be
	// distinguishable from a missing one in the log, while still producing the
	// same response to the caller.
	GetUserByEmail(ctx context.Context, email string) (*UserData, error)

	// ListUsers returns accounts newest first.
	ListUsers(ctx context.Context, limit, offset int) ([]UserData, error)

	// UpdateUser applies a partial update. Allowed keys: display_name, status,
	// must_change_password.
	UpdateUser(ctx context.Context, id uuid.UUID, updates map[string]any) error

	// SetPassword replaces the stored hash.
	SetPassword(ctx context.Context, id uuid.UUID, hash string, mustChange bool) error

	// TouchLastLogin records a successful sign-in.
	TouchLastLogin(ctx context.Context, id uuid.UUID) error

	// DeleteUser removes an account; its sessions cascade.
	DeleteUser(ctx context.Context, id uuid.UUID) error

	// UserIDExists reports whether a string identity is taken. Used when
	// deriving a default user_id from an email address.
	UserIDExists(ctx context.Context, userID string) (bool, error)

	// CreateSession inserts a login session.
	CreateSession(ctx context.Context, s *UserSessionData) error

	// GetSessionByHash returns a live session — not revoked, not expired —
	// together with its account. Returns (nil, nil, nil) when there is no match,
	// so an unknown token is not an error condition.
	GetSessionByHash(ctx context.Context, tokenHash string) (*UserSessionData, *UserData, error)

	// TouchSessionSeen records session activity.
	TouchSessionSeen(ctx context.Context, id uuid.UUID) error

	// RevokeSession marks one session revoked by its token hash.
	RevokeSession(ctx context.Context, tokenHash string) error

	// RevokeAllUserSessions revokes every live session for an account except
	// the one identified by exceptHash (pass "" to revoke all). Used after a
	// password change so other devices are signed out.
	RevokeAllUserSessions(ctx context.Context, userUUID uuid.UUID, exceptHash string) (int, error)

	// ListUserSessions returns live sessions for an account, newest first.
	ListUserSessions(ctx context.Context, userUUID uuid.UUID) ([]UserSessionData, error)

	// DeleteExpiredSessions removes rows that expired before the given time.
	DeleteExpiredSessions(ctx context.Context, before time.Time) (int, error)

	// CountActiveSessions counts live sessions for an account.
	CountActiveSessions(ctx context.Context, userUUID uuid.UUID) (int, error)

	// DeleteOldestSessions keeps the newest `keep` live sessions for an account
	// and deletes the rest.
	DeleteOldestSessions(ctx context.Context, userUUID uuid.UUID, keep int) error
}
