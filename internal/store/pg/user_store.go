package pg

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/nextlevelbuilder/goclaw/internal/store"
)

// PGUserStore implements store.UserStore using PostgreSQL.
type PGUserStore struct {
	db *sql.DB
}

// NewPGUserStore creates a new PostgreSQL-backed user account store.
func NewPGUserStore(db *sql.DB) *PGUserStore {
	return &PGUserStore{db: db}
}

const pgUserColumns = `id, user_id, email, password_hash, display_name, status,
	must_change_password, last_login_at, created_by, created_at, updated_at`

type rowScanner interface {
	Scan(dest ...any) error
}

func scanPGUser(sc rowScanner) (*store.UserData, error) {
	var u store.UserData
	if err := sc.Scan(
		&u.ID, &u.UserID, &u.Email, &u.PasswordHash, &u.DisplayName, &u.Status,
		&u.MustChangePassword, &u.LastLoginAt, &u.CreatedBy, &u.CreatedAt, &u.UpdatedAt,
	); err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *PGUserStore) CreateUser(ctx context.Context, u *store.UserData) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO users (id, user_id, email, password_hash, display_name, status,
			must_change_password, created_by, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		u.ID, u.UserID, u.Email, u.PasswordHash, u.DisplayName, u.Status,
		u.MustChangePassword, u.CreatedBy, u.CreatedAt, u.UpdatedAt,
	)
	return err
}

func (s *PGUserStore) GetUserByID(ctx context.Context, id uuid.UUID) (*store.UserData, error) {
	return scanPGUser(s.db.QueryRowContext(ctx,
		`SELECT `+pgUserColumns+` FROM users WHERE id = $1`, id))
}

func (s *PGUserStore) GetUserByUserID(ctx context.Context, userID string) (*store.UserData, error) {
	return scanPGUser(s.db.QueryRowContext(ctx,
		`SELECT `+pgUserColumns+` FROM users WHERE user_id = $1`, userID))
}

// GetUserByEmail matches case-insensitively against idx_users_email_lower.
func (s *PGUserStore) GetUserByEmail(ctx context.Context, email string) (*store.UserData, error) {
	return scanPGUser(s.db.QueryRowContext(ctx,
		`SELECT `+pgUserColumns+` FROM users WHERE lower(email) = lower($1)`, email))
}

func (s *PGUserStore) ListUsers(ctx context.Context, limit, offset int) ([]store.UserData, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+pgUserColumns+` FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
		limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []store.UserData
	for rows.Next() {
		u, err := scanPGUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, *u)
	}
	return users, rows.Err()
}

func (s *PGUserStore) UpdateUser(ctx context.Context, id uuid.UUID, updates map[string]any) error {
	return execMapUpdate(ctx, s.db, "users", id, updates)
}

func (s *PGUserStore) SetPassword(ctx context.Context, id uuid.UUID, hash string, mustChange bool) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE users SET password_hash = $2, must_change_password = $3, updated_at = $4 WHERE id = $1`,
		id, hash, mustChange, time.Now().UTC())
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *PGUserStore) TouchLastLogin(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET last_login_at = $2 WHERE id = $1`, id, time.Now().UTC())
	return err
}

func (s *PGUserStore) DeleteUser(ctx context.Context, id uuid.UUID) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *PGUserStore) UserIDExists(ctx context.Context, userID string) (bool, error) {
	var exists bool
	err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM users WHERE user_id = $1)`, userID).Scan(&exists)
	return exists, err
}

// --- Sessions ---

func (s *PGUserStore) CreateSession(ctx context.Context, sess *store.UserSessionData) error {
	var tenantID *uuid.UUID
	if sess.TenantID != uuid.Nil {
		tenantID = &sess.TenantID
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO user_sessions (id, user_uuid, user_id, token_hash, tenant_id,
			user_agent, ip, expires_at, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		sess.ID, sess.UserUUID, sess.UserID, sess.TokenHash, tenantID,
		sess.UserAgent, sess.IP, sess.ExpiresAt, sess.CreatedAt,
	)
	return err
}

// GetSessionByHash resolves a bearer token to its session and account in one
// indexed lookup. Revoked and expired rows are filtered in SQL so a token that
// has been signed out can never authenticate, whatever the caller does next.
//
// A miss returns (nil, nil, nil): an unrecognized token is an ordinary outcome
// on a public endpoint, not a failure worth reporting as an error.
func (s *PGUserStore) GetSessionByHash(ctx context.Context, tokenHash string) (*store.UserSessionData, *store.UserData, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT s.id, s.user_uuid, s.user_id, s.token_hash, s.tenant_id, s.user_agent,
			s.ip, s.expires_at, s.revoked_at, s.last_seen_at, s.created_at,
			u.id, u.user_id, u.email, u.password_hash, u.display_name, u.status,
			u.must_change_password, u.last_login_at, u.created_by, u.created_at, u.updated_at
		 FROM user_sessions s
		 JOIN users u ON u.id = s.user_uuid
		 WHERE s.token_hash = $1 AND s.revoked_at IS NULL AND s.expires_at > now()`,
		tokenHash)

	var sess store.UserSessionData
	var u store.UserData
	var tenantID *uuid.UUID
	err := row.Scan(
		&sess.ID, &sess.UserUUID, &sess.UserID, &sess.TokenHash, &tenantID, &sess.UserAgent,
		&sess.IP, &sess.ExpiresAt, &sess.RevokedAt, &sess.LastSeenAt, &sess.CreatedAt,
		&u.ID, &u.UserID, &u.Email, &u.PasswordHash, &u.DisplayName, &u.Status,
		&u.MustChangePassword, &u.LastLoginAt, &u.CreatedBy, &u.CreatedAt, &u.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if tenantID != nil {
		sess.TenantID = *tenantID
	}
	return &sess, &u, nil
}

func (s *PGUserStore) TouchSessionSeen(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE user_sessions SET last_seen_at = $2 WHERE id = $1`, id, time.Now().UTC())
	return err
}

func (s *PGUserStore) RevokeSession(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE user_sessions SET revoked_at = $2 WHERE token_hash = $1 AND revoked_at IS NULL`,
		tokenHash, time.Now().UTC())
	return err
}

func (s *PGUserStore) RevokeAllUserSessions(ctx context.Context, userUUID uuid.UUID, exceptHash string) (int, error) {
	q := `UPDATE user_sessions SET revoked_at = $2 WHERE user_uuid = $1 AND revoked_at IS NULL`
	args := []any{userUUID, time.Now().UTC()}
	if exceptHash != "" {
		q += ` AND token_hash <> $3`
		args = append(args, exceptHash)
	}
	res, err := s.db.ExecContext(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (s *PGUserStore) ListUserSessions(ctx context.Context, userUUID uuid.UUID) ([]store.UserSessionData, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, user_uuid, user_id, token_hash, tenant_id, user_agent, ip,
			expires_at, revoked_at, last_seen_at, created_at
		 FROM user_sessions
		 WHERE user_uuid = $1 AND revoked_at IS NULL AND expires_at > now()
		 ORDER BY created_at DESC`,
		userUUID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []store.UserSessionData
	for rows.Next() {
		var sess store.UserSessionData
		var tenantID *uuid.UUID
		if err := rows.Scan(
			&sess.ID, &sess.UserUUID, &sess.UserID, &sess.TokenHash, &tenantID,
			&sess.UserAgent, &sess.IP, &sess.ExpiresAt, &sess.RevokedAt,
			&sess.LastSeenAt, &sess.CreatedAt,
		); err != nil {
			return nil, err
		}
		if tenantID != nil {
			sess.TenantID = *tenantID
		}
		sessions = append(sessions, sess)
	}
	return sessions, rows.Err()
}

func (s *PGUserStore) DeleteExpiredSessions(ctx context.Context, before time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM user_sessions WHERE expires_at < $1`, before)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func (s *PGUserStore) CountActiveSessions(ctx context.Context, userUUID uuid.UUID) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM user_sessions
		 WHERE user_uuid = $1 AND revoked_at IS NULL AND expires_at > now()`,
		userUUID).Scan(&n)
	return n, err
}

func (s *PGUserStore) DeleteOldestSessions(ctx context.Context, userUUID uuid.UUID, keep int) error {
	if keep < 0 {
		keep = 0
	}
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM user_sessions
		 WHERE user_uuid = $1 AND id NOT IN (
		     SELECT id FROM user_sessions
		     WHERE user_uuid = $1 AND revoked_at IS NULL AND expires_at > now()
		     ORDER BY created_at DESC LIMIT $2
		 )`,
		userUUID, keep)
	return err
}

// ensure interface is satisfied at compile time
var _ store.UserStore = (*PGUserStore)(nil)
