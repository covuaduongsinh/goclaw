//go:build sqlite || sqliteonly

package sqlitestore

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/nextlevelbuilder/goclaw/internal/store"
)

// SQLiteUserStore implements store.UserStore backed by SQLite.
//
// Session expiry is evaluated in Go rather than in SQL. SQLite stores
// timestamps as text in whatever layout the driver wrote, which is not the
// layout datetime('now') produces, so a SQL comparison between the two is a
// string comparison between two different formats. Parsing the column and
// comparing time.Time values is the only version that is correct for every
// row, and session counts per account are small enough that it costs nothing.
type SQLiteUserStore struct {
	db *sql.DB
}

// NewSQLiteUserStore creates a new SQLite-backed user account store.
func NewSQLiteUserStore(db *sql.DB) *SQLiteUserStore {
	return &SQLiteUserStore{db: db}
}

const sqliteUserColumns = `id, user_id, email, password_hash, display_name, status,
	must_change_password, last_login_at, created_by, created_at, updated_at`

func scanSQLiteUser(sc sqliteRowScanner) (*store.UserData, error) {
	var u store.UserData
	var lastLogin nullSqliteTime
	createdAt, updatedAt := scanTimePair()
	if err := sc.Scan(
		&u.ID, &u.UserID, &u.Email, &u.PasswordHash, &u.DisplayName, &u.Status,
		&u.MustChangePassword, &lastLogin, &u.CreatedBy, createdAt, updatedAt,
	); err != nil {
		return nil, err
	}
	u.CreatedAt = createdAt.Time
	u.UpdatedAt = updatedAt.Time
	if lastLogin.Valid {
		u.LastLoginAt = &lastLogin.Time
	}
	return &u, nil
}

func (s *SQLiteUserStore) CreateUser(ctx context.Context, u *store.UserData) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO users (id, user_id, email, password_hash, display_name, status,
			must_change_password, created_by, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		u.ID, u.UserID, u.Email, u.PasswordHash, u.DisplayName, u.Status,
		u.MustChangePassword, u.CreatedBy, u.CreatedAt, u.UpdatedAt,
	)
	return err
}

func (s *SQLiteUserStore) GetUserByID(ctx context.Context, id uuid.UUID) (*store.UserData, error) {
	return scanSQLiteUser(s.db.QueryRowContext(ctx,
		`SELECT `+sqliteUserColumns+` FROM users WHERE id = ?`, id))
}

func (s *SQLiteUserStore) GetUserByUserID(ctx context.Context, userID string) (*store.UserData, error) {
	return scanSQLiteUser(s.db.QueryRowContext(ctx,
		`SELECT `+sqliteUserColumns+` FROM users WHERE user_id = ?`, userID))
}

// GetUserByEmail matches case-insensitively against idx_users_email_lower.
func (s *SQLiteUserStore) GetUserByEmail(ctx context.Context, email string) (*store.UserData, error) {
	return scanSQLiteUser(s.db.QueryRowContext(ctx,
		`SELECT `+sqliteUserColumns+` FROM users WHERE lower(email) = lower(?)`, email))
}

func (s *SQLiteUserStore) ListUsers(ctx context.Context, limit, offset int) ([]store.UserData, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+sqliteUserColumns+` FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?`,
		limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []store.UserData
	for rows.Next() {
		u, err := scanSQLiteUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, *u)
	}
	return users, rows.Err()
}

func (s *SQLiteUserStore) UpdateUser(ctx context.Context, id uuid.UUID, updates map[string]any) error {
	return execMapUpdate(ctx, s.db, "users", id, updates)
}

func (s *SQLiteUserStore) SetPassword(ctx context.Context, id uuid.UUID, hash string, mustChange bool) error {
	res, err := s.db.ExecContext(ctx,
		`UPDATE users SET password_hash = ?, must_change_password = ?, updated_at = ? WHERE id = ?`,
		hash, mustChange, time.Now().UTC(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *SQLiteUserStore) TouchLastLogin(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET last_login_at = ? WHERE id = ?`, time.Now().UTC(), id)
	return err
}

func (s *SQLiteUserStore) DeleteUser(ctx context.Context, id uuid.UUID) error {
	// SQLite enforces ON DELETE CASCADE only when foreign_keys is on; delete
	// the sessions explicitly so an account never leaves usable tokens behind.
	if _, err := s.db.ExecContext(ctx, `DELETE FROM user_sessions WHERE user_uuid = ?`, id); err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *SQLiteUserStore) UserIDExists(ctx context.Context, userID string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM users WHERE user_id = ?`, userID).Scan(&n)
	return n > 0, err
}

// --- Sessions ---

func (s *SQLiteUserStore) CreateSession(ctx context.Context, sess *store.UserSessionData) error {
	var tenantID *uuid.UUID
	if sess.TenantID != uuid.Nil {
		tenantID = &sess.TenantID
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO user_sessions (id, user_uuid, user_id, token_hash, tenant_id,
			user_agent, ip, expires_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sess.ID, sess.UserUUID, sess.UserID, sess.TokenHash, tenantID,
		sess.UserAgent, sess.IP, sess.ExpiresAt, sess.CreatedAt,
	)
	return err
}

// GetSessionByHash resolves a bearer token to its session and account.
// A miss returns (nil, nil, nil), as does an expired session.
func (s *SQLiteUserStore) GetSessionByHash(ctx context.Context, tokenHash string) (*store.UserSessionData, *store.UserData, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT s.id, s.user_uuid, s.user_id, s.token_hash, s.tenant_id, s.user_agent,
			s.ip, s.expires_at, s.revoked_at, s.last_seen_at, s.created_at,
			u.id, u.user_id, u.email, u.password_hash, u.display_name, u.status,
			u.must_change_password, u.last_login_at, u.created_by, u.created_at, u.updated_at
		 FROM user_sessions s
		 JOIN users u ON u.id = s.user_uuid
		 WHERE s.token_hash = ? AND s.revoked_at IS NULL`,
		tokenHash)

	var sess store.UserSessionData
	var u store.UserData
	var tenantID *uuid.UUID
	var expiresAt sqliteTime
	var revokedAt, lastSeenAt, userLastLogin nullSqliteTime
	sessCreated, userCreated := scanTimePair()
	var userUpdated sqliteTime

	err := row.Scan(
		&sess.ID, &sess.UserUUID, &sess.UserID, &sess.TokenHash, &tenantID, &sess.UserAgent,
		&sess.IP, &expiresAt, &revokedAt, &lastSeenAt, sessCreated,
		&u.ID, &u.UserID, &u.Email, &u.PasswordHash, &u.DisplayName, &u.Status,
		&u.MustChangePassword, &userLastLogin, &u.CreatedBy, userCreated, &userUpdated,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}

	sess.ExpiresAt = expiresAt.Time
	sess.CreatedAt = sessCreated.Time
	if revokedAt.Valid {
		sess.RevokedAt = &revokedAt.Time
	}
	if lastSeenAt.Valid {
		sess.LastSeenAt = &lastSeenAt.Time
	}
	if tenantID != nil {
		sess.TenantID = *tenantID
	}
	u.CreatedAt = userCreated.Time
	u.UpdatedAt = userUpdated.Time
	if userLastLogin.Valid {
		u.LastLoginAt = &userLastLogin.Time
	}

	if !sess.ExpiresAt.After(time.Now()) {
		return nil, nil, nil
	}
	return &sess, &u, nil
}

func (s *SQLiteUserStore) TouchSessionSeen(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE user_sessions SET last_seen_at = ? WHERE id = ?`, time.Now().UTC(), id)
	return err
}

func (s *SQLiteUserStore) RevokeSession(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE user_sessions SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL`,
		time.Now().UTC(), tokenHash)
	return err
}

func (s *SQLiteUserStore) RevokeAllUserSessions(ctx context.Context, userUUID uuid.UUID, exceptHash string) (int, error) {
	q := `UPDATE user_sessions SET revoked_at = ? WHERE user_uuid = ? AND revoked_at IS NULL`
	args := []any{time.Now().UTC(), userUUID}
	if exceptHash != "" {
		q += ` AND token_hash <> ?`
		args = append(args, exceptHash)
	}
	res, err := s.db.ExecContext(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// liveSessions returns non-revoked, unexpired sessions for an account,
// newest first. Expiry is filtered in Go — see the type comment.
func (s *SQLiteUserStore) liveSessions(ctx context.Context, userUUID uuid.UUID) ([]store.UserSessionData, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, user_uuid, user_id, token_hash, tenant_id, user_agent, ip,
			expires_at, revoked_at, last_seen_at, created_at
		 FROM user_sessions
		 WHERE user_uuid = ? AND revoked_at IS NULL
		 ORDER BY created_at DESC`,
		userUUID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	now := time.Now()
	var sessions []store.UserSessionData
	for rows.Next() {
		var sess store.UserSessionData
		var tenantID *uuid.UUID
		var expiresAt, createdAt sqliteTime
		var revokedAt, lastSeenAt nullSqliteTime
		if err := rows.Scan(
			&sess.ID, &sess.UserUUID, &sess.UserID, &sess.TokenHash, &tenantID,
			&sess.UserAgent, &sess.IP, &expiresAt, &revokedAt, &lastSeenAt, &createdAt,
		); err != nil {
			return nil, err
		}
		sess.ExpiresAt = expiresAt.Time
		sess.CreatedAt = createdAt.Time
		if revokedAt.Valid {
			sess.RevokedAt = &revokedAt.Time
		}
		if lastSeenAt.Valid {
			sess.LastSeenAt = &lastSeenAt.Time
		}
		if tenantID != nil {
			sess.TenantID = *tenantID
		}
		if !sess.ExpiresAt.After(now) {
			continue
		}
		sessions = append(sessions, sess)
	}
	return sessions, rows.Err()
}

func (s *SQLiteUserStore) ListUserSessions(ctx context.Context, userUUID uuid.UUID) ([]store.UserSessionData, error) {
	return s.liveSessions(ctx, userUUID)
}

func (s *SQLiteUserStore) DeleteExpiredSessions(ctx context.Context, before time.Time) (int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, expires_at FROM user_sessions`)
	if err != nil {
		return 0, err
	}
	var stale []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		var expiresAt sqliteTime
		if err := rows.Scan(&id, &expiresAt); err != nil {
			rows.Close()
			return 0, err
		}
		if expiresAt.Time.Before(before) {
			stale = append(stale, id)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()

	for _, id := range stale {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM user_sessions WHERE id = ?`, id); err != nil {
			return 0, err
		}
	}
	return len(stale), nil
}

func (s *SQLiteUserStore) CountActiveSessions(ctx context.Context, userUUID uuid.UUID) (int, error) {
	sessions, err := s.liveSessions(ctx, userUUID)
	if err != nil {
		return 0, err
	}
	return len(sessions), nil
}

func (s *SQLiteUserStore) DeleteOldestSessions(ctx context.Context, userUUID uuid.UUID, keep int) error {
	if keep < 0 {
		keep = 0
	}
	sessions, err := s.liveSessions(ctx, userUUID)
	if err != nil {
		return err
	}
	if len(sessions) <= keep {
		return nil
	}
	for _, sess := range sessions[keep:] {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM user_sessions WHERE id = ?`, sess.ID); err != nil {
			return err
		}
	}
	return nil
}

// ensure interface is satisfied at compile time
var _ store.UserStore = (*SQLiteUserStore)(nil)
