//go:build sqliteonly

package integration

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nextlevelbuilder/goclaw/internal/crypto"
	"github.com/nextlevelbuilder/goclaw/internal/store"
	"github.com/nextlevelbuilder/goclaw/internal/store/sqlitestore"
)

// A SQLite database created before this feature has to survive the upgrade.
// EnsureSchema fails hard when a version has no migration step, so an existing
// desktop install would refuse to open at all if the step were missing — this
// is the failure mode worth a dedicated test.
//
// The pre-upgrade state is reconstructed by dropping the two new tables and
// winding schema_version back, which is exactly what an older database looks
// like from EnsureSchema's point of view.
func TestUserAccounts_SQLiteUpgradeFromPreviousVersion(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "upgrade.db")
	skillDir := filepath.Join(tmpDir, "skills")
	if err := os.MkdirAll(skillDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	cfg := store.StoreConfig{
		SQLitePath:       dbPath,
		SkillsStorageDir: skillDir,
		EncryptionKey:    "test-key-32-bytes-long-for-aes!!",
	}

	stores, err := sqlitestore.NewSQLiteStores(cfg)
	if err != nil {
		t.Fatalf("NewSQLiteStores: %v", err)
	}

	previousVersion := sqlitestore.SchemaVersion - 1
	for _, stmt := range []string{
		"DROP TABLE IF EXISTS user_sessions",
		"DROP TABLE IF EXISTS users",
		"UPDATE schema_version SET version = ?",
	} {
		if stmt == "UPDATE schema_version SET version = ?" {
			if _, err := stores.DB.ExecContext(ctx, stmt, previousVersion); err != nil {
				t.Fatalf("wind back schema_version: %v", err)
			}
			continue
		}
		if _, err := stores.DB.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	stores.DB.Close()

	// Reopen: this is the upgrade path an existing install takes.
	upgraded, err := sqlitestore.NewSQLiteStores(cfg)
	if err != nil {
		t.Fatalf("reopening a database at version %d failed: %v", previousVersion, err)
	}
	defer upgraded.DB.Close()

	var version int
	if err := upgraded.DB.QueryRowContext(ctx, "SELECT version FROM schema_version LIMIT 1").Scan(&version); err != nil {
		t.Fatalf("read schema_version: %v", err)
	}
	if version != sqlitestore.SchemaVersion {
		t.Errorf("schema_version = %d after upgrade, want %d", version, sqlitestore.SchemaVersion)
	}

	// The upgraded database must be usable, not merely present.
	hash, err := crypto.HashPassword("a-perfectly-fine-password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	now := time.Now().UTC()
	u := &store.UserData{
		ID: store.GenNewID(), UserID: "alice", Email: "alice@example.com",
		PasswordHash: hash, Status: store.UserStatusActive, CreatedAt: now, UpdatedAt: now,
	}
	if err := upgraded.Users.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser after upgrade: %v", err)
	}
	if got, err := upgraded.Users.GetUserByEmail(ctx, "ALICE@example.com"); err != nil || got == nil {
		t.Fatalf("case-insensitive lookup after upgrade: %v (%+v)", err, got)
	}

	_, tokenHash, err := crypto.GenerateSessionToken()
	if err != nil {
		t.Fatalf("GenerateSessionToken: %v", err)
	}
	if err := upgraded.Users.CreateSession(ctx, &store.UserSessionData{
		ID: store.GenNewID(), UserUUID: u.ID, UserID: u.UserID, TokenHash: tokenHash,
		ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}); err != nil {
		t.Fatalf("CreateSession after upgrade: %v", err)
	}
	sess, _, err := upgraded.Users.GetSessionByHash(ctx, tokenHash)
	if err != nil || sess == nil {
		t.Fatalf("session lookup after upgrade: %v (%+v)", err, sess)
	}

	// The unique index has to come across with the tables, otherwise the
	// upgraded database silently allows duplicate accounts.
	dup := &store.UserData{
		ID: store.GenNewID(), UserID: "alice2", Email: "Alice@Example.com",
		PasswordHash: hash, Status: store.UserStatusActive, CreatedAt: now, UpdatedAt: now,
	}
	if err := upgraded.Users.CreateUser(ctx, dup); err == nil {
		t.Error("duplicate email accepted after upgrade; idx_users_email_lower is missing")
	}

	assertTableExists(t, upgraded.DB, "users")
	assertTableExists(t, upgraded.DB, "user_sessions")
}

func assertTableExists(t *testing.T, db *sql.DB, name string) {
	t.Helper()
	var found string
	err := db.QueryRow(
		"SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?", name,
	).Scan(&found)
	if err != nil {
		t.Errorf("table %q missing after upgrade: %v", name, err)
	}
}
