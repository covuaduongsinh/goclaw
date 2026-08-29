//go:build sqliteonly

package integration

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nextlevelbuilder/goclaw/internal/crypto"
	"github.com/nextlevelbuilder/goclaw/internal/store"
	"github.com/nextlevelbuilder/goclaw/internal/store/sqlitestore"
)

// openUserStore boots a fresh SQLite database and returns its account store.
func openUserStore(t *testing.T) store.UserStore {
	t.Helper()
	tmpDir := t.TempDir()
	skillDir := filepath.Join(tmpDir, "skills")
	if err := os.MkdirAll(skillDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	stores, err := sqlitestore.NewSQLiteStores(store.StoreConfig{
		SQLitePath:       filepath.Join(tmpDir, "accounts.db"),
		SkillsStorageDir: skillDir,
		EncryptionKey:    "test-key-32-bytes-long-for-aes!!",
	})
	if err != nil {
		t.Fatalf("NewSQLiteStores: %v", err)
	}
	t.Cleanup(func() { stores.DB.Close() })
	if stores.Users == nil {
		t.Fatal("Users store is nil; the factory did not wire it")
	}
	return stores.Users
}

func newTestUser(t *testing.T, userID, email string) *store.UserData {
	t.Helper()
	hash, err := crypto.HashPassword("a-perfectly-fine-password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	now := time.Now().UTC()
	return &store.UserData{
		ID:           store.GenNewID(),
		UserID:       userID,
		Email:        email,
		PasswordHash: hash,
		Status:       store.UserStatusActive,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

func TestUserStore_SQLite_CreateAndLookup(t *testing.T) {
	ctx := context.Background()
	users := openUserStore(t)

	u := newTestUser(t, "alice", "Alice@Example.COM")
	if err := users.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Email lookup is case-insensitive, so an account cannot be missed (or
	// duplicated) by the casing someone happens to type.
	got, err := users.GetUserByEmail(ctx, "alice@example.com")
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if got == nil || got.UserID != "alice" {
		t.Fatalf("GetUserByEmail returned %+v, want the alice account", got)
	}
	if !crypto.VerifyPassword(got.PasswordHash, "a-perfectly-fine-password") {
		t.Error("stored password hash does not verify")
	}

	byUserID, err := users.GetUserByUserID(ctx, "alice")
	if err != nil || byUserID == nil {
		t.Fatalf("GetUserByUserID: %v (%+v)", err, byUserID)
	}
	exists, err := users.UserIDExists(ctx, "alice")
	if err != nil || !exists {
		t.Errorf("UserIDExists(alice) = %v, %v; want true, nil", exists, err)
	}
}

func TestUserStore_SQLite_UniqueConstraints(t *testing.T) {
	ctx := context.Background()
	users := openUserStore(t)

	if err := users.CreateUser(ctx, newTestUser(t, "alice", "alice@example.com")); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Same address in different casing must collide: idx_users_email_lower is
	// what stops one person becoming two accounts.
	dup := newTestUser(t, "alice2", "ALICE@example.com")
	if err := users.CreateUser(ctx, dup); err == nil {
		t.Error("a second account with the same email in different casing was accepted")
	}

	sameID := newTestUser(t, "alice", "other@example.com")
	if err := users.CreateUser(ctx, sameID); err == nil {
		t.Error("a second account with the same user_id was accepted")
	}
}

func TestUserStore_SQLite_SessionLifecycle(t *testing.T) {
	ctx := context.Background()
	users := openUserStore(t)

	u := newTestUser(t, "alice", "alice@example.com")
	if err := users.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	raw, hash, err := crypto.GenerateSessionToken()
	if err != nil {
		t.Fatalf("GenerateSessionToken: %v", err)
	}
	if !crypto.IsSessionToken(raw) {
		t.Fatalf("generated token %q is not recognised as a session token", raw)
	}

	sess := &store.UserSessionData{
		ID: store.GenNewID(), UserUUID: u.ID, UserID: u.UserID, TokenHash: hash,
		ExpiresAt: time.Now().UTC().Add(time.Hour), CreatedAt: time.Now().UTC(),
	}
	if err := users.CreateSession(ctx, sess); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	gotSess, gotUser, err := users.GetSessionByHash(ctx, hash)
	if err != nil {
		t.Fatalf("GetSessionByHash: %v", err)
	}
	if gotSess == nil || gotUser == nil {
		t.Fatal("a live session did not resolve")
	}
	if gotUser.UserID != "alice" {
		t.Errorf("resolved account = %q, want alice", gotUser.UserID)
	}

	// Signing out must make the token stop working immediately.
	if err := users.RevokeSession(ctx, hash); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	gotSess, _, err = users.GetSessionByHash(ctx, hash)
	if err != nil {
		t.Fatalf("GetSessionByHash after revoke: %v", err)
	}
	if gotSess != nil {
		t.Error("a revoked session still resolves")
	}
}

func TestUserStore_SQLite_ExpiredSessionDoesNotResolve(t *testing.T) {
	ctx := context.Background()
	users := openUserStore(t)

	u := newTestUser(t, "alice", "alice@example.com")
	if err := users.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	_, hash, err := crypto.GenerateSessionToken()
	if err != nil {
		t.Fatalf("GenerateSessionToken: %v", err)
	}
	past := time.Now().UTC().Add(-time.Hour)
	if err := users.CreateSession(ctx, &store.UserSessionData{
		ID: store.GenNewID(), UserUUID: u.ID, UserID: u.UserID, TokenHash: hash,
		ExpiresAt: past, CreatedAt: past.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	sess, _, err := users.GetSessionByHash(ctx, hash)
	if err != nil {
		t.Fatalf("GetSessionByHash: %v", err)
	}
	if sess != nil {
		t.Error("an expired session resolved")
	}

	// The sweeper removes the row once it is past the retention window.
	deleted, err := users.DeleteExpiredSessions(ctx, time.Now().UTC())
	if err != nil {
		t.Fatalf("DeleteExpiredSessions: %v", err)
	}
	if deleted != 1 {
		t.Errorf("DeleteExpiredSessions removed %d rows, want 1", deleted)
	}
}

// Changing a password signs out every other device but keeps the session that
// made the change, which is what lets the person carry on working.
func TestUserStore_SQLite_RevokeAllExceptCurrent(t *testing.T) {
	ctx := context.Background()
	users := openUserStore(t)

	u := newTestUser(t, "alice", "alice@example.com")
	if err := users.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	hashes := make([]string, 3)
	for i := range hashes {
		_, hash, err := crypto.GenerateSessionToken()
		if err != nil {
			t.Fatalf("GenerateSessionToken: %v", err)
		}
		hashes[i] = hash
		if err := users.CreateSession(ctx, &store.UserSessionData{
			ID: store.GenNewID(), UserUUID: u.ID, UserID: u.UserID, TokenHash: hash,
			ExpiresAt: time.Now().UTC().Add(time.Hour), CreatedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
	}

	n, err := users.CountActiveSessions(ctx, u.ID)
	if err != nil || n != 3 {
		t.Fatalf("CountActiveSessions = %d, %v; want 3, nil", n, err)
	}

	keep := hashes[0]
	revoked, err := users.RevokeAllUserSessions(ctx, u.ID, keep)
	if err != nil {
		t.Fatalf("RevokeAllUserSessions: %v", err)
	}
	if revoked != 2 {
		t.Errorf("revoked %d sessions, want 2", revoked)
	}
	if sess, _, _ := users.GetSessionByHash(ctx, keep); sess == nil {
		t.Error("the excepted session was revoked too")
	}
	if sess, _, _ := users.GetSessionByHash(ctx, hashes[1]); sess != nil {
		t.Error("another session survived the revoke")
	}
}

func TestUserStore_SQLite_DeleteOldestSessions(t *testing.T) {
	ctx := context.Background()
	users := openUserStore(t)

	u := newTestUser(t, "alice", "alice@example.com")
	if err := users.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	base := time.Now().UTC()
	for i := range 5 {
		_, hash, err := crypto.GenerateSessionToken()
		if err != nil {
			t.Fatalf("GenerateSessionToken: %v", err)
		}
		if err := users.CreateSession(ctx, &store.UserSessionData{
			ID: store.GenNewID(), UserUUID: u.ID, UserID: u.UserID, TokenHash: hash,
			ExpiresAt: base.Add(time.Hour),
			CreatedAt: base.Add(time.Duration(i) * time.Minute),
		}); err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
	}

	if err := users.DeleteOldestSessions(ctx, u.ID, 2); err != nil {
		t.Fatalf("DeleteOldestSessions: %v", err)
	}
	n, err := users.CountActiveSessions(ctx, u.ID)
	if err != nil {
		t.Fatalf("CountActiveSessions: %v", err)
	}
	if n != 2 {
		t.Errorf("kept %d sessions, want 2", n)
	}
}

// Deleting an account must take its sessions with it, or a deleted person
// keeps working until their token expires.
func TestUserStore_SQLite_DeleteUserRemovesSessions(t *testing.T) {
	ctx := context.Background()
	users := openUserStore(t)

	u := newTestUser(t, "alice", "alice@example.com")
	if err := users.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	_, hash, err := crypto.GenerateSessionToken()
	if err != nil {
		t.Fatalf("GenerateSessionToken: %v", err)
	}
	if err := users.CreateSession(ctx, &store.UserSessionData{
		ID: store.GenNewID(), UserUUID: u.ID, UserID: u.UserID, TokenHash: hash,
		ExpiresAt: time.Now().UTC().Add(time.Hour), CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	if err := users.DeleteUser(ctx, u.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if sess, _, _ := users.GetSessionByHash(ctx, hash); sess != nil {
		t.Error("a deleted account still has a working session")
	}
}

func TestUserStore_SQLite_UpdateAndSetPassword(t *testing.T) {
	ctx := context.Background()
	users := openUserStore(t)

	u := newTestUser(t, "alice", "alice@example.com")
	if err := users.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	if err := users.UpdateUser(ctx, u.ID, map[string]any{
		"display_name": "Alice Example",
		"status":       store.UserStatusDisabled,
	}); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	got, err := users.GetUserByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if got.DisplayName != "Alice Example" {
		t.Errorf("DisplayName = %q, want %q", got.DisplayName, "Alice Example")
	}
	if got.IsActive() {
		t.Error("account still reports as active after being disabled")
	}

	newHash, err := crypto.HashPassword("an entirely different password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if err := users.SetPassword(ctx, u.ID, newHash, true); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}
	got, err = users.GetUserByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if !crypto.VerifyPassword(got.PasswordHash, "an entirely different password") {
		t.Error("the new password does not verify")
	}
	if crypto.VerifyPassword(got.PasswordHash, "a-perfectly-fine-password") {
		t.Error("the old password still verifies")
	}
	if !got.MustChangePassword {
		t.Error("must_change_password was not set")
	}

	if err := users.SetPassword(ctx, uuid.New(), newHash, false); err == nil {
		t.Error("SetPassword on a missing account did not report an error")
	}
}
