//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/nextlevelbuilder/goclaw/internal/crypto"
	"github.com/nextlevelbuilder/goclaw/internal/store"
	"github.com/nextlevelbuilder/goclaw/internal/store/pg"
)

// newPGUserStore returns the account store against the shared test database,
// cleaned of any rows a previous run left behind.
func newPGUserStore(t *testing.T) store.UserStore {
	t.Helper()
	db := testDB(t)
	t.Cleanup(func() {
		db.Exec(`DELETE FROM user_sessions WHERE user_id LIKE 'itest-%'`)
		db.Exec(`DELETE FROM users WHERE user_id LIKE 'itest-%'`)
	})
	if _, err := db.Exec(`DELETE FROM user_sessions WHERE user_id LIKE 'itest-%'`); err != nil {
		t.Fatalf("clean user_sessions: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM users WHERE user_id LIKE 'itest-%'`); err != nil {
		t.Fatalf("clean users: %v", err)
	}
	return pg.NewPGUserStore(db)
}

func newPGTestUser(t *testing.T, userID, email string) *store.UserData {
	t.Helper()
	hash, err := crypto.HashPassword("a-perfectly-fine-password")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	now := time.Now().UTC()
	return &store.UserData{
		ID: store.GenNewID(), UserID: userID, Email: email, PasswordHash: hash,
		Status: store.UserStatusActive, CreatedAt: now, UpdatedAt: now,
	}
}

func TestUserStore_PG_CreateAndCaseInsensitiveEmail(t *testing.T) {
	ctx := context.Background()
	users := newPGUserStore(t)

	u := newPGTestUser(t, "itest-alice", "Alice@Example.COM")
	if err := users.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	got, err := users.GetUserByEmail(ctx, "alice@example.com")
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if got == nil || got.UserID != "itest-alice" {
		t.Fatalf("GetUserByEmail returned %+v, want itest-alice", got)
	}

	// idx_users_email_lower is what stops one person becoming two accounts.
	dup := newPGTestUser(t, "itest-alice2", "ALICE@example.com")
	if err := users.CreateUser(ctx, dup); err == nil {
		t.Error("a duplicate email in different casing was accepted")
	}

	sameID := newPGTestUser(t, "itest-alice", "someone-else@example.com")
	if err := users.CreateUser(ctx, sameID); err == nil {
		t.Error("a duplicate user_id was accepted")
	}
}

func TestUserStore_PG_SessionResolutionAndRevoke(t *testing.T) {
	ctx := context.Background()
	users := newPGUserStore(t)

	u := newPGTestUser(t, "itest-bob", "bob@example.com")
	if err := users.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	_, hash, err := crypto.GenerateSessionToken()
	if err != nil {
		t.Fatalf("GenerateSessionToken: %v", err)
	}
	now := time.Now().UTC()
	if err := users.CreateSession(ctx, &store.UserSessionData{
		ID: store.GenNewID(), UserUUID: u.ID, UserID: u.UserID, TokenHash: hash,
		ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	sess, account, err := users.GetSessionByHash(ctx, hash)
	if err != nil {
		t.Fatalf("GetSessionByHash: %v", err)
	}
	if sess == nil || account == nil || account.UserID != "itest-bob" {
		t.Fatalf("session did not resolve to its account: %+v / %+v", sess, account)
	}

	if err := users.RevokeSession(ctx, hash); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	if sess, _, _ := users.GetSessionByHash(ctx, hash); sess != nil {
		t.Error("a revoked session still resolves")
	}
}

func TestUserStore_PG_ExpiredSessionAndSweep(t *testing.T) {
	ctx := context.Background()
	users := newPGUserStore(t)

	u := newPGTestUser(t, "itest-carol", "carol@example.com")
	if err := users.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	_, hash, err := crypto.GenerateSessionToken()
	if err != nil {
		t.Fatalf("GenerateSessionToken: %v", err)
	}
	past := time.Now().UTC().Add(-2 * time.Hour)
	if err := users.CreateSession(ctx, &store.UserSessionData{
		ID: store.GenNewID(), UserUUID: u.ID, UserID: u.UserID, TokenHash: hash,
		ExpiresAt: past, CreatedAt: past.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	if sess, _, _ := users.GetSessionByHash(ctx, hash); sess != nil {
		t.Error("an expired session resolved")
	}
	deleted, err := users.DeleteExpiredSessions(ctx, time.Now().UTC())
	if err != nil {
		t.Fatalf("DeleteExpiredSessions: %v", err)
	}
	if deleted < 1 {
		t.Errorf("DeleteExpiredSessions removed %d rows, want at least 1", deleted)
	}
}

func TestUserStore_PG_RevokeAllExceptCurrent(t *testing.T) {
	ctx := context.Background()
	users := newPGUserStore(t)

	u := newPGTestUser(t, "itest-dave", "dave@example.com")
	if err := users.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	now := time.Now().UTC()
	hashes := make([]string, 3)
	for i := range hashes {
		_, hash, err := crypto.GenerateSessionToken()
		if err != nil {
			t.Fatalf("GenerateSessionToken: %v", err)
		}
		hashes[i] = hash
		if err := users.CreateSession(ctx, &store.UserSessionData{
			ID: store.GenNewID(), UserUUID: u.ID, UserID: u.UserID, TokenHash: hash,
			ExpiresAt: now.Add(time.Hour), CreatedAt: now.Add(time.Duration(i) * time.Second),
		}); err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
	}

	revoked, err := users.RevokeAllUserSessions(ctx, u.ID, hashes[0])
	if err != nil {
		t.Fatalf("RevokeAllUserSessions: %v", err)
	}
	if revoked != 2 {
		t.Errorf("revoked %d sessions, want 2", revoked)
	}
	if sess, _, _ := users.GetSessionByHash(ctx, hashes[0]); sess == nil {
		t.Error("the excepted session was revoked")
	}
}

// Deleting an account cascades to its sessions through the foreign key.
func TestUserStore_PG_DeleteUserCascadesSessions(t *testing.T) {
	ctx := context.Background()
	users := newPGUserStore(t)

	u := newPGTestUser(t, "itest-erin", "erin@example.com")
	if err := users.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	_, hash, err := crypto.GenerateSessionToken()
	if err != nil {
		t.Fatalf("GenerateSessionToken: %v", err)
	}
	now := time.Now().UTC()
	if err := users.CreateSession(ctx, &store.UserSessionData{
		ID: store.GenNewID(), UserUUID: u.ID, UserID: u.UserID, TokenHash: hash,
		ExpiresAt: now.Add(time.Hour), CreatedAt: now,
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

func TestUserStore_PG_SessionCapTrim(t *testing.T) {
	ctx := context.Background()
	users := newPGUserStore(t)

	u := newPGTestUser(t, "itest-frank", "frank@example.com")
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
			ExpiresAt: base.Add(time.Hour), CreatedAt: base.Add(time.Duration(i) * time.Minute),
		}); err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
	}
	if n, err := users.CountActiveSessions(ctx, u.ID); err != nil || n != 5 {
		t.Fatalf("CountActiveSessions = %d, %v; want 5, nil", n, err)
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

// The password hash must never reach a client. UserData carries json:"-" on
// the field; this pins the store side of that contract.
func TestUserStore_PG_PasswordHashNotSerialized(t *testing.T) {
	ctx := context.Background()
	users := newPGUserStore(t)

	u := newPGTestUser(t, "itest-grace", "grace@example.com")
	if err := users.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	got, err := users.GetUserByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if got.PasswordHash == "" {
		t.Fatal("the store did not read the password hash back")
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal user: %v", err)
	}
	body := string(encoded)
	if strings.Contains(body, got.PasswordHash) || strings.Contains(body, "password_hash") {
		t.Errorf("the password hash appears in the JSON encoding: %s", body)
	}
}
