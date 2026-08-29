package http

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/nextlevelbuilder/goclaw/internal/crypto"
	"github.com/nextlevelbuilder/goclaw/internal/permissions"
	"github.com/nextlevelbuilder/goclaw/internal/store"
)

// --- mock user store ---

type mockUserStore struct {
	users        map[string]*store.UserData        // by user_id
	sessions     map[string]*store.UserSessionData // by token hash
	getByHashErr error
}

func newMockUserStore() *mockUserStore {
	return &mockUserStore{
		users:    make(map[string]*store.UserData),
		sessions: make(map[string]*store.UserSessionData),
	}
}

// addSession registers an account plus a live session for it and returns the
// raw token a client would send.
func (m *mockUserStore) addSession(t *testing.T, userID, status string, expiresAt time.Time) string {
	t.Helper()
	raw, hash, err := crypto.GenerateSessionToken()
	if err != nil {
		t.Fatalf("GenerateSessionToken: %v", err)
	}
	uid := uuid.New()
	m.users[userID] = &store.UserData{
		ID: uid, UserID: userID, Email: userID + "@example.com", Status: status,
	}
	m.sessions[hash] = &store.UserSessionData{
		ID: uuid.New(), UserUUID: uid, UserID: userID, TokenHash: hash, ExpiresAt: expiresAt,
	}
	return raw
}

func (m *mockUserStore) GetSessionByHash(_ context.Context, hash string) (*store.UserSessionData, *store.UserData, error) {
	if m.getByHashErr != nil {
		return nil, nil, m.getByHashErr
	}
	sess := m.sessions[hash]
	if sess == nil {
		return nil, nil, nil
	}
	// Mirror the SQL filter in the real stores.
	if sess.RevokedAt != nil || !sess.ExpiresAt.After(time.Now()) {
		return nil, nil, nil
	}
	return sess, m.users[sess.UserID], nil
}

func (m *mockUserStore) CreateUser(context.Context, *store.UserData) error { return nil }
func (m *mockUserStore) GetUserByID(context.Context, uuid.UUID) (*store.UserData, error) {
	return nil, nil
}
func (m *mockUserStore) GetUserByUserID(_ context.Context, userID string) (*store.UserData, error) {
	return m.users[userID], nil
}
func (m *mockUserStore) GetUserByEmail(context.Context, string) (*store.UserData, error) {
	return nil, nil
}
func (m *mockUserStore) ListUsers(context.Context, int, int) ([]store.UserData, error) {
	return nil, nil
}
func (m *mockUserStore) UpdateUser(context.Context, uuid.UUID, map[string]any) error { return nil }
func (m *mockUserStore) SetPassword(context.Context, uuid.UUID, string, bool) error  { return nil }
func (m *mockUserStore) TouchLastLogin(context.Context, uuid.UUID) error             { return nil }
func (m *mockUserStore) DeleteUser(context.Context, uuid.UUID) error                 { return nil }
func (m *mockUserStore) UserIDExists(context.Context, string) (bool, error)          { return false, nil }
func (m *mockUserStore) CreateSession(context.Context, *store.UserSessionData) error { return nil }
func (m *mockUserStore) TouchSessionSeen(context.Context, uuid.UUID) error           { return nil }
func (m *mockUserStore) RevokeSession(context.Context, string) error                 { return nil }
func (m *mockUserStore) RevokeAllUserSessions(context.Context, uuid.UUID, string) (int, error) {
	return 0, nil
}
func (m *mockUserStore) ListUserSessions(context.Context, uuid.UUID) ([]store.UserSessionData, error) {
	return nil, nil
}
func (m *mockUserStore) DeleteExpiredSessions(context.Context, time.Time) (int, error) {
	return 0, nil
}
func (m *mockUserStore) CountActiveSessions(context.Context, uuid.UUID) (int, error) { return 0, nil }
func (m *mockUserStore) DeleteOldestSessions(context.Context, uuid.UUID, int) error  { return nil }

var _ store.UserStore = (*mockUserStore)(nil)

func setupTestUserSessions(t *testing.T, ms *mockUserStore) {
	t.Helper()
	oldStore, oldCache := pkgUserStore, pkgUserSessionCache
	pkgUserStore = ms
	pkgUserSessionCache = newUserSessionCache(ms, sessionCacheTTL)
	t.Cleanup(func() {
		pkgUserStore, pkgUserSessionCache = oldStore, oldCache
	})
}

// --- tests ---

func TestResolveAuth_SessionToken_RoleFromTenantMembership(t *testing.T) {
	setupTestToken(t, "gateway-secret")
	ms := newMockUserStore()
	token := ms.addSession(t, "alice", store.UserStatusActive, time.Now().Add(time.Hour))
	setupTestUserSessions(t, ms)

	ts := newMockTenantStore()
	ts.addTenant(store.MasterTenantID, "master")
	ts.setUserRole(store.MasterTenantID, "alice", store.TenantRoleAdmin)
	setupTestTenantStore(t, ts)

	r := httptest.NewRequest("GET", "/v1/agents", nil)
	r.Header.Set("Authorization", "Bearer "+token)

	auth := resolveAuth(r)
	if !auth.Authenticated {
		t.Fatal("valid session token was not authenticated")
	}
	if auth.Role != permissions.RoleAdmin {
		t.Errorf("Role = %q, want %q", auth.Role, permissions.RoleAdmin)
	}
	if auth.SessionUserID != "alice" {
		t.Errorf("SessionUserID = %q, want %q", auth.SessionUserID, "alice")
	}
}

// An account with no tenant membership gets viewer, not operator. Pairing
// keeps operator for backwards compatibility; a new credential must not.
func TestResolveAuth_SessionToken_NoMembershipIsViewer(t *testing.T) {
	setupTestToken(t, "gateway-secret")
	ms := newMockUserStore()
	token := ms.addSession(t, "nobody", store.UserStatusActive, time.Now().Add(time.Hour))
	setupTestUserSessions(t, ms)

	ts := newMockTenantStore()
	ts.addTenant(store.MasterTenantID, "master")
	setupTestTenantStore(t, ts)

	r := httptest.NewRequest("GET", "/v1/agents", nil)
	r.Header.Set("Authorization", "Bearer "+token)

	auth := resolveAuth(r)
	if !auth.Authenticated {
		t.Fatal("session without membership was rejected outright")
	}
	if auth.Role != permissions.RoleViewer {
		t.Errorf("Role = %q, want %q", auth.Role, permissions.RoleViewer)
	}
}

func TestResolveAuth_SessionToken_ExpiredIsRejected(t *testing.T) {
	setupTestToken(t, "gateway-secret")
	ms := newMockUserStore()
	token := ms.addSession(t, "alice", store.UserStatusActive, time.Now().Add(-time.Minute))
	setupTestUserSessions(t, ms)
	setupTestTenantStore(t, newMockTenantStore())

	r := httptest.NewRequest("GET", "/v1/agents", nil)
	r.Header.Set("Authorization", "Bearer "+token)

	if auth := resolveAuth(r); auth.Authenticated {
		t.Error("an expired session authenticated")
	}
}

func TestResolveAuth_SessionToken_DisabledAccountIsRejected(t *testing.T) {
	setupTestToken(t, "gateway-secret")
	ms := newMockUserStore()
	token := ms.addSession(t, "alice", store.UserStatusDisabled, time.Now().Add(time.Hour))
	setupTestUserSessions(t, ms)
	setupTestTenantStore(t, newMockTenantStore())

	r := httptest.NewRequest("GET", "/v1/agents", nil)
	r.Header.Set("Authorization", "Bearer "+token)

	if auth := resolveAuth(r); auth.Authenticated {
		t.Error("a disabled account authenticated")
	}
}

// The most dangerous regression this branch can cause: an unrecognized session
// token must not fall through to the no-auth fallback, which grants RoleAdmin
// whenever no gateway token is configured.
func TestResolveAuth_UnknownSessionToken_DoesNotReachNoAuthFallback(t *testing.T) {
	setupTestToken(t, "") // dev/Lite deployment: no gateway token
	setupTestNoAuthFallback(t, true)
	setupTestUserSessions(t, newMockUserStore())
	setupTestTenantStore(t, newMockTenantStore())

	r := httptest.NewRequest("GET", "/v1/agents", nil)
	r.Header.Set("Authorization", "Bearer goclaws_"+
		"0000000000000000000000000000000000000000000000000000000000000000")

	auth := resolveAuth(r)
	if auth.Authenticated {
		t.Fatalf("an unknown session token authenticated as %q via the no-auth fallback", auth.Role)
	}
}

// The web client sends Authorization and X-GoClaw-Sender-Id together. The
// session branch has to win, otherwise a signed-in user on a paired browser
// authenticates as whatever X-GoClaw-User-Id claims.
func TestResolveAuth_SessionToken_TakesPrecedenceOverPairing(t *testing.T) {
	setupTestToken(t, "gateway-secret")
	ms := newMockUserStore()
	token := ms.addSession(t, "alice", store.UserStatusActive, time.Now().Add(time.Hour))
	setupTestUserSessions(t, ms)

	ts := newMockTenantStore()
	ts.addTenant(store.MasterTenantID, "master")
	ts.setUserRole(store.MasterTenantID, "alice", store.TenantRoleViewer)
	setupTestTenantStore(t, ts)

	ps := newMockPairingStore()
	ps.paired["paired-device"] = true
	setupTestPairingStore(t, ps)

	r := httptest.NewRequest("GET", "/v1/agents", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("X-GoClaw-Sender-Id", "paired-device")
	r.Header.Set("X-GoClaw-User-Id", "mallory")

	auth := resolveAuth(r)
	if auth.SessionUserID != "alice" {
		t.Fatalf("SessionUserID = %q, want alice — the pairing branch resolved first", auth.SessionUserID)
	}
	if auth.Role != permissions.RoleViewer {
		t.Errorf("Role = %q, want viewer (pairing would have given operator)", auth.Role)
	}
}

// enrichContext forces user_id to "system" in dev mode to stop header
// spoofing. A verified session identity has to be exempt, or every account on
// a deployment without a gateway token shares the owner identity.
func TestEnrichContext_SessionIdentitySurvivesDevModeOverride(t *testing.T) {
	setupTestToken(t, "") // dev mode

	r := httptest.NewRequest("GET", "/v1/agents", nil)
	r.Header.Set("X-GoClaw-User-Id", "alice")

	ctx := enrichContext(context.Background(), r, authResult{
		Role: permissions.RoleAdmin, Authenticated: true, SessionUserID: "alice",
	})
	if got := store.UserIDFromContext(ctx); got != "alice" {
		t.Errorf("user id = %q, want alice — the dev-mode override swallowed the session identity", got)
	}
}

func TestEnrichContext_SessionIdentityOverridesHeader(t *testing.T) {
	setupTestToken(t, "gateway-secret")

	r := httptest.NewRequest("GET", "/v1/agents", nil)
	r.Header.Set("X-GoClaw-User-Id", "mallory")

	ctx := enrichContext(context.Background(), r, authResult{
		Role: permissions.RoleOperator, Authenticated: true, SessionUserID: "alice",
	})
	if got := store.UserIDFromContext(ctx); got != "alice" {
		t.Errorf("user id = %q, want alice — the header claim was trusted over the session", got)
	}
}

func TestResolveUserSession_NilCacheReturnsNothing(t *testing.T) {
	old := pkgUserSessionCache
	pkgUserSessionCache = nil
	t.Cleanup(func() { pkgUserSessionCache = old })

	sess, user := ResolveUserSession(context.Background(), "goclaws_abc")
	if sess != nil || user != nil {
		t.Error("ResolveUserSession returned a result with no cache wired")
	}
}
