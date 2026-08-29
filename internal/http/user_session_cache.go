package http

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/nextlevelbuilder/goclaw/internal/bus"
	"github.com/nextlevelbuilder/goclaw/internal/crypto"
	"github.com/nextlevelbuilder/goclaw/internal/store"
	"github.com/nextlevelbuilder/goclaw/pkg/protocol"
)

// sessionCacheTTL is deliberately much shorter than the API key cache's five
// minutes. An API key is revoked rarely and by an administrator; a login
// session is revoked by the person using it, every time they sign out, and a
// token that keeps working for minutes after "Sign out" is not a sign-out.
// One minute keeps the database off the hot path without making revocation
// feel broken.
const sessionCacheTTL = 60 * time.Second

// sessionCacheEntry holds a cached session lookup result.
type sessionCacheEntry struct {
	session   *store.UserSessionData // nil = negative cache (no such live session)
	user      *store.UserData
	fetchedAt time.Time
}

// userSessionCache is a short-TTL cache for login session lookups.
type userSessionCache struct {
	mu      sync.RWMutex
	entries map[string]*sessionCacheEntry // keyed by SHA-256 token hash
	ttl     time.Duration
	store   store.UserStore
}

func newUserSessionCache(s store.UserStore, ttl time.Duration) *userSessionCache {
	return &userSessionCache{
		entries: make(map[string]*sessionCacheEntry),
		ttl:     ttl,
		store:   s,
	}
}

func (c *userSessionCache) get(hash string) (*store.UserSessionData, *store.UserData, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[hash]
	if !ok || time.Since(entry.fetchedAt) > c.ttl {
		return nil, nil, false
	}
	return entry.session, entry.user, true
}

// getOrFetch returns a cached session or loads it from the store.
func (c *userSessionCache) getOrFetch(ctx context.Context, hash string) (*store.UserSessionData, *store.UserData) {
	if sess, user, ok := c.get(hash); ok {
		return sess, user
	}

	sess, user, err := c.store.GetSessionByHash(ctx, hash)
	if err != nil {
		slog.Warn("security.session_lookup_failed", "error", err)
		return nil, nil
	}
	if sess == nil || user == nil {
		// Negative cache, capped the same way as the API key cache so token
		// spraying cannot grow the map without bound.
		c.mu.Lock()
		if len(c.entries) < maxNegativeCacheEntries {
			c.entries[hash] = &sessionCacheEntry{fetchedAt: time.Now()}
		}
		c.mu.Unlock()
		return nil, nil
	}

	c.mu.Lock()
	c.entries[hash] = &sessionCacheEntry{session: sess, user: user, fetchedAt: time.Now()}
	c.mu.Unlock()

	sessionID := sess.ID
	go func() {
		tctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := c.store.TouchSessionSeen(tctx, sessionID); err != nil {
			slog.Debug("session.touch_failed", "error", err)
		}
	}()

	return sess, user
}

// invalidate drops one cached session. Called by sign-out so the token stops
// working on this instance immediately rather than at the end of its TTL.
func (c *userSessionCache) invalidate(hash string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, hash)
}

// invalidateAll clears every cached session. Called on pubsub cache
// invalidation, which is how other instances learn about a sign-out.
func (c *userSessionCache) invalidateAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*sessionCacheEntry)
}

// --- Package-level wiring ---

var pkgUserStore store.UserStore
var pkgUserSessionCache *userSessionCache

// InitUserSessions wires the user account store into HTTP auth.
// Must be called once during server startup, before handling requests.
// When it is never called — because the migration that creates the users
// table has not run — session authentication simply resolves nothing and the
// pre-existing credential paths continue to work.
func InitUserSessions(s store.UserStore, mb *bus.MessageBus) {
	pkgUserStore = s
	pkgUserSessionCache = newUserSessionCache(s, sessionCacheTTL)
	if mb != nil {
		mb.Subscribe("http-user-session-cache", func(e bus.Event) {
			if p, ok := e.Payload.(bus.CacheInvalidatePayload); ok && p.Kind == bus.CacheKindUserSessions {
				pkgUserSessionCache.invalidateAll()
			}
		})
	}
}

// UserStoreAvailable reports whether email/password accounts are usable.
// Handlers use it to answer 503 rather than 500 when the table is missing.
func UserStoreAvailable() bool { return pkgUserStore != nil }

// ResolveUserSession resolves a raw session token to its session and account.
// Returns (nil, nil) when the token is not a live session or the account has
// been disabled.
//
// Role is deliberately not decided here: it depends on which tenant the
// request resolves to, which only the caller knows. Callers derive it from
// tenant_users the same way the browser-pairing path does.
//
// This lives in package http, not gateway, because the import edge runs
// gateway -> http. The WebSocket connect handler calls it from there.
func ResolveUserSession(ctx context.Context, token string) (*store.UserSessionData, *store.UserData) {
	if pkgUserSessionCache == nil || token == "" {
		return nil, nil
	}
	hash := crypto.HashAPIKey(token)
	sess, user := pkgUserSessionCache.getOrFetch(ctx, hash)
	if sess == nil || user == nil {
		return nil, nil
	}
	if !user.IsActive() {
		slog.Warn("security.session_account_disabled", "user_id", user.UserID)
		return nil, nil
	}
	return sess, user
}

// InvalidateUserSession drops a token from the local cache and tells other
// instances to clear theirs.
func InvalidateUserSession(hash string, mb *bus.MessageBus) {
	if pkgUserSessionCache != nil {
		pkgUserSessionCache.invalidate(hash)
	}
	if mb != nil {
		mb.Broadcast(bus.Event{
			Name:    protocol.EventCacheInvalidate,
			Payload: bus.CacheInvalidatePayload{Kind: bus.CacheKindUserSessions},
		})
	}
}
