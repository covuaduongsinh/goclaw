package http

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/nextlevelbuilder/goclaw/internal/i18n"
	"github.com/nextlevelbuilder/goclaw/pkg/protocol"
)

// Sign-in throttling.
//
// rateLimitKeyFromRequest is deliberately not reused here. It falls back to the
// X-GoClaw-User-Id header, which on a pre-auth endpoint is a value the caller
// chooses freely — rotating it would reset the bucket on every attempt.
//
// Two independent buckets are checked, and both must allow the request:
//
//   - per IP, which stops one host from stuffing credentials across many
//     accounts;
//   - per email, which stops a distributed attack from grinding one account
//     from many hosts.
//
// The per-IP bucket degrades behind a reverse proxy, where every request
// arrives from the proxy's address and shares a single bucket. X-Forwarded-For
// is NOT consulted to compensate: without a list of trusted proxies, honouring
// it would let any caller reset their own bucket by inventing a header, which
// is strictly worse than the degraded case. The per-email bucket is unaffected
// by proxying and carries the protection there.
var (
	loginIPLimiter        = newPerKeyRateLimiter(20, 5)
	loginEmailLimiter     = newPerKeyRateLimiter(5, 3)
	passwordChangeLimiter = newPerKeyRateLimiter(5, 2)
)

// clientIPOnly returns the remote host without its port.
func clientIPOnly(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || host == "" {
		return r.RemoteAddr
	}
	return host
}

// emailBucketKey hashes the address so the limiter's map does not accumulate
// plaintext email addresses in memory for every attempted sign-in.
func emailBucketKey(email string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(email))))
	return "email:" + hex.EncodeToString(sum[:])[:16]
}

// writeRateLimited answers 429 with a Retry-After hint.
func writeRateLimited(w http.ResponseWriter, locale, endpoint, key string) {
	slog.Warn("security.rate_limited", "endpoint", endpoint, "key", key)
	w.Header().Set("Retry-After", "60")
	writeError(w, http.StatusTooManyRequests, protocol.ErrResourceExhausted,
		i18n.T(locale, i18n.MsgLoginRateLimited))
}

// enforceLoginLimit checks both sign-in buckets. Returns true when the request
// may proceed; false means a 429 has already been written.
func enforceLoginLimit(w http.ResponseWriter, r *http.Request, locale, email string) bool {
	ipKey := "ip:" + clientIPOnly(r)
	if !loginIPLimiter.Allow(ipKey) {
		writeRateLimited(w, locale, "/v1/auth/login", ipKey)
		return false
	}
	emailKey := emailBucketKey(email)
	if !loginEmailLimiter.Allow(emailKey) {
		writeRateLimited(w, locale, "/v1/auth/login", emailKey)
		return false
	}
	return true
}

// enforcePasswordChangeLimit caps password changes per signed-in account.
func enforcePasswordChangeLimit(w http.ResponseWriter, r *http.Request, locale, userID string) bool {
	key := "uid:" + userID
	if passwordChangeLimiter.Allow(key) {
		return true
	}
	writeRateLimited(w, locale, "/v1/auth/change-password", key)
	return false
}
