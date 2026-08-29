package http

import (
	"fmt"
	"net/http/httptest"
	"testing"
)

// resetLoginLimiters gives each test its own buckets. The limiters are
// package-level, so without this a test would inherit whatever budget a
// previous test consumed.
func resetLoginLimiters(t *testing.T) {
	t.Helper()
	oldIP, oldEmail, oldChange := loginIPLimiter, loginEmailLimiter, passwordChangeLimiter
	loginIPLimiter = newPerKeyRateLimiter(20, 5)
	loginEmailLimiter = newPerKeyRateLimiter(5, 3)
	passwordChangeLimiter = newPerKeyRateLimiter(5, 2)
	t.Cleanup(func() {
		loginIPLimiter, loginEmailLimiter, passwordChangeLimiter = oldIP, oldEmail, oldChange
	})
}

func TestEnforceLoginLimit_AllowsBurstThenThrottles(t *testing.T) {
	resetLoginLimiters(t)

	const email = "alice@example.com"
	allowed := 0
	for i := range 10 {
		r := httptest.NewRequest("POST", "/v1/auth/login", nil)
		// A fresh source address each time, so what throttles here is the
		// per-email bucket rather than the per-IP one.
		r.RemoteAddr = fmt.Sprintf("198.51.100.%d:1234", i+1)
		w := httptest.NewRecorder()
		if enforceLoginLimit(w, r, "en", email) {
			allowed++
			continue
		}
		if w.Code != 429 {
			t.Fatalf("throttled response code = %d, want 429", w.Code)
		}
		if w.Header().Get("Retry-After") == "" {
			t.Error("throttled response has no Retry-After header")
		}
		break
	}
	if allowed == 0 {
		t.Error("the first attempt was throttled")
	}
	if allowed >= 10 {
		t.Errorf("all %d attempts were allowed; the email bucket did not engage", allowed)
	}
}

// The per-email bucket must key on the address, not on anything the caller
// controls freely. Rotating X-GoClaw-User-Id — which is what
// rateLimitKeyFromRequest would fall back to — must not reset the budget.
func TestEnforceLoginLimit_UserIDHeaderDoesNotBypass(t *testing.T) {
	resetLoginLimiters(t)

	const email = "victim@example.com"
	throttled := false
	for i := range 10 {
		r := httptest.NewRequest("POST", "/v1/auth/login", nil)
		r.RemoteAddr = fmt.Sprintf("198.51.100.%d:1234", i+1)
		r.Header.Set("X-GoClaw-User-Id", string(rune('a'+i))) // a different claim each time
		w := httptest.NewRecorder()
		if !enforceLoginLimit(w, r, "en", email) {
			throttled = true
			break
		}
	}
	if !throttled {
		t.Error("rotating X-GoClaw-User-Id kept the request allowed; the bucket is keyed on caller-controlled input")
	}
}

// Two different addresses hold separate budgets, so one account being ground
// down does not lock everyone else out.
//
// The attempts come from different remote addresses on purpose: the per-IP
// bucket would otherwise be the thing that stops the second address, and the
// test would pass without saying anything about the per-email bucket.
func TestEnforceLoginLimit_SeparateBucketsPerEmail(t *testing.T) {
	resetLoginLimiters(t)

	for range 6 {
		r := httptest.NewRequest("POST", "/v1/auth/login", nil)
		r.RemoteAddr = "198.51.100.10:1111"
		enforceLoginLimit(httptest.NewRecorder(), r, "en", "first@example.com")
	}

	r := httptest.NewRequest("POST", "/v1/auth/login", nil)
	r.RemoteAddr = "198.51.100.20:2222"
	w := httptest.NewRecorder()
	if !enforceLoginLimit(w, r, "en", "second@example.com") {
		t.Error("a different email address was throttled by the first one's budget")
	}
}

func TestEmailBucketKey_IsCaseAndSpaceInsensitive(t *testing.T) {
	a := emailBucketKey("Alice@Example.COM")
	b := emailBucketKey("  alice@example.com  ")
	if a != b {
		t.Errorf("bucket keys differ for the same address: %q vs %q", a, b)
	}
	if a == emailBucketKey("bob@example.com") {
		t.Error("different addresses share a bucket key")
	}
}

func TestClientIPOnly_StripsPort(t *testing.T) {
	r := httptest.NewRequest("POST", "/v1/auth/login", nil)
	r.RemoteAddr = "203.0.113.7:54321"
	if got := clientIPOnly(r); got != "203.0.113.7" {
		t.Errorf("clientIPOnly = %q, want 203.0.113.7", got)
	}

	r.RemoteAddr = "no-port-here"
	if got := clientIPOnly(r); got != "no-port-here" {
		t.Errorf("clientIPOnly on a portless address = %q, want the address unchanged", got)
	}
}

func TestEnforcePasswordChangeLimit(t *testing.T) {
	resetLoginLimiters(t)

	throttled := false
	for range 10 {
		r := httptest.NewRequest("POST", "/v1/auth/change-password", nil)
		if !enforcePasswordChangeLimit(httptest.NewRecorder(), r, "en", "alice") {
			throttled = true
			break
		}
	}
	if !throttled {
		t.Error("password changes were never throttled")
	}
}
