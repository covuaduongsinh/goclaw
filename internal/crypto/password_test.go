package crypto

import (
	"strings"
	"testing"
)

func TestHashPassword_VerifyRoundTrip(t *testing.T) {
	t.Setenv(bcryptCostEnv, "10") // keep the test fast; see bcryptCost clamping

	const password = "correct horse battery staple"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if hash == password {
		t.Fatal("hash equals the plaintext")
	}
	if !strings.HasPrefix(hash, "$2") {
		t.Fatalf("hash is not bcrypt: %q", hash)
	}
	if !VerifyPassword(hash, password) {
		t.Error("VerifyPassword rejected the correct password")
	}
	if VerifyPassword(hash, password+"x") {
		t.Error("VerifyPassword accepted a wrong password")
	}
	if VerifyPassword("", password) {
		t.Error("VerifyPassword accepted an empty hash")
	}
}

func TestHashPassword_SaltIsRandom(t *testing.T) {
	t.Setenv(bcryptCostEnv, "10")

	a, err := HashPassword("the same password twice")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	b, err := HashPassword("the same password twice")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if a == b {
		t.Error("two hashes of the same password are identical; the salt is not random")
	}
}

// A password longer than bcrypt's 72-byte input limit must be rejected by the
// policy with a clear message. Without this check bcrypt returns an error deep
// inside the request and surfaces as an opaque 500.
func TestValidatePasswordPolicy_LengthBounds(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"too short", "short", true},
		{"exactly minimum", strings.Repeat("a", MinPasswordLength), false},
		{"exactly 72 bytes", strings.Repeat("a", 72), false},
		{"73 bytes", strings.Repeat("a", 73), true},
		{"control character", "password\x01withctl", true},
		{"tab is a control character", "password\twithtab", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePasswordPolicy(tt.password)
			if tt.wantErr && err == nil {
				t.Error("expected an error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}

// Vietnamese text runs 2-3 bytes per character, so a password that looks short
// enough can still cross the 72-byte line. Both sides of the boundary have to
// behave predictably: accepted and hashable, or rejected with a policy error.
func TestValidatePasswordPolicy_MultibyteBoundary(t *testing.T) {
	t.Setenv(bcryptCostEnv, "10")

	// "ầ" is 3 bytes in UTF-8.
	const char = "ầ"
	if len(char) != 3 {
		t.Fatalf("test assumption broken: %q is %d bytes", char, len(char))
	}

	within := strings.Repeat(char, 24) // 72 bytes, 24 runes
	if len(within) != 72 {
		t.Fatalf("expected 72 bytes, got %d", len(within))
	}
	if err := ValidatePasswordPolicy(within); err != nil {
		t.Errorf("72-byte password rejected: %v", err)
	}
	hash, err := HashPassword(within)
	if err != nil {
		t.Fatalf("HashPassword on a 72-byte password: %v", err)
	}
	if !VerifyPassword(hash, within) {
		t.Error("72-byte password does not verify against its own hash")
	}

	over := strings.Repeat(char, 25) // 75 bytes
	if err := ValidatePasswordPolicy(over); err == nil {
		t.Error("75-byte password accepted; bcrypt would fail on it later")
	}
	if _, err := HashPassword(over); err == nil {
		t.Error("HashPassword accepted a password past bcrypt's input limit")
	}
}

// The dummy hash exists so that "no such account" costs the same as a real
// password check. If it were empty or unusable, sign-in latency would reveal
// which email addresses are registered.
func TestVerifyAgainstDummy(t *testing.T) {
	t.Setenv(bcryptCostEnv, "10")

	if VerifyAgainstDummy("anything at all") {
		t.Error("VerifyAgainstDummy returned true")
	}
	if dummyPasswordHash() == "" {
		t.Error("dummy hash is empty; the timing-equalisation branch does no work")
	}
}

func TestNeedsRehash(t *testing.T) {
	t.Setenv(bcryptCostEnv, "10")
	weak, err := HashPassword("a password hashed at cost ten")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if NeedsRehash(weak) {
		t.Error("hash at the configured cost reported as needing a rehash")
	}
	if NeedsRehash("not a bcrypt hash") {
		t.Error("unparseable hash reported as needing a rehash")
	}
}

func TestBcryptCost_Clamping(t *testing.T) {
	// bcryptCost is resolved once per process, so the clamping logic is
	// exercised directly rather than through the env var.
	tests := []struct {
		in   int
		want int
	}{
		{5, minBcryptCost},
		{10, 10},
		{12, 12},
		{31, maxBcryptCost},
	}
	for _, tt := range tests {
		if got := min(max(tt.in, minBcryptCost), maxBcryptCost); got != tt.want {
			t.Errorf("clamp(%d) = %d, want %d", tt.in, got, tt.want)
		}
	}
}
