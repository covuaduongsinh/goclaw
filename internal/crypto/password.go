package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"sync"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

// Password hashing for email + password sign-in.
//
// bcrypt is used rather than scrypt/argon2 because /v1/auth/login is a
// pre-auth endpoint: anyone who can reach the gateway can make it hash a
// password. A memory-hard KDF turns that into a denial-of-service lever
// (scrypt at N=16384,r=16 costs 32 MB per attempt, so a handful of concurrent
// logins exhausts a small container). bcrypt at cost 12 costs ~250 ms of CPU
// and ~4 KB of memory, which brute-force resistance-wise is the right trade
// for a login endpoint. A bcrypt hash also carries its own cost and salt, so
// the work factor can be raised later and existing hashes upgraded lazily.
const (
	// MinPasswordLength is the minimum accepted password length in runes.
	// Accounts here are provisioned by an admin rather than self-registered,
	// so length is the only requirement — NIST SP 800-63B advises against
	// composition rules, which mostly produce predictable substitutions.
	MinPasswordLength = 12

	// MaxPasswordBytes is bcrypt's hard input limit. Note this counts BYTES,
	// not characters: accented Vietnamese text runs 2-3 bytes per character,
	// so a 25-character password can cross this line. Callers must validate
	// before hashing, otherwise bcrypt returns an error that surfaces as a
	// confusing 500.
	MaxPasswordBytes = 72

	// DefaultBcryptCost is used when GOCLAW_BCRYPT_COST is unset.
	DefaultBcryptCost = 12

	minBcryptCost = 10
	maxBcryptCost = 15

	bcryptCostEnv = "GOCLAW_BCRYPT_COST"
)

// bcryptCost resolves the configured cost once per process.
var bcryptCost = sync.OnceValue(func() int {
	raw := os.Getenv(bcryptCostEnv)
	if raw == "" {
		return DefaultBcryptCost
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return DefaultBcryptCost
	}
	return min(max(n, minBcryptCost), maxBcryptCost)
})

// dummyPasswordHash is a hash of a random secret, computed lazily at the same
// cost as real hashes. Sign-in compares against it when no account matches the
// supplied email, so a request for an unknown address takes the same time as
// one for a known address. Without it, response latency alone reveals which
// email addresses are registered.
var dummyPasswordHash = sync.OnceValue(func() string {
	b := make([]byte, 32)
	rand.Read(b) //nolint:errcheck // crypto/rand.Read never returns an error
	h, err := bcrypt.GenerateFromPassword([]byte(hex.EncodeToString(b)), bcryptCost())
	if err != nil {
		return ""
	}
	return string(h)
})

// ValidatePasswordPolicy checks a plaintext password against the accepted
// length and character rules. It must be called before HashPassword.
func ValidatePasswordPolicy(plain string) error {
	if len([]rune(plain)) < MinPasswordLength {
		return fmt.Errorf("password must be at least %d characters", MinPasswordLength)
	}
	if len(plain) > MaxPasswordBytes {
		return fmt.Errorf("password must be at most %d bytes (accented characters use 2-3 bytes each)", MaxPasswordBytes)
	}
	for _, r := range plain {
		if r < 32 || r == 0x7f {
			return fmt.Errorf("password contains a control character: %U", r)
		}
		if unicode.Is(unicode.Cf, r) {
			return fmt.Errorf("password contains a format character: %U", r)
		}
	}
	return nil
}

// HashPassword returns a bcrypt hash of the password at the configured cost.
// The policy is enforced here too so no caller can bypass it by accident.
func HashPassword(plain string) (string, error) {
	if err := ValidatePasswordPolicy(plain); err != nil {
		return "", err
	}
	h, err := bcrypt.GenerateFromPassword([]byte(plain), bcryptCost())
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(h), nil
}

// VerifyPassword reports whether plain matches hash. bcrypt's comparison is
// constant-time with respect to the digest, so this is safe to call on
// attacker-supplied input.
//
// An empty hash always fails, which keeps VerifyAgainstDummy usable even if
// the dummy hash could not be generated.
func VerifyPassword(hash, plain string) bool {
	if hash == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil
}

// VerifyAgainstDummy burns the same work as a real password check. Call it on
// the "no such account" branch of sign-in so timing does not leak whether an
// email address is registered. The result is always false.
func VerifyAgainstDummy(plain string) bool {
	return VerifyPassword(dummyPasswordHash(), plain)
}

// NeedsRehash reports whether a stored hash was produced at a lower cost than
// the process is currently configured for, so it can be upgraded on next
// successful sign-in.
func NeedsRehash(hash string) bool {
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		return false
	}
	return cost < bcryptCost()
}
