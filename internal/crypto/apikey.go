package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

const apiKeyPrefix = "goclaw_"

// GenerateAPIKey creates a new API key with format "goclaw_<32hex>".
// Returns the raw key (show once), its SHA-256 hash, and 8-char display prefix.
func GenerateAPIKey() (raw, hash, displayPrefix string, err error) {
	b := make([]byte, 16) // 16 bytes = 32 hex chars
	if _, err = rand.Read(b); err != nil {
		return "", "", "", fmt.Errorf("generate random bytes: %w", err)
	}

	raw = apiKeyPrefix + hex.EncodeToString(b)
	hash = HashAPIKey(raw)
	displayPrefix = hex.EncodeToString(b[:4]) // first 8 hex chars of the random part
	return raw, hash, displayPrefix, nil
}

// HashAPIKey returns the SHA-256 hex digest of a raw API key.
func HashAPIKey(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// sessionTokenPrefix marks tokens issued by POST /v1/auth/login.
//
// It deliberately extends apiKeyPrefix by one character rather than sharing it:
// "goclaws_" does not match a HasPrefix test for "goclaw_" (the seventh byte is
// 's', not '_'), so the two token families can never be mistaken for one
// another on either the server or the client.
const sessionTokenPrefix = "goclaws_"

// GenerateSessionToken creates a login session token with format
// "goclaws_<64hex>". Returns the raw token (handed to the client once) and its
// SHA-256 hash, which is what gets stored.
//
// 32 bytes of entropy — double an API key — because a session token lives in
// browser localStorage for weeks, where it is exposed to a wider set of risks
// than a key an operator pastes into a config file.
func GenerateSessionToken() (raw, hash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", fmt.Errorf("generate random bytes: %w", err)
	}
	raw = sessionTokenPrefix + hex.EncodeToString(b)
	return raw, HashAPIKey(raw), nil
}

// IsSessionToken reports whether a bearer token was issued by the login
// endpoint. Auth uses it to route a token to the session branch instead of
// probing every credential store with it.
func IsSessionToken(raw string) bool {
	return strings.HasPrefix(raw, sessionTokenPrefix)
}
