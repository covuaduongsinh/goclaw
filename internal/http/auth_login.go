package http

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"net/mail"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/nextlevelbuilder/goclaw/internal/bus"
	"github.com/nextlevelbuilder/goclaw/internal/crypto"
	"github.com/nextlevelbuilder/goclaw/internal/i18n"
	"github.com/nextlevelbuilder/goclaw/internal/permissions"
	"github.com/nextlevelbuilder/goclaw/internal/store"
	"github.com/nextlevelbuilder/goclaw/pkg/protocol"
)

const (
	sessionTTLEnv     = "GOCLAW_SESSION_TTL_HOURS"
	defaultSessionTTL = 720 * time.Hour // 30 days
)

// sessionTTL resolves how long an issued token stays valid.
var sessionTTL = sync.OnceValue(func() time.Duration {
	raw := os.Getenv(sessionTTLEnv)
	if raw == "" {
		return defaultSessionTTL
	}
	h, err := strconv.Atoi(raw)
	if err != nil || h <= 0 {
		return defaultSessionTTL
	}
	return time.Duration(h) * time.Hour
})

// AuthLoginHandler serves email + password sign-in and the endpoints a
// signed-in person needs for their own account.
type AuthLoginHandler struct {
	users   store.UserStore
	tenants store.TenantStore
	msgBus  *bus.MessageBus
}

// NewAuthLoginHandler creates the sign-in handler.
func NewAuthLoginHandler(users store.UserStore, tenants store.TenantStore, msgBus *bus.MessageBus) *AuthLoginHandler {
	return &AuthLoginHandler{users: users, tenants: tenants, msgBus: msgBus}
}

// RegisterRoutes mounts the sign-in routes.
//
// RoleViewer is passed explicitly rather than letting requireAuth infer from
// the HTTP method. The default for POST is RoleOperator, which would leave an
// account holding only viewer membership unable to sign out or change its own
// password — the two things every account must always be able to do.
func (h *AuthLoginHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/auth/login", h.handleLogin)
	mux.HandleFunc("POST /v1/auth/logout", requireAuth(permissions.RoleViewer, h.handleLogout))
	mux.HandleFunc("GET /v1/auth/me", requireAuth(permissions.RoleViewer, h.handleMe))
	mux.HandleFunc("POST /v1/auth/change-password", requireAuth(permissions.RoleViewer, h.handleChangePassword))
}

// tenantMembership is the shape the web client needs to offer a tenant picker.
type tenantMembership struct {
	TenantID string `json:"tenant_id"`
	Name     string `json:"name"`
	Slug     string `json:"slug"`
	Role     string `json:"role"`
}

// userProfile is the public view of an account. It exists so no handler can
// serialize store.UserData by accident and leak the password hash.
type userProfile struct {
	ID                 string     `json:"id"`
	UserID             string     `json:"user_id"`
	Email              string     `json:"email"`
	DisplayName        string     `json:"display_name"`
	Status             string     `json:"status"`
	MustChangePassword bool       `json:"must_change_password"`
	LastLoginAt        *time.Time `json:"last_login_at"`
	CreatedAt          time.Time  `json:"created_at"`
}

func toUserProfile(u *store.UserData) userProfile {
	return userProfile{
		ID:                 u.ID.String(),
		UserID:             u.UserID,
		Email:              u.Email,
		DisplayName:        u.DisplayName,
		Status:             u.Status,
		MustChangePassword: u.MustChangePassword,
		LastLoginAt:        u.LastLoginAt,
		CreatedAt:          u.CreatedAt,
	}
}

// emailFingerprint is what gets logged instead of the address itself, so a
// failed-login log cannot be mined for a list of registered accounts.
func emailFingerprint(email string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(email))))
	return hex.EncodeToString(sum[:])[:8]
}

// storeUnavailable answers 503 when the users table is not wired up, which
// happens when migration 000098 has not run. The Docker entrypoint does not
// stop the server on a failed upgrade, so this path is reachable in practice
// and must not be a 500.
func (h *AuthLoginHandler) storeUnavailable(w http.ResponseWriter, locale string) bool {
	if h.users != nil {
		return false
	}
	writeError(w, http.StatusServiceUnavailable, protocol.ErrUnavailable,
		i18n.T(locale, i18n.MsgUserAccountsDisabled))
	return true
}

// handleLogin exchanges an email and password for a session token.
//
// Every failure answers with the same message and the same status. Sign-in is
// the one place where distinguishing "no such account" from "wrong password"
// hands an attacker a list of valid addresses, so the two are deliberately
// indistinguishable from outside — including in how long the request takes,
// which is why the miss branch still runs a bcrypt comparison.
func (h *AuthLoginHandler) handleLogin(w http.ResponseWriter, r *http.Request) {
	locale := extractLocale(r)
	if h.storeUnavailable(w, locale) {
		return
	}

	var input struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !bindJSON(w, r, locale, &input) {
		return
	}
	input.Email = strings.TrimSpace(input.Email)
	if input.Email == "" || input.Password == "" {
		writeError(w, http.StatusBadRequest, protocol.ErrInvalidRequest,
			i18n.T(locale, i18n.MsgRequired, "email and password"))
		return
	}
	if !enforceLoginLimit(w, r, locale, input.Email) {
		return
	}

	denied := func(reason string) {
		slog.Warn("security.login_failed",
			"reason", reason,
			"email_fp", emailFingerprint(input.Email),
			"ip", clientIPOnly(r),
		)
		writeError(w, http.StatusUnauthorized, protocol.ErrUnauthorized,
			i18n.T(locale, i18n.MsgInvalidCredentials))
	}

	ctx := r.Context()
	user, err := h.users.GetUserByEmail(ctx, input.Email)
	if errors.Is(err, sql.ErrNoRows) || user == nil {
		crypto.VerifyAgainstDummy(input.Password)
		denied("no_such_account")
		return
	}
	if err != nil {
		slog.Error("auth.login lookup failed", "error", err)
		writeError(w, http.StatusInternalServerError, protocol.ErrInternal,
			i18n.T(locale, i18n.MsgInternalError, "sign-in"))
		return
	}
	if !crypto.VerifyPassword(user.PasswordHash, input.Password) {
		denied("wrong_password")
		return
	}
	if !user.IsActive() {
		denied("account_disabled")
		return
	}

	memberships := h.membershipsFor(ctx, user.UserID)

	// Bind the session to the account's tenant when there is exactly one.
	// With several, the client picks and passes X-GoClaw-Tenant-Id per request.
	var tenantID uuid.UUID
	if len(memberships) == 1 {
		tenantID, _ = uuid.Parse(memberships[0].TenantID)
	}

	raw, hash, err := crypto.GenerateSessionToken()
	if err != nil {
		slog.Error("auth.login token generation failed", "error", err)
		writeError(w, http.StatusInternalServerError, protocol.ErrInternal,
			i18n.T(locale, i18n.MsgInternalError, "token generation"))
		return
	}

	now := time.Now().UTC()
	sess := &store.UserSessionData{
		ID:        store.GenNewID(),
		UserUUID:  user.ID,
		UserID:    user.UserID,
		TokenHash: hash,
		TenantID:  tenantID,
		UserAgent: truncate(r.UserAgent(), 255),
		IP:        truncate(clientIPOnly(r), 64),
		ExpiresAt: now.Add(sessionTTL()),
		CreatedAt: now,
	}
	if err := h.users.CreateSession(ctx, sess); err != nil {
		slog.Error("auth.login session creation failed", "error", err)
		writeError(w, http.StatusInternalServerError, protocol.ErrInternal,
			i18n.T(locale, i18n.MsgInternalError, "session"))
		return
	}

	// Keep the session table bounded: a script signing in on a loop would
	// otherwise accumulate rows for the lifetime of every token it created.
	if n, err := h.users.CountActiveSessions(ctx, user.ID); err == nil && n > store.MaxActiveSessionsPerUser {
		if err := h.users.DeleteOldestSessions(ctx, user.ID, store.MaxActiveSessionsPerUser); err != nil {
			slog.Warn("auth.login session trim failed", "error", err)
		}
	}
	if err := h.users.TouchLastLogin(ctx, user.ID); err != nil {
		slog.Debug("auth.login touch failed", "error", err)
	}

	slog.Info("auth.login succeeded", "user_id", user.UserID, "ip", clientIPOnly(r))
	writeJSON(w, http.StatusOK, map[string]any{
		"token":      raw,
		"expires_at": sess.ExpiresAt,
		"user":       toUserProfile(user),
		"tenants":    memberships,
	})
}

// handleLogout revokes the session that made the request.
func (h *AuthLoginHandler) handleLogout(w http.ResponseWriter, r *http.Request) {
	locale := extractLocale(r)
	if h.storeUnavailable(w, locale) {
		return
	}

	token := extractBearerToken(r)
	if !crypto.IsSessionToken(token) {
		// Signed in with a gateway token or API key: there is no session to end.
		writeJSON(w, http.StatusOK, map[string]string{"status": "no_session"})
		return
	}
	hash := crypto.HashAPIKey(token)
	if err := h.users.RevokeSession(r.Context(), hash); err != nil {
		slog.Error("auth.logout failed", "error", err)
		writeError(w, http.StatusInternalServerError, protocol.ErrInternal,
			i18n.T(locale, i18n.MsgInternalError, "sign-out"))
		return
	}
	InvalidateUserSession(hash, h.msgBus)
	writeJSON(w, http.StatusOK, map[string]string{"status": "signed_out"})
}

// handleMe returns the signed-in account, its role and its tenants.
func (h *AuthLoginHandler) handleMe(w http.ResponseWriter, r *http.Request) {
	locale := extractLocale(r)
	if h.storeUnavailable(w, locale) {
		return
	}

	ctx := r.Context()
	userID := store.UserIDFromContext(ctx)
	user, err := h.users.GetUserByUserID(ctx, userID)
	if errors.Is(err, sql.ErrNoRows) || user == nil {
		// Authenticated through a gateway token or API key rather than an
		// account: report the identity without an account body.
		writeJSON(w, http.StatusOK, map[string]any{
			"user":      nil,
			"user_id":   userID,
			"role":      store.RoleFromContext(ctx),
			"tenant_id": store.TenantIDFromContext(ctx).String(),
			"tenants":   h.membershipsFor(ctx, userID),
		})
		return
	}
	if err != nil {
		slog.Error("auth.me lookup failed", "error", err)
		writeError(w, http.StatusInternalServerError, protocol.ErrInternal,
			i18n.T(locale, i18n.MsgInternalError, "profile"))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"user":      toUserProfile(user),
		"user_id":   user.UserID,
		"role":      store.RoleFromContext(ctx),
		"tenant_id": store.TenantIDFromContext(ctx).String(),
		"tenants":   h.membershipsFor(ctx, user.UserID),
	})
}

// handleChangePassword updates the signed-in account's password.
//
// Every other session is revoked afterwards. If the old password leaked, the
// point of changing it is to lock out whoever had it, and that does not happen
// while their token still works.
func (h *AuthLoginHandler) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	locale := extractLocale(r)
	if h.storeUnavailable(w, locale) {
		return
	}

	ctx := r.Context()
	userID := store.UserIDFromContext(ctx)
	if !enforcePasswordChangeLimit(w, r, locale, userID) {
		return
	}

	var input struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if !bindJSON(w, r, locale, &input) {
		return
	}

	user, err := h.users.GetUserByUserID(ctx, userID)
	if errors.Is(err, sql.ErrNoRows) || user == nil {
		writeError(w, http.StatusNotFound, protocol.ErrNotFound,
			i18n.T(locale, i18n.MsgUserNotFound, userID))
		return
	}
	if err != nil {
		slog.Error("auth.change_password lookup failed", "error", err)
		writeError(w, http.StatusInternalServerError, protocol.ErrInternal,
			i18n.T(locale, i18n.MsgInternalError, "password change"))
		return
	}
	if !crypto.VerifyPassword(user.PasswordHash, input.CurrentPassword) {
		slog.Warn("security.change_password_rejected", "user_id", userID, "ip", clientIPOnly(r))
		writeError(w, http.StatusUnauthorized, protocol.ErrUnauthorized,
			i18n.T(locale, i18n.MsgCurrentPasswordWrong))
		return
	}
	if !validatePasswordOrFail(w, locale, input.NewPassword) {
		return
	}

	hash, err := crypto.HashPassword(input.NewPassword)
	if err != nil {
		slog.Error("auth.change_password hash failed", "error", err)
		writeError(w, http.StatusInternalServerError, protocol.ErrInternal,
			i18n.T(locale, i18n.MsgInternalError, "password hashing"))
		return
	}
	if err := h.users.SetPassword(ctx, user.ID, hash, false); err != nil {
		slog.Error("auth.change_password store failed", "error", err)
		writeError(w, http.StatusInternalServerError, protocol.ErrInternal,
			i18n.T(locale, i18n.MsgFailedToUpdate, "password", "internal error"))
		return
	}

	currentHash := ""
	if token := extractBearerToken(r); crypto.IsSessionToken(token) {
		currentHash = crypto.HashAPIKey(token)
	}
	revoked, err := h.users.RevokeAllUserSessions(ctx, user.ID, currentHash)
	if err != nil {
		slog.Warn("auth.change_password session revoke failed", "error", err)
	}
	InvalidateUserSession(currentHash, h.msgBus)

	slog.Info("auth.password_changed", "user_id", user.UserID, "sessions_revoked", revoked)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":           "password_changed",
		"sessions_revoked": revoked,
	})
}

// membershipsFor resolves an account's tenant memberships with display data.
// Returns an empty slice rather than nil so the JSON is always an array.
func (h *AuthLoginHandler) membershipsFor(ctx context.Context, userID string) []tenantMembership {
	out := []tenantMembership{}
	if h.tenants == nil || userID == "" {
		return out
	}
	rows, err := h.tenants.ListUserTenants(ctx, userID)
	if err != nil {
		slog.Warn("auth.tenant_memberships failed", "user_id", userID, "error", err)
		return out
	}
	ids := make([]uuid.UUID, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.TenantID)
	}
	byID := map[uuid.UUID]store.TenantData{}
	if len(ids) > 0 {
		if tenants, err := h.tenants.GetTenantsByIDs(ctx, ids); err == nil {
			for _, t := range tenants {
				byID[t.ID] = t
			}
		}
	}
	for _, row := range rows {
		m := tenantMembership{TenantID: row.TenantID.String(), Role: row.Role}
		if t, ok := byID[row.TenantID]; ok {
			m.Name = t.Name
			m.Slug = t.Slug
		}
		out = append(out, m)
	}
	return out
}

// validatePasswordOrFail applies the password policy and writes a 400 that
// says which rule was broken. bcrypt's 72-byte ceiling is part of that policy:
// left unchecked it surfaces as an opaque 500 for anyone whose password uses
// accented characters.
func validatePasswordOrFail(w http.ResponseWriter, locale, password string) bool {
	if len([]rune(password)) < crypto.MinPasswordLength {
		writeError(w, http.StatusBadRequest, protocol.ErrInvalidRequest,
			i18n.T(locale, i18n.MsgPasswordTooShort, strconv.Itoa(crypto.MinPasswordLength)))
		return false
	}
	if len(password) > crypto.MaxPasswordBytes {
		writeError(w, http.StatusBadRequest, protocol.ErrInvalidRequest,
			i18n.T(locale, i18n.MsgPasswordTooLong, strconv.Itoa(crypto.MaxPasswordBytes)))
		return false
	}
	if err := crypto.ValidatePasswordPolicy(password); err != nil {
		writeError(w, http.StatusBadRequest, protocol.ErrInvalidRequest,
			i18n.T(locale, i18n.MsgPasswordInvalidChars))
		return false
	}
	return true
}

// validateEmail checks the address is parseable and short enough for the column.
func validateEmail(email string) error {
	if len(email) > 320 {
		return errors.New("email too long")
	}
	_, err := mail.ParseAddress(email)
	return err
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
