package http

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nextlevelbuilder/goclaw/internal/bus"
	"github.com/nextlevelbuilder/goclaw/internal/crypto"
	"github.com/nextlevelbuilder/goclaw/internal/i18n"
	"github.com/nextlevelbuilder/goclaw/internal/permissions"
	"github.com/nextlevelbuilder/goclaw/internal/store"
	"github.com/nextlevelbuilder/goclaw/pkg/protocol"
)

// UsersAdminHandler manages email/password accounts.
//
// users is a global table with no tenant_id, so every write is gated by
// requireMasterScope on top of RoleAdmin. That follows the decision table in
// CONTRIBUTING.md, and it is what the schema requires: tenant_users already
// models membership with UNIQUE(tenant_id, user_id), so one account may belong
// to several tenants and cannot be owned by any one of them.
//
// The consequence is deliberate: an admin of a non-master tenant cannot create
// accounts. Delegating that would need a home-tenant column on users, which is
// an additive change and out of scope here.
type UsersAdminHandler struct {
	users   store.UserStore
	tenants store.TenantStore
	msgBus  *bus.MessageBus
}

// NewUsersAdminHandler creates the account management handler.
func NewUsersAdminHandler(users store.UserStore, tenants store.TenantStore, msgBus *bus.MessageBus) *UsersAdminHandler {
	return &UsersAdminHandler{users: users, tenants: tenants, msgBus: msgBus}
}

// RegisterRoutes mounts the account management routes.
func (h *UsersAdminHandler) RegisterRoutes(mux *http.ServeMux) {
	admin := func(next http.HandlerFunc) http.HandlerFunc {
		return requireAuth(permissions.RoleAdmin, next)
	}
	mux.HandleFunc("GET /v1/users", admin(h.handleList))
	mux.HandleFunc("POST /v1/users", admin(h.handleCreate))
	mux.HandleFunc("GET /v1/users/{id}", admin(h.handleGet))
	mux.HandleFunc("PATCH /v1/users/{id}", admin(h.handleUpdate))
	mux.HandleFunc("DELETE /v1/users/{id}", admin(h.handleDelete))
	mux.HandleFunc("POST /v1/users/{id}/password", admin(h.handleSetPassword))
	mux.HandleFunc("POST /v1/users/{id}/sessions/revoke", admin(h.handleRevokeSessions))
}

// validUserID matches the identity strings the rest of the system already
// uses in paths, logs and foreign keys.
var validUserID = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,255}$`)

// nonSlugChars matches everything that is not allowed in a derived user_id.
var nonSlugChars = regexp.MustCompile(`[^a-z0-9._-]+`)

func (h *UsersAdminHandler) unavailable(w http.ResponseWriter, locale string) bool {
	if h.users != nil {
		return false
	}
	writeError(w, http.StatusServiceUnavailable, protocol.ErrUnavailable,
		i18n.T(locale, i18n.MsgUserAccountsDisabled))
	return true
}

func (h *UsersAdminHandler) handleList(w http.ResponseWriter, r *http.Request) {
	locale := extractLocale(r)
	if h.unavailable(w, locale) || !requireMasterScope(w, r) {
		return
	}

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	users, err := h.users.ListUsers(r.Context(), limit, offset)
	if err != nil {
		slog.Error("users.list failed", "error", err)
		writeError(w, http.StatusInternalServerError, protocol.ErrInternal,
			i18n.T(locale, i18n.MsgFailedToList, "users"))
		return
	}
	out := make([]userProfile, 0, len(users))
	for i := range users {
		out = append(out, toUserProfile(&users[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *UsersAdminHandler) handleGet(w http.ResponseWriter, r *http.Request) {
	locale := extractLocale(r)
	if h.unavailable(w, locale) || !requireMasterScope(w, r) {
		return
	}
	user, ok := h.lookupPathUser(w, r, locale)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user":    toUserProfile(user),
		"tenants": h.membershipsFor(r.Context(), user.UserID),
	})
}

// handleCreate provisions an account.
//
// When tenant_id and tenant_role are supplied the tenant_users row is written
// in the same request. Skipping it produces an account that authenticates
// successfully but resolves to viewer with no membership, which the web client
// treats as a failed sign-in — so the two steps belong together.
func (h *UsersAdminHandler) handleCreate(w http.ResponseWriter, r *http.Request) {
	locale := extractLocale(r)
	if h.unavailable(w, locale) || !requireMasterScope(w, r) {
		return
	}

	var input struct {
		Email              string `json:"email"`
		Password           string `json:"password"`
		UserID             string `json:"user_id"`
		DisplayName        string `json:"display_name"`
		TenantID           string `json:"tenant_id"`
		TenantRole         string `json:"tenant_role"`
		MustChangePassword bool   `json:"must_change_password"`
	}
	if !bindJSON(w, r, locale, &input) {
		return
	}

	ctx := r.Context()
	input.Email = strings.TrimSpace(input.Email)
	if err := validateEmail(input.Email); err != nil {
		writeError(w, http.StatusBadRequest, protocol.ErrInvalidRequest,
			i18n.T(locale, i18n.MsgEmailInvalid, input.Email))
		return
	}
	if !validatePasswordOrFail(w, locale, input.Password) {
		return
	}

	// An operator may set user_id explicitly to bind the new account to an
	// identity that already owns agents, sessions or tenant membership —
	// including the bootstrap "system" identity.
	userID := strings.TrimSpace(input.UserID)
	if userID != "" {
		if !validUserID.MatchString(userID) || store.ValidateUserID(userID) != nil {
			writeError(w, http.StatusBadRequest, protocol.ErrInvalidRequest,
				i18n.T(locale, i18n.MsgInvalidRequest, "user_id must match [a-zA-Z0-9._-]{1,255}"))
			return
		}
		taken, err := h.users.UserIDExists(ctx, userID)
		if err != nil {
			slog.Error("users.create user_id check failed", "error", err)
			writeError(w, http.StatusInternalServerError, protocol.ErrInternal,
				i18n.T(locale, i18n.MsgInternalError, "user_id check"))
			return
		}
		if taken {
			writeError(w, http.StatusConflict, protocol.ErrAlreadyExists,
				i18n.T(locale, i18n.MsgUserIDExists, userID))
			return
		}
	} else {
		derived, err := h.deriveUserID(ctx, input.Email)
		if err != nil {
			slog.Error("users.create user_id derivation failed", "error", err)
			writeError(w, http.StatusInternalServerError, protocol.ErrInternal,
				i18n.T(locale, i18n.MsgInternalError, "user_id"))
			return
		}
		userID = derived
	}

	var tenantID uuid.UUID
	tenantRole := strings.TrimSpace(input.TenantRole)
	if input.TenantID != "" {
		tid, err := h.resolveTenantRef(ctx, input.TenantID)
		if err != nil {
			writeError(w, http.StatusBadRequest, protocol.ErrInvalidRequest,
				i18n.T(locale, i18n.MsgInvalidID, "tenant_id"))
			return
		}
		tenantID = tid
		if tenantRole == "" {
			tenantRole = store.TenantRoleMember
		}
		if !validTenantRole(tenantRole) {
			writeError(w, http.StatusBadRequest, protocol.ErrInvalidRequest,
				i18n.T(locale, i18n.MsgInvalidRole))
			return
		}
	}

	hash, err := crypto.HashPassword(input.Password)
	if err != nil {
		slog.Error("users.create hash failed", "error", err)
		writeError(w, http.StatusInternalServerError, protocol.ErrInternal,
			i18n.T(locale, i18n.MsgInternalError, "password hashing"))
		return
	}

	now := time.Now().UTC()
	user := &store.UserData{
		ID:                 store.GenNewID(),
		UserID:             userID,
		Email:              input.Email,
		PasswordHash:       hash,
		DisplayName:        strings.TrimSpace(input.DisplayName),
		Status:             store.UserStatusActive,
		MustChangePassword: input.MustChangePassword,
		CreatedBy:          store.UserIDFromContext(ctx),
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	if err := h.users.CreateUser(ctx, user); err != nil {
		if isUniqueViolation(err) {
			writeError(w, http.StatusConflict, protocol.ErrAlreadyExists,
				i18n.T(locale, i18n.MsgEmailExists))
			return
		}
		slog.Error("users.create failed", "error", err)
		writeError(w, http.StatusInternalServerError, protocol.ErrInternal,
			i18n.T(locale, i18n.MsgFailedToCreate, "user", "internal error"))
		return
	}

	if tenantID != uuid.Nil && h.tenants != nil {
		if err := h.tenants.AddUser(ctx, tenantID, userID, tenantRole); err != nil {
			// The account exists and can sign in; only its membership failed.
			// Report it rather than rolling back a usable credential.
			slog.Error("users.create tenant membership failed",
				"user_id", userID, "tenant_id", tenantID, "error", err)
		}
	}

	slog.Info("users.created", "user_id", userID, "by", store.UserIDFromContext(ctx))
	writeJSON(w, http.StatusCreated, map[string]any{
		"user":    toUserProfile(user),
		"tenants": h.membershipsFor(ctx, userID),
	})
}

// handleUpdate applies a partial update.
//
// user_id is not editable. Changing it would orphan every tenant_users,
// api_keys.owner_id and ownership row that points at the old value, so the
// account would silently lose its access. Rebinding an identity is a data
// migration, not a field edit.
func (h *UsersAdminHandler) handleUpdate(w http.ResponseWriter, r *http.Request) {
	locale := extractLocale(r)
	if h.unavailable(w, locale) || !requireMasterScope(w, r) {
		return
	}
	user, ok := h.lookupPathUser(w, r, locale)
	if !ok {
		return
	}

	var input struct {
		DisplayName        *string `json:"display_name"`
		Status             *string `json:"status"`
		MustChangePassword *bool   `json:"must_change_password"`
		UserID             *string `json:"user_id"`
	}
	if !bindJSON(w, r, locale, &input) {
		return
	}
	if input.UserID != nil {
		writeError(w, http.StatusBadRequest, protocol.ErrInvalidRequest,
			i18n.T(locale, i18n.MsgInvalidRequest,
				"user_id cannot be changed; it is referenced by tenant membership and resource ownership"))
		return
	}

	updates := map[string]any{}
	if input.DisplayName != nil {
		updates["display_name"] = strings.TrimSpace(*input.DisplayName)
	}
	if input.MustChangePassword != nil {
		updates["must_change_password"] = *input.MustChangePassword
	}
	if input.Status != nil {
		status := strings.TrimSpace(*input.Status)
		if status != store.UserStatusActive && status != store.UserStatusDisabled {
			writeError(w, http.StatusBadRequest, protocol.ErrInvalidRequest,
				i18n.T(locale, i18n.MsgInvalidRequest, "status must be active or disabled"))
			return
		}
		updates["status"] = status
	}
	if len(updates) == 0 {
		writeError(w, http.StatusBadRequest, protocol.ErrInvalidRequest,
			i18n.T(locale, i18n.MsgInvalidUpdates))
		return
	}

	ctx := r.Context()
	if err := h.users.UpdateUser(ctx, user.ID, updates); err != nil {
		slog.Error("users.update failed", "error", err)
		writeError(w, http.StatusInternalServerError, protocol.ErrInternal,
			i18n.T(locale, i18n.MsgFailedToUpdate, "user", "internal error"))
		return
	}

	// Disabling an account has to end its sessions too: ResolveUserSession
	// caches for up to a minute, and the point of disabling is immediate.
	if status, ok := updates["status"].(string); ok && status == store.UserStatusDisabled {
		if _, err := h.users.RevokeAllUserSessions(ctx, user.ID, ""); err != nil {
			slog.Warn("users.update session revoke failed", "error", err)
		}
		InvalidateUserSession("", h.msgBus)
	}

	updated, err := h.users.GetUserByID(ctx, user.ID)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": toUserProfile(updated)})
}

func (h *UsersAdminHandler) handleDelete(w http.ResponseWriter, r *http.Request) {
	locale := extractLocale(r)
	if h.unavailable(w, locale) || !requireMasterScope(w, r) {
		return
	}
	user, ok := h.lookupPathUser(w, r, locale)
	if !ok {
		return
	}

	ctx := r.Context()
	if err := h.users.DeleteUser(ctx, user.ID); err != nil {
		slog.Error("users.delete failed", "error", err)
		writeError(w, http.StatusInternalServerError, protocol.ErrInternal,
			i18n.T(locale, i18n.MsgFailedToDelete, "user", "internal error"))
		return
	}
	// Sessions are gone from the database; clear them from every cache too.
	InvalidateUserSession("", h.msgBus)

	// tenant_users rows are intentionally left alone: the identity string may
	// still be in use by an API key or a paired browser.
	slog.Info("users.deleted", "user_id", user.UserID, "by", store.UserIDFromContext(ctx))
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// handleSetPassword resets an account's password and signs it out everywhere.
func (h *UsersAdminHandler) handleSetPassword(w http.ResponseWriter, r *http.Request) {
	locale := extractLocale(r)
	if h.unavailable(w, locale) || !requireMasterScope(w, r) {
		return
	}
	user, ok := h.lookupPathUser(w, r, locale)
	if !ok {
		return
	}

	var input struct {
		NewPassword        string `json:"new_password"`
		MustChangePassword *bool  `json:"must_change_password"`
	}
	if !bindJSON(w, r, locale, &input) {
		return
	}
	if !validatePasswordOrFail(w, locale, input.NewPassword) {
		return
	}

	// An administrator setting someone else's password should force a change
	// on next sign-in, because the administrator now knows it.
	mustChange := true
	if input.MustChangePassword != nil {
		mustChange = *input.MustChangePassword
	}

	hash, err := crypto.HashPassword(input.NewPassword)
	if err != nil {
		slog.Error("users.set_password hash failed", "error", err)
		writeError(w, http.StatusInternalServerError, protocol.ErrInternal,
			i18n.T(locale, i18n.MsgInternalError, "password hashing"))
		return
	}

	ctx := r.Context()
	if err := h.users.SetPassword(ctx, user.ID, hash, mustChange); err != nil {
		slog.Error("users.set_password failed", "error", err)
		writeError(w, http.StatusInternalServerError, protocol.ErrInternal,
			i18n.T(locale, i18n.MsgFailedToUpdate, "password", "internal error"))
		return
	}
	revoked, err := h.users.RevokeAllUserSessions(ctx, user.ID, "")
	if err != nil {
		slog.Warn("users.set_password session revoke failed", "error", err)
	}
	InvalidateUserSession("", h.msgBus)

	slog.Info("users.password_reset", "user_id", user.UserID,
		"by", store.UserIDFromContext(ctx), "sessions_revoked", revoked)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":           "password_set",
		"sessions_revoked": revoked,
	})
}

func (h *UsersAdminHandler) handleRevokeSessions(w http.ResponseWriter, r *http.Request) {
	locale := extractLocale(r)
	if h.unavailable(w, locale) || !requireMasterScope(w, r) {
		return
	}
	user, ok := h.lookupPathUser(w, r, locale)
	if !ok {
		return
	}

	revoked, err := h.users.RevokeAllUserSessions(r.Context(), user.ID, "")
	if err != nil {
		slog.Error("users.revoke_sessions failed", "error", err)
		writeError(w, http.StatusInternalServerError, protocol.ErrInternal,
			i18n.T(locale, i18n.MsgInternalError, "session revoke"))
		return
	}
	InvalidateUserSession("", h.msgBus)
	slog.Info("users.sessions_revoked", "user_id", user.UserID, "count", revoked)
	writeJSON(w, http.StatusOK, map[string]any{"sessions_revoked": revoked})
}

// --- helpers ---

// lookupPathUser resolves {id} and pre-fetches the account, so every mutating
// handler verifies the target exists before acting on it.
func (h *UsersAdminHandler) lookupPathUser(w http.ResponseWriter, r *http.Request, locale string) (*store.UserData, bool) {
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, protocol.ErrInvalidRequest,
			i18n.T(locale, i18n.MsgInvalidID, "user"))
		return nil, false
	}
	user, err := h.users.GetUserByID(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && user == nil) {
		writeError(w, http.StatusNotFound, protocol.ErrNotFound,
			i18n.T(locale, i18n.MsgUserNotFound, idStr))
		return nil, false
	}
	if err != nil {
		slog.Error("users.lookup failed", "error", err)
		writeError(w, http.StatusInternalServerError, protocol.ErrInternal,
			i18n.T(locale, i18n.MsgInternalError, "user lookup"))
		return nil, false
	}
	return user, true
}

// deriveUserID builds a default identity from the local part of the email and
// makes it unique. The numeric suffixes keep readable ids for the common
// collision (two people named the same at different domains); the random
// suffix is the escape hatch when a name is contested many times over.
func (h *UsersAdminHandler) deriveUserID(ctx context.Context, email string) (string, error) {
	local, _, _ := strings.Cut(strings.ToLower(strings.TrimSpace(email)), "@")
	base := strings.Trim(nonSlugChars.ReplaceAllString(local, "-"), "-._")
	if base == "" {
		base = "user"
	}
	if len(base) > 240 {
		base = base[:240]
	}

	candidate := base
	for i := 2; i <= 50; i++ {
		taken, err := h.users.UserIDExists(ctx, candidate)
		if err != nil {
			return "", err
		}
		if !taken {
			return candidate, nil
		}
		candidate = fmt.Sprintf("%s-%d", base, i)
	}

	b := make([]byte, 3)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s-%s", base, hex.EncodeToString(b)), nil
}

// resolveTenantRef accepts either a tenant UUID or a slug.
func (h *UsersAdminHandler) resolveTenantRef(ctx context.Context, ref string) (uuid.UUID, error) {
	if h.tenants == nil {
		return uuid.Nil, errors.New("tenant store unavailable")
	}
	if id, err := uuid.Parse(ref); err == nil {
		t, err := h.tenants.GetTenant(ctx, id)
		if err != nil || t == nil {
			return uuid.Nil, errors.New("tenant not found")
		}
		return t.ID, nil
	}
	t, err := h.tenants.GetTenantBySlug(ctx, ref)
	if err != nil || t == nil {
		return uuid.Nil, errors.New("tenant not found")
	}
	return t.ID, nil
}

func (h *UsersAdminHandler) membershipsFor(ctx context.Context, userID string) []tenantMembership {
	return (&AuthLoginHandler{tenants: h.tenants}).membershipsFor(ctx, userID)
}

func validTenantRole(role string) bool {
	switch role {
	case store.TenantRoleOwner, store.TenantRoleAdmin, store.TenantRoleOperator,
		store.TenantRoleMember, store.TenantRoleViewer:
		return true
	}
	return false
}

// isUniqueViolation reports whether an insert failed on a uniqueness
// constraint. Matching on the message keeps one check working across the
// PostgreSQL and SQLite drivers, which report the condition differently.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "duplicate key") ||
		strings.Contains(msg, "unique constraint") ||
		strings.Contains(msg, "unique violation")
}
