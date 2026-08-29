package methods

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nextlevelbuilder/goclaw/internal/bus"
	"github.com/nextlevelbuilder/goclaw/internal/crypto"
	"github.com/nextlevelbuilder/goclaw/internal/gateway"
	"github.com/nextlevelbuilder/goclaw/internal/i18n"
	"github.com/nextlevelbuilder/goclaw/internal/store"
	"github.com/nextlevelbuilder/goclaw/pkg/protocol"
)

// UsersMethods handles user account management over WebSocket.
//
// It mirrors the HTTP handler in internal/http/users_admin.go, including its
// master-scope requirement: users is a global table, so a tenant-scoped admin
// must not be able to create or edit accounts. The predicate is shared with
// HTTP via store.IsMasterScope so the two transports cannot drift apart.
type UsersMethods struct {
	users   store.UserStore
	tenants store.TenantStore
	msgBus  *bus.MessageBus
}

// NewUsersMethods creates the user account RPC handler.
func NewUsersMethods(users store.UserStore, tenants store.TenantStore, msgBus *bus.MessageBus) *UsersMethods {
	return &UsersMethods{users: users, tenants: tenants, msgBus: msgBus}
}

// Register registers user account RPC methods.
func (m *UsersMethods) Register(router *gateway.MethodRouter) {
	router.Register(protocol.MethodUsersList, m.handleList)
	router.Register(protocol.MethodUsersGet, m.handleGet)
	router.Register(protocol.MethodUsersCreate, m.handleCreate)
	router.Register(protocol.MethodUsersUpdate, m.handleUpdate)
	router.Register(protocol.MethodUsersDelete, m.handleDelete)
	router.Register(protocol.MethodUsersPasswordSet, m.handlePasswordSet)
}

// userView is the wire shape of an account. store.UserData is never sent
// directly so the password hash cannot reach a client.
type userView struct {
	ID                 string     `json:"id"`
	UserID             string     `json:"user_id"`
	Email              string     `json:"email"`
	DisplayName        string     `json:"display_name"`
	Status             string     `json:"status"`
	MustChangePassword bool       `json:"must_change_password"`
	LastLoginAt        *time.Time `json:"last_login_at"`
	CreatedAt          time.Time  `json:"created_at"`
}

func toUserView(u *store.UserData) userView {
	return userView{
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

// guard applies the shared preconditions: the store must exist and the caller
// must be operating at master scope.
func (m *UsersMethods) guard(ctx context.Context, client *gateway.Client, req *protocol.RequestFrame, method string) bool {
	locale := store.LocaleFromContext(ctx)
	if m.users == nil {
		client.SendResponse(protocol.NewErrorResponse(req.ID, protocol.ErrUnavailable,
			i18n.T(locale, i18n.MsgUserAccountsDisabled)))
		return false
	}
	if !store.IsMasterScope(ctx) {
		slog.Warn("security.tenant_scope_violation",
			"method", method,
			"tenant_id", store.TenantIDFromContext(ctx),
			"user_id", store.UserIDFromContext(ctx),
		)
		client.SendResponse(protocol.NewErrorResponse(req.ID, protocol.ErrUnauthorized,
			i18n.T(locale, i18n.MsgMasterScopeRequired)))
		return false
	}
	return true
}

func (m *UsersMethods) handleList(ctx context.Context, client *gateway.Client, req *protocol.RequestFrame) {
	if !m.guard(ctx, client, req, protocol.MethodUsersList) {
		return
	}
	locale := store.LocaleFromContext(ctx)

	var params struct {
		Limit  int `json:"limit"`
		Offset int `json:"offset"`
	}
	if req.Params != nil {
		json.Unmarshal(req.Params, &params) //nolint:errcheck // both fields are optional
	}

	users, err := m.users.ListUsers(ctx, params.Limit, params.Offset)
	if err != nil {
		slog.Error("users.list failed", "error", err)
		client.SendResponse(protocol.NewErrorResponse(req.ID, protocol.ErrInternal,
			i18n.T(locale, i18n.MsgFailedToList, "users")))
		return
	}
	out := make([]userView, 0, len(users))
	for i := range users {
		out = append(out, toUserView(&users[i]))
	}
	client.SendResponse(protocol.NewOKResponse(req.ID, map[string]any{"users": out}))
}

func (m *UsersMethods) handleGet(ctx context.Context, client *gateway.Client, req *protocol.RequestFrame) {
	if !m.guard(ctx, client, req, protocol.MethodUsersGet) {
		return
	}
	user, ok := m.lookupUser(ctx, client, req)
	if !ok {
		return
	}
	client.SendResponse(protocol.NewOKResponse(req.ID, map[string]any{"user": toUserView(user)}))
}

func (m *UsersMethods) handleCreate(ctx context.Context, client *gateway.Client, req *protocol.RequestFrame) {
	if !m.guard(ctx, client, req, protocol.MethodUsersCreate) {
		return
	}
	locale := store.LocaleFromContext(ctx)

	var params struct {
		Email              string `json:"email"`
		Password           string `json:"password"`
		UserID             string `json:"userId"`
		DisplayName        string `json:"displayName"`
		TenantID           string `json:"tenantId"`
		TenantRole         string `json:"tenantRole"`
		MustChangePassword bool   `json:"mustChangePassword"`
	}
	if req.Params != nil {
		if err := json.Unmarshal(req.Params, &params); err != nil {
			client.SendResponse(protocol.NewErrorResponse(req.ID, protocol.ErrInvalidRequest,
				i18n.T(locale, i18n.MsgInvalidJSON)))
			return
		}
	}

	params.Email = strings.TrimSpace(params.Email)
	if params.Email == "" {
		client.SendResponse(protocol.NewErrorResponse(req.ID, protocol.ErrInvalidRequest,
			i18n.T(locale, i18n.MsgRequired, "email")))
		return
	}
	if err := crypto.ValidatePasswordPolicy(params.Password); err != nil {
		client.SendResponse(protocol.NewErrorResponse(req.ID, protocol.ErrInvalidRequest, err.Error()))
		return
	}

	userID := strings.TrimSpace(params.UserID)
	if userID == "" {
		local, _, _ := strings.Cut(strings.ToLower(params.Email), "@")
		userID = local
	}
	if err := store.ValidateUserID(userID); err != nil || userID == "" {
		client.SendResponse(protocol.NewErrorResponse(req.ID, protocol.ErrInvalidRequest,
			i18n.T(locale, i18n.MsgInvalidRequest, "user_id")))
		return
	}
	taken, err := m.users.UserIDExists(ctx, userID)
	if err != nil {
		slog.Error("users.create user_id check failed", "error", err)
		client.SendResponse(protocol.NewErrorResponse(req.ID, protocol.ErrInternal,
			i18n.T(locale, i18n.MsgInternalError, "user_id check")))
		return
	}
	if taken {
		client.SendResponse(protocol.NewErrorResponse(req.ID, protocol.ErrAlreadyExists,
			i18n.T(locale, i18n.MsgUserIDExists, userID)))
		return
	}

	hash, err := crypto.HashPassword(params.Password)
	if err != nil {
		slog.Error("users.create hash failed", "error", err)
		client.SendResponse(protocol.NewErrorResponse(req.ID, protocol.ErrInternal,
			i18n.T(locale, i18n.MsgInternalError, "password hashing")))
		return
	}

	now := time.Now().UTC()
	user := &store.UserData{
		ID:                 store.GenNewID(),
		UserID:             userID,
		Email:              params.Email,
		PasswordHash:       hash,
		DisplayName:        strings.TrimSpace(params.DisplayName),
		Status:             store.UserStatusActive,
		MustChangePassword: params.MustChangePassword,
		CreatedBy:          store.UserIDFromContext(ctx),
		CreatedAt:          now,
		UpdatedAt:          now,
	}
	if err := m.users.CreateUser(ctx, user); err != nil {
		slog.Error("users.create failed", "error", err)
		client.SendResponse(protocol.NewErrorResponse(req.ID, protocol.ErrInternal,
			i18n.T(locale, i18n.MsgFailedToCreate, "user", err.Error())))
		return
	}

	// Grant tenant membership in the same call. Without it the account signs
	// in as a viewer with no tenant, which the web client rejects.
	if params.TenantID != "" && m.tenants != nil {
		if tid, err := uuid.Parse(params.TenantID); err == nil {
			role := params.TenantRole
			if role == "" {
				role = store.TenantRoleMember
			}
			if err := m.tenants.AddUser(ctx, tid, userID, role); err != nil {
				slog.Error("users.create tenant membership failed",
					"user_id", userID, "tenant_id", tid, "error", err)
			} else {
				m.emitCacheInvalidate(bus.CacheKindTenantUsers, userID)
			}
		}
	}

	slog.Info("users.created", "user_id", userID, "by", store.UserIDFromContext(ctx))
	client.SendResponse(protocol.NewOKResponse(req.ID, map[string]any{"user": toUserView(user)}))
}

func (m *UsersMethods) handleUpdate(ctx context.Context, client *gateway.Client, req *protocol.RequestFrame) {
	if !m.guard(ctx, client, req, protocol.MethodUsersUpdate) {
		return
	}
	locale := store.LocaleFromContext(ctx)
	user, ok := m.lookupUser(ctx, client, req)
	if !ok {
		return
	}

	var params struct {
		DisplayName        *string `json:"displayName"`
		Status             *string `json:"status"`
		MustChangePassword *bool   `json:"mustChangePassword"`
	}
	if req.Params != nil {
		if err := json.Unmarshal(req.Params, &params); err != nil {
			client.SendResponse(protocol.NewErrorResponse(req.ID, protocol.ErrInvalidRequest,
				i18n.T(locale, i18n.MsgInvalidJSON)))
			return
		}
	}

	updates := map[string]any{}
	if params.DisplayName != nil {
		updates["display_name"] = strings.TrimSpace(*params.DisplayName)
	}
	if params.MustChangePassword != nil {
		updates["must_change_password"] = *params.MustChangePassword
	}
	if params.Status != nil {
		status := strings.TrimSpace(*params.Status)
		if status != store.UserStatusActive && status != store.UserStatusDisabled {
			client.SendResponse(protocol.NewErrorResponse(req.ID, protocol.ErrInvalidRequest,
				i18n.T(locale, i18n.MsgInvalidRequest, "status must be active or disabled")))
			return
		}
		updates["status"] = status
	}
	if len(updates) == 0 {
		client.SendResponse(protocol.NewErrorResponse(req.ID, protocol.ErrInvalidRequest,
			i18n.T(locale, i18n.MsgInvalidUpdates)))
		return
	}

	if err := m.users.UpdateUser(ctx, user.ID, updates); err != nil {
		slog.Error("users.update failed", "error", err)
		client.SendResponse(protocol.NewErrorResponse(req.ID, protocol.ErrInternal,
			i18n.T(locale, i18n.MsgFailedToUpdate, "user", err.Error())))
		return
	}
	// A disabled account must lose its live sessions, not just its ability to
	// sign in again.
	if status, ok := updates["status"].(string); ok && status == store.UserStatusDisabled {
		if _, err := m.users.RevokeAllUserSessions(ctx, user.ID, ""); err != nil {
			slog.Warn("users.update session revoke failed", "error", err)
		}
		m.emitCacheInvalidate(bus.CacheKindUserSessions, user.UserID)
	}

	client.SendResponse(protocol.NewOKResponse(req.ID, map[string]string{"ok": "true"}))
}

func (m *UsersMethods) handleDelete(ctx context.Context, client *gateway.Client, req *protocol.RequestFrame) {
	if !m.guard(ctx, client, req, protocol.MethodUsersDelete) {
		return
	}
	locale := store.LocaleFromContext(ctx)
	user, ok := m.lookupUser(ctx, client, req)
	if !ok {
		return
	}

	if err := m.users.DeleteUser(ctx, user.ID); err != nil {
		slog.Error("users.delete failed", "error", err)
		client.SendResponse(protocol.NewErrorResponse(req.ID, protocol.ErrInternal,
			i18n.T(locale, i18n.MsgFailedToDelete, "user", err.Error())))
		return
	}
	m.emitCacheInvalidate(bus.CacheKindUserSessions, user.UserID)
	slog.Info("users.deleted", "user_id", user.UserID, "by", store.UserIDFromContext(ctx))
	client.SendResponse(protocol.NewOKResponse(req.ID, map[string]string{"ok": "true"}))
}

func (m *UsersMethods) handlePasswordSet(ctx context.Context, client *gateway.Client, req *protocol.RequestFrame) {
	if !m.guard(ctx, client, req, protocol.MethodUsersPasswordSet) {
		return
	}
	locale := store.LocaleFromContext(ctx)
	user, ok := m.lookupUser(ctx, client, req)
	if !ok {
		return
	}

	var params struct {
		NewPassword        string `json:"newPassword"`
		MustChangePassword *bool  `json:"mustChangePassword"`
	}
	if req.Params != nil {
		if err := json.Unmarshal(req.Params, &params); err != nil {
			client.SendResponse(protocol.NewErrorResponse(req.ID, protocol.ErrInvalidRequest,
				i18n.T(locale, i18n.MsgInvalidJSON)))
			return
		}
	}
	if err := crypto.ValidatePasswordPolicy(params.NewPassword); err != nil {
		client.SendResponse(protocol.NewErrorResponse(req.ID, protocol.ErrInvalidRequest, err.Error()))
		return
	}

	// Default to forcing a change: whoever reset it now knows the password.
	mustChange := true
	if params.MustChangePassword != nil {
		mustChange = *params.MustChangePassword
	}

	hash, err := crypto.HashPassword(params.NewPassword)
	if err != nil {
		slog.Error("users.password.set hash failed", "error", err)
		client.SendResponse(protocol.NewErrorResponse(req.ID, protocol.ErrInternal,
			i18n.T(locale, i18n.MsgInternalError, "password hashing")))
		return
	}
	if err := m.users.SetPassword(ctx, user.ID, hash, mustChange); err != nil {
		slog.Error("users.password.set failed", "error", err)
		client.SendResponse(protocol.NewErrorResponse(req.ID, protocol.ErrInternal,
			i18n.T(locale, i18n.MsgFailedToUpdate, "password", err.Error())))
		return
	}
	revoked, err := m.users.RevokeAllUserSessions(ctx, user.ID, "")
	if err != nil {
		slog.Warn("users.password.set session revoke failed", "error", err)
	}
	m.emitCacheInvalidate(bus.CacheKindUserSessions, user.UserID)

	slog.Info("users.password_reset", "user_id", user.UserID,
		"by", store.UserIDFromContext(ctx), "sessions_revoked", revoked)
	client.SendResponse(protocol.NewOKResponse(req.ID, map[string]any{"sessions_revoked": revoked}))
}

// lookupUser resolves the id param and pre-fetches the account so every
// mutating handler confirms the target exists before acting.
func (m *UsersMethods) lookupUser(ctx context.Context, client *gateway.Client, req *protocol.RequestFrame) (*store.UserData, bool) {
	locale := store.LocaleFromContext(ctx)
	var params struct {
		ID string `json:"id"`
	}
	if req.Params != nil {
		json.Unmarshal(req.Params, &params) //nolint:errcheck // validated below
	}
	id, err := uuid.Parse(params.ID)
	if err != nil {
		client.SendResponse(protocol.NewErrorResponse(req.ID, protocol.ErrInvalidRequest,
			i18n.T(locale, i18n.MsgInvalidID, "user")))
		return nil, false
	}
	user, err := m.users.GetUserByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && user == nil) {
		client.SendResponse(protocol.NewErrorResponse(req.ID, protocol.ErrNotFound,
			i18n.T(locale, i18n.MsgUserNotFound, params.ID)))
		return nil, false
	}
	if err != nil {
		slog.Error("users.lookup failed", "error", err)
		client.SendResponse(protocol.NewErrorResponse(req.ID, protocol.ErrInternal,
			i18n.T(locale, i18n.MsgInternalError, "user lookup")))
		return nil, false
	}
	return user, true
}

func (m *UsersMethods) emitCacheInvalidate(kind, key string) {
	if m.msgBus == nil {
		return
	}
	m.msgBus.Broadcast(bus.Event{
		Name:    protocol.EventCacheInvalidate,
		Payload: bus.CacheInvalidatePayload{Kind: kind, Key: key},
	})
}
