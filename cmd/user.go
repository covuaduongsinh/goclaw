package cmd

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/nextlevelbuilder/goclaw/internal/crypto"
	"github.com/nextlevelbuilder/goclaw/internal/store"
)

// userCmd manages email + password accounts from the command line.
//
// The command is "user", not "auth": "goclaw auth" already manages the
// ChatGPT OAuth credential used by the Codex provider.
//
// It exists mainly to create the first account. Everything else here is also
// available over HTTP and WebSocket, but those require an administrator to
// already be signed in, which is impossible on a fresh install.
func userCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "user",
		Short: "Manage email + password accounts",
		Long: `Manage the accounts that can sign in to the web dashboard.

Accounts are created by an administrator; there is no self-service sign-up.
Use this command to create the first administrator account, after which the
rest can be managed from the dashboard.`,
	}
	cmd.AddCommand(userCreateCmd(), userListCmd(), userPasswdCmd(),
		userDisableCmd(), userEnableCmd(), userSessionsCmd())
	return cmd
}

// readPassword resolves the password for a command.
//
// A --password flag is accepted but not the default path: flag values are
// visible in the process list and in shell history, which is the wrong place
// for a credential. Without it the password is read from the terminal with
// echo off, from GOCLAW_USER_PASSWORD, or generated.
func readPassword(flagValue string, generate bool, prompt string) (password string, generated bool, err error) {
	if generate {
		b := make([]byte, 15) // 15 bytes -> 20 base64 characters
		if _, err := rand.Read(b); err != nil {
			return "", false, fmt.Errorf("generate password: %w", err)
		}
		return base64.RawURLEncoding.EncodeToString(b), true, nil
	}
	if flagValue != "" {
		return flagValue, false, nil
	}
	if env := os.Getenv("GOCLAW_USER_PASSWORD"); env != "" {
		return env, false, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", false, errors.New("no password supplied: pass --generate, set GOCLAW_USER_PASSWORD, or run interactively")
	}
	fmt.Fprint(os.Stderr, prompt)
	raw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", false, fmt.Errorf("read password: %w", err)
	}
	pw := string(raw)
	fmt.Fprint(os.Stderr, "Confirm password: ")
	confirmRaw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", false, fmt.Errorf("read password: %w", err)
	}
	if pw != string(confirmRaw) {
		return "", false, errors.New("passwords do not match")
	}
	return pw, false, nil
}

func userCreateCmd() *cobra.Command {
	var email, password, userID, displayName, tenantRef, role string
	var generate, mustChange bool

	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create an account",
		Long: `Create an email + password account.

--user-id binds the account to an existing identity string. Pass it when the
account should inherit agents, sessions or tenant membership that already
belong to that identity, including the bootstrap "system" identity. Without it
the identity is derived from the local part of the email address.

--tenant grants tenant membership in the same step. Without membership the
account signs in as a viewer with no tenant, which the dashboard rejects, so
this is effectively required for the first account.`,
		Example: `  goclaw user create --email admin@example.com --generate --tenant master --role owner
  goclaw user create --email me@example.com --user-id system --tenant master --role owner`,
		RunE: func(cmd *cobra.Command, args []string) error {
			email = strings.TrimSpace(email)
			if email == "" {
				return errors.New("--email is required")
			}
			pw, generated, err := readPassword(password, generate, "Password: ")
			if err != nil {
				return err
			}
			if err := crypto.ValidatePasswordPolicy(pw); err != nil {
				return err
			}

			ctx := cmd.Context()
			users, tenants, closeFn, err := openAccountStores(ctx)
			if err != nil {
				return err
			}
			defer closeFn()

			if userID == "" {
				local, _, _ := strings.Cut(strings.ToLower(email), "@")
				userID = strings.Map(func(r rune) rune {
					switch {
					case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
						return r
					default:
						return '-'
					}
				}, local)
			}
			if err := store.ValidateUserID(userID); err != nil {
				return err
			}
			taken, err := users.UserIDExists(ctx, userID)
			if err != nil {
				return fmt.Errorf("check user id: %w", err)
			}
			if taken {
				return fmt.Errorf("user id %q is already in use", userID)
			}

			hash, err := crypto.HashPassword(pw)
			if err != nil {
				return err
			}
			now := time.Now().UTC()
			u := &store.UserData{
				ID:                 store.GenNewID(),
				UserID:             userID,
				Email:              email,
				PasswordHash:       hash,
				DisplayName:        displayName,
				Status:             store.UserStatusActive,
				MustChangePassword: mustChange,
				CreatedBy:          "cli",
				CreatedAt:          now,
				UpdatedAt:          now,
			}
			if err := users.CreateUser(ctx, u); err != nil {
				return fmt.Errorf("create user: %w", err)
			}

			if tenantRef != "" {
				tid, err := resolveTenantRefCLI(ctx, tenants, tenantRef)
				if err != nil {
					return fmt.Errorf("account created but tenant lookup failed: %w", err)
				}
				if role == "" {
					role = store.TenantRoleMember
				}
				if err := tenants.AddUser(ctx, tid, userID, role); err != nil {
					return fmt.Errorf("account created but granting %s membership failed: %w", role, err)
				}
				fmt.Printf("Granted %s on tenant %s\n", role, tid)
			} else {
				fmt.Fprintln(os.Stderr,
					"Warning: no --tenant given. This account has no membership and will sign in as a viewer.")
			}

			fmt.Printf("Created account %s (user_id: %s)\n", email, userID)
			if generated {
				fmt.Printf("Generated password: %s\n", pw)
				fmt.Fprintln(os.Stderr, "This password is shown once. Store it now.")
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&email, "email", "", "email address (required)")
	cmd.Flags().StringVar(&password, "password", "", "password (prefer --generate or the interactive prompt)")
	cmd.Flags().BoolVar(&generate, "generate", false, "generate a random password and print it once")
	cmd.Flags().StringVar(&userID, "user-id", "", "identity string; defaults to the local part of the email")
	cmd.Flags().StringVar(&displayName, "name", "", "display name")
	cmd.Flags().StringVar(&tenantRef, "tenant", "", "tenant UUID or slug to grant membership in")
	cmd.Flags().StringVar(&role, "role", "", "tenant role: owner, admin, operator, member, viewer")
	cmd.Flags().BoolVar(&mustChange, "must-change-password", false, "require a password change on first sign-in")
	return cmd
}

func userListCmd() *cobra.Command {
	var limit int
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List accounts",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			users, _, closeFn, err := openAccountStores(ctx)
			if err != nil {
				return err
			}
			defer closeFn()

			rows, err := users.ListUsers(ctx, limit, 0)
			if err != nil {
				return fmt.Errorf("list users: %w", err)
			}
			if len(rows) == 0 {
				fmt.Println("No accounts yet. Create one with: goclaw user create --email you@example.com --generate")
				return nil
			}
			fmt.Printf("%-38s  %-24s  %-9s  %s\n", "EMAIL", "USER_ID", "STATUS", "LAST LOGIN")
			for _, u := range rows {
				last := "never"
				if u.LastLoginAt != nil {
					last = u.LastLoginAt.Format(time.RFC3339)
				}
				fmt.Printf("%-38s  %-24s  %-9s  %s\n", u.Email, u.UserID, u.Status, last)
			}
			return nil
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 50, "maximum accounts to list")
	return cmd
}

func userPasswdCmd() *cobra.Command {
	var email, password string
	var generate, keepSessions bool

	cmd := &cobra.Command{
		Use:   "passwd",
		Short: "Set an account password",
		Long: `Set an account password.

Every session for the account is revoked afterwards. If the old password
leaked, the point of changing it is to lock out whoever had it, which does not
happen while their token still works. Pass --keep-sessions to skip that.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(email) == "" {
				return errors.New("--email is required")
			}
			pw, generated, err := readPassword(password, generate, "New password: ")
			if err != nil {
				return err
			}
			if err := crypto.ValidatePasswordPolicy(pw); err != nil {
				return err
			}

			ctx := cmd.Context()
			users, _, closeFn, err := openAccountStores(ctx)
			if err != nil {
				return err
			}
			defer closeFn()

			u, err := lookupUserByEmail(ctx, users, email)
			if err != nil {
				return err
			}
			hash, err := crypto.HashPassword(pw)
			if err != nil {
				return err
			}
			if err := users.SetPassword(ctx, u.ID, hash, false); err != nil {
				return fmt.Errorf("set password: %w", err)
			}
			if !keepSessions {
				n, err := users.RevokeAllUserSessions(ctx, u.ID, "")
				if err != nil {
					return fmt.Errorf("password set but session revoke failed: %w", err)
				}
				fmt.Printf("Revoked %d session(s)\n", n)
			}
			fmt.Printf("Password updated for %s\n", u.Email)
			if generated {
				fmt.Printf("Generated password: %s\n", pw)
				fmt.Fprintln(os.Stderr, "This password is shown once. Store it now.")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&email, "email", "", "email address (required)")
	cmd.Flags().StringVar(&password, "password", "", "password (prefer --generate or the interactive prompt)")
	cmd.Flags().BoolVar(&generate, "generate", false, "generate a random password and print it once")
	cmd.Flags().BoolVar(&keepSessions, "keep-sessions", false, "do not revoke existing sessions")
	return cmd
}

func userDisableCmd() *cobra.Command { return userStatusCmd("disable", store.UserStatusDisabled) }
func userEnableCmd() *cobra.Command  { return userStatusCmd("enable", store.UserStatusActive) }

func userStatusCmd(name, status string) *cobra.Command {
	var email string
	cmd := &cobra.Command{
		Use:   name,
		Short: fmt.Sprintf("%s an account", strings.ToUpper(name[:1])+name[1:]),
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(email) == "" {
				return errors.New("--email is required")
			}
			ctx := cmd.Context()
			users, _, closeFn, err := openAccountStores(ctx)
			if err != nil {
				return err
			}
			defer closeFn()

			u, err := lookupUserByEmail(ctx, users, email)
			if err != nil {
				return err
			}
			if err := users.UpdateUser(ctx, u.ID, map[string]any{"status": status}); err != nil {
				return fmt.Errorf("update status: %w", err)
			}
			// Disabling has to end live sessions, not just block future sign-ins.
			if status == store.UserStatusDisabled {
				n, err := users.RevokeAllUserSessions(ctx, u.ID, "")
				if err != nil {
					return fmt.Errorf("status updated but session revoke failed: %w", err)
				}
				fmt.Printf("Revoked %d session(s)\n", n)
			}
			fmt.Printf("Account %s is now %s\n", u.Email, status)
			return nil
		},
	}
	cmd.Flags().StringVar(&email, "email", "", "email address (required)")
	return cmd
}

func userSessionsCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "sessions", Short: "Manage account sessions"}

	var email string
	revoke := &cobra.Command{
		Use:   "revoke",
		Short: "Revoke every session for an account",
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(email) == "" {
				return errors.New("--email is required")
			}
			ctx := cmd.Context()
			users, _, closeFn, err := openAccountStores(ctx)
			if err != nil {
				return err
			}
			defer closeFn()

			u, err := lookupUserByEmail(ctx, users, email)
			if err != nil {
				return err
			}
			n, err := users.RevokeAllUserSessions(ctx, u.ID, "")
			if err != nil {
				return fmt.Errorf("revoke sessions: %w", err)
			}
			fmt.Printf("Revoked %d session(s) for %s\n", n, u.Email)
			return nil
		},
	}
	revoke.Flags().StringVar(&email, "email", "", "email address (required)")

	list := &cobra.Command{
		Use:   "list",
		Short: "List live sessions for an account",
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(email) == "" {
				return errors.New("--email is required")
			}
			ctx := cmd.Context()
			users, _, closeFn, err := openAccountStores(ctx)
			if err != nil {
				return err
			}
			defer closeFn()

			u, err := lookupUserByEmail(ctx, users, email)
			if err != nil {
				return err
			}
			sessions, err := users.ListUserSessions(ctx, u.ID)
			if err != nil {
				return fmt.Errorf("list sessions: %w", err)
			}
			if len(sessions) == 0 {
				fmt.Printf("No live sessions for %s\n", u.Email)
				return nil
			}
			fmt.Printf("%-24s  %-20s  %s\n", "CREATED", "IP", "USER AGENT")
			for _, s := range sessions {
				fmt.Printf("%-24s  %-20s  %s\n",
					s.CreatedAt.Format(time.RFC3339), s.IP, s.UserAgent)
			}
			return nil
		},
	}
	list.Flags().StringVar(&email, "email", "", "email address (required)")

	cmd.AddCommand(revoke, list)
	return cmd
}

// lookupUserByEmail resolves an account and turns "no such row" into a clear
// message rather than a driver error.
func lookupUserByEmail(ctx context.Context, users store.UserStore, email string) (*store.UserData, error) {
	u, err := users.GetUserByEmail(ctx, strings.TrimSpace(email))
	if errors.Is(err, sql.ErrNoRows) || (err == nil && u == nil) {
		return nil, fmt.Errorf("no account with email %q", email)
	}
	if err != nil {
		return nil, fmt.Errorf("look up account: %w", err)
	}
	return u, nil
}

// resolveTenantRefCLI accepts a tenant UUID or slug.
func resolveTenantRefCLI(ctx context.Context, tenants store.TenantStore, ref string) (uuid.UUID, error) {
	if tenants == nil {
		return uuid.Nil, errors.New("tenant store unavailable")
	}
	if ref == "master" {
		return store.MasterTenantID, nil
	}
	if id, err := uuid.Parse(ref); err == nil {
		t, err := tenants.GetTenant(ctx, id)
		if err != nil || t == nil {
			return uuid.Nil, fmt.Errorf("tenant %q not found", ref)
		}
		return t.ID, nil
	}
	t, err := tenants.GetTenantBySlug(ctx, ref)
	if err != nil || t == nil {
		return uuid.Nil, fmt.Errorf("tenant %q not found", ref)
	}
	return t.ID, nil
}
