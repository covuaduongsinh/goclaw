package cmd

import (
	"context"
	"log/slog"
	"time"

	"github.com/nextlevelbuilder/goclaw/internal/safego"
	"github.com/nextlevelbuilder/goclaw/internal/store"
)

const (
	// sessionSweepInterval is how often expired login sessions are deleted.
	sessionSweepInterval = time.Hour

	// sessionSweepGrace keeps expired rows around for a while after they stop
	// working, so "when did this token last get used" is still answerable
	// while investigating an incident.
	sessionSweepGrace = 7 * 24 * time.Hour
)

// startUserSessionSweeper deletes expired login sessions on a timer.
//
// Expiry is already enforced at lookup time, so this is housekeeping rather
// than a security control: without it the table only grows, since a session
// row outlives the token it represents.
//
// The goroutine stops with ctx, which is what keeps it from outliving the
// gateway in tests that build and tear down a server repeatedly.
func startUserSessionSweeper(ctx context.Context, users store.UserStore) {
	if users == nil {
		return
	}
	go func() {
		defer safego.Recover(func(v any) {
			slog.Error("user session sweeper panicked", "panic", v)
		})
		ticker := time.NewTicker(sessionSweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cutoff := time.Now().UTC().Add(-sessionSweepGrace)
				n, err := users.DeleteExpiredSessions(ctx, cutoff)
				if err != nil {
					slog.Warn("user session sweep failed", "error", err)
					continue
				}
				if n > 0 {
					slog.Info("user sessions swept", "deleted", n)
				}
			}
		}
	}()
}
