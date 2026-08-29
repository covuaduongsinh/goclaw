//go:build sqliteonly

package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nextlevelbuilder/goclaw/internal/config"
	"github.com/nextlevelbuilder/goclaw/internal/store"
	"github.com/nextlevelbuilder/goclaw/internal/store/sqlitestore"
)

// openAccountStores opens the account and tenant stores against the local
// SQLite database. See the PostgreSQL variant for why this talks to the
// database rather than to the gateway API.
func openAccountStores(_ context.Context) (store.UserStore, store.TenantStore, func(), error) {
	cfg, err := config.Load(resolveConfigPath())
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load config: %w", err)
	}
	dataDir := cfg.ResolvedDataDir()
	sqlitePath := cfg.Database.SQLitePath
	if sqlitePath == "" {
		sqlitePath = filepath.Join(dataDir, "goclaw.db")
	}
	stores, err := sqlitestore.NewSQLiteStores(store.StoreConfig{
		SQLitePath:       sqlitePath,
		StorageBackend:   "sqlite",
		EncryptionKey:    os.Getenv("GOCLAW_ENCRYPTION_KEY"),
		SkillsStorageDir: filepath.Join(dataDir, "skills-store"),
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open sqlite stores: %w", err)
	}
	return stores.Users, stores.Tenants, func() { stores.DB.Close() }, nil
}
