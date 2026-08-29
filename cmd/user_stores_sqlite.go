//go:build sqlite && !sqliteonly

package cmd

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nextlevelbuilder/goclaw/internal/config"
	"github.com/nextlevelbuilder/goclaw/internal/store"
	"github.com/nextlevelbuilder/goclaw/internal/store/pg"
	"github.com/nextlevelbuilder/goclaw/internal/store/sqlitestore"
)

// openAccountStores opens the account and tenant stores for whichever backend
// GOCLAW_STORAGE_BACKEND selects. See the PostgreSQL variant for why this
// talks to the database rather than to the gateway API.
func openAccountStores(ctx context.Context) (store.UserStore, store.TenantStore, func(), error) {
	cfg, err := config.Load(resolveConfigPath())
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load config: %w", err)
	}
	if cfg.Database.StorageBackend != "sqlite" {
		dsn := cfg.Database.PostgresDSN
		if dsn == "" {
			return nil, nil, nil, fmt.Errorf("GOCLAW_POSTGRES_DSN environment variable is not set")
		}
		db, err := sql.Open("pgx", dsn)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("open db: %w", err)
		}
		if err := db.PingContext(ctx); err != nil {
			db.Close()
			return nil, nil, nil, fmt.Errorf("ping db: %w", err)
		}
		return pg.NewPGUserStore(db), pg.NewPGTenantStore(db), func() { db.Close() }, nil
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
