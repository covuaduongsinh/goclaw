//go:build !sqlite && !sqliteonly

package cmd

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/nextlevelbuilder/goclaw/internal/store"
	"github.com/nextlevelbuilder/goclaw/internal/store/pg"
)

// openAccountStores opens the account and tenant stores directly against the
// database, bypassing the gateway.
//
// Talking to the database rather than to the HTTP API is what makes this
// usable for bootstrapping: the first account has to be created at a point
// where nobody can sign in yet, so there is no credential to call the API with.
func openAccountStores(ctx context.Context) (store.UserStore, store.TenantStore, func(), error) {
	dsn, err := resolveDSN()
	if err != nil {
		return nil, nil, nil, err
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
