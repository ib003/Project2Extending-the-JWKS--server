// JWKS server entrypoint (Project 2).
package main

import (
	"database/sql"
	"log"
	"time"

	"jwks-server/internal/db"
	"jwks-server/internal/httpapi"
	"jwks-server/internal/keys"
)

const dbFile = "totally_not_my_privateKeys.db"

func main() {
	store, err := db.NewDB(dbFile)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}

	if err := store.Init(); err != nil {
		log.Fatalf("failed to initialize database: %v", err)
	}

	if err := ensureTestKeys(store); err != nil {
		log.Fatalf("failed to ensure test keys: %v", err)
	}

	srv := httpapi.NewServer(store)

	log.Println("JWKS server listening on :8080")
	if err := srv.ListenAndServe(":8080"); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

// ensureTestKeys guarantees the DB contains at least one expired key
// and at least one valid key so the endpoints can be tested.
func ensureTestKeys(store *db.DB) error {
	_, err := store.GetValidKey()
	if err != nil {
		if err == sql.ErrNoRows {
			priv, genErr := keys.GenerateRSAKey()
			if genErr != nil {
				return genErr
			}
			pemBytes := keys.PrivateKeyToPEM(priv)
			if insertErr := store.InsertKey(pemBytes, time.Now().Add(2*time.Hour).Unix()); insertErr != nil {
				return insertErr
			}
		} else {
			return err
		}
	}

	_, err = store.GetExpiredKey()
	if err != nil {
		if err == sql.ErrNoRows {
			priv, genErr := keys.GenerateRSAKey()
			if genErr != nil {
				return genErr
			}
			pemBytes := keys.PrivateKeyToPEM(priv)
			if insertErr := store.InsertKey(pemBytes, time.Now().Add(-2*time.Hour).Unix()); insertErr != nil {
				return insertErr
			}
		} else {
			return err
		}
	}

	return nil
}