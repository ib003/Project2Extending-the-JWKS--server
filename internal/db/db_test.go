package db_test

import (
	"database/sql"
	"testing"
	"time"

	"jwks-server/internal/db"
	"jwks-server/internal/keys"
)

func setupDB(t *testing.T) *db.DB {
	t.Helper()

	store, err := db.NewDB(":memory:")
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}

	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	return store
}

func TestInsertAndGetValidKey(t *testing.T) {
	store := setupDB(t)
	defer func() { _ = store.Close() }()

	priv, err := keys.GenerateRSAKey()
	if err != nil {
		t.Fatalf("GenerateRSAKey: %v", err)
	}

	err = store.InsertKey(keys.PrivateKeyToPEM(priv), time.Now().Add(2*time.Hour).Unix())
	if err != nil {
		t.Fatalf("InsertKey: %v", err)
	}

	rec, err := store.GetValidKey()
	if err != nil {
		t.Fatalf("GetValidKey: %v", err)
	}

	if rec.Kid == 0 {
		t.Fatal("expected non-zero kid")
	}
	if len(rec.Key) == 0 {
		t.Fatal("expected stored key bytes")
	}
	if rec.Exp <= time.Now().Unix() {
		t.Fatal("expected unexpired key")
	}
}

func TestInsertAndGetExpiredKey(t *testing.T) {
	store := setupDB(t)
	defer func() { _ = store.Close() }()

	priv, err := keys.GenerateRSAKey()
	if err != nil {
		t.Fatalf("GenerateRSAKey: %v", err)
	}

	err = store.InsertKey(keys.PrivateKeyToPEM(priv), time.Now().Add(-2*time.Hour).Unix())
	if err != nil {
		t.Fatalf("InsertKey: %v", err)
	}

	rec, err := store.GetExpiredKey()
	if err != nil {
		t.Fatalf("GetExpiredKey: %v", err)
	}

	if rec.Kid == 0 {
		t.Fatal("expected non-zero kid")
	}
	if len(rec.Key) == 0 {
		t.Fatal("expected stored key bytes")
	}
	if rec.Exp > time.Now().Unix() {
		t.Fatal("expected expired key")
	}
}

func TestGetValidKeys_ReturnsOnlyValidKeys(t *testing.T) {
	store := setupDB(t)
	defer func() { _ = store.Close() }()

	validPriv1, err := keys.GenerateRSAKey()
	if err != nil {
		t.Fatalf("GenerateRSAKey valid1: %v", err)
	}
	validPriv2, err := keys.GenerateRSAKey()
	if err != nil {
		t.Fatalf("GenerateRSAKey valid2: %v", err)
	}
	expiredPriv, err := keys.GenerateRSAKey()
	if err != nil {
		t.Fatalf("GenerateRSAKey expired: %v", err)
	}

	if err := store.InsertKey(keys.PrivateKeyToPEM(validPriv1), time.Now().Add(2*time.Hour).Unix()); err != nil {
		t.Fatalf("InsertKey valid1: %v", err)
	}
	if err := store.InsertKey(keys.PrivateKeyToPEM(validPriv2), time.Now().Add(3*time.Hour).Unix()); err != nil {
		t.Fatalf("InsertKey valid2: %v", err)
	}
	if err := store.InsertKey(keys.PrivateKeyToPEM(expiredPriv), time.Now().Add(-2*time.Hour).Unix()); err != nil {
		t.Fatalf("InsertKey expired: %v", err)
	}

	recs, err := store.GetValidKeys()
	if err != nil {
		t.Fatalf("GetValidKeys: %v", err)
	}

	if len(recs) != 2 {
		t.Fatalf("expected 2 valid keys, got %d", len(recs))
	}
	for _, rec := range recs {
		if rec.Exp <= time.Now().Unix() {
			t.Fatal("expected returned keys to all be valid")
		}
	}
}

func TestGetValidKey_NoRows(t *testing.T) {
	store := setupDB(t)
	defer func() { _ = store.Close() }()

	_, err := store.GetValidKey()
	if err == nil {
		t.Fatal("expected error when no valid keys exist")
	}
	if err != sql.ErrNoRows {
		t.Fatalf("expected sql.ErrNoRows, got %v", err)
	}
}

func TestGetExpiredKey_NoRows(t *testing.T) {
	store := setupDB(t)
	defer func() { _ = store.Close() }()

	_, err := store.GetExpiredKey()
	if err == nil {
		t.Fatal("expected error when no expired keys exist")
	}
	if err != sql.ErrNoRows {
		t.Fatalf("expected sql.ErrNoRows, got %v", err)
	}
}

func TestGetValidKeys_Empty(t *testing.T) {
	store := setupDB(t)
	defer func() { _ = store.Close() }()

	recs, err := store.GetValidKeys()
	if err != nil {
		t.Fatalf("GetValidKeys: %v", err)
	}
	if len(recs) != 0 {
		t.Fatalf("expected 0 valid keys, got %d", len(recs))
	}
}

func TestClose(t *testing.T) {
	store := setupDB(t)
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}