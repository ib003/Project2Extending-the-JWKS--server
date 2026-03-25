package main

import (
	"database/sql"
	"testing"
	"time"

	"jwks-server/internal/db"
	"jwks-server/internal/keys"
)

func TestEnsureTestKeys_InsertsValidAndExpiredKeys(t *testing.T) {
	store, err := db.NewDB(":memory:")
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer func() { _ = store.Close() }()

	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	if err := ensureTestKeys(store); err != nil {
		t.Fatalf("ensureTestKeys: %v", err)
	}

	if _, err := store.GetValidKey(); err != nil {
		t.Fatalf("expected valid key after ensureTestKeys, got error: %v", err)
	}

	if _, err := store.GetExpiredKey(); err != nil {
		t.Fatalf("expected expired key after ensureTestKeys, got error: %v", err)
	}
}

func TestEnsureTestKeys_DoesNotFailWhenKeysAlreadyExist(t *testing.T) {
	store, err := db.NewDB(":memory:")
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer func() { _ = store.Close() }()

	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	if err := ensureTestKeys(store); err != nil {
		t.Fatalf("first ensureTestKeys: %v", err)
	}

	if err := ensureTestKeys(store); err != nil {
		t.Fatalf("second ensureTestKeys: %v", err)
	}

	if _, err := store.GetValidKey(); err != nil && err != sql.ErrNoRows {
		t.Fatalf("unexpected valid key error: %v", err)
	}
	if _, err := store.GetExpiredKey(); err != nil && err != sql.ErrNoRows {
		t.Fatalf("unexpected expired key error: %v", err)
	}
}

func TestEnsureTestKeys_WhenOnlyValidExists_AddsExpired(t *testing.T) {
	store, err := db.NewDB(":memory:")
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer func() { _ = store.Close() }()

	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	priv, err := keys.GenerateRSAKey()
	if err != nil {
		t.Fatalf("GenerateRSAKey: %v", err)
	}

	if err := store.InsertKey(
		keys.PrivateKeyToPEM(priv),
		time.Now().Add(2*time.Hour).Unix(),
	); err != nil {
		t.Fatalf("InsertKey valid: %v", err)
	}

	if err := ensureTestKeys(store); err != nil {
		t.Fatalf("ensureTestKeys: %v", err)
	}

	if _, err := store.GetValidKey(); err != nil {
		t.Fatalf("expected valid key, got error: %v", err)
	}
	if _, err := store.GetExpiredKey(); err != nil {
		t.Fatalf("expected expired key to be added, got error: %v", err)
	}
}

func TestEnsureTestKeys_WhenOnlyExpiredExists_AddsValid(t *testing.T) {
	store, err := db.NewDB(":memory:")
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer func() { _ = store.Close() }()

	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	priv, err := keys.GenerateRSAKey()
	if err != nil {
		t.Fatalf("GenerateRSAKey: %v", err)
	}

	if err := store.InsertKey(
		keys.PrivateKeyToPEM(priv),
		time.Now().Add(-2*time.Hour).Unix(),
	); err != nil {
		t.Fatalf("InsertKey expired: %v", err)
	}

	if err := ensureTestKeys(store); err != nil {
		t.Fatalf("ensureTestKeys: %v", err)
	}

	if _, err := store.GetExpiredKey(); err != nil {
		t.Fatalf("expected expired key, got error: %v", err)
	}
	if _, err := store.GetValidKey(); err != nil {
		t.Fatalf("expected valid key to be added, got error: %v", err)
	}
	
}
func TestEnsureTestKeys_DBErrorReturnsError(t *testing.T) {
	store, err := db.NewDB(":memory:")
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}

	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Force DB operations to fail
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	err = ensureTestKeys(store)
	if err == nil {
		t.Fatal("expected ensureTestKeys to return an error when DB is closed")
	}
}