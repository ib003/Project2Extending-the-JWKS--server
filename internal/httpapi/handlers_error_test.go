package httpapi_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"jwks-server/internal/db"
	"jwks-server/internal/httpapi"
)

func TestJWKS_InvalidPEMReturns500(t *testing.T) {
	store, err := db.NewDB(":memory:")
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer func() { _ = store.Close() }()

	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Insert a "valid" DB row with bad PEM but future exp so JWKS tries to parse it
	if err := store.InsertKey([]byte("not-a-real-pem"), time.Now().Add(2*time.Hour).Unix()); err != nil {
		t.Fatalf("InsertKey: %v", err)
	}

	h := httpapi.Handlers{DB: store}

	req := httptest.NewRequest(http.MethodGet, "/jwks", nil)
	rr := httptest.NewRecorder()
	h.JWKS(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 got %d", rr.Code)
	}
}

func TestAuth_InvalidPEMReturns500(t *testing.T) {
	store, err := db.NewDB(":memory:")
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer func() { _ = store.Close() }()

	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Insert bad PEM for a valid key
	if err := store.InsertKey([]byte("definitely-not-pem"), time.Now().Add(2*time.Hour).Unix()); err != nil {
		t.Fatalf("InsertKey: %v", err)
	}

	h := httpapi.Handlers{DB: store}

	req := httptest.NewRequest(http.MethodPost, "/auth", nil)
	rr := httptest.NewRecorder()
	h.Auth(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 got %d", rr.Code)
	}
}
func TestAuth_NoValidKeyReturns500(t *testing.T) {
	store, err := db.NewDB(":memory:")
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer func() { _ = store.Close() }()

	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	h := httpapi.Handlers{DB: store}

	req := httptest.NewRequest(http.MethodPost, "/auth", nil)
	rr := httptest.NewRecorder()
	h.Auth(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 got %d", rr.Code)
	}
}