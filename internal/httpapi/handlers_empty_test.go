package httpapi_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"jwks-server/internal/db"
	"jwks-server/internal/httpapi"
)

func TestJWKS_EmptyDatabaseReturnsEmptyKeys(t *testing.T) {
	store, err := db.NewDB(":memory:")
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer func() { _ = store.Close() }()

	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	h := httpapi.Handlers{DB: store}

	req := httptest.NewRequest(http.MethodGet, "/jwks", nil)
	rr := httptest.NewRecorder()
	h.JWKS(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d", rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(body, `"keys"`) {
		t.Fatalf("expected keys field in JWKS, got: %s", body)
	}
}