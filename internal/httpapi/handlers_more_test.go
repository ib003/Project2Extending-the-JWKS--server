package httpapi_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"jwks-server/internal/db"
	"jwks-server/internal/httpapi"
	"jwks-server/internal/keys"
)

func setupHandlersTestDB(t *testing.T) *db.DB {
	t.Helper()

	store, err := db.NewDB(":memory:")
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}

	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	validPriv, err := keys.GenerateRSAKey()
	if err != nil {
		t.Fatalf("GenerateRSAKey valid: %v", err)
	}
	if err := store.InsertKey(
		keys.PrivateKeyToPEM(validPriv),
		time.Now().Add(2*time.Hour).Unix(),
	); err != nil {
		t.Fatalf("InsertKey valid: %v", err)
	}

	expiredPriv, err := keys.GenerateRSAKey()
	if err != nil {
		t.Fatalf("GenerateRSAKey expired: %v", err)
	}
	if err := store.InsertKey(
		keys.PrivateKeyToPEM(expiredPriv),
		time.Now().Add(-2*time.Hour).Unix(),
	); err != nil {
		t.Fatalf("InsertKey expired: %v", err)
	}

	return store
}

func TestJWKS_WithValidKeyReturnsKeysField(t *testing.T) {
	store := setupHandlersTestDB(t)
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
	if !strings.Contains(body, `"kid"`) {
		t.Fatalf("expected at least one valid JWK, got: %s", body)
	}
}

func TestAuth_ExpiredFalseAndZeroAreTreatedAsNotExpired(t *testing.T) {
	store := setupHandlersTestDB(t)
	h := httpapi.Handlers{DB: store}

	for _, q := range []string{"expired=false", "expired=0"} {
		req := httptest.NewRequest(http.MethodPost, "/auth?"+q, nil)
		rr := httptest.NewRecorder()
		h.Auth(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("query %q expected 200 got %d", q, rr.Code)
		}

		raw := strings.TrimSpace(rr.Body.String())
		if raw == "" || strings.Count(raw, ".") != 2 {
			t.Fatalf("query %q expected JWT, got: %s", q, raw)
		}
	}
}

func TestAuth_ExpiredWeirdValueCountsAsExpired(t *testing.T) {
	store := setupHandlersTestDB(t)
	h := httpapi.Handlers{DB: store}

	req := httptest.NewRequest(http.MethodPost, "/auth?expired=yes", nil)
	rr := httptest.NewRecorder()
	h.Auth(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d", rr.Code)
	}

	raw := strings.TrimSpace(rr.Body.String())
	if raw == "" || strings.Count(raw, ".") != 2 {
		t.Fatalf("expected JWT, got: %s", raw)
	}
}