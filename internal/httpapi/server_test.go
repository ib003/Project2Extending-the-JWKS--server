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

func setupTestDB(t *testing.T) *db.DB {
	t.Helper()

	store, err := db.NewDB(":memory:")
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}

	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Insert one valid key
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

	// Insert one expired key
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

func TestServer_RoutesJWKSPaths(t *testing.T) {
	store := setupTestDB(t)
	s := httpapi.NewServer(store)

	req1 := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rr1 := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("well-known jwks expected 200 got %d", rr1.Code)
	}
	if !strings.Contains(rr1.Body.String(), `"keys"`) {
		t.Fatalf("expected jwks json, got: %s", rr1.Body.String())
	}

	req2 := httptest.NewRequest(http.MethodGet, "/jwks", nil)
	rr2 := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("/jwks expected 200 got %d", rr2.Code)
	}
}

func TestServer_RoutesAuthAnd405(t *testing.T) {
	store := setupTestDB(t)
	s := httpapi.NewServer(store)

	req := httptest.NewRequest(http.MethodPost, "/auth", nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("POST /auth expected 200 got %d", rr.Code)
	}
	if strings.Count(strings.TrimSpace(rr.Body.String()), ".") != 2 {
		t.Fatalf("expected JWT token, got: %s", rr.Body.String())
	}

	reqBad := httptest.NewRequest(http.MethodGet, "/auth", nil)
	rrBad := httptest.NewRecorder()
	s.Handler().ServeHTTP(rrBad, reqBad)
	if rrBad.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /auth expected 405 got %d", rrBad.Code)
	}

	reqBad2 := httptest.NewRequest(http.MethodPost, "/jwks", nil)
	rrBad2 := httptest.NewRecorder()
	s.Handler().ServeHTTP(rrBad2, reqBad2)
	if rrBad2.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /jwks expected 405 got %d", rrBad2.Code)
	}
}