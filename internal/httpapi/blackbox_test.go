package httpapi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"jwks-server/internal/db"
	"jwks-server/internal/httpapi"
	"jwks-server/internal/jwks"
	"jwks-server/internal/keys"

	"github.com/golang-jwt/jwt/v5"
)

func setupBlackboxTestDB(t *testing.T) (*db.DB, int, int) {
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

	validRec, err := store.GetValidKey()
	if err != nil {
		t.Fatalf("GetValidKey: %v", err)
	}
	expiredRec, err := store.GetExpiredKey()
	if err != nil {
		t.Fatalf("GetExpiredKey: %v", err)
	}

	return store, validRec.Kid, expiredRec.Kid
}

func TestJWKS_OnlyUnexpiredKeyServed(t *testing.T) {
	store, validKid, expiredKid := setupBlackboxTestDB(t)
	h := httpapi.Handlers{DB: store}

	req := httptest.NewRequest(http.MethodGet, "/jwks", nil)
	rr := httptest.NewRecorder()
	h.JWKS(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d", rr.Code)
	}

	var got jwks.JWKS
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(got.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(got.Keys))
	}
	if got.Keys[0].KID != strconv.Itoa(validKid) {
		t.Fatalf("expected valid kid %d got %s", validKid, got.Keys[0].KID)
	}
	if got.Keys[0].KID == strconv.Itoa(expiredKid) {
		t.Fatalf("expired kid should not be served")
	}
}

func TestJWKS_WrongMethod405(t *testing.T) {
	store, _, _ := setupBlackboxTestDB(t)
	h := httpapi.Handlers{DB: store}

	req := httptest.NewRequest(http.MethodPost, "/jwks", nil)
	rr := httptest.NewRecorder()
	h.JWKS(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 got %d", rr.Code)
	}
}

func TestAuth_IssuesValidUnexpiredJWT(t *testing.T) {
	store, validKid, _ := setupBlackboxTestDB(t)
	h := httpapi.Handlers{DB: store}

	req := httptest.NewRequest(http.MethodPost, "/auth", nil)
	rr := httptest.NewRecorder()
	h.Auth(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d", rr.Code)
	}
	raw := strings.TrimSpace(rr.Body.String())
	if raw == "" {
		t.Fatal("expected token body")
	}

	validRec, err := store.GetValidKey()
	if err != nil {
		t.Fatalf("GetValidKey: %v", err)
	}
	validPriv, err := keys.PEMToPrivateKey(validRec.Key)
	if err != nil {
		t.Fatalf("PEMToPrivateKey valid: %v", err)
	}

	parsed, err := jwt.Parse(raw, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			t.Fatalf("unexpected method: %v", token.Header["alg"])
		}
		kid, _ := token.Header["kid"].(string)
		if kid != strconv.Itoa(validKid) {
			t.Fatalf("expected kid %d got %s", validKid, kid)
		}
		return &validPriv.PublicKey, nil
	})
	if err != nil || !parsed.Valid {
		t.Fatalf("token invalid: %v", err)
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("claims type wrong")
	}
	expFloat := claims["exp"].(float64)
	exp := time.Unix(int64(expFloat), 0)
	if !exp.After(time.Now().UTC()) {
		t.Fatalf("expected unexpired exp, got %v", exp)
	}
}

func TestAuth_ExpiredQueryIssuesExpiredJWT(t *testing.T) {
	store, _, expiredKid := setupBlackboxTestDB(t)
	h := httpapi.Handlers{DB: store}

	req := httptest.NewRequest(http.MethodPost, "/auth?expired=true", nil)
	rr := httptest.NewRecorder()
	h.Auth(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d", rr.Code)
	}
	raw := strings.TrimSpace(rr.Body.String())
	if raw == "" {
		t.Fatal("expected token body")
	}

	expiredRec, err := store.GetExpiredKey()
	if err != nil {
		t.Fatalf("GetExpiredKey: %v", err)
	}
	expiredPriv, err := keys.PEMToPrivateKey(expiredRec.Key)
	if err != nil {
		t.Fatalf("PEMToPrivateKey expired: %v", err)
	}

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsed, err := parser.Parse(raw, func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)
		if kid != strconv.Itoa(expiredKid) {
			t.Fatalf("expected expired kid %d got %s", expiredKid, kid)
		}
		return &expiredPriv.PublicKey, nil
	})
	if err != nil || !parsed.Valid {
		t.Fatalf("expired token should still verify signature; err=%v", err)
	}

	claims := parsed.Claims.(jwt.MapClaims)
	expFloat := claims["exp"].(float64)
	exp := time.Unix(int64(expFloat), 0)
	if !exp.Before(time.Now().UTC()) {
		t.Fatalf("expected expired exp, got %v", exp)
	}
}

func TestAuth_WrongMethod405(t *testing.T) {
	store, _, _ := setupBlackboxTestDB(t)
	h := httpapi.Handlers{DB: store}

	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	rr := httptest.NewRecorder()
	h.Auth(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 got %d", rr.Code)
	}
}