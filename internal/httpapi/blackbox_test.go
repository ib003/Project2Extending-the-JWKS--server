package httpapi_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"jwks-server/internal/httpapi"
	"jwks-server/internal/jwks"
	"jwks-server/internal/keys"

	"github.com/golang-jwt/jwt/v5"
)

func TestJWKS_OnlyUnexpiredKeyServed(t *testing.T) {
	km, err := keys.NewDefaultKeyManager()
	if err != nil {
		t.Fatalf("keys init: %v", err)
	}
	h := httpapi.Handlers{KM: km}

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
	if got.Keys[0].KID != km.Active().KID {
		t.Fatalf("expected active kid %s got %s", km.Active().KID, got.Keys[0].KID)
	}
	if got.Keys[0].KID == km.Expired().KID {
		t.Fatalf("expired kid should not be served")
	}
}

func TestJWKS_WrongMethod405(t *testing.T) {
	km, _ := keys.NewDefaultKeyManager()
	h := httpapi.Handlers{KM: km}

	req := httptest.NewRequest(http.MethodPost, "/jwks", nil)
	rr := httptest.NewRecorder()
	h.JWKS(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 got %d", rr.Code)
	}
}

func TestAuth_IssuesValidUnexpiredJWT(t *testing.T) {
	km, _ := keys.NewDefaultKeyManager()
	h := httpapi.Handlers{KM: km}

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

	parsed, err := jwt.Parse(raw, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			t.Fatalf("unexpected method: %v", token.Header["alg"])
		}
		kid, _ := token.Header["kid"].(string)
		if kid != km.Active().KID {
			t.Fatalf("expected kid %s got %s", km.Active().KID, kid)
		}
		return &km.Active().Priv.PublicKey, nil
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
	km, _ := keys.NewDefaultKeyManager()
	h := httpapi.Handlers{KM: km}

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

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsed, err := parser.Parse(raw, func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)
		if kid != km.Expired().KID {
			t.Fatalf("expected expired kid %s got %s", km.Expired().KID, kid)
		}
		return &km.Expired().Priv.PublicKey, nil
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
	km, _ := keys.NewDefaultKeyManager()
	h := httpapi.Handlers{KM: km}

	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	rr := httptest.NewRecorder()
	h.Auth(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 got %d", rr.Code)
	}
}