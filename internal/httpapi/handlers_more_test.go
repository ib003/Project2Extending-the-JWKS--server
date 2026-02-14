package httpapi_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"jwks-server/internal/httpapi"
	"jwks-server/internal/keys"
)

func TestJWKS_ReturnsEmptyWhenActiveExpired(t *testing.T) {
	km, err := keys.NewDefaultKeyManager()
	if err != nil {
		t.Fatalf("keys init: %v", err)
	}

	km.SetActiveExpiryForTest(time.Now().UTC().Add(-1 * time.Hour))

	h := httpapi.Handlers{KM: km}

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
	if strings.Contains(body, `"kid"`) {
		t.Fatalf("expected empty JWKS when active expired, got: %s", body)
	}
}

func TestAuth_ExpiredFalseAndZeroAreTreatedAsNotExpired(t *testing.T) {
	km, _ := keys.NewDefaultKeyManager()
	h := httpapi.Handlers{KM: km}

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
	km, _ := keys.NewDefaultKeyManager()
	h := httpapi.Handlers{KM: km}

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