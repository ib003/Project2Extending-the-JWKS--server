package httpapi

import (
	"crypto/rsa"
	"net/http"
	"strings"
	"time"

	"jwks-server/internal/jwks"
	"jwks-server/internal/keys"
	"jwks-server/internal/tokens"
)

// Handlers implements the HTTP endpoint handlers for the JWKS server.
type Handlers struct {
	KM *keys.KeyManager
}

// JWKS serves a JWKS document containing only unexpired public keys.
func (h Handlers) JWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	now := time.Now().UTC()
	active := h.KM.Active()

	if !h.KM.IsExpired(active, now) {
		j := jwks.BuildJWKS([]struct {
			KID string
			Pub *rsa.PublicKey
		}{
			{KID: active.KID, Pub: &active.Priv.PublicKey},
		})

		out, err := jwks.MarshalJWKS(j)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(out)
		return
	}

	// If active key is expired (shouldn't happen normally), return an empty JWKS.
	out, _ := jwks.MarshalJWKS(jwks.JWKS{Keys: []jwks.JWK{}})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}

// Auth issues a signed JWT. If the "expired" query parameter is present,
// it issues a JWT signed with an expired key and an expired exp claim.
func (h Handlers) Auth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	expiredParam := r.URL.Query().Get("expired")
	useExpired := expiredParam != "" && strings.ToLower(expiredParam) != "false" && expiredParam != "0"

	now := time.Now().UTC()

	var rec keys.KeyRecord
	var jwtExp time.Time

	if useExpired {
		rec = h.KM.Expired()
		jwtExp = now.Add(-5 * time.Minute)
	} else {
		rec = h.KM.Active()
		jwtExp = now.Add(5 * time.Minute)
	}

	tokenStr, err := tokens.IssueJWT(tokens.IssueInput{
		KID:      rec.KID,
		PrivKey:  rec.Priv,
		Expires:  jwtExp,
		Subject:  "mock-user",
		Issuer:   "jwks-server",
		Audience: "test-client",
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(tokenStr))
}