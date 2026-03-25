// Package httpapi provides HTTP handlers and server wiring for the JWKS service.
package httpapi

import (
	"crypto/rsa"
	"net/http"
	"strconv"
	"strings"
	"time"

	"jwks-server/internal/db"
	"jwks-server/internal/jwks"
	"jwks-server/internal/keys"
	"jwks-server/internal/tokens"
)

// Handlers implements the HTTP endpoint handlers for the JWKS server.
type Handlers struct {
	DB *db.DB
}

// JWKS serves a JWKS document containing only unexpired public keys.
func (h Handlers) JWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	records, err := h.DB.GetValidKeys()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	jwkInputs := make([]struct {
		KID string
		Pub *rsa.PublicKey
	}, 0, len(records))

	for _, rec := range records {
		priv, err := keys.PEMToPrivateKey(rec.Key)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		jwkInputs = append(jwkInputs, struct {
			KID string
			Pub *rsa.PublicKey
		}{
			KID: strconv.Itoa(rec.Kid),
			Pub: &priv.PublicKey,
		})
	}

	out, err := jwks.MarshalJWKS(jwks.BuildJWKS(jwkInputs))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

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

	var rec db.KeyRecord
	var err error
	var jwtExp time.Time

	if useExpired {
		rec, err = h.DB.GetExpiredKey()
		jwtExp = now.Add(-5 * time.Minute)
	} else {
		rec, err = h.DB.GetValidKey()
		jwtExp = now.Add(5 * time.Minute)
	}

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	priv, err := keys.PEMToPrivateKey(rec.Key)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	tokenStr, err := tokens.IssueJWT(tokens.IssueInput{
		KID:      strconv.Itoa(rec.Kid),
		PrivKey:  priv,
		Expires:  jwtExp,
		Subject:  "userABC",
		Issuer:   "jwks-server",
		Audience: "project2-client",
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(tokenStr))
}