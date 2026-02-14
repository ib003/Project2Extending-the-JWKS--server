// Package jwks builds JSON Web Key Sets (JWKS) for publishing RSA public keys.
package jwks

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
)

// JWK represents a single JSON Web Key (public key parameters only).
type JWK struct {
	KTY string `json:"kty"`
	ALG string `json:"alg"`
	USE string `json:"use"`
	KID string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS represents a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

func b64urlNoPad(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func encodeBigInt(i *big.Int) string {
	return b64urlNoPad(i.Bytes())
}

func rsaPublicToJWK(kid string, pub *rsa.PublicKey) JWK {
	eBytes := big.NewInt(int64(pub.E)).Bytes()
	return JWK{
		KTY: "RSA",
		ALG: "RS256",
		USE: "sig",
		KID: kid,
		N:   encodeBigInt(pub.N),
		E:   b64urlNoPad(eBytes),
	}
}

// BuildJWKS builds a JWKS from a list of (kid, RSA public key) pairs.
func BuildJWKS(activeOnly []struct {
	KID string
	Pub *rsa.PublicKey
}) JWKS {
	keys := make([]JWK, 0, len(activeOnly))
	for _, k := range activeOnly {
		keys = append(keys, rsaPublicToJWK(k.KID, k.Pub))
	}
	return JWKS{Keys: keys}
}

// MarshalJWKS serializes a JWKS to JSON.
func MarshalJWKS(j JWKS) ([]byte, error) {
	return json.Marshal(j)
}