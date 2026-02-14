package tokens_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"jwks-server/internal/tokens"

	"github.com/golang-jwt/jwt/v5"
)

func TestIssueJWT_SetsKidAndSigns(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	tokenStr, err := tokens.IssueJWT(tokens.IssueInput{
		KID:      "kid-abc",
		PrivKey:  priv,
		Expires:  time.Now().UTC().Add(2 * time.Minute),
		Subject:  "user1",
		Issuer:   "issuer1",
		Audience: "aud1",
	})
	if err != nil {
		t.Fatalf("IssueJWT: %v", err)
	}

	parsed, err := jwt.Parse(tokenStr, func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)
		if kid != "kid-abc" {
			t.Fatalf("expected kid kid-abc got %v", token.Header["kid"])
		}
		return &priv.PublicKey, nil
	})
	if err != nil || !parsed.Valid {
		t.Fatalf("expected valid token; err=%v", err)
	}
}