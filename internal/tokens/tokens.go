// Package tokens issues RS256 JWTs with a kid header for key selection.
package tokens

import (
	"crypto/rsa"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// IssueInput contains inputs needed to issue a signed JWT.
type IssueInput struct {
	KID      string
	PrivKey  *rsa.PrivateKey
	Expires  time.Time // JWT exp
	Subject  string
	Issuer   string
	Audience string
}

// IssueJWT issues an RS256 JWT with the provided claims and sets the kid header.
func IssueJWT(in IssueInput) (string, error) {
	now := time.Now().UTC()

	claims := jwt.RegisteredClaims{
		Issuer:    in.Issuer,
		Subject:   in.Subject,
		Audience:  jwt.ClaimStrings{in.Audience},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(in.Expires),
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = in.KID

	return tok.SignedString(in.PrivKey)
}