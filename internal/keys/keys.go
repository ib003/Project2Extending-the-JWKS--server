// Package keys provides RSA key generation and PEM serialization helpers.
package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// GenerateRSAKey creates a new 2048-bit RSA private key.
func GenerateRSAKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// PrivateKeyToPEM converts an RSA private key to PKCS1 PEM bytes.
func PrivateKeyToPEM(priv *rsa.PrivateKey) []byte {
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	}
	return pem.EncodeToMemory(block)
}

// PEMToPrivateKey converts PKCS1 PEM bytes back into an RSA private key.
func PEMToPrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return priv, nil
}