package keys_test

import (
	"testing"

	"jwks-server/internal/keys"
)

func TestGenerateRSAKey(t *testing.T) {
	priv, err := keys.GenerateRSAKey()
	if err != nil {
		t.Fatalf("GenerateRSAKey: %v", err)
	}
	if priv == nil {
		t.Fatal("expected private key, got nil")
	}
}

func TestPrivateKeyPEMRoundTrip(t *testing.T) {
	priv, err := keys.GenerateRSAKey()
	if err != nil {
		t.Fatalf("GenerateRSAKey: %v", err)
	}

	pemBytes := keys.PrivateKeyToPEM(priv)
	if len(pemBytes) == 0 {
		t.Fatal("expected PEM bytes, got empty output")
	}

	parsed, err := keys.PEMToPrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("PEMToPrivateKey: %v", err)
	}
	if parsed == nil {
	t.Fatal("expected parsed private key, got nil")
	return
}

if parsed.N == nil {
	t.Fatal("parsed key has nil modulus")
}

if priv.N.Cmp(parsed.N) != 0 {
	t.Fatal("expected parsed key to match original key")
}
}

func TestPEMToPrivateKey_InvalidPEM(t *testing.T) {
	_, err := keys.PEMToPrivateKey([]byte("not a pem key"))
	if err == nil {
		t.Fatal("expected error for invalid PEM input")
	}
}