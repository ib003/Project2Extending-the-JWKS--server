package jwks_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"

	"jwks-server/internal/jwks"
)

func TestMarshalJWKS_HasRequiredFields(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	j := jwks.BuildJWKS([]struct {
		KID string
		Pub *rsa.PublicKey
	}{
		{KID: "kid-123", Pub: &priv.PublicKey},
	})

	out, err := jwks.MarshalJWKS(j)
	if err != nil {
		t.Fatalf("MarshalJWKS: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	keysAny, ok := parsed["keys"].([]any)
	if !ok || len(keysAny) != 1 {
		t.Fatalf("expected keys array of len 1")
	}

	keyObj, ok := keysAny[0].(map[string]any)
	if !ok {
		t.Fatalf("expected first key to be an object")
	}

	for _, field := range []string{"kty", "alg", "use", "kid", "n", "e"} {
		if _, ok := keyObj[field]; !ok {
			t.Fatalf("missing field %q", field)
		}
	}
}