package keys_test

import (
	"testing"
	"time"

	"jwks-server/internal/keys"
)

func TestKeyManager_ActiveAndExpiredBehavior(t *testing.T) {
	km, err := keys.NewDefaultKeyManager()
	if err != nil {
		t.Fatalf("NewDefaultKeyManager: %v", err)
	}

	now := time.Now().UTC()
	if km.IsExpired(km.Active(), now) {
		t.Fatalf("active key should not be expired")
	}
	if !km.IsExpired(km.Expired(), now) {
		t.Fatalf("expired key should be expired")
	}

	if km.Active().KID == "" || km.Expired().KID == "" {
		t.Fatalf("kids should not be empty")
	}
	if km.Active().KID == km.Expired().KID {
		t.Fatalf("kids should be unique")
	}
}