// Package keys manages RSA key pairs, key IDs (kid), and expiry timestamps.
package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"time"

	"github.com/google/uuid"
)

// KeyRecord stores an RSA private key with its kid and expiry time.
type KeyRecord struct {
	KID       string
	Priv      *rsa.PrivateKey
	ExpiresAt time.Time
}

// KeyManager stores an active and an expired key for issuing JWTs and serving JWKS.
type KeyManager struct {
	active  KeyRecord
	expired KeyRecord
}

// NewDefaultKeyManager creates:
// - one active key that expires in the future
// - one expired key with expiry in the past
func NewDefaultKeyManager() (*KeyManager, error) {
	activePriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	expiredPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()

	km := &KeyManager{
		active: KeyRecord{
			KID:       uuid.NewString(),
			Priv:      activePriv,
			ExpiresAt: now.Add(24 * time.Hour),
		},
		expired: KeyRecord{
			KID:       uuid.NewString(),
			Priv:      expiredPriv,
			ExpiresAt: now.Add(-24 * time.Hour),
		},
	}

	if !km.expired.ExpiresAt.Before(now) {
		return nil, errors.New("expired key is not expired")
	}
	if !km.active.ExpiresAt.After(now) {
		return nil, errors.New("active key is not active")
	}

	return km, nil
}

// Active returns the current active key record.
func (km *KeyManager) Active() KeyRecord { return km.active }

// Expired returns the expired key record.
func (km *KeyManager) Expired() KeyRecord { return km.expired }

// IsExpired reports whether a key is expired at time t.
func (km *KeyManager) IsExpired(k KeyRecord, t time.Time) bool {
	return !k.ExpiresAt.After(t)
}

// SetActiveExpiryForTest allows tests to adjust the active key expiry.
// Not used by production code.
func (km *KeyManager) SetActiveExpiryForTest(t time.Time) {
	km.active.ExpiresAt = t
}