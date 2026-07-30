package jwt

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	v5 "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Ed25519 key pair from RFC 8037 Appendix A.1.
const (
	rfc8037Seed      = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
	rfc8037PublicKey = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
)

func newTestJwt(t *testing.T) *Jwt {
	t.Helper()
	seed, err := base64.RawURLEncoding.DecodeString(rfc8037Seed)
	require.NoError(t, err)
	pub, err := base64.RawURLEncoding.DecodeString(rfc8037PublicKey)
	require.NoError(t, err)

	return &Jwt{
		privateKey: ed25519.NewKeyFromSeed(seed),
		publicKey:  pub,
	}
}

func TestJwt_SignVerify_RoundTrip(t *testing.T) {
	j := newTestJwt(t)
	claims := map[string]any{"sub": "user-123"}

	token, err := j.Sign(claims)
	require.NoError(t, err)

	got, err := j.Verify(token)
	require.NoError(t, err)

	assert.Equal(t, claims["sub"], got["sub"])
}

func TestJwt_Verify_RejectsExpiredToken(t *testing.T) {
	j := newTestJwt(t)
	claims := map[string]any{
		"sub": "user-123",
		"exp": time.Now().Add(-time.Hour).Unix(),
	}

	token, err := j.Sign(claims)
	require.NoError(t, err)

	_, err = j.Verify(token)
	assert.ErrorIs(t, err, v5.ErrTokenExpired)
}

func TestJwt_Verify_RejectsNotYetValidToken(t *testing.T) {
	j := newTestJwt(t)
	claims := map[string]any{
		"sub": "user-123",
		"nbf": time.Now().Add(time.Hour).Unix(),
	}

	token, err := j.Sign(claims)
	require.NoError(t, err)

	_, err = j.Verify(token)
	assert.ErrorIs(t, err, v5.ErrTokenNotValidYet)
}

func TestJwt_Verify_RejectsTamperedSignature(t *testing.T) {
	j := newTestJwt(t)

	token, err := j.Sign(map[string]any{"sub": "user-123"})
	require.NoError(t, err)

	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)

	bogusSig := strings.Repeat("A", len(parts[2]))
	tampered := strings.Join([]string{parts[0], parts[1], bogusSig}, ".")

	_, err = j.Verify(tampered)
	assert.ErrorIs(t, err, v5.ErrTokenSignatureInvalid)
}
