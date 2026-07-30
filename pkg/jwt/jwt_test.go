package jwt

import (
	"crypto/ed25519"
	"encoding/base64"
	"maps"
	"strings"
	"testing"
	"time"

	v5 "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	rfc8037KeyId     = "Ed25519 key pair from RFC 8037 Appendix A.1"
	rfc8037Seed      = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
	rfc8037PublicKey = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
)

const (
	testIssuer   = "https://issuer.yam.test"
	testAudience = "https://resource.yam.test"
)

func newTestJwt(t *testing.T) *Jwt {
	t.Helper()
	seed, err := base64.RawURLEncoding.DecodeString(rfc8037Seed)
	require.NoError(t, err)
	pub, err := base64.RawURLEncoding.DecodeString(rfc8037PublicKey)
	require.NoError(t, err)

	return &Jwt{
		key: &Key{
			id:         rfc8037KeyId,
			privateKey: ed25519.NewKeyFromSeed(seed),
			publicKey:  pub,
		},
	}
}

func TestJwt_SignVerify_RoundTrip(t *testing.T) {
	j := newTestJwt(t)
	claims := map[string]any{
		"sub": "user-123",
		"iss": testIssuer,
		"aud": testAudience,
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	token, err := j.Sign(claims)
	require.NoError(t, err)

	got, err := j.Verify(token)
	require.NoError(t, err)

	assert.Equal(t, claims["sub"], got["sub"])
}

func TestJwt_Sign_RejectsMissingMandatoryClaims(t *testing.T) {
	base := map[string]any{
		"sub": "user-123",
		"iss": testIssuer,
		"aud": testAudience,
		"exp": time.Now().Add(time.Hour).Unix(),
	}

	cases := []struct {
		name    string
		missing []string
	}{
		{"missing exp", []string{"exp"}},
		{"missing aud", []string{"aud"}},
		{"missing iss", []string{"iss"}},
		{"missing exp and aud", []string{"exp", "aud"}},
		{"missing exp and iss", []string{"exp", "iss"}},
		{"missing aud and iss", []string{"aud", "iss"}},
		{"missing all mandatory claims", []string{"exp", "aud", "iss"}},
	}

	j := newTestJwt(t)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := maps.Clone(base)
			for _, k := range tc.missing {
				delete(claims, k)
			}

			_, err := j.Sign(claims)
			assert.ErrorIs(t, err, v5.ErrTokenRequiredClaimMissing)
		})
	}
}

func TestJwt_Verify_RejectsTokenMissingMandatoryClaims(t *testing.T) {
	j := newTestJwt(t)

	claims := v5.MapClaims{
		"sub": "user-123",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	token := v5.NewWithClaims(v5.SigningMethodEdDSA, claims)
	token.Header[KidHeader] = j.key.id
	signed, err := token.SignedString(j.key.privateKey)
	require.NoError(t, err)

	_, err = j.Verify(signed)
	assert.ErrorIs(t, err, v5.ErrTokenRequiredClaimMissing)
}

func TestJwt_Verify_RejectsAlgNoneToken(t *testing.T) {
	j := newTestJwt(t)

	claims := v5.MapClaims{
		"sub": "user-123",
		"iss": testIssuer,
		"aud": testAudience,
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	token := v5.NewWithClaims(v5.SigningMethodNone, claims)
	signed, err := token.SignedString(v5.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)

	_, err = j.Verify(signed)
	assert.ErrorIs(t, err, v5.ErrTokenUnverifiable)
}

func TestJwt_Verify_RejectsHMACConfusionToken(t *testing.T) {
	j := newTestJwt(t)

	claims := v5.MapClaims{
		"sub": "user-123",
		"iss": testIssuer,
		"aud": testAudience,
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	token := v5.NewWithClaims(v5.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(j.key.publicKey))
	require.NoError(t, err)

	_, err = j.Verify(signed)
	assert.ErrorIs(t, err, v5.ErrTokenUnverifiable)
}

func TestJwt_Verify_RejectsMismatchedKeyID(t *testing.T) {
	j := newTestJwt(t)

	claims := v5.MapClaims{
		"sub": "user-123",
		"iss": testIssuer,
		"aud": testAudience,
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	token := v5.NewWithClaims(v5.SigningMethodEdDSA, claims)
	token.Header[KidHeader] = "some-other-key"
	signed, err := token.SignedString(j.key.privateKey)
	require.NoError(t, err)

	_, err = j.Verify(signed)
	assert.ErrorIs(t, err, v5.ErrTokenUnverifiable)
}

func TestJwt_Verify_RejectsExpiredToken(t *testing.T) {
	j := newTestJwt(t)
	claims := map[string]any{
		"sub": "user-123",
		"iss": testIssuer,
		"aud": testAudience,
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
		"iss": testIssuer,
		"aud": testAudience,
		"exp": time.Now().Add(2 * time.Hour).Unix(),
		"nbf": time.Now().Add(time.Hour).Unix(),
	}

	token, err := j.Sign(claims)
	require.NoError(t, err)

	_, err = j.Verify(token)
	assert.ErrorIs(t, err, v5.ErrTokenNotValidYet)
}

func TestJwt_Verify_RejectsTamperedSignature(t *testing.T) {
	j := newTestJwt(t)

	token, err := j.Sign(map[string]any{
		"sub": "user-123",
		"iss": testIssuer,
		"aud": testAudience,
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	require.NoError(t, err)

	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)

	bogusSig := strings.Repeat("A", len(parts[2]))
	tampered := strings.Join([]string{parts[0], parts[1], bogusSig}, ".")

	_, err = j.Verify(tampered)
	assert.ErrorIs(t, err, v5.ErrTokenSignatureInvalid)
}
