package jwt

import (
	"crypto/ed25519"
	"fmt"

	v5 "github.com/golang-jwt/jwt/v5"
)

type Jwt struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

func (j *Jwt) Sign(claims map[string]any) (string, error) {
	token := v5.NewWithClaims(v5.SigningMethodEdDSA, v5.MapClaims(claims))
	return token.SignedString(j.privateKey)
}

func (j *Jwt) Verify(token string) (map[string]any, error) {
	claims := v5.MapClaims{}

	parsed, err := v5.ParseWithClaims(token, claims, func(t *v5.Token) (any, error) {
		if _, ok := t.Method.(*v5.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Method.Alg())
		}
		return j.publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	if !parsed.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}
