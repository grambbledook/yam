package jwt

import (
	"crypto/ed25519"
	"fmt"

	v5 "github.com/golang-jwt/jwt/v5"
)

const KidHeader = "kid"

type Key struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	id         string
}
type Jwt struct {
	key *Key
}

func (j *Jwt) Sign(claims map[string]any) (string, error) {
	if !enforceMandatoryClaims(claims) {
		return "", v5.ErrTokenRequiredClaimMissing
	}
	token := v5.NewWithClaims(v5.SigningMethodEdDSA, v5.MapClaims(claims))
	token.Header[KidHeader] = j.key.id
	return token.SignedString(j.key.privateKey)
}

func (j *Jwt) Verify(token string) (map[string]any, error) {
	claims := v5.MapClaims{}

	parsed, err := v5.ParseWithClaims(token, claims, func(t *v5.Token) (any, error) {
		if _, ok := t.Method.(*v5.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Method.Alg())
		}
		if t.Header[KidHeader] != j.key.id {
			return nil, fmt.Errorf("invalid key id")
		}
		return j.key.publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	if !enforceMandatoryClaims(claims) {
		return nil, v5.ErrTokenRequiredClaimMissing
	}

	if !parsed.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

func enforceMandatoryClaims(claims map[string]any) bool {
	if _, ok := claims["exp"]; !ok {
		return false
	}
	if _, ok := claims["aud"]; !ok {
		return false
	}
	if _, ok := claims["iss"]; !ok {
		return false
	}
	return true
}
