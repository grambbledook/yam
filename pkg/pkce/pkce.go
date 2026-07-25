package pkce

import (
	"crypto"
	"encoding/base64"
)

type CodeChallengeMethod string

const (
	CodeChallengeMethodPlain CodeChallengeMethod = "plain"
	CodeChallengeMethodS256  CodeChallengeMethod = "s256"
)

func VerifyCodeChallenge(verifier, challenge string, method CodeChallengeMethod) bool {
	if challenge == "" || method != CodeChallengeMethodS256 {
		return false
	}

	lenght := len(verifier)
	if lenght < 43 || lenght > 128 {
		return false
	}

	for _, char := range verifier {
		switch {
		case char >= 'A' && char <= 'Z':
		case char >= 'a' && char <= 'z':
		case char >= '0' && char <= '9':
		case char == '-' || char == '.' || char == '_' || char == '~':
		default:
			return false
		}
	}

	sha := crypto.SHA256.New()
	sha.Write([]byte(verifier))
	hashed := sha.Sum(nil)

	result := base64.RawURLEncoding.EncodeToString(hashed)
	return result == challenge
}
