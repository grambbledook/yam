package pkce

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVerifyCodeChallenge(t *testing.T) {
	tests := []struct {
		name      string
		verifier  string
		challenge string
		method    CodeChallengeMethod
		want      bool
	}{
		{
			name:      "valid verifier and matching challenge",
			verifier:  "2fe923812b93b239477d287f8eb13f76013242286794cce21b0a12a4",
			challenge: "Ww5AmVQkEI-jSX-DDqIwUKKm5R8zx1e_vd4GpBorCFw",
			method:    CodeChallengeMethodS256,
			want:      true,
		},
		{
			name:      "empty verifier is rejected",
			verifier:  "",
			challenge: "Ww5AmVQkEI-jSX-DDqIwUKKm5R8zx1e_vd4GpBorCFw",
			method:    CodeChallengeMethodS256,
			want:      false,
		},
		{
			name:      "empty verifier and empty challenge are rejected",
			verifier:  "",
			challenge: "",
			method:    CodeChallengeMethodS256,
			want:      false,
		},
		{
			name:      "verifier below minimum 43 chars length is rejected",
			verifier:  strings.Repeat("a", 42),
			challenge: "elOGB_2quSlplZKfRRVlu7gULhhEEXMiqv0rPXawGv8",
			method:    CodeChallengeMethodS256,
			want:      false,
		},
		{
			name:      "verifier at minimum 43 chars lenth is accepted",
			verifier:  strings.Repeat("a", 43),
			challenge: "ZtNPunH49FD35FWYhT5Tv8I7vRKQJ8uxMaL0_9eHjNA",
			method:    CodeChallengeMethodS256,
			want:      true,
		},
		{
			name:      "verifier at maximum 128 chars length is accepted",
			verifier:  strings.Repeat("a", 128),
			challenge: "aDbPE7rEAOkQUHHNavRwhN-srU5eMCyUv-0k4BOvtz4",
			method:    CodeChallengeMethodS256,
			want:      true,
		},
		{
			name:      "verifier above maximum length is rejected",
			verifier:  strings.Repeat("a", 129),
			challenge: "wSywJKLlVRzKDgj86PHF4xRVXMP-9jKe6ZSj23UhZq4",
			method:    CodeChallengeMethodS256,
			want:      false,
		},
		{
			name:      "verifier with disallowed character is rejected",
			verifier:  strings.Repeat("a", 42) + "!",
			challenge: "eejtYKWJY_EVRpWyQ5uVYYEekHJHZ8_ubIlUxhzqIMA",
			method:    CodeChallengeMethodS256,
			want:      false,
		},
		{
			name:      "code challenge plain is rejected",
			verifier:  "",
			challenge: "",
			method:    CodeChallengeMethodPlain,
			want:      false,
		},
		{
			name:      "plain verifier equal to challenge is still rejected",
			verifier:  "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			challenge: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			method:    CodeChallengeMethodPlain,
			want:      false,
		},
		{
			name:      "RFC 7636 Appendix B test vector",
			verifier:  "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
			method:    CodeChallengeMethodS256,
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := VerifyCodeChallenge(tt.verifier, tt.challenge, tt.method)
			assert.Equal(t, tt.want, result, fmt.Sprintf("VerifyChallenge(%s, %s) result = %v, want %v", tt.verifier, tt.challenge, result, tt.want))
		})
	}
}
