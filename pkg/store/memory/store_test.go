package memory

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestStore_Register(t *testing.T) {
	s := NewStore()

	id := "test-client"
	secret := "tomatos are berries"
	redirectURIs := []string{"https://example.com/callback"}
	grantTypes := []string{"authorization_code"}
	scopes := []string{"read", "write"}

	client, err := s.Register(id, secret, redirectURIs, grantTypes, scopes)
	require.NoError(t, err, "Register should not return an error")

	require.Equal(t, id, client.ID)
	require.NotEqual(t, secret, client.Secret, "secret should be hashed, not stored in plaintext")

	err = bcrypt.CompareHashAndPassword([]byte(client.Secret), []byte(secret))
	require.NoError(t, err)

	_, err = s.GetClient(id)
	require.NoError(t, err)

}
