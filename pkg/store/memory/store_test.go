package memory

import (
	"testing"
	"yam/pkg/store"

	"github.com/stretchr/testify/require"
)

func TestStore_Register_RedirectURI(t *testing.T) {
	tests := []struct {
		name    string
		uri     string
		wantErr bool
	}{
		// absolute vs relative
		{name: "relative path is rejected", uri: "/callback", wantErr: true},
		{name: "scheme-relative is rejected", uri: "//example.com/callback", wantErr: true},
		{name: "bare host without scheme is rejected", uri: "example.com/callback", wantErr: true},

		// https
		{name: "https with host is valid", uri: "https://example.com/callback", wantErr: false},
		{name: "https with port is valid", uri: "https://example.com:8443/callback", wantErr: false},
		{name: "https with query is valid", uri: "https://example.com/callback?foo=bar", wantErr: false},
		{name: "https with empty host is rejected", uri: "https:///callback", wantErr: true},

		// http loopback
		{name: "http loopback IPv4 is valid", uri: "http://127.0.0.1:8080/callback", wantErr: false},
		{name: "http loopback IPv4 range is valid", uri: "http://127.0.0.2:8080/callback", wantErr: false},
		{name: "http loopback IPv6 is valid", uri: "http://[::1]:8080/callback", wantErr: false},
		{name: "http IPv4-mapped IPv6 loopback is valid", uri: "http://[::ffff:127.0.0.1]:8080/callback", wantErr: false},
		{name: "http localhost hostname is rejected", uri: "http://localhost:8080/callback", wantErr: true},
		{name: "http non-loopback host is rejected", uri: "http://example.com/callback", wantErr: true},
		{name: "http non-loopback IP is rejected", uri: "http://192.168.1.5:8080/callback", wantErr: true},

		// private-use / custom schemes
		{name: "custom scheme with authority is valid", uri: "myapp://jopa/callback", wantErr: false},
		{name: "reverse-dns scheme without authority is valid", uri: "com.example.app:/oauth2/callback", wantErr: false},
		{name: "custom scheme opaque form is rejected", uri: "com.example.app:callback", wantErr: true},
		{name: "mailto opaque form is rejected", uri: "mailto:user@example.com", wantErr: true},

		// fragment
		{name: "https with fragment is rejected", uri: "https://example.com/callback#frag", wantErr: true},
		{name: "https with empty trailing fragment is rejected", uri: "https://example.com/callback#", wantErr: true},
		{name: "custom scheme with fragment is rejected", uri: "myapp://jopa/callback#frag", wantErr: true},

		// userinfo
		{name: "https with userinfo is rejected", uri: "https://user:pass@example.com/callback", wantErr: true},
		{name: "custom scheme with userinfo is rejected", uri: "myapp://user@jopa/callback", wantErr: true},

		// malformed
		{name: "malformed uri is rejected", uri: "http://[::1/callback", wantErr: true},

		// wildcards
		{name: "wildcard subdomain host is rejected", uri: "https://*.example.com/callback", wantErr: true},
		{name: "wildcard-only host is rejected", uri: "https://*/callback", wantErr: true},
		{name: "wildcard trailing path segment is rejected", uri: "https://example.com/callback/*", wantErr: true},
		{name: "wildcard mid path segment is rejected", uri: "https://example.com/*/callback", wantErr: true},
		{name: "wildcard in query is rejected", uri: "https://example.com/callback?next=*", wantErr: true},
		{name: "custom scheme wildcard host is rejected", uri: "myapp://*.jopa/callback", wantErr: true},
		{name: "loopback with wildcard path is rejected", uri: "http://127.0.0.1:8080/*", wantErr: true},

		// dot-segments
		{name: "single dot path segment is rejected", uri: "https://example.com/./callback", wantErr: true},
		{name: "double dot path segment is rejected", uri: "https://example.com/../callback", wantErr: true},

		// empty segments
		{name: "double slash in path is rejected", uri: "https://example.com/callback//x", wantErr: true},
		{name: "trailing slash is accepted", uri: "https://example.com/callback/", wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewStore()
			_, err := s.Register("test-client", store.Confidential, "tomatos are berries", []string{tt.uri}, []string{"authorization_code"}, []string{"read"})

			if tt.wantErr {
				require.Error(t, err, "uri %q should have been rejected", tt.uri)
			} else {
				require.NoError(t, err, "uri %q should have been accepted", tt.uri)
			}
		})
	}
}

func TestStore_Register_ClientTypeSecrets(t *testing.T) {
	redirectURIs := []string{"https://example.com/callback"}
	grantTypes := []string{"authorization_code"}
	scopes := []string{"read"}

	t.Run("public client with a secret is rejected", func(t *testing.T) {
		s := NewStore()
		_, err := s.Register("test-client", store.Public, "tomatos are berries", redirectURIs, grantTypes, scopes)
		require.Error(t, err)

		_, err = s.GetClient("test-client")
		require.Error(t, err, "client should not have been persisted")
	})

	t.Run("public client without a secret is accepted and stores no secret", func(t *testing.T) {
		s := NewStore()
		client, err := s.Register("test-client", store.Public, "", redirectURIs, grantTypes, scopes)
		require.NoError(t, err)
		require.Empty(t, client.Secret, "public client should not have a stored secret")
	})

	t.Run("confidential client with a secret is accepted", func(t *testing.T) {
		s := NewStore()
		client, err := s.Register("test-client", store.Confidential, "tomatos are berries", redirectURIs, grantTypes, scopes)
		require.NoError(t, err)
		require.NotEmpty(t, client.Secret)
	})
}

func TestStore_Register_RedirectURIs_OneInvalidFailsWholeRegistration(t *testing.T) {
	s := NewStore()

	redirectURIs := []string{
		"https://example.com/callback",
		"https://example.com/callback#frag", // invalid: has fragment
	}

	_, err := s.Register("test-client", store.Confidential, "tomatos are berries", redirectURIs, []string{"authorization_code"}, []string{"read"})
	require.Error(t, err)

	_, err = s.GetClient("test-client")
	require.Error(t, err, "client should not have been persisted when one redirect URI is invalid")
}

func TestStore_Authenticate(t *testing.T) {
	s := NewStore()

	id := "test-client"
	secret := "tomatos are berries"
	redirectURIs := []string{"https://example.com/callback"}
	grantTypes := []string{"authorization_code"}
	scopes := []string{"read", "write"}

	_, err := s.Register(id, store.Confidential, secret, redirectURIs, grantTypes, scopes)
	require.NoError(t, err)

	client, err := s.Authenticate(id, secret)
	require.NoError(t, err)
	require.Equal(t, id, client.ID)

	_, err = s.Authenticate(id, "wrong secret")
	require.Error(t, err)

	_, err = s.Authenticate("unknown-client", secret)
	require.Error(t, err)
}

func TestStore_Authenticate_ClientTypes(t *testing.T) {
	redirectURIs := []string{"https://example.com/callback"}
	grantTypes := []string{"authorization_code"}
	scopes := []string{"read"}

	tests := []struct {
		name           string
		clientType     store.ClientType
		registerSecret string
		authSecret     string
		wantErr        bool
	}{
		{name: "confidential client with correct secret succeeds", clientType: store.Confidential, registerSecret: "tomatos are berries", authSecret: "tomatos are berries", wantErr: false},
		{name: "confidential client with wrong secret fails", clientType: store.Confidential, registerSecret: "tomatos are berries", authSecret: "wrong secret", wantErr: true},
		{name: "confidential client with empty secret fails", clientType: store.Confidential, registerSecret: "tomatos are berries", authSecret: "", wantErr: true},
		{name: "public client with empty secret succeeds", clientType: store.Public, registerSecret: "", authSecret: "", wantErr: false},
		{name: "public client with a secret fails", clientType: store.Public, registerSecret: "", authSecret: "some-secret", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewStore()
			id := "test-client"

			_, err := s.Register(id, tt.clientType, tt.registerSecret, redirectURIs, grantTypes, scopes)
			require.NoError(t, err)

			client, err := s.Authenticate(id, tt.authSecret)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, id, client.ID)
			}
		})
	}
}
