package memory

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"yam/pkg/store"

	"golang.org/x/crypto/bcrypt"
)

type Store struct {
	mu      sync.RWMutex
	clients map[string]*store.Client
}

func NewStore() *Store {
	return &Store{
		clients: make(map[string]*store.Client),
	}
}

func (s *Store) Register(id string, clientType store.ClientType, secret string, redirectURIs, grantTypes, scopes []string) (*store.Client, error) {
	if err := validateRedirectUris(redirectURIs); err != nil {
		return nil, err
	}

	// OAuth 2.1 defines client types by credential possession: a client
	// holding a secret is confidential by definition (draft-15 §2.1).
	if clientType == store.Public && secret != "" {
		return nil, fmt.Errorf("public client %s must not have a secret", id)
	}

	hashedSecret := ""
	if clientType == store.Confidential {
		hashed, err := bcrypt.GenerateFromPassword([]byte(secret), 12)
		if err != nil {
			return nil, fmt.Errorf("failed to hash password: %w", err)
		}
		hashedSecret = string(hashed)
	}

	client := &store.Client{
		ID:           id,
		ClientType:   clientType,
		Secret:       hashedSecret,
		RedirectURIs: redirectURIs,
		GrantTypes:   grantTypes,
		Scopes:       scopes,
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[id] = client

	return client, nil
}

func validateRedirectUris(redirectUris []string) error {
	for _, uri := range redirectUris {
		if err := isValidRedirectUrl(uri); err != nil {
			return fmt.Errorf("invalid redirect uri %s: %w", uri, err)
		}
	}
	return nil
}

func isValidRedirectUrl(raw string) error {
	uri, err := url.Parse(raw)
	if err != nil {
		return err
	}

	if !uri.IsAbs() {
		return fmt.Errorf("not an absolute uri")
	}

	if uri.User != nil {
		return fmt.Errorf("uri must not have useinfo")
	}

	if !hasValidAuthority(uri) {
		return fmt.Errorf("uri authority is invalid")
	}

	if uri.Fragment != "" || strings.Contains(raw, "#") {
		return fmt.Errorf("uri must not contain a fragment")
	}

	if hasUnsafePathSegments(uri.Path) {
		return fmt.Errorf("uri path must not contain . or .. or empty segments")
	}

	if strings.ContainsRune(raw, '*') {
		return fmt.Errorf("uri must not contain a wildcard")
	}

	return nil
}

func hasValidAuthority(uri *url.URL) bool {
	switch uri.Scheme {
	case "https":
		return uri.Hostname() != ""
	case "http":
		ip := net.ParseIP(uri.Hostname())
		return ip != nil && ip.IsLoopback()
	default:
		return uri.Opaque == ""
	}
}

func hasUnsafePathSegments(path string) bool {
	segments := strings.Split(path, "/")
	for i, seg := range segments {
		switch {
		case seg == "." || seg == "..":
			return true
		case seg == "" && i > 0 && i < len(segments)-1:
			return true
		}
	}
	return false
}

func (s *Store) GetClient(id string) (*store.Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	client, ok := s.clients[id]
	if !ok {
		return nil, fmt.Errorf("client %s not found", id)
	}

	return client, nil
}

func (s *Store) Authenticate(id, secret string) (*store.Client, error) {
	client, err := s.GetClient(id)
	if err != nil {
		return nil, err
	}

	// Not an OAuth spec requirement, but Public clients have no secrets and having one here is suspicious.
	if client.ClientType == store.Public && secret != "" {
		return nil, fmt.Errorf("invalid credentials for client %s", id)
	}

	if client.ClientType == store.Public {
		return client, nil
	}

	if err := bcrypt.CompareHashAndPassword([]byte(client.Secret), []byte(secret)); err != nil {
		return nil, fmt.Errorf("invalid credentials for client %s", id)
	}

	return client, nil
}
