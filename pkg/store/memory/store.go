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
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(secret), 12)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	for _, uri := range redirectURIs {
		if err := isValidRedirectUrl(uri); err != nil {
			return nil, fmt.Errorf("invalid redirect uri %s: %w", uri, err)
		}
	}
	client := &store.Client{
		ID:           id,
		ClientType:   clientType,
		Secret:       string(hashedPassword),
		RedirectURIs: redirectURIs,
		GrantTypes:   grantTypes,
		Scopes:       scopes,
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.clients[id] = client
	return client, nil
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

	ok := false
	switch uri.Scheme {
	case "https":
		ok = uri.Hostname() != ""
	case "http":
		ip := net.ParseIP(uri.Hostname())
		ok = ip != nil && ip.IsLoopback()
	default:
		ok = uri.Opaque == ""
	}

	if !ok {
		return fmt.Errorf("uri authority is invalid")
	}

	if uri.Fragment != "" || strings.Contains(raw, "#") {
		return fmt.Errorf("uri must not contain a fragment")
	}

	if strings.ContainsRune(raw, '*') {
		return fmt.Errorf("uri must not contain a wildcard")
	}

	return nil
}

func (s *Store) GetClient(id string) (*store.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	client, ok := s.clients[id]
	if !ok {
		return nil, fmt.Errorf("client %s not founa", id)
	}

	return client, nil
}

func (s *Store) Authenticate(id, secret string) (*store.Client, error) {
	client, err := s.GetClient(id)
	if err != nil {
		return nil, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(client.Secret), []byte(secret)); err != nil {
		return nil, fmt.Errorf("invalid credentials for client %s", id)
	}

	return client, nil
}
