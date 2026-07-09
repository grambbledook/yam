package memory

import (
	"fmt"
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

func (s *Store) Register(id, secret string, redirectURId, grantTypes, scopes []string) (*store.Client, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(secret), 12)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	client := &store.Client{
		ID:           id,
		Secret:       string(hashedPassword),
		RedirectURIs: redirectURId,
		GrantTypes:   grantTypes,
		Scopes:       scopes,
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.clients[id] = client
	return client, nil
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
