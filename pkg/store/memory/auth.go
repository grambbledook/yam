package memory

import (
	"fmt"
	"sync"
)

type Versioned[T any] struct {
	value   T
	version uint
}

type AuthCodeRecord struct {
	code                string
	clientId            string
	redirectUri         string
	scope               []string
	codeChallenge       string
	codeChallengeMethod string
	expiresAt           uint32
	used                bool
}

type TokenRecord struct {
	jti       string
	clientId  string
	subject   string
	scope     []string
	expidedAt uint32
	revoked   bool
}

type GenericMemStore[T any] struct {
	mutex   sync.RWMutex
	storage map[string]Versioned[T]
}

func (s *GenericMemStore[T]) Store(code string, record Versioned[T]) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	old := s.storage[code]
	if old.version != record.version {
		return fmt.Errorf("record version mismatch")
	}
	s.storage[code] = Versioned[T]{value: record.value, version: record.version + 1}
	return nil
}

func (s *GenericMemStore[T]) Get(code string) (Versioned[T], error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	value, ok := s.storage[code]
	if !ok {
		return Versioned[T]{}, fmt.Errorf("auth code not found")
	}
	return value, nil
}
