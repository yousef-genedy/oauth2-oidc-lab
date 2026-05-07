package session

import (
	"refresh-token-flow/internal/models"
	"sync"
	"time"
)

type Store struct {
	mu      sync.RWMutex
	pending map[string]models.PendingAuthorization
	tokens  *models.TokenSet
}

func NewStore() *Store {
	return &Store{
		pending: make(map[string]models.PendingAuthorization),
	}
}

func (s *Store) SavePendingAuthorization(state, nonce, verifier string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.pending[state] = models.PendingAuthorization{
		State:        state,
		Nonce:        nonce,
		CodeVerifier: verifier,
		CreatedAt:    time.Now().UTC(),
	}
}

func (s *Store) ConsumePendingAuthorization(state string) (models.PendingAuthorization, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.pending[state]
	if ok {
		delete(s.pending, state)
	}
	return entry, ok
}

func (s *Store) SaveTokenSet(tokens models.TokenSet) {
	s.mu.Lock()
	defer s.mu.Unlock()

	copy := tokens
	s.tokens = &copy
}

func (s *Store) CurrentTokenSet() (models.TokenSet, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.tokens == nil {
		return models.TokenSet{}, false
	}

	copy := *s.tokens
	return copy, true
}
