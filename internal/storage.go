package internal

import (
	"errors"
	"sync"
)

type SessionStore struct {
	mu    sync.RWMutex
	store map[uint32]*Session
}

func NewSessionStore() *SessionStore {
	return &SessionStore{store: make(map[uint32]*Session)}
}

func (s *SessionStore) Put(sess *Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store[sess.ID] = sess
}

func (s *SessionStore) Get(id uint32) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.store[id]
	if !ok {
		return nil, errors.New("session not found")
	}
	return sess, nil
}
