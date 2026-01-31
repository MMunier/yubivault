package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"sync"
	"time"
)

const (
	// SessionTokenLength is the number of random bytes in a session token
	SessionTokenLength = 32 // 256 bits

	// DefaultSessionTTL is the default session duration
	DefaultSessionTTL = 15 * time.Minute
)

// Session represents an authenticated session
type Session struct {
	Token        string    `json:"token"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	CredentialID []byte    `json:"credential_id"`
}

// SessionStore manages active sessions
type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

// NewSessionStore creates a new session store
func NewSessionStore() *SessionStore {
	return &SessionStore{
		sessions: make(map[string]*Session),
	}
}

// Create generates a new session for the given credential
func (s *SessionStore) Create(credentialID []byte) (*Session, error) {
	tokenBytes := make([]byte, SessionTokenLength)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, err
	}

	token := base64.URLEncoding.EncodeToString(tokenBytes)
	now := time.Now()
	session := &Session{
		Token:        token,
		CreatedAt:    now,
		ExpiresAt:    now.Add(DefaultSessionTTL),
		CredentialID: credentialID,
	}

	s.mu.Lock()
	s.sessions[token] = session
	s.mu.Unlock()

	return session, nil
}

// Validate checks if a token is valid and returns the session
// Uses constant-time comparison to prevent timing attacks
func (s *SessionStore) Validate(token string) (*Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Use constant-time comparison to prevent timing attacks
	tokenBytes := []byte(token)
	for storedToken, session := range s.sessions {
		if subtle.ConstantTimeCompare(tokenBytes, []byte(storedToken)) == 1 {
			if time.Now().After(session.ExpiresAt) {
				// Don't revoke here to avoid lock upgrade; cleanup will handle it
				return nil, false
			}
			return session, true
		}
	}

	return nil, false
}

// Revoke removes a session
func (s *SessionStore) Revoke(token string) {
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
}

// Cleanup removes all expired sessions
func (s *SessionStore) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for token, session := range s.sessions {
		if now.After(session.ExpiresAt) {
			delete(s.sessions, token)
		}
	}
}
