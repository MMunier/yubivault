package server

import (
	"sync"
	"testing"
	"time"
)

func TestNewSessionStore(t *testing.T) {
	store := NewSessionStore()
	if store == nil {
		t.Fatal("NewSessionStore returned nil")
	}
	if store.sessions == nil {
		t.Fatal("sessions map is nil")
	}
}

func TestCreatePresharedToken(t *testing.T) {
	store := NewSessionStore()

	token, err := store.CreatePresharedToken()
	if err != nil {
		t.Fatalf("CreatePresharedToken failed: %v", err)
	}

	// Token should not be empty
	if token == "" {
		t.Error("CreatePresharedToken returned empty token")
	}

	// Token should be base64 URL encoded (44 chars for 32 bytes)
	if len(token) != 44 {
		t.Errorf("Expected token length 44, got %d", len(token))
	}

	// Session should be stored
	session, valid := store.Validate(token)
	if !valid {
		t.Error("Token should be valid immediately after creation")
	}
	if session == nil {
		t.Error("Session should not be nil for valid token")
	}

	// Session should have correct token
	if session.Token != token {
		t.Errorf("Session token mismatch: got %s, want %s", session.Token, token)
	}

	// Session should effectively never expire (100 years)
	expectedExpiry := session.CreatedAt.Add(100 * 365 * 24 * time.Hour)
	if !session.ExpiresAt.Equal(expectedExpiry) {
		t.Errorf("Session expiry mismatch: got %v, want %v", session.ExpiresAt, expectedExpiry)
	}
}

func TestCreatePresharedToken_Uniqueness(t *testing.T) {
	store := NewSessionStore()
	tokens := make(map[string]bool)

	// Generate 100 tokens and verify they're all unique
	for i := 0; i < 100; i++ {
		token, err := store.CreatePresharedToken()
		if err != nil {
			t.Fatalf("CreatePresharedToken failed on iteration %d: %v", i, err)
		}
		if tokens[token] {
			t.Errorf("Duplicate token generated on iteration %d", i)
		}
		tokens[token] = true
	}
}

func TestValidate_InvalidToken(t *testing.T) {
	store := NewSessionStore()

	// Create a valid token first
	validToken, _ := store.CreatePresharedToken()
	_ = validToken

	// Test with various invalid tokens
	invalidTokens := []string{
		"",
		"invalid",
		"too-short",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // wrong length
		validToken + "x",                                // modified valid token
	}

	for _, token := range invalidTokens {
		session, valid := store.Validate(token)
		if valid {
			t.Errorf("Token %q should be invalid", token)
		}
		if session != nil {
			t.Errorf("Session should be nil for invalid token %q", token)
		}
	}
}

func TestValidate_ExpiredSession(t *testing.T) {
	store := NewSessionStore()

	// Manually create an expired session
	token := "test-expired-token"
	store.mu.Lock()
	store.sessions[token] = &Session{
		Token:     token,
		CreatedAt: time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
	}
	store.mu.Unlock()

	session, valid := store.Validate(token)
	if valid {
		t.Error("Expired token should not be valid")
	}
	if session != nil {
		t.Error("Session should be nil for expired token")
	}
}

func TestValidate_ConstantTimeComparison(t *testing.T) {
	store := NewSessionStore()

	// Create a valid token
	validToken, _ := store.CreatePresharedToken()

	// This test verifies that the timing is consistent regardless of
	// whether the token matches or not (to prevent timing attacks).
	// We can't easily test timing, but we can verify the code path works.

	// Valid token should work
	session, valid := store.Validate(validToken)
	if !valid || session == nil {
		t.Error("Valid token should be accepted")
	}

	// Invalid token with same length should fail
	invalidToken := make([]byte, len(validToken))
	for i := range invalidToken {
		invalidToken[i] = 'x'
	}
	session, valid = store.Validate(string(invalidToken))
	if valid || session != nil {
		t.Error("Invalid token should be rejected")
	}
}

func TestCleanup(t *testing.T) {
	store := NewSessionStore()

	// Create a valid (non-expired) token
	validToken, _ := store.CreatePresharedToken()

	// Manually create an expired session
	expiredToken := "test-expired-for-cleanup"
	store.mu.Lock()
	store.sessions[expiredToken] = &Session{
		Token:     expiredToken,
		CreatedAt: time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	store.mu.Unlock()

	// Verify both sessions exist before cleanup
	store.mu.RLock()
	if len(store.sessions) != 2 {
		t.Errorf("Expected 2 sessions before cleanup, got %d", len(store.sessions))
	}
	store.mu.RUnlock()

	// Run cleanup
	store.Cleanup()

	// Verify only the valid session remains
	store.mu.RLock()
	if len(store.sessions) != 1 {
		t.Errorf("Expected 1 session after cleanup, got %d", len(store.sessions))
	}
	store.mu.RUnlock()

	// Valid token should still work
	session, valid := store.Validate(validToken)
	if !valid || session == nil {
		t.Error("Valid token should still work after cleanup")
	}

	// Expired token should be gone
	session, valid = store.Validate(expiredToken)
	if valid || session != nil {
		t.Error("Expired token should be removed by cleanup")
	}
}

func TestSessionStore_ConcurrentAccess(t *testing.T) {
	store := NewSessionStore()
	var wg sync.WaitGroup
	numGoroutines := 100

	// Concurrently create tokens and validate them
	tokens := make(chan string, numGoroutines)

	// Create tokens concurrently
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, err := store.CreatePresharedToken()
			if err != nil {
				t.Errorf("CreatePresharedToken failed: %v", err)
				return
			}
			tokens <- token
		}()
	}

	wg.Wait()
	close(tokens)

	// Collect all tokens
	allTokens := make([]string, 0, numGoroutines)
	for token := range tokens {
		allTokens = append(allTokens, token)
	}

	if len(allTokens) != numGoroutines {
		t.Errorf("Expected %d tokens, got %d", numGoroutines, len(allTokens))
	}

	// Concurrently validate all tokens
	for _, token := range allTokens {
		wg.Add(1)
		go func(tok string) {
			defer wg.Done()
			session, valid := store.Validate(tok)
			if !valid || session == nil {
				t.Errorf("Token %s should be valid", tok)
			}
		}(token)
	}

	wg.Wait()

	// Concurrently run cleanup while validating
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			store.Cleanup()
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, token := range allTokens {
				store.Validate(token)
			}
		}()
	}

	wg.Wait()
}

func TestSession_Fields(t *testing.T) {
	store := NewSessionStore()
	token, _ := store.CreatePresharedToken()

	session, valid := store.Validate(token)
	if !valid {
		t.Fatal("Token should be valid")
	}

	// Verify session fields are set correctly
	if session.Token == "" {
		t.Error("Session.Token should not be empty")
	}
	if session.CreatedAt.IsZero() {
		t.Error("Session.CreatedAt should not be zero")
	}
	if session.ExpiresAt.IsZero() {
		t.Error("Session.ExpiresAt should not be zero")
	}
	if !session.ExpiresAt.After(session.CreatedAt) {
		t.Error("Session.ExpiresAt should be after CreatedAt")
	}
}
