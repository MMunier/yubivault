package server

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewAuthMiddleware(t *testing.T) {
	store := NewSessionStore()
	mw := NewAuthMiddleware(store, true)

	if mw == nil {
		t.Fatal("NewAuthMiddleware returned nil")
	}
	if mw.sessions != store {
		t.Error("sessions not set correctly")
	}
	if !mw.authRequired {
		t.Error("authRequired should be true")
	}
}

func TestRequireAuth_NoAuthRequired(t *testing.T) {
	store := NewSessionStore()
	mw := NewAuthMiddleware(store, false)

	handlerCalled := false
	handler := mw.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if !handlerCalled {
		t.Error("Handler should be called when auth not required")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rec.Code)
	}
}

func TestRequireAuth_MissingAuthHeader(t *testing.T) {
	store := NewSessionStore()
	mw := NewAuthMiddleware(store, true)

	handlerCalled := false
	handler := mw.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if handlerCalled {
		t.Error("Handler should not be called without auth header")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}
}

func TestRequireAuth_BearerToken_Valid(t *testing.T) {
	store := NewSessionStore()
	token, _ := store.CreatePresharedToken()
	mw := NewAuthMiddleware(store, true)

	handlerCalled := false
	handler := mw.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if !handlerCalled {
		t.Error("Handler should be called with valid bearer token")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rec.Code)
	}
}

func TestRequireAuth_BearerToken_Invalid(t *testing.T) {
	store := NewSessionStore()
	mw := NewAuthMiddleware(store, true)

	handlerCalled := false
	handler := mw.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	rec := httptest.NewRecorder()

	handler(rec, req)

	if handlerCalled {
		t.Error("Handler should not be called with invalid bearer token")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}
}

func TestRequireAuth_BasicAuth_Valid(t *testing.T) {
	store := NewSessionStore()
	token, _ := store.CreatePresharedToken()
	mw := NewAuthMiddleware(store, true)

	handlerCalled := false
	handler := mw.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	// Basic auth format: base64(username:password)
	// In yubivault, the password is the token
	credentials := base64.StdEncoding.EncodeToString([]byte("any-user:" + token))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Basic "+credentials)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if !handlerCalled {
		t.Error("Handler should be called with valid basic auth")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, rec.Code)
	}
}

func TestRequireAuth_BasicAuth_Invalid(t *testing.T) {
	store := NewSessionStore()
	mw := NewAuthMiddleware(store, true)

	handlerCalled := false
	handler := mw.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	})

	credentials := base64.StdEncoding.EncodeToString([]byte("user:invalid-password"))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Basic "+credentials)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if handlerCalled {
		t.Error("Handler should not be called with invalid basic auth")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}
}

func TestExtractToken_BearerToken(t *testing.T) {
	store := NewSessionStore()
	mw := NewAuthMiddleware(store, true)

	tests := []struct {
		name     string
		header   string
		expected string
	}{
		{"Valid bearer token", "Bearer abc123", "abc123"},
		{"Bearer with spaces in token", "Bearer my token with spaces", "my token with spaces"},
		{"Empty bearer token", "Bearer ", ""},
		{"Just Bearer", "Bearer", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			token := mw.extractToken(req)
			if token != tt.expected {
				t.Errorf("Expected token %q, got %q", tt.expected, token)
			}
		})
	}
}

func TestExtractToken_BasicAuth(t *testing.T) {
	store := NewSessionStore()
	mw := NewAuthMiddleware(store, true)

	tests := []struct {
		name     string
		username string
		password string
		expected string
	}{
		{"Standard credentials", "user", "password123", "password123"},
		{"Empty username", "", "token-only", "token-only"},
		{"Special characters in password", "user", "p@ss:w0rd!", "p@ss:w0rd!"},
		{"Colon in password", "user", "pass:with:colons", "pass:with:colons"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			credentials := base64.StdEncoding.EncodeToString([]byte(tt.username + ":" + tt.password))
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			req.Header.Set("Authorization", "Basic "+credentials)
			token := mw.extractToken(req)
			if token != tt.expected {
				t.Errorf("Expected token %q, got %q", tt.expected, token)
			}
		})
	}
}

func TestExtractToken_InvalidFormats(t *testing.T) {
	store := NewSessionStore()
	mw := NewAuthMiddleware(store, true)

	tests := []struct {
		name   string
		header string
	}{
		{"Empty header", ""},
		{"Unknown scheme", "Digest abc123"},
		{"No space after scheme", "Bearerabc123"},
		{"Invalid base64 in Basic", "Basic not-valid-base64!!!"},
		{"Basic without colon", "Basic " + base64.StdEncoding.EncodeToString([]byte("no-colon-here"))},
		{"Just scheme name", "Bearer"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			token := mw.extractToken(req)
			if token != "" {
				t.Errorf("Expected empty token for invalid format, got %q", token)
			}
		})
	}
}

func TestRequireAuth_ExpiredToken(t *testing.T) {
	store := NewSessionStore()
	mw := NewAuthMiddleware(store, true)

	// Manually create an expired session
	expiredToken := "expired-token-12345"
	store.mu.Lock()
	store.sessions[expiredToken] = &Session{
		Token:     expiredToken,
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
	}
	store.mu.Unlock()

	handlerCalled := false
	handler := mw.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+expiredToken)
	rec := httptest.NewRecorder()

	handler(rec, req)

	if handlerCalled {
		t.Error("Handler should not be called with expired token")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}
}

func TestRequireAuth_MultipleRequests(t *testing.T) {
	store := NewSessionStore()
	token, _ := store.CreatePresharedToken()
	mw := NewAuthMiddleware(store, true)

	callCount := 0
	handler := mw.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
	})

	// Make multiple requests with the same token
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		handler(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Request %d: Expected status %d, got %d", i, http.StatusOK, rec.Code)
		}
	}

	if callCount != 10 {
		t.Errorf("Expected handler to be called 10 times, got %d", callCount)
	}
}
