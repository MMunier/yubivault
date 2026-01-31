package server

import (
	"net/http"
	"strings"
)

// AuthMiddleware handles authentication for protected endpoints
type AuthMiddleware struct {
	sessions    *SessionStore
	credentials *CredentialStore
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(sessions *SessionStore, credentials *CredentialStore) *AuthMiddleware {
	return &AuthMiddleware{
		sessions:    sessions,
		credentials: credentials,
	}
}

// RequireAuth wraps a handler to require authentication
// If no credentials are registered, requests are allowed through (backward compatibility)
func (am *AuthMiddleware) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// If no credentials registered, allow unauthenticated access
		if !am.credentials.HasCredentials() {
			next(w, r)
			return
		}

		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}

		// Expect: "Bearer <token>"
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "invalid authorization header format", http.StatusUnauthorized)
			return
		}

		token := parts[1]
		if _, valid := am.sessions.Validate(token); !valid {
			http.Error(w, "invalid or expired token", http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}
