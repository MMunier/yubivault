package server

import (
	"encoding/base64"
	"net/http"
	"strings"
)

// AuthMiddleware handles authentication for protected endpoints
type AuthMiddleware struct {
	sessions *SessionStore
	// authRequired controls whether authentication is enforced
	authRequired bool
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(sessions *SessionStore, authRequired bool) *AuthMiddleware {
	return &AuthMiddleware{
		sessions:     sessions,
		authRequired: authRequired,
	}
}

// RequireAuth wraps a handler to require authentication
// Accepts both Bearer token and Basic auth (password = token)
func (am *AuthMiddleware) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// If auth not required, allow unauthenticated access
		if !am.authRequired {
			next(w, r)
			return
		}

		// Extract token from Authorization header
		token := am.extractToken(r)
		if token == "" {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}

		if _, valid := am.sessions.Validate(token); !valid {
			http.Error(w, "invalid or expired token", http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}

// extractToken extracts the auth token from the request
// Supports both Bearer token and Basic auth (password = token)
func (am *AuthMiddleware) extractToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ""
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 {
		return ""
	}

	switch parts[0] {
	case "Bearer":
		return parts[1]
	case "Basic":
		// Basic auth: base64(username:password), we use password as token
		decoded, err := base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			return ""
		}
		// Format: username:password - we only care about password (token)
		creds := strings.SplitN(string(decoded), ":", 2)
		if len(creds) != 2 {
			return ""
		}
		return creds[1] // password is the token
	default:
		return ""
	}
}
