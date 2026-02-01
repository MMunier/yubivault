package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mmunier/terraform-provider-yubivault/internal/yubikey"
)

const (
	// MaxRequestBodySize is the maximum allowed request body size (10MB)
	MaxRequestBodySize = 10 * 1024 * 1024

	// LockTTL is how long state locks remain valid before auto-expiring
	LockTTL = 30 * time.Minute
)

// StateServer provides an HTTP backend for Terraform state storage
// and secrets with YubiKey-backed encryption
type StateServer struct {
	vault      *yubikey.Vault
	vaultPath  string
	stateDir   string
	secretsDir string
	locks      map[string]*StateLock
	lockMu     sync.RWMutex
	server     *http.Server
	listener   net.Listener

	// Token-based authentication
	sessions      *SessionStore
	authMw        *AuthMiddleware
	cleanupCancel context.CancelFunc
}

// StateLock represents a lock on a state file
type StateLock struct {
	ID        string    `json:"ID"`
	Operation string    `json:"Operation"`
	Info      string    `json:"Info"`
	Who       string    `json:"Who"`
	Version   string    `json:"Version"`
	Created   time.Time `json:"Created"`
	Path      string    `json:"Path"`
}

// NewStateServer creates a new state server
// The authRequired parameter controls whether token authentication is enforced
func NewStateServer(vault *yubikey.Vault, vaultPath string, authRequired bool) (*StateServer, error) {
	stateDir := filepath.Join(vaultPath, "state")
	secretsDir := filepath.Join(vaultPath, "secrets")

	// Create state directory if it doesn't exist
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create state directory: %w", err)
	}

	sessions := NewSessionStore()

	return &StateServer{
		vault:      vault,
		vaultPath:  vaultPath,
		stateDir:   stateDir,
		secretsDir: secretsDir,
		locks:      make(map[string]*StateLock),
		sessions:   sessions,
		authMw:     NewAuthMiddleware(sessions, authRequired),
	}, nil
}

// Sessions returns the session store for token management
func (s *StateServer) Sessions() *SessionStore {
	return s.sessions
}

// Listener returns the server's listener (for getting the bound address)
func (s *StateServer) Listener() net.Listener {
	return s.listener
}

// setupTLS prepares TLS configuration for the server
// Certificate priority: 1) import explicit certFile/keyFile, 2) vault/tls/ directory, 3) auto-generate
// All private keys are stored encrypted in vault/tls/server.key.enc
// Returns the TLS config, cert file path, and cert source description
func (s *StateServer) setupTLS(certFile, keyFile string) (*tls.Config, string, string, error) {
	tlsDir := filepath.Join(s.vaultPath, "tls")
	vaultCertFile := filepath.Join(tlsDir, "server.crt")
	vaultKeyFile := filepath.Join(tlsDir, "server.key.enc")

	var cert tls.Certificate
	var certSource string

	if certFile != "" && keyFile != "" {
		// Priority 1: Import explicitly provided certificates into vault
		log.Printf("Importing TLS certificates from %s and %s", certFile, keyFile)
		if err := ImportTLSCert(certFile, keyFile, vaultCertFile, vaultKeyFile, s.vault); err != nil {
			return nil, "", "", fmt.Errorf("failed to import TLS certificates: %w", err)
		}
		certSource = "imported"
		log.Printf("TLS certificates imported to %s", tlsDir)
	}

	// Check if encrypted certificates exist in vault
	if _, err := os.Stat(vaultCertFile); err == nil {
		if _, err := os.Stat(vaultKeyFile); err == nil {
			// Load existing encrypted certificates
			var loadErr error
			cert, loadErr = LoadTLSKeyPair(vaultCertFile, vaultKeyFile, s.vault)
			if loadErr != nil {
				return nil, "", "", fmt.Errorf("failed to load TLS certificates: %w", loadErr)
			}
			if certSource == "" {
				certSource = "vault"
			}
		}
	}

	// Auto-generate if no certificates found
	if certSource == "" {
		log.Printf("Generating new self-signed certificate in %s", tlsDir)
		if err := GenerateSelfSignedCert(vaultCertFile, vaultKeyFile, s.vault); err != nil {
			return nil, "", "", fmt.Errorf("failed to generate self-signed certificate: %w", err)
		}
		var loadErr error
		cert, loadErr = LoadTLSKeyPair(vaultCertFile, vaultKeyFile, s.vault)
		if loadErr != nil {
			return nil, "", "", fmt.Errorf("failed to load generated TLS certificates: %w", loadErr)
		}
		certSource = "auto-generated"
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	return tlsConfig, vaultCertFile, certSource, nil
}

// StartWithListener starts the HTTPS server using a pre-created listener.
// This allows the caller to bind to a random port and know the address before starting.
// The ready channel is closed when the server is ready to accept connections.
func (s *StateServer) StartWithListener(listener net.Listener, certFile, keyFile string, ready chan<- struct{}) error {
	tlsConfig, vaultCertFile, certSource, err := s.setupTLS(certFile, keyFile)
	if err != nil {
		return err
	}

	// Get certificate fingerprint for logging
	fingerprint, err := GetCertFingerprint(vaultCertFile)
	if err != nil {
		log.Printf("Warning: failed to get certificate fingerprint: %v", err)
		fingerprint = "unknown"
	}

	mux := http.NewServeMux()

	// Protected endpoints (auth required when configured)
	mux.HandleFunc("/state/", s.authMw.RequireAuth(s.handleState))
	mux.HandleFunc("/secret/", s.authMw.RequireAuth(s.handleSecret))

	s.server = &http.Server{
		Handler:      s.logMiddleware(mux),
		TLSConfig:    tlsConfig,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
	s.listener = listener

	// Log detailed TLS info when debug mode is enabled
	if os.Getenv("YUBIVAULT_DEBUG") != "" {
		vaultKeyFile := filepath.Join(s.vaultPath, "tls", "server.key.enc")
		log.Printf("Vault path: %s", s.vaultPath)
		log.Printf("TLS: ENABLED (HTTPS only)")
		log.Printf("  Certificate: %s (%s)", vaultCertFile, certSource)
		log.Printf("  Private key: encrypted at %s", vaultKeyFile)
		log.Printf("  Fingerprint: %s", fingerprint)
		if certSource == "auto-generated" {
			log.Printf("  Note: Self-signed certificate")
		}
		log.Printf("")
		log.Printf("Endpoints:")
		log.Printf("  GET  /secret/{name}   - Retrieve decrypted secret")
		log.Printf("  *    /state/{project} - Terraform state backend")
	}

	// Start background cleanup routine
	cleanupCtx, cleanupCancel := context.WithCancel(context.Background())
	s.cleanupCancel = cleanupCancel
	s.startCleanupRoutine(cleanupCtx)

	// Signal that we're ready to accept connections
	if ready != nil {
		close(ready)
	}

	// Wrap listener with TLS and serve
	tlsListener := tls.NewListener(listener, tlsConfig)
	return s.server.Serve(tlsListener)
}

// Shutdown gracefully shuts down the server
func (s *StateServer) Shutdown(ctx context.Context) error {
	// Stop cleanup routine
	if s.cleanupCancel != nil {
		s.cleanupCancel()
	}
	if s.server != nil {
		return s.server.Shutdown(ctx)
	}
	return nil
}

// startCleanupRoutine starts a background goroutine that periodically cleans up
// expired sessions, challenges, and state locks
func (s *StateServer) startCleanupRoutine(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	go func() {
		for {
			select {
			case <-ctx.Done():
				ticker.Stop()
				return
			case <-ticker.C:
				s.cleanup()
			}
		}
	}()
}

// cleanup removes expired sessions and state locks
func (s *StateServer) cleanup() {
	now := time.Now()

	// Cleanup expired sessions
	s.sessions.Cleanup()

	// Cleanup expired state locks
	s.lockMu.Lock()
	for project, lock := range s.locks {
		if now.Sub(lock.Created) > LockTTL {
			log.Printf("Auto-expiring stale lock for '%s' (held by %s)", project, lock.Who)
			delete(s.locks, project)
		}
	}
	s.lockMu.Unlock()
}

// logMiddleware logs incoming requests
func (s *StateServer) logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

// handleState routes state requests based on HTTP method
func (s *StateServer) handleState(w http.ResponseWriter, r *http.Request) {
	// Extract project name from path: /state/{project}
	path := strings.TrimPrefix(r.URL.Path, "/state/")
	if path == "" {
		http.Error(w, "project name required", http.StatusBadRequest)
		return
	}

	// Validate project name to prevent path traversal
	if err := yubikey.ValidateSecretName(path); err != nil {
		http.Error(w, fmt.Sprintf("invalid project name: %v", err), http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.getState(w, r, path)
	case http.MethodPost:
		s.postState(w, r, path)
	case "LOCK":
		s.lockState(w, r, path)
	case "UNLOCK":
		s.unlockState(w, r, path)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// getState retrieves and decrypts state
func (s *StateServer) getState(w http.ResponseWriter, r *http.Request, project string) {
	statePath := filepath.Join(s.stateDir, project+".tfstate.enc")

	// Check if state file exists
	encryptedState, err := os.ReadFile(statePath)
	if err != nil {
		if os.IsNotExist(err) {
			// Return empty response for non-existent state (Terraform expects this)
			w.WriteHeader(http.StatusOK)
			return
		}
		log.Printf("Error reading state file: %v", err)
		http.Error(w, "failed to read state", http.StatusInternalServerError)
		return
	}

	// Decrypt state (using project name as AAD)
	plaintext, err := s.vault.DecryptSecret(encryptedState, "state:"+project)
	if err != nil {
		log.Printf("Error decrypting state: %v", err)
		http.Error(w, "failed to decrypt state", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(plaintext)
}

// postState encrypts and stores state
func (s *StateServer) postState(w http.ResponseWriter, r *http.Request, project string) {
	// Check if locked by someone else
	s.lockMu.RLock()
	lock, locked := s.locks[project]
	s.lockMu.RUnlock()

	// If locked, verify the lock ID matches (from query param)
	if locked {
		lockID := r.URL.Query().Get("ID")
		if lockID == "" || lockID != lock.ID {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusLocked)
			json.NewEncoder(w).Encode(lock)
			return
		}
	}

	// Read state from request body (with size limit)
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxRequestBodySize))
	if err != nil {
		log.Printf("Error reading request body: %v", err)
		http.Error(w, "failed to read request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Encrypt state (using project name as AAD)
	encrypted, err := s.vault.EncryptSecret(body, "state:"+project)
	if err != nil {
		log.Printf("Error encrypting state: %v", err)
		http.Error(w, "failed to encrypt state", http.StatusInternalServerError)
		return
	}

	// Write encrypted state to file
	statePath := filepath.Join(s.stateDir, project+".tfstate.enc")
	if err := os.WriteFile(statePath, encrypted, 0600); err != nil {
		log.Printf("Error writing state file: %v", err)
		http.Error(w, "failed to write state", http.StatusInternalServerError)
		return
	}

	log.Printf("State for '%s' encrypted and saved (%d bytes)", project, len(body))
	w.WriteHeader(http.StatusOK)
}

// lockState handles LOCK requests
func (s *StateServer) lockState(w http.ResponseWriter, r *http.Request, project string) {
	// Parse lock info from request body
	var lockInfo StateLock
	if err := json.NewDecoder(r.Body).Decode(&lockInfo); err != nil {
		http.Error(w, "invalid lock info", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	lockInfo.Created = time.Now()
	lockInfo.Path = project

	s.lockMu.Lock()
	defer s.lockMu.Unlock()

	// Check if already locked
	if existingLock, locked := s.locks[project]; locked {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusLocked)
		json.NewEncoder(w).Encode(existingLock)
		return
	}

	// Create lock
	s.locks[project] = &lockInfo
	log.Printf("State '%s' locked by %s (ID: %s)", project, lockInfo.Who, lockInfo.ID)
	w.WriteHeader(http.StatusOK)
}

// unlockState handles UNLOCK requests
func (s *StateServer) unlockState(w http.ResponseWriter, r *http.Request, project string) {
	// Parse lock info from request body
	var lockInfo StateLock
	if err := json.NewDecoder(r.Body).Decode(&lockInfo); err != nil {
		http.Error(w, "invalid lock info", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	s.lockMu.Lock()
	defer s.lockMu.Unlock()

	// Check if locked
	existingLock, locked := s.locks[project]
	if !locked {
		// Already unlocked, that's fine
		w.WriteHeader(http.StatusOK)
		return
	}

	// Verify lock ID matches
	if existingLock.ID != lockInfo.ID {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(existingLock)
		return
	}

	// Remove lock
	delete(s.locks, project)
	log.Printf("State '%s' unlocked (ID: %s)", project, lockInfo.ID)
	w.WriteHeader(http.StatusOK)
}

// handleSecret handles secret retrieval requests
func (s *StateServer) handleSecret(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract secret name from path: /secret/{name}
	name := strings.TrimPrefix(r.URL.Path, "/secret/")
	if name == "" {
		http.Error(w, "secret name required", http.StatusBadRequest)
		return
	}

	// Validate secret name to prevent path traversal
	if err := yubikey.ValidateSecretName(name); err != nil {
		http.Error(w, fmt.Sprintf("invalid secret name: %v", err), http.StatusBadRequest)
		return
	}

	// Read encrypted secret from file
	secretPath := filepath.Join(s.secretsDir, name+".enc")
	encryptedSecret, err := os.ReadFile(secretPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "secret not found", http.StatusNotFound)
			return
		}
		log.Printf("Error reading secret file: %v", err)
		http.Error(w, "failed to read secret", http.StatusInternalServerError)
		return
	}

	// Decrypt secret (using secret name as AAD)
	plaintext, err := s.vault.DecryptSecret(encryptedSecret, "secret:"+name)
	if err != nil {
		log.Printf("Error decrypting secret '%s': %v", name, err)
		http.Error(w, "failed to decrypt secret", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write(plaintext)
}
