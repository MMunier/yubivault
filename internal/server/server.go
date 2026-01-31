package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/mmunier/terraform-provider-yubivault/internal/yubikey"
)

const (
	// MaxRequestBodySize is the maximum allowed request body size (10MB)
	MaxRequestBodySize = 10 * 1024 * 1024

	// ChallengeTTL is how long WebAuthn challenges remain valid
	ChallengeTTL = 60 * time.Second

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

	// FIDO2/WebAuthn authentication
	webauthn      *webauthn.WebAuthn
	sessions      *SessionStore
	credentials   *CredentialStore
	authMw        *AuthMiddleware
	challenges    map[string]*challengeData
	challengeMu   sync.RWMutex
	cleanupCancel context.CancelFunc
}

// challengeData wraps WebAuthn session data with creation time for expiration
type challengeData struct {
	sessionData *webauthn.SessionData
	createdAt   time.Time
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
// The addr parameter is used to configure the WebAuthn relying party origin
func NewStateServer(vault *yubikey.Vault, vaultPath, addr string) (*StateServer, error) {
	stateDir := filepath.Join(vaultPath, "state")
	secretsDir := filepath.Join(vaultPath, "secrets")

	// Create state directory if it doesn't exist
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create state directory: %w", err)
	}

	// Extract hostname for RPID (without port)
	rpID := addr
	if colonIdx := strings.Index(addr, ":"); colonIdx != -1 {
		rpID = addr[:colonIdx]
	}

	// Initialize WebAuthn with configurable origin based on server address (always HTTPS)
	wconfig := &webauthn.Config{
		RPDisplayName: "YubiVault",
		RPID:          rpID,
		RPOrigins:     []string{fmt.Sprintf("https://%s", addr)},
	}
	webauthnInstance, err := webauthn.New(wconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create webauthn: %w", err)
	}

	// Initialize credential store with encryption
	credentials, err := NewCredentialStore(vaultPath, vault)
	if err != nil {
		return nil, fmt.Errorf("failed to create credential store: %w", err)
	}

	sessions := NewSessionStore()

	return &StateServer{
		vault:       vault,
		vaultPath:   vaultPath,
		stateDir:    stateDir,
		secretsDir:  secretsDir,
		locks:       make(map[string]*StateLock),
		webauthn:    webauthnInstance,
		sessions:    sessions,
		credentials: credentials,
		authMw:      NewAuthMiddleware(sessions, credentials),
		challenges:  make(map[string]*challengeData),
	}, nil
}

// Start starts the HTTPS server (always uses TLS)
// Certificate priority: 1) import explicit certFile/keyFile, 2) vault/tls/ directory, 3) auto-generate
// All private keys are stored encrypted in vault/tls/server.key.enc
func (s *StateServer) Start(addr, certFile, keyFile string) error {
	tlsDir := filepath.Join(s.vaultPath, "tls")
	vaultCertFile := filepath.Join(tlsDir, "server.crt")
	vaultKeyFile := filepath.Join(tlsDir, "server.key.enc")

	var cert tls.Certificate
	var certSource string

	if certFile != "" && keyFile != "" {
		// Priority 1: Import explicitly provided certificates into vault
		log.Printf("Importing TLS certificates from %s and %s", certFile, keyFile)
		if err := ImportTLSCert(certFile, keyFile, vaultCertFile, vaultKeyFile, s.vault); err != nil {
			return fmt.Errorf("failed to import TLS certificates: %w", err)
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
				return fmt.Errorf("failed to load TLS certificates: %w", loadErr)
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
			return fmt.Errorf("failed to generate self-signed certificate: %w", err)
		}
		var loadErr error
		cert, loadErr = LoadTLSKeyPair(vaultCertFile, vaultKeyFile, s.vault)
		if loadErr != nil {
			return fmt.Errorf("failed to load generated TLS certificates: %w", loadErr)
		}
		certSource = "auto-generated"
	}

	// Get certificate fingerprint for logging
	fingerprint, err := GetCertFingerprint(vaultCertFile)
	if err != nil {
		log.Printf("Warning: failed to get certificate fingerprint: %v", err)
		fingerprint = "unknown"
	}

	mux := http.NewServeMux()

	// Auth endpoints (no authentication required)
	mux.HandleFunc("/auth/challenge", s.handleAuthChallenge)
	mux.HandleFunc("/auth/verify", s.handleAuthVerify)
	mux.HandleFunc("/auth/register/begin", s.handleRegisterBegin)
	mux.HandleFunc("/auth/register/complete", s.handleRegisterComplete)

	// Protected endpoints (auth required when credentials exist)
	mux.HandleFunc("/state/", s.authMw.RequireAuth(s.handleState))
	mux.HandleFunc("/secret/", s.authMw.RequireAuth(s.handleSecret))

	// Configure TLS with in-memory certificate (private key never on disk unencrypted)
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	s.server = &http.Server{
		Addr:         addr,
		Handler:      s.logMiddleware(mux),
		TLSConfig:    tlsConfig,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	log.Printf("Starting YubiVault server on %s", addr)
	log.Printf("Vault path: %s", s.vaultPath)
	log.Printf("TLS: ENABLED (HTTPS only)")
	log.Printf("  Certificate: %s (%s)", vaultCertFile, certSource)
	log.Printf("  Private key: encrypted at %s", vaultKeyFile)
	log.Printf("  Fingerprint: %s", fingerprint)
	if certSource == "auto-generated" {
		log.Printf("  Note: Self-signed certificate - clients must trust manually or use insecure_skip_verify")
	}
	if s.credentials.HasCredentials() {
		log.Printf("FIDO2 authentication: ENABLED")
	} else {
		log.Printf("FIDO2 authentication: DISABLED (no credentials registered)")
		log.Printf("  Run 'yubivault fido2-register' to enable authentication")
	}
	log.Printf("\nEndpoints:")
	log.Printf("  GET  /secret/{name}   - Retrieve decrypted secret")
	log.Printf("  *    /state/{project} - Terraform state backend")
	log.Printf("  GET  /auth/challenge  - Get FIDO2 authentication challenge")
	log.Printf("  POST /auth/verify     - Verify FIDO2 assertion")
	log.Printf("\nConfigure Terraform with:")
	log.Printf("  terraform {")
	log.Printf("    backend \"http\" {")
	log.Printf("      address        = \"https://%s/state/myproject\"", addr)
	log.Printf("      lock_address   = \"https://%s/state/myproject\"", addr)
	log.Printf("      unlock_address = \"https://%s/state/myproject\"", addr)
	log.Printf("    }")
	log.Printf("  }")
	log.Printf("")
	log.Printf("  provider \"yubivault\" {")
	log.Printf("    server_url = \"https://%s\"", addr)
	log.Printf("  }")

	// Start background cleanup routine
	cleanupCtx, cleanupCancel := context.WithCancel(context.Background())
	s.cleanupCancel = cleanupCancel
	s.startCleanupRoutine(cleanupCtx)

	// Start HTTPS server (cert/key already loaded in TLSConfig)
	return s.server.ListenAndServeTLS("", "")
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

// cleanup removes expired sessions, challenges, and state locks
func (s *StateServer) cleanup() {
	now := time.Now()

	// Cleanup expired sessions
	s.sessions.Cleanup()

	// Cleanup expired challenges
	s.challengeMu.Lock()
	for key, challenge := range s.challenges {
		if now.Sub(challenge.createdAt) > ChallengeTTL {
			delete(s.challenges, key)
		}
	}
	s.challengeMu.Unlock()

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

// handleAuthChallenge returns a WebAuthn challenge for authentication
func (s *StateServer) handleAuthChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.credentials.HasCredentials() {
		http.Error(w, "no credentials registered - run 'yubivault fido2-register' first", http.StatusPreconditionFailed)
		return
	}

	user := NewVaultUser(s.credentials)
	options, sessionData, err := s.webauthn.BeginLogin(user)
	if err != nil {
		log.Printf("Error creating challenge: %v", err)
		http.Error(w, fmt.Sprintf("failed to create challenge: %v", err), http.StatusInternalServerError)
		return
	}

	// Store session data keyed by challenge - use raw bytes as key
	challengeKey := string(options.Response.Challenge)
	s.challengeMu.Lock()
	s.challenges[challengeKey] = &challengeData{
		sessionData: sessionData,
		createdAt:   time.Now(),
	}
	s.challengeMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
}

// handleAuthVerify verifies a WebAuthn assertion and returns a session token
func (s *StateServer) handleAuthVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse the credential assertion response
	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(r.Body)
	if err != nil {
		log.Printf("Error parsing assertion: %v", err)
		http.Error(w, fmt.Sprintf("invalid assertion: %v", err), http.StatusBadRequest)
		return
	}

	// Find session data by challenge - already decoded by webauthn library
	challengeKey := parsedResponse.Response.CollectedClientData.Challenge
	s.challengeMu.RLock()
	challenge, exists := s.challenges[challengeKey]
	s.challengeMu.RUnlock()

	if !exists || time.Since(challenge.createdAt) > ChallengeTTL {
		if exists {
			// Clean up expired challenge
			s.challengeMu.Lock()
			delete(s.challenges, challengeKey)
			s.challengeMu.Unlock()
		}
		http.Error(w, "challenge not found or expired", http.StatusBadRequest)
		return
	}

	// Verify assertion
	user := NewVaultUser(s.credentials)
	credential, err := s.webauthn.ValidateLogin(user, *challenge.sessionData, parsedResponse)
	if err != nil {
		log.Printf("Authentication failed: %v", err)
		http.Error(w, fmt.Sprintf("authentication failed: %v", err), http.StatusUnauthorized)
		return
	}

	// Update sign count
	if err := s.credentials.UpdateSignCount(credential.ID, credential.Authenticator.SignCount); err != nil {
		log.Printf("Warning: failed to update sign count: %v", err)
	}

	// Create session
	session, err := s.sessions.Create(credential.ID)
	if err != nil {
		log.Printf("Error creating session: %v", err)
		http.Error(w, "failed to create session", http.StatusInternalServerError)
		return
	}

	// Cleanup challenge
	s.challengeMu.Lock()
	delete(s.challenges, challengeKey)
	s.challengeMu.Unlock()

	log.Printf("Authentication successful, token expires at %s", session.ExpiresAt.Format(time.RFC3339))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"token":      session.Token,
		"expires_at": session.ExpiresAt,
	})
}

// handleRegisterBegin starts the FIDO2 credential registration flow
func (s *StateServer) handleRegisterBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// If credentials already exist, require authentication for new registrations
	if s.credentials.HasCredentials() {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "authentication required to register additional credentials", http.StatusUnauthorized)
			return
		}
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "invalid authorization header", http.StatusUnauthorized)
			return
		}
		if _, valid := s.sessions.Validate(parts[1]); !valid {
			http.Error(w, "invalid or expired token", http.StatusUnauthorized)
			return
		}
	}

	user := NewVaultUser(s.credentials)
	options, sessionData, err := s.webauthn.BeginRegistration(user, webauthn.WithAttestationFormats([]protocol.AttestationFormat{protocol.AttestationFormatNone}))
	if err != nil {
		log.Printf("Error starting registration: %v", err)
		http.Error(w, fmt.Sprintf("failed to start registration: %v", err), http.StatusInternalServerError)
		return
	}

	// Store session data - use raw bytes as key (URLEncodedBase64 is []byte)
	challengeKey := string(options.Response.Challenge)
	s.challengeMu.Lock()
	s.challenges[challengeKey] = &challengeData{
		sessionData: sessionData,
		createdAt:   time.Now(),
	}
	s.challengeMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
}

// handleRegisterComplete completes the FIDO2 credential registration
func (s *StateServer) handleRegisterComplete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, MaxRequestBodySize))
	if err != nil {
		log.Printf("Error reading request body: %v", err)
		http.Error(w, "failed to read request", http.StatusBadRequest)
		return
	}

	// Parse the credential creation response from bytes
	parsedResponse, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(bodyBytes))
	if err != nil {
		log.Printf("Error parsing registration response: %v", err)
		http.Error(w, fmt.Sprintf("invalid registration response: %v", err), http.StatusBadRequest)
		return
	}

	// Find session data by challenge - already decoded by webauthn library
	challengeBytes, err := base64.RawURLEncoding.DecodeString(parsedResponse.Response.CollectedClientData.Challenge)
	if err != nil {
		log.Printf("Failed to decode challenge token: %v", err)
		http.Error(w, fmt.Sprintf("invalid challenge token: %v", err), http.StatusBadRequest)
		return
	}
	challengeKey := string(challengeBytes)

	s.challengeMu.RLock()
	challenge, exists := s.challenges[challengeKey]
	s.challengeMu.RUnlock()

	if !exists || time.Since(challenge.createdAt) > ChallengeTTL {
		if exists {
			// Clean up expired challenge
			s.challengeMu.Lock()
			delete(s.challenges, challengeKey)
			s.challengeMu.Unlock()
		}
		http.Error(w, "challenge not found or expired", http.StatusBadRequest)
		return
	}

	// Complete registration
	user := NewVaultUser(s.credentials)
	credential, err := s.webauthn.CreateCredential(user, *challenge.sessionData, parsedResponse)
	if err != nil {
		log.Printf("Registration failed: %v", err)
		http.Error(w, fmt.Sprintf("registration failed: %v", err), http.StatusBadRequest)
		return
	}

	// Store credential
	fido2Cred := &FIDO2Credential{
		ID:        credential.ID,
		PublicKey: credential.PublicKey,
		AAGUID:    credential.Authenticator.AAGUID,
		SignCount: credential.Authenticator.SignCount,
		CreatedAt: time.Now(),
		Name:      fmt.Sprintf("credential-%d", len(s.credentials.GetCredentials())+1),
	}
	if err := s.credentials.AddCredential(fido2Cred); err != nil {
		log.Printf("Error saving credential: %v", err)
		http.Error(w, "failed to save credential", http.StatusInternalServerError)
		return
	}

	// Cleanup challenge
	s.challengeMu.Lock()
	delete(s.challenges, challengeKey)
	s.challengeMu.Unlock()

	log.Printf("FIDO2 credential registered: %s", fido2Cred.Name)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "registered",
		"name":   fido2Cred.Name,
	})
}
