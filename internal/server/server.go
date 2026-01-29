package server

import (
	"context"
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

	"github.com/mmunier/terraform-provider-yubivault/internal/yubikey"
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
func NewStateServer(vault *yubikey.Vault, vaultPath string) (*StateServer, error) {
	stateDir := filepath.Join(vaultPath, "state")
	secretsDir := filepath.Join(vaultPath, "secrets")

	// Create state directory if it doesn't exist
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create state directory: %w", err)
	}

	return &StateServer{
		vault:      vault,
		vaultPath:  vaultPath,
		stateDir:   stateDir,
		secretsDir: secretsDir,
		locks:      make(map[string]*StateLock),
	}, nil
}

// Start starts the HTTP server
func (s *StateServer) Start(addr string) error {
	mux := http.NewServeMux()

	// State endpoints
	mux.HandleFunc("/state/", s.handleState)

	// Secret endpoints
	mux.HandleFunc("/secret/", s.handleSecret)

	s.server = &http.Server{
		Addr:         addr,
		Handler:      s.logMiddleware(mux),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	log.Printf("Starting YubiVault server on %s", addr)
	log.Printf("Vault path: %s", s.vaultPath)
	log.Printf("\nEndpoints:")
	log.Printf("  GET  /secret/{name}  - Retrieve decrypted secret")
	log.Printf("  *    /state/{project} - Terraform state backend")
	log.Printf("\nConfigure Terraform provider with:")
	log.Printf("  provider \"yubivault\" {")
	log.Printf("    server_url = \"http://%s\"", addr)
	log.Printf("  }")

	return s.server.ListenAndServe()
}

// Shutdown gracefully shuts down the server
func (s *StateServer) Shutdown(ctx context.Context) error {
	if s.server != nil {
		return s.server.Shutdown(ctx)
	}
	return nil
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

	// Decrypt state
	plaintext, err := s.vault.DecryptSecret(encryptedState)
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

	// Read state from request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading request body: %v", err)
		http.Error(w, "failed to read request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Encrypt state
	encrypted, err := s.vault.EncryptSecret(body)
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

	// Decrypt secret
	plaintext, err := s.vault.DecryptSecret(encryptedSecret)
	if err != nil {
		log.Printf("Error decrypting secret '%s': %v", name, err)
		http.Error(w, "failed to decrypt secret", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write(plaintext)
}
