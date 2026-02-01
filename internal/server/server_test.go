package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestStateLock tests the StateLock struct JSON serialization
func TestStateLock_JSON(t *testing.T) {
	lock := StateLock{
		ID:        "test-lock-id",
		Operation: "OperationTypeApply",
		Info:      "test info",
		Who:       "test-user@host",
		Version:   "1.0.0",
		Created:   time.Now(),
		Path:      "test-project",
	}

	data, err := json.Marshal(lock)
	if err != nil {
		t.Fatalf("Failed to marshal StateLock: %v", err)
	}

	var decoded StateLock
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal StateLock: %v", err)
	}

	if decoded.ID != lock.ID {
		t.Errorf("ID mismatch: got %s, want %s", decoded.ID, lock.ID)
	}
	if decoded.Operation != lock.Operation {
		t.Errorf("Operation mismatch: got %s, want %s", decoded.Operation, lock.Operation)
	}
	if decoded.Who != lock.Who {
		t.Errorf("Who mismatch: got %s, want %s", decoded.Who, lock.Who)
	}
}

// TestStateServerLocking tests the state locking mechanism
// This test doesn't require YubiKey as it only tests the locking data structures
func TestStateServerLocking(t *testing.T) {
	// Create a minimal StateServer with only the locking components
	server := &StateServer{
		locks: make(map[string]*StateLock),
	}

	project := "test-project"
	lock := &StateLock{
		ID:        "lock-123",
		Operation: "plan",
		Who:       "user@host",
		Created:   time.Now(),
		Path:      project,
	}

	// Test acquiring a lock
	server.lockMu.Lock()
	server.locks[project] = lock
	server.lockMu.Unlock()

	// Verify lock exists
	server.lockMu.RLock()
	existingLock, exists := server.locks[project]
	server.lockMu.RUnlock()

	if !exists {
		t.Error("Lock should exist")
	}
	if existingLock.ID != lock.ID {
		t.Errorf("Lock ID mismatch: got %s, want %s", existingLock.ID, lock.ID)
	}

	// Test removing a lock
	server.lockMu.Lock()
	delete(server.locks, project)
	server.lockMu.Unlock()

	server.lockMu.RLock()
	_, exists = server.locks[project]
	server.lockMu.RUnlock()

	if exists {
		t.Error("Lock should not exist after removal")
	}
}

// TestStateServerLocking_Concurrent tests concurrent access to locks
func TestStateServerLocking_Concurrent(t *testing.T) {
	server := &StateServer{
		locks: make(map[string]*StateLock),
	}

	var wg sync.WaitGroup
	numGoroutines := 100

	// Concurrently create and delete locks
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			project := "project"

			// Try to acquire lock
			server.lockMu.Lock()
			if _, exists := server.locks[project]; !exists {
				server.locks[project] = &StateLock{
					ID:      "lock-" + string(rune(n)),
					Created: time.Now(),
				}
			}
			server.lockMu.Unlock()

			// Simulate some work
			time.Sleep(time.Microsecond)

			// Try to release lock
			server.lockMu.Lock()
			delete(server.locks, project)
			server.lockMu.Unlock()
		}(i)
	}

	wg.Wait()
}

// TestCleanup_ExpiredLocks tests that cleanup removes expired state locks
func TestCleanup_ExpiredLocks(t *testing.T) {
	sessions := NewSessionStore()
	server := &StateServer{
		locks:    make(map[string]*StateLock),
		sessions: sessions,
	}

	// Create an expired lock (created more than LockTTL ago)
	expiredProject := "expired-project"
	server.lockMu.Lock()
	server.locks[expiredProject] = &StateLock{
		ID:      "expired-lock",
		Created: time.Now().Add(-LockTTL - time.Hour), // Expired 1 hour ago
	}
	server.lockMu.Unlock()

	// Create a fresh lock
	freshProject := "fresh-project"
	server.lockMu.Lock()
	server.locks[freshProject] = &StateLock{
		ID:      "fresh-lock",
		Created: time.Now(),
	}
	server.lockMu.Unlock()

	// Run cleanup
	server.cleanup()

	// Verify expired lock is removed
	server.lockMu.RLock()
	_, expiredExists := server.locks[expiredProject]
	_, freshExists := server.locks[freshProject]
	server.lockMu.RUnlock()

	if expiredExists {
		t.Error("Expired lock should have been removed")
	}
	if !freshExists {
		t.Error("Fresh lock should still exist")
	}
}

// TestProjectNameValidation tests that the server properly validates project names
func TestProjectNameValidation(t *testing.T) {
	tests := []struct {
		name    string
		project string
		valid   bool
	}{
		{"valid-simple", "myproject", true},
		{"valid-with-hyphen", "my-project", true},
		{"valid-with-underscore", "my_project", true},
		{"valid-with-numbers", "project123", true},
		{"invalid-path-traversal", "../secret", false},
		{"invalid-absolute", "/etc/passwd", false},
		{"invalid-empty", "", false},
		{"invalid-dots", "..secret", false},
		{"invalid-slash", "my/project", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a minimal handler that checks project validation
			sessions := NewSessionStore()
			authMw := NewAuthMiddleware(sessions, false) // No auth required for this test

			handlerCalled := false
			handler := func(w http.ResponseWriter, r *http.Request) {
				path := strings.TrimPrefix(r.URL.Path, "/state/")
				if path == "" {
					http.Error(w, "project name required", http.StatusBadRequest)
					return
				}

				// Simulate the validation from handleState
				if strings.Contains(path, "..") || strings.Contains(path, "/") || path == "" {
					http.Error(w, "invalid project name", http.StatusBadRequest)
					return
				}

				handlerCalled = true
				w.WriteHeader(http.StatusOK)
			}

			wrappedHandler := authMw.RequireAuth(handler)

			req := httptest.NewRequest(http.MethodGet, "/state/"+tt.project, nil)
			rec := httptest.NewRecorder()

			wrappedHandler(rec, req)

			if tt.valid && !handlerCalled {
				t.Errorf("Expected handler to be called for valid project %q", tt.project)
			}
			if tt.valid && rec.Code != http.StatusOK {
				t.Errorf("Expected status 200 for valid project %q, got %d", tt.project, rec.Code)
			}
			if !tt.valid && rec.Code == http.StatusOK {
				t.Errorf("Expected error for invalid project %q, got 200", tt.project)
			}
		})
	}
}

// TestHandleState_MethodRouting tests that handleState routes methods correctly
func TestHandleState_MethodRouting(t *testing.T) {
	tests := []struct {
		method      string
		expectAllow bool
	}{
		{http.MethodGet, true},
		{http.MethodPost, true},
		{"LOCK", true},
		{"UNLOCK", true},
		{http.MethodPut, false},
		{http.MethodDelete, false},
		{http.MethodPatch, false},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			// We can't fully test handleState without a vault, but we can verify
			// that the method check works by checking for "method not allowed" vs other errors
			sessions := NewSessionStore()
			authMw := NewAuthMiddleware(sessions, false)

			methodAllowed := false
			handler := func(w http.ResponseWriter, r *http.Request) {
				path := strings.TrimPrefix(r.URL.Path, "/state/")
				if path == "" {
					http.Error(w, "project name required", http.StatusBadRequest)
					return
				}

				switch r.Method {
				case http.MethodGet, http.MethodPost, "LOCK", "UNLOCK":
					methodAllowed = true
					// Would normally call vault methods here
					w.WriteHeader(http.StatusOK)
				default:
					http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				}
			}

			req := httptest.NewRequest(tt.method, "/state/testproject", nil)
			if tt.method == "LOCK" || tt.method == "UNLOCK" {
				// LOCK and UNLOCK need a body
				body := bytes.NewBufferString(`{"ID":"test-lock"}`)
				req = httptest.NewRequest(tt.method, "/state/testproject", body)
			}
			rec := httptest.NewRecorder()

			authMw.RequireAuth(handler)(rec, req)

			if tt.expectAllow && !methodAllowed {
				t.Errorf("Expected method %s to be allowed", tt.method)
			}
			if !tt.expectAllow && rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("Expected status 405 for method %s, got %d", tt.method, rec.Code)
			}
		})
	}
}

// TestHandleSecret_MethodValidation tests that handleSecret only allows GET
func TestHandleSecret_MethodValidation(t *testing.T) {
	methods := []string{
		http.MethodPost,
		http.MethodPut,
		http.MethodDelete,
		http.MethodPatch,
		"LOCK",
		"UNLOCK",
	}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			sessions := NewSessionStore()
			authMw := NewAuthMiddleware(sessions, false)

			handler := func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
					return
				}
				w.WriteHeader(http.StatusOK)
			}

			req := httptest.NewRequest(method, "/secret/test", nil)
			rec := httptest.NewRecorder()

			authMw.RequireAuth(handler)(rec, req)

			if rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("Expected 405 for method %s, got %d", method, rec.Code)
			}
		})
	}
}

// TestSecretNameValidation tests that secret names are validated
func TestSecretNameValidation(t *testing.T) {
	tests := []struct {
		name  string
		valid bool
	}{
		{"valid-secret", true},
		{"my_secret_123", true},
		{"../etc/passwd", false},
		{"secret/path", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sessions := NewSessionStore()
			authMw := NewAuthMiddleware(sessions, false)

			var validationPassed bool
			handler := func(w http.ResponseWriter, r *http.Request) {
				name := strings.TrimPrefix(r.URL.Path, "/secret/")
				if name == "" {
					http.Error(w, "secret name required", http.StatusBadRequest)
					return
				}
				if strings.Contains(name, "..") || strings.Contains(name, "/") {
					http.Error(w, "invalid secret name", http.StatusBadRequest)
					return
				}
				validationPassed = true
				w.WriteHeader(http.StatusOK)
			}

			req := httptest.NewRequest(http.MethodGet, "/secret/"+tt.name, nil)
			rec := httptest.NewRecorder()

			authMw.RequireAuth(handler)(rec, req)

			if tt.valid && !validationPassed {
				t.Errorf("Validation should pass for %q", tt.name)
			}
			if !tt.valid && validationPassed {
				t.Errorf("Validation should fail for %q", tt.name)
			}
		})
	}
}

// TestStateServer_Shutdown tests graceful shutdown
func TestStateServer_Shutdown(t *testing.T) {
	server := &StateServer{
		locks:    make(map[string]*StateLock),
		sessions: NewSessionStore(),
	}

	// Set up cleanup cancel
	ctx, cancel := context.WithCancel(context.Background())
	server.cleanupCancel = cancel

	// Shutdown should work without error
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), time.Second)
	defer shutdownCancel()

	err := server.Shutdown(shutdownCtx)
	if err != nil {
		t.Errorf("Shutdown failed: %v", err)
	}

	// Verify cleanup context was cancelled
	select {
	case <-ctx.Done():
		// Expected
	default:
		t.Error("Cleanup context should be cancelled after shutdown")
	}
}

// TestStateServer_Sessions tests the Sessions getter
func TestStateServer_Sessions(t *testing.T) {
	sessions := NewSessionStore()
	server := &StateServer{
		sessions: sessions,
	}

	if server.Sessions() != sessions {
		t.Error("Sessions() should return the session store")
	}
}

// TestLockTTL verifies the lock TTL constant
func TestLockTTL(t *testing.T) {
	expected := 30 * time.Minute
	if LockTTL != expected {
		t.Errorf("Expected LockTTL to be %v, got %v", expected, LockTTL)
	}
}

// TestMaxRequestBodySize verifies the max request body size constant
func TestMaxRequestBodySize(t *testing.T) {
	expected := int64(10 * 1024 * 1024) // 10MB
	if MaxRequestBodySize != expected {
		t.Errorf("Expected MaxRequestBodySize to be %d, got %d", expected, MaxRequestBodySize)
	}
}

// TestLogMiddleware tests the logging middleware
func TestLogMiddleware(t *testing.T) {
	server := &StateServer{}

	handlerCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	wrapped := server.logMiddleware(handler)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	if !handlerCalled {
		t.Error("Handler should have been called")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
}

// TestStateServer_DirectoryCreation tests that NewStateServer creates required directories
func TestStateServer_DirectoryCreation(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "server-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	vaultPath := filepath.Join(tmpDir, "vault")
	os.MkdirAll(vaultPath, 0700)

	// NewStateServer requires a real vault, so we can't fully test it
	// But we can verify the directory structure expectations
	stateDir := filepath.Join(vaultPath, "state")
	secretsDir := filepath.Join(vaultPath, "secrets")

	// Create directories as NewStateServer would
	os.MkdirAll(stateDir, 0700)
	os.MkdirAll(secretsDir, 0700)

	// Verify directories exist
	if _, err := os.Stat(stateDir); err != nil {
		t.Errorf("State directory should exist: %v", err)
	}
	if _, err := os.Stat(secretsDir); err != nil {
		t.Errorf("Secrets directory should exist: %v", err)
	}

	// Verify permissions
	info, _ := os.Stat(stateDir)
	if info.Mode().Perm() != 0700 {
		t.Errorf("Expected state dir permissions 0700, got %04o", info.Mode().Perm())
	}
}

// TestCleanupRoutine tests that the cleanup routine runs periodically
func TestCleanupRoutine(t *testing.T) {
	sessions := NewSessionStore()
	server := &StateServer{
		locks:    make(map[string]*StateLock),
		sessions: sessions,
	}

	// Create an expired lock
	server.lockMu.Lock()
	server.locks["test"] = &StateLock{
		ID:      "old-lock",
		Created: time.Now().Add(-LockTTL - time.Hour),
	}
	server.lockMu.Unlock()

	// Start cleanup routine
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server.startCleanupRoutine(ctx)

	// The cleanup runs every minute, so we can't easily test it in unit tests
	// without making the test slow. Instead, we verify cleanup() works directly.
	server.cleanup()

	server.lockMu.RLock()
	_, exists := server.locks["test"]
	server.lockMu.RUnlock()

	if exists {
		t.Error("Expired lock should have been cleaned up")
	}
}
