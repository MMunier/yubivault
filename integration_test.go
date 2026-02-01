//go:build integration

// Integration tests that require YubiKey hardware.
//
// Run with:
//
//	make integration_test
//
// Or using environment variable:
//
//	YUBIKEY_PIN=123456 go test -tags=integration -v ./...
//
// Or using a file:
//
//	echo -n "123456" > ~/.yubikey-test-pin
//	chmod 600 ~/.yubikey-test-pin
//	YUBIKEY_PIN_FILE=~/.yubikey-test-pin go test -tags=integration -v ./...
//
// These tests may require YubiKey touch.
// They are designed to be minimal to avoid excessive user interaction.

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-piv/piv-go/v2/piv"
	"github.com/mmunier/terraform-provider-yubivault/internal/server"
	"github.com/mmunier/terraform-provider-yubivault/internal/yubikey"
)

var (
	// cachedPIN stores the PIN to avoid re-reading
	cachedPIN  string
	pinOnce    sync.Once
	pinErr     error
	skipReason string
)

// getTestPIN returns the YubiKey PIN for tests.
// It checks (in order): YUBIKEY_PIN env var, YUBIKEY_PIN_FILE env var.
func getTestPIN(t *testing.T) string {
	pinOnce.Do(func() {
		// Check YUBIKEY_PIN environment variable
		if pin := os.Getenv("YUBIKEY_PIN"); pin != "" {
			cachedPIN = pin
			return
		}

		// Check YUBIKEY_PIN_FILE environment variable
		if pinFile := os.Getenv("YUBIKEY_PIN_FILE"); pinFile != "" {
			// Expand ~ to home directory
			if strings.HasPrefix(pinFile, "~/") {
				home, err := os.UserHomeDir()
				if err == nil {
					pinFile = filepath.Join(home, pinFile[2:])
				}
			}

			pinBytes, err := os.ReadFile(pinFile)
			if err != nil {
				pinErr = fmt.Errorf("failed to read PIN from %s: %w", pinFile, err)
				return
			}
			cachedPIN = strings.TrimSpace(string(pinBytes))
			return
		}

		skipReason = `YubiKey PIN not provided. Set one of:
  YUBIKEY_PIN=123456 go test -tags=integration -v ./...
  YUBIKEY_PIN_FILE=~/.yubikey-test-pin go test -tags=integration -v ./...`
	})

	if skipReason != "" {
		t.Skip(skipReason)
	}
	if pinErr != nil {
		t.Fatalf("PIN error: %v", pinErr)
	}

	return cachedPIN
}

// getTestSlot returns the PIV slot to use for testing
func getTestSlot() string {
	if slot := os.Getenv("YUBIVAULT_SLOT"); slot != "" {
		return slot
	}
	return "9d"
}

// initTestVault initializes a test vault with a temporary directory and returns the vault.
// It handles the full initialization process including creating the master key.
// The caller is responsible for calling vault.Close() and removing the temporary directory.
func initTestVault(t *testing.T, pin string, slot string) (*yubikey.Vault, string, func()) {
	// Create temp vault directory
	tmpDir, err := os.MkdirTemp("", "integration-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	vaultPath := filepath.Join(tmpDir, "vault")
	if err := os.MkdirAll(vaultPath, 0700); err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("Failed to create vault dir: %v", err)
	}

	// Open YubiKey to get public key for initialization
	cards, err := piv.Cards()
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("Failed to enumerate cards: %v", err)
	}
	if len(cards) == 0 {
		os.RemoveAll(tmpDir)
		t.Fatalf("No YubiKey found, integration test failed (or no yubikey present)")
	}

	// Parse slot
	pivSlot, err := yubikey.ParseSlot(slot)
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("Failed to parse slot: %v", err)
	}

	// We need to temporarily open the YubiKey to get the certificate for initialization
	yk, err := piv.Open(cards[0])
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("Failed to open YubiKey: %v", err)
	}

	cert, err := yk.Certificate(pivSlot)
	if err != nil {
		yk.Close()
		os.RemoveAll(tmpDir)
		t.Fatalf("Failed to get certificate: %v", err)
	}

	// Generate master key
	if err := yubikey.GenerateMasterKey(vaultPath, cert.PublicKey); err != nil {
		yk.Close()
		os.RemoveAll(tmpDir)
		t.Fatalf("Failed to generate master key: %v", err)
	}

	// Close the temporary YubiKey connection
	yk.Close()

	// Now open the vault properly with NewVault
	t.Log("Opening vault (may require touch)...")
	vault, err := yubikey.NewVault(vaultPath, slot, pin)
	if err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("Failed to create vault: %v", err)
	}

	cleanup := func() {
		vault.Close()
		os.RemoveAll(tmpDir)
	}

	return vault, vaultPath, cleanup
}

// TestIntegration_VaultEncryptDecrypt tests the full encrypt/decrypt cycle
// with a real YubiKey.
func TestIntegration_VaultEncryptDecrypt(t *testing.T) {
	pin := getTestPIN(t)
	slot := getTestSlot()

	vault, _, cleanup := initTestVault(t, pin, slot)
	defer cleanup()

	// Test encrypt/decrypt cycle
	testCases := []struct {
		name      string
		plaintext string
	}{
		{"simple", "hello world"},
		{"empty", ""},
		{"special-chars", "p@ssw0rd!#$%^&*()"},
		{"unicode", "Hello 世界 🌍"},
		{"multiline", "line1\nline2\nline3"},
		{"large", string(make([]byte, 10000))}, // 10KB
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			secretName := "secret:" + tc.name

			// Encrypt
			encrypted, err := vault.EncryptSecret([]byte(tc.plaintext), secretName)
			if err != nil {
				t.Fatalf("EncryptSecret failed: %v", err)
			}

			// Decrypt
			decrypted, err := vault.DecryptSecret(encrypted, secretName)
			if err != nil {
				t.Fatalf("DecryptSecret failed: %v", err)
			}

			if string(decrypted) != tc.plaintext {
				t.Errorf("Decrypted value mismatch: got %q, want %q", string(decrypted), tc.plaintext)
			}
		})
	}
}

// TestIntegration_VaultAADProtection tests that AAD protects against substitution attacks
func TestIntegration_VaultAADProtection(t *testing.T) {
	pin := getTestPIN(t)
	slot := getTestSlot()

	vault, _, cleanup := initTestVault(t, pin, slot)
	defer cleanup()

	// Encrypt with one name
	plaintext := []byte("sensitive data")
	encrypted, err := vault.EncryptSecret(plaintext, "secret:original")
	if err != nil {
		t.Fatalf("EncryptSecret failed: %v", err)
	}

	// Try to decrypt with a different name - should fail
	_, err = vault.DecryptSecret(encrypted, "secret:different")
	if err == nil {
		t.Error("Decryption should fail with different AAD")
	}

	// Decrypt with correct name - should succeed
	decrypted, err := vault.DecryptSecret(encrypted, "secret:original")
	if err != nil {
		t.Fatalf("DecryptSecret with correct AAD failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Error("Decrypted value mismatch")
	}
}

// TestIntegration_ServerWithRealVault tests the HTTP server with a real vault
func TestIntegration_ServerWithRealVault(t *testing.T) {
	pin := getTestPIN(t)
	slot := getTestSlot()

	vault, vaultPath, cleanup := initTestVault(t, pin, slot)
	defer cleanup()

	// Create secrets directory for this test
	if err := os.MkdirAll(filepath.Join(vaultPath, "secrets"), 0700); err != nil {
		t.Fatalf("Failed to create secrets dir: %v", err)
	}

	// Create a secret file
	secretName := "test-secret"
	secretValue := "super-secret-value"
	encrypted, err := vault.EncryptSecret([]byte(secretValue), "secret:"+secretName)
	if err != nil {
		t.Fatalf("Failed to encrypt secret: %v", err)
	}
	secretPath := filepath.Join(vaultPath, "secrets", secretName+".enc")
	if err := os.WriteFile(secretPath, encrypted, 0600); err != nil {
		t.Fatalf("Failed to write secret file: %v", err)
	}

	// Create server
	stateServer, err := server.NewStateServer(vault, vaultPath, true)
	if err != nil {
		t.Fatalf("Failed to create state server: %v", err)
	}

	// Create pre-shared token
	token, err := stateServer.Sessions().CreatePresharedToken()
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Start server on random port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}

	ready := make(chan struct{})
	serverErr := make(chan error, 1)

	go func() {
		err := stateServer.StartWithListener(listener, "", "", ready)
		if err != http.ErrServerClosed {
			serverErr <- err
		}
	}()

	// Wait for server to be ready
	select {
	case <-ready:
		t.Log("Server is ready")
	case err := <-serverErr:
		t.Fatalf("Server failed to start: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("Timeout waiting for server to start")
	}

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		stateServer.Shutdown(ctx)
	}()

	// Create HTTP client that trusts self-signed cert
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	// Test retrieving the secret
	addr := listener.Addr().String()
	url := fmt.Sprintf("https://%s/secret/%s", addr, secretName)

	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected 200, got %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	if string(body) != secretValue {
		t.Errorf("Expected %q, got %q", secretValue, string(body))
	}

	t.Log("Secret retrieval successful!")
}

// TestIntegration_StateStorage tests Terraform state storage with real vault
func TestIntegration_StateStorage(t *testing.T) {
	pin := getTestPIN(t)
	slot := getTestSlot()

	vault, vaultPath, cleanup := initTestVault(t, pin, slot)
	defer cleanup()

	stateServer, err := server.NewStateServer(vault, vaultPath, true)
	if err != nil {
		t.Fatalf("Failed to create state server: %v", err)
	}

	token, err := stateServer.Sessions().CreatePresharedToken()
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}

	ready := make(chan struct{})
	go func() {
		stateServer.StartWithListener(listener, "", "", ready)
	}()
	<-ready

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		stateServer.Shutdown(ctx)
	}()

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	addr := listener.Addr().String()
	projectName := "test-project"

	// Test state lifecycle: GET (empty) -> POST -> GET -> POST (update) -> GET
	stateURL := fmt.Sprintf("https://%s/state/%s", addr, projectName)

	// 1. GET empty state
	req, _ := http.NewRequest(http.MethodGet, stateURL, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET empty state failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 for empty state, got %d", resp.StatusCode)
	}

	// 2. POST new state
	stateV1 := `{"version": 4, "terraform_version": "1.0.0", "serial": 1}`
	req, _ = http.NewRequest(http.MethodPost, stateURL, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Body = io.NopCloser(stringReader(stateV1))
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("POST state failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 for POST state, got %d", resp.StatusCode)
	}

	// 3. GET state
	req, _ = http.NewRequest(http.MethodGet, stateURL, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("GET state failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != stateV1 {
		t.Errorf("State mismatch: got %q, want %q", string(body), stateV1)
	}

	t.Log("State storage test successful!")
}

// stringReader is a helper for creating io.Reader from string
type stringReader_ struct {
	s string
	i int
}

func (r *stringReader_) Read(b []byte) (n int, err error) {
	if r.i >= len(r.s) {
		return 0, io.EOF
	}
	n = copy(b, r.s[r.i:])
	r.i += n
	return
}

func stringReader(s string) io.Reader {
	return &stringReader_{s: s}
}
