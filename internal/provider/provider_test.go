package provider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	factory := New("1.0.0")
	if factory == nil {
		t.Fatal("New returned nil factory")
	}

	provider := factory()
	if provider == nil {
		t.Fatal("Factory returned nil provider")
	}

	yp, ok := provider.(*YubivaultProvider)
	if !ok {
		t.Fatal("Provider is not *YubivaultProvider")
	}

	if yp.version != "1.0.0" {
		t.Errorf("Expected version 1.0.0, got %s", yp.version)
	}
}

func TestProviderData_GetAuthToken_WithToken(t *testing.T) {
	pd := &ProviderData{
		ServerURL:    "https://localhost:8080",
		sessionToken: "test-token",
		tokenExpiry:  time.Now().Add(time.Hour),
	}

	ctx := context.Background()
	token, err := pd.GetAuthToken(ctx)
	if err != nil {
		t.Fatalf("GetAuthToken failed: %v", err)
	}

	if token != "test-token" {
		t.Errorf("Expected token 'test-token', got %q", token)
	}
}

func TestProviderData_GetAuthToken_ExpiredToken(t *testing.T) {
	pd := &ProviderData{
		ServerURL:    "https://localhost:8080",
		sessionToken: "expired-token",
		tokenExpiry:  time.Now().Add(-time.Hour), // Expired 1 hour ago
	}

	ctx := context.Background()
	token, err := pd.GetAuthToken(ctx)
	if err != nil {
		t.Fatalf("GetAuthToken failed: %v", err)
	}

	// Expired token should result in empty token
	if token != "" {
		t.Errorf("Expected empty token for expired session, got %q", token)
	}
}

func TestProviderData_GetAuthToken_NoToken(t *testing.T) {
	pd := &ProviderData{
		ServerURL: "https://localhost:8080",
	}

	ctx := context.Background()
	token, err := pd.GetAuthToken(ctx)
	if err != nil {
		t.Fatalf("GetAuthToken failed: %v", err)
	}

	if token != "" {
		t.Errorf("Expected empty token when no token set, got %q", token)
	}
}

func TestProviderData_ClearToken(t *testing.T) {
	pd := &ProviderData{
		ServerURL:    "https://localhost:8080",
		sessionToken: "test-token",
		tokenExpiry:  time.Now().Add(time.Hour),
	}

	pd.ClearToken()

	if pd.sessionToken != "" {
		t.Errorf("sessionToken should be empty after ClearToken, got %q", pd.sessionToken)
	}
	if !pd.tokenExpiry.IsZero() {
		t.Errorf("tokenExpiry should be zero after ClearToken, got %v", pd.tokenExpiry)
	}
}

func TestProviderData_GetHTTPClient_InsecureMode(t *testing.T) {
	pd := &ProviderData{
		ServerURL:          "https://localhost:8080",
		InsecureSkipVerify: true,
	}

	client, err := pd.GetHTTPClient()
	if err != nil {
		t.Fatalf("GetHTTPClient failed: %v", err)
	}

	if client == nil {
		t.Fatal("Client should not be nil")
	}

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("Transport is not *http.Transport")
	}

	if !transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be true")
	}
}

func TestProviderData_GetHTTPClient_WithCACert(t *testing.T) {
	// Create a temporary CA certificate
	tmpDir, err := os.MkdirTemp("", "provider-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	certPath := filepath.Join(tmpDir, "ca.crt")
	if err := createTestCertificate(certPath); err != nil {
		t.Fatalf("Failed to create test certificate: %v", err)
	}

	pd := &ProviderData{
		ServerURL: "https://localhost:8080",
		TLSCACert: certPath,
	}

	client, err := pd.GetHTTPClient()
	if err != nil {
		t.Fatalf("GetHTTPClient failed: %v", err)
	}

	if client == nil {
		t.Fatal("Client should not be nil")
	}

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("Transport is not *http.Transport")
	}

	if transport.TLSClientConfig.RootCAs == nil {
		t.Error("RootCAs should not be nil when CA cert is provided")
	}
}

func TestProviderData_GetHTTPClient_MissingCACert(t *testing.T) {
	pd := &ProviderData{
		ServerURL: "https://localhost:8080",
		TLSCACert: "/nonexistent/ca.crt",
	}

	_, err := pd.GetHTTPClient()
	if err == nil {
		t.Error("Expected error for missing CA cert")
	}
}

func TestProviderData_GetHTTPClient_InvalidCACert(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "provider-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create an invalid certificate file
	certPath := filepath.Join(tmpDir, "invalid.crt")
	os.WriteFile(certPath, []byte("not a valid certificate"), 0600)

	pd := &ProviderData{
		ServerURL: "https://localhost:8080",
		TLSCACert: certPath,
	}

	_, err = pd.GetHTTPClient()
	if err == nil {
		t.Error("Expected error for invalid CA cert")
	}
}

func TestProviderData_GetHTTPClient_DefaultVaultPath(t *testing.T) {
	// When no TLSCACert is set and no YUBIVAULT_PATH env var,
	// the client should fall back to system certs
	pd := &ProviderData{
		ServerURL: "https://localhost:8080",
	}

	// Clear YUBIVAULT_PATH to ensure default behavior
	os.Unsetenv("YUBIVAULT_PATH")

	client, err := pd.GetHTTPClient()
	if err != nil {
		t.Fatalf("GetHTTPClient failed: %v", err)
	}

	if client == nil {
		t.Fatal("Client should not be nil")
	}
}

func TestProviderData_GetHTTPClient_FromEnvVar(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "provider-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create TLS directory structure
	tlsDir := filepath.Join(tmpDir, "tls")
	os.MkdirAll(tlsDir, 0700)

	certPath := filepath.Join(tlsDir, "server.crt")
	if err := createTestCertificate(certPath); err != nil {
		t.Fatalf("Failed to create test certificate: %v", err)
	}

	// Set YUBIVAULT_PATH environment variable
	oldPath := os.Getenv("YUBIVAULT_PATH")
	os.Setenv("YUBIVAULT_PATH", tmpDir)
	defer os.Setenv("YUBIVAULT_PATH", oldPath)

	pd := &ProviderData{
		ServerURL: "https://localhost:8080",
		// TLSCACert not set, should use YUBIVAULT_PATH
	}

	client, err := pd.GetHTTPClient()
	if err != nil {
		t.Fatalf("GetHTTPClient failed: %v", err)
	}

	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil || transport.TLSClientConfig.RootCAs == nil {
		t.Error("Should have loaded CA from YUBIVAULT_PATH")
	}
}

func TestProviderData_Concurrent(t *testing.T) {
	pd := &ProviderData{
		ServerURL:    "https://localhost:8080",
		sessionToken: "test-token",
		tokenExpiry:  time.Now().Add(time.Hour),
	}

	var wg sync.WaitGroup
	ctx := context.Background()

	// Concurrently get and clear tokens
	for i := 0; i < 100; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			pd.GetAuthToken(ctx)
		}()
		go func() {
			defer wg.Done()
			pd.ClearToken()
		}()
	}

	wg.Wait()
}

// Helper function to create a test certificate
func createTestCertificate(path string) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return os.WriteFile(path, certPEM, 0600)
}

// TestProviderData_TokenCaching verifies token caching behavior
func TestProviderData_TokenCaching(t *testing.T) {
	pd := &ProviderData{
		ServerURL:    "https://localhost:8080",
		sessionToken: "cached-token",
		tokenExpiry:  time.Now().Add(time.Hour),
	}

	ctx := context.Background()

	// First call should return cached token
	token1, _ := pd.GetAuthToken(ctx)
	if token1 != "cached-token" {
		t.Errorf("Expected cached-token, got %q", token1)
	}

	// Second call should return same cached token
	token2, _ := pd.GetAuthToken(ctx)
	if token2 != token1 {
		t.Error("Token should be cached across calls")
	}

	// Clear token
	pd.ClearToken()

	// After clearing, should get empty token
	token3, _ := pd.GetAuthToken(ctx)
	if token3 != "" {
		t.Errorf("Expected empty token after clear, got %q", token3)
	}
}

// TestYubivaultProvider_DataSources tests that DataSources returns expected sources
func TestYubivaultProvider_DataSources(t *testing.T) {
	provider := &YubivaultProvider{version: "1.0.0"}
	ctx := context.Background()

	dataSources := provider.DataSources(ctx)
	if len(dataSources) != 1 {
		t.Errorf("Expected 1 data source, got %d", len(dataSources))
	}

	// Verify it creates a SecretDataSource
	ds := dataSources[0]()
	if _, ok := ds.(*SecretDataSource); !ok {
		t.Error("Data source should be *SecretDataSource")
	}
}

// TestYubivaultProvider_Resources tests that Resources returns empty slice
func TestYubivaultProvider_Resources(t *testing.T) {
	provider := &YubivaultProvider{version: "1.0.0"}
	ctx := context.Background()

	resources := provider.Resources(ctx)
	if len(resources) != 0 {
		t.Errorf("Expected 0 resources, got %d", len(resources))
	}
}

// Test HTTP client with a real server
func TestProviderData_HTTPClient_RealRequest(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer server.Close()

	pd := &ProviderData{
		ServerURL:          server.URL,
		InsecureSkipVerify: true, // Test server uses self-signed cert
	}

	client, err := pd.GetHTTPClient()
	if err != nil {
		t.Fatalf("GetHTTPClient failed: %v", err)
	}

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}
