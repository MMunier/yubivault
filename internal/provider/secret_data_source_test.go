package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewSecretDataSource(t *testing.T) {
	ds := NewSecretDataSource()
	if ds == nil {
		t.Fatal("NewSecretDataSource returned nil")
	}

	sds, ok := ds.(*SecretDataSource)
	if !ok {
		t.Fatal("Data source is not *SecretDataSource")
	}

	// providerData should be nil before Configure is called
	if sds.providerData != nil {
		t.Error("providerData should be nil before Configure")
	}
}

func TestSecretDataSource_FetchSecret_Success(t *testing.T) {
	// Create a test server that returns a secret
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request
		if r.URL.Path != "/secret/test-secret" {
			t.Errorf("Expected path /secret/test-secret, got %s", r.URL.Path)
		}
		if r.Method != http.MethodGet {
			t.Errorf("Expected GET method, got %s", r.Method)
		}

		// Check for Bearer token
		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer test-token" {
			t.Errorf("Expected Bearer test-token, got %s", authHeader)
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("secret-value"))
	}))
	defer server.Close()

	pd := &ProviderData{
		ServerURL:          server.URL,
		InsecureSkipVerify: true,
		sessionToken:       "test-token",
		tokenExpiry:        time.Now().Add(time.Hour),
	}

	ds := &SecretDataSource{providerData: pd}

	ctx := context.Background()
	value, err := ds.fetchSecret(ctx, "test-secret", "test-token")
	if err != nil {
		t.Fatalf("fetchSecret failed: %v", err)
	}

	if string(value) != "secret-value" {
		t.Errorf("Expected 'secret-value', got %q", string(value))
	}
}

func TestSecretDataSource_FetchSecret_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "secret not found", http.StatusNotFound)
	}))
	defer server.Close()

	pd := &ProviderData{
		ServerURL:          server.URL,
		InsecureSkipVerify: true,
	}

	ds := &SecretDataSource{providerData: pd}

	ctx := context.Background()
	_, err := ds.fetchSecret(ctx, "nonexistent", "")
	if err == nil {
		t.Error("Expected error for not found secret")
	}
}

func TestSecretDataSource_FetchSecret_Unauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer server.Close()

	pd := &ProviderData{
		ServerURL:          server.URL,
		InsecureSkipVerify: true,
	}

	ds := &SecretDataSource{providerData: pd}

	ctx := context.Background()
	_, err := ds.fetchSecret(ctx, "test-secret", "")
	if err == nil {
		t.Error("Expected error for unauthorized request")
	}

	// Verify it's an unauthorized error
	if !isUnauthorizedError(err) {
		t.Error("Error should be unauthorized error")
	}
}

func TestSecretDataSource_FetchSecret_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer server.Close()

	pd := &ProviderData{
		ServerURL:          server.URL,
		InsecureSkipVerify: true,
	}

	ds := &SecretDataSource{providerData: pd}

	ctx := context.Background()
	_, err := ds.fetchSecret(ctx, "test-secret", "")
	if err == nil {
		t.Error("Expected error for server error")
	}
}

func TestSecretDataSource_FetchSecret_NoToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify no auth header when no token
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			t.Errorf("Expected no auth header, got %s", authHeader)
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("public-secret"))
	}))
	defer server.Close()

	pd := &ProviderData{
		ServerURL:          server.URL,
		InsecureSkipVerify: true,
	}

	ds := &SecretDataSource{providerData: pd}

	ctx := context.Background()
	value, err := ds.fetchSecret(ctx, "test-secret", "")
	if err != nil {
		t.Fatalf("fetchSecret failed: %v", err)
	}

	if string(value) != "public-secret" {
		t.Errorf("Expected 'public-secret', got %q", string(value))
	}
}

func TestSecretDataSource_FetchSecret_ConnectionError(t *testing.T) {
	pd := &ProviderData{
		ServerURL:          "https://localhost:99999", // Invalid port
		InsecureSkipVerify: true,
	}

	ds := &SecretDataSource{providerData: pd}

	ctx := context.Background()
	_, err := ds.fetchSecret(ctx, "test-secret", "")
	if err == nil {
		t.Error("Expected error for connection failure")
	}
}

func TestSecretDataSource_FetchSecret_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow response
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	pd := &ProviderData{
		ServerURL:          server.URL,
		InsecureSkipVerify: true,
	}

	ds := &SecretDataSource{providerData: pd}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := ds.fetchSecret(ctx, "test-secret", "")
	if err == nil {
		t.Error("Expected error for cancelled context")
	}
}

func TestIsUnauthorizedError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"unauthorized error", &unauthorizedError{message: "test"}, true},
		{"generic error", context.Canceled, false},
		{"nil error", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isUnauthorizedError(tt.err)
			if result != tt.expected {
				t.Errorf("isUnauthorizedError(%v) = %v, want %v", tt.err, result, tt.expected)
			}
		})
	}
}

func TestUnauthorizedError_Error(t *testing.T) {
	err := &unauthorizedError{message: "test message"}
	if err.Error() != "test message" {
		t.Errorf("Expected 'test message', got %q", err.Error())
	}
}

func TestSecretDataSource_FetchSecret_LargeResponse(t *testing.T) {
	// Create a large response
	largeData := make([]byte, 1024*1024) // 1MB
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(largeData)
	}))
	defer server.Close()

	pd := &ProviderData{
		ServerURL:          server.URL,
		InsecureSkipVerify: true,
	}

	ds := &SecretDataSource{providerData: pd}

	ctx := context.Background()
	value, err := ds.fetchSecret(ctx, "large-secret", "")
	if err != nil {
		t.Fatalf("fetchSecret failed: %v", err)
	}

	if len(value) != len(largeData) {
		t.Errorf("Expected %d bytes, got %d", len(largeData), len(value))
	}
}

func TestSecretDataSource_FetchSecret_EmptyResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Don't write anything
	}))
	defer server.Close()

	pd := &ProviderData{
		ServerURL:          server.URL,
		InsecureSkipVerify: true,
	}

	ds := &SecretDataSource{providerData: pd}

	ctx := context.Background()
	value, err := ds.fetchSecret(ctx, "empty-secret", "")
	if err != nil {
		t.Fatalf("fetchSecret failed: %v", err)
	}

	if len(value) != 0 {
		t.Errorf("Expected empty response, got %d bytes", len(value))
	}
}

func TestSecretDataSource_FetchSecret_SpecialCharacters(t *testing.T) {
	secretValue := "password with special chars: !@#$%^&*()_+{}|:\"<>?`~"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(secretValue))
	}))
	defer server.Close()

	pd := &ProviderData{
		ServerURL:          server.URL,
		InsecureSkipVerify: true,
	}

	ds := &SecretDataSource{providerData: pd}

	ctx := context.Background()
	value, err := ds.fetchSecret(ctx, "special-secret", "")
	if err != nil {
		t.Fatalf("fetchSecret failed: %v", err)
	}

	if string(value) != secretValue {
		t.Errorf("Expected %q, got %q", secretValue, string(value))
	}
}

func TestSecretDataSource_FetchSecret_BinaryData(t *testing.T) {
	// Binary data with null bytes
	binaryData := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0x00, 0x10}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(binaryData)
	}))
	defer server.Close()

	pd := &ProviderData{
		ServerURL:          server.URL,
		InsecureSkipVerify: true,
	}

	ds := &SecretDataSource{providerData: pd}

	ctx := context.Background()
	value, err := ds.fetchSecret(ctx, "binary-secret", "")
	if err != nil {
		t.Fatalf("fetchSecret failed: %v", err)
	}

	if len(value) != len(binaryData) {
		t.Errorf("Expected %d bytes, got %d", len(binaryData), len(value))
	}

	for i, b := range value {
		if b != binaryData[i] {
			t.Errorf("Byte %d mismatch: got %d, want %d", i, b, binaryData[i])
		}
	}
}

// Test retry logic with token expiry
func TestSecretDataSource_FetchSecret_RetryOnUnauthorized(t *testing.T) {
	callCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			// First call returns unauthorized
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		// Second call succeeds
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("secret-after-retry"))
	}))
	defer server.Close()

	pd := &ProviderData{
		ServerURL:          server.URL,
		InsecureSkipVerify: true,
		sessionToken:       "old-token",
		tokenExpiry:        time.Now().Add(time.Hour),
	}

	ds := &SecretDataSource{providerData: pd}

	// First call should fail with unauthorized
	ctx := context.Background()
	_, err := ds.fetchSecret(ctx, "test-secret", "old-token")
	if err == nil {
		t.Fatal("First call should fail with unauthorized")
	}

	if !isUnauthorizedError(err) {
		t.Fatal("Error should be unauthorized")
	}

	// Clear token (simulating what Read() does)
	pd.ClearToken()

	// Second call should succeed
	value, err := ds.fetchSecret(ctx, "test-secret", "")
	if err != nil {
		t.Fatalf("Second call should succeed: %v", err)
	}

	if string(value) != "secret-after-retry" {
		t.Errorf("Expected 'secret-after-retry', got %q", string(value))
	}
}

// Test with various HTTP status codes
func TestSecretDataSource_FetchSecret_HTTPStatusCodes(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		body      string
		wantError bool
	}{
		{"200 OK", http.StatusOK, "success", false},
		{"201 Created", http.StatusCreated, "created", true}, // Only 200 is success
		{"400 Bad Request", http.StatusBadRequest, "bad request", true},
		{"403 Forbidden", http.StatusForbidden, "forbidden", true},
		{"500 Internal Server Error", http.StatusInternalServerError, "error", true},
		{"502 Bad Gateway", http.StatusBadGateway, "bad gateway", true},
		{"503 Service Unavailable", http.StatusServiceUnavailable, "unavailable", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				w.Write([]byte(tt.body))
			}))
			defer server.Close()

			pd := &ProviderData{
				ServerURL:          server.URL,
				InsecureSkipVerify: true,
			}

			ds := &SecretDataSource{providerData: pd}

			ctx := context.Background()
			_, err := ds.fetchSecret(ctx, "test-secret", "")

			if tt.wantError && err == nil {
				t.Error("Expected error")
			}
			if !tt.wantError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}
