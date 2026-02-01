package server

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

// MockEncrypter implements the Encrypter interface for testing
type MockEncrypter struct {
	encryptedData map[string][]byte
	encryptErr    error
	decryptErr    error
}

func NewMockEncrypter() *MockEncrypter {
	return &MockEncrypter{
		encryptedData: make(map[string][]byte),
	}
}

func (m *MockEncrypter) EncryptSecret(plaintext []byte, name string) ([]byte, error) {
	if m.encryptErr != nil {
		return nil, m.encryptErr
	}
	// Simple "encryption": just store the data with a prefix
	encrypted := append([]byte("ENC:"+name+":"), plaintext...)
	m.encryptedData[name] = encrypted
	return encrypted, nil
}

func (m *MockEncrypter) DecryptSecret(ciphertext []byte, name string) ([]byte, error) {
	if m.decryptErr != nil {
		return nil, m.decryptErr
	}
	// Simple "decryption": strip the prefix
	prefix := []byte("ENC:" + name + ":")
	if len(ciphertext) < len(prefix) {
		return nil, os.ErrInvalid
	}
	return ciphertext[len(prefix):], nil
}

func TestGenerateSelfSignedCert(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "tls-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	certPath := filepath.Join(tmpDir, "server.crt")
	keyPath := filepath.Join(tmpDir, "server.key.enc")

	encrypter := NewMockEncrypter()

	err = GenerateSelfSignedCert(certPath, keyPath, encrypter)
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}

	// Verify certificate file exists and is valid PEM
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("Failed to read certificate: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("Failed to decode certificate PEM")
	}
	if block.Type != "CERTIFICATE" {
		t.Errorf("Expected PEM type CERTIFICATE, got %s", block.Type)
	}

	// Parse and validate certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	// Verify certificate properties
	if cert.Subject.CommonName != "yubivault" {
		t.Errorf("Expected CN=yubivault, got CN=%s", cert.Subject.CommonName)
	}
	if len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != "YubiVault Self-Signed" {
		t.Errorf("Unexpected organization: %v", cert.Subject.Organization)
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "localhost" {
		t.Errorf("Unexpected DNS names: %v", cert.DNSNames)
	}
	if len(cert.IPAddresses) != 2 {
		t.Errorf("Expected 2 IP addresses (127.0.0.1, ::1), got %d", len(cert.IPAddresses))
	}

	// Verify encrypted key file exists
	encKeyData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("Failed to read encrypted key: %v", err)
	}
	if len(encKeyData) == 0 {
		t.Error("Encrypted key file is empty")
	}

	// Verify key was encrypted (should have our mock prefix)
	if len(encrypter.encryptedData) != 1 {
		t.Errorf("Expected 1 encrypted item, got %d", len(encrypter.encryptedData))
	}
	if _, exists := encrypter.encryptedData[TLSKeyAAD]; !exists {
		t.Errorf("Key not encrypted with expected AAD: %s", TLSKeyAAD)
	}
}

func TestGenerateSelfSignedCert_DirectoryCreation(t *testing.T) {
	// Create temp directory with nested path that doesn't exist
	tmpDir, err := os.MkdirTemp("", "tls-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	nestedDir := filepath.Join(tmpDir, "nested", "tls")
	certPath := filepath.Join(nestedDir, "server.crt")
	keyPath := filepath.Join(nestedDir, "server.key.enc")

	encrypter := NewMockEncrypter()

	err = GenerateSelfSignedCert(certPath, keyPath, encrypter)
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed to create nested directory: %v", err)
	}

	// Verify directory was created
	info, err := os.Stat(nestedDir)
	if err != nil {
		t.Fatalf("Nested directory not created: %v", err)
	}
	if !info.IsDir() {
		t.Error("Expected directory, got file")
	}
	// Verify permissions (0700)
	if info.Mode().Perm() != 0700 {
		t.Errorf("Expected permissions 0700, got %04o", info.Mode().Perm())
	}
}

func TestLoadTLSKeyPair(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "tls-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	certPath := filepath.Join(tmpDir, "server.crt")
	keyPath := filepath.Join(tmpDir, "server.key.enc")

	encrypter := NewMockEncrypter()

	// Generate a certificate first
	err = GenerateSelfSignedCert(certPath, keyPath, encrypter)
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}

	// Now load it back
	cert, err := LoadTLSKeyPair(certPath, keyPath, encrypter)
	if err != nil {
		t.Fatalf("LoadTLSKeyPair failed: %v", err)
	}

	// Verify we got a valid certificate
	if len(cert.Certificate) == 0 {
		t.Error("No certificates loaded")
	}
	if cert.PrivateKey == nil {
		t.Error("Private key is nil")
	}
}

func TestLoadTLSKeyPair_MissingCert(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tls-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	encrypter := NewMockEncrypter()

	_, err = LoadTLSKeyPair(
		filepath.Join(tmpDir, "nonexistent.crt"),
		filepath.Join(tmpDir, "server.key.enc"),
		encrypter,
	)
	if err == nil {
		t.Error("Expected error for missing certificate")
	}
}

func TestLoadTLSKeyPair_MissingKey(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tls-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	certPath := filepath.Join(tmpDir, "server.crt")
	keyPath := filepath.Join(tmpDir, "server.key.enc")

	encrypter := NewMockEncrypter()

	// Generate cert only
	err = GenerateSelfSignedCert(certPath, keyPath, encrypter)
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}

	// Remove the key file
	os.Remove(keyPath)

	_, err = LoadTLSKeyPair(certPath, keyPath, encrypter)
	if err == nil {
		t.Error("Expected error for missing key")
	}
}

func TestGetCertFingerprint(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tls-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	certPath := filepath.Join(tmpDir, "server.crt")
	keyPath := filepath.Join(tmpDir, "server.key.enc")

	encrypter := NewMockEncrypter()

	err = GenerateSelfSignedCert(certPath, keyPath, encrypter)
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}

	fingerprint, err := GetCertFingerprint(certPath)
	if err != nil {
		t.Fatalf("GetCertFingerprint failed: %v", err)
	}

	// SHA256 fingerprint should be 64 hex characters
	if len(fingerprint) != 64 {
		t.Errorf("Expected fingerprint length 64, got %d", len(fingerprint))
	}

	// Verify fingerprint is consistent
	fingerprint2, _ := GetCertFingerprint(certPath)
	if fingerprint != fingerprint2 {
		t.Error("Fingerprint should be consistent across calls")
	}
}

func TestGetCertFingerprint_InvalidFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tls-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Test with non-existent file
	_, err = GetCertFingerprint(filepath.Join(tmpDir, "nonexistent.crt"))
	if err == nil {
		t.Error("Expected error for non-existent file")
	}

	// Test with invalid PEM
	invalidPath := filepath.Join(tmpDir, "invalid.crt")
	os.WriteFile(invalidPath, []byte("not a valid PEM"), 0600)
	_, err = GetCertFingerprint(invalidPath)
	if err == nil {
		t.Error("Expected error for invalid PEM")
	}
}

func TestImportTLSCert(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tls-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// First, generate a certificate to use as source
	srcCertPath := filepath.Join(tmpDir, "src.crt")
	srcKeyPath := filepath.Join(tmpDir, "src.key")

	encrypter := NewMockEncrypter()

	// Generate source cert (we'll need to decrypt the key for import)
	encSrcKeyPath := filepath.Join(tmpDir, "src.key.enc")
	err = GenerateSelfSignedCert(srcCertPath, encSrcKeyPath, encrypter)
	if err != nil {
		t.Fatalf("Failed to generate source cert: %v", err)
	}

	// Decrypt the key to create an unencrypted source key
	encKeyData, _ := os.ReadFile(encSrcKeyPath)
	keyData, _ := encrypter.DecryptSecret(encKeyData, TLSKeyAAD)
	os.WriteFile(srcKeyPath, keyData, 0600)

	// Now import to a new location
	destCertPath := filepath.Join(tmpDir, "dest", "server.crt")
	destKeyPath := filepath.Join(tmpDir, "dest", "server.key.enc")

	err = ImportTLSCert(srcCertPath, srcKeyPath, destCertPath, destKeyPath, encrypter)
	if err != nil {
		t.Fatalf("ImportTLSCert failed: %v", err)
	}

	// Verify destination files exist
	if _, err := os.Stat(destCertPath); err != nil {
		t.Errorf("Destination cert not created: %v", err)
	}
	if _, err := os.Stat(destKeyPath); err != nil {
		t.Errorf("Destination key not created: %v", err)
	}

	// Verify we can load the imported cert
	cert, err := LoadTLSKeyPair(destCertPath, destKeyPath, encrypter)
	if err != nil {
		t.Fatalf("Failed to load imported cert: %v", err)
	}
	if cert.PrivateKey == nil {
		t.Error("Imported cert has no private key")
	}
}

func TestImportTLSCert_InvalidCertFormat(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tls-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	encrypter := NewMockEncrypter()

	// Create invalid cert file
	invalidCert := filepath.Join(tmpDir, "invalid.crt")
	os.WriteFile(invalidCert, []byte("not a certificate"), 0600)

	validKey := filepath.Join(tmpDir, "valid.key")
	os.WriteFile(validKey, []byte("-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----"), 0600)

	err = ImportTLSCert(invalidCert, validKey,
		filepath.Join(tmpDir, "dest.crt"),
		filepath.Join(tmpDir, "dest.key.enc"),
		encrypter)

	if err == nil {
		t.Error("Expected error for invalid certificate format")
	}
}

func TestImportTLSCert_InvalidKeyFormat(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tls-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	encrypter := NewMockEncrypter()

	// Generate valid cert
	srcCertPath := filepath.Join(tmpDir, "src.crt")
	srcKeyPath := filepath.Join(tmpDir, "src.key.enc")
	GenerateSelfSignedCert(srcCertPath, srcKeyPath, encrypter)

	// Create invalid key file
	invalidKey := filepath.Join(tmpDir, "invalid.key")
	os.WriteFile(invalidKey, []byte("not a key"), 0600)

	err = ImportTLSCert(srcCertPath, invalidKey,
		filepath.Join(tmpDir, "dest.crt"),
		filepath.Join(tmpDir, "dest.key.enc"),
		encrypter)

	if err == nil {
		t.Error("Expected error for invalid key format")
	}
}

func TestImportTLSCert_MismatchedKeyAndCert(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tls-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	encrypter := NewMockEncrypter()

	// Generate two different certs
	cert1Path := filepath.Join(tmpDir, "cert1.crt")
	key1Path := filepath.Join(tmpDir, "key1.enc")
	GenerateSelfSignedCert(cert1Path, key1Path, encrypter)

	cert2Path := filepath.Join(tmpDir, "cert2.crt")
	key2Path := filepath.Join(tmpDir, "key2.enc")
	GenerateSelfSignedCert(cert2Path, key2Path, encrypter)

	// Decrypt key2 to get unencrypted key
	encKey2, _ := os.ReadFile(key2Path)
	key2Data, _ := encrypter.DecryptSecret(encKey2, TLSKeyAAD)
	unencKey2 := filepath.Join(tmpDir, "key2.pem")
	os.WriteFile(unencKey2, key2Data, 0600)

	// Try to import cert1 with key2
	err = ImportTLSCert(cert1Path, unencKey2,
		filepath.Join(tmpDir, "dest.crt"),
		filepath.Join(tmpDir, "dest.key.enc"),
		encrypter)

	if err == nil {
		t.Error("Expected error for mismatched cert and key")
	}
}

func TestCertificateValidity(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tls-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	certPath := filepath.Join(tmpDir, "server.crt")
	keyPath := filepath.Join(tmpDir, "server.key.enc")

	encrypter := NewMockEncrypter()

	err = GenerateSelfSignedCert(certPath, keyPath, encrypter)
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}

	// Parse certificate to check validity period
	certPEM, _ := os.ReadFile(certPath)
	block, _ := pem.Decode(certPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)

	// Certificate should be valid now
	if cert.NotBefore.After(cert.NotAfter) {
		t.Error("NotBefore should be before NotAfter")
	}

	// Certificate should be valid for about 1 year (365 days)
	validityDuration := cert.NotAfter.Sub(cert.NotBefore)
	expectedDuration := 365 * 24 * 60 * 60 // 365 days in seconds
	actualSeconds := int(validityDuration.Seconds())

	// Allow 1 second tolerance for test execution time
	if actualSeconds < expectedDuration-1 || actualSeconds > expectedDuration+1 {
		t.Errorf("Expected validity ~365 days, got %v", validityDuration)
	}
}

func TestCertificateKeyUsage(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tls-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	certPath := filepath.Join(tmpDir, "server.crt")
	keyPath := filepath.Join(tmpDir, "server.key.enc")

	encrypter := NewMockEncrypter()

	err = GenerateSelfSignedCert(certPath, keyPath, encrypter)
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}

	certPEM, _ := os.ReadFile(certPath)
	block, _ := pem.Decode(certPEM)
	cert, _ := x509.ParseCertificate(block.Bytes)

	// Check key usage
	expectedKeyUsage := x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	if cert.KeyUsage != expectedKeyUsage {
		t.Errorf("Expected key usage %v, got %v", expectedKeyUsage, cert.KeyUsage)
	}

	// Check extended key usage
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Errorf("Expected ExtKeyUsageServerAuth, got %v", cert.ExtKeyUsage)
	}
}
