package server

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// TLSKeyAAD is the Additional Authenticated Data used for TLS private key encryption
const TLSKeyAAD = "tls:server-key"

// GenerateSelfSignedCert creates a new self-signed certificate and private key.
// The certificate is written to certPath unencrypted (it's public).
// The private key is encrypted using the provided encrypter and written to keyPath.
func GenerateSelfSignedCert(certPath, keyPath string, encrypter Encrypter) error {
	// Generate RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour) // Valid for 1 year

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "yubivault",
			Organization: []string{"YubiVault Self-Signed"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Ensure directory exists
	certDir := filepath.Dir(certPath)
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return fmt.Errorf("failed to create certificate directory: %w", err)
	}

	// Write certificate to file (unencrypted - it's public)
	certOut, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create certificate file: %w", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	// Marshal private key to PEM format
	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	var keyPEM bytes.Buffer
	if err := pem.Encode(&keyPEM, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return fmt.Errorf("failed to encode private key: %w", err)
	}

	// Encrypt the private key PEM
	encryptedKey, err := encrypter.EncryptSecret(keyPEM.Bytes(), TLSKeyAAD)
	if err != nil {
		return fmt.Errorf("failed to encrypt private key: %w", err)
	}

	// Write encrypted private key to file
	if err := os.WriteFile(keyPath, encryptedKey, 0600); err != nil {
		return fmt.Errorf("failed to write encrypted key file: %w", err)
	}

	return nil
}

// GetCertFingerprint reads a certificate file and returns its SHA256 fingerprint
// as a hex string.
func GetCertFingerprint(certPath string) (string, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return "", fmt.Errorf("failed to read certificate: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse certificate: %w", err)
	}

	fingerprint := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(fingerprint[:]), nil
}

// LoadTLSKeyPair loads a TLS certificate and decrypts the encrypted private key.
// The certificate is read from certPath (unencrypted PEM).
// The private key is read from encKeyPath and decrypted using the provided decrypter.
func LoadTLSKeyPair(certPath, encKeyPath string, decrypter Encrypter) (tls.Certificate, error) {
	// Read certificate (unencrypted)
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to read certificate: %w", err)
	}

	// Read encrypted private key
	encryptedKey, err := os.ReadFile(encKeyPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to read encrypted key: %w", err)
	}

	// Decrypt private key
	keyPEM, err := decrypter.DecryptSecret(encryptedKey, TLSKeyAAD)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to decrypt private key: %w", err)
	}

	// Parse certificate and key
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to parse TLS key pair: %w", err)
	}

	return cert, nil
}

// ImportTLSCert imports an external certificate and key, encrypting the private key.
// The certificate is copied to destCertPath.
// The private key is encrypted and written to destKeyPath.
func ImportTLSCert(srcCertPath, srcKeyPath, destCertPath, destKeyPath string, encrypter Encrypter) error {
	// Read source certificate
	certPEM, err := os.ReadFile(srcCertPath)
	if err != nil {
		return fmt.Errorf("failed to read source certificate: %w", err)
	}

	// Validate certificate format
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("invalid certificate format")
	}

	// Read source private key
	keyPEM, err := os.ReadFile(srcKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read source key: %w", err)
	}

	// Validate key format
	block, _ = pem.Decode(keyPEM)
	if block == nil || (block.Type != "PRIVATE KEY" && block.Type != "RSA PRIVATE KEY" && block.Type != "EC PRIVATE KEY") {
		return fmt.Errorf("invalid private key format")
	}

	// Validate that cert and key match by attempting to create a TLS pair
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return fmt.Errorf("certificate and key do not match: %w", err)
	}

	// Ensure destination directory exists
	destDir := filepath.Dir(destCertPath)
	if err := os.MkdirAll(destDir, 0700); err != nil {
		return fmt.Errorf("failed to create TLS directory: %w", err)
	}

	// Copy certificate to destination
	if err := os.WriteFile(destCertPath, certPEM, 0600); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	// Encrypt the private key
	encryptedKey, err := encrypter.EncryptSecret(keyPEM, TLSKeyAAD)
	if err != nil {
		return fmt.Errorf("failed to encrypt private key: %w", err)
	}

	// Write encrypted key to destination
	if err := os.WriteFile(destKeyPath, encryptedKey, 0600); err != nil {
		return fmt.Errorf("failed to write encrypted key: %w", err)
	}

	return nil
}
