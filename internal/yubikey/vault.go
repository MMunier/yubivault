package yubikey

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/go-piv/piv-go/v2/piv"
)

// validSecretNamePattern only allows alphanumeric characters, hyphens, and underscores
// This prevents path traversal attacks
var validSecretNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*$`)

// zeroBytes securely zeros a byte slice to prevent sensitive data from lingering in memory
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ValidateSecretName validates that a secret name is safe to use as a filename.
// It prevents path traversal attacks by only allowing alphanumeric characters,
// hyphens, and underscores. The name must start with an alphanumeric character.
func ValidateSecretName(name string) error {
	if name == "" {
		return fmt.Errorf("secret name cannot be empty")
	}
	if len(name) > 255 {
		return fmt.Errorf("secret name too long (max 255 characters)")
	}
	if !validSecretNamePattern.MatchString(name) {
		return fmt.Errorf("invalid secret name: must contain only alphanumeric characters, hyphens, and underscores, and start with an alphanumeric character")
	}
	return nil
}

// ValidateVaultPath validates and resolves a vault path, checking for symlink attacks.
// It returns the resolved absolute path or an error if the path is unsafe.
func ValidateVaultPath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("vault path cannot be empty")
	}

	// Convert to absolute path
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("failed to resolve absolute path: %w", err)
	}

	// Check if path exists
	info, err := os.Lstat(absPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Path doesn't exist yet, check parent directory
			parentDir := filepath.Dir(absPath)
			parentInfo, parentErr := os.Lstat(parentDir)
			if parentErr != nil {
				return "", fmt.Errorf("parent directory does not exist: %w", parentErr)
			}
			// Check if parent is a symlink
			if parentInfo.Mode()&os.ModeSymlink != 0 {
				return "", fmt.Errorf("parent directory is a symlink, which could be a security risk")
			}
			return absPath, nil
		}
		return "", fmt.Errorf("failed to stat path: %w", err)
	}

	// Check if the path itself is a symlink
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("vault path is a symlink, which could be a security risk")
	}

	// If path exists, ensure it's a directory
	if !info.IsDir() {
		return "", fmt.Errorf("vault path exists but is not a directory")
	}

	// Resolve any symlinks in the path components and compare
	resolvedPath, err := filepath.EvalSymlinks(absPath)
	if err != nil {
		return "", fmt.Errorf("failed to resolve symlinks: %w", err)
	}

	// Warn if resolved path differs (indicates symlinks in parent directories)
	if resolvedPath != absPath {
		return "", fmt.Errorf("vault path contains symlinks in parent directories (resolved to %s)", resolvedPath)
	}

	return absPath, nil
}

// CheckVaultPermissions verifies that the vault directory has secure permissions.
// It checks that the directory is not world-readable or writable.
func CheckVaultPermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Will be created with correct permissions
		}
		return fmt.Errorf("failed to stat vault path: %w", err)
	}

	mode := info.Mode().Perm()

	// Check for overly permissive permissions (world or group readable/writable)
	if mode&0077 != 0 {
		return fmt.Errorf("vault directory has insecure permissions %04o (should be 0700)", mode)
	}

	return nil
}

// ResolveVaultPath validates the vault path and optionally checks permissions.
// This is a convenience function that combines path validation and permission checks.
func ResolveVaultPath(path string, checkPerms bool) (string, error) {
	// Check for path traversal attempts
	if strings.Contains(path, "..") {
		return "", fmt.Errorf("vault path cannot contain '..'")
	}

	resolvedPath, err := ValidateVaultPath(path)
	if err != nil {
		return "", err
	}

	if checkPerms {
		if err := CheckVaultPermissions(resolvedPath); err != nil {
			return "", err
		}
	}

	return resolvedPath, nil
}

// Vault manages encrypted secrets using YubiKey PIV as trust anchor
type Vault struct {
	vaultPath  string
	yk         *piv.YubiKey
	slot       piv.Slot
	masterKey  []byte
	privateKey crypto.PrivateKey
}

// NewVault initializes a vault with YubiKey PIV
func NewVault(vaultPath, slotStr, pin string) (*Vault, error) {
	// Validate and resolve vault path
	resolvedPath, err := ResolveVaultPath(vaultPath, true)
	if err != nil {
		return nil, fmt.Errorf("invalid vault path: %w", err)
	}
	vaultPath = resolvedPath

	// Parse PIV slot
	slot, err := ParseSlot(slotStr)
	if err != nil {
		return nil, fmt.Errorf("invalid PIV slot: %w", err)
	}

	// Open YubiKey
	cards, err := piv.Cards()
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate cards: %w", err)
	}
	if len(cards) == 0 {
		return nil, fmt.Errorf("no YubiKey found")
	}

	yk, err := piv.Open(cards[0])
	if err != nil {
		return nil, fmt.Errorf("failed to open YubiKey: %w", err)
	}

	// Get private key from slot
	cert, err := yk.Certificate(slot)
	if err != nil {
		yk.Close()
		return nil, fmt.Errorf("failed to get certificate from slot %s: %w", slotStr, err)
	}

	privateKey, err := yk.PrivateKey(slot, cert.PublicKey, piv.KeyAuth{PIN: pin})
	if err != nil {
		yk.Close()
		return nil, fmt.Errorf("failed to get private key: %w", err)
	}

	vault := &Vault{
		vaultPath:  vaultPath,
		yk:         yk,
		slot:       slot,
		privateKey: privateKey,
	}

	// Load or generate master key
	if err := vault.loadOrGenerateMasterKey(); err != nil {
		yk.Close()
		return nil, err
	}

	return vault, nil
}

// Close closes the YubiKey connection and securely zeros sensitive data
func (v *Vault) Close() error {
	// Zero master key to prevent it from lingering in memory
	if v.masterKey != nil {
		zeroBytes(v.masterKey)
		v.masterKey = nil
	}

	if v.yk != nil {
		return v.yk.Close()
	}
	return nil
}

// loadOrGenerateMasterKey loads existing master key or generates a new one
func (v *Vault) loadOrGenerateMasterKey() error {
	masterKeyPath := filepath.Join(v.vaultPath, "master.key")

	// Try to load existing master key
	encryptedMasterKey, err := os.ReadFile(masterKeyPath)
	if err == nil {
		// Decrypt master key using YubiKey
		masterKey, err := v.decryptWithYubiKey(encryptedMasterKey)
		if err != nil {
			return fmt.Errorf("failed to decrypt master key: %w", err)
		}
		v.masterKey = masterKey
		return nil
	}

	// Generate new master key if it doesn't exist
	if !os.IsNotExist(err) {
		return fmt.Errorf("failed to read master key: %w", err)
	}

	return fmt.Errorf("master key not found at %s - use 'yubivault init' to initialize vault", masterKeyPath)
}

// decryptWithYubiKey decrypts data using YubiKey PIV private key
func (v *Vault) decryptWithYubiKey(ciphertext []byte) ([]byte, error) {
	rsaPrivateKey, ok := v.privateKey.(crypto.Decrypter)
	if !ok {
		return nil, fmt.Errorf("private key does not support decryption")
	}

	// piv-go only supports PKCS#1 v1.5 padding for RSA decryption
	plaintext, err := rsaPrivateKey.Decrypt(rand.Reader, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// DecryptSecret decrypts a secret using the master key
// The name parameter is used as Additional Authenticated Data (AAD) to bind
// the encrypted data to its context and prevent substitution attacks
func (v *Vault) DecryptSecret(ciphertext []byte, name string) ([]byte, error) {
	if v.masterKey == nil {
		return nil, fmt.Errorf("master key not loaded")
	}

	// Decode base64
	decoded, err := base64.StdEncoding.DecodeString(string(ciphertext))
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	// Extract nonce and ciphertext
	if len(decoded) < 12 {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := decoded[:12]
	encryptedData := decoded[12:]

	// Create AES-GCM cipher
	block, err := aes.NewCipher(v.masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Decrypt with AAD (binds decryption to specific name/context)
	aad := []byte(name)
	plaintext, err := gcm.Open(nil, nonce, encryptedData, aad)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// EncryptSecret encrypts a secret using the master key
// The name parameter is used as Additional Authenticated Data (AAD) to bind
// the encrypted data to its context and prevent substitution attacks
func (v *Vault) EncryptSecret(plaintext []byte, name string) ([]byte, error) {
	if v.masterKey == nil {
		return nil, fmt.Errorf("master key not loaded")
	}

	// Create AES-GCM cipher
	block, err := aes.NewCipher(v.masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt with AAD (binds encryption to specific name/context)
	aad := []byte(name)
	ciphertext := gcm.Seal(nonce, nonce, plaintext, aad)

	// Encode to base64
	encoded := base64.StdEncoding.EncodeToString(ciphertext)

	return []byte(encoded), nil
}

// GenerateMasterKey generates and encrypts a new master key
func GenerateMasterKey(vaultPath string, publicKey crypto.PublicKey) error {
	// Generate 256-bit master key
	masterKey := make([]byte, 32)
	defer zeroBytes(masterKey) // Zero master key when done

	if _, err := rand.Read(masterKey); err != nil {
		return fmt.Errorf("failed to generate master key: %w", err)
	}

	// Encrypt with YubiKey public key
	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not RSA")
	}

	// Use PKCS#1 v1.5 padding - piv-go only supports this for RSA decryption
	encryptedMasterKey, err := rsa.EncryptPKCS1v15(
		rand.Reader,
		rsaPublicKey,
		masterKey,
	)
	if err != nil {
		return fmt.Errorf("failed to encrypt master key: %w", err)
	}

	// Save encrypted master key
	masterKeyPath := filepath.Join(vaultPath, "master.key")
	if err := os.WriteFile(masterKeyPath, encryptedMasterKey, 0600); err != nil {
		return fmt.Errorf("failed to write master key: %w", err)
	}

	return nil
}

// ParseSlot converts a slot string (9a, 9c, 9d, 9e) to a piv.Slot.
// The slot string is case-insensitive and whitespace is trimmed.
// Note: Slot 9d (Key Management) is recommended for vault encryption.
// Slot 9a (Authentication) is not recommended as it's typically used for PIV authentication.
func ParseSlot(s string) (piv.Slot, error) {
	// Normalize input: trim whitespace and convert to lowercase
	s = strings.TrimSpace(strings.ToLower(s))

	slots := map[string]piv.Slot{
		"9a": piv.SlotAuthentication,
		"9c": piv.SlotSignature,
		"9d": piv.SlotKeyManagement,
		"9e": piv.SlotCardAuthentication,
	}

	slot, ok := slots[s]
	if !ok {
		return piv.Slot{}, fmt.Errorf("unknown slot: %s (valid: 9a, 9c, 9d, 9e)", s)
	}

	// Warn about non-recommended slots
	if s == "9a" {
		fmt.Println("Warning: Slot 9a (Authentication) is not recommended for vault encryption.")
		fmt.Println("         Consider using slot 9d (Key Management) instead.")
	}

	return slot, nil
}
