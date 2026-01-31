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
func (v *Vault) DecryptSecret(ciphertext []byte) ([]byte, error) {
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

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// EncryptSecret encrypts a secret using the master key
func (v *Vault) EncryptSecret(plaintext []byte) ([]byte, error) {
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

	// Encrypt
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

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

// ParseSlot converts a slot string (9a, 9c, 9d, 9e) to a piv.Slot
func ParseSlot(s string) (piv.Slot, error) {
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

	return slot, nil
}
