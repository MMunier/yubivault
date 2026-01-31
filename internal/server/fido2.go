package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// FIDO2Credential represents a registered FIDO2 credential
type FIDO2Credential struct {
	ID        []byte    `json:"id"`
	PublicKey []byte    `json:"public_key"`
	AAGUID    []byte    `json:"aaguid"`
	SignCount uint32    `json:"sign_count"`
	CreatedAt time.Time `json:"created_at"`
	Name      string    `json:"name"`
}

// FIDO2Store holds all registered credentials
type FIDO2Store struct {
	Version      int               `json:"version"`
	RelyingParty string            `json:"relying_party"`
	Credentials  []FIDO2Credential `json:"credentials"`
}

// CredentialStore manages FIDO2 credentials on disk
type CredentialStore struct {
	path  string
	store *FIDO2Store
}

// NewCredentialStore creates or loads a credential store
func NewCredentialStore(vaultPath string) (*CredentialStore, error) {
	fido2Dir := filepath.Join(vaultPath, "fido2")
	if err := os.MkdirAll(fido2Dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create fido2 directory: %w", err)
	}

	credPath := filepath.Join(fido2Dir, "credentials.json")
	cs := &CredentialStore{
		path: credPath,
		store: &FIDO2Store{
			Version:      1,
			RelyingParty: "yubivault",
			Credentials:  []FIDO2Credential{},
		},
	}

	// Load existing credentials if present
	if data, err := os.ReadFile(credPath); err == nil {
		if err := json.Unmarshal(data, cs.store); err != nil {
			return nil, fmt.Errorf("failed to parse credentials: %w", err)
		}
	}

	return cs, nil
}

// HasCredentials returns true if any credentials are registered
func (cs *CredentialStore) HasCredentials() bool {
	return len(cs.store.Credentials) > 0
}

// AddCredential adds a new credential to the store
func (cs *CredentialStore) AddCredential(cred *FIDO2Credential) error {
	cs.store.Credentials = append(cs.store.Credentials, *cred)
	return cs.save()
}

// GetCredentials returns all registered credentials
func (cs *CredentialStore) GetCredentials() []FIDO2Credential {
	return cs.store.Credentials
}

// UpdateSignCount updates the signature counter for a credential
func (cs *CredentialStore) UpdateSignCount(credID []byte, newCount uint32) error {
	for i := range cs.store.Credentials {
		if bytes.Equal(cs.store.Credentials[i].ID, credID) {
			cs.store.Credentials[i].SignCount = newCount
			return cs.save()
		}
	}
	return fmt.Errorf("credential not found")
}

// FindCredential finds a credential by ID
func (cs *CredentialStore) FindCredential(credID []byte) *FIDO2Credential {
	for i := range cs.store.Credentials {
		if bytes.Equal(cs.store.Credentials[i].ID, credID) {
			return &cs.store.Credentials[i]
		}
	}
	return nil
}

func (cs *CredentialStore) save() error {
	data, err := json.MarshalIndent(cs.store, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(cs.path, data, 0600)
}

// VaultUser implements webauthn.User for the yubivault single-user system
type VaultUser struct {
	credentials *CredentialStore
}

// NewVaultUser creates a new VaultUser
func NewVaultUser(credentials *CredentialStore) *VaultUser {
	return &VaultUser{credentials: credentials}
}

// WebAuthnID returns the user ID (fixed for single-user system)
func (u *VaultUser) WebAuthnID() []byte {
	return []byte("yubivault-user")
}

// WebAuthnName returns the username
func (u *VaultUser) WebAuthnName() string {
	return "yubivault"
}

// WebAuthnDisplayName returns the display name
func (u *VaultUser) WebAuthnDisplayName() string {
	return "YubiVault User"
}

// WebAuthnCredentials returns all registered credentials
func (u *VaultUser) WebAuthnCredentials() []webauthn.Credential {
	creds := u.credentials.GetCredentials()
	result := make([]webauthn.Credential, len(creds))
	for i, c := range creds {
		result[i] = webauthn.Credential{
			ID:              c.ID,
			PublicKey:       c.PublicKey,
			AttestationType: "",
			Authenticator: webauthn.Authenticator{
				AAGUID:    c.AAGUID,
				SignCount: c.SignCount,
			},
		}
	}
	return result
}

// WebAuthnIcon returns an empty icon URL (not used)
func (u *VaultUser) WebAuthnIcon() string {
	return ""
}
