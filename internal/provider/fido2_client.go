package provider

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/keys-pub/go-libfido2"
	"golang.org/x/term"
)

// FIDO2Client handles FIDO2 authentication with the yubivault server
type FIDO2Client struct {
	serverURL string
}

// NewFIDO2Client creates a new FIDO2 client
func NewFIDO2Client(serverURL string) *FIDO2Client {
	return &FIDO2Client{serverURL: serverURL}
}

// Authenticate performs FIDO2 authentication and returns a session token
func (c *FIDO2Client) Authenticate() (string, time.Time, error) {
	// Step 1: Get challenge from server
	resp, err := http.Get(c.serverURL + "/auth/challenge")
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to contact server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusPreconditionFailed {
		// No credentials registered - auth not required
		return "", time.Time{}, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", time.Time{}, fmt.Errorf("server error getting challenge: %s", string(body))
	}

	var options protocol.CredentialAssertion
	if err := json.NewDecoder(resp.Body).Decode(&options); err != nil {
		return "", time.Time{}, fmt.Errorf("failed to parse challenge: %w", err)
	}

	// Step 2: Find FIDO2 device
	locs, err := libfido2.DeviceLocations()
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to find FIDO2 devices: %w", err)
	}
	if len(locs) == 0 {
		return "", time.Time{}, fmt.Errorf("no FIDO2 devices found - insert YubiKey")
	}

	device, err := libfido2.NewDevice(locs[0].Path)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to open FIDO2 device: %w", err)
	}

	// Check if PIN is required
	var pin string
	info, err := device.Info()
	if err == nil && info.Options != nil {
		for _, opt := range info.Options {
			if opt.Name == "clientPin" && opt.Value == libfido2.True {
				// For Terraform provider, read PIN from environment or prompt
				pin = os.Getenv("FIDO2_PIN")
				if pin == "" {
					fmt.Print("[yubivault] Enter FIDO2 PIN: ")
					pinBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
					fmt.Println()
					if err != nil {
						return "", time.Time{}, fmt.Errorf("failed to read PIN: %w", err)
					}
					pin = string(pinBytes)
				}
				break
			}
		}
	}

	// Step 3: Create clientDataJSON
	clientData := map[string]interface{}{
		"type":        "webauthn.get",
		"challenge":   string(options.Response.Challenge),
		"origin":      c.serverURL,
		"crossOrigin": false,
	}
	clientDataJSON, err := json.Marshal(clientData)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to create client data: %w", err)
	}

	// Hash the client data for FIDO2
	clientDataHash := sha256.Sum256(clientDataJSON)

	// Step 4: Get allowed credential IDs
	var credentialIDs [][]byte
	for _, cred := range options.Response.AllowedCredentials {
		credentialIDs = append(credentialIDs, cred.CredentialID)
	}

	// Step 5: Get assertion from device (this requires touch)
	assertion, err := device.Assertion(
		options.Response.RelyingPartyID,
		clientDataHash[:],
		credentialIDs,
		pin, // FIDO2 PIN if required
		&libfido2.AssertionOpts{
			Extensions: []libfido2.Extension{},
		},
	)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("FIDO2 authentication failed (touch YubiKey): %w", err)
	}

	// Step 6: Build assertion response - use RawURLEncoding (no padding) as per WebAuthn spec
	payload := map[string]interface{}{
		"id":    base64.RawURLEncoding.EncodeToString(assertion.CredentialID),
		"rawId": base64.RawURLEncoding.EncodeToString(assertion.CredentialID),
		"type":  "public-key",
		"response": map[string]interface{}{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientDataJSON),
			"authenticatorData": base64.RawURLEncoding.EncodeToString(assertion.AuthDataCBOR),
			"signature":         base64.RawURLEncoding.EncodeToString(assertion.Sig),
		},
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to marshal assertion: %w", err)
	}

	// Step 7: Send assertion to server
	resp, err = http.Post(
		c.serverURL+"/auth/verify",
		"application/json",
		bytes.NewReader(payloadJSON),
	)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to verify assertion: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", time.Time{}, fmt.Errorf("authentication failed: %s", string(body))
	}

	// Step 8: Parse token response
	var result struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", time.Time{}, fmt.Errorf("failed to parse token response: %w", err)
	}

	return result.Token, result.ExpiresAt, nil
}
