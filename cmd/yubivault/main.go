package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/go-piv/piv-go/v2/piv"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/keys-pub/go-libfido2"
	"github.com/mmunier/terraform-provider-yubivault/internal/server"
	"github.com/mmunier/terraform-provider-yubivault/internal/yubikey"
	"golang.org/x/term"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "init":
		if err := initVault(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "encrypt":
		if err := encryptSecret(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "decrypt":
		if err := decryptSecret(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "serve":
		if err := serveStateBackend(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "state-decrypt":
		if err := stateDecrypt(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "state-encrypt":
		if err := stateEncrypt(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "fido2-register":
		if err := fido2Register(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: yubivault <command>")
	fmt.Println("\nCommands:")
	fmt.Println("  init                   Initialize a new vault")
	fmt.Println("  encrypt <name>         Encrypt a secret (reads from stdin)")
	fmt.Println("  decrypt <name>         Decrypt a secret")
	fmt.Println("  state-encrypt <name>   Encrypt a state file (reads from stdin)")
	fmt.Println("  state-decrypt <name>   Decrypt a state file")
	fmt.Println("  serve [addr] [--cert cert.pem] [--key key.pem]")
	fmt.Println("                         Start HTTPS server (default: localhost:8099)")
	fmt.Println("                         Certificates auto-generated if not provided")
	fmt.Println("                         Use --cert and --key for custom certificates")
	fmt.Println("  fido2-register [url]   Register FIDO2 credential for authentication")
}

// getHTTPClient returns an HTTP client configured to trust self-signed certificates
// from the vault's TLS directory
func getHTTPClient() (*http.Client, error) {
	// Try to load CA certificate from vault/tls/server.crt
	vaultPath := os.Getenv("YUBIVAULT_PATH")
	if vaultPath == "" {
		vaultPath = "vault"
	}
	caCertPath := filepath.Join(vaultPath, "tls", "server.crt")

	// Try to load the CA certificate
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		// If we can't load the cert, use system defaults
		// This allows the client to work with properly signed certificates
		return &http.Client{}, nil
	}

	// Create certificate pool and add our CA cert
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		// If parsing fails, fall back to system defaults
		return &http.Client{}, nil
	}

	tlsConfig := &tls.Config{
		RootCAs: caCertPool,
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}, nil
}

func initVault() error {
	vaultPath := os.Getenv("YUBIVAULT_PATH")
	if vaultPath == "" {
		vaultPath = "./vault"
	}

	slot := os.Getenv("YUBIVAULT_SLOT")
	if slot == "" {
		slot = "9d"
	}

	fmt.Printf("Initializing vault at: %s\n", vaultPath)
	fmt.Printf("Using PIV slot: %s\n", slot)

	// Create vault directory structure
	if err := os.MkdirAll(filepath.Join(vaultPath, "secrets"), 0700); err != nil {
		return fmt.Errorf("failed to create vault directory: %w", err)
	}

	// Open YubiKey
	cards, err := piv.Cards()
	if err != nil {
		return fmt.Errorf("failed to enumerate cards: %w", err)
	}
	if len(cards) == 0 {
		return fmt.Errorf("no YubiKey found")
	}

	yk, err := piv.Open(cards[0])
	if err != nil {
		return fmt.Errorf("failed to open YubiKey: %w", err)
	}
	defer yk.Close()

	// Get public key from certificate
	pivSlot, err := yubikey.ParseSlot(slot)
	if err != nil {
		return err
	}

	cert, err := yk.Certificate(pivSlot)
	if err != nil {
		return fmt.Errorf("failed to get certificate from slot %s: %w\nMake sure you have generated a key in this slot", slot, err)
	}

	// Generate and save encrypted master key
	if err := yubikey.GenerateMasterKey(vaultPath, cert.PublicKey); err != nil {
		return err
	}

	fmt.Println("✓ Vault initialized successfully")
	fmt.Printf("✓ Master key encrypted and saved to: %s/master.key\n", vaultPath)
	fmt.Println("\nNext steps:")
	fmt.Println("  1. Store secrets: echo 'secret-value' | yubivault encrypt my-secret")
	fmt.Println("  2. Use in Terraform: data.yubivault_secret.my-secret.value")

	return nil
}

func encryptSecret() error {
	if len(os.Args) < 3 {
		return fmt.Errorf("usage: yubivault encrypt <secret-name>")
	}

	secretName := os.Args[2]

	// Validate secret name to prevent path traversal
	if err := yubikey.ValidateSecretName(secretName); err != nil {
		return err
	}

	vaultPath := os.Getenv("YUBIVAULT_PATH")
	if vaultPath == "" {
		vaultPath = "./vault"
	}

	slot := os.Getenv("YUBIVAULT_SLOT")
	if slot == "" {
		slot = "9d"
	}

	pin := os.Getenv("YUBIKEY_PIN")
	if pin == "" {
		fmt.Print("Enter PIN: ")
		pinBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println() // newline after hidden input
		if err != nil {
			return fmt.Errorf("failed to read PIN: %w", err)
		}
		pin = string(pinBytes)
	}

	// Read secret from stdin
	fmt.Println("Enter secret value (press Ctrl+D when done):")
	plaintext, err := os.ReadFile("/dev/stdin")
	if err != nil {
		return fmt.Errorf("failed to read secret: %w", err)
	}

	// Initialize vault
	vault, err := yubikey.NewVault(vaultPath, slot, pin)
	if err != nil {
		return err
	}
	defer vault.Close()

	// Encrypt secret (using secret name as AAD)
	ciphertext, err := vault.EncryptSecret(plaintext, "secret:"+secretName)
	if err != nil {
		return err
	}

	// Save encrypted secret
	secretPath := filepath.Join(vaultPath, "secrets", secretName+".enc")
	if err := os.WriteFile(secretPath, ciphertext, 0600); err != nil {
		return fmt.Errorf("failed to write encrypted secret: %w", err)
	}

	fmt.Printf("✓ Secret encrypted and saved to: %s\n", secretPath)

	return nil
}

func decryptSecret() error {
	if len(os.Args) < 3 {
		return fmt.Errorf("usage: yubivault decrypt <secret-name>")
	}

	secretName := os.Args[2]

	// Validate secret name to prevent path traversal
	if err := yubikey.ValidateSecretName(secretName); err != nil {
		return err
	}

	vaultPath := os.Getenv("YUBIVAULT_PATH")
	if vaultPath == "" {
		vaultPath = "./vault"
	}

	slot := os.Getenv("YUBIVAULT_SLOT")
	if slot == "" {
		slot = "9d"
	}

	pin := os.Getenv("YUBIKEY_PIN")
	if pin == "" {
		fmt.Print("Enter PIN: ")
		pinBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println() // newline after hidden input
		if err != nil {
			return fmt.Errorf("failed to read PIN: %w", err)
		}
		pin = string(pinBytes)
	}

	// Initialize vault
	vault, err := yubikey.NewVault(vaultPath, slot, pin)
	if err != nil {
		return err
	}
	defer vault.Close()

	// Read encrypted secret
	secretPath := filepath.Join(vaultPath, "secrets", secretName+".enc")
	ciphertext, err := os.ReadFile(secretPath)
	if err != nil {
		return fmt.Errorf("failed to read secret: %w", err)
	}

	// Decrypt secret (using secret name as AAD)
	plaintext, err := vault.DecryptSecret(ciphertext, "secret:"+secretName)
	if err != nil {
		return err
	}

	fmt.Print(string(plaintext))

	return nil
}

func serveStateBackend() error {
	vaultPath := os.Getenv("YUBIVAULT_PATH")
	if vaultPath == "" {
		vaultPath = "./vault"
	}

	slot := os.Getenv("YUBIVAULT_SLOT")
	if slot == "" {
		slot = "9d"
	}

	pin := os.Getenv("YUBIKEY_PIN")
	if pin == "" {
		fmt.Print("Enter PIN: ")
		pinBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return fmt.Errorf("failed to read PIN: %w", err)
		}
		pin = string(pinBytes)
	}

	// Parse arguments for address and TLS options
	addr := "localhost:8099"
	certFile := ""
	keyFile := ""

	for i := 2; i < len(os.Args); i++ {
		arg := os.Args[i]
		if arg == "--cert" && i+1 < len(os.Args) {
			certFile = os.Args[i+1]
			i++
		} else if arg == "--key" && i+1 < len(os.Args) {
			keyFile = os.Args[i+1]
			i++
		} else if !startsWith(arg, "--") {
			addr = arg
		}
	}

	// Validate TLS options - if providing custom cert, both cert and key required
	if (certFile != "" && keyFile == "") || (certFile == "" && keyFile != "") {
		return fmt.Errorf("both --cert and --key must be provided together for custom certificates")
	}

	// Initialize vault
	vault, err := yubikey.NewVault(vaultPath, slot, pin)
	if err != nil {
		return err
	}
	defer vault.Close()

	// Create server
	srv, err := server.NewStateServer(vault, vaultPath, addr)
	if err != nil {
		return err
	}

	// Handle shutdown signals
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nShutting down...")
		srv.Shutdown(ctx)
	}()

	// Start server with optional TLS
	if err := srv.Start(addr, certFile, keyFile); err != nil && err.Error() != "http: Server closed" {
		return err
	}

	return nil
}

// Helper function to check if a string starts with a prefix
func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func stateDecrypt() error {
	if len(os.Args) < 3 {
		return fmt.Errorf("usage: yubivault state-decrypt <project-name>")
	}

	projectName := os.Args[2]

	// Validate project name to prevent path traversal
	if err := yubikey.ValidateSecretName(projectName); err != nil {
		return err
	}

	vaultPath := os.Getenv("YUBIVAULT_PATH")
	if vaultPath == "" {
		vaultPath = "./vault"
	}

	slot := os.Getenv("YUBIVAULT_SLOT")
	if slot == "" {
		slot = "9d"
	}

	pin := os.Getenv("YUBIKEY_PIN")
	if pin == "" {
		fmt.Print("Enter PIN: ")
		pinBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return fmt.Errorf("failed to read PIN: %w", err)
		}
		pin = string(pinBytes)
	}

	// Initialize vault
	vault, err := yubikey.NewVault(vaultPath, slot, pin)
	if err != nil {
		return err
	}
	defer vault.Close()

	// Read encrypted state
	statePath := filepath.Join(vaultPath, "state", projectName+".tfstate.enc")
	ciphertext, err := os.ReadFile(statePath)
	if err != nil {
		return fmt.Errorf("failed to read state file: %w", err)
	}

	// Decrypt state (using project name as AAD)
	plaintext, err := vault.DecryptSecret(ciphertext, "state:"+projectName)
	if err != nil {
		return err
	}

	fmt.Print(string(plaintext))

	return nil
}

func stateEncrypt() error {
	if len(os.Args) < 3 {
		return fmt.Errorf("usage: yubivault state-encrypt <project-name>")
	}

	projectName := os.Args[2]

	// Validate project name to prevent path traversal
	if err := yubikey.ValidateSecretName(projectName); err != nil {
		return err
	}

	vaultPath := os.Getenv("YUBIVAULT_PATH")
	if vaultPath == "" {
		vaultPath = "./vault"
	}

	slot := os.Getenv("YUBIVAULT_SLOT")
	if slot == "" {
		slot = "9d"
	}

	pin := os.Getenv("YUBIKEY_PIN")
	if pin == "" {
		fmt.Print("Enter PIN: ")
		pinBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return fmt.Errorf("failed to read PIN: %w", err)
		}
		pin = string(pinBytes)
	}

	// Read state from stdin
	fmt.Fprintln(os.Stderr, "Reading state from stdin...")
	plaintext, err := os.ReadFile("/dev/stdin")
	if err != nil {
		return fmt.Errorf("failed to read state: %w", err)
	}

	// Initialize vault
	vault, err := yubikey.NewVault(vaultPath, slot, pin)
	if err != nil {
		return err
	}
	defer vault.Close()

	// Encrypt state (using project name as AAD)
	ciphertext, err := vault.EncryptSecret(plaintext, "state:"+projectName)
	if err != nil {
		return err
	}

	// Ensure state directory exists
	stateDir := filepath.Join(vaultPath, "state")
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return fmt.Errorf("failed to create state directory: %w", err)
	}

	// Save encrypted state
	statePath := filepath.Join(stateDir, projectName+".tfstate.enc")
	if err := os.WriteFile(statePath, ciphertext, 0600); err != nil {
		return fmt.Errorf("failed to write state file: %w", err)
	}

	fmt.Fprintf(os.Stderr, "State encrypted and saved to: %s\n", statePath)

	return nil
}

func fido2Register() error {
	serverURL := "https://localhost:8099"
	if len(os.Args) >= 3 {
		serverURL = os.Args[2]
	}

	fmt.Println("Registering FIDO2 credential...")
	fmt.Printf("Server: %s\n", serverURL)

	// Get HTTP client with TLS configuration
	httpClient, err := getHTTPClient()
	if err != nil {
		return fmt.Errorf("failed to create HTTP client: %w", err)
	}

	// Step 1: Get registration options from server
	resp, err := httpClient.Get(serverURL + "/auth/register/begin")
	if err != nil {
		return fmt.Errorf("failed to contact server: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server error: %s", string(body))
	}

	var options protocol.CredentialCreation
	if err := json.NewDecoder(resp.Body).Decode(&options); err != nil {
		return fmt.Errorf("failed to parse registration options: %w", err)
	}

	// Step 2: Find FIDO2 device
	locs, err := libfido2.DeviceLocations()
	if err != nil {
		return fmt.Errorf("failed to find FIDO2 devices: %w", err)
	}
	if len(locs) == 0 {
		return fmt.Errorf("no FIDO2 devices found - insert YubiKey and try again")
	}

	device, err := libfido2.NewDevice(locs[0].Path)
	if err != nil {
		return fmt.Errorf("failed to open FIDO2 device: %w", err)
	}

	// Check if PIN is required
	var pin string
	info, err := device.Info()
	if err == nil && info.Options != nil {
		for _, opt := range info.Options {
			if opt.Name == "clientPin" && opt.Value == libfido2.True {
				fmt.Print("Enter FIDO2 PIN: ")
				pinBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
				fmt.Println()
				if err != nil {
					return fmt.Errorf("failed to read PIN: %w", err)
				}
				pin = string(pinBytes)
				break
			}
		}
	}

	fmt.Println("\nTouch your YubiKey to register...")

	// Step 3: Create clientDataJSON
	origin := serverURL
	clientData := map[string]interface{}{
		"type":        "webauthn.create",
		"challenge":   options.Response.Challenge,
		"origin":      origin,
		"crossOrigin": false,
	}
	clientDataJSON, err := json.Marshal(clientData)
	if err != nil {
		return fmt.Errorf("failed to create client data: %w", err)
	}

	// Hash the client data for FIDO2
	clientDataHash := sha256.Sum256(clientDataJSON)

	// Step 4: Create credential on device
	rp := libfido2.RelyingParty{
		ID:   options.Response.RelyingParty.ID,
		Name: options.Response.RelyingParty.Name,
	}

	// Extract user ID (it's base64url encoded in the options)
	userID := []byte(options.Response.User.Name) // Use name as ID fallback
	if idBytes, ok := options.Response.User.ID.([]byte); ok {
		userID = idBytes
	} else if idStr, ok := options.Response.User.ID.(string); ok {
		userID = []byte(idStr)
	}

	user := libfido2.User{
		ID:          userID,
		Name:        options.Response.User.Name,
		DisplayName: options.Response.User.DisplayName,
	}

	attestation, err := device.MakeCredential(
		clientDataHash[:],
		rp,
		user,
		libfido2.ES256, // ECDSA with SHA-256
		pin,            // FIDO2 PIN if required
		&libfido2.MakeCredentialOpts{
			Extensions: []libfido2.Extension{},
			RK:         libfido2.False, // Not a resident key
		},
	)
	if err != nil {
		return fmt.Errorf("failed to create credential (did you touch the key?): %w", err)
	}

	// Step 5: Build attestation object (CBOR encoded)
	attestationObject, err := buildAttestationObject(attestation)
	if err != nil {
		return fmt.Errorf("failed to build attestation object: %w", err)
	}

	// Step 6: Send to server - use RawURLEncoding (no padding) as per WebAuthn spec
	payload := map[string]interface{}{
		"id":    base64.RawURLEncoding.EncodeToString(attestation.CredentialID),
		"rawId": base64.RawURLEncoding.EncodeToString(attestation.CredentialID),
		"type":  "public-key",
		"response": map[string]interface{}{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientDataJSON),
			"attestationObject": base64.RawURLEncoding.EncodeToString(attestationObject),
		},
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal credential response: %w", err)
	}

	resp, err = httpClient.Post(
		serverURL+"/auth/register/complete",
		"application/json",
		bytes.NewReader(payloadJSON),
	)
	if err != nil {
		return fmt.Errorf("failed to complete registration: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("registration failed: %s", string(body))
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to parse registration response: %w", err)
	}

	fmt.Println("\n✓ FIDO2 credential registered successfully!")
	if name, ok := result["name"].(string); ok {
		fmt.Printf("  Credential: %s\n", name)
	}
	fmt.Println("\nAuthentication is now required for all server requests.")
	fmt.Println("The Terraform provider will authenticate automatically.")

	return nil
}

// buildAttestationObject creates a CBOR-encoded attestation object from libfido2 attestation
// per CTAP2 spec: https://fidoalliance.org/specs/fido2/fido-client-to-authenticator-protocol-v2.1-rd-20191217.html#authenticatorMakeCredential
func buildAttestationObject(att *libfido2.Attestation) ([]byte, error) {
	// libfido2 returns authData as CBOR-encoded bytes, decode it first
	var authData []byte
	if err := webauthncbor.Unmarshal(att.AuthData, &authData); err != nil {
		// If CBOR decode fails, assume it's already raw bytes
		authData = att.AuthData
	}

	if len(authData) < 37 {
		return nil, fmt.Errorf("authData too short: %d bytes", len(authData))
	}

	// Build attestation statement based on format
	attStmt := buildAttestationStatement(att)

	attObj := map[string]interface{}{
		"fmt":      att.Format,
		"authData": authData,
		"attStmt":  attStmt,
	}

	return webauthncbor.Marshal(attObj)
}

// buildAttestationStatement creates the attStmt map based on attestation format
// See: https://www.w3.org/TR/webauthn-2/#sctn-defined-attestation-formats
func buildAttestationStatement(att *libfido2.Attestation) map[string]interface{} {
	switch att.Format {
	case "packed":
		// https://www.w3.org/TR/webauthn-2/#sctn-packed-attestation
		stmt := map[string]interface{}{
			"alg": int64(att.CredentialType), // COSE algorithm identifier
			"sig": att.Sig,
		}
		if len(att.Cert) > 0 {
			// Full attestation with certificate chain
			stmt["x5c"] = [][]byte{att.Cert}
		}
		return stmt

	case "fido-u2f":
		// https://www.w3.org/TR/webauthn-2/#sctn-fido-u2f-attestation
		stmt := map[string]interface{}{
			"sig": att.Sig,
		}
		if len(att.Cert) > 0 {
			stmt["x5c"] = [][]byte{att.Cert}
		}
		return stmt

	case "none":
		// https://www.w3.org/TR/webauthn-2/#sctn-none-attestation
		return map[string]interface{}{}

	default:
		// For unknown formats, try to include available data
		// Fall back to "none" style if we don't recognize the format
		if len(att.Sig) == 0 && len(att.Cert) == 0 {
			return map[string]interface{}{}
		}
		stmt := map[string]interface{}{}
		if len(att.Sig) > 0 {
			stmt["sig"] = att.Sig
		}
		if len(att.Cert) > 0 {
			stmt["x5c"] = [][]byte{att.Cert}
		}
		return stmt
	}
}
