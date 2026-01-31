package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/go-piv/piv-go/v2/piv"
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
	case "run":
		exitCode, err := runCommand()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		os.Exit(exitCode)
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
	fmt.Println("  run [--project name] <terraform-args>")
	fmt.Println("                         Run terraform/tofu with YubiVault integration")
	fmt.Println("                         Auto-detects tofu or terraform in PATH")
	fmt.Println("                         Example: yubivault run plan")
	fmt.Println("                                  yubivault run apply -auto-approve")
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

	// Create server (no auth required for standalone serve mode)
	srv, err := server.NewStateServer(vault, vaultPath, false)
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

// runCommand starts the server and runs terraform/tofu as a subprocess
func runCommand() (int, error) {
	// Parse arguments: yubivault run [--project name] <terraform-args>
	var projectName string
	var tfArgs []string

	args := os.Args[2:] // Skip "yubivault" and "run"
	for i := 0; i < len(args); i++ {
		if args[i] == "--project" && i+1 < len(args) {
			projectName = args[i+1]
			i++
		} else {
			tfArgs = append(tfArgs, args[i:]...)
			break
		}
	}

	// Default project name to current directory basename
	if projectName == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return 1, fmt.Errorf("failed to get current directory: %w", err)
		}
		projectName = filepath.Base(cwd)
	}

	// Detect terraform/tofu
	tfBinary := detectTerraformBinary()
	if tfBinary == "" {
		return 1, fmt.Errorf("neither 'tofu' nor 'terraform' found in PATH")
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
			return 1, fmt.Errorf("failed to read PIN: %w", err)
		}
		pin = string(pinBytes)
	}

	// Initialize vault
	vault, err := yubikey.NewVault(vaultPath, slot, pin)
	if err != nil {
		return 1, err
	}
	defer vault.Close()

	// Create server with auth required
	srv, err := server.NewStateServer(vault, vaultPath, true)
	if err != nil {
		return 1, err
	}

	// Create a listener on a random port
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return 1, fmt.Errorf("failed to create listener: %w", err)
	}

	addr := listener.Addr().String()

	// Create pre-shared token
	token, err := srv.Sessions().CreatePresharedToken()
	if err != nil {
		listener.Close()
		return 1, fmt.Errorf("failed to create session token: %w", err)
	}

	// Start server in background with ready signal
	serverErr := make(chan error, 1)
	serverReady := make(chan struct{})
	go func() {
		serverErr <- srv.StartWithListener(listener, "", "", serverReady)
	}()

	// Wait for server to be ready
	select {
	case <-serverReady:
		// Server is ready
	case err := <-serverErr:
		return 1, fmt.Errorf("server failed to start: %w", err)
	}

	// Get TLS certificate path and content (may have been auto-generated)
	tlsCertPath := filepath.Join(vaultPath, "tls", "server.crt")
	certPEM, err := os.ReadFile(tlsCertPath)
	if err != nil {
		srv.Shutdown(context.Background())
		return 1, fmt.Errorf("failed to read TLS certificate: %w", err)
	}

	// Build environment variables for subprocess
	env := os.Environ()

	// Provider variables
	env = append(env, fmt.Sprintf("YUBIVAULT_SERVER_URL=https://%s", addr))
	env = append(env, fmt.Sprintf("YUBIVAULT_TOKEN=%s", token))
	env = append(env, fmt.Sprintf("YUBIVAULT_CA_CERT=%s", tlsCertPath))

	// Backend variables
	stateURL := fmt.Sprintf("https://%s/state/%s", addr, projectName)
	env = append(env, fmt.Sprintf("TF_HTTP_ADDRESS=%s", stateURL))
	env = append(env, fmt.Sprintf("TF_HTTP_LOCK_ADDRESS=%s", stateURL))
	env = append(env, fmt.Sprintf("TF_HTTP_UNLOCK_ADDRESS=%s", stateURL))
	env = append(env, "TF_HTTP_USERNAME=yubivault")
	env = append(env, fmt.Sprintf("TF_HTTP_PASSWORD=%s", token))
	env = append(env, fmt.Sprintf("TF_HTTP_CLIENT_CA_CERTIFICATE_PEM=%s", string(certPEM)))

	fmt.Printf("Starting YubiVault server on %s\n", addr)
	fmt.Printf("Project: %s\n", projectName)
	fmt.Printf("Running: %s %v\n\n", tfBinary, tfArgs)

	// Run terraform/tofu
	cmd := exec.Command(tfBinary, tfArgs...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	cmdErr := cmd.Run()

	// Shutdown server
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv.Shutdown(ctx)

	// Get exit code
	exitCode := 0
	if cmdErr != nil {
		if exitErr, ok := cmdErr.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			return 1, fmt.Errorf("failed to run %s: %w", tfBinary, cmdErr)
		}
	}

	return exitCode, nil
}

// detectTerraformBinary finds tofu or terraform in PATH
func detectTerraformBinary() string {
	// Prefer tofu
	if path, err := exec.LookPath("tofu"); err == nil {
		return path
	}
	// Fall back to terraform
	if path, err := exec.LookPath("terraform"); err == nil {
		return path
	}
	return ""
}
