package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-piv/piv-go/piv"
	"github.com/mmunier/terraform-provider-yubivault/internal/yubikey"
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
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: yubivault <command>")
	fmt.Println("\nCommands:")
	fmt.Println("  init              Initialize a new vault")
	fmt.Println("  encrypt <name>    Encrypt a secret (reads from stdin)")
	fmt.Println("  decrypt <name>    Decrypt a secret")
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
	pivSlot, err := parseSlot(slot)
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
		fmt.Scanln(&pin)
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

	// Encrypt secret
	ciphertext, err := vault.EncryptSecret(plaintext)
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
		fmt.Scanln(&pin)
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

	// Decrypt secret
	plaintext, err := vault.DecryptSecret(ciphertext)
	if err != nil {
		return err
	}

	fmt.Print(string(plaintext))

	return nil
}

func parseSlot(s string) (piv.Slot, error) {
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
