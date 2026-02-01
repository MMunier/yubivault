package yubikey

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-piv/piv-go/v2/piv"
)

func TestValidateSecretName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		// Valid names
		{"simple", "mysecret", false},
		{"with-hyphen", "my-secret", false},
		{"with-underscore", "my_secret", false},
		{"with-numbers", "secret123", false},
		{"uppercase", "MySecret", false},
		{"mixed", "My-Secret_123", false},
		{"single-char", "a", false},
		{"long-name", strings.Repeat("a", 255), false},

		// Invalid names - empty
		{"empty", "", true},

		// Invalid names - too long
		{"too-long", strings.Repeat("a", 256), true},

		// Invalid names - starts with invalid char
		{"starts-with-hyphen", "-secret", true},
		{"starts-with-underscore", "_secret", true},
		// Note: Numbers at start ARE allowed by the regex [a-zA-Z0-9]
		{"starts-with-number", "123secret", false},
		{"starts-with-dot", ".secret", true},

		// Invalid names - contains invalid characters
		{"with-dot", "my.secret", true},
		{"with-slash", "my/secret", true},
		{"with-backslash", "my\\secret", true},
		{"with-space", "my secret", true},
		{"path-traversal", "../secret", true},
		{"absolute-path", "/etc/passwd", true},
		{"with-colon", "my:secret", true},
		{"with-at", "my@secret", true},
		{"with-asterisk", "my*secret", true},
		{"with-question", "my?secret", true},
		{"with-quote", "my\"secret", true},
		{"with-angle", "my<secret>", true},
		{"with-pipe", "my|secret", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSecretName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateSecretName(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestValidateVaultPath(t *testing.T) {
	// Create temp directory for tests
	tmpDir, err := os.MkdirTemp("", "vault-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a regular directory
	regularDir := filepath.Join(tmpDir, "vault")
	if err := os.MkdirAll(regularDir, 0700); err != nil {
		t.Fatalf("Failed to create test dir: %v", err)
	}

	// Create a symlink
	symlinkPath := filepath.Join(tmpDir, "symlink")
	if err := os.Symlink(regularDir, symlinkPath); err != nil {
		t.Fatalf("Failed to create symlink: %v", err)
	}

	// Create a file (not a directory)
	filePath := filepath.Join(tmpDir, "file")
	if err := os.WriteFile(filePath, []byte("test"), 0600); err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		// Valid paths
		{"existing-directory", regularDir, false},
		{"non-existent-in-existing-parent", filepath.Join(tmpDir, "newvault"), false},

		// Invalid paths
		{"empty-path", "", true},
		{"symlink", symlinkPath, true},
		{"file-not-dir", filePath, true},
		{"non-existent-parent", filepath.Join(tmpDir, "nonexistent", "vault"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidateVaultPath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateVaultPath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}
}

func TestValidateVaultPath_ReturnsAbsolutePath(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "vault-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Change to temp dir
	oldWd, _ := os.Getwd()
	defer os.Chdir(oldWd)
	os.Chdir(tmpDir)

	// Create a relative path directory
	relPath := "myvault"
	os.MkdirAll(relPath, 0700)

	resolved, err := ValidateVaultPath(relPath)
	if err != nil {
		t.Fatalf("ValidateVaultPath failed: %v", err)
	}

	if !filepath.IsAbs(resolved) {
		t.Errorf("Expected absolute path, got %s", resolved)
	}

	expected := filepath.Join(tmpDir, relPath)
	if resolved != expected {
		t.Errorf("Expected %s, got %s", expected, resolved)
	}
}

func TestCheckVaultPermissions(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "vault-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	tests := []struct {
		name    string
		mode    os.FileMode
		wantErr bool
	}{
		{"secure-0700", 0700, false},
		{"world-readable", 0755, true},
		{"world-writable", 0777, true},
		{"group-readable", 0740, true},
		{"group-writable", 0770, true},
		{"other-readable", 0704, true},
		{"other-writable", 0707, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testDir := filepath.Join(tmpDir, tt.name)
			if err := os.MkdirAll(testDir, tt.mode); err != nil {
				t.Fatalf("Failed to create test dir: %v", err)
			}
			// Force the permissions (MkdirAll might be affected by umask)
			if err := os.Chmod(testDir, tt.mode); err != nil {
				t.Fatalf("Failed to chmod test dir: %v", err)
			}

			err := CheckVaultPermissions(testDir)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckVaultPermissions(%s) with mode %04o error = %v, wantErr %v",
					testDir, tt.mode, err, tt.wantErr)
			}
		})
	}
}

func TestCheckVaultPermissions_NonExistent(t *testing.T) {
	// Non-existent paths should return nil (will be created with correct perms)
	err := CheckVaultPermissions("/nonexistent/path/that/does/not/exist")
	if err != nil {
		t.Errorf("Expected nil for non-existent path, got %v", err)
	}
}

func TestResolveVaultPath(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "vault-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a secure directory
	secureDir := filepath.Join(tmpDir, "secure")
	os.MkdirAll(secureDir, 0700)

	// Create an insecure directory
	insecureDir := filepath.Join(tmpDir, "insecure")
	os.MkdirAll(insecureDir, 0755)

	tests := []struct {
		name       string
		path       string
		checkPerms bool
		wantErr    bool
	}{
		{"secure-with-check", secureDir, true, false},
		{"secure-without-check", secureDir, false, false},
		{"insecure-with-check", insecureDir, true, true},
		{"insecure-without-check", insecureDir, false, false},
		// Note: filepath.Join normalizes paths, so use string directly for path traversal test
		{"path-traversal", secureDir + "/../vault", false, true},
		{"empty-path", "", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ResolveVaultPath(tt.path, tt.checkPerms)
			if (err != nil) != tt.wantErr {
				t.Errorf("ResolveVaultPath(%q, %v) error = %v, wantErr %v",
					tt.path, tt.checkPerms, err, tt.wantErr)
			}
		})
	}
}

func TestResolveVaultPath_PathTraversal(t *testing.T) {
	tests := []string{
		"../vault",
		"vault/../secret",
		"/tmp/../etc/passwd",
		"./vault/../../etc",
	}

	for _, path := range tests {
		t.Run(path, func(t *testing.T) {
			_, err := ResolveVaultPath(path, false)
			if err == nil {
				t.Errorf("Expected error for path traversal attempt: %s", path)
			}
			if !strings.Contains(err.Error(), "..") {
				t.Errorf("Expected error about '..' in path, got: %v", err)
			}
		})
	}
}

func TestParseSlot(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected piv.Slot
		wantErr  bool
	}{
		// Valid slots
		{"9a", "9a", piv.SlotAuthentication, false},
		{"9c", "9c", piv.SlotSignature, false},
		{"9d", "9d", piv.SlotKeyManagement, false},
		{"9e", "9e", piv.SlotCardAuthentication, false},

		// Case insensitivity
		{"9A-upper", "9A", piv.SlotAuthentication, false},
		{"9D-upper", "9D", piv.SlotKeyManagement, false},

		// Whitespace handling
		{"9d-with-spaces", "  9d  ", piv.SlotKeyManagement, false},
		{"9d-with-tabs", "\t9d\t", piv.SlotKeyManagement, false},

		// Invalid slots
		{"invalid-9b", "9b", piv.Slot{}, true},
		{"invalid-empty", "", piv.Slot{}, true},
		{"invalid-text", "auth", piv.Slot{}, true},
		{"invalid-hex", "0x9d", piv.Slot{}, true},
		{"invalid-number", "1", piv.Slot{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			slot, err := ParseSlot(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSlot(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && slot != tt.expected {
				t.Errorf("ParseSlot(%q) = %v, want %v", tt.input, slot, tt.expected)
			}
		})
	}
}

func TestZeroBytes(t *testing.T) {
	// Create a byte slice with some data
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	original := make([]byte, len(data))
	copy(original, data)

	// Verify data is not zero
	isZero := true
	for _, b := range data {
		if b != 0 {
			isZero = false
			break
		}
	}
	if isZero {
		t.Fatal("Test data should not be all zeros initially")
	}

	// Zero the bytes
	zeroBytes(data)

	// Verify all bytes are zero
	for i, b := range data {
		if b != 0 {
			t.Errorf("Byte at index %d is %d, expected 0", i, b)
		}
	}
}

func TestZeroBytes_EmptySlice(t *testing.T) {
	// Should not panic on empty slice
	data := []byte{}
	zeroBytes(data)
}

func TestZeroBytes_NilSlice(t *testing.T) {
	// Should not panic on nil slice
	var data []byte
	zeroBytes(data)
}

func TestValidSecretNamePattern(t *testing.T) {
	// Test the regex pattern directly for edge cases
	tests := []struct {
		input   string
		matches bool
	}{
		{"a", true},
		{"A", true},
		{"0a", true},   // numbers at start ARE allowed by regex [a-zA-Z0-9]
		{"a0", true},
		{"a-b", true},
		{"a_b", true},
		{"a-", true},   // trailing hyphen is allowed
		{"a_", true},   // trailing underscore is allowed
		{"-a", false},  // leading hyphen not allowed
		{"_a", false},  // leading underscore not allowed
		{"a b", false}, // space not allowed
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			matches := validSecretNamePattern.MatchString(tt.input)
			if matches != tt.matches {
				t.Errorf("Pattern match for %q = %v, want %v", tt.input, matches, tt.matches)
			}
		})
	}
}

func TestValidateVaultPath_SymlinkInParent(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "vault-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a real directory
	realDir := filepath.Join(tmpDir, "real")
	os.MkdirAll(realDir, 0700)

	// Create a symlink to it
	symlinkDir := filepath.Join(tmpDir, "link")
	os.Symlink(realDir, symlinkDir)

	// Try to use a path through the symlink
	pathThroughSymlink := filepath.Join(symlinkDir, "vault")
	os.MkdirAll(filepath.Join(realDir, "vault"), 0700)

	_, err = ValidateVaultPath(pathThroughSymlink)
	if err == nil {
		t.Error("Expected error for path containing symlink in parent")
	}
}

// Benchmark tests
func BenchmarkValidateSecretName(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ValidateSecretName("my-secret-name-123")
	}
}

func BenchmarkParseSlot(b *testing.B) {
	for i := 0; i < b.N; i++ {
		ParseSlot("9d")
	}
}
