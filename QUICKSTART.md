# Quick Start Guide

## Prerequisites Setup

### 1. Generate PIV key on YubiKey

```bash
# Install ykman if not already installed
# Arch: sudo pacman -S yubikey-manager
# Ubuntu: sudo apt install yubikey-manager

# Generate RSA-2048 key in slot 9d with cached touch policy (15 second cache)
ykman piv keys generate --algorithm RSA2048 --touch-policy cached 9d pubkey.pem

# Create self-signed certificate
ykman piv certificates generate --subject "CN=yubivault" 9d pubkey.pem
```

### 2. Build the project

```bash
make build
# or: go mod download && go build -o yubivault ./cmd/yubivault && go build
```

## Usage Flow

### Step 1: Initialize vault

```bash
export YUBIVAULT_PATH=./vault
export YUBIKEY_PIN=123456  # Your PIV PIN (default is 123456)

./yubivault init
```

**Expected output:**
```
Initializing vault at: ./vault
Using PIV slot: 9d
✓ Vault initialized successfully
✓ Master key encrypted and saved to: ./vault/master.key
```

### Step 2: Store secrets

```bash
# Database password
echo -n "super-secret-password" | ./yubivault encrypt db_password

# API key
echo -n "sk-1234567890abcdef" | ./yubivault encrypt api_key

# Multi-line secret (JSON config)
cat <<'EOF' | ./yubivault encrypt app_config
{
  "database": {
    "host": "db.example.com",
    "port": 5432
  },
  "api_key": "secret123"
}
EOF
```

### Step 3: Test decryption

```bash
./yubivault decrypt db_password
# Output: super-secret-password
```

### Step 4: Install Terraform provider

```bash
make install
# This copies the provider to ~/.terraform.d/plugins/
```

### Step 5: Use in Terraform

Create `test.tf`:

```hcl
terraform {
  required_providers {
    yubivault = {
      source  = "mmunier/yubivault"
      version = "0.1.0"
    }
  }

  # Encrypted state backend - configured automatically by yubivault run
  backend "http" {}
}

# Provider configured automatically via environment variables
provider "yubivault" {}

data "yubivault_secret" "db_password" {
  name = "db_password"
}

output "password_loaded" {
  value = "Password length: ${length(data.yubivault_secret.db_password.value)}"
}
```

Run Terraform using `yubivault run`:

```bash
yubivault run init   # Initialize Terraform
yubivault run plan   # Touch YubiKey once, then plan runs
```

## Architecture Explained

```
Initialization:
1. Generate random 256-bit AES master key
2. Encrypt master key with YubiKey PIV public key (PKCS#1 v1.5)
3. Save encrypted master key to vault/master.key

Storing Secrets:
1. Load encrypted master key
2. Decrypt master key with YubiKey (requires touch)
3. Encrypt secret with master key (AES-256-GCM with AAD)
4. Save to vault/secrets/<name>.enc

Terraform Run (yubivault run):
1. Start HTTPS server on random port
2. Load and decrypt master key with YubiKey (one touch!)
3. Run terraform/tofu as subprocess with credentials
4. Server decrypts secrets on-demand
5. Shutdown server when terraform completes
```

## Troubleshooting

### "no YubiKey found"
```bash
# Check if YubiKey is detected
lsusb | grep Yubico

# Check ykman can see it
ykman list
```

### "failed to get certificate from slot 9d"
You need to generate a key first (see Prerequisites Setup step 1)

### Touch not working
```bash
# Check current touch policy
ykman piv info

# View detailed touch policy for a specific slot
ykman piv keys info 9d

# Note: Touch policy is set during key generation only.
# To change touch policy, you must regenerate the key:
ykman piv keys generate --touch-policy always 9d pubkey.pem     # Most secure
ykman piv keys generate --touch-policy cached 9d pubkey.pem     # Better UX (15s cache)

# ⚠️ Warning: Regenerating the key creates a NEW key pair.
# You'll need to re-initialize the vault and re-encrypt all secrets.
```

## Next Steps

- Read README.md for full documentation
- Check examples/basic/ for more complex usage
- Set up backup YubiKey for redundancy
- Integrate with your existing Terraform infrastructure
