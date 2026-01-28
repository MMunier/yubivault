# Terraform Provider YubiVault

A lightweight Terraform provider that uses YubiKey PIV as a hardware trust anchor for secrets management.

## Architecture

```
┌─────────────────┐
│   YubiKey PIV   │
│   (Slot 9d)     │
│                 │
│  Private Key    │◄────── Decrypts Master Key (once per run)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Master Key    │
│   (AES-256)     │◄────── Stored encrypted on disk
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│    Secrets      │
│  (encrypted)    │◄────── Fast symmetric encryption
└─────────────────┘
```

**Benefits:**
- Hardware-backed root of trust
- One YubiKey touch unlocks all secrets for Terraform run
- No cloud HSM costs
- Secrets can't be decrypted without physical YubiKey presence

## Prerequisites

1. **YubiKey with PIV support** (YubiKey 4+)
2. **PIV key generated** in slot 9d (Key Management):

```bash
# Generate RSA-2048 key in slot 9d with cached touch policy
ykman piv keys generate --algorithm RSA2048 --touch-policy cached 9d pubkey.pem

# Generate self-signed certificate
ykman piv certificates generate --subject "CN=yubivault" 9d pubkey.pem
```

## Installation

### Build from source

```bash
go mod download
go build -o yubivault ./cmd/yubivault
go build -o terraform-provider-yubivault
```

### Install Terraform provider

```bash
# Create provider directory
mkdir -p ~/.terraform.d/plugins/registry.terraform.io/mmunier/yubivault/0.1.0/linux_amd64

# Copy provider binary
cp terraform-provider-yubivault ~/.terraform.d/plugins/registry.terraform.io/mmunier/yubivault/0.1.0/linux_amd64/
```

## Quick Start

### 1. Initialize vault

```bash
export YUBIVAULT_PATH=./vault
export YUBIVAULT_SLOT=9d
export YUBIKEY_PIN=123456

./yubivault init
```

This creates:
- `vault/master.key` - Master encryption key (encrypted by YubiKey)
- `vault/secrets/` - Directory for encrypted secrets

### 2. Add secrets

```bash
# Store a secret
echo -n "my-database-password" | ./yubivault encrypt db_password

# Store multi-line secret
cat <<EOF | ./yubivault encrypt api_config
{
  "api_key": "secret123",
  "endpoint": "https://api.example.com"
}
EOF
```

### 3. Use in Terraform

```hcl
terraform {
  required_providers {
    yubivault = {
      source  = "mmunier/yubivault"
      version = "0.1.0"
    }
  }
}

provider "yubivault" {
  vault_path = "./vault"
  piv_slot   = "9d"
  piv_pin    = "123456"  # Or use YUBIKEY_PIN env var
}

data "yubivault_secret" "db_password" {
  name = "db_password"
}

resource "postgresql_database" "example" {
  name     = "mydb"
  password = data.yubivault_secret.db_password.value
}
```

### 4. Run Terraform

```bash
terraform init
terraform plan  # Touch YubiKey once to decrypt master key
terraform apply
```

## Configuration

### Environment Variables

- `YUBIVAULT_PATH` - Vault directory path (default: `./vault`)
- `YUBIVAULT_SLOT` - PIV slot to use (default: `9d`)
- `YUBIKEY_PIN` - PIV PIN for authentication

### PIV Slots

| Slot | Name | Purpose | Recommended Use |
|------|------|---------|-----------------|
| `9a` | Authentication | Login/SSH | Not recommended for vault |
| `9c` | Signature | Code signing | Not recommended for vault |
| `9d` | Key Management | Encryption | **Recommended for vault** |
| `9e` | Card Authentication | Physical access | Not recommended for vault |

## Security Considerations

### Touch Policy

⚠️ **Important:** Touch policy can only be set during key generation. To change the touch policy, you must regenerate the key pair, which means:
- Your old master.key will no longer be decryptable
- You'll need to run `yubivault init` again to create a new master key
- You'll need to re-encrypt all secrets

Configure touch caching for better UX during Terraform runs:

```bash
# View current touch policy:
ykman piv keys info 9d

# To change touch policy, regenerate the key:
# Cached touch (15 second cache, better UX)
ykman piv keys generate --touch-policy cached 9d pubkey.pem

# Always require touch (most secure)
ykman piv keys generate --touch-policy always 9d pubkey.pem
```

### PIN Protection

- Never hardcode PIN in Terraform files
- Use environment variable: `export YUBIKEY_PIN=123456`
- Or use provider configuration with sensitive variable

### Backup Strategy

⚠️ **Critical:** If you lose your YubiKey, you lose access to secrets!

**Backup options:**
1. **Multiple YubiKeys**: Generate same key on backup YubiKey
2. **Backup master key**: Securely store decrypted master key offline
3. **Re-encrypt secrets**: Keep plaintext secrets in secure vault, re-encrypt if needed

## CLI Commands

```bash
# Initialize vault
yubivault init

# Encrypt secret (reads from stdin)
echo "secret" | yubivault encrypt my-secret

# Decrypt secret (prints to stdout)
yubivault decrypt my-secret

# Batch encrypt
for secret in db_password api_key; do
  echo "value-$secret" | yubivault encrypt $secret
done
```

## Development

### Running provider locally

```bash
# Build provider
go build -o terraform-provider-yubivault

# Debug mode
go build -o terraform-provider-yubivault
TF_LOG=DEBUG terraform plan
```

### Testing

```bash
# Unit tests
go test ./...

# Integration test with YubiKey
go test ./internal/yubikey -v
```

## Troubleshooting

### "no YubiKey found"
- Ensure YubiKey is plugged in
- Check permissions: `lsusb | grep Yubico`
- May need udev rules on Linux

### "failed to get certificate from slot 9d"
- Generate PIV key first: `ykman piv keys generate 9d pubkey.pem`
- Generate certificate: `ykman piv certificates generate 9d pubkey.pem`

### "decryption failed"
- Wrong PIN: Check `YUBIKEY_PIN`
- Wrong slot: Ensure slot matches initialization
- Corrupted vault: Re-initialize and re-encrypt secrets

## Limitations

- **Single YubiKey dependency**: No cloud backup/recovery
- **No secret versioning**: Rotating secrets requires re-encryption
- **No access control**: Anyone with YubiKey + PIN can decrypt all secrets
- **CI/CD challenges**: Requires physical YubiKey presence (or remote access solution)

## License

MIT

## Contributing

Issues and PRs welcome at: https://github.com/mmunier/terraform-provider-yubivault
