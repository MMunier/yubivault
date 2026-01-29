terraform {
  required_providers {
    yubivault = {
      source  = "mmunier/yubivault"
      version = "0.1.0"
    }
  }

  # Encrypted state backend using YubiVault
  # Start the server first: yubivault serve
  backend "http" {
    address        = "http://localhost:8099/state/basic"
    lock_address   = "http://localhost:8099/state/basic"
    unlock_address = "http://localhost:8099/state/basic"
  }
}

# Provider connects to yubivault server for secrets
# Start server first: yubivault serve
provider "yubivault" {
  server_url = "http://localhost:8099"
}

# Read a single secret
data "yubivault_secret" "database_password" {
  name = "db_password"
}

# Read multiple secrets
data "yubivault_secret" "api_key" {
  name = "api_key"
}

data "yubivault_secret" "tls_cert" {
  name = "tls_certificate"
}

# Example usage with other providers
output "db_password_length" {
  value     = length(data.yubivault_secret.database_password.value)
  sensitive = true
}

output "secrets_loaded" {
  value = "Successfully loaded secrets from YubiKey vault"
}

# The actual secret values are marked sensitive and won't be displayed
# Access them in other resources like:
#
# resource "aws_db_instance" "example" {
#   password = data.yubivault_secret.database_password.value
# }
