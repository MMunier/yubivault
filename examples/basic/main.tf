terraform {
  required_providers {
    yubivault = {
      source  = "mmunier/yubivault"
      version = "0.1.0"
    }
  }

  # Encrypted state backend using YubiVault
  # Run with: yubivault run plan
  #
  # The yubivault run command automatically:
  # - Starts the HTTPS server on a random port
  # - Sets TF_HTTP_* environment variables for the backend
  # - Authenticates with your YubiKey once
  # - Runs terraform/tofu with proper credentials
  # - Shuts down the server when done
  #
  # Project name defaults to current directory name (basic)
  # Override with: yubivault run --project myproject plan
  backend "http" {
    # Configuration provided via environment variables by yubivault run
  }
}

# Provider connects to yubivault server for secrets
# Configuration is automatic when using: yubivault run plan
provider "yubivault" {
  # server_url provided via YUBIVAULT_SERVER_URL by yubivault run
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
#
# Usage:
#   1. Initialize vault:     yubivault init
#   2. Store secrets:        echo "mypassword" | yubivault encrypt db_password
#   3. Initialize terraform: yubivault run init
#   4. Plan changes:         yubivault run plan
#   5. Apply changes:        yubivault run apply
