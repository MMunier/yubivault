package provider

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var _ provider.Provider = &YubivaultProvider{}

type YubivaultProvider struct {
	version string
}

type YubivaultProviderModel struct {
	ServerURL          types.String `tfsdk:"server_url"`
	TLSCACert          types.String `tfsdk:"tls_ca_cert"`
	InsecureSkipVerify types.Bool   `tfsdk:"insecure_skip_verify"`
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &YubivaultProvider{
			version: version,
		}
	}
}

func (p *YubivaultProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "yubivault"
	resp.Version = p.version
}

func (p *YubivaultProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Terraform provider for secrets encrypted with YubiKey PIV as trust anchor. Requires yubivault server to be running.",
		Attributes: map[string]schema.Attribute{
			"server_url": schema.StringAttribute{
				Description: "URL of yubivault server (e.g., https://localhost:8099). Always use https:// as the server only supports TLS.",
				Required:    true,
			},
			"tls_ca_cert": schema.StringAttribute{
				Description: "Path to CA certificate file for verifying the server's certificate. If not set, the provider will automatically try to load the certificate from ${YUBIVAULT_PATH}/tls/server.crt (useful when provider and server share the same vault directory).",
				Optional:    true,
			},
			"insecure_skip_verify": schema.BoolAttribute{
				Description: "Skip TLS certificate verification (INSECURE - for development only). A warning will be logged if enabled.",
				Optional:    true,
			},
		},
	}
}

func (p *YubivaultProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config YubivaultProviderModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Create provider data that will be passed to data sources and resources
	providerData := &ProviderData{
		ServerURL:          config.ServerURL.ValueString(),
		TLSCACert:          config.TLSCACert.ValueString(),
		InsecureSkipVerify: config.InsecureSkipVerify.ValueBool(),
	}

	// Warn if insecure mode is enabled
	if providerData.InsecureSkipVerify {
		tflog.Warn(ctx, "TLS certificate verification is DISABLED (insecure_skip_verify=true) - this should only be used for development")
	}

	resp.DataSourceData = providerData
	resp.ResourceData = providerData
}

func (p *YubivaultProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{}
}

func (p *YubivaultProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewSecretDataSource,
	}
}

type ProviderData struct {
	ServerURL          string
	TLSCACert          string
	InsecureSkipVerify bool

	// Authentication state
	mu           sync.Mutex
	fido2Client  *FIDO2Client
	sessionToken string
	tokenExpiry  time.Time
}

// GetAuthToken returns a valid session token, authenticating if necessary
func (p *ProviderData) GetAuthToken(ctx context.Context) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Check if we have a valid token
	if p.sessionToken != "" && time.Now().Before(p.tokenExpiry) {
		return p.sessionToken, nil
	}

	// Initialize FIDO2 client if needed
	if p.fido2Client == nil {
		p.fido2Client = NewFIDO2Client(p)
	}

	tflog.Info(ctx, "Authenticating with FIDO2 - touch your YubiKey")
	fmt.Println("\n[yubivault] Touch your YubiKey to authenticate...")

	// Authenticate
	token, expiry, err := p.fido2Client.Authenticate()
	if err != nil {
		return "", fmt.Errorf("FIDO2 authentication failed: %w", err)
	}

	// Empty token means auth not required (no credentials registered)
	if token == "" {
		return "", nil
	}

	p.sessionToken = token
	p.tokenExpiry = expiry

	tflog.Info(ctx, "Authentication successful", map[string]interface{}{
		"expires_at": expiry.Format(time.RFC3339),
	})

	return token, nil
}

// ClearToken clears the cached session token (used on auth failure)
func (p *ProviderData) ClearToken() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sessionToken = ""
	p.tokenExpiry = time.Time{}
}

// GetHTTPClient returns an HTTP client configured with TLS settings
func (p *ProviderData) GetHTTPClient() (*http.Client, error) {
	tlsConfig := &tls.Config{}

	// If insecure mode is enabled, skip verification
	if p.InsecureSkipVerify {
		tlsConfig.InsecureSkipVerify = true
		return &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
			},
		}, nil
	}

	// Try to load CA certificate with priority:
	// 1. Explicit tls_ca_cert path
	// 2. ${YUBIVAULT_PATH}/tls/server.crt
	// 3. ./vault/tls/server.crt (default)
	var caCertPath string

	if p.TLSCACert != "" {
		// Priority 1: Use explicitly configured path
		caCertPath = p.TLSCACert
	} else {
		// Priority 2: Try YUBIVAULT_PATH env var
		vaultPath := os.Getenv("YUBIVAULT_PATH")
		if vaultPath == "" {
			// Priority 3: Use default ./vault
			vaultPath = "vault"
		}
		caCertPath = filepath.Join(vaultPath, "tls", "server.crt")
	}

	// Try to load the CA certificate
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		// If we can't load the cert and it wasn't explicitly specified, use system defaults
		if p.TLSCACert == "" {
			// No custom cert found, use system certificate pool
			return &http.Client{}, nil
		}
		return nil, fmt.Errorf("failed to read CA certificate from %s: %w", caCertPath, err)
	}

	// Create certificate pool and add our CA cert
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate from %s", caCertPath)
	}

	tlsConfig.RootCAs = caCertPool

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}, nil
}
