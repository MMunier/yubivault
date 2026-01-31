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
		Description: "Terraform provider for secrets encrypted with YubiKey PIV as trust anchor. Requires yubivault server to be running. When used with 'yubivault run', configuration is automatic via environment variables.",
		Attributes: map[string]schema.Attribute{
			"server_url": schema.StringAttribute{
				Description: "URL of yubivault server (e.g., https://localhost:8099). Can also be set via YUBIVAULT_SERVER_URL environment variable.",
				Optional:    true,
			},
			"tls_ca_cert": schema.StringAttribute{
				Description: "Path to CA certificate file for verifying the server's certificate. Can also be set via YUBIVAULT_CA_CERT environment variable.",
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

	// Determine server URL: config takes precedence over env var
	serverURL := config.ServerURL.ValueString()
	if serverURL == "" {
		serverURL = os.Getenv("YUBIVAULT_SERVER_URL")
	}
	if serverURL == "" {
		resp.Diagnostics.AddError(
			"Missing Server URL",
			"server_url must be set in provider configuration or YUBIVAULT_SERVER_URL environment variable",
		)
		return
	}

	// Determine TLS CA cert: config takes precedence over env var
	tlsCACert := config.TLSCACert.ValueString()
	if tlsCACert == "" {
		tlsCACert = os.Getenv("YUBIVAULT_CA_CERT")
	}

	// Check for pre-shared token from yubivault run
	token := os.Getenv("YUBIVAULT_TOKEN")

	// Create provider data that will be passed to data sources and resources
	providerData := &ProviderData{
		ServerURL:          serverURL,
		TLSCACert:          tlsCACert,
		InsecureSkipVerify: config.InsecureSkipVerify.ValueBool(),
		sessionToken:       token,
	}

	// If we have a pre-shared token, it never expires (subprocess lifetime)
	if token != "" {
		providerData.tokenExpiry = time.Now().Add(100 * 365 * 24 * time.Hour)
		tflog.Info(ctx, "Using pre-shared token from YUBIVAULT_TOKEN environment variable")
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
	sessionToken string
	tokenExpiry  time.Time
}

// GetAuthToken returns a valid session token
// When running via 'yubivault run', the token is provided via YUBIVAULT_TOKEN env var
func (p *ProviderData) GetAuthToken(ctx context.Context) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Check if we have a valid token
	if p.sessionToken != "" && time.Now().Before(p.tokenExpiry) {
		return p.sessionToken, nil
	}

	// No valid token available - when using 'yubivault run', token should always be present
	return "", nil
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
