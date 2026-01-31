package provider

import (
	"context"
	"fmt"
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
	ServerURL types.String `tfsdk:"server_url"`
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
				Description: "URL of yubivault server (e.g., http://localhost:8099)",
				Required:    true,
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
		ServerURL: config.ServerURL.ValueString(),
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
	ServerURL string

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
		p.fido2Client = NewFIDO2Client(p.ServerURL)
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
