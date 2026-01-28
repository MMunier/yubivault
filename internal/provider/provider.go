package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ provider.Provider = &YubivaultProvider{}

type YubivaultProvider struct {
	version string
}

type YubivaultProviderModel struct {
	VaultPath types.String `tfsdk:"vault_path"`
	PivSlot   types.String `tfsdk:"piv_slot"`
	PivPin    types.String `tfsdk:"piv_pin"`
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
		Description: "Terraform provider for secrets encrypted with YubiKey PIV as trust anchor",
		Attributes: map[string]schema.Attribute{
			"vault_path": schema.StringAttribute{
				Description: "Path to the vault directory containing encrypted secrets",
				Required:    true,
			},
			"piv_slot": schema.StringAttribute{
				Description: "PIV slot to use (default: 9d - Key Management)",
				Optional:    true,
			},
			"piv_pin": schema.StringAttribute{
				Description: "PIV PIN (can also be set via YUBIKEY_PIN environment variable)",
				Optional:    true,
				Sensitive:   true,
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
		VaultPath: config.VaultPath.ValueString(),
		PivSlot:   config.PivSlot.ValueString(),
		PivPin:    config.PivPin.ValueString(),
	}

	// Default to slot 9d if not specified
	if providerData.PivSlot == "" {
		providerData.PivSlot = "9d"
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
	VaultPath string
	PivSlot   string
	PivPin    string
}
