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
}
