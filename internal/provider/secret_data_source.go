package provider

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var _ datasource.DataSource = &SecretDataSource{}

func NewSecretDataSource() datasource.DataSource {
	return &SecretDataSource{}
}

type SecretDataSource struct {
	providerData *ProviderData
}

type SecretDataSourceModel struct {
	Name  types.String `tfsdk:"name"`
	Value types.String `tfsdk:"value"`
}

func (d *SecretDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_secret"
}

func (d *SecretDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Reads an encrypted secret from the vault",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Description: "Name of the secret to retrieve",
				Required:    true,
			},
			"value": schema.StringAttribute{
				Description: "Decrypted secret value",
				Computed:    true,
				Sensitive:   true,
			},
		},
	}
}

func (d *SecretDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	providerData, ok := req.ProviderData.(*ProviderData)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *ProviderData, got: %T", req.ProviderData),
		)
		return
	}

	d.providerData = providerData
}

func (d *SecretDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data SecretDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	secretName := data.Name.ValueString()
	tflog.Debug(ctx, "Reading secret from server", map[string]interface{}{
		"name": secretName,
	})

	// Fetch secret from yubivault server
	url := fmt.Sprintf("%s/secret/%s", d.providerData.ServerURL, secretName)
	httpResp, err := http.Get(url)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to connect to yubivault server",
			fmt.Sprintf("Could not reach server at %s: %s", d.providerData.ServerURL, err),
		)
		return
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode == http.StatusNotFound {
		resp.Diagnostics.AddError(
			"Secret not found",
			fmt.Sprintf("Secret '%s' does not exist in the vault", secretName),
		)
		return
	}

	if httpResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(httpResp.Body)
		resp.Diagnostics.AddError(
			"Failed to retrieve secret",
			fmt.Sprintf("Server returned status %d: %s", httpResp.StatusCode, string(body)),
		)
		return
	}

	plaintext, err := io.ReadAll(httpResp.Body)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to read secret response",
			fmt.Sprintf("Error reading response: %s", err),
		)
		return
	}

	data.Value = types.StringValue(string(plaintext))

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
