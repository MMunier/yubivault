package provider

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/mmunier/terraform-provider-yubivault/internal/yubikey"
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

	tflog.Debug(ctx, "Reading secret", map[string]any{
		"name": data.Name.ValueString(),
	})

	// Initialize YubiKey vault
	vault, err := yubikey.NewVault(
		d.providerData.VaultPath,
		d.providerData.PivSlot,
		d.providerData.PivPin,
	)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to initialize YubiKey vault",
			fmt.Sprintf("Error: %s", err),
		)
		return
	}
	defer vault.Close()

	// Read encrypted secret file
	secretPath := filepath.Join(d.providerData.VaultPath, "secrets", data.Name.ValueString()+".enc")
	ciphertext, err := os.ReadFile(secretPath)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to read secret file",
			fmt.Sprintf("Secret: %s, Error: %s", data.Name.ValueString(), err),
		)
		return
	}

	// Decrypt secret
	plaintext, err := vault.DecryptSecret(ciphertext)
	if err != nil {
		resp.Diagnostics.AddError(
			"Failed to decrypt secret",
			fmt.Sprintf("Secret: %s, Error: %s", data.Name.ValueString(), err),
		)
		return
	}

	data.Value = types.StringValue(string(plaintext))

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
