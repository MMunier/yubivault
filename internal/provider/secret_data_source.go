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

	// Get authentication token (may require YubiKey touch)
	token, err := d.providerData.GetAuthToken(ctx)
	if err != nil {
		resp.Diagnostics.AddError(
			"Authentication failed",
			fmt.Sprintf("Failed to authenticate with yubivault server: %s", err),
		)
		return
	}

	// Fetch secret from yubivault server with retry on auth failure
	plaintext, err := d.fetchSecret(ctx, secretName, token)
	if err != nil {
		// If unauthorized and we had a token, clear it and retry
		if token != "" && isUnauthorizedError(err) {
			tflog.Debug(ctx, "Token expired, re-authenticating")
			d.providerData.ClearToken()

			token, err = d.providerData.GetAuthToken(ctx)
			if err != nil {
				resp.Diagnostics.AddError(
					"Authentication failed",
					fmt.Sprintf("Failed to re-authenticate with yubivault server: %s", err),
				)
				return
			}

			plaintext, err = d.fetchSecret(ctx, secretName, token)
		}

		if err != nil {
			resp.Diagnostics.AddError(
				"Failed to retrieve secret",
				err.Error(),
			)
			return
		}
	}

	data.Value = types.StringValue(string(plaintext))

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (d *SecretDataSource) fetchSecret(ctx context.Context, secretName, token string) ([]byte, error) {
	url := fmt.Sprintf("%s/secret/%s", d.providerData.ServerURL, secretName)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add auth header if we have a token
	if token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+token)
	}

	client, err := d.providerData.GetHTTPClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	httpResp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("could not reach server at %s: %w", d.providerData.ServerURL, err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode == http.StatusUnauthorized {
		return nil, &unauthorizedError{message: "authentication required"}
	}

	if httpResp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("secret '%s' does not exist in the vault", secretName)
	}

	if httpResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(httpResp.Body)
		return nil, fmt.Errorf("server returned status %d: %s", httpResp.StatusCode, string(body))
	}

	return io.ReadAll(httpResp.Body)
}

type unauthorizedError struct {
	message string
}

func (e *unauthorizedError) Error() string {
	return e.message
}

func isUnauthorizedError(err error) bool {
	_, ok := err.(*unauthorizedError)
	return ok
}
