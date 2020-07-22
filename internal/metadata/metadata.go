package metadata

import (
	"errors"
	"fmt"

	"github.com/go-resty/resty/v2"
)

// Metadata represents oidc/oauth server metadata
type Metadata struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JwtKeysEndpoint       string `json:"jwks_uri"`
}

// GetMetadata returns configuration information
func GetMetadata(metadataURI string) (*Metadata, error) {
	if len(metadataURI) == 0 {
		return nil, errors.New("empty metadata URI")
	}

	client := resty.New()
	resp, err := client.R().SetResult(&Metadata{}).Get(metadataURI)
	if err != nil {
		return nil, err
	}

	if !resp.IsSuccess() {
		err = fmt.Errorf("failed to get configuration information from endpoint %v, response status code = %v", metadataURI, resp.StatusCode())
		return nil, err
	}

	result, ok := resp.Result().(*Metadata)
	if !ok {
		return nil, errors.New("failed to cast the result to *Metadata")
	}

	return result, nil
}
