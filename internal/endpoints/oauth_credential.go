package endpoints

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-kit/kit/log"
	appconfig "github.com/keyu/oidcapp/config"
)

type clientCredentialsEndpoint struct {
	logger log.Logger
	config *appconfig.Configuration
}

// NewOAuthClientCredentialEndpoint returns an endpoint for oauth authorize
func NewOAuthClientCredentialEndpoint(logger log.Logger, config *appconfig.Configuration) Endpoint {
	return &clientCredentialsEndpoint{logger, config}
}

func (e *clientCredentialsEndpoint) DecodeRequest(_ context.Context, r *http.Request) (interface{}, error) {
	return nil, nil
}

func (e *clientCredentialsEndpoint) ProcessRequest(_ context.Context, r interface{}) (interface{}, error) {
	resp, err := sendClientCredentialsRequest(e.config)
	if err != nil {
		e.logger.Log("error", err)
		return nil, err
	}

	if !resp.IsSuccess() {
		return nil, fmt.Errorf("client_credentials workflow response status: %v, response: %v", resp.StatusCode(), string(resp.Body()))
	}

	return resp.Result(), nil
}

func (e *clientCredentialsEndpoint) EncodeResponse(_ context.Context, w http.ResponseWriter, response interface{}) error {
	if accessTokenResponse, ok := response.(*AccessTokenResponse); ok {
		e.logger.Log("access_token", accessTokenResponse.AccessToken)
		tokenReponse := &TokenResponse{
			AccessToken: accessTokenResponse.AccessToken,
		}
		return redirectToHome(w, tokenReponse)
	}

	return errors.New("not able to get access token response")
}
