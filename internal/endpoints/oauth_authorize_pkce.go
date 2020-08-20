package endpoints

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/go-kit/kit/log"
	appconfig "github.com/keyu/oidcapp/config"
	"github.com/keyu/oidcapp/internal/oauth"
	"github.com/keyu/oidcapp/internal/oidc"
	"github.com/keyu/oidcapp/internal/security"
)

type oauthAuthorizePKCEEndpoint struct {
	logger log.Logger
	config *appconfig.Configuration
}

// NewOAuthAuthorizePKCEEndpoint returns an endpoint for oauth authorize
func NewOAuthAuthorizePKCEEndpoint(logger log.Logger, config *appconfig.Configuration) Endpoint {
	return &oauthAuthorizePKCEEndpoint{logger, config}
}

func (e *oauthAuthorizePKCEEndpoint) DecodeRequest(_ context.Context, r *http.Request) (interface{}, error) {
	return nil, nil
}

func (e *oauthAuthorizePKCEEndpoint) ProcessRequest(_ context.Context, r interface{}) (interface{}, error) {
	return r, nil
}

func (e *oauthAuthorizePKCEEndpoint) EncodeResponse(_ context.Context, w http.ResponseWriter, response interface{}) error {
	metadata, err := oauth.GetMetadata()
	if err != nil {
		return err
	}

	authorizeURL, err := url.Parse(metadata.AuthorizationEndpoint)
	if err != nil {
		return err
	}

	var payload *authorizePayload
	if response != nil {
		payload = response.(*authorizePayload)
	}
	authorizeURL.RawQuery, err = e.buildAuthorizeParameters(payload)
	if err != nil {
		return err
	}

	w.Header().Set("Location", authorizeURL.String())
	w.WriteHeader(http.StatusFound)
	e.logger.Log("msg", fmt.Sprintf("redirect to %v", authorizeURL.String()))

	return nil
}

func (e *oauthAuthorizePKCEEndpoint) buildAuthorizeParameters(payload *authorizePayload) (string, error) {
	state, err := security.NewState()
	if err != nil {
		return "", err
	}

	params := url.Values{}
	params.Add(oidc.ResponseType, oidc.ResponseTypeCode /*"token"*/)
	params.Add(oidc.RedirectURI, e.config.OAuthServer.OAuthPKCECallback)
	params.Add(oidc.Scope, oidc.ScopeOpenIDEmailOffline)
	params.Add(oidc.State, state)
	params.Add(oidc.ClientID, "0oath1rv8dR26uy2G0h7")
	params.Add(oidc.Nonce, "foo")
	params.Add("code_challenge_method", "S256")
	params.Add("code_challenge", "qjrzSW9gMiUgpUvqgEPE4_-8swvyCtfOVvg55o5S_es")

	return params.Encode(), nil
}
