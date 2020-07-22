package endpoints

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/go-kit/kit/log"
	appconfig "github.com/keyu/oidcapp/config"
	"github.com/keyu/oidcapp/internal/oidc"
	"github.com/keyu/oidcapp/internal/security"
)

type authorizeEndpoint struct {
	logger log.Logger
	config *appconfig.Configuration
}

// NewAuthorizeEndpoint returns an endpoint for authorize
func NewAuthorizeEndpoint(logger log.Logger, config *appconfig.Configuration) Endpoint {
	return &authorizeEndpoint{logger, config}
}

func (e *authorizeEndpoint) DecodeRequest(_ context.Context, r *http.Request) (interface{}, error) {
	query := r.URL.Query()
	if idp := query.Get("idp"); len(idp) > 0 {
		return idp, nil
	}

	return nil, nil
}

func (e *authorizeEndpoint) ProcessRequest(_ context.Context, r interface{}) (interface{}, error) {
	return r, nil
}

func (e *authorizeEndpoint) EncodeResponse(_ context.Context, w http.ResponseWriter, response interface{}) error {
	metadata, err := oidc.GetMetadata()
	if err != nil {
		return err
	}

	authorizeURL, err := url.Parse(metadata.AuthorizationEndpoint)
	if err != nil {
		return err
	}

	var idp string
	if response != nil {
		idp = response.(string)
	}
	authorizeURL.RawQuery, err = e.buildAuthorizeParameters(idp)
	if err != nil {
		return err
	}

	w.Header().Set("Location", authorizeURL.String())
	w.WriteHeader(http.StatusFound)
	e.logger.Log("msg", fmt.Sprintf("redirect to %v", authorizeURL.String()))

	return nil
}

func (e *authorizeEndpoint) buildAuthorizeParameters(idp string) (string, error) {
	state, err := security.NewState()
	if err != nil {
		return "", err
	}

	params := url.Values{}
	params.Add(oidc.ResponseType, oidc.ResponseTypeCode)
	params.Add(oidc.Scope, oidc.ScopeOpenIDEmail)
	params.Add(oidc.State, state)
	if len(idp) > 0 {
		params.Add("idp", idp)
	}
	params.Add(oidc.ClientID, e.config.OAuthServer.ClientID)
	params.Add(oidc.RedirectURI, e.config.OAuthServer.Callback)
	return params.Encode(), nil
}
