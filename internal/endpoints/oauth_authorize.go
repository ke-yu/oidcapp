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

type oauthAuthorizeEndpoint struct {
	logger log.Logger
	config *appconfig.Configuration
}

type authorizePayload struct {
	idp      string
	implicit bool
}

// NewOAuthAuthorizeEndpoint returns an endpoint for oauth authorize
func NewOAuthAuthorizeEndpoint(logger log.Logger, config *appconfig.Configuration) Endpoint {
	return &oauthAuthorizeEndpoint{logger, config}
}

func (e *oauthAuthorizeEndpoint) DecodeRequest(_ context.Context, r *http.Request) (interface{}, error) {
	var idp string
	var implicit bool

	if r.Method == http.MethodPost {
		idp = r.FormValue("idp")
		implicit = r.FormValue("implicit") == "on"
		e.logger.Log("idp", idp)
		e.logger.Log("implicit", r.FormValue("implicit"))
	} else {
		query := r.URL.Query()
		idp = query.Get("idp")
	}

	return &authorizePayload{
		idp:      idp,
		implicit: implicit,
	}, nil
}

func (e *oauthAuthorizeEndpoint) ProcessRequest(_ context.Context, r interface{}) (interface{}, error) {
	return r, nil
}

func (e *oauthAuthorizeEndpoint) EncodeResponse(_ context.Context, w http.ResponseWriter, response interface{}) error {
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

func (e *oauthAuthorizeEndpoint) buildAuthorizeParameters(payload *authorizePayload) (string, error) {
	state, err := security.NewState()
	if err != nil {
		return "", err
	}

	params := url.Values{}
	if payload != nil && payload.implicit {
		params.Add(oidc.ResponseType, oidc.ResponseTypeToken /*"token"*/)
		params.Add(oidc.RedirectURI, e.config.OAuthServer.OAuthImplicitCallback)
		params.Add("response_mode", "form_post")
	} else {
		params.Add(oidc.ResponseType, oidc.ResponseTypeCode /*"token"*/)
		params.Add(oidc.RedirectURI, e.config.OAuthServer.OAuthCallback)
	}
	params.Add(oidc.Scope, oidc.ScopeOpenIDEmailOffline)
	params.Add(oidc.State, state)
	if payload != nil && len(payload.idp) > 0 {
		params.Add("idp", payload.idp)
	}
	params.Add(oidc.ClientID, e.config.OAuthServer.ClientID)
	params.Add(oidc.Nonce, "foo")
	// params.Add("code_challenge_method", "S256")
	// params.Add("code_challenge", "qjrzSW9gMiUgpUvqgEPE4_-8swvyCtfOVvg55o5S_es")
	return params.Encode(), nil
}
