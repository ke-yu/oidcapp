package endpoints

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-kit/kit/log"
	appconfig "github.com/keyu/oidcapp/config"
	"github.com/keyu/oidcapp/internal/metadata"
	"github.com/keyu/oidcapp/internal/oidc"
	"github.com/keyu/oidcapp/internal/security"
)

type callbackEndpoint struct {
	logger log.Logger
	config *appconfig.Configuration
}

func (e *callbackEndpoint) DecodeRequest(_ context.Context, r *http.Request) (interface{}, error) {
	query := r.URL.Query()
	if err := query.Get("error"); len(err) > 0 {
		return nil, errors.New(err)
	}

	code := query.Get("code")
	if len(code) == 0 {
		return nil, errors.New("code is not found")
	}

	state := query.Get("state")
	if len(state) == 0 {
		return nil, errors.New("state is not found")
	}

	err := security.ValidateState(state)
	if err != nil {
		return nil, err
	}

	e.logger.Log("code", code)
	return code, nil
}

func (e *callbackEndpoint) ProcessRequest(_ context.Context, r interface{}) (interface{}, error) {
	code, ok := r.(string)
	if !ok {
		return nil, errors.New("code is not a string")
	}

	metadata, err := oidc.GetMetadata()
	if err != nil {
		return nil, err
	}

	digest := getDigest(e.config.OAuthServer.ClientID, e.config.OAuthServer.ClientSecret)
	resp, err := newTokenRequest(digest).
		SetFormData(map[string]string{
			oidc.GrantType:   oidc.GrantTypeAuthorizationCode,
			oidc.Code:        code,
			oidc.RedirectURI: e.config.OAuthServer.Callback,
		}).
		SetResult(&TokenResponse{}).
		Post(metadata.TokenEndpoint)

	e.logger.Log("gettoken", resp.Request.URL)
	if err != nil {
		return nil, err
	}

	if !resp.IsSuccess() {
		return nil, fmt.Errorf("get token response status: %v", resp.StatusCode())
	}

	return resp.Result(), nil
}

func (e *callbackEndpoint) EncodeResponse(_ context.Context, w http.ResponseWriter, response interface{}) error {
	tokenResponse, ok := response.(*TokenResponse)
	if !ok || tokenResponse == nil {
		return errors.New("not able to get gettoken response")
	}

	idToken := tokenResponse.IDToken
	e.logger.Log("id_token", idToken)

	keys, err := oidc.GetJwtKeys()
	if err != nil {
		return err
	}

	token, err := jwt.Parse(idToken, metadata.GetJwtKeyFunc(keys))
	if err != nil {
		return err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		e.logger.Log("email", claims["email"])
	}

	return redirectToHome(w, tokenResponse)
}

// NewCallbackEndpoint returns an endpoint for authorize
func NewCallbackEndpoint(logger log.Logger, config *appconfig.Configuration) Endpoint {
	return &callbackEndpoint{logger, config}
}
