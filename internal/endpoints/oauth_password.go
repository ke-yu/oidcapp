package endpoints

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-kit/kit/log"
	appconfig "github.com/keyu/oidcapp/config"
)

type passwordEndpoint struct {
	logger log.Logger
	config *appconfig.Configuration
}

type credential struct {
	UserName     string
	Password     string
	ClientID     string
	ClientSecret string
}

// NewPasswordEndpoint returns an endpoint for oauth /token
func NewPasswordEndpoint(logger log.Logger, config *appconfig.Configuration) Endpoint {
	return &passwordEndpoint{logger, config}
}

func (e *passwordEndpoint) DecodeRequest(_ context.Context, r *http.Request) (interface{}, error) {
	return &credential{
		UserName:     r.PostFormValue("username"),
		Password:     r.PostFormValue("password"),
		ClientID:     r.PostFormValue("clientid"),
		ClientSecret: r.PostFormValue("clientsecret"),
	}, nil
}

func (e *passwordEndpoint) ProcessRequest(_ context.Context, r interface{}) (interface{}, error) {
	c, ok := r.(*credential)
	if !ok {
		return nil, errors.New("not able to convert to credential")
	}

	resp, err := sendPasswordRequest(e.config, c.UserName, c.Password, c.ClientID, c.ClientSecret)
	if err != nil {
		e.logger.Log("error", err)
		return nil, err
	}

	if !resp.IsSuccess() {
		return nil, fmt.Errorf("password workflow response status: %v, response: %v", resp.StatusCode(), string(resp.Body()))
	}

	return resp.Result(), nil
}

func (e *passwordEndpoint) EncodeResponse(_ context.Context, w http.ResponseWriter, response interface{}) error {
	if accessTokenResponse, ok := response.(*AccessTokenResponse); ok {
		e.logger.Log("access_token", accessTokenResponse.AccessToken)
		tokenReponse := &TokenResponse{
			AccessToken: accessTokenResponse.AccessToken,
		}
		return redirectToHome(w, tokenReponse)
	}

	return errors.New("not able to get access token response")
}
