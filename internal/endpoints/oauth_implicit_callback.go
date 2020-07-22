package endpoints

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-kit/kit/log"
	appconfig "github.com/keyu/oidcapp/config"
)

type oauthImplicitCallbackEndpoint struct {
	logger log.Logger
	config *appconfig.Configuration
}

func (e *oauthImplicitCallbackEndpoint) DecodeRequest(_ context.Context, r *http.Request) (interface{}, error) {
	err := r.FormValue("err")
	if len(err) > 0 {
		e.logger.Log("error implicit callback", err)
		if errDescription := r.FormValue("error_description"); len(errDescription) > 0 {
			return nil, fmt.Errorf("error: %v, description: %v", err, errDescription)
		}
		return nil, errors.New(err)
	}

	accessToken := r.FormValue("access_token")
	if len(accessToken) == 0 {
		return nil, errors.New("access_token not found")
	}

	return accessToken, nil
}

func (e *oauthImplicitCallbackEndpoint) ProcessRequest(_ context.Context, r interface{}) (interface{}, error) {
	return r, nil
}

func (e *oauthImplicitCallbackEndpoint) EncodeResponse(_ context.Context, w http.ResponseWriter, response interface{}) error {
	accessToken, ok := response.(string)
	if !ok {
		return errors.New("not able to get access token")
	}

	e.logger.Log("access token:", accessToken)

	return redirectToHome(w, &TokenResponse{AccessToken: accessToken})
}

// NewOAuthImplicitCallbackEndpoint returns an endpoint for authorize
func NewOAuthImplicitCallbackEndpoint(logger log.Logger, config *appconfig.Configuration) Endpoint {
	return &oauthImplicitCallbackEndpoint{logger, config}
}
