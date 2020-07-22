package endpoints

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-kit/kit/log"
	appconfig "github.com/keyu/oidcapp/config"
)

type oauthCallbackEndpoint struct {
	logger log.Logger
	config *appconfig.Configuration
}

func (e *oauthCallbackEndpoint) DecodeRequest(_ context.Context, r *http.Request) (interface{}, error) {
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

	/*
		err := security.ValidateState(state)
		if err != nil {
			return nil, err
		}
	*/

	e.logger.Log("code", code)
	return code, nil
}

func (e *oauthCallbackEndpoint) ProcessRequest(_ context.Context, r interface{}) (interface{}, error) {
	code, ok := r.(string)
	if !ok {
		return nil, errors.New("code is not a string")
	}

	resp, err := sendAuthorizationCodeRequest(e.config, code)
	if err != nil {
		e.logger.Log("error", err)
		return nil, err
	}

	if !resp.IsSuccess() {
		return nil, fmt.Errorf("authorization_code workflow response status: %v, response: %v", resp.StatusCode(), string(resp.Body()))
	}

	e.logger.Log("callback response", resp)

	traceInfo := resp.Request.TraceInfo()
	e.logger.Log(
		"DNSLookup", traceInfo.DNSLookup,
		"ConnTime", traceInfo.ConnTime,
		"TLSHandshakeTime", traceInfo.TLSHandshake,
		"ServerTime", traceInfo.ServerTime,
		"ResponseTime", traceInfo.ServerTime,
		"TotalTime", traceInfo.TotalTime,
	)
	return resp.Result(), nil
}

func (e *oauthCallbackEndpoint) EncodeResponse(_ context.Context, w http.ResponseWriter, response interface{}) error {
	tokenResponse, ok := response.(*TokenResponse)
	if !ok || tokenResponse == nil {
		return errors.New("not able to get gettoken response")
	}

	return redirectToHome(w, tokenResponse)
}

// NewOAuthCallbackEndpoint returns an endpoint for authorize
func NewOAuthCallbackEndpoint(logger log.Logger, config *appconfig.Configuration) Endpoint {
	return &oauthCallbackEndpoint{logger, config}
}
