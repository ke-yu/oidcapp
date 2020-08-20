package endpoints

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-kit/kit/log"
	appconfig "github.com/keyu/oidcapp/config"
)

type oauthCallbackPKCEEndpoint struct {
	logger log.Logger
	config *appconfig.Configuration
}

func (e *oauthCallbackPKCEEndpoint) DecodeRequest(_ context.Context, r *http.Request) (interface{}, error) {
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

	e.logger.Log("code", code)
	return code, nil
}

func (e *oauthCallbackPKCEEndpoint) ProcessRequest(_ context.Context, r interface{}) (interface{}, error) {
	code, ok := r.(string)
	if !ok {
		return nil, errors.New("code is not a string")
	}

	resp, err := sendCodeVerifierRequest(e.config, code)
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

func (e *oauthCallbackPKCEEndpoint) EncodeResponse(_ context.Context, w http.ResponseWriter, response interface{}) error {
	tokenResponse, ok := response.(*TokenResponse)
	if !ok || tokenResponse == nil {
		return errors.New("not able to get gettoken response")
	}

	return redirectToHome(w, tokenResponse)
}

// NewOAuthCallbackPKCEEndpoint returns an endpoint for authorize
func NewOAuthCallbackPKCEEndpoint(logger log.Logger, config *appconfig.Configuration) Endpoint {
	return &oauthCallbackPKCEEndpoint{logger, config}
}
