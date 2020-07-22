package endpoints

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/go-kit/kit/log"
	"github.com/keyu/oidcapp/config"
)

// HomePageModel for homepage
type HomePageModel struct {
	AccessToken        string `json:"access_token"`
	RefreshToken       string `json:"refresh_token"`
	DecodedAccessToken string `json:"decoded_access_token"`
	Email              string `json:"email"`
}

type templateAndModel struct {
	template *template.Template
	model    *HomePageModel
}

type homeEndpoint struct {
	logger log.Logger
	config *config.Configuration
}

// NewHomeEndpoint returns an endpoint for home page
func NewHomeEndpoint(logger log.Logger, config *config.Configuration) Endpoint {
	return &homeEndpoint{logger, config}
}

func (e *homeEndpoint) DecodeRequest(_ context.Context, r *http.Request) (interface{}, error) {
	homePageModel := &HomePageModel{}
	query := r.URL.Query()
	if query != nil {
		accessToken := query.Get("access_token")
		if len(accessToken) > 0 {
			homePageModel.AccessToken = accessToken

			jwtParts := strings.Split(accessToken, ".")
			if decodedBuffer, err := base64.RawStdEncoding.DecodeString(jwtParts[1]); err == nil {
				homePageModel.DecodedAccessToken = string(decodedBuffer)
			} else {
				homePageModel.DecodedAccessToken = err.Error()
			}
		}
		refreshToken := query.Get("refresh_token")
		if len(refreshToken) > 0 {
			homePageModel.RefreshToken = refreshToken
		}
	}

	return homePageModel, nil
}

func (e *homeEndpoint) ProcessRequest(_ context.Context, r interface{}) (interface{}, error) {
	appRoot, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	indexTemplFile := filepath.Join(appRoot, "./web", "index.html")
	tmpl, err := template.ParseFiles(indexTemplFile)
	if err != nil {
		return nil, err
	}

	model, ok := r.(*HomePageModel)
	if !ok {
		return nil, errors.New("invalid home page model")
	}

	return &templateAndModel{
		template: tmpl,
		model:    model,
	}, nil
}

func (e *homeEndpoint) EncodeResponse(_ context.Context, w http.ResponseWriter, response interface{}) error {
	tm, ok := response.(*templateAndModel)
	if !ok {
		return errors.New("invalidate template")
	}

	err := tm.template.Execute(w, tm.model)
	if err != nil {
		return err
	}

	return nil
}

func redirectToHome(w http.ResponseWriter, tokenReponse *TokenResponse) error {
	homeURL, err := url.Parse("http://localhost:3000/")
	if err != nil {
		return err
	}

	params := url.Values{}
	params.Add("access_token", tokenReponse.AccessToken)
	params.Add("refresh_token", tokenReponse.RefreshToken)
	homeURL.RawQuery = params.Encode()

	w.Header().Set("Location", homeURL.String())
	w.WriteHeader(http.StatusFound)

	return nil
}
