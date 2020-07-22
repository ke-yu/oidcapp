package endpoints

import (
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
	appconfig "github.com/keyu/oidcapp/config"
	"github.com/keyu/oidcapp/internal/oauth"
	"github.com/keyu/oidcapp/internal/oidc"
)

var (
	client     *resty.Client
	clientOnce sync.Once
)

func newTokenRequest(digest string) *resty.Request {
	clientOnce.Do(func() {
		client = resty.New().SetTimeout(5 * time.Second)
	})

	return client.R().
		EnableTrace().
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		SetHeader("Accept", "application/json").
		SetHeader("Authorization", "Basic "+digest)
}

func getTokenEndpoint() (string, error) {
	metadata, err := oauth.GetMetadata()
	if err != nil {
		return "", err
	}

	return metadata.TokenEndpoint, nil
}

func sendAuthorizationCodeRequest(config *appconfig.Configuration, code string) (*resty.Response, error) {
	endpoint, err := getTokenEndpoint()
	if err != nil {
		return nil, err
	}

	digest := getDigest(config.OAuthServer.ClientID, config.OAuthServer.ClientSecret)

	return newTokenRequest(digest).
		SetFormData(map[string]string{
			oidc.GrantType:   oidc.GrantTypeAuthorizationCode,
			oidc.Code:        code,
			oidc.RedirectURI: config.OAuthServer.OAuthCallback,
			// "code_verifier":  "M25iVXpKU3puUjFaYWg3T1NDTDQtcW1ROUY5YXlwalNoc0hhkxifmZHag",
		}).
		SetResult(&TokenResponse{}).
		Post(endpoint)
}

func sendClientCredentialsRequest(config *appconfig.Configuration) (*resty.Response, error) {
	endpoint, err := getTokenEndpoint()
	if err != nil {
		return nil, err
	}

	digest := getDigest(config.OAuthServer.ClientID, config.OAuthServer.ClientSecret)

	return newTokenRequest(digest).
		SetFormData(map[string]string{
			oidc.GrantType: oidc.GrantTypeClientCredentials,
			oidc.Scope:     "sample_1",
		}).
		SetResult(&AccessTokenResponse{}).
		Post(endpoint)
}

func sendPasswordRequest(config *appconfig.Configuration, username, password, clientID, clientSecret string) (*resty.Response, error) {
	endpoint, err := getTokenEndpoint()
	if err != nil {
		return nil, err
	}

	var digest string
	if len(clientID) == 0 || len(clientSecret) == 0 {
		digest = getDigest(config.OAuthServer.ClientID, config.OAuthServer.ClientSecret)
	} else {
		digest = getDigest(clientID, clientSecret)
	}

	return newTokenRequest(digest).
		SetFormData(map[string]string{
			oidc.GrantType: oidc.GrantTypePassword,
			oidc.Scope:     oidc.ScopeOpenID,
			"username":     username,
			"password":     password,
		}).
		SetResult(&AccessTokenResponse{}).
		Post(endpoint)
}
