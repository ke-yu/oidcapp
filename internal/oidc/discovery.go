package oidc

import (
	"sync"

	"github.com/keyu/oidcapp/config"
	"github.com/keyu/oidcapp/internal/metadata"
)

const (
	// MetadataURI defined by oidc spec
	MetadataURI = ".well-known/openid-configuration"
)

var (
	configOnce    sync.Once
	configuration *metadata.Metadata
)

// GetMetadata takes org URI and returns metadata
func GetMetadata() (*metadata.Metadata, error) {
	var err error

	configOnce.Do(func() {
		conf := config.GetConfiguration()

		authServer := conf.OAuthServer.OrgURI
		var uri string
		if authServer[len(authServer)-1] == '/' {
			uri = authServer + MetadataURI
		} else {
			uri = authServer + "/" + MetadataURI
		}

		var err error
		configuration, err = metadata.GetMetadata(uri)
		if err != nil {
			return
		}
	})

	return configuration, err
}

// GetJwtKeys returns jwt keys for oidc
func GetJwtKeys() ([]*metadata.JwtKey, error) {
	data, err := GetMetadata()
	if err != nil {
		return nil, err
	}

	return metadata.GetJwtKeys(data)
}
