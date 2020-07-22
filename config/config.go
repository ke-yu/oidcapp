package config

import (
	"fmt"
	"sync"

	"github.com/spf13/viper"
)

var (
	config     *Configuration
	configOnce sync.Once
)

// OAuthServer structure
type OAuthServer struct {
	OrgURI                string
	ClientID              string
	ClientSecret          string
	Callback              string
	OAuthCallback         string
	OAuthImplicitCallback string
	AuthorizeServer       string
}

// Configuration structure
type Configuration struct {
	Addr        string
	MachineKey  string
	OAuthServer *OAuthServer
}

// GetConfiguration returns application configuration
func GetConfiguration() *Configuration {
	configOnce.Do(func() {
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
		viper.AddConfigPath("./config")
		err := viper.ReadInConfig()
		if err != nil {
			panic(fmt.Errorf("fatal error in reading config file: %s", err))
		}

		config = &Configuration{
			Addr:       viper.GetString("server.addr"),
			MachineKey: viper.GetString("server.machineKey"),
			OAuthServer: &OAuthServer{
				OrgURI:                viper.GetString("oauthServer.orgUri"),
				ClientID:              viper.GetString("oauthServer.clientId"),
				ClientSecret:          viper.GetString("oauthServer.clientSecret"),
				Callback:              viper.GetString("oauthServer.callback"),
				OAuthCallback:         viper.GetString("oauthServer.oauthCallback"),
				OAuthImplicitCallback: viper.GetString("oauthServer.oauthImplicitCallback"),
				AuthorizeServer:       viper.GetString("oauthServer.AuthorizeServer"),
			},
		}
	})
	return config
}
