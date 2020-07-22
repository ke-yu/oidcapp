module github.com/keyu/oidcapp

go 1.13

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/go-delve/delve v1.4.0 // indirect
	github.com/go-kit/kit v0.10.0
	github.com/go-resty/resty v1.12.0
	github.com/go-resty/resty/v2 v2.2.0
	github.com/gorilla/mux v1.7.4
	github.com/spf13/viper v1.6.3
	github.com/stretchr/testify v1.4.0
	gopkg.in/resty.v1 v1.12.0
)

replace github.com/go-resty/resty => gopkg.in/resty.v1 v1.11.0
