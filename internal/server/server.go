package server

import (
	"context"
	"net/http"
	"strings"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/transport"
	httptransport "github.com/go-kit/kit/transport/http"
	"github.com/gorilla/mux"
	appconfig "github.com/keyu/oidcapp/config"
	"github.com/keyu/oidcapp/internal/codec"
	"github.com/keyu/oidcapp/internal/endpoints"
)

func register(r *mux.Router,
	path string,
	methods []string,
	ep endpoints.Endpoint,
	options []httptransport.ServerOption) {

	r.NewRoute().Path(strings.ToLower(path)).Methods(methods...).Handler(httptransport.NewServer(
		ep.ProcessRequest,
		ep.DecodeRequest,
		ep.EncodeResponse,
		options...))
}

func registerCaseInsensitiveServer(r *mux.Router) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		req.URL.Path = strings.ToLower(req.URL.Path)
		r.ServeHTTP(w, req)
	})
}

func newServerErrorEncoder() httptransport.ErrorEncoder {
	return func(_ context.Context, err error, w http.ResponseWriter) {
		status := http.StatusInternalServerError
		codec.WriteJSONResponse(status, map[string]interface{}{
			"error": err.Error(),
		}, w)
	}
}

type logErrorHandler struct {
	logger log.Logger
}

func (l *logErrorHandler) Handle(_ context.Context, err error) {
	l.logger.Log(err.Error())
}

func newLogErrorHandler(logger log.Logger) transport.ErrorHandler {
	return &logErrorHandler{logger}
}

// NewServer returns a http server.
func NewServer(logger log.Logger, config *appconfig.Configuration) http.Handler {
	r := mux.NewRouter()

	options := []httptransport.ServerOption{
		httptransport.ServerErrorEncoder(newServerErrorEncoder()),
		httptransport.ServerErrorHandler(newLogErrorHandler(logger)),
	}

	r.PathPrefix("/css/").Handler(http.StripPrefix("/css/", http.FileServer(http.Dir("./web/css"))))
	register(r, "/", []string{http.MethodGet, http.MethodPost}, endpoints.NewHomeEndpoint(logger, config), options)
	register(r, "/authorize", []string{http.MethodGet}, endpoints.NewAuthorizeEndpoint(logger, config), options)
	register(r, "/callback", []string{http.MethodGet}, endpoints.NewCallbackEndpoint(logger, config), options)
	register(r, "/oauth_authorize", []string{http.MethodGet, http.MethodPost}, endpoints.NewOAuthAuthorizeEndpoint(logger, config), options)
	register(r, "/oauth_callback", []string{http.MethodGet}, endpoints.NewOAuthCallbackEndpoint(logger, config), options)
	register(r, "/oauth_implicit_callback", []string{http.MethodGet, http.MethodPost}, endpoints.NewOAuthImplicitCallbackEndpoint(logger, config), options)
	register(r, "/oauth_clientcredentail", []string{http.MethodGet}, endpoints.NewOAuthClientCredentialEndpoint(logger, config), options)
	register(r, "/oauth_password", []string{http.MethodPost}, endpoints.NewPasswordEndpoint(logger, config), options)

	return registerCaseInsensitiveServer(r)
}
