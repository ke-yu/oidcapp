package endpoints

import (
	"context"
	"net/http"
)

// Endpoint represents endpoint
type Endpoint interface {
	DecodeRequest(context.Context, *http.Request) (interface{}, error)
	ProcessRequest(context.Context, interface{}) (interface{}, error)
	EncodeResponse(context.Context, http.ResponseWriter, interface{}) error
}
