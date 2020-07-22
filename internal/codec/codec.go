package codec

import (
	"encoding/json"
	"net/http"
)

// WriteJSONResponse encodes data and write to response
func WriteJSONResponse(status int, data interface{}, w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(data)
}
