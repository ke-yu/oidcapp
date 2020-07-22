package endpoints

import (
	"encoding/base64"
)

func getDigest(clientID, clientSecret string) string {
	digest := base64.StdEncoding.EncodeToString([]byte(clientID + ":" + clientSecret))
	return digest
}
