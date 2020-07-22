package metadata

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-resty/resty/v2"
)

// JwtKey representation
type JwtKey struct {
	KeyType   string `json:"kty"`
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Use       string `json:"use"`
	Exponent  string `json:"e"`
	Modulus   string `json:"n"`
	RSAKey    *rsa.PublicKey
}

type jwtKeys struct {
	Keys []*JwtKey `json:"keys"`
}

// GetJwtKeys returns JSON web keys
func GetJwtKeys(metadata *Metadata) ([]*JwtKey, error) {
	if metadata == nil {
		return nil, errors.New("\"metadata\" cannot be nil")

	}
	jwtKeysEndpoint := metadata.JwtKeysEndpoint
	if len(jwtKeysEndpoint) == 0 {
		return nil, errors.New("jwks_uri not found")
	}

	resp, err := resty.New().R().SetResult(&jwtKeys{}).Get(jwtKeysEndpoint)
	if err != nil {
		return nil, err
	}

	if !resp.IsSuccess() {
		return nil, fmt.Errorf("failed to get jwt keys, response status code = %v", resp.StatusCode())
	}

	keys, ok := resp.Result().(*jwtKeys)
	if !ok {
		return nil, errors.New("failed to cast the result to *JwtKey")
	}

	for _, key := range keys.Keys {
		decodedN, err := base64.RawURLEncoding.DecodeString(key.Modulus)
		if err != nil {
			return nil, err
		}

		n := new(big.Int)
		n = n.SetBytes(decodedN)

		decodedE, err := base64.RawURLEncoding.DecodeString(key.Exponent)
		if err != nil {
			return nil, err
		}

		var buf bytes.Buffer
		buf.WriteByte(0)
		buf.Write(decodedE)
		e := binary.BigEndian.Uint32(buf.Bytes())

		key.RSAKey = &rsa.PublicKey{
			N: n,
			E: int(e),
		}
	}

	return keys.Keys, nil
}

// GetJwtKeyFunc returns a jwt.KeyFunc
func GetJwtKeyFunc(keys []*JwtKey) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		if len(keys) == 0 {
			return nil, errors.New("\"keys\" is empty")
		}

		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v in token", token.Header["alg"])
		}

		keyID, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("\"kid\" is not found in jwt token header")
		}

		var key *JwtKey
		for _, k := range keys {
			if k.KeyID == keyID {
				key = k
				break
			}
		}

		if key == nil {
			return nil, fmt.Errorf("cannot find kid \"%v\" in jwt keys", keyID)
		}

		return key.RSAKey, nil
	}
}
