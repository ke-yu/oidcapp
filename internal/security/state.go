package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"github.com/keyu/oidcapp/config"
	"io"
)

func encrypt(key []byte, message string) (string, error) {
	plainText := []byte(message)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	cipherText := make([]byte, aes.BlockSize+len(plainText))

	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

	return base64.URLEncoding.EncodeToString(cipherText), nil
}

func decrypt(key []byte, message string) (string, error) {
	cipherText, err := base64.URLEncoding.DecodeString(message)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	if len(cipherText) < aes.BlockSize {
		err = errors.New("ciphertext block size is too short")
		return "", err
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	return string(cipherText), nil
}

// NewState returns a new state
func NewState() (string, error) {
	conf := config.GetConfiguration()
	return encrypt([]byte(conf.MachineKey), conf.OAuthServer.Callback)
}

// ValidateState validates the state
func ValidateState(state string) error {
	conf := config.GetConfiguration()
	callback, err := decrypt([]byte(conf.MachineKey), state)
	if err != nil {
		return err
	}

	if callback != conf.OAuthServer.Callback {
		return errors.New("invalid state")
	}

	return nil
}
