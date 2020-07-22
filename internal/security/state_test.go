package security

import (
	assertion "github.com/stretchr/testify/assert"
	"testing"
)

func TestEncryptAndDescrypt(t *testing.T) {
	assert := assertion.New(t)

	key := []byte("4t7w!z%C*F-J@NcRfUjXn2r5u8x/A?D(")
	message, err := encrypt(key, "helloworld")
	assert.Nil(err)

	decrypted, err := decrypt(key, message)
	assert.Equal("helloworld", decrypted)
}
