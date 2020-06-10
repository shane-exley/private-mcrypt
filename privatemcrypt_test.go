// +build !release

package privatemcrypt

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_EncryptionDecrytionErr(t *testing.T) {
	var err error

	var tests = []struct {
		key string
	}{
		{ // nothing
			"",
		},
		{ // 1 char under
			"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567891",
		},
		{ // 1 char over
			"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789101",
		},
	}

	for k, test := range tests {
		t.Run(fmt.Sprintf("#%d", k), func(t *testing.T) {
			_, err = Encrypt("blank", test.key)
			assert.NotNil(t, err)

			_, err = Decrypt("blank", test.key)
			assert.NotNil(t, err)
		})
	}
}

func Test_EncryptionDecrytion(t *testing.T) {
	var e, d string
	var err error

	const key = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345678910"

	var tests = []struct {
		message string
	}{
		{
			"secure message",
		},
		{
			"secure & message",
		},
		{
			"test.html",
		},
		{
			"image.jpg",
		},
		{
			"test123@example.com",
		},
		{
			"test1@example.com,test2@example.com\ntest3@example.com,test4@example.com\ntest5@example.com,test6@example.com\n",
		},
	}

	for k, test := range tests {
		t.Run(fmt.Sprintf("#%d", k), func(t *testing.T) {
			e, err = Encrypt(test.message, key)
			assert.Nil(t, err)

			d, err = Decrypt(e, key)
			assert.Nil(t, err)
			assert.Equal(t, test.message, d)
		})
	}
}
