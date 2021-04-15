// +build !release

package privatemcrypt

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Test_EncryptionDecrytionFailure(t *testing.T) {
	var err error
	_, err = Decrypt("bad", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345678910", RFC4648_4)
	assert.NotNil(t, err)

	_, err = Decrypt("bad", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345678910")
	assert.NotNil(t, err)
}

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
		message, rfc string
	}{
		// uses default RFC4648_5
		{
			message: "secure message",
		},
		{
			message: "secure & message",
		},
		{
			message: "test.html",
		},
		{
			message: "image.jpg",
		},
		{
			message: "test123@example.com",
		},
		{
			message: "test1@example.com,test2@example.com\ntest3@example.com,test4@example.com\ntest5@example.com,test6@example.com\n",
		},
		// uses RFC4648_4
		{
			message: "secure message",
			rfc:     RFC4648_4,
		},
		{
			message: "secure & message",
			rfc:     RFC4648_4,
		},
		{
			message: "test.html",
			rfc:     RFC4648_4,
		},
		{
			message: "image.jpg",
			rfc:     RFC4648_4,
		},
		{
			message: "test123@example.com",
			rfc:     RFC4648_4,
		},
		{
			message: "test1@example.com,test2@example.com\ntest3@example.com,test4@example.com\ntest5@example.com,test6@example.com\n",
			rfc:     RFC4648_4,
		},
	}

	for k, test := range tests {
		t.Run(fmt.Sprintf("#%d", k), func(t *testing.T) {
			e, err = Encrypt(test.message, key, test.rfc)
			assert.Nil(t, err)

			d, err = Decrypt(e, key, test.rfc)
			assert.Nil(t, err)
			assert.Equal(t, test.message, d)
		})
	}
}

func Test_DecrytionBackwardsCompatibility(t *testing.T) {
	const key = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345678910"

	for k := 0; k < 5000; k++ {
		t.Run(fmt.Sprintf("#%d", k), func(t *testing.T) {
			// encrypt value in RFC4648 §4 format
			e, err := Encrypt(fmt.Sprintf("Test #%d", k), key, RFC4648_4)
			assert.Nil(t, err)

			// decrypt value in RFC4648 §5 format
			d, err := Decrypt(e, key, RFC4648_5)
			assert.Nil(t, err)
			assert.Equal(t, fmt.Sprintf("Test #%d", k), d)
		})
	}
}
