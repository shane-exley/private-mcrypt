package privatemcrypt

import (
	"encoding/base64"
	"fmt"
	"net/url"

	mcrypt "github.com/mfpierre/go-mcrypt"
)

// Encrypt takes a given value and encrypts using mcrypt and the provided key,
// and makes it URL safe
func Encrypt(raw, key string) (val string, err error) {
	if len(key) != keyLength {
		err = fmt.Errorf("provided key does not satisfy the key length of 64 chars")
		return
	}

	b, err := encrypt(raw, key)
	if err != nil {
		return
	}
	val = url.QueryEscape(base64.StdEncoding.EncodeToString(b))

	return
}

// encrypt uses mcrypt to perform cross language encryption
func encrypt(plaintext, key string) ([]byte, error) {
	iv, _, err := iv(cipherRijndael128, modeCBC)
	if err != nil {
		return []byte(``), err
	}

	encrypted, err := mcrypt.Encrypt(parseKey(key), iv, []byte(plaintext), cipherRijndael128, modeCBC)
	if err != nil {
		return []byte(``), err
	}

	return []byte(string(iv) + string(encrypted)), nil
}
