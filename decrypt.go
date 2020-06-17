package privatemcrypt

import (
	"encoding/base64"
	"fmt"
	"net/url"

	mcrypt "github.com/mfpierre/go-mcrypt"
)

// Decrypt takes a given value and decrypts using mcrypt
func Decrypt(cipher, key string) (raw string, err error) {
	if len(key) != keyLength {
		err = fmt.Errorf("provided key does not satisfy the key length of 64 chars")
		return
	}
	// needs to be url decoded
	d, err := url.QueryUnescape(cipher)
	if err != nil {
		return
	}

	encrypted, err := base64.StdEncoding.DecodeString(d)
	if err != nil {
		return
	}

	return decrypt(encrypted, key)
}

// decrypt uses mcrypt to perform cross language decryption
func decrypt(encrypted []byte, key string) (string, error) {
	_, size, err := iv(cipherRijndael128, modeCBC)
	if err != nil {
		return "", err
	}

	en := string(encrypted)
	iv := en[0:size]

	if len(iv) != size {
		return "", fmt.Errorf("encrypted value iv length incompatible match to cipher type: received %d", len(iv))
	}

	d, err := mcrypt.Decrypt(parseKey(key), []byte(iv), []byte(en[size:]), cipherRijndael128, modeCBC)
	if err != nil {
		return "", err
	}

	return string(d), nil
}
