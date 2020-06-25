package privatemcrypt

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"

	mcrypt "github.com/mfpierre/go-mcrypt"
)

// Encrypt takes a given value and encrypts using mcrypt and the provided key,
// and makes it URL safe. Please see notes regarding RFC standards
func Encrypt(raw, key string, rfc ...string) (val string, err error) {
	if len(key) != keyLength {
		err = fmt.Errorf("provided key does not satisfy the key length of 64 chars")
		return
	}

	b, err := encrypt(raw, key)
	if err != nil {
		return
	}

	val = out(b, rfc)

	return
}

// out is used to correctly encode the value so its safe for its conditional use
func out(b []byte, rfc []string) string {
	if len(rfc) > 0 {
		switch strings.ToUpper(rfc[0]) {
		case RFC4648_4:
			return url.QueryEscape(base64.StdEncoding.EncodeToString(b))
		}
	}
	// default is RFC4648_5
	val := base64.StdEncoding.EncodeToString(b)

	val = strings.Replace(val, "+", "-", -1)
	val = strings.Replace(val, "\\", "_", -1)
	val = strings.TrimRight(val, "=")

	return url.QueryEscape(val)
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
