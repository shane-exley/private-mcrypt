package privatemcrypt

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"

	mcrypt "github.com/mfpierre/go-mcrypt"
)

// Decrypt takes a given value and decrypts using mcrypt
func Decrypt(cipher, key string, rfc ...string) (raw string, err error) {
	if len(key) != keyLength {
		err = fmt.Errorf("provided key does not satisfy the key length of 64 chars")
		return
	}

	encrypted, err := in(cipher, rfc)
	if err != nil {
		return
	}

	return decrypt(encrypted, key)
}

// in is used to correctly decode the value from conditional
func in(s string, rfc []string) ([]byte, error) {
	val, err := url.QueryUnescape(s)
	if err != nil {
		return []byte(``), err
	}

	if len(rfc) > 0 {
		switch strings.ToUpper(rfc[0]) {
		case RFC4648_4:
			return base64.StdEncoding.DecodeString(val)
		}
	}

	// default is RFC4648_5, this means swpping back the previously swapped characters
	v := strings.Replace(val, "-", "+", -1)
	v = strings.Replace(v, "_", "\\", -1)
	// lets pad with the "="
	v = func(str string, length int, pad string) string {
		padding := func(str string, n int) string {
			if n >= 4 {
				return ""
			}
			return strings.Repeat(str, n)
		}(pad, 4-length)
		return str + padding
	}(v, (len(val) % 4), "=")

	return base64.StdEncoding.DecodeString(v)
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
