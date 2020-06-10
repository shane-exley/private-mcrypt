package privatemcrypt

import (
	"crypto/rand"
	"fmt"
	"strconv"
	"strings"
)

// iv is an IV belonging to the specific cipher/mode combination, in this
func iv(cipher, mode string) ([]byte, int, error) {
	var iv []byte
	var size int

	switch strings.ToLower(cipher) + "/" + strings.ToLower(mode) {
	case cipherRijndael128 + "/" + modeCBC:
		b := make([]byte, 16)
		rand.Read(b)

		return b, 16, nil
	}

	return iv, size, fmt.Errorf("unsupported cipher and mode combination provided. %s %s", cipher, mode)
}

// parseKey provides a consistent key format for encryption/decryption
func parseKey(k string) []byte {
	var key []byte
	for i := 0; i < len(k); i++ {
		if i%2 == 0 {
			n := i + 2
			x, _ := strconv.ParseUint(k[i:n], 16, 32)
			key = append(key, byte(x))
		}
	}

	return key
}
