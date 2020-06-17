package privatemcrypt

const (
	// cipherRijndael128 defines the cipher for rijndael 128
	cipherRijndael128 string = "rijndael-128"

	// modeCBC defines the mode for cbc
	modeCBC string = "cbc"

	// keyLength defines the expected length to validate a secret key against
	keyLength int = 64
)
