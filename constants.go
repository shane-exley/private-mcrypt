package privatemcrypt

const (
	// cipherRijndael128 defines the cipher for rijndael 128
	cipherRijndael128 string = "rijndael-128"

	// modeCBC defines the mode for cbc
	modeCBC string = "cbc"

	// keyLength defines the expected length to validate a secret key against
	keyLength int = 64
)

const (
	// RFC4648_4 gives us internal and external use of a consistent value
	RFC4648_4 string = "RFC4648_4"
	// RFC4648_5 gives us internal and external use of a consistent value
	RFC4648_5 string = "RFC4648_5"
)
