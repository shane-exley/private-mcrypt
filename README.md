# Private mcrypt

`go get github.com/shane-exley/private-mcrypt`

This is to provide a cross language mcrypt private encryption/decryption to prepare values for URL use

Requires on the hosting environment to have mcrypt installed, using docker this can be achieved by building in the alpine pack and the adding the required installations:

Example Dockerfile snippets
```
FROM golang:<version>-alpine

RUN apk --update --no-cache add \
    libmcrypt-dev \
    openssh \
    gcc \
    libc-dev
```
Go build argument should include:
```
CGO_ENABLED=1
```

## Usage

```
import mcrypt "github.com/shane-exley/private-mcrypt"
```

### Use to Encrypt

```
encrypted, err := mcrypt.Encrypt("Secret", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345678910")
```

### Use to Decrypt

```
decrypted, err := mcrypt.Decrypt(encryted, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345678910")
```
