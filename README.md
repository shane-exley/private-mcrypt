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

Alternatively to run on your local machine without Docker, `brew install mcrypt`

## Usage

```
import mcrypt "github.com/shane-exley/private-mcrypt"
```

To address a common issue with a lot of issues rasied with application handling of URL params that have
As per [RFC variant documentation](https://en.wikipedia.org/wiki/Base64#Variants_summary_table), variant RFC 4648 §5 base64 encoded values such as slashes are not safe regardless of being URL escaped as most applications will decode the percent-encoding too early in the process of normalising, security-escaping, and processing the URL. To address this, the default encryption is compliant with RFC4648 §5 and to apply RFC4648 §4 you can pass an additional param, using the package constant RFC4648_4; see below examples for both. It is important to note that where most cross encryptions will work, there will be a select number that do not. So encrypting using RFC 4648 §4 will require decrytion in RFC 4648 §4, and the same applies for RFC 4648 §5.

## RFC 4648 §4 (RFC4648_4)

### Usage for encryption

```
encrypted, err := mcrypt.Encrypt("This is my secret I want to hide from the world", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345678910", RFC4648_4)
```

### Usage for decryption

```
decrypted, err := mcrypt.Decrypt(encryted, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345678910", RFC4648_4)
fmt.Println(decrypted) // prints "This is my secret I want to hide from the world"
```

## RFC 4648 §5 (Default | RFC4648_5)

### Usage for encryption

```
encrypted, err := mcrypt.Encrypt("This is my secret I want to hide from the world", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345678910")
```

### Usage for decryption

```
decrypted, err := mcrypt.Decrypt(encryted, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345678910")
fmt.Println(decrypted) // prints "This is my secret I want to hide from the world"
```
