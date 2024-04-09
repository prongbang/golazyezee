# lazyxsalsa

Lazy XSalsa20-Poly1305 in golang base on libsodium.

[![Go Report Card](https://goreportcard.com/badge/github.com/prongbang/lazyxsalsa)](https://goreportcard.com/report/github.com/prongbang/lazyxsalsa)

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/prongbang)

### Algorithm details

- Key exchange: X25519
- Encryption: XSalsa20
- Authentication: Poly1305

### Install

```
go get github.com/prongbang/lazyxsalsa
```

### Benchmark

```shell
BenchmarkEncrypt-10        35792             33285 ns/op
BenchmarkDecrypt-10        36526             32821 ns/op
```

### How to use

- Create KeyPair

```go
keyPair := lazyxsalsa.NewKeyPair()
```

- Key Exchange

```go
clientKp := lazyxsalsa.NewKeyPair()
serverKp := lazyxsalsa.NewKeyPair()
clientSharedKey := clientKp.Exchange(serverKp.Pk)
serverSharedKey := serverKp.Exchange(clientKp.Pk)
```

- Encrypt

```go
lazyXsalsa := lazyxsalsa.New()

plaintext := `Plaintext`
ciphertext, err := lazyXsalsa.Encrypt(plaintext, clientSharedKey)
```

- Decrypt

```go
lazyXsalsa := lazyxsalsa.New()

ciphertext := "ae76477791140129a083a09ff68d5b10460f125c9affdefff48d52d30d774a7c3f42f364ea581eb9b114a65cdbf535171a"
plaintext, err := lazyXsalsa.Decrypt(ciphertext, serverSharedKey)
```
