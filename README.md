# golazyezee

End-to-End Encryption an wrapper for libsodium in golang.

[![Go Report Card](https://goreportcard.com/badge/github.com/prongbang/golazyezee)](https://goreportcard.com/report/github.com/prongbang/golazyezee)

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/prongbang)

### Install

```
go get github.com/prongbang/golazyezee
```

### Benchmark

```shell
BenchmarkEncrypt-10        35792             33285 ns/op
BenchmarkDecrypt-10        36526             32821 ns/op
```

### How to use

- Create KeyPair

```go
keyPair := golazyezee.NewKeyPair()
```

- Key Exchange

```go
clientKp := golazyezee.NewKeyPair()
serverKp := golazyezee.NewKeyPair()
clientSharedKey := clientKp.Exchange(serverKp.Pk)
serverSharedKey := serverKp.Exchange(clientKp.Pk)
```

- Encrypt

```go
lazyEzee := golazyezee.New()

plaintext := `Plaintext`
ciphertext, err := lazyEzee.Encrypt(plaintext, clientSharedKey)
```

- Decrypt

```go
lazyEzee := golazyezee.New()

ciphertext := "ae76477791140129a083a09ff68d5b10460f125c9affdefff48d52d30d774a7c3f42f364ea581eb9b114a65cdbf535171a"
plaintext, err := lazyEzee.Decrypt(ciphertext, serverSharedKey)
```