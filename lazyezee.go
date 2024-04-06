package golazyezee

import (
	"encoding/hex"
	"fmt"
	"github.com/jamesruan/sodium"
)

const NonceHexSize = 24 * 2

type LazyEzee interface {
	Encrypt(plainText string, keyPair KeyPair) (string, error)
	Decrypt(cipherText string, keyPair KeyPair) (string, error)
}

type lazyEzee struct {
}

func (e *lazyEzee) Encrypt(plainText string, keyPair KeyPair) (string, error) {
	kp, er := keyPair.toBoxKP()
	if er != nil {
		return "", er
	}
	plainByte := sodium.Bytes(plainText)
	nonceByte := sodium.BoxNonce{}
	sodium.Randomize(&nonceByte)
	cipherByte := plainByte.Box(nonceByte, kp.PublicKey, kp.SecretKey)
	nonceHex := hex.EncodeToString(nonceByte.Bytes)
	cipherHex := hex.EncodeToString(cipherByte)
	cipher := fmt.Sprintf("%s%s", cipherHex, nonceHex)
	return cipher, nil
}

func (e *lazyEzee) Decrypt(cipherText string, keyPair KeyPair) (string, error) {
	kp, er := keyPair.toBoxKP()
	if er != nil {
		return "", er
	}
	size := len(cipherText)
	cipherSize := size - NonceHexSize
	nonceHex := cipherText[cipherSize:]
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return "", err
	}
	nonceByte := sodium.BoxNonce{Bytes: nonce}
	cipherHex := cipherText[:cipherSize]
	cipher, err := hex.DecodeString(cipherHex)
	if err != nil {
		return "", err
	}
	cipherByte := sodium.Bytes(cipher)
	plainByte, err := cipherByte.BoxOpen(nonceByte, kp.PublicKey, kp.SecretKey)
	return string(plainByte), err
}

func New() LazyEzee {
	return &lazyEzee{}
}
