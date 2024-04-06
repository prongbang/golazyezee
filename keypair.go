package golazyezee

import (
	"encoding/hex"
	"errors"
	"github.com/goccy/go-json"
	"github.com/jamesruan/sodium"
)

type KeyPair struct {
	Pk string `json:"pk"`
	Sk string `json:"sk"`
}

// ToKeyPair kpStr is KeyPair json format
func ToKeyPair(kpStr string) KeyPair {
	kp := KeyPair{}
	_ = json.Unmarshal([]byte(kpStr), &kp)
	return kp
}

// ToString return KeyPair json format
func (k KeyPair) ToString() string {
	b, err := json.Marshal(k)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func (k KeyPair) toBoxKP() (sodium.BoxKP, error) {
	pk, err1 := hex.DecodeString(k.Pk)
	sk, err2 := hex.DecodeString(k.Sk)
	if err1 != nil || err2 != nil {
		return sodium.BoxKP{}, errors.New("decode error")
	}
	return sodium.BoxKP{
		PublicKey: sodium.BoxPublicKey{Bytes: pk},
		SecretKey: sodium.BoxSecretKey{Bytes: sk},
	}, nil
}

// Exchange pk is client Public Key
func (k KeyPair) Exchange(pk string) KeyPair {
	return KeyPair{
		Pk: pk,
		Sk: k.Sk,
	}
}

func NewKeyPair() KeyPair {
	kpBox := sodium.MakeBoxKP()
	return KeyPair{
		Pk: hex.EncodeToString(kpBox.PublicKey.Bytes),
		Sk: hex.EncodeToString(kpBox.SecretKey.Bytes),
	}
}
