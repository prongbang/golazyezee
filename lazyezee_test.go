package golazyezee_test

import (
	"github.com/goccy/go-json"
	"github.com/prongbang/golazyezee"
	"testing"
)

func TestLazyEzee_Encrypt(t *testing.T) {
	// Given
	clientKp := golazyezee.NewKeyPair()
	serverKp := golazyezee.NewKeyPair()
	clientSharedKey := clientKp.Exchange(serverKp.Pk)

	lazyEzee := golazyezee.New()
	message := `{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.rTCH8cLoGxAm_xw68z-zXVKi9ie6xJn9tnVWjd_9ftE"}`

	// When
	actual, _ := lazyEzee.Encrypt(message, clientSharedKey)

	// Then
	if actual == "" {
		t.Errorf("Error %s", actual)
	}
}

func TestLazyEzee_Decrypt(t *testing.T) {
	// Given
	sharedKey := golazyezee.KeyPair{
		Pk: "fef25d7134ca136fa99683c3eb3e0cb2fe53cd6f7c525b1f6cf65bd1e6fc0424",
		Sk: "01620434a12fa40cf2faeca11545eb2f8972e8c8624d7709e4a7898e9d181da3",
	}
	cipherText := "87ae1b5fd5b31dbb0d5762dfa98a10b329c897a8cf8e6c300011b5139f13484fb51b867ceb9eda2b7ecf82a738599682be8dfa53402734a30eb1fd10b0f8d9e267e1c2c87c915067e103162839984eab10f0899e95fdc32d738baee42cc8926846624801183cba95d599da0e4b668c8eb86e31b45c13a882f3fe0282e2b6db2c2a1d868aff4d3309d2050d6ee5f345532f209b8e27"
	lazyEzee := golazyezee.New()
	token := map[string]string{}

	// When
	actual, _ := lazyEzee.Decrypt(cipherText, sharedKey)
	_ = json.Unmarshal([]byte(actual), &token)

	// Then
	if token["token"] == "" {
		t.Errorf("Error %s", actual)
	}
}

func BenchmarkEncrypt(b *testing.B) {
	sharedKey := golazyezee.KeyPair{
		Pk: "50abdca1a4c526afbb1a6fa95c84905f0258f896ef1128099cff6d4c1baab12c",
		Sk: "8ba28b56ffae73a4f8d7a161f5126b50936330e9b93a1ba5ff5d89c59b0725f3",
	}
	lazyEzee := golazyezee.New()
	message := `{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.rTCH8cLoGxAm_xw68z-zXVKi9ie6xJn9tnVWjd_9ftE"}`

	for i := 0; i < b.N; i++ {
		_, _ = lazyEzee.Encrypt(message, sharedKey)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	sharedKey := golazyezee.KeyPair{
		Pk: "50abdca1a4c526afbb1a6fa95c84905f0258f896ef1128099cff6d4c1baab12c",
		Sk: "8ba28b56ffae73a4f8d7a161f5126b50936330e9b93a1ba5ff5d89c59b0725f3",
	}
	lazyEzee := golazyezee.New()
	cipherText := "f83c52f27e652df955eb1262d900b6213a6ba448922b34458484bf9f0d2bc1824f1e820ba7830c2563d569b4933a7e0ac7e14e9c23ca0c9ebb32cf5f3906de20a176e14692bb2064a7d48eba7a88c3a379ef755d801497fd7c1d4a1020d116fe079e8538abca57ff34d2650b6845f4a6c4b1352bf5a8405fb5e84e30f4046c2cb00d7424fc94436664d175b2d2b319efa8a8b369e3"

	for i := 0; i < b.N; i++ {
		_, _ = lazyEzee.Decrypt(cipherText, sharedKey)
	}
}
