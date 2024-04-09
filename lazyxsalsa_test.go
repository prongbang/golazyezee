package lazyxsalsa_test

import (
	"github.com/goccy/go-json"
	"github.com/prongbang/lazyxsalsa"
	"testing"
)

func TestLazyXSalsa_Encrypt(t *testing.T) {
	// Given
	clientKp := lazyxsalsa.NewKeyPair()
	serverKp := lazyxsalsa.NewKeyPair()
	clientSharedKey := clientKp.Exchange(serverKp.Pk)

	lazyXsalsa := lazyxsalsa.New()
	message := `{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.rTCH8cLoGxAm_xw68z-zXVKi9ie6xJn9tnVWjd_9ftE"}`

	// When
	actual, _ := lazyXsalsa.Encrypt(message, clientSharedKey)

	// Then
	if actual == "" {
		t.Errorf("Error %s", actual)
	}
}

func TestLazyXSalsa_Decrypt(t *testing.T) {
	// Given
	sharedKey := lazyxsalsa.KeyPair{
		Pk: "5bc57a78a8a31049445f76a72d527fe3346031ff052cc887cf156d0bac80da42",
		Sk: "7f326815981cc07e4635d51f6098845e2b54e0ae4d24ca064428fbef51464d3b",
	}
	cipherText := "10839a48edd5c9a43525e4b238eca12005245bd56907e78ca9700f78d017c55a674c1c8a0a64c70425166450955a055284fb7d8e94e9bffb081b8f96814adc8e50d07814398259a6214da017d75fd4c996cf6773f8a1432f8c6ddc38c252e2ea651989faf8f7030815ea642dffda352eaefca53ddaefd0c712311978ba4cd5908155af4e210d1fd93b360d6b99724d48db0a2df1ca"
	lazyXsalsa := lazyxsalsa.New()
	token := map[string]string{}

	// When
	actual, _ := lazyXsalsa.Decrypt(cipherText, sharedKey)
	_ = json.Unmarshal([]byte(actual), &token)

	// Then
	if token["token"] == "" {
		t.Errorf("Error %s", actual)
	}
}

func BenchmarkEncrypt(b *testing.B) {
	sharedKey := lazyxsalsa.KeyPair{
		Pk: "50abdca1a4c526afbb1a6fa95c84905f0258f896ef1128099cff6d4c1baab12c",
		Sk: "8ba28b56ffae73a4f8d7a161f5126b50936330e9b93a1ba5ff5d89c59b0725f3",
	}
	lazyXsalsa := lazyxsalsa.New()
	message := `{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.rTCH8cLoGxAm_xw68z-zXVKi9ie6xJn9tnVWjd_9ftE"}`

	for i := 0; i < b.N; i++ {
		_, err := lazyXsalsa.Encrypt(message, sharedKey)
		if err != nil {
			b.Errorf("Error %s", err)
		}
	}
}

func BenchmarkDecrypt(b *testing.B) {
	sharedKey := lazyxsalsa.KeyPair{
		Pk: "5bc57a78a8a31049445f76a72d527fe3346031ff052cc887cf156d0bac80da42",
		Sk: "7f326815981cc07e4635d51f6098845e2b54e0ae4d24ca064428fbef51464d3b",
	}
	lazyXsalsa := lazyxsalsa.New()
	cipherText := "10839a48edd5c9a43525e4b238eca12005245bd56907e78ca9700f78d017c55a674c1c8a0a64c70425166450955a055284fb7d8e94e9bffb081b8f96814adc8e50d07814398259a6214da017d75fd4c996cf6773f8a1432f8c6ddc38c252e2ea651989faf8f7030815ea642dffda352eaefca53ddaefd0c712311978ba4cd5908155af4e210d1fd93b360d6b99724d48db0a2df1ca"

	for i := 0; i < b.N; i++ {
		_, err := lazyXsalsa.Decrypt(cipherText, sharedKey)
		if err != nil {
			b.Errorf("Error %s", err)
		}
	}
}
