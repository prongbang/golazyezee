package lazyxsalsa_test

import (
	"fmt"
	"github.com/prongbang/lazyxsalsa"
	"strings"
	"testing"
)

func TestKeyPair_ToString(t *testing.T) {
	// Given
	keyPair := lazyxsalsa.NewKeyPair()

	// When
	actual := keyPair.ToString()

	// Then
	if !strings.Contains(actual, "pk") && !strings.Contains(actual, "sk") {
		t.Errorf("Error %s", actual)
	}
}

func TestKeyPair_ToKeyPair(t *testing.T) {
	// Given
	pk := "c5665863997704f6e6654264eb7e5be4f1999e4132f2b26440764d7f8e8ff872"
	sk := "47393ae25e44846a0cbd97a0fd4529a17deae9f500358fa9a6c2f8e1c88ee10d"
	kpStr := fmt.Sprintf(`{"pk":"%s","sk":"%s"}`, pk, sk)

	// When
	actual := lazyxsalsa.ToKeyPair(kpStr)

	// Then
	if actual.Pk != pk && actual.Sk != sk {
		t.Errorf("Error %s", actual)
	}
}
