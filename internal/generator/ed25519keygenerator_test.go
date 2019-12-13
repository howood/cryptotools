package generator

import (
	"testing"
)

func Test_ED25519KeyGenerator(t *testing.T) {
	pri, pub, err := GenerateEncryptedED25519PEM("")
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	t.Log(string(pri))
	t.Log(string(pub))
	pri, pub, err = GenerateEncryptedED25519PEM("aaa")
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	t.Log(string(pri))
	t.Log(string(pub))
	t.Log("success ED25519KeyGenerator")
}
