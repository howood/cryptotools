package generator

import (
	"testing"
)

func Test_RsaKeyGenerator(t *testing.T) {
	pri, pub, err := GenerateEncryptedRsaPEM(2048, "")
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	t.Log(string(pri))
	t.Log(string(pub))
	pri, pub, err = GenerateEncryptedRsaPEM(2048, "aaa")
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	t.Log(string(pri))
	t.Log(string(pub))
	if _, _, err := GenerateEncryptedRsaPEM(0, ""); err == nil {
		t.Fatal("failed GenerateEncryptedPEM ")
	} else {
		t.Logf("failed test %#v", err)
	}
	t.Log("success CryptoRsa")
}
