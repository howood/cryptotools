package generator

import (
	"testing"
)

func Test_EcdsaKeyGenerator(t *testing.T) {
	pri, pub, err := GenerateEncryptedEcdsaPEM(384, "")
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	t.Log(string(pri))
	t.Log(string(pub))
	pri, pub, err = GenerateEncryptedEcdsaPEM(384, "aaa")
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	t.Log(string(pri))
	t.Log(string(pub))
	if _, _, err := GenerateEncryptedEcdsaPEM(256, ""); err != nil {
		t.Fatalf("failed test %#v", err)
	}
	if _, _, err := GenerateEncryptedEcdsaPEM(521, ""); err != nil {
		t.Fatalf("failed test %#v", err)
	}
	if _, _, err := GenerateEncryptedEcdsaPEM(0, ""); err == nil {
		t.Fatal("failed GenerateEncryptedEcdsaPEM ")
	} else {
		t.Logf("failed test %#v", err)
	}
	t.Log("success EcdsaKeyGenerator")
}
