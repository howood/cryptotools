package publickeycrypto

import (
	"reflect"
	"testing"
)

func Test_PublicKeyCrypto(t *testing.T) {
	testdata := `
{
    "message": "ok",
    "message2": ["ng", "ng2"]
}
`
	if _, err := NewPublicKeyCrypto(0); err == nil {
		t.Fatal("failed NewPublicKeyCrypto ")
	} else {
		t.Logf("failed test %#v", err)
	}

	pc, err := NewPublicKeyCrypto(2048)
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	encryptdata, err := pc.Encrypt(testdata)
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	decryptdata, err := pc.Decrypt(encryptdata)
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	if reflect.DeepEqual([]byte(decryptdata), []byte(testdata)) == false {
		t.Fatal("failed PublicKeyCrypto ")
	}
	if _, err := pc.Decrypt("sssssss"); err == nil {
		t.Fatal("failed Decrypt ")
	} else {
		t.Logf("failed test %#v", err)
	}
	privatekey := pc.GetPrivateKey()
	t.Log(string(privatekey))
	privatekeypkcs8, err := pc.GetPrivateKeyPKCS8()
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	t.Log(string(privatekeypkcs8))
	publickey, err := pc.GetPublicKey()
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	t.Log(string(publickey))
	t.Log("success PublicKeyCrypto")
}
