package publickeycrypto

import (
	"reflect"
	"testing"
)

var testdata = `
{
    "message": "ok",
    "message2": ["ng", "ng2"]
}
`

func Test_PublicKeyCrypto(t *testing.T) {

	if _, err := NewPublicKeyCrypto(0, EncryptTypeRsa); err == nil {
		t.Fatal("failed NewPublicKeyCrypto ")
	} else {
		t.Logf("failed test %#v", err)
	}

	pc, err := NewPublicKeyCrypto(2048, EncryptTypeRsa)
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
	privatekey, err := pc.GetPrivateKey()
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
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

func Test_PublicKeyCryptoWithPublicKey(t *testing.T) {
	pc, err := NewPublicKeyCrypto(2048, EncryptTypeRsa)
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	publickey, err := pc.GetPublicKey()
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	t.Log(string(publickey))

	pcwp, err := NewPublicKeyCryptoWithPEMPublicKey(publickey, EncryptTypeRsa)
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}

	encryptdata, err := pcwp.Encrypt(testdata)
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	decryptdata, err := pc.Decrypt(encryptdata)
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	if reflect.DeepEqual([]byte(decryptdata), []byte(testdata)) == false {
		t.Fatal("failed PublicKeyCryptoWithPublicKey ")
	}
	if _, err := pcwp.Decrypt(encryptdata); err == nil {
		t.Fatal("failed Decrypt ")
	} else {
		t.Logf("failed test %#v", err)
	}
	if _, err := NewPublicKeyCryptoWithPEMPublicKey([]byte("sss"), EncryptTypeRsa); err == nil {
		t.Fatal("failed NewPublicKeyCryptoWithPEMPublicKey ")
	} else {
		t.Logf("failed test %#v", err)
	}
	t.Log("success PublicKeyCryptoWithPublicKey")
}

func Test_PublicKeyCryptoWithJWKPublicKey(t *testing.T) {
	pc, err := NewPublicKeyCrypto(2048, EncryptTypeRsa)
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	publickey, err := pc.GetPublicKeyWithJWK()
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	t.Log(string(publickey))

	pcwp, err := NewPublicKeyCryptoWithJWKPublicKey(publickey, EncryptTypeRsa)
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}

	encryptdata, err := pcwp.Encrypt(testdata)
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	decryptdata, err := pc.Decrypt(encryptdata)
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	if reflect.DeepEqual([]byte(decryptdata), []byte(testdata)) == false {
		t.Fatal("failed PublicKeyCryptoWithJWKPublicKey ")
	}
	if _, err := NewPublicKeyCryptoWithJWKPublicKey([]byte("sss"), EncryptTypeRsa); err == nil {
		t.Fatal("failed NewPublicKeyCryptoWithJWKPublicKey ")
	} else {
		t.Logf("failed test %#v", err)
	}
	t.Log("success PublicKeyCryptoWithJWKPublicKey")
}
