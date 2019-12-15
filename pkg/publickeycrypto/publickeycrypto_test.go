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

	if _, err := NewPublicKeyCrypto(0, EncryptTypeRSA); err == nil {
		t.Fatal("failed NewPublicKeyCrypto ")
	} else {
		t.Logf("failed test %#v", err)
	}

	pc, err := NewPublicKeyCrypto(2048, EncryptTypeRSA)
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
	pc, err := NewPublicKeyCrypto(2048, EncryptTypeRSA)
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	publickey, err := pc.GetPublicKey()
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	t.Log(string(publickey))

	pcwp, err := NewPublicKeyCryptoWithPEMPublicKey(publickey, EncryptTypeRSA)
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
	if _, err := NewPublicKeyCryptoWithPEMPublicKey([]byte("sss"), EncryptTypeRSA); err == nil {
		t.Fatal("failed NewPublicKeyCryptoWithPEMPublicKey ")
	} else {
		t.Logf("failed test %#v", err)
	}
	t.Log("success PublicKeyCryptoWithPublicKey")
}

func Test_PublicKeyCryptoWithPEcdsaPublicKey(t *testing.T) {
	pc, err := NewPublicKeyCrypto(256, EncryptTypeECDSA)
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	privatekey, err := pc.GetPrivateKey()
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	t.Log(string(privatekey))
	publickey, err := pc.GetPublicKey()
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	t.Log(string(publickey))

	pcwp, err := NewPublicKeyCryptoWithPEMPublicKey(publickey, EncryptTypeECDSA)
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
		t.Fatal("failed PublicKeyCryptoWithPEcdsaublicKey ")
	}
	if _, err := pcwp.Decrypt(encryptdata); err == nil {
		t.Fatal("failed Decrypt ")
	} else {
		t.Logf("failed test %#v", err)
	}
	if _, err := NewPublicKeyCryptoWithPEMPublicKey([]byte("sss"), EncryptTypeECDSA); err == nil {
		t.Fatal("failed PublicKeyCryptoWithPEcdsaublicKey ")
	} else {
		t.Logf("failed test %#v", err)
	}
	t.Log("success PublicKeyCryptoWithPEcdsaublicKey")
}

func Test_PublicKeyCryptoWithJWKRSAPublicKey(t *testing.T) {
	pc, err := NewPublicKeyCrypto(2048, EncryptTypeRSA)
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	publickey, err := pc.GetPublicKeyWithJWK()
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	t.Log(string(publickey))

	pcwp, err := NewPublicKeyCryptoWithJWKPublicKey(publickey, EncryptTypeRSA)
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
		t.Fatal("failed PublicKeyCryptoWithJWKRSAPublicKey ")
	}
	if _, err := NewPublicKeyCryptoWithJWKPublicKey([]byte("sss"), EncryptTypeRSA); err == nil {
		t.Fatal("failed PublicKeyCryptoWithJWKRSAPublicKey ")
	} else {
		t.Logf("failed test %#v", err)
	}
	t.Log("success PublicKeyCryptoWithJWKRSAPublicKey")
}

func Test_PublicKeyCryptoWithJWKEcdsaPublicKey(t *testing.T) {
	pc, err := NewPublicKeyCrypto(384, EncryptTypeECDSA)
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	publickey, err := pc.GetPublicKeyWithJWK()
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	t.Log(string(publickey))

	pcwp, err := NewPublicKeyCryptoWithJWKPublicKey(publickey, EncryptTypeECDSA)
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
		t.Fatal("failed ublicKeyCryptoWithJWKEcdsaPublicKey ")
	}
	if _, err := NewPublicKeyCryptoWithJWKPublicKey([]byte("sss"), EncryptTypeECDSA); err == nil {
		t.Fatal("failed ublicKeyCryptoWithJWKEcdsaPublicKey ")
	} else {
		t.Logf("failed test %#v", err)
	}
	t.Log("success ublicKeyCryptoWithJWKEcdsaPublicKey")
}

func Test_PublicKeyCryptoWithPED25519PublicKey(t *testing.T) {
	pc, err := NewPublicKeyCrypto(0, EncryptTypeED25519)
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	privatekey, err := pc.GetPrivateKey()
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	t.Log(string(privatekey))
	publickey, err := pc.GetPublicKey()
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	t.Log(string(publickey))

	pcwp, err := NewPublicKeyCryptoWithPEMPublicKey(publickey, EncryptTypeED25519)
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
		t.Fatal("failed Test_PublicKeyCryptoWithPED25519PublicKey ")
	}
	if _, err := pcwp.Decrypt(encryptdata); err == nil {
		t.Fatal("failed Decrypt ")
	} else {
		t.Logf("failed test %#v", err)
	}
	if _, err := NewPublicKeyCryptoWithPEMPublicKey([]byte("sss"), EncryptTypeECDSA); err == nil {
		t.Fatal("failed Test_PublicKeyCryptoWithPED25519PublicKey ")
	} else {
		t.Logf("failed test %#v", err)
	}
	t.Log("success Test_PublicKeyCryptoWithPED25519PublicKey")
}
