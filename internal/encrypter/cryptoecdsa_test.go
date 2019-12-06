package encrypter

import (
	"reflect"
	"testing"

	"github.com/howood/cryptotools/internal/entity"
	"github.com/howood/cryptotools/internal/parser"
)

const ecdsaprivatekey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIHlfWPDMDdtscbbVwF6lMo/rcjrNeBBe1fXtkgP0Neg4oAoGCCqGSM49
AwEHoUQDQgAEZ1y5/pKS9hBBfPxzBdIGYceWf5htPgYfnSPOLUerb63NsPCLGIOD
X8nPWQLBmBYWmcljPjFO3AvHEe7etnb3EA==
-----END EC PRIVATE KEY-----`

const ecdsapublickey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEZ1y5/pKS9hBBfPxzBdIGYceWf5ht
PgYfnSPOLUerb63NsPCLGIODX8nPWQLBmBYWmcljPjFO3AvHEe7etnb3EA==
-----END PUBLIC KEY-----`

func Test_CryptoEcdsa(t *testing.T) {
	testdata := `
{
    "message": "ok",
    "message2": ["ng", "ng2"]
}
`
	encryptkey := entity.EncryptKey{}
	if err := parser.DecodePrivateKey([]byte(ecdsaprivatekey), &encryptkey); err != nil {
		t.Fatalf("failed test %#v", err)
	}
	if err := parser.DecodePublicKey([]byte(ecdsapublickey), &encryptkey); err != nil {
		t.Fatalf("failed test %#v", err)
	}

	cryptoecdsa := NewCryptoEcdsa(&encryptkey.EcdsaKey)

	encryptdata, err := cryptoecdsa.EncryptWithBase64([]byte(testdata))
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	decryptdata, err := cryptoecdsa.DecryptWithBase64(encryptdata)
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	if reflect.DeepEqual(decryptdata, []byte(testdata)) == false {
		t.Fatal("failed CryptoRsa ")
	}

	if _, err := cryptoecdsa.DecryptWithBase64("sssssss"); err == nil {
		t.Fatal("failed DecryptWithBase64 ")
	} else {
		t.Logf("failed test %#v", err)
	}
	t.Log("success CryptoEcdsa")
}
