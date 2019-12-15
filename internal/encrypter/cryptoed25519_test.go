package encrypter

import (
	"reflect"
	"testing"

	"github.com/howood/cryptotools/internal/entity"
	"github.com/howood/cryptotools/internal/parser"
)

const ed25519privatekey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz
c2gtZWQyNTUxOQAAACB1Imr2Bz+hmyQTQdyACRAAnbiywzFVSJbxCAzCT+rROgAA
AIiaywRCmssEQgAAAAtzc2gtZWQyNTUxOQAAACB1Imr2Bz+hmyQTQdyACRAAnbiy
wzFVSJbxCAzCT+rROgAAAECqn2yjBBO1CTuvAeJnrV9AkodkKrEd4cZY0mhUwcnG
knUiavYHP6GbJBNB3IAJEACduLLDMVVIlvEIDMJP6tE6AAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----`

const ed25519publickey = `-----BEGIN OPENSSH PUBLIC KEY-----
MCowBQYDK2VwAyEAdSJq9gc/oZskE0HcgAkQAJ24ssMxVUiW8QgMwk/q0To=
-----END OPENSSH PUBLIC KEY-----`

func Test_CryptoEd25519(t *testing.T) {
	testdata := `
{
    "message": "ok",
    "message2": ["ng", "ng2"]
}
`
	encryptkey := entity.EncryptKey{}
	if err := parser.DecodePrivateKey([]byte(ed25519privatekey), &encryptkey); err != nil {
		t.Fatalf("failed test %#v", err)
	}
	if err := parser.DecodePublicKey([]byte(ed25519publickey), &encryptkey); err != nil {
		t.Fatalf("failed test %#v", err)
	}

	cryptoed25519 := NewCryptoEd25519(&encryptkey.Ed25519Key)

	encryptdata, err := cryptoed25519.EncryptWithBase64([]byte(testdata))
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	t.Log(string(encryptdata))
	decryptdata, err := cryptoed25519.DecryptWithBase64(encryptdata)
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	t.Log(string(decryptdata))
	if reflect.DeepEqual(decryptdata, []byte(testdata)) == false {
		t.Fatal("failed CryptoRsa ")
	}

	if _, err := cryptoed25519.DecryptWithBase64("sssssss"); err == nil {
		t.Fatal("failed DecryptWithBase64 ")
	} else {
		t.Logf("failed test %#v", err)
	}
	t.Log("success CryptoEd25519")
}
