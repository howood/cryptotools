package encrypter

import (
	"testing"
)

func Test_CryptoAes(t *testing.T) {
	key := []byte("passw0rdpassw0rdpassw0rdpassw0rd")
	identifier := "aaaaaaaaaa"
	testdata := `
{
    "message": "ok",
    "message2": ["ng", "ng2"]
}
`
	cryptoaes, err := NewCryptoAes(key, []byte(identifier))
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	encryptdata := cryptoaes.EncryptWithBase64(testdata)
	decryptdata, err := cryptoaes.DecryptWithBase64(encryptdata)
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	if decryptdata != testdata {
		t.Fatal("failed CryptoAes ")
	}
	t.Log("success CryptoAes")
}
