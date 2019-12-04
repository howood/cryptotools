package encrypter

import (
	"reflect"
	"testing"

	"github.com/howood/cryptotools/internal/entity"
	"github.com/howood/cryptotools/internal/parser"
)

const rsaprivatekey = `
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`

const rsapublickey = `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAopHmB0gquCxhX46Tn+O5
EfiAVUmjrCqOJLeZ0wZEaZpNDOUpbKO6Vb/MEJUiXfzoRH6Q23H3inzl02XQE1HF
wdV7EuT1ineHAL7h1MVwkFX2iBzPxuyg0pGl/yDg8aSWIWT0E+dlbAGXqzz6uISs
qURRUQYrVlirDV8JnQd3QHE87u4g5E00fKmwuH6viFlVr/zwvAU0airh0Fk4Agik
QdJxiGIzfOCapmy+LlnDb7Hu0bH9fUK04rr57F3LU/+9QPG7FoLYVFjg08dwlo8O
/sGMad8K7UGHuZBIyRz5SA9nmaCTj5xGjmpsJ1ZL8W5puUs/OWSFkIuDhPix+5vo
k/4Iw4O5jDiFGadJqHpfEGhZWL0037gg7X0YaFudvsdZdHrr9oFI3NUeAJGq82qu
ns/9c1ARiYssmt3YP5dkVilSfX0U7vM1QYcwffmH48+V7t+GN09PdFdN+iXJQlg9
nwzE573YHTXWdzgrN3KqGoRcaBCRcaq+nRW8RcHReIkxgAdXzQl2sSJLphZNH4pf
nSrR7ChAEk1ZR567L+malLKARkI3lNGlMFGvhjxpH1cHJeYGo2bHzYtbVhoNujF6
btwv7AzaptOn66KJ7tEo92yJbMdZvOxQfCLnjk9FqoLqFAPtiRXoqlNUfK7nAj9z
Sflwh6m3w5TyQziTOp9O468CAwEAAQ==
-----END PUBLIC KEY-----`

func Test_CryptoRsa(t *testing.T) {
	testdata := `
{
    "message": "ok",
    "message2": ["ng", "ng2"]
}
`
	rsakey := entity.RsaKey{}
	if err := parser.ReadPrivateKey([]byte(rsaprivatekey), &rsakey); err != nil {
		t.Fatalf("failed test %#v", err)
	}
	if err := parser.ReadPublicKey([]byte(rsapublickey), &rsakey); err != nil {
		t.Fatalf("failed test %#v", err)
	}
	cryptorsa := NewCryptoRsa(&rsakey)

	encryptdata, err := cryptorsa.EncryptWithBase64([]byte(testdata))
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	decryptdata, err := cryptorsa.DecryptWithBase64(encryptdata)
	if reflect.DeepEqual(decryptdata, []byte(testdata)) == false {
		t.Fatal("failed CryptoRsa ")
	}

	var checkdata string
	for i := 0; i < (rsakey.PrivateKey.N.BitLen()+7)/8+1; i++ {
		checkdata += "a"
	}
	if _, err := cryptorsa.EncryptWithBase64([]byte(checkdata)); err == nil {
		t.Fatal("failed EncryptWithBase64 ")
	} else {
		t.Logf("failed test %#v", err)
	}
	if _, err := cryptorsa.DecryptWithBase64("sssssss"); err == nil {
		t.Fatal("failed DecryptWithBase64 ")
	} else {
		t.Logf("failed test %#v", err)
	}
	t.Log("success CryptoRsa")
}
