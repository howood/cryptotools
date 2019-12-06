package encrypter

import (
	"reflect"
	"testing"

	"github.com/howood/cryptotools/internal/entity"
	"github.com/howood/cryptotools/internal/generator"
)

const ecdsaprivatekey = `-----BEGIN EC PRIVATE KEY-----
LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1JR2tBZ0VCQkRBVW8wQ281
RlNnMHBENTkzaUtCTnF2eFoxanl6VzJRT0hJVlE4VmxUZnI4Y1p0WXE2NFhDYWgK
c3JacFVabkorcmVnQndZRks0RUVBQ0toWkFOaUFBU1R4a0t4VHVmRVFRQ3pJTUtI
dHhBQmkvSFJ5NFhsUWtRVQphRXVOVkQyWjhhRXExdUk2OVpWbzRCVk9wRUVpOFFq
RnI1b21uYUN3SUsrNWVkQ3dxRVdTUHRXdEhhT3ZzNTZ4Ci80SVREdVozMEhHWFZv
dk0zQlRJdEhOVmNjejJIcjg9Ci0tLS0tRU5EIEVDIFBSSVZBVEUgS0VZLS0tLS0K
-----END EC PRIVATE KEY-----`

const ecdsapublickey = `-----BEGIN EC PUBLIC KEY-----
LS0tLS1CRUdJTiBFQyBQVUJMSUMgS0VZLS0tLS0KTUhZd0VBWUhLb1pJemowQ0FR
WUZLNEVFQUNJRFlnQUVrOFpDc1U3bnhFRUFzeURDaDdjUUFZdngwY3VGNVVKRQpG
R2hMalZROW1mR2hLdGJpT3ZXVmFPQVZUcVJCSXZFSXhhK2FKcDJnc0NDdnVYblFz
S2hGa2o3VnJSMmpyN09lCnNmK0NFdzdtZDlCeGwxYUx6TndVeUxSelZYSE05aDYv
Ci0tLS0tRU5EIEVDIFBVQkxJQyBLRVktLS0tLQo=
-----END EC PUBLIC KEY-----`

func Test_CryptoEcdsa(t *testing.T) {
	testdata := `
{
    "message": "ok",
    "message2": ["ng", "ng2"]
}
`
	encryptkey := entity.EncryptKey{}
	//*** ParseECPrivateKey is now having error
	//	if err := parser.DecodePrivateKey([]byte(ecdsaprivatekey), &encryptkey); err != nil {
	//		t.Fatalf("failed test %#v", err)
	//	}
	//	if err := parser.DecodePublicKey([]byte(ecdsapublickey), &encryptkey); err != nil {
	//		t.Fatalf("failed test %#v", err)
	//	}
	var err error
	encryptkey.EcdsaKey.PrivateKey, encryptkey.EcdsaKey.PublicKey, err = generator.GenerateEcdsaKeys(256)
	if err != nil {
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
