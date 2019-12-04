package commonkeycrypto

import (
	"reflect"
	"testing"
)

func Test_CommonKeyCrypto(t *testing.T) {
	testdata := `
{
    "message": "ok",
    "message2": ["ng", "ng2"]
}
`
	cc, err := NewCommonKeyCrypto([]byte("passw0rdpassw0rdpassw0rdpassw0rd"))
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	encryptdata := cc.Encrypt(testdata)
	decryptdata, err := cc.Decrypt(encryptdata)
	if err != nil {
		t.Fatalf("failed test %#v", err)
	}
	if reflect.DeepEqual([]byte(decryptdata), []byte(testdata)) == false {
		t.Fatal("failed CommonKeyCrypto ")
	}
	t.Log("success CommonKeyCrypto")
}
