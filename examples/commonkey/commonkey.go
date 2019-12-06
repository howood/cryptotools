package main

import (
	"log"

	"github.com/howood/cryptotools"
)

const commonKey = "passw0rdpassw0rdpassw0rdpassw0rd"

func main() {
	testdata := "testdata"

	cc, err := cryptotools.NewCommonKeyCrypto([]byte(commonKey))
	if err != nil {
		log.Fatalf("failed  :%#v", err)
	}
	encryptdata := cc.Encrypt(testdata)
	log.Printf("encryptdata : %s", encryptdata)
	decryptdata, err := cc.Decrypt(encryptdata)
	if err != nil {
		log.Fatalf("failed  :%#v", err)
	}
	log.Printf("decryptdata : %s", decryptdata)

}
