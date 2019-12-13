package main

import (
	"log"

	"github.com/howood/cryptotools"
)

func main() {
	testdata := "testdata"

	pcRsa, err := cryptotools.NewPublicKeyCrypto(2048, cryptotools.EncryptTypeRSA)
	if err != nil {
		log.Fatalf("failed  :%#v", err)
	}

	publickeyRsa, err := pcRsa.GetPublicKey()
	if err != nil {
		log.Fatalf("failed  %#v", err)
	}
	log.Print(string(publickeyRsa))

	pcwpRsa, err := cryptotools.NewPublicKeyCryptoWithPEMPublicKey(publickeyRsa, cryptotools.EncryptTypeRSA)
	if err != nil {
		log.Fatalf("failed %#v", err)
	}
	encryptdataRsa, err := pcwpRsa.Encrypt(testdata)
	if err != nil {
		log.Fatalf("failed %#v", err)
	}
	log.Printf("encryptdata : %s", encryptdataRsa)
	decryptdataRsa, err := pcRsa.Decrypt(encryptdataRsa)
	if err != nil {
		log.Fatalf("failed %#v", err)
	}
	log.Printf("decryptdata : %s", decryptdataRsa)

	pcEcdsa, err := cryptotools.NewPublicKeyCrypto(0, cryptotools.EncryptTypeECDSA)
	if err != nil {
		log.Fatalf("failed  :%#v", err)
	}

	publickeyEcdsa, err := pcEcdsa.GetPublicKey()
	if err != nil {
		log.Fatalf("failed  %#v", err)
	}
	log.Print(string(publickeyEcdsa))

	pcwpEcdsa, err := cryptotools.NewPublicKeyCryptoWithPEMPublicKey(publickeyEcdsa, cryptotools.EncryptTypeECDSA)
	if err != nil {
		log.Fatalf("failed %#v", err)
	}
	encryptdataEcdsa, err := pcwpEcdsa.Encrypt(testdata)
	if err != nil {
		log.Fatalf("failed %#v", err)
	}
	log.Printf("encryptdata : %s", encryptdataEcdsa)
	decryptdataEcdsa, err := pcEcdsa.Decrypt(encryptdataEcdsa)
	if err != nil {
		log.Fatalf("failed %#v", err)
	}
	log.Printf("decryptdata : %s", decryptdataEcdsa)

}
