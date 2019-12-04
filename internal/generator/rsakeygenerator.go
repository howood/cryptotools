package generator

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

func generatePrivateRsakey(bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}

// GenerateEncryptedPEM generates PEM type private key and public ley
func GenerateEncryptedPEM(bits int, pwd string) ([]byte, []byte, error) {
	derPrivateKey, derRsaPublicKey, err := GenerateEncryptedDER(bits)
	if err != nil {
		return nil, nil, err
	}

	privateblock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derPrivateKey,
	}
	if pwd != "" {
		if privateblock, err = x509.EncryptPEMBlock(rand.Reader, privateblock.Type, privateblock.Bytes, []byte(pwd), x509.PEMCipherAES256); err != nil {
			return nil, nil, err
		}
	}

	publicblock := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: derRsaPublicKey,
	}

	return pem.EncodeToMemory(privateblock), pem.EncodeToMemory(publicblock), nil
}

// GenerateEncryptedDER generates DER type private key and public ley
func GenerateEncryptedDER(bits int) ([]byte, []byte, error) {
	privatekey, err := generatePrivateRsakey(bits)
	if err != nil {
		return nil, nil, err
	}
	publickey := privatekey.Public()

	derPrivateKey := x509.MarshalPKCS1PrivateKey(privatekey)
	var derRsaPublicKey []byte
	if rsaPublicKeyPointer, ok := publickey.(*rsa.PublicKey); ok {
		derRsaPublicKey = x509.MarshalPKCS1PublicKey(rsaPublicKeyPointer)
	}
	return derPrivateKey, derRsaPublicKey, nil
}
