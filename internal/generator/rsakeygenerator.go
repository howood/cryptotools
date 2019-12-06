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

// GenerateEncryptedRsaPEM generates PEM type RSA private key and public key
func GenerateEncryptedRsaPEM(bits int, pwd string) ([]byte, []byte, error) {
	derPrivateKey, derRsaPublicKey, err := GenerateEncryptedRsaDER(bits)
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

// GenerateEncryptedRsaDER generates DER type RSA private key and public key
func GenerateEncryptedRsaDER(bits int) ([]byte, []byte, error) {
	privatekey, publickey, err := GenerateRsaKeys(bits)
	if err != nil {
		return nil, nil, err
	}

	derPrivateKey := x509.MarshalPKCS1PrivateKey(privatekey)
	derRsaPublicKey := x509.MarshalPKCS1PublicKey(publickey)
	return derPrivateKey, derRsaPublicKey, nil
}

// GenerateRsaKeys generates DER type  RSA private key and public key
func GenerateRsaKeys(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privatekey, err := generatePrivateRsakey(bits)
	if err != nil {
		return nil, nil, err
	}
	publickey := privatekey.Public().(*rsa.PublicKey)
	return privatekey, publickey, nil
}
