package generator

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/howood/cryptotools/internal/parser"
)

const (
	blockTypeEcdsaPrivateKey = "EC PRIVATE KEY"
	blockTypeEcdsaPublicKey  = "EC PUBLIC KEY"
)

// GenerateEncryptedEcdsaPEM generates PEM type ECDSA private key and public ley
func GenerateEncryptedEcdsaPEM(bits int, pwd string) ([]byte, []byte, error) {
	derPrivateKey, derRsaPublicKey, err := GenerateEncryptedEcdsaDER(bits)
	if err != nil {
		return nil, nil, err
	}

	privateblock := &pem.Block{
		Type:  blockTypeEcdsaPrivateKey,
		Bytes: derPrivateKey,
	}
	if pwd != "" {
		if privateblock, err = x509.EncryptPEMBlock(rand.Reader, privateblock.Type, privateblock.Bytes, []byte(pwd), x509.PEMCipherAES256); err != nil {
			return nil, nil, err
		}
	}

	publicblock := &pem.Block{
		Type:  blockTypeEcdsaPublicKey,
		Bytes: derRsaPublicKey,
	}

	return pem.EncodeToMemory(privateblock), pem.EncodeToMemory(publicblock), nil
}

// GenerateEncryptedEcdsaDER generates DER type ECDSA private key and public key
func GenerateEncryptedEcdsaDER(bits int) ([]byte, []byte, error) {
	privatekey, publickey, err := GenerateEcdsaKeys(bits)
	if err != nil {
		return nil, nil, err
	}

	derPrivateKey, err := parser.EncodeEcdsaPrivateKey(privatekey)
	if err != nil {
		return nil, nil, err
	}
	derPublicKey, err := parser.EncodeEcdsaPublicKey(publickey)
	if err != nil {
		return nil, nil, err
	}
	return derPrivateKey, derPublicKey, nil
}

// GenerateEcdsaKeys generates DER type ECDSAprivate key and public key
func GenerateEcdsaKeys(bits int) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privatekey, err := generatePrivateEcdsakey(bits)
	if err != nil {
		return nil, nil, err
	}
	publickey := privatekey.Public().(*ecdsa.PublicKey)
	return privatekey, publickey, nil
}

func generatePrivateEcdsakey(bits int) (*ecdsa.PrivateKey, error) {
	switch bits {
	case 256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case 384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case 521:
		return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		return nil, errors.New("Invalid bits")
	}

}
