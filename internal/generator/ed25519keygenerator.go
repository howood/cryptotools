package generator

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"

	"github.com/howood/cryptotools/internal/parser"
)

const (
	blockTypeED25519PrivateKey = "OPENSSH PRIVATE KEY"
	blockTypeED25519PublicKey  = "OPENSSH PUBLIC KEY"
)

// GenerateEncryptedED25519PEM generates PEM type ED25519 private key and public key
func GenerateEncryptedED25519PEM(pwd string) ([]byte, []byte, error) {
	derPrivateKey, derED25519PublicKey, err := GenerateEncryptedED25519DER()
	if err != nil {
		return nil, nil, err
	}

	privateblock := &pem.Block{
		Type:  blockTypeED25519PrivateKey,
		Bytes: derPrivateKey,
	}
	if pwd != "" {
		if privateblock, err = x509.EncryptPEMBlock(rand.Reader, privateblock.Type, privateblock.Bytes, []byte(pwd), x509.PEMCipherAES256); err != nil {
			return nil, nil, err
		}
	}

	publicblock := &pem.Block{
		Type:  blockTypeED25519PublicKey,
		Bytes: derED25519PublicKey,
	}

	return pem.EncodeToMemory(privateblock), pem.EncodeToMemory(publicblock), nil
}

// GenerateEncryptedED25519DER generates DER type ED25519 private key and public key
func GenerateEncryptedED25519DER() ([]byte, []byte, error) {
	publickey, privatekey, err := GenerateED25519Keys()
	if err != nil {
		return nil, nil, err
	}

	derPrivateKey := parser.MarshalED25519PrivateKey(&privatekey)
	if err != nil {
		return nil, nil, err
	}
	derED25519PublicKey, err := x509.MarshalPKIXPublicKey(publickey)
	if err != nil {
		return nil, nil, err
	}

	return derPrivateKey, derED25519PublicKey, nil
}

// GenerateED25519Keys generates DER type ED25519 private key and public key
func GenerateED25519Keys() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}
