package encrypter

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"github.com/howood/cryptotools/internal/entity"
)

// CryptoRsa is Rsa encryption struct
type CryptoRsa struct {
	rsakey *entity.RsaKey
}

// NewCryptoRsa create CryptoRsa struct
func NewCryptoRsa(rsakey *entity.RsaKey) *CryptoRsa {
	return &CryptoRsa{
		rsakey: rsakey,
	}
}

// Encrypt encrypts a input data
func (cr *CryptoRsa) Encrypt(input []byte) ([]byte, error) {
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, cr.rsakey.PublicKey, input)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

// Decrypt decrypts a input data
func (cr *CryptoRsa) Decrypt(input []byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, cr.rsakey.PrivateKey, input)
}

// EncryptWithBase64 encrypts a input data to base64 string
func (cr *CryptoRsa) EncryptWithBase64(input []byte) (string, error) {
	ciphertext, err := cr.Encrypt(input)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptWithBase64 decrypts a input data to base64 string
func (cr *CryptoRsa) DecryptWithBase64(input string) ([]byte, error) {
	inputdecoded, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return nil, err
	}
	return cr.Decrypt(inputdecoded)
}
