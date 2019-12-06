package encrypter

import (
	"crypto/rand"
	"encoding/base64"

	"github.com/howood/cryptotools/internal/entity"
	"github.com/howood/ecies"
)

// CryptoEcdsa represents Ecdsa encryption struct
type CryptoEcdsa struct {
	ecdsakey *entity.EcdsaKey
}

// NewCryptoEcdsa create CryptoEcdsa struct
func NewCryptoEcdsa(ecdsakey *entity.EcdsaKey) *CryptoEcdsa {
	return &CryptoEcdsa{
		ecdsakey: ecdsakey,
	}
}

// Encrypt encrypts a input data
func (ce *CryptoEcdsa) Encrypt(input []byte) ([]byte, error) {
	pub := ecies.ImportECDSAPublic(ce.ecdsakey.PublicKey)
	return ecies.Encrypt(rand.Reader, pub, input, nil, nil)

}

// Decrypt decrypts a input data
func (ce *CryptoEcdsa) Decrypt(input []byte) ([]byte, error) {
	pri := ecies.ImportECDSA(ce.ecdsakey.PrivateKey)
	return pri.Decrypt(rand.Reader, input, nil, nil)
}

// EncryptWithBase64 encrypts a input data to base64 string
func (ce *CryptoEcdsa) EncryptWithBase64(input []byte) (string, error) {
	ciphertext, err := ce.Encrypt(input)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptWithBase64 decrypts a input data to base64 string
func (ce *CryptoEcdsa) DecryptWithBase64(input string) ([]byte, error) {
	inputdecoded, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return nil, err
	}
	return ce.Decrypt(inputdecoded)
}
