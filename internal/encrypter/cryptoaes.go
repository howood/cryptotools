package encrypter

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
)

// CryptoAes represents AES encryption struct
type CryptoAes struct {
	cipherBlock cipher.Block
	commonIV    []byte
}

// NewCryptoAes create CryptoAes struct
func NewCryptoAes(encryptionkey []byte, commoniv []byte) (*CryptoAes, error) {
	c, err := aes.NewCipher(encryptionkey)
	if err != nil {
		return nil, fmt.Errorf("Error: NewCipher(%d bytes) = %s", len(encryptionkey), err)
	}
	cryptoaes := &CryptoAes{
		cipherBlock: c,
		commonIV:    commoniv[:aes.BlockSize],
	}
	return cryptoaes, nil
}

// Encrypt encrypts a input data
func (ca *CryptoAes) Encrypt(input []byte) []byte {
	cfb := cipher.NewOFB(ca.cipherBlock, ca.commonIV)
	ciphertext := make([]byte, len(input))
	cfb.XORKeyStream(ciphertext, input)
	return ciphertext
}

// Decrypt decrypts a input data
func (ca *CryptoAes) Decrypt(input []byte) []byte {
	cfbdec := cipher.NewOFB(ca.cipherBlock, ca.commonIV)
	decrypttext := make([]byte, len(input))
	cfbdec.XORKeyStream(decrypttext, input)
	return decrypttext
}

// EncryptWithBase64 encrypts a input data to base64 string
func (ca *CryptoAes) EncryptWithBase64(input string) string {
	ciphertext := ca.Encrypt([]byte(input))
	return base64.StdEncoding.EncodeToString(ciphertext)
}

// DecryptWithBase64 decrypts a input data to base64 string
func (ca *CryptoAes) DecryptWithBase64(input string) (string, error) {
	inputdecoded, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return "", err
	}
	decrypttext := ca.Decrypt(inputdecoded)
	return string(decrypttext), nil
}
