package publickeycrypto

import (
	"github.com/howood/cryptotools/internal/encrypter"
	"github.com/howood/cryptotools/internal/entity"
	"github.com/howood/cryptotools/internal/generator"
	"github.com/howood/cryptotools/internal/parser"
)

// PublicKeyCrypto represents PublicKeyCrypto struct
type PublicKeyCrypto struct {
	RsaKey    *entity.RsaKey
	encrypter *encrypter.CryptoRsa
}

// NewPublicKeyCrypto create PublicKeyCrypto struct
func NewPublicKeyCrypto(bits int) (*PublicKeyCrypto, error) {
	rsakey, err := generateRsaKey(bits)
	return &PublicKeyCrypto{
		RsaKey:    &rsakey,
		encrypter: encrypter.NewCryptoRsa(&rsakey),
	}, err
}

// Encrypt encrypts input data with publickey encryption
func (ck *PublicKeyCrypto) Encrypt(input string) (string, error) {
	return ck.encrypter.EncryptWithBase64([]byte(input))
}

// Decrypt decrypts input data with publickey encryption
func (ck *PublicKeyCrypto) Decrypt(input string) (string, error) {
	data, err := ck.encrypter.DecryptWithBase64(input)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// GetPrivateKey gets privatekey
func (ck *PublicKeyCrypto) GetPrivateKey() []byte {
	return parser.DecodePrivateKeyPKCS1(ck.RsaKey.PrivateKey)
}

// GetPrivateKeyPKCS8 gets pkcs8 privatekey
func (ck *PublicKeyCrypto) GetPrivateKeyPKCS8() ([]byte, error) {
	return parser.DecodePrivateKeyPKCS8(ck.RsaKey.PrivateKey)
}

// GetPublicKey gets publickey
func (ck *PublicKeyCrypto) GetPublicKey() ([]byte, error) {
	return parser.DecodePublicKey(ck.RsaKey.PublicKey)
}

func generateRsaKey(bits int) (entity.RsaKey, error) {
	rsakey := entity.RsaKey{}
	privateKey, publicKey, err := generator.GenerateEncryptedPEM(bits, "")
	if err != nil {
		return rsakey, err
	}
	if err := parser.ReadPrivateKey(privateKey, &rsakey); err != nil {
		return rsakey, err
	}
	if err := parser.ReadPublicKey(publicKey, &rsakey); err != nil {
		return rsakey, err
	}
	return rsakey, nil
}
