package publickeycrypto

import (
	"errors"

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

// NewPublicKeyCryptoWithPEMPublicKey create PublicKeyCrypto struct with PEM Public Key
func NewPublicKeyCryptoWithPEMPublicKey(publickey []byte) (*PublicKeyCrypto, error) {
	rsakey, err := generateRsaKeyWithPEMPublicKey(publickey)
	return &PublicKeyCrypto{
		RsaKey:    &rsakey,
		encrypter: encrypter.NewCryptoRsa(&rsakey),
	}, err
}

// NewPublicKeyCryptoWithJWKPublicKey create PublicKeyCrypto struct with JWK Public Key
func NewPublicKeyCryptoWithJWKPublicKey(publickey []byte) (*PublicKeyCrypto, error) {
	rsakey, err := generateRsaKeyWithJWKMPublicKey(publickey)
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
	if ck.RsaKey.PrivateKey == nil {
		return "", errors.New("no private key available")
	}
	data, err := ck.encrypter.DecryptWithBase64(input)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// GetPrivateKey gets privatekey
func (ck *PublicKeyCrypto) GetPrivateKey() []byte {
	return parser.DecodeRsaPrivateKeyPKCS1(ck.RsaKey.PrivateKey)
}

// GetPrivateKeyPKCS8 gets pkcs8 privatekey
func (ck *PublicKeyCrypto) GetPrivateKeyPKCS8() ([]byte, error) {
	return parser.DecodeRsaPrivateKeyPKCS8(ck.RsaKey.PrivateKey)
}

// GetPublicKey gets publickey
func (ck *PublicKeyCrypto) GetPublicKey() ([]byte, error) {
	return parser.DecodeRsaPublicKey(ck.RsaKey.PublicKey)
}

// GetPublicKeyWithJWK gets jwk publickey
func (ck *PublicKeyCrypto) GetPublicKeyWithJWK() ([]byte, error) {
	kid := parser.GenerateHashFromRsaKey(ck.RsaKey.PublicKey)
	return parser.GenerateJSONWebKeyWithRSAPublicKey(ck.RsaKey.PublicKey, kid)
}

func generateRsaKey(bits int) (entity.RsaKey, error) {
	rsakey := entity.RsaKey{}
	privateKey, publicKey, err := generator.GenerateEncryptedPEM(bits, "")
	if err != nil {
		return rsakey, err
	}
	if err := parser.ReadRsaPrivateKey(privateKey, &rsakey); err != nil {
		return rsakey, err
	}
	if err := parser.ReadRsaPublicKey(publicKey, &rsakey); err != nil {
		return rsakey, err
	}
	return rsakey, nil
}

func generateRsaKeyWithPEMPublicKey(publickey []byte) (entity.RsaKey, error) {
	rsakey := entity.RsaKey{}
	if err := parser.ReadRsaPublicKey(publickey, &rsakey); err != nil {
		return rsakey, err
	}
	return rsakey, nil
}

func generateRsaKeyWithJWKMPublicKey(publickey []byte) (entity.RsaKey, error) {
	rsakey := entity.RsaKey{}
	jwk, err := parser.ConvertToJSONWebKey([]byte(publickey))
	if err != nil {
		return rsakey, err
	}
	if rsakey.PublicKey, err = parser.ConvertToRSAPublicFromJWK(&jwk); err != nil {
		return rsakey, err
	}
	return rsakey, nil
}
