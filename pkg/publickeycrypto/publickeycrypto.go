package publickeycrypto

import (
	"errors"

	"github.com/howood/cryptotools/internal/encrypter"
	"github.com/howood/cryptotools/internal/entity"
	"github.com/howood/cryptotools/internal/generator"
	"github.com/howood/cryptotools/internal/parser"
)

const (
	EncryptTypeRsa   entity.EncriptKeyType = entity.EncriptTypeRsa
	EncryptTypeEcdsa entity.EncriptKeyType = entity.EncriptTypeECDSA
)

// PublicKeyCrypto represents PublicKeyCrypto struct
type PublicKeyCrypto struct {
	EncryptType  entity.EncriptKeyType
	EncryptKey   *entity.EncryptKey
	encrypterrsa *encrypter.CryptoRsa
	//	encrypterrecdsa *encrypter.CryptoEcdsa
}

// NewPublicKeyCrypto create PublicKeyCrypto struct
func NewPublicKeyCrypto(bits int, encryptType entity.EncriptKeyType) (*PublicKeyCrypto, error) {
	encryptkey, err := generateKey(bits, encryptType)
	return &PublicKeyCrypto{
		EncryptKey:   &encryptkey,
		encrypterrsa: encrypter.NewCryptoRsa(&encryptkey.RsaKey),
	}, err
}

// NewPublicKeyCryptoWithPEMPublicKey create PublicKeyCrypto struct with PEM Public Key
func NewPublicKeyCryptoWithPEMPublicKey(publickey []byte) (*PublicKeyCrypto, error) {
	encryptkey, err := generateKeyWithPEMPublicKey(publickey)
	return &PublicKeyCrypto{
		EncryptKey:   &encryptkey,
		encrypterrsa: encrypter.NewCryptoRsa(&encryptkey.RsaKey),
	}, err
}

// NewPublicKeyCryptoWithJWKPublicKey create PublicKeyCrypto struct with JWK Public Key
func NewPublicKeyCryptoWithJWKPublicKey(publickey []byte) (*PublicKeyCrypto, error) {
	encryptkey, err := generateKeyWithJWKMPublicKey(publickey)
	return &PublicKeyCrypto{
		EncryptKey:   &encryptkey,
		encrypterrsa: encrypter.NewCryptoRsa(&encryptkey.RsaKey),
	}, err
}

// Encrypt encrypts input data with publickey encryption
func (ck *PublicKeyCrypto) Encrypt(input string) (string, error) {
	return ck.encrypterrsa.EncryptWithBase64([]byte(input))
}

// Decrypt decrypts input data with publickey encryption
func (ck *PublicKeyCrypto) Decrypt(input string) (string, error) {
	if ck.EncryptKey.RsaKey.PrivateKey == nil {
		return "", errors.New("no private key available")
	}
	data, err := ck.encrypterrsa.DecryptWithBase64(input)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// GetPrivateKey gets privatekey
func (ck *PublicKeyCrypto) GetRsaPrivateKey() []byte {
	return parser.EncodeRsaPrivateKeyPKCS1(ck.EncryptKey.RsaKey.PrivateKey)
}

// GetPrivateKeyPKCS8 gets pkcs8 privatekey
func (ck *PublicKeyCrypto) GetRsaPrivateKeyPKCS8() ([]byte, error) {
	return parser.EncodeRsaPrivateKeyPKCS8(ck.EncryptKey.RsaKey.PrivateKey)
}

// GetPublicKey gets publickey
func (ck *PublicKeyCrypto) GetRsaPublicKey() ([]byte, error) {
	return parser.EncodeRsaPublicKey(ck.EncryptKey.RsaKey.PublicKey)
}

// GetPublicKeyWithJWK gets jwk publickey
func (ck *PublicKeyCrypto) GetRsaPublicKeyWithJWK() ([]byte, error) {
	kid := parser.GenerateHashFromRsaKey(ck.EncryptKey.RsaKey.PublicKey)
	return parser.GenerateJSONWebKeyWithRSAPublicKey(ck.EncryptKey.RsaKey.PublicKey, kid)
}

func generateKey(bits int, encryptType entity.EncriptKeyType) (entity.EncryptKey, error) {
	encryptKey := entity.EncryptKey{}
	switch encryptType {
	case EncryptTypeRsa:
		privateKey, publicKey, err := generator.GenerateEncryptedRsaPEM(bits, "")
		if err != nil {
			return encryptKey, err
		}
		if err := parser.DecodePrivateKey(privateKey, &encryptKey); err != nil {
			return encryptKey, err
		}
		if err := parser.DecodePublicKey(publicKey, &encryptKey); err != nil {
			return encryptKey, err
		}
	case EncryptTypeEcdsa:
		privateKey, publicKey, err := generator.GenerateEncryptedEcdsaPEM(bits, "")
		if err != nil {
			return encryptKey, err
		}
		if err := parser.DecodePrivateKey(privateKey, &encryptKey); err != nil {
			return encryptKey, err
		}
		if err := parser.DecodePublicKey(publicKey, &encryptKey); err != nil {
			return encryptKey, err
		}
	}
	return encryptKey, nil
}

func generateKeyWithPEMPublicKey(publickey []byte) (entity.EncryptKey, error) {
	encryptkey := entity.EncryptKey{}
	if err := parser.DecodePublicKey(publickey, &encryptkey); err != nil {
		return encryptkey, err
	}
	return encryptkey, nil
}

func generateKeyWithJWKMPublicKey(publickey []byte) (entity.EncryptKey, error) {
	encryptkey := entity.EncryptKey{}
	jwk, err := parser.ConvertToJSONWebKey([]byte(publickey))
	if err != nil {
		return encryptkey, err
	}
	if encryptkey.RsaKey.PublicKey, err = parser.ConvertToRSAPublicFromJWK(&jwk); err != nil {
		return encryptkey, err
	}
	return encryptkey, nil
}
