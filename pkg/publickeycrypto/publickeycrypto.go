package publickeycrypto

import (
	"errors"
	"log"

	"github.com/howood/cryptotools/internal/encrypter"
	"github.com/howood/cryptotools/internal/entity"
	"github.com/howood/cryptotools/internal/generator"
	"github.com/howood/cryptotools/internal/parser"
)

// EncryptKeyType is EncryptKey KeyType
type EncryptKeyType entity.EncryptKeyType

const (
	errorInvalidEncryptType = "Invalid encryptType"
	errorNoEncryptKeyType   = "No encrypt keytype"
)

const (
	// EncryptTypeRSA is RSA KeyType
	EncryptTypeRSA EncryptKeyType = EncryptKeyType(entity.EncryptTypeRSA)
	// EncryptTypeECDSA is ECDSASA KeyType
	EncryptTypeECDSA EncryptKeyType = EncryptKeyType(entity.EncryptTypeECDSA)
)

// PublicKeyCrypto represents PublicKeyCrypto struct
type PublicKeyCrypto struct {
	EncryptKey     *entity.EncryptKey
	encrypterRsa   *encrypter.CryptoRsa
	encrypterEcdsa *encrypter.CryptoEcdsa
}

// NewPublicKeyCrypto create PublicKeyCrypto struct
func NewPublicKeyCrypto(bits int, encryptType EncryptKeyType) (*PublicKeyCrypto, error) {
	encryptkey, err := generateEncryptKey(bits, encryptType)
	log.Print(encryptType)
	if err != nil {
		log.Print("33333333")
		return nil, err
	}
	var encrypterRsa *encrypter.CryptoRsa
	var encrypterEcdsa *encrypter.CryptoEcdsa
	switch encryptkey.Keytype {
	case entity.EncryptTypeRSA:
		encrypterRsa = encrypter.NewCryptoRsa(&encryptkey.RsaKey)
	case entity.EncryptTypeECDSA:
		encrypterEcdsa = encrypter.NewCryptoEcdsa(&encryptkey.EcdsaKey)
	default:
		return nil, errors.New(errorNoEncryptKeyType)
	}
	return &PublicKeyCrypto{
		EncryptKey:     &encryptkey,
		encrypterRsa:   encrypterRsa,
		encrypterEcdsa: encrypterEcdsa,
	}, nil
}

// NewPublicKeyCryptoWithPEMPublicKey create PublicKeyCrypto struct with PEM Public Key
func NewPublicKeyCryptoWithPEMPublicKey(publickey []byte, encryptType EncryptKeyType) (*PublicKeyCrypto, error) {
	encryptkey, err := generateKeyWithPEMPublicKey(publickey)
	if err != nil {
		return nil, err
	}
	var encrypterRsa *encrypter.CryptoRsa
	var encrypterEcdsa *encrypter.CryptoEcdsa
	switch encryptkey.Keytype {
	case entity.EncryptTypeRSA:
		encrypterRsa = encrypter.NewCryptoRsa(&encryptkey.RsaKey)
	case entity.EncryptTypeECDSA:
		encrypterEcdsa = encrypter.NewCryptoEcdsa(&encryptkey.EcdsaKey)
	default:
		return nil, errors.New(errorNoEncryptKeyType)
	}
	return &PublicKeyCrypto{
		EncryptKey:     &encryptkey,
		encrypterRsa:   encrypterRsa,
		encrypterEcdsa: encrypterEcdsa,
	}, nil
}

// NewPublicKeyCryptoWithJWKPublicKey create PublicKeyCrypto struct with JWK Public Key
func NewPublicKeyCryptoWithJWKPublicKey(publickey []byte, encryptType EncryptKeyType) (*PublicKeyCrypto, error) {
	encryptkey, err := generateKeyWithJWKMPublicKey(publickey, encryptType)
	if err != nil {
		return nil, err
	}
	var encrypterRsa *encrypter.CryptoRsa
	var encrypterEcdsa *encrypter.CryptoEcdsa
	switch encryptkey.Keytype {
	case entity.EncryptTypeRSA:
		encrypterRsa = encrypter.NewCryptoRsa(&encryptkey.RsaKey)
	case entity.EncryptTypeECDSA:
		encrypterEcdsa = encrypter.NewCryptoEcdsa(&encryptkey.EcdsaKey)
	default:
		return nil, errors.New(errorNoEncryptKeyType)
	}
	return &PublicKeyCrypto{
		EncryptKey:     &encryptkey,
		encrypterRsa:   encrypterRsa,
		encrypterEcdsa: encrypterEcdsa,
	}, nil
}

// Encrypt encrypts input data with publickey encryption
func (ck *PublicKeyCrypto) Encrypt(input string) (string, error) {
	switch ck.EncryptKey.Keytype {
	case entity.EncryptTypeRSA:
		return ck.encrypterRsa.EncryptWithBase64([]byte(input))
	case entity.EncryptTypeECDSA:
		return ck.encrypterEcdsa.EncryptWithBase64([]byte(input))
	default:
		return "", errors.New(errorInvalidEncryptType)
	}
}

// Decrypt decrypts input data with publickey encryption
func (ck *PublicKeyCrypto) Decrypt(input string) (string, error) {
	switch ck.EncryptKey.Keytype {
	case entity.EncryptTypeRSA:
		if ck.EncryptKey.RsaKey.PrivateKey == nil {
			return "", errors.New("no private key available")
		}
		data, err := ck.encrypterRsa.DecryptWithBase64(input)
		if err != nil {
			return "", err
		}
		return string(data), nil
	case entity.EncryptTypeECDSA:
		if ck.EncryptKey.EcdsaKey.PrivateKey == nil {
			return "", errors.New("no private key available")
		}
		data, err := ck.encrypterEcdsa.DecryptWithBase64(input)
		if err != nil {
			return "", err
		}
		return string(data), nil
	default:
		return "", errors.New(errorInvalidEncryptType)
	}
}

// GetPrivateKey gets privatekey
func (ck *PublicKeyCrypto) GetPrivateKey() ([]byte, error) {
	switch ck.EncryptKey.Keytype {
	case entity.EncryptTypeRSA:
		return parser.EncodeRsaPrivateKeyPKCS1(ck.EncryptKey.RsaKey.PrivateKey), nil
	case entity.EncryptTypeECDSA:
		return parser.EncodeEcdsaPrivateKey(ck.EncryptKey.EcdsaKey.PrivateKey)
	default:
		return nil, errors.New(errorInvalidEncryptType)
	}
}

// GetPrivateKeyPKCS8 gets pkcs8 privatekey
func (ck *PublicKeyCrypto) GetPrivateKeyPKCS8() ([]byte, error) {
	switch ck.EncryptKey.Keytype {
	case entity.EncryptTypeRSA:
		return parser.EncodeRsaPrivateKeyPKCS8(ck.EncryptKey.RsaKey.PrivateKey)
	default:
		return nil, errors.New(errorInvalidEncryptType)
	}
}

// GetPublicKey gets publickey
func (ck *PublicKeyCrypto) GetPublicKey() ([]byte, error) {
	switch ck.EncryptKey.Keytype {
	case entity.EncryptTypeRSA:
		return parser.EncodeRsaPublicKey(ck.EncryptKey.RsaKey.PublicKey)
	case entity.EncryptTypeECDSA:
		return parser.EncodeEcdsaPublicKey(ck.EncryptKey.EcdsaKey.PublicKey)
	default:
		return nil, errors.New(errorInvalidEncryptType)
	}
}

// GetPublicKeyWithJWK gets jwk publickey
func (ck *PublicKeyCrypto) GetPublicKeyWithJWK() ([]byte, error) {
	switch ck.EncryptKey.Keytype {
	case entity.EncryptTypeRSA:
		kid := parser.GenerateHashFromCrptoKey(ck.EncryptKey.RsaKey.PublicKey)
		return parser.GenerateJSONWebKeyWithRSAPublicKey(ck.EncryptKey.RsaKey.PublicKey, kid)
	default:
		return nil, errors.New(errorInvalidEncryptType)
	}
}

func generateEncryptKey(bits int, encryptType EncryptKeyType) (entity.EncryptKey, error) {
	encryptkey := entity.EncryptKey{}
	switch encryptType {
	case EncryptTypeRSA:
		encryptkey.Keytype = entity.EncryptTypeRSA
		privateKey, publicKey, err := generator.GenerateEncryptedRsaPEM(bits, "")
		if err != nil {
			return encryptkey, err
		}
		if err := parser.DecodePrivateKey(privateKey, &encryptkey); err != nil {
			return encryptkey, err
		}
		if err := parser.DecodePublicKey(publicKey, &encryptkey); err != nil {
			return encryptkey, err
		}
		return encryptkey, nil

	case EncryptTypeECDSA:
		var err error
		encryptkey.Keytype = entity.EncryptTypeECDSA
		encryptkey.EcdsaKey.PrivateKey, encryptkey.EcdsaKey.PublicKey, err = generator.GenerateEcdsaKeys(bits)
		if err != nil {
			return encryptkey, err
		}
	}
	return encryptkey, nil
}

func generateKeyWithPEMPublicKey(publickey []byte) (entity.EncryptKey, error) {
	encryptkey := entity.EncryptKey{}
	if err := parser.DecodePublicKey(publickey, &encryptkey); err != nil {
		return encryptkey, err
	}
	return encryptkey, nil
}

func generateKeyWithJWKMPublicKey(publickey []byte, encryptType EncryptKeyType) (entity.EncryptKey, error) {
	encryptkey := entity.EncryptKey{}
	switch encryptType {
	case EncryptTypeRSA:
		encryptkey.Keytype = entity.EncryptTypeRSA
		jwk, err := parser.ConvertToJSONWebKey([]byte(publickey))
		if err != nil {
			return encryptkey, err
		}
		if encryptkey.RsaKey.PublicKey, err = parser.ConvertToRSAPublicFromJWK(&jwk); err != nil {
			return encryptkey, err
		}
		return encryptkey, nil
	default:
		return encryptkey, errors.New(errorInvalidEncryptType)
	}
}
