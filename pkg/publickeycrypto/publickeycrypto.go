package publickeycrypto

import (
	"errors"

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
	// EncryptTypeED25519 is ED25519 KeyType
	EncryptTypeED25519 EncryptKeyType = EncryptKeyType(entity.EncryptTypeED25519)
)

// PublicKeyCrypto represents PublicKeyCrypto struct
type PublicKeyCrypto struct {
	EncryptKey       *entity.EncryptKey
	encrypterRsa     *encrypter.CryptoRsa
	encrypterEcdsa   *encrypter.CryptoEcdsa
	encrypterEd25519 *encrypter.CryptoEd25519
}

// NewPublicKeyCrypto create PublicKeyCrypto struct
func NewPublicKeyCrypto(bits int, encryptType EncryptKeyType) (*PublicKeyCrypto, error) {
	encryptkey, err := generateEncryptKey(bits, encryptType)
	if err != nil {
		return nil, err
	}
	var encrypterRsa *encrypter.CryptoRsa
	var encrypterEcdsa *encrypter.CryptoEcdsa
	var encrypterEd25519 *encrypter.CryptoEd25519
	switch encryptkey.Keytype {
	case entity.EncryptTypeRSA:
		encrypterRsa = encrypter.NewCryptoRsa(&encryptkey.RsaKey)
	case entity.EncryptTypeECDSA:
		encrypterEcdsa = encrypter.NewCryptoEcdsa(&encryptkey.EcdsaKey)
	case entity.EncryptTypeED25519:
		encrypterEd25519 = encrypter.NewCryptoEd25519(&encryptkey.Ed25519Key)
	default:
		return nil, errors.New(errorNoEncryptKeyType)
	}
	return &PublicKeyCrypto{
		EncryptKey:       &encryptkey,
		encrypterRsa:     encrypterRsa,
		encrypterEcdsa:   encrypterEcdsa,
		encrypterEd25519: encrypterEd25519,
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
	var encrypterEd25519 *encrypter.CryptoEd25519
	switch encryptkey.Keytype {
	case entity.EncryptTypeRSA:
		encrypterRsa = encrypter.NewCryptoRsa(&encryptkey.RsaKey)
	case entity.EncryptTypeECDSA:
		encrypterEcdsa = encrypter.NewCryptoEcdsa(&encryptkey.EcdsaKey)
	case entity.EncryptTypeED25519:
		encrypterEd25519 = encrypter.NewCryptoEd25519(&encryptkey.Ed25519Key)
	default:
		return nil, errors.New(errorNoEncryptKeyType)
	}
	return &PublicKeyCrypto{
		EncryptKey:       &encryptkey,
		encrypterRsa:     encrypterRsa,
		encrypterEcdsa:   encrypterEcdsa,
		encrypterEd25519: encrypterEd25519,
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
	case entity.EncryptTypeED25519:
		return ck.encrypterEd25519.EncryptWithBase64([]byte(input))
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
	case entity.EncryptTypeED25519:
		if ck.EncryptKey.Ed25519Key.PrivateKey == nil {
			return "", errors.New("no private key available")
		}
		data, err := ck.encrypterEd25519.DecryptWithBase64(input)
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
	return parser.EncodePrivateKey(ck.EncryptKey)
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
	return parser.EncodePublicKey(ck.EncryptKey)
}

// GetPublicKeyWithJWK gets jwk publickey
func (ck *PublicKeyCrypto) GetPublicKeyWithJWK() ([]byte, error) {
	var kid string
	switch ck.EncryptKey.Keytype {
	case entity.EncryptTypeRSA:
		kid = parser.GenerateHashFromCrptoKey(ck.EncryptKey.RsaKey.PublicKey)
	case entity.EncryptTypeECDSA:
		kid = parser.GenerateHashFromCrptoKey(ck.EncryptKey.EcdsaKey.PublicKey)
	default:
		return nil, errors.New(errorInvalidEncryptType)
	}
	return parser.GenerateJSONWebKeyWithEncryptPublicKey(ck.EncryptKey, kid)
}

func generateEncryptKey(bits int, encryptType EncryptKeyType) (entity.EncryptKey, error) {
	encryptkey := entity.EncryptKey{}
	switch encryptType {
	case EncryptTypeRSA:
		var err error
		encryptkey.Keytype = entity.EncryptTypeRSA
		encryptkey.RsaKey.PrivateKey, encryptkey.RsaKey.PublicKey, err = generator.GenerateRsaKeys(bits)
		if err != nil {
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
	case EncryptTypeED25519:
		var err error
		encryptkey.Keytype = entity.EncryptTypeED25519
		encryptkey.Ed25519Key.PublicKey, encryptkey.Ed25519Key.PrivateKey, err = generator.GenerateED25519Keys()
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
	case EncryptTypeECDSA:
		encryptkey.Keytype = entity.EncryptTypeECDSA
		jwk, err := parser.ConvertToJSONWebKey([]byte(publickey))
		if err != nil {
			return encryptkey, err
		}
		if encryptkey.EcdsaKey.PublicKey, err = parser.ConvertToEcdsaPublicFromJWK(&jwk); err != nil {
			return encryptkey, err
		}
		return encryptkey, nil
	default:
		return encryptkey, errors.New(errorInvalidEncryptType)
	}
}
