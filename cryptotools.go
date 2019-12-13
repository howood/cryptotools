package cryptotools

import (
	"github.com/howood/cryptotools/pkg/commonkeycrypto"
	"github.com/howood/cryptotools/pkg/publickeycrypto"
)

const defaultRSABits = 2048
const defaultECDSABits = 521

const (
	// EncryptTypeRSA is RSA KeyType
	EncryptTypeRSA publickeycrypto.EncryptKeyType = publickeycrypto.EncryptTypeRSA
	// EncryptTypeECDSA is ECDSASA KeyType
	EncryptTypeECDSA publickeycrypto.EncryptKeyType = publickeycrypto.EncryptTypeECDSA
)

// NewCommonKeyCrypto create CommonKeyCrypto
func NewCommonKeyCrypto(commonKey []byte) (*commonkeycrypto.CommonKeyCrypto, error) {
	return commonkeycrypto.NewCommonKeyCrypto(commonKey)
}

// NewPublicKeyCrypto create PublicKeyCrypto
func NewPublicKeyCrypto(bits int, encryptType publickeycrypto.EncryptKeyType) (*publickeycrypto.PublicKeyCrypto, error) {
	if bits == 0 {
		switch encryptType {
		case EncryptTypeRSA:
			bits = defaultRSABits
		case EncryptTypeECDSA:
			bits = defaultECDSABits
		}
	}
	return publickeycrypto.NewPublicKeyCrypto(bits, encryptType)
}

// NewPublicKeyCryptoWithPEMPublicKey create PublicKeyCrypto with PEM PublicKey
func NewPublicKeyCryptoWithPEMPublicKey(publickey []byte) (*publickeycrypto.PublicKeyCrypto, error) {
	return publickeycrypto.NewPublicKeyCryptoWithPEMPublicKey(publickey, publickeycrypto.EncryptTypeRSA)
}

// NewPublicKeyCryptoWithJWKPublicKey create PublicKeyCrypto with JWK PublicKey
func NewPublicKeyCryptoWithJWKPublicKey(publickey []byte) (*publickeycrypto.PublicKeyCrypto, error) {
	return publickeycrypto.NewPublicKeyCryptoWithJWKPublicKey(publickey, publickeycrypto.EncryptTypeRSA)
}
