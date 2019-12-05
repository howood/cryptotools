package cryptotools

import (
	"github.com/howood/cryptotools/pkg/commonkeycrypto"
	"github.com/howood/cryptotools/pkg/publickeycrypto"
)

const defaultBits = 2048

// NewCommonKeyCrypto create CommonKeyCrypto
func NewCommonKeyCrypto(commonKey []byte) (*commonkeycrypto.CommonKeyCrypto, error) {
	return commonkeycrypto.NewCommonKeyCrypto(commonKey)
}

// NewPublicKeyCrypto create PublicKeyCrypto
func NewPublicKeyCrypto(bits int) (*publickeycrypto.PublicKeyCrypto, error) {
	if bits == 0 {
		bits = defaultBits
	}
	return publickeycrypto.NewPublicKeyCrypto(bits, publickeycrypto.EncryptTypeRsa)
}

// NewPublicKeyCryptoWithPEMPublicKey create PublicKeyCrypto with PEM PublicKey
func NewPublicKeyCryptoWithPEMPublicKey(publickey []byte) (*publickeycrypto.PublicKeyCrypto, error) {
	return publickeycrypto.NewPublicKeyCryptoWithPEMPublicKey(publickey)
}

// NewPublicKeyCryptoWithJWKPublicKey create PublicKeyCrypto with JWK PublicKey
func NewPublicKeyCryptoWithJWKPublicKey(publickey []byte) (*publickeycrypto.PublicKeyCrypto, error) {
	return publickeycrypto.NewPublicKeyCryptoWithJWKPublicKey(publickey)
}
