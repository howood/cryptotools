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
	return publickeycrypto.NewPublicKeyCrypto(bits)
}
