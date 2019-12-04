package cryptotools

import (
	"github.com/howood/cryptotools/pkg/commonkeycrypto"
	"github.com/howood/cryptotools/pkg/publickeycrypto"
)

const defaultBits = 2048

func NewCommonKeyCrypto(commonKey []byte) (*commonkeycrypto.CommonKeyCrypto, error) {
	return commonkeycrypto.NewCommonKeyCrypto(commonKey)
}

func NewPublicKeyCrypto(bits int) (*publickeycrypto.PublicKeyCrypto, error) {
	if bits == 0 {
		bits = defaultBits
	}
	return publickeycrypto.NewPublicKeyCrypto(bits)
}
