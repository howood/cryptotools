package commonkeycrypto

import (
	"github.com/howood/cryptotools/internal/encrypter"
	"github.com/segmentio/ksuid"
)

// CommonKeyCrypto represents CommonKeyCrypto struct
type CommonKeyCrypto struct {
	Identifier string
	encrypter  *encrypter.CryptoAes
}

// NewCommonKeyCrypto create CommonKeyCrypto struct
func NewCommonKeyCrypto(commonKey []byte) (*CommonKeyCrypto, error) {
	identifier := getUUID()
	cryptoaes, err := encrypter.NewCryptoAes(commonKey, []byte(identifier))
	return &CommonKeyCrypto{
		Identifier: identifier,
		encrypter:  cryptoaes,
	}, err
}

// Encrypt encrypts input data with commonkey encryption
func (ck *CommonKeyCrypto) Encrypt(input string) string {
	return ck.encrypter.EncryptWithBase64(input)
}

// Decrypt decrypts input data with commonkey encryption
func (ck *CommonKeyCrypto) Decrypt(input string) (string, error) {
	return ck.encrypter.DecryptWithBase64(input)
}

func getUUID() string {
	return ksuid.New().String()
}
