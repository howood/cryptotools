package entity

type EncryptKeyType string

const (
	EncryptTypeRsa   EncryptKeyType = "rsa"
	EncryptTypeECDSA EncryptKeyType = "ecdsa"
)

// EncryptKey represents private & public key
type EncryptKey struct {
	Keytype    EncryptKeyType
	RsaKey     RsaKey
	EcdsaKey   EcdsaKey
	Ed25519Key Ed25519Key
}
