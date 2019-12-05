package entity

type EncriptKeyType string

const (
	EncriptTypeRsa   EncriptKeyType = "rsa"
	EncriptTypeECDSA EncriptKeyType = "ecdsa"
)

// EncryptKey represents private & public key
type EncryptKey struct {
	Keytype    EncriptKeyType
	RsaKey     RsaKey
	EcdsaKey   EcdsaKey
	Ed25519Key Ed25519Key
}
