package entity

// EncryptKeyType is EncryptKey KeyType
type EncryptKeyType string

const (
	// EncryptTypeRSA is RSA KeyType
	EncryptTypeRSA EncryptKeyType = "rsa"
	// EncryptTypeECDSA is ECDSASA KeyType
	EncryptTypeECDSA EncryptKeyType = "ecdsa"
)

// EncryptKey represents private & public key
type EncryptKey struct {
	Keytype    EncryptKeyType
	RsaKey     RsaKey
	EcdsaKey   EcdsaKey
	Ed25519Key Ed25519Key
}
