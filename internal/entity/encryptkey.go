package entity

// EncryptKeyType is EncryptKey KeyType
type EncryptKeyType string

const (
	// EncryptTypeRSA is RSA KeyType
	EncryptTypeRSA EncryptKeyType = "rsa"
	// EncryptTypeECDSA is ECDSASA KeyType
	EncryptTypeECDSA EncryptKeyType = "ecdsa"
	// EncryptTypeED25519 is ED25519 KeyType
	EncryptTypeED25519 EncryptKeyType = "ed25519"
)

// EncryptKey represents private & public key
type EncryptKey struct {
	Keytype    EncryptKeyType
	RsaKey     RsaKey
	EcdsaKey   EcdsaKey
	Ed25519Key Ed25519Key
}
