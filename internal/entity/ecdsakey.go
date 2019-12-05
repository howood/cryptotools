package entity

import (
	"crypto/ecdsa"
)

// EcdsaKey represents ECDSA private & public key
type EcdsaKey struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
}
