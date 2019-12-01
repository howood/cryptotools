package entity

import (
	"crypto/rsa"
)

// RsaKey represents RSA private & public key
type RsaKey struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}
