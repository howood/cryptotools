package entity

import (
	"crypto/rsa"
)

type RsaKey struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}
