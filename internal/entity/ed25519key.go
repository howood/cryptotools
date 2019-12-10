package entity

import (
	"crypto/ed25519"
)

// Ed25519Key represents Ed25519 private & public key
type Ed25519Key struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}
