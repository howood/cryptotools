package generator

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	mathrand "math/rand"

	"golang.org/x/crypto/ssh"
)

const (
	blockTypeED25519PrivateKey = "OPENSSH PRIVATE KEY"
	blockTypeED25519PublicKey  = "OPENSSH PUBLIC KEY"
)

// GenerateEncryptedED25519PEM generates PEM type ED25519 private key and public key
func GenerateEncryptedED25519PEM(pwd string) ([]byte, []byte, error) {
	derPrivateKey, derED25519PublicKey, err := GenerateEncryptedED25519DER()
	if err != nil {
		return nil, nil, err
	}

	privateblock := &pem.Block{
		Type:  blockTypeED25519PrivateKey,
		Bytes: derPrivateKey,
	}
	if pwd != "" {
		if privateblock, err = x509.EncryptPEMBlock(rand.Reader, privateblock.Type, privateblock.Bytes, []byte(pwd), x509.PEMCipherAES256); err != nil {
			return nil, nil, err
		}
	}

	publicblock := &pem.Block{
		Type:  blockTypeED25519PublicKey,
		Bytes: derED25519PublicKey,
	}

	return pem.EncodeToMemory(privateblock), pem.EncodeToMemory(publicblock), nil
}

// GenerateEncryptedED25519DER generates DER type ED25519 private key and public key
func GenerateEncryptedED25519DER() ([]byte, []byte, error) {
	publickey, privatekey, err := GenerateED25519Keys()
	if err != nil {
		return nil, nil, err
	}

	derPrivateKey := marshalED25519PrivateKey(privatekey)
	if err != nil {
		return nil, nil, err
	}
	derED25519PublicKey, err := x509.MarshalPKIXPublicKey(publickey)
	if err != nil {
		return nil, nil, err
	}

	return derPrivateKey, derED25519PublicKey, nil
}

// GenerateED25519Keys generates DER type ED25519 private key and public key
func GenerateED25519Keys() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func marshalED25519PrivateKey(key ed25519.PrivateKey) []byte {
	magic := append([]byte("openssh-key-v1"), 0)

	var w struct {
		CipherName   string
		KdfName      string
		KdfOpts      string
		NumKeys      uint32
		PubKey       []byte
		PrivKeyBlock []byte
	}

	pk1 := struct {
		Check1  uint32
		Check2  uint32
		Keytype string
		Pub     []byte
		Priv    []byte
		Comment string
		Pad     []byte `ssh:"rest"`
	}{}

	ci := mathrand.Uint32()
	pk1.Check1 = ci
	pk1.Check2 = ci
	pk1.Keytype = ssh.KeyAlgoED25519

	pk, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		return nil
	}
	pubKey := []byte(pk)
	pk1.Pub = pubKey
	pk1.Priv = []byte(key)
	pk1.Comment = ""

	bs := 8
	blockLen := len(ssh.Marshal(pk1))
	padLen := (bs - (blockLen % bs)) % bs
	pk1.Pad = make([]byte, padLen)

	for i := 0; i < padLen; i++ {
		pk1.Pad[i] = byte(i + 1)
	}

	prefix := []byte{0x0, 0x0, 0x0, 0x0b}
	prefix = append(prefix, []byte(ssh.KeyAlgoED25519)...)
	prefix = append(prefix, []byte{0x0, 0x0, 0x0, 0x20}...)

	w.CipherName = "none"
	w.KdfName = "none"
	w.KdfOpts = ""
	w.NumKeys = 1
	w.PubKey = append(prefix, pubKey...)
	w.PrivKeyBlock = ssh.Marshal(pk1)

	magic = append(magic, ssh.Marshal(w)...)

	return magic
}
