package parser

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	mathrand "math/rand"
	"unsafe"

	"github.com/ScaleFT/sshkeys"
	"github.com/howood/cryptotools/internal/entity"
	"golang.org/x/crypto/ssh"
)

const (
	blockTypeRsaPrivateKey     = "RSA PRIVATE KEY"
	blockTypeEcdsaPrivateKey   = "EC PRIVATE KEY"
	blockTypeOpenSSHPrivateKey = "OPENSSH PRIVATE KEY"
	blockTypePrivateKey        = "PRIVATE KEY"
	blockTypeRsaPublicKey      = "RSA PUBLIC KEY"
	blockTypeEcdsaPublicKey    = "EC PUBLIC KEY"
	blockTypeOpenSSHPublicKey  = "OPENSSH PUBLIC KEY"
	blockTypePublicKey         = "PUBLIC KEY"
)

// DecodePrivateKey decodes private to entity struct
func DecodePrivateKey(bytedata []byte, encryptkey *entity.EncryptKey) error {
	block, _ := pem.Decode(bytedata)
	if block == nil {
		return errors.New("failed to decode private key data")
	}
	switch block.Type {
	case blockTypeRsaPrivateKey:
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return err
		}
		key.Precompute()
		encryptkey.RsaKey.PrivateKey = key
		encryptkey.Keytype = entity.EncryptTypeRSA
	case blockTypeEcdsaPrivateKey:
		var err error
		encryptkey.EcdsaKey.PrivateKey, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return err
		}
		encryptkey.Keytype = entity.EncryptTypeECDSA
	case blockTypeOpenSSHPrivateKey:
		keyInterface, err := sshkeys.ParseEncryptedRawPrivateKey(bytedata, nil)
		if err != nil {
			return err
		}
		if err := castPrivateKeyToEncryptKey(keyInterface, encryptkey); err != nil {
			return err
		}
	case blockTypePrivateKey:
		keyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return err
		}
		if err := castPrivateKeyToEncryptKey(keyInterface, encryptkey); err != nil {
			return err
		}
	default:
		return fmt.Errorf("invalid private key type : %s", block.Type)
	}
	return nil
}

// DecodePublicKey decodes publickey to entity struct
func DecodePublicKey(bytedata []byte, encryptkey *entity.EncryptKey) error {
	block, _ := pem.Decode(bytedata)
	if block == nil {
		return errors.New("failed to decode PEM block containing public key")
	}
	var err error
	switch block.Type {
	case blockTypeRsaPublicKey:
		if encryptkey.RsaKey.PublicKey, err = x509.ParsePKCS1PublicKey(block.Bytes); err != nil {
			return err
		}
		encryptkey.Keytype = entity.EncryptTypeRSA
	case blockTypeEcdsaPublicKey:
		keyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return err
		}
		if err := castPublicKeyToEncryptKey(keyInterface, encryptkey); err != nil {
			return err
		}
	case blockTypeOpenSSHPublicKey, blockTypePublicKey:
		keyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return err
		}
		if err := castPublicKeyToEncryptKey(keyInterface, encryptkey); err != nil {
			return err
		}
	default:
		return fmt.Errorf("invalid public key type : %s", block.Type)
	}
	return nil
}

// DecodeAuthorizedKey decodes authorizedkey to entity struct
func DecodeAuthorizedKey(input []byte, encryptkey *entity.EncryptKey) error {
	pkey, _, _, _, err := ssh.ParseAuthorizedKey(input)
	if err != nil {
		return err
	}
	if pkey, ok := pkey.(ssh.CryptoPublicKey); ok {
		return castPublicKeyToEncryptKey(pkey.CryptoPublicKey(), encryptkey)
	}
	return errors.New("not RSA / ECDSA / ED25519 public key")
}

// EncodePrivateKey decodes private key to bytes
func EncodePrivateKey(encryptkey *entity.EncryptKey) ([]byte, error) {
	switch encryptkey.Keytype {
	case entity.EncryptTypeRSA:
		return EncodeRsaPrivateKeyPKCS1(encryptkey.RsaKey.PrivateKey), nil
	case entity.EncryptTypeECDSA:
		return EncodeEcdsaPrivateKey(encryptkey.EcdsaKey.PrivateKey)
	case entity.EncryptTypeED25519:
		return EncodeEd25519PrivateKey(encryptkey.Ed25519Key.PrivateKey), nil
	default:
		return nil, errors.New("No encryptkey KeyType")
	}
}

// EncodeRsaPrivateKeyPKCS1 encodes PKCS1 private key to bytes
func EncodeRsaPrivateKeyPKCS1(prikey *rsa.PrivateKey) []byte {
	prikeybytes := x509.MarshalPKCS1PrivateKey(prikey)
	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  blockTypeRsaPrivateKey,
			Bytes: prikeybytes,
		},
	)
	return pemdata
}

// EncodeRsaPrivateKeyPKCS8 encodes PKCS8 private key to bytes
func EncodeRsaPrivateKeyPKCS8(prikey *rsa.PrivateKey) ([]byte, error) {
	prikeybytes, err := x509.MarshalPKCS8PrivateKey(prikey)
	if err != nil {
		return nil, err
	}
	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  blockTypePrivateKey,
			Bytes: prikeybytes,
		},
	)
	return pemdata, nil
}

// EncodeEcdsaPrivateKey encodes ECDSA private key to bytes
func EncodeEcdsaPrivateKey(prikey *ecdsa.PrivateKey) ([]byte, error) {
	prikeybytes, err := x509.MarshalECPrivateKey(prikey)
	if err != nil {
		return nil, err
	}
	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  blockTypeEcdsaPrivateKey,
			Bytes: prikeybytes,
		},
	)
	return pemdata, nil
}

// EncodeEd25519PrivateKey encodes ED25519 private key to bytes
func EncodeEd25519PrivateKey(prikey *ed25519.PrivateKey) []byte {
	prikeybytes := MarshalED25519PrivateKey(prikey)
	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  blockTypeOpenSSHPrivateKey,
			Bytes: prikeybytes,
		},
	)
	return pemdata
}

// EncodePublicKey encodes public key to bytes
func EncodePublicKey(encryptkey *entity.EncryptKey) ([]byte, error) {
	switch encryptkey.Keytype {
	case entity.EncryptTypeRSA:
		return EncodeRsaPublicKey(encryptkey.RsaKey.PublicKey)
	case entity.EncryptTypeECDSA:
		return EncodeEcdsaPublicKey(encryptkey.EcdsaKey.PublicKey)
	case entity.EncryptTypeED25519:
		return EncodeED25519PublicKey(encryptkey.Ed25519Key.PublicKey)
	default:
		return nil, errors.New("No encryptkey KeyType")
	}
}

// EncodeRsaPublicKey encodes public key to bytes
func EncodeRsaPublicKey(pubkey *rsa.PublicKey) ([]byte, error) {
	prikeybytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return nil, err
	}
	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  blockTypePublicKey,
			Bytes: prikeybytes,
		},
	)
	return pemdata, nil
}

// EncodeEcdsaPublicKey encodes public key to bytes
func EncodeEcdsaPublicKey(pubkey *ecdsa.PublicKey) ([]byte, error) {
	prikeybytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return nil, err
	}
	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  blockTypeEcdsaPublicKey,
			Bytes: prikeybytes,
		},
	)
	return pemdata, nil
}

// EncodeED25519PublicKey encodes public key to bytes
func EncodeED25519PublicKey(pubkey *ed25519.PublicKey) ([]byte, error) {
	prikeybytes, err := x509.MarshalPKIXPublicKey(*pubkey)
	if err != nil {
		return nil, err
	}
	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  blockTypeOpenSSHPublicKey,
			Bytes: prikeybytes,
		},
	)
	return pemdata, nil
}

func castPrivateKeyToEncryptKey(keyInterface interface{}, encryptkey *entity.EncryptKey) error {
	switch priv := keyInterface.(type) {
	case *rsa.PrivateKey:
		priv.Precompute()
		encryptkey.RsaKey.PrivateKey = priv
		encryptkey.Keytype = entity.EncryptTypeRSA
		return nil
	case *ecdsa.PrivateKey:
		encryptkey.EcdsaKey.PrivateKey = priv
		encryptkey.Keytype = entity.EncryptTypeECDSA
		return nil
	case *ed25519.PrivateKey:
		encryptkey.Ed25519Key.PrivateKey = priv
		encryptkey.Keytype = entity.EncryptTypeED25519
		return nil
	case ed25519.PrivateKey:
		encryptkey.Ed25519Key.PrivateKey = &priv
		encryptkey.Keytype = entity.EncryptTypeED25519
		return nil
	default:
		return errors.New("not RSA / ECDSA / ED25519 private key")
	}
}

func castPublicKeyToEncryptKey(keyInterface interface{}, encryptkey *entity.EncryptKey) error {
	switch priv := keyInterface.(type) {
	case *rsa.PublicKey:
		encryptkey.RsaKey.PublicKey = priv
		encryptkey.Keytype = entity.EncryptTypeRSA
		return nil
	case *ecdsa.PublicKey:
		encryptkey.EcdsaKey.PublicKey = priv
		encryptkey.Keytype = entity.EncryptTypeECDSA
		return nil
	case *ed25519.PublicKey:
		encryptkey.Ed25519Key.PublicKey = priv
		encryptkey.Keytype = entity.EncryptTypeED25519
		return nil
	case ed25519.PublicKey:
		encryptkey.Ed25519Key.PublicKey = &priv
		encryptkey.Keytype = entity.EncryptTypeED25519
		return nil
	default:
		return errors.New("not RSA / ECDSA / ED25519 public key")
	}
}

// MarshalED25519PrivateKey marshal ED25519 privatekey to bytes
func MarshalED25519PrivateKey(key *ed25519.PrivateKey) []byte {
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
	pk1.Priv = []byte(*(*[]byte)(unsafe.Pointer(key)))
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
