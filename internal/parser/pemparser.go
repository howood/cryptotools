package parser

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/ScaleFT/sshkeys"
	"golang.org/x/crypto/ssh"

	"github.com/howood/cryptotools/internal/entity"
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
		return EncodeEd25519PrivateKey(encryptkey.Ed25519Key.PrivateKey)
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
func EncodeEd25519PrivateKey(prikey ed25519.PrivateKey) ([]byte, error) {
	prikeybytes, err := x509.MarshalPKCS8PrivateKey(prikey)
	if err != nil {
		return nil, err
	}
	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  blockTypeOpenSSHPrivateKey,
			Bytes: prikeybytes,
		},
	)
	return pemdata, nil
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
func EncodeED25519PublicKey(pubkey ed25519.PublicKey) ([]byte, error) {
	prikeybytes, err := x509.MarshalPKIXPublicKey(pubkey)
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
	case ed25519.PrivateKey:
		encryptkey.Ed25519Key.PrivateKey = priv
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
	case ed25519.PublicKey:
		encryptkey.Ed25519Key.PublicKey = priv
		encryptkey.Keytype = entity.EncryptTypeED25519
		return nil
	default:
		return errors.New("not RSA / ECDSA / ED25519 public key")
	}
}
