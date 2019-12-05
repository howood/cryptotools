package parser

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/howood/cryptotools/internal/entity"
)

const (
	blockTypeRsaPrivateKey   = "RSA PRIVATE KEY"
	blockTypeEcdsaPrivateKey = "EC PRIVATE KEY"
	blockTypePrivateKey      = "PRIVATE KEY"
	blockTypeRsaPublicKey    = "RSA PUBLIC KEY"
	blockTypeEcdsaPublicKey  = "EC PUBLIC KEY"
	blockTypePublicKey       = "PUBLIC KEY"
)

// DecodePrivateKey reads private to entity struct
func DecodePrivateKey(bytedata []byte, encryptkey *entity.EncryptKey) error {
	block, _ := pem.Decode(bytedata)
	if block == nil {
		return errors.New("failed to decode private key data")
	}
	var err error
	switch block.Type {
	case blockTypeRsaPrivateKey:
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return err
		}
		key.Precompute()
		encryptkey.RsaKey.PrivateKey = key
		encryptkey.Keytype = entity.EncriptTypeRsa
	case blockTypeEcdsaPrivateKey:
		encryptkey.EcdsaKey.PrivateKey, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return err
		}
		encryptkey.Keytype = entity.EncriptTypeECDSA
	case blockTypePrivateKey:
		keyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return err
		}
		key, ok := keyInterface.(*rsa.PrivateKey)
		if !ok {
			return errors.New("not RSA private key")
		}
		key.Precompute()
		encryptkey.RsaKey.PrivateKey = key
		encryptkey.Keytype = entity.EncriptTypeRsa
	default:
		return fmt.Errorf("invalid private key type : %s", block.Type)
	}
	return nil
}

// DecodePublicKey reads publickey to entity struct
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
		encryptkey.Keytype = entity.EncriptTypeRsa
	case blockTypeEcdsaPublicKey:
		keyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return err
		}
		var ok bool
		if encryptkey.EcdsaKey.PublicKey, ok = keyInterface.(*ecdsa.PublicKey); !ok {
			return errors.New("not ECDSA public key")
		}
		encryptkey.Keytype = entity.EncriptTypeECDSA
	case blockTypePublicKey:
		keyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return err
		}
		var ok bool
		if encryptkey.RsaKey.PublicKey, ok = keyInterface.(*rsa.PublicKey); !ok {
			return errors.New("not RSA public key")
		}
		encryptkey.Keytype = entity.EncriptTypeRsa
	default:
		return fmt.Errorf("invalid public key type : %s", block.Type)
	}
	return nil
}

// EncodeRsaPrivateKeyPKCS1 decodes PKCS1 private key to bytes
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

// EncodeRsaPrivateKeyPKCS8 decodes PKCS8 private key to bytes
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

// EncodeEcdsaPrivateKey decodes ECDSA private key to bytes
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

// EncodeRsaPublicKey decodes public key to bytes
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

// EncodeEcdsaPublicKey decodes public key to bytes
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
