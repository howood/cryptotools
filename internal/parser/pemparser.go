package parser

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/ScaleFT/sshkeys"

	"github.com/howood/cryptotools/internal/entity"
)

const (
	blockTypeRsaPrivateKey   = "RSA PRIVATE KEY"
	blockTypeEcdsaPrivateKey = "EC PRIVATE KEY"
	blockTypeOpenPrivateKey  = "OPEN PRIVATE KEY"
	blockTypePrivateKey      = "PRIVATE KEY"
	blockTypeRsaPublicKey    = "RSA PUBLIC KEY"
	blockTypeEcdsaPublicKey  = "EC PUBLIC KEY"
	blockTypeOpenPublicKey   = "OPEN PUBLIC KEY"
	blockTypePublicKey       = "PUBLIC KEY"
)

// DecodePrivateKey reads private to entity struct
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
	case blockTypeOpenPrivateKey:
		keyInterface, err := sshkeys.ParseEncryptedRawPrivateKey(block.Bytes, nil)
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
		encryptkey.Keytype = entity.EncryptTypeRSA
	case blockTypeEcdsaPublicKey:
		keyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return err
		}
		if err := castPublicKeyToEncryptKey(keyInterface, encryptkey); err != nil {
			return err
		}
	/*
		case blockTypeOpenPublicKey:
			keyInterface, err := sshkeys.ParseEncryptedRawPrivateKey(block.Bytes, nil)
			if err != nil {
				return err
			}
			if err := castPublicKeyToEncryptKey(keyInterface, encryptkey); err != nil {
				return err
			}
	*/
	case blockTypePublicKey:
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

func castPrivateKeyToEncryptKey(keyInterface interface{}, encryptkey *entity.EncryptKey) error {
	switch priv := keyInterface.(type) {
	case *ecdsa.PrivateKey:
		encryptkey.EcdsaKey.PrivateKey = priv
		encryptkey.Keytype = entity.EncryptTypeECDSA
		return nil
	case *rsa.PrivateKey:
		priv.Precompute()
		encryptkey.RsaKey.PrivateKey = priv
		encryptkey.Keytype = entity.EncryptTypeRSA
		return nil
	default:
		return errors.New("not RSA / ECDSA private key")
	}
}

func castPublicKeyToEncryptKey(keyInterface interface{}, encryptkey *entity.EncryptKey) error {
	switch priv := keyInterface.(type) {
	case *ecdsa.PublicKey:
		encryptkey.EcdsaKey.PublicKey = priv
		encryptkey.Keytype = entity.EncryptTypeECDSA
		return nil
	case *rsa.PublicKey:
		encryptkey.RsaKey.PublicKey = priv
		encryptkey.Keytype = entity.EncryptTypeRSA
		return nil
	default:
		return errors.New("not RSA / ECDSA private key")
	}
}
