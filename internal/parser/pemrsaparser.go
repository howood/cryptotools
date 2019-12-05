package parser

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/howood/cryptotools/internal/entity"
)

const (
	blockTypeRsaPrivateKey = "RSA PRIVATE KEY"
	blockTypePrivateKey    = "PRIVATE KEY"
	blockTypeRsaPublicKey  = "RSA PUBLIC KEY"
	blockTypePublicKey     = "PUBLIC KEY"
)

// DecodeRsaPrivateKey reads private to entity struct
func DecodeRsaPrivateKey(bytedata []byte, rsakey *entity.RsaKey) error {
	block, _ := pem.Decode(bytedata)
	if block == nil {
		return errors.New("failed to decode private key data")
	}
	var key *rsa.PrivateKey
	var err error
	switch block.Type {
	case blockTypeRsaPrivateKey:
		if key, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
			return err
		}
	case blockTypePrivateKey:
		keyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return err
		}
		var ok bool
		if key, ok = keyInterface.(*rsa.PrivateKey); !ok {
			return errors.New("not RSA private key")
		}
	default:
		return fmt.Errorf("invalid private key type : %s", block.Type)
	}
	key.Precompute()
	rsakey.PrivateKey = key
	return nil
}

// DecodeRsaPublicKey reads publickey to entity struct
func DecodeRsaPublicKey(bytedata []byte, rsakey *entity.RsaKey) error {
	block, _ := pem.Decode(bytedata)
	if block == nil {
		return errors.New("failed to decode PEM block containing public key")
	}
	var key *rsa.PublicKey
	var err error
	switch block.Type {
	case blockTypeRsaPublicKey:
		if key, err = x509.ParsePKCS1PublicKey(block.Bytes); err != nil {
			return err
		}
	case blockTypePublicKey:
		keyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return err
		}
		var ok bool
		if key, ok = keyInterface.(*rsa.PublicKey); !ok {
			return errors.New("not RSA public key")
		}
	default:
		return fmt.Errorf("invalid public key type : %s", block.Type)
	}
	rsakey.PublicKey = key
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
