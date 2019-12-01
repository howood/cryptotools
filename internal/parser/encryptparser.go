package parser

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/howood/cryptotools/internal/entity"
	"io/ioutil"
)

const (
	blockTypeRsaPrivateKey = "RSA PRIVATE KEY"
	blockTypePrivateKey    = "PRIVATE KEY"
	blockTypeRsaPublicKey  = "RSA PUBLIC KEY"
	blockTypePublicKey     = "PUBLIC KEY"
)

func ReadPrivateKey(filepath string, rsakey *entity.RsaKey) error {
	bytes, err := ioutil.ReadFile(filepath)
	if err != nil {
		return err
	}
	return ReadPrivateKeyFromByte(bytes, rsakey)
}

func ReadPublicKey(filepath string, rsakey *entity.RsaKey) error {
	bytes, err := ioutil.ReadFile(filepath)
	if err != nil {
		return err
	}
	return ReadPublicKeyFromByte(bytes, rsakey)
}

func ReadPrivateKeyFromByte(bytedata []byte, rsakey *entity.RsaKey) error {
	block, _ := pem.Decode(bytedata)
	if block == nil {
		return errors.New("failed to decode private key data")
	}
	var key *rsa.PrivateKey
	var err error
	switch block.Type {
	case blockTypeRsaPrivateKey:
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return err
		}
	case blockTypePrivateKey:
		keyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return err
		}
		var ok bool
		key, ok = keyInterface.(*rsa.PrivateKey)
		if !ok {
			return errors.New("not RSA private key")
		}
	default:
		return fmt.Errorf("invalid private key type : %s", block.Type)
	}
	key.Precompute()
	rsakey.PrivateKey = key
	return nil
}

func ReadPublicKeyFromByte(bytedata []byte, rsakey *entity.RsaKey) error {
	block, _ := pem.Decode(bytedata)
	if block == nil {
		return errors.New("failed to decode PEM block containing public key")
	}
	var key *rsa.PublicKey
	var err error
	switch block.Type {
	case blockTypeRsaPublicKey:
		key, err = x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return err
		}
	case blockTypePublicKey:
		keyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return err
		}
		if keyconverted, ok := keyInterface.(*rsa.PublicKey); !ok {
			return errors.New("not RSA public key")
		} else {
			key = keyconverted
		}
	default:
		return fmt.Errorf("invalid public key type : %s", block.Type)
	}
	rsakey.PublicKey = key
	return nil
}

func DecodePrivateKeyPKCS1(pubkey *rsa.PrivateKey) []byte {
	prikey_bytes := x509.MarshalPKCS1PrivateKey(pubkey)
	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  blockTypeRsaPrivateKey,
			Bytes: prikey_bytes,
		},
	)
	return pemdata
}

func DecodePrivateKeyPKCS8(pubkey *rsa.PrivateKey) ([]byte, error) {
	prikey_bytes, err := x509.MarshalPKCS8PrivateKey(pubkey)
	if err != nil {
		return nil, err
	}
	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  blockTypePrivateKey,
			Bytes: prikey_bytes,
		},
	)
	return pemdata, nil
}

func DecodePublicKey(pubkey *rsa.PublicKey) ([]byte, error) {
	pubkey_bytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return nil, err
	}
	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  blockTypePublicKey,
			Bytes: pubkey_bytes,
		},
	)
	return pemdata, nil
}
