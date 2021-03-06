package parser

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/md5"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/howood/cryptotools/internal/entity"
	jose "gopkg.in/square/go-jose.v2"
)

// ConvertToJSONWebKey convert to JWK
func ConvertToJSONWebKey(input []byte) (jose.JSONWebKey, error) {
	var jwk jose.JSONWebKey
	err := jwk.UnmarshalJSON(input)
	return jwk, err
}

// GenerateJSONWebKeyWithEncryptPrivateKey convert  privatekey to JWK
func GenerateJSONWebKeyWithEncryptPrivateKey(encryptkey *entity.EncryptKey, kid string) ([]byte, error) {
	switch encryptkey.Keytype {
	case entity.EncryptTypeRSA:
		return GenerateJSONWebKeyWithRSAPrivateKey(encryptkey.RsaKey.PrivateKey, kid)
	case entity.EncryptTypeECDSA:
		return GenerateJSONWebKeyWithEcdsaPrivateKey(encryptkey.EcdsaKey.PrivateKey, kid)
	default:
		return nil, errors.New("No encryptkey KeyType")
	}
}

// GenerateJSONWebKeyWithRSAPrivateKey convert rsa privatekey to JWK
func GenerateJSONWebKeyWithRSAPrivateKey(privatekey *rsa.PrivateKey, kid string) ([]byte, error) {
	jwk := jose.JSONWebKey{
		KeyID: kid,
		Key:   privatekey,
	}
	return jwk.MarshalJSON()
}

// GenerateJSONWebKeyWithEcdsaPrivateKey convert ecdsa privatekey to JWK
func GenerateJSONWebKeyWithEcdsaPrivateKey(privatekey *ecdsa.PrivateKey, kid string) ([]byte, error) {
	jwk := jose.JSONWebKey{
		KeyID: kid,
		Key:   privatekey,
	}
	return jwk.MarshalJSON()
}

// GenerateJSONWebKeyWithEncryptPublicKey convert  publickey to JWK
func GenerateJSONWebKeyWithEncryptPublicKey(encryptkey *entity.EncryptKey, kid string) ([]byte, error) {
	switch encryptkey.Keytype {
	case entity.EncryptTypeRSA:
		return GenerateJSONWebKeyWithRSAPublicKey(encryptkey.RsaKey.PublicKey, kid)
	case entity.EncryptTypeECDSA:
		return GenerateJSONWebKeyWithEcdsaPublicKey(encryptkey.EcdsaKey.PublicKey, kid)
	default:
		return nil, errors.New("No encryptkey KeyType")
	}
}

// GenerateJSONWebKeyWithRSAPublicKey convert rsa publickey to JWK
func GenerateJSONWebKeyWithRSAPublicKey(publickey *rsa.PublicKey, kid string) ([]byte, error) {
	jwk := jose.JSONWebKey{
		KeyID:     kid,
		Key:       publickey,
		Algorithm: getPublickeyAlgorithm(publickey),
	}
	return jwk.MarshalJSON()
}

// GenerateJSONWebKeyWithEcdsaPublicKey convert ecdsa publickey to JWK
func GenerateJSONWebKeyWithEcdsaPublicKey(publickey *ecdsa.PublicKey, kid string) ([]byte, error) {
	jwk := jose.JSONWebKey{
		KeyID:     kid,
		Key:       publickey,
		Algorithm: getPublickeyAlgorithm(publickey),
	}
	return jwk.MarshalJSON()
}

// ConvertToRSAPublicFromJWK convert to RSA public key from JWK
func ConvertToRSAPublicFromJWK(key *jose.JSONWebKey) (*rsa.PublicKey, error) {
	res, ok := key.Key.(*rsa.PublicKey)
	if !ok {
		return res, errors.New("Could not convert key to RSA Public Key")
	}
	return res, nil
}

// ConvertToRSAPrivateFromJWK convert to RSA private key from JWK
func ConvertToRSAPrivateFromJWK(key *jose.JSONWebKey) (*rsa.PrivateKey, error) {
	res, ok := key.Key.(*rsa.PrivateKey)
	if !ok {
		return res, errors.New("Could not convert key to RSA Private Key")
	}
	return res, nil
}

// ConvertToEcdsaPublicFromJWK convert to ECDSA public key from JWK
func ConvertToEcdsaPublicFromJWK(key *jose.JSONWebKey) (*ecdsa.PublicKey, error) {
	res, ok := key.Key.(*ecdsa.PublicKey)
	if !ok {
		return res, errors.New("Could not convert key to Ecdsa Public Key")
	}
	return res, nil
}

// GenerateHashFromCrptoKey generates Hash from private / public key
func GenerateHashFromCrptoKey(key interface{}) string {
	hasher := md5.New()
	hasher.Write([]byte(fmt.Sprintf("%v", key)))
	return hex.EncodeToString(hasher.Sum(nil))
}

func getPublickeyAlgorithm(pub crypto.PublicKey) string {
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return "RS256"
	case *ecdsa.PublicKey:
		switch pub.Params().Name {
		case "P-256":
			return "ES256"
		case "P-384":
			return "ES384"
		case "P-521":
			return "ES512"
		}
	}
	return ""
}
