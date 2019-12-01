package parser

import (
	"crypto/rsa"
	"errors"
	jose "gopkg.in/square/go-jose.v2"
)

// ConvertToJSONWebKey convert to JWK
func ConvertToJSONWebKey(input []byte) (jose.JSONWebKey, error) {
	var jwk jose.JSONWebKey
	err := jwk.UnmarshalJSON(input)
	return jwk, err
}

// ConvertToRSAPublicFromJWK convert to RSA public key from JWK
func ConvertToRSAPublicFromJWK(key *jose.JSONWebKey) (*rsa.PublicKey, error) {
	res, ok := key.Key.(*rsa.PublicKey)
	if !ok {
		return res, errors.New("Could not convert key to RSA Private Key")
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
