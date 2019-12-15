package encrypter

import (
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"errors"

	"github.com/howood/cryptotools/internal/entity"
)

// CryptoEcdsa represents Ecdsa encryption struct
type CryptoEcdsa struct {
	ecdsakey *entity.EcdsaKey
}

// NewCryptoEcdsa create CryptoEcdsa struct
func NewCryptoEcdsa(ecdsakey *entity.EcdsaKey) *CryptoEcdsa {
	return &CryptoEcdsa{
		ecdsakey: ecdsakey,
	}
}

// Encrypt encrypts a input data
func (ce *CryptoEcdsa) Encrypt(input []byte) ([]byte, error) {
	ephemeral, err := ecdsa.GenerateKey(ce.ecdsakey.PublicKey.Curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	x, _ := ce.ecdsakey.PublicKey.Curve.ScalarMult(ce.ecdsakey.PublicKey.X, ce.ecdsakey.PublicKey.Y, ephemeral.D.Bytes())
	if x == nil {
		return nil, errors.New("fail to generate encryptionkey")
	}
	shared := sha256.Sum256(x.Bytes())
	iv, err := makeRandomData(16)
	if err != nil {
		return nil, err
	}

	paddedIn := addPaddingBlock(input)
	ct, err := encryptCBC(paddedIn, iv, shared[:16])
	if err != nil {
		return nil, err
	}

	ephPub := elliptic.Marshal(ce.ecdsakey.PublicKey.Curve, ephemeral.PublicKey.X, ephemeral.PublicKey.Y)
	out := make([]byte, 1+len(ephPub)+16)
	out[0] = byte(len(ephPub))
	copy(out[1:], ephPub)
	copy(out[1+len(ephPub):], iv)
	out = append(out, ct...)

	h := hmac.New(sha1.New, shared[16:])
	h.Write(iv)
	h.Write(ct)
	out = h.Sum(out)
	return out, nil
}

// Decrypt decrypts a input data
func (ce *CryptoEcdsa) Decrypt(input []byte) ([]byte, error) {
	ephLen := int(input[0])
	ephPub := input[1 : 1+ephLen]
	ct := input[1+ephLen:]
	if len(ct) < (sha1.Size + aes.BlockSize) {
		return nil, errors.New("Invalid inputdata")
	}

	x, y := elliptic.Unmarshal(ce.ecdsakey.PrivateKey.Curve, ephPub)
	ok := ce.ecdsakey.PrivateKey.Curve.IsOnCurve(x, y)
	if x == nil || !ok {
		return nil, errors.New("Invalid Key curve")
	}

	x, _ = ce.ecdsakey.PrivateKey.Curve.ScalarMult(x, y, ce.ecdsakey.PrivateKey.D.Bytes())
	if x == nil {
		return nil, errors.New("Failed to generate encryptionkey")
	}
	shared := sha256.Sum256(x.Bytes())

	tagStart := len(ct) - sha1.Size
	h := hmac.New(sha1.New, shared[16:])
	h.Write(ct[:tagStart])
	mac := h.Sum(nil)
	if !hmac.Equal(mac, ct[tagStart:]) {
		return nil, errors.New("Invalid MAC")
	}

	paddedOut, err := decryptCBC(ct[aes.BlockSize:tagStart], ct[:aes.BlockSize], shared[:16])
	if err != nil {
		return nil, err
	}
	return removePaddingBlock(paddedOut)
}

// EncryptWithBase64 encrypts a input data to base64 string
func (ce *CryptoEcdsa) EncryptWithBase64(input []byte) (string, error) {
	ciphertext, err := ce.Encrypt(input)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptWithBase64 decrypts a input data to base64 string
func (ce *CryptoEcdsa) DecryptWithBase64(input string) ([]byte, error) {
	inputdecoded, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return nil, err
	}
	return ce.Decrypt(inputdecoded)
}
