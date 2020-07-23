package encrypter

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"unsafe"

	"github.com/howood/cryptotools/internal/encrypter/edwards25519"
	"github.com/howood/cryptotools/internal/entity"
	"golang.org/x/crypto/curve25519"
)

// CryptoEd25519 represents ED25519 encryption struct
type CryptoEd25519 struct {
	ed25519key *entity.Ed25519Key
}

// NewCryptoEd25519 create CryptoEd25519 struct
func NewCryptoEd25519(ed25519key *entity.Ed25519Key) *CryptoEd25519 {
	return &CryptoEd25519{
		ed25519key: ed25519key,
	}
}

// Encrypt encrypts a input data
func (ce *CryptoEd25519) Encrypt(input []byte) ([]byte, error) {
	publickey, err := ce.publicKeyToCurve25519()
	if err != nil {
		return nil, err
	}
	var r, R, S, KB [32]byte

	if _, err := rand.Read(r[:]); err != nil {
		return nil, err
	}
	r[0] &= 248
	r[31] &= 127
	r[31] |= 64

	copy(KB[:], publickey)

	curve25519.ScalarBaseMult(&R, &r)
	curve25519.ScalarMult(&S, &r, &KB)
	kE := sha512.Sum512(S[:])

	srclen := len(input)
	if srclen > 64 {
		return nil, errors.New("source data is exceed 64 bytes")
	}
	encryptData := make([]byte, 32+srclen)
	copy(encryptData[:32], R[:])
	for i := 0; i < srclen; i++ {
		encryptData[32+i] = input[i] ^ kE[i]
	}

	return encryptData, nil
}

// Decrypt decrypts a input data
func (ce *CryptoEd25519) Decrypt(input []byte) ([]byte, error) {
	privatekey := ce.privateKeyToCurve25519()

	var R, S, kB [32]byte
	copy(R[:], input[:32])
	copy(kB[:], privatekey)

	curve25519.ScalarMult(&S, &kB, &R)

	kE := sha512.Sum512(S[:])

	decryptData := make([]byte, len(input)-32)
	for i := 0; i < len(decryptData); i++ {
		decryptData[i] = input[32+i] ^ kE[i]
	}

	return decryptData, nil
}

// EncryptWithBase64 encrypts a input data to base64 string
func (ce *CryptoEd25519) EncryptWithBase64(input []byte) (string, error) {
	ciphertext, err := ce.Encrypt(input)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptWithBase64 decrypts a input data to base64 string
func (ce *CryptoEd25519) DecryptWithBase64(input string) ([]byte, error) {
	inputdecoded, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return nil, err
	}
	return ce.Decrypt(inputdecoded)
}

func (ce *CryptoEd25519) privateKeyToCurve25519() []byte {
	var curve25519Private [32]byte
	h := sha512.New()
	privatekey := *(*[]byte)(unsafe.Pointer(ce.ed25519key.PrivateKey))
	h.Write(privatekey[:32])
	digest := h.Sum(nil)

	digest[0] &= 248
	digest[31] &= 127
	digest[31] |= 64

	copy(curve25519Private[:], digest)
	return curve25519Private[:]
}

func (ce *CryptoEd25519) publicKeyToCurve25519() ([]byte, error) {
	var curve25519Public, publickeyBytes [32]byte
	var A edwards25519.ExtendedGroupElement
	pubkey := *(*[]byte)(unsafe.Pointer(ce.ed25519key.PublicKey))
	copy(publickeyBytes[:], pubkey)
	if !A.FromBytes(&publickeyBytes) {
		return nil, errors.New("cannot convert to Curve25519 publickey")
	}

	// A.Z = 1 as a postcondition of FromBytes.
	var x edwards25519.FieldElement
	ce.edwardsToMontgomeryX(&x, &A.Y)
	edwards25519.FeToBytes(&curve25519Public, &x)
	return curve25519Public[:], nil
}

func (ce *CryptoEd25519) edwardsToMontgomeryX(outX, y *edwards25519.FieldElement) {
	// We only need the x-coordinate of the curve25519 point, which I'll
	// call u. The isomorphism is u=(y+1)/(1-y), since y=Y/Z, this gives
	// u=(Y+Z)/(Z-Y). We know that Z=1, thus u=(Y+1)/(1-Y).
	var oneMinusY edwards25519.FieldElement
	edwards25519.FeOne(&oneMinusY)
	edwards25519.FeSub(&oneMinusY, &oneMinusY, y)
	edwards25519.FeInvert(&oneMinusY, &oneMinusY)

	edwards25519.FeOne(outX)
	edwards25519.FeAdd(outX, outX, y)

	edwards25519.FeMul(outX, outX, &oneMinusY)
}
