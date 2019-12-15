package encrypter

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

// removePaddingBlock removes padding from data that was added with
func removePaddingBlock(b []byte) ([]byte, error) {
	l := int(b[len(b)-1])
	if l > 16 {
		return nil, errors.New("Padding incorrect")
	}

	return b[:len(b)-l], nil
}

// addPaddingBlock adds padding to a block of data
func addPaddingBlock(b []byte) []byte {
	l := 16 - len(b)%16
	padding := make([]byte, l)
	padding[l-1] = byte(l)
	return append(b, padding...)
}

// DecryptCBC decrypt with AES in CBC mode.
func decryptCBC(data, iv, key []byte) (decryptedData []byte, err error) {
	aesCrypt, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	ivBytes := append([]byte{}, iv...)

	decryptedData = make([]byte, len(data))
	aesCBC := cipher.NewCBCDecrypter(aesCrypt, ivBytes)
	aesCBC.CryptBlocks(decryptedData, data)

	return
}

// EncryptCBC encrypt with AES in CBC mode.
func encryptCBC(data, iv, key []byte) (encryptedData []byte, err error) {
	aesCrypt, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	ivBytes := append([]byte{}, iv...)

	encryptedData = make([]byte, len(data))
	aesCBC := cipher.NewCBCEncrypter(aesCrypt, ivBytes)
	aesCBC.CryptBlocks(encryptedData, data)

	return
}

// MakeRandom makes random data.
func makeRandomData(length int) ([]byte, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	return bytes, err
}
