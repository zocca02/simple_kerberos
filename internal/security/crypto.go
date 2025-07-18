package security

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// Padding PKCS#7 (mandatory for CBC)
// Chat-GPT
func pad(src []byte, blockSize int) []byte {
	padLen := blockSize - len(src)%blockSize
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(src, padding...)
}

// Padding PKCS#7 (mandatory for CBC)
// Chat-GPT
func unpad(src []byte) ([]byte, error) {
	length := len(src)
	if length == 0 {
		return nil, fmt.Errorf("empty ciphertext")
	}
	padLen := int(src[length-1])
	if padLen > length || padLen == 0 {
		return nil, fmt.Errorf("invalid padding")
	}
	return src[:length-padLen], nil
}

func GenerateRandomKey(keyDim int) []byte {
	key := make([]byte, keyDim/8)
	_, err := io.ReadFull(rand.Reader, key)

	if err != nil {
		return nil
	}

	return key
}

func SymmetricEncryption(plaintext []byte, key []byte) ([]byte, error) {
	//INIT AES ALGORITHM
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	//GENARATE IV
	iv := make([]byte, aes.BlockSize)
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		return nil, err
	}

	//INIT CBC MODE
	cbc := cipher.NewCBCEncrypter(block, iv)

	//ADD PADDING
	plaintext = pad(plaintext, aes.BlockSize)

	//ENCRYPT
	ciphertext := make([]byte, len(plaintext))
	cbc.CryptBlocks(ciphertext, plaintext)
	ciphertext = append(iv, ciphertext...)
	return ciphertext, nil
}

func SymmetricDecryption(ciphertext []byte, key []byte) ([]byte, error) {
	//INIT AES ALGORITHM
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	//RETRIVE IV
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of block size")
	}

	//INIT CBC MODE
	cbc := cipher.NewCBCDecrypter(block, iv)

	//DECRYPT
	plaintext := make([]byte, len(ciphertext))
	cbc.CryptBlocks(plaintext, ciphertext)

	//REMOVE PADDING
	plaintext, err = unpad(plaintext)

	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
