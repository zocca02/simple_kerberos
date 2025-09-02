package security

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	config "simple_kerberos/configs"
)

func pad(src []byte, blockSize int) []byte {
	padLen := blockSize - len(src)%blockSize
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(src, padding...)
}

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
	block, err := aes.NewCipher(generateCryptKey(key, config.SymmKeyDim))
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
	block, err := aes.NewCipher(generateCryptKey(key, config.SymmKeyDim))
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

// in this case salt is an example, but also kerberos calculate it in a deterministic way
func GenerateClientKeyFromPwd(pwd string, keyDim int) ([]byte, error) {
	return pbkdf2.Key(sha256.New, pwd, []byte("salt"), 4096, keyDim/8)
}

func MacData(data []byte, key []byte) []byte {
	mac := hmac.New(sha256.New, generateMacKey(key, config.SymmKeyDim))
	mac.Write(data)
	return mac.Sum(nil)
}

func generateMacKey(key []byte, keyDim int) []byte {
	sha := sha256.New()
	sha.Write(key)
	sha.Write([]byte("macKey"))
	return sha.Sum(nil)[:keyDim/8]
}

func generateCryptKey(key []byte, keyDim int) []byte {
	sha := sha256.New()
	sha.Write(key)
	sha.Write([]byte("cryptKey"))
	return sha.Sum(nil)[:keyDim/8]
}
