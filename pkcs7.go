package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

type crypto struct {
	content []byte
	cipherText []byte
}

var (
	ErrInvalidBlockSize = errors.New("pkcs7: block size must be between 1 and 255 inclusive")
	ErrEmptySlice       = errors.New("pkcs7: source must not be empty slice")
	ErrInvalidPadding   = errors.New("pkcs7: invalid padding")
)

func (p7 *crypto) Padding(content[]byte, blockSize int) error {
	if 1 > blockSize || 255 < blockSize {
		return ErrInvalidBlockSize
	}

	padLen := blockSize - len(content) % blockSize

	padding := []byte{byte(padLen)}
	padding = bytes.Repeat(padding, padLen)

	p7.content = append(content, padding...)

	return nil
}

func (p7 *crypto) unPadding()  {
	length := len(p7.content)
	unPad := int(p7.content[length - 1])
	p7.content = p7.content[:(length - unPad)]
}

//aes加密，填充秘钥key的16位，24,32分别对应AES-128, AES-192, or AES-256.
func (p7 *crypto) Encrypt(content []byte, key []byte) error  {
	block, err := aes.NewCipher(key)

	if err!=nil {
		return err
	}

	blockSize := block.BlockSize()

	err = p7.Padding(content, blockSize)

	if err != nil {
		return err
	}

	iv := "1234567890123456"

	mode := cipher.NewCBCEncrypter(block, []byte(iv))

	out := make([]byte, len(p7.content))
	mode.CryptBlocks(out, p7.content)
	p7.cipherText = out
	return nil
}

func (p7 *crypto) Decrypt(content []byte, key []byte) error {
	p7.cipherText = content

	block, err := aes.NewCipher(key)

	if err !=  nil {
		return err
	}

	iv := "1234567890123456"

	mode := cipher.NewCBCDecrypter(block, []byte(iv))

	p7.content = make([]byte, len(p7.cipherText))
	mode.CryptBlocks(p7.content, p7.cipherText)

	p7.unPadding()
	return nil
}
