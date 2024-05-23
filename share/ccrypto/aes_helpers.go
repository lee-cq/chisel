package ccrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// AesEncrypt 对数据进行 AES-256 加密
func AesEncrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// 填充原始数据以满足 AES 块大小要求
	padding := aes.BlockSize - len(data)%aes.BlockSize
	p := bytes.Repeat([]byte{byte(padding)}, padding)
	data = append(data, p...)

	// 初始化向量 IV 需要是唯一的，但不需要保密
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// 加密数据
	mode := cipher.NewCBCEncrypter(block, iv)
	encrypted := make([]byte, len(data))
	mode.CryptBlocks(encrypted, data)

	return append(iv, encrypted...), nil
}

// AesDecrypt 对数据进行 AES-256 解密
func AesDecrypt(cryptoText []byte, key []byte) ([]byte, error) {
	iv := cryptoText[:aes.BlockSize]
	encrypted := cryptoText[aes.BlockSize:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(encrypted))
	mode.CryptBlocks(decrypted, encrypted)

	// 移除填充
	padding := int(decrypted[len(decrypted)-1])
	if padding < 1 || padding > aes.BlockSize {
		return nil, fmt.Errorf("invalid padding")
	}
	decrypted = decrypted[:len(decrypted)-padding]

	return decrypted, nil
}
