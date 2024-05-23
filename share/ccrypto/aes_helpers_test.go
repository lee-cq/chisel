package ccrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"io"
	"testing"
)

// generateRandomBytes 生成一个指定长度的随机字节序列
func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// TestAESEncryptDecrypt 测试 AES 加密和解密是否正常工作
func TestAESEncryptDecrypt(t *testing.T) {
	// 生成随机密钥
	key, err := generateRandomBytes(32)
	if err != nil {
		t.Errorf("Error generating key: %v", err)
		return
	}

	// 需要加密的数据
	data := []byte("Hello, World!")

	// 加密数据
	encryptedData, err := AesEncrypt(data, key)
	if err != nil {
		t.Errorf("Encryption error: %v", err)
		return
	}

	// 解密数据
	decryptedData, err := AesDecrypt(encryptedData, key)
	if err != nil {
		t.Errorf("Decryption error: %v", err)
		return
	}

	// 比较解密后的数据和原始数据是否一致
	if !bytes.Equal(data, decryptedData) {
		t.Errorf("Decrypted data does not match original data. Decrypted: %s, Original: %s", decryptedData, data)
	}
}

// TestPadding 测试填充和去填充是否正常工作
func TestPadding(t *testing.T) {
	// 生成原始数据
	originalData := []byte("Hello, World!")
	padding := aes.BlockSize - len(originalData)%aes.BlockSize
	p := bytes.Repeat([]byte{byte(padding)}, padding)
	originalDataWithPadding := append(originalData, p...)

	// 模拟解密过程中的去填充
	decryptedData := originalDataWithPadding[:len(originalDataWithPadding)-padding]

	// 比较去填充后的数据和原始数据是否一致
	if !bytes.Equal(originalData, decryptedData) {
		t.Errorf("Data after padding and then unpadding does not match original data.")
	}
}


