// cipher_test.go
package fastchacha20

import (
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	cipher, err := NewCipher(key)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}

	nonce := make([]byte, cipher.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("Failed to generate nonce: %v", err)
	}

	plaintext := []byte("The quick brown fox jumps over the lazy dog")
	additionalData := []byte("Additional authenticated data")

	ciphertext, err := cipher.Encrypt(nonce, plaintext, additionalData)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decryptedText, err := cipher.Decrypt(nonce, ciphertext, additionalData)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if string(decryptedText) != string(plaintext) {
		t.Errorf("Decrypted text does not match original plaintext.\nExpected: %s\nGot: %s", plaintext, decryptedText)
	}
}

func TestDecryptWithWrongKey(t *testing.T) {
	key1 := make([]byte, chacha20poly1305.KeySize)
	key2 := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key1); err != nil {
		t.Fatalf("Failed to generate key1: %v", err)
	}
	if _, err := rand.Read(key2); err != nil {
		t.Fatalf("Failed to generate key2: %v", err)
	}

	cipher1, err := NewCipher(key1)
	if err != nil {
		t.Fatalf("Failed to create cipher1: %v", err)
	}
	cipher2, err := NewCipher(key2)
	if err != nil {
		t.Fatalf("Failed to create cipher2: %v", err)
	}

	nonce := make([]byte, cipher1.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("Failed to generate nonce: %v", err)
	}

	plaintext := []byte("Confidential data")
	additionalData := []byte("AAD")

	ciphertext, err := cipher1.Encrypt(nonce, plaintext, additionalData)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Attempt to decrypt with the wrong key
	_, err = cipher2.Decrypt(nonce, ciphertext, additionalData)
	if err == nil {
		t.Error("Decryption should have failed with wrong key but succeeded")
	}
}

func TestDecryptWithWrongNonce(t *testing.T) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	cipher, err := NewCipher(key)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}

	nonce1 := make([]byte, cipher.aead.NonceSize())
	nonce2 := make([]byte, cipher.aead.NonceSize())
	if _, err := rand.Read(nonce1); err != nil {
		t.Fatalf("Failed to generate nonce1: %v", err)
	}
	if _, err := rand.Read(nonce2); err != nil {
		t.Fatalf("Failed to generate nonce2: %v", err)
	}

	plaintext := []byte("Sensitive information")
	additionalData := []byte("AAD")

	ciphertext, err := cipher.Encrypt(nonce1, plaintext, additionalData)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Attempt to decrypt with the wrong nonce
	_, err = cipher.Decrypt(nonce2, ciphertext, additionalData)
	if err == nil {
		t.Error("Decryption should have failed with wrong nonce but succeeded")
	}
}

func TestDecryptWithWrongAdditionalData(t *testing.T) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	cipher, err := NewCipher(key)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}

	nonce := make([]byte, cipher.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("Failed to generate nonce: %v", err)
	}

	plaintext := []byte("Top secret message")
	additionalData1 := []byte("Correct AAD")
	additionalData2 := []byte("Incorrect AAD")

	ciphertext, err := cipher.Encrypt(nonce, plaintext, additionalData1)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Attempt to decrypt with the wrong additional data
	_, err = cipher.Decrypt(nonce, ciphertext, additionalData2)
	if err == nil {
		t.Error("Decryption should have failed with wrong additional data but succeeded")
	}
}

func TestEncryptWithShortNonce(t *testing.T) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	cipher, err := NewCipher(key)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}

	nonce := make([]byte, cipher.aead.NonceSize()-1) // Short nonce
	plaintext := []byte("Data with short nonce")

	_, err = cipher.Encrypt(nonce, plaintext, nil)
	if err == nil {
		t.Error("Encryption should have failed with short nonce but succeeded")
	}
}
