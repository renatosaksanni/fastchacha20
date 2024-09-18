// parallel_test.go
package fastchacha20

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestEncryptDecryptChunks(t *testing.T) {
	key := make([]byte, 32) // 256-bit key
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	cipher, err := NewCipher(key)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}

	plaintext := []byte("This is a test plaintext message.")

	encryptedChunks, err := cipher.EncryptChunks(plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decryptedPlaintext, err := cipher.DecryptChunks(encryptedChunks)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !bytes.Equal(plaintext, decryptedPlaintext) {
		t.Errorf("Decrypted plaintext does not match original.\nOriginal: %s\nDecrypted: %s", plaintext, decryptedPlaintext)
	}
}

func TestEncryptDecryptEmptyPlaintext(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	cipher, err := NewCipher(key)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}

	var plaintext []byte // Empty plaintext

	encryptedChunks, err := cipher.EncryptChunks(plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decryptedPlaintext, err := cipher.DecryptChunks(encryptedChunks)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if len(decryptedPlaintext) != 0 {
		t.Errorf("Expected decrypted plaintext to be empty, got length %d", len(decryptedPlaintext))
	}
}

func TestEncryptDecryptLargePlaintext(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	cipher, err := NewCipher(key)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}

	plaintext := make([]byte, 10*1024*1024) // 10 MB plaintext
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatalf("Failed to generate plaintext: %v", err)
	}

	encryptedChunks, err := cipher.EncryptChunks(plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decryptedPlaintext, err := cipher.DecryptChunks(encryptedChunks)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !bytes.Equal(plaintext, decryptedPlaintext) {
		t.Errorf("Decrypted plaintext does not match original for large plaintext")
	}
}

func TestDecryptWithModifiedCiphertext(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	cipher, err := NewCipher(key)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}

	plaintext := []byte("Sensitive data that needs encryption.")

	encryptedChunks, err := cipher.EncryptChunks(plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Modify one byte in the ciphertext
	encryptedChunks[0][10] ^= 0xFF

	_, err = cipher.DecryptChunks(encryptedChunks)
	if err == nil {
		t.Errorf("Decryption should have failed with modified ciphertext")
	}
}

func TestInvalidKeySize(t *testing.T) {
	key := make([]byte, 16) // Invalid key size for ChaCha20-Poly1305 (requires 32 bytes)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	_, err := NewCipher(key)
	if err == nil {
		t.Errorf("Expected error for invalid key size, got nil")
	}
}
