// cipher_test.go
package fastchacha20

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func generateRandomKey(t *testing.T, size int) []byte {
	key := make([]byte, size)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}
	return key
}

func generateRandomNonce(t *testing.T, size int) []byte {
	nonce := make([]byte, size)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("Failed to generate random nonce: %v", err)
	}
	return nonce
}

func TestEncryptDecrypt(t *testing.T) {
	// Generate random key and nonce
	key := generateRandomKey(t, 32)     // 256-bit key
	nonce := generateRandomNonce(t, 24) // 192-bit nonce (for ChaCha20-Poly1305)

	cipher, err := NewCipher(key)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}

	plaintext := []byte("This is a test plaintext message.")
	aad := []byte("Additional data for authentication")

	// Encrypt the plaintext
	ciphertext, err := cipher.Encrypt(nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Decrypt the ciphertext
	decryptedPlaintext, err := cipher.Decrypt(nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Verify that the decrypted plaintext matches the original plaintext
	if !bytes.Equal(plaintext, decryptedPlaintext) {
		t.Errorf("Decrypted plaintext does not match the original.\nOriginal: %s\nDecrypted: %s", plaintext, decryptedPlaintext)
	}
}

func TestEncryptDecryptWithEmptyPlaintext(t *testing.T) {
	// Generate random key and nonce
	key := generateRandomKey(t, 32)
	nonce := generateRandomNonce(t, 24)

	cipher, err := NewCipher(key)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}

	plaintext := []byte("") // Empty plaintext
	aad := []byte("Additional data")

	// Encrypt the empty plaintext
	ciphertext, err := cipher.Encrypt(nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Decrypt the ciphertext
	decryptedPlaintext, err := cipher.Decrypt(nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Verify that the decrypted plaintext is also empty
	if len(decryptedPlaintext) != 0 {
		t.Errorf("Expected empty decrypted plaintext, got length %d", len(decryptedPlaintext))
	}
}

func TestInvalidNonceLength(t *testing.T) {
	// Generate a valid key
	key := generateRandomKey(t, 32)

	cipher, err := NewCipher(key)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}

	// Generate invalid nonce
	invalidNonce := generateRandomNonce(t, 16) // Should be 24 bytes for ChaCha20-Poly1305
	plaintext := []byte("Test plaintext")
	aad := []byte("AAD data")

	// Try to encrypt with the invalid nonce
	_, err = cipher.Encrypt(invalidNonce, plaintext, aad)
	if err == nil {
		t.Errorf("Expected error due to invalid nonce length, but encryption succeeded")
	}
}

func TestDecryptWithInvalidNonce(t *testing.T) {
	// Generate random key and nonce
	key := generateRandomKey(t, 32)
	nonce := generateRandomNonce(t, 24)

	cipher, err := NewCipher(key)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}

	plaintext := []byte("Valid plaintext message.")
	aad := []byte("Authenticated data")

	// Encrypt the plaintext
	ciphertext, err := cipher.Encrypt(nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Modify the nonce (introduce an error)
	invalidNonce := generateRandomNonce(t, 24)

	// Attempt to decrypt with an invalid nonce
	_, err = cipher.Decrypt(invalidNonce, ciphertext, aad)
	if err == nil {
		t.Error("Decryption should have failed due to invalid nonce, but it succeeded")
	}
}
