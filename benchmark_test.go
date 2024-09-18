// benchmark_test.go
package fastchacha20

import (
	"crypto/rand"
	"testing"
)

func BenchmarkEncryptChunks(b *testing.B) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		b.Fatalf("Failed to generate key: %v", err)
	}

	cipher, err := NewCipher(key)
	if err != nil {
		b.Fatalf("Failed to create cipher: %v", err)
	}

	plaintext := make([]byte, 10*1024*1024) // 10 MB plaintext
	if _, err := rand.Read(plaintext); err != nil {
		b.Fatalf("Failed to generate plaintext: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := cipher.EncryptChunks(plaintext)
		if err != nil {
			b.Fatalf("Encryption failed: %v", err)
		}
	}
}

func BenchmarkDecryptChunks(b *testing.B) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		b.Fatalf("Failed to generate key: %v", err)
	}

	cipher, err := NewCipher(key)
	if err != nil {
		b.Fatalf("Failed to create cipher: %v", err)
	}

	plaintext := make([]byte, 10*1024*1024) // 10 MB plaintext
	if _, err := rand.Read(plaintext); err != nil {
		b.Fatalf("Failed to generate plaintext: %v", err)
	}

	encryptedChunks, err := cipher.EncryptChunks(plaintext)
	if err != nil {
		b.Fatalf("Encryption failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := cipher.DecryptChunks(encryptedChunks)
		if err != nil {
			b.Fatalf("Decryption failed: %v", err)
		}
	}
}

func BenchmarkEncryptDecryptChunks(b *testing.B) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		b.Fatalf("Failed to generate key: %v", err)
	}

	cipher, err := NewCipher(key)
	if err != nil {
		b.Fatalf("Failed to create cipher: %v", err)
	}

	plaintext := make([]byte, 10*1024*1024) // 10 MB plaintext
	if _, err := rand.Read(plaintext); err != nil {
		b.Fatalf("Failed to generate plaintext: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encryptedChunks, err := cipher.EncryptChunks(plaintext)
		if err != nil {
			b.Fatalf("Encryption failed: %v", err)
		}

		_, err = cipher.DecryptChunks(encryptedChunks)
		if err != nil {
			b.Fatalf("Decryption failed: %v", err)
		}
	}
}
