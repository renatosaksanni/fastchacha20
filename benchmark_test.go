package fastchacha20

import (
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func benchmarkEncrypt(b *testing.B, dataSize int) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		b.Fatalf("Failed to generate key: %v", err)
	}

	cipher, err := NewCipher(key)
	if err != nil {
		b.Fatalf("Failed to create cipher: %v", err)
	}

	nonce := make([]byte, cipher.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		b.Fatalf("Failed to generate nonce: %v", err)
	}

	plaintext := make([]byte, dataSize)
	if _, err := rand.Read(plaintext); err != nil {
		b.Fatalf("Failed to generate plaintext: %v", err)
	}

	additionalData := []byte("Benchmark AAD")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := cipher.Encrypt(nonce, plaintext, additionalData)
		if err != nil {
			b.Fatalf("Encryption failed: %v", err)
		}
	}
}

func benchmarkDecrypt(b *testing.B, dataSize int) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		b.Fatalf("Failed to generate key: %v", err)
	}

	cipher, err := NewCipher(key)
	if err != nil {
		b.Fatalf("Failed to create cipher: %v", err)
	}

	nonce := make([]byte, cipher.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		b.Fatalf("Failed to generate nonce: %v", err)
	}

	plaintext := make([]byte, dataSize)
	if _, err := rand.Read(plaintext); err != nil {
		b.Fatalf("Failed to generate plaintext: %v", err)
	}

	additionalData := []byte("Benchmark AAD")
	ciphertext, err := cipher.Encrypt(nonce, plaintext, additionalData)
	if err != nil {
		b.Fatalf("Encryption failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := cipher.Decrypt(nonce, ciphertext, additionalData)
		if err != nil {
			b.Fatalf("Decryption failed: %v", err)
		}
	}
}

func BenchmarkEncrypt1KB(b *testing.B) {
	benchmarkEncrypt(b, 1024)
}

func BenchmarkEncrypt8KB(b *testing.B) {
	benchmarkEncrypt(b, 8*1024)
}

func BenchmarkEncrypt64KB(b *testing.B) {
	benchmarkEncrypt(b, 64*1024)
}

func BenchmarkEncrypt512KB(b *testing.B) {
	benchmarkEncrypt(b, 512*1024)
}

func BenchmarkEncrypt1MB(b *testing.B) {
	benchmarkEncrypt(b, 1024*1024)
}

func BenchmarkDecrypt1KB(b *testing.B) {
	benchmarkDecrypt(b, 1024)
}

func BenchmarkDecrypt8KB(b *testing.B) {
	benchmarkDecrypt(b, 8*1024)
}

func BenchmarkDecrypt64KB(b *testing.B) {
	benchmarkDecrypt(b, 64*1024)
}

func BenchmarkDecrypt512KB(b *testing.B) {
	benchmarkDecrypt(b, 512*1024)
}

func BenchmarkDecrypt1MB(b *testing.B) {
	benchmarkDecrypt(b, 1024*1024)
}
