package main

import (
	"crypto/rand"
	"fmt"
	"log"

	"fastchacha20"

	"golang.org/x/crypto/chacha20poly1305"
)

func main() {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}

	cipher, err := fastchacha20.NewCipher(key)
	if err != nil {
		log.Fatalf("Failed to create cipher: %v", err)
	}

	// Simulate large plaintext
	plaintext := make([]byte, 10*1024*1024) // 10 MB
	if _, err := rand.Read(plaintext); err != nil {
		log.Fatalf("Failed to generate plaintext: %v", err)
	}

	// Encrypt the plaintext in chunks
	chunks, err := cipher.EncryptChunks(plaintext)
	if err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}

	fmt.Printf("Encrypted %d chunks\n", len(chunks))

	// Decrypt the chunks to recover the plaintext
	decryptedText, err := cipher.DecryptChunks(chunks)
	if err != nil {
		log.Fatalf("Decryption failed: %v", err)
	}

	// Verify that the decrypted text matches the original plaintext
	if string(decryptedText) != string(plaintext) {
		log.Fatal("Decrypted text does not match the original plaintext")
	} else {
		fmt.Println("Decryption successful, plaintext recovered")
	}
}
