// cmd/main.go
package main

import (
	"crypto/rand"
	"fastchacha20"
	"fmt"
	"log"

	"golang.org/x/crypto/chacha20poly1305"
)

func main() {
	key := make([]byte, chacha20poly1305.KeySize)      // 32 bytes
	nonce := make([]byte, chacha20poly1305.NonceSizeX) // 24 bytes for NewX()

	_, err := rand.Read(key)
	if err != nil {
		log.Fatal(err)
	}
	_, err = rand.Read(nonce)
	if err != nil {
		log.Fatal(err)
	}

	plaintext := []byte("This is a secret message that will be encrypted.")

	cipher, err := fastchacha20.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	// Encrypt
	ciphertext, err := cipher.Encrypt(nonce, plaintext, nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Ciphertext: %x\n", ciphertext)

	// Decrypt
	decryptedText, err := cipher.Decrypt(nonce, ciphertext, nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Decrypted Text: %s\n", decryptedText)
}
