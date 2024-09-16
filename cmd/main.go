// examples/main.go
package main

import (
	"crypto/rand"
	"fmt"
	"log"

	"github.com/renatosaksanni/fastchacha20"
)

func main() {
	key := make([]byte, 32)   // 256-bit key
	nonce := make([]byte, 24) // 192-bit nonce for ChaCha20-Poly1305 X

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

	// Using parallel encryption
	ciphertext, err := cipher.ParallelEncrypt(key, nonce, plaintext)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Ciphertext: %x\n", ciphertext)

	// Decrypting
	decryptedText, err := cipher.ParallelDecrypt(key, nonce, ciphertext)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Decrypted Text: %s\n", decryptedText)
}
