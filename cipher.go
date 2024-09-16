// cipher.go
package fastchacha20

import (
	"crypto/cipher"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

type Cipher struct {
	aead cipher.AEAD
}

// NewCipher creates a new Cipher instance with the provided key.
func NewCipher(key []byte) (*Cipher, error) {
	aead, err := chacha20poly1305.NewX(key) // For 192-bit nonces. Use New() for 96-bit nonces.
	if err != nil {
		return nil, err
	}
	return &Cipher{aead: aead}, nil
}

// Encrypt encrypts plaintext with the given nonce and additional data.
func (c *Cipher) Encrypt(nonce, plaintext, additionalData []byte) ([]byte, error) {
	if len(nonce) != c.aead.NonceSize() {
		return nil, fmt.Errorf("invalid nonce length: got %d, expected %d", len(nonce), c.aead.NonceSize())
	}
	ciphertext := c.aead.Seal(nil, nonce, plaintext, additionalData)
	return ciphertext, nil
}

// Decrypt decrypts ciphertext with the given nonce and additional data.
func (c *Cipher) Decrypt(nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != c.aead.NonceSize() {
		return nil, fmt.Errorf("invalid nonce length: got %d, expected %d", len(nonce), c.aead.NonceSize())
	}
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
