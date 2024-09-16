// cipher.go
package fastchacha20

import (
	"crypto/cipher"

	"golang.org/x/crypto/chacha20poly1305"
)

type Cipher struct {
	aead cipher.AEAD
}

// NewCipher creates a new Cipher instance with the given key.
func NewCipher(key []byte) (*Cipher, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return &Cipher{aead: aead}, nil
}

// Encrypt encrypts plaintext with the given nonce and optional additional data.
func (c *Cipher) Encrypt(nonce, plaintext, additionalData []byte) ([]byte, error) {
	ciphertext := c.aead.Seal(nil, nonce, plaintext, additionalData)
	return ciphertext, nil
}

// Decrypt decrypts ciphertext with the given nonce and optional additional data.
func (c *Cipher) Decrypt(nonce, ciphertext, additionalData []byte) ([]byte, error) {
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
