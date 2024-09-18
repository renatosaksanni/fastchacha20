// parallel.go
package fastchacha20

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"sync"
)

// EncryptChunks encrypts the plaintext in parallel using unique nonces for each chunk.
func (c *Cipher) EncryptChunks(plaintext []byte) ([][]byte, error) {
	const chunkSize = 64 * 1024 // 64KB
	numChunks := (len(plaintext) + chunkSize - 1) / chunkSize
	encryptedChunks := make([][]byte, numChunks)
	var wg sync.WaitGroup
	var errOnce sync.Once
	var err error

	for i := 0; i < numChunks; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			start := i * chunkSize
			end := start + chunkSize
			if end > len(plaintext) {
				end = len(plaintext)
			}
			chunk := plaintext[start:end]

			// Generate a unique nonce for each chunk
			nonce := make([]byte, c.aead.NonceSize())
			if _, e := rand.Read(nonce); e != nil {
				errOnce.Do(func() { err = e })
				return
			}

			// Include the chunk index in AAD
			aad := make([]byte, 8)
			binary.BigEndian.PutUint64(aad, uint64(i))

			// Encrypt the chunk using the Encrypt method from cipher.go
			ciphertext, e := c.Encrypt(nonce, chunk, aad)
			if e != nil {
				errOnce.Do(func() { err = e })
				return
			}

			// Prepend nonce to the ciphertext for storage
			encryptedChunk := append(nonce, ciphertext...)
			encryptedChunks[i] = encryptedChunk
		}(i)
	}
	wg.Wait()

	if err != nil {
		return nil, err
	}

	return encryptedChunks, nil
}

// DecryptChunks decrypts the encrypted chunks in parallel and reassembles the plaintext.
func (c *Cipher) DecryptChunks(encryptedChunks [][]byte) ([]byte, error) {
	numChunks := len(encryptedChunks)
	plaintextChunks := make([][]byte, numChunks)
	var wg sync.WaitGroup
	var errOnce sync.Once
	var err error

	for i, chunk := range encryptedChunks {
		wg.Add(1)
		go func(i int, chunk []byte) {
			defer wg.Done()
			nonceSize := c.aead.NonceSize()
			if len(chunk) < nonceSize+16 { // 16 bytes for Poly1305 tag
				errOnce.Do(func() { err = ErrInvalidCiphertext })
				return
			}

			nonce := chunk[:nonceSize]
			ciphertext := chunk[nonceSize:]

			// Include the chunk index in AAD
			aad := make([]byte, 8)
			binary.BigEndian.PutUint64(aad, uint64(i))

			// Decrypt the chunk using the Decrypt method from cipher.go
			plaintext, e := c.Decrypt(nonce, ciphertext, aad)
			if e != nil {
				errOnce.Do(func() { err = e })
				return
			}
			plaintextChunks[i] = plaintext
		}(i, chunk)
	}
	wg.Wait()

	if err != nil {
		return nil, err
	}

	// Reassemble the plaintext
	var plaintext bytes.Buffer
	for _, chunk := range plaintextChunks {
		plaintext.Write(chunk)
	}

	return plaintext.Bytes(), nil
}
