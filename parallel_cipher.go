// parallel_cipher.go
package fastchacha20

import (
	"runtime"
	"sync"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/poly1305"
)

const chunkSize = 64 * 1024 // 64KB per chunk

// ParallelEncrypt encrypts data in parallel.
func (c *Cipher) ParallelEncrypt(key, nonce, plaintext []byte) ([]byte, error) {
	numChunks := (len(plaintext) + chunkSize - 1) / chunkSize
	ciphertext := make([]byte, len(plaintext))
	var wg sync.WaitGroup
	numWorkers := runtime.NumCPU()

	sem := make(chan struct{}, numWorkers)

	for i := 0; i < numChunks; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			start := i * chunkSize
			end := start + chunkSize
			if end > len(plaintext) {
				end = len(plaintext)
			}

			stream, err := chacha20.NewUnauthenticatedCipher(key, nonce)
			if err != nil {
				return
			}
			stream.SetCounter(uint32(start / chacha20.BlockSize))
			stream.XORKeyStream(ciphertext[start:end], plaintext[start:end])
		}(i)
	}
	wg.Wait()

	// Add Poly1305 MAC
	mac := make([]byte, poly1305.TagSize)
	poly1305.Sum(mac, ciphertext, &c.aead.(*chacha20poly1305.ChaCha20Poly1305).Key)

	return append(ciphertext, mac...), nil
}

// ParallelDecrypt decrypts data in parallel.
func (c *Cipher) ParallelDecrypt(key, nonce, ciphertext []byte) ([]byte, error) {
	// Separate MAC from ciphertext
	if len(ciphertext) < poly1305.TagSize {
		return nil, ErrInvalidCiphertext
	}
	macStart := len(ciphertext) - poly1305.TagSize
	mac := ciphertext[macStart:]
	ciphertext = ciphertext[:macStart]

	// Verify MAC
	expectedMAC := make([]byte, poly1305.TagSize)
	poly1305.Sum(expectedMAC, ciphertext, &c.aead.(*chacha20poly1305.ChaCha20Poly1305).Key)
	if !poly1305.Verify(&mac, &expectedMAC) {
		return nil, ErrInvalidMAC
	}

	numChunks := (len(ciphertext) + chunkSize - 1) / chunkSize
	plaintext := make([]byte, len(ciphertext))
	var wg sync.WaitGroup
	numWorkers := runtime.NumCPU()

	sem := make(chan struct{}, numWorkers)

	for i := 0; i < numChunks; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			start := i * chunkSize
			end := start + chunkSize
			if end > len(ciphertext) {
				end = len(ciphertext)
			}

			stream, err := chacha20.NewUnauthenticatedCipher(key, nonce)
			if err != nil {
				return
			}
			stream.SetCounter(uint32(start / chacha20.BlockSize))
			stream.XORKeyStream(plaintext[start:end], ciphertext[start:end])
		}(i)
	}
	wg.Wait()

	return plaintext, nil
}
