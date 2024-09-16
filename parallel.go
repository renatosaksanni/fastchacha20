// fastchacha20_parallel.go
package fastchacha20

import (
	"crypto/rand"
	"sync"
)

type Chunk struct {
	Nonce      []byte
	Ciphertext []byte
}

// EncryptChunks encrypts the plaintext by splitting it into chunks and processing them in parallel.
func (c *Cipher) EncryptChunks(plaintext []byte) ([]Chunk, error) {
	chunkSize := 64 * 1024 // Adjust chunk size as needed
	numChunks := (len(plaintext) + chunkSize - 1) / chunkSize
	chunks := make([]Chunk, numChunks)
	var wg sync.WaitGroup
	var errMutex sync.Mutex
	var encErr error

	for i := 0; i < numChunks; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			start := i * chunkSize
			end := start + chunkSize
			if end > len(plaintext) {
				end = len(plaintext)
			}

			nonce := make([]byte, c.aead.NonceSize())
			if _, err := rand.Read(nonce); err != nil {
				errMutex.Lock()
				encErr = err
				errMutex.Unlock()
				return
			}

			ciphertext := c.aead.Seal(nil, nonce, plaintext[start:end], nil)
			chunks[i] = Chunk{
				Nonce:      nonce,
				Ciphertext: ciphertext,
			}
		}(i)
	}
	wg.Wait()

	if encErr != nil {
		return nil, encErr
	}

	return chunks, nil
}

// DecryptChunks decrypts the ciphertext chunks in parallel and reassembles the plaintext.
func (c *Cipher) DecryptChunks(chunks []Chunk) ([]byte, error) {
	var wg sync.WaitGroup
	plaintextParts := make([][]byte, len(chunks))
	var errMutex sync.Mutex
	var decErr error

	for i, chunk := range chunks {
		wg.Add(1)
		go func(i int, chunk Chunk) {
			defer wg.Done()
			plaintext, err := c.aead.Open(nil, chunk.Nonce, chunk.Ciphertext, nil)
			if err != nil {
				errMutex.Lock()
				decErr = err
				errMutex.Unlock()
				return
			}
			plaintextParts[i] = plaintext
		}(i, chunk)
	}
	wg.Wait()

	if decErr != nil {
		return nil, decErr
	}

	// Reassemble plaintext
	plaintext := make([]byte, 0)
	for _, part := range plaintextParts {
		plaintext = append(plaintext, part...)
	}

	return plaintext, nil
}
