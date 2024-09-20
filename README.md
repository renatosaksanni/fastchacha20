# FastChaCha20

FastChaCha20 is a Go library that provides an optimized implementation of the **ChaCha20-Poly1305** encryption algorithm. It leverages Go's concurrency features to encrypt and decrypt data in parallel, enhancing performance for large data sets.

## Table of Contents

- [Features](#features)
- [Parallel Processing with Goroutines](#parallel-processing-with-goroutines)
- [Mathematical Explanations](#mathematical-explanations)
- [Installation](#installation)
- [Usage](#usage)
- [Testing and Benchmarking](#testing-and-benchmarking)
- [Security Considerations](#security-considerations)
- [Notes](#notes)
- [Additional Resources](#additional-resources)
- [Shortcuts and Tips](#shortcuts-and-tips)

## Features

- **Parallel Encryption and Decryption**: Splits data into chunks and processes them concurrently using goroutines.
- **Simple API**: Easy-to-use interface for integrating into your projects.
- **High Security**: Adheres to cryptographic best practices to ensure data safety.


## Parallel Processing with Goroutines

- **Chunking Data:** Your data gets chopped into smaller pieces (like 64KB each).
- **Concurrent Encryption:** Each chunk gets encrypted or decrypted at the same time using Go's goroutines, which are lightweight threads.
- **Managing Goroutines:** Uses `sync.WaitGroup` and semaphores to keep things organized and prevent overloading your CPU.


## Mathematical Explanations

**ChaCha20 Algorithm Basics:**

ChaCha20 is a stream cipher that generates a keystream to encrypt data using XOR operations.

- **State Matrix:** ChaCha20 uses a 4x4 matrix of 32-bit words:

$$
\begin{pmatrix}
\text{const}_0 & \text{const}_1 & \text{const}_2 & \text{const}_3 \\
\text{key}_0 & \text{key}_1 & \text{key}_2 & \text{key}_3 \\
\text{key}_4 & \text{key}_5 & \text{key}_6 & \text{key}_7 \\
\text{counter} & \text{nonce}_0 & \text{nonce}_1 & \text{nonce}_2 \\
\end{pmatrix}
$$

- **Quarter Round Function:** Core of the algorithm, mixing the state with additions, XORs, and rotations.

$$
\begin{align*}
a &= a + b;\quad d = \text{ROTL}(d \oplus a, 16) \\
c &= c + d;\quad b = \text{ROTL}(b \oplus c, 12) \\
a &= a + b;\quad d = \text{ROTL}(d \oplus a, 8) \\
c &= c + d;\quad b = \text{ROTL}(b \oplus c, 7)
\end{align*}
$$

  - **ROTL:** Rotate left operation.

- **Keystream Generation:** After running the rounds, the state is used to produce the keystream.

**Parallelization Approach:**

- **Setting Counters for Chunks:**

  - Each chunk uses a counter based on its position:

$$
\text{counter}_i = \text{initial counter} + \left\lfloor \dfrac{\text{offset}_i}{64} \right\rfloor
$$

  Where $\text{offset}_i$ is the starting byte of chunk $i$.

- **Ensuring Unique Keystreams:**

  - By assigning unique counters, each chunk's encryption is independent and secure.

**Poly1305 MAC:**

- **Message Authentication Code:**

  - Poly1305 generates a 128-bit tag to verify data integrity.
  - Calculated as:

$$
\text{Tag} = \left( \left( \sum_{i=1}^{n} a_i \cdot r^{i} \right) \mod (2^{130} - 5) \right) + s \mod \left(2^{128}\right)
$$

   Where:

   - $a_i$ are blocks of the message.
   - $r$ and $s$ are 128-bit key (clamped).
   - $n$ is the number of blocks.

**Parallel MAC Computation:**

   - While tricky, parts of Poly1305 can be optimized for large data sets.


## Installation

Make sure you have Go installed (version 1.15 or newer).

```bash
go get -u github.com/renatosaksanni/fastchacha20
```

## Usage

Here's how you can use FastChaCha20 in your project:

```go
package main

import (
    "bytes"
    "crypto/rand"
    "encoding/binary"
    "fmt"
    "log"

    "github.com/renatosaksanni/fastchacha20"
)

func main() {
    key := make([]byte, 32) // 256-bit key
    if _, err := rand.Read(key); err != nil {
        log.Fatalf("Failed to generate key: %v", err)
    }

    cipher, err := fastchacha20.NewCipher(key)
    if err != nil {
        log.Fatalf("Failed to create cipher: %v", err)
    }

    // Your plaintext data
    plaintext := []byte("This is some secret data.")

    // Encrypting the data
    encryptedChunks, err := cipher.EncryptChunks(plaintext)
    if err != nil {
        log.Fatalf("Encryption failed: %v", err)
    }

    // Decrypting the data
    decryptedPlaintext, err := cipher.DecryptChunks(encryptedChunks)
    if err != nil {
        log.Fatalf("Decryption failed: %v", err)
    }

    if !bytes.Equal(plaintext, decryptedPlaintext) {
        log.Fatal("Decrypted plaintext does not match original")
    }

    fmt.Printf("Decrypted text: %s\n", decryptedPlaintext)
}
```


## Testing and Benchmarking

### Running Tests

```bash
go test
```

### Running Benchmarks

```bash
go test -bench=. -benchtime=10s
```

## Security Considerations

- **Nonce Uniqueness:** Always use a unique nonce for each encryption operation with the same key.
- **Chunk Index in AAD:** Including the chunk index in the Additional Authenticated Data (AAD) binds each chunk to its position.
- **Avoid Reusing Nonces:** Reusing a nonce with the same key can completely break the security.


## Notes

- **Concurrency:** Be cautious with goroutines; too many can cause overhead.
- **Error Handling:** Always check for errors, especially when dealing with encryption.
- **Stay Updated:** Keep dependencies up to date for security patches.



## Additional Resources

- **Go Cryptography Documentation:** [https://golang.org/pkg/crypto/](https://golang.org/pkg/crypto/)
- **ChaCha20 and Poly1305 Specification:** [RFC 8439](https://tools.ietf.org/html/rfc8439)
- **Practical Cryptography in Go:** [Blog Post](https://blog.gopheracademy.com/advent-2017/practical-cryptography-go/)



## Shortcuts and Tips

- **Import the Package:**

  ```go
  import "github.com/renatosaksanni/fastchacha20"
  ```

- **Generate Secure Random Data:**

  ```go
  rand.Read(data)
  ```

- **Check Nonce Sizes:**

  ```go
  nonce := make([]byte, cipher.aead.NonceSize())
  ```

- **Handle Errors:**

  ```go
  if err != nil {
      log.Fatalf("An error occurred: %v", err)
  }
  ```

