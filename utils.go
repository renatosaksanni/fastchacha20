// utils.go
package fastchacha20

import "errors"

var (
	ErrInvalidCiphertext = errors.New("ciphertext too short")
	ErrInvalidMAC        = errors.New("invalid MAC")
	ErrInvalidLength     = errors.New("length exceeds maximum allowed")
)
