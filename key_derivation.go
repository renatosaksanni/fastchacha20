// key_derivation.go
package fastchacha20

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"
)

func hkdfExtract(salt, inputKeyMaterial []byte, hashFunc func() hash.Hash) []byte {
	if salt == nil {
		salt = make([]byte, hashFunc().Size())
	}
	h := hmac.New(hashFunc, salt)
	h.Write(inputKeyMaterial)
	return h.Sum(nil)
}

func hkdfExpand(prk, info []byte, length int, hashFunc func() hash.Hash) []byte {
	n := (length + hashFunc().Size() - 1) / hashFunc().Size()
	var t []byte
	var okm []byte
	for i := 0; i < n; i++ {
		h := hmac.New(hashFunc, prk)
		h.Write(append(t, info...))
		h.Write([]byte{byte(i + 1)})
		t = h.Sum(nil)
		okm = append(okm, t...)
	}
	return okm[:length]
}

// DeriveKey generates a derived key from the input key material.
func DeriveKey(salt, inputKeyMaterial, info []byte, length int) []byte {
	prk := hkdfExtract(salt, inputKeyMaterial, sha256.New)
	return hkdfExpand(prk, info, length, sha256.New)
}
