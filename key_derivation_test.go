package fastchacha20

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func decodeHex(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("failed to decode hex: %v", err)
	}
	return b
}

func TestDeriveKeyRFC5869Case1(t *testing.T) {
	ikm := bytes.Repeat([]byte{0x0b}, 22)
	salt := decodeHex(t, "000102030405060708090a0b0c")
	info := decodeHex(t, "f0f1f2f3f4f5f6f7f8f9")

	expected := decodeHex(t, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
	got, err := DeriveKey(salt, ikm, info, len(expected))
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	if !bytes.Equal(got, expected) {
		t.Errorf("HKDF test vector case 1 mismatch\nexpected %x\ngot %x", expected, got)
	}
}

func TestDeriveKeyRFC5869Case2(t *testing.T) {
	ikm := make([]byte, 80)
	for i := 0; i < 80; i++ {
		ikm[i] = byte(i)
	}

	salt := make([]byte, 80)
	for i := 0; i < 80; i++ {
		salt[i] = byte(0x60 + i)
	}

	info := make([]byte, 80)
	for i := 0; i < 80; i++ {
		info[i] = byte(0xb0 + i)
	}

	expected := decodeHex(t, "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87")
	got, err := DeriveKey(salt, ikm, info, len(expected))
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	if !bytes.Equal(got, expected) {
		t.Errorf("HKDF test vector case 2 mismatch\nexpected %x\ngot %x", expected, got)
	}
}

func TestDeriveKeyRFC5869Case3(t *testing.T) {
	ikm := bytes.Repeat([]byte{0x0b}, 22)
	var salt []byte // nil salt
	var info []byte // nil info

	expected := decodeHex(t, "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")
	got, err := DeriveKey(salt, ikm, info, len(expected))
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	if !bytes.Equal(got, expected) {
		t.Errorf("HKDF test vector case 3 mismatch\nexpected %x\ngot %x", expected, got)
	}
}
