package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

const (
	Version = 0x01

	NonceSize = 12

	DEKSize = 32

	headerLen = 1 + 2
)

func Open(blob []byte, key *rsa.PrivateKey) ([]byte, error) {
	if len(blob) < headerLen {
		return nil, fmt.Errorf("envelope: too short")
	}

	if blob[0] != Version {
		return nil, fmt.Errorf("envelope: unsupported version %d", blob[0])
	}

	wrappedLen := int(binary.BigEndian.Uint16(blob[1:3]))
	if wrappedLen <= 0 || len(blob) < headerLen+wrappedLen+NonceSize {
		return nil, fmt.Errorf("envelope: truncated")
	}

	wrapped := blob[headerLen : headerLen+wrappedLen]
	nonce := blob[headerLen+wrappedLen : headerLen+wrappedLen+NonceSize]
	ciphertext := blob[headerLen+wrappedLen+NonceSize:]

	dek, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, wrapped, nil)
	if err != nil {
		return nil, fmt.Errorf("envelope: unwrap dek: %w", err)
	}

	gcm, err := newGCM(dek)
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("envelope: open: %w", err)
	}

	return plaintext, nil
}

func Seal(plaintext []byte, pub *rsa.PublicKey) ([]byte, error) {
	dek := make([]byte, DEKSize)
	if _, err := rand.Read(dek); err != nil {
		return nil, fmt.Errorf("envelope: dek: %w", err)
	}

	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, dek, nil)
	if err != nil {
		return nil, fmt.Errorf("envelope: wrap dek: %w", err)
	}

	if len(wrapped) > 0xffff {
		return nil, fmt.Errorf("envelope: wrapped dek too large")
	}

	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("envelope: nonce: %w", err)
	}

	gcm, err := newGCM(dek)
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	out := make([]byte, 0, headerLen+len(wrapped)+NonceSize+len(ciphertext))
	out = append(out, Version)
	out = binary.BigEndian.AppendUint16(out, uint16(len(wrapped)))
	out = append(out, wrapped...)
	out = append(out, nonce...)
	out = append(out, ciphertext...)

	return out, nil
}

func newGCM(dek []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}

	return cipher.NewGCM(block)
}
