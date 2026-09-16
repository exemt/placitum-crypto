package contourkey

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

type Key struct {
	Private     *rsa.PrivateKey
	Fingerprint string
}

func Load(value string) (*Key, error) {
	raw, err := read(value)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("not pem")
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not rsa")
	}

	spki, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		return nil, err
	}

	sum := sha256.Sum256(spki)

	return &Key{
		Private:     rsaKey,
		Fingerprint: "sha256:" + hex.EncodeToString(sum[:]),
	}, nil
}

func read(value string) ([]byte, error) {
	trimmed := strings.TrimSpace(value)
	if strings.Contains(trimmed, "BEGIN") {
		return []byte(trimmed), nil
	}
	return os.ReadFile(trimmed)
}
