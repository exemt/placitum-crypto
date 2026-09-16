package certmeta

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

type Meta struct {
	SANs        []string
	NotBefore   time.Time
	NotAfter    time.Time
	Fingerprint string
	Subject     string
	Issuer      string
	Serial      string
	IsCA        bool
}

type CRLMeta struct {
	Issuer     string
	ThisUpdate time.Time
	NextUpdate time.Time
	Revoked    int
}

var (
	ErrNotCertificate = errors.New("not a pem certificate")
	ErrNotPrivateKey  = errors.New("not a pem private key")
	ErrKeyMismatch    = errors.New("private key does not match certificate")
	ErrNotCRL         = errors.New("not a pem crl")
)

func ParseCertificate(pemBytes []byte) (Meta, error) {
	cert, err := parseCertificateBlock(pemBytes)
	if err != nil {
		return Meta{}, err
	}

	sum := sha256.Sum256(cert.Raw)

	sans := make([]string, 0, len(cert.DNSNames)+len(cert.IPAddresses))
	sans = append(sans, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}

	return Meta{
		SANs:        sans,
		NotBefore:   cert.NotBefore,
		NotAfter:    cert.NotAfter,
		Fingerprint: "sha256:" + hex.EncodeToString(sum[:]),
		Subject:     cert.Subject.String(),
		Issuer:      cert.Issuer.String(),
		Serial:      cert.SerialNumber.String(),
		IsCA:        cert.IsCA,
	}, nil
}

func ParseCRL(pemBytes []byte) (CRLMeta, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || (block.Type != "X509 CRL" && block.Type != "CRL") {
		return CRLMeta{}, ErrNotCRL
	}

	list, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return CRLMeta{}, fmt.Errorf("%w: %v", ErrNotCRL, err)
	}

	return CRLMeta{
		Issuer:     list.Issuer.String(),
		ThisUpdate: list.ThisUpdate,
		NextUpdate: list.NextUpdate,
		Revoked:    len(list.RevokedCertificateEntries),
	}, nil
}

func ParseChain(pemBytes []byte) error {
	rest := pemBytes
	count := 0

	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			return ErrNotCertificate
		}

		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return fmt.Errorf("%w: %v", ErrNotCertificate, err)
		}

		count++
	}

	if count == 0 {
		return ErrNotCertificate
	}

	return nil
}

func MatchesKey(certPEM, keyPEM []byte) error {
	cert, err := parseCertificateBlock(certPEM)
	if err != nil {
		return err
	}

	priv, err := parsePrivateKeyBlock(keyPEM)
	if err != nil {
		return err
	}

	equaler, ok := cert.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return fmt.Errorf("%w: unsupported certificate key type", ErrKeyMismatch)
	}

	if !equaler.Equal(priv.Public()) {
		return ErrKeyMismatch
	}

	return nil
}

func parseCertificateBlock(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, ErrNotCertificate
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotCertificate, err)
	}

	return cert, nil
}

func parsePrivateKeyBlock(pemBytes []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, ErrNotPrivateKey
	}

	switch block.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrNotPrivateKey, err)
		}

		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("%w: unsupported key type", ErrNotPrivateKey)
		}

		return signer, nil
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrNotPrivateKey, err)
		}

		return key, nil
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrNotPrivateKey, err)
		}

		return key, nil
	default:
		return nil, ErrNotPrivateKey
	}
}
