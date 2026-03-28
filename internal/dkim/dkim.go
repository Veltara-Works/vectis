package dkim

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const keyBits = 2048

// KeyPair holds a generated DKIM key pair.
type KeyPair struct {
	PrivateKeyPEM string
	PublicKeyDER  []byte // DER-encoded public key
	Selector      string
	Domain        string
	KeyPath       string // filesystem path where private key is stored
}

// DNSRecord returns the DKIM TXT record value.
func (kp *KeyPair) DNSRecord() string {
	b64 := base64.StdEncoding.EncodeToString(kp.PublicKeyDER)
	return fmt.Sprintf("v=DKIM1; k=rsa; p=%s", b64)
}

// DNSName returns the full DNS name for the TXT record.
func (kp *KeyPair) DNSName() string {
	return fmt.Sprintf("%s._domainkey.%s", kp.Selector, kp.Domain)
}

// GenerateKey creates a new RSA-2048 DKIM key pair for a domain.
// The private key is written to basePath/<domain>/<selector>.key.
func GenerateKey(basePath, domain, selector string) (*KeyPair, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return nil, fmt.Errorf("generate RSA key: %w", err)
	}

	// Encode private key to PEM.
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})

	// Extract DER-encoded public key.
	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}

	// Write private key to disk.
	keyDir := filepath.Join(basePath, domain)
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return nil, fmt.Errorf("create DKIM key directory: %w", err)
	}

	keyPath := filepath.Join(keyDir, selector+".key")
	if err := os.WriteFile(keyPath, privPEM, 0600); err != nil {
		return nil, fmt.Errorf("write private key: %w", err)
	}

	return &KeyPair{
		PrivateKeyPEM: string(privPEM),
		PublicKeyDER:  pubDER,
		Selector:      selector,
		Domain:        domain,
		KeyPath:       keyPath,
	}, nil
}

// ReadPublicKey reads a DKIM private key from disk and returns the public key
// DER bytes for DNS record generation.
func ReadPublicKey(keyPath string) ([]byte, error) {
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM data")
	}

	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}

	return pubDER, nil
}

// DefaultSelector returns a date-based DKIM selector (e.g., "202603").
func DefaultSelector() string {
	return time.Now().UTC().Format("200601")
}

// SPFRecord returns a recommended SPF TXT record for a given IP.
func SPFRecord(ipv4 string) string {
	parts := []string{"v=spf1", "mx", "a"}
	if ipv4 != "" {
		parts = append(parts, "ip4:"+ipv4)
	}
	parts = append(parts, "-all")
	return strings.Join(parts, " ")
}

// DMARCRecord returns a recommended DMARC TXT record.
func DMARCRecord(domain string) string {
	return fmt.Sprintf("v=DMARC1; p=quarantine; rua=mailto:dmarc@%s; fo=1", domain)
}
