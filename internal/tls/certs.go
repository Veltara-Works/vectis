package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// GenerateSelfSigned creates a self-signed TLS certificate for development use.
// Writes fullchain.pem and privkey.pem to the given directory.
func GenerateSelfSigned(certDir, hostname string) error {
	return generateSelfSigned(selfSignedOptions{
		CertDir:      certDir,
		Hostname:     hostname,
		Organization: "Vectis Mail Server (self-signed)",
		Validity:     365 * 24 * time.Hour,
		WriteCertPem: false,
	})
}

// GenerateSelfSignedPlaceholder creates a short-lived self-signed cert
// used as a mail-TLS bootstrap when the real Let's Encrypt cert hasn't
// been issued yet (e.g. Traefik still completing HTTP-01, LE rate-limited,
// port-80 unreachable). Same shape as GenerateSelfSigned but:
//
//   - Organization = "VECTIS PLACEHOLDER — awaiting Let's Encrypt" so
//     any cert-validation tooling can identify + skip placeholder certs.
//   - Validity = 7 days, short enough that a forgotten placeholder can't
//     linger silently serving mail indefinitely.
//   - Writes all three files (fullchain.pem, cert.pem, privkey.pem) so
//     consumers that look for either fullchain or cert both find a PEM.
//
// Called by the cert-extractor sidecar when it polls an empty acme.json
// on a fresh install: dovecot otherwise crashloops with exit 89 until
// Traefik issues, which can take minutes on a fresh DNS record and
// forever if LE fails. The placeholder lets dovecot start cleanly; when
// the real cert arrives, the extractor's content-hash check detects the
// change and SIGHUPs dovecot/postfix so they reload the real cert.
func GenerateSelfSignedPlaceholder(certDir, hostname string) error {
	return generateSelfSigned(selfSignedOptions{
		CertDir:      certDir,
		Hostname:     hostname,
		Organization: "VECTIS PLACEHOLDER — awaiting Let's Encrypt",
		Validity:     7 * 24 * time.Hour,
		WriteCertPem: true,
	})
}

type selfSignedOptions struct {
	CertDir      string
	Hostname     string
	Organization string
	Validity     time.Duration
	// WriteCertPem duplicates fullchain.pem to cert.pem for consumers
	// (e.g. postfix main.cf) that look for the shorter name.
	WriteCertPem bool
}

func generateSelfSigned(opts selfSignedOptions) error {
	if err := os.MkdirAll(opts.CertDir, 0o755); err != nil {
		return fmt.Errorf("create cert directory: %w", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate private key: %w", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   opts.Hostname,
			Organization: []string{opts.Organization},
		},
		DNSNames:  []string{opts.Hostname},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(opts.Validity),

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	fullchainPath := filepath.Join(opts.CertDir, "fullchain.pem")
	if err := os.WriteFile(fullchainPath, certPEM, 0o644); err != nil {
		return fmt.Errorf("write fullchain.pem: %w", err)
	}

	if opts.WriteCertPem {
		certPath := filepath.Join(opts.CertDir, "cert.pem")
		if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
			return fmt.Errorf("write cert.pem: %w", err)
		}
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	keyPath := filepath.Join(opts.CertDir, "privkey.pem")
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write privkey.pem: %w", err)
	}

	return nil
}

// CertInfo holds information about a TLS certificate on disk.
type CertInfo struct {
	Path      string    `json:"path"`
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	DNSNames  []string  `json:"dns_names"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	IsExpired bool      `json:"is_expired"`
	DaysLeft  int       `json:"days_left"`
}

// ReadCertInfo reads a PEM certificate file and returns its metadata.
func ReadCertInfo(certPath string) (*CertInfo, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read cert file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM data found in %s", certPath)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	now := time.Now()
	return &CertInfo{
		Path:      certPath,
		Subject:   cert.Subject.CommonName,
		Issuer:    cert.Issuer.CommonName,
		DNSNames:  cert.DNSNames,
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
		IsExpired: now.After(cert.NotAfter),
		DaysLeft:  int(cert.NotAfter.Sub(now).Hours() / 24),
	}, nil
}
