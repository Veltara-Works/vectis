package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const (
	// InternalCertDir is the default directory for internal mTLS certificates.
	InternalCertDir = "/var/vectis/certs/internal"

	caFile         = "ca.pem"
	caKeyFile      = "ca-key.pem"
	serverCertFile = "server.pem"
	serverKeyFile  = "server-key.pem"
	clientCertFile = "client.pem"
	clientKeyFile  = "client-key.pem"
)

// InternalCAPaths returns the expected file paths for the internal CA.
func InternalCAPaths(certDir string) (caCert, caKey string) {
	return filepath.Join(certDir, caFile), filepath.Join(certDir, caKeyFile)
}

// InternalServerPaths returns the expected file paths for the orchestrator server cert.
func InternalServerPaths(certDir string) (cert, key string) {
	return filepath.Join(certDir, serverCertFile), filepath.Join(certDir, serverKeyFile)
}

// InternalClientPaths returns the expected file paths for the API client cert.
func InternalClientPaths(certDir string) (cert, key string) {
	return filepath.Join(certDir, clientCertFile), filepath.Join(certDir, clientKeyFile)
}

// GenerateInternalCA creates an ECDSA P-256 certificate authority for internal
// mTLS between the API server and orchestrator. Valid for 10 years.
func GenerateInternalCA(certDir string) error {
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return fmt.Errorf("create cert directory: %w", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate CA key: %w", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Vectis Internal CA",
			Organization: []string{"Vectis Mail Server"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create CA certificate: %w", err)
	}

	if err := writePEM(filepath.Join(certDir, caFile), "CERTIFICATE", certDER, 0644); err != nil {
		return err
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal CA key: %w", err)
	}
	return writePEM(filepath.Join(certDir, caKeyFile), "EC PRIVATE KEY", keyDER, 0600)
}

// GenerateSignedCert creates a certificate signed by the internal CA.
// The dnsNames and isServer/isClient flags control the ExtKeyUsage.
func GenerateSignedCert(certDir, certName, keyName string, dnsNames []string, isServer, isClient bool) error {
	// Load CA.
	caCert, caKey, err := loadCA(certDir)
	if err != nil {
		return fmt.Errorf("load CA: %w", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	cn := "Vectis Orchestrator Server"
	if isClient && !isServer {
		cn = "Vectis API Client"
	}

	var extKeyUsage []x509.ExtKeyUsage
	if isServer {
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageServerAuth)
	}
	if isClient {
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageClientAuth)
	}

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Vectis Mail Server"},
		},
		DNSNames:              dnsNames,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           extKeyUsage,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}

	if err := writePEM(filepath.Join(certDir, certName), "CERTIFICATE", certDER, 0644); err != nil {
		return err
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	return writePEM(filepath.Join(certDir, keyName), "EC PRIVATE KEY", keyDER, 0600)
}

// GenerateInternalCerts generates the full set of internal mTLS certificates:
// CA, server cert (for orchestrator), and client cert (for API).
func GenerateInternalCerts(certDir string) error {
	if err := GenerateInternalCA(certDir); err != nil {
		return fmt.Errorf("generate CA: %w", err)
	}

	// Server cert for orchestrator — reachable as "orchestrator" and "localhost".
	if err := GenerateSignedCert(certDir, serverCertFile, serverKeyFile,
		[]string{"orchestrator", "localhost"}, true, false); err != nil {
		return fmt.Errorf("generate server cert: %w", err)
	}

	// Client cert for API server.
	if err := GenerateSignedCert(certDir, clientCertFile, clientKeyFile,
		[]string{"api", "localhost"}, false, true); err != nil {
		return fmt.Errorf("generate client cert: %w", err)
	}

	return nil
}

// NewServerTLSConfig creates a tls.Config for the orchestrator server that
// requires and verifies client certificates against the internal CA.
func NewServerTLSConfig(certDir string) (*tls.Config, error) {
	caCertPEM, err := os.ReadFile(filepath.Join(certDir, caFile))
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	serverCert, err := tls.LoadX509KeyPair(
		filepath.Join(certDir, serverCertFile),
		filepath.Join(certDir, serverKeyFile),
	)
	if err != nil {
		return nil, fmt.Errorf("load server keypair: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// NewClientTLSConfig creates a tls.Config for the API client that presents
// a client certificate and verifies the orchestrator server cert against the CA.
func NewClientTLSConfig(certDir string) (*tls.Config, error) {
	caCertPEM, err := os.ReadFile(filepath.Join(certDir, caFile))
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	clientCert, err := tls.LoadX509KeyPair(
		filepath.Join(certDir, clientCertFile),
		filepath.Join(certDir, clientKeyFile),
	)
	if err != nil {
		return nil, fmt.Errorf("load client keypair: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// InternalCertsExist returns true if the CA, server, and client certs all exist.
func InternalCertsExist(certDir string) bool {
	files := []string{caFile, serverCertFile, serverKeyFile, clientCertFile, clientKeyFile}
	for _, f := range files {
		if _, err := os.Stat(filepath.Join(certDir, f)); err != nil {
			return false
		}
	}
	return true
}

// --- helpers ---

func loadCA(certDir string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certPEM, err := os.ReadFile(filepath.Join(certDir, caFile))
	if err != nil {
		return nil, nil, fmt.Errorf("read CA cert: %w", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("no PEM data in CA cert")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA cert: %w", err)
	}

	keyPEM, err := os.ReadFile(filepath.Join(certDir, caKeyFile))
	if err != nil {
		return nil, nil, fmt.Errorf("read CA key: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("no PEM data in CA key")
	}

	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA key: %w", err)
	}

	return cert, key, nil
}

func writePEM(path, blockType string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("create %s: %w", filepath.Base(path), err)
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: blockType, Bytes: data})
}
