package dkim

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	dir := t.TempDir()

	kp, err := GenerateKey(dir, "example.com", "202603")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	if kp.Domain != "example.com" {
		t.Errorf("domain: %s", kp.Domain)
	}
	if kp.Selector != "202603" {
		t.Errorf("selector: %s", kp.Selector)
	}

	// Key file should exist on disk.
	expectedPath := filepath.Join(dir, "example.com", "202603.key")
	if kp.KeyPath != expectedPath {
		t.Errorf("key path: %s", kp.KeyPath)
	}
	if _, err := os.Stat(expectedPath); os.IsNotExist(err) {
		t.Fatal("key file not found on disk")
	}

	// DNS record should be valid format.
	dns := kp.DNSRecord()
	if !strings.HasPrefix(dns, "v=DKIM1; k=rsa; p=") {
		t.Errorf("invalid DNS record: %s", dns[:40])
	}

	// DNS name should be correct.
	if kp.DNSName() != "202603._domainkey.example.com" {
		t.Errorf("DNS name: %s", kp.DNSName())
	}
}

func TestReadPublicKey(t *testing.T) {
	dir := t.TempDir()

	kp, err := GenerateKey(dir, "test.com", "sel")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	pubDER, err := ReadPublicKey(kp.KeyPath)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(pubDER) == 0 {
		t.Fatal("empty public key")
	}
}

func TestDefaultSelector(t *testing.T) {
	sel := DefaultSelector()
	if len(sel) != 6 {
		t.Errorf("selector should be YYYYMM (6 chars), got: %s", sel)
	}
}

func TestSPFRecord(t *testing.T) {
	spf := SPFRecord("203.0.113.10")
	if !strings.Contains(spf, "ip4:203.0.113.10") {
		t.Errorf("SPF missing IP: %s", spf)
	}
	if !strings.Contains(spf, "v=spf1") {
		t.Errorf("SPF missing version: %s", spf)
	}
}

func TestDMARCRecord(t *testing.T) {
	dmarc := DMARCRecord("example.com")
	if !strings.Contains(dmarc, "v=DMARC1") {
		t.Errorf("DMARC missing version: %s", dmarc)
	}
	if !strings.Contains(dmarc, "dmarc@example.com") {
		t.Errorf("DMARC missing rua: %s", dmarc)
	}
}
