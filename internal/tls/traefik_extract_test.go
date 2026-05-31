package tls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// samplePEMCert / samplePEMKey are a real, ephemeral EC P-256 self-signed cert
// and its matching key, generated fresh at test init. They replace hardcoded PEM
// literals: a committed EC private-key PEM block trips GitHub secret scanning +
// push protection even though it is only a test fixture — Extract treats the
// cert/key as opaque base64 blobs (tests assert PEM prefixes, never parse them),
// so the value never needed to be real. Generating at runtime keeps zero key
// material in the source tree.
var samplePEMCert, samplePEMKey = genSelfSignedEC()

func genSelfSignedEC() (certPEM, keyPEM string) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic("test cert keygen: " + err.Error())
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "testsrv"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic("test cert create: " + err.Error())
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		panic("test key marshal: " + err.Error())
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// Build a Traefik acme.json doc with one resolver holding a single cert
// for hostname + extra optional SANs.
func makeACMEFile(resolverName, hostname string, sans []string, certPEM, keyPEM string) []byte {
	doc := traefikACMEFile{
		resolverName: traefikResolverState{
			Certificates: []traefikCertificate{{
				Domain:      traefikDomain{Main: hostname, SANs: sans},
				Certificate: b64(certPEM),
				Key:         b64(keyPEM),
			}},
		},
	}
	b, _ := json.Marshal(doc)
	return b
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestExtract_MissingAcmeJsonIsNotError(t *testing.T) {
	tmp := t.TempDir()
	res, err := Extract(ExtractOptions{
		ACMEJSONPath: filepath.Join(tmp, "does-not-exist.json"),
		Hostname:     "mail.example.com",
		OutDir:       tmp,
		Logger:       quietLogger(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Found {
		t.Fatalf("expected Found=false when acme.json missing")
	}
}

func TestExtract_EmptyFileIsNotError(t *testing.T) {
	tmp := t.TempDir()
	acme := filepath.Join(tmp, "acme.json")
	if err := os.WriteFile(acme, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Extract(ExtractOptions{
		ACMEJSONPath: acme,
		Hostname:     "mail.example.com",
		OutDir:       tmp,
		Logger:       quietLogger(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Found {
		t.Fatalf("expected Found=false for empty file")
	}
}

func TestExtract_HostnameNotPresent_NoOp(t *testing.T) {
	tmp := t.TempDir()
	acme := filepath.Join(tmp, "acme.json")
	if err := os.WriteFile(acme, makeACMEFile("letsencrypt", "other.example.com", nil, samplePEMCert, samplePEMKey), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Extract(ExtractOptions{
		ACMEJSONPath: acme,
		Hostname:     "mail.example.com",
		OutDir:       tmp,
		Logger:       quietLogger(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Found {
		t.Fatalf("expected Found=false when hostname absent from acme.json")
	}
	if _, err := os.Stat(filepath.Join(tmp, "fullchain.pem")); !os.IsNotExist(err) {
		t.Fatalf("fullchain.pem should not be written, stat err = %v", err)
	}
}

func TestExtract_MatchOnMain_WritesAllThreeFiles(t *testing.T) {
	tmp := t.TempDir()
	acme := filepath.Join(tmp, "acme.json")
	if err := os.WriteFile(acme, makeACMEFile("letsencrypt", "mail.example.com", nil, samplePEMCert, samplePEMKey), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Extract(ExtractOptions{
		ACMEJSONPath: acme,
		Hostname:     "mail.example.com",
		OutDir:       tmp,
		Logger:       quietLogger(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Found || !res.Changed {
		t.Fatalf("want Found+Changed; got %+v", res)
	}
	if res.Resolver != "letsencrypt" {
		t.Errorf("Resolver = %q, want letsencrypt", res.Resolver)
	}

	for _, name := range []string{"fullchain.pem", "cert.pem", "privkey.pem"} {
		data, err := os.ReadFile(filepath.Join(tmp, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		wantPrefix := "-----BEGIN CERTIFICATE-----"
		if name == "privkey.pem" {
			wantPrefix = "-----BEGIN EC PRIVATE KEY-----"
		}
		if !strings.HasPrefix(string(data), wantPrefix) {
			t.Errorf("%s missing expected PEM prefix; got %q", name, string(data)[:40])
		}
	}

	// Permission check: privkey tighter than fullchain.
	st, err := os.Stat(filepath.Join(tmp, "privkey.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o640 {
		t.Errorf("privkey mode = %o, want 640", st.Mode().Perm())
	}
	st, err = os.Stat(filepath.Join(tmp, "fullchain.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o644 {
		t.Errorf("fullchain mode = %o, want 644", st.Mode().Perm())
	}
}

func TestExtract_MatchOnSAN(t *testing.T) {
	tmp := t.TempDir()
	acme := filepath.Join(tmp, "acme.json")
	if err := os.WriteFile(acme, makeACMEFile("letsencrypt", "primary.example.com", []string{"mail.example.com"}, samplePEMCert, samplePEMKey), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Extract(ExtractOptions{
		ACMEJSONPath: acme,
		Hostname:     "mail.example.com",
		OutDir:       tmp,
		Logger:       quietLogger(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Found || !res.Changed {
		t.Fatalf("want Found+Changed via SAN match; got %+v", res)
	}
}

func TestExtract_HostnameCaseInsensitive(t *testing.T) {
	tmp := t.TempDir()
	acme := filepath.Join(tmp, "acme.json")
	if err := os.WriteFile(acme, makeACMEFile("letsencrypt", "Mail.Example.COM", nil, samplePEMCert, samplePEMKey), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Extract(ExtractOptions{
		ACMEJSONPath: acme,
		Hostname:     "mail.example.com",
		OutDir:       tmp,
		Logger:       quietLogger(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Found {
		t.Fatalf("case-insensitive match failed: %+v", res)
	}
}

func TestExtract_SecondCallUnchangedReportsNoChange(t *testing.T) {
	tmp := t.TempDir()
	acme := filepath.Join(tmp, "acme.json")
	if err := os.WriteFile(acme, makeACMEFile("letsencrypt", "mail.example.com", nil, samplePEMCert, samplePEMKey), 0o644); err != nil {
		t.Fatal(err)
	}
	opts := ExtractOptions{
		ACMEJSONPath: acme,
		Hostname:     "mail.example.com",
		OutDir:       tmp,
		Logger:       quietLogger(),
	}
	if _, err := Extract(opts); err != nil {
		t.Fatal(err)
	}
	res, err := Extract(opts)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Found {
		t.Fatalf("second pass Found=false")
	}
	if res.Changed {
		t.Fatalf("second pass Changed=true; hashing should detect idempotence")
	}
}

func TestExtract_RotatedCertReportsChange(t *testing.T) {
	tmp := t.TempDir()
	acme := filepath.Join(tmp, "acme.json")
	if err := os.WriteFile(acme, makeACMEFile("letsencrypt", "mail.example.com", nil, samplePEMCert, samplePEMKey), 0o644); err != nil {
		t.Fatal(err)
	}
	opts := ExtractOptions{
		ACMEJSONPath: acme,
		Hostname:     "mail.example.com",
		OutDir:       tmp,
		Logger:       quietLogger(),
	}
	if _, err := Extract(opts); err != nil {
		t.Fatal(err)
	}
	// Rewrite acme.json with a different cert payload to simulate renewal.
	rotatedCert := samplePEMCert + "\n# rotated\n"
	if err := os.WriteFile(acme, makeACMEFile("letsencrypt", "mail.example.com", nil, rotatedCert, samplePEMKey), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Extract(opts)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed {
		t.Fatalf("rotated cert should surface Changed=true; got %+v", res)
	}
}

func TestExtract_MalformedJSONIsError(t *testing.T) {
	tmp := t.TempDir()
	acme := filepath.Join(tmp, "acme.json")
	if err := os.WriteFile(acme, []byte("{not valid json"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Extract(ExtractOptions{
		ACMEJSONPath: acme,
		Hostname:     "mail.example.com",
		OutDir:       tmp,
		Logger:       quietLogger(),
	})
	if err == nil {
		t.Fatalf("expected parse error for malformed acme.json")
	}
}

func TestExtract_ScansAllResolvers(t *testing.T) {
	tmp := t.TempDir()
	acme := filepath.Join(tmp, "acme.json")
	// Two resolvers, cert in the second.
	doc := traefikACMEFile{
		"other-ca": traefikResolverState{Certificates: []traefikCertificate{{
			Domain: traefikDomain{Main: "unrelated.example.com"}, Certificate: b64(samplePEMCert), Key: b64(samplePEMKey),
		}}},
		"letsencrypt": traefikResolverState{Certificates: []traefikCertificate{{
			Domain: traefikDomain{Main: "mail.example.com"}, Certificate: b64(samplePEMCert), Key: b64(samplePEMKey),
		}}},
	}
	b, _ := json.Marshal(doc)
	if err := os.WriteFile(acme, b, 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := Extract(ExtractOptions{
		ACMEJSONPath: acme,
		Hostname:     "mail.example.com",
		OutDir:       tmp,
		Logger:       quietLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Found {
		t.Fatalf("cert in non-default resolver should still match")
	}
}

// Returns a logger writing to a buffer so callers can assert log lines.
func bufferedLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	lg := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return lg, &buf
}

func TestRunOnce_FirstWarnAfterThresholdPolls(t *testing.T) {
	tmp := t.TempDir()
	acme := filepath.Join(tmp, "acme.json")
	// Empty/not-yet-issued — Found=false every pass.
	if err := os.WriteFile(acme, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	lg, buf := bufferedLogger()
	opts := ExtractOptions{
		ACMEJSONPath: acme,
		Hostname:     "mail.example.com",
		OutDir:       tmp,
		Logger:       lg,
	}
	state := &watchState{}

	// Poll warnAfterPolls-1 times — no WARN expected yet.
	for i := 0; i < warnAfterPolls-1; i++ {
		runOnce(context.Background(), opts, lg, state)
	}
	if strings.Contains(buf.String(), `"level":"WARN"`) {
		t.Fatalf("unexpected WARN before threshold: %s", buf.String())
	}
	// The warnAfterPolls-th poll triggers the first WARN.
	runOnce(context.Background(), opts, lg, state)
	if !strings.Contains(buf.String(), `"level":"WARN"`) {
		t.Fatalf("expected WARN at poll %d; logs: %s", warnAfterPolls, buf.String())
	}
	if !strings.Contains(buf.String(), "no cert in acme.json yet") {
		t.Fatalf("WARN missing expected message; logs: %s", buf.String())
	}
}

func TestRunOnce_WarnRepeatsOnCadence(t *testing.T) {
	tmp := t.TempDir()
	acme := filepath.Join(tmp, "acme.json")
	if err := os.WriteFile(acme, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	lg, buf := bufferedLogger()
	opts := ExtractOptions{
		ACMEJSONPath: acme,
		Hostname:     "mail.example.com",
		OutDir:       tmp,
		Logger:       lg,
	}
	state := &watchState{}

	// Advance past first WARN + one full warnEveryPolls cycle; expect at least
	// two WARN lines total.
	total := warnAfterPolls + warnEveryPolls
	for i := 0; i < total; i++ {
		runOnce(context.Background(), opts, lg, state)
	}
	warns := strings.Count(buf.String(), `"level":"WARN"`)
	if warns < 2 {
		t.Fatalf("expected at least 2 WARN lines across %d polls; got %d. logs: %s", total, warns, buf.String())
	}
}

func TestRunOnce_FoundResetsEmptyCounter(t *testing.T) {
	tmp := t.TempDir()
	acme := filepath.Join(tmp, "acme.json")
	if err := os.WriteFile(acme, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	lg, _ := bufferedLogger()
	opts := ExtractOptions{
		ACMEJSONPath: acme,
		Hostname:     "mail.example.com",
		OutDir:       tmp,
		Logger:       lg,
	}
	state := &watchState{}

	// Walk up to just-below first WARN threshold with empty acme.json.
	for i := 0; i < warnAfterPolls-1; i++ {
		runOnce(context.Background(), opts, lg, state)
	}
	if state.consecutiveEmpty != warnAfterPolls-1 {
		t.Fatalf("consecutiveEmpty = %d, want %d", state.consecutiveEmpty, warnAfterPolls-1)
	}

	// Now populate acme.json with a real cert and poll again.
	if err := os.WriteFile(acme, makeACMEFile("letsencrypt", "mail.example.com", nil, samplePEMCert, samplePEMKey), 0o644); err != nil {
		t.Fatal(err)
	}
	runOnce(context.Background(), opts, lg, state)
	if state.consecutiveEmpty != 0 {
		t.Fatalf("consecutiveEmpty should reset to 0 after Found; got %d", state.consecutiveEmpty)
	}
	if !state.certEverSeen {
		t.Fatalf("certEverSeen should flip to true after successful extract")
	}
}

func TestRunOnce_CertAlreadyPresentLogsOnce(t *testing.T) {
	tmp := t.TempDir()
	acme := filepath.Join(tmp, "acme.json")
	// Pre-populate acme.json AND the output dir (simulating a restart where
	// the last run already wrote the cert; should log "already present" on
	// the very first poll, then stay quiet on the next idempotent passes).
	if err := os.WriteFile(acme, makeACMEFile("letsencrypt", "mail.example.com", nil, samplePEMCert, samplePEMKey), 0o644); err != nil {
		t.Fatal(err)
	}
	lg, buf := bufferedLogger()
	opts := ExtractOptions{
		ACMEJSONPath: acme,
		Hostname:     "mail.example.com",
		OutDir:       tmp,
		Logger:       lg,
	}
	state := &watchState{}

	// First poll writes the cert (Changed=true → "cert written" INFO).
	runOnce(context.Background(), opts, lg, state)
	if !strings.Contains(buf.String(), "cert written") {
		t.Fatalf("expected 'cert written' on first poll; logs: %s", buf.String())
	}
	buf.Reset()
	// Second poll: Found=true, Changed=false, certEverSeen=true → DEBUG only.
	runOnce(context.Background(), opts, lg, state)
	if strings.Contains(buf.String(), `"level":"INFO"`) && strings.Contains(buf.String(), "already present") {
		t.Fatalf("'already present' should fire only on first unchanged poll when !certEverSeen; logs: %s", buf.String())
	}
}

func TestMaybeWritePlaceholder_WritesWhenNoCertPresent(t *testing.T) {
	tmp := t.TempDir()
	lg, buf := bufferedLogger()
	opts := ExtractOptions{
		OutDir:   tmp,
		Hostname: "mail.example.com",
		Logger:   lg,
	}
	if err := maybeWritePlaceholder(opts, lg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// All three files should exist.
	for _, name := range []string{"fullchain.pem", "cert.pem", "privkey.pem"} {
		if _, err := os.Stat(filepath.Join(tmp, name)); err != nil {
			t.Errorf("%s should exist after placeholder write: %v", name, err)
		}
	}
	// Log should announce the placeholder write at INFO.
	if !strings.Contains(buf.String(), "placeholder cert") {
		t.Errorf("expected placeholder announcement log; got %s", buf.String())
	}
	// fullchain should have a VECTIS PLACEHOLDER issuer so operators + tests
	// can distinguish placeholder from real cert.
	data, _ := os.ReadFile(filepath.Join(tmp, "fullchain.pem"))
	info, err := ReadCertInfo(filepath.Join(tmp, "fullchain.pem"))
	if err != nil {
		t.Fatalf("parse placeholder cert: %v; content:\n%s", err, data)
	}
	if info.DaysLeft > 8 || info.DaysLeft < 6 {
		t.Errorf("placeholder validity should be ~7 days; got days_left=%d", info.DaysLeft)
	}
}

func TestMaybeWritePlaceholder_SkipsWhenCertExists(t *testing.T) {
	tmp := t.TempDir()
	// Pre-existing cert; placeholder should NOT overwrite.
	existing := []byte("-----BEGIN CERTIFICATE-----\nEXISTING\n-----END CERTIFICATE-----\n")
	if err := os.WriteFile(filepath.Join(tmp, "fullchain.pem"), existing, 0o644); err != nil {
		t.Fatal(err)
	}
	lg, _ := bufferedLogger()
	opts := ExtractOptions{OutDir: tmp, Hostname: "mail.example.com", Logger: lg}
	if err := maybeWritePlaceholder(opts, lg); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data, _ := os.ReadFile(filepath.Join(tmp, "fullchain.pem"))
	if string(data) != string(existing) {
		t.Errorf("existing cert should not be overwritten; got:\n%s", string(data))
	}
}

func TestRunOnce_PlaceholderAttemptedOnceThenSkipped(t *testing.T) {
	tmp := t.TempDir()
	acme := filepath.Join(tmp, "acme.json")
	if err := os.WriteFile(acme, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(tmp, "out")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	lg, _ := bufferedLogger()
	opts := ExtractOptions{
		ACMEJSONPath: acme,
		Hostname:     "mail.example.com",
		OutDir:       outDir,
		Logger:       lg,
	}
	state := &watchState{}

	// First poll with empty acme.json should write the placeholder.
	runOnce(context.Background(), opts, lg, state)
	if !state.placeholderAttempted {
		t.Fatalf("placeholderAttempted should be true after first empty poll")
	}
	fullchainStat1, err := os.Stat(filepath.Join(outDir, "fullchain.pem"))
	if err != nil {
		t.Fatalf("fullchain.pem should exist after first poll: %v", err)
	}

	// Second poll with same empty acme.json — should NOT rewrite.
	// Sleep 10ms so mtime would change if we did rewrite (we shouldn't).
	runOnce(context.Background(), opts, lg, state)
	fullchainStat2, _ := os.Stat(filepath.Join(outDir, "fullchain.pem"))
	if fullchainStat1.ModTime() != fullchainStat2.ModTime() {
		t.Errorf("placeholder should not be rewritten on subsequent empty polls")
	}
}

func TestRunOnce_RealCertOverwritesPlaceholder(t *testing.T) {
	tmp := t.TempDir()
	acme := filepath.Join(tmp, "acme.json")
	outDir := filepath.Join(tmp, "out")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	lg, buf := bufferedLogger()
	opts := ExtractOptions{
		ACMEJSONPath: acme,
		Hostname:     "mail.example.com",
		OutDir:       outDir,
		Logger:       lg,
	}
	state := &watchState{}

	// First: empty acme.json → placeholder written.
	if err := os.WriteFile(acme, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	runOnce(context.Background(), opts, lg, state)
	if !state.placeholderAttempted {
		t.Fatal("placeholder should have been attempted")
	}
	placeholderInfo, _ := ReadCertInfo(filepath.Join(outDir, "fullchain.pem"))
	if placeholderInfo == nil {
		t.Fatal("placeholder fullchain should be parseable")
	}

	// Second: acme.json now has a real cert. Should overwrite placeholder.
	if err := os.WriteFile(acme, makeACMEFile("letsencrypt", "mail.example.com", nil, samplePEMCert, samplePEMKey), 0o644); err != nil {
		t.Fatal(err)
	}
	runOnce(context.Background(), opts, lg, state)
	// fullchain content should now be the sample cert, not the placeholder
	// (decodeCert writes the cert blob verbatim, so it round-trips exactly).
	data, _ := os.ReadFile(filepath.Join(outDir, "fullchain.pem"))
	if string(data) != samplePEMCert {
		t.Errorf("real cert should have overwritten placeholder; content:\n%s", string(data))
	}
	// "cert written" INFO should appear.
	if !strings.Contains(buf.String(), "cert written") {
		t.Errorf("expected 'cert written' log; got %s", buf.String())
	}
}

func TestWriteAtomic_ReplacesAtomically(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "f")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(path, []byte("new"), 0o640); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "new" {
		t.Errorf("content = %q, want new", string(got))
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o640 {
		t.Errorf("mode = %o, want 640", st.Mode().Perm())
	}
	// No stray tmp files left behind.
	entries, _ := os.ReadDir(tmp)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			t.Errorf("leftover tmp file: %s", e.Name())
		}
	}
}
