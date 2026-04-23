package tls

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Traefik writes its ACME state as a JSON document keyed by certResolver
// name. The shape is stable across v2.x and v3.x — one object per resolver,
// each holding an Account + a Certificates slice.
type traefikACMEFile map[string]traefikResolverState

type traefikResolverState struct {
	Certificates []traefikCertificate `json:"Certificates"`
}

type traefikCertificate struct {
	Domain      traefikDomain `json:"domain"`
	Certificate string        `json:"certificate"` // base64-encoded PEM fullchain
	Key         string        `json:"key"`         // base64-encoded PEM private key
}

type traefikDomain struct {
	Main string   `json:"main"`
	SANs []string `json:"sans"`
}

// ExtractOptions configures a single cert-extraction pass (or a watch loop).
type ExtractOptions struct {
	ACMEJSONPath   string        // e.g. /var/traefik/acme/acme.json
	Hostname       string        // cert whose domain.main or sans matches this
	OutDir         string        // e.g. /etc/ssl/mail
	ReloadPostfix  string        // container name to SIGHUP on change, "" to skip
	ReloadDovecot  string        // container name to SIGHUP on change, "" to skip
	PollInterval   time.Duration // only used by Watch; defaults to 30s
	Logger         *slog.Logger
}

// matchedCert returns the first certificate from acme.json whose main or
// SAN matches hostname. Traefik v3 may have multiple resolvers — we scan
// all of them so operators can rename the resolver without updating us.
func (c traefikACMEFile) matchedCert(hostname string) (*traefikCertificate, string, bool) {
	hostname = strings.ToLower(hostname)
	for resolverName, resolver := range c {
		for i := range resolver.Certificates {
			cert := &resolver.Certificates[i]
			if strings.ToLower(cert.Domain.Main) == hostname {
				return cert, resolverName, true
			}
			for _, san := range cert.Domain.SANs {
				if strings.ToLower(san) == hostname {
					return cert, resolverName, true
				}
			}
		}
	}
	return nil, "", false
}

// decodeCert returns (fullchainPEM, privkeyPEM) from a base64-encoded
// Traefik cert entry. Traefik stores both already as PEM inside base64.
func decodeCert(cert *traefikCertificate) ([]byte, []byte, error) {
	fullchain, err := base64.StdEncoding.DecodeString(cert.Certificate)
	if err != nil {
		return nil, nil, fmt.Errorf("decode certificate: %w", err)
	}
	privkey, err := base64.StdEncoding.DecodeString(cert.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("decode key: %w", err)
	}
	return fullchain, privkey, nil
}

// writeAtomic writes data to path via a sibling tmp file + rename so
// readers never observe a partial file. mode is applied after close.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-"+filepath.Base(path)+"-*")
	if err != nil {
		return fmt.Errorf("create tmp: %w", err)
	}
	tmpPath := tmp.Name()
	// Best-effort cleanup on failure paths below.
	defer func() { _ = os.Remove(tmpPath) }()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync tmp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close tmp: %w", err)
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		return fmt.Errorf("chmod tmp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename tmp: %w", err)
	}
	return nil
}

// ExtractResult reports what a single extraction pass did.
type ExtractResult struct {
	Found     bool   // cert for hostname present in acme.json
	Changed   bool   // cert content differed from on-disk and was written
	Resolver  string // traefik certResolver name the cert was found under
	CertHash  string // sha256 of fullchain+privkey after this pass
}

// Extract performs one pass: read acme.json, locate the cert, write atomically.
// Returns Found=false without error if acme.json is missing or empty — the
// watch loop treats that as "traefik hasn't issued yet, keep polling."
func Extract(opts ExtractOptions) (ExtractResult, error) {
	var res ExtractResult

	raw, err := os.ReadFile(opts.ACMEJSONPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return res, nil
		}
		return res, fmt.Errorf("read acme.json: %w", err)
	}
	// Traefik writes the file empty ({}) or with empty Certificates before
	// the first challenge completes — treat those as "not yet issued".
	if len(raw) == 0 {
		return res, nil
	}

	var parsed traefikACMEFile
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return res, fmt.Errorf("parse acme.json: %w", err)
	}

	cert, resolver, ok := parsed.matchedCert(opts.Hostname)
	if !ok {
		return res, nil
	}
	res.Found = true
	res.Resolver = resolver

	fullchain, privkey, err := decodeCert(cert)
	if err != nil {
		return res, err
	}

	newHash := hashBytes(fullchain, privkey)
	res.CertHash = newHash

	oldHash, _ := hashExistingFiles(
		filepath.Join(opts.OutDir, "fullchain.pem"),
		filepath.Join(opts.OutDir, "privkey.pem"),
	)
	if oldHash == newHash {
		return res, nil
	}

	if err := os.MkdirAll(opts.OutDir, 0o755); err != nil {
		return res, fmt.Errorf("mkdir out: %w", err)
	}
	if err := writeAtomic(filepath.Join(opts.OutDir, "fullchain.pem"), fullchain, 0o644); err != nil {
		return res, err
	}
	// cert.pem mirrors fullchain.pem — some consumers look for either name.
	if err := writeAtomic(filepath.Join(opts.OutDir, "cert.pem"), fullchain, 0o644); err != nil {
		return res, err
	}
	if err := writeAtomic(filepath.Join(opts.OutDir, "privkey.pem"), privkey, 0o640); err != nil {
		return res, err
	}

	res.Changed = true
	return res, nil
}

func hashBytes(parts ...[]byte) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func hashExistingFiles(paths ...string) (string, error) {
	h := sha256.New()
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return "", err
		}
		h.Write(data)
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// reloadMailServices sends SIGHUP via `docker kill` to the configured
// postfix/dovecot containers. Called only when Changed=true. Failures are
// logged, not fatal — a stale in-memory cert is better than crashing the
// extractor and losing the watch loop entirely.
func reloadMailServices(ctx context.Context, opts ExtractOptions) {
	for _, name := range []string{opts.ReloadPostfix, opts.ReloadDovecot} {
		if name == "" {
			continue
		}
		cmd := exec.CommandContext(ctx, "docker", "kill", "--signal=HUP", name)
		out, err := cmd.CombinedOutput()
		if err != nil {
			opts.Logger.Warn("reload signal failed",
				"container", name,
				"error", err,
				"output", strings.TrimSpace(string(out)),
			)
			continue
		}
		opts.Logger.Info("sent SIGHUP", "container", name)
	}
}

// Watch runs the extraction loop until ctx is cancelled. PollInterval
// defaults to 30s. Logs each pass at DEBUG on no-op, INFO on change.
func Watch(ctx context.Context, opts ExtractOptions) error {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = 30 * time.Second
	}
	log := opts.Logger.With(
		"hostname", opts.Hostname,
		"acme_json", opts.ACMEJSONPath,
		"out_dir", opts.OutDir,
	)

	log.Info("cert-extractor starting", "poll_interval", opts.PollInterval.String())

	// Immediate pass so startup doesn't idle for a full poll interval.
	runOnce(ctx, opts, log)

	ticker := time.NewTicker(opts.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Info("cert-extractor stopping")
			return nil
		case <-ticker.C:
			runOnce(ctx, opts, log)
		}
	}
}

func runOnce(ctx context.Context, opts ExtractOptions, log *slog.Logger) {
	res, err := Extract(opts)
	if err != nil {
		log.Error("extract failed", "error", err)
		return
	}
	if !res.Found {
		log.Debug("cert not yet available in acme.json")
		return
	}
	if !res.Changed {
		log.Debug("cert unchanged", "resolver", res.Resolver)
		return
	}
	log.Info("cert written",
		"resolver", res.Resolver,
		"cert_hash", res.CertHash[:12],
	)
	reloadMailServices(ctx, opts)
}
