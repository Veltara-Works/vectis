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
	ACMEJSONPath  string        // e.g. /var/traefik/acme/acme.json
	Hostname      string        // cert whose domain.main or sans matches this
	OutDir        string        // e.g. /etc/ssl/mail
	ReloadPostfix string        // container name to SIGHUP on change, "" to skip
	ReloadDovecot string        // container name to SIGHUP on change, "" to skip
	PollInterval  time.Duration // only used by Watch; defaults to 30s
	Logger        *slog.Logger
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
	Found    bool   // cert for hostname present in acme.json
	Changed  bool   // cert content differed from on-disk and was written
	Resolver string // traefik certResolver name the cert was found under
	CertHash string // sha256 of fullchain+privkey after this pass
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

	if err := os.MkdirAll(opts.OutDir, 0o750); err != nil {
		return res, fmt.Errorf("mkdir out: %w", err)
	}
	// MkdirAll only sets the mode when it creates the dir; on an existing install
	// OutDir predates this hardening and keeps its old (0755) mode, so enforce
	// 0750 explicitly (Copilot review, #149). Best-effort — a chmod failure must
	// not abort a cert write.
	_ = os.Chmod(opts.OutDir, 0o750)
	// The cert triple (fullchain/cert/privkey) is written as three separate
	// atomic renames — a POSIX filesystem offers no way to swap three files as
	// one atomic set (TLS-3). Each writeAtomic is itself atomic + fsync-durable,
	// and consistency across the triple is guaranteed two other ways: (1) the
	// SIGHUP reload fires only after all three writes succeed (reloadMailServices
	// runs post-write on Changed=true), so no consumer is signalled to read a
	// half-written pair; (2) a crash mid-triple self-heals on the next poll —
	// hashExistingFiles(fullchain, privkey) won't match newHash, so the triple is
	// rewritten. The only residual is a service that restarts of its own accord
	// inside the sub-second window between the fullchain and privkey renames; it
	// would load a mismatched pair and fail its own TLS startup, then recover on
	// the next poll. Bounded and self-correcting; a true fix needs a single
	// combined file, which consumers don't support.
	if err := writeAtomic(filepath.Join(opts.OutDir, "fullchain.pem"), fullchain, 0o644); err != nil {
		return res, err
	}
	// cert.pem mirrors fullchain.pem — some consumers look for either name.
	if err := writeAtomic(filepath.Join(opts.OutDir, "cert.pem"), fullchain, 0o644); err != nil {
		return res, err
	}
	// 0600 to match the self-signed placeholder (certs.go) — the private key is
	// never group/world readable. All consumers run as root, so this loses no
	// access; it's defence-in-depth + consistency (TLS-1).
	if err := writeAtomic(filepath.Join(opts.OutDir, "privkey.pem"), privkey, 0o600); err != nil {
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

// reloadMailServices brings the configured postfix/dovecot containers to a
// running state with the freshly-written cert loaded. Called only when
// Changed=true. Failures are logged, not fatal — a stale in-memory cert is
// better than crashing the extractor and losing the watch loop entirely.
//
// Order matters: `docker container start` first (idempotent — silent no-op
// on a running container, restart on an Exited one), THEN SIGHUP. Why:
// during a fresh `vectis install` on a `letsencrypt` provider, dovecot
// crashloops 5-7× before Traefik issues + cert-extractor populates the
// fullchain. Docker's restart-policy backoff can leave it in state=Exited
// at the moment we write the cert, and `docker kill --signal=HUP` against
// an Exited container fails silently — the operator is left with a stack
// where IMAPS/POP3S never come up. The start guarantees the container is
// running; the SIGHUP then triggers a config reload for the *already*
// running case (where startup happened before the cert rotated).
// (Found by 2026-05-10 fresh-VPS §10 walkthrough — see
// docs/notes/2026-05-10-fresh-vps-walkthrough-v0.1.10.md FINDING #1.)
func reloadMailServices(ctx context.Context, opts ExtractOptions) {
	for _, name := range []string{opts.ReloadPostfix, opts.ReloadDovecot} {
		if name == "" {
			continue
		}
		// Bound each docker invocation with its own timeout (TLS-2). Without it
		// the commands inherit only the long-lived Watch ctx, so a wedged docker
		// daemon would block CombinedOutput() indefinitely and stall the whole
		// cert-rotation watch loop. A per-command deadline lets a hung reload
		// fail loudly and the loop keep polling.
		startCtx, cancelStart := context.WithTimeout(ctx, dockerCmdTimeout)
		startCmd := exec.CommandContext(startCtx, "docker", "container", "start", name)
		if out, err := startCmd.CombinedOutput(); err != nil {
			opts.Logger.Warn("docker container start failed",
				"container", name,
				"error", err,
				"output", strings.TrimSpace(string(out)),
			)
			// Do not skip the SIGHUP — `start` may have failed because the
			// container is already running, in which case the HUP is the
			// reload path we actually want.
		}
		cancelStart()
		killCtx, cancelKill := context.WithTimeout(ctx, dockerCmdTimeout)
		killCmd := exec.CommandContext(killCtx, "docker", "kill", "--signal=HUP", name)
		out, err := killCmd.CombinedOutput()
		cancelKill()
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
// defaults to 30s.
//
// Log cadence is designed around the two realistic failure modes:
//
//   - Happy path: Traefik issues in <~90s, cert lands on poll 1-3. We log
//     INFO on first write and then stay quiet until the cert rotates.
//
//   - Stuck path: Traefik never issues (rate limit, bad DNS, :80 blocked,
//     wrong email in acme account). Poll loop would otherwise go silent
//     forever. So we:
//
//   - emit a WARN after `warnAfterPolls` (default 10 polls = 5min) telling
//     the operator where to look, and repeat it every `warnEveryPolls`
//     (default 20 polls = 10min) so the signal doesn't get buried
//
//   - emit a plain INFO heartbeat every `heartbeatEveryPolls` so operators
//     watching `docker logs -f` have evidence the extractor is alive even
//     during the silent-but-waiting phase
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

	state := &watchState{}

	// Immediate pass so startup doesn't idle for a full poll interval.
	runOnce(ctx, opts, log, state)

	ticker := time.NewTicker(opts.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Info("cert-extractor stopping", "total_polls", state.totalPolls)
			return nil
		case <-ticker.C:
			runOnce(ctx, opts, log, state)
		}
	}
}

// watchState tracks counters across poll iterations so the logger can
// escalate / throttle based on how long the extractor has been waiting.
type watchState struct {
	totalPolls           int
	consecutiveEmpty     int  // polls since last successful Found=true
	certEverSeen         bool // true once we've written or confirmed a cert at least once
	placeholderAttempted bool // true once we've tried the bootstrap placeholder write (success or fail)
}

// maybeWritePlaceholder writes a short-lived self-signed cert into OutDir
// if no fullchain.pem is already present there. A no-op when a cert
// already exists (either a previous placeholder or a real cert from a
// prior run).
func maybeWritePlaceholder(opts ExtractOptions, log *slog.Logger) error {
	fullchain := filepath.Join(opts.OutDir, "fullchain.pem")
	if _, err := os.Stat(fullchain); err == nil {
		log.Debug("placeholder skipped — cert already present", "path", fullchain)
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat existing cert: %w", err)
	}

	if opts.Hostname == "" || opts.OutDir == "" {
		return fmt.Errorf("hostname or outdir empty; refusing placeholder write")
	}

	log.Info("writing self-signed placeholder cert so dovecot can start",
		"hostname", opts.Hostname,
		"out_dir", opts.OutDir,
		"validity_days", 7,
		"note", "will be replaced when Traefik issues the real cert",
	)
	if err := GenerateSelfSignedPlaceholder(opts.OutDir, opts.Hostname); err != nil {
		return fmt.Errorf("generate placeholder: %w", err)
	}
	return nil
}

const (
	// Emit first WARN about a missing cert after this many consecutive
	// Found=false polls. At the default 30s poll, 10 = ~5 min — long enough
	// that a normal LE issuance (usually 30-90s) would have landed but
	// short enough that an operator watching logs sees the signal promptly.
	warnAfterPolls = 10
	// Repeat the WARN every this many polls (default 30s × 20 = 10 min).
	warnEveryPolls = 20
	// Emit an INFO heartbeat every this many polls (default 30s × 60 = 30 min)
	// so operators tailing logs can tell the extractor is still alive even
	// during long-silent waits (e.g. while rate-limited).
	heartbeatEveryPolls = 60
	// Per-command deadline for the `docker start`/`docker kill` reload calls
	// (TLS-2). Generous enough for a healthy daemon (these are near-instant),
	// tight enough that a wedged daemon can't hang the watch loop for long.
	dockerCmdTimeout = 30 * time.Second
)

func runOnce(ctx context.Context, opts ExtractOptions, log *slog.Logger, state *watchState) {
	state.totalPolls++

	res, err := Extract(opts)
	if err != nil {
		log.Error("extract failed", "error", err)
		return
	}

	if !res.Found {
		state.consecutiveEmpty++
		// No real cert yet — if the mail-certs directory is also empty,
		// dovecot will crashloop with exit 89 ("ssl_cert: Can't open
		// fullchain.pem") every 30s under Docker's restart policy. Write
		// a short-lived self-signed placeholder so dovecot can at least
		// start. When the real cert arrives, the content-hash check in
		// Extract() detects the difference and SIGHUPs dovecot+postfix
		// to reload.
		if !state.placeholderAttempted {
			state.placeholderAttempted = true
			if err := maybeWritePlaceholder(opts, log); err != nil {
				log.Warn("placeholder cert write failed", "error", err)
			}
		}
		// First WARN: the moment we cross warnAfterPolls.
		if state.consecutiveEmpty == warnAfterPolls {
			log.Warn("no cert in acme.json yet — Traefik has not issued",
				"consecutive_empty_polls", state.consecutiveEmpty,
				"hint", "check `docker logs vectis-traefik | grep -iE 'acme|error|ratelimit'` — common causes: :80 unreachable, wrong DNS, LE rate-limited, bogus tls.email",
			)
		} else if state.consecutiveEmpty > warnAfterPolls &&
			(state.consecutiveEmpty-warnAfterPolls)%warnEveryPolls == 0 {
			// Repeat WARN every warnEveryPolls past the first one.
			log.Warn("still no cert in acme.json",
				"consecutive_empty_polls", state.consecutiveEmpty,
			)
		} else if state.totalPolls%heartbeatEveryPolls == 0 {
			// Lower-volume heartbeat when we're not already WARNing.
			log.Info("heartbeat — still watching acme.json",
				"total_polls", state.totalPolls,
				"cert_ever_seen", state.certEverSeen,
			)
		} else {
			log.Debug("cert not yet available in acme.json",
				"consecutive_empty_polls", state.consecutiveEmpty,
			)
		}
		return
	}

	// res.Found == true from here on: reset the no-cert counter.
	if state.consecutiveEmpty > 0 {
		log.Info("cert now available after wait",
			"consecutive_empty_polls_before_found", state.consecutiveEmpty,
		)
	}
	state.consecutiveEmpty = 0

	if !res.Changed {
		// Cert is present and matches what's on disk. On the very first
		// confirm-unchanged after boot, let operators know the pipeline is
		// warm so they don't assume "no log lines = nothing happening".
		if !state.certEverSeen {
			log.Info("cert already present on disk and matches acme.json",
				"resolver", res.Resolver,
				"cert_hash", res.CertHash[:12],
			)
		} else if state.totalPolls%heartbeatEveryPolls == 0 {
			log.Info("heartbeat — cert unchanged",
				"total_polls", state.totalPolls,
				"resolver", res.Resolver,
			)
		} else {
			log.Debug("cert unchanged", "resolver", res.Resolver)
		}
		state.certEverSeen = true
		return
	}

	log.Info("cert written",
		"resolver", res.Resolver,
		"cert_hash", res.CertHash[:12],
	)
	state.certEverSeen = true
	reloadMailServices(ctx, opts)
}
