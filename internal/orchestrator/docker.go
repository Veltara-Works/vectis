package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// DockerManager handles container lifecycle operations via the docker CLI.
// All Vectis containers are prefixed with "vectis-".
type DockerManager struct {
	cfg    Config
	logger *slog.Logger
}

// NewDockerManager creates a DockerManager.
func NewDockerManager(cfg Config, logger *slog.Logger) *DockerManager {
	return &DockerManager{
		cfg:    cfg,
		logger: logger,
	}
}

// containerName returns the Docker container name for a Vectis service.
func containerName(service string) string {
	return "vectis-" + service
}

// PullImages pulls container images in parallel for the given services.
// Services not defined in the compose file are skipped. Services whose image
// reference is a locally-built tag (no registry hostname, e.g. "vectis-api:dev")
// are also skipped — pulling them would fail with "denied" against ghcr.io.
// Each remaining pull is bounded by Config.ImagePullTimeout.
func (dm *DockerManager) PullImages(ctx context.Context, services []string) error {
	defined, err := dm.composeServices(ctx)
	if err != nil {
		return fmt.Errorf("enumerate compose services: %w", err)
	}

	images, err := dm.composeImages(ctx)
	if err != nil {
		return fmt.Errorf("enumerate compose images: %w", err)
	}

	var toPull []string
	for _, svc := range services {
		if !defined[svc] {
			dm.logger.Info("skipping pull: service not defined in compose", "service", svc)
			continue
		}
		img := images[svc]
		if isLocalImageRef(img) {
			dm.logger.Info("skipping pull: local image reference", "service", svc, "image", img)
			continue
		}
		toPull = append(toPull, svc)
	}

	if len(toPull) == 0 {
		dm.logger.Info("pulling images: nothing to pull after filtering")
		return nil
	}

	dm.logger.Info("pulling images", "services", toPull)

	var (
		mu   sync.Mutex
		errs []string
		wg   sync.WaitGroup
	)

	for _, svc := range toPull {
		wg.Add(1)
		go func(service string) {
			defer wg.Done()

			pullCtx, cancel := context.WithTimeout(ctx, dm.cfg.ImagePullTimeout)
			defer cancel()

			if err := dm.pullImage(pullCtx, service); err != nil {
				mu.Lock()
				errs = append(errs, fmt.Sprintf("%s: %v", service, err))
				mu.Unlock()
			}
		}(svc)
	}

	wg.Wait()

	if len(errs) > 0 {
		return fmt.Errorf("image pull failures: %s", strings.Join(errs, "; "))
	}
	return nil
}

// isLocalImageRef reports whether an image reference points to a locally-built
// image rather than a remote registry. Any reference without a dotted hostname
// before the first slash (or with no slash at all) is treated as local: Docker
// would default such refs to Docker Hub, which for our services means "this is
// our locally-built :dev tag". Empty strings are treated as local (skip pull).
func isLocalImageRef(ref string) bool {
	if ref == "" {
		return true
	}
	slash := strings.Index(ref, "/")
	if slash < 0 {
		// No slash at all → "name:tag" form → locally built or Docker Hub library.
		return true
	}
	host := ref[:slash]
	// Registry hostnames always contain a "." (ghcr.io, docker.io, quay.io) or
	// a ":" for a port, or are literally "localhost".
	if strings.ContainsAny(host, ".:") || host == "localhost" {
		return false
	}
	// e.g. "library/postgres" — treat as Docker Hub official, pull.
	return false
}

// composeServices returns the set of service names defined in the compose file.
func (dm *DockerManager) composeServices(ctx context.Context) (map[string]bool, error) {
	args := append([]string{"compose"}, dm.cfg.composeFileArgs()...)
	args = append(args, "config", "--services")
	cmd := exec.CommandContext(ctx, "docker", args...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("docker compose config --services: %w", err)
	}

	out := make(map[string]bool)
	for _, line := range strings.Split(strings.TrimSpace(stdout.String()), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out[line] = true
		}
	}
	return out, nil
}

// composeImages returns the image reference per service as defined in the
// compose file. Maps service name → image (e.g. "vectis-api:dev").
func (dm *DockerManager) composeImages(ctx context.Context) (map[string]string, error) {
	args := append([]string{"compose"}, dm.cfg.composeFileArgs()...)
	args = append(args, "config", "--format", "json")
	cmd := exec.CommandContext(ctx, "docker", args...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("docker compose config --format json: %w", err)
	}

	var parsed struct {
		Services map[string]struct {
			Image string `json:"image"`
		} `json:"services"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		return nil, fmt.Errorf("parse compose json: %w", err)
	}

	out := make(map[string]string, len(parsed.Services))
	for name, svc := range parsed.Services {
		out[name] = svc.Image
	}
	return out, nil
}

// pullImage pulls the image for a single service using docker compose pull.
func (dm *DockerManager) pullImage(ctx context.Context, service string) error {
	dm.logger.Info("pulling image", "service", service)

	args := append([]string{"compose"}, dm.cfg.composeFileArgs()...)
	args = append(args, "pull", service)
	cmd := exec.CommandContext(ctx, "docker", args...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker compose pull %s: %w: %s", service, err, string(output))
	}

	dm.logger.Info("image pulled", "service", service)
	return nil
}

// PullImageRef pulls an explicit image reference (e.g. the target release's api
// image for render-from-target), independent of the compose file — at the point
// of use the compose file may still carry the OLD tags, so `docker compose pull`
// can't reach the new image. Uses a plain `docker pull` with its own timeout.
func (dm *DockerManager) PullImageRef(ctx context.Context, imageRef string, timeout time.Duration) error {
	if imageRef == "" {
		return fmt.Errorf("PullImageRef: empty image reference")
	}
	pullCtx := ctx
	if timeout > 0 {
		var cancel context.CancelFunc
		pullCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	dm.logger.Info("pulling image ref", "image", imageRef)
	cmd := exec.CommandContext(pullCtx, "docker", "pull", imageRef)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker pull %s: %w: %s", imageRef, err, strings.TrimSpace(string(output)))
	}
	dm.logger.Info("image ref pulled", "image", imageRef)
	return nil
}

// ── Image provenance verification (REL-3 Part B, defence-in-depth) ──────────
//
// The vectis-* images are signed in CI by the release.yml workflow (Sigstore
// keyless / OIDC), pinned to their immutable manifest digest. On the host, the
// orchestrator additionally runs cosign — before recreating the stack — to
// verify each pulled image carries a valid signature from OUR release workflow.
// This layers provenance on top of the digest pin (Part A): the Ed25519-signed
// release manifest already guarantees we run exactly the bytes it names; cosign
// proves those bytes were built + signed by the release pipeline.

const (
	// cosignImage is the Sigstore cosign container used for host-side verify.
	// Digest-pinned so the verifier itself can't be swapped via a floating tag
	// (a mutable cosign would defeat the point). MANUALLY maintained — bump the
	// tag and digest together; resolve the new digest with:
	//   docker buildx imagetools inspect ghcr.io/sigstore/cosign/cosign:<tag> --format '{{.Manifest.Digest}}'
	// NB the image path is .../cosign/cosign (the bare .../cosign repo 404s).
	cosignImage = "ghcr.io/sigstore/cosign/cosign:v3.0.6@sha256:de9c65609e6bde17e6b48de485ee788407c9502fa08b8f4459f595b21f56cd00"

	// cosignCertIdentityRegexp is the Sigstore certificate SAN a genuine vectis
	// image signature must match: the release.yml workflow at a tag ref. Kept in
	// lockstep with .github/workflows/release.yml + docs/notes/verifying-downloads.md.
	cosignCertIdentityRegexp = `^https://github\.com/Veltara-Works/vectis/\.github/workflows/release\.yml@refs/tags/`
	// cosignCertOIDCIssuer is GitHub Actions' OIDC token issuer.
	cosignCertOIDCIssuer = "https://token.actions.githubusercontent.com"
)

// provenanceTarget is one image the verify pass will check.
type provenanceTarget struct {
	Service  string
	ImageRef string // ghcr.io/veltara-works/vectis-<svc>@sha256:<digest>
}

// vectisProvenanceTargets maps Plan.ImageDigests (service → sha256:<digest>) to
// the vectis-* image refs to verify, in stable service order. Entries whose
// digest isn't a sha256:… ref are dropped (can't be content-verified). Split
// out from VerifyImageProvenance so the selection logic is unit-testable without
// shelling out to docker.
func vectisProvenanceTargets(digests map[string]string) []provenanceTarget {
	svcs := make([]string, 0, len(digests))
	for svc := range digests {
		svcs = append(svcs, svc)
	}
	sort.Strings(svcs)

	targets := make([]provenanceTarget, 0, len(svcs))
	for _, svc := range svcs {
		digest := digests[svc]
		if !strings.HasPrefix(digest, "sha256:") {
			continue
		}
		targets = append(targets, provenanceTarget{
			Service:  svc,
			ImageRef: releaseServicePrefix + svc + "@" + digest,
		})
	}
	return targets
}

// cosignVerifyArgs builds the `docker run` argv that verifies one image ref with
// the pinned cosign container against the release-workflow identity. Pure so the
// exact flags stay under test.
func cosignVerifyArgs(imageRef string) []string {
	return []string{
		"run", "--rm", cosignImage,
		"verify",
		"--certificate-identity-regexp", cosignCertIdentityRegexp,
		"--certificate-oidc-issuer", cosignCertOIDCIssuer,
		imageRef,
	}
}

// VerifyImageProvenance verifies each vectis-* image's Sigstore signature via the
// pinned cosign container, keyed off Plan.ImageDigests, before the stack is
// recreated (Apply Phase 4.1.5).
//
// Best-effort by design — it never returns an error and never blocks Apply. Any
// failure (cosign image unpullable, Rekor/Fulcio unreachable on an air-gapped
// or DR host, or a verify error) is logged; the Apply proceeds because the
// digest pin (Part A) is the hard integrity guarantee and must not be gated on
// transparency-log availability. Bricking updates or DR on a provenance-service
// outage would be a worse failure than proceeding on already-authenticated
// bytes. A tag-only pin (empty/nil digests) is a no-op with an info log.
//
// Only vectis-* images are checked; third-party images aren't signed by our
// workflow (they're integrity-pinned by digest in the compose template instead).
func (dm *DockerManager) VerifyImageProvenance(ctx context.Context, digests map[string]string) {
	targets := vectisProvenanceTargets(digests)
	if len(targets) == 0 {
		dm.logger.Info("image provenance verification skipped: no manifest digests to verify (tag-only pin)")
		return
	}

	dm.logger.Info("verifying image provenance (cosign)", "image_count", len(targets))
	for _, t := range targets {
		if err := dm.verifyImageProvenance(ctx, t.ImageRef); err != nil {
			dm.logger.Warn("image provenance NOT verified — proceeding (the signed-manifest digest pin already guarantees these exact bytes)",
				"service", t.Service, "image", t.ImageRef, "error", err)
			continue
		}
		dm.logger.Info("image provenance verified", "service", t.Service, "image", t.ImageRef)
	}
}

// verifyImageProvenance runs the pinned cosign container to verify one image ref.
// The container reaches ghcr + Rekor/Fulcio over the host daemon's default
// bridge (outbound); bounded by ImagePullTimeout (covers the first-time cosign
// image pull + the network verify).
func (dm *DockerManager) verifyImageProvenance(ctx context.Context, imageRef string) error {
	verifyCtx := ctx
	if dm.cfg.ImagePullTimeout > 0 {
		var cancel context.CancelFunc
		verifyCtx, cancel = context.WithTimeout(ctx, dm.cfg.ImagePullTimeout)
		defer cancel()
	}
	cmd := exec.CommandContext(verifyCtx, "docker", cosignVerifyArgs(imageRef)...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("cosign verify %s: %w: %s", imageRef, err, strings.TrimSpace(string(output)))
	}
	return nil
}

// Legacy DKIM migration constants. Before the dkim dir became a host bind
// mount, rspamd + api mounted it from this named volume; keys written via the
// api landed in the volume while host-CLI `vectis domain add` wrote to the host
// path — the two diverged (outbound could go unsigned). See
// feedback_vectis_cli_db_and_sidecar_compose_gaps gap #4.
const (
	legacyDKIMVolume   = "vectis_dkim-keys"
	dkimHostPath       = "/var/vectis/dkim"
	dkimMigrationImage = "alpine:3.24" // already a stack dependency (rspamd/clamav base)
)

// MigrateLegacyDKIMVolume copies DKIM keys from the legacy named volume into
// the host bind path that rspamd + api now share. Runs a one-shot container
// (the orchestrator can't mount the volume itself) that copies, per domain,
// volume → host path. Must run BEFORE rspamd is recreated against the new bind
// mount (or, on render-from-target upgrades where the recreate already
// happened, BEFORE rspamd/postfix are restarted) so no key goes missing.
//
// Returns whether it actually copied any keys, so the caller can decide whether
// the running signing services need a restart to pick them up.
//
// Idempotent: never clobbers an existing host key; safe to re-run. No-op when
// the legacy volume is absent (fresh installs never created it). Best-effort —
// callers log failures rather than aborting the upgrade.
func (dm *DockerManager) MigrateLegacyDKIMVolume(ctx context.Context) (bool, error) {
	// Gate on the volume existing — `docker run -v <name>:...` would otherwise
	// CREATE a stray empty volume on fresh installs. Only a genuine "No such
	// volume" means absent; any other error (daemon down, permission denied) is
	// returned so the caller's warning fires instead of silently skipping.
	if out, err := exec.CommandContext(ctx, "docker", "volume", "inspect", legacyDKIMVolume).CombinedOutput(); err != nil {
		if strings.Contains(string(out), "No such volume") {
			dm.logger.Info("dkim migration: no legacy volume, nothing to migrate", "volume", legacyDKIMVolume)
			return false, nil
		}
		return false, fmt.Errorf("dkim migration: inspect %s: %w: %s", legacyDKIMVolume, err, strings.TrimSpace(string(out)))
	}

	// Ensure the tiny copy image is present (avoids a network round-trip when
	// it already is — alpine is the rspamd/clamav base, usually cached).
	if err := exec.CommandContext(ctx, "docker", "image", "inspect", dkimMigrationImage).Run(); err != nil {
		if err := dm.PullImageRef(ctx, dkimMigrationImage, 2*time.Minute); err != nil {
			return false, fmt.Errorf("pull %s for dkim migration: %w", dkimMigrationImage, err)
		}
	}

	dm.logger.Info("dkim migration: copying keys from legacy volume to host bind path",
		"volume", legacyDKIMVolume, "dest", dkimHostPath)
	args := []string{
		"run", "--rm",
		"-v", legacyDKIMVolume + ":/from:ro",
		"-v", dkimHostPath + ":/to",
		dkimMigrationImage,
		// Per-KEY-FILE, no-clobber copy. We deliberately do NOT use the obvious
		// `cp -an /from/. /to/`: under busybox (this alpine image) that form
		// silently copies NOTHING once /to already holds any entry — it bails at
		// the existing top-level dir instead of merging per-file like GNU cp.
		// (Verified the hard way on the v0.1.27 mx1 canary, 2026-06-13.) We go
		// per file rather than per domain dir so a domain whose dir already
		// exists on the host but is missing a newer selector key (e.g. created
		// via host CLI, then DKIM-rotated by the pre-migration API into the
		// legacy volume) still gets that key copied. `mkdir -p` the dest domain
		// dir, never clobber an existing host key, and echo each copied key so
		// the Go side can tell whether anything actually moved. Keys live at
		// /from/<domain>/<selector>.key — exactly two levels.
		"sh", "-c",
		`set -e; for f in /from/*/*; do [ -e "$f" ] || continue; rel=${f#/from/}; if [ ! -e "/to/$rel" ]; then mkdir -p "/to/$(dirname "$rel")"; cp -a "$f" "/to/$rel" && echo "copied:$rel"; fi; done`,
	}
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("dkim volume migration: %w: %s", err, strings.TrimSpace(string(out)))
	}
	copied := strings.Contains(string(out), "copied:")
	if copied {
		dm.logger.Info("dkim migration: copied volume-only keys to host",
			"detail", strings.TrimSpace(string(out)))
	}
	dm.logger.Info("dkim migration: complete (legacy volume kept; remove with `docker volume rm vectis_dkim-keys` once verified)",
		"copied", copied)
	return copied, nil
}

// StopServices stops containers in the given order (should be reverse dependency order).
// Each container is stopped gracefully with a 30-second timeout.
func (dm *DockerManager) StopServices(ctx context.Context, order []string) error {
	dm.logger.Info("stopping services", "order", order)

	for _, svc := range order {
		name := containerName(svc)
		dm.logger.Info("stopping container", "service", svc, "container", name)

		cmd := exec.CommandContext(ctx, "docker", "stop", "--time", "30", name)
		output, err := cmd.CombinedOutput()
		if err != nil {
			// If the container is already stopped or doesn't exist, that's fine.
			outStr := string(output)
			if strings.Contains(outStr, "No such container") ||
				strings.Contains(outStr, "is not running") {
				dm.logger.Info("container already stopped", "service", svc)
				continue
			}
			return fmt.Errorf("stop %s: %w: %s", svc, err, outStr)
		}
	}

	dm.logger.Info("all services stopped")
	return nil
}

// StartServices starts containers in the given order (should be dependency order).
// Uses docker compose up with the specific service names.
//
// Services listed in `order` but not present in the compose file are skipped
// (e.g. `clamav` when the install doesn't have virus scanning enabled). Without
// this filter, `docker compose up -d --no-deps clamav` fails with "no such
// service: clamav" and aborts the whole rollout chain (Phase 5 health check
// or rollback Phase 4 restart). Matches the existing filter behaviour in
// PullImages + ApplyComposeServices.
func (dm *DockerManager) StartServices(ctx context.Context, order []string) error {
	defined, err := dm.composeServices(ctx)
	if err != nil {
		return fmt.Errorf("enumerate compose services: %w", err)
	}
	dm.logger.Info("starting services", "order", order)

	for _, svc := range order {
		if !defined[svc] {
			dm.logger.Info("skipping start: service not defined in compose", "service", svc)
			continue
		}
		dm.logger.Info("starting service", "service", svc)

		args := append([]string{"compose"}, dm.cfg.composeFileArgs()...)
		args = append(args, "up", "-d", "--no-deps", svc)
		cmd := exec.CommandContext(ctx, "docker", args...)

		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("start %s: %w: %s", svc, err, string(output))
		}

		// Wait for health check before starting the next dependent service.
		timeout, ok := ServiceHealthTimeouts[svc]
		if !ok {
			timeout = dm.cfg.HealthCheckTimeout
		}

		if err := dm.WaitHealthy(ctx, svc, timeout); err != nil {
			return fmt.Errorf("health check failed for %s: %w", svc, err)
		}

		dm.logger.Info("service started and healthy", "service", svc)
	}

	dm.logger.Info("all services started")
	return nil
}

// WaitHealthy polls Docker until the container's HEALTHCHECK reports healthy
// or the timeout expires. Returns an error if the container does not become
// healthy within the timeout.
func (dm *DockerManager) WaitHealthy(ctx context.Context, service string, timeout time.Duration) error {
	name := containerName(service)
	deadline := time.Now().Add(timeout)
	pollInterval := 2 * time.Second

	dm.logger.Info("waiting for health check",
		"service", service,
		"container", name,
		"timeout", timeout.String(),
	)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		status, err := dm.containerHealthStatus(ctx, name)
		if err != nil {
			dm.logger.Debug("health check probe error", "service", service, "error", err)
			time.Sleep(pollInterval)
			continue
		}

		switch status {
		case "healthy":
			return nil
		case "unhealthy":
			return fmt.Errorf("container %s is unhealthy", name)
		default:
			// "starting" or no health check defined — keep polling.
			time.Sleep(pollInterval)
		}
	}

	return fmt.Errorf("health check timeout for %s after %s", service, timeout)
}

// containerHealthStatus returns the health status of a container via docker inspect.
// Returns "healthy", "unhealthy", "starting", or "none" (no health check).
func (dm *DockerManager) containerHealthStatus(ctx context.Context, containerName string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", "inspect",
		"--format", "{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}",
		containerName,
	)

	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("docker inspect %s: %w", containerName, err)
	}

	return strings.TrimSpace(stdout.String()), nil
}

// GetContainerVersions returns the current image tags for all Vectis containers.
// Keys are service names, values are full image references (e.g. "vectis/api:1.2.3").
//
// Iterates VectisImageServices (everything whose tag moves with releases) plus
// the data services from ServiceStartOrder so Plan's baseline has running
// versions for every upgradable service. Iterating only ServiceStartOrder
// dropped orchestrator + cert-extractor, which made Plan report them as
// "create" instead of "update" — see VectisImageServices doc.
func (dm *DockerManager) GetContainerVersions(ctx context.Context) (map[string]string, error) {
	versions := make(map[string]string)

	seen := make(map[string]bool)
	inspect := func(svc string) {
		if seen[svc] {
			return
		}
		seen[svc] = true
		name := containerName(svc)
		image, err := dm.getContainerImage(ctx, name)
		if err != nil {
			dm.logger.Debug("could not get image for container",
				"service", svc,
				"container", name,
				"error", err,
			)
			return // Container may not exist yet.
		}
		versions[svc] = image
	}
	for _, svc := range VectisImageServices {
		inspect(svc)
	}
	for _, svc := range ServiceStartOrder {
		inspect(svc)
	}

	return versions, nil
}

// listPhantomContainers returns the names of containers attached to any
// vectis_* docker network but NOT defined by the configured compose project.
// These are typically containers that were started outside the project (e.g.
// `docker run` against a vectis-* image) or under a different compose file —
// either way, they hold the network endpoint open and break compose-up's
// recreate path with "active endpoints" errors. Catching them up-front lets
// self-heal refuse-and-skip rather than partial-stopping the live stack.
//
// Detection logic:
//   - Enumerate networks whose name has the project's compose-derived prefix
//     ("vectis_") OR a vectis-* shape (covers networks created via `docker
//     network create vectis_xxx` outside compose).
//   - For each network, list attached containers via `docker network inspect`.
//   - Filter out any container whose name is `vectis-<svc>` for an svc
//     defined in the compose file — those are legitimate, project-managed
//     services.
//
// Returns the deduplicated list of phantom container names. A non-nil error
// means the probe itself failed (e.g. docker daemon unreachable), in which
// case the caller should treat the result as inconclusive — neither
// "phantoms exist" nor "no phantoms".
func (dm *DockerManager) listPhantomContainers(ctx context.Context) ([]string, error) {
	composeServices, err := dm.composeServices(ctx)
	if err != nil {
		return nil, fmt.Errorf("enumerate compose services: %w", err)
	}
	expected := make(map[string]bool, len(composeServices))
	for svc := range composeServices {
		expected[containerName(svc)] = true
	}

	networks, err := dm.listVectisNetworks(ctx)
	if err != nil {
		return nil, fmt.Errorf("list vectis networks: %w", err)
	}

	seen := make(map[string]bool)
	var phantoms []string
	for _, net := range networks {
		names, err := dm.containersOnNetwork(ctx, net)
		if err != nil {
			dm.logger.Debug("network inspect failed (skipping)", "network", net, "error", err)
			continue
		}
		for _, name := range names {
			if expected[name] || seen[name] {
				continue
			}
			seen[name] = true
			phantoms = append(phantoms, name)
		}
	}
	return phantoms, nil
}

// listVectisNetworks returns docker network names that look like they belong
// to the Vectis compose project. Matches the prefix "vectis_" (compose's
// default project-network naming) and "vectis-" (alternate styles seen on
// older installs).
func (dm *DockerManager) listVectisNetworks(ctx context.Context) ([]string, error) {
	cmd := exec.CommandContext(ctx, "docker", "network", "ls", "--format", "{{.Name}}")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("docker network ls: %w", err)
	}
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(stdout.String()), "\n") {
		name := strings.TrimSpace(line)
		if name == "" {
			continue
		}
		if strings.HasPrefix(name, "vectis_") || strings.HasPrefix(name, "vectis-") {
			out = append(out, name)
		}
	}
	return out, nil
}

// containersOnNetwork lists the names of containers attached to a docker
// network. Uses `docker network inspect` JSON output rather than the format
// template so multi-container networks parse reliably.
func (dm *DockerManager) containersOnNetwork(ctx context.Context, network string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "docker", "network", "inspect", network)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("docker network inspect %s: %w", network, err)
	}
	var parsed []struct {
		Containers map[string]struct {
			Name string `json:"Name"`
		} `json:"Containers"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		return nil, fmt.Errorf("parse network inspect: %w", err)
	}
	if len(parsed) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(parsed[0].Containers))
	for _, c := range parsed[0].Containers {
		if c.Name != "" {
			out = append(out, c.Name)
		}
	}
	return out, nil
}

// getContainerImage returns the image reference for a running container.
func (dm *DockerManager) getContainerImage(ctx context.Context, name string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", "inspect",
		"--format", "{{.Config.Image}}",
		name,
	)

	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("docker inspect %s: %w", name, err)
	}

	return strings.TrimSpace(stdout.String()), nil
}

// ApplyCompose runs docker compose up -d across all configured compose files.
// This applies any changes to service definitions (new images, config, etc.).
func (dm *DockerManager) ApplyCompose(ctx context.Context) error {
	dm.logger.Info("applying docker compose", "paths", dm.cfg.ComposePaths)

	args := append([]string{"compose"}, dm.cfg.composeFileArgs()...)
	args = append(args, "up", "-d", "--remove-orphans")
	cmd := exec.CommandContext(ctx, "docker", args...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker compose up: %w: %s", err, string(output))
	}

	dm.logger.Info("docker compose applied", "paths", dm.cfg.ComposePaths)
	return nil
}

// RestartContainers issues `docker container restart` for every named container
// in a single shell-out. Idempotent (no-op on already-running containers gets
// a brief stop+start). Used by self-heal after RegenerateConfigs writes new
// per-service config files: a `compose up -d` with unchanged image+compose is
// a no-op, so containers keep their old bind-mount inodes for any single-file
// config that was atomically replaced (postfix main.cf, dovecot.conf, etc).
// `docker container restart` re-resolves bind-mount inodes at start time —
// this is the surgical fix for the bind-mount-inode class of bug.
//
// Names are container names (e.g. "vectis-postfix"), NOT compose service
// names. Failures are returned as a wrapped error; the caller decides
// whether to surface or continue.
//
// (Found by 2026-05-10 v0.1.11-rc2 sa1001 walkthrough — main.cf had the
// fix but postfix wasn't reading it because compose up -d didn't recreate
// the container. See feedback_bind_mount_edits.md.)
func (dm *DockerManager) RestartContainers(ctx context.Context, names []string) error {
	if len(names) == 0 {
		return nil
	}
	args := append([]string{"container", "restart"}, names...)
	cmd := exec.CommandContext(ctx, "docker", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker container restart %v: %w: %s", names, err, strings.TrimSpace(string(out)))
	}
	dm.logger.Info("restarted containers", "containers", names)
	return nil
}

// ApplyComposeServices runs `docker compose up -d <s1> <s2> …` for exactly the
// listed services, rather than the whole compose like ApplyCompose.
//
// Used by Apply's Phase 4.3 to recreate every vectis-* service EXCEPT the
// orchestrator itself — the orchestrator's self-replacement is handled
// asynchronously via a detached helper (SpawnSelfReplaceHelper). Without the
// split, `docker compose up -d` issued from inside the orchestrator container
// got SIGTERM'd mid-command when the daemon started swapping the orchestrator
// — 0.35s was all Phase 4.3 got before dying (rc33→rc35 walkthrough 2026-04-24).
//
// --remove-orphans is intentionally NOT passed here — we're targeting specific
// services, not reconciling the whole stack, and passing it would remove
// containers we're deliberately leaving alone (orchestrator).
func (dm *DockerManager) ApplyComposeServices(ctx context.Context, services []string) error {
	if len(services) == 0 {
		return fmt.Errorf("ApplyComposeServices called with empty service list")
	}

	// Filter to services actually present in the compose file. Optional
	// services (clamav, webmail, etc.) may be absent depending on install
	// config; listing them explicitly in `docker compose up -d` fails with
	// "no such service" and aborts the whole command. Matches PullImages'
	// existing defined-filter pattern.
	defined, err := dm.composeServices(ctx)
	if err != nil {
		return fmt.Errorf("enumerate compose services: %w", err)
	}

	filtered := make([]string, 0, len(services))
	for _, svc := range services {
		if !defined[svc] {
			dm.logger.Info("skipping compose up: service not defined in compose", "service", svc)
			continue
		}
		filtered = append(filtered, svc)
	}

	if len(filtered) == 0 {
		dm.logger.Info("ApplyComposeServices: nothing to apply after filtering (all requested services undefined in compose)")
		return nil
	}

	dm.logger.Info("applying docker compose for specific services",
		"paths", dm.cfg.ComposePaths, "services", filtered)

	// --no-deps: don't let compose's own `depends_on: condition: service_healthy`
	// gate hard-fail this command. During a rolling recreate a dependency (e.g.
	// dovecot) is briefly "starting"/"unhealthy"; without --no-deps `compose up`
	// aborts with "dependency failed to start: container vectis-dovecot is
	// unhealthy" and the whole Apply rolls back. Ordered, health-gated startup is
	// Phase 5's job (StartServices + WaitHealthy, which tolerates "starting"); the
	// data-layer deps these services need are already running. Reproduced on the
	// mx1 v0.1.24 canary (webmail→dovecot). Matches StartServices's per-service
	// `up -d --no-deps`.
	args := append([]string{"compose"}, dm.cfg.composeFileArgs()...)
	args = append(args, "up", "-d", "--no-deps")
	args = append(args, filtered...)
	cmd := exec.CommandContext(ctx, "docker", args...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker compose up %v: %w: %s", filtered, err, string(output))
	}

	dm.logger.Info("docker compose applied for services", "services", filtered)
	return nil
}

// SpawnSelfReplaceHelper launches a short-lived detached container that, after
// `delay` seconds, runs `docker compose up -d orchestrator` — triggering a
// recreation of the orchestrator container with whatever image tag is in the
// compose file (rewritten by Phase 3.5 to the target rc). The helper reuses
// the currently-running orchestrator image (guaranteed-working docker CLI
// that can talk to the mounted socket), runs with --rm so it self-cleans,
// and has no network dependencies — just /var/run/docker.sock and /etc/vectis
// bind-mounted in.
//
// Rationale: Phase 4.3's ordinary `docker compose up -d` gets SIGTERM'd
// mid-command when the daemon starts swapping the orchestrator itself — see
// the Apply's Phase 4.3 split comment above. Handing the orchestrator's own
// recreation off to a helper breaks that race: the orchestrator records Apply
// completion cleanly, the helper fires N seconds later, docker sends SIGTERM
// to the orchestrator (which uses its normal graceful-shutdown path), new
// orchestrator starts on the new image. User-visible flow is continuous.
//
// helperImage should be the CURRENT (pre-upgrade) orchestrator image — we
// don't want to depend on the new image being healthy just to launch the
// helper. Returns the helper container ID on success.
func (dm *DockerManager) SpawnSelfReplaceHelper(ctx context.Context, helperImage string, delay time.Duration, helperNameSuffix string) (string, error) {
	if helperImage == "" {
		return "", fmt.Errorf("SpawnSelfReplaceHelper called with empty helperImage")
	}
	if delay < 0 {
		return "", fmt.Errorf("SpawnSelfReplaceHelper called with negative delay %s", delay)
	}
	if helperNameSuffix == "" {
		return "", fmt.Errorf("SpawnSelfReplaceHelper called with empty helperNameSuffix")
	}

	// Compose file inside the helper container is the first of the configured
	// compose paths — the same one Phase 3.5 just rewrote. Helper runs outside
	// the vectis compose project, so we pass -f explicitly.
	composePath := "/etc/vectis/docker-compose.yml"
	if len(dm.cfg.ComposePaths) > 0 {
		composePath = dm.cfg.ComposePaths[0]
	}

	delaySeconds := int(delay.Seconds())
	shCommand := fmt.Sprintf(
		"sleep %d && docker compose -f %s up -d orchestrator",
		delaySeconds, composePath,
	)
	helperName := "vectis-apply-helper-" + helperNameSuffix

	// Bind mounts:
	//   - docker socket so the helper can talk to the daemon
	//   - the directory containing composePath, so `docker compose -f <path>`
	//     can actually read the file. Prod points VECTIS_ORCH_COMPOSE_PATHS
	//     at /opt/vectis/docker-compose.yml, NOT /etc/vectis/...; without
	//     this mount the helper failed silently with "no configuration file
	//     provided: not found" and left orchestrator on the old image
	//     (2026-04-28 prod cutover; project_self_replace_helper_rc60_bug).
	//   - /etc/vectis as a fallback (some installs may keep config there).
	composeDir := filepath.Dir(composePath)
	args := []string{
		"run", "-d",
		"--name", helperName,
		"-v", "/var/run/docker.sock:/var/run/docker.sock",
		"-v", composeDir + ":" + composeDir + ":ro",
	}
	if composeDir != "/etc/vectis" {
		args = append(args, "-v", "/etc/vectis:/etc/vectis:ro")
	}
	args = append(args,
		"--entrypoint", "sh",
		helperImage,
		"-c", shCommand,
	)
	// --rm intentionally omitted: when the helper fails, --rm wipes its
	// logs along with the container. Keeping the exited container lets
	// `docker logs vectis-apply-helper-<suffix>` surface the failure.
	// Stale containers can be pruned with
	// `docker rm $(docker ps -aq --filter name=vectis-apply-helper-)`.

	dm.logger.Info("spawning orchestrator self-replace helper",
		"helper_name", helperName,
		"helper_image", helperImage,
		"delay_seconds", delaySeconds,
		"compose_path", composePath,
	)

	cmd := exec.CommandContext(ctx, "docker", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("docker run helper: %w: %s", err, strings.TrimSpace(stderr.String()))
	}

	containerID := strings.TrimSpace(stdout.String())
	dm.logger.Info("self-replace helper spawned",
		"helper_name", helperName,
		"container_id", containerID,
	)
	return containerID, nil
}

// containerInfo holds the inspect output fields we care about.
type containerInfo struct {
	State struct {
		Status string `json:"Status"`
		Health *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	} `json:"State"`
	Config struct {
		Image string `json:"Image"`
	} `json:"Config"`
}

// InspectContainer returns parsed container info for a Vectis service.
func (dm *DockerManager) InspectContainer(ctx context.Context, service string) (*containerInfo, error) {
	name := containerName(service)

	cmd := exec.CommandContext(ctx, "docker", "inspect", name)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("docker inspect %s: %w", name, err)
	}

	var infos []containerInfo
	if err := json.Unmarshal(stdout.Bytes(), &infos); err != nil {
		return nil, fmt.Errorf("unmarshal inspect output for %s: %w", name, err)
	}
	if len(infos) == 0 {
		return nil, fmt.Errorf("no inspect data for container %s", name)
	}

	return &infos[0], nil
}
