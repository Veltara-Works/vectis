package orchestrator

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// TargetRenderImageRepo is the ghcr repository of the image that carries the
// `vectis` CLI (built from cmd/vectis, ENTRYPOINT ["vectis"]). The render-from-
// target path runs `<repo>:<tag> config generate` to produce the desired
// compose + per-service configs for the TARGET release — rather than rendering
// from the running (old) orchestrator's embedded templates. This is the fix for
// the upgrade bootstrap deadlock (GH #47): a template/healthcheck change shipped
// in release N is invisible during the very Apply that delivers it, because the
// orchestrator only self-replaces in Phase 7. Rendering from N's own image
// removes the entire "old code renders new config" class.
//
// Must stay in sync with the api image ref in templates/docker-compose.yml.tmpl.
const TargetRenderImageRepo = "ghcr.io/veltara-works/vectis-api"

// renderViaTargetImage runs the target release image's `vectis config generate`
// in a throwaway container and returns the rendered docker-compose.yml bytes and
// the per-service config files. The orchestrator stays a thin executor: it pulls
// the image, runs the generate, and reads the result — the NEW image owns all
// template logic.
//
// Mechanics (docker-in-docker bind-mount aware):
//   - Input: the host config dir (cfg.ConfigDirHost, e.g. /etc/vectis) is mounted
//     read-only at /etc/vectis so the target CLI can read config.yaml + secrets.yaml.
//   - Output: a scratch dir under cfg.GeneratedConfigDir (a host-shared bind mount
//     at an identical host:container path) is mounted at /out. The generate writes
//     compose + configs there; the orchestrator reads them back via the same path.
//     A path under SnapshotDir can't be used — that's a named volume with no stable
//     host path the daemon could bind into a sibling container.
//   - Network: the throwaway container joins the running postgres container's
//     network so `config generate` (which lists domains from Postgres) can connect
//     via --db-host.
//
// The scratch dir is always removed before returning.
func (o *Orchestrator) renderViaTargetImage(ctx context.Context, releaseTag, jobID string) (composeYAML []byte, configs []ConfigFile, err error) {
	if releaseTag == "" {
		return nil, nil, fmt.Errorf("renderViaTargetImage: empty releaseTag")
	}
	if o.cfg.GeneratedConfigDir == "" {
		return nil, nil, fmt.Errorf("renderViaTargetImage: GeneratedConfigDir not configured")
	}
	if o.cfg.ConfigDirHost == "" {
		return nil, nil, fmt.Errorf("renderViaTargetImage: ConfigDirHost not configured")
	}

	image := TargetRenderImageRepo + ":" + releaseTag

	// Scratch dir lives under the host-shared generated-configs root so the
	// same absolute path is valid both inside the orchestrator container (to
	// read results) and on the host (for the sibling container's bind mount).
	// Hidden + job-scoped so it never collides with RegenerateConfigs's
	// reconcile set (postfix/..., rspamd/..., never .apply-render-*).
	scratch := filepath.Join(o.cfg.GeneratedConfigDir, ".apply-render-"+sanitizeForPath(jobID))
	if err := os.RemoveAll(scratch); err != nil {
		return nil, nil, fmt.Errorf("clear render scratch %s: %w", scratch, err)
	}
	if err := os.MkdirAll(scratch, 0o755); err != nil {
		return nil, nil, fmt.Errorf("create render scratch %s: %w", scratch, err)
	}
	defer func() { _ = os.RemoveAll(scratch) }()

	// Pull the target image first so render doesn't depend on it being pre-present.
	if err := o.docker.PullImageRef(ctx, image, o.cfg.ImagePullTimeout); err != nil {
		return nil, nil, fmt.Errorf("pull target render image %s: %w", image, err)
	}

	if err := o.docker.RenderConfigsViaImage(ctx, RenderRequest{
		Image:         image,
		ConfigDirHost: o.cfg.ConfigDirHost,
		OutDirHost:    scratch,
		DBHost:        o.cfg.DBHost,
	}); err != nil {
		return nil, nil, fmt.Errorf("render via target image %s: %w", image, err)
	}

	// Read results back. docker-compose.yml at the root is the compose; every
	// other file is a per-service config keyed by its rel-path (postfix/main.cf,
	// rspamd/local.lua, postgres/init-users.sh, ...).
	composePath := filepath.Join(scratch, "docker-compose.yml")
	composeYAML, err = os.ReadFile(composePath)
	if err != nil {
		return nil, nil, fmt.Errorf("read rendered compose: %w", err)
	}
	if len(bytes.TrimSpace(composeYAML)) == 0 {
		return nil, nil, fmt.Errorf("rendered compose is empty")
	}

	configs, err = collectRenderedConfigs(scratch)
	if err != nil {
		return nil, nil, err
	}

	return composeYAML, configs, nil
}

// collectRenderedConfigs walks a render scratch dir and returns every file
// except docker-compose.yml as a ConfigFile, with RelPath relative to the root
// and Mode taken from the on-disk file (preserves the 0755 bit on shell scripts
// such as postgres/init-users.sh).
func collectRenderedConfigs(root string) ([]ConfigFile, error) {
	var out []ConfigFile
	err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		// Compose is handled separately by RegenerateCompose.
		if rel == "docker-compose.yml" {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read rendered config %s: %w", rel, err)
		}
		out = append(out, ConfigFile{
			RelPath: filepath.ToSlash(rel),
			Content: content,
			Mode:    info.Mode() & os.ModePerm,
		})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk rendered configs: %w", err)
	}
	return out, nil
}

// staticComposeGenerator returns a ComposeGenerator that ignores its arguments
// and always returns the supplied pre-rendered compose bytes. Lets the
// render-from-target path reuse RegenerateCompose's backup / no-op / atomic-write
// machinery without it caring where the bytes came from.
func staticComposeGenerator(composeYAML []byte) ComposeGenerator {
	return func(context.Context, string) ([]byte, error) {
		if len(composeYAML) == 0 {
			return nil, fmt.Errorf("static compose generator has no content")
		}
		return composeYAML, nil
	}
}

// staticConfigGenerator returns a ConfigGenerator that always returns the
// supplied pre-rendered config files, for the same reuse reason as
// staticComposeGenerator.
func staticConfigGenerator(files []ConfigFile) ConfigGenerator {
	return func(context.Context, string) ([]ConfigFile, error) {
		return files, nil
	}
}

// sanitizeForPath reduces an arbitrary identifier (job ID / UUID) to a safe
// path segment: keep [A-Za-z0-9._-], replace everything else with '-'. Defends
// the scratch-dir path against unexpected characters without depending on the
// caller's ID format.
func sanitizeForPath(s string) string {
	if s == "" {
		return "render"
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return b.String()
}

// RenderRequest carries the inputs for a single render-via-target-image run.
type RenderRequest struct {
	Image         string // full image ref incl. tag, e.g. ghcr.io/.../vectis-api:v0.1.25
	ConfigDirHost string // host path of the config dir to mount read-only at /etc/vectis
	OutDirHost    string // host path of the scratch output dir to mount at /out
	DBHost        string // --db-host value for `config generate` (e.g. "postgres")
}

// RenderConfigsViaImage runs `<image> config generate` in a throwaway container
// that joins the running postgres container's network, mounting the config dir
// in and an output dir out. The target image's CLI does all template rendering;
// the orchestrator only wires up mounts + network and waits for it to finish.
//
// --rm cleans the container up regardless of outcome. Failure surfaces the
// combined stdout+stderr so a template/config error in the target image is
// diagnosable from the orchestrator log.
func (dm *DockerManager) RenderConfigsViaImage(ctx context.Context, req RenderRequest) error {
	if req.Image == "" {
		return fmt.Errorf("RenderConfigsViaImage: empty image")
	}
	if req.ConfigDirHost == "" || req.OutDirHost == "" {
		return fmt.Errorf("RenderConfigsViaImage: ConfigDirHost and OutDirHost are required")
	}

	// Discover the postgres container's network so `config generate` can reach
	// Postgres to list domains. postgres sits on exactly one network (vectis-data);
	// if it's on several, pick one deterministically (sorted) and rely on the
	// embedded DNS resolving --db-host on it.
	pgName := containerName("postgres")
	nets, err := dm.containerNetworks(ctx, pgName)
	if err != nil {
		return fmt.Errorf("discover %s network: %w", pgName, err)
	}
	network := firstSorted(nets)
	if network == "" {
		return fmt.Errorf("no network found for %s; cannot reach Postgres for render", pgName)
	}

	dbHost := req.DBHost
	if dbHost == "" {
		dbHost = "postgres"
	}

	args := []string{
		"run", "--rm",
		"--network", network,
		"-v", req.ConfigDirHost + ":/etc/vectis:ro",
		"-v", req.OutDirHost + ":/out",
		req.Image,
		"config", "generate",
		"--config-dir", "/etc/vectis",
		"--db-host", dbHost,
		"-o", "/out",
	}

	dm.logger.Info("rendering configs via target image",
		"image", req.Image,
		"network", network,
		"db_host", dbHost,
		"out_dir", req.OutDirHost,
	)

	cmd := exec.CommandContext(ctx, "docker", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker run %s config generate: %w: %s", req.Image, err, strings.TrimSpace(string(output)))
	}
	return nil
}

// firstSorted returns the lexicographically smallest key of the set, or "" if
// empty. Deterministic pick when a container is on multiple networks.
func firstSorted(set map[string]bool) string {
	first := ""
	for k := range set {
		if first == "" || k < first {
			first = k
		}
	}
	return first
}
