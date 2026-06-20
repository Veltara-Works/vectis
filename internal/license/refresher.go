package license

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// defaultRefreshInterval is how often the keyset is re-resolved in the
// background. ValidonX mints 96h tokens and rotates keys with overlap, so a
// twice-daily refresh keeps the cached/embedded keyset comfortably current
// without hammering the JWKS endpoint.
const defaultRefreshInterval = 12 * time.Hour

// refreshTimeout bounds a single background refresh (fetch + parse + cache
// write). The Resolver's HTTP client has its own shorter fetch timeout; this
// is the outer budget for the whole resolution.
const refreshTimeout = 30 * time.Second

// Refresher keeps a Provider's keyset current in the background. It follows
// the same start/stop lifecycle as monitor.Monitor and validonx.UsageReporter:
// Start does a synchronous initial load then spawns a ticking goroutine; Stop
// halts it. Trigger forces an out-of-band refresh (e.g. from the revoke
// webhook). Refresh failures are logged and the previous keyset is retained —
// the hot path never blocks on the network.
type Refresher struct {
	provider *Provider
	interval time.Duration
	logger   *slog.Logger

	stopCh  chan struct{}
	trigger chan struct{}

	// onRefresh, if non-nil, receives the Source of each background refresh.
	// Test/observability hook only; never blocks the loop.
	onRefresh chan<- Source
}

// NewRefresher builds a Refresher for p. A non-positive interval falls back to
// defaultRefreshInterval; a nil logger falls back to slog.Default.
func NewRefresher(p *Provider, interval time.Duration, logger *slog.Logger) *Refresher {
	if interval <= 0 {
		interval = defaultRefreshInterval
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Refresher{
		provider: p,
		interval: interval,
		logger:   logger,
		stopCh:   make(chan struct{}),
		trigger:  make(chan struct{}, 1), // coalesced: one pending trigger is enough
	}
}

// Start performs a synchronous initial keyset load so the verification hot
// path is ready before Start returns, then launches the background refresh
// loop. It returns an error only if the initial load fails every layer
// (including the embedded fallback) — i.e. a build/config fault, not a
// transient network problem. The caller wires Stop into its shutdown.
func (r *Refresher) Start(ctx context.Context) error {
	src, err := r.provider.Refresh(ctx)
	if err != nil {
		return fmt.Errorf("initial license jwks load: %w", err)
	}
	r.logger.Info("license jwks loaded", "source", src, "refresh_interval", r.interval)
	go r.loop()
	return nil
}

// Stop signals the refresh loop to stop. Safe to call once; mirrors the
// monitor/usage-reporter convention.
func (r *Refresher) Stop() {
	r.logger.Info("stopping license jwks refresher")
	close(r.stopCh)
}

// Trigger requests an out-of-band refresh. Non-blocking and coalesced:
// concurrent or rapid triggers collapse into a single pending refresh.
func (r *Refresher) Trigger() {
	select {
	case r.trigger <- struct{}{}:
	default: // a refresh is already pending; nothing to do
	}
}

func (r *Refresher) loop() {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			r.refreshOnce()
		case <-r.trigger:
			r.refreshOnce()
		}
	}
}

// refreshOnce re-resolves the keyset under a bounded context. A failure is
// logged and swallowed: Provider.Refresh retains the previous keyset, so a
// transient outage degrades to "running on the last-good keyset", never to a
// blanked hot path.
func (r *Refresher) refreshOnce() {
	ctx, cancel := context.WithTimeout(context.Background(), refreshTimeout)
	defer cancel()
	src, err := r.provider.Refresh(ctx)
	if err != nil {
		r.logger.Warn("license jwks refresh failed; keeping previous keyset", "error", err)
	} else {
		r.logger.Debug("license jwks refreshed", "source", src)
	}
	if r.onRefresh != nil {
		select {
		case r.onRefresh <- src:
		default:
		}
	}
}
