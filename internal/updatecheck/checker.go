// Package updatecheck tells the operator when a newer Vectis release exists.
//
// Once a day (after a randomised start delay) the API asks the orchestrator for
// the latest release on the configured channel. The orchestrator fetches the
// public, Ed25519-signed release manifest from dl.vectismail.com and verifies
// it exactly as an update would (signature, channel binding, anti-rollback), so
// the answer can't be forged by a compromised download origin. The check sends
// nothing about this install: no identifier, licence key or usage data.
//
// The result is kept in Valkey for the admin dashboard, and the admin is
// emailed once per new version. Turn the whole thing off with
// `updates: {check: false}` in config.yaml (e.g. for air-gapped servers).
package updatecheck

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"time"

	"github.com/Veltara-Works/vectis/internal/orchestrator"
	"github.com/valkey-io/valkey-go"
)

// Source answers "what is the latest release?" (the orchestrator client).
type Source interface {
	LatestRelease(ctx context.Context) (*orchestrator.LatestRelease, error)
}

// Notifier emails the admin about a new release.
type Notifier interface {
	SendUpdateAvailable(toEmail, currentVersion, newVersion, releaseNotesURL string) error
}

// Store persists State between checks and API restarts.
type Store interface {
	Load(ctx context.Context) (State, error)
	Save(ctx context.Context, s State) error
}

// State is what the dashboard shows and what keeps the email to once per
// version.
type State struct {
	CheckedAt       time.Time `json:"checked_at,omitzero"`
	Current         string    `json:"current,omitempty"`
	Latest          string    `json:"latest,omitempty"`
	ReleasedAt      time.Time `json:"released_at,omitzero"`
	UpdateAvailable bool      `json:"update_available"`
	ReleaseNotesURL string    `json:"release_notes_url,omitempty"`
	// LastError is the reason the most recent check failed ("" on success).
	// The previous Latest/UpdateAvailable are kept so one failed check doesn't
	// hide a known update.
	LastError string `json:"last_error,omitempty"`
	// NotifiedVersion is the newest release the admin has been emailed about.
	NotifiedVersion string `json:"notified_version,omitempty"`
}

// ReleaseNotesURL is the public changelog for a release tag.
func ReleaseNotesURL(tag string) string {
	return "https://github.com/Veltara-Works/vectis/releases/tag/" + tag
}

// Config controls the checker.
type Config struct {
	Interval time.Duration // between checks; default 24h
	// StartDelayMin/Max bound the randomised delay before the first check, so
	// a fleet of installs restarted together doesn't hit the download origin at
	// once, and a check never races the API's own startup or an update. Default
	// 5–30 minutes.
	StartDelayMin, StartDelayMax time.Duration
	AdminEmail                   string // "" = no email, dashboard only
}

// Checker runs the periodic check.
type Checker struct {
	src    Source
	store  Store
	notify Notifier
	cfg    Config
	logger *slog.Logger
	stopCh chan struct{}
	now    func() time.Time
}

// New builds a Checker. notify may be nil (no email).
func New(src Source, store Store, notify Notifier, cfg Config, logger *slog.Logger) *Checker {
	if cfg.Interval <= 0 {
		cfg.Interval = 24 * time.Hour
	}
	if cfg.StartDelayMax <= 0 {
		cfg.StartDelayMin, cfg.StartDelayMax = 5*time.Minute, 30*time.Minute
	}
	if cfg.StartDelayMin > cfg.StartDelayMax {
		cfg.StartDelayMin = cfg.StartDelayMax
	}
	return &Checker{src: src, store: store, notify: notify, cfg: cfg, logger: logger,
		stopCh: make(chan struct{}), now: time.Now}
}

// Start launches the check loop in a background goroutine.
func (c *Checker) Start() {
	delay := c.cfg.StartDelayMin
	if span := c.cfg.StartDelayMax - c.cfg.StartDelayMin; span > 0 {
		delay += rand.N(span)
	}
	c.logger.Info("starting update checker", "first_check_in", delay.Round(time.Second), "interval", c.cfg.Interval,
		"email", c.cfg.AdminEmail != "" && c.notify != nil)
	go c.loop(delay)
}

// Stop ends the loop. Safe to call more than once.
func (c *Checker) Stop() {
	select {
	case <-c.stopCh:
	default:
		close(c.stopCh)
	}
}

func (c *Checker) loop(first time.Duration) {
	t := time.NewTimer(first)
	defer t.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			c.RunOnce(ctx)
			cancel()
			t.Reset(c.cfg.Interval)
		}
	}
}

// RunOnce performs one check, records it, and emails the admin the first time
// a given newer release is seen. Returns the stored state. Exposed for tests.
func (c *Checker) RunOnce(ctx context.Context) State {
	st, err := c.store.Load(ctx)
	if err != nil {
		c.logger.Warn("update check: could not load previous state; starting fresh", "error", err)
		st = State{}
	}
	st.CheckedAt = c.now().UTC()

	lr, err := c.src.LatestRelease(ctx)
	if err != nil {
		st.LastError = err.Error()
		c.logger.Warn("update check failed", "error", err)
		c.save(ctx, st)
		return st
	}
	st.LastError = ""
	st.Current = lr.Current
	st.Latest = lr.Latest
	st.ReleasedAt = lr.ReleasedAt
	st.UpdateAvailable = lr.UpdateAvailable
	st.ReleaseNotesURL = ""
	if lr.Latest != "" {
		st.ReleaseNotesURL = ReleaseNotesURL(lr.Latest)
	}

	if st.UpdateAvailable {
		c.logger.Info("update available", "current", st.Current, "latest", st.Latest)
		if st.NotifiedVersion != st.Latest && c.notify != nil && c.cfg.AdminEmail != "" {
			if err := c.notify.SendUpdateAvailable(c.cfg.AdminEmail, st.Current, st.Latest, st.ReleaseNotesURL); err != nil {
				// Not recorded as notified, so the next check retries.
				c.logger.Error("update check: could not email the admin", "error", err)
			} else {
				st.NotifiedVersion = st.Latest
				c.logger.Info("update check: admin emailed", "latest", st.Latest)
			}
		}
	}
	c.save(ctx, st)
	return st
}

func (c *Checker) save(ctx context.Context, st State) {
	if err := c.store.Save(ctx, st); err != nil {
		c.logger.Warn("update check: could not save state", "error", err)
	}
}

// valkeyKey holds the JSON State. No TTL: the "already emailed" marker must
// survive restarts. If it's ever lost, the worst case is one repeat email.
const valkeyKey = "vectis:update-check:state"

// ValkeyStore keeps State in Valkey.
type ValkeyStore struct{ VK valkey.Client }

func (s ValkeyStore) Load(ctx context.Context) (State, error) {
	raw, err := s.VK.Do(ctx, s.VK.B().Get().Key(valkeyKey).Build()).ToString()
	if err != nil {
		if valkey.IsValkeyNil(err) {
			return State{}, nil
		}
		return State{}, err
	}
	var st State
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		return State{}, fmt.Errorf("decode update-check state: %w", err)
	}
	return st, nil
}

func (s ValkeyStore) Save(ctx context.Context, st State) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return s.VK.Do(ctx, s.VK.B().Set().Key(valkeyKey).Value(string(b)).Build()).Error()
}
