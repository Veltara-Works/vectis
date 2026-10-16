package mail

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/Veltara-Works/vectis/internal/repository"
)

// WarmupDays is the length of the warmup schedule. The warmup completes (and
// stops limiting) when the day after the last one begins.
const WarmupDays = 30

// warmupPassTimeout bounds a background schedule pass, so a stalled database
// can't hold the rollover lock indefinitely.
const warmupPassTimeout = 30 * time.Second

// warmupReleaseTimeout bounds giving a reservation back. It is best-effort,
// and runs while an HTTP error response or an SMTP DATA decision waits.
const warmupReleaseTimeout = 5 * time.Second

// warmupActiveTTL is how long Active caches whether a warmup is running.
// Starting or cancelling a warmup through the API refreshes it at once.
const warmupActiveTTL = 30 * time.Second

// warmupDayLength is one warmup day: the daily count resets, and the schedule
// advances, this long after the previous reset.
const warmupDayLength = 24 * time.Hour

// warmupStore is the part of repository.IPWarmupRepo the manager uses.
type warmupStore interface {
	List(ctx context.Context) ([]repository.IPWarmup, error)
	GetActive(ctx context.Context) (*repository.IPWarmup, error)
	Reserve(ctx context.Context, n int, dayStartedAfter time.Time) (*repository.IPWarmup, bool, error)
	Release(ctx context.Context, id string, n int, dayStart time.Time) error
	AdvanceDay(ctx context.Context, id string, prevReset time.Time, newDay, newLimit int, resetAt time.Time) (bool, error)
	Deactivate(ctx context.Context, id string) error
}

// WarmupManager advances the IP warmup schedule and enforces its daily limit.
// Both outbound entry points (the HTTP send API and authenticated SMTP
// submission) reserve each message's external recipients through Reserve.
// With no active warmup entry nothing is limited.
type WarmupManager struct {
	repo     warmupStore
	logger   *slog.Logger
	interval time.Duration
	release  time.Duration // bound on Release
	now      func() time.Time
	stopCh   chan struct{}

	// advanceLock serialises advanceSchedules (the loop and Reserve). It is a
	// one-slot channel rather than a mutex so a caller can stop waiting when
	// its context ends.
	advanceLock chan struct{}

	activeMu sync.Mutex
	active   bool
	activeAt time.Time // when active was read; zero = unknown
}

// NewWarmupManager creates a new warmup manager.
func NewWarmupManager(repo warmupStore, logger *slog.Logger) *WarmupManager {
	return &WarmupManager{
		repo:     repo,
		logger:   logger,
		interval: 5 * time.Minute,
		release:  warmupReleaseTimeout,
		now:      func() time.Time { return time.Now().UTC() },
		stopCh:   make(chan struct{}),

		advanceLock: make(chan struct{}, 1),
	}
}

// WarmupDecision is the outcome of reserving sends against the active warmup.
type WarmupDecision struct {
	Limited bool // a warmup is active; false means sending is unlimited
	Allowed bool
	EntryID string
	IP      string
	Day     int
	Sent    int       // sent today, including this reservation when allowed
	Limit   int       // today's limit
	ResetAt time.Time // when today's count resets and the next day's limit applies

	dayStart time.Time // the day this decision counted against (for Release)
}

// RetryAfter is how long a refused sender should wait: until the daily reset,
// and at least a minute.
func (d WarmupDecision) RetryAfter(now time.Time) time.Duration {
	wait := d.ResetAt.Sub(now)
	if wait < time.Minute {
		wait = time.Minute
	}
	return wait
}

func decisionFrom(e *repository.IPWarmup, allowed bool) WarmupDecision {
	if e == nil {
		return WarmupDecision{Allowed: true}
	}
	return WarmupDecision{
		Limited: true,
		Allowed: allowed,
		EntryID: e.ID,
		IP:      e.IPAddress,
		Day:     e.WarmupDay,
		Sent:    e.DailySent,
		Limit:   e.DailyLimit,
		ResetAt: e.LastResetAt.Add(warmupDayLength),

		dayStart: e.LastResetAt,
	}
}

// Start begins the schedule loop, with a first pass straight away.
func (m *WarmupManager) Start() {
	m.logger.Info("starting IP warmup manager", "interval", m.interval)
	go func() {
		m.backgroundPass()

		ticker := time.NewTicker(m.interval)
		defer ticker.Stop()
		for {
			select {
			case <-m.stopCh:
				return
			case <-ticker.C:
				m.backgroundPass()
			}
		}
	}()
}

// backgroundPass runs one schedule pass under its own deadline. Errors are
// logged inside advanceSchedules.
func (m *WarmupManager) backgroundPass() {
	ctx, cancel := context.WithTimeout(context.Background(), warmupPassTimeout)
	defer cancel()
	_ = m.advanceSchedules(ctx)
}

// Stop signals the warmup manager to stop.
func (m *WarmupManager) Stop() {
	m.logger.Info("stopping IP warmup manager")
	close(m.stopCh)
}

// Active reports whether a warmup is running, from a short cache, so senders
// can skip classifying recipients when nothing is limited. A lookup error
// reports true (classify, and let Reserve fail open) with the error.
func (m *WarmupManager) Active(ctx context.Context) (bool, error) {
	m.activeMu.Lock()
	defer m.activeMu.Unlock()
	now := m.now()
	if !m.activeAt.IsZero() && now.Sub(m.activeAt) < warmupActiveTTL {
		return m.active, nil
	}
	e, err := m.repo.GetActive(ctx)
	if err != nil {
		return true, err
	}
	m.active, m.activeAt = e != nil, now
	return m.active, nil
}

// Invalidate drops the cached Active answer; call it after starting or
// cancelling a warmup.
func (m *WarmupManager) Invalidate() {
	m.activeMu.Lock()
	m.activeAt = time.Time{}
	m.activeMu.Unlock()
}

// Reserve counts n external recipients against today's limit of the active
// warmup. It reserves all n or none. On a store error it returns an allowed
// decision with the error, so callers that fail open can ignore the error.
func (m *WarmupManager) Reserve(ctx context.Context, n int) (WarmupDecision, error) {
	if n <= 0 {
		return WarmupDecision{Allowed: true}, nil
	}
	// A reservation only counts against a day that is still current: once
	// the reset is due, the store refuses, and the day is advanced here
	// before trying again, so a send after the boundary is charged to the new
	// day rather than to yesterday's count (which the reset would then wipe).
	//
	// A refusal is only final when the entry read back is on a current day
	// and really has no room. The day can roll over between the store's
	// UPDATE and its read-back (the loop advanced it), which reads back as a
	// refusal with room to spare; that is retried. A rollover that fails
	// (a database error) fails open with the error, like any other.
	var e *repository.IPWarmup
	var ok bool
	for attempt := 0; attempt < 3; attempt++ {
		var err error
		e, ok, err = m.repo.Reserve(ctx, n, m.now().Add(-warmupDayLength))
		if err != nil {
			return WarmupDecision{Allowed: true}, err
		}
		if e == nil || ok {
			break
		}
		if !m.now().Before(e.LastResetAt.Add(warmupDayLength)) {
			if err := m.advanceSchedules(ctx); err != nil {
				return WarmupDecision{Allowed: true}, fmt.Errorf("advance warmup day: %w", err)
			}
			continue
		}
		if e.DailySent+n <= e.DailyLimit {
			continue // changed between the update and the read-back
		}
		break
	}
	return decisionFrom(e, ok), nil
}

// Release returns sends reserved by a decision whose message then failed to
// send. If the day has reset since, nothing is given back. Best-effort: it
// runs under its own short deadline, detached from ctx's cancellation (the
// request may already be finishing), and errors are logged.
func (m *WarmupManager) Release(ctx context.Context, d WarmupDecision, n int) {
	if !d.Limited || !d.Allowed || n <= 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), m.release)
	defer cancel()
	if err := m.repo.Release(ctx, d.EntryID, n, d.dayStart); err != nil {
		m.logger.Error("release warmup sends failed", "error", err, "ip", d.IP, "count", n)
	}
}

// advanceSchedules moves each active warmup on to its next day once a full day
// has passed since its last reset, and completes it after the last day. Missed
// days (the api was down) advance the schedule by one day, not several: the
// ramp only speeds up on days the server actually sent. The reset stays at the
// same time of day. Failures are logged, and the first is returned.
func (m *WarmupManager) advanceSchedules(ctx context.Context) error {
	select {
	case m.advanceLock <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err() // another pass holds the lock; Reserve fails open
	}
	defer func() { <-m.advanceLock }()

	entries, err := m.repo.List(ctx)
	if err != nil {
		m.logger.Error("list warmup entries failed", "error", err)
		return err
	}
	var firstErr error
	keep := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
	}

	now := m.now()
	for _, entry := range entries {
		if !entry.Active {
			continue
		}
		elapsed := now.Sub(entry.LastResetAt)
		if elapsed < warmupDayLength {
			continue
		}

		newDay := entry.WarmupDay + 1
		if newDay > WarmupDays {
			if err := m.repo.Deactivate(ctx, entry.ID); err != nil {
				m.logger.Error("deactivate warmup failed", "error", err, "ip", entry.IPAddress)
				keep(err)
			} else {
				m.logger.Info("warmup complete: IP fully warmed, sending no longer limited", "ip", entry.IPAddress)
			}
			continue
		}

		resetAt := entry.LastResetAt.Add(elapsed.Truncate(warmupDayLength))
		newLimit := repository.WarmupSchedule(newDay)
		advanced, err := m.repo.AdvanceDay(ctx, entry.ID, entry.LastResetAt, newDay, newLimit, resetAt)
		if err != nil {
			m.logger.Error("advance warmup day failed", "error", err, "ip", entry.IPAddress)
			keep(err)
			continue
		}
		if !advanced {
			continue // changed since it was listed (cancelled or already advanced)
		}
		m.logger.Info("warmup day advanced",
			"ip", entry.IPAddress,
			"day", newDay,
			"daily_limit", newLimit,
			"previous_sent", entry.DailySent,
		)
	}
	return firstErr
}
