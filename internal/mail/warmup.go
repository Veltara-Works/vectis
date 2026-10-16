package mail

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/Veltara-Works/vectis/internal/repository"
)

// WarmupDays is the length of the warmup schedule. The warmup completes (and
// stops limiting) when the day after the last one begins.
const WarmupDays = 30

// warmupDayLength is one warmup day: the daily count resets, and the schedule
// advances, this long after the previous reset.
const warmupDayLength = 24 * time.Hour

// warmupStore is the part of repository.IPWarmupRepo the manager uses.
type warmupStore interface {
	List(ctx context.Context) ([]repository.IPWarmup, error)
	Reserve(ctx context.Context, n int) (*repository.IPWarmup, bool, error)
	Release(ctx context.Context, id string, n int) error
	AdvanceDay(ctx context.Context, id string, newDay, newLimit int, resetAt time.Time) error
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
	now      func() time.Time
	stopCh   chan struct{}

	advanceMu sync.Mutex // serialises advanceSchedules (ticker and Reserve)
}

// NewWarmupManager creates a new warmup manager.
func NewWarmupManager(repo warmupStore, logger *slog.Logger) *WarmupManager {
	return &WarmupManager{
		repo:     repo,
		logger:   logger,
		interval: 5 * time.Minute,
		now:      func() time.Time { return time.Now().UTC() },
		stopCh:   make(chan struct{}),
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
	}
}

// Start begins the schedule loop, with a first pass straight away.
func (m *WarmupManager) Start() {
	m.logger.Info("starting IP warmup manager", "interval", m.interval)
	go func() {
		m.advanceSchedules(context.Background())

		ticker := time.NewTicker(m.interval)
		defer ticker.Stop()
		for {
			select {
			case <-m.stopCh:
				return
			case <-ticker.C:
				m.advanceSchedules(context.Background())
			}
		}
	}()
}

// Stop signals the warmup manager to stop.
func (m *WarmupManager) Stop() {
	m.logger.Info("stopping IP warmup manager")
	close(m.stopCh)
}

// Reserve counts n external recipients against today's limit of the active
// warmup. It reserves all n or none. On a store error it returns an allowed
// decision with the error, so callers that fail open can ignore the error.
func (m *WarmupManager) Reserve(ctx context.Context, n int) (WarmupDecision, error) {
	if n <= 0 {
		return WarmupDecision{Allowed: true}, nil
	}
	e, ok, err := m.repo.Reserve(ctx, n)
	if err != nil {
		return WarmupDecision{Allowed: true}, err
	}
	if e != nil && !ok && !m.now().Before(e.LastResetAt.Add(warmupDayLength)) {
		// Refused, but today's count is already due to reset and the loop
		// hasn't got to it yet: advance now and try once more.
		m.advanceSchedules(ctx)
		e, ok, err = m.repo.Reserve(ctx, n)
		if err != nil {
			return WarmupDecision{Allowed: true}, err
		}
	}
	return decisionFrom(e, ok), nil
}

// Release returns sends reserved by a decision whose message then failed to
// send. Best-effort: errors are logged.
func (m *WarmupManager) Release(ctx context.Context, d WarmupDecision, n int) {
	if !d.Limited || !d.Allowed || n <= 0 {
		return
	}
	if err := m.repo.Release(ctx, d.EntryID, n); err != nil {
		m.logger.Error("release warmup sends failed", "error", err, "ip", d.IP, "count", n)
	}
}

// advanceSchedules moves each active warmup on to its next day once a full day
// has passed since its last reset, and completes it after the last day. Missed
// days (the api was down) advance the schedule by one day, not several: the
// ramp only speeds up on days the server actually sent. The reset stays at the
// same time of day.
func (m *WarmupManager) advanceSchedules(ctx context.Context) {
	m.advanceMu.Lock()
	defer m.advanceMu.Unlock()

	entries, err := m.repo.List(ctx)
	if err != nil {
		m.logger.Error("list warmup entries failed", "error", err)
		return
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
			} else {
				m.logger.Info("warmup complete: IP fully warmed, sending no longer limited", "ip", entry.IPAddress)
			}
			continue
		}

		resetAt := entry.LastResetAt.Add(elapsed.Truncate(warmupDayLength))
		newLimit := repository.WarmupSchedule(newDay)
		if err := m.repo.AdvanceDay(ctx, entry.ID, newDay, newLimit, resetAt); err != nil {
			m.logger.Error("advance warmup day failed", "error", err, "ip", entry.IPAddress)
			continue
		}
		m.logger.Info("warmup day advanced",
			"ip", entry.IPAddress,
			"day", newDay,
			"daily_limit", newLimit,
			"previous_sent", entry.DailySent,
		)
	}
}
