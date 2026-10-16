package mail

import (
	"context"
	"log/slog"
	"time"

	"github.com/Veltara-Works/vectis/internal/repository"
)

// WarmupManager handles daily IP warmup schedule advancement and limit checks.
type WarmupManager struct {
	repo   *repository.IPWarmupRepo
	logger *slog.Logger
	stopCh chan struct{}
}

// NewWarmupManager creates a new warmup manager.
func NewWarmupManager(repo *repository.IPWarmupRepo, logger *slog.Logger) *WarmupManager {
	return &WarmupManager{
		repo:   repo,
		logger: logger,
		stopCh: make(chan struct{}),
	}
}

// Start begins the daily schedule advancement loop.
// Checks every hour whether any IPs need their daily counter reset and warmup day advanced.
func (m *WarmupManager) Start() {
	m.logger.Info("starting IP warmup manager")
	go func() {
		// Run immediately on start.
		m.advanceSchedules()

		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-m.stopCh:
				return
			case <-ticker.C:
				m.advanceSchedules()
			}
		}
	}()
}

// Stop signals the warmup manager to stop.
func (m *WarmupManager) Stop() {
	m.logger.Info("stopping IP warmup manager")
	close(m.stopCh)
}

// CheckLimit returns true if the IP has remaining daily capacity.
// Returns (allowed, dailySent, dailyLimit).
func (m *WarmupManager) CheckLimit(ctx context.Context, ipAddress string) (bool, int, int) {
	entry, err := m.repo.GetByIP(ctx, ipAddress)
	if err != nil || entry == nil || !entry.Active {
		// No warmup entry or inactive = unlimited (warmup complete or not configured).
		return true, 0, 0
	}
	return entry.DailySent < entry.DailyLimit, entry.DailySent, entry.DailyLimit
}

// RecordSend increments the daily send counter for an IP.
func (m *WarmupManager) RecordSend(ctx context.Context, ipAddress string) {
	entry, err := m.repo.GetByIP(ctx, ipAddress)
	if err != nil || entry == nil || !entry.Active {
		return
	}
	if err := m.repo.IncrementSent(ctx, entry.ID); err != nil {
		m.logger.Error("increment warmup sent failed", "error", err, "ip", ipAddress)
	}
}

// GetStatus returns the current warmup status for all IPs.
func (m *WarmupManager) GetStatus(ctx context.Context) ([]repository.IPWarmup, error) {
	return m.repo.List(ctx)
}

func (m *WarmupManager) advanceSchedules() {
	ctx := context.Background()
	entries, err := m.repo.List(ctx)
	if err != nil {
		m.logger.Error("list warmup entries failed", "error", err)
		return
	}

	now := time.Now().UTC()
	for _, entry := range entries {
		if !entry.Active {
			continue
		}

		// Check if we need to advance to the next day (24h since last reset).
		if now.Sub(entry.LastResetAt) < 24*time.Hour {
			continue
		}

		newDay := entry.WarmupDay + 1
		newLimit := repository.WarmupSchedule(newDay)

		if err := m.repo.AdvanceDay(ctx, entry.ID, newDay, newLimit); err != nil {
			m.logger.Error("advance warmup day failed", "error", err, "ip", entry.IPAddress)
			continue
		}

		m.logger.Info("warmup day advanced",
			"ip", entry.IPAddress,
			"day", newDay,
			"daily_limit", newLimit,
			"previous_sent", entry.DailySent,
		)

		// Auto-complete warmup after 30 days.
		if newDay > 30 {
			if err := m.repo.Deactivate(ctx, entry.ID); err != nil {
				m.logger.Error("deactivate warmup failed", "error", err, "ip", entry.IPAddress)
			} else {
				m.logger.Info("warmup complete — IP fully warmed", "ip", entry.IPAddress)
			}
		}
	}
}
