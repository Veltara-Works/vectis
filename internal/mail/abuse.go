package mail

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/valkey-io/valkey-go"
)

// AbuseDetector tracks outbound sending rates and detects anomalies.
// Uses Valkey sliding window counters for real-time detection.
type AbuseDetector struct {
	vk     valkey.Client
	logger *slog.Logger
	cfg    AbuseConfig
}

// AbuseConfig holds thresholds for abuse detection.
type AbuseConfig struct {
	// Per-mailbox limits (per hour).
	MailboxHourlyLimit   int // default 100; 0 = disabled
	MailboxHourlySuspend int // auto-suspend above this; default 500

	// Per-domain limits (per hour).
	DomainHourlyLimit   int // alert threshold; default 1000
	DomainHourlySuspend int // not auto-suspended (too broad); default 0 = disabled

	// Spike detection: if current hour rate > N * previous hour average, flag as spike.
	SpikeMultiplier float64 // default 5.0
}

// DefaultAbuseConfig returns sensible defaults.
func DefaultAbuseConfig() AbuseConfig {
	return AbuseConfig{
		MailboxHourlyLimit:   100,
		MailboxHourlySuspend: 500,
		DomainHourlyLimit:    1000,
		DomainHourlySuspend:  0,
		SpikeMultiplier:      5.0,
	}
}

// AbuseCheckResult is the outcome of a pre-send abuse check.
type AbuseCheckResult struct {
	Allowed       bool
	Reason        string
	MailboxCount  int64 // current hour count for the mailbox
	DomainCount   int64 // current hour count for the domain
	SpikeDetected bool
}

// NewAbuseDetector creates a new abuse detector.
func NewAbuseDetector(vk valkey.Client, cfg AbuseConfig, logger *slog.Logger) *AbuseDetector {
	if cfg.MailboxHourlyLimit == 0 {
		cfg.MailboxHourlyLimit = 100
	}
	if cfg.MailboxHourlySuspend == 0 {
		cfg.MailboxHourlySuspend = 500
	}
	if cfg.DomainHourlyLimit == 0 {
		cfg.DomainHourlyLimit = 1000
	}
	if cfg.SpikeMultiplier == 0 {
		cfg.SpikeMultiplier = 5.0
	}
	return &AbuseDetector{vk: vk, logger: logger, cfg: cfg}
}

// CheckAndRecord validates whether a send should proceed based on current
// rates, increments the counters, and returns the check result.
// Called synchronously in the send handler BEFORE submitting to Postfix.
func (d *AbuseDetector) CheckAndRecord(ctx context.Context, mailboxID, domainID string) (*AbuseCheckResult, error) {
	now := time.Now().UTC()
	hourKey := now.Format("2006010215") // YYYYMMDDHH
	prevHourKey := now.Add(-1 * time.Hour).Format("2006010215")

	mbKey := fmt.Sprintf("abuse:mailbox:%s:%s", mailboxID, hourKey)
	dmKey := fmt.Sprintf("abuse:domain:%s:%s", domainID, hourKey)
	mbPrevKey := fmt.Sprintf("abuse:mailbox:%s:%s", mailboxID, prevHourKey)

	// Increment counters and get current values atomically via pipeline.
	mbIncrCmd := d.vk.B().Incr().Key(mbKey).Build()
	dmIncrCmd := d.vk.B().Incr().Key(dmKey).Build()
	mbPrevCmd := d.vk.B().Get().Key(mbPrevKey).Build()

	results := d.vk.DoMulti(ctx, mbIncrCmd, dmIncrCmd, mbPrevCmd)

	mbCount, err := results[0].AsInt64()
	if err != nil {
		return nil, fmt.Errorf("incr mailbox counter: %w", err)
	}

	dmCount, err := results[1].AsInt64()
	if err != nil {
		return nil, fmt.Errorf("incr domain counter: %w", err)
	}

	// Set TTL on counters (2 hours — current + lookback).
	if mbCount == 1 {
		d.vk.Do(ctx, d.vk.B().Expire().Key(mbKey).Seconds(7200).Build())
	}
	if dmCount == 1 {
		d.vk.Do(ctx, d.vk.B().Expire().Key(dmKey).Seconds(7200).Build())
	}

	var mbPrevCount int64
	if prevStr, err := results[2].ToString(); err == nil {
		mbPrevCount, _ = strconv.ParseInt(prevStr, 10, 64)
	}

	result := &AbuseCheckResult{
		Allowed:      true,
		MailboxCount: mbCount,
		DomainCount:  dmCount,
	}

	// Check mailbox auto-suspend threshold.
	if d.cfg.MailboxHourlySuspend > 0 && mbCount > int64(d.cfg.MailboxHourlySuspend) {
		result.Allowed = false
		result.Reason = fmt.Sprintf("mailbox sending suspended: %d messages this hour (limit: %d)",
			mbCount, d.cfg.MailboxHourlySuspend)
		return result, nil
	}

	// Check spike detection: current hour rate > N * previous hour.
	if mbPrevCount > 10 && d.cfg.SpikeMultiplier > 0 {
		if float64(mbCount) > d.cfg.SpikeMultiplier*float64(mbPrevCount) {
			result.SpikeDetected = true
		}
	}

	return result, nil
}

// GetMailboxHourlyCount returns the current hour send count for a mailbox.
func (d *AbuseDetector) GetMailboxHourlyCount(ctx context.Context, mailboxID string) (int64, error) {
	hourKey := time.Now().UTC().Format("2006010215")
	key := fmt.Sprintf("abuse:mailbox:%s:%s", mailboxID, hourKey)
	result, err := d.vk.Do(ctx, d.vk.B().Get().Key(key).Build()).ToString()
	if err != nil {
		return 0, nil // key doesn't exist = 0 sends
	}
	count, _ := strconv.ParseInt(result, 10, 64)
	return count, nil
}

// GetDomainHourlyCount returns the current hour send count for a domain.
func (d *AbuseDetector) GetDomainHourlyCount(ctx context.Context, domainID string) (int64, error) {
	hourKey := time.Now().UTC().Format("2006010215")
	key := fmt.Sprintf("abuse:domain:%s:%s", domainID, hourKey)
	result, err := d.vk.Do(ctx, d.vk.B().Get().Key(key).Build()).ToString()
	if err != nil {
		return 0, nil
	}
	count, _ := strconv.ParseInt(result, 10, 64)
	return count, nil
}
