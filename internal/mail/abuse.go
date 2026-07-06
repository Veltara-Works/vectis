package mail

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/valkey-io/valkey-go"
)

// AbuseDetector tracks outbound sending rates and detects anomalies using
// Valkey per-hour fixed-window counters (keyed YYYYMMDDHH). The window is FIXED,
// not sliding: counts reset at each :00 boundary, so a determined sender can
// burst up to ~2x a threshold across an hour boundary (ABUSE-1). That is an
// accepted tradeoff for a coarse backstop — the per-recipient metering and the
// auto-suspend ceiling are the primary controls.
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
// rates, increments the counters by ONE, and returns the check result. Called
// synchronously in the send handler BEFORE submitting to Postfix, and by the
// Postfix policy backend (which Postfix already invokes once per recipient).
func (d *AbuseDetector) CheckAndRecord(ctx context.Context, mailboxID, domainID string) (*AbuseCheckResult, error) {
	return d.CheckAndRecordN(ctx, mailboxID, domainID, 1)
}

// CheckAndRecordN is CheckAndRecord but records n recipients in one shot. The
// API send path passes the message's total recipient count (To+CC+BCC) so the
// abuse counters meter DELIVERED emails, not messages — otherwise a single API
// call fanning out to ~1000 recipients counts as 1 against the hourly caps and
// slips under every abuse threshold (SEND-2). n is clamped to >= 1.
func (d *AbuseDetector) CheckAndRecordN(ctx context.Context, mailboxID, domainID string, n int) (*AbuseCheckResult, error) {
	if n < 1 {
		n = 1
	}
	now := time.Now().UTC()
	hourKey := now.Format("2006010215") // YYYYMMDDHH
	prevHourKey := now.Add(-1 * time.Hour).Format("2006010215")

	mbKey := fmt.Sprintf("abuse:mailbox:%s:%s", mailboxID, hourKey)
	dmKey := fmt.Sprintf("abuse:domain:%s:%s", domainID, hourKey)
	mbPrevKey := fmt.Sprintf("abuse:mailbox:%s:%s", mailboxID, prevHourKey)

	// Increment counters by n and get current values atomically via pipeline.
	mbIncrCmd := d.vk.B().Incrby().Key(mbKey).Increment(int64(n)).Build()
	dmIncrCmd := d.vk.B().Incrby().Key(dmKey).Increment(int64(n)).Build()
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

	// Set TTL on counters (2 hours — current + lookback), but only on the first
	// write of the hour. With INCRBY n a freshly-created key returns exactly n
	// (not 1), so compare against n — otherwise the counter never expires.
	if mbCount == int64(n) {
		d.vk.Do(ctx, d.vk.B().Expire().Key(mbKey).Seconds(7200).Build())
	}
	if dmCount == int64(n) {
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

// CheckAndRecordDomain enforces the per-domain hourly cap on the no-mailbox
// send path — a From: address on an owned domain that matches no provisioned
// mailbox (e.g. noreply@) has no per-mailbox counter, so without this it
// bypasses abuse limiting entirely (audit SEND-1). It increments the same
// domain counter CheckAndRecord uses for mailbox sends (so the domain aggregate
// stays consistent) and refuses the individual send once the domain exceeds its
// hourly cap. Unlike the per-mailbox path it never auto-suspends — a
// domain-wide suspend would take down every mailbox, which is too broad.
//
// The cap is DomainHourlySuspend when the operator set it, else DomainHourlyLimit
// (default 1000). Either way this turns the previously alert-only domain
// threshold into a hard ceiling for the otherwise-unmetered no-mailbox path.
func (d *AbuseDetector) CheckAndRecordDomain(ctx context.Context, domainID string) (*AbuseCheckResult, error) {
	return d.CheckAndRecordDomainN(ctx, domainID, 1)
}

// CheckAndRecordDomainN is CheckAndRecordDomain metering n recipients — the
// no-mailbox send path's SEND-2 counterpart (see CheckAndRecordN).
func (d *AbuseDetector) CheckAndRecordDomainN(ctx context.Context, domainID string, n int) (*AbuseCheckResult, error) {
	if n < 1 {
		n = 1
	}
	hourKey := time.Now().UTC().Format("2006010215") // YYYYMMDDHH
	dmKey := fmt.Sprintf("abuse:domain:%s:%s", domainID, hourKey)

	dmCount, err := d.vk.Do(ctx, d.vk.B().Incrby().Key(dmKey).Increment(int64(n)).Build()).AsInt64()
	if err != nil {
		return nil, fmt.Errorf("incr domain counter: %w", err)
	}
	if dmCount == int64(n) {
		d.vk.Do(ctx, d.vk.B().Expire().Key(dmKey).Seconds(7200).Build())
	}

	result := &AbuseCheckResult{Allowed: true, DomainCount: dmCount}

	limit := d.cfg.DomainHourlySuspend
	if limit <= 0 {
		limit = d.cfg.DomainHourlyLimit
	}
	if limit > 0 && dmCount > int64(limit) {
		result.Allowed = false
		result.Reason = fmt.Sprintf("domain sending rate limit exceeded: %d messages this hour (limit: %d)",
			dmCount, limit)
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
