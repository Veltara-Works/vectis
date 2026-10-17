package monitor

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Valkey memory pressure (#254 item 3). Valkey runs with allkeys-lru, so when
// it reaches maxmemory it evicts keys rather than refusing writes: Bayes
// tokens, greylist and rate-limit state, sessions. That degrades quietly, so
// the monitor warns before and when it happens.
const (
	valkeyMemoryWarnPercent = 80
	// An eviction keeps the alert firing this long, so one burst doesn't send a
	// WARN and then a "healthy" recovery a minute later.
	valkeyEvictionHold = time.Hour
)

// valkeyInfo holds the INFO fields the check uses.
type valkeyInfo struct {
	UsedMemory  int64
	MaxMemory   int64 // 0 = no limit
	EvictedKeys int64 // cumulative since Valkey started
}

// parseValkeyInfo reads used_memory, maxmemory and evicted_keys from INFO
// output ("key:value" lines, "# Section" headers). All three must be present.
func parseValkeyInfo(info string) (valkeyInfo, error) {
	var v valkeyInfo
	found := 0
	for _, line := range strings.Split(info, "\n") {
		key, val, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		var dst *int64
		switch key {
		case "used_memory":
			dst = &v.UsedMemory
		case "maxmemory":
			dst = &v.MaxMemory
		case "evicted_keys":
			dst = &v.EvictedKeys
		default:
			continue
		}
		n, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return valkeyInfo{}, fmt.Errorf("parse %s %q: %w", key, val, err)
		}
		*dst = n
		found++
	}
	if found != 3 {
		return valkeyInfo{}, fmt.Errorf("INFO is missing used_memory, maxmemory or evicted_keys")
	}
	return v, nil
}

// valkeyMemState is what the check remembers between runs.
type valkeyMemState struct {
	haveBaseline bool
	evicted      int64
	lastEviction time.Time
}

// evalValkeyMemory is the pure decision: it returns the updated state and a
// warning message, empty when healthy. A rise in evicted_keys counts as a new
// eviction; so does a non-zero count on the first sample, since nothing earlier
// was observed. A drop (Valkey restarted) resets the baseline.
func evalValkeyMemory(st valkeyMemState, info valkeyInfo, now time.Time) (valkeyMemState, string) {
	var newly int64
	switch {
	case !st.haveBaseline, info.EvictedKeys < st.evicted: // first sample, or Valkey restarted
		newly = info.EvictedKeys
	default:
		newly = info.EvictedKeys - st.evicted
	}
	if newly > 0 {
		st.lastEviction = now
	}
	st.haveBaseline = true
	st.evicted = info.EvictedKeys

	var parts []string
	if info.MaxMemory > 0 {
		pct := info.UsedMemory * 100 / info.MaxMemory
		if pct >= valkeyMemoryWarnPercent {
			parts = append(parts, fmt.Sprintf("Valkey memory at %d%% of its limit (%s of %s); at the limit it starts evicting keys",
				pct, mib(info.UsedMemory), mib(info.MaxMemory)))
		}
	}
	if !st.lastEviction.IsZero() && now.Sub(st.lastEviction) < valkeyEvictionHold {
		if newly > 0 {
			parts = append(parts, fmt.Sprintf("Valkey evicted %d key(s) (%d since it started): spam-filter learning, greylisting and rate-limit state are being dropped",
				newly, info.EvictedKeys))
		} else {
			parts = append(parts, fmt.Sprintf("Valkey evicted keys in the last hour (%d since it started)", info.EvictedKeys))
		}
	}
	return st, strings.Join(parts, "; ")
}

func mib(b int64) string { return fmt.Sprintf("%.1f MiB", float64(b)/(1<<20)) }

// checkValkeyMemory warns on Valkey memory pressure and evictions. Its service
// name is "valkey-memory", not "valkey", so its WARN can't dedup against or be
// resolved by the connection check's alerts.
func (m *Monitor) checkValkeyMemory(ctx context.Context) {
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := m.vk.Do(checkCtx, m.vk.B().Info().Section("memory", "stats").Build()).ToString()
	if err != nil {
		m.logger.Debug("valkey INFO failed", "error", err) // the connection check alerts on this
		return
	}
	info, err := parseValkeyInfo(out)
	if err != nil {
		m.logger.Warn("valkey INFO unreadable", "error", err)
		return
	}

	m.vkMemMu.Lock()
	st, msg := evalValkeyMemory(m.vkMem, info, m.now())
	m.vkMem = st
	m.vkMemMu.Unlock()

	if msg != "" {
		m.alerter.Send(ctx, "WARN", "valkey-memory", msg)
		m.alerter.ResolveServiceExcept(ctx, "valkey-memory", "warn")
	} else {
		m.alerter.ResolveService(ctx, "valkey-memory")
	}
}
