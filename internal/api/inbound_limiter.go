package api

import (
	"sync"

	vectismetrics "github.com/Veltara-Works/vectis/internal/metrics"
)

// maxInboundAsyncBytes bounds the total in-memory size of inbound messages
// being processed asynchronously at once. Each inbound message can be up to
// maxInboundBodySize (72 MB) and its async handlers (full-message webhook, ARF
// parse) decode + reparse it into several in-memory copies, so the api
// container (mem_limit 512 MB) would OOM under a mail flood that spawned an
// unbounded goroutine per message. The budget is byte-weighted rather than a
// flat count so a burst of small messages still parallelises while a few
// max-size messages serialise. (#120)
//
// Tasks are weighted by len(RawMessageB64) — the base64 string actually held
// for the goroutine's lifetime, ~1.33x the raw size (a deliberately conservative
// proxy for the larger decoded+parsed peak). NOT notif.Size: that is supplied by
// the inbound-notify script, and a missing/zero value would make acquire(0)
// always succeed and silently defeat the bound, whereas the base64 length is
// intrinsic to the payload and never zero behind the != "" guard.
const maxInboundAsyncBytes = 64 << 20 // 64 MB of encoded inbound in flight

// inboundAsyncLimiter is a byte-weighted admission limiter for fire-and-forget
// inbound processing. It is not a queue: when the budget is exhausted the task
// is dropped (these are best-effort webhooks / FBL records, and queueing would
// let memory grow under the very flood we're bounding).
type inboundAsyncLimiter struct {
	mu       sync.Mutex
	inFlight int64
	max      int64
}

func newInboundAsyncLimiter(maxBytes int64) *inboundAsyncLimiter {
	return &inboundAsyncLimiter{max: maxBytes}
}

// acquire reserves n bytes if that stays within budget, returning true. It
// always admits a task when nothing else is in flight — even one larger than
// the whole budget — so a single oversized-but-legitimate message is never
// permanently undeliverable; it just runs alone. Returns false (drop) when
// other work is in flight and admitting n would exceed the budget.
func (l *inboundAsyncLimiter) acquire(n int64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.inFlight > 0 && l.inFlight+n > l.max {
		return false
	}
	l.inFlight += n
	return true
}

func (l *inboundAsyncLimiter) release(n int64) {
	l.mu.Lock()
	l.inFlight -= n
	if l.inFlight < 0 {
		l.inFlight = 0
	}
	l.mu.Unlock()
}

// spawnInboundAsync runs fn in a goroutine, admitted through the byte-weighted
// inbound budget so a mail flood can't spawn unbounded goroutines each holding a
// full message in memory (#120). sizeBytes is the weight — callers pass
// len(RawMessageB64), the in-memory size of the held message (see
// maxInboundAsyncBytes for why that, not notif.Size). If the budget is exhausted
// the task is dropped with a warning + metric rather than queued. When the
// limiter is unset (e.g. tests construct a bare Server) it falls back to a
// direct goroutine so behaviour is unchanged.
func (s *Server) spawnInboundAsync(task string, sizeBytes int, fn func()) {
	if s.inboundAsync == nil {
		go fn()
		return
	}
	n := int64(sizeBytes)
	if !s.inboundAsync.acquire(n) {
		s.logger.Warn("inbound async budget exhausted, dropping task",
			"task", task, "size_bytes", sizeBytes, "max_bytes", s.inboundAsync.max)
		vectismetrics.InboundAsyncDropped.WithLabelValues(task).Inc()
		return
	}
	go func() {
		defer s.inboundAsync.release(n)
		fn()
	}()
}
