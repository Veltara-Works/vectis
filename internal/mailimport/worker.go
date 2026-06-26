package mailimport

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/Veltara-Works/vectis/internal/repository"
)

const (
	// maxConcurrentImports bounds simultaneous imports — each is a long-lived,
	// network- and IO-heavy job, so a small cap protects Dovecot and the box.
	maxConcurrentImports = 2
	enqueueBuffer        = 64
	// recoveryInterval re-scans for pending/running jobs the live enqueue path
	// missed (a full buffer, or a crash that left a job mid-flight). The
	// dedupe-by-Message-ID design makes re-running a partial job safe.
	recoveryInterval = 1 * time.Minute
	// maxJobDuration is a generous backstop on a single import's total wall time.
	// A genuinely large mailbox finishes well within it; it only fires for a job
	// stuck making pathologically slow progress, so the slot is reclaimed and the
	// job recovered (resumed via the safe Message-ID dedupe) on a later scan.
	maxJobDuration = 24 * time.Hour
)

// ActiveLister is the worker's view of the job repository: the jobs it must pick
// up on startup and on each recovery scan.
type ActiveLister interface {
	ListActive(ctx context.Context) ([]repository.ImportJob, error)
}

// runner runs a single job to completion; *Importer satisfies it. An interface
// keeps the worker's scheduling logic unit-testable without real IMAP.
type runner interface {
	Run(ctx context.Context, jobID string)
}

// Worker runs import jobs in the background: it drains an enqueue channel (fed by
// the API on job creation) and periodically recovers any pending/running job the
// channel missed. Mirrors the webhook dispatcher's Start/Stop lifecycle.
type Worker struct {
	importer runner
	active   ActiveLister
	logger   *slog.Logger

	enqueue chan string
	stopCh  chan struct{}
	sem     chan struct{}

	rootCtx context.Context // cancelled by Stop(); parent of every job context
	cancel  context.CancelFunc

	mu      sync.Mutex
	running map[string]struct{} // jobs in-flight in THIS process (dedupe guard)
}

// NewWorker creates an import worker.
func NewWorker(importer *Importer, active ActiveLister, logger *slog.Logger) *Worker {
	ctx, cancel := context.WithCancel(context.Background())
	return &Worker{
		importer: importer,
		active:   active,
		logger:   logger,
		enqueue:  make(chan string, enqueueBuffer),
		stopCh:   make(chan struct{}),
		sem:      make(chan struct{}, maxConcurrentImports),
		rootCtx:  ctx,
		cancel:   cancel,
		running:  make(map[string]struct{}),
	}
}

// Start begins the worker loop in a background goroutine.
func (w *Worker) Start() {
	w.logger.Info("starting imap import worker", "max_concurrent", maxConcurrentImports)
	go w.loop()
}

// Stop signals the worker loop to stop and cancels the root context so in-flight
// imports are interrupted at their next context-aware step (rather than running
// to completion or hanging). Interrupted jobs are recovered on next start.
func (w *Worker) Stop() {
	w.logger.Info("stopping imap import worker")
	w.cancel()
	close(w.stopCh)
}

// Enqueue asks the worker to run a job now. Non-blocking: if the buffer is full
// the job is still picked up by the next recovery scan.
func (w *Worker) Enqueue(jobID string) {
	select {
	case w.enqueue <- jobID:
	default:
		w.logger.Warn("imap import enqueue buffer full; job deferred to recovery scan", "job_id", jobID)
	}
}

func (w *Worker) loop() {
	w.recover() // startup recovery
	ticker := time.NewTicker(recoveryInterval)
	defer ticker.Stop()
	for {
		select {
		case <-w.stopCh:
			return
		case id := <-w.enqueue:
			w.dispatch(id)
		case <-ticker.C:
			w.recover()
		}
	}
}

// recover re-dispatches all pending/running jobs (already-running ones are
// skipped by the in-process guard in dispatch).
func (w *Worker) recover() {
	jobs, err := w.active.ListActive(w.rootCtx)
	if err != nil {
		w.logger.Error("imap import recovery scan failed", "error", err)
		return
	}
	for _, j := range jobs {
		w.dispatch(j.ID)
	}
}

// dispatch runs a job under the concurrency cap, skipping any job already
// in-flight in this process so the enqueue path and recovery scan can't run the
// same import twice (which would race the de-dup check and double-append).
func (w *Worker) dispatch(jobID string) {
	w.mu.Lock()
	if _, busy := w.running[jobID]; busy {
		w.mu.Unlock()
		return
	}
	w.running[jobID] = struct{}{}
	w.mu.Unlock()

	release := func() {
		w.mu.Lock()
		delete(w.running, jobID)
		w.mu.Unlock()
	}

	select {
	case w.sem <- struct{}{}:
	case <-w.stopCh:
		release()
		return
	}
	go func() {
		defer func() {
			<-w.sem
			release()
		}()
		// Per-job context: descends from rootCtx (so Stop() cancels it) and has
		// a generous total-duration backstop so a job that makes pathologically
		// slow progress cannot occupy a slot indefinitely. Combined with the
		// source client's per-command timeout, a hung source is always recovered.
		ctx, cancel := context.WithTimeout(w.rootCtx, maxJobDuration)
		defer cancel()
		w.importer.Run(ctx, jobID)
	}()
}
