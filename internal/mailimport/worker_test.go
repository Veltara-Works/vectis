package mailimport

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Veltara-Works/vectis/internal/repository"
)

type recordingRunner struct {
	mu      sync.Mutex
	started int32
	release chan struct{} // each Run blocks until a token is sent
	seen    []string
}

func (r *recordingRunner) Run(_ context.Context, jobID string) {
	atomic.AddInt32(&r.started, 1)
	r.mu.Lock()
	r.seen = append(r.seen, jobID)
	r.mu.Unlock()
	<-r.release
}

type fakeActive struct{ jobs []repository.ImportJob }

func (f *fakeActive) ListActive(context.Context) ([]repository.ImportJob, error) { return f.jobs, nil }

func newTestWorker(r runner, a ActiveLister) *Worker {
	ctx, cancel := context.WithCancel(context.Background())
	return &Worker{
		importer: r,
		active:   a,
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		enqueue:  make(chan string, enqueueBuffer),
		stopCh:   make(chan struct{}),
		sem:      make(chan struct{}, maxConcurrentImports),
		rootCtx:  ctx,
		cancel:   cancel,
		running:  make(map[string]struct{}),
	}
}

// A job already in-flight must not be dispatched a second time (the enqueue path
// and the recovery scan must not race the de-dup check and double-append).
func TestWorker_NoDoubleDispatch(t *testing.T) {
	r := &recordingRunner{release: make(chan struct{}, 10)}
	w := newTestWorker(r, &fakeActive{})

	w.dispatch("job-1") // starts and blocks in Run
	// Wait until Run is actually in-flight.
	waitFor(t, func() bool { return atomic.LoadInt32(&r.started) == 1 })

	w.dispatch("job-1") // should be a no-op (already running)
	w.dispatch("job-1")

	if got := atomic.LoadInt32(&r.started); got != 1 {
		t.Fatalf("job dispatched %d times while in-flight, want 1", got)
	}

	// Let it finish, then it can be dispatched again.
	r.release <- struct{}{}
	waitFor(t, func() bool {
		w.mu.Lock()
		defer w.mu.Unlock()
		_, busy := w.running["job-1"]
		return !busy
	})
	w.dispatch("job-1")
	waitFor(t, func() bool { return atomic.LoadInt32(&r.started) == 2 })
	r.release <- struct{}{}
}

// Startup recovery dispatches every pending/running job exactly once.
func TestWorker_RecoverDispatchesActive(t *testing.T) {
	r := &recordingRunner{release: make(chan struct{}, 10)}
	a := &fakeActive{jobs: []repository.ImportJob{{ID: "a"}, {ID: "b"}}}
	w := newTestWorker(r, a)

	w.recover()
	waitFor(t, func() bool { return atomic.LoadInt32(&r.started) == 2 })
	r.release <- struct{}{}
	r.release <- struct{}{}

	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.seen) != 2 {
		t.Fatalf("recover dispatched %d jobs, want 2", len(r.seen))
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("condition not met within timeout")
}
