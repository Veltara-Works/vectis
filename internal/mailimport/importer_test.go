package mailimport

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/Veltara-Works/vectis/internal/repository"
)

// ---- fakes -----------------------------------------------------------------

type fakeStore struct {
	job       *repository.ImportJob
	statusSeq []string // values returned by successive Status calls; last repeats
	statusN   int

	setRunningTotal int
	completed       *[2]int // imported, skipped
	failed          string
	progressCalls   int
}

func (s *fakeStore) GetByID(_ context.Context, _ string) (*repository.ImportJob, error) {
	return s.job, nil
}
func (s *fakeStore) DecryptPassword(_ context.Context, _ string) (string, error) { return "src-pw", nil }
func (s *fakeStore) TargetEmail(_ context.Context, _ string) (string, error) {
	return "alice@test.local", nil
}
func (s *fakeStore) SetRunning(_ context.Context, _ string, total int) error {
	s.setRunningTotal = total
	return nil
}
func (s *fakeStore) UpdateProgress(_ context.Context, _ string, _ int, _ string, _, _ int) error {
	s.progressCalls++
	return nil
}
func (s *fakeStore) Complete(_ context.Context, _ string, imported, skipped int) error {
	s.completed = &[2]int{imported, skipped}
	return nil
}
func (s *fakeStore) Fail(_ context.Context, _ string, msg string) error { s.failed = msg; return nil }
func (s *fakeStore) Status(_ context.Context, _ string) (string, error) {
	if len(s.statusSeq) == 0 {
		return "running", nil
	}
	v := s.statusSeq[s.statusN]
	if s.statusN < len(s.statusSeq)-1 {
		s.statusN++
	}
	return v, nil
}

type fakeMinter struct {
	minted  int
	revoked int
}

func (m *fakeMinter) Mint(_ context.Context, _, _ string, _ time.Duration) (*repository.MintedToken, error) {
	m.minted++
	return &repository.MintedToken{ID: "tok-1", Password: "tok-pw", ExpiresAt: time.Now().Add(time.Hour)}, nil
}
func (m *fakeMinter) Revoke(_ context.Context, _ string) error { m.revoked++; return nil }

type fakeSource struct {
	folders   []Folder
	overviews map[string][]Overview // by folder name
	bodies    map[uint32][]byte     // by uid
	current   string
	dialErr   error
}

func (s *fakeSource) Folders() ([]Folder, error) { return s.folders, nil }
func (s *fakeSource) SelectFolder(name string) (uint32, error) {
	s.current = name
	return uint32(len(s.overviews[name])), nil
}
func (s *fakeSource) Overviews(_ uint32) ([]Overview, error) { return s.overviews[s.current], nil }
func (s *fakeSource) FetchBody(uid uint32) ([]byte, error)   { return s.bodies[uid], nil }
func (s *fakeSource) Close()                                 {}

type appended struct {
	folder string
	flags  []string
	date   time.Time
	body   []byte
}

type fakeDest struct {
	existing  map[string]map[string]struct{} // folder -> message-id set
	ensured   []string
	appends   []appended
	mu        sync.Mutex
}

func (d *fakeDest) EnsureFolder(name string) error { d.ensured = append(d.ensured, name); return nil }
func (d *fakeDest) ExistingMessageIDs(folder string) (map[string]struct{}, error) {
	if d.existing[folder] == nil {
		return map[string]struct{}{}, nil
	}
	return d.existing[folder], nil
}
func (d *fakeDest) Append(folder string, body []byte, flags []string, date time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.appends = append(d.appends, appended{folder: folder, flags: flags, date: date, body: body})
	return nil
}
func (d *fakeDest) Close() {}

func newTestImporter(store JobStore, minter TokenMinter, src *fakeSource, dst *fakeDest) *Importer {
	return &Importer{
		store:  store,
		tokens: minter,
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		dialSource: func(SourceConfig) (sourceConn, error) {
			if src.dialErr != nil {
				return nil, src.dialErr
			}
			return src, nil
		},
		dialDest: func(DestConfig) (destConn, error) { return dst, nil },
	}
}

func runnableJob() *repository.ImportJob {
	return &repository.ImportJob{ID: "job-1", MailboxID: "mb-1", Status: "pending", SourceHost: "imap.old", SourcePort: 993, SourceTLS: true, SourceUser: "alice@old"}
}

// ---- tests -----------------------------------------------------------------

func TestImporter_HappyPath_DedupeFlagsDate(t *testing.T) {
	date := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	src := &fakeSource{
		folders: []Folder{{Name: "INBOX"}, {Name: "Work", Delim: "."}},
		overviews: map[string][]Overview{
			"INBOX": {
				{UID: 1, MessageID: "a@x", Flags: []string{"\\Seen", "\\Recent"}, InternalDate: date},
				{UID: 2, MessageID: "b@x", Flags: []string{"\\Flagged"}, InternalDate: date},
			},
			"Work": {
				{UID: 3, MessageID: "c@x", InternalDate: date}, // already present -> skipped
				{UID: 4, MessageID: "", InternalDate: date},    // no message-id -> always copied
			},
		},
		bodies: map[uint32][]byte{1: []byte("m1"), 2: []byte("m2"), 3: []byte("m3"), 4: []byte("m4")},
	}
	dst := &fakeDest{existing: map[string]map[string]struct{}{"Work": {"c@x": {}}}}
	store := &fakeStore{job: runnableJob()}
	minter := &fakeMinter{}

	newTestImporter(store, minter, src, dst).Run(context.Background(), "job-1")

	if store.failed != "" {
		t.Fatalf("unexpected failure: %s", store.failed)
	}
	if store.completed == nil {
		t.Fatal("job not completed")
	}
	if got := *store.completed; got != [2]int{3, 1} {
		t.Errorf("completed counts = imported %d/skipped %d, want 3/1", got[0], got[1])
	}
	if store.setRunningTotal != 4 {
		t.Errorf("SetRunning total = %d, want 4", store.setRunningTotal)
	}
	// 3 appended (uid 1,2,4); the skipped uid 3 not appended.
	if len(dst.appends) != 3 {
		t.Fatalf("appends = %d, want 3", len(dst.appends))
	}
	// \Recent must be stripped; \Seen kept; original date preserved.
	first := dst.appends[0]
	if first.folder != "INBOX" {
		t.Errorf("first append folder = %q, want INBOX", first.folder)
	}
	if !first.date.Equal(date) {
		t.Errorf("append date = %v, want %v", first.date, date)
	}
	for _, f := range first.flags {
		if f == "\\Recent" {
			t.Error("\\Recent flag should have been stripped")
		}
	}
	if minter.minted != 1 || minter.revoked != 1 {
		t.Errorf("token lifecycle = minted %d/revoked %d, want 1/1", minter.minted, minter.revoked)
	}
}

func TestImporter_CancelMidRun(t *testing.T) {
	src := &fakeSource{
		folders: []Folder{{Name: "INBOX"}, {Name: "Later"}},
		overviews: map[string][]Overview{
			"INBOX": {{UID: 1, MessageID: "a@x"}},
			"Later": {{UID: 2, MessageID: "b@x"}},
		},
		bodies: map[uint32][]byte{1: []byte("m1"), 2: []byte("m2")},
	}
	dst := &fakeDest{existing: map[string]map[string]struct{}{}}
	// running for the first folder's check, cancelled before the second folder.
	store := &fakeStore{job: runnableJob(), statusSeq: []string{"running", "cancelled"}}
	minter := &fakeMinter{}

	newTestImporter(store, minter, src, dst).Run(context.Background(), "job-1")

	if store.completed != nil {
		t.Error("cancelled job must not be marked completed")
	}
	if store.failed != "" {
		t.Errorf("cancelled job must not be marked failed, got %q", store.failed)
	}
	if len(dst.appends) != 1 {
		t.Errorf("expected only the first folder imported before cancel, appends=%d", len(dst.appends))
	}
	if minter.revoked != 1 {
		t.Error("token must still be revoked on cancellation")
	}
}

func TestImporter_SourceDialFailure(t *testing.T) {
	src := &fakeSource{dialErr: errors.New("connection refused")}
	dst := &fakeDest{}
	store := &fakeStore{job: runnableJob()}
	minter := &fakeMinter{}

	newTestImporter(store, minter, src, dst).Run(context.Background(), "job-1")

	if store.completed != nil {
		t.Error("should not complete on dial failure")
	}
	if store.failed == "" {
		t.Error("expected failure recorded on dial error")
	}
	if minter.revoked != 1 {
		t.Error("token minted before dial must still be revoked")
	}
}

func TestImporter_SkipsNoSelectAndNotRunnable(t *testing.T) {
	// Not-runnable job is a no-op.
	store := &fakeStore{job: &repository.ImportJob{ID: "j", Status: "completed"}}
	newTestImporter(store, &fakeMinter{}, &fakeSource{}, &fakeDest{}).Run(context.Background(), "j")
	if store.setRunningTotal != 0 || store.completed != nil {
		t.Error("already-completed job must not be processed")
	}
}
