package mailimport

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Veltara-Works/vectis/internal/repository"
)

// Zero the per-message retry backoff so the retry tests don't sleep.
func TestMain(m *testing.M) {
	msgRetryBackoff = 0
	os.Exit(m.Run())
}

// ---- fakes -----------------------------------------------------------------

type fakeStore struct {
	job       *repository.ImportJob
	statusSeq []string // values returned by successive Status calls; last repeats
	statusN   int

	setRunningTotal int
	completed       *[2]int // imported, skipped
	completeNoOp    bool    // when true, Complete reports no transition (raced-in terminal state)
	failed          string
	progressCalls   int
}

func (s *fakeStore) GetByID(_ context.Context, _ string) (*repository.ImportJob, error) {
	return s.job, nil
}
func (s *fakeStore) DecryptPassword(_ context.Context, _ string) (string, error) {
	return "src-pw", nil
}
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
func (s *fakeStore) Complete(_ context.Context, _ string, imported, skipped int) (bool, error) {
	// Mirror the conditional repository UPDATE: if a cancel/failure raced in,
	// the transition is a no-op and Complete reports false.
	if s.completeNoOp {
		return false, nil
	}
	s.completed = &[2]int{imported, skipped}
	return true, nil
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
	minted            int
	revoked           int
	revokeHadDeadline bool // whether the last Revoke ctx carried a deadline (#153)
}

func (m *fakeMinter) Mint(_ context.Context, _, _ string, _ time.Duration) (*repository.MintedToken, error) {
	m.minted++
	return &repository.MintedToken{ID: "tok-1", Password: "tok-pw", ExpiresAt: time.Now().Add(time.Hour)}, nil
}
func (m *fakeMinter) Revoke(ctx context.Context, _ string) error {
	m.revoked++
	_, m.revokeHadDeadline = ctx.Deadline()
	return nil
}

type fakeSource struct {
	folders    []Folder
	overviews  map[string][]Overview // by folder name
	bodies     map[uint32][]byte     // by uid
	fetchFails map[uint32]int        // remaining transient FetchBody failures per uid
	current    string
	dialErr    error
}

func (s *fakeSource) Folders() ([]Folder, error) { return s.folders, nil }
func (s *fakeSource) SelectFolder(name string) (uint32, error) {
	s.current = name
	return uint32(len(s.overviews[name])), nil
}
func (s *fakeSource) Overviews(_ uint32) ([]Overview, error) { return s.overviews[s.current], nil }
func (s *fakeSource) FetchBody(uid uint32) ([]byte, error) {
	if s.fetchFails != nil && s.fetchFails[uid] > 0 {
		s.fetchFails[uid]--
		return nil, errors.New("transient fetch error")
	}
	return s.bodies[uid], nil
}
func (s *fakeSource) Close() {}

type appended struct {
	folder string
	flags  []string
	date   time.Time
	body   []byte
}

type fakeDest struct {
	existing       map[string]map[string]struct{} // folder -> message-id set
	existingHashes map[string]map[string]struct{} // folder -> content-hash set (header-less)
	ensured        []string
	appends        []appended
	mu             sync.Mutex
}

func (d *fakeDest) EnsureFolder(name string) error { d.ensured = append(d.ensured, name); return nil }
func (d *fakeDest) Existing(folder string) (*ExistingIndex, error) {
	idx := &ExistingIndex{MessageIDs: map[string]struct{}{}, ContentHashes: map[string]struct{}{}}
	if d.existing[folder] != nil {
		idx.MessageIDs = d.existing[folder]
	}
	if d.existingHashes[folder] != nil {
		idx.ContentHashes = d.existingHashes[folder]
	}
	return idx, nil
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

func TestImporter_DedupesHeaderlessByContent(t *testing.T) {
	date := time.Date(2025, 5, 5, 0, 0, 0, 0, time.UTC)
	src := &fakeSource{
		folders: []Folder{{Name: "INBOX"}},
		overviews: map[string][]Overview{
			"INBOX": {
				{UID: 1, MessageID: "", InternalDate: date}, // body "X" already present -> skipped
				{UID: 2, MessageID: "", InternalDate: date}, // body "Y" new -> imported
				{UID: 3, MessageID: "", InternalDate: date}, // body "Y" again -> within-run dup skipped
			},
		},
		bodies: map[uint32][]byte{1: []byte("X"), 2: []byte("Y"), 3: []byte("Y")},
	}
	// The dest already holds a header-less message whose body is "X".
	dst := &fakeDest{existingHashes: map[string]map[string]struct{}{
		"INBOX": {contentHash([]byte("X")): {}},
	}}
	store := &fakeStore{job: runnableJob()}

	newTestImporter(store, &fakeMinter{}, src, dst).Run(context.Background(), "job-1")

	if store.failed != "" {
		t.Fatalf("unexpected failure: %s", store.failed)
	}
	if store.completed == nil {
		t.Fatal("job not completed")
	}
	// "X" is a dest dup; the second "Y" is a within-run dup of the first -> 1 imported, 2 skipped.
	if got := *store.completed; got != [2]int{1, 2} {
		t.Errorf("completed = imported %d/skipped %d, want 1/2", got[0], got[1])
	}
	if len(dst.appends) != 1 || string(dst.appends[0].body) != "Y" {
		t.Fatalf("expected only the unique header-less message appended once; appends=%d", len(dst.appends))
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

// TestImporter_CancelRaceBeforeComplete is the regression for #184: a cancel
// that lands after the loop finishes but before the terminal transition must NOT
// be overwritten by Complete. The single folder imports fully (status "running"
// at the folder check), then the final pre-Complete check observes "cancelled" —
// the job must end cancelled, not completed.
func TestImporter_CancelRaceBeforeComplete(t *testing.T) {
	src := &fakeSource{
		folders:   []Folder{{Name: "INBOX"}},
		overviews: map[string][]Overview{"INBOX": {{UID: 1, MessageID: "a@x"}}},
		bodies:    map[uint32][]byte{1: []byte("m1")},
	}
	dst := &fakeDest{existing: map[string]map[string]struct{}{}}
	// 1st Status (folder-loop check) = running; 2nd (final pre-Complete) = cancelled.
	store := &fakeStore{job: runnableJob(), statusSeq: []string{"running", "cancelled"}}
	minter := &fakeMinter{}

	newTestImporter(store, minter, src, dst).Run(context.Background(), "job-1")

	if store.completed != nil {
		t.Error("a cancel racing in before Complete must not be marked completed (#184)")
	}
	if store.failed != "" {
		t.Errorf("late-cancelled job must not be marked failed, got %q", store.failed)
	}
	// The folder finished before the cancel was observed, so its message was imported.
	if len(dst.appends) != 1 {
		t.Errorf("expected the folder's message imported before the late cancel, appends=%d", len(dst.appends))
	}
	if minter.revoked != 1 {
		t.Error("token must still be revoked on cancellation")
	}
}

// TestImporter_RevokeIsTimeBounded is the regression for #153: the post-run
// token revocation must run on a context with a deadline so a hung token store
// can't block the import goroutine from returning and leak the concurrency slot.
// TestImporter_CompleteNoOpNotMisreported guards the log-accuracy half of #184:
// if a cancel/failure races in between the final check and the conditional
// Complete UPDATE (so Complete reports no transition), the runner must NOT claim
// the job completed — it leaves the recorded terminal status untouched.
func TestImporter_CompleteNoOpNotMisreported(t *testing.T) {
	src := &fakeSource{
		folders:   []Folder{{Name: "INBOX"}},
		overviews: map[string][]Overview{"INBOX": {{UID: 1, MessageID: "a@x"}}},
		bodies:    map[uint32][]byte{1: []byte("m1")},
	}
	dst := &fakeDest{existing: map[string]map[string]struct{}{}}
	store := &fakeStore{job: runnableJob(), completeNoOp: true} // Complete is a no-op
	minter := &fakeMinter{}

	newTestImporter(store, minter, src, dst).Run(context.Background(), "job-1")

	if store.completed != nil {
		t.Error("a no-op Complete must not record completion counts")
	}
	if store.failed != "" {
		t.Errorf("must not be marked failed, got %q", store.failed)
	}
}

func TestImporter_RevokeIsTimeBounded(t *testing.T) {
	src := &fakeSource{
		folders:   []Folder{{Name: "INBOX"}},
		overviews: map[string][]Overview{"INBOX": {{UID: 1, MessageID: "a@x"}}},
		bodies:    map[uint32][]byte{1: []byte("m1")},
	}
	dst := &fakeDest{existing: map[string]map[string]struct{}{}}
	store := &fakeStore{job: runnableJob()}
	minter := &fakeMinter{}

	newTestImporter(store, minter, src, dst).Run(context.Background(), "job-1")

	if minter.revoked != 1 {
		t.Fatalf("expected exactly one revoke, got %d", minter.revoked)
	}
	if !minter.revokeHadDeadline {
		t.Error("revoke ran on an unbounded context — a hung token store would wedge the slot (#153)")
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

func TestImporter_RetriesTransientThenSucceeds(t *testing.T) {
	src := &fakeSource{
		folders:    []Folder{{Name: "INBOX"}},
		overviews:  map[string][]Overview{"INBOX": {{UID: 1, MessageID: "a@x"}}},
		bodies:     map[uint32][]byte{1: []byte("m1")},
		fetchFails: map[uint32]int{1: 2}, // fail twice, succeed on the 3rd attempt
	}
	dst := &fakeDest{existing: map[string]map[string]struct{}{}}
	store := &fakeStore{job: runnableJob()}

	newTestImporter(store, &fakeMinter{}, src, dst).Run(context.Background(), "job-1")

	if store.failed != "" {
		t.Fatalf("transient errors should have been retried, not failed: %s", store.failed)
	}
	if store.completed == nil || len(dst.appends) != 1 {
		t.Errorf("message should import after retries; completed=%v appends=%d", store.completed != nil, len(dst.appends))
	}
}

func TestImporter_FailsAfterMaxAttempts(t *testing.T) {
	src := &fakeSource{
		folders:    []Folder{{Name: "INBOX"}},
		overviews:  map[string][]Overview{"INBOX": {{UID: 1, MessageID: "a@x"}}},
		bodies:     map[uint32][]byte{1: []byte("m1")},
		fetchFails: map[uint32]int{1: 99}, // never succeeds
	}
	dst := &fakeDest{existing: map[string]map[string]struct{}{}}
	store := &fakeStore{job: runnableJob()}

	newTestImporter(store, &fakeMinter{}, src, dst).Run(context.Background(), "job-1")

	if store.completed != nil {
		t.Error("a permanently failing message must not complete the job")
	}
	if store.failed == "" {
		t.Error("expected the job to be failed after exhausting retries")
	}
}

func TestImporter_SkipsGmailVirtualFolders(t *testing.T) {
	src := &fakeSource{
		folders: []Folder{
			{Name: "INBOX"},
			{Name: "[Gmail]/All Mail", Delim: "/", Attrs: []string{"\\All"}},
			{Name: "[Gmail]/Important", Delim: "/", Attrs: []string{"\\Important"}},
		},
		overviews: map[string][]Overview{
			"INBOX":             {{UID: 1, MessageID: "a@x"}},
			"[Gmail]/All Mail":  {{UID: 2, MessageID: "a@x"}, {UID: 3, MessageID: "b@x"}},
			"[Gmail]/Important": {{UID: 4, MessageID: "a@x"}},
		},
		bodies: map[uint32][]byte{1: []byte("m1"), 2: []byte("m2"), 3: []byte("m3"), 4: []byte("m4")},
	}
	dst := &fakeDest{existing: map[string]map[string]struct{}{}}
	store := &fakeStore{job: runnableJob()}

	newTestImporter(store, &fakeMinter{}, src, dst).Run(context.Background(), "job-1")

	// Only the single INBOX message should be imported; the virtual folders
	// (which duplicate it) are skipped, so total is 1 and one append happens.
	if store.setRunningTotal != 1 {
		t.Errorf("virtual folders should be excluded from the total; got %d, want 1", store.setRunningTotal)
	}
	if len(dst.appends) != 1 || dst.appends[0].folder != "INBOX" {
		t.Errorf("expected only the INBOX message imported, got %d appends", len(dst.appends))
	}
}
