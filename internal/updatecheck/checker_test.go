package updatecheck

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/Veltara-Works/vectis/internal/orchestrator"
)

type fakeSource struct {
	lr  *orchestrator.LatestRelease
	err error
}

func (f *fakeSource) LatestRelease(context.Context) (*orchestrator.LatestRelease, error) {
	return f.lr, f.err
}

type memStore struct{ st State }

func (m *memStore) Load(context.Context) (State, error) { return m.st, nil }
func (m *memStore) Save(_ context.Context, s State) error {
	m.st = s
	return nil
}

type fakeNotifier struct {
	sent []string // newVersion per send
	err  error
	to   string
	url  string
}

func (f *fakeNotifier) SendUpdateAvailable(to, _, newVersion, url string) error {
	if f.err != nil {
		return f.err
	}
	f.sent = append(f.sent, newVersion)
	f.to, f.url = to, url
	return nil
}

func newTestChecker(src Source, st Store, n Notifier, admin string) *Checker {
	c := New(src, st, n, Config{AdminEmail: admin}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	c.now = func() time.Time { return time.Date(2026, 11, 24, 9, 0, 0, 0, time.UTC) }
	return c
}

func avail(cur, latest string) *orchestrator.LatestRelease {
	return &orchestrator.LatestRelease{Current: cur, Latest: latest, UpdateAvailable: true, Channel: "stable"}
}

func TestRunOnce_EmailsOncePerVersion(t *testing.T) {
	src := &fakeSource{lr: avail("v0.1.65", "v0.1.66")}
	st, n := &memStore{}, &fakeNotifier{}
	c := newTestChecker(src, st, n, "admin@example.com")

	got := c.RunOnce(context.Background())
	if !got.UpdateAvailable || got.Latest != "v0.1.66" || got.NotifiedVersion != "v0.1.66" {
		t.Fatalf("first run state = %+v", got)
	}
	if got.ReleaseNotesURL != "https://github.com/Veltara-Works/vectis/releases/tag/v0.1.66" {
		t.Errorf("release notes URL = %q", got.ReleaseNotesURL)
	}
	if len(n.sent) != 1 || n.to != "admin@example.com" || n.url != got.ReleaseNotesURL {
		t.Fatalf("first run sent=%v to=%q url=%q", n.sent, n.to, n.url)
	}

	c.RunOnce(context.Background()) // same version again: no second email
	if len(n.sent) != 1 {
		t.Fatalf("same version emailed twice: %v", n.sent)
	}

	src.lr = avail("v0.1.65", "v0.1.67") // a newer one appears: email again
	c.RunOnce(context.Background())
	if len(n.sent) != 2 || n.sent[1] != "v0.1.67" {
		t.Fatalf("newer version not emailed: %v", n.sent)
	}
}

func TestRunOnce_FailedEmailIsRetried(t *testing.T) {
	src := &fakeSource{lr: avail("v0.1.65", "v0.1.66")}
	st, n := &memStore{}, &fakeNotifier{err: errors.New("smtp down")}
	c := newTestChecker(src, st, n, "admin@example.com")

	if got := c.RunOnce(context.Background()); got.NotifiedVersion != "" {
		t.Fatalf("failed send recorded as notified: %+v", got)
	}
	n.err = nil
	c.RunOnce(context.Background())
	if len(n.sent) != 1 || st.st.NotifiedVersion != "v0.1.66" {
		t.Fatalf("retry did not send: sent=%v state=%+v", n.sent, st.st)
	}
}

func TestRunOnce_UpToDateSendsNothing(t *testing.T) {
	src := &fakeSource{lr: &orchestrator.LatestRelease{Current: "v0.1.66", Latest: "v0.1.66"}}
	n := &fakeNotifier{}
	got := newTestChecker(src, &memStore{}, n, "admin@example.com").RunOnce(context.Background())
	if got.UpdateAvailable || len(n.sent) != 0 || got.LastError != "" {
		t.Fatalf("up to date: state=%+v sent=%v", got, n.sent)
	}
}

func TestRunOnce_NoAdminEmailOrNotifierIsDashboardOnly(t *testing.T) {
	src := &fakeSource{lr: avail("v0.1.65", "v0.1.66")}
	n := &fakeNotifier{}
	got := newTestChecker(src, &memStore{}, n, "").RunOnce(context.Background())
	if !got.UpdateAvailable || len(n.sent) != 0 || got.NotifiedVersion != "" {
		t.Fatalf("no admin email: state=%+v sent=%v", got, n.sent)
	}
	got = newTestChecker(src, &memStore{}, nil, "admin@example.com").RunOnce(context.Background())
	if !got.UpdateAvailable || got.NotifiedVersion != "" {
		t.Fatalf("nil notifier: state=%+v", got)
	}
}

func TestRunOnce_FailedCheckKeepsLastKnownUpdate(t *testing.T) {
	src := &fakeSource{lr: avail("v0.1.65", "v0.1.66")}
	st := &memStore{}
	c := newTestChecker(src, st, &fakeNotifier{}, "admin@example.com")
	c.RunOnce(context.Background())

	src.lr, src.err = nil, errors.New("release channel unavailable: signature mismatch")
	got := c.RunOnce(context.Background())
	if got.LastError == "" || !got.UpdateAvailable || got.Latest != "v0.1.66" || got.NotifiedVersion != "v0.1.66" {
		t.Fatalf("failed check lost state: %+v", got)
	}
	src.lr, src.err = avail("v0.1.65", "v0.1.66"), nil
	if got := c.RunOnce(context.Background()); got.LastError != "" {
		t.Fatalf("recovered check kept the error: %+v", got)
	}
}

func TestNew_Defaults(t *testing.T) {
	c := New(&fakeSource{}, &memStore{}, nil, Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if c.cfg.Interval != 24*time.Hour || c.cfg.StartDelayMin != 5*time.Minute || c.cfg.StartDelayMax != 30*time.Minute {
		t.Fatalf("defaults = %+v", c.cfg)
	}
	c.Stop()
	c.Stop() // idempotent
}
