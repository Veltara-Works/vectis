package mail

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Veltara-Works/vectis/internal/repository"
)

// fakeResolver answers from a table; names not in it are NXDOMAIN.
type fakeResolver struct {
	answers map[string][]string
	errs    map[string]error

	mu    sync.Mutex
	calls int
}

func (f *fakeResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	if err, ok := f.errs[host]; ok {
		return nil, err
	}
	if a, ok := f.answers[host]; ok {
		return a, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

type storedCheck struct {
	ip, zone, status, response string
	at                         time.Time
}

type fakeStore struct{ rows []storedCheck }

func (f *fakeStore) Create(_ context.Context, ip, zone, status string, response *string, at time.Time) (string, error) {
	r := ""
	if response != nil {
		r = *response
	}
	f.rows = append(f.rows, storedCheck{ip, zone, status, r, at})
	return "id", nil
}

func (f *fakeStore) PruneOlderThan(context.Context, time.Duration) (int64, error) { return 0, nil }

var (
	spamhaus = Blocklist{Zone: "zen.spamhaus.org", Name: "Spamhaus ZEN",
		ListedCodes: []string{"127.0.0.2", "127.0.0.4", "127.0.0.10"}}
	spamcop = Blocklist{Zone: "bl.spamcop.net", Name: "SpamCop", ListedCodes: []string{"127.0.0.2"}}
)

func mustCheck(t *testing.T, m *RBLMonitor) {
	t.Helper()
	if _, err := m.CheckNow(context.Background()); err != nil {
		t.Fatalf("CheckNow: %v", err)
	}
}

func testMonitor(r Lookuper, ips []string, lists ...Blocklist) (*RBLMonitor, *fakeStore) {
	store := &fakeStore{}
	m := NewRBLMonitor(store, []Lookuper{r}, func(context.Context) ([]string, error) { return ips, nil },
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	m.lists = lists
	return m, store
}

func TestClassifyAnswer(t *testing.T) {
	cases := []struct {
		name   string
		addrs  []string
		status string
	}{
		{"listed code", []string{"127.0.0.4"}, repository.RBLStatusListed},
		{"several codes incl. listed", []string{"127.0.0.10", "127.0.0.2"}, repository.RBLStatusListed},
		{"spamhaus refusal: public resolver", []string{"127.255.255.254"}, repository.RBLStatusUnknown},
		{"spamhaus refusal: excessive queries", []string{"127.255.255.255"}, repository.RBLStatusUnknown},
		{"unexpected code", []string{"127.0.0.1"}, repository.RBLStatusUnknown},
		{"empty answer", nil, repository.RBLStatusUnknown},
	}
	for _, c := range cases {
		status, _ := classifyAnswer(c.addrs, spamhaus)
		if status != c.status {
			t.Errorf("%s: status = %q, want %q", c.name, status, c.status)
		}
	}
}

func TestCheckNowStatuses(t *testing.T) {
	r := &fakeResolver{
		answers: map[string][]string{
			// test addresses: both lists healthy
			"2.0.0.127.zen.spamhaus.org": {"127.0.0.2"},
			"2.0.0.127.bl.spamcop.net":   {"127.0.0.2"},
			// 203.0.113.7 listed on Spamhaus, NXDOMAIN on SpamCop
			"7.113.0.203.zen.spamhaus.org": {"127.0.0.4"},
		},
		errs: map[string]error{
			// 198.51.100.9: Spamhaus times out
			"9.100.51.198.zen.spamhaus.org": &net.DNSError{Err: "i/o timeout", IsTimeout: true},
		},
	}
	m, store := testMonitor(r, []string{"203.0.113.7", "198.51.100.9"}, spamhaus, spamcop)
	results, err := m.CheckNow(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"203.0.113.7 zen.spamhaus.org":  repository.RBLStatusListed,
		"203.0.113.7 bl.spamcop.net":    repository.RBLStatusClean,
		"198.51.100.9 zen.spamhaus.org": repository.RBLStatusUnknown,
		"198.51.100.9 bl.spamcop.net":   repository.RBLStatusClean,
	}
	if len(results) != len(want) || len(store.rows) != len(want) {
		t.Fatalf("got %d results / %d stored, want %d", len(results), len(store.rows), len(want))
	}
	for _, row := range store.rows {
		key := row.ip + " " + row.zone
		if row.status != want[key] {
			t.Errorf("%s: status = %q, want %q (response %q)", key, row.status, want[key], row.response)
		}
	}
	if got := m.IPs(); len(got) != 2 {
		t.Errorf("IPs() = %v, want the two checked", got)
	}
}

// A list that doesn't answer its own test address can't be trusted to say
// "clean": that is how an unregistered or refused resolver looks.
func TestCheckNowListFailingSelfTestIsUnknown(t *testing.T) {
	r := &fakeResolver{answers: map[string][]string{
		"2.0.0.127.bl.spamcop.net": {"127.0.0.2"},
		// Spamhaus refuses everything from this resolver, including its test address.
		"2.0.0.127.zen.spamhaus.org":   {"127.255.255.254"},
		"7.113.0.203.zen.spamhaus.org": {"127.255.255.254"},
	}}
	m, store := testMonitor(r, []string{"203.0.113.7"}, spamhaus, spamcop)
	mustCheck(t, m)

	for _, row := range store.rows {
		switch row.zone {
		case "zen.spamhaus.org":
			if row.status != repository.RBLStatusUnknown {
				t.Errorf("spamhaus status = %q, want unknown", row.status)
			}
			if !strings.Contains(row.response, "list unavailable") {
				t.Errorf("spamhaus reason = %q, want it to say the list is unavailable", row.response)
			}
		case "bl.spamcop.net":
			if row.status != repository.RBLStatusClean {
				t.Errorf("spamcop status = %q, want clean", row.status)
			}
		}
	}
}

// NXDOMAIN from an unhealthy list (e.g. it silently drops unregistered
// queries) must not read as clean.
func TestCheckNowNXDOMAINFromUnhealthyListIsUnknown(t *testing.T) {
	r := &fakeResolver{} // every name NXDOMAIN, test addresses included
	m, store := testMonitor(r, []string{"203.0.113.7"}, spamcop)
	mustCheck(t, m)
	if len(store.rows) != 1 || store.rows[0].status != repository.RBLStatusUnknown {
		t.Fatalf("rows = %+v, want one unknown", store.rows)
	}
}

func TestCheckNowKeepsLastIPsWhenSourceFails(t *testing.T) {
	r := &fakeResolver{answers: map[string][]string{"2.0.0.127.bl.spamcop.net": {"127.0.0.2"}}}
	m, store := testMonitor(r, []string{"203.0.113.7"}, spamcop)
	mustCheck(t, m)

	m.ipSource = func(context.Context) ([]string, error) { return nil, errors.New("dns blip") }
	mustCheck(t, m)
	if len(store.rows) != 2 || store.rows[1].ip != "203.0.113.7" {
		t.Fatalf("second run rows = %+v, want 203.0.113.7 checked again", store.rows)
	}
}

func TestFallbackLookuper(t *testing.T) {
	primary := &fakeResolver{errs: map[string]error{"down.example": errors.New("connection refused")}}
	secondary := &fakeResolver{answers: map[string][]string{"down.example": {"127.0.0.2"}}}
	f := FallbackLookuper{Primary: primary, Secondary: secondary}

	if a, err := f.LookupHost(context.Background(), "down.example"); err != nil || len(a) != 1 {
		t.Errorf("primary failure: got %v, %v; want the secondary's answer", a, err)
	}
	// NXDOMAIN is an answer, not a failure: no fallback.
	secondary.calls = 0
	if _, err := f.LookupHost(context.Background(), "missing.example"); !isNotFound(err) || secondary.calls != 0 {
		t.Errorf("NXDOMAIN: err = %v, secondary calls = %d; want not-found without fallback", err, secondary.calls)
	}
}

func TestHostnameIPs(t *testing.T) {
	r := &fakeResolver{answers: map[string][]string{
		"mail.example.com": {"203.0.113.7", "2001:db8::1", "10.0.0.5", "127.0.0.1"},
	}}
	ips, err := HostnameIPs(context.Background(), r, "mail.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0] != "203.0.113.7" {
		t.Errorf("HostnameIPs = %v, want only the public IPv4", ips)
	}
}

func TestDefaultBlocklistsHaveDelistPages(t *testing.T) {
	for _, l := range DefaultBlocklists {
		if l.Name == "" || !strings.HasPrefix(l.DelistURL, "https://") || len(l.ListedCodes) == 0 {
			t.Errorf("%s: incomplete entry %+v", l.Zone, l)
		}
		if l.Zone == "dnsbl.sorbs.net" {
			t.Error("SORBS shut down in 2024 and must not be checked")
		}
	}
}

// blockingResolver never answers until its context ends.
type blockingResolver struct{}

func (blockingResolver) LookupHost(ctx context.Context, _ string) ([]string, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// Copilot finding 2: a list's "not listed" must come from the resolver that
// just passed that list's self-test.
func TestCheckNowUsesTheResolverThatPassedSelfTest(t *testing.T) {
	primary := &fakeResolver{errs: map[string]error{
		"2.0.0.127.bl.spamcop.net": &net.DNSError{Err: "i/o timeout", IsTimeout: true},
	}}
	secondary := &fakeResolver{answers: map[string][]string{"2.0.0.127.bl.spamcop.net": {"127.0.0.2"}}}
	store := &fakeStore{}
	m := NewRBLMonitor(store, []Lookuper{primary, secondary},
		func(context.Context) ([]string, error) { return []string{"203.0.113.7"}, nil },
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	m.lists = []Blocklist{spamcop}
	mustCheck(t, m)

	if len(store.rows) != 1 || store.rows[0].status != repository.RBLStatusClean {
		t.Fatalf("rows = %+v, want clean via the secondary", store.rows)
	}
	if primary.calls != 1 {
		t.Errorf("primary calls = %d, want only the failed self-test", primary.calls)
	}
}

// ...and a resolver that passed the self-test but then fails an IP query
// gives unknown, not a fallback answer from an untested resolver.
func TestCheckNowNoMidRunFallback(t *testing.T) {
	primary := &fakeResolver{
		answers: map[string][]string{"2.0.0.127.bl.spamcop.net": {"127.0.0.2"}},
		errs:    map[string]error{"7.113.0.203.bl.spamcop.net": &net.DNSError{Err: "server misbehaving"}},
	}
	secondary := &fakeResolver{}
	store := &fakeStore{}
	m := NewRBLMonitor(store, []Lookuper{primary, secondary},
		func(context.Context) ([]string, error) { return []string{"203.0.113.7"}, nil },
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	m.lists = []Blocklist{spamcop}
	mustCheck(t, m)

	if len(store.rows) != 1 || store.rows[0].status != repository.RBLStatusUnknown {
		t.Fatalf("rows = %+v, want unknown", store.rows)
	}
	if secondary.calls != 0 {
		t.Errorf("secondary calls = %d, want 0", secondary.calls)
	}
}

// Copilot finding 3: a primary that hangs must not use up the deadline the
// secondary needs.
func TestFallbackLookuperPrimaryDeadline(t *testing.T) {
	secondary := &fakeResolver{answers: map[string][]string{"mail.example.com": {"203.0.113.7"}}}
	f := FallbackLookuper{Primary: blockingResolver{}, Secondary: secondary, PrimaryTimeout: 50 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	a, err := f.LookupHost(ctx, "mail.example.com")
	if err != nil || len(a) != 1 {
		t.Fatalf("got %v, %v; want the secondary's answer within the caller's deadline", a, err)
	}
}

// Copilot finding 4: partial IP discovery must not drop a known IP.
func TestCheckNowMergesIPsOnPartialDiscovery(t *testing.T) {
	r := &fakeResolver{answers: map[string][]string{"2.0.0.127.bl.spamcop.net": {"127.0.0.2"}}}
	m, store := testMonitor(r, []string{"203.0.113.7", "198.51.100.9"}, spamcop)
	mustCheck(t, m)

	// The hostname lookup fails; only the warmup IP comes back.
	m.ipSource = func(context.Context) ([]string, error) {
		return []string{"198.51.100.9"}, errors.New("resolve mail.example.com: timeout")
	}
	store.rows = nil
	mustCheck(t, m)
	got := map[string]bool{}
	for _, row := range store.rows {
		got[row.ip] = true
	}
	if !got["203.0.113.7"] || !got["198.51.100.9"] {
		t.Fatalf("second run checked %v, want both IPs", got)
	}
	if ips := m.IPs(); len(ips) != 2 {
		t.Errorf("IPs() = %v, want both kept", ips)
	}
}

// Copilot review 2, finding 2: a clean discovery that finds no IPs clears
// what the dashboard shows; a failed one keeps the old IPs.
func TestCheckNowClearsIPsOnSuccessfulEmptyDiscovery(t *testing.T) {
	r := &fakeResolver{answers: map[string][]string{"2.0.0.127.bl.spamcop.net": {"127.0.0.2"}}}
	m, _ := testMonitor(r, []string{"203.0.113.7"}, spamcop)
	mustCheck(t, m)

	m.ipSource = func(context.Context) ([]string, error) { return nil, errors.New("dns blip") }
	mustCheck(t, m)
	if len(m.IPs()) != 1 {
		t.Fatalf("after a failed discovery IPs() = %v, want the old IP kept", m.IPs())
	}
	m.ipSource = func(context.Context) ([]string, error) { return nil, nil }
	mustCheck(t, m)
	if len(m.IPs()) != 0 {
		t.Errorf("after an empty successful discovery IPs() = %v, want none", m.IPs())
	}
}

// Copilot review 2, finding 1: a hung primary resolver must not stretch a run
// past the API's response deadline.
func TestCheckNowFitsTheRequestDeadlineWithAHungPrimary(t *testing.T) {
	secondary := &fakeResolver{answers: map[string][]string{}}
	lists := []Blocklist{}
	for _, z := range []string{"a.example", "b.example", "c.example", "d.example", "e.example", "f.example"} {
		lists = append(lists, Blocklist{Zone: z, Name: z, ListedCodes: []string{"127.0.0.2"}})
		secondary.answers["2.0.0.127."+z] = []string{"127.0.0.2"}
	}
	store := &fakeStore{}
	m := NewRBLMonitor(store, []Lookuper{blockingResolver{}, secondary},
		func(context.Context) ([]string, error) { return []string{"203.0.113.7"}, nil },
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	m.lists = lists
	m.timeout = 100 * time.Millisecond

	start := time.Now()
	mustCheck(t, m)
	// Sequential would be 6 lists x 100 ms on the hung primary alone.
	if took := time.Since(start); took > 400*time.Millisecond {
		t.Errorf("run took %v; lists should be self-tested concurrently", took)
	}
	if len(store.rows) != len(lists) {
		t.Fatalf("rows = %d, want %d", len(store.rows), len(lists))
	}
	for _, row := range store.rows {
		if row.status != repository.RBLStatusClean {
			t.Errorf("%s: %q, want clean via the secondary", row.zone, row.status)
		}
	}
}

// ctxStore rejects writes made with a cancelled context, like pgx does.
type ctxStore struct{ fakeStore }

func (s *ctxStore) Create(ctx context.Context, ip, zone, status string, response *string, at time.Time) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return s.fakeStore.Create(ctx, ip, zone, status, response, at)
}

// Copilot review 3, finding 1: a run that exhausts its deadline still stores
// what it found, and storage failures are reported.
func TestCheckNowStoresResultsAfterTheDeadline(t *testing.T) {
	r := &fakeResolver{answers: map[string][]string{"2.0.0.127.bl.spamcop.net": {"127.0.0.2"}}}
	store := &ctxStore{}
	m := NewRBLMonitor(store, []Lookuper{r},
		func(context.Context) ([]string, error) { return []string{"203.0.113.7"}, nil },
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	m.lists = []Blocklist{spamcop}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the request deadline is already gone
	results, err := m.CheckNow(ctx)
	if err != nil {
		t.Fatalf("CheckNow: %v", err)
	}
	// The result itself depends on the resolver (this fake ignores the
	// context); what matters is that it was stored despite the dead context.
	if len(results) != 1 || len(store.rows) != 1 {
		t.Fatalf("results=%d rows=%+v, want the run's result stored", len(results), store.rows)
	}
}

type failingStore struct{ fakeStore }

func (failingStore) Create(context.Context, string, string, string, *string, time.Time) (string, error) {
	return "", errors.New("db down")
}

func TestCheckNowReportsStoreFailures(t *testing.T) {
	r := &fakeResolver{answers: map[string][]string{"2.0.0.127.bl.spamcop.net": {"127.0.0.2"}}}
	m := NewRBLMonitor(&failingStore{}, []Lookuper{r},
		func(context.Context) ([]string, error) { return []string{"203.0.113.7"}, nil },
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	m.lists = []Blocklist{spamcop}
	if _, err := m.CheckNow(context.Background()); err == nil {
		t.Fatal("CheckNow succeeded although no result could be stored")
	}
}

// gatedResolver answers like fakeResolver, but a lookup of gate blocks until
// release is closed, signalling entered when it starts waiting.
type gatedResolver struct {
	fakeResolver
	gate    string
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (g *gatedResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	if host == g.gate {
		g.once.Do(func() { close(g.entered) })
		select {
		case <-g.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return g.fakeResolver.LookupHost(ctx, host)
}

type syncStore struct {
	mu sync.Mutex
	fakeStore
}

func (s *syncStore) Create(ctx context.Context, ip, zone, status string, response *string, at time.Time) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fakeStore.Create(ctx, ip, zone, status, response, at)
}

// Copilot review 4, previously missed: the background loop and "Check now" can
// overlap. A run that started earlier and finishes later must not overwrite
// the IPs a newer run already published.
func TestCheckNowOlderRunDoesNotOverwriteNewerIPs(t *testing.T) {
	r := &gatedResolver{
		fakeResolver: fakeResolver{answers: map[string][]string{"2.0.0.127.bl.spamcop.net": {"127.0.0.2"}}},
		gate:         "7.113.0.203.bl.spamcop.net",
		entered:      make(chan struct{}),
		release:      make(chan struct{}),
	}
	var calls int
	var callsMu sync.Mutex
	m := NewRBLMonitor(&syncStore{}, []Lookuper{r}, func(context.Context) ([]string, error) {
		callsMu.Lock()
		defer callsMu.Unlock()
		calls++
		if calls == 1 {
			return []string{"203.0.113.7"}, nil // older run: the address it checks hangs
		}
		return []string{"198.51.100.9"}, nil // newer run: fresher discovery
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	m.lists = []Blocklist{spamcop}

	older := make(chan error, 1)
	go func() {
		_, err := m.CheckNow(context.Background())
		older <- err
	}()
	<-r.entered
	mustCheck(t, m) // the newer run completes while the older one is stuck
	close(r.release)
	if err := <-older; err != nil {
		t.Fatalf("older CheckNow: %v", err)
	}

	if ips := m.IPs(); len(ips) != 1 || ips[0] != "198.51.100.9" {
		t.Errorf("IPs() = %v, want the newer run's [198.51.100.9]", ips)
	}
}

// latest returns the newest result for ip on zone the way the repository's
// latest-result queries pick it: by observation time, not by save order.
func (s *syncStore) latest(ip, zone string) (storedCheck, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var best storedCheck
	found := false
	for _, r := range s.rows {
		if r.ip == ip && r.zone == zone && (!found || r.at.After(best.at)) {
			best, found = r, true
		}
	}
	return best, found
}

// overlapResolver: SpamCop answers 203.0.113.7 clean the first time and listed
// after that; Spamhaus's first lookup of it stalls until release.
type overlapResolver struct {
	mu           sync.Mutex
	spamcopCalls int
	stalled      bool
	firstSpamcop chan struct{} // closed once the first SpamCop answer is in
	stalling     chan struct{} // closed when the Spamhaus lookup starts stalling
	release      chan struct{}
}

func (o *overlapResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	nx := &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	switch host {
	case "2.0.0.127.bl.spamcop.net", "2.0.0.127.zen.spamhaus.org":
		return []string{"127.0.0.2"}, nil
	case "7.113.0.203.bl.spamcop.net":
		o.mu.Lock()
		o.spamcopCalls++
		n := o.spamcopCalls
		o.mu.Unlock()
		if n == 1 {
			defer close(o.firstSpamcop)
			return nil, nx
		}
		return []string{"127.0.0.2"}, nil
	case "7.113.0.203.zen.spamhaus.org":
		o.mu.Lock()
		first := !o.stalled
		o.stalled = true
		o.mu.Unlock()
		if first {
			close(o.stalling)
			select {
			case <-o.release:
			case <-ctx.Done():
			}
		}
		return nil, nx
	}
	return nil, nx
}

// Copilot review 5: overlapping runs must not let an older run's answer,
// saved late, replace a newer run's listing as the latest result.
func TestCheckNowOlderAnswerSavedLateDoesNotReplaceNewerListing(t *testing.T) {
	r := &overlapResolver{firstSpamcop: make(chan struct{}), stalling: make(chan struct{}), release: make(chan struct{})}
	store := &syncStore{}
	m := NewRBLMonitor(store, []Lookuper{r}, func(context.Context) ([]string, error) {
		return []string{"203.0.113.7"}, nil
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	m.lists = []Blocklist{spamcop, spamhaus}

	older := make(chan error, 1)
	go func() {
		_, err := m.CheckNow(context.Background())
		older <- err
	}()
	<-r.firstSpamcop // the older run has seen SpamCop clean ...
	<-r.stalling     // ... and is stuck on Spamhaus, so hasn't saved yet
	mustCheck(t, m)  // the newer run sees the listing and saves it
	close(r.release)
	if err := <-older; err != nil {
		t.Fatalf("older CheckNow: %v", err)
	}

	got, ok := store.latest("203.0.113.7", "bl.spamcop.net")
	if !ok || got.status != repository.RBLStatusListed {
		t.Errorf("latest SpamCop result = %+v, want the newer run's listing", got)
	}
}

// Copilot review 6, previously missed 1: a failed discovery with no IPs known
// from before is reported, not passed off as a run, and the loop retries soon.
func TestCheckNowReportsDiscoveryFailureWithNoKnownIPs(t *testing.T) {
	r := &fakeResolver{answers: map[string][]string{"2.0.0.127.bl.spamcop.net": {"127.0.0.2"}}}
	m, store := testMonitor(r, nil, spamcop)
	m.ipSource = func(context.Context) ([]string, error) { return nil, errors.New("resolve mail.example.com: timeout") }

	_, err := m.CheckNow(context.Background())
	var de *DiscoveryError
	if !errors.As(err, &de) {
		t.Fatalf("CheckNow error = %v, want a *DiscoveryError", err)
	}
	if len(store.rows) != 0 || len(m.IPs()) != 0 {
		t.Errorf("stored %d rows, IPs %v; want nothing", len(store.rows), m.IPs())
	}
	if got := m.nextDelay(err); got != rblRetryInterval {
		t.Errorf("next run after a discovery failure in %v, want %v", got, rblRetryInterval)
	}

	// With an IP known from an earlier run, a failed discovery still checks it.
	m.ipSource = func(context.Context) ([]string, error) { return []string{"203.0.113.7"}, nil }
	mustCheck(t, m)
	m.ipSource = func(context.Context) ([]string, error) { return nil, errors.New("timeout") }
	if _, err := m.CheckNow(context.Background()); err != nil {
		t.Fatalf("CheckNow with a known IP = %v, want the known IP checked", err)
	}
	if got := m.nextDelay(nil); got != m.interval {
		t.Errorf("next run after a normal run in %v, want %v", got, m.interval)
	}
}

// selfTestOverlapResolver: SpamCop fails its self-test the first time and
// passes after that (and lists 203.0.113.7); Spamhaus's first self-test
// stalls until release.
type selfTestOverlapResolver struct {
	mu            sync.Mutex
	spamcopTests  int
	stalled       bool
	firstSelfTest chan struct{}
	stalling      chan struct{}
	release       chan struct{}
}

func (o *selfTestOverlapResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	nx := &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	switch host {
	case "2.0.0.127.bl.spamcop.net":
		o.mu.Lock()
		o.spamcopTests++
		n := o.spamcopTests
		o.mu.Unlock()
		if n == 1 {
			defer close(o.firstSelfTest)
			return nil, nx
		}
		return []string{"127.0.0.2"}, nil
	case "7.113.0.203.bl.spamcop.net":
		return []string{"127.0.0.2"}, nil
	case "2.0.0.127.zen.spamhaus.org":
		o.mu.Lock()
		first := !o.stalled
		o.stalled = true
		o.mu.Unlock()
		if first {
			close(o.stalling)
			select {
			case <-o.release:
			case <-ctx.Done():
			}
		}
		return []string{"127.0.0.2"}, nil
	}
	return nil, nx
}

// Copilot review 6, previously missed 2: a list's failed self-test is
// timestamped when it fails, not after the other lists finish, so an older
// "unknown" can't replace a newer run's listing.
func TestCheckNowSelfTestFailureKeepsItsOwnTime(t *testing.T) {
	r := &selfTestOverlapResolver{firstSelfTest: make(chan struct{}), stalling: make(chan struct{}), release: make(chan struct{})}
	store := &syncStore{}
	m := NewRBLMonitor(store, []Lookuper{r}, func(context.Context) ([]string, error) {
		return []string{"203.0.113.7"}, nil
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	m.lists = []Blocklist{spamcop, spamhaus}

	older := make(chan error, 1)
	go func() {
		_, err := m.CheckNow(context.Background())
		older <- err
	}()
	<-r.firstSelfTest // the older run's SpamCop self-test has failed ...
	<-r.stalling      // ... while its Spamhaus self-test is stuck
	mustCheck(t, m)   // the newer run sees SpamCop list the IP and saves it
	close(r.release)
	if err := <-older; err != nil {
		t.Fatalf("older CheckNow: %v", err)
	}

	got, ok := store.latest("203.0.113.7", "bl.spamcop.net")
	if !ok || got.status != repository.RBLStatusListed {
		t.Errorf("latest SpamCop result = %+v, want the newer run's listing", got)
	}
}

// TestSpamhausDQSKey covers #260 in the monitor: with a key, Spamhaus ZEN is
// queried through the operator's DQS zone, while the stored zone, the stored
// reason and every other list stay as they were. The key must never be stored.
func TestSpamhausDQSKey(t *testing.T) {
	const key = "abcdefghijklmnopqrstuvwxyz"
	dqs := key + ".zen.dq.spamhaus.net"
	r := &fakeResolver{
		answers: map[string][]string{
			// RFC 5782 test addresses (the per-list health check); DQS answers
			// them like the public zone.
			"2.0.0.127." + dqs:             {"127.0.0.2"},
			"2.0.0.127.bl.spamcop.net":     {"127.0.0.2"},
			"7.113.0.203." + dqs:           {"127.0.0.4"},
			"7.113.0.203.bl.spamcop.net":   {"127.0.0.2"},
			"7.113.0.203.zen.spamhaus.org": {"127.0.0.2"}, // must NOT be queried
		},
		errs: map[string]error{
			"9.100.51.198." + dqs: &net.DNSError{Err: "i/o timeout", Name: "9.100.51.198." + dqs, IsTimeout: true},
		},
	}
	m, store := testMonitor(r, []string{"203.0.113.7", "198.51.100.9"}, spamhaus, spamcop)
	m.WithSpamhausDQSKey(key)
	mustCheck(t, m)

	got := map[string]storedCheck{}
	for _, row := range store.rows {
		got[row.ip+" "+row.zone] = row
		if strings.Contains(row.zone+row.response, key) {
			t.Errorf("DQS key leaked into a stored row: %+v", row)
		}
	}
	if row := got["203.0.113.7 zen.spamhaus.org"]; row.status != repository.RBLStatusListed || row.response != "127.0.0.4" {
		t.Errorf("ZEN via DQS: %+v, want listed with the DQS answer 127.0.0.4", row)
	}
	if row := got["203.0.113.7 bl.spamcop.net"]; row.status != repository.RBLStatusListed {
		t.Errorf("other lists must be unaffected: %+v", row)
	}
	if row := got["198.51.100.9 zen.spamhaus.org"]; row.status != repository.RBLStatusUnknown || !strings.Contains(row.response, "zen.spamhaus.org (DQS)") {
		t.Errorf("DQS lookup error: %+v, want unknown naming zen.spamhaus.org (DQS)", row)
	}

	// The package default list itself is never modified.
	for _, b := range DefaultBlocklists {
		if b.queryZone != "" {
			t.Errorf("DefaultBlocklists mutated: %+v", b)
		}
	}

	// No key: unchanged behaviour.
	m2, _ := testMonitor(r, nil, spamhaus)
	if m2.WithSpamhausDQSKey(""); m2.lists[0].lookupZone() != "zen.spamhaus.org" {
		t.Errorf("empty key must leave the public zone, got %q", m2.lists[0].lookupZone())
	}
}
