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

type storedCheck struct{ ip, zone, status, response string }

type fakeStore struct{ rows []storedCheck }

func (f *fakeStore) Create(_ context.Context, ip, zone, status string, response *string) (string, error) {
	r := ""
	if response != nil {
		r = *response
	}
	f.rows = append(f.rows, storedCheck{ip, zone, status, r})
	return "id", nil
}

func (f *fakeStore) PruneOlderThan(context.Context, time.Duration) (int64, error) { return 0, nil }

var (
	spamhaus = Blocklist{Zone: "zen.spamhaus.org", Name: "Spamhaus ZEN",
		ListedCodes: []string{"127.0.0.2", "127.0.0.4", "127.0.0.10"}}
	spamcop = Blocklist{Zone: "bl.spamcop.net", Name: "SpamCop", ListedCodes: []string{"127.0.0.2"}}
)

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
	results := m.CheckNow(context.Background())

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
	m.CheckNow(context.Background())

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
	m.CheckNow(context.Background())
	if len(store.rows) != 1 || store.rows[0].status != repository.RBLStatusUnknown {
		t.Fatalf("rows = %+v, want one unknown", store.rows)
	}
}

func TestCheckNowKeepsLastIPsWhenSourceFails(t *testing.T) {
	r := &fakeResolver{answers: map[string][]string{"2.0.0.127.bl.spamcop.net": {"127.0.0.2"}}}
	m, store := testMonitor(r, []string{"203.0.113.7"}, spamcop)
	m.CheckNow(context.Background())

	m.ipSource = func(context.Context) ([]string, error) { return nil, errors.New("dns blip") }
	m.CheckNow(context.Background())
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
	m.CheckNow(context.Background())

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
	m.CheckNow(context.Background())

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
	m.CheckNow(context.Background())

	// The hostname lookup fails; only the warmup IP comes back.
	m.ipSource = func(context.Context) ([]string, error) {
		return []string{"198.51.100.9"}, errors.New("resolve mail.example.com: timeout")
	}
	store.rows = nil
	m.CheckNow(context.Background())
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
	m.CheckNow(context.Background())

	m.ipSource = func(context.Context) ([]string, error) { return nil, errors.New("dns blip") }
	m.CheckNow(context.Background())
	if len(m.IPs()) != 1 {
		t.Fatalf("after a failed discovery IPs() = %v, want the old IP kept", m.IPs())
	}
	m.ipSource = func(context.Context) ([]string, error) { return nil, nil }
	m.CheckNow(context.Background())
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
	m.CheckNow(context.Background())
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
