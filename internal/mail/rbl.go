package mail

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Veltara-Works/vectis/internal/repository"
)

// Blocklist is one DNS blocklist the monitor checks the server's sending IPs
// against.
type Blocklist struct {
	Zone      string `json:"zone"`
	Name      string `json:"name"`
	DelistURL string `json:"delist_url"`
	// ListedCodes are the A-record answers that mean "listed". Any other
	// answer is a list-side status code (Spamhaus answers 127.255.255.x when it
	// refuses a query) and makes the result unknown, never listed or clean.
	ListedCodes []string `json:"-"`
}

// DefaultBlocklists are the lists checked by default. Each answers its RFC 5782
// test address (127.0.0.2) as listed; SORBS was dropped when it shut down in
// 2024. Spamhaus ZEN includes the CBL (as XBL).
var DefaultBlocklists = []Blocklist{
	{Zone: "zen.spamhaus.org", Name: "Spamhaus ZEN", DelistURL: "https://check.spamhaus.org/",
		ListedCodes: []string{"127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.5", "127.0.0.6", "127.0.0.7", "127.0.0.9", "127.0.0.10", "127.0.0.11"}},
	{Zone: "bl.spamcop.net", Name: "SpamCop", DelistURL: "https://www.spamcop.net/bl.shtml",
		ListedCodes: []string{"127.0.0.2"}},
	{Zone: "b.barracudacentral.org", Name: "Barracuda BRBL", DelistURL: "https://www.barracudacentral.org/rbl/removal-request",
		ListedCodes: []string{"127.0.0.2"}},
	{Zone: "psbl.surriel.com", Name: "PSBL", DelistURL: "https://psbl.org/",
		ListedCodes: []string{"127.0.0.2"}},
	{Zone: "dnsbl-1.uceprotect.net", Name: "UCEPROTECT Level 1", DelistURL: "https://www.uceprotect.net/en/rblcheck.php",
		ListedCodes: []string{"127.0.0.2"}},
	{Zone: "all.s5h.net", Name: "s5h.net", DelistURL: "https://www.usenix.org.uk/content/rbl.html",
		ListedCodes: []string{"127.0.0.2"}},
}

// BlocklistByZone returns the default list with the given zone.
func BlocklistByZone(zone string) (Blocklist, bool) {
	for _, b := range DefaultBlocklists {
		if b.Zone == zone {
			return b, true
		}
	}
	return Blocklist{}, false
}

// A run makes at most 2 sequential self-test lookups per list (one per
// resolver, lists in parallel) and then the IP lookups, rblConcurrency at a
// time, each bounded by rblLookupTimeout. For one IP and six lists that is at
// most ~4 lookups deep (~16 s), inside the API's 30 s write timeout.
const (
	rblLookupTimeout = 4 * time.Second
	rblConcurrency   = 8
	rblStoreTimeout  = 10 * time.Second // storing a run's results; independent of the lookups' deadline
)

// rblRetryInterval is how soon the loop tries again when it couldn't find
// any IP to check, rather than waiting a whole interval.
const rblRetryInterval = 5 * time.Minute

// DiscoveryError reports that a run couldn't determine the server's IPs and
// had none from an earlier run to check instead, so nothing was checked.
type DiscoveryError struct{ Err error }

func (e *DiscoveryError) Error() string {
	return "could not determine the server's IP addresses: " + e.Err.Error()
}
func (e *DiscoveryError) Unwrap() error { return e.Err }

// testAddress is the RFC 5782 test entry every list should answer as listed.
const testAddress = "127.0.0.2"

// Lookuper resolves a DNS name to addresses. *net.Resolver implements it.
type Lookuper interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// FallbackLookuper tries Primary and, when it fails for a reason other than
// "name not found", Secondary. The monitor uses it only for positive lookups
// (the mail hostname's A records); blocklist queries pick one resolver per
// list per run instead, so a "not listed" answer always comes from a resolver
// that just passed that list's self-test.
type FallbackLookuper struct {
	Primary, Secondary Lookuper
	// PrimaryTimeout bounds the Primary attempt so Secondary still has time
	// within the caller's deadline. Zero means no separate bound.
	PrimaryTimeout time.Duration
}

// LookupHost implements Lookuper.
func (f FallbackLookuper) LookupHost(ctx context.Context, host string) ([]string, error) {
	pctx, cancel := ctx, context.CancelFunc(func() {})
	if f.PrimaryTimeout > 0 {
		pctx, cancel = context.WithTimeout(ctx, f.PrimaryTimeout)
	}
	addrs, err := f.Primary.LookupHost(pctx, host)
	cancel()
	if err == nil || isNotFound(err) || f.Secondary == nil {
		return addrs, err
	}
	return f.Secondary.LookupHost(ctx, host)
}

// NewServerResolver returns a resolver that sends every query to addr
// (host:port), e.g. "rspamd:53".
func NewServerResolver(addr string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, network, addr)
		},
	}
}

func isNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

// rblStore is the part of the results repository the monitor uses.
type rblStore interface {
	Create(ctx context.Context, ipAddress, rblName, status string, response *string, checkedAt time.Time) (string, error)
	PruneOlderThan(ctx context.Context, age time.Duration) (int64, error)
}

// RBLMonitor periodically checks the server's sending IPs against DNS
// blocklists.
type RBLMonitor struct {
	repo      rblStore
	logger    *slog.Logger
	resolvers []Lookuper // tried in order per list; see CheckNow
	ipSource  func(ctx context.Context) ([]string, error)
	lists     []Blocklist
	interval  time.Duration
	retry     time.Duration // after a run that found no IP to check
	timeout   time.Duration
	stopCh    chan struct{}

	mu     sync.Mutex
	ips    []string // IPs from the most recent run to publish
	runSeq uint64   // numbers runs in the order they start
	pubSeq uint64   // the run that last published ips
}

// NewRBLMonitor creates a monitor. resolvers are tried in order for each list
// (rspamd's bundled resolver first, then the default). ipSource returns the IPs
// to check on each run, so a changed A record or a new warmup IP is picked up
// without a restart.
func NewRBLMonitor(repo rblStore, resolvers []Lookuper, ipSource func(ctx context.Context) ([]string, error), logger *slog.Logger) *RBLMonitor {
	return &RBLMonitor{
		repo:      repo,
		logger:    logger,
		resolvers: resolvers,
		ipSource:  ipSource,
		lists:     DefaultBlocklists,
		interval:  6 * time.Hour,
		retry:     rblRetryInterval,
		timeout:   rblLookupTimeout,
		stopCh:    make(chan struct{}),
	}
}

// Start begins the periodic checking loop, with a first run straight away.
func (m *RBLMonitor) Start() {
	m.logger.Info("starting RBL monitor", "lists", len(m.lists), "interval", m.interval)
	go func() {
		timer := time.NewTimer(m.nextDelay(m.checkAll()))
		defer timer.Stop()
		for {
			select {
			case <-m.stopCh:
				return
			case <-timer.C:
				timer.Reset(m.nextDelay(m.checkAll()))
			}
		}
	}()
}

// nextDelay is the wait before the next run: the normal interval, or a short
// retry when the last run couldn't find any IP to check.
func (m *RBLMonitor) nextDelay(runErr error) time.Duration {
	var de *DiscoveryError
	if errors.As(runErr, &de) {
		return m.retry
	}
	return m.interval
}

// Stop signals the monitor to stop.
func (m *RBLMonitor) Stop() {
	m.logger.Info("stopping RBL monitor")
	close(m.stopCh)
}

// IPs returns the IPs checked by the most recent run.
func (m *RBLMonitor) IPs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.ips...)
}

// CheckNow checks every IP against every list and stores the results. ctx
// bounds the DNS work only: results are stored under their own short deadline
// that isn't cancelled with ctx, so a run that hits its deadline still records
// what it found (pending lookups as unknown). The error is a *DiscoveryError
// when no IP could be found to check, and otherwise reports results that could
// not be stored.
func (m *RBLMonitor) CheckNow(ctx context.Context) ([]repository.RBLCheck, error) {
	// The background loop and "Check now" can overlap. Number each run as it
	// starts, so a slower run that began earlier can't overwrite the IPs a
	// newer run (with a fresher discovery) has already published.
	m.mu.Lock()
	m.runSeq++
	seq := m.runSeq
	m.mu.Unlock()

	ips, err := m.ipSource(ctx)
	m.mu.Lock()
	if err != nil {
		// Partial or failed discovery: keep checking every IP we knew about,
		// so a DNS blip can't silently drop the server's main address.
		m.logger.Warn("rbl monitor: could not fully determine server IPs", "error", err)
		ips = unionIPs(m.ips, ips)
	}
	if len(ips) == 0 {
		// A clean discovery that finds nothing (e.g. the A record was removed)
		// clears what the dashboard shows. A failed one with nothing known
		// from before is reported, so it isn't mistaken for a run.
		m.mu.Unlock()
		if err != nil {
			return nil, &DiscoveryError{Err: err}
		}
		m.mu.Lock()
		m.publishLocked(seq, nil)
		m.mu.Unlock()
		return nil, nil
	}
	m.mu.Unlock()

	// Pick a resolver per list: the first that answers the list's own RFC 5782
	// test address as listed. That list's IP queries then use the same
	// resolver, so a "not listed" answer is only trusted from a resolver the
	// list was just seen to answer (an unregistered or refused resolver often
	// returns NXDOMAIN for everything). No resolver passing means unknown.
	// Lists are tested concurrently, and every lookup has its own short
	// deadline, so a whole run fits inside an API request ("Check now").
	chosen := make([]Lookuper, len(m.lists))
	unhealthy := make([]string, len(m.lists))
	unhealthyAt := make([]time.Time, len(m.lists)) // when the list failed its self-test
	var wg sync.WaitGroup
	for i, l := range m.lists {
		wg.Add(1)
		go func(i int, l Blocklist) {
			defer wg.Done()
			reason := "list did not answer its test address"
			for _, r := range m.resolvers {
				st, why := m.lookup(ctx, r, testAddress, l)
				if st == repository.RBLStatusListed {
					chosen[i] = r
					return
				}
				if why != "" {
					reason = "list did not answer its test address: " + why
				}
			}
			unhealthy[i] = reason
			unhealthyAt[i] = time.Now().UTC()
		}(i, l)
	}
	wg.Wait()

	// Query every (IP, list) pair, at most rblConcurrency at a time. Each
	// result keeps the time it was observed, which is what gets stored: runs
	// can overlap (the loop and "Check now"), and a slower run saving later
	// must not make its older answer look newer than another run's.
	type outcome struct {
		status, reason string
		at             time.Time
	}
	outcomes := make([]outcome, len(ips)*len(m.lists))
	sem := make(chan struct{}, rblConcurrency)
	for ipIdx, ip := range ips {
		for listIdx, l := range m.lists {
			k := ipIdx*len(m.lists) + listIdx
			r := chosen[listIdx]
			if r == nil {
				outcomes[k] = outcome{repository.RBLStatusUnknown, "list unavailable: " + unhealthy[listIdx], unhealthyAt[listIdx]}
				continue
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(k int, r Lookuper, ip string, l Blocklist) {
				defer func() { <-sem; wg.Done() }()
				st, why := m.lookup(ctx, r, ip, l)
				outcomes[k] = outcome{st, why, time.Now().UTC()}
			}(k, r, ip, l)
		}
	}
	wg.Wait()

	storeCtx, cancelStore := context.WithTimeout(context.WithoutCancel(ctx), rblStoreTimeout)
	defer cancelStore()
	var results []repository.RBLCheck
	var storeErrs []error
	for ipIdx, ip := range ips {
		for listIdx, l := range m.lists {
			o := outcomes[ipIdx*len(m.lists)+listIdx]
			status, reason := o.status, o.reason
			var respPtr *string
			if reason != "" {
				respPtr = &reason
			}
			id, err := m.repo.Create(storeCtx, ip, l.Zone, status, respPtr, o.at)
			if err != nil {
				m.logger.Error("store rbl check failed", "error", err, "ip", ip, "rbl", l.Zone)
				storeErrs = append(storeErrs, fmt.Errorf("%s on %s: %w", ip, l.Zone, err))
				continue
			}
			results = append(results, repository.RBLCheck{
				ID: id, IPAddress: ip, RBLName: l.Zone, Status: status,
				Listed: status == repository.RBLStatusListed, Response: respPtr,
				CheckedAt: o.at,
			})
			switch status {
			case repository.RBLStatusListed:
				m.logger.Warn("IP listed on RBL", "ip", ip, "rbl", l.Zone, "response", reason)
			case repository.RBLStatusUnknown:
				m.logger.Info("RBL check inconclusive", "ip", ip, "rbl", l.Zone, "reason", reason)
			}
		}
	}

	// Publish the IPs only once their results are stored, so the dashboard
	// never shows an IP mid-run.
	m.mu.Lock()
	m.publishLocked(seq, ips)
	m.mu.Unlock()
	return results, errors.Join(storeErrs...)
}

// publishLocked sets the published IPs for run seq unless a newer run has
// already published. m.mu must be held.
func (m *RBLMonitor) publishLocked(seq uint64, ips []string) {
	if seq < m.pubSeq {
		return
	}
	m.ips = ips
	m.pubSeq = seq
}

// unionIPs returns a's IPs followed by any in b that a lacks.
func unionIPs(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	var out []string
	for _, ip := range append(append([]string(nil), a...), b...) {
		if !seen[ip] {
			seen[ip] = true
			out = append(out, ip)
		}
	}
	return out
}

// lookup queries one list for one IPv4 address. It returns the status and, for
// listed, the answer, or for unknown, the reason.
func (m *RBLMonitor) lookup(ctx context.Context, r Lookuper, ipAddr string, l Blocklist) (string, string) {
	ip := net.ParseIP(ipAddr).To4()
	if ip == nil {
		return repository.RBLStatusUnknown, "not an IPv4 address"
	}
	query := fmt.Sprintf("%d.%d.%d.%d.%s", ip[3], ip[2], ip[1], ip[0], l.Zone)

	ctx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()
	addrs, err := r.LookupHost(ctx, query)
	if err != nil {
		if isNotFound(err) {
			return repository.RBLStatusClean, ""
		}
		return repository.RBLStatusUnknown, "lookup failed: " + err.Error()
	}
	return classifyAnswer(addrs, l)
}

// classifyAnswer turns a list's A records into a status. Only the list's
// documented listing codes count as listed; anything else (e.g. Spamhaus's
// 127.255.255.252/254/255 refusals) is unknown.
func classifyAnswer(addrs []string, l Blocklist) (string, string) {
	sort.Strings(addrs)
	answer := strings.Join(addrs, ", ")
	for _, a := range addrs {
		for _, code := range l.ListedCodes {
			if a == code {
				return repository.RBLStatusListed, answer
			}
		}
	}
	if len(addrs) == 0 {
		return repository.RBLStatusUnknown, "empty answer"
	}
	return repository.RBLStatusUnknown, "list returned a status code, not a listing: " + answer
}

// checkAll runs one check and prunes old results. It returns the run's error.
func (m *RBLMonitor) checkAll() error {
	ctx := context.Background()
	_, runErr := m.CheckNow(ctx)
	var de *DiscoveryError
	switch {
	case errors.As(runErr, &de):
		m.logger.Warn("rbl run: nothing checked, retrying soon", "error", runErr, "retry_in", m.retry)
	case runErr != nil:
		m.logger.Error("rbl run: some results were not stored", "error", runErr)
	}

	// Prune old results (keep 30 days).
	pruned, err := m.repo.PruneOlderThan(ctx, 30*24*time.Hour)
	if err != nil {
		m.logger.Error("prune rbl checks failed", "error", err)
	} else if pruned > 0 {
		m.logger.Debug("pruned old rbl checks", "count", pruned)
	}
	return runErr
}

// HostnameIPs returns the IPv4 addresses the mail hostname resolves to. These
// are the addresses MX records point at and, on a single-IP server, the one
// Postfix sends from.
func HostnameIPs(ctx context.Context, r Lookuper, hostname string) ([]string, error) {
	addrs, err := r.LookupHost(ctx, hostname)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", hostname, err)
	}
	var out []string
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil && ip.To4() != nil && !ip.IsPrivate() && !ip.IsLoopback() {
			out = append(out, ip.String())
		}
	}
	return out, nil
}
