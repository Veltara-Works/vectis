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

// testAddress is the RFC 5782 test entry every list should answer as listed.
const testAddress = "127.0.0.2"

// Lookuper resolves a DNS name to addresses. *net.Resolver implements it.
type Lookuper interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// FallbackLookuper tries Primary and, when it fails for a reason other than
// "name not found", Secondary. It lets the monitor prefer the resolver the
// blocklists accept (rspamd's bundled unbound, ADR-026 amendment A) without
// going dark when that resolver is down or disabled.
type FallbackLookuper struct {
	Primary, Secondary Lookuper
}

// LookupHost implements Lookuper.
func (f FallbackLookuper) LookupHost(ctx context.Context, host string) ([]string, error) {
	addrs, err := f.Primary.LookupHost(ctx, host)
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
	Create(ctx context.Context, ipAddress, rblName, status string, response *string) (string, error)
	PruneOlderThan(ctx context.Context, age time.Duration) (int64, error)
}

// RBLMonitor periodically checks the server's sending IPs against DNS
// blocklists.
type RBLMonitor struct {
	repo     rblStore
	logger   *slog.Logger
	resolver Lookuper
	ipSource func(ctx context.Context) ([]string, error)
	lists    []Blocklist
	interval time.Duration
	timeout  time.Duration
	stopCh   chan struct{}

	mu  sync.Mutex
	ips []string // IPs from the most recent run
}

// NewRBLMonitor creates a monitor. ipSource returns the IPs to check on each
// run, so a changed A record or a new warmup IP is picked up without a restart.
func NewRBLMonitor(repo rblStore, resolver Lookuper, ipSource func(ctx context.Context) ([]string, error), logger *slog.Logger) *RBLMonitor {
	return &RBLMonitor{
		repo:     repo,
		logger:   logger,
		resolver: resolver,
		ipSource: ipSource,
		lists:    DefaultBlocklists,
		interval: 6 * time.Hour,
		timeout:  10 * time.Second,
		stopCh:   make(chan struct{}),
	}
}

// Start begins the periodic checking loop, with a first run straight away.
func (m *RBLMonitor) Start() {
	m.logger.Info("starting RBL monitor", "lists", len(m.lists), "interval", m.interval)
	go func() {
		m.checkAll()
		ticker := time.NewTicker(m.interval)
		defer ticker.Stop()
		for {
			select {
			case <-m.stopCh:
				return
			case <-ticker.C:
				m.checkAll()
			}
		}
	}()
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

// CheckNow checks every IP against every list and stores the results.
func (m *RBLMonitor) CheckNow(ctx context.Context) []repository.RBLCheck {
	ips, err := m.ipSource(ctx)
	if err != nil {
		m.logger.Warn("rbl monitor: could not determine server IPs", "error", err)
	}
	m.mu.Lock()
	if len(ips) > 0 || err == nil {
		m.ips = ips
	} else {
		ips = m.ips // keep checking the last known IPs through a lookup blip
	}
	m.mu.Unlock()
	if len(ips) == 0 {
		return nil
	}

	// Self-test each list once per run: a list that doesn't answer its own test
	// address (unregistered resolver, refused query, list down) can't be trusted
	// to say "clean" either.
	healthy := make(map[string]string, len(m.lists)) // zone -> reason when unhealthy
	for _, l := range m.lists {
		st, reason := m.lookup(ctx, testAddress, l)
		if st != repository.RBLStatusListed {
			if reason == "" {
				reason = "list did not answer its test address"
			}
			healthy[l.Zone] = reason
		}
	}

	var results []repository.RBLCheck
	for _, ip := range ips {
		for _, l := range m.lists {
			status, reason := m.lookup(ctx, ip, l)
			if r, bad := healthy[l.Zone]; bad && status != repository.RBLStatusListed {
				status, reason = repository.RBLStatusUnknown, "list unavailable: "+r
			}
			var respPtr *string
			if reason != "" {
				respPtr = &reason
			}
			id, err := m.repo.Create(ctx, ip, l.Zone, status, respPtr)
			if err != nil {
				m.logger.Error("store rbl check failed", "error", err, "ip", ip, "rbl", l.Zone)
				continue
			}
			results = append(results, repository.RBLCheck{
				ID: id, IPAddress: ip, RBLName: l.Zone, Status: status,
				Listed: status == repository.RBLStatusListed, Response: respPtr,
				CheckedAt: time.Now().UTC(),
			})
			switch status {
			case repository.RBLStatusListed:
				m.logger.Warn("IP listed on RBL", "ip", ip, "rbl", l.Zone, "response", reason)
			case repository.RBLStatusUnknown:
				m.logger.Info("RBL check inconclusive", "ip", ip, "rbl", l.Zone, "reason", reason)
			}
		}
	}
	return results
}

// lookup queries one list for one IPv4 address. It returns the status and, for
// listed, the answer, or for unknown, the reason.
func (m *RBLMonitor) lookup(ctx context.Context, ipAddr string, l Blocklist) (string, string) {
	ip := net.ParseIP(ipAddr).To4()
	if ip == nil {
		return repository.RBLStatusUnknown, "not an IPv4 address"
	}
	query := fmt.Sprintf("%d.%d.%d.%d.%s", ip[3], ip[2], ip[1], ip[0], l.Zone)

	ctx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()
	addrs, err := m.resolver.LookupHost(ctx, query)
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

func (m *RBLMonitor) checkAll() {
	ctx := context.Background()
	m.CheckNow(ctx)

	// Prune old results (keep 30 days).
	pruned, err := m.repo.PruneOlderThan(ctx, 30*24*time.Hour)
	if err != nil {
		m.logger.Error("prune rbl checks failed", "error", err)
	} else if pruned > 0 {
		m.logger.Debug("pruned old rbl checks", "count", pruned)
	}
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
