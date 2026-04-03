package mail

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/Veltara-Works/vectis/internal/repository"
)

// DefaultRBLs is the list of major DNS blacklists to check.
var DefaultRBLs = []string{
	"zen.spamhaus.org",
	"bl.spamcop.net",
	"b.barracudacentral.org",
	"dnsbl.sorbs.net",
	"psbl.surriel.com",
	"dnsbl-1.uceprotect.net",
	"all.s5h.net",
}

// RBLMonitor periodically checks server IPs against DNS blacklists.
type RBLMonitor struct {
	repo     *repository.RBLCheckRepo
	logger   *slog.Logger
	ips      []string // server IPs to check
	rbls     []string
	interval time.Duration
	stopCh   chan struct{}
}

// NewRBLMonitor creates a new RBL monitor.
func NewRBLMonitor(repo *repository.RBLCheckRepo, ips []string, logger *slog.Logger) *RBLMonitor {
	return &RBLMonitor{
		repo:     repo,
		logger:   logger,
		ips:      ips,
		rbls:     DefaultRBLs,
		interval: 6 * time.Hour, // check every 6 hours
		stopCh:   make(chan struct{}),
	}
}

// Start begins the periodic RBL checking loop.
func (m *RBLMonitor) Start() {
	m.logger.Info("starting RBL monitor",
		"ips", m.ips, "rbls", len(m.rbls), "interval", m.interval)

	// Run initial check immediately.
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

// CheckNow runs an immediate check of all IPs against all RBLs.
func (m *RBLMonitor) CheckNow(ctx context.Context) []repository.RBLCheck {
	var results []repository.RBLCheck
	for _, ip := range m.ips {
		for _, rbl := range m.rbls {
			listed, response := checkRBL(ip, rbl)
			var respPtr *string
			if response != "" {
				respPtr = &response
			}
			id, err := m.repo.Create(ctx, ip, rbl, listed, respPtr)
			if err != nil {
				m.logger.Error("store rbl check failed", "error", err, "ip", ip, "rbl", rbl)
				continue
			}
			results = append(results, repository.RBLCheck{
				ID: id, IPAddress: ip, RBLName: rbl,
				Listed: listed, Response: respPtr,
				CheckedAt: time.Now().UTC(),
			})
			if listed {
				m.logger.Warn("IP listed on RBL",
					"ip", ip, "rbl", rbl, "response", response)
			}
		}
	}
	return results
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

// IPs returns the list of server IPs being monitored.
func (m *RBLMonitor) IPs() []string {
	return m.ips
}

// checkRBL does a DNS lookup against a single RBL for an IP address.
// Returns (listed, response). IPv4 only for now (most RBLs only support IPv4).
func checkRBL(ipAddr, rbl string) (bool, string) {
	ip := net.ParseIP(ipAddr)
	if ip == nil {
		return false, ""
	}

	// Only IPv4 for RBL lookups.
	ip4 := ip.To4()
	if ip4 == nil {
		return false, ""
	}

	// Reverse the IP octets for DNSBL lookup.
	reversed := fmt.Sprintf("%d.%d.%d.%d", ip4[3], ip4[2], ip4[1], ip4[0])
	query := reversed + "." + rbl

	addrs, err := net.LookupHost(query)
	if err != nil {
		// DNS error = not listed (NXDOMAIN).
		return false, ""
	}

	if len(addrs) > 0 {
		return true, strings.Join(addrs, ", ")
	}
	return false, ""
}
