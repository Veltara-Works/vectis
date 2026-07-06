package cli

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Veltara-Works/vectis/internal/dkim"
	"github.com/Veltara-Works/vectis/internal/repository"
)

// domain check — deliverability self-check for a configured domain.
//
// Verifies the public DNS + TLS posture of a domain Vectis manages:
//   SPF   — a v=spf1 TXT record exists and ends in a restrictive qualifier.
//   DKIM  — the published <selector>._domainkey TXT matches the local signing key.
//   DMARC — a v=DMARC1 policy record exists at _dmarc.<domain>.
//   PTR   — the domain's MX host has forward-confirmed reverse DNS (FCrDNS).
//   TLS   — the MX host offers STARTTLS with a currently-valid, hostname-matching cert.
//
// The domain must already exist (`vectis domain add` first) so the DKIM key and
// selector are known. Network/DNS checks degrade gracefully: an unreachable MX or
// unreadable local key downgrades a check to WARN rather than crashing the run.

var domainCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Run deliverability checks (SPF/DKIM/DMARC/PTR/TLS) for a domain",
	Long: "Checks the public DNS and TLS posture of a configured domain and reports " +
		"PASS/WARN/FAIL for SPF, DKIM, DMARC, PTR (FCrDNS) and inbound STARTTLS.",
	RunE: runDomainCheck,
}

// checkStatus is the tri-state outcome of a single check.
type checkStatus string

const (
	statusPass checkStatus = "pass"
	statusWarn checkStatus = "warn"
	statusFail checkStatus = "fail"
)

// domainCheckResult is one row of the report.
type domainCheckResult struct {
	Check  string      `json:"check"`
	Status checkStatus `json:"status"`
	Detail string      `json:"detail"`
}

func runDomainCheck(cmd *cobra.Command, args []string) error {
	if domainName == "" && len(args) == 1 {
		domainName = args[0]
	}
	if domainName == "" {
		fmt.Fprintln(cmd.ErrOrStderr(), "Error: --name is required (or pass the domain as an argument)")
		os.Exit(2)
	}

	pool, _, cleanup := connectDB(cmd)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	jsonOutput, _ := cmd.Flags().GetBool("json")

	repo := repository.NewDomainRepo(pool)
	domain, err := repo.GetByName(ctx, domainName)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", err)
		os.Exit(1)
	}
	if domain == nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: domain %s not found. Add it first: vectis domain add --name %s\n",
			domainName, domainName)
		os.Exit(1)
	}

	results := []domainCheckResult{
		checkSPF(domainName),
		checkDKIM(domainName, domain.DKIMSelector, dkimKeyPath(domain)),
		checkDMARC(domainName),
	}
	// PTR + TLS both depend on the domain's MX host; resolve it once.
	mxHost, mxResult := primaryMX(domainName)
	if mxResult != nil {
		// MX lookup failed — surface that and skip the MX-dependent checks.
		results = append(results, *mxResult,
			domainCheckResult{Check: "PTR", Status: statusWarn, Detail: "skipped: no usable MX host"},
			domainCheckResult{Check: "TLS", Status: statusWarn, Detail: "skipped: no usable MX host"})
	} else {
		results = append(results, checkPTR(mxHost), checkTLS(mxHost))
	}

	if jsonOutput {
		out, _ := json.MarshalIndent(struct {
			Domain string              `json:"domain"`
			Checks []domainCheckResult `json:"checks"`
		}{Domain: domainName, Checks: results}, "", "  ")
		fmt.Fprintln(cmd.OutOrStdout(), string(out))
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "Deliverability check for %s\n\n", domainName)
		for _, r := range results {
			fmt.Fprintf(cmd.OutOrStdout(), "  %-6s %-5s %s\n", r.Check, strings.ToUpper(string(r.Status)), r.Detail)
		}
		fmt.Fprintln(cmd.OutOrStdout())
	}

	// Exit non-zero if any check FAILed, so the command is scriptable.
	for _, r := range results {
		if r.Status == statusFail {
			os.Exit(1)
		}
	}
	return nil
}

// dkimKeyPath returns the local DKIM private-key path for a domain, or "" if unset.
func dkimKeyPath(d *repository.Domain) string {
	if d.DKIMKeyPath != nil {
		return *d.DKIMKeyPath
	}
	return ""
}

// --- pure classifiers (unit-tested; no network) -------------------------------

// classifySPF inspects a domain's TXT records for a single valid SPF policy.
func classifySPF(txts []string) domainCheckResult {
	var spf []string
	for _, t := range txts {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=spf1") {
			spf = append(spf, strings.TrimSpace(t))
		}
	}
	switch {
	case len(spf) == 0:
		return domainCheckResult{"SPF", statusFail, "no v=spf1 record found"}
	case len(spf) > 1:
		// RFC 7208: multiple SPF records is a permerror.
		return domainCheckResult{"SPF", statusFail, fmt.Sprintf("%d SPF records (must be exactly 1)", len(spf))}
	}
	rec := spf[0]
	switch {
	case strings.Contains(rec, "-all"):
		return domainCheckResult{"SPF", statusPass, "record present, hard fail (-all)"}
	case strings.Contains(rec, "~all"):
		return domainCheckResult{"SPF", statusPass, "record present, soft fail (~all)"}
	case strings.Contains(rec, "?all"), strings.Contains(rec, "+all"):
		return domainCheckResult{"SPF", statusWarn, "record present but permissive (?all/+all) — tighten to -all"}
	default:
		return domainCheckResult{"SPF", statusWarn, "record present but no all-qualifier — add -all"}
	}
}

// classifyDKIM compares a domain's _domainkey TXT records against the local key.
// expectedB64 is the base64 of the local public key DER (empty if unreadable).
func classifyDKIM(txts []string, selector, expectedB64 string) domainCheckResult {
	var dk string
	for _, t := range txts {
		if strings.Contains(strings.ToLower(t), "v=dkim1") || strings.Contains(t, "p=") {
			dk += strings.TrimSpace(t)
		}
	}
	if dk == "" {
		return domainCheckResult{"DKIM", statusFail, fmt.Sprintf("no record at %s._domainkey", selector)}
	}
	pub := extractDKIMPub(dk)
	if pub == "" {
		return domainCheckResult{"DKIM", statusFail, "record present but no p= public key"}
	}
	if expectedB64 == "" {
		return domainCheckResult{"DKIM", statusWarn, "record published; local key unreadable, not verified"}
	}
	if pub == expectedB64 {
		return domainCheckResult{"DKIM", statusPass, fmt.Sprintf("published key matches local selector %s", selector)}
	}
	return domainCheckResult{"DKIM", statusFail, "published key does NOT match local signing key"}
}

// extractDKIMPub pulls the p= value out of a DKIM TXT record body.
func extractDKIMPub(rec string) string {
	for _, tag := range strings.Split(rec, ";") {
		tag = strings.TrimSpace(tag)
		if strings.HasPrefix(tag, "p=") {
			return strings.TrimSpace(strings.TrimPrefix(tag, "p="))
		}
	}
	return ""
}

// classifyDMARC inspects _dmarc TXT records for a valid policy.
func classifyDMARC(txts []string) domainCheckResult {
	for _, t := range txts {
		t = strings.TrimSpace(t)
		if !strings.HasPrefix(strings.ToLower(t), "v=dmarc1") {
			continue
		}
		policy := ""
		for _, tag := range strings.Split(t, ";") {
			tag = strings.TrimSpace(tag)
			if strings.HasPrefix(tag, "p=") {
				policy = strings.TrimSpace(strings.TrimPrefix(tag, "p="))
			}
		}
		switch policy {
		case "reject", "quarantine":
			return domainCheckResult{"DMARC", statusPass, "policy p=" + policy}
		case "none":
			return domainCheckResult{"DMARC", statusWarn, "policy p=none (monitor-only) — strengthen to quarantine/reject"}
		default:
			return domainCheckResult{"DMARC", statusWarn, "record present but no/unknown policy"}
		}
	}
	return domainCheckResult{"DMARC", statusFail, "no v=DMARC1 record at _dmarc"}
}

// --- network checks (thin shells over the pure classifiers) -------------------

func checkSPF(domain string) domainCheckResult {
	txts, _ := net.LookupTXT(domain)
	return classifySPF(txts)
}

func checkDMARC(domain string) domainCheckResult {
	txts, _ := net.LookupTXT("_dmarc." + domain)
	return classifyDMARC(txts)
}

func checkDKIM(domain, selector, keyPath string) domainCheckResult {
	if selector == "" {
		return domainCheckResult{"DKIM", statusWarn, "no DKIM selector configured for this domain"}
	}
	txts, _ := net.LookupTXT(selector + "._domainkey." + domain)
	var expectedB64 string
	if keyPath != "" {
		if der, err := dkim.ReadPublicKey(keyPath); err == nil {
			expectedB64 = base64.StdEncoding.EncodeToString(der)
		}
	}
	return classifyDKIM(txts, selector, expectedB64)
}

// primaryMX returns the lowest-preference MX hostname for a domain. On failure it
// returns ("", <fail result>) so the caller can record it and skip MX-dependent checks.
func primaryMX(domain string) (string, *domainCheckResult) {
	mxs, err := net.LookupMX(domain)
	if err != nil || len(mxs) == 0 {
		return "", &domainCheckResult{Check: "MX", Status: statusFail, Detail: "no MX records found"}
	}
	sort.Slice(mxs, func(i, j int) bool { return mxs[i].Pref < mxs[j].Pref })
	return strings.TrimSuffix(mxs[0].Host, "."), nil
}

// checkPTR confirms the MX host has forward-confirmed reverse DNS (FCrDNS): its IP
// reverse-resolves to a name that forward-resolves back to the same IP.
func checkPTR(mxHost string) domainCheckResult {
	ips, err := net.LookupIP(mxHost)
	if err != nil || len(ips) == 0 {
		return domainCheckResult{"PTR", statusFail, "MX host " + mxHost + " does not resolve"}
	}
	ip := ips[0]
	names, err := net.LookupAddr(ip.String())
	if err != nil || len(names) == 0 {
		return domainCheckResult{"PTR", statusFail, "no PTR record for " + ip.String()}
	}
	for _, name := range names {
		fwd, err := net.LookupIP(strings.TrimSuffix(name, "."))
		if err != nil {
			continue
		}
		for _, f := range fwd {
			if f.Equal(ip) {
				return domainCheckResult{"PTR", statusPass, fmt.Sprintf("%s → %s (FCrDNS confirmed)", ip, strings.TrimSuffix(name, "."))}
			}
		}
	}
	return domainCheckResult{"PTR", statusWarn, fmt.Sprintf("PTR %q does not forward-confirm to %s", strings.TrimSuffix(names[0], "."), ip)}
}

// checkTLS dials the MX host on port 25, negotiates STARTTLS, and inspects the
// presented certificate for validity window and hostname match.
func checkTLS(mxHost string) domainCheckResult {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(mxHost, "25"), 8*time.Second)
	if err != nil {
		return domainCheckResult{"TLS", statusFail, "cannot connect to " + mxHost + ":25 — " + err.Error()}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(12 * time.Second))

	c, err := smtp.NewClient(conn, mxHost)
	if err != nil {
		return domainCheckResult{"TLS", statusFail, "SMTP handshake failed: " + err.Error()}
	}
	defer c.Close()

	if ok, _ := c.Extension("STARTTLS"); !ok {
		return domainCheckResult{"TLS", statusFail, "MX does not advertise STARTTLS"}
	}
	// Verify the presented cert against the MX hostname — the posture a strict
	// sender / MTA-STS peer applies. A bad cert (expired, wrong host, untrusted
	// chain) surfaces here as a descriptive handshake error, reported verbatim.
	if err := c.StartTLS(&tls.Config{ServerName: mxHost, MinVersion: tls.VersionTLS12}); err != nil {
		return domainCheckResult{"TLS", statusFail, "STARTTLS cert verification failed: " + err.Error()}
	}
	state, ok := c.TLSConnectionState()
	if !ok || len(state.PeerCertificates) == 0 {
		return domainCheckResult{"TLS", statusFail, "no certificate presented"}
	}
	// The handshake already validated the expiry window, hostname and chain;
	// only the soft "expiring soon" warning remains.
	daysLeft := int(time.Until(state.PeerCertificates[0].NotAfter).Hours() / 24)
	if daysLeft < 14 {
		return domainCheckResult{"TLS", statusWarn, fmt.Sprintf("STARTTLS OK but cert expires in %dd — renew soon", daysLeft)}
	}
	return domainCheckResult{"TLS", statusPass, fmt.Sprintf("STARTTLS OK, cert valid %dd, matches %s", daysLeft, mxHost)}
}

func init() {
	domainCheckCmd.Flags().StringVar(&domainName, "name", "", "Domain name (required)")
	domainCmd.AddCommand(domainCheckCmd)
}
