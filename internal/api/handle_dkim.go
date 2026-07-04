package api

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/Veltara-Works/vectis/internal/dkim"
	"github.com/Veltara-Works/vectis/internal/repository"
)

// publicDNSResolver bypasses Docker's embedded resolver (127.0.0.11) so
// hostname→A lookups aren't intercepted by in-network containers that share
// the public hostname. Without this, mail.vectismail.com resolves to the
// postfix container's internal IP (172.x.x.x) inside the api container,
// which poisons the PTR check in deliverability reports.
var publicDNSResolver = &net.Resolver{
	PreferGo: true,
	Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		d := net.Dialer{Timeout: 3 * time.Second}
		return d.DialContext(ctx, network, "1.1.1.1:53")
	},
}

// firstPublicAddr returns the first non-RFC1918, non-loopback, non-link-local
// address in the list — defensive belt-and-braces alongside the public
// resolver, so even if Docker DNS leaks an internal address we never report
// on it.
func firstPublicAddr(addrs []string) string {
	for _, a := range addrs {
		ip := net.ParseIP(a)
		if ip == nil {
			continue
		}
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			continue
		}
		return a
	}
	return ""
}

type dkimResponse struct {
	DNSName  string `json:"dns_name"`
	DNSValue string `json:"dns_value"`
	Selector string `json:"selector"`
	KeyPath  string `json:"key_path"`
}

type deliverabilityResponse struct {
	Domain string                `json:"domain"`
	Checks []deliverabilityCheck `json:"checks"`
}

type deliverabilityCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"` // "pass", "fail", "warn", "info"
	Value  string `json:"value,omitempty"`
	Hint   string `json:"hint,omitempty"`
}

func (s *Server) handleGenerateDKIM(w http.ResponseWriter, r *http.Request) {
	domainID := chi.URLParam(r, "domainID")

	domain, err := s.domains.GetByID(r.Context(), domainID)
	if err != nil {
		s.logger.Error("get domain failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get domain")
		return
	}
	if domain == nil {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "Domain not found")
		return
	}

	selector := dkim.DefaultSelector()
	kp, err := dkim.GenerateKey(s.dkimBasePath, domain.Name, selector)
	if err != nil {
		s.logger.Error("generate DKIM key failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to generate DKIM key")
		return
	}

	// Update domain with new DKIM key info.
	keyPath := kp.KeyPath
	_, err = s.domains.Update(r.Context(), domainID, repository.DomainUpdate{
		DKIMSelector: &selector,
		DKIMKeyPath:  &keyPath,
	})
	if err != nil {
		s.logger.Error("update domain DKIM failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Key generated but failed to update domain record")
		return
	}

	adminID := getAdminID(r.Context())
	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "dkim.generate", "domain", &domainID,
		map[string]string{"selector": selector, "domain": domain.Name}, &ip)

	respond(w, r, http.StatusOK, dkimResponse{
		DNSName:  kp.DNSName(),
		DNSValue: kp.DNSRecord(),
		Selector: selector,
		KeyPath:  kp.KeyPath,
	})
}

func (s *Server) handleGetDKIM(w http.ResponseWriter, r *http.Request) {
	domainID := chi.URLParam(r, "domainID")
	if !s.canAccessDomain(r.Context(), domainID) {
		respondError(w, r, http.StatusForbidden, "FORBIDDEN", "You do not have access to this domain")
		return
	}

	domain, err := s.domains.GetByID(r.Context(), domainID)
	if err != nil {
		s.logger.Error("get domain failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get domain")
		return
	}
	if domain == nil {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "Domain not found")
		return
	}

	if domain.DKIMKeyPath == nil || *domain.DKIMKeyPath == "" {
		respondError(w, r, http.StatusNotFound, "DKIM_NOT_CONFIGURED",
			"DKIM keys have not been generated for this domain. Use POST /domains/:id/dkim/generate")
		return
	}

	pubDER, err := dkim.ReadPublicKey(*domain.DKIMKeyPath)
	if err != nil {
		s.logger.Error("read DKIM key failed", "error", err, "path", *domain.DKIMKeyPath)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to read DKIM key")
		return
	}

	dnsName := fmt.Sprintf("%s._domainkey.%s", domain.DKIMSelector, domain.Name)
	dnsValue := fmt.Sprintf("v=DKIM1; k=rsa; p=%s", base64.StdEncoding.EncodeToString(pubDER))

	respond(w, r, http.StatusOK, dkimResponse{
		DNSName:  dnsName,
		DNSValue: dnsValue,
		Selector: domain.DKIMSelector,
		KeyPath:  *domain.DKIMKeyPath,
	})
}

func (s *Server) handleRotateDKIM(w http.ResponseWriter, r *http.Request) {
	domainID := chi.URLParam(r, "domainID")

	domain, err := s.domains.GetByID(r.Context(), domainID)
	if err != nil {
		s.logger.Error("get domain failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get domain")
		return
	}
	if domain == nil {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "Domain not found")
		return
	}

	// New selector for rotation.
	newSelector := dkim.DefaultSelector() + "r"

	kp, err := dkim.GenerateKey(s.dkimBasePath, domain.Name, newSelector)
	if err != nil {
		s.logger.Error("rotate DKIM key failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to generate new DKIM key")
		return
	}

	keyPath := kp.KeyPath
	_, err = s.domains.Update(r.Context(), domainID, repository.DomainUpdate{
		DKIMSelector: &newSelector,
		DKIMKeyPath:  &keyPath,
	})
	if err != nil {
		s.logger.Error("update domain DKIM failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Key generated but failed to update domain record")
		return
	}

	adminID := getAdminID(r.Context())
	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "dkim.rotate", "domain", &domainID,
		map[string]string{"old_selector": domain.DKIMSelector, "new_selector": newSelector}, &ip)

	respond(w, r, http.StatusOK, dkimResponse{
		DNSName:  kp.DNSName(),
		DNSValue: kp.DNSRecord(),
		Selector: newSelector,
		KeyPath:  kp.KeyPath,
	})
}

func (s *Server) handleDeliverability(w http.ResponseWriter, r *http.Request) {
	domainID := chi.URLParam(r, "domainID")
	if !s.canAccessDomain(r.Context(), domainID) {
		respondError(w, r, http.StatusForbidden, "FORBIDDEN", "You do not have access to this domain")
		return
	}

	domain, err := s.domains.GetByID(r.Context(), domainID)
	if err != nil {
		s.logger.Error("get domain failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get domain")
		return
	}
	if domain == nil {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "Domain not found")
		return
	}

	var checks []deliverabilityCheck

	// MX record check. Docker's embedded DNS resolver (127.0.0.11) has
	// known flakiness forwarding MX queries — go straight to a public
	// resolver so deliverability results match what remote senders see.
	dnsCtx, dnsCancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer dnsCancel()
	mxRecords, err := publicDNSResolver.LookupMX(dnsCtx, domain.Name)
	if err != nil || len(mxRecords) == 0 {
		checks = append(checks, deliverabilityCheck{
			Name:   "MX",
			Status: "fail",
			Hint:   fmt.Sprintf("No MX record found for %s. Add: %s MX 10 %s", domain.Name, domain.Name, s.hostname),
		})
	} else {
		hosts := make([]string, 0, len(mxRecords))
		for _, mx := range mxRecords {
			hosts = append(hosts, strings.TrimSuffix(mx.Host, "."))
		}
		checks = append(checks, deliverabilityCheck{
			Name:   "MX",
			Status: "pass",
			Value:  strings.Join(hosts, ", "),
		})
	}

	// SPF record check — public resolver for consistency with MX above.
	txtRecords, _ := publicDNSResolver.LookupTXT(dnsCtx, domain.Name)
	spfFound := false
	for _, txt := range txtRecords {
		if strings.HasPrefix(txt, "v=spf1") {
			spfFound = true
			checks = append(checks, deliverabilityCheck{
				Name:   "SPF",
				Status: "pass",
				Value:  txt,
			})
			break
		}
	}
	if !spfFound {
		checks = append(checks, deliverabilityCheck{
			Name:   "SPF",
			Status: "fail",
			Hint:   fmt.Sprintf("No SPF record found. Add TXT: %s", dkim.SPFRecord("")),
		})
	}

	// DKIM record check
	if domain.DKIMKeyPath != nil && *domain.DKIMKeyPath != "" {
		dkimHost := fmt.Sprintf("%s._domainkey.%s", domain.DKIMSelector, domain.Name)
		dkimTxt, _ := publicDNSResolver.LookupTXT(dnsCtx, dkimHost)
		dkimFound := false
		for _, txt := range dkimTxt {
			if strings.Contains(txt, "v=DKIM1") {
				dkimFound = true
				checks = append(checks, deliverabilityCheck{
					Name:   "DKIM",
					Status: "pass",
					Value:  fmt.Sprintf("%s (selector: %s)", dkimHost, domain.DKIMSelector),
				})
				break
			}
		}
		if !dkimFound {
			checks = append(checks, deliverabilityCheck{
				Name:   "DKIM",
				Status: "fail",
				Hint:   fmt.Sprintf("No DKIM record at %s. Add the TXT record from GET /domains/%s/dkim", dkimHost, domainID),
			})
		}
	} else {
		checks = append(checks, deliverabilityCheck{
			Name:   "DKIM",
			Status: "warn",
			Hint:   "DKIM keys not generated. Use POST /domains/:id/dkim/generate",
		})
	}

	// DMARC record check
	dmarcTxt, _ := publicDNSResolver.LookupTXT(dnsCtx, "_dmarc."+domain.Name)
	dmarcFound := false
	for _, txt := range dmarcTxt {
		if strings.HasPrefix(txt, "v=DMARC1") {
			dmarcFound = true
			checks = append(checks, deliverabilityCheck{
				Name:   "DMARC",
				Status: "pass",
				Value:  txt,
			})
			break
		}
	}
	if !dmarcFound {
		checks = append(checks, deliverabilityCheck{
			Name:   "DMARC",
			Status: "fail",
			Hint:   fmt.Sprintf("No DMARC record. Add TXT at _dmarc.%s: %s", domain.Name, dkim.DMARCRecord(domain.Name)),
		})
	}

	// TXT verification auto-check: if domain is not yet verified, check if the
	// verification token is present in TXT records and auto-verify.
	if domain.VerificationStatus != "verified" && domain.VerificationToken != nil && *domain.VerificationToken != "" {
		verifyFound := false
		for _, txt := range txtRecords {
			if strings.TrimSpace(txt) == *domain.VerificationToken {
				verifyFound = true
				break
			}
		}
		if verifyFound {
			verified := "verified"
			s.domains.Update(r.Context(), domainID, repository.DomainUpdate{VerificationStatus: &verified})
			checks = append(checks, deliverabilityCheck{
				Name:   "Verification",
				Status: "pass",
				Value:  "Domain ownership verified via TXT record",
			})
		} else {
			checks = append(checks, deliverabilityCheck{
				Name:   "Verification",
				Status: "warn",
				Hint:   fmt.Sprintf("Domain not verified. Add TXT record: %s", *domain.VerificationToken),
			})
		}
	} else if domain.VerificationStatus == "verified" {
		checks = append(checks, deliverabilityCheck{
			Name:   "Verification",
			Status: "pass",
			Value:  "Domain ownership verified",
		})
	}

	// PTR record check (reverse DNS).
	// Resolve the hostname via a public resolver rather than Docker's
	// embedded DNS — otherwise `mail.vectismail.com` collides with the
	// postfix container's hostname inside the same network and we report
	// on a 172.x internal IP instead of the real public one.
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	addrs, _ := publicDNSResolver.LookupHost(ctx, s.hostname)
	publicAddr := firstPublicAddr(addrs)
	if publicAddr != "" {
		names, _ := publicDNSResolver.LookupAddr(ctx, publicAddr)
		if len(names) > 0 {
			checks = append(checks, deliverabilityCheck{
				Name:   "PTR",
				Status: "pass",
				Value:  fmt.Sprintf("%s → %s", publicAddr, strings.TrimSuffix(names[0], ".")),
			})
		} else {
			checks = append(checks, deliverabilityCheck{
				Name:   "PTR",
				Status: "warn",
				Hint:   fmt.Sprintf("No PTR record for %s. Ask your hosting provider to set it to %s", publicAddr, s.hostname),
			})
		}
	}

	respond(w, r, http.StatusOK, deliverabilityResponse{
		Domain: domain.Name,
		Checks: checks,
	})
}
