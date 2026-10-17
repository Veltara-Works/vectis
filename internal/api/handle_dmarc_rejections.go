package api

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
)

// dmarcRejectsKey is the Valkey sorted set rspamd's VECTIS_DMARC_REJECT_LOG
// rule writes (rspamd.local.lua.tmpl): one JSON member per rejected message,
// scored by Unix time, trimmed to 30 days and 5000 entries.
const dmarcRejectsKey = "vectis_dmarc_rejects"

const (
	dmarcRejectsDefaultDays = 7
	dmarcRejectsMaxDays     = 30
)

// dmarcRejectRecord is one member of the sorted set, as rspamd writes it.
type dmarcRejectRecord struct {
	Time          int64    `json:"t"`
	ID            string   `json:"id"`
	From          string   `json:"from"`
	FromDomain    string   `json:"from_domain"`
	EnvFromDomain string   `json:"env_from_domain"`
	IP            string   `json:"ip"`
	Host          string   `json:"host"`
	RcptDomains   []string `json:"rcpt_domains"`
	SPF           string   `json:"spf"`
	DKIM          string   `json:"dkim"`
}

// dmarcRejectSource is one sending network within a sender group.
type dmarcRejectSource struct {
	IP       string    `json:"ip"`
	Hostname string    `json:"hostname,omitempty"`
	Count    int       `json:"count"`
	LastSeen time.Time `json:"last_seen"`
}

// dmarcRejectSender groups the rejections of one header-From domain.
type dmarcRejectSender struct {
	FromDomain     string              `json:"from_domain"`
	Count          int                 `json:"count"`
	FirstSeen      time.Time           `json:"first_seen"`
	LastSeen       time.Time           `json:"last_seen"`
	ExampleFrom    string              `json:"example_from"`
	EnvFromDomains []string            `json:"envelope_from_domains"`
	SPF            string              `json:"spf"`
	DKIM           string              `json:"dkim"`
	Sources        []dmarcRejectSource `json:"sources"`
}

type dmarcRejectionsResponse struct {
	Domain  string              `json:"domain"`
	Days    int                 `json:"days"`
	Total   int                 `json:"total"`
	Senders []dmarcRejectSender `json:"senders"`
}

// groupDMARCRejections keeps the records addressed to rcptDomain and groups
// them by header-From domain, then by sending IP. Senders are ordered by count
// (most rejected first), sources likewise. SPF/DKIM are those of the most
// recent message. Malformed records are skipped.
func groupDMARCRejections(members []string, rcptDomain string) ([]dmarcRejectSender, int) {
	rcptDomain = strings.ToLower(rcptDomain)
	type acc struct {
		sender  dmarcRejectSender
		envFrom map[string]bool
		sources map[string]*dmarcRejectSource
	}
	groups := map[string]*acc{}
	total := 0
	for _, m := range members {
		var rec dmarcRejectRecord
		if err := json.Unmarshal([]byte(m), &rec); err != nil || rec.FromDomain == "" || rec.Time <= 0 {
			continue
		}
		addressed := false
		for _, d := range rec.RcptDomains {
			if strings.ToLower(d) == rcptDomain {
				addressed = true
				break
			}
		}
		if !addressed {
			continue
		}
		total++
		at := time.Unix(rec.Time, 0).UTC()
		g := groups[rec.FromDomain]
		if g == nil {
			g = &acc{
				sender:  dmarcRejectSender{FromDomain: rec.FromDomain, FirstSeen: at, LastSeen: at},
				envFrom: map[string]bool{},
				sources: map[string]*dmarcRejectSource{},
			}
			groups[rec.FromDomain] = g
		}
		g.sender.Count++
		if at.Before(g.sender.FirstSeen) {
			g.sender.FirstSeen = at
		}
		if !at.Before(g.sender.LastSeen) {
			g.sender.LastSeen = at
			g.sender.ExampleFrom = rec.From
			g.sender.SPF = rec.SPF
			g.sender.DKIM = rec.DKIM
		}
		if rec.EnvFromDomain != "" {
			g.envFrom[rec.EnvFromDomain] = true
		}
		src := g.sources[rec.IP]
		if src == nil {
			src = &dmarcRejectSource{IP: rec.IP}
			g.sources[rec.IP] = src
		}
		src.Count++
		if !at.Before(src.LastSeen) {
			src.LastSeen = at
			if rec.Host != "" {
				src.Hostname = rec.Host
			}
		}
	}

	senders := make([]dmarcRejectSender, 0, len(groups))
	for _, g := range groups {
		s := g.sender
		s.EnvFromDomains = make([]string, 0, len(g.envFrom))
		for d := range g.envFrom {
			s.EnvFromDomains = append(s.EnvFromDomains, d)
		}
		sort.Strings(s.EnvFromDomains)
		s.Sources = make([]dmarcRejectSource, 0, len(g.sources))
		for _, src := range g.sources {
			s.Sources = append(s.Sources, *src)
		}
		sort.Slice(s.Sources, func(i, j int) bool {
			if s.Sources[i].Count != s.Sources[j].Count {
				return s.Sources[i].Count > s.Sources[j].Count
			}
			return s.Sources[i].IP < s.Sources[j].IP
		})
		senders = append(senders, s)
	}
	sort.Slice(senders, func(i, j int) bool {
		if senders[i].Count != senders[j].Count {
			return senders[i].Count > senders[j].Count
		}
		return senders[i].FromDomain < senders[j].FromDomain
	})
	return senders, total
}

// handleDMARCRejections lists mail addressed to this domain that DMARC
// enforcement rejected in the last N days (default 7, max 30), grouped by
// sender, so an operator can spot a legitimate sender with broken DNS and add a
// DMARC exception for it. Not licence-gated: seeing lost mail matters on every
// tier (adding an exception is the Pro part).
//
// GET /api/v1/domains/{domainID}/dmarc-rejections?days=7
func (s *Server) handleDMARCRejections(w http.ResponseWriter, r *http.Request) {
	days := dmarcRejectsDefaultDays
	if v := strings.TrimSpace(r.URL.Query().Get("days")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > dmarcRejectsMaxDays {
			respondError(w, r, http.StatusBadRequest, "INVALID_DAYS", "days must be a whole number from 1 to 30")
			return
		}
		days = n
	}

	domainID := chi.URLParam(r, "domainID")
	domain, err := s.domains.GetByID(r.Context(), domainID)
	if err != nil {
		s.logger.Error("get domain failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load domain")
		return
	}
	if domain == nil {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "Domain not found")
		return
	}
	if s.vk == nil {
		respondError(w, r, http.StatusServiceUnavailable, "VALKEY_UNAVAILABLE", "The rejection log is unavailable")
		return
	}

	since := time.Now().Add(-time.Duration(days) * 24 * time.Hour).Unix()
	cmd := s.vk.B().Zrangebyscore().Key(dmarcRejectsKey).Min(strconv.FormatInt(since, 10)).Max("+inf").Build()
	members, err := s.vk.Do(r.Context(), cmd).AsStrSlice()
	if err != nil {
		s.logger.Error("read DMARC rejection log failed", "error", err)
		respondError(w, r, http.StatusServiceUnavailable, "VALKEY_UNAVAILABLE", "The rejection log is unavailable")
		return
	}

	senders, total := groupDMARCRejections(members, domain.Name)
	respond(w, r, http.StatusOK, dmarcRejectionsResponse{
		Domain:  domain.Name,
		Days:    days,
		Total:   total,
		Senders: senders,
	})
}
