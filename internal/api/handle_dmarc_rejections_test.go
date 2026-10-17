package api

import (
	"encoding/json"
	"testing"
	"time"
)

func rejectMember(t *testing.T, rec dmarcRejectRecord) string {
	t.Helper()
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestGroupDMARCRejections(t *testing.T) {
	base := time.Date(2026, 10, 17, 3, 0, 0, 0, time.UTC).Unix()
	awp := func(dt int64, ip, host, spf string, rcpts ...string) dmarcRejectRecord {
		return dmarcRejectRecord{Time: base + dt, From: "notices@aussiewebpro.com", FromDomain: "aussiewebpro.com",
			EnvFromDomain: "aussiewebpro.com", IP: ip, Host: host, RcptDomains: rcpts, SPF: spf, DKIM: "none"}
	}
	members := []string{
		rejectMember(t, awp(0, "27.111.95.31", "mail-p4-fv.ipv4.au.ds.network", "R_SPF_FAIL", "afxgroup.com.au")),
		rejectMember(t, awp(60, "27.111.95.31", "mail-p4-fv.ipv4.au.ds.network", "R_SPF_FAIL", "AFXGROUP.com.au", "other.example")),
		rejectMember(t, awp(120, "27.111.95.32", "", "R_SPF_SOFTFAIL", "afxgroup.com.au")),
		// Forged PayPal: one message, a different sender group.
		rejectMember(t, dmarcRejectRecord{Time: base + 30, From: "service@paypal.com", FromDomain: "paypal.com",
			EnvFromDomain: "phish.example", IP: "203.0.113.7", RcptDomains: []string{"afxgroup.com.au"}, SPF: "R_SPF_NA", DKIM: "none"}),
		// Not addressed to this domain.
		rejectMember(t, awp(10, "27.111.95.31", "", "R_SPF_FAIL", "other.example")),
		// Malformed members are skipped.
		`not json`,
		`{"t":0,"from_domain":"x.example","rcpt_domains":["afxgroup.com.au"]}`,
		`{"t":5,"from_domain":"","rcpt_domains":["afxgroup.com.au"]}`,
	}

	senders, total := groupDMARCRejections(members, "afxgroup.com.au")
	if total != 4 {
		t.Fatalf("total = %d, want 4", total)
	}
	if len(senders) != 2 {
		t.Fatalf("got %d senders, want 2: %+v", len(senders), senders)
	}

	a := senders[0]
	if a.FromDomain != "aussiewebpro.com" || a.Count != 3 {
		t.Fatalf("first sender = %s ×%d, want aussiewebpro.com ×3", a.FromDomain, a.Count)
	}
	if !a.FirstSeen.Equal(time.Unix(base, 0).UTC()) || !a.LastSeen.Equal(time.Unix(base+120, 0).UTC()) {
		t.Errorf("first/last seen = %v / %v", a.FirstSeen, a.LastSeen)
	}
	if a.SPF != "R_SPF_SOFTFAIL" || a.ExampleFrom != "notices@aussiewebpro.com" {
		t.Errorf("latest SPF/example = %q / %q, want those of the newest message", a.SPF, a.ExampleFrom)
	}
	if len(a.Sources) != 2 || a.Sources[0].IP != "27.111.95.31" || a.Sources[0].Count != 2 ||
		a.Sources[0].Hostname != "mail-p4-fv.ipv4.au.ds.network" || a.Sources[1].IP != "27.111.95.32" || a.Sources[1].Hostname != "" {
		t.Errorf("sources = %+v", a.Sources)
	}

	p := senders[1]
	if p.FromDomain != "paypal.com" || p.Count != 1 || len(p.EnvFromDomains) != 1 || p.EnvFromDomains[0] != "phish.example" {
		t.Errorf("second sender = %+v", p)
	}

	if s, n := groupDMARCRejections(members, "nobody.example"); n != 0 || len(s) != 0 {
		t.Errorf("unrelated domain: got %d records, %d senders", n, len(s))
	}
	if s, n := groupDMARCRejections(nil, "afxgroup.com.au"); n != 0 || s == nil || len(s) != 0 {
		t.Errorf("empty log must give an empty, non-nil list: %v %d", s, n)
	}
}
