package api

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestUpdateDomainRequest_AbsentVsNull locks the PATCH semantics of the
// per-domain spam overrides: an absent key leaves the stored value alone, an
// explicit null clears it back to the config.yaml default, and only setting a
// value needs Pro.
func TestUpdateDomainRequest_AbsentVsNull(t *testing.T) {
	decode := func(body string) updateDomainRequest {
		t.Helper()
		var req updateDomainRequest
		if err := json.Unmarshal([]byte(body), &req); err != nil {
			t.Fatalf("decode %s: %v", body, err)
		}
		return req
	}

	absent := decode(`{"active":true}`)
	if absent.SpamThreshold.Set || absent.touchesAdvancedSpamFields() || absent.setsAdvancedSpamFields() {
		t.Errorf("absent spam fields must leave everything alone: %+v", absent)
	}

	cleared := decode(`{"spam_threshold":null,"reject_threshold":null,"greylist_enabled":null}`)
	if !cleared.SpamThreshold.clears() || !cleared.RejectThreshold.clears() || !cleared.GreylistEnabled.clears() {
		t.Errorf("explicit null must clear: %+v", cleared)
	}
	if !cleared.touchesAdvancedSpamFields() {
		t.Error("a clear must rewrite settings.conf")
	}
	if cleared.setsAdvancedSpamFields() {
		t.Error("clearing an override must not need Pro")
	}

	set := decode(`{"spam_threshold":6.5,"greylist_enabled":false}`)
	if set.SpamThreshold.Value == nil || *set.SpamThreshold.Value != 6.5 || set.SpamThreshold.clears() {
		t.Errorf("spam_threshold 6.5 not decoded: %+v", set.SpamThreshold)
	}
	if set.GreylistEnabled.Value == nil || *set.GreylistEnabled.Value {
		t.Errorf("greylist_enabled false must be a value, not a clear: %+v", set.GreylistEnabled)
	}
	if !set.setsAdvancedSpamFields() {
		t.Error("setting a value needs Pro")
	}

	if err := json.Unmarshal([]byte(`{"spam_threshold":"high"}`), new(updateDomainRequest)); err == nil {
		t.Error("a non-number spam_threshold must be a decode error")
	}

	// The audit log records the request: unsent fields are omitted, a clear is
	// null and a value is the value.
	b, err := json.Marshal(decode(`{"spam_threshold":null,"reject_threshold":12.5}`))
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	for _, want := range []string{`"spam_threshold":null`, `"reject_threshold":12.5`} {
		if !strings.Contains(got, want) {
			t.Errorf("audit JSON %s missing %s", got, want)
		}
	}
	if strings.Contains(got, "greylist_enabled") {
		t.Errorf("an unsent field must be omitted from the audit JSON: %s", got)
	}
}

// TestNormalizeStripHeaders (#231): the per-domain list reuses the host-wide
// validation, is de-duplicated case-insensitively, and an empty list clears.
func TestNormalizeStripHeaders(t *testing.T) {
	got, msg := normalizeStripHeaders([]string{"X-Mailer", "x-mailer", "User-Agent"})
	if msg != "" || len(got) != 2 || got[0] != "X-Mailer" || got[1] != "User-Agent" {
		t.Errorf("de-dup: got %v %q", got, msg)
	}
	if got, msg := normalizeStripHeaders([]string{}); msg != "" || got != nil {
		t.Errorf("empty list must clear (nil), got %v %q", got, msg)
	}
	for _, bad := range [][]string{{"Subject"}, {"Subject+"}, {"X Mailer"}, {""}, {"Received"}} {
		if _, msg := normalizeStripHeaders(bad); !strings.HasPrefix(msg, "strip_submission_headers[0]: ") {
			t.Errorf("%q must be refused with a field-named message, got %q", bad, msg)
		}
	}
	tooMany := make([]string, maxStripHeaders+1)
	for i := range tooMany {
		tooMany[i] = "X-H" + strings.Repeat("a", i+1)
	}
	if _, msg := normalizeStripHeaders(tooMany); msg == "" {
		t.Error("more than maxStripHeaders must be refused")
	}

	var req updateDomainRequest
	if err := json.Unmarshal([]byte(`{"strip_submission_headers":null}`), &req); err != nil || !req.StripSubmissionHeaders.clears() {
		t.Errorf("explicit null must clear: %+v %v", req.StripSubmissionHeaders, err)
	}
}

// TestNormalizeThreshold: values are rounded to the one decimal place the
// DECIMAL(4,1) column stores BEFORE the 0.1–999.9 range check, so what passes
// validation is exactly what gets stored (Copilot review on #246).
func TestNormalizeThreshold(t *testing.T) {
	f := func(v float64) *float64 { return &v }
	if got, ok := normalizeThreshold(nil); !ok || got != nil {
		t.Errorf("nil must stay nil and be valid, got %v %v", got, ok)
	}
	for in, want := range map[float64]float64{6: 6, 0.1: 0.1, 6.26: 6.3, 0.06: 0.1, 999.9: 999.9, 999.94: 999.9} {
		got, ok := normalizeThreshold(f(in))
		if !ok || got == nil || *got != want {
			t.Errorf("normalizeThreshold(%v) = %v %v, want %v", in, got, ok, want)
		}
	}
	// 0.01 would be stored as 0.0 (every message hits the action); 999.96
	// rounds to 1000.0, which overflows the column.
	for _, bad := range []float64{0, 0.01, 0.04, -1, 999.96, 999.99, 1000} {
		if _, ok := normalizeThreshold(f(bad)); ok {
			t.Errorf("normalizeThreshold(%v) must be refused", bad)
		}
	}
}
