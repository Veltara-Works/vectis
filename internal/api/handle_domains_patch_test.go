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

func TestValidSpamThreshold(t *testing.T) {
	f := func(v float64) *float64 { return &v }
	for _, ok := range []*float64{nil, f(0.1), f(6), f(999.9)} {
		if !validSpamThreshold(ok) {
			t.Errorf("%v should be valid", ok)
		}
	}
	for _, bad := range []*float64{f(0), f(-1), f(1000)} {
		if validSpamThreshold(bad) {
			t.Errorf("%v must be refused", *bad)
		}
	}
}
