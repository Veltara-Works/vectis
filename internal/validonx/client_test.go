package validonx

import (
	"encoding/json"
	"testing"
	"time"
)

// TestResolveLicenseEnvelope_RealValidonXShape feeds the decoder the
// byte-for-byte shape ValidonX returns from
// POST /api/v1/integration/licensing/resolve, captured from the live
// integration walkthrough on 2026-04-27 (PR #14 merge).
//
// The literal below is intentionally written as JSON-on-the-wire (not
// constructed from a struct) — same lesson as the rc59 path-1 envelope
// regression. A test that round-trips our own struct can't catch real
// shape drift; one that decodes a real captured response can.
//
// What this pins:
//   - Envelope wrapper {data, meta} unwraps cleanly into LicenseResponse.
//   - data.valid → bool.
//   - data.status → string matching one of the 6 enum values.
//   - data.allowed_features → []string.
//   - data.grace_period_ends_at → nullable; null decodes to nil pointer.
//   - data.expires_at → nullable; populated decodes to non-nil pointer.
//   - data.license.{id,key,type} → silently dropped (we don't model it).
//   - meta.request_id + meta.api_version → present (used for logging).
func TestResolveLicenseEnvelope_RealValidonXShape(t *testing.T) {
	// The exact body captured from a vectis-beta-test resolve call.
	// If ValidonX changes the shape, this test fails first — which is
	// the point. Update both this string AND the struct definitions in
	// lockstep, never one without the other.
	wire := []byte(`{
		"data": {
			"valid": true,
			"status": "active",
			"allowed_features": [
				"basic_mail",
				"analytics",
				"oidc_sso",
				"custom_branding",
				"advanced_spam",
				"priority_support"
			],
			"grace_period_ends_at": null,
			"expires_at": "2027-04-26T00:00:00+00:00",
			"license": {
				"id": "01HXYZ00000000000000000001",
				"key": "VLDX-VECTIS-PRO-TEST-001",
				"type": "subscription"
			}
		},
		"meta": {
			"request_id": "01984f81-9ec6-7d8a-9a0a-c4c2dafc8b3a",
			"api_version": "1"
		}
	}`)

	var env licensingResolveEnvelope
	if err := json.Unmarshal(wire, &env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}

	// data.valid
	if !env.Data.Valid {
		t.Errorf("data.valid: want true, got false")
	}

	// data.status — must be one of the six values our enum admits.
	switch SubscriptionStatus(env.Data.Status) {
	case StatusActive, StatusTrialing, StatusPastDue, StatusPaused, StatusCanceled, StatusExpired:
		// ok
	default:
		t.Errorf("data.status %q is not in the documented enum set", env.Data.Status)
	}

	// data.allowed_features — six features for vectis-beta-test.
	if got := len(env.Data.AllowedFeatures); got != 6 {
		t.Errorf("allowed_features length: want 6, got %d", got)
	}

	// data.grace_period_ends_at → nil for active customer.
	if env.Data.GracePeriodEndsAt != nil {
		t.Errorf("grace_period_ends_at: want nil for active customer, got %v", env.Data.GracePeriodEndsAt)
	}

	// data.expires_at → populated, parseable as RFC3339.
	if env.Data.ExpiresAt == nil {
		t.Fatalf("expires_at: want non-nil for subscription license, got nil")
	}
	if env.Data.ExpiresAt.IsZero() {
		t.Errorf("expires_at: want parseable timestamp, got zero time")
	}
	wantYear := 2027
	if env.Data.ExpiresAt.Year() != wantYear {
		t.Errorf("expires_at year: want %d, got %d", wantYear, env.Data.ExpiresAt.Year())
	}

	// meta — present, populated.
	if env.Meta.APIVersion != "1" {
		t.Errorf("meta.api_version: want %q, got %q", "1", env.Meta.APIVersion)
	}
	if env.Meta.RequestID == "" {
		t.Errorf("meta.request_id should be populated")
	}
}

// TestResolveLicenseEnvelope_GracePeriodPopulated covers the canceled-with-
// grace branch where grace_period_ends_at is set. The middleware's
// offline-tolerance logic depends on this decoding to a non-nil *time.Time.
func TestResolveLicenseEnvelope_GracePeriodPopulated(t *testing.T) {
	wire := []byte(`{
		"data": {
			"valid": true,
			"status": "canceled",
			"allowed_features": ["basic_mail", "analytics"],
			"grace_period_ends_at": "2026-05-15T00:00:00+00:00",
			"expires_at": "2026-05-15T00:00:00+00:00"
		},
		"meta": {"request_id": "test", "api_version": "1"}
	}`)

	var env licensingResolveEnvelope
	if err := json.Unmarshal(wire, &env); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if env.Data.GracePeriodEndsAt == nil {
		t.Fatalf("grace_period_ends_at should decode to non-nil pointer when populated")
	}
	want := time.Date(2026, 5, 15, 0, 0, 0, 0, time.UTC)
	if !env.Data.GracePeriodEndsAt.Equal(want) {
		t.Errorf("grace_period_ends_at: want %v, got %v", want, *env.Data.GracePeriodEndsAt)
	}
	if SubscriptionStatus(env.Data.Status) != StatusCanceled {
		t.Errorf("status: want canceled, got %q", env.Data.Status)
	}
	// Even canceled-in-grace customers are valid:true until their grace
	// window elapses — that's the whole point of grace_period_ends_at.
	if !env.Data.Valid {
		t.Errorf("data.valid: a canceled-in-grace customer must still be valid until grace_period_ends_at; got false")
	}
}

// TestSubscriptionStatusEnum_PathTwoSet pins the path-2 enum membership
// against ADR-041. The set is exactly the values ValidonX emits in
// data.status; suspended (HTTP 403) and revoked (HTTP 404) are NOT enum
// members.
func TestSubscriptionStatusEnum_PathTwoSet(t *testing.T) {
	want := map[SubscriptionStatus]bool{
		StatusActive:   true,
		StatusTrialing: true,
		StatusPastDue:  true,
		StatusPaused:   true,
		StatusCanceled: true,
		StatusExpired:  true,
	}

	// IsUsable contract: active, trialing, past_due → true. Others → false.
	for s := range want {
		got := s.IsUsable()
		switch s {
		case StatusActive, StatusTrialing, StatusPastDue:
			if !got {
				t.Errorf("IsUsable(%q): want true, got false", s)
			}
		default:
			if got {
				t.Errorf("IsUsable(%q): want false, got true", s)
			}
		}
	}

	// Defensive: reject the path-1-era status that is no longer emitted.
	// This guards against an accidental re-introduction of a constant
	// for "scheduled_for_cancellation" without ADR sign-off.
	bogus := SubscriptionStatus("scheduled_for_cancellation")
	if bogus.IsUsable() {
		t.Errorf("scheduled_for_cancellation must not be considered usable post-path-2")
	}
}
