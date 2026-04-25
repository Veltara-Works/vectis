package validonx

import (
	"io"
	"log/slog"
	"testing"
	"time"
)

// testLogger returns a slog.Logger that discards output, suitable for tests.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestCachedLicenseIsExpired(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name      string
		expiresAt time.Time
		want      bool
	}{
		{"expired by 1 second", now.Add(-1 * time.Second), true},
		{"expired by full grace period", now.Add(-GracePeriod), true},
		{"valid for 1 second more", now.Add(1 * time.Second), false},
		{"valid for full grace period", now.Add(GracePeriod), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cl := &CachedLicense{ExpiresAt: tt.expiresAt}
			got := cl.IsExpired()
			if got != tt.want {
				t.Errorf("IsExpired() with ExpiresAt %v = %v, want %v",
					tt.expiresAt, got, tt.want)
			}
		})
	}
}

func TestCachedLicenseHasFeature(t *testing.T) {
	cl := &CachedLicense{
		Features: []string{FeatureBasicMail, FeatureAnalytics},
		LicenseData: LicenseResponse{
			AllowedFeatures: []string{FeatureCustomBranding},
		},
	}

	cases := []struct {
		feature string
		want    bool
	}{
		{FeatureBasicMail, true},     // in Features
		{FeatureAnalytics, true},     // in Features
		{FeatureCustomBranding, true}, // in LicenseData.AllowedFeatures (alt list)
		{FeatureMultiTenant, false},  // not in either
		{"unknown_feature", false},
	}

	for _, c := range cases {
		t.Run(c.feature, func(t *testing.T) {
			got := cl.HasFeature(c.feature)
			if got != c.want {
				t.Errorf("HasFeature(%q) = %v, want %v", c.feature, got, c.want)
			}
		})
	}
}

// TestGracePeriodConstant guards against accidental change to the user-facing
// "30-day offline grace period" promise on the pricing page.
func TestGracePeriodConstant(t *testing.T) {
	want := 30 * 24 * time.Hour
	if GracePeriod != want {
		t.Errorf("GracePeriod = %v, want %v (advertised on pricing page)", GracePeriod, want)
	}
}
