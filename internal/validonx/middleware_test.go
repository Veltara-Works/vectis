package validonx

import (
	"context"
	"testing"
)

func TestTierFromFeatures(t *testing.T) {
	tests := []struct {
		name     string
		features []string
		want     string
	}{
		{"empty", []string{}, TierFree},
		{"nil", nil, TierFree},
		{"basic_mail only", []string{FeatureBasicMail}, TierFree},
		{"unknown feature only", []string{"nonsense"}, TierFree},
		{"pro: custom_branding", []string{FeatureBasicMail, FeatureCustomBranding}, TierPro},
		{"pro: analytics", []string{FeatureBasicMail, FeatureAnalytics}, TierPro},
		{"pro: oidc_sso", []string{FeatureBasicMail, FeatureOIDCSSO}, TierPro},
		{"pro: advanced_spam", []string{FeatureBasicMail, FeatureAdvancedSpam}, TierPro},
		{"pro: priority_support", []string{FeatureBasicMail, FeaturePrioritySupport}, TierPro},
		{"pro: full set", ProFeatures, TierPro},
		{"enterprise: saml_sso", []string{FeatureSAMLSSO}, TierEnterprise},
		{"enterprise: dsar", []string{FeatureDSAR}, TierEnterprise},
		{"enterprise: sla", []string{FeatureSLA}, TierEnterprise},
		{"enterprise: full set", EnterpriseFeatures, TierEnterprise},
		{"enterprise wins over pro", []string{FeatureCustomBranding, FeatureSLA}, TierEnterprise},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tierFromFeatures(tt.features)
			if got != tt.want {
				t.Errorf("tierFromFeatures(%v) = %q, want %q", tt.features, got, tt.want)
			}
		})
	}
}

// TestResolveTierUnconfigured verifies the safe-default path: when ValidonX
// is not configured (free-tier mode), ResolveTier returns TierFree without
// touching the cache or making network calls.
func TestResolveTierUnconfigured(t *testing.T) {
	// NewFeatureGateService with nil client + nil db produces a service that
	// safely passes through; ResolveTier should short-circuit on
	// !client.Configured().
	gate := NewFeatureGateService(nil, nil, testLogger())

	tier, err := gate.ResolveTier(context.Background())
	if err != nil {
		t.Fatalf("ResolveTier on unconfigured gate returned error: %v", err)
	}
	if tier != TierFree {
		t.Errorf("ResolveTier on unconfigured gate = %q, want %q", tier, TierFree)
	}
}

// TestIsFreeTierFeature spot-checks the helper FeatureGate uses to
// short-circuit on always-allowed features.
func TestIsFreeTierFeature(t *testing.T) {
	if !featureInList(FreeTierFeatures, FeatureBasicMail) {
		t.Error("basic_mail should be a free-tier feature")
	}
	if featureInList(FreeTierFeatures, FeatureAnalytics) {
		t.Error("analytics must NOT be a free-tier feature (Pro-only)")
	}
	if featureInList(FreeTierFeatures, FeatureOIDCSSO) {
		t.Error("oidc_sso must NOT be a free-tier feature (Pro-only)")
	}
	if featureInList(FreeTierFeatures, FeatureSLA) {
		t.Error("sla must NOT be a free-tier feature (Enterprise-only)")
	}
}
