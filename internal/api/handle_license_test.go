package api

import (
	"testing"

	"github.com/Veltara-Works/vectis/internal/validonx"
)

// TestTierFromCachedFeatures locks the api-side tier mirror to the same
// classification as validonx.tierFromFeatures. The mirror previously drifted
// (it omitted saml_sso + dsar from the Enterprise set), so every Enterprise
// feature is exercised here to prevent that regression recurring.
func TestTierFromCachedFeatures(t *testing.T) {
	tests := []struct {
		name     string
		features []string
		want     string
	}{
		{"empty", nil, validonx.TierFree},
		{"basic only", []string{validonx.FeatureBasicMail}, validonx.TierFree},
		{"unknown only", []string{"nonsense"}, validonx.TierFree},
		{"pro: custom_branding", []string{validonx.FeatureCustomBranding}, validonx.TierPro},
		{"pro: oidc_sso", []string{validonx.FeatureOIDCSSO}, validonx.TierPro},
		{"enterprise: saml_sso", []string{validonx.FeatureSAMLSSO}, validonx.TierEnterprise},
		{"enterprise: dsar", []string{validonx.FeatureDSAR}, validonx.TierEnterprise},
		{"enterprise: sla", []string{validonx.FeatureSLA}, validonx.TierEnterprise},
		{"enterprise: scim", []string{validonx.FeatureSCIM}, validonx.TierEnterprise}, // #126 regression
		{"enterprise wins over pro", []string{validonx.FeatureCustomBranding, validonx.FeatureDSAR}, validonx.TierEnterprise},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tierFromCachedFeatures(tt.features); got != tt.want {
				t.Errorf("tierFromCachedFeatures(%v) = %q, want %q", tt.features, got, tt.want)
			}
		})
	}
}

// TestTierFromCachedFeaturesNoDrift derives its cases from the exported
// validonx feature lists rather than a hand-written enum, so a feature added to
// EnterpriseFeatures/ProFeatures but forgotten in the api-side mirror fails the
// build. This is the guard the hand-enumerated test above lacked when it missed
// FeatureSCIM (#126): every Enterprise-exclusive feature must classify as
// Enterprise, and every Pro-exclusive feature as Pro, on its own.
func TestTierFromCachedFeaturesNoDrift(t *testing.T) {
	inList := func(list []string, f string) bool {
		for _, v := range list {
			if v == f {
				return true
			}
		}
		return false
	}

	// Enterprise-exclusive = in EnterpriseFeatures, not in ProFeatures.
	for _, f := range validonx.EnterpriseFeatures {
		if inList(validonx.ProFeatures, f) {
			continue
		}
		t.Run("enterprise/"+f, func(t *testing.T) {
			if got := tierFromCachedFeatures([]string{f}); got != validonx.TierEnterprise {
				t.Errorf("tierFromCachedFeatures([%q]) = %q, want %q — mirror drifted from EnterpriseFeatures", f, got, validonx.TierEnterprise)
			}
		})
	}

	// Pro-exclusive = in ProFeatures, not in FreeTierFeatures.
	for _, f := range validonx.ProFeatures {
		if inList(validonx.FreeTierFeatures, f) {
			continue
		}
		t.Run("pro/"+f, func(t *testing.T) {
			if got := tierFromCachedFeatures([]string{f}); got != validonx.TierPro {
				t.Errorf("tierFromCachedFeatures([%q]) = %q, want %q — mirror drifted from ProFeatures", f, got, validonx.TierPro)
			}
		})
	}
}
