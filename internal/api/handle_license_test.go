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
		{"enterprise: deliverability", []string{validonx.FeatureDeliverability}, validonx.TierEnterprise},
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
