package validonx

import "testing"

// TestEnterpriseFeatureWireContract locks the exact feature strings ValidonX
// must emit per tier. This is the cross-system contract handed to the ValidonX
// side: the Enterprise SKU's /api/v1/integration/licensing/resolve response
// must return these strings, or the FeatureGate will not open Enterprise
// endpoints for a paying customer. Changing any constant value here is a
// breaking change that must be coordinated with ValidonX.
func TestEnterpriseFeatureWireContract(t *testing.T) {
	wire := []struct{ name, constant, want string }{
		{"FeatureBasicMail", FeatureBasicMail, "basic_mail"},
		{"FeatureAnalytics", FeatureAnalytics, "analytics"},
		{"FeatureOIDCSSO", FeatureOIDCSSO, "oidc_sso"},
		{"FeatureCustomBranding", FeatureCustomBranding, "custom_branding"},
		{"FeatureAdvancedSpam", FeatureAdvancedSpam, "advanced_spam"},
		{"FeaturePrioritySupport", FeaturePrioritySupport, "priority_support"},
		{"FeatureSAMLSSO", FeatureSAMLSSO, "saml_sso"},
		{"FeatureDeliverability", FeatureDeliverability, "advanced_deliverability"},
		{"FeatureSLA", FeatureSLA, "sla"},
		{"FeatureDSAR", FeatureDSAR, "dsar"},
	}
	for _, w := range wire {
		if w.constant != w.want {
			t.Errorf("%s = %q, want %q (ValidonX wire contract — coordinate before changing)", w.name, w.constant, w.want)
		}
	}

	// The Enterprise entitlement set must advertise every Enterprise-only
	// feature, so a resolved Enterprise license classifies as Enterprise and
	// the gates open.
	for _, f := range []string{FeatureSAMLSSO, FeatureDeliverability, FeatureSLA, FeatureDSAR} {
		found := false
		for _, e := range EnterpriseFeatures {
			if e == f {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("EnterpriseFeatures missing Enterprise feature %q", f)
		}
	}
}
