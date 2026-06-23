package validonx

import "testing"

// TestSCIMIsEnterpriseOnly locks SCIM 2.0 provisioning to the Enterprise tier,
// paired with saml_sso. SCIM grants full mailbox provisioning authority, so it
// must never leak into Pro or Free. A future edit that drops scim into a lower
// tier must fail here. Mirrors TestSAMLSSOIsEnterpriseOnly.
func TestSCIMIsEnterpriseOnly(t *testing.T) {
	if samlSliceHas(ProFeatures, FeatureSCIM) {
		t.Error("scim must NOT be a Pro feature — SCIM provisioning is Enterprise-only")
	}
	if samlSliceHas(FreeTierFeatures, FeatureSCIM) {
		t.Error("scim must NOT be a free-tier feature")
	}
	if !samlSliceHas(EnterpriseFeatures, FeatureSCIM) {
		t.Error("scim must be an Enterprise feature")
	}
	if got := tierFromFeatures([]string{FeatureSCIM}); got != TierEnterprise {
		t.Errorf("tierFromFeatures([scim]) = %q, want %q", got, TierEnterprise)
	}
}
