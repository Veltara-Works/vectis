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

// TestOfflineEnterpriseTierGrantsSCIM locks the offline-path tier→feature
// mapping: a verifier-resolved "Enterprise" tier (what VMPolicy now emits for a
// real tier:"enterprise" token) maps to a feature set that includes scim (plus
// the other Enterprise features), so an offline Enterprise license opens the
// SCIM gate. Pro must not. Pairs with the real-envelope regression vector
// license.TestRealValidonXEnterpriseToken.
func TestOfflineEnterpriseTierGrantsSCIM(t *testing.T) {
	ent := featuresForTier("Enterprise")
	for _, f := range []string{FeatureSCIM, FeatureSAMLSSO, FeatureDSAR} {
		if !samlSliceHas(ent, f) {
			t.Errorf("featuresForTier(Enterprise) must include %q", f)
		}
	}
	if samlSliceHas(featuresForTier("Pro"), FeatureSCIM) {
		t.Error("featuresForTier(Pro) must NOT include scim")
	}
}
