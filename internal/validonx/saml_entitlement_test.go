package validonx

import "testing"

func samlSliceHas(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// TestSAMLSSOIsEnterpriseOnly locks the tier placement decided in the canonical
// pricing strategy: OIDC stays Pro, SAML is the Enterprise line ("SSO-tax
// avoidance"). A future edit that drops saml_sso into Pro must fail here.
func TestSAMLSSOIsEnterpriseOnly(t *testing.T) {
	if samlSliceHas(ProFeatures, FeatureSAMLSSO) {
		t.Error("saml_sso must NOT be a Pro feature — OIDC is the Pro SSO; SAML is Enterprise-only")
	}
	if samlSliceHas(FreeTierFeatures, FeatureSAMLSSO) {
		t.Error("saml_sso must NOT be a free-tier feature")
	}
	if !samlSliceHas(EnterpriseFeatures, FeatureSAMLSSO) {
		t.Error("saml_sso must be an Enterprise feature")
	}
	if got := tierFromFeatures([]string{FeatureSAMLSSO}); got != TierEnterprise {
		t.Errorf("tierFromFeatures([saml_sso]) = %q, want %q", got, TierEnterprise)
	}
}
