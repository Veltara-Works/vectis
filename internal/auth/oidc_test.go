package auth

import "testing"

// TestEmailClaimVerified locks the security-relevant decision that an absent
// email_verified claim is treated as unverified. The OIDC callback uses this to
// decide whether an asserted email may auto-link to an existing admin; trusting
// an unverified (or absent) claim would allow admin account takeover via IdPs
// that emit attacker-controlled emails.
func TestEmailClaimVerified(t *testing.T) {
	tru := true
	fals := false
	cases := []struct {
		name  string
		claim *bool
		want  bool
	}{
		{"absent claim is unverified", nil, false},
		{"explicit false is unverified", &fals, false},
		{"explicit true is verified", &tru, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := emailClaimVerified(tc.claim); got != tc.want {
				t.Fatalf("emailClaimVerified(%v) = %v, want %v", tc.claim, got, tc.want)
			}
		})
	}
}
