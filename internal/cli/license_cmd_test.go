package cli

import (
	"testing"

	"github.com/Veltara-Works/vectis/internal/license"
)

// TestLicenseExitCode locks the operator exit-code contract for `vectis license
// verify`: a live/in-grace ACCEPT entitles (0); a REJECT or a past-grace
// (downgraded) ACCEPT does not (1). Exit 2 is an operator/config error handled
// before a verdict exists and is not exercised here.
func TestLicenseExitCode(t *testing.T) {
	tests := []struct {
		name         string
		verdict      license.Verdict
		wantEntitled bool
		wantCode     int
	}{
		{
			name:         "live accept entitles",
			verdict:      license.Verdict{Accepted: true, GraceState: license.GraceLive, InternalTier: "Pro"},
			wantEntitled: true,
			wantCode:     exitLicenseOK,
		},
		{
			name:         "in-grace accept entitles",
			verdict:      license.Verdict{Accepted: true, GraceState: license.GraceInGrace, InternalTier: "Pro"},
			wantEntitled: true,
			wantCode:     exitLicenseOK,
		},
		{
			name:         "past-grace accept does not entitle",
			verdict:      license.Verdict{Accepted: true, GraceState: license.GracePastGrace, InternalTier: "Free"},
			wantEntitled: false,
			wantCode:     exitLicenseInvalid,
		},
		{
			name:         "reject does not entitle",
			verdict:      license.Verdict{Accepted: false, Reason: "bad signature"},
			wantEntitled: false,
			wantCode:     exitLicenseInvalid,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotEntitled, gotCode := licenseExitCode(tt.verdict)
			if gotEntitled != tt.wantEntitled || gotCode != tt.wantCode {
				t.Errorf("licenseExitCode(%+v) = (%v, %d), want (%v, %d)",
					tt.verdict, gotEntitled, gotCode, tt.wantEntitled, tt.wantCode)
			}
		})
	}
}
