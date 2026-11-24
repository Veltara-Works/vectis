package updatecheck

import (
	"testing"

	"github.com/Veltara-Works/vectis/internal/config"
)

func bp(b bool) *bool { return &b }

func TestEffective(t *testing.T) {
	on, off := bp(true), bp(false)
	cases := []struct {
		name   string
		file   config.UpdatesConfig
		stored *Stored
		want   Settings
	}{
		{"defaults: nothing set, nothing saved", config.UpdatesConfig{}, nil,
			Settings{CheckEnabled: true, EmailEnabled: true, Switchable: true}},
		{"dashboard turned the check off", config.UpdatesConfig{}, &Stored{CheckEnabled: false, EmailEnabled: true},
			Settings{CheckEnabled: false, EmailEnabled: false, Switchable: true}},
		{"dashboard turned only email off", config.UpdatesConfig{}, &Stored{CheckEnabled: true, EmailEnabled: false},
			Settings{CheckEnabled: true, EmailEnabled: false, Switchable: true}},
		{"config.yaml check: false locks both off, whatever was saved", config.UpdatesConfig{Check: off}, &Stored{CheckEnabled: true, EmailEnabled: true},
			Settings{CheckLocked: true, EmailLocked: true, Switchable: true}},
		{"config.yaml email: false locks email only", config.UpdatesConfig{Email: off}, &Stored{CheckEnabled: true, EmailEnabled: true},
			Settings{CheckEnabled: true, EmailLocked: true, Switchable: true}},
		{"config.yaml explicit true is just the default: dashboard can still turn it off", config.UpdatesConfig{Check: on, Email: on}, &Stored{CheckEnabled: false, EmailEnabled: false},
			Settings{Switchable: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Effective(tc.file, tc.stored, true); got != tc.want {
				t.Errorf("Effective = %+v, want %+v", got, tc.want)
			}
		})
	}
	// Table missing (pre-migration): config.yaml alone, switches not offered.
	if got := Effective(config.UpdatesConfig{}, nil, false); got != (Settings{CheckEnabled: true, EmailEnabled: true}) {
		t.Errorf("no table = %+v", got)
	}
}

func TestFailClosed(t *testing.T) {
	if FailClosed.CheckEnabled || FailClosed.EmailEnabled || FailClosed.Switchable || !FailClosed.ReadFailed {
		t.Fatalf("FailClosed must turn everything off and flag the read failure: %+v", FailClosed)
	}
}
