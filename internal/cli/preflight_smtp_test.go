package cli

import (
	"errors"
	"net"
	"strings"
	"syscall"
	"testing"
)

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestOutboundSMTPFailure(t *testing.T) {
	cases := []struct {
		name      string
		err       error
		wantValue string
		wantIn    []string
		wantNot   []string
	}{
		{
			name:      "DNS failure is not a port 25 verdict",
			err:       &net.OpError{Op: "dial", Net: "tcp", Err: &net.DNSError{Err: "no such host", Name: smtpProbeHost}},
			wantValue: "not checked",
			wantIn:    []string{"check this server's DNS"},
			wantNot:   []string{port25GuideURL},
		},
		{
			name:      "timeout points to the guide",
			err:       &net.OpError{Op: "dial", Net: "tcp", Err: timeoutErr{}},
			wantValue: "port 25 blocked",
			wantIn:    []string{"Connection timed out.", port25GuideURL, "firewall"},
		},
		{
			name:      "refused shows the reason",
			err:       &net.OpError{Op: "dial", Net: "tcp", Err: &net.OpError{Op: "connect", Err: syscall.ECONNREFUSED}},
			wantValue: "port 25 blocked",
			wantIn:    []string{"Connection refused.", port25GuideURL},
		},
		{
			name:      "plain error falls back to its text",
			err:       errors.New("network is unreachable"),
			wantValue: "port 25 blocked",
			wantIn:    []string{"Network is unreachable.", port25GuideURL},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := outboundSMTPFailure(c.err)
			if got.Status != "warn" || got.Value != c.wantValue {
				t.Errorf("status/value = %s/%q, want warn/%q", got.Status, got.Value, c.wantValue)
			}
			for _, w := range c.wantIn {
				if !strings.Contains(got.Message, w) {
					t.Errorf("message %q missing %q", got.Message, w)
				}
			}
			for _, w := range c.wantNot {
				if strings.Contains(got.Message, w) {
					t.Errorf("message %q should not contain %q", got.Message, w)
				}
			}
		})
	}
}
