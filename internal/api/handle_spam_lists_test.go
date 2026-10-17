package api

import "testing"

func TestNormalizeExceptionNetwork(t *testing.T) {
	tests := []struct {
		in, want, code string
	}{
		{"27.111.95.31", "27.111.95.31", ""},
		{" 27.111.95.31 ", "27.111.95.31", ""},
		{"198.51.100.77/24", "198.51.100.0/24", ""}, // stored masked
		{"198.51.100.0/23", "", "NETWORK_TOO_BROAD"},
		{"0.0.0.0/0", "", "NETWORK_TOO_BROAD"},
		{"2001:DB8::25", "2001:db8::25", ""},
		{"2001:db8:1::/48", "2001:db8:1::/48", ""},
		{"2001:db8::/32", "", "NETWORK_TOO_BROAD"},
		{"::ffff:27.111.95.31", "27.111.95.31", ""},
		{"Mail-P4-FV.ipv4.au.ds.network", "mail-p4-fv.ipv4.au.ds.network", ""},
		{".ipv4.au.ds.network", ".ipv4.au.ds.network", ""},
		{".network", "", "NETWORK_TOO_BROAD"},
		{".com", "", "NETWORK_TOO_BROAD"},
		{"not a host", "", "INVALID_NETWORK"},
		{"1.2.3.4/33", "", "INVALID_NETWORK"},
		{"host.example\nexample.com:evil.example 0.0.0.0/0", "", "INVALID_NETWORK"}, // map-line injection
		{"host.example 1.2.3.4", "", "INVALID_NETWORK"},
		{"*.example.com", "", "INVALID_NETWORK"},
	}
	for _, tt := range tests {
		got, code, _ := normalizeExceptionNetwork(tt.in)
		if code != tt.code || got != tt.want {
			t.Errorf("normalizeExceptionNetwork(%q) = %q, %q; want %q, %q", tt.in, got, code, tt.want, tt.code)
		}
	}
}
