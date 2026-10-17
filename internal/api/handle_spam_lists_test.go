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
		// Copilot #291: no suffixes (".com.au" is a public suffix).
		{".ipv4.au.ds.network", "", "NETWORK_TOO_BROAD"},
		{".com.au", "", "NETWORK_TOO_BROAD"},
		{".co.uk", "", "NETWORK_TOO_BROAD"},
		{".network", "", "NETWORK_TOO_BROAD"},
		{".com", "", "NETWORK_TOO_BROAD"},
		{"not a host", "", "INVALID_NETWORK"},
		{"1.2.3.4/33", "", "INVALID_NETWORK"},
		{"host.example\nexample.com:evil.example 0.0.0.0/0", "", "INVALID_NETWORK"}, // map-line injection
		{"host.example 1.2.3.4", "", "INVALID_NETWORK"},
		{"*.example.com", "", "INVALID_NETWORK"},
		// Copilot #291: IPv4-mapped prefixes are judged as IPv4.
		{"::ffff:27.111.95.31/119", "", "NETWORK_TOO_BROAD"}, // = IPv4 /23
		{"::ffff:27.111.95.31/24", "", "NETWORK_TOO_BROAD"},
		{"::ffff:27.111.95.31/120", "27.111.95.0/24", ""},
		{"::ffff:27.111.95.31/128", "27.111.95.31/32", ""},
		// Copilot #291: no IPv6 zones (arbitrary text, incl. a newline that would forge a map line).
		{"2001:db8::1%eth0", "", "INVALID_NETWORK"},
		{"2001:db8::1%eth0\nvictim.example:forged.example 198.51.100.123", "", "INVALID_NETWORK"},
		{"fe80::1%25eth0/64", "", "INVALID_NETWORK"},
	}
	for _, tt := range tests {
		got, code, _ := normalizeExceptionNetwork(tt.in)
		if code != tt.code || got != tt.want {
			t.Errorf("normalizeExceptionNetwork(%q) = %q, %q; want %q, %q", tt.in, got, code, tt.want, tt.code)
		}
	}
}
