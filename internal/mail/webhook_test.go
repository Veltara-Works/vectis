package mail

import (
	"net"
	"testing"
)

func TestIsBlockedWebhookIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1",       // loopback
		"::1",             // loopback v6
		"10.1.2.3",        // RFC1918
		"192.168.0.5",     // RFC1918
		"172.16.9.9",      // RFC1918
		"169.254.169.254", // link-local / cloud metadata
		"100.64.0.1",      // CGNAT (RFC 6598), not caught by IsPrivate
		"100.127.255.254", // CGNAT upper bound
		"0.0.0.0",         // unspecified
		"224.0.0.1",       // multicast
		"fd00::1",         // unique-local v6 (IsPrivate)
	}
	for _, s := range blocked {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("bad test IP %q", s)
		}
		if !IsBlockedWebhookIP(ip) {
			t.Errorf("IsBlockedWebhookIP(%s) = false, want true", s)
		}
	}

	allowed := []string{
		"8.8.8.8",
		"1.1.1.1",
		"93.184.216.34", // example.com
		"99.63.255.255", // just below CGNAT
		"2606:4700:4700::1111",
	}
	for _, s := range allowed {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("bad test IP %q", s)
		}
		if IsBlockedWebhookIP(ip) {
			t.Errorf("IsBlockedWebhookIP(%s) = true, want false", s)
		}
	}
}

func TestBlockPrivateDial(t *testing.T) {
	// Control runs with the concrete resolved IP:port about to be dialed.
	if err := blockPrivateDial("tcp", "169.254.169.254:443", nil); err == nil {
		t.Error("blockPrivateDial allowed the cloud-metadata address, want error")
	}
	if err := blockPrivateDial("tcp", "10.0.0.5:443", nil); err == nil {
		t.Error("blockPrivateDial allowed an RFC1918 address, want error")
	}
	if err := blockPrivateDial("tcp", "8.8.8.8:443", nil); err != nil {
		t.Errorf("blockPrivateDial blocked a public address: %v", err)
	}
}
