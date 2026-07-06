package monitor

import (
	"net"
	"testing"
	"time"
)

// TestDedupKeyFor pins the single key-derivation used by both Send and every
// Resolve path. If Send and the resolve helpers ever derive keys differently,
// alerts stop auto-resolving — the exact regression this file guards.
func TestDedupKeyFor(t *testing.T) {
	cases := []struct{ service, severity, want string }{
		{"disk", "WARN", "disk:warn"},
		{"disk", "CRITICAL", "disk:critical"},
		{"postgres", "ERROR", "postgres:error"},
		{"tls", "warn", "tls:warn"},
	}
	for _, c := range cases {
		if got := dedupKeyFor(c.service, c.severity); got != c.want {
			t.Errorf("dedupKeyFor(%q, %q) = %q, want %q", c.service, c.severity, got, c.want)
		}
	}
}

// TestServiceResolveKeys is the MON-1 regression: a healthy check must resolve
// the keys Send actually wrote (<svc>:warn / <svc>:critical / <svc>:error), never
// a hand-written key like "disk:disk" that Send never sets.
func TestServiceResolveKeys(t *testing.T) {
	got := serviceResolveKeys("disk")
	want := map[string]bool{"disk:warn": false, "disk:critical": false, "disk:error": false}
	for _, k := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("serviceResolveKeys(disk) returned unexpected key %q", k)
		}
		want[k] = true
	}
	for k, seen := range want {
		if !seen {
			t.Errorf("serviceResolveKeys(disk) missing expected key %q", k)
		}
	}
	// The historical bug: the healthy branch resolved "disk:disk".
	for _, k := range got {
		if k == "disk:disk" {
			t.Fatal("serviceResolveKeys(disk) resolved the bogus key disk:disk")
		}
	}
}

// TestServiceResolveKeysExcept verifies a firing check clears its siblings but
// not the tier it just raised (so a re-raise isn't immediately self-resolved).
func TestServiceResolveKeysExcept(t *testing.T) {
	got := serviceResolveKeysExcept("tls", "critical")
	for _, k := range got {
		if k == "tls:critical" {
			t.Errorf("serviceResolveKeysExcept(tls, critical) must NOT include tls:critical")
		}
	}
	// Must still clear the sibling warn (cert expiry CRITICAL → later WARN edge).
	var sawWarn bool
	for _, k := range got {
		if k == "tls:warn" {
			sawWarn = true
		}
	}
	if !sawWarn {
		t.Error("serviceResolveKeysExcept(tls, critical) must include the sibling tls:warn")
	}
}

// TestDedupNamespacesDisjoint is the MON-2 / MON-5 regression: the disk check on
// the Postgres data volume, the connection-pool check, and the container-health
// check must live in separate dedup namespaces so none can mask or auto-resolve
// another's alert.
func TestDedupNamespacesDisjoint(t *testing.T) {
	disjoint := func(a, b string) {
		t.Helper()
		set := map[string]bool{}
		for _, k := range serviceResolveKeys(a) {
			set[k] = true
		}
		for _, k := range serviceResolveKeys(b) {
			if set[k] {
				t.Errorf("services %q and %q share dedup key %q — one can mask/resolve the other", a, b, k)
			}
		}
	}
	disjoint("disk-postgres", "postgres")   // MON-2: pg-disk WARN vs pool-hot WARN
	disjoint("container-postgres", "postgres") // MON-5: container-down vs DB-unreachable
	disjoint("container-valkey", "valkey")
}

// TestSendMailWithTimeout_Timeout is the MON-3 regression: a hung SMTP server
// (accepts the TCP connection but never sends its greeting) must not block the
// caller indefinitely — the send returns an error bounded by the timeout.
func TestSendMailWithTimeout_Timeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// Accept and hold the connection open, silent — the classic wedged server.
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		time.Sleep(5 * time.Second)
		_ = conn.Close()
	}()

	const timeout = 200 * time.Millisecond
	start := time.Now()
	err = sendMailWithTimeout(ln.Addr().String(), "vectis@test", []string{"admin@test"}, []byte("hi"), timeout)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected a timeout error from a silent SMTP server, got nil")
	}
	if elapsed > 3*time.Second {
		t.Errorf("send took %v — deadline not enforced (want ~%v)", elapsed, timeout)
	}
}

// TestStop_Idempotent is the MON-6 regression: a second Stop must not panic on a
// double close of stopCh.
func TestStop_Idempotent(t *testing.T) {
	m := New(nil, nil, nil, Config{}, mustLogger())
	m.Stop()
	m.Stop() // must be a no-op, not a panic
}
