package monitor

import (
	"strings"
	"testing"
	"time"
)

func TestParseValkeyInfo(t *testing.T) {
	info := "# Memory\r\nused_memory:22209344\r\nused_memory_human:21.18M\r\nmaxmemory:134217728\r\nmaxmemory_policy:allkeys-lru\r\n" +
		"\r\n# Stats\r\ntotal_connections_received:12\r\nevicted_keys:7\r\nevicted_clients:0\r\n"
	v, err := parseValkeyInfo(info)
	if err != nil {
		t.Fatal(err)
	}
	if v.UsedMemory != 22209344 || v.MaxMemory != 134217728 || v.EvictedKeys != 7 {
		t.Errorf("parsed %+v", v)
	}
	if _, err := parseValkeyInfo("# Memory\r\nused_memory:1\r\nmaxmemory:0\r\n"); err == nil {
		t.Error("missing evicted_keys: want error")
	}
	if _, err := parseValkeyInfo("used_memory:x\nmaxmemory:0\nevicted_keys:0\n"); err == nil {
		t.Error("non-numeric value: want error")
	}
}

func TestEvalValkeyMemory(t *testing.T) {
	t0 := time.Date(2026, 10, 17, 4, 0, 0, 0, time.UTC)
	const max = 128 << 20
	healthy := valkeyInfo{UsedMemory: 21 << 20, MaxMemory: max}

	// Healthy first sample: nothing to say.
	st, msg := evalValkeyMemory(valkeyMemState{}, healthy, t0)
	if msg != "" || !st.haveBaseline {
		t.Fatalf("healthy: msg=%q state=%+v", msg, st)
	}

	// Memory at 80% warns; below clears.
	if _, msg := evalValkeyMemory(st, valkeyInfo{UsedMemory: max * 8 / 10, MaxMemory: max}, t0); !strings.Contains(msg, "80% of its limit") {
		t.Errorf("80%%: msg=%q", msg)
	}
	if _, msg := evalValkeyMemory(st, valkeyInfo{UsedMemory: max * 8 / 10, MaxMemory: 0}, t0); msg != "" {
		t.Errorf("no limit set: msg=%q", msg)
	}

	// New evictions warn and keep warning for an hour, then clear.
	st, msg = evalValkeyMemory(st, valkeyInfo{UsedMemory: 21 << 20, MaxMemory: max, EvictedKeys: 3}, t0.Add(time.Minute))
	if !strings.Contains(msg, "evicted 3 key(s)") {
		t.Fatalf("eviction: msg=%q", msg)
	}
	st, msg = evalValkeyMemory(st, valkeyInfo{UsedMemory: 21 << 20, MaxMemory: max, EvictedKeys: 3}, t0.Add(30*time.Minute))
	if !strings.Contains(msg, "in the last hour") {
		t.Errorf("held: msg=%q", msg)
	}
	st, msg = evalValkeyMemory(st, valkeyInfo{UsedMemory: 21 << 20, MaxMemory: max, EvictedKeys: 3}, t0.Add(62*time.Minute))
	if msg != "" {
		t.Errorf("after the hold: msg=%q", msg)
	}
	st, msg = evalValkeyMemory(st, valkeyInfo{UsedMemory: 21 << 20, MaxMemory: max, EvictedKeys: 10}, t0.Add(63*time.Minute))
	if !strings.Contains(msg, "evicted 7 key(s) (10 since it started)") {
		t.Errorf("second burst: msg=%q", msg)
	}

	// Valkey restarted: the counter dropped; a non-zero new count is new evictions.
	_, msg = evalValkeyMemory(st, valkeyInfo{UsedMemory: 1 << 20, MaxMemory: max, EvictedKeys: 2}, t0.Add(3*time.Hour))
	if !strings.Contains(msg, "evicted 2 key(s)") {
		t.Errorf("after restart: msg=%q", msg)
	}

	// A non-zero count on the very first sample counts (nothing was observed before).
	if _, msg := evalValkeyMemory(valkeyMemState{}, valkeyInfo{UsedMemory: 1, MaxMemory: max, EvictedKeys: 5}, t0); !strings.Contains(msg, "evicted 5 key(s)") {
		t.Errorf("first sample with evictions: msg=%q", msg)
	}
}
