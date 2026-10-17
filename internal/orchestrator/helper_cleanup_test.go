package orchestrator

import (
	"reflect"
	"sort"
	"testing"
	"time"
)

func TestSelectHelpersToRemove(t *testing.T) {
	base := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	h := func(name, status string, code, ageHours int) applyHelper {
		return applyHelper{ID: "id-" + name, Name: applyHelperPrefix + name, Status: status, ExitCode: code,
			Created: base.Add(-time.Duration(ageHours) * time.Hour)}
	}

	tests := []struct {
		name    string
		helpers []applyHelper
		want    []string // suffixes, any order
	}{
		{"none", nil, nil},
		{"one success kept", []applyHelper{h("a", "exited", 0, 1)}, nil},
		{
			"only newest success kept",
			[]applyHelper{h("old", "exited", 0, 30), h("new", "exited", 0, 1), h("mid", "exited", 0, 10)},
			[]string{"old", "mid"},
		},
		{
			"failures kept up to the cap, newest first",
			[]applyHelper{
				h("f1", "exited", 1, 1), h("f2", "exited", 125, 2), h("f3", "dead", 0, 3),
				h("f4", "exited", 1, 4), h("f5", "created", 0, 5),
			},
			[]string{"f4", "f5"},
		},
		{
			"failures do not displace the newest success",
			[]applyHelper{h("ok-old", "exited", 0, 9), h("ok-new", "exited", 0, 8), h("fail", "exited", 2, 1)},
			[]string{"ok-old"},
		},
		{
			"helpers that may still be working are never removed",
			[]applyHelper{
				h("run", "running", 0, 50), h("pause", "paused", 0, 49), h("restart", "restarting", 0, 48),
				h("removing", "removing", 0, 47), h("ok", "exited", 0, 1), h("ok-old", "exited", 0, 2),
			},
			[]string{"ok-old"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, r := range selectHelpersToRemove(tc.helpers, keepSucceededHelpers, keepFailedHelpers) {
				got = append(got, r.Name[len(applyHelperPrefix):])
			}
			sort.Strings(got)
			want := append([]string(nil), tc.want...)
			sort.Strings(want)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("removed %v, want %v", got, want)
			}
		})
	}
}

func TestParseApplyHelpers(t *testing.T) {
	data := []byte(`[
	  {"Id":"aaa","Name":"/vectis-apply-helper-01a1","Created":"2026-10-17T01:06:29.694491962Z",
	   "State":{"Status":"exited","ExitCode":0}},
	  {"Id":"bbb","Name":"/my-vectis-apply-helper-x","Created":"2026-10-17T01:06:29Z",
	   "State":{"Status":"exited","ExitCode":0}},
	  {"Id":"ccc","Name":"/vectis-apply-helper-01a2","Created":"2026-10-16T08:48:10.1Z",
	   "State":{"Status":"exited","ExitCode":1}}
	]`)
	got, err := parseApplyHelpers(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d helpers, want 2 (substring match must be dropped): %+v", len(got), got)
	}
	if got[0].Name != "vectis-apply-helper-01a1" || got[0].Status != "exited" || got[0].ExitCode != 0 ||
		!got[0].Created.Equal(time.Date(2026, 10, 17, 1, 6, 29, 694491962, time.UTC)) {
		t.Errorf("first helper parsed wrong: %+v", got[0])
	}
	if got[1].ID != "ccc" || got[1].ExitCode != 1 {
		t.Errorf("second helper parsed wrong: %+v", got[1])
	}

	if _, err := parseApplyHelpers([]byte(`[{"Name":"/vectis-apply-helper-z","Created":"yesterday","State":{}}]`)); err == nil {
		t.Error("bad Created time: want error")
	}
}
