package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeVerifyRecord(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "last.json")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

var verifyNow = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

func TestReadVerifyStatus_NeverRecorded(t *testing.T) {
	got := readVerifyStatus(filepath.Join(t.TempDir(), "last.json"), verifyNow)
	if got.Status != "never" || got.CheckedAt != nil || got.Stale {
		t.Fatalf("missing file: got %+v, want status never", got)
	}
}

func TestReadVerifyStatus_Pass(t *testing.T) {
	p := writeVerifyRecord(t, `{"version":"v0.1.52","result":"pass","checked_at":"2026-10-09T06:00:00Z",
		"checks":[{"name":"manifest","status":"pass"},{"name":"image api","status":"pass"}]}`)
	got := readVerifyStatus(p, verifyNow)
	if got.Status != "pass" || got.Version != "v0.1.52" || got.Stale || len(got.FailedChecks) != 0 {
		t.Fatalf("pass: got %+v", got)
	}
	if got.CheckedAt == nil || !got.CheckedAt.Equal(time.Date(2026, 10, 9, 6, 0, 0, 0, time.UTC)) {
		t.Fatalf("pass: checked_at %v", got.CheckedAt)
	}
}

func TestReadVerifyStatus_FailListsFailedChecksAndSince(t *testing.T) {
	p := writeVerifyRecord(t, `{"version":"v0.1.52","result":"fail","checked_at":"2026-10-09T06:00:00Z",
		"failing_since":"2026-10-08T18:00:00Z",
		"checks":[{"name":"manifest","status":"pass"},{"name":"image api","status":"fail","detail":"digest mismatch"},
		          {"name":"binary","status":"fail"}]}`)
	got := readVerifyStatus(p, verifyNow)
	if got.Status != "fail" || got.FailingSince == nil {
		t.Fatalf("fail: got %+v", got)
	}
	if len(got.FailedChecks) != 2 || got.FailedChecks[0] != "image api" || got.FailedChecks[1] != "binary" {
		t.Fatalf("fail: failed_checks %v, want [image api binary]", got.FailedChecks)
	}
}

func TestReadVerifyStatus_StaleWhenTimerStopped(t *testing.T) {
	p := writeVerifyRecord(t, `{"version":"v0.1.52","result":"pass","checked_at":"2026-10-06T06:00:00Z","checks":[]}`)
	if got := readVerifyStatus(p, verifyNow); !got.Stale || got.Status != "pass" {
		t.Fatalf("3-day-old record: got %+v, want stale pass", got)
	}
}

func TestReadVerifyStatus_Unreadable(t *testing.T) {
	for _, body := range []string{"not json", `{"version":"v0.1.52"}`} {
		if got := readVerifyStatus(writeVerifyRecord(t, body), verifyNow); got.Status != "unreadable" {
			t.Errorf("%q: got %+v, want unreadable", body, got)
		}
	}
}

func TestHandleVerifyStatus_RespondsWithEnvelope(t *testing.T) {
	p := writeVerifyRecord(t, `{"version":"v0.1.52","result":"pass","checked_at":"2026-10-09T06:00:00Z","checks":[]}`)
	s := &Server{verifyStatePath: p}
	rec := httptest.NewRecorder()
	s.handleVerifyStatus(rec, httptest.NewRequest(http.MethodGet, "/api/v1/system/verify", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var body struct {
		Data verifyStatusResponse `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body.String())
	}
	if body.Data.Status != "pass" || body.Data.Version != "v0.1.52" {
		t.Fatalf("body %+v", body.Data)
	}
}
