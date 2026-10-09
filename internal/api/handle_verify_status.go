package api

import (
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"time"
)

// defaultVerifyStatePath is where the host's `vectis verify` timer records its
// last result; the compose template bind-mounts its directory read-only into
// this container. Keep in sync with cli.verifyStatePath.
const defaultVerifyStatePath = "/var/lib/vectis/verify/last.json"

// verifyStaleAfter: the timer runs at least daily, so a record older than
// this means the timer has stopped (or never ran since a host change).
const verifyStaleAfter = 48 * time.Hour

// verifyRecord mirrors the fields of the CLI's verify report that the
// dashboard needs. Unknown fields in the file are ignored.
type verifyRecord struct {
	Version      string     `json:"version"`
	Result       string     `json:"result"` // pass | fail | unverifiable
	CheckedAt    time.Time  `json:"checked_at"`
	FailingSince *time.Time `json:"failing_since,omitempty"`
	Checks       []struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	} `json:"checks"`
}

type verifyStatusResponse struct {
	// Status is the last result (pass | fail | unverifiable), or "never" when
	// no result has been recorded, or "unreadable" when the file exists but
	// can't be parsed.
	Status       string     `json:"status"`
	Version      string     `json:"version,omitempty"`
	CheckedAt    *time.Time `json:"checked_at,omitempty"`
	FailingSince *time.Time `json:"failing_since,omitempty"`
	FailedChecks []string   `json:"failed_checks,omitempty"`
	Stale        bool       `json:"stale"`
}

// readVerifyStatus turns the recorded file into the dashboard view. It never
// returns an error: every outcome is a displayable status.
func readVerifyStatus(path string, now time.Time) verifyStatusResponse {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return verifyStatusResponse{Status: "never"}
	}
	var rec verifyRecord
	if err != nil || json.Unmarshal(b, &rec) != nil || rec.Result == "" {
		return verifyStatusResponse{Status: "unreadable"}
	}
	resp := verifyStatusResponse{
		Status:       rec.Result,
		Version:      rec.Version,
		FailingSince: rec.FailingSince,
		Stale:        now.Sub(rec.CheckedAt) > verifyStaleAfter,
	}
	if !rec.CheckedAt.IsZero() {
		at := rec.CheckedAt
		resp.CheckedAt = &at
	}
	for _, c := range rec.Checks {
		if c.Status == "fail" {
			resp.FailedChecks = append(resp.FailedChecks, c.Name)
		}
	}
	return resp
}

// GET /api/v1/system/verify — the last `vectis verify` result recorded on the
// host. Informational only: the emailed alert is the real signal, because a
// compromised box can't be trusted to report on itself.
func (s *Server) handleVerifyStatus(w http.ResponseWriter, r *http.Request) {
	path := s.verifyStatePath
	if path == "" {
		path = defaultVerifyStatePath
	}
	respond(w, r, http.StatusOK, readVerifyStatus(path, time.Now()))
}
