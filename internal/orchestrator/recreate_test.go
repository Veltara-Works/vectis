package orchestrator

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"context"
)

func TestValidateRecreateRequest(t *testing.T) {
	defined := map[string]bool{"api": true, "rspamd": true, "postgres": true, "webmail": true, "orchestrator": true}
	ok := []RecreateRequest{
		{Services: []string{"api", "rspamd"}},
		{Removed: []string{"clamav"}},
		{Services: []string{"webmail"}, Removed: []string{"loki"}},
		{Removed: []string{"cert-extractor"}}, // tls.provider switched to custom
	}
	for _, r := range ok {
		if err := validateRecreateRequest(r, defined); err != nil {
			t.Errorf("%+v: unexpected error %v", r, err)
		}
	}
	bad := map[string]RecreateRequest{
		"empty":                 {},
		"orchestrator":          {Services: []string{"orchestrator"}},
		"orchestrator removed":  {Removed: []string{"orchestrator"}},
		"not in compose":        {Services: []string{"clamav"}},
		"core removed":          {Removed: []string{"postgres"}},
		"removed still defined": {Removed: []string{"webmail"}},
		"duplicate":             {Services: []string{"api"}, Removed: []string{"api"}},
		"bad name":              {Services: []string{"api; rm -rf /"}},
		"uppercase":             {Services: []string{"API"}},
	}
	for name, r := range bad {
		if err := validateRecreateRequest(r, defined); err == nil {
			t.Errorf("%s: want error for %+v", name, r)
		}
	}
}

func TestRecreateOrder(t *testing.T) {
	got := recreateOrder([]string{"webmail", "api", "traefik", "postgres", "rspamd", "cert-extractor"})
	want := []string{"postgres", "rspamd", "api", "cert-extractor", "traefik", "webmail"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
}

func TestClientRecreate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/internal/recreate" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer tok" {
			t.Errorf("auth header %q", got)
		}
		body, _ := io.ReadAll(r.Body)
		var req RecreateRequest
		if err := json.Unmarshal(body, &req); err != nil || !reflect.DeepEqual(req.Services, []string{"api"}) || !reflect.DeepEqual(req.Removed, []string{"clamav"}) {
			t.Errorf("request body %s", body)
		}
		// Slower than the client's usual 30 s timeout would allow if it applied.
		time.Sleep(50 * time.Millisecond)
		_, _ = io.WriteString(w, `{"state":"idle","data":{"result":{"success":true,"steps":[{"service":"clamav","action":"remove","success":true,"seconds":2},{"service":"api","action":"recreate","success":true,"seconds":9}]}}}`)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "tok")
	c.http.Timeout = 10 * time.Millisecond // the recreate call must not use it
	res, err := c.Recreate(context.Background(), RecreateRequest{Services: []string{"api"}, Removed: []string{"clamav"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Success || len(res.Steps) != 2 || res.Steps[1].Service != "api" || res.Steps[1].Seconds != 9 {
		t.Fatalf("result %+v", res)
	}
	if c.http.Timeout != 10*time.Millisecond {
		t.Error("Recreate must not change the shared client's timeout")
	}

	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = io.WriteString(w, `{"error":{"code":"STATE_CONFLICT","message":"operation \"recreate\" not allowed in state \"applying\""}}`)
	}))
	defer srv2.Close()
	if _, err := NewClient(srv2.URL, "tok").Recreate(context.Background(), RecreateRequest{Services: []string{"api"}}); err == nil || !strings.Contains(err.Error(), "409") {
		t.Fatalf("conflict: err = %v", err)
	}
}

// handleRecreate extends its write deadline through loggingMiddleware's
// statusWriter. Without Unwrap, ResponseController can't reach the real
// writer, the server's WriteTimeout still applies, and the client loses the
// response of any recreate longer than it (Copilot, #296/#297).
func TestWriteDeadlineExtendsThroughLoggingMiddleware(t *testing.T) {
	s := &Server{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	h := s.loggingMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Errorf("SetWriteDeadline through the middleware: %v", err)
		}
		time.Sleep(600 * time.Millisecond) // longer than the server's WriteTimeout
		_, _ = io.WriteString(w, "done")
	}))
	srv := httptest.NewUnstartedServer(h)
	srv.Config.WriteTimeout = 200 * time.Millisecond
	srv.Start()
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("response lost: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "done" {
		t.Fatalf("body = %q", body)
	}
}

func TestClientBeginAndCancelRecreate(t *testing.T) {
	var cancelled string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/internal/recreate/begin":
			_, _ = io.WriteString(w, `{"state":"recreating","data":{"reservation":"res-1"}}`)
		case "/internal/recreate/cancel":
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			cancelled = body["reservation"]
			_, _ = io.WriteString(w, `{"state":"idle"}`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "tok")
	id, err := c.BeginRecreate(context.Background())
	if err != nil || id != "res-1" {
		t.Fatalf("begin: %q %v", id, err)
	}
	if err := c.CancelRecreate(context.Background(), id); err != nil || cancelled != "res-1" {
		t.Fatalf("cancel: %v (server saw %q)", err, cancelled)
	}

	// Unreachable orchestrator is distinguishable from a refusal.
	_, err = NewClient("http://127.0.0.1:1", "tok").BeginRecreate(context.Background())
	if !errors.Is(err, ErrOrchestratorUnreachable) {
		t.Fatalf("unreachable: %v", err)
	}
	busy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = io.WriteString(w, `{"error":{"code":"STATE_CONFLICT","message":"busy"}}`)
	}))
	defer busy.Close()
	_, err = NewClient(busy.URL, "tok").BeginRecreate(context.Background())
	if err == nil || errors.Is(err, ErrOrchestratorUnreachable) {
		t.Fatalf("refusal must be an error but not 'unreachable': %v", err)
	}
}
