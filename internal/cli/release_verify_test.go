package cli

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Veltara-Works/vectis/internal/releasesign"
)

// classifyVerifyErr must tell an active-attack signal (a real verification
// failure) apart from a benign skip (this build has no embedded key), so the
// self-update callers can surface tampering loudly and exit non-zero (audit U-5).
func TestClassifyVerifyErr(t *testing.T) {
	if got := classifyVerifyErr(nil); got != nil {
		t.Errorf("nil in → nil out, got %v", got)
	}

	// A build with no embedded key is a benign skip, NOT errReleaseVerification.
	notConfigured := classifyVerifyErr(releasesign.ErrNotConfigured)
	if notConfigured == nil {
		t.Fatal("ErrNotConfigured should surface as a (benign) error")
	}
	if errors.Is(notConfigured, errReleaseVerification) {
		t.Error("ErrNotConfigured must NOT be tagged as a verification failure")
	}
	if !errors.Is(notConfigured, releasesign.ErrNotConfigured) {
		t.Error("ErrNotConfigured should remain unwrappable")
	}

	// Any other verification error is an attack-class failure.
	tampered := classifyVerifyErr(errors.New("release signature verification failed"))
	if !errors.Is(tampered, errReleaseVerification) {
		t.Error("a genuine verify failure must be tagged errReleaseVerification")
	}
}

func TestHTTPGetBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			_, _ = w.Write([]byte("hello-body"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	body, ok, err := httpGetBody(srv.Client(), srv.URL+"/ok", 1024)
	if err != nil || !ok {
		t.Fatalf("200 path: ok=%v err=%v", ok, err)
	}
	if string(body) != "hello-body" {
		t.Errorf("body = %q, want hello-body", body)
	}

	// Limit is honoured.
	body, ok, err = httpGetBody(srv.Client(), srv.URL+"/ok", 5)
	if err != nil || !ok || string(body) != "hello" {
		t.Errorf("limited read: body=%q ok=%v err=%v", body, ok, err)
	}

	// Non-200 → ok=false, nil error (caller classifies).
	_, ok, err = httpGetBody(srv.Client(), srv.URL+"/missing", 1024)
	if ok || err != nil {
		t.Errorf("404 path: ok=%v err=%v; want ok=false err=nil", ok, err)
	}
}
