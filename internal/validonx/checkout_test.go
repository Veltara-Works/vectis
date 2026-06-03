package validonx

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestCreateVectisProCheckout_Success feeds the decoder the real on-the-wire
// 201 envelope shape returned by POST /api/v1/checkout/vectis-pro and asserts
// it round-trips, that NO X-API-Key is sent (keyless), that the request hits
// the keyless path, and that it carries vm_source but no install fingerprint.
func TestCreateVectisProCheckout_Success(t *testing.T) {
	const realBody = `{"data":{"checkout_url":"https://checkout.stripe.com/c/pay/cs_test_abc123","session_id":"cs_test_abc123"},"meta":{"request_id":"req_xyz","api_version":"2026-01-01"}}`

	var gotPath, gotAPIKey, gotCT string
	var gotReqBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAPIKey = r.Header.Get("X-API-Key")
		gotCT = r.Header.Get("Content-Type")
		gotReqBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, realBody)
	}))
	defer srv.Close()

	req := VectisProCheckoutRequest{
		OwnerEmail:          "ianholt@validonx.com",
		OwnerName:           "ianholt",
		SuccessURL:          "https://vectismail.com/upgrade/success/?origin=install&session={CHECKOUT_SESSION_ID}",
		CancelURL:           "https://vectismail.com/upgrade/cancelled/?origin=install",
		AllowPromotionCodes: true,
		Metadata:            map[string]string{"vm_source": "in-product"},
	}

	resp, err := CreateVectisProCheckout(context.Background(), srv.Client(), nil, srv.URL, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.CheckoutURL != "https://checkout.stripe.com/c/pay/cs_test_abc123" {
		t.Errorf("checkout_url = %q", resp.CheckoutURL)
	}
	if resp.SessionID != "cs_test_abc123" {
		t.Errorf("session_id = %q", resp.SessionID)
	}
	if gotPath != "/api/v1/checkout/vectis-pro" {
		t.Errorf("path = %q, want the keyless endpoint", gotPath)
	}
	if gotAPIKey != "" {
		t.Errorf("keyless endpoint must NOT send X-API-Key, got %q", gotAPIKey)
	}
	if gotCT != "application/json" {
		t.Errorf("content-type = %q, want application/json", gotCT)
	}
	if !strings.Contains(string(gotReqBody), `"vm_source":"in-product"`) {
		t.Errorf("request body missing vm_source metadata: %s", gotReqBody)
	}
	if strings.Contains(string(gotReqBody), "fingerprint") {
		t.Errorf("keyless request must not carry an install fingerprint: %s", gotReqBody)
	}
}

// TestCreateVectisProCheckout_ValidationError feeds the real 422 body shape
// (Laravel {message, errors}) and asserts the message surfaces in the error.
func TestCreateVectisProCheckout_ValidationError(t *testing.T) {
	const realBody = `{"message":"The owner email field is required. (and 1 more error)","errors":{"owner_email":["The owner email field is required."],"owner_name":["The owner name field is required."]}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = io.WriteString(w, realBody)
	}))
	defer srv.Close()

	_, err := CreateVectisProCheckout(context.Background(), srv.Client(), nil, srv.URL,
		VectisProCheckoutRequest{OwnerEmail: "x@y.com", OwnerName: "x"})
	if err == nil {
		t.Fatal("expected error on 422")
	}
	if !strings.Contains(err.Error(), "owner email field is required") {
		t.Errorf("error should surface the Vx validation message, got: %v", err)
	}
}

// TestCreateVectisProCheckout_RateLimited maps a 429 to a clear, retryable
// message rather than dumping the raw body.
func TestCreateVectisProCheckout_RateLimited(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"message":"Too Many Attempts."}`)
	}))
	defer srv.Close()

	_, err := CreateVectisProCheckout(context.Background(), srv.Client(), nil, srv.URL,
		VectisProCheckoutRequest{OwnerEmail: "x@y.com", OwnerName: "x"})
	if err == nil || !strings.Contains(err.Error(), "rate-limited") {
		t.Errorf("expected a rate-limit error, got: %v", err)
	}
}

// TestCreateVectisProCheckout_RequiresOwner asserts the client-side guard fires
// before any network call when the required owner fields are empty.
func TestCreateVectisProCheckout_RequiresOwner(t *testing.T) {
	_, err := CreateVectisProCheckout(context.Background(), nil, nil, "https://api.validonx.com",
		VectisProCheckoutRequest{OwnerEmail: "", OwnerName: ""})
	if err == nil || !strings.Contains(err.Error(), "owner_email and owner_name are required") {
		t.Errorf("expected owner-required guard error, got: %v", err)
	}
}
