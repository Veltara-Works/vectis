package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Veltara-Works/vectis/internal/mail"
)

// TestSendMessageValidation is the regression for audit finding #156: the single
// and batch send paths were duplicated and had drifted. They now share one
// sendMessage core, so this locks its pre-authorization validation contract —
// the codes/statuses every caller relies on. These cases all return before any
// repository access, so a bare Server suffices (DB-dependent paths need the
// integration harness, tracked separately).
func TestSendMessageValidation(t *testing.T) {
	s := &Server{}
	r := httptest.NewRequest(http.MethodPost, "/send", nil)

	tests := []struct {
		name        string
		req         sendRequest
		wantCode    string
		wantStatus  int
		wantMsgPart string
	}{
		{
			name:       "missing from email",
			req:        sendRequest{To: []mail.Address{{Email: "x@y.com"}}, Subject: "s", TextBody: "b"},
			wantCode:   "MISSING_FIELDS",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "no recipients",
			req:        sendRequest{From: mail.Address{Email: "a@b.com"}, Subject: "s", TextBody: "b"},
			wantCode:   "MISSING_FIELDS",
			wantStatus: http.StatusBadRequest,
		},
		{
			// Unified behavior: the recipient index is reported on both paths now
			// (batch previously emitted a generic "to[].email is required").
			name:        "empty recipient email reports index",
			req:         sendRequest{From: mail.Address{Email: "a@b.com"}, To: []mail.Address{{Email: ""}}, Subject: "s", TextBody: "b"},
			wantCode:    "MISSING_FIELDS",
			wantStatus:  http.StatusBadRequest,
			wantMsgPart: "to[0].email",
		},
		{
			name:       "missing subject",
			req:        sendRequest{From: mail.Address{Email: "a@b.com"}, To: []mail.Address{{Email: "x@y.com"}}, TextBody: "b"},
			wantCode:   "MISSING_FIELDS",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "missing body",
			req:        sendRequest{From: mail.Address{Email: "a@b.com"}, To: []mail.Address{{Email: "x@y.com"}}, Subject: "s"},
			wantCode:   "MISSING_FIELDS",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "sender address without domain",
			req:        sendRequest{From: mail.Address{Email: "not-an-email"}, To: []mail.Address{{Email: "x@y.com"}}, Subject: "s", TextBody: "b"},
			wantCode:   "INVALID_SENDER",
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := s.sendMessage(r, tt.req, "", "", "", "", sendVariant{auditAction: "mail.send"})
			if out.code != tt.wantCode {
				t.Errorf("code = %q, want %q", out.code, tt.wantCode)
			}
			if out.httpStatus != tt.wantStatus {
				t.Errorf("httpStatus = %d, want %d", out.httpStatus, tt.wantStatus)
			}
			if out.messageID != "" {
				t.Errorf("messageID = %q, want empty on failure", out.messageID)
			}
			if tt.wantMsgPart != "" && !strings.Contains(out.message, tt.wantMsgPart) {
				t.Errorf("message = %q, want to contain %q", out.message, tt.wantMsgPart)
			}
		})
	}
}

// TestHandleSendRendersOutcome confirms the single-send handler translates a
// sendOutcome into the HTTP error envelope (status + code) and rejects a
// malformed body before invoking the shared core.
func TestHandleSendRendersOutcome(t *testing.T) {
	t.Run("invalid json", func(t *testing.T) {
		s := &Server{}
		r := httptest.NewRequest(http.MethodPost, "/send", strings.NewReader("{not-json"))
		rec := httptest.NewRecorder()
		s.handleSend(rec, r)
		assertErrorEnvelope(t, rec, http.StatusBadRequest, "INVALID_JSON")
	})

	t.Run("validation failure rendered", func(t *testing.T) {
		s := &Server{}
		// Missing "from" — sendMessage returns MISSING_FIELDS, handler renders 400.
		body := `{"to":[{"email":"x@y.com"}],"subject":"s","text_body":"b"}`
		r := httptest.NewRequest(http.MethodPost, "/send", strings.NewReader(body))
		rec := httptest.NewRecorder()
		s.handleSend(rec, r)
		assertErrorEnvelope(t, rec, http.StatusBadRequest, "MISSING_FIELDS")
	})
}

// TestHandleBatchSendRequestLevel covers the batch-only request-level guards that
// run before the per-message loop, including the preserved whole-batch 503 when
// sending is unconfigured (rather than a per-message failure).
func TestHandleBatchSendRequestLevel(t *testing.T) {
	t.Run("empty batch", func(t *testing.T) {
		s := &Server{}
		r := httptest.NewRequest(http.MethodPost, "/batch", strings.NewReader(`{"messages":[]}`))
		rec := httptest.NewRecorder()
		s.handleBatchSend(rec, r)
		assertErrorEnvelope(t, rec, http.StatusBadRequest, "EMPTY_BATCH")
	})

	t.Run("batch too large", func(t *testing.T) {
		s := &Server{mailSender: &mail.Sender{}}
		msgs := make([]sendRequest, maxBatchSize+1)
		for i := range msgs {
			msgs[i] = sendRequest{From: mail.Address{Email: "a@b.com"}, To: []mail.Address{{Email: "x@y.com"}}, Subject: "s", TextBody: "b"}
		}
		b, err := json.Marshal(batchSendRequest{Messages: msgs})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		r := httptest.NewRequest(http.MethodPost, "/batch", bytes.NewReader(b))
		rec := httptest.NewRecorder()
		s.handleBatchSend(rec, r)
		assertErrorEnvelope(t, rec, http.StatusBadRequest, "BATCH_TOO_LARGE")
	})

	t.Run("send unconfigured fails whole batch", func(t *testing.T) {
		s := &Server{} // mailSender nil
		body := `{"messages":[{"from":{"email":"a@b.com"},"to":[{"email":"x@y.com"}],"subject":"s","text_body":"b"}]}`
		r := httptest.NewRequest(http.MethodPost, "/batch", strings.NewReader(body))
		rec := httptest.NewRecorder()
		s.handleBatchSend(rec, r)
		assertErrorEnvelope(t, rec, http.StatusServiceUnavailable, "SEND_UNAVAILABLE")
	})
}

// TestHandleBatchSendPerMessageMapping is the core #156 mapping regression: each
// message's sendOutcome is rendered into the correct indexed batchSendResult with
// the right code, and the succeeded/failed tallies are correct. Every message
// here fails validation before any repository access, so mailSender is set
// non-nil only to clear the request-level gate and is never invoked.
func TestHandleBatchSendPerMessageMapping(t *testing.T) {
	s := &Server{mailSender: &mail.Sender{}}
	msgs := []sendRequest{
		{To: []mail.Address{{Email: "x@y.com"}}, Subject: "s", TextBody: "b"},                                            // missing from → MISSING_FIELDS
		{From: mail.Address{Email: "a@b.com"}, Subject: "s", TextBody: "b"},                                              // no recipients → MISSING_FIELDS
		{From: mail.Address{Email: "not-an-email"}, To: []mail.Address{{Email: "x@y.com"}}, Subject: "s", TextBody: "b"}, // bad sender → INVALID_SENDER
	}
	b, err := json.Marshal(batchSendRequest{Messages: msgs})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, "/batch", bytes.NewReader(b))
	rec := httptest.NewRecorder()

	s.handleBatchSend(rec, r)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	var resp struct {
		Data batchSendResponse `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	d := resp.Data
	if d.Total != 3 || d.Succeeded != 0 || d.Failed != 3 {
		t.Errorf("tallies = total %d / ok %d / fail %d, want 3/0/3", d.Total, d.Succeeded, d.Failed)
	}
	if len(d.Results) != 3 {
		t.Fatalf("results len = %d, want 3", len(d.Results))
	}
	wantCodes := []string{"MISSING_FIELDS", "MISSING_FIELDS", "INVALID_SENDER"}
	for i, wc := range wantCodes {
		if d.Results[i].Index != i {
			t.Errorf("Results[%d].Index = %d, want %d", i, d.Results[i].Index, i)
		}
		if d.Results[i].Code != wc {
			t.Errorf("Results[%d].Code = %q, want %q", i, d.Results[i].Code, wc)
		}
		if d.Results[i].MessageID != "" {
			t.Errorf("Results[%d].MessageID = %q, want empty on failure", i, d.Results[i].MessageID)
		}
		if d.Results[i].Error == "" {
			t.Errorf("Results[%d].Error is empty, want a message", i)
		}
	}
}

// assertErrorEnvelope checks an httptest recorder carries the expected status and
// the standard {error:{code}} envelope.
func assertErrorEnvelope(t *testing.T, rec *httptest.ResponseRecorder, wantStatus int, wantCode string) {
	t.Helper()
	if rec.Code != wantStatus {
		t.Fatalf("status = %d, want %d", rec.Code, wantStatus)
	}
	var resp apiResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if resp.Error == nil || resp.Error.Code != wantCode {
		t.Fatalf("error envelope = %+v, want code %q", resp.Error, wantCode)
	}
}
