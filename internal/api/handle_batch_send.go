package api

import (
	"net/http"

	"github.com/Veltara-Works/vectis/internal/mail"
)

const maxBatchSize = 100

type batchSendRequest struct {
	Messages []sendRequest `json:"messages"`
}

type batchSendResult struct {
	Index     int    `json:"index"`
	MessageID string `json:"message_id,omitempty"`
	Error     string `json:"error,omitempty"`
	Code      string `json:"code,omitempty"`
}

type batchSendResponse struct {
	Total     int               `json:"total"`
	Succeeded int               `json:"succeeded"`
	Failed    int               `json:"failed"`
	Results   []batchSendResult `json:"results"`
}

// handleBatchSend accepts an array of messages and sends each one, returning
// per-message results. Maximum 100 messages per batch.
func (s *Server) handleBatchSend(w http.ResponseWriter, r *http.Request) {
	var req batchSendRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, r, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON request body")
		return
	}

	if len(req.Messages) == 0 {
		respondError(w, r, http.StatusBadRequest, "EMPTY_BATCH", "messages array is required and must not be empty")
		return
	}
	if len(req.Messages) > maxBatchSize {
		respondError(w, r, http.StatusBadRequest, "BATCH_TOO_LARGE",
			"Maximum batch size is 100 messages")
		return
	}

	if s.mailSender == nil {
		respondError(w, r, http.StatusServiceUnavailable, "SEND_UNAVAILABLE",
			"Sending is not configured on this server")
		return
	}

	// Resolve the auth/abuse caller context once for the whole batch, then run
	// each message through the shared sendMessage core (audit finding #156).
	adminID := getAdminID(r.Context())
	adminRole := getAdminRole(r.Context())
	apiKeyID := getAPIKeyID(r.Context())
	ip := clientIP(r)

	resp := batchSendResponse{
		Total:   len(req.Messages),
		Results: make([]batchSendResult, len(req.Messages)),
	}

	for i, msg := range req.Messages {
		out := s.sendMessage(r, msg, adminID, adminRole, apiKeyID, ip,
			sendVariant{auditAction: "mail.batch_send", batch: true})
		resp.Results[i] = batchSendResult{
			Index:     i,
			MessageID: out.messageID,
			Error:     out.message,
			Code:      out.code,
		}
		if out.code == "" {
			resp.Succeeded++
		} else {
			resp.Failed++
		}
	}

	respond(w, r, http.StatusOK, resp)
}

func allRecipients(to, cc, bcc []mail.Address) []string {
	var emails []string
	for _, a := range to {
		emails = append(emails, a.Email)
	}
	for _, a := range cc {
		emails = append(emails, a.Email)
	}
	for _, a := range bcc {
		emails = append(emails, a.Email)
	}
	return emails
}
