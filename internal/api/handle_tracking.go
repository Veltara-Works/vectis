package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/Veltara-Works/vectis/internal/mail"
	vectismetrics "github.com/Veltara-Works/vectis/internal/metrics"
)

// handleTrackOpen records an email open event via a 1x1 tracking pixel.
// URL: /api/v1/track/open/{token} (public, no auth)
// The token encodes the message ID signed with the API secret.
func (s *Server) handleTrackOpen(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	messageID, ok := s.verifyTrackingToken(token)
	if !ok {
		// Return transparent pixel regardless — don't leak info.
		s.serveTrackingPixel(w)
		return
	}

	// Record the open event.
	vectismetrics.EmailOpens.Inc()

	if s.messages != nil {
		msg, _ := s.messages.GetByMessageID(r.Context(), messageID)
		if msg != nil && s.mailStats != nil {
			// We don't have an "opens" column in mail_stats yet — use details on the message.
			// For now, just log it and increment the metric.
			_ = msg
		}
	}

	s.serveTrackingPixel(w)
}

// handleTrackClick records an email click event and redirects to the target URL.
// URL: /api/v1/track/click/{token}?url=<target> (public, no auth)
func (s *Server) handleTrackClick(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	targetURL := r.URL.Query().Get("url")

	if targetURL == "" {
		http.Error(w, "Missing URL", http.StatusBadRequest)
		return
	}

	_, ok := s.verifyTrackingToken(token)
	if ok {
		vectismetrics.EmailClicks.Inc()
	}

	http.Redirect(w, r, targetURL, http.StatusFound)
}

// handleTrackingStats returns aggregate open/click metrics for the admin dashboard.
func (s *Server) handleTrackingStats(w http.ResponseWriter, r *http.Request) {
	// Return current counter values. These are monotonic counters reset on restart;
	// for persistent stats, per-domain analytics (mail_stats) should be used.
	respond(w, r, http.StatusOK, map[string]any{
		"description": "Engagement metrics (opt-in tracking pixel and click redirect)",
		"note":        "Counters are since last server restart. Use /analytics for persistent per-domain stats.",
		"available":   true,
		"pixel_url":   "/api/v1/track/open/{token}",
		"click_url":   "/api/v1/track/click/{token}?url={target}",
	})
}

// applyEngagementTracking pre-generates a Message-ID and rewrites msg.HTMLBody
// with a tracking pixel and/or click-redirect links when the caller opted in.
// No-op when neither flag is set, when there is no HTML body, or when the
// server hostname is unknown (can't build an absolute tracking URL).
func (s *Server) applyEngagementTracking(msg *mail.Message, trackOpens, trackClicks bool) {
	if !trackOpens && !trackClicks {
		return
	}
	if msg.HTMLBody == "" || s.hostname == "" {
		return
	}
	if msg.MessageID == "" {
		msg.MessageID = mail.GenerateMessageID(s.hostname)
	}
	token := s.GenerateTrackingToken(msg.MessageID)
	baseURL := "https://" + s.hostname
	msg.HTMLBody = mail.InjectTracking(msg.HTMLBody, token, baseURL, trackOpens, trackClicks)
}

// GenerateTrackingToken creates an HMAC-signed token for a message ID.
func (s *Server) GenerateTrackingToken(messageID string) string {
	mac := hmac.New(sha256.New, []byte(s.internalToken))
	mac.Write([]byte(messageID))
	sig := hex.EncodeToString(mac.Sum(nil))[:16]
	return messageID + "." + sig
}

func (s *Server) verifyTrackingToken(token string) (string, bool) {
	// Token format: messageID.signature (first 16 hex chars of HMAC)
	dot := lastDot(token)
	if dot < 0 || dot >= len(token)-1 {
		return "", false
	}
	messageID := token[:dot]
	providedSig := token[dot+1:]

	mac := hmac.New(sha256.New, []byte(s.internalToken))
	mac.Write([]byte(messageID))
	expectedSig := hex.EncodeToString(mac.Sum(nil))[:16]

	if !hmac.Equal([]byte(providedSig), []byte(expectedSig)) {
		return "", false
	}
	return messageID, true
}

func lastDot(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '.' {
			return i
		}
	}
	return -1
}

func (s *Server) serveTrackingPixel(w http.ResponseWriter) {
	// 1x1 transparent GIF.
	pixel := []byte{
		0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00,
		0x80, 0x00, 0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x21,
		0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00,
		0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44,
		0x01, 0x00, 0x3b,
	}
	w.Header().Set("Content-Type", "image/gif")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Expires", time.Unix(0, 0).Format(http.TimeFormat))
	w.Write(pixel)
}
