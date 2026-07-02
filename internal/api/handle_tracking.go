package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/Veltara-Works/vectis/internal/mail"
	vectismetrics "github.com/Veltara-Works/vectis/internal/metrics"
	"github.com/Veltara-Works/vectis/internal/repository"
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

	vectismetrics.EmailOpens.Inc()
	s.recordEngagement(r, messageID, "open", "")
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

	// The token's HMAC covers messageID + the exact target URL, so a token
	// captured from a real tracked email cannot be reused to redirect to a
	// different destination (audit D-M2 open redirect). Forged/expired tokens
	// and any tampering with the url query param fail verification and never
	// redirect.
	messageID, ok := s.verifyClickToken(token, targetURL)
	if !ok {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	// Only follow http(s) targets — blocks javascript:/data: redirect payloads.
	if u, err := url.Parse(targetURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		http.Error(w, "Invalid redirect target", http.StatusBadRequest)
		return
	}

	vectismetrics.EmailClicks.Inc()
	s.recordEngagement(r, messageID, "click", targetURL)
	http.Redirect(w, r, targetURL, http.StatusFound)
}

// recordEngagement persists an open/click event. It looks up the message to
// resolve the domain_id; if the message is unknown (expired, never stored, or
// test token), the insert is skipped. Silent on errors — tracking must never
// block pixel/redirect response.
func (s *Server) recordEngagement(r *http.Request, messageID, eventType, targetURL string) {
	// Engagement tracking is opt-in (GDPR): record nothing unless the operator
	// has enabled it. The pixel/redirect still function regardless (P5-H2).
	if s.cfg == nil || !s.cfg.Tracking.Enabled {
		return
	}
	if s.emailEvents == nil || s.messages == nil {
		return
	}
	msg, _ := s.messages.GetByMessageID(r.Context(), messageID)
	if msg == nil {
		return
	}
	ev := &repository.EmailEvent{
		DomainID:  msg.DomainID,
		MessageID: messageID,
	}
	ev.EventType = eventType
	if targetURL != "" {
		ev.TargetURL = &targetURL
	}
	if ua := r.Header.Get("User-Agent"); ua != "" {
		ev.UserAgent = &ua
	}
	if ip := trackingClientIP(r); ip != "" {
		ev.IPAddress = &ip
	}
	_ = s.emailEvents.Create(r.Context(), ev)
}

// trackingClientIP extracts the client IP for engagement tracking, honoring
// X-Forwarded-For since Traefik sits in front of the API. Unlike the shared
// clientIP helper, XFF matters here so we record the real recipient's IP
// rather than the reverse proxy.
func trackingClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if xr := r.Header.Get("X-Real-IP"); xr != "" {
		return strings.TrimSpace(xr)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// handleTrackingStats returns aggregate open/click metrics for a domain over a
// time range. Query params: domain_id (required), period (1h, 24h, 7d, 30d).
func (s *Server) handleTrackingStats(w http.ResponseWriter, r *http.Request) {
	domainID := r.URL.Query().Get("domain_id")
	if domainID == "" {
		respondError(w, r, http.StatusBadRequest, "MISSING_DOMAIN_ID", "domain_id query parameter is required")
		return
	}
	if !s.canAccessDomain(r.Context(), domainID) {
		respondError(w, r, http.StatusForbidden, "FORBIDDEN", "You do not have access to this domain")
		return
	}

	period := r.URL.Query().Get("period")
	if period == "" {
		period = "24h"
	}
	now := time.Now().UTC()
	var from time.Time
	switch period {
	case "1h":
		from = now.Add(-1 * time.Hour)
	case "24h":
		from = now.Add(-24 * time.Hour)
	case "7d":
		from = now.Add(-7 * 24 * time.Hour)
	case "30d":
		from = now.Add(-30 * 24 * time.Hour)
	default:
		respondError(w, r, http.StatusBadRequest, "INVALID_PERIOD", "Valid periods: 1h, 24h, 7d, 30d")
		return
	}

	agg, err := s.emailEvents.GetDomainEngagement(r.Context(), domainID, from, now)
	if err != nil {
		s.logger.Error("get domain engagement failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get engagement stats")
		return
	}

	respond(w, r, http.StatusOK, map[string]any{
		"domain_id": domainID,
		"period":    period,
		"from":      from,
		"to":        now,
		"opens":     agg.Opens,
		"clicks":    agg.Clicks,
		"messages_opened":  agg.MessagesOpened,
		"messages_clicked": agg.MessagesClicked,
	})
}

// handleMessageEngagement returns aggregate open/click counts for a single message.
// URL: /tracking/messages/{messageID}
func (s *Server) handleMessageEngagement(w http.ResponseWriter, r *http.Request) {
	messageID := chi.URLParam(r, "messageID")
	if messageID == "" {
		respondError(w, r, http.StatusBadRequest, "MISSING_MESSAGE_ID", "messageID is required")
		return
	}

	msg, err := s.messages.GetByMessageID(r.Context(), messageID)
	if err != nil {
		s.logger.Error("lookup message failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to look up message")
		return
	}
	if msg == nil {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "Message not found")
		return
	}
	if !s.canAccessDomain(r.Context(), msg.DomainID) {
		respondError(w, r, http.StatusForbidden, "FORBIDDEN", "You do not have access to this message")
		return
	}

	eng, err := s.emailEvents.GetMessageEngagement(r.Context(), messageID)
	if err != nil {
		s.logger.Error("get message engagement failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get engagement")
		return
	}
	respond(w, r, http.StatusOK, eng)
}

// handleMessageEngagementEvents returns the raw event list for a single message.
// URL: /tracking/messages/{messageID}/events
func (s *Server) handleMessageEngagementEvents(w http.ResponseWriter, r *http.Request) {
	messageID := chi.URLParam(r, "messageID")
	if messageID == "" {
		respondError(w, r, http.StatusBadRequest, "MISSING_MESSAGE_ID", "messageID is required")
		return
	}

	msg, err := s.messages.GetByMessageID(r.Context(), messageID)
	if err != nil {
		s.logger.Error("lookup message failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to look up message")
		return
	}
	if msg == nil {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "Message not found")
		return
	}
	if !s.canAccessDomain(r.Context(), msg.DomainID) {
		respondError(w, r, http.StatusForbidden, "FORBIDDEN", "You do not have access to this message")
		return
	}

	events, err := s.emailEvents.ListByMessage(r.Context(), messageID, 200)
	if err != nil {
		s.logger.Error("list message events failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list events")
		return
	}
	respond(w, r, http.StatusOK, map[string]any{
		"message_id": messageID,
		"events":     events,
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
	openToken := s.GenerateTrackingToken(msg.MessageID)
	baseURL := "https://" + s.hostname
	messageID := msg.MessageID
	clickToken := func(rawURL string) string {
		return s.GenerateClickToken(messageID, rawURL)
	}
	msg.HTMLBody = mail.InjectTracking(msg.HTMLBody, openToken, baseURL, trackOpens, trackClicks, clickToken)
}

// GenerateTrackingToken creates an HMAC-signed token for a message ID. Used for
// the open pixel, where the message ID is the only bound value.
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

// clickMAC computes the HMAC over messageID + a domain-separator byte + the
// exact redirect URL. The separator prevents an open-pixel token (message ID
// only) from ever being accepted as a click token, and vice versa.
func (s *Server) clickMAC(messageID, rawURL string) string {
	mac := hmac.New(sha256.New, []byte(s.internalToken))
	mac.Write([]byte(messageID))
	mac.Write([]byte{0})
	mac.Write([]byte(rawURL))
	return hex.EncodeToString(mac.Sum(nil))[:16]
}

// GenerateClickToken creates an HMAC-signed token binding a message ID to a
// specific redirect URL, so the click endpoint can refuse any url that wasn't
// signed for this exact link (audit D-M2 open redirect).
func (s *Server) GenerateClickToken(messageID, rawURL string) string {
	return messageID + "." + s.clickMAC(messageID, rawURL)
}

// verifyClickToken validates a click token against the URL actually requested.
// It returns the bound message ID only when the signature covers exactly this
// messageID + rawURL pair.
func (s *Server) verifyClickToken(token, rawURL string) (string, bool) {
	dot := lastDot(token)
	if dot < 0 || dot >= len(token)-1 {
		return "", false
	}
	messageID := token[:dot]
	providedSig := token[dot+1:]

	expectedSig := s.clickMAC(messageID, rawURL)
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
