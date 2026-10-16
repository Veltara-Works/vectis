package api

import (
	"context"
	"os"
	"strings"

	vectismetrics "github.com/Veltara-Works/vectis/internal/metrics"
	"github.com/Veltara-Works/vectis/internal/policy"
)

// policyBackend adapts the API server's repositories and abuse detector to the
// policy.Backend interface, so the Postfix submission policy server enforces the
// same per-mailbox send-suspend + rate-limit controls as the HTTP send path
// (handle_send.go). See internal/policy and vectis-private issue #5.
type policyBackend struct {
	s *Server
}

// ResolveLogin maps a SASL login (full email) to its mailbox + domain IDs,
// mirroring how the send handler resolves a sender. A login for a domain or
// mailbox this server doesn't manage returns found=false (no error), so the
// policy server lets it pass rather than tempfailing.
func (b policyBackend) ResolveLogin(ctx context.Context, login string) (mailboxID, domainID string, found bool, err error) {
	local := extractLocalPart(login)
	dom := extractDomain(login)
	if local == "" || dom == "" {
		return "", "", false, nil
	}
	domain, err := b.s.domains.GetByName(ctx, dom)
	if err != nil {
		return "", "", false, err
	}
	if domain == nil {
		return "", "", false, nil
	}
	mailbox, err := b.s.mailboxes.GetByEmail(ctx, domain.ID, local)
	if err != nil {
		return "", "", false, err
	}
	if mailbox == nil {
		return "", "", false, nil
	}
	return mailbox.ID, domain.ID, true, nil
}

func (b policyBackend) IsMailboxSuspended(ctx context.Context, mailboxID string) (bool, string, error) {
	return b.s.abuseEvents.IsMailboxSuspended(ctx, mailboxID)
}

func (b policyBackend) CheckAndRecord(ctx context.Context, mailboxID, domainID string) (bool, string, int64, error) {
	if b.s.abuseDetector == nil {
		return true, "", 0, nil
	}
	res, err := b.s.abuseDetector.CheckAndRecord(ctx, mailboxID, domainID)
	if err != nil {
		return true, "", 0, err
	}
	return res.Allowed, res.Reason, res.MailboxCount, nil
}

// AutoSuspend mirrors the auto-suspend branch of handle_send: flip
// send_suspended, log a critical abuse event, bump the metric. Best-effort.
func (b policyBackend) AutoSuspend(ctx context.Context, mailboxID, domainID, reason string, hourly int64) {
	if err := b.s.abuseEvents.SuspendMailbox(ctx, mailboxID, reason); err != nil {
		b.s.logger.Error("policy: auto-suspend failed", "mailbox_id", mailboxID, "error", err)
		return
	}
	action := "suspend"
	b.s.abuseEvents.LogEvent(ctx, &domainID, &mailboxID, "auto_suspend", "critical",
		map[string]any{"reason": reason, "hourly_count": hourly, "path": "submission"}, &action)
	vectismetrics.EmailsSendSuspended.Inc()
}

// StartPolicyServer starts the Postfix submission access-policy server. It
// listens on an internal TCP port (default :10099) that the submission/smtps
// services reach via check_policy_service; Postfix shares the vectis-data
// network with the api container and resolves it as vectis-api.
//
// Configuration via env (all optional):
//   - VECTIS_POLICY_LISTEN   listen address, default ":10099"; "off"/"disabled" disables
//   - VECTIS_POLICY_RATELIMIT "false" to enforce only the explicit suspend flag (no rate-limit)
//   - VECTIS_POLICY_FAILOPEN  "false" to tempfail (451) on backend errors instead of failing open
func (s *Server) StartPolicyServer() {
	addr := os.Getenv("VECTIS_POLICY_LISTEN")
	if addr == "" {
		addr = ":10099"
	}
	if strings.EqualFold(addr, "off") || strings.EqualFold(addr, "disabled") {
		s.logger.Info("submission policy server disabled via VECTIS_POLICY_LISTEN")
		return
	}

	s.policyServer = policy.New(policyBackend{s: s}, policy.Config{
		ListenAddr: addr,
		Hostname:   s.hostname,
		RateLimit:  os.Getenv("VECTIS_POLICY_RATELIMIT") != "false",
		FailOpen:   os.Getenv("VECTIS_POLICY_FAILOPEN") != "false",
		OnReject: func(reason string) {
			vectismetrics.SubmissionPolicyRejects.WithLabelValues(reason).Inc()
		},
	}, s.logger.With("component", "submission-policy"))

	if err := s.policyServer.Start(); err != nil {
		s.logger.Error("failed to start submission policy server", "error", err)
	}
}

// StopPolicyServer drains the policy server on shutdown.
func (s *Server) StopPolicyServer() {
	if s.policyServer != nil {
		s.policyServer.Stop()
	}
}
