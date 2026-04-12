package mail

import "fmt"

// NotificationSender wraps a Sender to send product notification emails.
type NotificationSender struct {
	sender   *Sender
	hostname string
}

// NewNotificationSender creates a NotificationSender.
func NewNotificationSender(sender *Sender, hostname string) *NotificationSender {
	return &NotificationSender{sender: sender, hostname: hostname}
}

func (n *NotificationSender) from() Address {
	return Address{Name: "Vectis Mail", Email: "noreply@" + n.hostname}
}

// SendPasswordReset sends a password reset email with the reset link.
func (n *NotificationSender) SendPasswordReset(toEmail, resetToken string) error {
	resetURL := fmt.Sprintf("https://%s/reset-password?token=%s", n.hostname, resetToken)

	msg := &Message{
		From:    n.from(),
		To:      []Address{{Email: toEmail}},
		Subject: "Password Reset — " + n.hostname,
		TextBody: fmt.Sprintf(`You requested a password reset for your admin account on %s.

Click the link below to set a new password:

  %s

This link expires in 1 hour. If you did not request a reset, ignore this email.

— Vectis Mail Server
`, n.hostname, resetURL),
		HTMLBody: fmt.Sprintf(`<div style="font-family:sans-serif;max-width:520px;margin:0 auto;padding:20px">
<h2 style="color:#1a1a2e">Password Reset</h2>
<p>You requested a password reset for your admin account on <strong>%s</strong>.</p>
<p><a href="%s" style="display:inline-block;background:#4361ee;color:#fff;padding:10px 24px;border-radius:6px;text-decoration:none;font-weight:bold">Reset Password</a></p>
<p style="color:#666;font-size:13px">This link expires in 1 hour. If you did not request a reset, ignore this email.</p>
<hr style="border:none;border-top:1px solid #eee;margin:20px 0">
<p style="color:#999;font-size:12px">Vectis Mail Server &mdash; %s</p>
</div>`, n.hostname, resetURL, n.hostname),
	}

	_, err := n.sender.Send(msg)
	return err
}

// SendDomainVerified sends a confirmation after a domain passes DNS verification.
func (n *NotificationSender) SendDomainVerified(toEmail, domainName string) error {
	dashboardURL := fmt.Sprintf("https://%s/domains", n.hostname)

	msg := &Message{
		From:    n.from(),
		To:      []Address{{Email: toEmail}},
		Subject: fmt.Sprintf("Domain Verified — %s", domainName),
		TextBody: fmt.Sprintf(`Your domain %s has been verified on %s.

DNS ownership has been confirmed. The domain is now fully active for
sending and receiving email.

Manage your domain: %s

— Vectis Mail Server
`, domainName, n.hostname, dashboardURL),
		HTMLBody: fmt.Sprintf(`<div style="font-family:sans-serif;max-width:520px;margin:0 auto;padding:20px">
<h2 style="color:#1a1a2e">Domain Verified &#10003;</h2>
<p>Your domain <strong>%s</strong> has been verified on <strong>%s</strong>.</p>
<p>DNS ownership has been confirmed. The domain is now fully active for sending and receiving email.</p>
<p><a href="%s" style="display:inline-block;background:#4361ee;color:#fff;padding:10px 24px;border-radius:6px;text-decoration:none;font-weight:bold">Manage Domain</a></p>
<hr style="border:none;border-top:1px solid #eee;margin:20px 0">
<p style="color:#999;font-size:12px">Vectis Mail Server &mdash; %s</p>
</div>`, domainName, n.hostname, dashboardURL, n.hostname),
	}

	_, err := n.sender.Send(msg)
	return err
}

// SendBackupComplete notifies admin that a backup finished.
func (n *NotificationSender) SendBackupComplete(toEmail, snapshotPath string, sizeMB int64, durationSecs int) error {
	msg := &Message{
		From:    n.from(),
		To:      []Address{{Email: toEmail}},
		Subject: fmt.Sprintf("Backup Complete — %s", n.hostname),
		TextBody: fmt.Sprintf(`A backup completed successfully on %s.

Snapshot : %s
Size     : %d MB
Duration : %d seconds

— Vectis Mail Server
`, n.hostname, snapshotPath, sizeMB, durationSecs),
	}

	_, err := n.sender.Send(msg)
	return err
}

// SendBackupFailed notifies admin that a backup failed.
func (n *NotificationSender) SendBackupFailed(toEmail, errorMsg string) error {
	msg := &Message{
		From:    n.from(),
		To:      []Address{{Email: toEmail}},
		Subject: fmt.Sprintf("[ALERT] Backup Failed — %s", n.hostname),
		TextBody: fmt.Sprintf(`A backup failed on %s.

Error: %s

Check server logs for details:
  vectis logs api | grep backup

— Vectis Mail Server
`, n.hostname, errorMsg),
	}

	_, err := n.sender.Send(msg)
	return err
}

// SendCertExpiring notifies admin that a TLS certificate is expiring soon.
func (n *NotificationSender) SendCertExpiring(toEmail, domain string, daysLeft int) error {
	msg := &Message{
		From:    n.from(),
		To:      []Address{{Email: toEmail}},
		Subject: fmt.Sprintf("[ALERT] TLS Certificate Expiring — %s", domain),
		TextBody: fmt.Sprintf(`The TLS certificate for %s expires in %d days.

Check certificate status:
  vectis tls status

If using Let's Encrypt, renewal should happen automatically. If it
has not, check the acme.sh logs:
  docker logs vectis-acme

— Vectis Mail Server (%s)
`, domain, daysLeft, n.hostname),
	}

	_, err := n.sender.Send(msg)
	return err
}

// SendUpdateAvailable notifies admin that a Vectis update is available.
func (n *NotificationSender) SendUpdateAvailable(toEmail, currentVersion, newVersion, releaseNotes string) error {
	msg := &Message{
		From:    n.from(),
		To:      []Address{{Email: toEmail}},
		Subject: fmt.Sprintf("Update Available — Vectis %s", newVersion),
		TextBody: fmt.Sprintf(`A new Vectis release is available.

Current : %s
New     : %s

%s

Update via:
  vectis update

— Vectis Mail Server (%s)
`, currentVersion, newVersion, releaseNotes, n.hostname),
	}

	_, err := n.sender.Send(msg)
	return err
}
