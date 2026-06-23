package scim

import (
	"fmt"
	"strings"
	"time"

	"github.com/Veltara-Works/vectis/internal/repository"
)

// MailboxToUser maps a Vectis mailbox to a SCIM User resource. domainName is the
// mailbox's domain (mailboxes only store domain_id); baseURL is the install's
// public base (cfg.CallbackBaseURL) used to build the absolute meta.location.
func MailboxToUser(m *repository.Mailbox, domainName, baseURL string) User {
	userName := m.LocalPart + "@" + domainName
	u := User{
		Schemas:  []string{UserSchema},
		ID:       m.ID,
		UserName: userName,
		Active:   m.Active,
		Emails:   []Email{{Value: userName, Primary: true}},
		Meta: Meta{
			ResourceType: ResourceTypeUser,
			Created:      m.CreatedAt.UTC().Format(time.RFC3339),
			LastModified: m.UpdatedAt.UTC().Format(time.RFC3339),
			Location:     strings.TrimRight(baseURL, "/") + "/scim/v2/Users/" + m.ID,
		},
	}
	if m.ExternalID != nil {
		u.ExternalID = *m.ExternalID
	}
	if m.DisplayName != nil && *m.DisplayName != "" {
		u.DisplayName = *m.DisplayName
		u.Name = &Name{Formatted: *m.DisplayName}
	}
	return u
}

// SplitUserName splits a SCIM userName ("local@domain") into its local part and
// domain. It rejects values without exactly the local@domain shape (empty local
// part, empty domain, or no "@"). The domain split uses the last "@".
func SplitUserName(userName string) (localPart, domain string, err error) {
	at := strings.LastIndex(userName, "@")
	if at <= 0 || at >= len(userName)-1 {
		return "", "", fmt.Errorf("invalid userName %q: expected local@domain", userName)
	}
	return userName[:at], userName[at+1:], nil
}
