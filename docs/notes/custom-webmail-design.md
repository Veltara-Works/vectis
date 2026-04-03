# Custom Webmail — Future Design Notes

> **Status**: Design reference for future implementation (Phase 3+)
> **Current**: Roundcube handles webmail in Phase 2A
> **Goal**: Replace Roundcube with a bespoke Go+React webmail for competitive advantage

## Why Custom

Roundcube is functional but not a differentiator. A modern, fast, branded webmail
built into Vectis would:

1. **Eliminate PHP dependency** — pure Go+React stack, consistent with the rest of Vectis
2. **Unified auth** — share admin sessions, OIDC SSO, and Vectis RBAC seamlessly
3. **Full branding** — deep customisation per tenant (Phase 4 multi-tenant)
4. **Performance** — Go IMAP proxy with connection pooling beats PHP per-request IMAP
5. **Feature integration** — sending API, Sieve filters, deliverability, all in one UI
6. **Mobile-first** — modern React SPA with offline support (service worker)

## Architecture

```
┌──────────────┐       ┌───────────────────┐       ┌──────────────┐
│  React SPA   │──────▶│  Go Mail API      │──────▶│  Dovecot     │
│  (webmail)   │  WS   │  (IMAP proxy)     │ IMAP  │  (IMAPS:993) │
│              │◀──────│                   │◀──────│              │
└──────────────┘       │  - Connection pool │       └──────────────┘
                       │  - MIME parsing    │
                       │  - HTML sanitize   │       ┌──────────────┐
                       │  - Search index    │──────▶│  Postfix     │
                       │  - Draft autosave  │ SMTP  │  (587)       │
                       └───────────────────┘       └──────────────┘
```

### Go Mail API (new binary or extend vectis-api)

**Option A — Extend vectis-api**: Add `/api/v1/mail/*` endpoints to the existing Go API.
Pros: single binary, shared auth, no new container. Cons: larger binary, IMAP connections
tied to API process lifecycle.

**Option B — Separate vectis-mail-api**: Dedicated container for mail operations.
Pros: independent scaling, failure isolation. Cons: another container, auth delegation.

**Recommendation**: Option A for MVP (fewer moving parts), extract to Option B if needed.

### Key Libraries

| Library | Purpose | Maturity |
|---|---|---|
| `emersion/go-imap` v2 | IMAP client (IMAP4rev2) | Production-grade, actively maintained |
| `emersion/go-message` | MIME parsing, RFC 5322 | Companion to go-imap |
| `emersion/go-smtp` | SMTP client for sending | Production-grade |
| `microcosm-cc/bluemonday` | HTML sanitisation | Standard Go HTML sanitiser |
| `blevesearch/bleve` | Full-text search index | Embedded search engine |

### IMAP Connection Pooling

```go
// Per-user connection pool. Key = adminID or mailboxID.
// Connections authenticated via Dovecot master user or direct credentials.
type IMAPPool struct {
    mu    sync.Mutex
    conns map[string]*pooledConn
}

type pooledConn struct {
    client  *imapclient.Client
    lastUse time.Time
    userID  string
}
```

- Pool idle connections for 5 minutes (configurable)
- Max 3 connections per user (LIST, FETCH, IDLE)
- One persistent IDLE connection per active user for push notifications

### Authentication Options

1. **Dovecot master user**: API authenticates as `user*masteruser` with a shared secret.
   No need to store user passwords. Cleanest integration.
2. **Direct IMAP auth**: API proxies user credentials to Dovecot on each session.
   Simpler but requires credential caching.
3. **Vectis session**: If webmail is embedded in vectis-api, reuse the existing
   session system. Map admin sessions to mail identities via the database.

**Recommendation**: Dovecot master user — avoids password handling entirely.

## API Design

### Endpoints

```
GET    /api/v1/mail/folders              List IMAP folders
GET    /api/v1/mail/folders/{id}/messages List messages (paginated)
GET    /api/v1/mail/messages/{uid}        Get full message (headers + body)
GET    /api/v1/mail/messages/{uid}/raw    Get raw RFC 5322 message
POST   /api/v1/mail/messages/send         Compose and send
POST   /api/v1/mail/messages/draft        Save draft
DELETE /api/v1/mail/messages/{uid}        Move to trash / expunge
PATCH  /api/v1/mail/messages/{uid}/flags  Set/unset flags (read, starred, etc.)
POST   /api/v1/mail/messages/move         Move between folders
GET    /api/v1/mail/search                Full-text search

WebSocket /api/v1/mail/events             Real-time push (new mail, flag changes)
```

### Message Format (JSON)

```json
{
  "uid": 12345,
  "folder": "INBOX",
  "from": {"name": "Jane Smith", "email": "jane@example.com"},
  "to": [{"name": "John", "email": "john@example.com"}],
  "subject": "Re: Project update",
  "date": "2026-04-03T10:30:00Z",
  "flags": ["\\Seen"],
  "size": 4521,
  "has_attachments": true,
  "snippet": "Thanks for the update. I've reviewed the...",
  "body_html": "<sanitised HTML>",
  "body_text": "plain text fallback",
  "attachments": [
    {"filename": "report.pdf", "content_type": "application/pdf", "size": 102400}
  ]
}
```

## React Frontend

### Tech Stack
- React 18+ with TypeScript
- TanStack Query for data fetching / caching
- Zustand for UI state (selected folder, message, compose window)
- Tiptap for rich text compose editor
- Bundled alongside existing admin UI (same `web/` directory, different routes)

### Key Screens
1. **Inbox / folder view** — message list with preview pane (responsive: side/bottom/none)
2. **Message viewer** — sanitised HTML rendering, attachment download
3. **Compose** — rich text editor, attachments, CC/BCC, draft autosave
4. **Folder management** — create/rename/delete IMAP folders
5. **Sieve filters** — visual filter rule builder (reuse Phase 2A.5 work)
6. **Settings** — identity management, vacation auto-reply, signature

### Routing
```
/webmail                    Inbox (default folder)
/webmail/folder/:name       Specific folder
/webmail/message/:uid       Message viewer
/webmail/compose            New message
/webmail/compose?reply=:uid Reply
/webmail/settings           User settings
```

## Effort Estimate

| Component | Effort | Notes |
|---|---|---|
| Go IMAP proxy + connection pool | 2-3 weeks | go-imap v2 does the heavy lifting |
| MIME parsing + HTML sanitisation | 1-2 weeks | go-message + bluemonday |
| REST API endpoints | 2 weeks | Standard CRUD + pagination |
| WebSocket push (IDLE) | 1 week | Single IDLE connection per user |
| React message list + viewer | 2-3 weeks | Responsive, virtualized list |
| Compose editor + attachments | 2-3 weeks | Tiptap, multipart MIME |
| Search (bleve integration) | 1-2 weeks | Index on first access, incremental |
| Sieve filter UI | 1 week | Reuse ManageSieve protocol work |
| Testing + polish | 2-3 weeks | Edge cases, mobile, accessibility |
| **Total** | **14-20 weeks** | ~3.5-5 months, one developer |

## Migration Path: Roundcube → Custom

1. Deploy custom webmail alongside Roundcube at `/webmail-beta`
2. Feature-flag users to opt in
3. Monitor for parity issues (missing features, rendering bugs)
4. Once parity confirmed, swap routes: `/webmail` → custom, `/webmail-classic` → Roundcube
5. Deprecate and remove Roundcube container

## Decision Criteria for Starting Custom Webmail

Start this work when:
- Phase 2B (Sending API) is complete — custom webmail needs the send endpoint
- Vectis has paying users who request a better webmail experience
- A full-time frontend developer is available (this is not a side project)

Do NOT start this work if:
- Roundcube is meeting user needs
- Phase 2B or 3 (clustering) is still incomplete
- Team bandwidth is limited — core mail server stability comes first
