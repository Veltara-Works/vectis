package mail

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"
)

// maxSieveScriptSize bounds how many octets GetScript will allocate/read for a
// GETSCRIPT literal response. Matches the API's maxBodySize (1 MiB) that caps
// the write path, and comfortably exceeds Dovecot's default sieve_max_script_size.
const maxSieveScriptSize = 1 << 20

// SieveClient manages Sieve filter rules via the ManageSieve protocol (RFC 5804).
// Connects to Dovecot's ManageSieve service on the internal network.
type SieveClient struct {
	host   string // e.g. "vectis-dovecot"
	port   string // e.g. "4190"
	logger *slog.Logger
}

// SieveScript represents a named Sieve filter script.
type SieveScript struct {
	Name   string `json:"name"`
	Active bool   `json:"active"`
}

// NewSieveClient creates a new ManageSieve client.
func NewSieveClient(host, port string, logger *slog.Logger) *SieveClient {
	return &SieveClient{host: host, port: port, logger: logger}
}

// ListScripts returns all Sieve scripts for the given user.
func (c *SieveClient) ListScripts(user, password string) ([]SieveScript, error) {
	conn, reader, err := c.connect(user, password)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if _, err := fmt.Fprintf(conn, "LISTSCRIPTS\r\n"); err != nil {
		return nil, fmt.Errorf("send LISTSCRIPTS: %w", err)
	}

	var scripts []SieveScript
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("read LISTSCRIPTS: %w", err)
		}
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "OK") {
			break
		}
		if strings.HasPrefix(line, "NO") {
			return nil, fmt.Errorf("LISTSCRIPTS failed: %s", line)
		}

		// Format: "scriptname" [ACTIVE]
		if strings.HasPrefix(line, "\"") {
			name := extractQuoted(line)
			active := strings.Contains(line, "ACTIVE")
			scripts = append(scripts, SieveScript{Name: name, Active: active})
		}
	}
	return scripts, nil
}

// validateSieveName rejects script names that can't be safely interpolated into
// a ManageSieve quoted-string. The name reaches these commands from a JSON body
// or a URL path segment and is written as `"<name>"`; without validation a `"`,
// `\` or CRLF would break out of the quoted string and inject a second command
// (MAIL-1). ManageSieve script names are short UTF-8 labels, so we allow any
// printable rune except the quote/backslash and reject control characters
// (incl. CR/LF) and over-long names. This closes the injection without
// restricting legitimate names (a real name never contains those bytes).
func validateSieveName(name string) error {
	if name == "" {
		return fmt.Errorf("sieve script name must not be empty")
	}
	if len(name) > 128 {
		return fmt.Errorf("sieve script name too long (max 128 bytes)")
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f || r == '"' || r == '\\' {
			return fmt.Errorf("sieve script name contains an invalid character")
		}
	}
	return nil
}

// GetScript returns the content of a named Sieve script.
func (c *SieveClient) GetScript(user, password, name string) (string, error) {
	if err := validateSieveName(name); err != nil {
		return "", err
	}
	conn, reader, err := c.connect(user, password)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	if _, err := fmt.Fprintf(conn, "GETSCRIPT \"%s\"\r\n", name); err != nil {
		return "", fmt.Errorf("send GETSCRIPT: %w", err)
	}

	// First line is a ManageSieve literal length header: {N} or {N+} (RFC 5804
	// §4.5). It tells us exactly how many octets of script content follow, before
	// the terminating "OK" line.
	firstLine, ferr := reader.ReadString('\n')
	firstLine = strings.TrimSpace(firstLine)
	if firstLine == "" {
		// Nothing came back (truncated response / closed connection). Don't fall
		// through to the fallback loop, which would return "" as a false success.
		return "", fmt.Errorf("GETSCRIPT: empty response: %w", ferr)
	}
	if strings.HasPrefix(firstLine, "NO") {
		return "", fmt.Errorf("GETSCRIPT failed: %s", firstLine)
	}

	if n, ok := parseSieveLiteral(firstLine); ok {
		// Reject an implausible literal length before allocating (defence in
		// depth against a buggy/hostile server — the box has an OOM history).
		// The write path caps a whole PUTSCRIPT JSON body at maxBodySize (1 MiB),
		// so a legitimately-stored script is always smaller than this.
		if n > maxSieveScriptSize {
			return "", fmt.Errorf("GETSCRIPT literal too large: %d bytes (max %d)", n, maxSieveScriptSize)
		}
		// Read exactly N octets. Reading "until a line == OK" (the previous
		// approach) silently truncated any script whose body contained a line
		// that was literally `OK` (MAIL-6). The literal count is authoritative.
		buf := make([]byte, n)
		if _, err := io.ReadFull(reader, buf); err != nil {
			return "", fmt.Errorf("read GETSCRIPT literal (%d bytes): %w", n, err)
		}
		// The connection is closed by the deferred conn.Close(); the trailing
		// CRLF + "OK" framing after the literal doesn't need draining.
		return string(buf), nil
	}

	// Fallback: no literal header (defensive — non-conformant server / test
	// stub). Read until the OK line as before.
	var content strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "OK" || strings.HasPrefix(trimmed, "OK ") {
			break
		}
		content.WriteString(line)
	}
	return strings.TrimSpace(content.String()), nil
}

// parseSieveLiteral parses a ManageSieve literal length header of the form
// `{N}` or `{N+}` (RFC 5804 non-synchronizing literal) and returns N. The
// second return is false when the line is not a literal header at all.
func parseSieveLiteral(line string) (int, bool) {
	if !strings.HasPrefix(line, "{") || !strings.HasSuffix(line, "}") {
		return 0, false
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(line, "{"), "}")
	inner = strings.TrimSuffix(inner, "+") // non-synchronizing literal marker
	n, err := strconv.Atoi(inner)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// PutScript uploads or replaces a Sieve script.
func (c *SieveClient) PutScript(user, password, name, content string) error {
	if err := validateSieveName(name); err != nil {
		return err
	}
	conn, reader, err := c.connect(user, password)
	if err != nil {
		return err
	}
	defer conn.Close()

	// PUTSCRIPT "name" {size+}\r\ncontent\r\n
	if _, err := fmt.Fprintf(conn, "PUTSCRIPT \"%s\" {%d+}\r\n%s\r\n", name, len(content), content); err != nil {
		return fmt.Errorf("send PUTSCRIPT: %w", err)
	}

	resp, _ := reader.ReadString('\n')
	resp = strings.TrimSpace(resp)
	if !strings.HasPrefix(resp, "OK") {
		return fmt.Errorf("PUTSCRIPT failed: %s", resp)
	}
	return nil
}

// SetActive activates a named script (deactivates any previously active script).
func (c *SieveClient) SetActive(user, password, name string) error {
	if err := validateSieveName(name); err != nil {
		return err
	}
	conn, reader, err := c.connect(user, password)
	if err != nil {
		return err
	}
	defer conn.Close()

	if _, err := fmt.Fprintf(conn, "SETACTIVE \"%s\"\r\n", name); err != nil {
		return fmt.Errorf("send SETACTIVE: %w", err)
	}

	resp, _ := reader.ReadString('\n')
	resp = strings.TrimSpace(resp)
	if !strings.HasPrefix(resp, "OK") {
		return fmt.Errorf("SETACTIVE failed: %s", resp)
	}
	return nil
}

// DeleteScript removes a named script.
func (c *SieveClient) DeleteScript(user, password, name string) error {
	if err := validateSieveName(name); err != nil {
		return err
	}
	conn, reader, err := c.connect(user, password)
	if err != nil {
		return err
	}
	defer conn.Close()

	if _, err := fmt.Fprintf(conn, "DELETESCRIPT \"%s\"\r\n", name); err != nil {
		return fmt.Errorf("send DELETESCRIPT: %w", err)
	}

	resp, _ := reader.ReadString('\n')
	resp = strings.TrimSpace(resp)
	if !strings.HasPrefix(resp, "OK") {
		return fmt.Errorf("DELETESCRIPT failed: %s", resp)
	}
	return nil
}

func (c *SieveClient) connect(user, password string) (net.Conn, *bufio.Reader, error) {
	addr := net.JoinHostPort(c.host, c.port)
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, nil, fmt.Errorf("dial managesieve %s: %w", addr, err)
	}

	reader := bufio.NewReader(conn)

	// Read server greeting (multi-line, ends with OK).
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			conn.Close()
			return nil, nil, fmt.Errorf("read greeting: %w", err)
		}
		if strings.HasPrefix(strings.TrimSpace(line), "OK") {
			break
		}
	}

	// AUTHENTICATE PLAIN.
	authStr := fmt.Sprintf("\x00%s\x00%s", user, password)
	encoded := encodeBase64([]byte(authStr))
	if _, err := fmt.Fprintf(conn, "AUTHENTICATE \"PLAIN\" \"%s\"\r\n", encoded); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("send AUTHENTICATE: %w", err)
	}

	resp, _ := reader.ReadString('\n')
	resp = strings.TrimSpace(resp)
	if !strings.HasPrefix(resp, "OK") {
		conn.Close()
		return nil, nil, fmt.Errorf("authentication failed: %s", resp)
	}

	return conn, reader, nil
}

func extractQuoted(s string) string {
	start := strings.Index(s, "\"")
	if start < 0 {
		return ""
	}
	end := strings.Index(s[start+1:], "\"")
	if end < 0 {
		return ""
	}
	return s[start+1 : start+1+end]
}

func encodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}
