package mail

import (
	"net/url"
	"regexp"
	"strings"
)

// anchorHrefRE matches <a ...> tags and captures the href attribute value.
// Kept deliberately permissive on tag attribute whitespace/ordering; the
// href value itself is captured with either double or single quotes.
var anchorHrefRE = regexp.MustCompile(`(?is)(<a\b[^>]*?\shref\s*=\s*)(?:"([^"]*)"|'([^']*)')([^>]*>)`)

// closingBodyRE finds the closing </body> tag (case-insensitive, allowing
// whitespace) so we can place the open-tracking pixel immediately before it.
var closingBodyRE = regexp.MustCompile(`(?i)</\s*body\s*>`)

// InjectTracking rewrites an HTML body to route link clicks and image opens
// through the Vectis tracking endpoints. Returns the HTML unchanged if tracking
// is disabled or the body is empty.
//
//   - openToken:  HMAC-signed message token from Server.GenerateTrackingToken,
//     embedded in the open pixel (/api/v1/track/open/{openToken}).
//   - baseURL:    public base URL of the Vectis API (e.g. https://mail.example.com), no trailing slash
//   - opens:      when true, appends a 1x1 pixel to /api/v1/track/open/{openToken}
//   - clicks:     when true, rewrites http(s) anchor hrefs via /api/v1/track/click/{token}?url=...
//   - clickToken: mints the per-link click token for a given raw href; the HMAC
//     covers the destination URL so a token can't be reused to
//     redirect elsewhere. Must be non-nil when clicks is true.
//
// Link rewriting skips: mailto:, tel:, sms:, javascript:, fragment (#...)
// anchors, empty hrefs, and URLs already pointing at our own click endpoint.
func InjectTracking(htmlBody, openToken, baseURL string, opens, clicks bool, clickToken func(rawURL string) string) string {
	if htmlBody == "" || baseURL == "" || (!opens && !clicks) {
		return htmlBody
	}
	baseURL = strings.TrimRight(baseURL, "/")

	out := htmlBody
	if clicks && clickToken != nil {
		out = rewriteLinks(out, baseURL, clickToken)
	}
	if opens && openToken != "" {
		out = appendPixel(out, openToken, baseURL)
	}
	return out
}

// rewriteLinks wraps each eligible anchor href in a click-tracking redirect.
// The token is minted per-link via clickToken(href) so that the HMAC covers
// the exact destination URL — a signed token can no longer be reused to
// redirect anywhere else (audit D-M2 open redirect).
func rewriteLinks(html, baseURL string, clickToken func(rawURL string) string) string {
	clickBase := baseURL + "/api/v1/track/click/"
	return anchorHrefRE.ReplaceAllStringFunc(html, func(match string) string {
		sub := anchorHrefRE.FindStringSubmatch(match)
		if len(sub) < 5 {
			return match
		}
		prefix := sub[1]
		href := sub[2]
		quote := `"`
		if href == "" && sub[3] != "" {
			href = sub[3]
			quote = `'`
		}
		suffix := sub[4]

		if !shouldRewriteHref(href, baseURL) {
			return match
		}
		return prefix + quote + clickBase + clickToken(href) + "?url=" + url.QueryEscape(href) + quote + suffix
	})
}

func shouldRewriteHref(href, baseURL string) bool {
	trimmed := strings.TrimSpace(href)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return false
	}
	lower := strings.ToLower(trimmed)
	switch {
	case strings.HasPrefix(lower, "mailto:"),
		strings.HasPrefix(lower, "tel:"),
		strings.HasPrefix(lower, "sms:"),
		strings.HasPrefix(lower, "javascript:"),
		strings.HasPrefix(lower, "data:"):
		return false
	}
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		return false
	}
	// Don't double-wrap links already pointing at our click endpoint.
	if strings.HasPrefix(trimmed, baseURL+"/api/v1/track/click/") {
		return false
	}
	return true
}

func appendPixel(html, token, baseURL string) string {
	pixel := `<img src="` + baseURL + `/api/v1/track/open/` + token +
		`" width="1" height="1" alt="" style="display:none" />`

	if loc := closingBodyRE.FindStringIndex(html); loc != nil {
		return html[:loc[0]] + pixel + html[loc[0]:]
	}
	return html + pixel
}
