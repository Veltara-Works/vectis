package mail

import (
	"strings"
	"testing"
)

const testBase = "https://mail.example.com"
const testToken = "abc123.deadbeef00001111"

func TestInjectTracking_NoopWhenDisabled(t *testing.T) {
	html := `<html><body><a href="https://x.example/">x</a></body></html>`
	got := InjectTracking(html, testToken, testBase, false, false)
	if got != html {
		t.Fatalf("expected no change, got %q", got)
	}
}

func TestInjectTracking_NoopWhenEmpty(t *testing.T) {
	if got := InjectTracking("", testToken, testBase, true, true); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}

func TestInjectTracking_NoopWhenMissingToken(t *testing.T) {
	html := `<p>hi</p>`
	if got := InjectTracking(html, "", testBase, true, true); got != html {
		t.Fatalf("expected unchanged without token, got %q", got)
	}
}

func TestInjectTracking_AppendsPixelBeforeBody(t *testing.T) {
	html := `<html><body><p>hi</p></body></html>`
	got := InjectTracking(html, testToken, testBase, true, false)
	wantPixel := `<img src="https://mail.example.com/api/v1/track/open/` + testToken + `"`
	if !strings.Contains(got, wantPixel) {
		t.Fatalf("missing pixel: %q", got)
	}
	// Pixel must be before the closing body tag.
	if idx := strings.Index(got, wantPixel); idx == -1 || idx > strings.Index(got, "</body>") {
		t.Fatalf("pixel not before </body>: %q", got)
	}
}

func TestInjectTracking_AppendsPixelWithNoBodyTag(t *testing.T) {
	html := `<p>hi</p>`
	got := InjectTracking(html, testToken, testBase, true, false)
	if !strings.HasSuffix(got, `/>`) || !strings.Contains(got, "/api/v1/track/open/"+testToken) {
		t.Fatalf("expected pixel appended at end, got %q", got)
	}
}

func TestInjectTracking_RewritesHttpLinks(t *testing.T) {
	html := `<a href="https://example.com/path?a=1&b=2">click</a>`
	got := InjectTracking(html, testToken, testBase, false, true)
	want := `/api/v1/track/click/` + testToken + `?url=https%3A%2F%2Fexample.com%2Fpath%3Fa%3D1%26b%3D2`
	if !strings.Contains(got, want) {
		t.Fatalf("link not rewritten:\n got: %s\nwant substring: %s", got, want)
	}
}

func TestInjectTracking_SkipsNonHttpSchemes(t *testing.T) {
	cases := []string{
		`<a href="mailto:x@y.com">x</a>`,
		`<a href="tel:+15551234">x</a>`,
		`<a href="sms:+15551234">x</a>`,
		`<a href="javascript:void(0)">x</a>`,
		`<a href="#section">x</a>`,
		`<a href="">x</a>`,
	}
	for _, in := range cases {
		got := InjectTracking(in, testToken, testBase, false, true)
		if got != in {
			t.Errorf("expected unchanged for %q, got %q", in, got)
		}
	}
}

func TestInjectTracking_DoesNotDoubleWrap(t *testing.T) {
	existing := testBase + "/api/v1/track/click/" + testToken + "?url=https%3A%2F%2Fx"
	html := `<a href="` + existing + `">x</a>`
	got := InjectTracking(html, testToken, testBase, false, true)
	if got != html {
		t.Fatalf("double-wrapped already-tracked link: %q", got)
	}
}

func TestInjectTracking_HandlesSingleQuotedHrefAndAttrs(t *testing.T) {
	html := `<a class="btn" href='https://example.com/x' target="_blank">go</a>`
	got := InjectTracking(html, testToken, testBase, false, true)
	if !strings.Contains(got, `/api/v1/track/click/`+testToken+`?url=https%3A%2F%2Fexample.com%2Fx`) {
		t.Fatalf("single-quoted href not rewritten: %q", got)
	}
	if !strings.Contains(got, `target="_blank"`) {
		t.Fatalf("lost trailing attribute: %q", got)
	}
}

func TestInjectTracking_PixelAndLinksTogether(t *testing.T) {
	html := `<html><body><a href="https://x.test/">x</a></body></html>`
	got := InjectTracking(html, testToken, testBase, true, true)
	if !strings.Contains(got, "/api/v1/track/click/"+testToken) {
		t.Fatalf("expected click rewrite in %q", got)
	}
	if !strings.Contains(got, "/api/v1/track/open/"+testToken) {
		t.Fatalf("expected pixel in %q", got)
	}
}

func TestInjectTracking_TrimsTrailingSlashOnBaseURL(t *testing.T) {
	html := `<a href="https://x.test/">x</a>`
	got := InjectTracking(html, testToken, testBase+"/", false, true)
	if strings.Contains(got, "com//api/") {
		t.Fatalf("trailing slash produced double slash: %q", got)
	}
}
