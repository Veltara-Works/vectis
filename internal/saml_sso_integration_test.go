//go:build integration

package internal_test

// Signed-assertion negative-case suite for Enterprise SAML SSO (design §10).
//
// A throwaway crewjam IdentityProvider mints REAL signed SAML responses (the
// real-envelope rule: the validator is fed on-the-wire signed XML, not a struct
// we built). The SP under test is the production auth.SAMLManager, whose trusted
// IdP cert comes from the same IdP's metadata. Each test exercises the full ACS
// path: BuildAuthnRedirect (seeds RelayState in Valkey) -> POST signed response
// -> ParseAndVerifyAssertion. The positive case must pass; every negative case
// must be REJECTED.
//
// Runs under `go test -tags integration ./internal/` (Valkey provided by CI).

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"

	"github.com/Veltara-Works/vectis/internal/auth"
	"github.com/Veltara-Works/vectis/internal/config"
	"github.com/Veltara-Works/vectis/internal/database"
)

const (
	samlTestSPEntityID = "https://mail.example.com/saml/metadata"
	samlTestACSBase    = "https://mail.example.com"
	samlTestACSURL     = samlTestACSBase + "/api/v1/auth/saml/acs/okta"
	samlTestEmail      = "admin@example.com"
)

// samlTestIdP is a minimal SAML IdP that mints signed responses for tests.
type samlTestIdP struct {
	idp *saml.IdentityProvider
}

func newSAMLTestIdP(t *testing.T) *samlTestIdP {
	t.Helper()
	key, cert := genRSAKeyCert(t, "test-idp")
	idp := &saml.IdentityProvider{
		Key:         key,
		Certificate: cert,
		MetadataURL: mustURL(t, "https://idp.example.com/saml/metadata"),
		SSOURL:      mustURL(t, "https://idp.example.com/saml/sso"),
	}
	return &samlTestIdP{idp: idp}
}

// metadataXML returns the IdP metadata (incl. signing cert) the SP must trust.
func (t2 *samlTestIdP) metadataXML(t *testing.T) string {
	t.Helper()
	b, err := xml.MarshalIndent(t2.idp.Metadata(), "", "  ")
	if err != nil {
		t.Fatalf("marshal idp metadata: %v", err)
	}
	return string(b)
}

type mintOpts struct {
	now         time.Time
	requestID   string // becomes InResponseTo
	audience    string // SP entityID the assertion is restricted to
	recipient   string // ACS URL recorded in the assertion
	email       string
	assertionID string // override to force a replay collision; "" = generated
	corruptSig  bool   // flip a byte of the signature after signing
}

// mint produces a signed SAML Response XML string per opts.
func (t2 *samlTestIdP) mint(t *testing.T, o mintOpts) string {
	t.Helper()
	spForMeta := saml.ServiceProvider{
		EntityID:    o.audience,
		MetadataURL: mustURL(t, o.audience),
		AcsURL:      mustURL(t, o.recipient),
	}
	spMeta := spForMeta.Metadata()

	req := &saml.IdpAuthnRequest{
		IDP:         t2.idp,
		HTTPRequest: &http.Request{RemoteAddr: "127.0.0.1"},
		Now:         o.now,
		Request: saml.AuthnRequest{
			ID:                          o.requestID,
			IssueInstant:                o.now,
			Destination:                 t2.idp.SSOURL.String(),
			AssertionConsumerServiceURL: o.recipient,
			Issuer:                      &saml.Issuer{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity", Value: o.audience},
		},
		ServiceProviderMetadata: spMeta,
		ACSEndpoint:             &saml.IndexedEndpoint{Binding: saml.HTTPPostBinding, Location: o.recipient},
	}
	if len(spMeta.SPSSODescriptors) > 0 {
		req.SPSSODescriptor = &spMeta.SPSSODescriptors[0]
	}
	session := &saml.Session{
		ID:           "test-session",
		CreateTime:   o.now,
		ExpireTime:   o.now.Add(time.Hour),
		Index:        "test-index",
		NameID:       o.email,
		NameIDFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		UserEmail:    o.email,
	}

	if err := (saml.DefaultAssertionMaker{}).MakeAssertion(req, session); err != nil {
		t.Fatalf("MakeAssertion: %v", err)
	}
	if o.assertionID != "" {
		req.Assertion.ID = o.assertionID // signed over below, so this is a real, valid signature
	}
	if err := req.MakeAssertionEl(); err != nil {
		t.Fatalf("MakeAssertionEl: %v", err)
	}
	if err := req.MakeResponse(); err != nil {
		t.Fatalf("MakeResponse: %v", err)
	}
	doc := etree.NewDocument()
	doc.SetRoot(req.ResponseEl)
	out, err := doc.WriteToString()
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	if o.corruptSig {
		out = corruptSignatureValue(t, out)
	}
	return out
}

// setupSAMLManager builds the production SAMLManager trusting this IdP, backed
// by a real Valkey connection.
func setupSAMLManager(t *testing.T, idp *samlTestIdP) (*auth.SAMLManager, *auth.SAMLProvider) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	vk, err := database.NewValkeyClient(database.ValkeyConfig{
		Host:     envOr("VECTIS_TEST_VK_HOST", "127.0.0.1"),
		Port:     envOrInt("VECTIS_TEST_VK_PORT", 6379),
		Password: envOr("VECTIS_TEST_VK_PASSWORD", "vectis_dev_valkey"),
	}, logger)
	if err != nil {
		t.Fatalf("connect valkey: %v", err)
	}
	t.Cleanup(func() { vk.Close() })

	spKeyPEM, spCertPEM := genRSAKeyCertPEM(t, "test-sp")
	secrets := config.SAMLSecrets{
		SPEntityID:    samlTestSPEntityID,
		SPPrivateKey:  spKeyPEM,
		SPCertificate: spCertPEM,
		Providers: map[string]config.SAMLProviderConfig{
			"okta": {Enabled: true, IDPMetadataXML: idp.metadataXML(t)},
		},
	}
	m, err := auth.NewSAMLManager(context.Background(), vk, secrets, samlTestACSBase)
	if err != nil {
		t.Fatalf("NewSAMLManager: %v", err)
	}
	p := m.GetProvider("okta")
	if p == nil {
		t.Fatal("provider okta not configured")
	}
	return m, p
}

// startFlow runs BuildAuthnRedirect and returns the issued request ID (which the
// minted assertion must echo as InResponseTo) and the RelayState to POST back.
func startFlow(t *testing.T, m *auth.SAMLManager, p *auth.SAMLProvider) (requestID, relayState string) {
	t.Helper()
	redirect, err := m.BuildAuthnRedirect(context.Background(), p)
	if err != nil {
		t.Fatalf("BuildAuthnRedirect: %v", err)
	}
	u, err := url.Parse(redirect)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	relayState = u.Query().Get("RelayState")
	if relayState == "" {
		t.Fatal("redirect missing RelayState")
	}
	deflated, err := base64.StdEncoding.DecodeString(u.Query().Get("SAMLRequest"))
	if err != nil {
		t.Fatalf("decode SAMLRequest: %v", err)
	}
	raw, err := io.ReadAll(flate.NewReader(bytes.NewReader(deflated)))
	if err != nil {
		t.Fatalf("inflate SAMLRequest: %v", err)
	}
	var ar struct {
		ID string `xml:"ID,attr"`
	}
	if err := xml.Unmarshal(raw, &ar); err != nil {
		t.Fatalf("parse AuthnRequest: %v", err)
	}
	if ar.ID == "" {
		t.Fatal("AuthnRequest has no ID")
	}
	return ar.ID, relayState
}

// acsRequest builds the POST request the IdP browser would submit to the ACS.
func acsRequest(samlResponse, relayState string) *http.Request {
	form := url.Values{
		"SAMLResponse": {base64.StdEncoding.EncodeToString([]byte(samlResponse))},
		"RelayState":   {relayState},
	}
	r := httptest.NewRequest(http.MethodPost, samlTestACSURL, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

func TestSAMLAssertion_ValidAccepted(t *testing.T) {
	idp := newSAMLTestIdP(t)
	m, p := setupSAMLManager(t, idp)
	reqID, relay := startFlow(t, m, p)

	resp := idp.mint(t, mintOpts{
		now: saml.TimeNow(), requestID: reqID,
		audience: samlTestSPEntityID, recipient: samlTestACSURL, email: samlTestEmail,
	})

	id, err := m.ParseAndVerifyAssertion(context.Background(), p, acsRequest(resp, relay))
	if err != nil {
		t.Fatalf("valid assertion rejected: %v", err)
	}
	if id.Email != samlTestEmail {
		t.Errorf("email = %q, want %q", id.Email, samlTestEmail)
	}
	if id.Provider != "okta" {
		t.Errorf("provider = %q, want okta", id.Provider)
	}
}

func TestSAMLAssertion_NegativeCasesRejected(t *testing.T) {
	idp := newSAMLTestIdP(t)
	m, p := setupSAMLManager(t, idp)

	cases := []struct {
		name string
		opts func(reqID string) mintOpts
		// relayOverride replaces the real RelayState (for the CSRF case)
		relayOverride string
	}{
		{
			name: "bad signature",
			opts: func(reqID string) mintOpts {
				return mintOpts{now: saml.TimeNow(), requestID: reqID, audience: samlTestSPEntityID, recipient: samlTestACSURL, email: samlTestEmail, corruptSig: true}
			},
		},
		{
			name: "expired (NotOnOrAfter in the past)",
			opts: func(reqID string) mintOpts {
				return mintOpts{now: saml.TimeNow().Add(-15 * time.Minute), requestID: reqID, audience: samlTestSPEntityID, recipient: samlTestACSURL, email: samlTestEmail}
			},
		},
		{
			name: "not yet valid (NotBefore in the future)",
			opts: func(reqID string) mintOpts {
				return mintOpts{now: saml.TimeNow().Add(15 * time.Minute), requestID: reqID, audience: samlTestSPEntityID, recipient: samlTestACSURL, email: samlTestEmail}
			},
		},
		{
			name: "wrong audience",
			opts: func(reqID string) mintOpts {
				return mintOpts{now: saml.TimeNow(), requestID: reqID, audience: "https://evil.example.com/metadata", recipient: samlTestACSURL, email: samlTestEmail}
			},
		},
		{
			name: "wrong recipient",
			opts: func(reqID string) mintOpts {
				return mintOpts{now: saml.TimeNow(), requestID: reqID, audience: samlTestSPEntityID, recipient: "https://evil.example.com/acs", email: samlTestEmail}
			},
		},
		{
			name: "RelayState not recognised (CSRF)",
			opts: func(reqID string) mintOpts {
				return mintOpts{now: saml.TimeNow(), requestID: reqID, audience: samlTestSPEntityID, recipient: samlTestACSURL, email: samlTestEmail}
			},
			relayOverride: "bogus-relay-state-not-in-valkey",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reqID, relay := startFlow(t, m, p)
			if c.relayOverride != "" {
				relay = c.relayOverride
			}
			resp := idp.mint(t, c.opts(reqID))
			if _, err := m.ParseAndVerifyAssertion(context.Background(), p, acsRequest(resp, relay)); err == nil {
				t.Fatalf("%s: expected rejection, got nil error", c.name)
			}
		})
	}
}

// TestSAMLAssertion_ReplayRejected proves a once-accepted assertion ID cannot be
// presented again, even with a fresh (valid) RelayState. Two flows share a fixed
// assertion ID; the second presentation must be rejected by the replay cache.
func TestSAMLAssertion_ReplayRejected(t *testing.T) {
	idp := newSAMLTestIdP(t)
	m, p := setupSAMLManager(t, idp)
	const fixedID = "_replayed_assertion_id_0001"

	reqID1, relay1 := startFlow(t, m, p)
	resp1 := idp.mint(t, mintOpts{now: saml.TimeNow(), requestID: reqID1, audience: samlTestSPEntityID, recipient: samlTestACSURL, email: samlTestEmail, assertionID: fixedID})
	if _, err := m.ParseAndVerifyAssertion(context.Background(), p, acsRequest(resp1, relay1)); err != nil {
		t.Fatalf("first presentation should succeed: %v", err)
	}

	reqID2, relay2 := startFlow(t, m, p)
	resp2 := idp.mint(t, mintOpts{now: saml.TimeNow(), requestID: reqID2, audience: samlTestSPEntityID, recipient: samlTestACSURL, email: samlTestEmail, assertionID: fixedID})
	if _, err := m.ParseAndVerifyAssertion(context.Background(), p, acsRequest(resp2, relay2)); err == nil {
		t.Fatal("replayed assertion ID should be rejected, got nil error")
	}
}

// --- helpers ---

func corruptSignatureValue(t *testing.T, xmlStr string) string {
	t.Helper()
	i := strings.Index(xmlStr, "SignatureValue>")
	if i < 0 {
		t.Fatal("no SignatureValue element to corrupt")
	}
	j := i + len("SignatureValue>")
	b := []byte(xmlStr)
	for k := j; k < len(b); k++ {
		if b[k] == '<' {
			break
		}
		if (b[k] >= 'A' && b[k] <= 'Z') || (b[k] >= 'a' && b[k] <= 'z') {
			if b[k] == 'A' {
				b[k] = 'B'
			} else {
				b[k] = 'A'
			}
			return string(b)
		}
	}
	t.Fatal("could not corrupt signature value")
	return ""
}

func genRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func genRSAKeyCert(t *testing.T, cn string) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key := genRSAKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    saml.TimeNow().Add(-time.Hour),
		NotAfter:     saml.TimeNow().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return key, cert
}

func genRSAKeyCertPEM(t *testing.T, cn string) (keyPEM, certPEM string) {
	t.Helper()
	key, cert := genRSAKeyCert(t, cn)
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	return keyPEM, certPEM
}

func mustURL(t *testing.T, s string) url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatalf("parse url %q: %v", s, err)
	}
	return *u
}
