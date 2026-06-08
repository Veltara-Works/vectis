package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/crewjam/saml"

	"github.com/Veltara-Works/vectis/internal/config"
)

// testKeypair generates an RSA key (PKCS1 PEM), a self-signed cert (PEM), and
// the raw cert DER (for embedding in IdP metadata).
func testKeypair(t *testing.T) (keyPEM, certPEM string, certDER []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	return keyPEM, certPEM, certDER
}

func TestParseRSAPrivateKeyPEM(t *testing.T) {
	keyPEM, _, _ := testKeypair(t)
	if _, err := parseRSAPrivateKeyPEM(keyPEM); err != nil {
		t.Fatalf("PKCS1 PEM should parse: %v", err)
	}

	// PKCS8-wrapped RSA key.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	p8 := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if _, err := parseRSAPrivateKeyPEM(p8); err != nil {
		t.Fatalf("PKCS8 PEM should parse: %v", err)
	}

	if _, err := parseRSAPrivateKeyPEM("not a pem at all"); err == nil {
		t.Fatal("expected error on non-PEM input")
	}
}

func TestParseCertificatePEM(t *testing.T) {
	_, certPEM, _ := testKeypair(t)
	if _, err := parseCertificatePEM(certPEM); err != nil {
		t.Fatalf("valid cert PEM should parse: %v", err)
	}
	if _, err := parseCertificatePEM("garbage"); err == nil {
		t.Fatal("expected error on non-PEM cert input")
	}
}

func TestExtractAssertionEmail(t *testing.T) {
	const emailFmt = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	const persistentFmt = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"

	attrStmt := func(name, friendly, val string) []saml.AttributeStatement {
		return []saml.AttributeStatement{{
			Attributes: []saml.Attribute{{
				Name:         name,
				FriendlyName: friendly,
				Values:       []saml.AttributeValue{{Value: val}},
			}},
		}}
	}

	cases := []struct {
		name      string
		assertion saml.Assertion
		emailAttr string
		want      string
	}{
		{
			name: "nameid emailAddress format is lowercased",
			assertion: saml.Assertion{
				Subject: &saml.Subject{NameID: &saml.NameID{Format: emailFmt, Value: "Alice@Example.COM"}},
			},
			emailAttr: "email",
			want:      "alice@example.com",
		},
		{
			name: "falls back to attribute by Name when NameID is not email",
			assertion: saml.Assertion{
				Subject:             &saml.Subject{NameID: &saml.NameID{Format: persistentFmt, Value: "opaque-123"}},
				AttributeStatements: attrStmt("email", "", "Bob@Example.com"),
			},
			emailAttr: "email",
			want:      "bob@example.com",
		},
		{
			name: "matches attribute by FriendlyName",
			assertion: saml.Assertion{
				Subject:             &saml.Subject{NameID: &saml.NameID{Format: persistentFmt, Value: "opaque"}},
				AttributeStatements: attrStmt("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "email", "carol@example.com"),
			},
			emailAttr: "email",
			want:      "carol@example.com",
		},
		{
			name: "no email resolvable returns empty",
			assertion: saml.Assertion{
				Subject:             &saml.Subject{NameID: &saml.NameID{Format: persistentFmt, Value: "opaque"}},
				AttributeStatements: attrStmt("groups", "", "admins"),
			},
			emailAttr: "email",
			want:      "",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := extractAssertionEmail(&c.assertion, c.emailAttr)
			if got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

// realIDPMetadataXML builds a structurally-valid SAML IdP EntityDescriptor with
// a real signing certificate embedded — fed through samlsp.ParseMetadata in
// NewSAMLManager, this exercises the metadata decoder on real on-the-wire bytes.
func realIDPMetadataXML(certDER []byte) string {
	certB64 := base64.StdEncoding.EncodeToString(certDER)
	return `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com/metadata">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>` + certB64 + `</X509Certificate></X509Data></KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`
}

func TestNewSAMLManager(t *testing.T) {
	spKeyPEM, spCertPEM, _ := testKeypair(t)
	_, _, idpCertDER := testKeypair(t)
	idpXML := realIDPMetadataXML(idpCertDER)

	secrets := config.SAMLSecrets{
		SPEntityID:    "https://mail.example.com/saml/metadata",
		SPPrivateKey:  spKeyPEM,
		SPCertificate: spCertPEM,
		Providers: map[string]config.SAMLProviderConfig{
			"okta":     {Enabled: true, IDPMetadataXML: idpXML},
			"disabled": {Enabled: false, IDPMetadataXML: idpXML},
		},
	}

	m, err := NewSAMLManager(context.Background(), nil, secrets, "https://mail.example.com")
	if err != nil {
		t.Fatalf("NewSAMLManager: %v", err)
	}
	if !m.HasProviders() {
		t.Fatal("expected providers")
	}
	if got := m.ListProviders(); len(got) != 1 || got[0] != "okta" {
		t.Fatalf("expected only [okta], got %v (disabled provider must be skipped)", got)
	}
	p := m.GetProvider("okta")
	if p == nil {
		t.Fatal("GetProvider(okta) returned nil")
	}
	if p.EmailAttr != "email" {
		t.Errorf("default EmailAttr should be 'email', got %q", p.EmailAttr)
	}
	if p.SP.EntityID != secrets.SPEntityID {
		t.Errorf("SP EntityID = %q, want %q", p.SP.EntityID, secrets.SPEntityID)
	}
	// The IdP metadata's HTTP-Redirect SSO binding must be discoverable.
	if loc := p.SP.GetSSOBindingLocation(saml.HTTPRedirectBinding); loc != "https://idp.example.com/sso" {
		t.Errorf("SSO binding location = %q, want the IdP SSO URL", loc)
	}
	if m.GetProvider("disabled") != nil {
		t.Error("disabled provider must not be present")
	}
}

func TestNewSAMLManager_BadKeypair(t *testing.T) {
	_, _, idpCertDER := testKeypair(t)
	secrets := config.SAMLSecrets{
		SPEntityID:    "https://mail.example.com/saml/metadata",
		SPPrivateKey:  "not a real key",
		SPCertificate: "not a real cert",
		Providers: map[string]config.SAMLProviderConfig{
			"okta": {Enabled: true, IDPMetadataXML: realIDPMetadataXML(idpCertDER)},
		},
	}
	if _, err := NewSAMLManager(context.Background(), nil, secrets, "https://mail.example.com"); err == nil {
		t.Fatal("expected error on invalid SP keypair")
	}
}
