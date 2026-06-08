package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/valkey-io/valkey-go"

	"github.com/Veltara-Works/vectis/internal/config"
)

// SAMLManager holds configured SAML Service Provider instances per provider and
// a Valkey handle for RelayState (CSRF) and assertion-ID replay protection.
// It mirrors OIDCManager: one global SP keypair, a provider map, and stateless
// handlers that lean on Valkey for short-lived per-flow state.
type SAMLManager struct {
	vk        valkey.Client
	providers map[string]*SAMLProvider
}

// SAMLProvider is a single configured IdP wired into a crewjam ServiceProvider.
type SAMLProvider struct {
	Name      string
	SP        *saml.ServiceProvider // IdP metadata, SP key/cert, entityID, ACS URL
	EmailAttr string                // attribute holding email when not in the NameID
}

// SAMLIdentity mirrors OIDCIdentity — the verified identity from an assertion.
type SAMLIdentity struct {
	Provider string
	Subject  string // SAML NameID value
	Email    string
}

const (
	samlRelayPrefix    = "saml_relay:"
	samlRelayTTL       = 10 * time.Minute
	samlSeenPrefix     = "saml_seen:"
	samlSeenDefaultTTL = time.Hour // covers any sane assertion validity window
)

// NewSAMLManager builds the SP instances from secrets. The SP keypair is shared
// across providers (one SP identity per install). IdP metadata is loaded from
// inline XML (air-gapped) or fetched from the metadata URL at startup. A failure
// here is returned to the caller, which logs it and runs without SAML (mirrors
// the OIDC discovery-failure path).
func NewSAMLManager(ctx context.Context, vk valkey.Client, secrets config.SAMLSecrets, acsBaseURL string) (*SAMLManager, error) {
	m := &SAMLManager{
		vk:        vk,
		providers: make(map[string]*SAMLProvider),
	}

	spKey, err := parseRSAPrivateKeyPEM(secrets.SPPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("saml: SP private key: %w", err)
	}
	spCert, err := parseCertificatePEM(secrets.SPCertificate)
	if err != nil {
		return nil, fmt.Errorf("saml: SP certificate: %w", err)
	}

	base := strings.TrimRight(acsBaseURL, "/")

	for name, pc := range secrets.Providers {
		if !pc.Enabled {
			continue
		}

		idpMeta, err := loadIDPMetadata(ctx, pc)
		if err != nil {
			return nil, fmt.Errorf("saml provider %s: %w", name, err)
		}

		metaURL, err := url.Parse(base + "/api/v1/auth/saml/metadata/" + name)
		if err != nil {
			return nil, fmt.Errorf("saml provider %s: metadata URL: %w", name, err)
		}
		acsURL, err := url.Parse(base + "/api/v1/auth/saml/acs/" + name)
		if err != nil {
			return nil, fmt.Errorf("saml provider %s: acs URL: %w", name, err)
		}

		sp := &saml.ServiceProvider{
			EntityID:          secrets.SPEntityID,
			Key:               spKey,
			Certificate:       spCert,
			MetadataURL:       *metaURL,
			AcsURL:            *acsURL,
			IDPMetadata:       idpMeta,
			AuthnNameIDFormat: saml.EmailAddressNameIDFormat,
		}

		emailAttr := pc.EmailAttr
		if emailAttr == "" {
			emailAttr = "email"
		}

		m.providers[name] = &SAMLProvider{Name: name, SP: sp, EmailAttr: emailAttr}
	}

	return m, nil
}

func loadIDPMetadata(ctx context.Context, pc config.SAMLProviderConfig) (*saml.EntityDescriptor, error) {
	if pc.IDPMetadataXML != "" {
		md, err := samlsp.ParseMetadata([]byte(pc.IDPMetadataXML))
		if err != nil {
			return nil, fmt.Errorf("parse inline idp metadata: %w", err)
		}
		return md, nil
	}
	if pc.IDPMetadataURL != "" {
		u, err := url.Parse(pc.IDPMetadataURL)
		if err != nil {
			return nil, fmt.Errorf("idp_metadata_url: %w", err)
		}
		md, err := samlsp.FetchMetadata(ctx, http.DefaultClient, *u)
		if err != nil {
			return nil, fmt.Errorf("fetch idp metadata: %w", err)
		}
		return md, nil
	}
	return nil, fmt.Errorf("provider needs idp_metadata_url or idp_metadata_xml")
}

// GetProvider returns the configured provider by name, or nil.
func (m *SAMLManager) GetProvider(name string) *SAMLProvider {
	return m.providers[name]
}

// ListProviders returns the names of all enabled providers.
func (m *SAMLManager) ListProviders() []string {
	names := make([]string, 0, len(m.providers))
	for name := range m.providers {
		names = append(names, name)
	}
	return names
}

// HasProviders reports whether at least one provider is configured.
func (m *SAMLManager) HasProviders() bool {
	return len(m.providers) > 0
}

// BuildAuthnRedirect mints an SP-initiated AuthnRequest (HTTP-Redirect binding),
// stores the request ID under a fresh RelayState token in Valkey (CSRF +
// InResponseTo binding), and returns the IdP redirect URL.
func (m *SAMLManager) BuildAuthnRedirect(ctx context.Context, provider *SAMLProvider) (string, error) {
	idpURL := provider.SP.GetSSOBindingLocation(saml.HTTPRedirectBinding)
	if idpURL == "" {
		return "", fmt.Errorf("idp has no HTTP-Redirect SSO binding")
	}

	authReq, err := provider.SP.MakeAuthenticationRequest(idpURL, saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		return "", fmt.Errorf("make authn request: %w", err)
	}

	relayState, err := m.createRelayState(ctx, provider.Name, authReq.ID)
	if err != nil {
		return "", err
	}

	redirectURL, err := authReq.Redirect(relayState, provider.SP)
	if err != nil {
		return "", fmt.Errorf("build redirect: %w", err)
	}
	return redirectURL.String(), nil
}

// ParseAndVerifyAssertion validates the SAML response on r and returns the
// identity. It enforces: RelayState (CSRF, consumed from Valkey), full assertion
// validation via crewjam (signature, audience, time-window, recipient,
// InResponseTo), and single-use replay protection on the assertion ID.
func (m *SAMLManager) ParseAndVerifyAssertion(ctx context.Context, provider *SAMLProvider, r *http.Request) (*SAMLIdentity, error) {
	if err := r.ParseForm(); err != nil {
		return nil, fmt.Errorf("parse form: %w", err)
	}

	relayState := r.PostForm.Get("RelayState")
	if relayState == "" {
		return nil, fmt.Errorf("missing RelayState")
	}
	relayProvider, requestID, err := m.validateRelayState(ctx, relayState)
	if err != nil {
		return nil, err
	}
	if relayProvider != provider.Name {
		return nil, fmt.Errorf("relay state provider mismatch")
	}

	// crewjam validates signature, audience (== sp.EntityID), NotBefore/
	// NotOnOrAfter (with MaxClockSkew), recipient (== sp.AcsURL), and the
	// InResponseTo against our issued request ID. It also defends against XSW.
	assertion, err := provider.SP.ParseResponse(r, []string{requestID})
	if err != nil {
		return nil, fmt.Errorf("assertion validation: %w", err)
	}

	if err := m.assertNotReplayed(ctx, assertion); err != nil {
		return nil, err
	}

	subject := ""
	if assertion.Subject != nil && assertion.Subject.NameID != nil {
		subject = assertion.Subject.NameID.Value
	}
	if subject == "" {
		return nil, fmt.Errorf("assertion has no NameID subject")
	}

	email := extractAssertionEmail(assertion, provider.EmailAttr)
	if email == "" {
		return nil, fmt.Errorf("no email resolvable from assertion")
	}

	return &SAMLIdentity{
		Provider: provider.Name,
		Subject:  subject,
		Email:    email,
	}, nil
}

// MetadataXML returns the SP metadata XML for this provider, to hand to the IdP.
func (p *SAMLProvider) MetadataXML() ([]byte, error) {
	ed := p.SP.Metadata()
	return xml.MarshalIndent(ed, "", "  ")
}

// createRelayState stores "provider|requestID" under a random token.
func (m *SAMLManager) createRelayState(ctx context.Context, provider, requestID string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate relay state: %w", err)
	}
	token := hex.EncodeToString(b)
	cmd := m.vk.B().Set().Key(samlRelayPrefix + token).Value(provider + "|" + requestID).Ex(samlRelayTTL).Build()
	if err := m.vk.Do(ctx, cmd).Error(); err != nil {
		return "", fmt.Errorf("store relay state: %w", err)
	}
	return token, nil
}

// validateRelayState atomically gets-and-deletes the token, returning the
// stored provider name and request ID.
func (m *SAMLManager) validateRelayState(ctx context.Context, token string) (provider, requestID string, err error) {
	cmd := m.vk.B().Getdel().Key(samlRelayPrefix + token).Build()
	v, err := m.vk.Do(ctx, cmd).ToString()
	if err != nil {
		return "", "", fmt.Errorf("invalid or expired relay state")
	}
	parts := strings.SplitN(v, "|", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("malformed relay state")
	}
	return parts[0], parts[1], nil
}

// assertNotReplayed marks the assertion ID single-use in Valkey. A second
// presentation of the same assertion within the validity window is rejected.
func (m *SAMLManager) assertNotReplayed(ctx context.Context, assertion *saml.Assertion) error {
	if assertion.ID == "" {
		return fmt.Errorf("assertion has no ID")
	}
	ttl := samlSeenDefaultTTL
	if assertion.Conditions != nil && !assertion.Conditions.NotOnOrAfter.IsZero() {
		if d := time.Until(assertion.Conditions.NotOnOrAfter); d > 0 {
			ttl = d + time.Minute
		}
	}
	cmd := m.vk.B().Set().Key(samlSeenPrefix + assertion.ID).Value("1").Nx().Ex(ttl).Build()
	if err := m.vk.Do(ctx, cmd).Error(); err != nil {
		if valkey.IsValkeyNil(err) {
			return fmt.Errorf("assertion replay detected")
		}
		return fmt.Errorf("replay cache: %w", err)
	}
	return nil
}

// extractAssertionEmail prefers an emailAddress-format NameID, then the
// configured email attribute (by Name or FriendlyName). Result is lowercased.
func extractAssertionEmail(a *saml.Assertion, emailAttr string) string {
	if a.Subject != nil && a.Subject.NameID != nil {
		nid := a.Subject.NameID
		if strings.Contains(strings.ToLower(nid.Format), "emailaddress") && nid.Value != "" {
			return strings.ToLower(nid.Value)
		}
	}
	for _, stmt := range a.AttributeStatements {
		for _, attr := range stmt.Attributes {
			if attr.Name != emailAttr && attr.FriendlyName != emailAttr {
				continue
			}
			for _, v := range attr.Values {
				if v.Value != "" {
					return strings.ToLower(v.Value)
				}
			}
		}
	}
	return ""
}

func parseRSAPrivateKeyPEM(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not RSA")
	}
	return rk, nil
}

func parseCertificatePEM(pemStr string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}
