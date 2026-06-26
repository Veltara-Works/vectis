package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/valkey-io/valkey-go"
	"golang.org/x/oauth2"

	"github.com/Veltara-Works/vectis/internal/config"
)

// OIDCManager handles OIDC provider discovery, state management, and token exchange.
type OIDCManager struct {
	vk        valkey.Client
	providers map[string]*OIDCProvider
}

// OIDCProvider holds a configured and discovered OIDC provider.
type OIDCProvider struct {
	Name         string
	OAuth2Config oauth2.Config
	Verifier     *oidc.IDTokenVerifier
}

// OIDCIdentity represents the identity claims extracted from an OIDC ID token.
type OIDCIdentity struct {
	Provider string
	Subject  string
	Email    string
	// EmailVerified reflects the IdP's email_verified claim. It is true only
	// when the claim is explicitly present AND true; an absent claim is treated
	// as unverified. The email address must NOT be trusted for account matching
	// or auto-linking unless this is true (see handleOIDCCallback).
	EmailVerified bool
}

const oidcStatePrefix = "oidc_state:"
const oidcStateTTL = 10 * time.Minute

// NewOIDCManager creates a new OIDC manager from the configured providers.
// It performs OIDC discovery for each enabled provider.
func NewOIDCManager(ctx context.Context, vk valkey.Client, secrets config.OIDCSecrets, callbackBaseURL string) (*OIDCManager, error) {
	m := &OIDCManager{
		vk:        vk,
		providers: make(map[string]*OIDCProvider),
	}

	for name, cfg := range secrets.Providers {
		if !cfg.Enabled {
			continue
		}

		provider, err := oidc.NewProvider(ctx, cfg.DiscoveryURL)
		if err != nil {
			return nil, fmt.Errorf("oidc discovery for %s: %w", name, err)
		}

		scopes := cfg.Scopes
		if len(scopes) == 0 {
			scopes = []string{oidc.ScopeOpenID, "email", "profile"}
		}

		callbackURL := strings.TrimRight(callbackBaseURL, "/") + "/api/v1/auth/oidc/callback/" + name

		m.providers[name] = &OIDCProvider{
			Name: name,
			OAuth2Config: oauth2.Config{
				ClientID:     cfg.ClientID,
				ClientSecret: cfg.ClientSecret,
				Endpoint:     provider.Endpoint(),
				RedirectURL:  callbackURL,
				Scopes:       scopes,
			},
			Verifier: provider.Verifier(&oidc.Config{
				ClientID: cfg.ClientID,
			}),
		}
	}

	return m, nil
}

// GetProvider returns the configured provider by name, or nil if not found.
func (m *OIDCManager) GetProvider(name string) *OIDCProvider {
	return m.providers[name]
}

// ListProviders returns the names of all enabled providers.
func (m *OIDCManager) ListProviders() []string {
	names := make([]string, 0, len(m.providers))
	for name := range m.providers {
		names = append(names, name)
	}
	return names
}

// HasProviders returns true if at least one OIDC provider is configured and enabled.
func (m *OIDCManager) HasProviders() bool {
	return len(m.providers) > 0
}

// CreateState generates a cryptographic state token for CSRF protection
// and stores it in Valkey with a 10-minute TTL.
func (m *OIDCManager) CreateState(ctx context.Context, provider string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate state: %w", err)
	}
	state := hex.EncodeToString(b)

	cmd := m.vk.B().Set().Key(oidcStatePrefix + state).Value(provider).Ex(oidcStateTTL).Build()
	if err := m.vk.Do(ctx, cmd).Error(); err != nil {
		return "", fmt.Errorf("store state: %w", err)
	}
	return state, nil
}

// ValidateState checks and consumes the state token from Valkey.
// Returns the provider name that was stored with the state.
func (m *OIDCManager) ValidateState(ctx context.Context, state string) (string, error) {
	key := oidcStatePrefix + state

	// Get and delete atomically.
	cmd := m.vk.B().Getdel().Key(key).Build()
	provider, err := m.vk.Do(ctx, cmd).ToString()
	if err != nil {
		return "", fmt.Errorf("invalid or expired state")
	}
	return provider, nil
}

// ExchangeAndVerify exchanges the authorization code for tokens, verifies the
// ID token, and extracts the identity claims.
func (m *OIDCManager) ExchangeAndVerify(ctx context.Context, provider *OIDCProvider, code string) (*OIDCIdentity, error) {
	// Exchange authorization code for tokens.
	token, err := provider.OAuth2Config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}

	// Extract and verify the ID token.
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token in response")
	}

	idToken, err := provider.Verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("verify id_token: %w", err)
	}

	// Extract claims. email_verified is a *bool so we can distinguish an
	// explicit "false" from an absent claim — both are treated as unverified,
	// but the distinction is useful for operator-facing diagnostics.
	var claims struct {
		Email         string `json:"email"`
		EmailVerified *bool  `json:"email_verified"`
		Sub           string `json:"sub"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("parse claims: %w", err)
	}

	if claims.Email == "" {
		return nil, fmt.Errorf("email claim missing from id_token")
	}

	return &OIDCIdentity{
		Provider:      provider.Name,
		Subject:       claims.Sub,
		Email:         strings.ToLower(claims.Email),
		EmailVerified: emailClaimVerified(claims.EmailVerified),
	}, nil
}

// emailClaimVerified reports whether the IdP positively asserted that the email
// is verified. The email_verified claim is OPTIONAL in OIDC, so an absent claim
// (nil) is treated as UNVERIFIED — the secure default. Only an explicit true is
// trusted. The email address must not be used for account auto-linking unless
// this returns true.
func emailClaimVerified(claim *bool) bool {
	return claim != nil && *claim
}
