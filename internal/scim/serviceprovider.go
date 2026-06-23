package scim

import "strings"

// Supported is the common {"supported": bool} SCIM capability flag.
type Supported struct {
	Supported bool `json:"supported"`
}

// BulkConfig describes /Bulk support (unsupported in Phase 1).
type BulkConfig struct {
	Supported      bool `json:"supported"`
	MaxOperations  int  `json:"maxOperations"`
	MaxPayloadSize int  `json:"maxPayloadSize"`
}

// FilterConfig describes filter support and the result cap.
type FilterConfig struct {
	Supported  bool `json:"supported"`
	MaxResults int  `json:"maxResults"`
}

// AuthScheme describes an authentication scheme the SCIM endpoint accepts.
type AuthScheme struct {
	Type        string `json:"type"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Primary     bool   `json:"primary,omitempty"`
}

// ServiceProviderConfig is the /ServiceProviderConfig resource (RFC 7644 §5).
// Okta/Azure fetch it to discover capabilities before provisioning.
type ServiceProviderConfig struct {
	Schemas               []string     `json:"schemas"`
	DocumentationURI      string       `json:"documentationUri,omitempty"`
	Patch                 Supported    `json:"patch"`
	Bulk                  BulkConfig   `json:"bulk"`
	Filter                FilterConfig `json:"filter"`
	ChangePassword        Supported    `json:"changePassword"`
	Sort                  Supported    `json:"sort"`
	ETag                  Supported    `json:"etag"`
	AuthenticationSchemes []AuthScheme `json:"authenticationSchemes"`
	Meta                  Meta         `json:"meta"`
}

// DefaultFilterMaxResults caps filter results (Phase 1 filters are exact
// userName lookups, so this is generous).
const DefaultFilterMaxResults = 200

// DefaultServiceProviderConfig returns the capabilities Vectis advertises in
// Phase 1: PATCH + filter supported; bulk/sort/etag/changePassword not; bearer
// token auth. location is built from baseURL.
func DefaultServiceProviderConfig(baseURL string) ServiceProviderConfig {
	return ServiceProviderConfig{
		Schemas:        []string{ServiceProviderConfigSchema},
		Patch:          Supported{Supported: true},
		Bulk:           BulkConfig{Supported: false},
		Filter:         FilterConfig{Supported: true, MaxResults: DefaultFilterMaxResults},
		ChangePassword: Supported{Supported: false},
		Sort:           Supported{Supported: false},
		ETag:           Supported{Supported: false},
		AuthenticationSchemes: []AuthScheme{{
			Type:        "oauthbearertoken",
			Name:        "OAuth Bearer Token",
			Description: "Authentication via a static SCIM bearer token (scim_…).",
			Primary:     true,
		}},
		Meta: Meta{
			ResourceType: "ServiceProviderConfig",
			Location:     strings.TrimRight(baseURL, "/") + "/scim/v2/ServiceProviderConfig",
		},
	}
}
