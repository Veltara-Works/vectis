// Package scim implements the wire types and mapping for SCIM 2.0 user
// provisioning (RFC 7643 schema / RFC 7644 protocol). It is transport-agnostic:
// HTTP handlers in internal/api own routing and auth; this package owns the
// shapes Okta/Azure AD exchange and the mailbox<->User mapping.
package scim

import (
	"encoding/json"
	"net/http"
	"strconv"
)

// SCIM schema URNs (RFC 7643/7644).
const (
	UserSchema                  = "urn:ietf:params:scim:schemas:core:2.0:User"
	ServiceProviderConfigSchema = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	ResourceTypeSchema          = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
	SchemaResourceSchema        = "urn:ietf:params:scim:schemas:core:2.0:Schema"
	ListResponseSchema          = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	ErrorSchema                 = "urn:ietf:params:scim:api:messages:2.0:Error"
	PatchOpSchema               = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
)

// ContentType is the SCIM 2.0 media type (RFC 7644 §3.1). Responses — including
// errors — use this type, not application/json or the Vectis error envelope.
const ContentType = "application/scim+json"

// ResourceTypeUser is the meta.resourceType for User resources.
const ResourceTypeUser = "User"

// Meta is the common SCIM resource metadata.
type Meta struct {
	ResourceType string `json:"resourceType"`
	Created      string `json:"created,omitempty"`
	LastModified string `json:"lastModified,omitempty"`
	Location     string `json:"location,omitempty"`
}

// Name is the SCIM complex name attribute (Phase 1 uses formatted only).
type Name struct {
	Formatted string `json:"formatted,omitempty"`
}

// Email is a SCIM multi-valued email entry.
type Email struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

// User is a SCIM 2.0 core User resource (the subset Vectis maps to a mailbox).
type User struct {
	Schemas     []string `json:"schemas"`
	ID          string   `json:"id"`
	ExternalID  string   `json:"externalId,omitempty"`
	UserName    string   `json:"userName"`
	Name        *Name    `json:"name,omitempty"`
	DisplayName string   `json:"displayName,omitempty"`
	Active      bool     `json:"active"`
	Emails      []Email  `json:"emails,omitempty"`
	Meta        Meta     `json:"meta"`
}

// ListResponse is the SCIM list envelope (RFC 7644 §3.4.2). A filter that
// matches nothing returns this with TotalResults 0 — never a 404.
type ListResponse struct {
	Schemas      []string `json:"schemas"`
	TotalResults int      `json:"totalResults"`
	StartIndex   int      `json:"startIndex"`
	ItemsPerPage int      `json:"itemsPerPage"`
	Resources    []User   `json:"Resources"`
}

// NewListResponse builds a single-page ListResponse from the given users.
func NewListResponse(users []User) ListResponse {
	if users == nil {
		users = []User{}
	}
	return ListResponse{
		Schemas:      []string{ListResponseSchema},
		TotalResults: len(users),
		StartIndex:   1,
		ItemsPerPage: len(users),
		Resources:    users,
	}
}

// Error is the SCIM 2.0 error object (RFC 7644 §3.12). Note "status" is a
// STRING (e.g. "409"), not an integer, and "scimType" is the detail keyword
// (e.g. "uniqueness", "invalidValue").
type Error struct {
	Schemas  []string `json:"schemas"`
	Status   string   `json:"status"`
	SCIMType string   `json:"scimType,omitempty"`
	Detail   string   `json:"detail,omitempty"`
}

// WriteError writes a SCIM-shaped error under application/scim+json. scimType is
// optional; pass "" to omit it.
func WriteError(w http.ResponseWriter, status int, scimType, detail string) {
	w.Header().Set("Content-Type", ContentType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(Error{
		Schemas:  []string{ErrorSchema},
		Status:   strconv.Itoa(status),
		SCIMType: scimType,
		Detail:   detail,
	})
}
