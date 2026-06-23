package scim

import "strings"

// schemaAttr is one entry in a SCIM schema's attribute list.
type schemaAttr struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Required   bool   `json:"required"`
	MultiVal   bool   `json:"multiValued"`
	Mutability string `json:"mutability"`
	CaseExact  bool   `json:"caseExact"`
}

// listEnvelope wraps discovery resources in a SCIM ListResponse.
func listEnvelope(resources []any) map[string]any {
	return map[string]any{
		"schemas":      []string{ListResponseSchema},
		"totalResults": len(resources),
		"startIndex":   1,
		"itemsPerPage": len(resources),
		"Resources":    resources,
	}
}

// UserResourceTypesResponse is the /ResourceTypes payload: a ListResponse with
// the single User resource type Vectis exposes.
func UserResourceTypesResponse(baseURL string) map[string]any {
	base := strings.TrimRight(baseURL, "/")
	rt := map[string]any{
		"schemas":     []string{ResourceTypeSchema},
		"id":          ResourceTypeUser,
		"name":        ResourceTypeUser,
		"endpoint":    "/Users",
		"description": "SCIM User — maps to a Vectis mailbox.",
		"schema":      UserSchema,
		"meta": map[string]any{
			"resourceType": "ResourceType",
			"location":     base + "/scim/v2/ResourceTypes/User",
		},
	}
	return listEnvelope([]any{rt})
}

// UserSchemasResponse is the /Schemas payload: the core User schema with the
// attribute subset Vectis maps (userName, active, displayName, externalId,
// emails). Minimal but valid for Okta/Azure schema discovery.
func UserSchemasResponse() map[string]any {
	userSchema := map[string]any{
		"schemas":     []string{SchemaResourceSchema},
		"id":          UserSchema,
		"name":        ResourceTypeUser,
		"description": "SCIM core User resource.",
		"attributes": []any{
			schemaAttr{Name: "userName", Type: "string", Required: true, Mutability: "readWrite", CaseExact: false},
			schemaAttr{Name: "active", Type: "boolean", Mutability: "readWrite"},
			schemaAttr{Name: "displayName", Type: "string", Mutability: "readWrite"},
			schemaAttr{Name: "externalId", Type: "string", Mutability: "readWrite"},
			schemaAttr{Name: "emails", Type: "complex", MultiVal: true, Mutability: "readWrite"},
		},
		"meta": map[string]any{"resourceType": "Schema"},
	}
	return listEnvelope([]any{userSchema})
}
