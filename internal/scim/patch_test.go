package scim

import (
	"encoding/json"
	"testing"
)

func TestExtractActiveChange(t *testing.T) {
	cases := []struct {
		name      string
		body      string
		wantFound bool
		wantValue bool // only checked when wantFound
		wantErr   bool
	}{
		{
			name:      "replace active bool false (Okta)",
			body:      `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false}]}`,
			wantFound: true, wantValue: false,
		},
		{
			name:      "replace active bool true",
			body:      `{"Operations":[{"op":"replace","path":"active","value":true}]}`,
			wantFound: true, wantValue: true,
		},
		{
			name:      "replace active string False (Azure)",
			body:      `{"Operations":[{"op":"replace","path":"active","value":"False"}]}`,
			wantFound: true, wantValue: false,
		},
		{
			name:      "replace no-path object value (Azure)",
			body:      `{"Operations":[{"op":"replace","value":{"active":false}}]}`,
			wantFound: true, wantValue: false,
		},
		{
			name:      "add active true",
			body:      `{"Operations":[{"op":"add","path":"active","value":true}]}`,
			wantFound: true, wantValue: true,
		},
		{
			name:      "unsupported attribute path -> not found",
			body:      `{"Operations":[{"op":"replace","path":"displayName","value":"New Name"}]}`,
			wantFound: false,
		},
		{
			name:      "no operations -> not found",
			body:      `{"Operations":[]}`,
			wantFound: false,
		},
		{
			name:    "active with non-boolean string -> error",
			body:    `{"Operations":[{"op":"replace","path":"active","value":"banana"}]}`,
			wantErr: true,
		},
		{
			name:      "last active op wins",
			body:      `{"Operations":[{"op":"replace","path":"active","value":true},{"op":"replace","path":"active","value":false}]}`,
			wantFound: true, wantValue: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var req PatchRequest
			if err := json.Unmarshal([]byte(tc.body), &req); err != nil {
				t.Fatalf("invalid test body JSON: %v", err)
			}
			active, found, err := ExtractActiveChange(req)

			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if found != tc.wantFound {
				t.Fatalf("found = %v, want %v", found, tc.wantFound)
			}
			if !tc.wantFound {
				if active != nil {
					t.Errorf("active = %v, want nil when not found", *active)
				}
				return
			}
			if active == nil {
				t.Fatal("active is nil but found = true")
			}
			if *active != tc.wantValue {
				t.Errorf("active = %v, want %v", *active, tc.wantValue)
			}
		})
	}
}
