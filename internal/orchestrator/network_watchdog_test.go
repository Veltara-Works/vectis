package orchestrator

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseComposeServiceNetworks_HappyPath(t *testing.T) {
	raw := []byte(`{
		"name": "vectis",
		"networks": {
			"vectis-data":         {"name": "vectis_vectis-data",         "internal": true},
			"vectis-frontend":     {"name": "vectis_vectis-frontend"},
			"vectis-mail":         {"name": "vectis_vectis-mail",         "internal": true},
			"vectis-orchestrator": {"name": "vectis_vectis-orchestrator", "internal": true}
		},
		"services": {
			"api": {
				"networks": {
					"vectis-data":         null,
					"vectis-frontend":     null,
					"vectis-orchestrator": null
				}
			},
			"postgres": {
				"networks": {
					"vectis-data": null
				}
			},
			"acme-sh": {
				"networks": {
					"vectis-frontend": null
				}
			}
		}
	}`)

	got, err := parseComposeServiceNetworks(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := map[string][]string{
		"api":      {"vectis_vectis-data", "vectis_vectis-frontend", "vectis_vectis-orchestrator"},
		"postgres": {"vectis_vectis-data"},
		"acme-sh":  {"vectis_vectis-frontend"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mismatch:\n got=%v\nwant=%v", got, want)
	}
}

func TestParseComposeServiceNetworks_SkipsServicesWithNoNetworks(t *testing.T) {
	// A service with no networks key (e.g. uses default network) should be
	// omitted from the map so the watchdog doesn't try to "heal" it onto
	// nothing.
	raw := []byte(`{
		"name": "vectis",
		"networks": {
			"vectis-data": {"name": "vectis_vectis-data"}
		},
		"services": {
			"api":  {"networks": {"vectis-data": null}},
			"none": {}
		}
	}`)
	got, err := parseComposeServiceNetworks(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, ok := got["none"]; ok {
		t.Errorf("expected service 'none' (no networks) to be skipped; got entry %v", got["none"])
	}
	if !reflect.DeepEqual(got["api"], []string{"vectis_vectis-data"}) {
		t.Errorf("api networks: got %v, want [vectis_vectis-data]", got["api"])
	}
}

func TestParseComposeServiceNetworks_UndeclaredNetworkErrors(t *testing.T) {
	// If a service references a network that isn't in the top-level networks
	// map, the watchdog should refuse to act rather than silently treat the
	// container as fully drifted.
	raw := []byte(`{
		"name": "vectis",
		"networks": {
			"vectis-data": {"name": "vectis_vectis-data"}
		},
		"services": {
			"api": {"networks": {"ghost-net": null}}
		}
	}`)
	_, err := parseComposeServiceNetworks(raw)
	if err == nil {
		t.Fatal("expected error for undeclared network reference, got nil")
	}
	if !strings.Contains(err.Error(), "ghost-net") {
		t.Errorf("error should mention the offending network name; got: %v", err)
	}
}

func TestParseComposeServiceNetworks_MalformedJSON(t *testing.T) {
	if _, err := parseComposeServiceNetworks([]byte("not json")); err == nil {
		t.Fatal("expected JSON parse error, got nil")
	}
}

func TestParseComposeServiceNetworks_NetworkMissingName(t *testing.T) {
	// Compose normally always populates networks[*].name, but if it ever
	// omits it we must not silently produce an empty-string network name
	// (which would then be treated as drift on every container).
	raw := []byte(`{
		"name": "vectis",
		"networks": {
			"vectis-data": {}
		},
		"services": {
			"api": {"networks": {"vectis-data": null}}
		}
	}`)
	if _, err := parseComposeServiceNetworks(raw); err == nil {
		t.Fatal("expected error when top-level network has empty name, got nil")
	}
}
