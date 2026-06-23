package scim

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// PatchRequest is a SCIM 2.0 PATCH body (RFC 7644 §3.5.2).
type PatchRequest struct {
	Schemas    []string         `json:"schemas"`
	Operations []PatchOperation `json:"Operations"`
}

// PatchOperation is one operation within a PATCH request. Value is left raw so
// it can be a scalar, a string, or an object depending on the IdP.
type PatchOperation struct {
	Op    string          `json:"op"`
	Path  string          `json:"path,omitempty"`
	Value json.RawMessage `json:"value,omitempty"`
}

// ExtractActiveChange inspects a PATCH request for a change to the "active"
// attribute — the only mutation Phase 1 supports (IdP enable/disable). It
// returns (value, true, nil) when an active toggle is present, (nil, false, nil)
// when the body is well-formed but touches no supported attribute, and an error
// when an active operation is present but its value cannot be parsed as boolean.
//
// Handles the shapes Okta and Azure AD emit:
//   - {"op":"replace","path":"active","value":false}
//   - {"op":"replace","path":"active","value":"False"}   (string boolean)
//   - {"op":"replace","value":{"active":false}}          (no path, object value)
func ExtractActiveChange(req PatchRequest) (active *bool, found bool, err error) {
	var result *bool
	for _, op := range req.Operations {
		verb := strings.ToLower(strings.TrimSpace(op.Op))
		if verb != "replace" && verb != "add" {
			continue
		}

		switch strings.ToLower(strings.TrimSpace(op.Path)) {
		case "active":
			b, perr := parseSCIMBool(op.Value)
			if perr != nil {
				return nil, false, fmt.Errorf("patch active: %w", perr)
			}
			result = &b
		case "":
			// No path: the value is an object, e.g. {"active": false}.
			var obj map[string]json.RawMessage
			if json.Unmarshal(op.Value, &obj) != nil {
				continue // not an object — unsupported attribute, ignore
			}
			raw, ok := obj["active"]
			if !ok {
				continue
			}
			b, perr := parseSCIMBool(raw)
			if perr != nil {
				return nil, false, fmt.Errorf("patch active: %w", perr)
			}
			result = &b
		default:
			// Any other attribute path is unsupported in Phase 1 — ignore here;
			// the handler rejects unsupported mutations (e.g. userName rename).
			continue
		}
	}
	if result == nil {
		return nil, false, nil
	}
	return result, true, nil
}

// parseSCIMBool accepts a JSON boolean or a quoted string boolean ("True",
// "false", "1", "0") — Azure AD sends the string form.
func parseSCIMBool(raw json.RawMessage) (bool, error) {
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return b, nil
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		v, err := strconv.ParseBool(strings.TrimSpace(s))
		if err != nil {
			return false, fmt.Errorf("invalid boolean string %q", s)
		}
		return v, nil
	}
	return false, fmt.Errorf("value %s is not a boolean", string(raw))
}
