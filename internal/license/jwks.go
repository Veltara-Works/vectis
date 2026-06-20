package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// jwk is a single JSON Web Key. Only the Ed25519 (OKP) fields the verifier
// needs are modelled; unknown fields are ignored.
type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	X   string `json:"x"` // base64url(raw 32-byte Ed25519 public key)
}

// KeySet is a parsed, trusted set of Ed25519 public keys indexed by `kid`.
// Key selection is fail-closed: a token whose `kid` is absent here is
// rejected, never matched against an arbitrary key.
type KeySet struct {
	keys map[string]ed25519.PublicKey
}

// jwksDoc is the JWKS wire shape: {"keys": [ ... ]}.
type jwksDoc struct {
	Keys []jwk `json:"keys"`
}

// ParseJWKS parses a JWKS document into a KeySet, accepting only
// OKP/Ed25519 entries with a non-empty `kid` and a 32-byte public key.
// Non-Ed25519 entries are skipped rather than failing the whole set.
func ParseJWKS(raw []byte) (*KeySet, error) {
	var doc jwksDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse jwks: %w", err)
	}
	ks := &KeySet{keys: make(map[string]ed25519.PublicKey, len(doc.Keys))}
	for _, k := range doc.Keys {
		if k.Kty != "OKP" || k.Crv != "Ed25519" {
			continue // not an Ed25519 key; ignore
		}
		if k.Kid == "" {
			continue // unusable without a key id
		}
		pub, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, fmt.Errorf("jwks kid %q: decode x: %w", k.Kid, err)
		}
		if len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("jwks kid %q: bad public key length %d", k.Kid, len(pub))
		}
		ks.keys[k.Kid] = ed25519.PublicKey(pub)
	}
	if len(ks.keys) == 0 {
		return nil, fmt.Errorf("parse jwks: no usable Ed25519 keys")
	}
	return ks, nil
}

// lookup returns the trusted public key for kid, or ok=false if absent.
func (ks *KeySet) lookup(kid string) (ed25519.PublicKey, bool) {
	k, ok := ks.keys[kid]
	return k, ok
}
