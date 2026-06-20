package license

import (
	"context"
	"sync/atomic"
)

// Provider holds the current trusted KeySet for the verification hot path and
// supports atomic refresh. [Verify] reads Current() with no I/O; a background
// task or the revoke webhook calls Refresh to re-resolve and swap the keyset.
// This is what keeps the contract's "never needs the network on the hot path"
// guarantee: resolution (which may touch the network) is fully decoupled from
// verification.
type Provider struct {
	resolver *Resolver
	current  atomic.Pointer[KeySet]
	source   atomic.Pointer[Source]
}

// NewProvider builds a Provider backed by r. The keyset is empty until the
// first successful Refresh.
func NewProvider(r *Resolver) *Provider { return &Provider{resolver: r} }

// Refresh re-resolves the JWKS and, on success, atomically swaps in the new
// keyset and records its source. On failure the previously-loaded keyset (if
// any) is retained and the error is returned, so a transient outage never
// blanks the hot path.
func (p *Provider) Refresh(ctx context.Context) (Source, error) {
	ks, src, err := p.resolver.Resolve(ctx)
	if err != nil {
		return "", err
	}
	p.current.Store(ks)
	p.source.Store(&src)
	return src, nil
}

// Current returns the most recently loaded KeySet, or nil if Refresh has never
// succeeded. Verify treats a nil keyset as misconfiguration (REJECT), so an
// unrefreshed Provider fails closed rather than verifying against nothing.
func (p *Provider) Current() *KeySet { return p.current.Load() }

// Source returns the layer that produced the current keyset, or "" if never
// refreshed. For operator diagnostics (e.g. "running on the embedded key").
func (p *Provider) Source() Source {
	if s := p.source.Load(); s != nil {
		return *s
	}
	return ""
}
