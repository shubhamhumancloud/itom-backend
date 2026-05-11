// Package driver holds the registry that maps a Fingerprint vendor to
// a Driver factory. The registry is set up once at process start
// (init wiring in the dispatcher); the crawl loop reads from it
// concurrently, never writes.
//
// Why a registry instead of a switch in the dispatcher? Because the
// list of supported vendors grows with every chapter — keeping it in
// one place behind a lookup makes adding Palo Alto / Cisco / SNMP
// drivers a one-line registration in their package's init() rather
// than a touch to the dispatcher.
package driver

import (
	"fmt"
	"sync"

	"github.com/itom-mini/collector/internal/discovery/device"
)

// Registry holds vendor → factory mappings. Zero value is unusable;
// always go through New().
type Registry struct {
	mu       sync.RWMutex
	factories map[device.Vendor]device.Factory
}

// New returns an empty registry. Callers populate it via Register.
func New() *Registry {
	return &Registry{factories: map[device.Vendor]device.Factory{}}
}

// Register associates a vendor with a constructor. Calling twice for
// the same vendor returns an error — registries should be deterministic.
func (r *Registry) Register(v device.Vendor, f device.Factory) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.factories[v]; exists {
		return fmt.Errorf("driver registry: %s already registered", v)
	}
	r.factories[v] = f
	return nil
}

// MustRegister is the panic-on-duplicate variant for init blocks.
func (r *Registry) MustRegister(v device.Vendor, f device.Factory) {
	if err := r.Register(v, f); err != nil {
		panic(err)
	}
}

// Pick returns a fresh Driver for the vendor, or nil if no factory is
// registered. Returning nil rather than an error keeps the call site
// in the crawl loop trivial — "no driver" is a normal, expected case
// (unknown device, fall back to recording basic facts).
func (r *Registry) Pick(v device.Vendor) device.Driver {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if f := r.factories[v]; f != nil {
		return f()
	}
	return nil
}

// Vendors lists every registered vendor. Useful for diagnostics + the
// /v1/discovery/capabilities endpoint we'll expose later.
func (r *Registry) Vendors() []device.Vendor {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]device.Vendor, 0, len(r.factories))
	for v := range r.factories {
		out = append(out, v)
	}
	return out
}
