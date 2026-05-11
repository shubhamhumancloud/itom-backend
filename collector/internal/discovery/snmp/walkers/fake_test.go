package walkers

import (
	"strings"

	"github.com/itom-mini/collector/internal/discovery/snmp"
)

// fakeRunner implements snmp.Runner against a static set of OID/value
// pairs. Tests build one with NewFake() and pre-load it with the rows
// the device they're simulating would have returned.
type fakeRunner struct {
	// rows maps full OID → Value. For walks, we filter by prefix.
	rows map[string]snmp.Value
}

func newFake() *fakeRunner { return &fakeRunner{rows: map[string]snmp.Value{}} }

func (f *fakeRunner) setString(oid, s string) {
	f.rows[oid] = snmp.Value{OID: oid, Kind: snmp.KindString, Str: s}
}
func (f *fakeRunner) setInt(oid string, n int64) {
	f.rows[oid] = snmp.Value{OID: oid, Kind: snmp.KindInt, Int: n}
}
func (f *fakeRunner) setBytes(oid string, b []byte) {
	f.rows[oid] = snmp.Value{OID: oid, Kind: snmp.KindBytes, Bytes: b}
}

func (f *fakeRunner) Get(oids []string) (map[string]snmp.Value, error) {
	out := make(map[string]snmp.Value, len(oids))
	for _, o := range oids {
		if v, ok := f.rows[o]; ok {
			out[o] = v
		} else {
			out[o] = snmp.Value{OID: o, Kind: snmp.KindNull}
		}
	}
	return out, nil
}

func (f *fakeRunner) WalkTable(rootOID string) (map[string]snmp.Value, error) {
	prefix := rootOID + "."
	out := map[string]snmp.Value{}
	for oid, v := range f.rows {
		if strings.HasPrefix(oid, prefix) {
			out[strings.TrimPrefix(oid, prefix)] = v
		}
	}
	return out, nil
}
