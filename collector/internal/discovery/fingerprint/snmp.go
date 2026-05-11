package fingerprint

import (
	"context"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/itom-mini/collector/internal/discovery/snmp"
)

// probeSNMPSysObjectID does a single SNMPv2c GET for sysObjectID.0.
// Returns the OID as a dotted string, or "" on any failure
// (no-community, timeout, NoSuchObject).
//
// This is the authoritative vendor signal — the score.go switch maps
// known sysObjectID prefixes (Fortinet 12356, Palo Alto 25461, Check
// Point 2620, Cisco 9, Juniper 2636) to vendors with high confidence.
//
// Cost: one UDP round trip with a small payload (~80 bytes). Cheap
// enough to run on every probe; we still gate it on "community is set"
// since v2c is the v2c-only path for now.
func probeSNMPSysObjectID(ctx context.Context, host, community string, timeout time.Duration) string {
	if community == "" {
		return ""
	}
	cfg := snmp.Config{
		Target:    host,
		Community: community,
		Version:   gosnmp.Version2c,
		Timeout:   timeout,
		Retries:   1, // fingerprint probe — one retry is enough, don't burn time
	}
	c, err := snmp.Open(ctx, cfg)
	if err != nil {
		return ""
	}
	defer c.Close()

	res, err := c.Get([]string{snmp.OIDSysObjectID + ".0"})
	if err != nil {
		return ""
	}
	v := res[snmp.OIDSysObjectID+".0"]
	return v.AsString()
}
