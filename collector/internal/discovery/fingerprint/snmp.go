package fingerprint

import (
	"context"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/itom-mini/collector/internal/discovery/device"
	"github.com/itom-mini/collector/internal/discovery/snmp"
)

// probeSNMPSysObjectID does a single GET for sysObjectID.0 in whichever
// SNMP version the credentials support (v3 preferred when username is
// set; v2c otherwise). Returns the OID as a dotted string, or "" on
// any failure.
//
// Score.go maps known sysObjectID prefixes (Fortinet 12356, Palo Alto
// 25461, Check Point 2620, Cisco 9, Juniper 2636) to vendors with high
// confidence — this is the strongest signal we have outside SSH banner.
//
// Cost: one UDP round trip (v2c) or three for v3's engine discovery.
// Cheap enough on every probe; gated on "SNMP creds present" so v3-only
// customers don't pay for v2c attempts that would silently fail.
func probeSNMPSysObjectID(ctx context.Context, host string, creds device.Creds, timeout time.Duration) string {
	if !creds.HasSNMP() {
		return ""
	}
	cfg := snmp.Config{
		Target:  host,
		Timeout: timeout,
		Retries: 1, // one retry — don't burn time on a probe
		RatePPS: 50,
	}
	if creds.SNMPv3Username != "" {
		cfg.Version = gosnmp.Version3
		cfg.V3 = snmp.V3Config{
			Username:     creds.SNMPv3Username,
			AuthProtocol: creds.SNMPv3AuthProtocol,
			AuthKey:      creds.SNMPv3AuthKey,
			PrivProtocol: creds.SNMPv3PrivProtocol,
			PrivKey:      creds.SNMPv3PrivKey,
		}
	} else {
		cfg.Version = gosnmp.Version2c
		cfg.Community = creds.SNMPCommunity
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
