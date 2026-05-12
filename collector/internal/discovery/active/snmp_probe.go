package active

import (
	"context"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/itom-mini/collector/internal/discovery/snmp"
)

// snmpID is what one successful SNMP probe yielded.
type snmpID struct {
	SysName     string
	SysDescr    string
	SysObjectID string
	Vendor      string // best-effort label from the OID prefix
}

// probeSNMP tries each configured community in order. Returns nil if
// none answered. Order matters — the dispatcher puts tenant-supplied
// communities first so we never try "public" against a host whose
// real community we know.
func (s *Scanner) probeSNMP(ctx context.Context, ip string, cfg Config, state *runState) *snmpID {
	for _, community := range cfg.SNMPCommunities {
		state.rates.take(ip)
		id := trySNMP(ctx, ip, community)
		if id != nil {
			return id
		}
	}
	return nil
}

// trySNMP issues one GET for sysObjectID + sysName + sysDescr with a
// tight timeout. We reuse the existing snmp.Client which already
// handles unprivileged UDP and rate-limit token bucket.
func trySNMP(ctx context.Context, ip, community string) *snmpID {
	if community == "" {
		return nil
	}
	c, err := snmp.Open(ctx, snmp.Config{
		Target:    ip,
		Community: community,
		Version:   gosnmp.Version2c,
		Timeout:   1500 * time.Millisecond,
		Retries:   1, // single retry — this is a sweep probe, not a deep walk
		RatePPS:   100,
	})
	if err != nil {
		return nil
	}
	defer c.Close()

	res, err := c.Get([]string{
		snmp.OIDSysName + ".0",
		snmp.OIDSysDescr + ".0",
		snmp.OIDSysObjectID + ".0",
	})
	if err != nil {
		return nil
	}
	objID := res[snmp.OIDSysObjectID+".0"].AsString()
	if objID == "" {
		return nil
	}
	return &snmpID{
		SysName:     res[snmp.OIDSysName+".0"].AsString(),
		SysDescr:    res[snmp.OIDSysDescr+".0"].AsString(),
		SysObjectID: objID,
		Vendor:      vendorFromSysObjectID(objID),
	}
}

// vendorFromSysObjectID maps the IANA enterprise OID prefix to a
// human label. Tiny lookup table; full IANA list has ~70k entries
// but ~50 cover 95% of enterprise customers. Extend on demand.
func vendorFromSysObjectID(oid string) string {
	oid = strings.TrimPrefix(oid, ".")
	switch {
	case strings.HasPrefix(oid, "1.3.6.1.4.1.9."):
		return "cisco"
	case strings.HasPrefix(oid, "1.3.6.1.4.1.11."):
		return "hp"
	case strings.HasPrefix(oid, "1.3.6.1.4.1.674."):
		return "dell"
	case strings.HasPrefix(oid, "1.3.6.1.4.1.2636."):
		return "juniper"
	case strings.HasPrefix(oid, "1.3.6.1.4.1.12356."):
		return "fortinet"
	case strings.HasPrefix(oid, "1.3.6.1.4.1.25461."):
		return "paloalto"
	case strings.HasPrefix(oid, "1.3.6.1.4.1.2620."):
		return "checkpoint"
	case strings.HasPrefix(oid, "1.3.6.1.4.1.4526."):
		return "netgear"
	case strings.HasPrefix(oid, "1.3.6.1.4.1.171."):
		return "dlink"
	case strings.HasPrefix(oid, "1.3.6.1.4.1.14988."):
		return "mikrotik"
	case strings.HasPrefix(oid, "1.3.6.1.4.1.6027."):
		return "force10"
	case strings.HasPrefix(oid, "1.3.6.1.4.1.318."):
		return "apc"
	case strings.HasPrefix(oid, "1.3.6.1.4.1.41112."):
		return "ubiquiti"
	case strings.HasPrefix(oid, "1.3.6.1.4.1.6486."):
		return "alcatel-lucent"
	case strings.HasPrefix(oid, "1.3.6.1.4.1.890."):
		return "zyxel"
	case strings.HasPrefix(oid, "1.3.6.1.4.1.6876."):
		return "vmware"
	case strings.HasPrefix(oid, "1.3.6.1.4.1.311."):
		return "microsoft"
	case strings.HasPrefix(oid, "1.3.6.1.4.1.8072."):
		return "net-snmp"
	}
	return ""
}
