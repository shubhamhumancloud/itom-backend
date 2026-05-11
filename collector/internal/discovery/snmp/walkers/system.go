// Package walkers contains one file per MIB table we read. Each
// returns typed rows; observation mapping lives in the generic_snmp
// driver so walker output stays vendor-neutral (a future Cisco-IOS
// driver can re-use the walkers and emit different observations).
package walkers

import "github.com/itom-mini/collector/internal/discovery/snmp"

// System is what the device says about itself. Read first on every
// crawl — sysObjectID feeds the fingerprint, sysName labels the node,
// sysDescr carries the OS+version we keep for inventory.
type System struct {
	Name        string
	Description string
	ObjectID    string
	Uptime      int64
	Location    string
}

// ReadSystem pulls the four scalars we care about with one GET. If a
// device doesn't expose sysLocation (most don't), it stays empty.
func ReadSystem(c snmp.Runner) (System, error) {
	res, err := c.Get([]string{
		snmp.OIDSysName + ".0",
		snmp.OIDSysDescr + ".0",
		snmp.OIDSysObjectID + ".0",
		snmp.OIDSysUpTime + ".0",
		snmp.OIDSysLocation + ".0",
	})
	if err != nil {
		return System{}, err
	}
	return System{
		Name:        res[snmp.OIDSysName+".0"].AsString(),
		Description: res[snmp.OIDSysDescr+".0"].AsString(),
		ObjectID:    res[snmp.OIDSysObjectID+".0"].AsString(),
		Uptime:      res[snmp.OIDSysUpTime+".0"].AsInt(),
		Location:    res[snmp.OIDSysLocation+".0"].AsString(),
	}, nil
}
