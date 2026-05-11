package walkers

import (
	"testing"

	"github.com/itom-mini/collector/internal/discovery/snmp"
)

func TestReadSystem_AllFields(t *testing.T) {
	f := newFake()
	f.setString(snmp.OIDSysName+".0", "swA-floor3")
	f.setString(snmp.OIDSysDescr+".0", "Cisco IOS Software, C9300 17.6.4")
	f.setString(snmp.OIDSysObjectID+".0", "1.3.6.1.4.1.9.1.2370")
	f.setInt(snmp.OIDSysUpTime+".0", 1234567)

	sys, err := ReadSystem(f)
	if err != nil {
		t.Fatal(err)
	}
	if sys.Name != "swA-floor3" {
		t.Errorf("Name = %q", sys.Name)
	}
	if sys.Description != "Cisco IOS Software, C9300 17.6.4" {
		t.Errorf("Description = %q", sys.Description)
	}
	if sys.ObjectID != "1.3.6.1.4.1.9.1.2370" {
		t.Errorf("ObjectID = %q", sys.ObjectID)
	}
	if sys.Uptime != 1234567 {
		t.Errorf("Uptime = %d", sys.Uptime)
	}
}
