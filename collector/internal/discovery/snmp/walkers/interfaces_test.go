package walkers

import (
	"testing"

	"github.com/itom-mini/collector/internal/discovery/snmp"
)

func TestReadInterfaces_JoinsTablesAndPrefersHighSpeed(t *testing.T) {
	f := newFake()
	// Two interfaces: Gi1/0/1 (1Gbps, up) and Gi1/0/2 (down, no speed).
	f.setString(snmp.OIDIfDescr+".1", "GigabitEthernet1/0/1")
	f.setString(snmp.OIDIfDescr+".2", "GigabitEthernet1/0/2")
	f.setString(snmp.OIDIfName+".1", "Gi1/0/1")
	f.setString(snmp.OIDIfName+".2", "Gi1/0/2")
	f.setString(snmp.OIDIfAlias+".1", "uplink to coreR")
	f.setInt(snmp.OIDIfType+".1", 6)
	f.setInt(snmp.OIDIfType+".2", 6)
	f.setInt(snmp.OIDIfHighSpeed+".1", 1000) // 1Gbps -> 1_000_000_000 bps
	f.setInt(snmp.OIDIfAdminStatus+".1", 1)  // up
	f.setInt(snmp.OIDIfOperStatus+".1", 1)
	f.setInt(snmp.OIDIfAdminStatus+".2", 2) // down
	f.setInt(snmp.OIDIfOperStatus+".2", 2)
	f.setBytes(snmp.OIDIfPhysAddress+".1", []byte{0x00, 0x1a, 0x9b, 0x11, 0x22, 0x33})

	ifs, err := ReadInterfaces(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(ifs) != 2 {
		t.Fatalf("got %d interfaces, want 2", len(ifs))
	}
	// Find the row for index 1
	var p1 Interface
	for _, it := range ifs {
		if it.Index == 1 {
			p1 = it
		}
	}
	if p1.Name != "Gi1/0/1" {
		t.Errorf("name = %q, want %q (prefer ifName)", p1.Name, "Gi1/0/1")
	}
	if p1.Alias != "uplink to coreR" {
		t.Errorf("alias = %q", p1.Alias)
	}
	if p1.Speed != 1_000_000_000 {
		t.Errorf("speed = %d, want 1Gbps in bps", p1.Speed)
	}
	if p1.MAC != "00:1a:9b:11:22:33" {
		t.Errorf("mac = %q", p1.MAC)
	}
	if p1.OperStatus != "up" {
		t.Errorf("operStatus = %q", p1.OperStatus)
	}
}
