package walkers

import (
	"testing"

	"github.com/itom-mini/collector/internal/discovery/snmp"
)

func TestReadLldp_DecodesIndexAndPeerFields(t *testing.T) {
	f := newFake()
	// Index shape: timeMark.localPortNum.remIndex
	//   timeMark = 0, localPortNum = 5, remIndex = 1
	const suffix = "0.5.1"
	f.setString(snmp.OIDLldpRemChassisId+"."+suffix, "00:11:22:33:44:55")
	f.setString(snmp.OIDLldpRemPortId+"."+suffix, "Gi1/0/3")
	f.setString(snmp.OIDLldpRemSysName+"."+suffix, "swB")
	f.setString(snmp.OIDLldpRemSysDesc+"."+suffix, "Cisco C9300")

	rows, err := ReadLldp(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	r := rows[0]
	if r.LocalPortNum != 5 {
		t.Errorf("LocalPortNum = %d, want 5", r.LocalPortNum)
	}
	if r.PeerSysName != "swB" {
		t.Errorf("PeerSysName = %q", r.PeerSysName)
	}
	if r.PeerPortID != "Gi1/0/3" {
		t.Errorf("PeerPortID = %q", r.PeerPortID)
	}
}

func TestReadLldpManagementAddresses_DecodesIPv4(t *testing.T) {
	f := newFake()
	// Index: timeMark.localPort.remIdx.addrSubtype(1=ipv4).addrLen(4).bytes(4)
	// localPort = 7; address = 10.0.0.2
	const suffix = "0.7.1.1.4.10.0.0.2"
	f.setInt(snmp.OIDLldpRemManAddrIfId+"."+suffix, 999) // ifId — we don't care, just need the row

	mp, err := ReadLldpManagementAddresses(f)
	if err != nil {
		t.Fatal(err)
	}
	ips, ok := mp[7]
	if !ok {
		t.Fatalf("missing entry for localPort 7; got %v", mp)
	}
	if len(ips) != 1 || ips[0] != "10.0.0.2" {
		t.Errorf("mgmt ips for port 7 = %v, want [10.0.0.2]", ips)
	}
}
