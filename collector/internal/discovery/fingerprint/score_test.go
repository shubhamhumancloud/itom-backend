package fingerprint

import (
	"testing"

	"github.com/itom-mini/collector/internal/discovery/device"
)

func TestScore_FortiGateSSHBannerHighConfidence(t *testing.T) {
	fp := device.Fingerprint{SSHBanner: "SSH-2.0-FortiSSH_1.0"}
	v, c, _ := score(fp)
	if v != device.VendorFortiGate {
		t.Errorf("vendor = %s; want fortigate", v)
	}
	if c < device.ConfidenceMedium {
		t.Errorf("confidence = %s; want >= medium", c)
	}
}

func TestScore_CombinedSignalsBumpToHigh(t *testing.T) {
	fp := device.Fingerprint{
		SSHBanner:  "SSH-2.0-FortiSSH_1.0",
		TLSSubject: "CN=FGT60E-1234, O=Fortinet, OU=FortiGate",
	}
	v, c, _ := score(fp)
	if v != device.VendorFortiGate {
		t.Errorf("vendor = %s", v)
	}
	if c != device.ConfidenceHigh {
		t.Errorf("confidence = %s; want high (banner+tls = 90)", c)
	}
}

func TestScore_PaloAltoFromBanner(t *testing.T) {
	fp := device.Fingerprint{SSHBanner: "SSH-2.0-mpSSH_0.2.1"}
	v, _, _ := score(fp)
	if v != device.VendorPaloAlto {
		t.Errorf("vendor = %s; want paloalto", v)
	}
}

func TestScore_CiscoIOSFromSSHBanner(t *testing.T) {
	fp := device.Fingerprint{SSHBanner: "SSH-2.0-Cisco-1.25"}
	v, _, _ := score(fp)
	if v != device.VendorCiscoIOS {
		t.Errorf("vendor = %s; want cisco_ios", v)
	}
}

func TestScore_SNMPSysObjectIDAuthoritative(t *testing.T) {
	fp := device.Fingerprint{SysObjectID: ".1.3.6.1.4.1.25461.2.3.4"}
	v, c, _ := score(fp)
	if v != device.VendorPaloAlto {
		t.Errorf("vendor = %s", v)
	}
	if c != device.ConfidenceHigh {
		t.Errorf("confidence = %s; SNMP OID should be high", c)
	}
}

func TestScore_NoEvidenceReturnsUnknown(t *testing.T) {
	v, c, _ := score(device.Fingerprint{})
	if v != device.VendorUnknown {
		t.Errorf("vendor = %s; want unknown", v)
	}
	if c != device.ConfidenceNone {
		t.Errorf("confidence = %s; want none", c)
	}
}
