package fingerprint

import (
	"strings"

	"github.com/itom-mini/collector/internal/discovery/device"
)

// score turns evidence into (Vendor, Confidence, Reasons). The signal
// weights are deliberately conservative:
//   - SSH banner match: +50 (strongest free signal short of SNMP)
//   - TLS subject contains vendor string: +40
//   - TLS issuer contains vendor string: +30
//   - HTTP Server header match: +20 (often customised, sometimes wrong)
//   - SNMP sysObjectID prefix match: +100 (authoritative; chapter-2)
//   - SSH banner is plain `OpenSSH`: +5 to GenericSNMP (it's something)
//
// Confidence buckets:
//   ≥80 = high   (multiple strong signals or one authoritative)
//   ≥40 = medium (one strong signal)
//   ≥15 = low    (something landed but it's a weak match)
//    <15 = none
//
// The scorer never lies: ambiguous evidence stays low/none. Better to
// fall back to generic-SNMP than to mis-claim "this is a Cisco" and
// fire a wrong driver.
func score(fp device.Fingerprint) (device.Vendor, device.Confidence, []string) {
	scores := map[device.Vendor]int{}
	reasons := map[device.Vendor][]string{}

	add := func(v device.Vendor, n int, why string) {
		scores[v] += n
		reasons[v] = append(reasons[v], why)
	}

	// SSH banner — RFC 4253 mandates a leak.
	if fp.SSHBanner != "" {
		banner := strings.ToLower(fp.SSHBanner)
		switch {
		case strings.Contains(banner, "fortissh"), strings.Contains(banner, "fortinet"):
			add(device.VendorFortiGate, 50, "ssh banner: "+fp.SSHBanner)
		case strings.Contains(banner, "mpssh"), strings.Contains(banner, "paloalto"):
			add(device.VendorPaloAlto, 50, "ssh banner: "+fp.SSHBanner)
		case strings.Contains(banner, "cisco asa"), strings.Contains(banner, "asaoss"):
			add(device.VendorCiscoASA, 50, "ssh banner: "+fp.SSHBanner)
		case strings.Contains(banner, "cisco"):
			add(device.VendorCiscoIOS, 45, "ssh banner: "+fp.SSHBanner)
		case strings.Contains(banner, "checkpoint"), strings.Contains(banner, "chkp"):
			add(device.VendorCheckPoint, 50, "ssh banner: "+fp.SSHBanner)
		case strings.Contains(banner, "junos"), strings.Contains(banner, "juniper"):
			add(device.VendorJuniperOS, 50, "ssh banner: "+fp.SSHBanner)
		}
	}

	// TLS subject + issuer. Free-text scan.
	if fp.TLSSubject != "" || fp.TLSIssuer != "" {
		subj := strings.ToLower(fp.TLSSubject + " | " + fp.TLSIssuer)
		switch {
		case strings.Contains(subj, "fortinet"), strings.Contains(subj, "fortigate"), strings.Contains(subj, "fgt"):
			add(device.VendorFortiGate, 40, "tls subject/issuer mentions Fortinet")
		case strings.Contains(subj, "palo alto"), strings.Contains(subj, "paloaltonetworks"), strings.Contains(subj, "pan-os"):
			add(device.VendorPaloAlto, 40, "tls subject/issuer mentions Palo Alto")
		case strings.Contains(subj, "check point"), strings.Contains(subj, "checkpoint"):
			add(device.VendorCheckPoint, 40, "tls subject/issuer mentions Check Point")
		case strings.Contains(subj, "cisco asa"), strings.Contains(subj, "asa firewall"):
			add(device.VendorCiscoASA, 40, "tls subject/issuer mentions Cisco ASA")
		case strings.Contains(subj, "cisco"):
			add(device.VendorCiscoIOS, 30, "tls subject/issuer mentions Cisco")
		case strings.Contains(subj, "juniper"):
			add(device.VendorJuniperOS, 40, "tls subject/issuer mentions Juniper")
		}
	}

	// HTTP Server header. Lower weight: nginx/apache/IIS are noise.
	if fp.HTTPServer != "" {
		srv := strings.ToLower(fp.HTTPServer)
		switch {
		case strings.Contains(srv, "fortinet"), strings.Contains(srv, "xxxxxxxx"): // FortiGate WAF cloaks behind a sentinel — keep both
			add(device.VendorFortiGate, 20, "http server: "+fp.HTTPServer)
		case strings.Contains(srv, "pan-os"):
			add(device.VendorPaloAlto, 20, "http server: "+fp.HTTPServer)
		case strings.Contains(srv, "checkpoint"):
			add(device.VendorCheckPoint, 20, "http server: "+fp.HTTPServer)
		case strings.Contains(srv, "cisco"):
			add(device.VendorCiscoIOS, 15, "http server: "+fp.HTTPServer)
		}
	}

	// SNMP sysObjectID — chapter-2 wiring. The OID prefixes are
	// IANA-assigned and authoritative.
	if fp.SysObjectID != "" {
		switch {
		case strings.HasPrefix(fp.SysObjectID, ".1.3.6.1.4.1.12356"),
			strings.HasPrefix(fp.SysObjectID, "1.3.6.1.4.1.12356"):
			add(device.VendorFortiGate, 100, "snmp sysObjectID: "+fp.SysObjectID)
		case strings.HasPrefix(fp.SysObjectID, ".1.3.6.1.4.1.25461"),
			strings.HasPrefix(fp.SysObjectID, "1.3.6.1.4.1.25461"):
			add(device.VendorPaloAlto, 100, "snmp sysObjectID: "+fp.SysObjectID)
		case strings.HasPrefix(fp.SysObjectID, ".1.3.6.1.4.1.2620"),
			strings.HasPrefix(fp.SysObjectID, "1.3.6.1.4.1.2620"):
			add(device.VendorCheckPoint, 100, "snmp sysObjectID: "+fp.SysObjectID)
		case strings.HasPrefix(fp.SysObjectID, ".1.3.6.1.4.1.9"),
			strings.HasPrefix(fp.SysObjectID, "1.3.6.1.4.1.9"):
			// .9 is Cisco's umbrella; we'd need the sub-prefix to tell
			// ASA vs IOS apart. Score weakly for both and let other
			// signals decide.
			add(device.VendorCiscoIOS, 60, "snmp sysObjectID under Cisco: "+fp.SysObjectID)
			add(device.VendorCiscoASA, 30, "snmp sysObjectID under Cisco (could be ASA): "+fp.SysObjectID)
		case strings.HasPrefix(fp.SysObjectID, ".1.3.6.1.4.1.2636"),
			strings.HasPrefix(fp.SysObjectID, "1.3.6.1.4.1.2636"):
			add(device.VendorJuniperOS, 100, "snmp sysObjectID: "+fp.SysObjectID)
		default:
			add(device.VendorGenericSNMP, 30, "snmp responded but vendor OID unknown: "+fp.SysObjectID)
		}
	}

	// Generic-SNMP fallback: if the device has 161/UDP open and
	// nothing strong elsewhere, the generic-SNMP driver gets a shot.
	// (Port 161 doesn't appear in our TCP-only port scan, so this
	// branch fires only after the SNMP probe sees a response — i.e.,
	// chapter-2 territory.)

	// Pick the winner.
	var winner device.Vendor
	best := 0
	for v, s := range scores {
		if s > best {
			best = s
			winner = v
		}
	}
	if winner == "" {
		return device.VendorUnknown, device.ConfidenceNone, nil
	}
	conf := bucketConfidence(best)
	return winner, conf, reasons[winner]
}

func bucketConfidence(s int) device.Confidence {
	switch {
	case s >= 80:
		return device.ConfidenceHigh
	case s >= 40:
		return device.ConfidenceMedium
	case s >= 15:
		return device.ConfidenceLow
	default:
		return device.ConfidenceNone
	}
}
