package walkers

import (
	"net"
	"strconv"
	"strings"
)

// parseIntSuffix turns a single-integer table index ("3" → 3) into an
// int. Multi-component suffixes return ok=false.
func parseIntSuffix(s string) (int, bool) {
	if strings.Contains(s, ".") {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return n, true
}

// splitSuffix breaks a compound index ("3.10.0.0.1") into its parts.
func splitSuffix(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ".")
}

// inetAddressFromSuffix decodes the SNMP "InetAddress" encoding used
// by modern tables (ipAddressTable, ipNetToPhysicalTable, inetCidrRouteTable).
//
// Format: <addrType>.<len>.<bytes...>
//   addrType: 1=IPv4, 2=IPv6
//   len:      4 for v4, 16 for v6
//
// Returns the IP as a parseable string and the number of suffix
// elements consumed.
func inetAddressFromSuffix(parts []string) (ip string, consumed int) {
	if len(parts) < 2 {
		return "", 0
	}
	at, err := strconv.Atoi(parts[0])
	if err != nil {
		return "", 0
	}
	ln, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", 0
	}
	if len(parts) < 2+ln {
		return "", 0
	}
	bytesRaw := make([]byte, ln)
	for i := 0; i < ln; i++ {
		n, err := strconv.Atoi(parts[2+i])
		if err != nil {
			return "", 0
		}
		bytesRaw[i] = byte(n)
	}
	switch at {
	case 1:
		return net.IP(bytesRaw).To4().String(), 2 + ln
	case 2:
		return net.IP(bytesRaw).String(), 2 + ln
	default:
		return "", 0
	}
}

// ipv4FromSuffix decodes 4 dotted decimals (e.g. "10.0.0.1") at the
// start of `parts` into a string IP. Returns "" if parts doesn't start
// with 4 byte-valued ints.
func ipv4FromSuffix(parts []string) (string, bool) {
	if len(parts) < 4 {
		return "", false
	}
	octets := make([]byte, 4)
	for i := 0; i < 4; i++ {
		n, err := strconv.Atoi(parts[i])
		if err != nil || n < 0 || n > 255 {
			return "", false
		}
		octets[i] = byte(n)
	}
	return net.IP(octets).String(), true
}

// macFromDecOctets decodes "0.26.155.17.34.51" → "00:1a:9b:11:22:33".
// Used for FDB table indices (the row key IS the MAC, as 6 dotted
// decimal numbers).
func macFromDecOctets(parts []string) string {
	if len(parts) != 6 {
		return ""
	}
	const hex = "0123456789abcdef"
	out := make([]byte, 0, 17)
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return ""
		}
		if i > 0 {
			out = append(out, ':')
		}
		out = append(out, hex[byte(n)>>4], hex[byte(n)&0x0f])
	}
	return string(out)
}
