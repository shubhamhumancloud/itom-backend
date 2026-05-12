package active

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/itom-mini/collector/internal/wsproto"
)

// runMulticastForSubnets fires one of each multicast probe per /24
// the scan touched, listens briefly for replies, and emits one
// observation per discovered host.
//
// Cross-platform: every probe in this file is plain UDP. mDNS,
// WS-Discovery, and SSDP use the well-known multicast groups
// (224.0.0.251, 239.255.255.250). NetBIOS NBSTAT is a directed UDP/137
// probe per IP, NOT multicast — but it's the standard "what's your
// hostname" path for Windows hosts and fits here logically.
func (s *Scanner) runMulticastForSubnets(ctx context.Context, ips []string, state *runState) {
	// Deduplicate by /24.
	seen := map[string]bool{}
	subnets := make([]string, 0)
	for _, ip := range ips {
		k := subnetOf(ip)
		if seen[k] {
			continue
		}
		seen[k] = true
		subnets = append(subnets, k)
	}

	mcastCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	// mDNS / WS-Discovery / SSDP are all multicast and reach any host
	// in any subnet we have a route to — no need to iterate subnets
	// for those. We send each once.
	var wg sync.WaitGroup
	for _, fn := range []func(context.Context, *runState){
		s.probeMDNS,
		s.probeWSDiscovery,
		s.probeSSDP,
	} {
		wg.Add(1)
		go func(f func(context.Context, *runState)) {
			defer wg.Done()
			f(mcastCtx, state)
		}(fn)
	}

	// NetBIOS is directed; iterate the alive IPs. We do this only on
	// /24 representatives' first 10 hosts to keep cost bounded — most
	// Windows networks have the same NetBIOS responder coverage you'd
	// see by sampling.
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.probeNetBIOS(mcastCtx, ips, state)
	}()

	wg.Wait()
}

// ---------- mDNS ----------

// probeMDNS sends one PTR query for `_services._dns-sd._udp.local` to
// 224.0.0.251:5353 and listens for ~3s. mDNS-aware hosts (Macs,
// printers, AirPlay devices, modern IoT) reply with their service
// names, which include the host's `.local` name.
func (s *Scanner) probeMDNS(ctx context.Context, state *runState) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 0})
	if err != nil {
		return
	}
	defer conn.Close()

	dst := &net.UDPAddr{IP: net.ParseIP("224.0.0.251"), Port: 5353}
	query := buildDNSQuery("_services._dns-sd._udp.local", 12 /* PTR */)
	_, _ = conn.WriteTo(query, dst)

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4096)
	for ctx.Err() == nil {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		names := parseDNSNames(buf[:n])
		// Filter the obvious self/multicast answers.
		clean := make([]string, 0, len(names))
		for _, n := range names {
			if n == "" || strings.HasSuffix(n, ".arpa.") || strings.HasSuffix(n, ".arpa") {
				continue
			}
			clean = append(clean, n)
		}
		if len(clean) == 0 {
			continue
		}
		state.mu.Lock()
		state.stats.MulticastResponses++
		state.mu.Unlock()
		state.emitObs(wsproto.Observation{
			SubjectKind: "host",
			SubjectKey:  fmt.Sprintf("ip:%s", addr.IP.String()),
			Attribute:   "mdns_name",
			Value: map[string]any{
				"names":  clean,
				"source": "mdns",
			},
			SeenAt: ts(time.Now()),
		})
	}
}

// buildDNSQuery returns the bytes of a single-question DNS packet.
// Used for mDNS PTR queries. The wire format is RFC 1035: 12-byte
// header + qname + qtype + qclass.
func buildDNSQuery(name string, qtype uint16) []byte {
	header := make([]byte, 12)
	header[0] = 0x00 // ID hi
	header[1] = 0x01 // ID lo
	header[2] = 0x00 // flags hi
	header[3] = 0x00 // flags lo
	header[4] = 0x00 // qdcount hi
	header[5] = 0x01 // qdcount lo (one question)

	var qname []byte
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			continue
		}
		qname = append(qname, byte(len(label)))
		qname = append(qname, []byte(label)...)
	}
	qname = append(qname, 0x00) // root label

	qtail := make([]byte, 4)
	binary.BigEndian.PutUint16(qtail[0:2], qtype)
	binary.BigEndian.PutUint16(qtail[2:4], 1) // qclass=IN

	out := append(header, qname...)
	out = append(out, qtail...)
	return out
}

// parseDNSNames extracts every dotted name (qname or rdata PTR) from
// the response, decompressing 0xC0 pointer labels along the way. We
// don't try to interpret record types — just pull text we recognise.
func parseDNSNames(b []byte) []string {
	if len(b) < 12 {
		return nil
	}
	// Scan record names beginning at the answer section. Simpler
	// approach: walk every byte; whenever we see a length byte that
	// looks plausible (1-63) starting a chain of printable ASCII,
	// decode it. This forgives malformed implementations and avoids
	// re-implementing the full RFC1035 state machine.
	var out []string
	for i := 12; i < len(b); i++ {
		// Try to decode a name starting at i.
		name, _, ok := decodeDNSName(b, i)
		if ok && name != "" && len(name) <= 253 {
			if isPrintableName(name) {
				out = append(out, name)
			}
		}
	}
	return dedup(out)
}

func decodeDNSName(b []byte, start int) (string, int, bool) {
	var parts []string
	pos := start
	jumped := false
	maxJumps := 5
	for {
		if pos >= len(b) {
			return "", 0, false
		}
		l := int(b[pos])
		if l == 0 {
			pos++
			break
		}
		if l&0xC0 == 0xC0 {
			// Pointer — RFC1035 §4.1.4.
			if pos+1 >= len(b) || maxJumps == 0 {
				return "", 0, false
			}
			ptr := int(binary.BigEndian.Uint16(b[pos:pos+2]) & 0x3FFF)
			if ptr >= start || ptr < 12 { // forward pointers and header pointers are invalid
				return "", 0, false
			}
			pos = ptr
			maxJumps--
			jumped = true
			continue
		}
		if l > 63 {
			return "", 0, false
		}
		if pos+1+l > len(b) {
			return "", 0, false
		}
		parts = append(parts, string(b[pos+1:pos+1+l]))
		pos += 1 + l
	}
	if jumped {
		// We can't know exact end of original record without tracking
		// it through the jump — caller doesn't need it precisely.
		pos = start
	}
	return strings.Join(parts, "."), pos, true
}

func isPrintableName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r >= 0x20 && r < 0x7f {
			continue
		}
		return false
	}
	return true
}

func dedup(xs []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		if seen[x] {
			continue
		}
		seen[x] = true
		out = append(out, x)
	}
	return out
}

// ---------- WS-Discovery ----------

// probeWSDiscovery sends a SOAP probe envelope to 239.255.255.250:3702.
// Cameras, printers, and ONVIF devices reply with their model and
// service URLs.
func (s *Scanner) probeWSDiscovery(ctx context.Context, state *runState) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 0})
	if err != nil {
		return
	}
	defer conn.Close()

	dst := &net.UDPAddr{IP: net.ParseIP("239.255.255.250"), Port: 3702}
	envelope := []byte(`<?xml version="1.0"?>` +
		`<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" ` +
		`xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" ` +
		`xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">` +
		`<s:Header>` +
		`<a:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action>` +
		`<a:MessageID>urn:uuid:itom-collector-probe</a:MessageID>` +
		`<a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>` +
		`</s:Header>` +
		`<s:Body><d:Probe/></s:Body>` +
		`</s:Envelope>`)
	_, _ = conn.WriteTo(envelope, dst)

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 8192)
	for ctx.Err() == nil {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		body := string(buf[:n])
		if !strings.Contains(body, "ProbeMatches") && !strings.Contains(body, "Hello") {
			continue
		}
		// Extract the optional "Types" field — vendor-specific but
		// often contains model hints like "dn:NetworkVideoTransmitter".
		types := extractXMLValue(body, "Types")
		scopes := extractXMLValue(body, "Scopes")
		state.mu.Lock()
		state.stats.MulticastResponses++
		state.mu.Unlock()
		state.emitObs(wsproto.Observation{
			SubjectKind: "host",
			SubjectKey:  fmt.Sprintf("ip:%s", addr.IP.String()),
			Attribute:   "ws_discovery",
			Value: map[string]any{
				"types":  types,
				"scopes": scopes,
				"source": "ws-discovery",
			},
			SeenAt: ts(time.Now()),
		})
	}
}

// extractXMLValue pulls the first <tag>...</tag> body out of a string.
// Permissive — works with any namespace prefix.
func extractXMLValue(xml, tag string) string {
	// Find ">tag" allowing namespace prefix.
	lower := strings.ToLower(xml)
	needle := ":" + strings.ToLower(tag) + ">"
	idx := strings.Index(lower, needle)
	if idx < 0 {
		needle = "<" + strings.ToLower(tag) + ">"
		idx = strings.Index(lower, needle)
		if idx < 0 {
			return ""
		}
	}
	start := idx + len(needle)
	end := strings.Index(lower[start:], "</")
	if end < 0 {
		return ""
	}
	return strings.TrimSpace(xml[start : start+end])
}

// ---------- SSDP ----------

// probeSSDP sends an HTTP-over-UDP M-SEARCH to 239.255.255.250:1900.
// UPnP-capable devices (smart TVs, IoT, some printers) respond with
// their identity in HTTP headers.
func (s *Scanner) probeSSDP(ctx context.Context, state *runState) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 0})
	if err != nil {
		return
	}
	defer conn.Close()

	dst := &net.UDPAddr{IP: net.ParseIP("239.255.255.250"), Port: 1900}
	msg := []byte(
		"M-SEARCH * HTTP/1.1\r\n" +
			"HOST: 239.255.255.250:1900\r\n" +
			"MAN: \"ssdp:discover\"\r\n" +
			"MX: 2\r\n" +
			"ST: ssdp:all\r\n\r\n",
	)
	_, _ = conn.WriteTo(msg, dst)

	_ = conn.SetReadDeadline(time.Now().Add(2500 * time.Millisecond))
	buf := make([]byte, 2048)
	for ctx.Err() == nil {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		resp := string(buf[:n])
		server := extractHeader(resp, "Server")
		st := extractHeader(resp, "ST")
		usn := extractHeader(resp, "USN")
		if server == "" && st == "" {
			continue
		}
		state.mu.Lock()
		state.stats.MulticastResponses++
		state.mu.Unlock()
		state.emitObs(wsproto.Observation{
			SubjectKind: "host",
			SubjectKey:  fmt.Sprintf("ip:%s", addr.IP.String()),
			Attribute:   "ssdp",
			Value: map[string]any{
				"server": server,
				"st":     st,
				"usn":    usn,
				"source": "ssdp",
			},
			SeenAt: ts(time.Now()),
		})
	}
}

// ---------- NetBIOS NBSTAT ----------

// probeNetBIOS sends an NBSTAT name query (UDP/137) to every IP and
// listens for replies. Windows hosts (and some NAS) respond with
// their workstation name even when DNS is silent.
//
// The query payload is the same 50 bytes for every target; the trick
// is just unicasting it. Worker pool is small (32) — Windows boxes
// don't usually rate-limit NetBIOS but we keep things gentle.
func (s *Scanner) probeNetBIOS(ctx context.Context, ips []string, state *runState) {
	const wantPort = 137
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 0})
	if err != nil {
		return
	}
	defer conn.Close()
	query := buildNBSTAT()

	sem := make(chan struct{}, 32)
	var wg sync.WaitGroup
	for _, ip := range ips {
		select {
		case <-ctx.Done():
			break
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			defer func() { <-sem }()
			state.rates.take(target)
			_, _ = conn.WriteToUDP(query, &net.UDPAddr{IP: net.ParseIP(target), Port: wantPort})
		}(ip)
	}

	// Reader: listen 3s after the last send for replies. Run it
	// concurrently so we don't lose early responses while still
	// dispatching.
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = conn.SetReadDeadline(time.Now().Add(4 * time.Second))
		buf := make([]byte, 1500)
		for ctx.Err() == nil {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			name := parseNBSTATName(buf[:n])
			if name == "" {
				continue
			}
			state.mu.Lock()
			state.stats.MulticastResponses++
			state.mu.Unlock()
			state.emitObs(wsproto.Observation{
				SubjectKind: "host",
				SubjectKey:  fmt.Sprintf("ip:%s", addr.IP.String()),
				Attribute:   "netbios_name",
				Value: map[string]any{
					"name":   name,
					"source": "netbios",
				},
				SeenAt: ts(time.Now()),
			})
		}
	}()

	wg.Wait()
}

// buildNBSTAT returns the wire bytes of a "NBSTAT *" query — the
// special wildcard NetBIOS name encoded per RFC 1002 §4.2.
func buildNBSTAT() []byte {
	// Header (12 bytes): tx id 0x1234, flags=0, qdcount=1, anr/aus/add 0.
	hdr := []byte{0x12, 0x34, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	// QNAME: encode "*               " (16 chars, * pad spaces) into
	// the NetBIOS first-level encoding (each byte → two nibble bytes
	// added to 'A').
	const raw = "*\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	encoded := make([]byte, 0, 32)
	for i := 0; i < 16; i++ {
		c := raw[i]
		encoded = append(encoded, 'A'+(c>>4), 'A'+(c&0x0f))
	}
	qname := []byte{0x20} // length=32
	qname = append(qname, encoded...)
	qname = append(qname, 0x00) // root label
	// QTYPE=NBSTAT (0x21), QCLASS=IN (0x01).
	qtail := []byte{0x00, 0x21, 0x00, 0x01}
	out := append(hdr, qname...)
	out = append(out, qtail...)
	return out
}

// parseNBSTATName pulls the first name out of a Node Status Response.
// The response carries a list of NetBIOS names; the workstation name
// is conventionally the first non-group entry.
func parseNBSTATName(b []byte) string {
	// The first ~57 bytes are header + answer-section name + fixed
	// RR fields; the name list begins after that. The number of
	// names is the byte at offset 56 (counting from start of payload).
	// Be defensive — many vendors lie about counts.
	if len(b) < 58 {
		return ""
	}
	// Find the first 18-byte name slot. Trim trailing spaces/nulls
	// and check it's printable ASCII.
	off := 57
	for off+18 <= len(b) {
		raw := b[off : off+15] // name is 15 bytes, byte 16 is the type
		name := strings.TrimRight(string(raw), " \x00")
		if name != "" && isPrintableName(name) {
			return name
		}
		off += 18
	}
	return ""
}
