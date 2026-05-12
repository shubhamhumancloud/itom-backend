package active

import (
	"context"
	"fmt"
	"time"

	"github.com/itom-mini/collector/internal/wsproto"
)

// scanHost runs stages 1-4 against one IP. Stage 5 is per-subnet,
// driven separately from active.go.
//
// Hard timeout via context deadline so a tarpit host can't pin a
// worker indefinitely.
func (s *Scanner) scanHost(ctx context.Context, ip string, cfg Config, state *runState) {
	hostCtx, cancel := context.WithTimeout(ctx, cfg.HostTimeout)
	defer cancel()

	now := time.Now().UTC()

	// Stage 1 — discovery. Three probes in parallel; any "yes" wins.
	alive, probes, rtt := s.discoverHost(hostCtx, ip, state)
	if !alive {
		state.mu.Lock()
		state.stats.HostsUnresponsive++
		state.mu.Unlock()
		// We don't emit a per-IP "no_response" observation by default —
		// a /16 sweep would otherwise produce 60k+ rows of nothing. The
		// dispatcher's scan_summary captures the count.
		return
	}
	state.mu.Lock()
	state.stats.HostsAlive++
	state.mu.Unlock()
	state.emitObs(wsproto.Observation{
		SubjectKind: "host",
		SubjectKey:  fmt.Sprintf("ip:%s", ip),
		Attribute:   "alive",
		Value: map[string]any{
			"probes": probes,
			"rttMs":  rtt.Milliseconds(),
		},
		SeenAt: ts(now),
	})

	// Stage 2 — port scan. Top-20 first; expand to top-100 if any
	// landed. (Chapter 3 doc heuristic — most hosts have either
	// nothing or a handful of services on the well-known list, so
	// the expand path runs rarely.)
	openPorts := s.scanPorts(hostCtx, ip, cfg.Ports, state)
	if len(openPorts) == 0 {
		// Alive but quiet — done with this host.
		return
	}

	// Stage 3 — banner per open port.
	for _, port := range openPorts {
		state.stats.OpenPorts++
		banner := grabBanner(hostCtx, ip, port)
		if banner != nil {
			state.stats.BannersGrabbed++
		}
		v := map[string]any{
			"port":     port,
			"protocol": "tcp",
		}
		if banner != nil {
			v["banner"] = banner.Banner
			v["service"] = banner.Service
			if banner.TLSCertCN != "" {
				v["tlsCertCn"] = banner.TLSCertCN
				v["tlsCertSans"] = banner.TLSCertSANs
				v["tlsIssuer"] = banner.TLSIssuer
			}
		}
		state.emitObs(wsproto.Observation{
			SubjectKind: "open_port",
			SubjectKey:  fmt.Sprintf("ip:%s|port:%d", ip, port),
			Attribute:   "service",
			Value:       v,
			SeenAt:      ts(now),
		})
		// If we learned a hostname from a TLS cert, surface it as a
		// host-level discovery — fusion in chapter 4 joins this back
		// to the IP.
		if banner != nil && banner.TLSCertCN != "" {
			state.emitObs(wsproto.Observation{
				SubjectKind: "host",
				SubjectKey:  fmt.Sprintf("ip:%s", ip),
				Attribute:   "tls_hostname",
				Value: map[string]any{
					"commonName": banner.TLSCertCN,
					"sans":       banner.TLSCertSANs,
					"sourcePort": port,
				},
				SeenAt: ts(now),
			})
		}
	}

	// Stage 4 — SNMP probe (UDP 161). Tries tenant community first,
	// then any extra communities the caller passed in. Cheap when it
	// fails; valuable when it succeeds.
	if id := s.probeSNMP(hostCtx, ip, cfg, state); id != nil {
		state.mu.Lock()
		state.stats.SNMPMatches++
		state.mu.Unlock()
		state.emitObs(wsproto.Observation{
			SubjectKind: "host",
			SubjectKey:  fmt.Sprintf("ip:%s", ip),
			Attribute:   "snmp_identity",
			Value: map[string]any{
				"sysName":     id.SysName,
				"sysDescr":    id.SysDescr,
				"sysObjectId": id.SysObjectID,
				"vendor":      id.Vendor,
				"community":   "<redacted>",
			},
			SeenAt: ts(now),
		})
	}
}
