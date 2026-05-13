# ITOM Collector

The collector daemon. Installed once per customer site, runs as an OS
service (`kardianos/service`), and walks the customer's network by
talking to firewalls and switches with read-only credentials.

This document is a **living status doc**: it tracks what each chapter
landed and what's deferred. Update it whenever a chapter merges.

**Latest milestone:** Chapter 4 — Fusion engine + Cytoscape UI. The
end-to-end pipeline is now exercisable: seed a synthetic network from
the **Network Topology** page and the graph renders within ~1s. See
the "Testing the whole pipeline end-to-end" section below.

---

## What it does, in one paragraph

The dashboard creates a scan job. Postgres `NOTIFY` wakes the BE
dispatcher. The dispatcher signs the tenant's CIDR allowlist with
Ed25519 and pushes a `scan_job.assign` frame down the collector's
WebSocket. The collector verifies the signature, fetches credentials
JIT from the BE, and runs one of three pillars: **seed-and-crawl**
(chapters 1+2: hop neighbour-to-neighbour via firewall/SNMP),
**active sweep** (chapter 3: probe every IP in a CIDR with ICMP +
TCP + banner + SNMP + multicast), or noop. Every fact lands in
`disc_observation` on the BE; **chapter 4 fusion** turns those raw
facts into typed device / interface / ip / edge rows that drive the
Network Topology page in the dashboard.

## Cross-platform stance

The collector binary runs unchanged on Linux, macOS, and Windows
with **no admin / root / Npcap required**. Every network probe in
the codebase uses:

- pure Go stdlib (`net`, `crypto/tls`, UDP for multicast)
- `pro-bing` in unprivileged mode (UDP datagram on Linux/macOS,
  IcmpSendEcho on Windows)
- `gosnmp` (UDP — no raw sockets)

This sacrifices some accuracy at the edges (no raw ARP probe on local
L2, no SYN half-open scan) in exchange for "one binary, every OS,
zero setup." Privileged paths are documented as future polish — they
can be added behind capability detection without breaking the
unprivileged default.

---

## The map (current state, kept up to date)

```
   Customer site                                Our SaaS
   ─────────────                                ────────

   ┌─────────────┐                              ┌──────────────────────┐
   │ Firewall    │◄── HTTPS read-only ──┐       │ NestJS               │
   │ (FortiGate, │                      │       │  POST /scans         │
   │  PAN-OS,    │                      │       │   ↓ NOTIFY           │
   │  ASA, CP)   │                      │       │  Dispatcher          │
   └─────────────┘                      │       │   ↓ sign allowlist   │
                                        │       │   ↓ scan_job.assign  │
   ┌─────────────┐                      │       │      │               │
   │ Router /    │◄── SNMP v2c/v3 ───┐  │       │      │ WebSocket     │
   │ L3 switch   │                   │  │       │      ▼               │
   └─────────────┘                   │  │       │ ┌──────────────────┐ │
                                     │  │       │ │ Discovery WS GW  │ │
   ┌─────────────┐                   │  │       │ │ /v1/discovery/ws │ │
   │ Access      │◄── LLDP/CDP ───┐  │  │       │ └────┬─────────────┘ │
   │ switch      │   neighbours   │  │  │       │      │ chunks        │
   └─────────────┘                │  │  │       │      ▼               │
                                  │  │  │       │ ┌──────────────────┐ │
   ┌─────────────┐                │  │  │       │ │ Postgres (raw)   │ │
   │ Hosts /     │   (FDB+ARP+    │  │  │       │ │  disc_observation│ │
   │ printers /  │    banner +    │  │  │       │ │  disc_scan_job   │ │
   │ IoT /       │    multicast)  │  │  │       │ │  disc_credential │ │
   │ workstation │                │  │  │       │ │  disc_audit_log  │ │
   └─────────────┘                │  │  │       │ │  disc_collector  │ │
                                  │  │  │       │ └────┬─────────────┘ │
                  ┌───────────────┴──┴──┴───────┴┐     │ on scan_done  │
                  │   itom-collector daemon      │     ▼               │
                  │  ┌────────────────────────┐  │┌──────────────────┐ │
                  │  │ fingerprint probe      │  ││ FusionService    │ │
                  │  │   ladder (TCP/TLS/SSH/ │  ││   identity merge │ │
                  │  │   HTTP/SNMP-sysOID)    │  ││   source-rank    │ │
                  │  └──────────┬─────────────┘  ││   precedence     │ │
                  │             ▼                ││                  │ │
                  │  ┌────────────────────────┐  │└────┬─────────────┘ │
                  │  │ driver registry        │  │     │               │
                  │  │   fortigate  → REST    │  │     ▼ typed rows    │
                  │  │   paloalto   → XML API │  │┌──────────────────┐ │
                  │  │   cisco_asa  → REST    │  ││ Postgres (typed) │ │
                  │  │   checkpoint → mgmt API│  ││  disc_device     │ │
                  │  │   sophos     → XML :4444│ ││                  │ │
                  │  │   generic_snmp → v2c/v3│  ││                  │ │
                  │  └──────────┬─────────────┘  ││  disc_iface      │ │
                  │             ▼                ││  disc_ip_binding │ │
                  │  ┌────────────────────────┐  ││  disc_neighbor   │ │
                  │  │ crawl loop  +  active  │  ││  disc_open_port  │ │
                  │  │   BFS, chassis dedup,  │  ││  disc_event      │ │
                  │  │   CIDR allowlist,      │  │└────┬─────────────┘ │
                  │  │   bounded concurrency, │  │     │               │
                  │  │   backoff + blacklist  │  │     ▼               │
                  │  └──────────┬─────────────┘  │┌──────────────────┐ │
                  │             ▼                ││ Topology API     │ │
                  │       observations           ││  GET /topology   │ │
                  └──────────────┼───────────────┘│  GET /devices    │ │
                                 │                │  GET /devices/:id│ │
                                 │ scan_job.chunk │└────┬─────────────┘ │
                                 └────────────────┘     │               │
                                                        ▼               │
                                                ┌──────────────────┐    │
                                                │ Frontend (Next)  │    │
                                                │  /discovery/     │    │
                                                │    topology      │    │
                                                │  Cytoscape graph │    │
                                                │  + device panel  │    │
                                                └──────────────────┘    │
                                                                        │
   * Cisco ASA driver pending — see "Status" below.                     │
                                                                        │
   Fusion runs once per scan session via the WS gateway's `scan_done`   │
   handler — it reads every observation for that session, merges them   │
   into existing devices by chassis serial → MAC → IP, and emits        │
   `discovery_event` rows so the UI can show "new device" / "new port". │
```

---

## Status by chapter

Tick each item when the underlying code lands. Lab-only items (need
EVE-NG / GNS3 / hardware) are flagged ⚠️.

### Chapter 0 — Foundation

- [x] Per-tenant Postgres tables (`disc_*`)
- [x] Envelope-encrypted credential vault (AES-256-GCM)
- [x] Signed CIDR allowlist (Ed25519)
- [x] WebSocket gateway at `/v1/discovery/ws`
- [x] LISTEN/NOTIFY + `FOR UPDATE SKIP LOCKED` dispatch
- [x] **Stale-job sweeper** (cron flips running→timeout after 20 min)
- [x] **RLS policies** — written, NOT auto-applied (see
      `src/discovery/migrations/001_enable_rls.sql`)

### Chapter 1 — Firewall ingestor

- [x] Vendor-neutral `device.Driver` interface
- [x] Shared `firewall.GenericDriver` adapter (one `firewall.Ingestor`
      per vendor → automatic observation mapping + neighbour hints)
- [x] FortiGate REST driver (interfaces, routes, ARP, NAT,
      zones, policies, IPsec, BGP, OSPF)
- [x] **Palo Alto PAN-OS** driver (XML API: interfaces, routes, ARP,
      NAT policy, zones, security policy, IPsec, BGP, OSPF)
- [x] **Cisco ASA** driver (REST API: physical/VLAN interfaces, ARP,
      monitoring routes + static routes, twice-NAT, ACLs, IPsec,
      BGP/OSPF best-effort)
- [x] **Check Point R80+** driver (Management API: gateway interfaces,
      access rulebase, NAT rulebase, security zones, VPN communities)
- [x] **Sophos Firewall (SFOS 18.x+)** driver (XML API on :4444:
      interfaces, zones, firewall rules, NAT rules, IPsec, BGP, OSPF,
      static routes)
- [x] Observations stream via `scan_job.chunk`
- [x] **Fingerprint probe ladder** (TCP/TLS/SSH/HTTP)
- [x] **Seed-and-crawl loop** (per-customer perimeter shape)
- [ ] Check Point per-gateway Gaia REST for runtime ARP/routes
      (management API only exposes config)
- [ ] Cisco ASA SSH/CLI fallback for boxes where REST is disabled
- [ ] ⚠️ Lab tests: subnet count, VPN tunnel edge, multi-VDOM,
      multi-vsys, multi-context ASA, multi-domain Check Point

### Chapter 2 — SNMP crawler

- [x] gosnmp client wrapper with typed errors
- [x] 10 walkers (system, interfaces, LLDP, CDP, ARP, FDB,
      routes, ipAddress, chassis, vlans)
- [x] generic_snmp driver — observations + neighbour hints
- [x] SNMP sysObjectID probe wired into fingerprint
- [x] Chassis-ID dedup + `chassis_alias` observations
- [x] Bounded concurrency (default 8, configurable per job)
- [x] Per-device backoff + blacklist after 3 consecutive failures
- [x] Per-device PPS rate-limit (token bucket, default 50)
- [x] **SNMPv3** (USM auth+priv; SHA/SHA256/SHA512, AES/AES192/AES256)
- [x] **Cisco per-VLAN FDB community trick** (`community@vlan-id`)
- [x] auth_failed vs unreachable surfaced to `disc_audit_log`
- [ ] ⚠️ Lab tests: 100-device topology, CPU under 50%, ARP+FDB join

### Chapter 3 — Active scanner

- [x] Stage 1 — host discovery (unprivileged ICMP + parallel TCP-ping)
- [x] Stage 2 — TCP-connect port scan (top-20 list, worker pool)
- [x] Stage 3 — banner grabs (HTTP `Server`, SSH banner, TLS cert
      CN+SAN, passive read for FTP/SMTP/MySQL/POP3/IMAP)
- [x] Stage 4 — SNMP probe (tenant communities first; defaults
      behind explicit opt-in)
- [x] Stage 5 — multicast discovery (mDNS, NetBIOS NBSTAT,
      WS-Discovery SOAP, SSDP M-SEARCH) using only stdlib UDP
- [x] Per-/24 token-bucket rate limit (default 1000 PPS)
- [x] Signed CIDR allowlist enforced on every IP before any packet
- [x] Per-host timeout (default 30s) to prevent tarpit goroutine leaks
- [ ] ⚠️ Lab tests: mixed Linux/Win/Mac/printer subnet, IDS-storm
      check, conntrack stability over 4h soak
- [ ] Raw ARP probe (needs `CAP_NET_RAW` / Npcap — deferred,
      crossplatform stance documented above)
- [ ] SMB Negotiate Windows OS fingerprint (port 445 open is bulk
      of signal today)
- [ ] Optional Nmap deep tier behind `deep_fingerprint` flag

### Chapter 4 — Topology engine + UI

- [x] Typed entities — `disc_device`, `disc_site`, `disc_iface`,
      `disc_ip_binding`, `disc_neighbor_edge`, `disc_open_port`,
      `disc_event`
- [x] FusionService — two-pass merge (device facts → child rows),
      identity merge by chassis serial → MAC → IP, source-rank
      precedence (SNMP=100, LLDP/CDP=50, fingerprint=40, active=20),
      single-transaction commit per session
- [x] WS gateway wired — `scan_job.done` triggers fire-and-forget
      fusion for that sessionId
- [x] Topology REST API — `GET /v1/discovery/sites|topology|devices|devices/:id`
      returning Cytoscape-ready node/edge arrays
- [x] Demo seeder — `POST /v1/discovery/demo/seed` plants a synthetic
      6-device network (HQ FW → core switch → 2 edge switches →
      2 hosts), runs through fusion, idempotent on re-seed
- [x] Frontend page — `/discovery/topology` with 3-column layout
      (searchable device list, Cytoscape+fcose graph, detail panel),
      30s refetch, edge styling per kind, kind-coloured nodes,
      availability-coloured borders
- [x] DiscoveryEvent feed surfaced in the detail panel
- [ ] Topology snapshots + diff API (retention ladder: 5min → 1h → 1d)
- [ ] Time-slider in the UI ("show topology 1h ago")
- [ ] Hysteresis-based availability flap suppression
- [ ] Conflict log surface (when two sources disagree on hostname etc.)
- [ ] Full lifecycle automation — `archived` after N missed scans

### Cross-cutting (built alongside chapters 1-3)

- [x] **Binary patcher** for 5 placeholders (tenant id, server URL,
      collector id, auth token, CIDR pubkey)
- [x] Per-tenant install download endpoint

---

## Pending before chapter 5

Reviewed 2026-05-12. Chapter 4 is exercisable end-to-end (see the
testing recipe below). Snapshots/diff, time-slider, and flap
hysteresis are tracked above and can land alongside chapter 5
(alerting) without blocking it.

---

## Running locally (dev)

The collector is normally byte-patched at install time. For local
development you can run from source against env vars:

```bash
export ITOM_COLLECTOR_TENANT_ID=<uuid>
export ITOM_COLLECTOR_SERVER_URL=http://localhost:3005
export ITOM_COLLECTOR_ID=<uuid>
export ITOM_COLLECTOR_AUTH_TOKEN=<64-hex-token>
export ITOM_COLLECTOR_CIDR_PUBKEY=<base64-ed25519-pubkey-from-BE>

cd backend/collector
go run ./cmd/collectord run
```

Get the CIDR pubkey from the BE:

```bash
curl http://localhost:3005/v1/discovery/signing/public-key
```

Create a collector row first (returns the bearer once):

```bash
curl -X POST http://localhost:3005/v1/discovery/collectors \
  -H "Content-Type: application/json" \
  -H "x-tenant-id: <tenant-uuid>" \
  -d '{"name":"dev-collector","allowedCidrs":["10.0.0.0/8","192.168.0.0/16"]}'
```

---

## Testing the whole pipeline end-to-end

You don't need a firewall, switch, or even a working collector to see
the full chapter-0-through-4 flow. The demo seeder synthesises a
6-device network of `disc_observation` rows, runs them through
FusionService, and the frontend renders the resulting graph.

**Prerequisites:** Postgres running with the BE schema migrated.

### 1. Start the backend

```powershell
cd backend\BE
npm install
npm run start:dev      # listens on http://localhost:3005
```

Watch for `Discovery WS gateway listening on /v1/discovery/ws` and
`Nest application successfully started` in the log.

### 2. Start the frontend

In a second terminal:

```powershell
cd frontend
npm install
npm run dev            # listens on http://localhost:3008
```

### 3. Open the Network Topology page

1. Browse to `http://localhost:3008` and log in.
2. In the left sidebar, expand **Discovery** → click **Network Topology**.
3. You should land on `/discovery/topology` showing the empty-state
   card *"No devices discovered yet"*.

### 4. Seed the demo network

Click **Seed demo data** (top right). The toast confirms
`Demo data seeded — N observations`. Within ~1s the page swaps from
the empty-state card to the 3-column graph view:

- **Left:** searchable list with 6 devices — `hq-fw-01` (firewall),
  `core-sw-01`, `edge-sw-a`, `edge-sw-b`, `host-a1`, `host-b1`.
- **Middle:** Cytoscape graph with fcose layout. Firewall is red,
  switches are cyan, hosts are green. LLDP links are solid grey.
- **Right:** detail panel for the first device.

### 5. Exercise the UI

- **Click any node** in the graph — the right-hand panel updates with
  identity, interfaces, IP bindings, open ports, and recent events.
- **Type in the search box** ("edge", "10.10") — matching nodes get
  the amber highlight ring in the graph and the list filters.
- **Click "Refresh"** — both queries (`topology`, `devices`) re-run.
  The seeder is idempotent, so clicking **Seed demo data** again just
  refreshes the same 6 devices.

### 6. Verify with raw queries (optional)

```sql
SELECT identity_key, hostname, kind, availability_state FROM disc_device;
SELECT source_kind, COUNT(*) FROM disc_event GROUP BY source_kind;
SELECT kind, COUNT(*) FROM disc_neighbor_edge GROUP BY kind;
```

You should see 6 device rows, a handful of `device_added`/`new_neighbor_edge`
events, and 5 LLDP edges (4 access-link + 1 uplink).

### 7. Run the unit tests

```powershell
cd backend\collector
go test .\...                       # collector probes, walkers, crawler
cd ..\BE
npm test                            # BE unit tests
```

---

## Building templates (prod)

Cross-compile `itom-collector-<os>-<arch>` and drop into
`<BE>/agents-dist/collector-templates/`. The BE's
`CollectorBinaryPatcherService` reads from that folder.

```bash
cd backend/collector
GOOS=linux   GOARCH=amd64 go build -o dist/itom-collector-linux-amd64   ./cmd/collectord
GOOS=darwin  GOARCH=arm64 go build -o dist/itom-collector-darwin-arm64  ./cmd/collectord
GOOS=windows GOARCH=amd64 go build -o dist/itom-collector-windows-amd64.exe ./cmd/collectord
# ... etc
```

---

## File map

```
backend/collector/
├── cmd/collectord/main.go          service lifecycle + baked identity
└── internal/
    ├── cidrguard/                  Ed25519 verify + IP-in-CIDR check
    ├── wsproto/                    WS frame envelopes
    ├── wsclient/                   WS client + scan-job dispatcher
    └── discovery/
        ├── device/                 Driver interface, Creds, errors
        ├── driver/                 vendor → factory registry
        ├── fingerprint/            probe ladder (ports/TLS/SSH/HTTP/SNMP)
        ├── crawl/                  BFS, chassis dedup, blacklist, workers
        ├── active/                 chapter 3 — CIDR sweep + 5-stage probe
        ├── snmp/                   gosnmp wrapper + OIDs + rate limit
        ├── snmp/walkers/           one file per MIB table
        ├── firewall/               firewall.Ingestor + payload types + generic driver adapter
        ├── firewall/fortigate/     FortiOS 7.2+ REST driver
        ├── firewall/paloalto/      PAN-OS 10.x XML API driver
        ├── firewall/cisco_asa/     Cisco ASA 9.6+ REST driver
        ├── firewall/checkpoint/    Check Point R80+ Management REST driver
        ├── firewall/sophos/        Sophos Firewall SFOS 18.x+ XML API driver
        └── drivers/
            └── generic_snmp/       generic SNMP driver (used for Cisco IOS too)
```

## Pillars at a glance

| pillar     | What it does                                                  | targetSpec keys                                                |
|------------|---------------------------------------------------------------|----------------------------------------------------------------|
| `firewall` | Seed-and-crawl (Ch1 + Ch2): hop neighbour-to-neighbour        | `seeds: [ip]`, `vendor?: "fortigate"`, `maxDepth?`, `maxDevices?`, `maxConcurrency?` |
| `active`   | CIDR sweep (Ch3): ICMP+TCP+banner+SNMP+multicast              | `cidrs: [cidr]`, `ports?: [int]`, `maxConcurrency?`, `rateLimitPps?`, `snmpAllowDefaults?`, `skipMulticast?` |
| `noop`     | Smoke test                                                    | n/a                                                            |

---

## Adding a new driver

1. Implement `device.Driver` in `internal/discovery/drivers/<name>/`.
2. Export a `Factory func() device.Driver`.
3. Add a `device.Vendor` constant in `internal/discovery/device/device.go`.
4. Register in `internal/wsclient/dispatcher.go`:
   ```go
   reg.MustRegister(device.VendorNewVendor, newvendor.Factory)
   ```
5. Add fingerprint scoring in `internal/discovery/fingerprint/score.go`
   so probes pick the right vendor.
6. If the driver needs auth fields beyond what `device.Creds` already
   has, extend `device.Creds` + plumb through the BE credential vault
   + the wsclient credential resolver.

---

## Adding a new pillar

1. Add the constant to `wsproto.FrameKind` (collector) and `protocol.ts` (BE).
2. Add a case in `wsclient/dispatcher.go:Run()`.
3. If it's a new shape entirely (e.g. DHCP lease ingest, NetFlow), it
   probably shouldn't use the crawl loop — wire it directly inside the
   dispatcher case arm.

---

## Living document checklist

When a chapter merges, update:

1. The "Status by chapter" section above (tick items, add new chapter).
2. The diagram, if a new module / arrow appears.
3. The "Pending" section.

Don't leave this README pointing at a state that no longer matches the
code — that's worse than no README at all.
