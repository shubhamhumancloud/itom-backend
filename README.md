# ITOM Mini — Backend (Phase 1)

NestJS API plus Postgres ingest, and a Go agent that collects host metrics and POSTs them on an interval. The parent repo root also contains a `frontend/` folder for the UI (see repo root `README.md`).

```
Laptop A (API)                       Laptop B / C / ... (agent)
┌─────────────────────────┐          ┌──────────────────────────┐
│ NestJS (backend/BE)     │ ◀─POST── │ Go binary (gopsutil)     │
│   POST /v1/metrics      │          │  config: ~/.itom-agent/  │
│   GET  /v1/metrics      │          │  log:    ~/.itom-agent/  │
│   GET  /v1/metrics/agents│         └──────────────────────────┘
│   /v1/agents/...        │
│   GET  /v1/health       │
│        ↓                │
│ Postgres (local)        │
│   db: itom              │
└─────────────────────────┘
        port 3000                              no inbound port
```

## Folder layout

From the repository root (`Code/`):

```
Code/
├── backend/                         ← this document
│   ├── BE/                          NestJS + TypeORM + PostgreSQL
│   │   ├── src/
│   │   │   ├── main.ts              bootstrap, global prefix `v1`, CORS, `0.0.0.0`
│   │   │   ├── app.module.ts        TypeORM + entity registration
│   │   │   ├── health/              GET /v1/health
│   │   │   ├── metrics/             ingest + list metrics, list reporting agents
│   │   │   └── agents/              agent registration, list/detail, binary/install routes
│   │   ├── agents-dist/             optional: pre-built agent binaries + install.sh
│   │   ├── package.json
│   │   ├── .env.example
│   │   └── tsconfig.json
│   └── agent/                       Go agent (Go 1.22+)
│       ├── cmd/agentd/main.go     run loop, signal handling
│       ├── internal/
│       │   ├── config/              ~/.itom-agent/config.json (auto-created)
│       │   ├── collector/           CPU / memory / disk (+ optional network/disk detail)
│       │   ├── sender/              POST /v1/metrics
│       │   ├── logger/              slog → stderr + ~/.itom-agent/agent.log
│       │   └── info/                host metadata for registration
│       ├── go.mod
│       ├── Makefile                 build / build-all / clean (Unix)
│       └── build.ps1                Windows helper for builds (optional)
└── frontend/                        UI (separate app; may be empty in early phases)
```

---

## Prerequisites

**API machine:**

- Node.js 20+ and npm
- PostgreSQL 14+ (same install notes as before: Homebrew, apt, Windows installer, or Postgres.app)

**Agent build machine:**

- Go 1.22+ to compile; target hosts only need the compiled binary.

---

## One-time PostgreSQL setup

Create database `itom` and user `itom` (adjust names/passwords to match `backend/BE/.env`):

```sql
CREATE USER itom WITH PASSWORD 'itom';
CREATE DATABASE itom OWNER itom;
GRANT ALL PRIVILEGES ON DATABASE itom TO itom;
\q
```

Verify:

```bash
psql -h localhost -U itom -d itom -c '\conninfo'
```

If authentication fails on Linux, see peer vs md5/scram notes in the original project docs; update `.env` or `pg_hba.conf` accordingly.

TypeORM `synchronize: true` creates and updates tables (`metric`, `network_metric`, `disk_metric`, `agent`, etc.) on startup — you do not hand-create the schema for local dev.

---

## Run the API

```bash
cd backend/BE
cp .env.example .env           # edit DB_* if needed
npm install
npm run start:dev              # default 0.0.0.0:3000, hot-reload
```

Expected log line:

`ITOM server listening on 0.0.0.0:3000`

### Verify

```bash
curl http://localhost:3000/v1/health
# {"status":"ok","time":"2026-..."}
```

### LAN IP and firewall

Agents need `http://<SERVER_IP>:3000`. Discover IP the same way as before (e.g. `ipconfig` on Windows, `ipconfig getifaddr en0` on macOS). Open inbound TCP 3000 on the API host if a firewall blocks it.

---

## Build the agent

```bash
cd backend/agent

# Current OS → backend/agent/dist/itom-agent
make build

# All common platforms
make build-all
ls dist/
# itom-agent-linux-amd64, itom-agent-linux-arm64, …
```

On Windows without Make, use `build.ps1` if present, or invoke `go build` similarly to the Makefile targets.

Static binaries can be copied to `backend/BE/agents-dist/` so the API can serve them from `/v1/agents/download/:filename` (set `AGENTS_DIST_PATH` if you store them elsewhere).

---

## Run the agent

First run — point at the server:

```bash
# Linux / macOS
ITOM_SERVER_URL=http://<SERVER_IP>:3000 ./dist/itom-agent

# Windows (PowerShell)
$env:ITOM_SERVER_URL="http://<SERVER_IP>:3000"
.\dist\itom-agent-windows-amd64.exe
```

Config and logs live under `~/.itom-agent/` (or `%USERPROFILE%\.itom-agent\` on Windows). Subsequent runs pick up `serverUrl` from config unless you override env vars (per agent implementation).

Useful flags (when implemented in `main.go`): `-version`, `-config <path>`.

---

## Verify end-to-end

```bash
curl http://localhost:3000/v1/metrics/agents
curl 'http://localhost:3000/v1/metrics?limit=10'
curl 'http://localhost:3000/v1/metrics?agentId=<uuid>&limit=10'
```

Direct SQL (identifiers may be snake_case in DB; quote if needed):

```bash
psql -h localhost -U itom -d itom -c 'SELECT * FROM metric ORDER BY timestamp DESC LIMIT 5;'
```

---

## API summary

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/v1/health` | Liveness |
| POST | `/v1/metrics` | Ingest metric batches from agents |
| GET | `/v1/metrics` | Recent samples (`agentId`, `limit` query params) |
| GET | `/v1/metrics/agents` | Agents seen via metrics ingest |
| POST | `/v1/agents/register` | Register/update agent metadata |
| GET | `/v1/agents` | List registered agents |
| GET | `/v1/agents/:agentId` | Agent detail |
| GET | `/v1/agents/install.sh` | Served from `agents-dist/install.sh` if present |
| GET | `/v1/agents/download/:filename` | Whitelisted pre-built binaries from `agents-dist` |

### POST `/v1/metrics` body (shape)

Core fields per sample: `timestamp` (ISO-8601), `cpuPercent`, `memoryPercent`, `diskPercent` (0–100). Optional fields include `memAvailableBytes`, `loadAvg1m`, `processCount`, `network[]` (per-interface counters), and `disks[]` (per-mount usage). See `backend/BE/src/metrics/dto/create-metrics.dto.ts` for validation rules.

### POST `/v1/agents/register` body (shape)

Requires `agentId` (string). Optional metadata: `hostname`, `os`, `arch`, IP lists, MAC addresses, CPU/memory/disk totals, etc. See `backend/BE/src/agents/dto/register-agent.dto.ts`.

---

## Agent execution flow (conceptual)

```
START
  ├─ load ~/.itom-agent/config.json (create with new UUID if missing)
  ├─ log file append
  ├─ collect → POST /v1/metrics (+ register metadata when applicable)
  └─ ticker → repeat; SIGINT/SIGTERM exits cleanly
```

Failed sends are logged; the next interval retries.

---

## Troubleshooting

| Symptom | Likely fix |
|---------|------------|
| `ECONNREFUSED` to Postgres | Start Postgres; check `DB_HOST` / `DB_PORT` |
| Password auth failed | Fix `DB_USER` / `DB_PASSWORD` in `.env` |
| Database missing | Create `itom` database and owner |
| Agent connection refused | API listening on `0.0.0.0`, firewall, same network |
| `400` on metrics | Check server logs; validate payload against DTO |
| `404` on install/binary download | Populate `backend/BE/agents-dist/` or set `AGENTS_DIST_PATH` |
| Reset dev data | Stop API, drop tables or database, restart (TypeORM recreates schema) |

---

## Environment variables (`backend/BE`)

| Variable | Purpose |
|----------|---------|
| `PORT` | HTTP port (default `3000`) |
| `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME` | PostgreSQL connection |
| `DB_LOGGING` | `true` to log SQL |
| `AGENTS_DIST_PATH` | Optional absolute path to folder containing `install.sh` and agent binaries for download routes (defaults to `agents-dist` under `BE`) |
